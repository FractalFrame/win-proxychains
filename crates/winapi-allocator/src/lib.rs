#![no_std]

use core::{
    alloc::{GlobalAlloc, Layout},
    ffi::c_void,
    mem,
    ptr::{self, null_mut},
    sync::atomic::{AtomicUsize, Ordering},
};

use windows_sys::Wdk::Storage::FileSystem::{
    HEAP_GROWABLE, RtlAllocateHeap, RtlCreateHeap, RtlDestroyHeap, RtlFreeHeap,
};

const RTL_HEAP_ZERO_MEMORY: u32 = 0x0000_0008;
const HEAP_ALIGNMENT: usize = 2 * mem::size_of::<usize>();
static PRIVATE_HEAP: AtomicUsize = AtomicUsize::new(0);

#[repr(C)]
struct AlignedAllocHeader {
    base: *mut c_void,
}

pub struct WinApiAllocator<const BREAK_ON_ALLOC_FAILURE: bool = false>;

impl<const BREAK_ON_ALLOC_FAILURE: bool> WinApiAllocator<BREAK_ON_ALLOC_FAILURE> {
    pub const fn new() -> Self {
        Self
    }

    #[inline]
    fn process_heap() -> *mut c_void {
        let heap = PRIVATE_HEAP.load(Ordering::Acquire);
        if heap != 0 {
            return heap as *mut c_void;
        }

        let new_heap =
            unsafe { RtlCreateHeap(HEAP_GROWABLE, null_mut(), 0, 0, null_mut(), null_mut()) };
        if new_heap.is_null() {
            return null_mut();
        }

        match PRIVATE_HEAP.compare_exchange(
            0,
            new_heap as usize,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => new_heap,
            Err(existing) => {
                unsafe {
                    let _ = RtlDestroyHeap(new_heap);
                }
                existing as *mut c_void
            }
        }
    }

    #[inline]
    fn uses_manual_alignment(layout: Layout) -> bool {
        layout.align() > HEAP_ALIGNMENT
    }

    #[inline]
    unsafe fn rtl_alloc(size: usize, zeroed: bool) -> *mut u8 {
        let heap = Self::process_heap();
        if heap.is_null() {
            return null_mut();
        }

        let flags = if zeroed { RTL_HEAP_ZERO_MEMORY } else { 0 };
        unsafe { RtlAllocateHeap(heap, flags, size) as *mut u8 }
    }

    #[inline]
    unsafe fn rtl_free(ptr: *mut u8) {
        let heap = Self::process_heap();
        if heap.is_null() || ptr.is_null() {
            return;
        }

        unsafe {
            let _ = RtlFreeHeap(heap, 0, ptr as *const c_void);
        }
    }

    #[inline]
    unsafe fn alloc_manual_aligned(layout: Layout, zeroed: bool) -> *mut u8 {
        let header_size = mem::size_of::<AlignedAllocHeader>();
        let Some(total_size) = layout
            .size()
            .checked_add(layout.align() - 1)
            .and_then(|size| size.checked_add(header_size))
        else {
            return null_mut();
        };

        let base = unsafe { Self::rtl_alloc(total_size, zeroed) };
        if base.is_null() {
            return null_mut();
        }

        let aligned_addr =
            (base as usize + header_size + (layout.align() - 1)) & !(layout.align() - 1);
        let aligned_ptr = aligned_addr as *mut u8;
        let header_ptr = unsafe { aligned_ptr.sub(header_size) as *mut AlignedAllocHeader };
        unsafe {
            ptr::write(
                header_ptr,
                AlignedAllocHeader {
                    base: base as *mut c_void,
                },
            );
        }

        aligned_ptr
    }

    #[inline]
    unsafe fn free_manual_aligned(ptr: *mut u8) {
        let header_ptr =
            unsafe { ptr.sub(mem::size_of::<AlignedAllocHeader>()) as *const AlignedAllocHeader };
        let base = unsafe { (*header_ptr).base as *mut u8 };
        unsafe { Self::rtl_free(base) };
    }

    #[inline]
    fn handle_alloc_failure() {
        if BREAK_ON_ALLOC_FAILURE {
            unsafe {
                core::arch::asm!("int3");
            }
        }
    }
}

impl<const BREAK_ON_ALLOC_FAILURE: bool> Default for WinApiAllocator<BREAK_ON_ALLOC_FAILURE> {
    fn default() -> Self {
        Self::new()
    }
}

unsafe impl<const BREAK_ON_ALLOC_FAILURE: bool> GlobalAlloc
    for WinApiAllocator<BREAK_ON_ALLOC_FAILURE>
{
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if layout.size() == 0 {
            return layout.align() as *mut u8;
        }

        let ptr = if Self::uses_manual_alignment(layout) {
            unsafe { Self::alloc_manual_aligned(layout, false) }
        } else {
            unsafe { Self::rtl_alloc(layout.size(), false) }
        };

        if ptr.is_null() {
            Self::handle_alloc_failure();
        }

        ptr
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        if layout.size() == 0 {
            return layout.align() as *mut u8;
        }

        let ptr = if Self::uses_manual_alignment(layout) {
            unsafe { Self::alloc_manual_aligned(layout, true) }
        } else {
            unsafe { Self::rtl_alloc(layout.size(), true) }
        };

        if ptr.is_null() {
            Self::handle_alloc_failure();
        }

        ptr
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        if layout.size() == 0 || ptr.is_null() {
            return;
        }

        if Self::uses_manual_alignment(layout) {
            unsafe { Self::free_manual_aligned(ptr) };
        } else {
            unsafe { Self::rtl_free(ptr) };
        }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        if layout.size() == 0 {
            let new_layout = unsafe { Layout::from_size_align_unchecked(new_size, layout.align()) };
            let new_ptr = unsafe { self.alloc(new_layout) };
            if new_ptr.is_null() {
                Self::handle_alloc_failure();
            }
            return new_ptr;
        }

        if new_size == 0 {
            unsafe { self.dealloc(ptr, layout) };
            return layout.align() as *mut u8;
        }

        let new_layout = unsafe { Layout::from_size_align_unchecked(new_size, layout.align()) };
        let new_ptr = unsafe { self.alloc(new_layout) };
        if new_ptr.is_null() {
            Self::handle_alloc_failure();
            return null_mut();
        }

        unsafe {
            ptr::copy_nonoverlapping(ptr, new_ptr, layout.size().min(new_size));
            self.dealloc(ptr, layout);
        }

        new_ptr
    }
}

#[cfg(test)]
extern crate std;

#[cfg(test)]
mod tests {
    use super::WinApiAllocator;
    use std::alloc::{GlobalAlloc, Layout};

    #[test]
    fn test_allocation() {
        let allocator = WinApiAllocator::<false>::new();
        let layout = Layout::from_size_align(1024, 16).unwrap();
        unsafe {
            let ptr = allocator.alloc(layout);
            assert!(!ptr.is_null(), "allocation failed");
            allocator.dealloc(ptr, layout);
        }
    }
}
