// Copyright (c) 2026 FractalFrame <https://fractalframe.eu>
// Part of the win-proxychains project. Licensed under BSL-1.1; see LICENCE.md.

use windows_sys::Win32::Foundation::{
    CloseHandle, DUPLICATE_SAME_ACCESS, DuplicateHandle, HANDLE, INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::System::Threading::GetCurrentProcess;

#[derive(Debug)]
pub struct ScopedHandle(HANDLE);

impl ScopedHandle {
    pub fn new(handle: HANDLE) -> Self {
        Self(handle)
    }

    pub fn duplicate_from_raw(handle: HANDLE) -> Self {
        if !is_valid_handle(handle) {
            return Self(handle);
        }

        let process = unsafe { GetCurrentProcess() };
        let mut new_handle = HANDLE::default();
        let result = unsafe {
            DuplicateHandle(
                process,
                handle,
                process,
                &mut new_handle,
                0,
                0,
                DUPLICATE_SAME_ACCESS,
            )
        };

        if result == 0 {
            panic!("Failed to duplicate handle");
        }

        Self(new_handle)
    }

    pub fn raw(&self) -> HANDLE {
        self.0
    }
}

impl Drop for ScopedHandle {
    fn drop(&mut self) {
        if is_valid_handle(self.0) {
            unsafe {
                CloseHandle(self.0);
            }
        }
    }
}

impl Clone for ScopedHandle {
    fn clone(&self) -> Self {
        Self::duplicate_from_raw(self.0)
    }
}

unsafe impl Send for ScopedHandle {}
unsafe impl Sync for ScopedHandle {}

fn is_valid_handle(handle: HANDLE) -> bool {
    !handle.is_null() && handle != INVALID_HANDLE_VALUE
}
