use iced_x86::{BlockEncoderOptions, Decoder, DecoderOptions, Instruction};
use windows_sys::Win32::System::{
    Diagnostics::Debug::FlushInstructionCache,
    LibraryLoader::{GetModuleHandleA, GetProcAddress, LoadLibraryA},
    Memory::{
        MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE, VirtualAlloc, VirtualFree, VirtualProtect,
    },
    Threading::GetCurrentProcess,
};

use anyhow::Result;

use crate::bail_with_last_error;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HookStatus {
    Unhooked,
    Hooked,
}

#[derive(Debug)]
pub struct HookContext {
    /// Module name in which the hook is applied, e.g., "ntdll.dll"
    pub module: String,
    /// Function name for reporting & debugging purposes
    pub function: String,
    /// A handle to the patchd module
    pub h_module: u64,
    /// Handle to the function being hooked, used for calculating the hook location and restoring original bytes
    pub h_proc: u64,
    /// These document the start of the patched bytes
    pub hook_start: u64,
    /// This is the end of the patched bytes
    pub hook_end: u64,
    /// The target to which the function must redirect
    pub target: u64,
    /// The store for reach the O.G. function without hitting our hook
    pub trampoline: u64,
    /// For restoring the original bytes when unhooking, we store them here
    pub original_bytes: [u8; 36],
    /// The status of the hook, whether it's currently active or not
    hook_status: HookStatus,
}

impl HookContext {
    pub fn new(module: &str, function: &str, target: u64) -> Result<Self> {
        let c_string_module_name = std::ffi::CString::new(module)?;

        let mut h_module = unsafe { GetModuleHandleA(c_string_module_name.as_ptr() as *const _) };

        if h_module.is_null() {
            // try to load it then
            h_module = unsafe { LoadLibraryA(c_string_module_name.as_ptr() as *const _) };

            if h_module.is_null() {
                bail_with_last_error(format!("Failed to get or load module {module}"))?;
            }
        }

        let h_proc = unsafe {
            GetProcAddress(
                h_module,
                std::ffi::CString::new(function)?.as_ptr() as *const _,
            )
        };

        let Some(h_proc) = h_proc else {
            return bail_with_last_error(format!(
                "Failed to get address of function {function} in module {module}"
            ));
        };

        // cast to u64
        let h_proc = unsafe { core::mem::transmute::<_, u64>(h_proc) };

        // A 5-byte rel32 jump has slightly less room when the target is below the source, so keep
        // direct hook targets inside the tighter bound and use the inline wrapping u32 math later.
        let distance = if target > h_proc {
            target - h_proc
        } else {
            h_proc - target
        };

        if distance > 0x7FFF_FFFB {
            return bail_with_last_error(format!(
                "Target {target:#x} is too far from original function {h_proc:#x} for a relative jump"
            ));
        }

        Ok(Self {
            module: module.to_string(),
            function: function.to_string(),
            h_module: h_module as u64,
            h_proc: h_proc as u64,
            hook_start: 0,
            hook_end: 0,
            target,
            trampoline: 0,
            original_bytes: [0; 36],
            hook_status: HookStatus::Unhooked,
        })
    }

    pub fn status(&self) -> &HookStatus {
        &self.hook_status
    }

    fn fetch_instruction_bytes_at(address: u64) -> [u8; 16] {
        let mut bytes = [0u8; 16];
        unsafe {
            std::ptr::copy_nonoverlapping(address as *const u8, bytes.as_mut_ptr(), bytes.len());
        }
        bytes
    }

    // set the hook with on the configured target
    pub fn hook(&mut self) -> Result<()> {
        // bail if status set
        if let HookStatus::Hooked = self.hook_status {
            return bail_with_last_error(format!(
                "Function {} in module {} is already hooked",
                self.function, self.module
            ));
        }

        let mut transplanted_instructions: Vec<Instruction> = Vec::new();
        let mut original_bytes = [0u8; 36];
        let mut offset: usize = 0;

        let ip = self.h_proc;
        // Only need a single jump here
        let size_needed = 5;

        // Procedure:
        // - Check the target, and gather sufficient opcodes to overwrite the start of the symbol with a jump to a trampoline.
        // - We only support simple instructions (should cover _all_ winapi functions, since their prologues are usually just push/reg/mov instructions).
        // - We require that we can find at least 5 bytes of them, since that's how big the jump instruction we'll be writing is. If we encounter an instruction we don't support, or we can't find 5 bytes worth of instructions, we bail with an error.
        while offset < size_needed {
            let instruction_bytes = Self::fetch_instruction_bytes_at(ip + offset as u64);
            let mut decoder = Decoder::with_ip(
                64,
                &instruction_bytes,
                ip + offset as u64,
                DecoderOptions::NONE,
            );
            let instruction = decoder.decode();

            let instruction_len = instruction.len();
            if instruction_len == 0 {
                return bail_with_last_error(format!(
                    "Failed to decode instruction at {:#x} for function {} in module {}",
                    ip + offset as u64,
                    self.function,
                    self.module
                ));
            }

            // Also check that controlflow is fallthrough
            // On anything else, return an error
            // let control_flow = instruction.flow_control();

            // if control_flow != FlowControl::Next {
            //     return bail_with_last_error(format!(
            //         "Cannot hook function {} in module {}: instruction at {:#x} has non-fallthrough control flow",
            //         self.function,
            //         self.module,
            //         ip + offset as u64
            //     ));
            // }

            transplanted_instructions.push(instruction);

            // copy the instruction bytes to the original_bytes buffer for later restoration when unhooking
            original_bytes[offset..offset + instruction_len]
                .copy_from_slice(&instruction_bytes[..instruction_len]);

            // Update offset
            offset += instruction_len;
        }

        // Allocate trampoline
        // format:
        // [original bytes]
        // jmp target + sizeof original bytes
        // We must allocate the trampoline within 2GB of the original function
        // so we'll use a little loop over VirtualAlloc to grab a chunk of memory within 2GB around the original function

        // VirtualAlloc rounds requested addresses down to allocation granularity. Keep 64 KiB of
        // headroom so the actual trampoline address cannot be rounded far enough away to overflow
        // the rel32 jump-back that we encode with wrapping u32 arithmetic below.
        let trampoline_search_radius = 0x7FFE_FFFB_u64;
        let mut alloc_address = self.h_proc.saturating_sub(trampoline_search_radius);
        let max_address = self.h_proc.saturating_add(trampoline_search_radius);

        let trampoline_address = loop {
            let potential_addr = unsafe {
                VirtualAlloc(
                    alloc_address as *const _,
                    0x1000,
                    MEM_COMMIT | MEM_RESERVE,
                    PAGE_EXECUTE_READWRITE,
                )
            };

            if !potential_addr.is_null() {
                break potential_addr as u64;
            }

            if alloc_address >= max_address {
                return bail_with_last_error(format!(
                    "Failed to allocate trampoline within 2GB of original function {:#x}",
                    self.h_proc
                ));
            }

            // The only thing likely in the way here are other modules
            // And those are allocated on 64k boundaries, so we can just skip ahead by that amount
            alloc_address += 0x10000;
        };

        // Store trampoline for potential cleanup
        self.trampoline = trampoline_address;

        let Ok(jump_back) = Instruction::with_branch(
            iced_x86::Code::Jmp_rel32_64,
            (self.h_proc + offset as u64) as u64,
        ) else {
            return bail_with_last_error(format!(
                "Failed to create jump instruction for trampoline for function {} in module {}",
                self.function, self.module
            ));
        };

        // Add the jump back
        transplanted_instructions.push(jump_back);

        // set ip for all instructions to '0'.
        transplanted_instructions
            .iter_mut()
            .for_each(|instr| instr.set_ip(0));

        // Encode/assemble the transplanted instructions into the trampoline
        // Note: these may expand in size, which is why we need to store the original bytes and restore them when unhooking
        // since the trampoline is not guaranteed to be the same size or the same bytes as the original overwritten instructions
        let instruction_block =
            iced_x86::InstructionBlock::new(&transplanted_instructions, self.trampoline);

        let Ok(encoded_block) =
            iced_x86::BlockEncoder::encode(64, instruction_block, BlockEncoderOptions::NONE)
        else {
            return bail_with_last_error(format!(
                "Failed to create block encoder for trampoline for function {} in module {}",
                self.function, self.module
            ));
        };

        // The size of the newly transplanted instructions
        // Not to be confused with the `offset` which encodes the size of the original instructions.
        let encoded_size = encoded_block.code_buffer.len();

        // copy the tranplanted instructions to the trampoline memory
        unsafe {
            std::ptr::copy_nonoverlapping(
                encoded_block.code_buffer.as_ptr(),
                self.trampoline as *mut u8,
                encoded_size,
            );
        }

        // let jump_back_from = trampoline_address + offset as u64;
        // let jump_back_to = self.h_proc + offset as u64;
        // let le_jump_bytes = (jump_back_to as u32)
        //     .wrapping_sub(jump_back_from as u32)
        //     .wrapping_sub(5)
        //     .to_le_bytes();

        // write 0xe9 [le_jump_bytes] to trampoline_address + offset
        unsafe {
            // let mut patch_bytes = [0u8; 5];
            // patch_bytes[0] = 0xe9; // JMP opcode
            // patch_bytes[1..].copy_from_slice(&le_jump_bytes);
            // std::ptr::copy_nonoverlapping(
            //     patch_bytes.as_ptr(),
            //     (trampoline_address + offset as u64) as *mut u8,
            //     patch_bytes.len(),
            // );
            FlushInstructionCache(
                GetCurrentProcess(),
                self.trampoline as *const _,
                //offset + patch_bytes.len(),
                encoded_size,
            );
        }

        // trampoline is ready at `trampoline_address`, now we just need to write the jump from the original function to the target, and we're done
        let jump_from = self.h_proc;
        let jump_to = self.target;
        let le_jump_bytes = (jump_to as u32)
            .wrapping_sub(jump_from as u32)
            .wrapping_sub(5)
            .to_le_bytes();

        let mut old_protection: u32 = 0;
        // Change the protection of the original function's memory to allow writing
        unsafe {
            let result = VirtualProtect(
                self.h_proc as *const _,
                offset,
                PAGE_EXECUTE_READWRITE,
                &mut old_protection,
            );
            if result == 0 {
                return bail_with_last_error(format!(
                    "Failed to change memory protection for hooking function {} in module {}",
                    self.function, self.module
                ));
            }

            // Write the jump to the target at the original function
            let mut patch_bytes = [0u8; 5];
            patch_bytes[0] = 0xe9; // JMP opcode
            patch_bytes[1..].copy_from_slice(&le_jump_bytes);
            std::ptr::copy_nonoverlapping(
                patch_bytes.as_ptr(),
                self.h_proc as *mut u8,
                patch_bytes.len(),
            );

            // flush bytes
            FlushInstructionCache(GetCurrentProcess(), self.h_proc as *const _, offset);

            // Restore original protection
            let _ = VirtualProtect(
                self.h_proc as *const _,
                offset,
                old_protection,
                &mut old_protection,
            );
        }

        // At this point we're hooked
        self.hook_start = self.h_proc;
        self.hook_end = self.h_proc + offset as u64;
        self.original_bytes.copy_from_slice(&original_bytes);
        self.hook_status = HookStatus::Hooked;

        Ok(())
    }

    // Unhook the target
    pub fn unhook(&mut self) -> Result<()> {
        // Bail if wrong status
        if let HookStatus::Unhooked = self.hook_status {
            return bail_with_last_error(format!(
                "Function {} in module {} is not currently hooked",
                self.function, self.module
            ));
        }

        // Restore the original bytes
        let mut old_protection: u32 = 0;
        unsafe {
            let result = VirtualProtect(
                self.hook_start as *const _,
                (self.hook_end - self.hook_start) as usize,
                PAGE_EXECUTE_READWRITE,
                &mut old_protection,
            );

            if result == 0 {
                return bail_with_last_error(format!(
                    "Failed to change memory protection for unhooking function {} in module {}",
                    self.function, self.module
                ));
            }

            std::ptr::copy_nonoverlapping(
                self.original_bytes.as_ptr(),
                self.hook_start as *mut u8,
                (self.hook_end - self.hook_start) as usize,
            );

            FlushInstructionCache(
                GetCurrentProcess(),
                self.hook_start as *const _,
                (self.hook_end - self.hook_start) as usize,
            );

            let _ = VirtualProtect(
                self.hook_start as *const _,
                (self.hook_end - self.hook_start) as usize,
                old_protection,
                &mut old_protection,
            );
        }

        // The original bytes are back in place, so cleanup can proceed.
        self.hook_status = HookStatus::Unhooked;

        self.reset()
    }

    // Clear errors and release memory
    pub fn reset(&mut self) -> Result<()> {
        // Do not allow this to be called while hooked, since it doesn't restore the original bytes or free the trampoline
        if let HookStatus::Hooked = self.hook_status {
            return bail_with_last_error(format!(
                "Cannot reset hook context for function {} in module {} while hooked. Please unhook first.",
                self.function, self.module
            ));
        }

        // This is a helper for testing, to reset the hook context without needing to unhook (since we might be in the middle of development and have broken unhooking)
        self.hook_start = 0;
        self.hook_end = 0;
        self.original_bytes = [0; 36];
        self.hook_status = HookStatus::Unhooked;

        if self.trampoline != 0 {
            unsafe {
                let result = VirtualFree(
                    self.trampoline as *mut _,
                    0,
                    windows_sys::Win32::System::Memory::MEM_RELEASE,
                );
                if result == 0 {
                    return bail_with_last_error("Failed to free trampoline memory");
                }
            }
            self.trampoline = 0;
        }
        Ok(())
    }

    // Get the trampoline address for calling the original function
    pub fn trampoline(&self) -> u64 {
        self.trampoline
    }
}

// Don't let hooks go out of scope without unhooking
impl Drop for HookContext {
    fn drop(&mut self) {
        if let HookStatus::Hooked = self.hook_status {
            let _ = self.unhook();
        }
    }
}

#[cfg(all(test, target_arch = "x86_64"))]
mod tests {
    use super::{HookContext, HookStatus};
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

    type TestFn = unsafe extern "C" fn(i32) -> i32;

    static TEST_MUTEX: Mutex<()> = Mutex::new(());
    static TRAMPOLINE_ADDR: AtomicU64 = AtomicU64::new(0);
    static TRAMPOLINE_HOOK_CALLS: AtomicUsize = AtomicUsize::new(0);
    static RETURN_ONLY_HOOK_CALLS: AtomicUsize = AtomicUsize::new(0);

    #[inline(never)]
    unsafe extern "C" fn target_for_unhook(value: i32) -> i32 {
        value + 1
    }

    #[inline(never)]
    unsafe extern "C" fn target_for_trampoline(value: i32) -> i32 {
        (value * 2) + 1
    }

    #[inline(never)]
    unsafe extern "C" fn target_for_return_only(value: i32) -> i32 {
        (value * 3) - 2
    }

    #[inline(never)]
    unsafe extern "C" fn hook_with_trampoline(value: i32) -> i32 {
        TRAMPOLINE_HOOK_CALLS.fetch_add(1, Ordering::SeqCst);

        let trampoline = TRAMPOLINE_ADDR.load(Ordering::SeqCst);
        if trampoline == 0 {
            return i32::MIN;
        }

        let original: TestFn = unsafe { std::mem::transmute(trampoline as usize) };
        unsafe { original(value) + 10 }
    }

    #[inline(never)]
    unsafe extern "C" fn hook_without_original(_value: i32) -> i32 {
        RETURN_ONLY_HOOK_CALLS.fetch_add(1, Ordering::SeqCst);
        777
    }

    fn test_context(function: &str, original: TestFn, hook: TestFn) -> HookContext {
        HookContext {
            module: "unit-test".to_owned(),
            function: function.to_owned(),
            h_module: 0,
            h_proc: original as usize as u64,
            hook_start: 0,
            hook_end: 0,
            target: hook as usize as u64,
            trampoline: 0,
            original_bytes: [0; 36],
            hook_status: HookStatus::Unhooked,
        }
    }

    fn lock_tests() -> std::sync::MutexGuard<'static, ()> {
        TEST_MUTEX
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    #[test]
    fn hook_and_unhook_restores_original_behavior() {
        let _guard = lock_tests();
        let original: TestFn = target_for_unhook;

        let baseline = unsafe { original(41) };
        assert_eq!(baseline, 42);

        let mut context = test_context(
            "target_for_unhook",
            target_for_unhook,
            hook_without_original,
        );

        context.hook().expect("hook should install successfully");

        assert_eq!(context.status(), &HookStatus::Hooked);
        assert_ne!(context.trampoline(), 0);
        assert_eq!(unsafe { original(41) }, 777);

        context
            .unhook()
            .expect("hook should uninstall successfully");

        assert_eq!(context.status(), &HookStatus::Unhooked);
        assert_eq!(context.trampoline(), 0);
        assert_eq!(unsafe { original(41) }, 42);
    }

    #[test]
    fn hook_can_call_original_function_via_trampoline() {
        let _guard = lock_tests();
        let original: TestFn = target_for_trampoline;

        TRAMPOLINE_ADDR.store(0, Ordering::SeqCst);
        TRAMPOLINE_HOOK_CALLS.store(0, Ordering::SeqCst);

        let baseline = unsafe { original(5) };
        assert_eq!(baseline, 11);

        let mut context = test_context(
            "target_for_trampoline",
            target_for_trampoline,
            hook_with_trampoline,
        );

        context.hook().expect("hook should install successfully");
        TRAMPOLINE_ADDR.store(context.trampoline(), Ordering::SeqCst);

        let hooked_result = unsafe { original(5) };
        assert_eq!(hooked_result, 21);
        assert_eq!(TRAMPOLINE_HOOK_CALLS.load(Ordering::SeqCst), 1);

        context
            .unhook()
            .expect("hook should uninstall successfully");
        TRAMPOLINE_ADDR.store(0, Ordering::SeqCst);

        assert_eq!(unsafe { original(5) }, 11);
    }

    #[test]
    fn hook_can_skip_calling_the_original_function() {
        let _guard = lock_tests();
        let original: TestFn = target_for_return_only;

        RETURN_ONLY_HOOK_CALLS.store(0, Ordering::SeqCst);

        let baseline = unsafe { original(7) };
        assert_eq!(baseline, 19);

        let mut context = test_context(
            "target_for_return_only",
            target_for_return_only,
            hook_without_original,
        );

        context.hook().expect("hook should install successfully");

        let hooked_result = unsafe { original(7) };
        assert_eq!(hooked_result, 777);
        assert_eq!(RETURN_ONLY_HOOK_CALLS.load(Ordering::SeqCst), 1);

        context
            .unhook()
            .expect("hook should uninstall successfully");

        assert_eq!(unsafe { original(7) }, 19);
    }
}
