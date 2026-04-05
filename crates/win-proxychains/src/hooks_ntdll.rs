use std::{ffi::c_void, sync::atomic::AtomicU64};

use magpie_process::{MemorySection, Process};
use windows_sys::{
    Wdk::{
        Foundation::OBJECT_ATTRIBUTES,
        System::SystemServices::{PAGE_EXECUTE_WRITECOPY, PAGE_READWRITE},
    },
    Win32::{
        Foundation::{HANDLE, STATUS_NOT_IMPLEMENTED, STATUS_SUCCESS},
        System::{
            Diagnostics::Debug::{FlushInstructionCache, IMAGE_NT_HEADERS64},
            Memory::{SECTION_MAP_EXECUTE, SECTION_MAP_READ, SECTION_MAP_WRITE},
            SystemServices::IMAGE_DOS_HEADER,
            Threading::{GetProcessId, TerminateProcess},
        },
    },
};

use anyhow::Result;

use crate::{InitializePacket, get_context, map_pe::custom_get_proc_address, set_last_error};

fn resume_process_with_og_bytes(
    process: &Process,
    original_bytes: &[u8],
    entry: u64,
) -> Result<()> {
    // write the original bytes back to the entry
    process.write_memory_at(entry, original_bytes)?;

    // flush the instruction cache to ensure the original bytes are executed
    unsafe {
        FlushInstructionCache(
            process.raw_handle(),
            entry as *const _,
            original_bytes.len(),
        )
    };

    // resume the process
    process.resume()?;

    Ok(())
}

const THREAD_CREATE_FLAGS_CREATE_SUSPENDED: u32 = 0x0000_0001;

// global mutable u64 to hold some context
static FPTR_O_NT_CREATE_USER_PROCESS: AtomicU64 = AtomicU64::new(0);

#[unsafe(no_mangle)]
pub unsafe extern "system" fn hooked_NtCreateUserProcess(
    process_handle: *mut HANDLE,
    thread_handle: *mut HANDLE,
    process_desired_access: u32,
    thread_desired_access: u32,
    process_object_attributes: *mut OBJECT_ATTRIBUTES,
    thread_object_attributes: *mut OBJECT_ATTRIBUTES,
    process_flags: u32,
    thread_flags: u32,
    process_parameters: *mut c_void,
    create_info: *mut c_void,
    attribute_list: *mut c_void,
) -> i32 {
    // check if we have the quick-call fptr already
    let fptr = FPTR_O_NT_CREATE_USER_PROCESS.load(std::sync::atomic::Ordering::SeqCst);
    if fptr == 0 {
        // Fetch it via context lookup
        let context = get_context();

        let hook = context
            .hooks
            .iter()
            .find(|hook| hook.target == hooked_NtCreateUserProcess as u64);

        let Some(hook) = hook else {
            set_last_error("Failed to find hook context for NtCreateUserProcess".to_string());

            // return an NTSTATUS error to caller
            return 0xC0000002u32 as i32; // STATUS_NOT_IMPLEMENTED
        };

        FPTR_O_NT_CREATE_USER_PROCESS.store(hook.trampoline(), std::sync::atomic::Ordering::SeqCst);
    }
    let fptr = FPTR_O_NT_CREATE_USER_PROCESS.load(std::sync::atomic::Ordering::SeqCst);

    let original: unsafe extern "system" fn(
        *mut HANDLE,
        *mut HANDLE,
        u32,
        u32,
        *mut OBJECT_ATTRIBUTES,
        *mut OBJECT_ATTRIBUTES,
        u32,
        u32,
        *mut c_void,
        *mut c_void,
        *mut c_void,
    ) -> i32 = unsafe { std::mem::transmute(fptr) };

    let already_suspended = thread_flags & THREAD_CREATE_FLAGS_CREATE_SUSPENDED != 0;

    let actual_flags = if already_suspended {
        thread_flags
    } else {
        thread_flags | THREAD_CREATE_FLAGS_CREATE_SUSPENDED
    };

    let result = unsafe {
        original(
            process_handle,
            thread_handle,
            process_desired_access,
            thread_desired_access,
            process_object_attributes,
            thread_object_attributes,
            process_flags,
            actual_flags,
            process_parameters,
            create_info,
            attribute_list,
        )
    };

    // Check if there was an error or not
    if result != STATUS_SUCCESS {
        return result;
    }

    let process_id = unsafe { GetProcessId(*process_handle) };

    let h_proc = unsafe { *process_handle };

    // Grab a handle with supporting crate
    let Ok(process) = Process::open(process_id) else {
        set_last_error("Failed to open target process".to_string());
        // Can't recover from this
        // Terminate it and return failure

        unsafe { TerminateProcess(h_proc as *mut _, 1) };

        return STATUS_NOT_IMPLEMENTED;
    };

    // grab the base address and entry point
    let Ok(image_base) = process.main_module_base() else {
        set_last_error("Failed to get main module base address".to_string());

        if !already_suspended {
            if process.resume().is_err() {
                set_last_error(
                    "Failed to get main module base address and then failed to resume process"
                        .to_string(),
                );
                // can't recover from this one
                unsafe { TerminateProcess(h_proc as *mut _, 1) };

                return STATUS_NOT_IMPLEMENTED;
            }
        }

        // ok, return as if nothing went wrong
        return result;
    };

    // read the image base into the buffer
    let Ok(remote_header) = process.read_memory_at(image_base, 0x4096) else {
        set_last_error("Failed to read memory at image base".to_string());

        if !already_suspended {
            if process.resume().is_err() {
                set_last_error(
                    "Failed to read memory at image base and then failed to resume process"
                        .to_string(),
                );
                // can't recover from this one
                unsafe { TerminateProcess(h_proc as *mut _, 1) };

                return STATUS_NOT_IMPLEMENTED;
            }
        }

        // ok, return as if nothing went wrong
        return result;
    };

    let remote_image_dos_header = unsafe { &*(remote_header.as_ptr() as *const IMAGE_DOS_HEADER) };

    // check magic or bail
    if remote_image_dos_header.e_magic != 0x5A4D {
        set_last_error("Invalid DOS header magic".to_string());
        if !already_suspended {
            if process.resume().is_err() {
                set_last_error(
                    "Invalid DOS header magic and then failed to resume process".to_string(),
                );
                // can't recover from this one
                unsafe { TerminateProcess(h_proc as *mut _, 1) };

                return STATUS_NOT_IMPLEMENTED;
            }
        }

        // ok, return as if nothing went wrong
        return result;
    }

    // ensure e_lfanew is within the buffer or bail
    if remote_image_dos_header.e_lfanew as usize
        > remote_header.len() - core::mem::size_of::<IMAGE_NT_HEADERS64>()
    {
        set_last_error("Invalid e_lfanew, points outside of read buffer".to_string());
        if !already_suspended {
            if process.resume().is_err() {
                set_last_error(
                    "Invalid e_lfanew, points outside of read buffer and then failed to resume process"
                        .to_string(),
                );
                // can't recover from this one
                unsafe { TerminateProcess(h_proc as *mut _, 1) };

                return STATUS_NOT_IMPLEMENTED;
            }
        }

        // ok, return as if nothing went wrong
        return result;
    }

    let remote_nt_header = unsafe {
        &*(remote_header
            .as_ptr()
            .add(remote_image_dos_header.e_lfanew as usize) as *const IMAGE_NT_HEADERS64)
    };

    // check magic or bail
    if remote_nt_header.Signature != 0x00004550 {
        set_last_error("Invalid NT header signature".to_string());
        if !already_suspended {
            if process.resume().is_err() {
                set_last_error(
                    "Invalid NT header signature and then failed to resume process".to_string(),
                );
                // can't recover from this one
                unsafe { TerminateProcess(h_proc as *mut _, 1) };

                return STATUS_NOT_IMPLEMENTED;
            }
        }

        // ok, return as if nothing went wrong
        return result;
    }

    let aop = remote_nt_header.OptionalHeader.AddressOfEntryPoint;

    let entry = image_base.saturating_add(aop as u64);

    // 48 B9 B3 73 04 D6 FA 6F 00 00 48 B8 B3 73 04 D6 FA 6F 00 00 FF E0
    let mut template: [u8; 22] = [
        0x48, 0xB9, 0xB3, 0x73, 0x04, 0xD6, 0xFA, 0x6F, 0x00, 0x00, 0x48, 0xB8, 0xB3, 0x73, 0x04,
        0xD6, 0xFA, 0x6F, 0x00, 0x00, 0xFF, 0xE0,
    ];

    // first we need the original bytes
    let Ok(original_bytes) = process.read_memory_at(entry, template.len()) else {
        set_last_error("Failed to read original bytes at entry point".to_string());
        if !already_suspended {
            if process.resume().is_err() {
                set_last_error(
                    "Failed to read original bytes at entry point and then failed to resume process"
                        .to_string(),
                );
                // can't recover from this one
                unsafe { TerminateProcess(h_proc as *mut _, 1) };

                return STATUS_NOT_IMPLEMENTED;
            }
        }

        // ok, return as if nothing went wrong
        return result;
    };

    // Now map our DLL in there.
    // We grab our own section first
    let context = get_context();
    let section_base = context.section_base;

    let Ok(map) = MemorySection::open_section(
        &context.section_name,
        SECTION_MAP_READ | SECTION_MAP_WRITE | SECTION_MAP_EXECUTE,
    ) else {
        set_last_error("Failed to open section for mapping".to_string());
        if !already_suspended {
            if resume_process_with_og_bytes(&process, &original_bytes, entry).is_err() {
                set_last_error("Failed to open section for mapping and then failed to restore original entry bytes".to_string());
                // can't recover from this one
                unsafe { TerminateProcess(h_proc as *mut _, 1) };

                return STATUS_NOT_IMPLEMENTED;
            }
        }

        // ok, return as if nothing went wrong
        return result;
    };

    // we've got our map mapped
    let Ok(mapped_section_base) =
        process.map_section_with_protection(&map, section_base as *const _, PAGE_EXECUTE_WRITECOPY)
    else {
        set_last_error("Failed to map section into target process".to_string());
        if !already_suspended {
            if resume_process_with_og_bytes(&process, &original_bytes, entry).is_err() {
                set_last_error("Failed to map section into target process and then failed to restore original entry bytes".to_string());

                // can't recover from this one
                unsafe { TerminateProcess(h_proc as *mut _, 1) };

                return STATUS_NOT_IMPLEMENTED;
            }
        }

        // ok, return as if nothing went wrong
        return result;
    };

    if mapped_section_base as u64 != section_base {
        set_last_error("Mapped section into target process at the wrong base".to_string());
        if !already_suspended {
            if resume_process_with_og_bytes(&process, &original_bytes, entry).is_err() {
                set_last_error("Mapped section into target process at the wrong base and then failed to restore original entry bytes".to_string());

                // can't recover from this one
                unsafe { TerminateProcess(h_proc as *mut _, 1) };

                return STATUS_NOT_IMPLEMENTED;
            }
        }

        // ok, return as if nothing went wrong
        return result;
    }

    let config = match &context.config {
        Some(config) => config,
        None => {
            set_last_error("No config found in context after mapping section".to_string());

            if !already_suspended {
                if resume_process_with_og_bytes(&process, &original_bytes, entry).is_err() {
                    set_last_error("No config found in context after mapping section and then failed to restore original entry bytes".to_string());

                    // can't recover from this one
                    unsafe { TerminateProcess(h_proc as *mut _, 1) };

                    return STATUS_NOT_IMPLEMENTED;
                }
            }

            // ok, return as if nothing went wrong
            return result;
        }
    };

    // Finally, grab our config, and call initialize on the remote copy of us
    let config_str = config.to_string();

    // The "initialize" function is at the same address as it is in our own process
    // So we can grab section_base here, call GetProcAddress to find initialize,
    // and then call it via a function pointer cast
    let maybe_proc_addr =
        custom_get_proc_address(context.section_base as *mut _, "initialize_remote");

    let Ok(initialize_function_address) = maybe_proc_addr else {
        set_last_error("Failed to find initialize function in mapped section".to_string());
        if !already_suspended {
            if resume_process_with_og_bytes(&process, &original_bytes, entry).is_err() {
                set_last_error("Failed to find initialize function in mapped section and then failed to restore original entry bytes".to_string());

                // can't recover from this one
                unsafe { TerminateProcess(h_proc as *mut _, 1) };

                return STATUS_NOT_IMPLEMENTED;
            }
        }
        // ok, return as if nothing went wrong
        return result;
    };

    // create the packet
    let Ok(mut initialize_packet) =
        InitializePacket::new(&config_str, &context.section_name, context.section_base)
    else {
        set_last_error("Failed to create initialize packet".to_string());
        if !already_suspended {
            if resume_process_with_og_bytes(&process, &original_bytes, entry).is_err() {
                set_last_error("Failed to create initialize packet and then failed to restore original entry bytes".to_string());

                // can't recover from this one
                unsafe { TerminateProcess(h_proc as *mut _, 1) };

                return STATUS_NOT_IMPLEMENTED;
            }
        }

        // ok, return as if nothing went wrong
        return result;
    };

    // grab random address
    let Ok(initialize_packet_address) = process.allocate_memory_at(
        None,
        core::mem::size_of::<InitializePacket>(),
        PAGE_READWRITE,
    ) else {
        set_last_error(
            "Failed to allocate memory in target process for initialize packet".to_string(),
        );
        if !already_suspended {
            if resume_process_with_og_bytes(&process, &original_bytes, entry).is_err() {
                set_last_error("Failed to allocate memory in target process for initialize packet and then failed to restore original entry bytes".to_string());

                // can't recover from this one
                unsafe { TerminateProcess(h_proc as *mut _, 1) };

                return STATUS_NOT_IMPLEMENTED;
            }
        }

        // ok, return as if nothing went wrong
        return result;
    };

    // Finalize the packet by setting the restore data.
    if initialize_packet
        .set_remote_restore_data(entry, &original_bytes)
        .is_err()
    {
        set_last_error("Failed to set restore data in initialize packet".to_string());
        if !already_suspended {
            if resume_process_with_og_bytes(&process, &original_bytes, entry).is_err() {
                set_last_error("Failed to set restore data in initialize packet and then failed to restore original entry bytes".to_string());

                // can't recover from this one
                unsafe { TerminateProcess(h_proc as *mut _, 1) };

                return STATUS_NOT_IMPLEMENTED;
            }
        }

        // ok, return as if nothing went wrong
        return result;
    }

    // write the packet to the target process
    if process
        .write_memory_at(initialize_packet_address, initialize_packet.as_bytes())
        .is_err()
    {
        set_last_error("Failed to write initialize packet to target process".to_string());
        if !already_suspended {
            if resume_process_with_og_bytes(&process, &original_bytes, entry).is_err() {
                set_last_error("Failed to write initialize packet to target process and then failed to restore original entry bytes".to_string());

                // can't recover from this one
                unsafe { TerminateProcess(h_proc as *mut _, 1) };

                return STATUS_NOT_IMPLEMENTED;
            }
        }

        // ok, return as if nothing went wrong
        return result;
    }

    // now we need to construct the template
    // mov rcx, addr initialze_packet
    // mov rax, addr initialize_remote
    // jmp rax
    // 48 B9 [8 byte address]
    // 48 B8 [8 byte address]
    // FF E0
    let remote_initialize_address = initialize_packet_address as u64;
    template[2..10].copy_from_slice(&remote_initialize_address.to_le_bytes());
    let remote_function_address = initialize_function_address as u64;
    template[12..20].copy_from_slice(&remote_function_address.to_le_bytes());

    // write the template to the entry point
    if process.write_memory_at(entry, &template).is_err() {
        set_last_error("Failed to write jump template to entry point".to_string());
        if !already_suspended {
            if resume_process_with_og_bytes(&process, &original_bytes, entry).is_err() {
                set_last_error("Failed to write jump template to entry point and then failed to restore original entry bytes".to_string());

                // can't recover from this one
                unsafe { TerminateProcess(h_proc as *mut _, 1) };

                return STATUS_NOT_IMPLEMENTED;
            }
        }

        // ok, return as if nothing went wrong
        return result;
    }

    // All done, now this is done the target may be resumed by us, or downstream code.
    if !already_suspended {
        // This is the success branch where we needed to suspend the process
        // So resume it now with our hook in place
        if process.resume().is_err() {
            set_last_error("Failed to resume target process after initialization".to_string());

            // can't recover from this one
            unsafe { TerminateProcess(h_proc as *mut _, 1) };

            return STATUS_NOT_IMPLEMENTED;
        }
    }

    return result;
}
