use alloc::{
    ffi::CString,
    format,
    string::ToString,
    vec,
    vec::Vec,
};
use core::{ffi::c_void, iter, mem, ptr};

use anyhow::Result;
use magpie_process::{MemorySection, ParsedNtHeaders, ParsedPeFile, Process};
use windows_sys::Win32::{
    Foundation::{CloseHandle, GENERIC_READ, INVALID_HANDLE_VALUE},
    Storage::FileSystem::{
        CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, GetFileSizeEx, OPEN_EXISTING,
        ReadFile,
    },
    System::Memory::PAGE_EXECUTE_WRITECOPY,
};
use windows_sys::Win32::System::SystemInformation::{GetSystemInfo, SYSTEM_INFO};
use windows_sys::Win32::System::SystemServices::{
    DLL_PROCESS_ATTACH, IMAGE_BASE_RELOCATION, IMAGE_EXPORT_DIRECTORY, IMAGE_REL_BASED_ABSOLUTE,
    IMAGE_REL_BASED_DIR64, IMAGE_REL_BASED_HIGHLOW, IMAGE_TLS_DIRECTORY32, IMAGE_TLS_DIRECTORY64,
};
use windows_sys::Win32::System::{
    LibraryLoader::{GetProcAddress, LoadLibraryA},
    Memory::{PAGE_EXECUTE_READWRITE, SECTION_MAP_EXECUTE, SECTION_MAP_READ, SECTION_MAP_WRITE},
    SystemInformation::GetTickCount64,
    Threading::GetCurrentProcessId,
};

use crate::bail_with_last_error;

fn wide_null(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(iter::once(0)).collect()
}

fn basename(path: &str) -> &str {
    path.rsplit(['\\', '/']).next().unwrap_or(path)
}

fn read_file(path: &str) -> Result<Vec<u8>> {
    let path_wide = wide_null(path);
    let handle = unsafe {
        CreateFileW(
            path_wide.as_ptr(),
            GENERIC_READ,
            FILE_SHARE_READ,
            core::ptr::null(),
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            core::ptr::null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return bail_with_last_error("failed to open PE file");
    }

    let result = (|| -> Result<Vec<u8>> {
        let mut file_size = 0i64;
        if unsafe { GetFileSizeEx(handle, &mut file_size) } == 0 {
            return bail_with_last_error("failed to query PE file size");
        }

        let file_size = usize::try_from(file_size)
            .map_err(|_| anyhow::anyhow!("PE file size does not fit in usize"))?;
        let mut bytes = vec![0u8; file_size];
        let mut bytes_read = 0u32;
        if file_size != 0
            && unsafe {
                ReadFile(
                    handle,
                    bytes.as_mut_ptr(),
                    u32::try_from(file_size)
                        .map_err(|_| anyhow::anyhow!("PE file exceeds 4 GiB"))?,
                    &mut bytes_read,
                    core::ptr::null_mut(),
                )
            } == 0
        {
            return bail_with_last_error("failed to read PE file");
        }

        bytes.truncate(bytes_read as usize);
        Ok(bytes)
    })();

    unsafe {
        CloseHandle(handle);
    }

    result
}

// This function takes a PE file and maps it into memory.
// It takes a path to the PE file and returns a MemorySection containing the mapped image.
// it makes a bunch of assumptions about the PE file, since it's only meant to be used with our own DLLs
// It is very much expected this won't work for exotic species
// We go through all this copy, and not just a generic .dll injection, because we want to use rel_32 offsets in our jump hooks
// And to do that we need to restrict the mapping address to a base address in range of the required bases
pub fn map_and_load_pe(
    path: &str,
    required_bases_in_range: &[u64],
) -> Result<(u64, MemorySection)> {
    let pe_bytes = read_file(path)
        .map_err(|e| anyhow::anyhow!("failed to read PE file {path}: {e}"))?;
    let pe = ParsedPeFile::parse(&pe_bytes)?;
    let sections = pe.sections()?;

    let mut system_info: SYSTEM_INFO = unsafe { mem::zeroed() };
    unsafe {
        GetSystemInfo(&mut system_info);
    }

    let mut image_size = pe.size_of_image();
    let allocation_granularity = system_info.dwAllocationGranularity as usize;
    image_size = (image_size + allocation_granularity - 1) & !(allocation_granularity - 1);

    let timestamp = unsafe { GetTickCount64() };

    let name = format!(
        "win-proxy-section-{}-{}",
        basename(path),
        timestamp
    );

    let section = MemorySection::create_section(
        &name,
        SECTION_MAP_READ | SECTION_MAP_WRITE | SECTION_MAP_EXECUTE,
        image_size,
        PAGE_EXECUTE_READWRITE,
    )
    .map_err(|e| anyhow::anyhow!("failed to create memory section: {e}"))?;

    let current_process = Process::open(unsafe { GetCurrentProcessId() })
        .map_err(|e| anyhow::anyhow!("failed to open current process: {e}"))?;

    let search_radius = (8_u64 * 1024 * 1024 * 1024) / 5;
    let allocation_granularity = allocation_granularity as u64;

    let lowest_address = required_bases_in_range
        .iter()
        .copied()
        .map(|base| base.saturating_sub(search_radius))
        .max()
        .ok_or_else(|| anyhow::anyhow!("required_bases_in_range cannot be empty"))?;
    let highest_address = required_bases_in_range
        .iter()
        .copied()
        .map(|base| base.saturating_add(search_radius))
        .min()
        .ok_or_else(|| anyhow::anyhow!("required_bases_in_range cannot be empty"))?;

    let lowest_address = lowest_address.saturating_add(allocation_granularity - 1)
        / allocation_granularity
        * allocation_granularity;
    let highest_address = highest_address / allocation_granularity * allocation_granularity;

    let address = if lowest_address > highest_address {
        None
    } else {
        let mut offset = lowest_address;
        loop {
            if let Ok(mapped_address) = section.map_section(&current_process, offset as *const _) {
                break Some(mapped_address);
            }

            if offset >= highest_address {
                // We've gone too far, bail out
                break None;
            }

            offset = offset.saturating_add(allocation_granularity);
        }
    };

    let image_base = address
        .ok_or_else(|| anyhow::anyhow!("failed to map section within 1.6 GiB of required bases"))?;

    if pe.size_of_headers() > pe_bytes.len() {
        anyhow::bail!("PE headers are outside the file");
    }
    unsafe {
        ptr::copy_nonoverlapping(
            pe_bytes.as_ptr(),
            image_base as *mut u8,
            pe.size_of_headers(),
        );
    }

    for section in &sections {
        if section.PointerToRawData == 0 || section.SizeOfRawData == 0 {
            continue;
        }

        let raw_start = section.PointerToRawData as usize;
        let raw_size = section.SizeOfRawData as usize;
        let raw_end = raw_start
            .checked_add(raw_size)
            .ok_or_else(|| anyhow::anyhow!("section raw data overflowed the file bounds"))?;
        if raw_end > pe_bytes.len() {
            anyhow::bail!("section raw data is outside the file");
        }

        let virtual_size = unsafe { section.Misc.VirtualSize };
        let copy_size = if virtual_size == 0 {
            section.SizeOfRawData
        } else {
            virtual_size.min(section.SizeOfRawData)
        } as usize;
        let dest = unsafe { (image_base as *mut u8).add(section.VirtualAddress as usize) };
        let src = pe_bytes[raw_start..raw_end].as_ptr();

        unsafe {
            ptr::copy_nonoverlapping(src, dest, copy_size);
        }
    }

    let mapped_pe = ParsedNtHeaders::parse(image_base as *const _)?;
    let delta = image_base as i64 - pe.image_base() as i64;

    if delta != 0
        && let Some(reloc_directory) = mapped_pe.reloc_directory()
        && reloc_directory.VirtualAddress != 0
        && reloc_directory.Size != 0
    {
        let mut block_rva = reloc_directory.VirtualAddress;
        let reloc_end = reloc_directory
            .VirtualAddress
            .checked_add(reloc_directory.Size)
            .ok_or_else(|| anyhow::anyhow!("relocation directory overflowed"))?;

        while block_rva < reloc_end {
            let block = mapped_pe.read::<IMAGE_BASE_RELOCATION>(block_rva)?;
            if block.SizeOfBlock == 0 {
                break;
            }
            if block.SizeOfBlock < mem::size_of::<IMAGE_BASE_RELOCATION>() as u32 {
                anyhow::bail!("invalid relocation block size");
            }

            let entries_size = block.SizeOfBlock as usize - mem::size_of::<IMAGE_BASE_RELOCATION>();
            let entries = mapped_pe.slice(
                block_rva + mem::size_of::<IMAGE_BASE_RELOCATION>() as u32,
                entries_size,
            )?;

            for entry in entries.chunks_exact(2) {
                let entry = u16::from_le_bytes([entry[0], entry[1]]);
                let relocation_type = u32::from(entry >> 12);
                let offset = usize::from(entry & 0x0fff);

                match relocation_type {
                    IMAGE_REL_BASED_ABSOLUTE => {}
                    IMAGE_REL_BASED_HIGHLOW => {
                        let patch_address = unsafe {
                            (image_base as *mut u8).add(block.VirtualAddress as usize + offset)
                        } as *mut u32;
                        unsafe {
                            *patch_address = (*patch_address).wrapping_add(delta as u32);
                        }
                    }
                    IMAGE_REL_BASED_DIR64 => {
                        let patch_address = unsafe {
                            (image_base as *mut u8).add(block.VirtualAddress as usize + offset)
                        } as *mut u64;
                        unsafe {
                            *patch_address = (*patch_address).wrapping_add(delta as u64);
                        }
                    }
                    _ => anyhow::bail!("unsupported relocation type: {relocation_type}"),
                }
            }

            block_rva = block_rva
                .checked_add(block.SizeOfBlock)
                .ok_or_else(|| anyhow::anyhow!("relocation block overflowed"))?;
        }
    }

    fix_import_table(image_base as *const _)?;

    // now briefly unmap the section, and remap in COW
    section.unmap_section(&current_process, image_base as *const _)?;

    // remap to cow
    section.map_section_with_protection(
        &current_process,
        image_base as *const _,
        PAGE_EXECUTE_WRITECOPY,
    )?;

    // Prepare our own image for execution
    // execute_tls(image_base)?;

    // prepare our own image for execution
    // execute_dll_main(image_base)?;

    Ok((image_base as u64, section))
}

pub fn execute_dll_main(image_base: *const c_void) -> Result<()> {
    let mapped_pe = ParsedNtHeaders::parse(image_base as *const _)?;

    // grab the aop
    let entry_point_rva = match mapped_pe {
        ParsedNtHeaders::Pe32 { nt_headers, .. } => nt_headers.OptionalHeader.AddressOfEntryPoint,
        ParsedNtHeaders::Pe64 { nt_headers, .. } => nt_headers.OptionalHeader.AddressOfEntryPoint,
    };

    unsafe {
        let dll_main_fptr = mapped_pe.va(entry_point_rva)?;

        let dll_main: extern "system" fn(*mut u8, u32, *mut u8) = mem::transmute(dll_main_fptr);

        // call dll main with process attach
        dll_main(
            image_base as *mut u8,
            DLL_PROCESS_ATTACH,
            ptr::null_mut(),
        );
    };

    Ok(())
}

pub fn execute_tls(image_base: *const c_void) -> Result<()> {
    let mapped_pe = ParsedNtHeaders::parse(image_base as *const _)?;

    Ok(
        if let Some(tls_directory) = mapped_pe.tls_directory()
            && tls_directory.VirtualAddress != 0
            && tls_directory.Size != 0
        {
            let image_base_usize = image_base as usize;

            if mapped_pe.is_64() {
                let tls = mapped_pe.read::<IMAGE_TLS_DIRECTORY64>(tls_directory.VirtualAddress)?;
                if tls.AddressOfCallBacks != 0 {
                    let mut callbacks_rva = usize::try_from(tls.AddressOfCallBacks)
                        .ok()
                        .and_then(|va| va.checked_sub(image_base_usize))
                        .ok_or_else(|| anyhow::anyhow!("invalid TLS callback table"))?;

                    loop {
                        let callback = mapped_pe.read::<u64>(
                            u32::try_from(callbacks_rva)
                                .map_err(|_| anyhow::anyhow!("TLS callback table overflowed"))?,
                        )?;
                        if callback == 0 {
                            break;
                        }

                        let callback_fn: extern "system" fn(*mut u8, u32, *mut u8) =
                            unsafe { mem::transmute(callback as usize) };
                        callback_fn(
                            image_base as *mut u8,
                            DLL_PROCESS_ATTACH,
                            ptr::null_mut(),
                        );
                        callbacks_rva += mem::size_of::<u64>();
                    }
                }
            } else {
                let tls = mapped_pe.read::<IMAGE_TLS_DIRECTORY32>(tls_directory.VirtualAddress)?;
                if tls.AddressOfCallBacks != 0 {
                    let mut callbacks_rva = (tls.AddressOfCallBacks as usize)
                        .checked_sub(image_base_usize)
                        .ok_or_else(|| anyhow::anyhow!("invalid TLS callback table"))?;

                    loop {
                        let callback = mapped_pe.read::<u32>(
                            u32::try_from(callbacks_rva)
                                .map_err(|_| anyhow::anyhow!("TLS callback table overflowed"))?,
                        )?;
                        if callback == 0 {
                            break;
                        }

                        let callback_fn: extern "system" fn(*mut u8, u32, *mut u8) =
                            unsafe { mem::transmute(callback as usize) };
                        callback_fn(
                            image_base as *mut u8,
                            DLL_PROCESS_ATTACH,
                            ptr::null_mut(),
                        );
                        callbacks_rva += mem::size_of::<u32>();
                    }
                }
            }
        },
    )
}

// This function will get or load all imported images of the specified PE file. It will not fix the imports itself.
pub fn load_all_import_images(image_base: *const c_void) -> Result<()> {
    let nt_headers = ParsedNtHeaders::parse(image_base)?;
    let Some(import_descriptors) = nt_headers.import_descriptors()? else {
        return Ok(());
    };

    for import_descriptor in &import_descriptors {
        if ParsedNtHeaders::is_null_import_descriptor(import_descriptor) {
            break;
        }

        if import_descriptor.Name == 0 {
            anyhow::bail!("import descriptor has no DLL name RVA");
        }

        let dll_name = nt_headers.c_string(import_descriptor.Name)?;
        let module = unsafe { LoadLibraryA(dll_name.as_ptr() as *const u8) };
        if module.is_null() {
            return bail_with_last_error(format!(
                "LoadLibraryA failed for {}",
                dll_name.to_string_lossy()
            ));
        }
    }

    Ok(())
}

pub fn custom_get_proc_address(image_base: *const c_void, symbol_name: &str) -> Result<u64> {
    let nt_headers = ParsedNtHeaders::parse(image_base)?;
    let export_directory_entry = nt_headers
        .export_directory()
        .ok_or_else(|| anyhow::anyhow!("PE image has no export directory"))?;
    if export_directory_entry.VirtualAddress == 0 || export_directory_entry.Size == 0 {
        anyhow::bail!("PE image has no export directory");
    }

    let export_directory: IMAGE_EXPORT_DIRECTORY =
        nt_headers.read::<IMAGE_EXPORT_DIRECTORY>(export_directory_entry.VirtualAddress)?;
    let name_count = export_directory.NumberOfNames as usize;
    let function_count = export_directory.NumberOfFunctions as usize;
    let name_rvas = nt_headers.u32s(export_directory.AddressOfNames, name_count)?;
    let name_ordinals = nt_headers.u16s(export_directory.AddressOfNameOrdinals, name_count)?;
    let function_rvas = nt_headers.u32s(export_directory.AddressOfFunctions, function_count)?;

    let ordinal_index = name_rvas
        .iter()
        .zip(name_ordinals.iter())
        .find_map(|(name_rva, ordinal)| {
            let export_name = nt_headers.c_string(*name_rva).ok()?;
            (export_name.to_bytes() == symbol_name.as_bytes()).then_some(*ordinal as usize)
        })
        .ok_or_else(|| anyhow::anyhow!("export not found: {symbol_name}"))?;
    if ordinal_index >= function_rvas.len() {
        anyhow::bail!(
            "export ordinal index {} is outside the address table for {symbol_name}",
            ordinal_index
        );
    }

    let export_rva = function_rvas[ordinal_index];
    if export_rva == 0 {
        anyhow::bail!("export {symbol_name} resolved to a null RVA");
    }

    if nt_headers.directory_contains_rva(export_directory_entry, export_rva) {
        let forwarded_export = nt_headers.c_string(export_rva)?;
        let forwarded_export = forwarded_export
            .to_str()
            .map_err(|e| anyhow::anyhow!("invalid forwarded export for {symbol_name}: {e}"))?;
        let (library_name, forwarded_symbol) =
            forwarded_export.rsplit_once('.').ok_or_else(|| {
                anyhow::anyhow!("invalid forwarded export for {symbol_name}: {forwarded_export:?}")
            })?;

        let library_name = if library_name.to_ascii_lowercase().ends_with(".dll") {
            library_name.to_string()
        } else {
            format!("{library_name}.dll")
        };

        let dll_name = CString::new(library_name.as_str()).map_err(|e| {
            anyhow::anyhow!("invalid forwarded export DLL name {library_name:?}: {e}")
        })?;
        let module = unsafe { LoadLibraryA(dll_name.as_ptr() as *const u8) };
        if module.is_null() {
            return bail_with_last_error(format!(
                "LoadLibraryA failed for forwarded export {} -> {}!{}",
                symbol_name, library_name, forwarded_symbol
            ));
        }

        let proc_address = if let Some(ordinal) = forwarded_symbol.strip_prefix('#') {
            let ordinal = ordinal.parse::<u16>().map_err(|e| {
                anyhow::anyhow!(
                    "invalid forwarded export ordinal {} -> {}!{}: {e}",
                    symbol_name,
                    library_name,
                    forwarded_symbol
                )
            })?;

            unsafe { GetProcAddress(module, ordinal as usize as *const u8) }
        } else {
            let forwarded_name = CString::new(forwarded_symbol).map_err(|e| {
                anyhow::anyhow!(
                    "invalid forwarded export name {} -> {}!{}: {e}",
                    symbol_name,
                    library_name,
                    forwarded_symbol
                )
            })?;

            unsafe { GetProcAddress(module, forwarded_name.as_ptr() as *const u8) }
        };

        let proc_address = if let Some(proc_address) = proc_address {
            proc_address
        } else {
            return bail_with_last_error(format!(
                "GetProcAddress failed for forwarded export {} -> {}!{}",
                symbol_name, library_name, forwarded_symbol
            ));
        };

        return Ok(proc_address as usize as u64);
    }

    nt_headers.va(export_rva)
}

pub fn fix_import_table(image_base: *const c_void) -> Result<()> {
    let nt_headers = ParsedNtHeaders::parse(image_base)?;
    let Some(import_descriptors) = nt_headers.import_descriptors()? else {
        return Ok(());
    };

    for import_descriptor in &import_descriptors {
        if ParsedNtHeaders::is_null_import_descriptor(import_descriptor) {
            break;
        }

        if import_descriptor.Name == 0 {
            anyhow::bail!("import descriptor has no DLL name RVA");
        }

        let dll_name = nt_headers.c_string(import_descriptor.Name)?;
        if import_descriptor.FirstThunk == 0 {
            anyhow::bail!(
                "import descriptor for {} has no IAT RVA",
                dll_name.to_string_lossy()
            );
        }

        let module = unsafe { LoadLibraryA(dll_name.as_ptr() as *const u8) };
        if module.is_null() {
            return bail_with_last_error(format!(
                "LoadLibraryA failed for {}",
                dll_name.to_string_lossy()
            ));
        }

        let original_first_thunk = unsafe { import_descriptor.Anonymous.OriginalFirstThunk };
        let mut lookup_rva = if original_first_thunk != 0 {
            original_first_thunk
        } else {
            import_descriptor.FirstThunk
        };
        let mut iat_rva = import_descriptor.FirstThunk;
        let entry_size = u32::try_from(nt_headers.thunk_entry_size())
            .map_err(|_| anyhow::anyhow!("import thunk entry size overflowed"))?;

        loop {
            let lookup_entry = nt_headers.read_import_lookup_entry(lookup_rva)?;
            if lookup_entry == 0 {
                break;
            }

            let (proc_address, symbol) = if nt_headers.is_ordinal_import(lookup_entry) {
                let ordinal = nt_headers.import_ordinal(lookup_entry);
                (
                    unsafe { GetProcAddress(module, ordinal as usize as *const u8) },
                    format!("#{ordinal}"),
                )
            } else {
                let symbol_name = nt_headers.import_name(lookup_entry)?;
                (
                    unsafe { GetProcAddress(module, symbol_name.as_ptr() as *const u8) },
                    symbol_name.to_string_lossy().into_owned(),
                )
            };

            let proc_address = if let Some(proc_address) = proc_address {
                proc_address
            } else {
                return bail_with_last_error(format!(
                    "GetProcAddress failed for {}!{}",
                    dll_name.to_string_lossy(),
                    symbol
                ));
            };

            nt_headers.write_import_address(iat_rva, proc_address as usize)?;
            lookup_rva = lookup_rva
                .checked_add(entry_size)
                .ok_or_else(|| anyhow::anyhow!("import lookup table RVA overflowed"))?;
            iat_rva = iat_rva
                .checked_add(entry_size)
                .ok_or_else(|| anyhow::anyhow!("import address table RVA overflowed"))?;
        }
    }

    Ok(())
}
