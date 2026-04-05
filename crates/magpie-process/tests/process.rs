#![cfg(all(windows, target_arch = "x86_64"))]

use std::{
    ops::Range,
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

use anyhow::{Context, Result, anyhow, bail};
use magpie_process::{MemoryInfo, MemorySection, ModuleInfo, Process, ProcessBuilder, SectionTable};
use windows_sys::Win32::System::Memory::{
    PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY, PAGE_GUARD, PAGE_NOCACHE,
    PAGE_READONLY, PAGE_READWRITE, PAGE_TARGETS_INVALID, PAGE_WRITECOMBINE, SECTION_MAP_EXECUTE,
    SECTION_MAP_READ, SECTION_MAP_WRITE,
};

fn notepad_path() -> PathBuf {
    let windir = std::env::var_os("WINDIR").unwrap_or_else(|| "C:\\Windows".into());
    PathBuf::from(windir).join("System32").join("notepad.exe")
}

fn find_main_module<'a>(process: &Process, modules: &'a [ModuleInfo]) -> Result<&'a ModuleInfo> {
    let process_name = notepad_path()
        .file_name()
        .ok_or_else(|| anyhow!("notepad path has no file name"))?
        .to_string_lossy()
        .to_ascii_lowercase();

    modules
        .iter()
        .find(|module| {
            module
                .path
                .file_name()
                .map(|name| name.to_string_lossy().eq_ignore_ascii_case(&process_name))
                .unwrap_or(false)
        })
        .ok_or_else(|| anyhow!("failed to locate main module for pid {}", process.id()))
}

fn wait_for_modules(process: &Process, timeout: Duration) -> Result<Vec<ModuleInfo>> {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        let modules = process.modules()?;
        if !modules.is_empty() {
            return Ok(modules);
        }
        std::thread::sleep(Duration::from_millis(50));
    }

    bail!("timed out waiting for modules to load")
}

fn section_name(section: &SectionTable) -> Result<&str> {
    let end = section
        .Name
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(section.Name.len());
    std::str::from_utf8(&section.Name[..end]).context("section name was not valid utf-8")
}

fn region_contains(range: &Range<u64>, address: u64) -> bool {
    range.contains(&address)
}

fn base_protection(protection: u32) -> u32 {
    protection & !(PAGE_GUARD | PAGE_NOCACHE | PAGE_WRITECOMBINE | PAGE_TARGETS_INVALID)
}

fn memory_info_for_address(process: &Process, address: u64) -> Result<MemoryInfo> {
    process
        .memory()?
        .iter()
        .find(|(range, _)| region_contains(range, address))
        .map(|(_, info)| *info)
        .ok_or_else(|| anyhow!("failed to locate memory information for address {address:#x}"))
}

fn unique_section_name() -> String {
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    format!(
        "magpie-process-test-section-{}-{timestamp}",
        std::process::id()
    )
}

struct RemoteThreadState {
    started: AtomicBool,
    release: AtomicBool,
}

unsafe extern "system" fn test_remote_thread_main(parameter: *mut core::ffi::c_void) -> u32 {
    let state = unsafe { Arc::from_raw(parameter as *const RemoteThreadState) };
    state.started.store(true, Ordering::SeqCst);

    while !state.release.load(Ordering::SeqCst) {
        std::thread::yield_now();
    }

    0
}

#[test]
fn open_process_without_debugger_supports_generic_inspection() -> Result<()> {
    let notepad = notepad_path();
    if !notepad.exists() {
        bail!("notepad not found at {}", notepad.display());
    }

    let launched = ProcessBuilder::new(notepad)
        .start()
        .context("failed to launch notepad without debugger flags")?;
    let opened = Process::open(launched.id()).context("failed to reopen process by pid")?;

    let test_result = (|| -> Result<()> {
        if !opened.is_alive().context("failed to query liveness")? {
            bail!("opened process was not alive");
        }

        let threads = opened.threads().context("failed to enumerate threads")?;
        if threads.is_empty() {
            bail!("expected at least one thread");
        }

        let modules = wait_for_modules(&opened, Duration::from_secs(5))
            .context("failed to enumerate modules")?;
        let main_module = find_main_module(&opened, &modules)?;
        let analysed = main_module
            .analyse(&opened)
            .context("failed to analyse the main module")?;
        let sections = analysed
            .sections()
            .context("failed to enumerate parsed PE sections")?;
        let text_section = sections
            .iter()
            .find(|section| {
                section_name(section)
                    .map(|name| name == ".text")
                    .unwrap_or(false)
            })
            .ok_or_else(|| {
                anyhow!(
                    "failed to locate .text section in {}",
                    main_module.path.display()
                )
            })?;

        let memory = opened.memory().context("failed to enumerate memory")?;
        if memory.iter().next().is_none() {
            bail!("expected at least one memory region");
        }

        let text_section_va = main_module
            .base_address
            .checked_add(u64::from(text_section.VirtualAddress))
            .ok_or_else(|| anyhow!("overflow while computing .text section VA"))?;

        let text_region = memory
            .iter()
            .find(|(range, _)| region_contains(range, text_section_va))
            .ok_or_else(|| {
                anyhow!(
                    "failed to locate the memory region containing .text at {text_section_va:#x}"
                )
            })?;

        if !text_region.1.is_committed() {
            bail!(
                ".text section lives in an uncommitted region: state={:#x} base={:#x} size={:#x}",
                text_region.1.state,
                text_region.0.start,
                text_region.0.end - text_region.0.start
            );
        }

        let effective_protection = base_protection(text_region.1.protection);
        if effective_protection != PAGE_EXECUTE_READ {
            bail!(
                ".text section had unexpected protection: raw={:#x} effective={:#x} expected={:#x}",
                text_region.1.protection,
                effective_protection,
                PAGE_EXECUTE_READ
            );
        }

        Ok(())
    })();

    let _ = opened.terminate(0xDEAD);

    test_result
}

#[test]
fn open_current_process_can_create_remote_thread() -> Result<()> {
    let process = Process::open(std::process::id()).context("failed to open current process")?;
    let existing_thread_ids: std::collections::BTreeSet<u32> = process
        .threads()
        .context("failed to enumerate current-process threads before remote thread creation")?
        .into_iter()
        .map(|thread| thread.id())
        .collect();

    let state = Arc::new(RemoteThreadState {
        started: AtomicBool::new(false),
        release: AtomicBool::new(false),
    });
    let parameter = Arc::into_raw(state.clone()) as usize as u64;
    let release_state = state.clone();

    let thread = process
        .create_remote_thread(test_remote_thread_main as usize as u64, parameter)
        .context("failed to create remote thread in current process")?;

    let remote_thread_id =
        unsafe { windows_sys::Win32::System::Threading::GetThreadId(thread.raw()) };

    let test_result = (|| -> Result<()> {
        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline {
            if state.started.load(Ordering::SeqCst) {
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }

        if !state.started.load(Ordering::SeqCst) {
            bail!("remote thread never signalled startup");
        }

        let observed_thread_ids: std::collections::BTreeSet<u32> = process
            .threads()
            .context("failed to enumerate current-process threads after remote thread creation")?
            .into_iter()
            .map(|thread| thread.id())
            .collect();

        if !observed_thread_ids.contains(&remote_thread_id) {
            bail!(
                "new remote thread {} was not visible in thread enumeration",
                remote_thread_id
            );
        }

        if existing_thread_ids.contains(&remote_thread_id) {
            bail!(
                "new remote thread id {} was already present",
                remote_thread_id
            );
        }

        Ok(())
    })();

    release_state.release.store(true, Ordering::SeqCst);

    test_result
}

#[test]
fn section_mapping_is_visible_across_processes() -> Result<()> {
    let notepad = notepad_path();
    if !notepad.exists() {
        bail!("notepad not found at {}", notepad.display());
    }

    let launched = ProcessBuilder::new(notepad)
        .start()
        .context("failed to launch notepad for section mapping test")?;
    let current_process =
        Process::open(std::process::id()).context("failed to open current process")?;
    let remote_process =
        Process::open(launched.id()).context("failed to open launched notepad process")?;

    let test_result = (|| -> Result<()> {
        let section_name = unique_section_name();
        let payload = b"shared section bytes";
        let section = MemorySection::create_section(
            &section_name,
            SECTION_MAP_READ | SECTION_MAP_WRITE,
            0x1000,
            PAGE_READWRITE,
        )
        .context("failed to create section")?;

        let opened = MemorySection::open_section(&section_name, SECTION_MAP_READ)
            .context("failed to reopen section by name")?;

        if section.memory_info().protection != PAGE_READWRITE {
            bail!(
                "created section reported unexpected protection {:#x}",
                section.memory_info().protection
            );
        }

        if opened.memory_info().protection != PAGE_READONLY {
            bail!(
                "opened section reported unexpected protection {:#x}",
                opened.memory_info().protection
            );
        }

        let mut local_address = core::ptr::null();
        local_address = section
            .map_section(&current_process, local_address)
            .context("failed to map section into current process")?;

        unsafe {
            let local_slice = std::slice::from_raw_parts_mut(
                local_address.cast::<u8>() as *mut u8,
                payload.len(),
            );
            local_slice.copy_from_slice(payload);
        }

        let remote_address = remote_process
            .map_section(&opened, core::ptr::null())
            .context("failed to map reopened section into notepad")?;
        let observed = remote_process
            .read_memory_at(remote_address as usize as u64, payload.len())
            .context("failed to read mapped bytes from notepad")?;

        if observed != payload {
            bail!(
                "remote mapped bytes did not match: expected {:x?}, got {:x?}",
                payload,
                observed
            );
        }

        Ok(())
    })();

    let _ = remote_process.terminate(0xBEEF);

    test_result
}

#[test]
fn section_can_be_unmapped_and_remapped_at_same_address_with_writecopy() -> Result<()> {
    let current_process =
        Process::open(std::process::id()).context("failed to open current process")?;

    let section_name = unique_section_name();
    let original_signature = b"rwx-signature";
    let ephemeral_signature = b"cow-signature";
    let section = MemorySection::create_section(
        &section_name,
        SECTION_MAP_EXECUTE | SECTION_MAP_READ | SECTION_MAP_WRITE,
        0x1000,
        PAGE_EXECUTE_READWRITE,
    )
    .context("failed to create executable section")?;

    let initial_mapping = section
        .map_section(&current_process, core::ptr::null())
        .context("failed to map section into the current process")?;

    if initial_mapping.is_null() {
        bail!("initial section mapping returned a null base address");
    }

    let initial_info = memory_info_for_address(&current_process, initial_mapping as usize as u64)
        .context("failed to inspect the initial section mapping")?;
    if base_protection(initial_info.protection) != PAGE_EXECUTE_READWRITE {
        bail!(
            "initial mapping had unexpected protection: raw={:#x} effective={:#x} expected={:#x}",
            initial_info.protection,
            base_protection(initial_info.protection),
            PAGE_EXECUTE_READWRITE
        );
    }

    unsafe {
        let mapped_slice = std::slice::from_raw_parts_mut(
            initial_mapping.cast::<u8>() as *mut u8,
            original_signature.len(),
        );
        mapped_slice.copy_from_slice(original_signature);
    }

    let observed_original = current_process
        .read_memory_at(initial_mapping as usize as u64, original_signature.len())
        .context("failed to read the original signature from the initial mapping")?;
    if observed_original != original_signature {
        bail!(
            "initial mapping did not retain the original signature: expected {:x?}, got {:x?}",
            original_signature,
            observed_original
        );
    }

    section
        .unmap_section(&current_process, initial_mapping)
        .context("failed to unmap the initial executable section view")?;

    let writecopy_mapping = section
        .map_section_with_protection(&current_process, initial_mapping, PAGE_EXECUTE_WRITECOPY)
        .context("failed to remap the section with PAGE_EXECUTE_WRITECOPY")?;

    if writecopy_mapping != initial_mapping {
        bail!(
            "writecopy remap used a different base address: expected {:p}, got {:p}",
            initial_mapping,
            writecopy_mapping
        );
    }

    let writecopy_info =
        memory_info_for_address(&current_process, writecopy_mapping as usize as u64)
            .context("failed to inspect the writecopy section mapping")?;
    if base_protection(writecopy_info.protection) != PAGE_EXECUTE_WRITECOPY {
        bail!(
            "writecopy remap had unexpected protection: raw={:#x} effective={:#x} expected={:#x}",
            writecopy_info.protection,
            base_protection(writecopy_info.protection),
            PAGE_EXECUTE_WRITECOPY
        );
    }

    let observed_after_writecopy_remap = current_process
        .read_memory_at(writecopy_mapping as usize as u64, original_signature.len())
        .context("failed to verify the original signature after the writecopy remap")?;
    if observed_after_writecopy_remap != original_signature {
        bail!(
            "writecopy remap did not preserve the original signature: expected {:x?}, got {:x?}",
            original_signature,
            observed_after_writecopy_remap
        );
    }

    unsafe {
        let mapped_slice = std::slice::from_raw_parts_mut(
            writecopy_mapping.cast::<u8>() as *mut u8,
            ephemeral_signature.len(),
        );
        mapped_slice.copy_from_slice(ephemeral_signature);
    }

    let observed_ephemeral = current_process
        .read_memory_at(writecopy_mapping as usize as u64, ephemeral_signature.len())
        .context("failed to read the ephemeral writecopy signature")?;
    if observed_ephemeral != ephemeral_signature {
        bail!(
            "writecopy mapping did not expose the ephemeral signature: expected {:x?}, got {:x?}",
            ephemeral_signature,
            observed_ephemeral
        );
    }

    section
        .unmap_section(&current_process, writecopy_mapping)
        .context("failed to unmap the writecopy section view")?;

    let final_mapping = section
        .map_section(&current_process, initial_mapping)
        .context("failed to remap the section back with PAGE_EXECUTE_READWRITE")?;

    if final_mapping != initial_mapping {
        bail!(
            "final remap used a different base address: expected {:p}, got {:p}",
            initial_mapping,
            final_mapping
        );
    }

    let final_info = memory_info_for_address(&current_process, final_mapping as usize as u64)
        .context("failed to inspect the final section mapping")?;
    if base_protection(final_info.protection) != PAGE_EXECUTE_READWRITE {
        bail!(
            "final remap had unexpected protection: raw={:#x} effective={:#x} expected={:#x}",
            final_info.protection,
            base_protection(final_info.protection),
            PAGE_EXECUTE_READWRITE
        );
    }

    let observed_final = current_process
        .read_memory_at(final_mapping as usize as u64, original_signature.len())
        .context("failed to read the final remapped signature")?;
    if observed_final != original_signature {
        bail!(
            "final remap did not restore the original signature: expected {:x?}, got {:x?}",
            original_signature,
            observed_final
        );
    }

    if observed_final == ephemeral_signature {
        bail!(
            "final remap unexpectedly retained the ephemeral signature {:x?}",
            ephemeral_signature
        );
    }

    section
        .unmap_section(&current_process, final_mapping)
        .context("failed to unmap the final executable section view")?;

    Ok(())
}
