// Copyright (c) 2026 Fractal Frame <https://fractalframe.eu>
// Part of the win-proxychains project. Licensed under FSL-1.1-MIT; see LICENCE.md.

use std::{
    cmp::Ordering,
    collections::{BTreeMap, HashMap},
    ffi::{OsString, c_void},
    mem,
    ops::Range,
    os::windows::ffi::OsStrExt,
    path::PathBuf,
};

use anyhow::Result;
use windows_sys::{
    Wdk::{
        Foundation::OBJECT_ATTRIBUTES,
        System::{
            Memory::{ViewUnmap, ZwMapViewOfSection, ZwOpenSection, ZwUnmapViewOfSection},
            SystemServices::ZwCreateSection,
            Threading::{NtQueryInformationProcess, ProcessBasicInformation},
        },
    },
    Win32::{
        Foundation::{
            CloseHandle, GetLastError, HANDLE, INVALID_HANDLE_VALUE, NTSTATUS,
            OBJ_CASE_INSENSITIVE, STILL_ACTIVE, UNICODE_STRING,
        },
        System::{
            Diagnostics::{
                Debug::{
                    CONTEXT, GetThreadContext, ReadProcessMemory, SetThreadContext,
                    WriteProcessMemory,
                },
                ToolHelp::{
                    CreateToolhelp32Snapshot, MODULEENTRY32W, Module32FirstW, Module32NextW,
                    TH32CS_SNAPMODULE, TH32CS_SNAPTHREAD, THREADENTRY32, Thread32First,
                    Thread32Next,
                },
            },
            Memory::{
                MEM_COMMIT, MEM_FREE, MEM_RESERVE, MEMORY_BASIC_INFORMATION, PAGE_EXECUTE_READ,
                PAGE_EXECUTE_READWRITE, PAGE_READONLY, PAGE_READWRITE, SEC_COMMIT,
                SECTION_MAP_EXECUTE, SECTION_MAP_READ, SECTION_MAP_WRITE, VirtualQueryEx,
            },
            RemoteDesktop::ProcessIdToSessionId,
            SystemInformation::{GetSystemInfo, SYSTEM_INFO},
            Threading::{
                CreateProcessW, CreateRemoteThread, GetExitCodeProcess, OpenProcess, OpenThread,
                PROCESS_BASIC_INFORMATION, PROCESS_CREATE_THREAD, PROCESS_INFORMATION,
                PROCESS_QUERY_INFORMATION, PROCESS_TERMINATE, PROCESS_VM_OPERATION,
                PROCESS_VM_READ, PROCESS_VM_WRITE, ResumeThread, STARTUPINFOW, SuspendThread,
                THREAD_GET_CONTEXT, THREAD_SET_CONTEXT, THREAD_SUSPEND_RESUME, TerminateProcess,
            },
        },
    },
    core::{BOOL, PCWSTR, PWSTR},
};

use crate::{
    pe_file::{ParsedPeFile, SectionTable},
    scoped_handle::ScopedHandle,
};

#[cfg(target_arch = "x86_64")]
use windows_sys::Win32::System::Diagnostics::Debug::CONTEXT_ALL_AMD64;
#[cfg(target_arch = "aarch64")]
use windows_sys::Win32::System::Diagnostics::Debug::CONTEXT_ALL_ARM64;
#[cfg(target_arch = "x86")]
use windows_sys::Win32::System::Diagnostics::Debug::CONTEXT_ALL_X86;

fn bail_with_last_error<T>(message: &str) -> Result<T> {
    let error_code = unsafe { GetLastError() };
    Err(anyhow::anyhow!(
        "{}: Windows API error {}",
        message,
        error_code
    ))
}

fn bail_with_ntstatus<T>(message: &str, status: NTSTATUS) -> Result<T> {
    Err(anyhow::anyhow!(
        "{}: NTSTATUS 0x{:08X}",
        message,
        status as u32
    ))
}

fn nt_success(status: NTSTATUS) -> bool {
    status >= 0
}

#[cfg(target_arch = "aarch64")]
const FULL_THREAD_CONTEXT_FLAGS: u32 = CONTEXT_ALL_ARM64;
#[cfg(target_arch = "x86_64")]
const FULL_THREAD_CONTEXT_FLAGS: u32 = CONTEXT_ALL_AMD64;
#[cfg(target_arch = "x86")]
const FULL_THREAD_CONTEXT_FLAGS: u32 = CONTEXT_ALL_X86;

#[repr(C, align(16))]
struct AlignedContext(CONTEXT);

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct PebHeader {
    reserved: [u8; 4],
    mutant: *mut c_void,
    image_base_address: *mut c_void,
}

const DOS_HEADER_LEN: usize = 64;
const DOS_MAGIC: [u8; 2] = *b"MZ";
const PE_SIGNATURE: [u8; 4] = *b"PE\0\0";
const NT_SIGNATURE_LEN: usize = 4;
const COFF_HEADER_LEN: usize = 20;
const COFF_SIZE_OF_OPTIONAL_HEADER_OFFSET: usize = 16;
const OPTIONAL_HEADER_MAGIC_OFFSET: usize = 0;
const OPTIONAL_HEADER_SIZE_OF_IMAGE_OFFSET: usize = 56;
const MIN_OPTIONAL_HEADER_FOR_SIZE_OF_IMAGE: usize = OPTIONAL_HEADER_SIZE_OF_IMAGE_OFFSET + 4;
const OPTIONAL_HEADER_MAGIC_PE32: u16 = 0x10B;
const OPTIONAL_HEADER_MAGIC_PE32_PLUS: u16 = 0x20B;
const MAX_REMOTE_HEADER_PROBE: usize = 16 * 1024 * 1024;
const BASE_NAMED_OBJECTS_PREFIX: &str = "\\BaseNamedObjects\\";
const SESSION_BASE_NAMED_OBJECTS_PREFIX: &str = "\\Sessions\\";

#[derive(Debug, Clone)]
pub struct MemorySection {
    name: String,
    access_mask: u32,
    size: Option<usize>,
    page_protection: u32,
    memory_info: MemoryInfo,
    section_handle: ScopedHandle,
}

pub type Section = MemorySection;

impl MemorySection {
    pub fn create_section(
        name: &str,
        access_mask: u32,
        size: usize,
        page_protection: u32,
    ) -> Result<Self> {
        if size == 0 {
            return Err(anyhow::anyhow!("section size must be greater than zero"));
        }

        let maximum_size = i64::try_from(size)
            .map_err(|_| anyhow::anyhow!("section size {size} does not fit in i64"))?;
        let object_name = OwnedUnicodeString::new(&normalize_section_name(name)?)?;
        let object_attributes = build_object_attributes(object_name.as_unicode_string());

        let mut handle = HANDLE::default();
        let status = unsafe {
            ZwCreateSection(
                &mut handle,
                access_mask,
                &object_attributes,
                &maximum_size,
                page_protection,
                SEC_COMMIT,
                core::ptr::null_mut(),
            )
        };
        if !nt_success(status) {
            return bail_with_ntstatus(
                &format!("ZwCreateSection failed for {}", object_name.as_str()),
                status,
            );
        }

        Ok(Self {
            name: object_name.into_string(),
            access_mask,
            size: Some(size),
            page_protection,
            memory_info: MemoryInfo {
                protection: page_protection,
                state: MEM_COMMIT,
            },
            section_handle: ScopedHandle::new(handle),
        })
    }

    pub fn open_section(name: &str, access_mask: u32) -> Result<Self> {
        let object_name = OwnedUnicodeString::new(&normalize_section_name(name)?)?;
        let object_attributes = build_object_attributes(object_name.as_unicode_string());

        let mut handle = HANDLE::default();
        let status = unsafe { ZwOpenSection(&mut handle, access_mask, &object_attributes) };
        if !nt_success(status) {
            return bail_with_ntstatus(
                &format!("ZwOpenSection failed for {}", object_name.as_str()),
                status,
            );
        }

        let page_protection = section_view_protection(access_mask);
        Ok(Self {
            name: object_name.into_string(),
            access_mask,
            size: None,
            page_protection,
            memory_info: MemoryInfo {
                protection: page_protection,
                state: MEM_COMMIT,
            },
            section_handle: ScopedHandle::new(handle),
        })
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn access_mask(&self) -> u32 {
        self.access_mask
    }

    pub fn size(&self) -> Option<usize> {
        self.size
    }

    pub fn memory_info(&self) -> MemoryInfo {
        self.memory_info
    }

    pub fn raw_handle(&self) -> HANDLE {
        self.section_handle.raw()
    }

    pub fn map_section(
        &self,
        target_process: &Process,
        address: *const core::ffi::c_void,
    ) -> Result<*const core::ffi::c_void> {
        self.map_section_with_protection(target_process, address, self.page_protection)
    }

    pub fn map_section_with_protection(
        &self,
        target_process: &Process,
        address: *const core::ffi::c_void,
        protection: u32,
    ) -> Result<*const core::ffi::c_void> {
        let mut base_address = address as *mut core::ffi::c_void;
        let mut view_size = 0usize;
        let status = unsafe {
            ZwMapViewOfSection(
                self.section_handle.raw(),
                target_process.raw_handle(),
                &mut base_address,
                0,
                0,
                core::ptr::null_mut(),
                &mut view_size,
                ViewUnmap,
                0,
                protection,
            )
        };
        if !nt_success(status) {
            return bail_with_ntstatus(
                &format!(
                    "ZwMapViewOfSection failed for section {} into pid {} with protection {:#x}",
                    self.name,
                    target_process.id(),
                    protection
                ),
                status,
            );
        }

        Ok(base_address as *const core::ffi::c_void)
    }

    pub fn unmap_section(
        &self,
        target_process: &Process,
        address: *const core::ffi::c_void,
    ) -> Result<()> {
        let status = unsafe { ZwUnmapViewOfSection(target_process.raw_handle(), address) };
        if !nt_success(status) {
            return bail_with_ntstatus(
                &format!(
                    "ZwUnmapViewOfSection failed for section {} from pid {}",
                    self.name,
                    target_process.id(),
                ),
                status,
            );
        }
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct ProcessBuilder {
    program: PathBuf,
    arguments: Vec<OsString>,
    environment: Option<HashMap<OsString, OsString>>,
    working_directory: Option<PathBuf>,
    creation_flags: u32,
}

impl ProcessBuilder {
    pub fn new(program: PathBuf) -> Self {
        Self {
            program,
            arguments: Vec::new(),
            environment: None,
            working_directory: None,
            creation_flags: 0,
        }
    }

    pub fn arguments(mut self, args: Vec<OsString>) -> Self {
        self.arguments = args;
        self
    }

    pub fn add_argument(mut self, arg: OsString) -> Self {
        self.arguments.push(arg);
        self
    }

    pub fn environment(mut self, env: HashMap<OsString, OsString>) -> Self {
        self.environment = Some(env);
        self
    }

    pub fn working_directory(mut self, dir: PathBuf) -> Self {
        self.working_directory = Some(dir);
        self
    }

    pub fn flags(mut self, creation_flags: u32) -> Self {
        self.creation_flags = creation_flags;
        self
    }

    pub fn start(&self) -> Result<Process> {
        let command_line = build_command_line(&self.program, &self.arguments);
        let mut command_line_wide: Vec<u16> = command_line.encode_wide().collect();
        command_line_wide.push(0);

        let env_block = self.environment.as_ref().map(build_environment_block);
        let working_dir_wide = self.working_directory.as_ref().map(|path| {
            let mut wide: Vec<u16> = path.as_os_str().encode_wide().collect();
            wide.push(0);
            wide
        });

        let mut startup_info: STARTUPINFOW = unsafe { mem::zeroed() };
        startup_info.cb = mem::size_of::<STARTUPINFOW>() as u32;

        let mut process_info: PROCESS_INFORMATION = unsafe { mem::zeroed() };
        let result = unsafe {
            CreateProcessW(
                core::ptr::null(),
                command_line_wide.as_mut_ptr() as PWSTR,
                core::ptr::null(),
                core::ptr::null(),
                BOOL::from(false),
                self.creation_flags,
                env_block
                    .as_ref()
                    .map(|block| block.as_ptr() as *const _)
                    .unwrap_or(core::ptr::null()),
                working_dir_wide
                    .as_ref()
                    .map(|wide| wide.as_ptr() as PCWSTR)
                    .unwrap_or(core::ptr::null()),
                &startup_info,
                &mut process_info,
            )
        };
        if result == 0 {
            bail_with_last_error("Failed to create process")?;
        }

        if !process_info.hThread.is_null() {
            unsafe {
                CloseHandle(process_info.hThread);
            }
        }

        Ok(Process::from_handle(
            process_info.dwProcessId,
            ScopedHandle::new(process_info.hProcess),
        ))
    }
}

#[derive(Debug, Clone)]
pub struct Process {
    process_id: u32,
    process_handle: ScopedHandle,
}

impl Process {
    pub fn open(process_id: u32) -> Result<Self> {
        let handle = unsafe {
            OpenProcess(
                PROCESS_CREATE_THREAD
                    | PROCESS_QUERY_INFORMATION
                    | PROCESS_TERMINATE
                    | PROCESS_VM_OPERATION
                    | PROCESS_VM_READ
                    | PROCESS_VM_WRITE,
                BOOL::from(false),
                process_id,
            )
        };
        if handle.is_null() {
            return bail_with_last_error(&format!("Failed to open process {}", process_id));
        }

        Ok(Self::from_handle(process_id, ScopedHandle::new(handle)))
    }

    pub fn from_handle(process_id: u32, handle: ScopedHandle) -> Self {
        Self {
            process_id,
            process_handle: handle,
        }
    }

    pub fn id(&self) -> u32 {
        self.process_id
    }

    pub fn raw_handle(&self) -> HANDLE {
        self.process_handle.raw()
    }

    pub fn is_alive(&self) -> Result<bool> {
        let mut exit_code = 0u32;
        let result = unsafe { GetExitCodeProcess(self.process_handle.raw(), &mut exit_code) };
        if result == 0 {
            return bail_with_last_error("GetExitCodeProcess failed");
        }

        Ok(exit_code == STILL_ACTIVE as u32)
    }

    pub fn terminate(&self, exit_code: u32) -> Result<()> {
        let result = unsafe { TerminateProcess(self.process_handle.raw(), exit_code) };
        if result == 0 {
            return bail_with_last_error(&format!(
                "TerminateProcess failed for pid {}",
                self.process_id
            ));
        }

        Ok(())
    }

    pub fn create_remote_thread(&self, start_address: u64, parameter: u64) -> Result<ScopedHandle> {
        self.create_remote_thread_with_options(start_address, parameter, 0, 0)
    }

    pub fn create_remote_thread_with_options(
        &self,
        start_address: u64,
        parameter: u64,
        stack_size: usize,
        creation_flags: u32,
    ) -> Result<ScopedHandle> {
        let mut thread_id = 0u32;
        let thread_handle = unsafe {
            CreateRemoteThread(
                self.process_handle.raw(),
                core::ptr::null(),
                stack_size,
                Some(std::mem::transmute::<
                    usize,
                    unsafe extern "system" fn(*mut core::ffi::c_void) -> u32,
                >(start_address as usize)),
                parameter as *const core::ffi::c_void,
                creation_flags,
                &mut thread_id,
            )
        };
        if thread_handle.is_null() {
            return bail_with_last_error(&format!(
                "CreateRemoteThread failed for pid {} at {start_address:#x}",
                self.process_id
            ));
        }

        Ok(ScopedHandle::new(thread_handle))
    }

    pub fn threads(&self) -> Result<Vec<Thread>> {
        let mut threads = Vec::new();
        let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, self.process_id) };
        if snapshot == INVALID_HANDLE_VALUE {
            return bail_with_last_error("CreateToolhelp32Snapshot failed");
        }

        let mut entry: THREADENTRY32 = unsafe { mem::zeroed() };
        entry.dwSize = mem::size_of::<THREADENTRY32>() as u32;
        let mut success = unsafe { Thread32First(snapshot, &mut entry) };
        while success != 0 {
            if entry.th32OwnerProcessID == self.process_id {
                threads.push(Thread::from_id(entry.th32ThreadID));
            }
            success = unsafe { Thread32Next(snapshot, &mut entry) };
        }

        unsafe {
            CloseHandle(snapshot);
        }
        Ok(threads)
    }

    pub fn suspend(&self) -> Result<()> {
        for thread in self.threads()? {
            thread.suspend()?;
        }
        Ok(())
    }

    pub fn resume(&self) -> Result<()> {
        for thread in self.threads()? {
            thread.resume()?;
        }
        Ok(())
    }

    pub fn main_module_base(&self) -> Result<u64> {
        let mut process_info = PROCESS_BASIC_INFORMATION::default();
        let mut return_length = 0u32;
        let status = unsafe {
            NtQueryInformationProcess(
                self.process_handle.raw(),
                ProcessBasicInformation,
                &mut process_info as *mut _ as *mut c_void,
                mem::size_of::<PROCESS_BASIC_INFORMATION>() as u32,
                &mut return_length,
            )
        };
        if !nt_success(status) {
            return bail_with_ntstatus(
                &format!(
                    "NtQueryInformationProcess(ProcessBasicInformation) failed for pid {}",
                    self.process_id
                ),
                status,
            );
        }

        if process_info.PebBaseAddress.is_null() {
            return Err(anyhow::anyhow!(
                "NtQueryInformationProcess returned a null PEB address for pid {}",
                self.process_id
            ));
        }

        let peb_bytes = self.read_memory_at(
            process_info.PebBaseAddress as usize as u64,
            mem::size_of::<PebHeader>(),
        )?;
        if peb_bytes.len() != mem::size_of::<PebHeader>() {
            return Err(anyhow::anyhow!(
                "read_memory_at read {} bytes from the PEB for pid {}, expected {}",
                peb_bytes.len(),
                self.process_id,
                mem::size_of::<PebHeader>()
            ));
        }
        let peb = unsafe { core::ptr::read_unaligned(peb_bytes.as_ptr() as *const PebHeader) };

        Ok(peb.image_base_address as u64)
    }

    pub fn modules(&self) -> Result<Vec<ModuleInfo>> {
        let mut modules = Vec::new();
        let snapshot = loop {
            let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, self.process_id) };
            if snapshot != INVALID_HANDLE_VALUE {
                break snapshot;
            }

            let last_error = unsafe { GetLastError() };
            if last_error != 24 {
                return bail_with_last_error("CreateToolhelp32Snapshot failed");
            }
        };

        let mut entry: MODULEENTRY32W = unsafe { mem::zeroed() };
        entry.dwSize = mem::size_of::<MODULEENTRY32W>() as u32;
        let mut success = unsafe { Module32FirstW(snapshot, &mut entry) };
        while success != 0 {
            if entry.th32ProcessID == self.process_id {
                modules.push(ModuleInfo {
                    path: PathBuf::from(
                        String::from_utf16_lossy(&entry.szExePath)
                            .trim_end_matches('\0')
                            .to_string(),
                    ),
                    base_address: entry.modBaseAddr as u64,
                    size: Some(entry.modBaseSize as usize),
                });
            }
            success = unsafe { Module32NextW(snapshot, &mut entry) };
        }

        unsafe {
            CloseHandle(snapshot);
        }
        Ok(modules)
    }

    pub fn memory(&self) -> Result<MemoryMap> {
        let mut regions = MemoryMap::new();
        let mut address;
        let mut buffer: MEMORY_BASIC_INFORMATION = unsafe { mem::zeroed() };
        let mut system_info: SYSTEM_INFO = unsafe { mem::zeroed() };
        unsafe {
            GetSystemInfo(&mut system_info);
        }

        let page_size = system_info.dwPageSize as u64;
        let minimum_application_address = system_info.lpMinimumApplicationAddress as u64;
        let maximum_application_address = system_info.lpMaximumApplicationAddress as u64;
        address = minimum_application_address;

        while address < maximum_application_address {
            let result = unsafe {
                VirtualQueryEx(
                    self.process_handle.raw(),
                    address as *const core::ffi::c_void,
                    &mut buffer,
                    mem::size_of::<MEMORY_BASIC_INFORMATION>(),
                )
            };

            if result == 0 {
                address = address
                    .checked_add(page_size)
                    .unwrap_or(maximum_application_address);
                continue;
            }

            let base_address = buffer.BaseAddress as u64;
            let region_size = buffer.RegionSize as u64;
            let Some(end_address) = base_address.checked_add(region_size) else {
                break;
            };

            regions.insert(
                base_address..end_address,
                MemoryInfo {
                    protection: buffer.Protect,
                    state: buffer.State,
                },
            );

            if let Some(next_address) = address.checked_add(region_size) {
                address = next_address;
            } else {
                break;
            }
        }

        Ok(regions)
    }

    pub fn allocate_memory_at(
        &self,
        address: Option<u64>,
        size: usize,
        protection: u32,
    ) -> Result<u64> {
        let desired_address = address.unwrap_or(0) as *mut core::ffi::c_void;
        let allocated_address = unsafe {
            windows_sys::Win32::System::Memory::VirtualAllocEx(
                self.process_handle.raw(),
                desired_address,
                size,
                MEM_COMMIT | MEM_RESERVE,
                protection,
            )
        };
        if allocated_address.is_null() {
            return bail_with_last_error("VirtualAllocEx failed");
        }

        Ok(allocated_address as u64)
    }

    pub fn read_memory_at(&self, address: u64, length: usize) -> Result<Vec<u8>> {
        let mut data = vec![0u8; length];
        let mut bytes_read = 0usize;
        let result = unsafe {
            ReadProcessMemory(
                self.process_handle.raw(),
                address as *const core::ffi::c_void,
                data.as_mut_ptr() as *mut core::ffi::c_void,
                length,
                &mut bytes_read,
            )
        };
        if result == 0 {
            return bail_with_last_error("ReadProcessMemory failed");
        }

        data.truncate(bytes_read);
        Ok(data)
    }

    pub fn write_memory_at(&self, address: u64, data: &[u8]) -> Result<()> {
        let mut bytes_written = 0usize;
        let result = unsafe {
            WriteProcessMemory(
                self.process_handle.raw(),
                address as *mut core::ffi::c_void,
                data.as_ptr() as *const core::ffi::c_void,
                data.len(),
                &mut bytes_written,
            )
        };
        if result == 0 {
            return bail_with_last_error("WriteProcessMemory failed");
        }

        if bytes_written != data.len() {
            return Err(anyhow::anyhow!(
                "WriteProcessMemory wrote {} bytes, expected {}",
                bytes_written,
                data.len()
            ));
        }

        Ok(())
    }

    pub fn map_section(
        &self,
        section: &Section,
        address: *const c_void,
    ) -> Result<*const core::ffi::c_void> {
        section.map_section(self, address)
    }

    pub fn map_section_with_protection(
        &self,
        section: &Section,
        address: *const c_void,
        protection: u32,
    ) -> Result<*const core::ffi::c_void> {
        section.map_section_with_protection(self, address, protection)
    }

    pub fn unmap_section(&self, section: &Section, address: *const c_void) -> Result<()> {
        section.unmap_section(self, address)
    }
}

#[derive(Debug, Clone)]
pub struct Thread {
    thread_id: u32,
}

impl Thread {
    pub fn from_id(thread_id: u32) -> Self {
        Self { thread_id }
    }

    pub fn id(&self) -> u32 {
        self.thread_id
    }

    pub fn resume(&self) -> Result<()> {
        let thread_handle =
            unsafe { OpenThread(THREAD_SUSPEND_RESUME, BOOL::from(false), self.thread_id) };
        if thread_handle.is_null() {
            return bail_with_last_error(&format!("Failed to open thread {}", self.thread_id));
        }
        let result = unsafe { ResumeThread(thread_handle) };
        unsafe {
            CloseHandle(thread_handle);
        }
        if result == u32::MAX {
            return bail_with_last_error(&format!("Failed to resume thread {}", self.thread_id));
        }
        Ok(())
    }

    pub fn suspend(&self) -> Result<()> {
        let thread_handle =
            unsafe { OpenThread(THREAD_SUSPEND_RESUME, BOOL::from(false), self.thread_id) };
        if thread_handle.is_null() {
            return bail_with_last_error(&format!("Failed to open thread {}", self.thread_id));
        }
        let result = unsafe { SuspendThread(thread_handle) };
        unsafe {
            CloseHandle(thread_handle);
        }
        if result == u32::MAX {
            return bail_with_last_error(&format!("Failed to suspend thread {}", self.thread_id));
        }
        Ok(())
    }

    pub fn get_context(&self) -> Result<CONTEXT> {
        let thread_handle = unsafe {
            OpenThread(
                THREAD_GET_CONTEXT | THREAD_SUSPEND_RESUME,
                BOOL::from(false),
                self.thread_id,
            )
        };
        if thread_handle.is_null() {
            return bail_with_last_error(&format!("Failed to open thread {}", self.thread_id));
        }

        let mut context = AlignedContext(unsafe { mem::zeroed() });
        context.0.ContextFlags = FULL_THREAD_CONTEXT_FLAGS;

        let result = unsafe { GetThreadContext(thread_handle, &mut context.0) };
        unsafe {
            CloseHandle(thread_handle);
        }
        if result == 0 {
            return bail_with_last_error(&format!(
                "Failed to get context for thread {}",
                self.thread_id
            ));
        }

        Ok(context.0)
    }

    pub fn set_context(&self, context: &CONTEXT) -> Result<()> {
        let thread_handle = unsafe {
            OpenThread(
                THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME,
                BOOL::from(false),
                self.thread_id,
            )
        };
        if thread_handle.is_null() {
            return bail_with_last_error(&format!("Failed to open thread {}", self.thread_id));
        }

        let context = AlignedContext(*context);
        let result = unsafe { SetThreadContext(thread_handle, &context.0) };
        unsafe {
            CloseHandle(thread_handle);
        }
        if result == 0 {
            return bail_with_last_error(&format!(
                "Failed to set context for thread {}",
                self.thread_id
            ));
        }

        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct ModuleInfo {
    pub path: PathBuf,
    pub base_address: u64,
    pub size: Option<usize>,
}

#[derive(Debug)]
pub struct AnalysedModuleInfo {
    pub module: ModuleInfo,
    pub parsed: ParsedPeFile<'static>,
    _backing: Box<[u8]>,
}

impl AnalysedModuleInfo {
    pub fn sections(&self) -> Result<Vec<SectionTable>> {
        self.parsed.sections()
    }

    pub fn size_of_headers(&self) -> Option<usize> {
        Some(self.parsed.size_of_headers())
    }
}

impl ModuleInfo {
    pub fn analyse(&self, process: &Process) -> Result<AnalysedModuleInfo> {
        let image_size = self.remote_image_size(process)?;
        let backing = process
            .read_memory_at(self.base_address, image_size)?
            .into_boxed_slice();
        let parsed = ParsedPeFile::parse(&backing)?;
        let parsed = unsafe { std::mem::transmute::<ParsedPeFile<'_>, ParsedPeFile<'static>>(parsed) };

        Ok(AnalysedModuleInfo {
            module: ModuleInfo {
                path: self.path.clone(),
                base_address: self.base_address,
                size: Some(image_size),
            },
            parsed,
            _backing: backing,
        })
    }

    fn remote_image_size(&self, process: &Process) -> Result<usize> {
        let dos_header = process.read_memory_at(self.base_address, DOS_HEADER_LEN)?;
        if dos_header.len() < DOS_HEADER_LEN {
            return Err(anyhow::anyhow!(
                "module at {} is too small to contain a DOS header",
                self.path.display()
            ));
        }
        if dos_header[..2] != DOS_MAGIC {
            return Err(anyhow::anyhow!(
                "module at {} does not start with an MZ header",
                self.path.display()
            ));
        }

        let e_lfanew = read_u32(&dos_header, 0x3C)? as usize;
        let nt_headers_end = e_lfanew
            .checked_add(NT_SIGNATURE_LEN)
            .and_then(|value| value.checked_add(COFF_HEADER_LEN))
            .and_then(|value| value.checked_add(MIN_OPTIONAL_HEADER_FOR_SIZE_OF_IMAGE))
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "module at {} has an overflowing PE header offset",
                    self.path.display()
                )
            })?;

        if let Some(known_size) = self.size {
            if nt_headers_end > known_size {
                return Err(anyhow::anyhow!(
                    "module at {} reports NT headers outside the known image size",
                    self.path.display()
                ));
            }
        } else if nt_headers_end > MAX_REMOTE_HEADER_PROBE {
            return Err(anyhow::anyhow!(
                "module at {} has an implausibly distant NT header offset ({:#x})",
                self.path.display(),
                e_lfanew
            ));
        }

        let nt_probe = process.read_memory_at(self.base_address, nt_headers_end)?;
        if nt_probe.len() < nt_headers_end {
            return Err(anyhow::anyhow!(
                "module at {} did not yield enough bytes to cover its NT headers",
                self.path.display()
            ));
        }
        if nt_probe[e_lfanew..e_lfanew + NT_SIGNATURE_LEN] != PE_SIGNATURE {
            return Err(anyhow::anyhow!(
                "module at {} does not contain a valid PE signature",
                self.path.display()
            ));
        }

        let coff_header_offset = e_lfanew + NT_SIGNATURE_LEN;
        let size_of_optional_header = read_u16(
            &nt_probe,
            coff_header_offset + COFF_SIZE_OF_OPTIONAL_HEADER_OFFSET,
        )? as usize;
        if size_of_optional_header < MIN_OPTIONAL_HEADER_FOR_SIZE_OF_IMAGE {
            return Err(anyhow::anyhow!(
                "module at {} has an optional header too small for SizeOfImage",
                self.path.display()
            ));
        }

        let optional_header_offset = coff_header_offset + COFF_HEADER_LEN;
        let optional_header_magic = read_u16(
            &nt_probe,
            optional_header_offset + OPTIONAL_HEADER_MAGIC_OFFSET,
        )?;
        if optional_header_magic != OPTIONAL_HEADER_MAGIC_PE32
            && optional_header_magic != OPTIONAL_HEADER_MAGIC_PE32_PLUS
        {
            return Err(anyhow::anyhow!(
                "module at {} has an unsupported PE optional header magic {:#x}",
                self.path.display(),
                optional_header_magic
            ));
        }

        let image_size = read_u32(
            &nt_probe,
            optional_header_offset + OPTIONAL_HEADER_SIZE_OF_IMAGE_OFFSET,
        )? as usize;
        if image_size == 0 {
            return Err(anyhow::anyhow!(
                "module at {} reported a zero image size",
                self.path.display()
            ));
        }

        Ok(image_size)
    }
}

fn build_command_line(program: &PathBuf, arguments: &[OsString]) -> OsString {
    let mut command_line = OsString::new();
    let program_str = program.as_os_str();
    if program_str.to_string_lossy().contains(' ') {
        command_line.push("\"");
        command_line.push(program_str);
        command_line.push("\"");
    } else {
        command_line.push(program_str);
    }

    for arg in arguments {
        command_line.push(" ");
        let arg_str = arg.to_string_lossy();
        if arg_str.contains(' ') || arg_str.contains('"') {
            command_line.push("\"");
            command_line.push(&arg_str.replace('"', "\\\""));
            command_line.push("\"");
        } else {
            command_line.push(arg);
        }
    }

    command_line
}

fn build_environment_block(env: &HashMap<OsString, OsString>) -> Vec<u16> {
    let mut block = Vec::new();
    for (key, value) in env {
        block.extend(key.encode_wide());
        block.push('=' as u16);
        block.extend(value.encode_wide());
        block.push(0);
    }
    block.push(0);
    block
}

fn normalize_section_name(name: &str) -> Result<String> {
    if name.starts_with('\\') {
        return Ok(name.to_string());
    }

    if let Some(local_name) = name.strip_prefix("Local\\") {
        let session_id = current_session_id()?;
        return Ok(format!(
            "{SESSION_BASE_NAMED_OBJECTS_PREFIX}{session_id}\\BaseNamedObjects\\{local_name}"
        ));
    }

    if let Some(global_name) = name.strip_prefix("Global\\") {
        return Ok(format!("{BASE_NAMED_OBJECTS_PREFIX}{global_name}"));
    }

    let session_id = current_session_id()?;
    Ok(format!(
        "{SESSION_BASE_NAMED_OBJECTS_PREFIX}{session_id}\\BaseNamedObjects\\{name}"
    ))
}

fn current_session_id() -> Result<u32> {
    let mut session_id = 0u32;
    let result = unsafe { ProcessIdToSessionId(std::process::id(), &mut session_id) };
    if result == 0 {
        return bail_with_last_error("ProcessIdToSessionId failed");
    }

    Ok(session_id)
}

fn build_object_attributes(object_name: &UNICODE_STRING) -> OBJECT_ATTRIBUTES {
    OBJECT_ATTRIBUTES {
        Length: mem::size_of::<OBJECT_ATTRIBUTES>() as u32,
        RootDirectory: core::ptr::null_mut(),
        ObjectName: object_name as *const UNICODE_STRING,
        Attributes: OBJ_CASE_INSENSITIVE,
        SecurityDescriptor: core::ptr::null(),
        SecurityQualityOfService: core::ptr::null(),
    }
}

fn section_view_protection(access_mask: u32) -> u32 {
    let can_execute = access_mask & SECTION_MAP_EXECUTE != 0;
    let can_write = access_mask & SECTION_MAP_WRITE != 0;
    let can_read = can_write || access_mask & SECTION_MAP_READ != 0;

    match (can_execute, can_write, can_read) {
        (true, true, _) => PAGE_EXECUTE_READWRITE,
        (true, false, _) => PAGE_EXECUTE_READ,
        (false, true, _) => PAGE_READWRITE,
        (false, false, true) => PAGE_READONLY,
        (false, false, false) => PAGE_READONLY,
    }
}

struct OwnedUnicodeString {
    text: String,
    _wide: Vec<u16>,
    unicode: UNICODE_STRING,
}

impl OwnedUnicodeString {
    fn new(text: &str) -> Result<Self> {
        let mut wide: Vec<u16> = text.encode_utf16().collect();
        let length_bytes = wide
            .len()
            .checked_mul(mem::size_of::<u16>())
            .ok_or_else(|| anyhow::anyhow!("unicode string too large"))?;
        let maximum_length_bytes = length_bytes
            .checked_add(mem::size_of::<u16>())
            .ok_or_else(|| anyhow::anyhow!("unicode string too large"))?;
        let length =
            u16::try_from(length_bytes).map_err(|_| anyhow::anyhow!("unicode string too large"))?;
        let maximum_length = u16::try_from(maximum_length_bytes)
            .map_err(|_| anyhow::anyhow!("unicode string too large"))?;
        wide.push(0);

        let unicode = UNICODE_STRING {
            Length: length,
            MaximumLength: maximum_length,
            Buffer: wide.as_mut_ptr(),
        };

        Ok(Self {
            text: text.to_string(),
            _wide: wide,
            unicode,
        })
    }

    fn as_str(&self) -> &str {
        &self.text
    }

    fn as_unicode_string(&self) -> &UNICODE_STRING {
        &self.unicode
    }

    fn into_string(self) -> String {
        self.text
    }
}

fn read_u16(buffer: &[u8], offset: usize) -> Result<u16> {
    let bytes = buffer
        .get(offset..offset + 2)
        .ok_or_else(|| anyhow::anyhow!("short buffer while reading u16 at offset {offset:#x}"))?;
    Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
}

fn read_u32(buffer: &[u8], offset: usize) -> Result<u32> {
    let bytes = buffer
        .get(offset..offset + 4)
        .ok_or_else(|| anyhow::anyhow!("short buffer while reading u32 at offset {offset:#x}"))?;
    Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

#[derive(Debug, Clone, Eq, PartialEq)]
struct MemoryRange(Range<u64>);

impl MemoryRange {
    fn new(range: Range<u64>) -> Self {
        Self(range)
    }

    fn as_range(&self) -> &Range<u64> {
        &self.0
    }
}

impl Ord for MemoryRange {
    fn cmp(&self, other: &Self) -> Ordering {
        self.0
            .start
            .cmp(&other.0.start)
            .then_with(|| self.0.end.cmp(&other.0.end))
    }
}

impl PartialOrd for MemoryRange {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

#[derive(Debug, Default)]
pub struct MemoryMap(BTreeMap<MemoryRange, MemoryInfo>);

impl MemoryMap {
    pub fn new() -> Self {
        Self(BTreeMap::new())
    }

    pub fn insert(&mut self, range: Range<u64>, info: MemoryInfo) -> Option<MemoryInfo> {
        self.0.insert(MemoryRange::new(range), info)
    }

    pub fn iter(&self) -> impl Iterator<Item = (&Range<u64>, &MemoryInfo)> {
        self.0.iter().map(|(range, info)| (range.as_range(), info))
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct MemoryInfo {
    pub protection: u32,
    pub state: u32,
}

impl MemoryInfo {
    pub fn is_committed(&self) -> bool {
        self.state == MEM_COMMIT
    }

    pub fn is_reserved(&self) -> bool {
        self.state == MEM_RESERVE
    }

    pub fn is_free(&self) -> bool {
        self.state == MEM_FREE
    }
}
