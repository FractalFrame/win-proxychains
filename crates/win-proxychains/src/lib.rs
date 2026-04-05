// Copyright (c) 2026 FractalFrame <https://fractalframe.eu>
// Part of the win-proxychains project. Licensed under FSL-1.1-MIT; see LICENCE.md.

use std::{
    collections::HashMap,
    ffi::c_void,
    sync::{Mutex, atomic::AtomicU64},
};

use anyhow::Result;

use windows_sys::Win32::{
    Foundation::GetLastError,
    System::{
        Memory::{PAGE_EXECUTE_READWRITE, VirtualProtect},
        SystemServices::{IMAGE_DOS_HEADER, IMAGE_DOS_SIGNATURE},
    },
};

use crate::{hook::HookContext, map_pe::load_all_import_images};

pub mod config;
pub mod hook;
pub mod hooks_dns;
pub mod hooks_ntdll;
pub mod hooks_sockets;
pub mod map_pe;
pub mod socks;

// stati
static CONTEXT: AtomicU64 = AtomicU64::new(0);

static FAILURE: u32 = 0;
static SUCCESS: u32 = 1;

pub struct Context {
    pub last_error: String,
    pub config: Option<config::ProxychainsConfig>,

    pub section_name: String,
    pub section_base: u64,

    pub hooks: Vec<HookContext>,
    pub socket_states: Mutex<HashMap<usize, SocketRuntimeState>>,

    // The counter for the fake IPv4 addresses we return when proxy_dns is enabled. The config's `remote_dns_subnet`
    // seeds the top octet.
    pub ipv4_fake_counter: u32,

    // The counter for the fake IPv6 addresses we return when proxy_dns is enabled. The config's `remote_dns_subnet_6`
    // seeds the top octet.
    pub ipv6_fake_counter: u128,

    // When proxy_dns is set, we will intercept DNS lookups, return a fake IP, and store the fake <-> real mapping here.
    // When connect is called with these IP addresses later, we will substitute the destination with the hostname
    // This matches proxychains-ng's behavior.
    // Each "lookup" will generate two mappings. One for Ipv4 and one for Ipv6.
    // Afer 0xffffff requests, IPv4 will be dropped from that point on, only IPv6 will be generated.
    pub dns_cache: Mutex<HashMap<String, Vec<std::net::IpAddr>>>,
    pub reverse_dns_cache: Mutex<HashMap<std::net::IpAddr, String>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IocpAssociationState {
    pub completion_port: usize,
    pub completion_key: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SyntheticConnectExState {
    pub overlapped: usize,
    pub bytes_sent: u32,
    pub error: i32,
    pub completed: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SocketConnectContract {
    #[default]
    Blocking,
    NonBlockingPoll,
    EventAsync,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct EventSelectState {
    pub event_handle: usize,
    pub network_events: i32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct AsyncSelectState {
    pub window_handle: usize,
    pub message_id: u32,
    pub network_events: i32,
}

#[derive(Debug, Clone, Default)]
pub struct SocketRuntimeState {
    pub iocp_association: Option<IocpAssociationState>,
    pub synthetic_connectex: Option<SyntheticConnectExState>,
    pub allow_update_connect_context: bool,
    pub nonblocking: bool,
    pub event_select: Option<EventSelectState>,
    pub async_select: Option<AsyncSelectState>,
}

pub fn get_context() -> &'static mut Context {
    unsafe {
        let context_ptr = CONTEXT.load(std::sync::atomic::Ordering::SeqCst) as *mut Context;
        if context_ptr.is_null() {
            let new_context = Box::new(Context {
                last_error: String::new(),
                config: None,
                section_name: String::new(),
                section_base: 0,
                hooks: Vec::new(),
                socket_states: Mutex::new(HashMap::new()),
                ipv4_fake_counter: 0,
                ipv6_fake_counter: 0,
                dns_cache: Mutex::new(HashMap::new()),
                reverse_dns_cache: Mutex::new(HashMap::new()),
            });
            let new_context_ptr = Box::into_raw(new_context);

            CONTEXT.store(new_context_ptr as u64, std::sync::atomic::Ordering::SeqCst);

            &mut *new_context_ptr
        } else {
            &mut *context_ptr
        }
    }
}

pub fn release_context() {
    unsafe {
        let context_ptr = CONTEXT.load(std::sync::atomic::Ordering::SeqCst) as *mut Context;
        if !context_ptr.is_null() {
            let _ = Box::from_raw(context_ptr);
            CONTEXT.store(0, std::sync::atomic::Ordering::SeqCst);
        }
    }
}

pub fn set_last_error(message: String) {
    emit_debug_last_error(&message);
    let context = get_context();
    context.last_error = message;
}

#[cfg(debug_assertions)]
fn emit_debug_last_error(message: &str) {
    let wide_message: Vec<u16> = format!("win-proxychains: {message}")
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    unsafe {
        windows_sys::Win32::System::Diagnostics::Debug::OutputDebugStringW(wide_message.as_ptr());
    }
}

#[cfg(not(debug_assertions))]
fn emit_debug_last_error(_message: &str) {}

pub fn bail_with_last_error<T>(message: impl std::fmt::Display) -> Result<T> {
    let error_code = unsafe { GetLastError() };
    let full_message = format!("{message}: Windows API error {error_code}");
    set_last_error(full_message.clone());
    Err(anyhow::anyhow!(full_message))
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn get_last_error_size() -> usize {
    let context = get_context();
    let message = &context.last_error;
    message.as_bytes().len()
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn get_last_error_message(buffer: *mut u8, buffer_len: usize) -> usize {
    let context = get_context();
    let message = &context.last_error;
    let bytes = message.as_bytes();
    let copy_len = bytes.len().min(buffer_len);

    if !buffer.is_null() && copy_len > 0 {
        unsafe {
            std::ptr::copy_nonoverlapping(bytes.as_ptr(), buffer, copy_len);
        }
    }

    copy_len
}

// #[unsafe(no_mangle)]
// pub unsafe extern "C" fn get_last_error_message_remote(buffer: *mut u8) {

// }

// pub fn read_last_error_message_remote(process: &Process) -> Result<String> {
//     // first allocate a buffer remote

// }

fn find_own_header() -> Result<*const c_void> {
    // Get the address of a function in our own module (e.g., this function)
    let func_address = find_own_header as usize;

    // First round _down_ to next 64k boundary
    let mut base_address = func_address & !0xFFFF;

    loop {
        unsafe {
            let potential_image_base = base_address as *const IMAGE_DOS_HEADER;

            // Check if the magic is valid, and the jump to the PE header is not too far
            if (*potential_image_base).e_magic != IMAGE_DOS_SIGNATURE {
                base_address = base_address.wrapping_sub(0x10000);
                continue;
            }

            // fetch the PE header then
            let pe_header_offset = (*potential_image_base).e_lfanew as usize;
            let pe_header_address = (base_address as usize).wrapping_add(pe_header_offset);

            // Check if the PE header is valid
            let pe_signature = *(pe_header_address as *const u32);
            if pe_signature != 0x00004550 {
                // "PE\0\0"
                base_address = base_address.wrapping_sub(0x10000);
                continue;
            }

            // If we got here, it means the PE header was valid
            return Ok(base_address as *const c_void);
        }
    }
}

// This structure is used to inject the config remotely
// It is called when our section propagates to a new process, and the remote "initialize" function is called
#[repr(C)]
pub struct InitializePacket {
    pub config_slice: [u8; 0x1000],
    pub config_len: usize,

    pub section_name_slice: [u8; 256],
    pub section_name_len: usize,

    pub section_base: u64,

    // We will use these to restore the target after we're done, if we had to suspend it to inject
    // target AOP was overwritten with
    // mov rcx, addr initialze_packet
    // mov rax, addr initialize_remote
    // jmp rax
    // 48 B9 [8 byte address]
    // 48 B8 [8 byte address]
    // FF E0
    pub og_bytes: [u8; 2 + 2 + 8 + 8 + 2],
    pub og_entry: u64,
}

impl InitializePacket {
    pub fn new(config: &str, section: &str, section_base: u64) -> Result<Self> {
        let config_bytes = config.as_bytes();
        let section_bytes = section.as_bytes();
        let mut packet = InitializePacket {
            config_slice: [0; 0x1000],
            config_len: config_bytes.len(),
            section_name_slice: [0; 256],
            section_name_len: section_bytes.len(),
            section_base,
            og_bytes: [0; 2 + 2 + 8 + 8 + 2],
            og_entry: 0,
        };

        if !config.is_empty() && config_bytes.len() <= packet.config_slice.len() {
            unsafe {
                std::ptr::copy_nonoverlapping(
                    config_bytes.as_ptr(),
                    packet.config_slice.as_mut_ptr(),
                    config_bytes.len(),
                );
            }
        } else {
            return Err(anyhow::anyhow!(
                "Config string is too long to fit in packet"
            ));
        }

        if !section.is_empty() && section_bytes.len() <= packet.section_name_slice.len() {
            unsafe {
                std::ptr::copy_nonoverlapping(
                    section_bytes.as_ptr(),
                    packet.section_name_slice.as_mut_ptr(),
                    section_bytes.len(),
                );
            }
        } else {
            return Err(anyhow::anyhow!(
                "Section name string is too long to fit in packet"
            ));
        }

        Ok(packet)
    }

    pub fn set_remote_restore_data(&mut self, og_entry: u64, og_bytes: &[u8]) -> Result<()> {
        if og_bytes.len() != self.og_bytes.len() {
            return Err(anyhow::anyhow!(
                "Original bytes length does not match packet og_bytes length"
            ));
        }

        self.og_entry = og_entry;
        unsafe {
            std::ptr::copy_nonoverlapping(
                og_bytes.as_ptr(),
                self.og_bytes.as_mut_ptr(),
                og_bytes.len(),
            );
        }

        Ok(())
    }

    pub fn as_bytes(&self) -> &[u8] {
        unsafe {
            std::slice::from_raw_parts(
                (self as *const InitializePacket) as *const u8,
                std::mem::size_of::<InitializePacket>(),
            )
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn initialize_remote(packet: *const InitializePacket) -> u32 {
    // First we need to initialize our allocators
    let Ok(local_pe) = find_own_header() else {
        // can't set errors yet.
        return FAILURE;
    };

    // Verify the section base and our header are in the same place, otherwise something is very wrong
    // This bit is purely defensive, we _must_ have been loaded at the right place for anything to work,
    // I can't think of a scenario where this would fail, but it's just a sanity check
    unsafe {
        if local_pe != (*packet).section_base as *const c_void {
            // can't set errors yet.
            return FAILURE;
        }
    }

    // first execute tls
    if map_pe::execute_tls(local_pe as *const _).is_err() {
        // can't set errors yet.
        return FAILURE;
    }

    // From here on out we've got allocators and memory working.
    if packet.is_null() {
        set_last_error("initialize_remote received a null packet pointer".to_string());
        return FAILURE;
    }

    let packet = unsafe { &*packet };

    let res = unsafe {
        initialize(
            packet.config_slice.as_ptr(),
            packet.config_len,
            packet.section_name_slice.as_ptr(),
            packet.section_name_len,
            packet.section_base,
        )
    };

    if res != SUCCESS {
        // if initialize failed, we should have set an error message by now, so just return failure
        return res;
    }

    // Restore our entry point if needed
    // if we got this, we've just been injected in a target
    if packet.og_entry != 0 {
        // virtual protect RWX
        let mut old_protect = 0;
        unsafe {
            if VirtualProtect(
                packet.og_entry as *const c_void,
                packet.og_bytes.len(),
                PAGE_EXECUTE_READWRITE,
                &mut old_protect,
            ) == 0
            {
                set_last_error(
                    "Failed to change memory protection to restore original entry bytes"
                        .to_string(),
                );
                return FAILURE;
            }

            // write original bytes back
            std::ptr::copy_nonoverlapping(
                packet.og_bytes.as_ptr(),
                packet.og_entry as *mut u8,
                packet.og_bytes.len(),
            );

            // restore original protection
            let mut _temp = 0;
            if VirtualProtect(
                packet.og_entry as *const c_void,
                packet.og_bytes.len(),
                old_protect,
                &mut _temp,
            ) == 0
            {
                set_last_error(
                    "Failed to restore original memory protection after restoring entry bytes"
                        .to_string(),
                );
                return FAILURE;
            }
        }

        // jump to it
        let entry_fn: extern "C" fn() = unsafe { std::mem::transmute(packet.og_entry) };
        entry_fn();
    }

    SUCCESS
}

unsafe fn initialize(
    config: *const u8,
    config_len: usize,
    section_name: *const u8,
    section_name_len: usize,
    section_base: u64,
) -> u32 {
    // Check all pointers are not null at least for early-sanity check
    if config.is_null() && config_len != 0 {
        let context = get_context();
        context.config = None;
        context.last_error = "initialize received a null config pointer".to_owned();
        return FAILURE;
    }

    if section_name.is_null() && section_name_len != 0 {
        let context = get_context();
        context.section_name.clear();
        context.last_error = "initialize received a null section name pointer".to_owned();
        return FAILURE;
    }

    // We know our header is here, we've checked it before
    let own_header = section_base as *const c_void;

    // When our section is mapped, the relocation is still applied
    // Our IMAGE_THUNK import data are also correct _iff_ the targeted dlls are loaded
    // If we've not crashed yet, we'll simply load them up to ensure we're ready to go.
    // We could further restrict our imports and build fully self-importing
    // But that's a chore
    if load_all_import_images(own_header as *const _).is_err() {
        let context = get_context();
        context.config = None;
        context.last_error = "Failed to load import images".to_owned();
        return FAILURE;
    };

    let config_slice = unsafe { std::slice::from_raw_parts(config, config_len) };
    match std::str::from_utf8(config_slice) {
        Ok(config_str) => match config::ProxychainsConfig::parse(config_str) {
            Ok(parsed_config) => {
                let context = get_context();
                context.last_error.clear();
                context.config = Some(parsed_config);
            }
            Err(error) => {
                let context = get_context();
                context.config = None;
                context.last_error = format!("Invalid proxychains configuration: {error:#}");
                return FAILURE;
            }
        },
        Err(error) => {
            let context = get_context();
            context.config = None;
            context.last_error = format!("Invalid UTF-8 configuration: {error}");
            return FAILURE;
        }
    }

    // now set our section data
    let context = get_context();
    let section_name_slice = unsafe { std::slice::from_raw_parts(section_name, section_name_len) };
    match std::str::from_utf8(section_name_slice) {
        Ok(section_name_str) => {
            context.section_name = section_name_str.to_owned();
        }
        Err(error) => {
            context.section_name.clear();
            context.last_error = format!("Invalid UTF-8 section name: {error}");
            return FAILURE;
        }
    }

    context.section_base = section_base;

    let proxy_dns = context
        .config
        .as_ref()
        .map(|c| c.proxy_dns)
        .unwrap_or(false);

    // Our context is set
    // Now hook the local functions we need to

    let Ok(mut create_user_process_hook) = HookContext::new(
        "ntdll.dll",
        "NtCreateUserProcess",
        hooks_ntdll::hooked_NtCreateUserProcess as u64,
    ) else {
        let context = get_context();
        context.last_error = "Failed to create hook for NtCreateUserProcess".to_owned();
        return FAILURE;
    };

    if let Err(e) = create_user_process_hook.hook() {
        let context = get_context();
        context.last_error = format!("Failed to hook NtCreateUserProcess: {e:#}");
        return FAILURE;
    }

    context.hooks.push(create_user_process_hook);

    if proxy_dns {
        let Ok(mut gethostbyname_hook) = HookContext::new(
            "ws2_32.dll",
            "gethostbyname",
            hooks_dns::hooked_gethostbyname as u64,
        ) else {
            let context = get_context();
            context.last_error = "Failed to create hook for gethostbyname".to_owned();
            return FAILURE;
        };

        if let Err(e) = gethostbyname_hook.hook() {
            let context = get_context();
            context.last_error = format!("Failed to hook gethostbyname: {e:#}");
            return FAILURE;
        }

        context.hooks.push(gethostbyname_hook);

        let Ok(mut wsa_async_get_host_by_name_hook) = HookContext::new(
            "ws2_32.dll",
            "WSAAsyncGetHostByName",
            hooks_dns::hooked_WSAAsyncGetHostByName as u64,
        ) else {
            let context = get_context();
            context.last_error = "Failed to create hook for WSAAsyncGetHostByName".to_owned();
            return FAILURE;
        };

        if let Err(e) = wsa_async_get_host_by_name_hook.hook() {
            let context = get_context();
            context.last_error = format!("Failed to hook WSAAsyncGetHostByName: {e:#}");
            return FAILURE;
        }

        context.hooks.push(wsa_async_get_host_by_name_hook);

        let Ok(mut getaddrinfo_hook) = HookContext::new(
            "ws2_32.dll",
            "getaddrinfo",
            hooks_dns::hooked_getaddrinfo as u64,
        ) else {
            let context = get_context();
            context.last_error = "Failed to create hook for getaddrinfo".to_owned();
            return FAILURE;
        };

        if let Err(e) = getaddrinfo_hook.hook() {
            let context = get_context();
            context.last_error = format!("Failed to hook getaddrinfo: {e:#}");
            return FAILURE;
        }

        context.hooks.push(getaddrinfo_hook);

        let Ok(mut freeaddrinfo_hook) = HookContext::new(
            "ws2_32.dll",
            "freeaddrinfo",
            hooks_dns::hooked_freeaddrinfo as u64,
        ) else {
            let context = get_context();
            context.last_error = "Failed to create hook for freeaddrinfo".to_owned();
            return FAILURE;
        };

        if let Err(e) = freeaddrinfo_hook.hook() {
            let context = get_context();
            context.last_error = format!("Failed to hook freeaddrinfo: {e:#}");
            return FAILURE;
        }

        context.hooks.push(freeaddrinfo_hook);

        let Ok(mut get_addr_info_w_hook) = HookContext::new(
            "ws2_32.dll",
            "GetAddrInfoW",
            hooks_dns::hooked_GetAddrInfoW as u64,
        ) else {
            let context = get_context();
            context.last_error = "Failed to create hook for GetAddrInfoW".to_owned();
            return FAILURE;
        };

        if let Err(e) = get_addr_info_w_hook.hook() {
            let context = get_context();
            context.last_error = format!("Failed to hook GetAddrInfoW: {e:#}");
            return FAILURE;
        }

        context.hooks.push(get_addr_info_w_hook);

        let Ok(mut free_addr_info_w_hook) = HookContext::new(
            "ws2_32.dll",
            "FreeAddrInfoW",
            hooks_dns::hooked_FreeAddrInfoW as u64,
        ) else {
            let context = get_context();
            context.last_error = "Failed to create hook for FreeAddrInfoW".to_owned();
            return FAILURE;
        };

        if let Err(e) = free_addr_info_w_hook.hook() {
            let context = get_context();
            context.last_error = format!("Failed to hook FreeAddrInfoW: {e:#}");
            return FAILURE;
        }

        context.hooks.push(free_addr_info_w_hook);
    }

    // hook connect to insert our socks proxies
    let Ok(mut connect_hook) = HookContext::new(
        "ws2_32.dll",
        "connect",
        hooks_sockets::hooked_connect as u64,
    ) else {
        let context = get_context();
        context.last_error = "Failed to create hook for connect".to_owned();
        return FAILURE;
    };

    if let Err(e) = connect_hook.hook() {
        let context = get_context();
        context.last_error = format!("Failed to hook connect: {e:#}");
        return FAILURE;
    }

    context.hooks.push(connect_hook);

    let Ok(mut wsa_connect_hook) = HookContext::new(
        "ws2_32.dll",
        "WSAConnect",
        hooks_sockets::hooked_WSAConnect as u64,
    ) else {
        let context = get_context();
        context.last_error = "Failed to create hook for WSAConnect".to_owned();
        return FAILURE;
    };

    if let Err(e) = wsa_connect_hook.hook() {
        let context = get_context();
        context.last_error = format!("Failed to hook WSAConnect: {e:#}");
        return FAILURE;
    }

    context.hooks.push(wsa_connect_hook);

    let Ok(mut ioctlsocket_hook) = HookContext::new(
        "ws2_32.dll",
        "ioctlsocket",
        hooks_sockets::hooked_ioctlsocket as u64,
    ) else {
        let context = get_context();
        context.last_error = "Failed to create hook for ioctlsocket".to_owned();
        return FAILURE;
    };

    if let Err(e) = ioctlsocket_hook.hook() {
        let context = get_context();
        context.last_error = format!("Failed to hook ioctlsocket: {e:#}");
        return FAILURE;
    }

    context.hooks.push(ioctlsocket_hook);

    let Ok(mut wsa_event_select_hook) = HookContext::new(
        "ws2_32.dll",
        "WSAEventSelect",
        hooks_sockets::hooked_WSAEventSelect as u64,
    ) else {
        let context = get_context();
        context.last_error = "Failed to create hook for WSAEventSelect".to_owned();
        return FAILURE;
    };

    if let Err(e) = wsa_event_select_hook.hook() {
        let context = get_context();
        context.last_error = format!("Failed to hook WSAEventSelect: {e:#}");
        return FAILURE;
    }

    context.hooks.push(wsa_event_select_hook);

    let Ok(mut wsa_async_select_hook) = HookContext::new(
        "ws2_32.dll",
        "WSAAsyncSelect",
        hooks_sockets::hooked_WSAAsyncSelect as u64,
    ) else {
        let context = get_context();
        context.last_error = "Failed to create hook for WSAAsyncSelect".to_owned();
        return FAILURE;
    };

    if let Err(e) = wsa_async_select_hook.hook() {
        let context = get_context();
        context.last_error = format!("Failed to hook WSAAsyncSelect: {e:#}");
        return FAILURE;
    }

    context.hooks.push(wsa_async_select_hook);

    let Ok(mut wsa_ioctl_hook) = HookContext::new(
        "ws2_32.dll",
        "WSAIoctl",
        hooks_sockets::hooked_WSAIoctl as u64,
    ) else {
        let context = get_context();
        context.last_error = "Failed to create hook for WSAIoctl".to_owned();
        return FAILURE;
    };

    if let Err(e) = wsa_ioctl_hook.hook() {
        let context = get_context();
        context.last_error = format!("Failed to hook WSAIoctl: {e:#}");
        return FAILURE;
    }

    context.hooks.push(wsa_ioctl_hook);

    let Ok(mut create_iocp_hook) = HookContext::new(
        "kernelbase.dll",
        "CreateIoCompletionPort",
        hooks_sockets::hooked_CreateIoCompletionPort as u64,
    ) else {
        let context = get_context();
        context.last_error = "Failed to create hook for CreateIoCompletionPort".to_owned();
        return FAILURE;
    };

    if let Err(e) = create_iocp_hook.hook() {
        let context = get_context();
        context.last_error = format!("Failed to hook CreateIoCompletionPort: {e:#}");
        return FAILURE;
    }

    context.hooks.push(create_iocp_hook);

    let Ok(mut setsockopt_hook) = HookContext::new(
        "ws2_32.dll",
        "setsockopt",
        hooks_sockets::hooked_setsockopt as u64,
    ) else {
        let context = get_context();
        context.last_error = "Failed to create hook for setsockopt".to_owned();
        return FAILURE;
    };

    if let Err(e) = setsockopt_hook.hook() {
        let context = get_context();
        context.last_error = format!("Failed to hook setsockopt: {e:#}");
        return FAILURE;
    }

    context.hooks.push(setsockopt_hook);

    let Ok(mut wsa_get_overlapped_result_hook) = HookContext::new(
        "ws2_32.dll",
        "WSAGetOverlappedResult",
        hooks_sockets::hooked_WSAGetOverlappedResult as u64,
    ) else {
        let context = get_context();
        context.last_error = "Failed to create hook for WSAGetOverlappedResult".to_owned();
        return FAILURE;
    };

    if let Err(e) = wsa_get_overlapped_result_hook.hook() {
        let context = get_context();
        context.last_error = format!("Failed to hook WSAGetOverlappedResult: {e:#}");
        return FAILURE;
    }

    context.hooks.push(wsa_get_overlapped_result_hook);

    let Ok(mut closesocket_hook) = HookContext::new(
        "ws2_32.dll",
        "closesocket",
        hooks_sockets::hooked_closesocket as u64,
    ) else {
        let context = get_context();
        context.last_error = "Failed to create hook for closesocket".to_owned();
        return FAILURE;
    };

    if let Err(e) = closesocket_hook.hook() {
        let context = get_context();
        context.last_error = format!("Failed to hook closesocket: {e:#}");
        return FAILURE;
    }

    context.hooks.push(closesocket_hook);

    SUCCESS
}

#[cfg(test)]
mod tests {
    use super::find_own_header;
    use windows_sys::Win32::System::Diagnostics::Debug::{
        IMAGE_FILE_HEADER, IMAGE_NT_HEADERS32, IMAGE_NT_HEADERS64,
    };
    use windows_sys::Win32::System::SystemInformation::{
        IMAGE_FILE_MACHINE_AMD64, IMAGE_FILE_MACHINE_I386,
    };
    use windows_sys::Win32::System::SystemServices::{IMAGE_DOS_HEADER, IMAGE_DOS_SIGNATURE};

    const PE_SIGNATURE: u32 = 0x0000_4550;

    #[repr(C)]
    struct ImageNtHeadersPrefix {
        signature: u32,
        file_header: IMAGE_FILE_HEADER,
    }

    #[test]
    fn find_own_header_returns_this_modules_pe_base() {
        let header = find_own_header().expect("should find this module's PE header");
        let header_addr = header as usize;
        let function_addr = find_own_header as usize;

        assert_eq!(header_addr & 0xFFFF, 0, "header should be 64 KiB aligned");
        assert!(
            header_addr <= function_addr,
            "function should live after module base"
        );

        let dos_header = unsafe { &*(header as *const IMAGE_DOS_HEADER) };
        assert_eq!(
            dos_header.e_magic, IMAGE_DOS_SIGNATURE,
            "image should start with MZ"
        );

        let nt_header_offset =
            usize::try_from(dos_header.e_lfanew).expect("NT header offset should be non-negative");
        let nt_header = unsafe {
            &*(((header as *const u8).add(nt_header_offset)) as *const ImageNtHeadersPrefix)
        };
        assert_eq!(
            nt_header.signature, PE_SIGNATURE,
            "image should contain a PE header"
        );

        let size_of_image = match nt_header.file_header.Machine {
            IMAGE_FILE_MACHINE_I386 => unsafe {
                (&*(((header as *const u8).add(nt_header_offset)) as *const IMAGE_NT_HEADERS32))
                    .OptionalHeader
                    .SizeOfImage as usize
            },
            IMAGE_FILE_MACHINE_AMD64 => unsafe {
                (&*(((header as *const u8).add(nt_header_offset)) as *const IMAGE_NT_HEADERS64))
                    .OptionalHeader
                    .SizeOfImage as usize
            },
            machine => panic!("unexpected machine type: {machine:#x}"),
        };
        assert!(
            function_addr < header_addr + size_of_image,
            "function address {function_addr:#x} should be inside image [{header_addr:#x}, {:#x})",
            header_addr + size_of_image,
        );
        assert!(
            nt_header.file_header.SizeOfOptionalHeader > 0,
            "image should include an optional header"
        );
    }
}
