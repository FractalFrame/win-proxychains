use alloc::{
    borrow::ToOwned,
    boxed::Box,
    format,
    string::String,
    vec::Vec,
};
use core::{
    ffi::CStr,
    iter,
    mem::{self, align_of, size_of},
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    ptr::{copy_nonoverlapping, null, null_mut, write_unaligned},
    slice,
    sync::atomic::{AtomicU64, AtomicUsize, Ordering},
};

use windows_sys::Win32::{
    Foundation::{HANDLE, HWND},
    Networking::WinSock::{
        ADDRINFOA, ADDRINFOW, AF_INET, AF_INET6, AF_UNSPEC, FreeAddrInfoW, GetAddrInfoW, HOSTENT,
        IN_ADDR, IN_ADDR_0, IN_ADDR_0_0, IN6_ADDR, IN6_ADDR_0, SOCKADDR, SOCKADDR_IN, SOCKADDR_IN6,
        SOCKADDR_IN6_0, WSAAsyncGetHostByName, WSAEINVAL, WSAENOBUFS, WSANO_DATA, WSASetLastError,
        freeaddrinfo, getaddrinfo, gethostbyname,
    },
    System::Threading::GetCurrentThreadId,
    UI::WindowsAndMessaging::PostMessageW,
};

use crate::{Context, lock_context, set_last_error_in_context, trace};

const DEFAULT_REMOTE_DNS_SUBNET_V4: u8 = 224;
const DEFAULT_REMOTE_DNS_SUBNET_V6: u8 = 252;
const MAX_FAKE_IPV4_REQUESTS: u32 = 0x00FF_FFFF;

static FPTR_O_GETHOSTBYNAME: AtomicU64 = AtomicU64::new(0);
static FPTR_O_WSA_ASYNC_GET_HOST_BY_NAME: AtomicU64 = AtomicU64::new(0);
static FPTR_O_GETADDRINFO: AtomicU64 = AtomicU64::new(0);
static FPTR_O_FREEADDRINFO: AtomicU64 = AtomicU64::new(0);
static FPTR_O_GET_ADDR_INFOW: AtomicU64 = AtomicU64::new(0);
static FPTR_O_FREE_ADDR_INFOW: AtomicU64 = AtomicU64::new(0);
static NEXT_ASYNC_TASK_HANDLE: AtomicUsize = AtomicUsize::new(1);

fn cached_trampoline(
    context: &mut Context,
    cache: &AtomicU64,
    target: u64,
    function_name: &str,
) -> Option<u64> {
    let mut trampoline = cache.load(Ordering::SeqCst);
    if trampoline != 0 {
        return Some(trampoline);
    }

    let hook_trampoline = context
        .hooks
        .iter()
        .find(|hook| hook.target == target)
        .map(|hook| hook.trampoline());
    let Some(hook_trampoline) = hook_trampoline else {
        set_last_error_in_context(
            context,
            format!("Failed to find hook context for {function_name}"),
        );
        return None;
    };

    trampoline = hook_trampoline;
    cache.store(trampoline, Ordering::SeqCst);
    Some(trampoline)
}

fn proxy_dns_enabled(context: &Context) -> Option<(u8, u8)> {
    let config = context.config.as_ref()?;
    if !config.proxy_dns {
        return None;
    }

    Some((
        config
            .remote_dns_subnet
            .unwrap_or(DEFAULT_REMOTE_DNS_SUBNET_V4),
        config
            .remote_dns_subnet_6
            .unwrap_or(DEFAULT_REMOTE_DNS_SUBNET_V6),
    ))
}

fn should_proxy_dns_name(name: &str) -> bool {
    !name.is_empty() && name.parse::<IpAddr>().is_err()
}

fn next_fake_ipv4(subnet: u8, counter: &mut u32) -> Option<Ipv4Addr> {
    if *counter >= MAX_FAKE_IPV4_REQUESTS {
        return None;
    }

    *counter += 1;
    let raw = ((subnet as u32) << 24) | *counter;
    Some(Ipv4Addr::from(raw.to_be_bytes()))
}

fn next_fake_ipv6(subnet: u8, counter: &mut u128) -> Ipv6Addr {
    *counter += 1;
    let raw = ((subnet as u128) << 120) | *counter;
    Ipv6Addr::from(raw.to_be_bytes())
}

fn cached_or_allocate_fake_dns_entries(context: &mut Context, name: &str) -> Option<Vec<IpAddr>> {
    if !should_proxy_dns_name(name) {
        return None;
    }

    let (ipv4_subnet, ipv6_subnet) = proxy_dns_enabled(context)?;
    let mut addresses = Vec::with_capacity(2);
    if let Some(ipv4) = next_fake_ipv4(ipv4_subnet, &mut context.ipv4_fake_counter) {
        addresses.push(IpAddr::V4(ipv4));
    }

    let ipv6 = next_fake_ipv6(ipv6_subnet, &mut context.ipv6_fake_counter);
    addresses.push(IpAddr::V6(ipv6));

    {
        let mut dns_cache = context
            .dns_cache
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(addresses) = dns_cache.get(name).cloned() {
            return Some(addresses);
        }
        dns_cache.insert(name.to_owned(), addresses.clone());
    }

    let mut reverse_dns_cache = context
        .reverse_dns_cache
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());

    for address in &addresses {
        reverse_dns_cache.insert(*address, name.to_owned());
    }

    Some(addresses)
}

pub fn reverse_fake_dns_name(context: &Context, name: &str) -> Option<String> {
    let address = name.parse::<IpAddr>().ok()?;
    let reverse_dns_cache = context
        .reverse_dns_cache
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    reverse_dns_cache.get(&address).cloned()
}

fn filter_fake_dns_addresses(addresses: Vec<IpAddr>, family: i32) -> Vec<IpAddr> {
    addresses
        .into_iter()
        .filter(|address| match family {
            family if family == AF_UNSPEC as i32 => true,
            family if family == AF_INET as i32 => address.is_ipv4(),
            family if family == AF_INET6 as i32 => address.is_ipv6(),
            _ => false,
        })
        .collect()
}

unsafe fn pcstr_to_string(value: *const i8) -> Option<String> {
    if value.is_null() {
        return None;
    }

    Some(
        unsafe { CStr::from_ptr(value) }
            .to_string_lossy()
            .into_owned(),
    )
}

unsafe fn pcwstr_to_string(value: *const u16) -> Option<String> {
    if value.is_null() {
        return None;
    }

    let mut len = 0usize;
    while unsafe { *value.add(len) } != 0 {
        len += 1;
    }

    Some(String::from_utf16_lossy(unsafe { slice::from_raw_parts(value, len) }))
}

fn wide_null(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(iter::once(0)).collect()
}

fn port_from_sockaddr(addr: *const SOCKADDR, addr_len: usize) -> Option<u16> {
    if addr.is_null() {
        return None;
    }

    match unsafe { (*addr).sa_family as i32 } {
        family if family == AF_INET as i32 => {
            if addr_len < size_of::<SOCKADDR_IN>() {
                return None;
            }
            Some(u16::from_be(unsafe {
                (*(addr as *const SOCKADDR_IN)).sin_port
            }))
        }
        family if family == AF_INET6 as i32 => {
            if addr_len < size_of::<SOCKADDR_IN6>() {
                return None;
            }
            Some(u16::from_be(unsafe {
                (*(addr as *const SOCKADDR_IN6)).sin6_port
            }))
        }
        _ => None,
    }
}

#[derive(Clone, Copy)]
struct ServiceInfo {
    port: u16,
    socktype: i32,
    protocol: i32,
    flags: i32,
}

#[derive(Default)]
pub struct FakeHostentStorage {
    hostent: HOSTENT,
    aliases: [*mut i8; 1],
    addr_list: [*mut i8; 2],
    name: Vec<u8>,
    addr: [u8; 4],
}

impl FakeHostentStorage {
    fn populate(&mut self, name: &str, address: Ipv4Addr) -> *mut HOSTENT {
        self.name.clear();
        self.name.extend_from_slice(name.as_bytes());
        self.name.push(0);
        self.addr = address.octets();
        self.aliases = [null_mut()];
        self.addr_list = [self.addr.as_mut_ptr() as *mut i8, null_mut()];
        self.hostent = HOSTENT {
            h_name: self.name.as_mut_ptr(),
            h_aliases: self.aliases.as_mut_ptr(),
            h_addrtype: AF_INET as i16,
            h_length: 4,
            h_addr_list: self.addr_list.as_mut_ptr(),
        };

        &mut self.hostent
    }
}

fn populate_thread_hostent_storage(
    context: &mut Context,
    name: &str,
    address: Ipv4Addr,
) -> *mut HOSTENT {
    let thread_id = unsafe { GetCurrentThreadId() };
    let mut hostent_storage = context
        .dns_hostent_storage
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let storage = hostent_storage
        .entry(thread_id)
        .or_insert_with(|| Box::new(FakeHostentStorage::default()));
    storage.populate(name, address)
}

#[repr(C)]
struct OwnedAddrInfoA {
    addrinfo: ADDRINFOA,
    sockaddr_v4: SOCKADDR_IN,
    sockaddr_v6: SOCKADDR_IN6,
    canonname: Vec<u8>,
}

#[repr(C)]
struct OwnedAddrInfoW {
    addrinfo: ADDRINFOW,
    sockaddr_v4: SOCKADDR_IN,
    sockaddr_v6: SOCKADDR_IN6,
    canonname: Vec<u16>,
}

unsafe fn service_info_from_ansi(
    context: &mut Context,
    service: *const i8,
    hints: *const ADDRINFOA,
) -> Result<ServiceInfo, i32> {
    let default = if hints.is_null() {
        ServiceInfo {
            port: 0,
            socktype: 0,
            protocol: 0,
            flags: 0,
        }
    } else {
        let hints = unsafe { &*hints };
        ServiceInfo {
            port: 0,
            socktype: hints.ai_socktype,
            protocol: hints.ai_protocol,
            flags: hints.ai_flags,
        }
    };

    if service.is_null() {
        return Ok(default);
    }

    let service_name = unsafe { pcstr_to_string(service) }.unwrap_or_default();
    if service_name.is_empty() {
        return Ok(default);
    }

    if let Ok(port) = service_name.parse::<u16>() {
        return Ok(ServiceInfo { port, ..default });
    }

    let mut result = null_mut();
    let status = unsafe { o_getaddrinfo(context, null(), service, hints, &mut result) };
    if status != 0 {
        return Err(status);
    }

    let mut cursor = result;
    while !cursor.is_null() {
        let addr = unsafe { &*cursor };
        if let Some(port) = port_from_sockaddr(addr.ai_addr, addr.ai_addrlen) {
            unsafe {
                o_freeaddrinfo(context, result);
            }
            return Ok(ServiceInfo {
                port,
                socktype: if default.socktype == 0 {
                    addr.ai_socktype
                } else {
                    default.socktype
                },
                protocol: if default.protocol == 0 {
                    addr.ai_protocol
                } else {
                    default.protocol
                },
                flags: default.flags,
            });
        }
        cursor = addr.ai_next;
    }

    unsafe {
        o_freeaddrinfo(context, result);
    }

    Ok(default)
}

unsafe fn service_info_from_wide(
    context: &mut Context,
    service: *const u16,
    hints: *const ADDRINFOW,
) -> Result<ServiceInfo, i32> {
    let default = if hints.is_null() {
        ServiceInfo {
            port: 0,
            socktype: 0,
            protocol: 0,
            flags: 0,
        }
    } else {
        let hints = unsafe { &*hints };
        ServiceInfo {
            port: 0,
            socktype: hints.ai_socktype,
            protocol: hints.ai_protocol,
            flags: hints.ai_flags,
        }
    };

    if service.is_null() {
        return Ok(default);
    }

    let service_name = unsafe { pcwstr_to_string(service) }.unwrap_or_default();
    if service_name.is_empty() {
        return Ok(default);
    }

    if let Ok(port) = service_name.parse::<u16>() {
        return Ok(ServiceInfo { port, ..default });
    }

    let mut result = null_mut();
    let status = unsafe { o_GetAddrInfoW(context, null(), service, hints, &mut result) };
    if status != 0 {
        return Err(status);
    }

    let mut cursor = result;
    while !cursor.is_null() {
        let addr = unsafe { &*cursor };
        if let Some(port) = port_from_sockaddr(addr.ai_addr, addr.ai_addrlen) {
            unsafe {
                o_FreeAddrInfoW(context, result);
            }
            return Ok(ServiceInfo {
                port,
                socktype: if default.socktype == 0 {
                    addr.ai_socktype
                } else {
                    default.socktype
                },
                protocol: if default.protocol == 0 {
                    addr.ai_protocol
                } else {
                    default.protocol
                },
                flags: default.flags,
            });
        }
        cursor = addr.ai_next;
    }

    unsafe {
        o_FreeAddrInfoW(context, result);
    }

    Ok(default)
}

impl OwnedAddrInfoA {
    fn new(address: IpAddr, name: Option<&str>, service: ServiceInfo) -> Box<Self> {
        let mut canonname = name.unwrap_or_default().as_bytes().to_vec();
        if !canonname.is_empty() {
            canonname.push(0);
        }

        let mut node = Box::new(Self {
            addrinfo: ADDRINFOA {
                ai_flags: service.flags,
                ai_family: if address.is_ipv4() {
                    AF_INET as i32
                } else {
                    AF_INET6 as i32
                },
                ai_socktype: service.socktype,
                ai_protocol: service.protocol,
                ai_addrlen: 0,
                ai_canonname: null_mut(),
                ai_addr: null_mut(),
                ai_next: null_mut(),
            },
            sockaddr_v4: SOCKADDR_IN {
                sin_family: AF_INET,
                sin_port: 0,
                sin_addr: IN_ADDR {
                    S_un: IN_ADDR_0 {
                        S_un_b: IN_ADDR_0_0 {
                            s_b1: 0,
                            s_b2: 0,
                            s_b3: 0,
                            s_b4: 0,
                        },
                    },
                },
                sin_zero: [0; 8],
            },
            sockaddr_v6: SOCKADDR_IN6 {
                sin6_family: AF_INET6,
                sin6_port: 0,
                sin6_flowinfo: 0,
                sin6_addr: IN6_ADDR {
                    u: IN6_ADDR_0 { Byte: [0; 16] },
                },
                Anonymous: SOCKADDR_IN6_0 { sin6_scope_id: 0 },
            },
            canonname,
        });

        if !node.canonname.is_empty() {
            node.addrinfo.ai_canonname = node.canonname.as_mut_ptr();
        }

        match address {
            IpAddr::V4(ipv4) => {
                let octets = ipv4.octets();
                node.sockaddr_v4 = SOCKADDR_IN {
                    sin_family: AF_INET,
                    sin_port: service.port.to_be(),
                    sin_addr: IN_ADDR {
                        S_un: IN_ADDR_0 {
                            S_un_b: IN_ADDR_0_0 {
                                s_b1: octets[0],
                                s_b2: octets[1],
                                s_b3: octets[2],
                                s_b4: octets[3],
                            },
                        },
                    },
                    sin_zero: [0; 8],
                };
                node.addrinfo.ai_addrlen = size_of::<SOCKADDR_IN>();
                node.addrinfo.ai_addr = &mut node.sockaddr_v4 as *mut _ as *mut SOCKADDR;
            }
            IpAddr::V6(ipv6) => {
                node.sockaddr_v6 = SOCKADDR_IN6 {
                    sin6_family: AF_INET6,
                    sin6_port: service.port.to_be(),
                    sin6_flowinfo: 0,
                    sin6_addr: IN6_ADDR {
                        u: IN6_ADDR_0 {
                            Byte: ipv6.octets(),
                        },
                    },
                    Anonymous: SOCKADDR_IN6_0 { sin6_scope_id: 0 },
                };
                node.addrinfo.ai_addrlen = size_of::<SOCKADDR_IN6>();
                node.addrinfo.ai_addr = &mut node.sockaddr_v6 as *mut _ as *mut SOCKADDR;
            }
        }

        node
    }
}

impl OwnedAddrInfoW {
    fn new(address: IpAddr, name: Option<&str>, service: ServiceInfo) -> Box<Self> {
        let canonname = name.map(wide_null).unwrap_or_default();

        let mut node = Box::new(Self {
            addrinfo: ADDRINFOW {
                ai_flags: service.flags,
                ai_family: if address.is_ipv4() {
                    AF_INET as i32
                } else {
                    AF_INET6 as i32
                },
                ai_socktype: service.socktype,
                ai_protocol: service.protocol,
                ai_addrlen: 0,
                ai_canonname: null_mut(),
                ai_addr: null_mut(),
                ai_next: null_mut(),
            },
            sockaddr_v4: SOCKADDR_IN {
                sin_family: AF_INET,
                sin_port: 0,
                sin_addr: IN_ADDR {
                    S_un: IN_ADDR_0 {
                        S_un_b: IN_ADDR_0_0 {
                            s_b1: 0,
                            s_b2: 0,
                            s_b3: 0,
                            s_b4: 0,
                        },
                    },
                },
                sin_zero: [0; 8],
            },
            sockaddr_v6: SOCKADDR_IN6 {
                sin6_family: AF_INET6,
                sin6_port: 0,
                sin6_flowinfo: 0,
                sin6_addr: IN6_ADDR {
                    u: IN6_ADDR_0 { Byte: [0; 16] },
                },
                Anonymous: SOCKADDR_IN6_0 { sin6_scope_id: 0 },
            },
            canonname,
        });

        if !node.canonname.is_empty() {
            node.addrinfo.ai_canonname = node.canonname.as_mut_ptr();
        }

        match address {
            IpAddr::V4(ipv4) => {
                let octets = ipv4.octets();
                node.sockaddr_v4 = SOCKADDR_IN {
                    sin_family: AF_INET,
                    sin_port: service.port.to_be(),
                    sin_addr: IN_ADDR {
                        S_un: IN_ADDR_0 {
                            S_un_b: IN_ADDR_0_0 {
                                s_b1: octets[0],
                                s_b2: octets[1],
                                s_b3: octets[2],
                                s_b4: octets[3],
                            },
                        },
                    },
                    sin_zero: [0; 8],
                };
                node.addrinfo.ai_addrlen = size_of::<SOCKADDR_IN>();
                node.addrinfo.ai_addr = &mut node.sockaddr_v4 as *mut _ as *mut SOCKADDR;
            }
            IpAddr::V6(ipv6) => {
                node.sockaddr_v6 = SOCKADDR_IN6 {
                    sin6_family: AF_INET6,
                    sin6_port: service.port.to_be(),
                    sin6_flowinfo: 0,
                    sin6_addr: IN6_ADDR {
                        u: IN6_ADDR_0 {
                            Byte: ipv6.octets(),
                        },
                    },
                    Anonymous: SOCKADDR_IN6_0 { sin6_scope_id: 0 },
                };
                node.addrinfo.ai_addrlen = size_of::<SOCKADDR_IN6>();
                node.addrinfo.ai_addr = &mut node.sockaddr_v6 as *mut _ as *mut SOCKADDR;
            }
        }

        node
    }
}

unsafe fn build_owned_addrinfo_a(
    context: &mut Context,
    addresses: Vec<IpAddr>,
    name: &str,
    service: ServiceInfo,
    result: *mut *mut ADDRINFOA,
) -> i32 {
    if result.is_null() {
        return WSAEINVAL as i32;
    }

    let mut head = null_mut::<OwnedAddrInfoA>();
    let mut previous = null_mut::<OwnedAddrInfoA>();

    for (index, address) in addresses.into_iter().enumerate() {
        let raw = Box::into_raw(OwnedAddrInfoA::new(
            address,
            if index == 0 { Some(name) } else { None },
            service,
        ));

        if previous.is_null() {
            head = raw;
        } else {
            unsafe {
                (*previous).addrinfo.ai_next = &mut (*raw).addrinfo;
            }
        }

        previous = raw;
    }

    let root = if head.is_null() {
        null_mut()
    } else {
        unsafe { &mut (*head).addrinfo as *mut ADDRINFOA }
    };

    context.owned_addrinfo_a_roots.insert(root as usize);
    unsafe {
        *result = root;
    }
    0
}

unsafe fn build_owned_addrinfo_w(
    context: &mut Context,
    addresses: Vec<IpAddr>,
    name: &str,
    service: ServiceInfo,
    result: *mut *mut ADDRINFOW,
) -> i32 {
    if result.is_null() {
        return WSAEINVAL as i32;
    }

    let mut head = null_mut::<OwnedAddrInfoW>();
    let mut previous = null_mut::<OwnedAddrInfoW>();

    for (index, address) in addresses.into_iter().enumerate() {
        let raw = Box::into_raw(OwnedAddrInfoW::new(
            address,
            if index == 0 { Some(name) } else { None },
            service,
        ));

        if previous.is_null() {
            head = raw;
        } else {
            unsafe {
                (*previous).addrinfo.ai_next = &mut (*raw).addrinfo;
            }
        }

        previous = raw;
    }

    let root = if head.is_null() {
        null_mut()
    } else {
        unsafe { &mut (*head).addrinfo as *mut ADDRINFOW }
    };

    context.owned_addrinfow_roots.insert(root as usize);
    unsafe {
        *result = root;
    }
    0
}

unsafe fn free_owned_addrinfo_a(root: *const ADDRINFOA) {
    let mut cursor = root as *mut ADDRINFOA;
    while !cursor.is_null() {
        let next = unsafe { (*cursor).ai_next };
        unsafe {
            drop(Box::from_raw(cursor as *mut OwnedAddrInfoA));
        }
        cursor = next;
    }
}

unsafe fn free_owned_addrinfo_w(root: *const ADDRINFOW) {
    let mut cursor = root as *mut ADDRINFOW;
    while !cursor.is_null() {
        let next = unsafe { (*cursor).ai_next };
        unsafe {
            drop(Box::from_raw(cursor as *mut OwnedAddrInfoW));
        }
        cursor = next;
    }
}

fn try_free_owned_addrinfo_alias_in_context(context: &mut Context, root: usize) -> bool {
    let was_owned_a = context.owned_addrinfo_a_roots.remove(&root);
    if was_owned_a {
        unsafe {
            free_owned_addrinfo_a(root as *const ADDRINFOA);
        }
        return true;
    }

    let was_owned_w = context.owned_addrinfow_roots.remove(&root);
    if was_owned_w {
        unsafe {
            free_owned_addrinfo_w(root as *const ADDRINFOW);
        }
        return true;
    }

    false
}

fn align_up(value: usize, align: usize) -> usize {
    (value + (align - 1)) & !(align - 1)
}

fn async_hostent_size(name: &str) -> usize {
    let pointer_align = align_of::<*mut i8>();
    let mut offset = size_of::<HOSTENT>();
    offset = align_up(offset, pointer_align);
    offset += size_of::<*mut i8>();
    offset = align_up(offset, pointer_align);
    offset += 2 * size_of::<*mut i8>();
    offset += name.len() + 1;
    offset += 4;
    offset
}

unsafe fn write_async_hostent(
    buffer: *mut u8,
    buffer_len: usize,
    name: &str,
    address: Ipv4Addr,
) -> Result<(), usize> {
    let required = async_hostent_size(name);
    if buffer_len < required {
        return Err(required);
    }

    let pointer_align = align_of::<*mut i8>();
    let mut offset = size_of::<HOSTENT>();

    offset = align_up(offset, pointer_align);
    let aliases = unsafe { buffer.add(offset) as *mut *mut i8 };
    unsafe {
        *aliases = null_mut();
    }
    offset += size_of::<*mut i8>();

    offset = align_up(offset, pointer_align);
    let addr_list = unsafe { buffer.add(offset) as *mut *mut i8 };
    offset += 2 * size_of::<*mut i8>();

    let name_ptr = unsafe { buffer.add(offset) };
    unsafe {
        copy_nonoverlapping(name.as_ptr(), name_ptr, name.len());
        *name_ptr.add(name.len()) = 0;
    }
    offset += name.len() + 1;

    let addr_ptr = unsafe { buffer.add(offset) };
    let octets = address.octets();
    unsafe {
        copy_nonoverlapping(octets.as_ptr(), addr_ptr, octets.len());
        *addr_list = addr_ptr as *mut i8;
        *addr_list.add(1) = null_mut();
    }

    let hostent = HOSTENT {
        h_name: name_ptr,
        h_aliases: aliases,
        h_addrtype: AF_INET as i16,
        h_length: 4,
        h_addr_list: addr_list,
    };
    unsafe {
        write_unaligned(buffer as *mut HOSTENT, hostent);
    }

    Ok(())
}

fn async_lparam(error_code: i32, buffer_len: usize) -> isize {
    ((((error_code as u32) & 0xFFFF) << 16) | ((buffer_len as u32) & 0xFFFF)) as isize
}

unsafe fn post_async_dns_completion(
    hwnd: HWND,
    message: u32,
    task_handle: HANDLE,
    error_code: i32,
    required_buffer_len: usize,
) -> bool {
    unsafe {
        PostMessageW(
            hwnd,
            message,
            task_handle as usize,
            async_lparam(error_code, required_buffer_len),
        ) != 0
    }
}

unsafe fn o_gethostbyname(context: &mut Context, name: *const i8) -> *mut HOSTENT {
    let Some(fptr) = cached_trampoline(
        context,
        &FPTR_O_GETHOSTBYNAME,
        hooked_gethostbyname as u64,
        "gethostbyname",
    ) else {
        return unsafe { gethostbyname(name as *const u8) };
    };

    let original: unsafe extern "system" fn(*const i8) -> *mut HOSTENT =
        unsafe { mem::transmute(fptr) };
    unsafe { original(name) }
}

#[allow(non_snake_case)]
unsafe fn o_WSAAsyncGetHostByName(
    context: &mut Context,
    hwnd: HWND,
    message: u32,
    name: *const i8,
    buffer: *mut i8,
    buffer_len: i32,
) -> HANDLE {
    let Some(fptr) = cached_trampoline(
        context,
        &FPTR_O_WSA_ASYNC_GET_HOST_BY_NAME,
        hooked_WSAAsyncGetHostByName as u64,
        "WSAAsyncGetHostByName",
    ) else {
        return unsafe {
            WSAAsyncGetHostByName(
                hwnd,
                message,
                name as *const u8,
                buffer as *mut u8,
                buffer_len,
            )
        };
    };

    let original: unsafe extern "system" fn(HWND, u32, *const i8, *mut i8, i32) -> HANDLE =
        unsafe { mem::transmute(fptr) };
    unsafe { original(hwnd, message, name, buffer, buffer_len) }
}

unsafe fn o_getaddrinfo(
    context: &mut Context,
    node_name: *const i8,
    service_name: *const i8,
    hints: *const ADDRINFOA,
    result: *mut *mut ADDRINFOA,
) -> i32 {
    let Some(fptr) = cached_trampoline(
        context,
        &FPTR_O_GETADDRINFO,
        hooked_getaddrinfo as u64,
        "getaddrinfo",
    ) else {
        return unsafe {
            getaddrinfo(
                node_name as *const u8,
                service_name as *const u8,
                hints,
                result,
            )
        };
    };

    let original: unsafe extern "system" fn(
        *const i8,
        *const i8,
        *const ADDRINFOA,
        *mut *mut ADDRINFOA,
    ) -> i32 = unsafe { mem::transmute(fptr) };
    unsafe { original(node_name, service_name, hints, result) }
}

unsafe fn o_freeaddrinfo(context: &mut Context, result: *const ADDRINFOA) {
    let Some(fptr) = cached_trampoline(
        context,
        &FPTR_O_FREEADDRINFO,
        hooked_freeaddrinfo as u64,
        "freeaddrinfo",
    ) else {
        unsafe {
            freeaddrinfo(result);
        }
        return;
    };

    let original: unsafe extern "system" fn(*const ADDRINFOA) =
        unsafe { mem::transmute(fptr) };
    unsafe { original(result) }
}

#[allow(non_snake_case)]
pub unsafe fn o_GetAddrInfoW(
    context: &mut Context,
    node_name: *const u16,
    service_name: *const u16,
    hints: *const ADDRINFOW,
    result: *mut *mut ADDRINFOW,
) -> i32 {
    let Some(fptr) = cached_trampoline(
        context,
        &FPTR_O_GET_ADDR_INFOW,
        hooked_GetAddrInfoW as u64,
        "GetAddrInfoW",
    ) else {
        return unsafe { GetAddrInfoW(node_name, service_name, hints, result) };
    };

    let original: unsafe extern "system" fn(
        *const u16,
        *const u16,
        *const ADDRINFOW,
        *mut *mut ADDRINFOW,
    ) -> i32 = unsafe { mem::transmute(fptr) };
    unsafe { original(node_name, service_name, hints, result) }
}

#[allow(non_snake_case)]
pub unsafe fn o_FreeAddrInfoW(context: &mut Context, result: *const ADDRINFOW) {
    let Some(fptr) = cached_trampoline(
        context,
        &FPTR_O_FREE_ADDR_INFOW,
        hooked_FreeAddrInfoW as u64,
        "FreeAddrInfoW",
    ) else {
        unsafe {
            FreeAddrInfoW(result);
        }
        return;
    };

    let original: unsafe extern "system" fn(*const ADDRINFOW) =
        unsafe { mem::transmute(fptr) };
    unsafe { original(result) }
}

#[unsafe(no_mangle)]
pub unsafe extern "system" fn hooked_gethostbyname(name: *const i8) -> *mut HOSTENT {
    let mut context = lock_context();
    let Some(name_string) = (unsafe { pcstr_to_string(name) }) else {
        return unsafe { o_gethostbyname(&mut context, name) };
    };
    trace::log(format!("hooked_gethostbyname name={name_string}"));

    let Some(addresses) = cached_or_allocate_fake_dns_entries(&mut context, &name_string) else {
        trace::log(format!(
            "hooked_gethostbyname passthrough name={name_string}"
        ));
        return unsafe { o_gethostbyname(&mut context, name) };
    };

    let Some(ipv4) = addresses.into_iter().find_map(|address| match address {
        IpAddr::V4(ipv4) => Some(ipv4),
        IpAddr::V6(_) => None,
    }) else {
        unsafe {
            WSASetLastError(WSANO_DATA as i32);
        }
        trace::log(format!(
            "hooked_gethostbyname no_ipv4_mapping name={name_string}"
        ));
        return null_mut();
    };
    trace::log(format!(
        "hooked_gethostbyname fabricated name={name_string} ipv4={ipv4}"
    ));

    populate_thread_hostent_storage(&mut context, &name_string, ipv4)
}

#[unsafe(no_mangle)]
pub unsafe extern "system" fn hooked_WSAAsyncGetHostByName(
    hwnd: HWND,
    message: u32,
    name: *const i8,
    buffer: *mut i8,
    buffer_len: i32,
) -> HANDLE {
    let mut context = lock_context();
    let Some(name_string) = (unsafe { pcstr_to_string(name) }) else {
        return unsafe {
            o_WSAAsyncGetHostByName(&mut context, hwnd, message, name, buffer, buffer_len)
        };
    };
    trace::log(format!(
        "hooked_WSAAsyncGetHostByName name={} buffer={buffer:p} buffer_len={}",
        name_string, buffer_len
    ));

    let Some(addresses) = cached_or_allocate_fake_dns_entries(&mut context, &name_string) else {
        trace::log(format!(
            "hooked_WSAAsyncGetHostByName passthrough name={name_string}"
        ));
        return unsafe {
            o_WSAAsyncGetHostByName(&mut context, hwnd, message, name, buffer, buffer_len)
        };
    };

    if buffer.is_null() || buffer_len < 0 {
        unsafe {
            WSASetLastError(WSAEINVAL as i32);
        }
        return null_mut();
    }

    let task_handle = NEXT_ASYNC_TASK_HANDLE.fetch_add(1, Ordering::SeqCst) as HANDLE;
    let Some(ipv4) = addresses.into_iter().find_map(|address| match address {
        IpAddr::V4(ipv4) => Some(ipv4),
        IpAddr::V6(_) => None,
    }) else {
        trace::log(format!(
            "hooked_WSAAsyncGetHostByName no_ipv4_mapping name={name_string}"
        ));
        if !unsafe { post_async_dns_completion(hwnd, message, task_handle, WSANO_DATA as i32, 0) } {
            unsafe {
                WSASetLastError(WSAEINVAL as i32);
            }
            return null_mut();
        }
        unsafe {
            WSASetLastError(0);
        }
        return task_handle;
    };

    match unsafe { write_async_hostent(buffer as *mut u8, buffer_len as usize, &name_string, ipv4) }
    {
        Ok(()) => {
            trace::log(format!(
                "hooked_WSAAsyncGetHostByName fabricated name={} ipv4={} task_handle={:#x}",
                name_string, ipv4, task_handle as usize
            ));
            if !unsafe { post_async_dns_completion(hwnd, message, task_handle, 0, 0) } {
                unsafe {
                    WSASetLastError(WSAEINVAL as i32);
                }
                return null_mut();
            }
        }
        Err(required_size) => {
            if !unsafe {
                post_async_dns_completion(
                    hwnd,
                    message,
                    task_handle,
                    WSAENOBUFS as i32,
                    required_size,
                )
            } {
                unsafe {
                    WSASetLastError(WSAEINVAL as i32);
                }
                return null_mut();
            }
        }
    }

    unsafe {
        WSASetLastError(0);
    }
    task_handle
}

#[unsafe(no_mangle)]
pub unsafe extern "system" fn hooked_getaddrinfo(
    node_name: *const i8,
    service_name: *const i8,
    hints: *const ADDRINFOA,
    result: *mut *mut ADDRINFOA,
) -> i32 {
    let mut context = lock_context();
    let Some(name_string) = (unsafe { pcstr_to_string(node_name) }) else {
        return unsafe { o_getaddrinfo(&mut context, node_name, service_name, hints, result) };
    };
    trace::log(format!("hooked_getaddrinfo node={name_string}"));

    let requested_family = if hints.is_null() {
        AF_UNSPEC as i32
    } else {
        unsafe { (*hints).ai_family }
    };
    if !matches!(
        requested_family,
        family if family == AF_UNSPEC as i32 || family == AF_INET as i32 || family == AF_INET6 as i32
    ) {
        trace::log(format!(
            "hooked_getaddrinfo passthrough node={} family={requested_family}",
            name_string
        ));
        return unsafe { o_getaddrinfo(&mut context, node_name, service_name, hints, result) };
    }

    let Some(addresses) = cached_or_allocate_fake_dns_entries(&mut context, &name_string) else {
        trace::log(format!("hooked_getaddrinfo passthrough node={name_string}"));
        return unsafe { o_getaddrinfo(&mut context, node_name, service_name, hints, result) };
    };

    let filtered = filter_fake_dns_addresses(addresses, requested_family);
    if filtered.is_empty() {
        trace::log(format!(
            "hooked_getaddrinfo no_filtered_addresses node={} family={requested_family}",
            name_string
        ));
        if !result.is_null() {
            unsafe {
                *result = null_mut();
            }
        }
        return WSANO_DATA as i32;
    }

    let service = match unsafe { service_info_from_ansi(&mut context, service_name, hints) } {
        Ok(service) => service,
        Err(status) => {
            if !result.is_null() {
                unsafe {
                    *result = null_mut();
                }
            }
            return status;
        }
    };

    trace::log(format!(
        "hooked_getaddrinfo fabricated node={} family={} result_ptr={result:p} count={}",
        name_string,
        requested_family,
        filtered.len()
    ));
    unsafe { build_owned_addrinfo_a(&mut context, filtered, &name_string, service, result) }
}

#[unsafe(no_mangle)]
pub unsafe extern "system" fn hooked_GetAddrInfoW(
    node_name: *const u16,
    service_name: *const u16,
    hints: *const ADDRINFOW,
    result: *mut *mut ADDRINFOW,
) -> i32 {
    let mut context = lock_context();
    let Some(name_string) = (unsafe { pcwstr_to_string(node_name) }) else {
        return unsafe { o_GetAddrInfoW(&mut context, node_name, service_name, hints, result) };
    };
    trace::log(format!("hooked_GetAddrInfoW node={name_string}"));

    let requested_family = if hints.is_null() {
        AF_UNSPEC as i32
    } else {
        unsafe { (*hints).ai_family }
    };
    if !matches!(
        requested_family,
        family if family == AF_UNSPEC as i32 || family == AF_INET as i32 || family == AF_INET6 as i32
    ) {
        trace::log(format!(
            "hooked_GetAddrInfoW passthrough node={} family={requested_family}",
            name_string
        ));
        return unsafe { o_GetAddrInfoW(&mut context, node_name, service_name, hints, result) };
    }

    let Some(addresses) = cached_or_allocate_fake_dns_entries(&mut context, &name_string) else {
        trace::log(format!(
            "hooked_GetAddrInfoW passthrough node={name_string}"
        ));
        return unsafe { o_GetAddrInfoW(&mut context, node_name, service_name, hints, result) };
    };

    let filtered = filter_fake_dns_addresses(addresses, requested_family);
    if filtered.is_empty() {
        trace::log(format!(
            "hooked_GetAddrInfoW no_filtered_addresses node={} family={requested_family}",
            name_string
        ));
        if !result.is_null() {
            unsafe {
                *result = null_mut();
            }
        }
        return WSANO_DATA as i32;
    }

    let service = match unsafe { service_info_from_wide(&mut context, service_name, hints) } {
        Ok(service) => service,
        Err(status) => {
            if !result.is_null() {
                unsafe {
                    *result = null_mut();
                }
            }
            return status;
        }
    };

    trace::log(format!(
        "hooked_GetAddrInfoW fabricated node={} family={} result_ptr={result:p} count={}",
        name_string,
        requested_family,
        filtered.len()
    ));
    unsafe { build_owned_addrinfo_w(&mut context, filtered, &name_string, service, result) }
}

#[unsafe(no_mangle)]
pub unsafe extern "system" fn hooked_freeaddrinfo(result: *const ADDRINFOA) {
    let mut context = lock_context();
    if result.is_null() {
        return;
    }

    let root = result as usize;
    let was_owned = try_free_owned_addrinfo_alias_in_context(&mut context, root);
    trace::log(format!(
        "hooked_freeaddrinfo result={result:p} owned={was_owned}"
    ));
    if was_owned {
        return;
    }

    unsafe {
        o_freeaddrinfo(&mut context, result);
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "system" fn hooked_FreeAddrInfoW(result: *const ADDRINFOW) {
    let mut context = lock_context();
    if result.is_null() {
        return;
    }

    let root = result as usize;
    let was_owned = try_free_owned_addrinfo_alias_in_context(&mut context, root);
    trace::log(format!(
        "hooked_FreeAddrInfoW result={result:p} owned={was_owned}"
    ));
    if was_owned {
        return;
    }

    unsafe {
        o_FreeAddrInfoW(&mut context, result);
    }
}

#[cfg(all(test, target_arch = "x86_64"))]
mod tests {
    use super::{
        MAX_FAKE_IPV4_REQUESTS, async_hostent_size, cached_or_allocate_fake_dns_entries,
        reverse_fake_dns_name, write_async_hostent,
    };
    use crate::lock_context;
    use std::{
        ffi::CStr,
        net::{IpAddr, Ipv4Addr, Ipv6Addr},
        ptr::null_mut,
        sync::Mutex,
        string::ToString,
        vec,
    };
    use windows_sys::Win32::Networking::WinSock::HOSTENT;

    static TEST_MUTEX: Mutex<()> = Mutex::new(());

    fn lock_tests() -> std::sync::MutexGuard<'static, ()> {
        TEST_MUTEX
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn reset_dns_state() {
        let mut context = lock_context();
        context.ipv4_fake_counter = 0;
        context.ipv6_fake_counter = 0;
        context
            .dns_cache
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clear();
        context
            .reverse_dns_cache
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clear();
        context.owned_addrinfo_a_roots.clear();
        context.owned_addrinfow_roots.clear();
        context.config = Some(
            crate::config::ProxychainsConfig::parse(
                "strict_chain\nproxy_dns\nremote_dns_subnet 224\nremote_dns_subnet_6 252\n[ProxyList]\nsocks5 127.0.0.1 1080\n",
            )
            .expect("test config should parse"),
        );
    }

    #[test]
    fn fake_dns_lookup_caches_forward_and_reverse_entries() {
        let _guard = lock_tests();
        reset_dns_state();
        let mut context = lock_context();

        let first = cached_or_allocate_fake_dns_entries(&mut context, "example.com")
            .expect("proxy_dns should fabricate a mapping");
        let second = cached_or_allocate_fake_dns_entries(&mut context, "example.com")
            .expect("cached lookup should succeed");

        assert_eq!(first, second);
        assert_eq!(
            first,
            vec![
                IpAddr::V4(Ipv4Addr::new(224, 0, 0, 1)),
                IpAddr::V6(Ipv6Addr::from(((252u128) << 120 | 1).to_be_bytes())),
            ]
        );
        assert_eq!(
            reverse_fake_dns_name(&context, "224.0.0.1").as_deref(),
            Some("example.com")
        );
        assert_eq!(
            reverse_fake_dns_name(&context, "fc00::1").as_deref(),
            Some("example.com")
        );
    }

    #[test]
    fn fake_dns_lookup_drops_ipv4_after_counter_exhaustion() {
        let _guard = lock_tests();
        reset_dns_state();

        let mut context = lock_context();
        context.ipv4_fake_counter = MAX_FAKE_IPV4_REQUESTS;

        let addresses = cached_or_allocate_fake_dns_entries(&mut context, "ipv6-only.example")
            .expect("proxy_dns should still fabricate IPv6 mappings");

        assert_eq!(addresses.len(), 1);
        assert!(matches!(addresses[0], IpAddr::V6(_)));
        assert_eq!(
            reverse_fake_dns_name(&context, &addresses[0].to_string()).as_deref(),
            Some("ipv6-only.example")
        );
    }

    #[test]
    fn async_hostent_writer_packs_hostent_into_caller_buffer() {
        let _guard = lock_tests();
        let name = "example.com";
        let required = async_hostent_size(name);
        let mut buffer = vec![0u8; required];

        unsafe {
            write_async_hostent(
                buffer.as_mut_ptr(),
                buffer.len(),
                name,
                Ipv4Addr::new(1, 2, 3, 4),
            )
            .expect("buffer should be large enough");
        }

        let hostent = unsafe { &*(buffer.as_ptr() as *const HOSTENT) };
        assert_eq!(hostent.h_addrtype, super::AF_INET as i16);
        assert_eq!(hostent.h_length, 4);
        assert_eq!(
            unsafe { CStr::from_ptr(hostent.h_name as *const i8) }
                .to_str()
                .expect("host name should be valid utf-8"),
            name
        );
        let addr_list = hostent.h_addr_list;
        assert!(!addr_list.is_null());
        assert!(unsafe { *addr_list.add(1) }.is_null());
        let addr = unsafe { std::slice::from_raw_parts(*addr_list as *const u8, 4) };
        assert_eq!(addr, &[1, 2, 3, 4]);
    }

    #[test]
    fn owned_addrinfo_roots_live_in_context() {
        let _guard = lock_tests();
        reset_dns_state();

        let mut context = lock_context();
        let service = super::ServiceInfo {
            port: 443,
            socktype: 0,
            protocol: 0,
            flags: 0,
        };
        let mut result_a = null_mut();
        let mut result_w = null_mut();

        unsafe {
            assert_eq!(
                super::build_owned_addrinfo_a(
                    &mut context,
                    vec![IpAddr::V4(Ipv4Addr::new(224, 0, 0, 1))],
                    "example.com",
                    service,
                    &mut result_a,
                ),
                0
            );
            assert_eq!(
                super::build_owned_addrinfo_w(
                    &mut context,
                    vec![IpAddr::V6(Ipv6Addr::LOCALHOST)],
                    "example.com",
                    service,
                    &mut result_w,
                ),
                0
            );
        }

        assert!(context.owned_addrinfo_a_roots.contains(&(result_a as usize)));
        assert!(context.owned_addrinfow_roots.contains(&(result_w as usize)));

        assert!(super::try_free_owned_addrinfo_alias_in_context(
            &mut context,
            result_a as usize,
        ));
        assert!(super::try_free_owned_addrinfo_alias_in_context(
            &mut context,
            result_w as usize,
        ));

        assert!(context.owned_addrinfo_a_roots.is_empty());
        assert!(context.owned_addrinfow_roots.is_empty());
    }
}
