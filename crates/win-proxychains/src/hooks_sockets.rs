use std::{
    ffi::c_void,
    mem::{size_of, size_of_val},
    ptr::{copy_nonoverlapping, null_mut},
    sync::atomic::AtomicU64,
};

use windows_sys::{
    Win32::{
        Foundation::{HANDLE, HWND, INVALID_HANDLE_VALUE},
        Networking::WinSock::{
            FD_CONNECT, FIONBIO, LPFN_CONNECTEX, SIO_GET_EXTENSION_FUNCTION_POINTER,
            SO_UPDATE_CONNECT_CONTEXT, SOCKADDR, SOCKET, SOL_SOCKET, WSA_IO_PENDING, WSABUF,
            WSAECONNABORTED, WSAEFAULT, WSAENOTSOCK, WSAEWOULDBLOCK, WSAGetLastError,
            WSAID_CONNECTEX, WSASetLastError, send,
        },
        System::{
            IO::{OVERLAPPED, PostQueuedCompletionStatus},
            Threading::SetEvent,
        },
    },
    core::BOOL,
};

use anyhow::Result;

use crate::{
    AsyncSelectState, EventSelectState, IocpAssociationState, SocketConnectContract,
    SyntheticConnectExState, get_context, set_last_error, socks::wrap_socket_in_requested_chain,
};

static FPTR_O_CONNECT: AtomicU64 = AtomicU64::new(0);
static FPTR_O_IOCTLSOCKET: AtomicU64 = AtomicU64::new(0);
static FPTR_O_WSA_EVENT_SELECT: AtomicU64 = AtomicU64::new(0);
static FPTR_O_WSA_ASYNC_SELECT: AtomicU64 = AtomicU64::new(0);
static FPTR_O_WSA_IOCTL: AtomicU64 = AtomicU64::new(0);
static FPTR_O_CREATE_IO_COMPLETION_PORT: AtomicU64 = AtomicU64::new(0);
static FPTR_O_WSA_GET_OVERLAPPED_RESULT: AtomicU64 = AtomicU64::new(0);
static FPTR_O_SETSOCKOPT: AtomicU64 = AtomicU64::new(0);
static FPTR_O_CLOSESOCKET: AtomicU64 = AtomicU64::new(0);

fn cached_trampoline(cache: &AtomicU64, target: u64, function_name: &str) -> Option<u64> {
    let mut trampoline = cache.load(std::sync::atomic::Ordering::SeqCst);
    if trampoline != 0 {
        return Some(trampoline);
    }

    let context = get_context();
    let hook = context.hooks.iter().find(|hook| hook.target == target);
    let Some(hook) = hook else {
        set_last_error(format!("Failed to find hook context for {function_name}"));
        return None;
    };

    trampoline = hook.trampoline();
    cache.store(trampoline, std::sync::atomic::Ordering::SeqCst);
    Some(trampoline)
}

fn with_socket_states<R>(
    f: impl FnOnce(&mut std::collections::HashMap<usize, crate::SocketRuntimeState>) -> R,
) -> R {
    let context = get_context();
    let mut socket_states = context
        .socket_states
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    f(&mut socket_states)
}

fn reset_socket_connect_tracking(socket: usize) {
    with_socket_states(|socket_states| {
        let state = socket_states.entry(socket).or_default();
        state.synthetic_connectex = None;
        state.allow_update_connect_context = false;
    });
}

fn record_socket_nonblocking(socket: usize, nonblocking: bool) {
    with_socket_states(|socket_states| {
        let state = socket_states.entry(socket).or_default();
        state.nonblocking = nonblocking;
    });
}

fn record_socket_event_select(socket: usize, event_handle: HANDLE, network_events: i32) {
    with_socket_states(|socket_states| {
        let state = socket_states.entry(socket).or_default();
        if event_handle.is_null() || network_events == 0 {
            state.event_select = None;
        } else {
            state.event_select = Some(EventSelectState {
                event_handle: event_handle as usize,
                network_events,
            });
            state.nonblocking = true;
        }
    });
}

fn record_socket_async_select(
    socket: usize,
    window_handle: HWND,
    message_id: u32,
    network_events: i32,
) {
    with_socket_states(|socket_states| {
        let state = socket_states.entry(socket).or_default();
        if window_handle.is_null() || network_events == 0 {
            state.async_select = None;
        } else {
            state.async_select = Some(AsyncSelectState {
                window_handle: window_handle as usize,
                message_id,
                network_events,
            });
            state.nonblocking = true;
        }
    });
}

fn socket_connect_contract(socket: usize) -> SocketConnectContract {
    with_socket_states(|socket_states| {
        let Some(state) = socket_states.get(&socket) else {
            return SocketConnectContract::Blocking;
        };

        let wants_event_connect = state
            .event_select
            .map(|state| state.network_events & FD_CONNECT as i32 != 0)
            .unwrap_or(false)
            || state
                .async_select
                .map(|state| state.network_events & FD_CONNECT as i32 != 0)
                .unwrap_or(false);

        if wants_event_connect {
            SocketConnectContract::EventAsync
        } else if state.nonblocking {
            SocketConnectContract::NonBlockingPoll
        } else {
            SocketConnectContract::Blocking
        }
    })
}

fn record_socket_iocp_association(socket: usize, completion_port: HANDLE, completion_key: usize) {
    with_socket_states(|socket_states| {
        let state = socket_states.entry(socket).or_default();
        state.iocp_association = Some(IocpAssociationState {
            completion_port: completion_port as usize,
            completion_key,
        });
    });
}

fn socket_iocp_association(socket: usize) -> Option<IocpAssociationState> {
    with_socket_states(|socket_states| {
        socket_states
            .get(&socket)
            .and_then(|state| state.iocp_association)
    })
}

fn record_synthetic_connectex(socket: usize, overlapped: *mut OVERLAPPED, bytes_sent: u32) {
    with_socket_states(|socket_states| {
        let state = socket_states.entry(socket).or_default();
        state.allow_update_connect_context = true;
        state.synthetic_connectex = Some(SyntheticConnectExState {
            overlapped: overlapped as usize,
            bytes_sent,
            error: 0,
            completed: true,
        });
    });
}

fn synthetic_connectex(
    socket: usize,
    overlapped: *mut OVERLAPPED,
) -> Option<SyntheticConnectExState> {
    with_socket_states(|socket_states| {
        socket_states.get(&socket).and_then(|state| {
            state
                .synthetic_connectex
                .filter(|synthetic| synthetic.overlapped == overlapped as usize)
        })
    })
}

fn clear_synthetic_connectex(socket: usize, overlapped: *mut OVERLAPPED) -> bool {
    with_socket_states(|socket_states| {
        let Some(state) = socket_states.get_mut(&socket) else {
            return false;
        };

        let Some(synthetic) = state.synthetic_connectex else {
            return false;
        };

        if synthetic.overlapped != overlapped as usize {
            return false;
        }

        state.synthetic_connectex = None;
        true
    })
}

fn socket_allows_connect_context_update(socket: usize) -> bool {
    with_socket_states(|socket_states| {
        socket_states
            .get(&socket)
            .map(|state| state.allow_update_connect_context)
            .unwrap_or(false)
    })
}

fn remove_socket_state(socket: usize) {
    with_socket_states(|socket_states| {
        socket_states.remove(&socket);
    });
}

fn bail_with_wsa_error<T>(message: impl std::fmt::Display) -> Result<T> {
    let error_code = unsafe { WSAGetLastError() };
    let full_message = format!("{message}: WSA error {error_code}");
    set_last_error(full_message.clone());
    Err(anyhow::anyhow!(full_message))
}

fn set_wsa_error(message: impl Into<String>, code: i32) {
    set_last_error(message.into());
    unsafe {
        WSASetLastError(code);
    }
}

fn set_proxy_connect_error() {
    let last_error = get_context().last_error.clone();
    let error_code = if last_error.contains("sample proxy chain") {
        WSAECONNABORTED as i32
    } else {
        WSAEFAULT as i32
    };
    set_wsa_error(last_error, error_code);
}

fn connect_success_result(contract: SocketConnectContract) -> (i32, i32) {
    match contract {
        SocketConnectContract::Blocking => (0, 0),
        SocketConnectContract::NonBlockingPoll | SocketConnectContract::EventAsync => {
            (-1, WSAEWOULDBLOCK as i32)
        }
    }
}

fn proxy_connect_socket(socket: SOCKET, address: *const SOCKADDR, address_len: i32) -> Result<()> {
    let context = get_context();
    let Some(config) = context.config.as_ref() else {
        let message = "No config found in context for connect hook".to_string();
        set_last_error(message.clone());
        return Err(anyhow::anyhow!(message));
    };

    let (top_level_name, top_level_port, chain) = match config.sample_chain(address, address_len) {
        Ok(chain) => chain,
        Err(error) => {
            let message = format!("Failed to sample proxy chain: {error:#}");
            set_last_error(message.clone());
            return Err(anyhow::anyhow!(message));
        }
    };

    wrap_socket_in_requested_chain(
        &top_level_name,
        top_level_port,
        socket as u32,
        config.tcp_read_time_out,
        config.tcp_connect_time_out,
        &chain,
        config.chain_type == crate::config::ChainType::Dynamic,
    )
    .map_err(|error| {
        let message = format!("Failed to wrap socket in requested proxy chain: {error:#}");
        set_last_error(message.clone());
        anyhow::anyhow!(message)
    })
}

fn send_connectex_payload(socket: SOCKET, buffer: *const c_void, buffer_len: u32) -> Result<u32> {
    if buffer.is_null() {
        return Ok(0);
    }

    let payload = unsafe { std::slice::from_raw_parts(buffer as *const u8, buffer_len as usize) };
    let mut sent = 0usize;

    while sent < payload.len() {
        let send_result = unsafe {
            send(
                socket,
                payload[sent..].as_ptr(),
                (payload.len() - sent) as i32,
                0,
            )
        };

        if send_result == -1 {
            return bail_with_wsa_error("ConnectEx payload send failed");
        }

        if send_result == 0 {
            return Err(anyhow::anyhow!(
                "ConnectEx payload send returned zero before the buffer was fully written"
            ));
        }

        sent += send_result as usize;
    }

    Ok(sent as u32)
}

fn raw_overlapped_event(overlapped: *mut OVERLAPPED) -> usize {
    if overlapped.is_null() {
        0
    } else {
        unsafe { (*overlapped).hEvent as usize }
    }
}

fn notify_synthetic_connectex_completion(
    socket: SOCKET,
    overlapped: *mut OVERLAPPED,
    bytes_sent: u32,
) -> bool {
    record_synthetic_connectex(socket, overlapped, bytes_sent);

    let raw_event = raw_overlapped_event(overlapped);
    let suppress_iocp = raw_event & 1 != 0;
    let event = (raw_event & !1) as HANDLE;
    let mut notified = false;

    if !suppress_iocp {
        if let Some(iocp) = socket_iocp_association(socket) {
            let posted = unsafe {
                PostQueuedCompletionStatus(
                    iocp.completion_port as HANDLE,
                    bytes_sent,
                    iocp.completion_key,
                    overlapped,
                )
            };
            if posted != 0 {
                notified = true;
            }
        }
    }

    if event != null_mut() && unsafe { SetEvent(event) } != 0 {
        notified = true;
    }

    notified
}

#[cfg(test)]
pub(crate) fn set_o_connect_for_tests(
    fptr: unsafe extern "system" fn(
        usize,
        *const windows_sys::Win32::Networking::WinSock::SOCKADDR,
        i32,
    ) -> i32,
) {
    FPTR_O_CONNECT.store(fptr as usize as u64, std::sync::atomic::Ordering::SeqCst);
}

#[cfg(test)]
pub(crate) fn reset_o_connect_for_tests() {
    FPTR_O_CONNECT.store(0, std::sync::atomic::Ordering::SeqCst);
}

pub unsafe fn o_connect(socket: SOCKET, address: *const SOCKADDR, address_len: i32) -> i32 {
    let Some(fptr) = cached_trampoline(&FPTR_O_CONNECT, hooked_connect as u64, "connect") else {
        return -1;
    };

    let original: unsafe extern "system" fn(SOCKET, *const SOCKADDR, i32) -> i32 =
        unsafe { std::mem::transmute(fptr) };

    unsafe { original(socket, address, address_len) }
}

unsafe fn o_ioctlsocket(socket: SOCKET, cmd: i32, argp: *mut u32) -> i32 {
    let Some(fptr) = cached_trampoline(
        &FPTR_O_IOCTLSOCKET,
        hooked_ioctlsocket as u64,
        "ioctlsocket",
    ) else {
        unsafe {
            WSASetLastError(WSAEFAULT as i32);
        }
        return -1;
    };

    let original: unsafe extern "system" fn(SOCKET, i32, *mut u32) -> i32 =
        unsafe { std::mem::transmute(fptr) };

    unsafe { original(socket, cmd, argp) }
}

unsafe fn o_wsa_event_select(socket: SOCKET, event_object: HANDLE, network_events: i32) -> i32 {
    let Some(fptr) = cached_trampoline(
        &FPTR_O_WSA_EVENT_SELECT,
        hooked_WSAEventSelect as u64,
        "WSAEventSelect",
    ) else {
        unsafe {
            WSASetLastError(WSAEFAULT as i32);
        }
        return -1;
    };

    let original: unsafe extern "system" fn(SOCKET, HANDLE, i32) -> i32 =
        unsafe { std::mem::transmute(fptr) };

    unsafe { original(socket, event_object, network_events) }
}

unsafe fn o_wsa_async_select(
    socket: SOCKET,
    window_handle: HWND,
    message_id: u32,
    network_events: i32,
) -> i32 {
    let Some(fptr) = cached_trampoline(
        &FPTR_O_WSA_ASYNC_SELECT,
        hooked_WSAAsyncSelect as u64,
        "WSAAsyncSelect",
    ) else {
        unsafe {
            WSASetLastError(WSAEFAULT as i32);
        }
        return -1;
    };

    let original: unsafe extern "system" fn(SOCKET, HWND, u32, i32) -> i32 =
        unsafe { std::mem::transmute(fptr) };

    unsafe { original(socket, window_handle, message_id, network_events) }
}

#[unsafe(no_mangle)]
pub unsafe extern "system" fn hooked_connect(
    socket: SOCKET,
    address: *const SOCKADDR,
    address_len: i32,
) -> i32 {
    reset_socket_connect_tracking(socket);

    if proxy_connect_socket(socket, address, address_len).is_err() {
        set_proxy_connect_error();
        return -1;
    }

    let (result, error_code) = connect_success_result(socket_connect_contract(socket));
    unsafe { WSASetLastError(error_code) };
    result
}

#[unsafe(no_mangle)]
pub unsafe extern "system" fn hooked_WSAConnect(
    socket: SOCKET,
    name: *const SOCKADDR,
    name_len: i32,
    _caller_data: *const WSABUF,
    _callee_data: *mut WSABUF,
    _sqos: *mut windows_sys::Win32::Networking::WinSock::QOS,
    _gqos: *mut windows_sys::Win32::Networking::WinSock::QOS,
) -> i32 {
    reset_socket_connect_tracking(socket);

    if proxy_connect_socket(socket, name, name_len).is_err() {
        set_proxy_connect_error();
        return -1;
    }

    let (result, error_code) = connect_success_result(socket_connect_contract(socket));
    unsafe { WSASetLastError(error_code) };
    result
}

#[unsafe(no_mangle)]
pub unsafe extern "system" fn hooked_ioctlsocket(socket: SOCKET, cmd: i32, argp: *mut u32) -> i32 {
    let result = unsafe { o_ioctlsocket(socket, cmd, argp) };
    if result == 0 && cmd == FIONBIO as i32 && !argp.is_null() {
        let nonblocking = unsafe { *argp != 0 };
        record_socket_nonblocking(socket, nonblocking);
    }
    result
}

#[unsafe(no_mangle)]
pub unsafe extern "system" fn hooked_WSAEventSelect(
    socket: SOCKET,
    event_object: HANDLE,
    network_events: i32,
) -> i32 {
    let result = unsafe { o_wsa_event_select(socket, event_object, network_events) };
    if result == 0 {
        record_socket_event_select(socket, event_object, network_events);
    }
    result
}

#[unsafe(no_mangle)]
pub unsafe extern "system" fn hooked_WSAAsyncSelect(
    socket: SOCKET,
    window_handle: HWND,
    message_id: u32,
    network_events: i32,
) -> i32 {
    let result = unsafe { o_wsa_async_select(socket, window_handle, message_id, network_events) };
    if result == 0 {
        record_socket_async_select(socket, window_handle, message_id, network_events);
    }
    result
}

unsafe fn o_wsa_ioctl(
    socket: SOCKET,
    io_control_code: u32,
    in_buffer: *const c_void,
    in_buffer_len: u32,
    out_buffer: *mut c_void,
    out_buffer_len: u32,
    bytes_returned: *mut u32,
    overlapped: *mut OVERLAPPED,
    completion_routine: windows_sys::Win32::Networking::WinSock::LPWSAOVERLAPPED_COMPLETION_ROUTINE,
) -> i32 {
    let Some(fptr) = cached_trampoline(&FPTR_O_WSA_IOCTL, hooked_WSAIoctl as u64, "WSAIoctl")
    else {
        unsafe {
            WSASetLastError(WSAEFAULT as i32);
        }
        return -1;
    };

    let original: unsafe extern "system" fn(
        SOCKET,
        u32,
        *const c_void,
        u32,
        *mut c_void,
        u32,
        *mut u32,
        *mut OVERLAPPED,
        windows_sys::Win32::Networking::WinSock::LPWSAOVERLAPPED_COMPLETION_ROUTINE,
    ) -> i32 = unsafe { std::mem::transmute(fptr) };

    unsafe {
        original(
            socket,
            io_control_code,
            in_buffer,
            in_buffer_len,
            out_buffer,
            out_buffer_len,
            bytes_returned,
            overlapped,
            completion_routine,
        )
    }
}

unsafe fn o_create_iocp(
    file_handle: HANDLE,
    existing_completion_port: HANDLE,
    completion_key: usize,
    number_of_concurrent_threads: u32,
) -> HANDLE {
    let Some(fptr) = cached_trampoline(
        &FPTR_O_CREATE_IO_COMPLETION_PORT,
        hooked_CreateIoCompletionPort as u64,
        "CreateIoCompletionPort",
    ) else {
        return null_mut();
    };

    let original: unsafe extern "system" fn(HANDLE, HANDLE, usize, u32) -> HANDLE =
        unsafe { std::mem::transmute(fptr) };

    unsafe {
        original(
            file_handle,
            existing_completion_port,
            completion_key,
            number_of_concurrent_threads,
        )
    }
}

unsafe fn o_wsa_get_overlapped_result(
    socket: SOCKET,
    overlapped: *mut OVERLAPPED,
    bytes_transferred: *mut u32,
    wait: BOOL,
    flags: *mut u32,
) -> BOOL {
    let Some(fptr) = cached_trampoline(
        &FPTR_O_WSA_GET_OVERLAPPED_RESULT,
        hooked_WSAGetOverlappedResult as u64,
        "WSAGetOverlappedResult",
    ) else {
        unsafe {
            WSASetLastError(WSAEFAULT as i32);
        }
        return 0;
    };

    let original: unsafe extern "system" fn(
        SOCKET,
        *mut OVERLAPPED,
        *mut u32,
        BOOL,
        *mut u32,
    ) -> BOOL = unsafe { std::mem::transmute(fptr) };

    unsafe { original(socket, overlapped, bytes_transferred, wait, flags) }
}

unsafe fn o_setsockopt(
    socket: SOCKET,
    level: i32,
    option_name: i32,
    option_value: *const u8,
    option_len: i32,
) -> i32 {
    let Some(fptr) = cached_trampoline(&FPTR_O_SETSOCKOPT, hooked_setsockopt as u64, "setsockopt")
    else {
        unsafe {
            WSASetLastError(WSAEFAULT as i32);
        }
        return -1;
    };

    let original: unsafe extern "system" fn(SOCKET, i32, i32, *const u8, i32) -> i32 =
        unsafe { std::mem::transmute(fptr) };

    unsafe { original(socket, level, option_name, option_value, option_len) }
}

unsafe fn o_closesocket(socket: SOCKET) -> i32 {
    let Some(fptr) = cached_trampoline(
        &FPTR_O_CLOSESOCKET,
        hooked_closesocket as u64,
        "closesocket",
    ) else {
        unsafe {
            WSASetLastError(WSAENOTSOCK as i32);
        }
        return -1;
    };

    let original: unsafe extern "system" fn(SOCKET) -> i32 = unsafe { std::mem::transmute(fptr) };
    unsafe { original(socket) }
}

fn is_connectex_ioctl_request(
    io_control_code: u32,
    in_buffer: *const c_void,
    in_buffer_len: u32,
) -> bool {
    if io_control_code != SIO_GET_EXTENSION_FUNCTION_POINTER {
        return false;
    }

    if in_buffer.is_null() || in_buffer_len < size_of_val(&WSAID_CONNECTEX) as u32 {
        return false;
    }

    unsafe {
        let requested =
            std::slice::from_raw_parts(in_buffer as *const u8, size_of_val(&WSAID_CONNECTEX));
        let expected = std::slice::from_raw_parts(
            (&WSAID_CONNECTEX as *const _) as *const u8,
            size_of_val(&WSAID_CONNECTEX),
        );
        requested == expected
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "system" fn hooked_WSAIoctl(
    socket: SOCKET,
    io_control_code: u32,
    in_buffer: *const c_void,
    in_buffer_len: u32,
    out_buffer: *mut c_void,
    out_buffer_len: u32,
    bytes_returned: *mut u32,
    overlapped: *mut OVERLAPPED,
    completion_routine: windows_sys::Win32::Networking::WinSock::LPWSAOVERLAPPED_COMPLETION_ROUTINE,
) -> i32 {
    if is_connectex_ioctl_request(io_control_code, in_buffer, in_buffer_len) {
        if out_buffer.is_null()
            || out_buffer_len < size_of::<LPFN_CONNECTEX>() as u32
            || bytes_returned.is_null()
        {
            set_wsa_error(
                "WSAIoctl received an invalid buffer while requesting ConnectEx",
                WSAEFAULT as i32,
            );
            return -1;
        }

        let connect_ex: LPFN_CONNECTEX = Some(hooked_ConnectEx);
        unsafe {
            copy_nonoverlapping(
                &connect_ex as *const LPFN_CONNECTEX as *const u8,
                out_buffer as *mut u8,
                size_of::<LPFN_CONNECTEX>(),
            );
            *bytes_returned = size_of::<LPFN_CONNECTEX>() as u32;
            WSASetLastError(0);
        }

        return 0;
    }

    unsafe {
        o_wsa_ioctl(
            socket,
            io_control_code,
            in_buffer,
            in_buffer_len,
            out_buffer,
            out_buffer_len,
            bytes_returned,
            overlapped,
            completion_routine,
        )
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "system" fn hooked_ConnectEx(
    socket: SOCKET,
    address: *const SOCKADDR,
    address_len: i32,
    send_buffer: *const c_void,
    send_buffer_len: u32,
    bytes_sent: *mut u32,
    overlapped: *mut OVERLAPPED,
) -> BOOL {
    if overlapped.is_null() {
        set_wsa_error(
            "ConnectEx requires a non-null OVERLAPPED pointer",
            WSAEFAULT as i32,
        );
        return 0;
    }

    reset_socket_connect_tracking(socket);

    if let Err(error) = proxy_connect_socket(socket, address, address_len) {
        let message = get_context().last_error.clone();
        let error_code = if message.contains("sample proxy chain") {
            WSAECONNABORTED as i32
        } else {
            let wsa_error = unsafe { WSAGetLastError() };
            if wsa_error == 0 {
                WSAEFAULT as i32
            } else {
                wsa_error
            }
        };
        set_wsa_error(
            format!("ConnectEx proxy connect failed: {error:#}"),
            error_code,
        );
        return 0;
    }

    let payload_result = send_connectex_payload(socket, send_buffer, send_buffer_len);
    let payload_bytes_sent = match payload_result {
        Ok(bytes) => bytes,
        Err(error) => {
            let error_code = unsafe { WSAGetLastError() };
            let error_code = if error_code == 0 {
                WSAEFAULT as i32
            } else {
                error_code
            };
            set_wsa_error(
                format!("ConnectEx payload send failed: {error:#}"),
                error_code,
            );
            return 0;
        }
    };

    record_synthetic_connectex(socket, overlapped, payload_bytes_sent);

    if notify_synthetic_connectex_completion(socket, overlapped, payload_bytes_sent) {
        unsafe {
            WSASetLastError(WSA_IO_PENDING as i32);
        }
        return 0;
    }

    if !bytes_sent.is_null() {
        unsafe {
            *bytes_sent = payload_bytes_sent;
        }
    }

    unsafe {
        WSASetLastError(0);
    }
    1
}

#[unsafe(no_mangle)]
pub unsafe extern "system" fn hooked_CreateIoCompletionPort(
    file_handle: HANDLE,
    existing_completion_port: HANDLE,
    completion_key: usize,
    number_of_concurrent_threads: u32,
) -> HANDLE {
    let completion_port = unsafe {
        o_create_iocp(
            file_handle,
            existing_completion_port,
            completion_key,
            number_of_concurrent_threads,
        )
    };

    if completion_port != null_mut() && file_handle != INVALID_HANDLE_VALUE {
        record_socket_iocp_association(file_handle as usize, completion_port, completion_key);
    }

    completion_port
}

#[unsafe(no_mangle)]
pub unsafe extern "system" fn hooked_WSAGetOverlappedResult(
    socket: SOCKET,
    overlapped: *mut OVERLAPPED,
    bytes_transferred: *mut u32,
    wait: BOOL,
    flags: *mut u32,
) -> BOOL {
    if let Some(synthetic) = synthetic_connectex(socket, overlapped) {
        if !synthetic.completed {
            unsafe {
                WSASetLastError(WSA_IO_PENDING as i32);
            }
            return 0;
        }

        if synthetic.error != 0 {
            clear_synthetic_connectex(socket, overlapped);
            unsafe {
                WSASetLastError(synthetic.error);
            }
            return 0;
        }

        if !bytes_transferred.is_null() {
            unsafe {
                *bytes_transferred = synthetic.bytes_sent;
            }
        }
        if !flags.is_null() {
            unsafe {
                *flags = 0;
            }
        }

        clear_synthetic_connectex(socket, overlapped);
        unsafe {
            WSASetLastError(0);
        }
        return 1;
    }

    unsafe { o_wsa_get_overlapped_result(socket, overlapped, bytes_transferred, wait, flags) }
}

#[unsafe(no_mangle)]
pub unsafe extern "system" fn hooked_setsockopt(
    socket: SOCKET,
    level: i32,
    option_name: i32,
    option_value: *const u8,
    option_len: i32,
) -> i32 {
    if level == SOL_SOCKET && option_name == SO_UPDATE_CONNECT_CONTEXT {
        if socket_allows_connect_context_update(socket) {
            unsafe {
                WSASetLastError(0);
            }
            return 0;
        }
    }

    unsafe { o_setsockopt(socket, level, option_name, option_value, option_len) }
}

#[unsafe(no_mangle)]
pub unsafe extern "system" fn hooked_closesocket(socket: SOCKET) -> i32 {
    let result = unsafe { o_closesocket(socket) };
    if result == 0 {
        remove_socket_state(socket);
    }
    result
}

#[cfg(all(test, target_arch = "x86_64"))]
mod tests {
    use super::{
        clear_synthetic_connectex, connect_success_result, record_socket_async_select,
        record_socket_event_select, record_socket_nonblocking, record_synthetic_connectex,
        remove_socket_state, reset_socket_connect_tracking, socket_allows_connect_context_update,
        socket_connect_contract, synthetic_connectex,
    };
    use crate::SocketConnectContract;
    use std::sync::Mutex;
    use windows_sys::Win32::Networking::WinSock::{FD_CONNECT, WSAEWOULDBLOCK};
    use windows_sys::Win32::System::IO::OVERLAPPED;

    static TEST_MUTEX: Mutex<()> = Mutex::new(());

    fn lock_tests() -> std::sync::MutexGuard<'static, ()> {
        TEST_MUTEX
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    #[test]
    fn synthetic_connectex_state_is_cleared_after_consumption() {
        let _guard = lock_tests();
        let socket = 0x1234usize;
        let mut overlapped = OVERLAPPED::default();

        reset_socket_connect_tracking(socket);
        record_synthetic_connectex(socket, &mut overlapped, 17);

        let synthetic = synthetic_connectex(socket, &mut overlapped)
            .expect("synthetic ConnectEx state should be recorded");
        assert_eq!(synthetic.bytes_sent, 17);
        assert!(socket_allows_connect_context_update(socket));

        assert!(
            clear_synthetic_connectex(socket, &mut overlapped),
            "clearing the matching synthetic ConnectEx state should succeed"
        );
        assert!(
            synthetic_connectex(socket, &mut overlapped).is_none(),
            "synthetic ConnectEx state should be consumed after the result is observed"
        );
        assert!(
            socket_allows_connect_context_update(socket),
            "consuming the synthetic result must not revoke SO_UPDATE_CONNECT_CONTEXT permission"
        );

        remove_socket_state(socket);
    }

    #[test]
    fn socket_contract_defaults_to_blocking() {
        let _guard = lock_tests();
        let socket = 0x2001usize;

        reset_socket_connect_tracking(socket);
        assert_eq!(
            socket_connect_contract(socket),
            SocketConnectContract::Blocking
        );

        remove_socket_state(socket);
    }

    #[test]
    fn socket_contract_tracks_nonblocking_poll() {
        let _guard = lock_tests();
        let socket = 0x2002usize;

        record_socket_nonblocking(socket, true);
        assert_eq!(
            socket_connect_contract(socket),
            SocketConnectContract::NonBlockingPoll
        );

        record_socket_nonblocking(socket, false);
        assert_eq!(
            socket_connect_contract(socket),
            SocketConnectContract::Blocking
        );

        remove_socket_state(socket);
    }

    #[test]
    fn socket_contract_prefers_event_async() {
        let _guard = lock_tests();
        let socket = 0x2003usize;

        record_socket_nonblocking(socket, true);
        record_socket_event_select(socket, 0x4000usize as _, FD_CONNECT as i32);
        assert_eq!(
            socket_connect_contract(socket),
            SocketConnectContract::EventAsync
        );

        record_socket_event_select(socket, 0 as _, 0);
        assert_eq!(
            socket_connect_contract(socket),
            SocketConnectContract::NonBlockingPoll
        );

        record_socket_async_select(socket, 0x5000usize as _, 0x0401, FD_CONNECT as i32);
        assert_eq!(
            socket_connect_contract(socket),
            SocketConnectContract::EventAsync
        );

        remove_socket_state(socket);
    }

    #[test]
    fn connect_success_result_matches_contract() {
        let _guard = lock_tests();

        assert_eq!(
            connect_success_result(SocketConnectContract::Blocking),
            (0, 0)
        );
        assert_eq!(
            connect_success_result(SocketConnectContract::NonBlockingPoll),
            (-1, WSAEWOULDBLOCK as i32)
        );
        assert_eq!(
            connect_success_result(SocketConnectContract::EventAsync),
            (-1, WSAEWOULDBLOCK as i32)
        );
    }
}
