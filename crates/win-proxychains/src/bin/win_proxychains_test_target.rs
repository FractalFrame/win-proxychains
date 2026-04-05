use std::{
    collections::HashMap,
    ffi::OsStr,
    mem::MaybeUninit,
    os::windows::ffi::OsStrExt,
    path::PathBuf,
    process::{Command, ExitCode, Stdio},
    ptr::{null, null_mut},
    sync::Once,
};

use anyhow::{Context, Result, anyhow, bail, ensure};
use clap::{Parser, Subcommand};
use windows_sys::Win32::{
    Foundation::{CloseHandle, HANDLE, HWND, INVALID_HANDLE_VALUE, WAIT_OBJECT_0},
    Networking::WinSock::{
        ADDRINFOW, AF_INET, AF_INET6, AF_UNSPEC, FD_CONNECT, FD_CONNECT_BIT, FD_SET, FIONBIO,
        FreeAddrInfoW, GetAddrInfoW, IN_ADDR, IN_ADDR_0, IN_ADDR_0_0, IN6_ADDR, IN6_ADDR_0,
        INVALID_SOCKET, IPPROTO_TCP, LPFN_CONNECTEX, SIO_GET_EXTENSION_FUNCTION_POINTER, SO_ERROR,
        SO_UPDATE_CONNECT_CONTEXT, SOCK_STREAM, SOCKADDR, SOCKADDR_IN, SOCKADDR_IN6,
        SOCKADDR_IN6_0, SOCKADDR_STORAGE, SOCKET, SOL_SOCKET, WSA_FLAG_OVERLAPPED, WSA_IO_PENDING,
        WSA_WAIT_FAILED, WSA_WAIT_TIMEOUT, WSAAsyncSelect, WSABUF, WSACloseEvent, WSAConnect,
        WSACreateEvent, WSADATA, WSAEWOULDBLOCK, WSAEnumNetworkEvents, WSAEventSelect,
        WSAGetLastError, WSAGetOverlappedResult, WSAID_CONNECTEX, WSAIoctl, WSANETWORKEVENTS,
        WSARecv, WSASend, WSASocketW, WSAStartup, WSAWaitForMultipleEvents, bind, closesocket,
        connect, getsockopt, ioctlsocket, recv, select, send, setsockopt,
    },
    System::{
        IO::{CreateIoCompletionPort, GetQueuedCompletionStatus, OVERLAPPED},
        Threading::INFINITE,
    },
    UI::WindowsAndMessaging::{CreateWindowExW, DestroyWindow, GetMessageW, MSG, WM_USER},
};

const ASYNC_SELECT_CONNECT_MESSAGE: u32 = WM_USER + 0x41;

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            println!("{error:#}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        CommandKind::Connect {
            host,
            port,
            string_to_send,
        } => run_connect(&host, port, &string_to_send),
        CommandKind::ConnectWsa {
            host,
            port,
            string_to_send,
        } => run_connect_wsa(&host, port, &string_to_send),
        CommandKind::ConnectNonblocking {
            host,
            port,
            string_to_send,
        } => run_connect_nonblocking(&host, port, &string_to_send),
        CommandKind::ConnectEventSelect {
            host,
            port,
            string_to_send,
        } => run_connect_event_select(&host, port, &string_to_send),
        CommandKind::ConnectAsyncSelect {
            host,
            port,
            string_to_send,
        } => run_connect_async_select(&host, port, &string_to_send),
        CommandKind::ConnectOverlapped {
            host,
            port,
            string_to_send,
        } => run_connect_overlapped(&host, port, &string_to_send),
        CommandKind::ConnectIOCP {
            host,
            port,
            string_to_send,
        } => run_connect_iocp(&host, port, &string_to_send),
        CommandKind::IocpMultiple {
            host,
            port,
            string_to_send,
        } => run_connect_iocp_multiple(&host, port, &string_to_send),
        CommandKind::Spawn => run_spawn(),
    }
}

fn run_connect(host: &str, port: u16, string_to_send: &str) -> Result<()> {
    ensure_winsock_started()?;

    let payload = normalize_string_to_send(string_to_send);
    let mut last_error = None;

    for target in resolve_targets(host, port)?.iter() {
        match connect_and_exchange_blocking(target, payload.as_bytes()) {
            Ok(response) => {
                print!("{}", String::from_utf8_lossy(&response));
                return Ok(());
            }
            Err(error) => last_error = Some(error),
        }
    }

    Err(last_error.unwrap_or_else(|| anyhow!("no addresses resolved for {host}:{port}")))
}

fn run_connect_wsa(host: &str, port: u16, string_to_send: &str) -> Result<()> {
    ensure_winsock_started()?;

    let payload = normalize_string_to_send(string_to_send);
    let mut last_error = None;

    for target in resolve_targets(host, port)?.iter() {
        match connect_and_exchange_wsa_blocking(target, payload.as_bytes()) {
            Ok(response) => {
                print!("{}", String::from_utf8_lossy(&response));
                return Ok(());
            }
            Err(error) => last_error = Some(error),
        }
    }

    Err(last_error.unwrap_or_else(|| anyhow!("no addresses resolved for {host}:{port}")))
}

fn run_connect_nonblocking(host: &str, port: u16, string_to_send: &str) -> Result<()> {
    ensure_winsock_started()?;

    let payload = normalize_string_to_send(string_to_send);
    let mut last_error = None;

    for target in resolve_targets(host, port)?.iter() {
        match connect_and_exchange_nonblocking(target, payload.as_bytes()) {
            Ok(response) => {
                print!("{}", String::from_utf8_lossy(&response));
                return Ok(());
            }
            Err(error) => last_error = Some(error),
        }
    }

    Err(last_error.unwrap_or_else(|| anyhow!("no addresses resolved for {host}:{port}")))
}

fn run_connect_event_select(host: &str, port: u16, string_to_send: &str) -> Result<()> {
    ensure_winsock_started()?;

    let payload = normalize_string_to_send(string_to_send);
    let mut last_error = None;

    for target in resolve_targets(host, port)?.iter() {
        match connect_and_exchange_event_select(target, payload.as_bytes()) {
            Ok(response) => {
                print!("{}", String::from_utf8_lossy(&response));
                return Ok(());
            }
            Err(error) => last_error = Some(error),
        }
    }

    Err(last_error.unwrap_or_else(|| anyhow!("no addresses resolved for {host}:{port}")))
}

fn run_connect_async_select(host: &str, port: u16, string_to_send: &str) -> Result<()> {
    ensure_winsock_started()?;

    let payload = normalize_string_to_send(string_to_send);
    let mut last_error = None;

    for target in resolve_targets(host, port)?.iter() {
        match connect_and_exchange_async_select(target, payload.as_bytes()) {
            Ok(response) => {
                print!("{}", String::from_utf8_lossy(&response));
                return Ok(());
            }
            Err(error) => last_error = Some(error),
        }
    }

    Err(last_error.unwrap_or_else(|| anyhow!("no addresses resolved for {host}:{port}")))
}

fn run_connect_overlapped(host: &str, port: u16, string_to_send: &str) -> Result<()> {
    ensure_winsock_started()?;

    let payload = normalize_string_to_send(string_to_send);
    let mut last_error = None;

    for target in resolve_targets(host, port)?.iter() {
        match connect_and_exchange_overlapped(target, payload.as_bytes()) {
            Ok(response) => {
                print!("{}", String::from_utf8_lossy(&response));
                return Ok(());
            }
            Err(error) => last_error = Some(error),
        }
    }

    Err(last_error.unwrap_or_else(|| anyhow!("no addresses resolved for {host}:{port}")))
}

fn run_connect_iocp(host: &str, port: u16, string_to_send: &str) -> Result<()> {
    ensure_winsock_started()?;

    let payload = normalize_string_to_send(string_to_send);
    let mut last_error = None;

    for target in resolve_targets(host, port)?.iter() {
        match connect_and_exchange_iocp(target, payload.as_bytes()) {
            Ok(response) => {
                print!("{}", String::from_utf8_lossy(&response));
                return Ok(());
            }
            Err(error) => last_error = Some(error),
        }
    }

    Err(last_error.unwrap_or_else(|| anyhow!("no addresses resolved for {host}:{port}")))
}

fn run_connect_iocp_multiple(host: &str, port: u16, string_to_send: &str) -> Result<()> {
    ensure_winsock_started()?;

    let payload = normalize_string_to_send(string_to_send);
    let mut last_error = None;

    for target in resolve_targets(host, port)?.iter() {
        match connect_and_exchange_iocp_multiple(target, payload.as_bytes()) {
            Ok(responses) => {
                print_multiple_iocp_responses(&responses);
                return Ok(());
            }
            Err(error) => last_error = Some(error),
        }
    }

    Err(last_error.unwrap_or_else(|| anyhow!("no addresses resolved for {host}:{port}")))
}

fn connect_and_exchange_overlapped(target: &ResolvedTarget, payload: &[u8]) -> Result<Vec<u8>> {
    let socket = create_overlapped_socket(target)?;
    bind_connectex_socket(socket.raw, target.family)
        .with_context(|| format!("failed to bind local socket for {}", target.display_name))?;
    let connect_ex = load_connect_ex(socket.raw)
        .with_context(|| format!("failed to load ConnectEx for {}", target.display_name))?;

    let connect_event = EventHandle::create().context("failed to create connect event")?;
    let mut connect_overlapped = new_overlapped_with_event(connect_event.raw as HANDLE);
    let mut connect_bytes = 0u32;
    unsafe {
        let connect_result = connect_ex(
            socket.raw,
            target.addr(),
            target.addr_len,
            null(),
            0,
            &mut connect_bytes,
            &mut connect_overlapped,
        );
        if connect_result == 0 {
            let error = WSAGetLastError();
            if error != WSA_IO_PENDING {
                bail!(
                    "ConnectEx to {} failed: {}",
                    target.display_name,
                    format_wsa_error(error)
                );
            }
        }
    }

    wait_for_overlapped_socket(socket.raw, &mut connect_overlapped, "ConnectEx")
        .with_context(|| format!("async connect to {} failed", target.display_name))?;
    update_connect_context(socket.raw).context("failed to update connect context")?;

    send_all_overlapped(socket.raw, payload).context("overlapped send failed")?;
    recv_to_end_overlapped(socket.raw).context("overlapped receive failed")
}

fn connect_and_exchange_iocp(target: &ResolvedTarget, payload: &[u8]) -> Result<Vec<u8>> {
    let socket = create_overlapped_socket(target)?;
    bind_connectex_socket(socket.raw, target.family)
        .with_context(|| format!("failed to bind local socket for {}", target.display_name))?;
    let connect_ex = load_connect_ex(socket.raw)
        .with_context(|| format!("failed to load ConnectEx for {}", target.display_name))?;

    let completion_port = CompletionPort::new().context("failed to create completion port")?;
    completion_port
        .associate_socket(socket.raw, 1)
        .context("failed to associate socket with completion port")?;

    let mut connect_overlapped = OVERLAPPED::default();
    let mut connect_bytes = 0u32;
    unsafe {
        let connect_result = connect_ex(
            socket.raw,
            target.addr(),
            target.addr_len,
            null(),
            0,
            &mut connect_bytes,
            &mut connect_overlapped,
        );
        if connect_result == 0 {
            let error = WSAGetLastError();
            if error != WSA_IO_PENDING {
                bail!(
                    "ConnectEx to {} failed: {}",
                    target.display_name,
                    format_wsa_error(error)
                );
            }
        }
    }

    completion_port
        .wait(&mut connect_overlapped, "ConnectEx")
        .with_context(|| format!("iocp connect to {} failed", target.display_name))?;
    update_connect_context(socket.raw).context("failed to update connect context")?;

    send_all_iocp(socket.raw, completion_port.raw, payload).context("iocp send failed")?;
    recv_to_end_iocp(socket.raw, completion_port.raw).context("iocp receive failed")
}

fn connect_and_exchange_iocp_multiple(
    target: &ResolvedTarget,
    payload: &[u8],
) -> Result<Vec<Vec<u8>>> {
    ensure!(
        !payload.is_empty(),
        "iocp-multiple requires a non-empty payload"
    );

    let completion_port = CompletionPort::new().context("failed to create completion port")?;
    let mut connections = Vec::with_capacity(2);

    for connection_index in 0..2 {
        let socket = create_overlapped_socket(target)?;
        bind_connectex_socket(socket.raw, target.family).with_context(|| {
            format!(
                "failed to bind local socket for {} connection {}",
                target.display_name,
                connection_index + 1
            )
        })?;
        let connect_ex = load_connect_ex(socket.raw).with_context(|| {
            format!(
                "failed to load ConnectEx for {} connection {}",
                target.display_name,
                connection_index + 1
            )
        })?;
        let completion_key = connection_index + 1;
        completion_port
            .associate_socket(socket.raw, completion_key)
            .with_context(|| {
                format!(
                    "failed to associate connection {} with completion port",
                    connection_index + 1
                )
            })?;
        connections.push(IocpTrackedConnection::new(
            socket,
            completion_key,
            connect_ex,
        ));
    }

    ensure!(
        connections[0].completion_key != connections[1].completion_key,
        "iocp-multiple requires distinct completion keys"
    );

    let mut active_operations = HashMap::new();
    let mut completed_operations = HashMap::new();
    let mut ready_completions = Vec::new();

    for connection_index in 0..connections.len() {
        enqueue_immediate_completion(
            submit_iocp_connect(
                target,
                connection_index,
                &mut connections,
                &mut active_operations,
                &mut completed_operations,
            )?,
            &mut ready_completions,
        );
    }

    while !connections.iter().all(IocpTrackedConnection::is_complete) {
        let completion = match ready_completions.pop() {
            Some(completion) => completion,
            None => completion_port.dequeue()?,
        };

        process_iocp_completion(
            completion,
            &mut connections,
            payload,
            completion_port.raw,
            &mut active_operations,
            &mut completed_operations,
            &mut ready_completions,
        )?;
    }

    validate_iocp_multiple_results(&connections, payload)?;

    Ok(connections
        .into_iter()
        .map(|connection| connection.response)
        .collect())
}

fn connect_and_exchange_blocking(target: &ResolvedTarget, payload: &[u8]) -> Result<Vec<u8>> {
    let socket = create_blocking_socket(target)?;
    let connect_result = unsafe { connect(socket.raw, target.addr(), target.addr_len) };
    if connect_result != 0 {
        bail!(
            "connect to {} failed: {}",
            target.display_name,
            last_wsa_error()
        );
    }

    send_all_blocking(socket.raw, payload).context("blocking send failed")?;
    recv_to_end_blocking(socket.raw).context("blocking receive failed")
}

fn connect_and_exchange_wsa_blocking(target: &ResolvedTarget, payload: &[u8]) -> Result<Vec<u8>> {
    let socket = create_blocking_socket(target)?;
    let connect_result = unsafe {
        WSAConnect(
            socket.raw,
            target.addr(),
            target.addr_len,
            null(),
            null_mut(),
            null(),
            null(),
        )
    };
    if connect_result != 0 {
        bail!(
            "WSAConnect to {} failed: {}",
            target.display_name,
            last_wsa_error()
        );
    }

    send_all_wsa_blocking(socket.raw, payload).context("WSASend blocking send failed")?;
    recv_to_end_wsa_blocking(socket.raw).context("WSARecv blocking receive failed")
}

fn connect_and_exchange_nonblocking(target: &ResolvedTarget, payload: &[u8]) -> Result<Vec<u8>> {
    let socket = create_blocking_socket(target)?;
    set_socket_nonblocking(socket.raw, true).context("failed to enable nonblocking mode")?;

    let connect_result = unsafe { connect(socket.raw, target.addr(), target.addr_len) };
    if connect_result != 0 {
        let error = unsafe { WSAGetLastError() };
        if error != WSAEWOULDBLOCK {
            bail!(
                "nonblocking connect to {} failed: {}",
                target.display_name,
                format_wsa_error(error)
            );
        }

        wait_for_nonblocking_connect(socket.raw).with_context(|| {
            format!(
                "nonblocking connect to {} did not complete",
                target.display_name
            )
        })?;
    }

    set_socket_nonblocking(socket.raw, false).context("failed to restore blocking mode")?;
    send_all_blocking(socket.raw, payload).context("nonblocking send failed")?;
    recv_to_end_blocking(socket.raw).context("nonblocking receive failed")
}

fn connect_and_exchange_event_select(target: &ResolvedTarget, payload: &[u8]) -> Result<Vec<u8>> {
    let socket = create_blocking_socket(target)?;
    let connect_event = EventHandle::create().context("failed to create connect event")?;

    let event_select_result =
        unsafe { WSAEventSelect(socket.raw, connect_event.raw, FD_CONNECT as i32) };
    if event_select_result != 0 {
        bail!("WSAEventSelect failed: {}", last_wsa_error());
    }

    let connect_result = unsafe { connect(socket.raw, target.addr(), target.addr_len) };
    if connect_result != 0 {
        let error = unsafe { WSAGetLastError() };
        if error != WSAEWOULDBLOCK {
            bail!(
                "event-select connect to {} failed: {}",
                target.display_name,
                format_wsa_error(error)
            );
        }

        wait_for_event_select_connect(socket.raw, connect_event.raw).with_context(|| {
            format!(
                "event-select connect to {} did not complete",
                target.display_name
            )
        })?;
    }

    disable_event_select(socket.raw).context("failed to disable WSAEventSelect")?;
    set_socket_nonblocking(socket.raw, false).context("failed to restore blocking mode")?;
    send_all_blocking(socket.raw, payload).context("event-select send failed")?;
    recv_to_end_blocking(socket.raw).context("event-select receive failed")
}

fn connect_and_exchange_async_select(target: &ResolvedTarget, payload: &[u8]) -> Result<Vec<u8>> {
    let socket = create_blocking_socket(target)?;
    let message_window = WindowHandle::create_async_select_window()
        .context("failed to create WSAAsyncSelect message window")?;

    let async_select_result = unsafe {
        WSAAsyncSelect(
            socket.raw,
            message_window.raw,
            ASYNC_SELECT_CONNECT_MESSAGE,
            FD_CONNECT as i32,
        )
    };
    if async_select_result != 0 {
        bail!("WSAAsyncSelect failed: {}", last_wsa_error());
    }

    let connect_result = unsafe { connect(socket.raw, target.addr(), target.addr_len) };
    if connect_result != 0 {
        let error = unsafe { WSAGetLastError() };
        if error != WSAEWOULDBLOCK {
            bail!(
                "async-select connect to {} failed: {}",
                target.display_name,
                format_wsa_error(error)
            );
        }

        wait_for_async_select_connect(socket.raw, message_window.raw).with_context(|| {
            format!(
                "async-select connect to {} did not complete",
                target.display_name
            )
        })?;
    }

    disable_async_select(socket.raw, message_window.raw)
        .context("failed to disable WSAAsyncSelect")?;
    set_socket_nonblocking(socket.raw, false).context("failed to restore blocking mode")?;
    send_all_blocking(socket.raw, payload).context("async-select send failed")?;
    recv_to_end_blocking(socket.raw).context("async-select receive failed")
}

fn run_spawn() -> Result<()> {
    let plan = SpawnPlan {
        program: current_exe_path()?,
        args: vec![
            "connect".into(),
            "google.com".into(),
            "80".into(),
            "GET / HTTP/1.1\\r\\nHost: google.com\\r\\nConnection: close\\r\\n\\r\\n".into(),
        ],
    };

    let mut child = spawn_self(&plan).context("failed to spawn child process")?;
    let status = child.wait().context("failed to wait for child process")?;

    if !status.success() {
        anyhow::bail!("child exited with status {status}");
    }

    Ok(())
}

fn spawn_self(plan: &SpawnPlan) -> Result<std::process::Child> {
    Command::new(&plan.program)
        .args(&plan.args)
        .stdin(Stdio::null())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()
        .with_context(|| {
            format!(
                "failed to launch {} with args {:?}",
                plan.program.display(),
                plan.args
            )
        })
}

fn current_exe_path() -> Result<PathBuf> {
    std::env::current_exe().context("failed to determine current executable path")
}

fn normalize_string_to_send(input: &str) -> String {
    input.replace("\\r\\n", "\r\n")
}

fn ensure_winsock_started() -> Result<()> {
    static WINSOCK_INIT: Once = Once::new();
    static mut STARTUP_RESULT: i32 = 0;

    WINSOCK_INIT.call_once(|| unsafe {
        let mut wsadata = MaybeUninit::<WSADATA>::zeroed();
        STARTUP_RESULT = WSAStartup(0x0202, wsadata.as_mut_ptr());
    });

    let startup_result = unsafe { STARTUP_RESULT };
    if startup_result != 0 {
        bail!("WSAStartup failed: {}", format_wsa_error(startup_result));
    }

    Ok(())
}

fn resolve_targets(host: &str, port: u16) -> Result<Vec<ResolvedTarget>> {
    let host_wide = wide_null(host);
    let service_wide = wide_null(&port.to_string());
    let hints = ADDRINFOW {
        ai_family: AF_UNSPEC.into(),
        ai_socktype: SOCK_STREAM,
        ai_protocol: IPPROTO_TCP,
        ..Default::default()
    };
    let mut result = null_mut();

    let status = unsafe {
        GetAddrInfoW(
            host_wide.as_ptr(),
            service_wide.as_ptr(),
            &hints,
            &mut result,
        )
    };
    if status != 0 {
        bail!(
            "GetAddrInfoW({host}, {port}) failed: {}",
            format_wsa_error(status)
        );
    }

    let result = AddrInfoList { raw: result };
    let mut targets = Vec::new();
    let mut cursor = result.raw;
    while !cursor.is_null() {
        let addr = unsafe { &*cursor };
        if addr.ai_addr.is_null() {
            cursor = addr.ai_next;
            continue;
        }

        let display_name = sockaddr_to_display_name(addr.ai_addr, addr.ai_addrlen as i32)
            .unwrap_or_else(|_| format!("{host}:{port}"));
        targets.push(ResolvedTarget {
            family: addr.ai_family,
            socktype: addr.ai_socktype,
            protocol: addr.ai_protocol,
            addr_len: addr.ai_addrlen as i32,
            storage: copy_sockaddr(addr.ai_addr, addr.ai_addrlen as i32)?,
            display_name,
        });
        cursor = addr.ai_next;
    }

    ensure!(
        !targets.is_empty(),
        "GetAddrInfoW returned no usable addresses"
    );
    Ok(targets)
}

fn copy_sockaddr(addr: *const SOCKADDR, addr_len: i32) -> Result<SOCKADDR_STORAGE> {
    ensure!(
        addr_len >= 0 && (addr_len as usize) <= std::mem::size_of::<SOCKADDR_STORAGE>(),
        "sockaddr length {addr_len} exceeds storage size"
    );

    let mut storage = SOCKADDR_STORAGE::default();
    unsafe {
        std::ptr::copy_nonoverlapping(
            addr as *const u8,
            &mut storage as *mut SOCKADDR_STORAGE as *mut u8,
            addr_len as usize,
        );
    }
    Ok(storage)
}

fn sockaddr_to_display_name(addr: *const SOCKADDR, addr_len: i32) -> Result<String> {
    let mut host_buffer = vec![0u16; 256];
    let status = unsafe {
        windows_sys::Win32::Networking::WinSock::GetNameInfoW(
            addr,
            addr_len,
            host_buffer.as_mut_ptr(),
            host_buffer.len() as u32,
            null_mut(),
            0,
            windows_sys::Win32::Networking::WinSock::NI_NUMERICHOST as i32,
        )
    };
    if status != 0 {
        bail!("GetNameInfoW failed: {}", format_wsa_error(status));
    }

    let host_len = host_buffer
        .iter()
        .position(|ch| *ch == 0)
        .unwrap_or(host_buffer.len());
    Ok(String::from_utf16_lossy(&host_buffer[..host_len]))
}

fn create_overlapped_socket(target: &ResolvedTarget) -> Result<SocketHandle> {
    create_socket_with_flags(target, WSA_FLAG_OVERLAPPED)
}

fn create_blocking_socket(target: &ResolvedTarget) -> Result<SocketHandle> {
    create_socket_with_flags(target, 0)
}

fn create_socket_with_flags(target: &ResolvedTarget, flags: u32) -> Result<SocketHandle> {
    let raw = unsafe {
        WSASocketW(
            target.family,
            target.socktype,
            target.protocol,
            null_mut(),
            0,
            flags,
        )
    };
    if raw == INVALID_SOCKET {
        bail!("WSASocketW failed: {}", last_wsa_error());
    }

    Ok(SocketHandle { raw })
}

fn set_socket_nonblocking(socket: SOCKET, nonblocking: bool) -> Result<()> {
    let mut value = u32::from(nonblocking);
    let result = unsafe { ioctlsocket(socket, FIONBIO as i32, &mut value) };
    if result == 0 {
        Ok(())
    } else {
        bail!(
            "ioctlsocket(FIONBIO={}) failed: {}",
            value,
            last_wsa_error()
        )
    }
}

fn disable_event_select(socket: SOCKET) -> Result<()> {
    let result = unsafe { WSAEventSelect(socket, 0, 0) };
    if result == 0 {
        Ok(())
    } else {
        bail!("WSAEventSelect(reset) failed: {}", last_wsa_error())
    }
}

fn disable_async_select(socket: SOCKET, window: HWND) -> Result<()> {
    let result = unsafe { WSAAsyncSelect(socket, window, 0, 0) };
    if result == 0 {
        Ok(())
    } else {
        bail!("WSAAsyncSelect(reset) failed: {}", last_wsa_error())
    }
}

fn bind_connectex_socket(socket: SOCKET, family: i32) -> Result<()> {
    match family {
        x if x == AF_INET.into() => {
            let sockaddr = SOCKADDR_IN {
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
            };
            let result = unsafe {
                bind(
                    socket,
                    &sockaddr as *const SOCKADDR_IN as *const SOCKADDR,
                    std::mem::size_of::<SOCKADDR_IN>() as i32,
                )
            };
            if result == 0 {
                Ok(())
            } else {
                bail!("bind(AF_INET) failed: {}", last_wsa_error())
            }
        }
        x if x == AF_INET6.into() => {
            let sockaddr = SOCKADDR_IN6 {
                sin6_family: AF_INET6,
                sin6_port: 0,
                sin6_flowinfo: 0,
                sin6_addr: IN6_ADDR {
                    u: IN6_ADDR_0 { Byte: [0; 16] },
                },
                Anonymous: SOCKADDR_IN6_0 { sin6_scope_id: 0 },
            };
            let result = unsafe {
                bind(
                    socket,
                    &sockaddr as *const SOCKADDR_IN6 as *const SOCKADDR,
                    std::mem::size_of::<SOCKADDR_IN6>() as i32,
                )
            };
            if result == 0 {
                Ok(())
            } else {
                bail!("bind(AF_INET6) failed: {}", last_wsa_error())
            }
        }
        other => bail!("unsupported address family {other} for ConnectEx"),
    }
}

fn load_connect_ex(socket: SOCKET) -> Result<ConnectExFn> {
    let mut bytes_returned = 0u32;
    let mut connect_ex: LPFN_CONNECTEX = None;

    let result = unsafe {
        WSAIoctl(
            socket,
            SIO_GET_EXTENSION_FUNCTION_POINTER,
            &WSAID_CONNECTEX as *const _ as *const _,
            std::mem::size_of_val(&WSAID_CONNECTEX) as u32,
            &mut connect_ex as *mut _ as *mut _,
            std::mem::size_of::<LPFN_CONNECTEX>() as u32,
            &mut bytes_returned,
            null_mut(),
            None,
        )
    };
    if result != 0 {
        bail!(
            "WSAIoctl(SIO_GET_EXTENSION_FUNCTION_POINTER) failed: {}",
            last_wsa_error()
        );
    }

    connect_ex.ok_or_else(|| anyhow!("ConnectEx function pointer was null"))
}

fn update_connect_context(socket: SOCKET) -> Result<()> {
    let result = unsafe { setsockopt(socket, SOL_SOCKET, SO_UPDATE_CONNECT_CONTEXT, null(), 0) };
    if result == 0 {
        Ok(())
    } else {
        bail!(
            "setsockopt(SO_UPDATE_CONNECT_CONTEXT) failed: {}",
            last_wsa_error()
        )
    }
}

fn send_all_overlapped(socket: SOCKET, payload: &[u8]) -> Result<()> {
    let mut sent = 0usize;
    while sent < payload.len() {
        let send_event = EventHandle::create().context("failed to create send event")?;
        let mut overlapped = new_overlapped_with_event(send_event.raw as HANDLE);
        let mut bytes_sent = 0u32;
        let buffer = WSABUF {
            len: (payload.len() - sent) as u32,
            buf: payload[sent..].as_ptr() as *mut u8,
        };

        let send_result = unsafe {
            WSASend(
                socket,
                &buffer,
                1,
                &mut bytes_sent,
                0,
                &mut overlapped,
                None,
            )
        };
        if send_result == 0 {
            sent += bytes_sent as usize;
            continue;
        }

        let error = unsafe { WSAGetLastError() };
        if error != WSA_IO_PENDING {
            bail!("WSASend failed: {}", format_wsa_error(error));
        }

        let completed = wait_for_overlapped_socket(socket, &mut overlapped, "WSASend")?;
        ensure!(
            completed > 0,
            "WSASend completed without transferring any bytes"
        );
        sent += completed as usize;
    }

    Ok(())
}

fn send_all_blocking(socket: SOCKET, payload: &[u8]) -> Result<()> {
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
            bail!("send failed: {}", last_wsa_error());
        }
        ensure!(
            send_result > 0,
            "send returned zero before the request was fully written"
        );
        sent += send_result as usize;
    }

    Ok(())
}

fn send_all_wsa_blocking(socket: SOCKET, payload: &[u8]) -> Result<()> {
    let mut sent = 0usize;
    while sent < payload.len() {
        let mut bytes_sent = 0u32;
        let buffer = WSABUF {
            len: (payload.len() - sent) as u32,
            buf: payload[sent..].as_ptr() as *mut u8,
        };
        let send_result =
            unsafe { WSASend(socket, &buffer, 1, &mut bytes_sent, 0, null_mut(), None) };
        if send_result != 0 {
            bail!("WSASend failed: {}", last_wsa_error());
        }
        ensure!(
            bytes_sent > 0,
            "WSASend returned zero before the request was fully written"
        );
        sent += bytes_sent as usize;
    }

    Ok(())
}

fn recv_to_end_overlapped(socket: SOCKET) -> Result<Vec<u8>> {
    let mut response = Vec::new();

    loop {
        let recv_event = EventHandle::create().context("failed to create recv event")?;
        let mut overlapped = new_overlapped_with_event(recv_event.raw as HANDLE);
        let mut flags = 0u32;
        let mut bytes_recvd = 0u32;
        let mut buffer_storage = vec![0u8; 4096];
        let mut buffer = WSABUF {
            len: buffer_storage.len() as u32,
            buf: buffer_storage.as_mut_ptr(),
        };

        let recv_result = unsafe {
            WSARecv(
                socket,
                &mut buffer,
                1,
                &mut bytes_recvd,
                &mut flags,
                &mut overlapped,
                None,
            )
        };
        if recv_result == 0 {
            if bytes_recvd == 0 {
                break;
            }
            response.extend_from_slice(&buffer_storage[..bytes_recvd as usize]);
            continue;
        }

        let error = unsafe { WSAGetLastError() };
        if error != WSA_IO_PENDING {
            bail!("WSARecv failed: {}", format_wsa_error(error));
        }

        let completed = wait_for_overlapped_socket(socket, &mut overlapped, "WSARecv")?;
        if completed == 0 {
            break;
        }
        response.extend_from_slice(&buffer_storage[..completed as usize]);
    }

    Ok(response)
}

fn recv_to_end_blocking(socket: SOCKET) -> Result<Vec<u8>> {
    let mut response = Vec::new();
    let mut buffer = vec![0u8; 4096];

    loop {
        let recv_result = unsafe { recv(socket, buffer.as_mut_ptr(), buffer.len() as i32, 0) };
        if recv_result == -1 {
            bail!("recv failed: {}", last_wsa_error());
        }
        if recv_result == 0 {
            break;
        }

        response.extend_from_slice(&buffer[..recv_result as usize]);
    }

    Ok(response)
}

fn recv_to_end_wsa_blocking(socket: SOCKET) -> Result<Vec<u8>> {
    let mut response = Vec::new();
    let mut buffer_storage = vec![0u8; 4096];

    loop {
        let mut flags = 0u32;
        let mut bytes_recvd = 0u32;
        let mut buffer = WSABUF {
            len: buffer_storage.len() as u32,
            buf: buffer_storage.as_mut_ptr(),
        };

        let recv_result = unsafe {
            WSARecv(
                socket,
                &mut buffer,
                1,
                &mut bytes_recvd,
                &mut flags,
                null_mut(),
                None,
            )
        };
        if recv_result != 0 {
            bail!("WSARecv failed: {}", last_wsa_error());
        }
        ensure!(flags == 0, "WSARecv returned unexpected flags {flags}");
        if bytes_recvd == 0 {
            break;
        }

        response.extend_from_slice(&buffer_storage[..bytes_recvd as usize]);
    }

    Ok(response)
}

fn wait_for_nonblocking_connect(socket: SOCKET) -> Result<()> {
    let mut write_fds = FD_SET::default();
    write_fds.fd_count = 1;
    write_fds.fd_array[0] = socket;

    let mut except_fds = FD_SET::default();
    except_fds.fd_count = 1;
    except_fds.fd_array[0] = socket;

    let wait_result = unsafe { select(0, null_mut(), &mut write_fds, &mut except_fds, null()) };
    if wait_result == -1 {
        bail!(
            "select failed while waiting for connect: {}",
            last_wsa_error()
        );
    }
    ensure!(wait_result > 0, "select returned without any ready sockets");

    let mut socket_error = 0i32;
    let mut socket_error_len = std::mem::size_of::<i32>() as i32;
    let getsockopt_result = unsafe {
        getsockopt(
            socket,
            SOL_SOCKET,
            SO_ERROR,
            &mut socket_error as *mut i32 as *mut u8,
            &mut socket_error_len,
        )
    };
    if getsockopt_result != 0 {
        bail!(
            "getsockopt(SO_ERROR) failed while waiting for connect: {}",
            last_wsa_error()
        );
    }
    ensure!(
        socket_error == 0,
        "nonblocking connect completion reported {}",
        format_wsa_error(socket_error)
    );

    Ok(())
}

fn wait_for_event_select_connect(socket: SOCKET, event: isize) -> Result<()> {
    let event_handle = event as HANDLE;
    let wait_result = unsafe { WSAWaitForMultipleEvents(1, &event_handle, 0, INFINITE, 0) };
    if wait_result == WSA_WAIT_FAILED {
        bail!("WSAEventSelect wait failed: {}", last_wsa_error());
    }
    if wait_result == WSA_WAIT_TIMEOUT {
        bail!("WSAEventSelect wait timed out");
    }
    ensure!(
        wait_result == WAIT_OBJECT_0,
        "WSAEventSelect wait returned unexpected code {wait_result}"
    );

    let mut network_events = WSANETWORKEVENTS::default();
    let enum_result = unsafe { WSAEnumNetworkEvents(socket, event, &mut network_events) };
    if enum_result != 0 {
        bail!("WSAEnumNetworkEvents failed: {}", last_wsa_error());
    }

    ensure!(
        network_events.lNetworkEvents & FD_CONNECT as i32 != 0,
        "WSAEventSelect completed without FD_CONNECT"
    );

    let connect_error = network_events.iErrorCode[FD_CONNECT_BIT as usize];
    ensure!(
        connect_error == 0,
        "WSAEventSelect connect completion reported {}",
        format_wsa_error(connect_error)
    );

    Ok(())
}

fn wait_for_async_select_connect(socket: SOCKET, window: HWND) -> Result<()> {
    loop {
        let mut message = MaybeUninit::<MSG>::zeroed();
        let get_message_result = unsafe {
            GetMessageW(
                message.as_mut_ptr(),
                window,
                ASYNC_SELECT_CONNECT_MESSAGE,
                ASYNC_SELECT_CONNECT_MESSAGE,
            )
        };

        if get_message_result == -1 {
            bail!("GetMessageW failed while waiting for WSAAsyncSelect completion");
        }
        ensure!(
            get_message_result != 0,
            "GetMessageW returned WM_QUIT before WSAAsyncSelect completion"
        );

        let message = unsafe { message.assume_init() };
        ensure!(
            message.wParam == socket,
            "WSAAsyncSelect completion reported socket {} but expected {}",
            message.wParam,
            socket
        );

        let event_code = (message.lParam as u32 & 0xffff) as i32;
        let error_code = ((message.lParam as u32 >> 16) & 0xffff) as i32;
        ensure!(
            event_code & FD_CONNECT as i32 != 0,
            "WSAAsyncSelect completion reported unexpected event mask {event_code}"
        );
        ensure!(
            error_code == 0,
            "WSAAsyncSelect connect completion reported {}",
            format_wsa_error(error_code)
        );

        return Ok(());
    }
}

fn send_all_iocp(socket: SOCKET, completion_port: HANDLE, payload: &[u8]) -> Result<()> {
    let mut sent = 0usize;
    while sent < payload.len() {
        let mut overlapped = OVERLAPPED::default();
        let mut bytes_sent = 0u32;
        let buffer = WSABUF {
            len: (payload.len() - sent) as u32,
            buf: payload[sent..].as_ptr() as *mut u8,
        };

        let send_result = unsafe {
            WSASend(
                socket,
                &buffer,
                1,
                &mut bytes_sent,
                0,
                &mut overlapped,
                None,
            )
        };
        if send_result == 0 {
            sent += bytes_sent as usize;
            continue;
        }

        let error = unsafe { WSAGetLastError() };
        if error != WSA_IO_PENDING {
            bail!("WSASend failed: {}", format_wsa_error(error));
        }

        let completed = wait_for_iocp(completion_port, &mut overlapped, "WSASend")?;
        ensure!(
            completed > 0,
            "WSASend completed without transferring any bytes"
        );
        sent += completed as usize;
    }

    Ok(())
}

fn recv_to_end_iocp(socket: SOCKET, completion_port: HANDLE) -> Result<Vec<u8>> {
    let mut response = Vec::new();

    loop {
        let mut overlapped = OVERLAPPED::default();
        let mut flags = 0u32;
        let mut bytes_recvd = 0u32;
        let mut buffer_storage = vec![0u8; 4096];
        let mut buffer = WSABUF {
            len: buffer_storage.len() as u32,
            buf: buffer_storage.as_mut_ptr(),
        };

        let recv_result = unsafe {
            WSARecv(
                socket,
                &mut buffer,
                1,
                &mut bytes_recvd,
                &mut flags,
                &mut overlapped,
                None,
            )
        };
        if recv_result == 0 {
            if bytes_recvd == 0 {
                break;
            }
            response.extend_from_slice(&buffer_storage[..bytes_recvd as usize]);
            continue;
        }

        let error = unsafe { WSAGetLastError() };
        if error != WSA_IO_PENDING {
            bail!("WSARecv failed: {}", format_wsa_error(error));
        }

        let completed = wait_for_iocp(completion_port, &mut overlapped, "WSARecv")?;
        if completed == 0 {
            break;
        }
        response.extend_from_slice(&buffer_storage[..completed as usize]);
    }

    Ok(response)
}

fn submit_iocp_connect(
    target: &ResolvedTarget,
    connection_index: usize,
    connections: &mut [IocpTrackedConnection],
    active_operations: &mut HashMap<usize, Box<IocpOperation>>,
    _completed_operations: &mut HashMap<usize, CompletedIocpOperation>,
) -> Result<Option<IocpCompletion>> {
    let connection = &mut connections[connection_index];
    let mut operation = Box::new(IocpOperation::new(
        connection_index,
        connection.socket.raw,
        connection.completion_key,
        IocpOperationKind::Connect,
        Vec::new(),
    ));
    let operation_ptr = operation.overlapped_ptr();
    let mut bytes_sent = 0u32;

    let connect_result = unsafe {
        (connection.connect_ex)(
            connection.socket.raw,
            target.addr(),
            target.addr_len,
            null(),
            0,
            &mut bytes_sent,
            operation_ptr,
        )
    };
    if connect_result == 0 {
        let error = unsafe { WSAGetLastError() };
        if error != WSA_IO_PENDING {
            bail!(
                "ConnectEx for connection {} to {} failed: {}",
                connection_index + 1,
                target.display_name,
                format_wsa_error(error)
            );
        }

        active_operations.insert(operation_ptr as usize, operation);
        return Ok(None);
    }

    active_operations.insert(operation_ptr as usize, operation);
    Ok(Some(IocpCompletion {
        transferred: bytes_sent,
        completion_key: connection.completion_key,
        overlapped: operation_ptr,
        source: IocpCompletionSource::Immediate,
    }))
}

fn submit_iocp_send(
    connection_index: usize,
    connections: &mut [IocpTrackedConnection],
    payload: &[u8],
    active_operations: &mut HashMap<usize, Box<IocpOperation>>,
    _completed_operations: &mut HashMap<usize, CompletedIocpOperation>,
) -> Result<Option<IocpCompletion>> {
    let connection = &mut connections[connection_index];
    let start_offset = connection.sent_total;
    ensure!(
        start_offset < payload.len(),
        "connection {} has no payload remaining to send",
        connection_index + 1
    );

    let mut operation = Box::new(IocpOperation::new(
        connection_index,
        connection.socket.raw,
        connection.completion_key,
        IocpOperationKind::Send { start_offset },
        payload[start_offset..].to_vec(),
    ));
    let operation_ptr = operation.overlapped_ptr();
    let mut bytes_sent = 0u32;
    let buffer = WSABUF {
        len: operation.buffer.len() as u32,
        buf: operation.buffer.as_mut_ptr(),
    };

    let send_result = unsafe {
        WSASend(
            connection.socket.raw,
            &buffer,
            1,
            &mut bytes_sent,
            0,
            operation_ptr,
            None,
        )
    };
    if send_result == 0 {
        active_operations.insert(operation_ptr as usize, operation);
        return Ok(Some(IocpCompletion {
            transferred: bytes_sent,
            completion_key: connection.completion_key,
            overlapped: operation_ptr,
            source: IocpCompletionSource::Immediate,
        }));
    }

    let error = unsafe { WSAGetLastError() };
    if error != WSA_IO_PENDING {
        bail!(
            "WSASend for connection {} failed: {}",
            connection_index + 1,
            format_wsa_error(error)
        );
    }

    active_operations.insert(operation_ptr as usize, operation);
    Ok(None)
}

fn submit_iocp_recv(
    connection_index: usize,
    connections: &mut [IocpTrackedConnection],
    active_operations: &mut HashMap<usize, Box<IocpOperation>>,
    _completed_operations: &mut HashMap<usize, CompletedIocpOperation>,
) -> Result<Option<IocpCompletion>> {
    let connection = &mut connections[connection_index];
    let mut operation = Box::new(IocpOperation::new(
        connection_index,
        connection.socket.raw,
        connection.completion_key,
        IocpOperationKind::Recv,
        vec![0u8; 4096],
    ));
    let operation_ptr = operation.overlapped_ptr();
    let mut flags = 0u32;
    let mut bytes_recvd = 0u32;
    let mut buffer = WSABUF {
        len: operation.buffer.len() as u32,
        buf: operation.buffer.as_mut_ptr(),
    };

    let recv_result = unsafe {
        WSARecv(
            connection.socket.raw,
            &mut buffer,
            1,
            &mut bytes_recvd,
            &mut flags,
            operation_ptr,
            None,
        )
    };
    if recv_result == 0 {
        active_operations.insert(operation_ptr as usize, operation);
        return Ok(Some(IocpCompletion {
            transferred: bytes_recvd,
            completion_key: connection.completion_key,
            overlapped: operation_ptr,
            source: IocpCompletionSource::Immediate,
        }));
    }

    let error = unsafe { WSAGetLastError() };
    if error != WSA_IO_PENDING {
        bail!(
            "WSARecv for connection {} failed: {}",
            connection_index + 1,
            format_wsa_error(error)
        );
    }

    active_operations.insert(operation_ptr as usize, operation);
    Ok(None)
}

fn enqueue_immediate_completion(
    completion: Option<IocpCompletion>,
    ready_completions: &mut Vec<IocpCompletion>,
) {
    if let Some(completion) = completion {
        ready_completions.push(completion);
    }
}

fn process_iocp_completion(
    completion: IocpCompletion,
    connections: &mut [IocpTrackedConnection],
    payload: &[u8],
    completion_port: HANDLE,
    active_operations: &mut HashMap<usize, Box<IocpOperation>>,
    completed_operations: &mut HashMap<usize, CompletedIocpOperation>,
    ready_completions: &mut Vec<IocpCompletion>,
) -> Result<()> {
    let operation_key = completion.overlapped as usize;

    if let Some(mut operation) = active_operations.remove(&operation_key) {
        verify_iocp_completion(&completion, &mut operation, connections)?;
        let result = complete_iocp_operation(
            completion,
            &mut operation,
            connections,
            payload,
            completion_port,
            active_operations,
            completed_operations,
            ready_completions,
        );
        if matches!(completion.source, IocpCompletionSource::Immediate) {
            completed_operations.insert(
                operation_key,
                CompletedIocpOperation::from_operation(&completion, operation),
            );
        }
        return result;
    }

    if let Some(completed_operation) = completed_operations.get(&operation_key) {
        verify_completed_iocp_completion(&completion, completed_operation, connections)?;
        return Ok(());
    }

    bail!(
        "IOCP returned an unknown OVERLAPPED pointer {:p}",
        completion.overlapped
    )
}

fn verify_iocp_completion(
    completion: &IocpCompletion,
    operation: &mut IocpOperation,
    connections: &[IocpTrackedConnection],
) -> Result<()> {
    ensure!(
        completion.overlapped == operation.overlapped_ptr(),
        "completion OVERLAPPED pointer {:p} did not match operation pointer {:p}",
        completion.overlapped,
        operation.overlapped_ptr()
    );
    ensure!(
        operation.connection_index < connections.len(),
        "completion referenced invalid connection index {}",
        operation.connection_index
    );

    let connection = &connections[operation.connection_index];
    ensure!(
        completion.completion_key == operation.completion_key,
        "completion key {} did not match operation key {} for connection {}",
        completion.completion_key,
        operation.completion_key,
        operation.connection_index + 1
    );
    ensure!(
        connection.completion_key == completion.completion_key,
        "completion key {} did not match socket association key {} for connection {}",
        completion.completion_key,
        connection.completion_key,
        operation.connection_index + 1
    );
    ensure!(
        connection.socket.raw == operation.socket,
        "completion socket {} did not match tracked socket {} for connection {}",
        operation.socket,
        connection.socket.raw,
        operation.connection_index + 1
    );

    if matches!(completion.source, IocpCompletionSource::Immediate) {
        return Ok(());
    }

    let mut overlapped_bytes = 0u32;
    let mut flags = 0u32;
    let ok = unsafe {
        WSAGetOverlappedResult(
            operation.socket,
            operation.overlapped_ptr(),
            &mut overlapped_bytes,
            0,
            &mut flags,
        )
    };
    if ok == 0 {
        bail!(
            "WSAGetOverlappedResult failed for connection {}: {}",
            operation.connection_index + 1,
            last_wsa_error()
        );
    }

    ensure!(
        overlapped_bytes == completion.transferred,
        "completion for connection {} reported {} bytes from IOCP and {} bytes from WSAGetOverlappedResult",
        operation.connection_index + 1,
        completion.transferred,
        overlapped_bytes
    );
    ensure!(
        flags == 0,
        "completion for connection {} returned unexpected flags {flags}",
        operation.connection_index + 1
    );

    Ok(())
}

fn complete_iocp_operation(
    completion: IocpCompletion,
    operation: &mut IocpOperation,
    connections: &mut [IocpTrackedConnection],
    payload: &[u8],
    _completion_port: HANDLE,
    active_operations: &mut HashMap<usize, Box<IocpOperation>>,
    completed_operations: &mut HashMap<usize, CompletedIocpOperation>,
    ready_completions: &mut Vec<IocpCompletion>,
) -> Result<()> {
    let connection_index = operation.connection_index;

    match operation.kind {
        IocpOperationKind::Connect => {
            ensure!(
                completion.transferred == 0,
                "ConnectEx for connection {} completed with unexpected byte count {}",
                connection_index + 1,
                completion.transferred
            );
            ensure!(
                operation.buffer.is_empty(),
                "ConnectEx for connection {} unexpectedly carried a payload",
                connection_index + 1
            );

            {
                let connection = &mut connections[connection_index];
                ensure!(
                    !connection.connect_complete,
                    "connection {} completed ConnectEx twice",
                    connection_index + 1
                );
                update_connect_context(connection.socket.raw).with_context(|| {
                    format!(
                        "failed to update connect context for connection {}",
                        connection_index + 1
                    )
                })?;
                connection.connect_complete = true;
            }

            enqueue_immediate_completion(
                submit_iocp_send(
                    connection_index,
                    connections,
                    payload,
                    active_operations,
                    completed_operations,
                )?,
                ready_completions,
            );
        }
        IocpOperationKind::Send { start_offset } => {
            let transferred = completion.transferred as usize;
            ensure!(
                transferred > 0,
                "WSASend for connection {} completed without transferring any bytes",
                connection_index + 1
            );
            ensure!(
                start_offset < payload.len(),
                "WSASend for connection {} started past the end of the payload",
                connection_index + 1
            );

            let expected = &payload[start_offset..];
            ensure!(
                operation.buffer.as_slice() == expected,
                "WSASend for connection {} used an unexpected payload buffer",
                connection_index + 1
            );
            ensure!(
                transferred <= expected.len(),
                "WSASend for connection {} transferred {} bytes from a {} byte buffer",
                connection_index + 1,
                transferred,
                expected.len()
            );

            let should_start_recv = {
                let connection = &mut connections[connection_index];
                ensure!(
                    connection.connect_complete,
                    "WSASend for connection {} completed before ConnectEx",
                    connection_index + 1
                );
                ensure!(
                    !connection.send_complete,
                    "WSASend for connection {} completed after the send phase had already finished",
                    connection_index + 1
                );
                ensure!(
                    connection.sent_total == start_offset,
                    "WSASend for connection {} completed out of order: expected offset {}, got {}",
                    connection_index + 1,
                    connection.sent_total,
                    start_offset
                );

                connection.sent_total += transferred;
                connection.sent_total == payload.len()
            };

            if should_start_recv {
                connections[connection_index].send_complete = true;
                enqueue_immediate_completion(
                    submit_iocp_recv(
                        connection_index,
                        connections,
                        active_operations,
                        completed_operations,
                    )?,
                    ready_completions,
                );
            } else {
                enqueue_immediate_completion(
                    submit_iocp_send(
                        connection_index,
                        connections,
                        payload,
                        active_operations,
                        completed_operations,
                    )?,
                    ready_completions,
                );
            }
        }
        IocpOperationKind::Recv => {
            let transferred = completion.transferred as usize;
            ensure!(
                transferred <= operation.buffer.len(),
                "WSARecv for connection {} transferred {} bytes into a {} byte buffer",
                connection_index + 1,
                transferred,
                operation.buffer.len()
            );

            let should_continue = {
                let connection = &mut connections[connection_index];
                ensure!(
                    connection.send_complete,
                    "WSARecv for connection {} completed before the full request was sent",
                    connection_index + 1
                );
                ensure!(
                    !connection.recv_complete,
                    "WSARecv for connection {} completed after EOF had already been observed",
                    connection_index + 1
                );

                if transferred == 0 {
                    connection.recv_complete = true;
                    false
                } else {
                    connection
                        .response
                        .extend_from_slice(&operation.buffer[..transferred]);
                    true
                }
            };

            if should_continue {
                enqueue_immediate_completion(
                    submit_iocp_recv(
                        connection_index,
                        connections,
                        active_operations,
                        completed_operations,
                    )?,
                    ready_completions,
                );
            }
        }
    }

    Ok(())
}

fn validate_iocp_multiple_results(
    connections: &[IocpTrackedConnection],
    payload: &[u8],
) -> Result<()> {
    ensure!(
        connections.len() == 2,
        "iocp-multiple expected exactly two connections, got {}",
        connections.len()
    );

    for (connection_index, connection) in connections.iter().enumerate() {
        ensure!(
            connection.connect_complete,
            "connection {} never completed ConnectEx",
            connection_index + 1
        );
        ensure!(
            connection.send_complete,
            "connection {} never finished sending the request payload",
            connection_index + 1
        );
        ensure!(
            connection.recv_complete,
            "connection {} never observed EOF on the response stream",
            connection_index + 1
        );
        ensure!(
            connection.sent_total == payload.len(),
            "connection {} only sent {} of {} request bytes",
            connection_index + 1,
            connection.sent_total,
            payload.len()
        );
        validate_http_response(connection_index, &connection.response)?;
    }

    Ok(())
}

fn validate_http_response(connection_index: usize, response: &[u8]) -> Result<()> {
    ensure!(
        !response.is_empty(),
        "connection {} received an empty response",
        connection_index + 1
    );
    ensure!(
        response.starts_with(b"HTTP/"),
        "connection {} received a non-HTTP response",
        connection_index + 1
    );

    let Some(header_end) = response.windows(4).position(|window| window == b"\r\n\r\n") else {
        bail!(
            "connection {} response did not contain a complete HTTP header",
            connection_index + 1
        );
    };
    let header_end = header_end + 4;

    if let Some(content_length) = parse_content_length(&response[..header_end])? {
        ensure!(
            response.len() == header_end + content_length,
            "connection {} response length {} did not match Content-Length {}",
            connection_index + 1,
            response.len() - header_end,
            content_length
        );
    }

    Ok(())
}

fn parse_content_length(headers: &[u8]) -> Result<Option<usize>> {
    let header_text = String::from_utf8_lossy(headers);

    for line in header_text.split("\r\n") {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };

        if !name.eq_ignore_ascii_case("Content-Length") {
            continue;
        }

        let value = value.trim();
        let parsed = value
            .parse::<usize>()
            .with_context(|| format!("invalid Content-Length header value {value:?}"))?;
        return Ok(Some(parsed));
    }

    Ok(None)
}

fn print_multiple_iocp_responses(responses: &[Vec<u8>]) {
    for (index, response) in responses.iter().enumerate() {
        if index > 0 {
            println!();
        }

        println!("--- response {} ---", index + 1);
        print!("{}", String::from_utf8_lossy(response));
    }
}

fn wait_for_overlapped_socket(
    socket: SOCKET,
    overlapped: &mut OVERLAPPED,
    operation: &str,
) -> Result<u32> {
    let event = overlapped.hEvent;
    ensure!(
        event != null_mut(),
        "{operation} requires a valid event handle"
    );

    let wait_result = unsafe { WSAWaitForMultipleEvents(1, &event, 0, INFINITE, 0) };
    if wait_result == WSA_WAIT_FAILED {
        bail!("{operation} wait failed: {}", last_wsa_error());
    }
    if wait_result == WSA_WAIT_TIMEOUT {
        bail!("{operation} wait timed out");
    }
    ensure!(
        wait_result == WAIT_OBJECT_0,
        "{operation} wait returned unexpected code {wait_result}"
    );

    let mut transferred = 0u32;
    let mut flags = 0u32;
    let ok = unsafe { WSAGetOverlappedResult(socket, overlapped, &mut transferred, 0, &mut flags) };
    if ok == 0 {
        bail!("{operation} completion failed: {}", last_wsa_error());
    }

    Ok(transferred)
}

fn wait_for_iocp(
    completion_port: HANDLE,
    overlapped: &mut OVERLAPPED,
    operation: &str,
) -> Result<u32> {
    let expected_overlapped = overlapped as *mut OVERLAPPED;

    loop {
        let mut transferred = 0u32;
        let mut completion_key = 0usize;
        let mut completed_overlapped = null_mut();

        let ok = unsafe {
            GetQueuedCompletionStatus(
                completion_port,
                &mut transferred,
                &mut completion_key,
                &mut completed_overlapped,
                INFINITE,
            )
        };

        if completed_overlapped != expected_overlapped {
            if completed_overlapped.is_null() {
                bail!("{operation} completion failed: {}", last_wsa_error());
            }

            // Winsock can still queue an IOCP packet for an earlier operation that
            // already completed synchronously. Ignore those stale completions and
            // keep waiting for the OVERLAPPED backing the operation we marked pending.
            continue;
        }

        if ok == 0 {
            bail!("{operation} completion failed: {}", last_wsa_error());
        }

        let _ = completion_key;
        return Ok(transferred);
    }
}

fn new_overlapped_with_event(event: HANDLE) -> OVERLAPPED {
    let mut overlapped = OVERLAPPED::default();
    overlapped.hEvent = event;
    overlapped
}

fn last_wsa_error() -> String {
    format_wsa_error(unsafe { WSAGetLastError() })
}

fn format_wsa_error(code: i32) -> String {
    format!("WSA error {code}")
}

fn wide_null(value: &str) -> Vec<u16> {
    OsStr::new(value)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

type ConnectExFn = unsafe extern "system" fn(
    SOCKET,
    *const SOCKADDR,
    i32,
    *const core::ffi::c_void,
    u32,
    *mut u32,
    *mut OVERLAPPED,
) -> windows_sys::core::BOOL;

#[derive(Debug, Parser)]
#[command(name = "win-proxychains-test-target", arg_required_else_help = true)]
struct Cli {
    #[command(subcommand)]
    command: CommandKind,
}

#[derive(Debug, Subcommand)]
enum CommandKind {
    Connect {
        host: String,
        port: u16,
        string_to_send: String,
    },
    ConnectWsa {
        host: String,
        port: u16,
        string_to_send: String,
    },
    ConnectNonblocking {
        host: String,
        port: u16,
        string_to_send: String,
    },
    ConnectEventSelect {
        host: String,
        port: u16,
        string_to_send: String,
    },
    ConnectAsyncSelect {
        host: String,
        port: u16,
        string_to_send: String,
    },
    ConnectOverlapped {
        host: String,
        port: u16,
        string_to_send: String,
    },
    ConnectIOCP {
        host: String,
        port: u16,
        string_to_send: String,
    },
    IocpMultiple {
        host: String,
        port: u16,
        string_to_send: String,
    },
    Spawn,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SpawnPlan {
    program: PathBuf,
    args: Vec<String>,
}

#[derive(Clone)]
struct ResolvedTarget {
    family: i32,
    socktype: i32,
    protocol: i32,
    addr_len: i32,
    storage: SOCKADDR_STORAGE,
    display_name: String,
}

impl ResolvedTarget {
    fn addr(&self) -> *const SOCKADDR {
        &self.storage as *const SOCKADDR_STORAGE as *const SOCKADDR
    }
}

struct IocpTrackedConnection {
    socket: SocketHandle,
    completion_key: usize,
    connect_ex: ConnectExFn,
    sent_total: usize,
    response: Vec<u8>,
    connect_complete: bool,
    send_complete: bool,
    recv_complete: bool,
}

impl IocpTrackedConnection {
    fn new(socket: SocketHandle, completion_key: usize, connect_ex: ConnectExFn) -> Self {
        Self {
            socket,
            completion_key,
            connect_ex,
            sent_total: 0,
            response: Vec::new(),
            connect_complete: false,
            send_complete: false,
            recv_complete: false,
        }
    }

    fn is_complete(&self) -> bool {
        self.connect_complete && self.send_complete && self.recv_complete
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum IocpOperationKind {
    Connect,
    Send { start_offset: usize },
    Recv,
}

#[repr(C)]
struct IocpOperation {
    overlapped: OVERLAPPED,
    connection_index: usize,
    socket: SOCKET,
    completion_key: usize,
    kind: IocpOperationKind,
    buffer: Vec<u8>,
}

impl IocpOperation {
    fn new(
        connection_index: usize,
        socket: SOCKET,
        completion_key: usize,
        kind: IocpOperationKind,
        buffer: Vec<u8>,
    ) -> Self {
        Self {
            overlapped: OVERLAPPED::default(),
            connection_index,
            socket,
            completion_key,
            kind,
            buffer,
        }
    }

    fn overlapped_ptr(&mut self) -> *mut OVERLAPPED {
        &mut self.overlapped
    }

    fn overlapped_addr(&self) -> usize {
        &self.overlapped as *const OVERLAPPED as usize
    }
}

#[derive(Debug, Clone, Copy)]
struct IocpCompletion {
    transferred: u32,
    completion_key: usize,
    overlapped: *mut OVERLAPPED,
    source: IocpCompletionSource,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum IocpCompletionSource {
    Immediate,
    Queued,
}

struct CompletedIocpOperation {
    operation: Box<IocpOperation>,
    transferred: u32,
    source: IocpCompletionSource,
}

impl CompletedIocpOperation {
    fn from_operation(completion: &IocpCompletion, operation: Box<IocpOperation>) -> Self {
        Self {
            operation,
            transferred: completion.transferred,
            source: completion.source,
        }
    }
}

fn verify_completed_iocp_completion(
    completion: &IocpCompletion,
    operation: &CompletedIocpOperation,
    connections: &[IocpTrackedConnection],
) -> Result<()> {
    let completed_operation = &operation.operation;

    ensure!(
        matches!(completion.source, IocpCompletionSource::Queued),
        "completed operation received an unexpected inline completion replay"
    );
    ensure!(
        matches!(operation.source, IocpCompletionSource::Immediate),
        "received an unexpected duplicate IOCP completion for connection {}",
        completed_operation.connection_index + 1
    );
    ensure!(
        completed_operation.connection_index < connections.len(),
        "late completion referenced invalid connection index {}",
        completed_operation.connection_index
    );

    let connection = &connections[completed_operation.connection_index];
    ensure!(
        completion.overlapped as usize == completed_operation.overlapped_addr(),
        "late completion OVERLAPPED pointer {:p} did not match completed operation pointer {:p}",
        completion.overlapped,
        completed_operation.overlapped_addr() as *mut OVERLAPPED
    );
    ensure!(
        completion.completion_key == completed_operation.completion_key,
        "late completion key {} did not match completed operation key {} for connection {}",
        completion.completion_key,
        completed_operation.completion_key,
        completed_operation.connection_index + 1
    );
    ensure!(
        connection.completion_key == completion.completion_key,
        "late completion key {} did not match socket association key {} for connection {}",
        completion.completion_key,
        connection.completion_key,
        completed_operation.connection_index + 1
    );
    ensure!(
        connection.socket.raw == completed_operation.socket,
        "late completion socket {} did not match tracked socket {} for connection {}",
        completed_operation.socket,
        connection.socket.raw,
        completed_operation.connection_index + 1
    );
    ensure!(
        completion.transferred == operation.transferred,
        "late completion for connection {} reported {} bytes, expected {}",
        completed_operation.connection_index + 1,
        completion.transferred,
        operation.transferred
    );

    Ok(())
}

struct AddrInfoList {
    raw: *mut ADDRINFOW,
}

impl Drop for AddrInfoList {
    fn drop(&mut self) {
        if !self.raw.is_null() {
            unsafe { FreeAddrInfoW(self.raw) };
        }
    }
}

struct SocketHandle {
    raw: SOCKET,
}

impl Drop for SocketHandle {
    fn drop(&mut self) {
        if self.raw != INVALID_SOCKET {
            unsafe {
                closesocket(self.raw);
            }
        }
    }
}

struct EventHandle {
    raw: isize,
}

impl EventHandle {
    fn create() -> Result<Self> {
        let raw = unsafe { WSACreateEvent() };
        if raw == 0 {
            bail!("WSACreateEvent failed: {}", last_wsa_error());
        }
        Ok(Self { raw })
    }
}

impl Drop for EventHandle {
    fn drop(&mut self) {
        if self.raw != 0 {
            unsafe {
                WSACloseEvent(self.raw);
            }
        }
    }
}

struct WindowHandle {
    raw: HWND,
}

impl WindowHandle {
    fn create_async_select_window() -> Result<Self> {
        let class_name = wide_null("STATIC");
        let window_name = wide_null("win-proxychains-async-connect");
        let raw = unsafe {
            CreateWindowExW(
                0,
                class_name.as_ptr(),
                window_name.as_ptr(),
                0,
                0,
                0,
                0,
                0,
                null_mut(),
                null_mut(),
                null_mut(),
                null(),
            )
        };
        if raw == null_mut() {
            bail!("CreateWindowExW(STATIC) failed");
        }

        Ok(Self { raw })
    }
}

impl Drop for WindowHandle {
    fn drop(&mut self) {
        if self.raw != null_mut() {
            unsafe {
                let _ = DestroyWindow(self.raw);
            }
        }
    }
}

struct CompletionPort {
    raw: HANDLE,
}

impl CompletionPort {
    fn new() -> Result<Self> {
        let raw = unsafe { CreateIoCompletionPort(INVALID_HANDLE_VALUE, null_mut(), 0, 0) };
        if raw == null_mut() {
            bail!("CreateIoCompletionPort failed");
        }
        Ok(Self { raw })
    }

    fn associate_socket(&self, socket: SOCKET, completion_key: usize) -> Result<()> {
        let associated =
            unsafe { CreateIoCompletionPort(socket as HANDLE, self.raw, completion_key, 0) };
        if associated == null_mut() {
            bail!("CreateIoCompletionPort(socket) failed");
        }
        Ok(())
    }

    fn wait(&self, overlapped: &mut OVERLAPPED, operation: &str) -> Result<u32> {
        wait_for_iocp(self.raw, overlapped, operation)
    }

    fn dequeue(&self) -> Result<IocpCompletion> {
        let mut transferred = 0u32;
        let mut completion_key = 0usize;
        let mut completed_overlapped = null_mut();

        let ok = unsafe {
            GetQueuedCompletionStatus(
                self.raw,
                &mut transferred,
                &mut completion_key,
                &mut completed_overlapped,
                INFINITE,
            )
        };
        if completed_overlapped.is_null() {
            bail!("GetQueuedCompletionStatus failed: {}", last_wsa_error());
        }
        if ok == 0 {
            bail!("GetQueuedCompletionStatus failed: {}", last_wsa_error());
        }

        Ok(IocpCompletion {
            transferred,
            completion_key,
            overlapped: completed_overlapped,
            source: IocpCompletionSource::Queued,
        })
    }
}

impl Drop for CompletionPort {
    fn drop(&mut self) {
        if self.raw != null_mut() && self.raw != INVALID_HANDLE_VALUE {
            unsafe {
                CloseHandle(self.raw);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Cli, CommandKind, SpawnPlan, current_exe_path, normalize_string_to_send};
    use clap::Parser;
    use std::path::PathBuf;

    #[test]
    fn parses_connect_command() {
        let cli = Cli::parse_from([
            "win-proxychains-test-target",
            "connect",
            "example.com",
            "80",
            "GET / HTTP/1.1\\r\\nHost: example.com\\r\\n\\r\\n",
        ]);

        match cli.command {
            CommandKind::Connect {
                host,
                port,
                string_to_send,
            } => {
                assert_eq!(host, "example.com");
                assert_eq!(port, 80);
                assert_eq!(
                    string_to_send,
                    "GET / HTTP/1.1\\r\\nHost: example.com\\r\\n\\r\\n"
                );
            }
            _ => panic!("expected connect command"),
        }
    }

    #[test]
    fn parses_connect_overlapped_command() {
        let cli = Cli::parse_from([
            "win-proxychains-test-target",
            "connect-overlapped",
            "example.com",
            "80",
            "ping",
        ]);

        match cli.command {
            CommandKind::ConnectOverlapped {
                host,
                port,
                string_to_send,
            } => {
                assert_eq!(host, "example.com");
                assert_eq!(port, 80);
                assert_eq!(string_to_send, "ping");
            }
            _ => panic!("expected connect-overlapped command"),
        }
    }

    #[test]
    fn parses_connect_wsa_command() {
        let cli = Cli::parse_from([
            "win-proxychains-test-target",
            "connect-wsa",
            "example.com",
            "80",
            "ping",
        ]);

        match cli.command {
            CommandKind::ConnectWsa {
                host,
                port,
                string_to_send,
            } => {
                assert_eq!(host, "example.com");
                assert_eq!(port, 80);
                assert_eq!(string_to_send, "ping");
            }
            _ => panic!("expected connect-wsa command"),
        }
    }

    #[test]
    fn parses_connect_nonblocking_command() {
        let cli = Cli::parse_from([
            "win-proxychains-test-target",
            "connect-nonblocking",
            "example.com",
            "80",
            "ping",
        ]);

        match cli.command {
            CommandKind::ConnectNonblocking {
                host,
                port,
                string_to_send,
            } => {
                assert_eq!(host, "example.com");
                assert_eq!(port, 80);
                assert_eq!(string_to_send, "ping");
            }
            _ => panic!("expected connect-nonblocking command"),
        }
    }

    #[test]
    fn parses_connect_event_select_command() {
        let cli = Cli::parse_from([
            "win-proxychains-test-target",
            "connect-event-select",
            "example.com",
            "80",
            "ping",
        ]);

        match cli.command {
            CommandKind::ConnectEventSelect {
                host,
                port,
                string_to_send,
            } => {
                assert_eq!(host, "example.com");
                assert_eq!(port, 80);
                assert_eq!(string_to_send, "ping");
            }
            _ => panic!("expected connect-event-select command"),
        }
    }

    #[test]
    fn parses_connect_async_select_command() {
        let cli = Cli::parse_from([
            "win-proxychains-test-target",
            "connect-async-select",
            "example.com",
            "80",
            "ping",
        ]);

        match cli.command {
            CommandKind::ConnectAsyncSelect {
                host,
                port,
                string_to_send,
            } => {
                assert_eq!(host, "example.com");
                assert_eq!(port, 80);
                assert_eq!(string_to_send, "ping");
            }
            _ => panic!("expected connect-async-select command"),
        }
    }

    #[test]
    fn parses_connect_iocp_command() {
        let cli = Cli::parse_from([
            "win-proxychains-test-target",
            "connect-iocp",
            "example.com",
            "80",
            "ping",
        ]);

        match cli.command {
            CommandKind::ConnectIOCP {
                host,
                port,
                string_to_send,
            } => {
                assert_eq!(host, "example.com");
                assert_eq!(port, 80);
                assert_eq!(string_to_send, "ping");
            }
            _ => panic!("expected connect-iocp command"),
        }
    }

    #[test]
    fn parses_iocp_multiple_command() {
        let cli = Cli::parse_from([
            "win-proxychains-test-target",
            "iocp-multiple",
            "example.com",
            "80",
            "ping",
        ]);

        match cli.command {
            CommandKind::IocpMultiple {
                host,
                port,
                string_to_send,
            } => {
                assert_eq!(host, "example.com");
                assert_eq!(port, 80);
                assert_eq!(string_to_send, "ping");
            }
            _ => panic!("expected iocp-multiple command"),
        }
    }

    #[test]
    fn parses_spawn_command() {
        let cli = Cli::parse_from(["win-proxychains-test-target", "spawn"]);

        assert!(matches!(cli.command, CommandKind::Spawn));
    }

    #[test]
    fn normalizes_literal_crlf_sequences() {
        assert_eq!(
            normalize_string_to_send("line1\\r\\nline2\\r\\n"),
            "line1\r\nline2\r\n"
        );
    }

    #[test]
    fn spawn_plan_supports_custom_arguments() {
        let plan = SpawnPlan {
            program: PathBuf::from("win-proxychains-test-target.exe"),
            args: vec![
                "connect".into(),
                "localhost".into(),
                "8080".into(),
                "ping".into(),
            ],
        };

        assert_eq!(plan.args[0], "connect");
        assert_eq!(plan.args[1], "localhost");
        assert_eq!(plan.args[2], "8080");
        assert_eq!(plan.args[3], "ping");
    }

    #[test]
    fn resolves_current_executable_path() {
        let path = current_exe_path().expect("current exe path should resolve during tests");
        assert!(!path.as_os_str().is_empty());
    }
}
