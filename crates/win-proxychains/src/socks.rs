use std::{
    mem::size_of,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6},
    ptr::null_mut,
    thread,
    time::{Duration, Instant},
};

use anyhow::Result;
use windows_sys::Win32::Networking::WinSock::{
    ADDRINFOW, AF_INET, AF_INET6, AF_UNSPEC, IN_ADDR, IN_ADDR_0, IN_ADDR_0_0, IN6_ADDR, IN6_ADDR_0,
    IPPROTO_TCP, SO_RCVTIMEO, SO_SNDTIMEO, SOCK_STREAM, SOCKADDR, SOCKADDR_IN, SOCKADDR_IN6,
    SOCKADDR_IN6_0, SOL_SOCKET, WSAEALREADY, WSAEINPROGRESS, WSAEISCONN, WSAEWOULDBLOCK,
    WSAGetLastError, recv, send, setsockopt,
};

use crate::{
    bail_with_last_error,
    config::{ProxyEntry, ProxyType},
    hooks_dns::{o_FreeAddrInfoW, o_GetAddrInfoW, reverse_fake_dns_name},
    hooks_sockets::o_connect,
};

const WINSOCK_SPIN_WAIT: Duration = Duration::from_millis(0);
const DEFAULT_TCP_CONNECT_TIMEOUT_MS: u64 = 20_000;

type SpinTimeout = Option<(u64, Instant)>;

fn spin_on_would_block(error_code: i32) -> bool {
    matches!(
        error_code,
        code if code == WSAEWOULDBLOCK as i32
            || code == WSAEINPROGRESS as i32
            || code == WSAEALREADY as i32
    )
}

fn spin_wait() {
    thread::sleep(WINSOCK_SPIN_WAIT);
}

fn new_spin_timeout(timeout_ms: Option<u64>) -> SpinTimeout {
    timeout_ms.map(|timeout_ms| {
        (
            timeout_ms,
            Instant::now() + Duration::from_millis(timeout_ms),
        )
    })
}

fn bail_with_socket_error<T>(message: impl std::fmt::Display) -> Result<T> {
    let error_code = unsafe { WSAGetLastError() };
    let full_message = format!("{message}: WSA error {error_code}");
    crate::set_last_error(full_message.clone());
    Err(anyhow::anyhow!(full_message))
}

fn timeout_error<T>(timeout_ms: u64, message: impl std::fmt::Display) -> Result<T> {
    let full_message = format!("Timed out after {timeout_ms}ms while {message}");
    crate::set_last_error(full_message.clone());
    Err(anyhow::anyhow!(full_message))
}

fn spin_wait_with_timeout(timeout: SpinTimeout, message: impl std::fmt::Display) -> Result<()> {
    if let Some((timeout_ms, deadline)) = timeout {
        if Instant::now() >= deadline {
            return timeout_error(timeout_ms, message);
        }
    }

    spin_wait();
    Ok(())
}

fn receive_exact(
    socket: u32,
    buffer: &mut [u8],
    timeout: SpinTimeout,
    timeout_context: &str,
) -> Result<()> {
    let mut received = 0;

    while received < buffer.len() {
        let recv_resp = unsafe {
            recv(
                socket as usize,
                buffer[received..].as_mut_ptr(),
                (buffer.len() - received) as i32,
                0,
            )
        };

        if recv_resp == -1 {
            let error_code = unsafe { WSAGetLastError() };
            if error_code == WSAEWOULDBLOCK as i32 {
                spin_wait_with_timeout(timeout, timeout_context)?;
                continue;
            }
            return bail_with_socket_error("Failed to receive exact bytes");
        }

        if recv_resp == 0 {
            return Err(anyhow::anyhow!(
                "Socket closed before receiving {} bytes",
                buffer.len()
            ));
        }

        received += recv_resp as usize;
    }

    Ok(())
}

fn send_exact(
    socket: u32,
    buffer: &[u8],
    timeout: SpinTimeout,
    timeout_context: &str,
) -> Result<()> {
    let mut sent = 0;

    while sent < buffer.len() {
        let send_resp = unsafe {
            send(
                socket as usize,
                buffer[sent..].as_ptr(),
                (buffer.len() - sent) as i32,
                0,
            )
        };

        if send_resp == -1 {
            let error_code = unsafe { WSAGetLastError() };
            if error_code == WSAEWOULDBLOCK as i32 {
                spin_wait_with_timeout(timeout, timeout_context)?;
                continue;
            }
            return bail_with_socket_error("Failed to send exact bytes");
        }

        if send_resp == 0 {
            return Err(anyhow::anyhow!(
                "Socket closed before sending {} bytes",
                buffer.len()
            ));
        }

        sent += send_resp as usize;
    }

    Ok(())
}

pub fn wrap_socket_in_single_socks4a(
    next_name: &str,
    next_port: u16,
    socket: u32,
    proxy: &ProxyEntry,
    read_timeout_ms: Option<u64>,
) -> Result<()> {
    let needs_4a = next_name.parse::<std::net::Ipv4Addr>().is_err();
    let wrap_timeout = new_spin_timeout(read_timeout_ms);
    let timeout_context = format!(
        "wrapping socket in SOCKS4a proxy {}:{} for {next_name}:{next_port}",
        proxy.host, proxy.port
    );

    let mut reqest_format = Vec::new();
    reqest_format.push(0x04); // SOCKS4 version
    reqest_format.push(0x01); // Command: CONNECT
    reqest_format.extend_from_slice(&next_port.to_be_bytes()); // Port in big-endian

    if needs_4a {
        // If the next_name is not an IP address, we need to use the 4a format
        reqest_format.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]); // Fake IP for 4a
    } else {
        // If the next_name is an IP address, we can use the normal format
        let ip = next_name.parse::<std::net::Ipv4Addr>()?;
        reqest_format.extend_from_slice(&ip.octets()); // IP address in octets
    }

    // if we have credentials, treat user as the userid
    if let Some(creds) = &proxy.credentials {
        // write user id
        reqest_format.extend_from_slice(creds.username.as_bytes());
    }

    reqest_format.push(0); // Null terminator for the user id

    if needs_4a {
        // If we are using 4a, we need to append the next_name as a null-terminated string
        reqest_format.extend_from_slice(next_name.as_bytes());
        reqest_format.push(0); // Null terminator for the domain name
    }

    send_exact(socket, &reqest_format, wrap_timeout, &timeout_context)?;

    // Wait for a response
    let mut response_buffer: [u8; 8] = [0; 8];
    receive_exact(socket, &mut response_buffer, wrap_timeout, &timeout_context)?;

    // Validate the response
    if response_buffer[0] != 0x00 {
        return Err(anyhow::anyhow!(
            "Invalid SOCKS4a response version: expected 0x00, got {:#02x}",
            response_buffer[0]
        ));
    }

    // Check granted
    if response_buffer[1] != 0x5A {
        return Err(anyhow::anyhow!(
            "SOCKS4a request was rejected or failed with code: {:#02x}",
            response_buffer[1]
        ));
    }

    Ok(())
}

pub fn wrap_socket_in_single_socks5(
    next_name: &str,
    next_port: u16,
    socket: u32,
    proxy: &ProxyEntry,
    read_timeout_ms: Option<u64>,
) -> Result<()> {
    let wrap_timeout = new_spin_timeout(read_timeout_ms);
    let timeout_context = format!(
        "wrapping socket in SOCKS5 proxy {}:{} for {next_name}:{next_port}",
        proxy.host, proxy.port
    );
    let negotiate_packet: [u8; 3] = [
        0x05, // SOCKS5 version
        0x01, // Number of authentication methods supported
        if proxy.credentials.is_some() {
            0x02
        } else {
            0x00
        }, // Authentication method: either "no authentication" or "username/password"
    ];

    send_exact(socket, &negotiate_packet, wrap_timeout, &timeout_context)?;

    let mut negotiate_response = [0u8; 2];
    receive_exact(
        socket,
        &mut negotiate_response,
        wrap_timeout,
        &timeout_context,
    )?;

    if negotiate_response[0] != 0x05 {
        return Err(anyhow::anyhow!(
            "Failed to receive SOCKS5 negotiation response"
        ));
    }

    match negotiate_response[1] {
        0x00 => {
            // No authentication, proceed to send the connection request
        }
        0x02 => {
            // Username/password authentication
            if let Some(creds) = &proxy.credentials {
                let mut auth_packet = Vec::new();
                auth_packet.push(0x01); // Authentication version
                auth_packet.push(creds.username.len() as u8); // Username length
                auth_packet.extend_from_slice(creds.username.as_bytes()); // Username
                auth_packet.push(creds.password.len() as u8); // Password length
                auth_packet.extend_from_slice(creds.password.as_bytes()); // Password

                send_exact(socket, &auth_packet, wrap_timeout, &timeout_context)?;

                let mut auth_response = [0u8; 2];
                receive_exact(socket, &mut auth_response, wrap_timeout, &timeout_context)?;

                if auth_response[0] != 0x01 {
                    return Err(anyhow::anyhow!(
                        "Failed to receive SOCKS5 authentication response"
                    ));
                }

                if auth_response[1] != 0x00 {
                    return Err(anyhow::anyhow!(
                        "SOCKS5 authentication failed with code: {:#02x}",
                        auth_response[1]
                    ));
                }
            } else {
                return Err(anyhow::anyhow!(
                    "Proxy requires username/password authentication, but no credentials were provided"
                ));
            }
        }
        0xFF => {
            return Err(anyhow::anyhow!(
                "SOCKS5 server does not accept any of the proposed authentication methods"
            ));
        }
        method => {
            return Err(anyhow::anyhow!(
                "SOCKS5 server responded with unknown authentication method: {:#02x}",
                method
            ));
        }
    }

    let mut request_packet = Vec::new();
    request_packet.push(0x05); // SOCKS5 version
    request_packet.push(0x01); // Command: CONNECT
    request_packet.push(0x00); // Reserved
    if let Ok(ip) = next_name.parse::<std::net::Ipv4Addr>() {
        request_packet.push(0x01); // Address type: IPv4
        request_packet.extend_from_slice(&ip.octets()); // IPv4 address in octets
    } else if let Ok(ip) = next_name.parse::<std::net::Ipv6Addr>() {
        request_packet.push(0x04); // Address type: IPv6
        request_packet.extend_from_slice(&ip.octets()); // IPv6 address in octets
    } else {
        request_packet.push(0x03); // Address type: Domain name
        request_packet.push(next_name.len() as u8); // Domain name length
        request_packet.extend_from_slice(next_name.as_bytes()); // Domain name in bytes
    }

    request_packet.extend_from_slice(&next_port.to_be_bytes()); // Port in big-endian

    send_exact(socket, &request_packet, wrap_timeout, &timeout_context)?;

    // we must now carefully parse the reply, which has a variable length header depending on the address type
    // first grab the first two bytes
    let mut response_header = [0u8; 2];
    receive_exact(socket, &mut response_header, wrap_timeout, &timeout_context)?;

    if response_header[0] != 0x05 {
        return Err(anyhow::anyhow!(
            "Failed to receive SOCKS5 connection response"
        ));
    }

    // bail early if the connection was not granted
    if response_header[1] != 0x00 {
        return Err(anyhow::anyhow!(
            "SOCKS5 connection request was rejected or failed with code: {:#02x}",
            response_header[1]
        ));
    }

    // now read the next 2 bytes to determine the address type
    // 1 byte reserved, 1 byte address type
    let mut response_addr_header = [0u8; 2];
    receive_exact(
        socket,
        &mut response_addr_header,
        wrap_timeout,
        &timeout_context,
    )?;

    let addr_type = response_addr_header[1];

    // now read the address based on the address type
    match addr_type {
        0x01 => {
            // IPv4 address, read 4 bytes for the address and 2 bytes for the port
            let mut ipv4_response = [0u8; 6];
            receive_exact(socket, &mut ipv4_response, wrap_timeout, &timeout_context)?;
        }
        0x03 => {
            // Domain name, read 1 byte for the domain length, then read the domain and 2 bytes for the port
            let mut domain_length_buf = [0u8; 1];
            receive_exact(
                socket,
                &mut domain_length_buf,
                wrap_timeout,
                &timeout_context,
            )?;
            let domain_length = domain_length_buf[0] as usize;

            let mut domain_response = vec![0u8; domain_length + 2];
            receive_exact(socket, &mut domain_response, wrap_timeout, &timeout_context)?;
        }
        0x04 => {
            // IPv6 address, read 16 bytes for the address and 2 bytes for the port
            let mut ipv6_response = [0u8; 18];
            receive_exact(socket, &mut ipv6_response, wrap_timeout, &timeout_context)?;
        }
        _ => {
            return Err(anyhow::anyhow!(
                "SOCKS5 server responded with unknown address type in connection response: {:#02x}",
                addr_type
            ));
        }
    }

    // all done
    Ok(())
}

pub fn wrap_socket_in_single_proxy(
    next_name: &str,
    next_port: u16,
    socket: u32,
    proxy: &ProxyEntry,
    read_timeout_ms: Option<u64>,
) -> Result<()> {
    match proxy.proxy_type {
        ProxyType::Socks4 => {
            wrap_socket_in_single_socks4a(next_name, next_port, socket, proxy, read_timeout_ms)
        }
        ProxyType::Socks5 => {
            wrap_socket_in_single_socks5(next_name, next_port, socket, proxy, read_timeout_ms)
        }
    }
}

fn wide_null(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}

struct AddrInfoList {
    raw: *mut ADDRINFOW,
}

impl Drop for AddrInfoList {
    fn drop(&mut self) {
        if !self.raw.is_null() {
            unsafe { o_FreeAddrInfoW(self.raw) };
        }
    }
}

fn socket_addr_from_raw(addr: *const SOCKADDR, addr_len: usize) -> Result<Option<SocketAddr>> {
    if addr.is_null() {
        return Ok(None);
    }

    match unsafe { (*addr).sa_family as i32 } {
        family if family == AF_INET as i32 => {
            if addr_len < size_of::<SOCKADDR_IN>() {
                return Err(anyhow::anyhow!(
                    "GetAddrInfoW returned truncated IPv4 sockaddr ({addr_len} bytes)"
                ));
            }

            let sockaddr = unsafe { &*(addr as *const SOCKADDR_IN) };
            let octets = unsafe {
                let octets = sockaddr.sin_addr.S_un.S_un_b;
                [octets.s_b1, octets.s_b2, octets.s_b3, octets.s_b4]
            };

            Ok(Some(SocketAddr::V4(SocketAddrV4::new(
                Ipv4Addr::from(octets),
                u16::from_be(sockaddr.sin_port),
            ))))
        }
        family if family == AF_INET6 as i32 => {
            if addr_len < size_of::<SOCKADDR_IN6>() {
                return Err(anyhow::anyhow!(
                    "GetAddrInfoW returned truncated IPv6 sockaddr ({addr_len} bytes)"
                ));
            }

            let sockaddr = unsafe { &*(addr as *const SOCKADDR_IN6) };
            let octets = unsafe { sockaddr.sin6_addr.u.Byte };
            let scope_id = unsafe { sockaddr.Anonymous.sin6_scope_id };

            Ok(Some(SocketAddr::V6(SocketAddrV6::new(
                Ipv6Addr::from(octets),
                u16::from_be(sockaddr.sin6_port),
                sockaddr.sin6_flowinfo,
                scope_id,
            ))))
        }
        _ => Ok(None),
    }
}

fn resolve_targets(name: &str, port: u16) -> Result<Vec<SocketAddr>> {
    if let Ok(ip) = name.parse::<IpAddr>() {
        return Ok(vec![SocketAddr::new(ip, port)]);
    }

    let host_wide = wide_null(name);
    let service_wide = wide_null(&port.to_string());
    let hints = ADDRINFOW {
        ai_family: AF_UNSPEC.into(),
        ai_socktype: SOCK_STREAM,
        ai_protocol: IPPROTO_TCP,
        ..Default::default()
    };
    let mut result = null_mut();

    let status = unsafe {
        o_GetAddrInfoW(
            host_wide.as_ptr(),
            service_wide.as_ptr(),
            &hints,
            &mut result,
        )
    };
    if status != 0 {
        return Err(anyhow::anyhow!(
            "GetAddrInfoW({name}, {port}) failed with code {status}"
        ));
    }

    let result = AddrInfoList { raw: result };
    let mut targets = Vec::new();
    let mut cursor = result.raw;
    while !cursor.is_null() {
        let addr = unsafe { &*cursor };
        if let Some(target) = socket_addr_from_raw(addr.ai_addr, addr.ai_addrlen)? {
            targets.push(target);
        }
        cursor = addr.ai_next;
    }

    if targets.is_empty() {
        return Err(anyhow::anyhow!(
            "GetAddrInfoW returned no usable addresses for {name}:{port}"
        ));
    }

    Ok(targets)
}

pub fn connect_socket(socket: u32, name: &str, port: u16, connect_timeout_ms: u64) -> Result<()> {
    // A note about proxy_dns, we _do_ leak the addresses of the proxy here
    // proxy_dns does not prevent DNS lookups for your proxies, it only prevents lookups for the final destination.
    let targets = resolve_targets(name, port)?;
    let connect_timeout = new_spin_timeout(Some(connect_timeout_ms));
    let timeout_context = format!("connecting socket to {name}:{port}");

    for target in targets {
        match target {
            SocketAddr::V4(addr) => {
                let octets = addr.ip().octets();
                let sockaddr = SOCKADDR_IN {
                    sin_family: AF_INET,
                    sin_port: addr.port().to_be(),
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

                loop {
                    let connect_result = unsafe {
                        o_connect(
                            socket as usize,
                            &sockaddr as *const SOCKADDR_IN as *const SOCKADDR,
                            std::mem::size_of::<SOCKADDR_IN>() as i32,
                        )
                    };

                    if connect_result == 0 {
                        return Ok(());
                    }

                    let error_code = unsafe { WSAGetLastError() };
                    if error_code == WSAEISCONN as i32 {
                        return Ok(());
                    }
                    if spin_on_would_block(error_code) {
                        spin_wait_with_timeout(connect_timeout, &timeout_context)?;
                        continue;
                    }
                    break;
                }
            }
            SocketAddr::V6(addr) => {
                let sockaddr = SOCKADDR_IN6 {
                    sin6_family: AF_INET6,
                    sin6_port: addr.port().to_be(),
                    sin6_flowinfo: addr.flowinfo(),
                    sin6_addr: IN6_ADDR {
                        u: IN6_ADDR_0 {
                            Byte: addr.ip().octets(),
                        },
                    },
                    Anonymous: SOCKADDR_IN6_0 {
                        sin6_scope_id: addr.scope_id(),
                    },
                };

                loop {
                    let connect_result = unsafe {
                        o_connect(
                            socket as usize,
                            &sockaddr as *const SOCKADDR_IN6 as *const SOCKADDR,
                            std::mem::size_of::<SOCKADDR_IN6>() as i32,
                        )
                    };

                    if connect_result == 0 {
                        return Ok(());
                    }

                    let error_code = unsafe { WSAGetLastError() };
                    if error_code == WSAEISCONN as i32 {
                        return Ok(());
                    }
                    if spin_on_would_block(error_code) {
                        spin_wait_with_timeout(connect_timeout, &timeout_context)?;
                        continue;
                    }
                    break;
                }
            }
        }
    }

    bail_with_socket_error(format!("Failed to connect socket to {name}:{port}"))
}

pub fn wrap_socket_in_requested_chain(
    top_level_name: &str,
    top_level_port: u16,
    socket: u32,
    tcp_read_timeout_ms: Option<u64>,
    tcp_connect_timeout_ms: Option<u64>,
    chain: &Vec<ProxyEntry>,
    is_dynamic: bool,
) -> Result<()> {
    let connect_timeout_ms = tcp_connect_timeout_ms.unwrap_or(DEFAULT_TCP_CONNECT_TIMEOUT_MS);

    unsafe {
        if let Some(recv_timeout_ms) = tcp_read_timeout_ms {
            let recv_timeout_ptr = &recv_timeout_ms as *const u64 as *const _;
            if setsockopt(
                socket as usize,
                SOL_SOCKET,
                SO_RCVTIMEO,
                recv_timeout_ptr,
                std::mem::size_of_val(&recv_timeout_ms) as i32,
            ) == -1
            {
                return bail_with_last_error("Failed to set receive timeout");
            }
        }

        if let Some(connect_timeout_ms) = tcp_connect_timeout_ms {
            let send_timeout_ptr = &connect_timeout_ms as *const u64 as *const _;
            if setsockopt(
                socket as usize,
                SOL_SOCKET,
                SO_SNDTIMEO,
                send_timeout_ptr,
                std::mem::size_of_val(&connect_timeout_ms) as i32,
            ) == -1
            {
                return bail_with_last_error("Failed to set send timeout");
            }
        }
    }

    if chain.is_empty() {
        return connect_socket(socket, top_level_name, top_level_port, connect_timeout_ms);
    }

    // Iterate through the chain in dynamic mode until we find a proxy that works
    let mut start_index = 0;
    loop {
        if let Err(error) = connect_socket(
            socket,
            &chain[start_index].host,
            chain[start_index].port,
            connect_timeout_ms,
        ) {
            // Short circuit to the next iteration of the loop if we're in dynamic mode
            if is_dynamic && start_index + 1 < chain.len() {
                start_index += 1;
                continue;
            }

            // Bail fatal error if we're in strict mode, or if we're in dynamic mode but we've exhausted the entire chain
            return Err(anyhow::anyhow!(
                "Strict chain: Failed to connect to proxy {}:{}: {error:#}",
                chain[start_index].host,
                chain[start_index].port
            ));
        }

        // We found a working proxy
        break;
    }

    // continue with the rest of the chain where we left of for the dynamic case, or the entire chain for the strict case
    // it is possible no proxyies remain in the chain here in the dynamic case
    for i in start_index..chain.len() {
        let proxy = &chain[i];
        let final_request_name;
        let next_name;
        let next_port;

        // if we're in the last hop of the chain, the connection _must_ be made to the final destination,
        // even if we're in a dynamic chain and some proxies earlier in the chain failed to connect
        if i == chain.len() - 1 {
            // The next entry is the final destination
            final_request_name = reverse_fake_dns_name(top_level_name);
            next_name = final_request_name.as_deref().unwrap_or(top_level_name);
            next_port = top_level_port;

            // We can't connect to an IPv6 destination through a socks4 proxy if we only have an IPv6 address
            if proxy.proxy_type == ProxyType::Socks4
                && matches!(next_name.parse::<IpAddr>(), Ok(IpAddr::V6(_)))
            {
                return Err(anyhow::anyhow!(
                    "IPv6 destination `{next_name}` cannot be reached through final SOCKS4 proxy"
                ));
            }
        } else {
            // the next entry is a normal proxy hop
            next_name = &chain[i + 1].host;
            next_port = chain[i + 1].port;
        }

        let result =
            wrap_socket_in_single_proxy(next_name, next_port, socket, proxy, tcp_read_timeout_ms);

        // Check if there was an error
        // If we're in a dynamic chain and this isn't the last proxy,
        if result.is_err() {
            // if this is the last hop (== the final destination), this is an error regardless of dynamic or strict
            if i == chain.len() - 1 {
                return Err(anyhow::anyhow!(
                    "Failed to connect to destination through final proxy {}:{}: {:#}",
                    proxy.host,
                    proxy.port,
                    result.err().unwrap()
                ));
            }

            // if this isn't the last proxy, only error if we're in a strict chain
            if !is_dynamic {
                return Err(anyhow::anyhow!(
                    "Strict chain: Failed to connect to destination through proxy {}:{}: {:#}",
                    proxy.host,
                    proxy.port,
                    result.err().unwrap()
                ));
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::{
        io::ErrorKind,
        mem::MaybeUninit,
        net::{Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs},
        os::windows::io::AsRawSocket,
        sync::{
            Mutex, Once,
            atomic::{AtomicUsize, Ordering},
        },
        thread,
        time::{Duration, Instant},
    };

    use windows_sys::Win32::Networking::WinSock::{
        AF_INET, AF_INET6, FIONBIO, INVALID_SOCKET, IPPROTO_TCP, SOCK_STREAM, SOCKADDR, WSADATA,
        WSAEWOULDBLOCK, WSASetLastError, WSAStartup, closesocket, connect, ioctlsocket, socket,
    };

    use super::{connect_socket, wrap_socket_in_single_socks5};
    use crate::config::{ProxyEntry, ProxyType};
    use crate::hooks_sockets::{reset_o_connect_for_tests, set_o_connect_for_tests};

    static WINSOCK_INIT: Once = Once::new();
    static TEST_MUTEX: Mutex<()> = Mutex::new(());
    static CONNECT_CALLS: AtomicUsize = AtomicUsize::new(0);

    struct OriginalConnectGuard;

    impl OriginalConnectGuard {
        fn install(
            fptr: unsafe extern "system" fn(
                usize,
                *const windows_sys::Win32::Networking::WinSock::SOCKADDR,
                i32,
            ) -> i32,
        ) -> Self {
            set_o_connect_for_tests(fptr);
            Self
        }
    }

    impl Drop for OriginalConnectGuard {
        fn drop(&mut self) {
            reset_o_connect_for_tests();
        }
    }

    fn ensure_winsock_started() {
        WINSOCK_INIT.call_once(|| {
            let mut wsadata = MaybeUninit::<WSADATA>::zeroed();
            let startup_result = unsafe { WSAStartup(0x0202, wsadata.as_mut_ptr()) };
            assert_eq!(startup_result, 0, "WSAStartup failed with {startup_result}");
        });
    }

    fn connect_socket_to_listener(name: &str, listen_addr: SocketAddr, family: i32) {
        let _test_guard = TEST_MUTEX
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        ensure_winsock_started();
        let _connect_guard = OriginalConnectGuard::install(connect);

        let listener =
            std::net::TcpListener::bind(listen_addr).expect("listener should bind successfully");
        listener
            .set_nonblocking(true)
            .expect("listener should switch to nonblocking mode");
        let port = listener
            .local_addr()
            .expect("listener should expose its local address")
            .port();

        let accept_thread = thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(5);
            loop {
                match listener.accept() {
                    Ok((_stream, _peer)) => return Ok::<(), String>(()),
                    Err(error) if error.kind() == ErrorKind::WouldBlock => {
                        if Instant::now() >= deadline {
                            return Err("timed out waiting for client connection".to_string());
                        }
                        thread::sleep(Duration::from_millis(10));
                    }
                    Err(error) => return Err(format!("listener accept failed: {error}")),
                }
            }
        });

        let raw_socket = unsafe { socket(family, SOCK_STREAM, IPPROTO_TCP) };
        assert_ne!(raw_socket, INVALID_SOCKET, "socket creation should succeed");

        let connect_result = connect_socket(
            u32::try_from(raw_socket).expect("SOCKET handle should fit into u32"),
            name,
            port,
            5000,
        );

        let close_result = unsafe { closesocket(raw_socket) };
        assert_eq!(close_result, 0, "closesocket should succeed");

        connect_result.unwrap_or_else(|error| {
            panic!("connect_socket({name}, {port}) should succeed: {error:#}")
        });

        accept_thread
            .join()
            .expect("accept thread should not panic")
            .expect("listener should accept the client connection");
    }

    #[test]
    fn connect_socket_connects_to_ipv4_literal() {
        connect_socket_to_listener(
            "127.0.0.1",
            SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
            AF_INET as i32,
        );
    }

    #[test]
    fn connect_socket_connects_to_localhost_domain() {
        let family = match ("localhost", 1)
            .to_socket_addrs()
            .expect("localhost should resolve")
            .next()
            .expect("localhost should produce at least one address")
        {
            SocketAddr::V4(_) => AF_INET as i32,
            SocketAddr::V6(_) => AF_INET6 as i32,
        };

        let listen_addr = if family == AF_INET as i32 {
            SocketAddr::from((Ipv4Addr::LOCALHOST, 0))
        } else {
            SocketAddr::from((Ipv6Addr::LOCALHOST, 0))
        };

        connect_socket_to_listener("localhost", listen_addr, family);
    }

    #[test]
    fn connect_socket_connects_to_ipv6_literal() {
        connect_socket_to_listener(
            "::1",
            SocketAddr::from((Ipv6Addr::LOCALHOST, 0)),
            AF_INET6 as i32,
        );
    }

    unsafe extern "system" fn always_would_block_connect(
        _socket: usize,
        _address: *const SOCKADDR,
        _address_len: i32,
    ) -> i32 {
        CONNECT_CALLS.fetch_add(1, Ordering::SeqCst);
        unsafe { WSASetLastError(WSAEWOULDBLOCK as i32) };
        -1
    }

    #[test]
    fn connect_socket_times_out_when_connect_never_completes() {
        let _test_guard = TEST_MUTEX
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        ensure_winsock_started();
        let _connect_guard = OriginalConnectGuard::install(always_would_block_connect);

        let raw_socket = unsafe { socket(AF_INET as i32, SOCK_STREAM, IPPROTO_TCP) };
        assert_ne!(raw_socket, INVALID_SOCKET, "socket creation should succeed");

        CONNECT_CALLS.store(0, Ordering::SeqCst);
        let started = Instant::now();
        let error = connect_socket(
            u32::try_from(raw_socket).expect("SOCKET handle should fit into u32"),
            "127.0.0.1",
            8080,
            20,
        )
        .expect_err("connect_socket should time out when connect keeps returning WSAEWOULDBLOCK");

        let close_result = unsafe { closesocket(raw_socket) };
        assert_eq!(close_result, 0, "closesocket should succeed");

        assert!(
            error
                .to_string()
                .contains("Timed out after 20ms while connecting socket to 127.0.0.1:8080")
        );
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "timeout path should complete promptly"
        );
        assert!(
            CONNECT_CALLS.load(Ordering::SeqCst) > 0,
            "fake connect should be exercised"
        );
    }

    #[test]
    fn wrap_socket_in_single_socks5_times_out_when_proxy_never_replies() {
        let _test_guard = TEST_MUTEX
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());

        let listener =
            std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("listener should bind");
        let port = listener
            .local_addr()
            .expect("listener should expose its local address")
            .port();

        let server_thread = thread::spawn(move || {
            let (_stream, _) = listener.accept().expect("listener should accept");
            thread::sleep(Duration::from_millis(200));
        });

        let stream = std::net::TcpStream::connect((Ipv4Addr::LOCALHOST, port))
            .expect("client should connect");
        let mut nonblocking = 1u32;
        let ioctl_result = unsafe {
            ioctlsocket(
                stream.as_raw_socket() as usize,
                FIONBIO as i32,
                &mut nonblocking,
            )
        };
        assert_eq!(ioctl_result, 0, "ioctlsocket(FIONBIO) should succeed");

        let proxy = ProxyEntry {
            proxy_type: ProxyType::Socks5,
            host: Ipv4Addr::LOCALHOST.to_string(),
            port,
            credentials: None,
        };

        let error = wrap_socket_in_single_socks5(
            "example.com",
            443,
            u32::try_from(stream.as_raw_socket()).expect("SOCKET handle should fit into u32"),
            &proxy,
            Some(20),
        )
        .expect_err("SOCKS5 wrap should time out when the proxy does not reply");

        assert!(
            error.to_string().contains(&format!(
                "Timed out after 20ms while wrapping socket in SOCKS5 proxy 127.0.0.1:{port} for example.com:443"
            ))
        );

        server_thread
            .join()
            .expect("server thread should not panic");
    }
}
