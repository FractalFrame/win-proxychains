# win-proxychains

`win-proxychains` is a clone of [`proxychains`](https://github.com/haad/proxychains) for Windows developed and maintained by [FractalFrame](https://fractalframe.eu).

While `win-proxychains` preserves the core concepts and goals of the original `proxychains`, the implementation and architecture differ significantly due to platform differences (Linux v.s. Windows) and the resulting design decisions. 

## Usage

```
# Use the <config> file to proxy connections of target.exe
win-proxychains.exe -f <config> C:\path\to\target.exe

# Write the default config file to the disk
win-proxychains.exe -c default_config.conf
```

Example:

```
.\win-proxychains.exe "powershell -c iwr -UseBasicParsing https://google.com/"
```

`win-proxychains` can parse `proxychains4` configs and warns you when invalid or unsupported modes from `proxychains4` are used.

`win-proxychains` may look for the config path set in `WIN_PROXYCHAINS_CONFIG` if no config is supplied as an argument.

*Note:* the timeout mechanism in `win-proxychains` works differently from that of `proxychains` because `win-proxychains` aims to support blocking and nonblocking sockets. For good performance, set your timeouts as low as possible. Higher values will perform badly, especially for asynchronous connections. A good timeout is 500ms or less, and 250 if your connection has a general low latency. The timeout values in the default configuration are too high for usage with ordinary socks proxies, you should change them.

To build `win-proxychains` you need at least:

- rustc 1.85
- cargo 1.85

You can use the following command in the root of the repository to build:

```
cargo build --release
```

## Features
`Win-proxychains` was tested on Windows 11 and Windows 10, against firefox.exe, msedge.exe, chrome.exe, and various test programs. Currently `win-proxychains` only supports 64 bit programs. 

| Feature              | Support |
|----------------------|---------|
| strict chains        | ✅      |
| dynamic chains       | ✅      |
| random chains        | ✅      |
| socks4 proxy         | ✅      |
| socks5 proxy         | ✅      |
| proxy_dns            | ⚠️      |
| dnat                 | ❌      |
| raw proxies          | ❌      |
| http proxies         | ❌      |
| 32 bit support       | ❌      |

## Opsec notice

**DO NOT** rely on `win-proxychains` to fully prevent leakage of DNS requests. Due to the large number of ways in which DNS resolving can happen in Windows, only a best effort attempt was made to implement `proxy_dns` mode. Several known avenues of DNS leakage remain due to implementation complexity. Applications written to use these APIs or mechanisms to resolve DNS names *will* leak DNS traffic on your local interfaces. *If opsec is important `win-proxychains` must be used with additional measures to ensure an airgap*.

The DNS leakage gap is as follows:

| DNS resolving mechanism   | Support |
|---------------------------|---------|
| gethostbyname             | ✅      |
| WSAAsyncGetHostByName     | ✅      |
| getaddrinfo               | ✅      |
| GetAddrInfoW              | ✅      |
| GetAddrInfoExA/W          | ❌      |
| DnsQuery_A/W/UTF8         | ❌      |
| DnsQueryEx                | ❌      |
| DNS Over HTTP (DOH)       | ❌      |

Configuration of a "leak free" `win-proxychains` setup is out of scope for this project.

## Anti-virus warnings

`win-proxychains` uses invasive process injection techniques to hook the interface between the target program and Windows' socket implementation. The techniques are used to inject proxies of your choosing between the target application and whatever TCP ports it's trying to connect to, and will not harm your computer or your files. However, these techniques are also employed by malware and make the behavior of `win-proxychains` appear malicious to anti-virus and anti-malware products. As a result, these products may flag `win-proxychains` as malware or as a virus. 

To be clear: `win-proxychains` is not malware, or a virus, and does not contain malicious code.

## TODO:
* 32-bit support
* GetAddrInfoEx support
* default config file location lookup

## License

Copyright (c) 2026 FractalFrame BV

This project is licensed under the BSL-1.1 License, see the LICENCE.md file for details.
