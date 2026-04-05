# win-proxychains
win-proxychains is a clone of [proxychains](https://github.com/haad/proxychains) for windows, it implements many of the original features. 

While win-proxychains preserves the core concepts and goals of the original proxychains, the implementation and architecture differ significantly due to platform differences (Linux v.s. Windows) and the resulting design decisions. Please review the section `Scope` to further understand the differences between proxychains and win-proxychains.

## Usage

```
win-proxychains.exe -f <config> C:\target\program\path\bin.exe
```

## Features
Win-proxychains was tested on Windows 11 and Windows 10, against firefox.exe, msedge.exe, chrome.exe, and various test programs.

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

## Opsec notice

**DO NOT** rely on win-proxychains to fully prevent leakage of DNS requests. Due to the sprawling number of DNS resolving infrastructure in Windows only a best effort attempt was made to implement `proxy_dns` mode, several known avenues of DNS leakage remain due to implementation complexity. Applications written to use these APIs or mechanisms to resolve DNS names *will* leak DNS traffic on your local interfaces. *win-proxychains should be considered a convenience tool, not an airgap*.

The DNS leakage gap is as follows:

| Feature                   | Support |
|---------------------------|---------|
| gethostbyname             | ✅      |
| WSAAsyncGetHostByName     | ✅      |
| getaddrinfo               | ✅      |
| GetAddrInfoW              | ✅      |
| GetAddrInfoExA/W          | ❌      |
| FreeAddrInfoExA/W         | ❌      |
| DnsQuery_A/W/UTF8         | ❌      |
| DnsQueryEx                | ❌      |
| DNS Over HTTP (DOH)       | ❌      |

Configuration of a "leak free" win-proxychains setup is out of scope for this project.

## Anti-virus warnings

Win-proxychains uses invasive process injection techniques to hook the interface between the target program and Window's socket implementation. In this case these techniques are intended to inject proxies of your choosing between the target application and whatever TCP ports its trying to connect to, and will not harm your computer or your files. However, these techniques are also employed by malware and make the behavior of win-proxychains appear malicious to anti-virus and anti-malware products. These products may flag win-proxychains as malware or as a virus. 

To be clear: win-proxychains is not malware, or a virus, and does not contain malicious code. It only appears to behave as such to anti-virus products.

