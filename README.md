# win-proxychains
win-proxychains is a clone of [proxychains](https://github.com/haad/proxychains) for windows, it implements many of the same feautres as the original. Socks4/Socks5, proxy_dns, and random/dynamic/strict chains are supported. Raw/http proxies are not supported, nor is dnat functionality.

While win-proxychains preserves the core concepts and goals of the original proxychains, the implementation and architecture differ significantly due to platform differences (Linux v.s. Windows) and the resulting design decisions. Please review the section `Scope` to further understand the differences between proxychains and win-proxychains.

## Usage

```
win-proxychains.exe -f <config> C:\target\program\path\bin.exe
```

## Offsec notice

Notice: due to the sprawling number of DNS resolving infrastructure in Windows only a best effort attempt was made to implement `proxy_dns` mode, several known avenues of DNS leakage remain due to implementation complexity. Applications coded to use these avenues to resolve DNS names *will* leak DNS traffic on your local interfaces. **DO NOT** rely on win-proxychains to fully isolate your connection and prevent leakage of DNS requests. *win-proxychains should be considered as a convenience tool, not an airgap*.

## Anti-virus warnings

Win-proxychains uses invasive process injection techniques to hook the interface between the target program and Window's socket implementation. In this case these techniques are intended to inject proxies of your choosing between the target application and whatever TCP ports its trying to connect to, and will not harm your computer or your files. However, these techniques are also employed by malware and make the behavior of win-proxychains appear malicious to anti-virus and anti-malware products. These products may flag win-proxychains as malware or as a virus. 

To be clear: win-proxychains is not malware, or a virus, and does not contain malicious code. It only appears to behave as such to anti-virus products.

## Scope

This project is not a drop-in replacement for the original project. win-proxychains supports:
- proxy_dns
- strict chains
- dynamic chains
- random chains
- socks4 and socks5 proxy servers

win-proxychains does not support:
- dnat
- raw proxies
- http proxies

Implementation details 
