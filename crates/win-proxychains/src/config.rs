use alloc::{
    borrow::ToOwned,
    format,
    string::{String, ToString},
    vec::Vec,
};
use core::{
    fmt,
    hash::{Hash, Hasher},
    mem,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV6},
    str::FromStr,
};
use anyhow::{Context, Result, anyhow, bail, ensure};
use windows_sys::Win32::Networking::WinSock::{
    AF_INET, AF_INET6, SOCKADDR, SOCKADDR_IN, SOCKADDR_IN6,
};
use windows_sys::Win32::System::SystemInformation::GetTickCount64;

struct SeedHasher(u64);

impl Default for SeedHasher {
    fn default() -> Self {
        Self(0xcbf2_9ce4_8422_2325)
    }
}

impl Hasher for SeedHasher {
    fn finish(&self) -> u64 {
        self.0
    }

    fn write(&mut self, bytes: &[u8]) {
        for byte in bytes {
            self.0 ^= u64::from(*byte);
            self.0 = self.0.wrapping_mul(0x100_0000_01b3);
        }
    }
}

pub const SAMPLE_PROXYCHAINS_CONFIG: &str = r#"# win-proxychains.conf  
#
#        SOCKS4, SOCKS5 tunneling proxifier with partial DNS.
#	

# This adapted proxychains4 configuration file is an example of a 
# working configuration with win-proxychains, 

# The option below identifies how the ProxyList is treated.
# only one option should be uncommented at time,
# otherwise the last appearing option will be accepted
#
#dynamic_chain
#
# Dynamic - Each connection will be done via chained proxies
# all proxies chained in the order as they appear in the list
# at least one proxy must be online to play in chain
# (dead proxies are skipped)
# otherwise EINTR is returned to the app
#
strict_chain
#
# Strict - Each connection will be done via chained proxies
# all proxies chained in the order as they appear in the list
# all proxies must be online to play in chain
# otherwise EINTR is returned to the app
#
#random_chain
#
# Random - Each connection will be done via random proxy
# (or proxy chain, see  chain_len) from the list.
# this option is good to test your IDS :)

# Make sense only if random_chain
#chain_len = 2

# Quiet mode (no output from library)
#quiet_mode

# Proxy DNS requests - no leak for DNS data
proxy_dns 

# set the class A subnet number to usefor use of the internal remote DNS mapping
# we use the reserved 224.x.x.x range by default,
# if the proxified app does a DNS request, we will return an IP from that range.
# on further accesses to this ip we will send the saved DNS name to the proxy.
# in case some control-freak app checks the returned ip, and denies to 
# connect, you can use another subnet, e.g. 10.x.x.x or 127.x.x.x.
# of course you should make sure that the proxified app does not need
# *real* access to this subnet. 
# i.e. dont use the same subnet then in the localnet section
#remote_dns_subnet 127 
#remote_dns_subnet 10
remote_dns_subnet 224

# set the top IPv6 octet to use for the internal remote DNS mapping.
# if the proxified app requests IPv6 records, we will return addresses from
# this synthetic range and translate later connections back to the saved name.
# pick a value that does not overlap with IPv6 ranges the proxified app must
# reach directly.
#remote_dns_subnet_6 252
remote_dns_subnet_6 252

# Some timeouts in milliseconds
tcp_read_time_out 15000
tcp_connect_time_out 8000

# By default enable localnet for loopback address ranges
# RFC5735 Loopback address range
localnet 127.0.0.0/255.0.0.0
# RFC1918 Private Address Ranges
# localnet 10.0.0.0/255.0.0.0
# localnet 172.16.0.0/255.240.0.0
# localnet 192.168.0.0/255.255.0.0

# Example for localnet exclusion
## Exclude connections to 192.168.1.0/24 with port 80
# localnet 192.168.1.0:80/255.255.255.0

## Exclude connections to 192.168.100.0/24
# localnet 192.168.100.0/255.255.255.0

## Exclude connections to ANYwhere with port 80
# localnet 0.0.0.0:80/0.0.0.0

# ProxyList format
#       type  host  port [user pass]
#       (values separated by 'tab' or 'blank')
#
#
#        Examples:
#
#       socks5	192.168.67.78	1080	lamer	secret
#	 	socks4	192.168.1.49	1080
#		
#
#       proxy types: socks4, socks5
#        ( auth types supported: "user/pass"-socks )
#
[ProxyList]
# add proxy here ...
# meanwhile
# defaults set to "tor"
socks4 	127.0.0.1 9050
"#;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProxychainsConfig {
    pub chain_type: ChainType,
    pub chain_len: Option<usize>,
    pub quiet_mode: bool,
    pub proxy_dns: bool,
    pub remote_dns_subnet: Option<u8>,
    pub remote_dns_subnet_6: Option<u8>,
    pub tcp_read_time_out: Option<u64>,
    pub tcp_connect_time_out: Option<u64>,
    pub localnets: Vec<LocalnetRule>,
    pub proxies: Vec<ProxyEntry>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChainType {
    /// Each connection will be done via chained proxies, any number of proxies may fail and be skipped
    /// reasoning from first principles, we require _at least_ one proxy between us and the target
    Dynamic,
    /// Each connection will be done via chained proxies, no failed proxies are allowed
    Strict,
    /// A random chain of proxies with length `chain_len` is selected for each connection
    /// No failures are allowed in the selected chain, but different connections may use different chains
    Random,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalnetRule {
    pub network: IpAddr,
    pub port: Option<u16>,
    pub mask: IpAddr,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProxyEntry {
    pub proxy_type: ProxyType,
    pub host: String,
    pub port: u16,
    pub credentials: Option<ProxyCredentials>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProxyType {
    Socks4,
    Socks5,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProxyCredentials {
    pub username: String,
    pub password: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Section {
    Global,
    ProxyList,
}

#[derive(Debug, Default)]
struct ConfigBuilder {
    chain_type: Option<ChainType>,
    chain_len: Option<usize>,
    quiet_mode: bool,
    proxy_dns: bool,
    remote_dns_subnet: Option<u8>,
    remote_dns_subnet_6: Option<u8>,
    tcp_read_time_out: Option<u64>,
    tcp_connect_time_out: Option<u64>,
    localnets: Vec<LocalnetRule>,
    proxies: Vec<ProxyEntry>,
    saw_proxy_list: bool,
}

impl ProxychainsConfig {
    pub fn parse(input: &str) -> Result<Self> {
        let mut builder = ConfigBuilder::default();
        let mut section = Section::Global;

        for (index, raw_line) in input.lines().enumerate() {
            let line_number = index + 1;
            let line = strip_comments(raw_line).trim();

            if line.is_empty() {
                continue;
            }

            if line.starts_with('[') {
                section = parse_section(line)
                    .with_context(|| format!("line {line_number}: invalid section header"))?;
                if section == Section::ProxyList {
                    ensure!(
                        !builder.saw_proxy_list,
                        "line {line_number}: duplicate [ProxyList] section"
                    );
                    builder.saw_proxy_list = true;
                }
                continue;
            }

            match section {
                Section::Global => builder
                    .parse_global_directive(line)
                    .with_context(|| format!("line {line_number}: `{line}`"))?,
                Section::ProxyList => builder
                    .parse_proxy(line)
                    .with_context(|| format!("line {line_number}: `{line}`"))?,
            }
        }

        builder.build()
    }

    pub fn sample_chain(
        &self,
        address: *const SOCKADDR,
        address_len: i32,
    ) -> Result<(String, u16, Vec<ProxyEntry>)> {
        let target = unsafe { sockaddr_to_socket_addr(address, address_len)? };
        let top_level_name = target.ip().to_string();
        let top_level_port = target.port();

        if self
            .localnets
            .iter()
            .any(|rule| localnet_matches(rule, target.ip(), top_level_port))
        {
            return Ok((top_level_name, top_level_port, Vec::new()));
        }

        let chain = match self.chain_type {
            ChainType::Strict | ChainType::Dynamic => self.proxies.clone(),
            ChainType::Random => {
                let chain_len = self.chain_len.unwrap_or(1);
                sample_random_chain(&self.proxies, chain_len, target)?
            }
        };

        Ok((top_level_name, top_level_port, chain))
    }
}

impl FromStr for ProxychainsConfig {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self> {
        Self::parse(s)
    }
}

impl fmt::Display for ProxychainsConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "{}", self.chain_type)?;

        if self.chain_type == ChainType::Random
            && let Some(chain_len) = self.chain_len
        {
            writeln!(f, "chain_len = {chain_len}")?;
        }

        if self.quiet_mode {
            writeln!(f, "quiet_mode")?;
        }

        if self.proxy_dns {
            writeln!(f, "proxy_dns")?;
        }

        if let Some(remote_dns_subnet) = self.remote_dns_subnet {
            writeln!(f, "remote_dns_subnet {remote_dns_subnet}")?;
        }

        if let Some(remote_dns_subnet_6) = self.remote_dns_subnet_6 {
            writeln!(f, "remote_dns_subnet_6 {remote_dns_subnet_6}")?;
        }

        if let Some(tcp_read_time_out) = self.tcp_read_time_out {
            writeln!(f, "tcp_read_time_out {tcp_read_time_out}")?;
        }

        if let Some(tcp_connect_time_out) = self.tcp_connect_time_out {
            writeln!(f, "tcp_connect_time_out {tcp_connect_time_out}")?;
        }

        for localnet in &self.localnets {
            writeln!(f, "localnet {localnet}")?;
        }

        writeln!(f, "[ProxyList]")?;
        for proxy in &self.proxies {
            writeln!(f, "{proxy}")?;
        }

        Ok(())
    }
}

impl ConfigBuilder {
    fn parse_global_directive(&mut self, line: &str) -> Result<()> {
        let keyword = first_token(line);
        match keyword {
            "dynamic_chain" => self.set_chain_type(ChainType::Dynamic, line),
            "strict_chain" => self.set_chain_type(ChainType::Strict, line),
            "random_chain" => self.set_chain_type(ChainType::Random, line),
            "chain_len" => {
                let chain_len = parse_single_value::<usize>(line, "chain_len")?;
                ensure!(chain_len > 0, "`chain_len` must be greater than zero");
                self.chain_len = Some(chain_len);
                Ok(())
            }
            "quiet_mode" => ensure_no_arguments(line, "quiet_mode").map(|_| {
                self.quiet_mode = true;
            }),
            "proxy_dns" => ensure_no_arguments(line, "proxy_dns").map(|_| {
                self.proxy_dns = true;
            }),
            "proxy_dns_old" | "proxy_dns_daemon" => {
                bail!("unsupported DNS mode `{keyword}`");
            }
            "remote_dns_subnet" => {
                let subnet = parse_single_value::<u8>(line, "remote_dns_subnet")?;
                self.remote_dns_subnet = Some(subnet);
                Ok(())
            }
            "remote_dns_subnet_6" => {
                let subnet = parse_single_value::<u8>(line, "remote_dns_subnet_6")?;
                self.remote_dns_subnet_6 = Some(subnet);
                Ok(())
            }
            "tcp_read_time_out" => {
                self.tcp_read_time_out =
                    Some(parse_single_value::<u64>(line, "tcp_read_time_out")?);
                Ok(())
            }
            "tcp_connect_time_out" => {
                self.tcp_connect_time_out =
                    Some(parse_single_value::<u64>(line, "tcp_connect_time_out")?);
                Ok(())
            }
            "localnet" => {
                self.localnets.push(parse_localnet_rule(line)?);
                Ok(())
            }
            "dnat" => bail!("unsupported directive `dnat`"),
            "[ProxyList]" => bail!("unexpected section header"),
            other => bail!("unsupported or unknown directive `{other}`"),
        }
    }

    fn parse_proxy(&mut self, line: &str) -> Result<()> {
        let parts: Vec<_> = line.split_whitespace().collect();
        ensure!(
            parts.len() == 3 || parts.len() == 5,
            "proxy entries must be `type host port [user pass]`"
        );

        let proxy_type = match parts[0] {
            "socks4" => ProxyType::Socks4,
            "socks5" => ProxyType::Socks5,
            "http" => bail!("unsupported proxy type `http`"),
            "raw" => bail!("unsupported proxy type `raw`"),
            other => bail!("unsupported proxy type `{other}`"),
        };

        let port = parts[2]
            .parse::<u16>()
            .with_context(|| format!("invalid proxy port `{}`", parts[2]))?;

        let credentials = if parts.len() == 5 {
            Some(ProxyCredentials {
                username: parts[3].to_owned(),
                password: parts[4].to_owned(),
            })
        } else {
            None
        };

        self.proxies.push(ProxyEntry {
            proxy_type,
            host: parts[1].to_owned(),
            port,
            credentials,
        });

        Ok(())
    }

    fn set_chain_type(&mut self, chain_type: ChainType, line: &str) -> Result<()> {
        ensure_no_arguments(line, chain_type.as_str())?;
        match self.chain_type {
            Some(existing) if existing != chain_type => bail!(
                "multiple chain types configured: `{}` and `{}`",
                existing.as_str(),
                chain_type.as_str()
            ),
            _ => {
                self.chain_type = Some(chain_type);
                Ok(())
            }
        }
    }

    fn build(self) -> Result<ProxychainsConfig> {
        let chain_type = self.chain_type.ok_or_else(|| {
            anyhow!(
                "missing chain mode: expected one of dynamic_chain, strict_chain, or random_chain"
            )
        })?;

        if self.chain_len.is_some() && chain_type != ChainType::Random {
            bail!("`chain_len` is only valid with `random_chain`");
        }

        ensure!(self.saw_proxy_list, "missing [ProxyList] section");
        ensure!(
            !self.proxies.is_empty(),
            "[ProxyList] must contain at least one supported proxy"
        );
        if let Some(chain_len) = self.chain_len {
            ensure!(
                chain_len <= self.proxies.len(),
                "`chain_len` cannot exceed the number of configured proxies"
            );
        }
        validate_localnets_do_not_overlap_remote_dns_subnets(
            &self.localnets,
            self.remote_dns_subnet,
            self.remote_dns_subnet_6,
        )?;
        validate_proxy_packet_constraints(&self.proxies)?;

        Ok(ProxychainsConfig {
            chain_type,
            chain_len: self.chain_len,
            quiet_mode: self.quiet_mode,
            proxy_dns: self.proxy_dns,
            remote_dns_subnet: self.remote_dns_subnet,
            remote_dns_subnet_6: self.remote_dns_subnet_6,
            tcp_read_time_out: self.tcp_read_time_out,
            tcp_connect_time_out: self.tcp_connect_time_out,
            localnets: self.localnets,
            proxies: self.proxies,
        })
    }
}

unsafe fn sockaddr_to_socket_addr(
    address: *const SOCKADDR,
    address_len: i32,
) -> Result<SocketAddr> {
    ensure!(!address.is_null(), "destination address pointer is null");
    ensure!(
        address_len >= mem::size_of::<SOCKADDR>() as i32,
        "destination address length {address_len} is too small for SOCKADDR"
    );

    let family = unsafe { (*address).sa_family };

    match family {
        AF_INET => {
            ensure!(
                address_len >= mem::size_of::<SOCKADDR_IN>() as i32,
                "destination address length {address_len} is too small for SOCKADDR_IN"
            );
            let address = unsafe { &*(address as *const SOCKADDR_IN) };
            let octets = unsafe { address.sin_addr.S_un.S_un_b };
            Ok(SocketAddr::from((
                Ipv4Addr::new(octets.s_b1, octets.s_b2, octets.s_b3, octets.s_b4),
                u16::from_be(address.sin_port),
            )))
        }
        AF_INET6 => {
            ensure!(
                address_len >= mem::size_of::<SOCKADDR_IN6>() as i32,
                "destination address length {address_len} is too small for SOCKADDR_IN6"
            );
            let address = unsafe { &*(address as *const SOCKADDR_IN6) };
            let octets = unsafe { address.sin6_addr.u.Byte };
            let scope_id = unsafe { address.Anonymous.sin6_scope_id };
            Ok(SocketAddr::V6(SocketAddrV6::new(
                Ipv6Addr::from(octets),
                u16::from_be(address.sin6_port),
                address.sin6_flowinfo,
                scope_id,
            )))
        }
        _ => bail!("unsupported destination address family {family}"),
    }
}

fn localnet_matches(rule: &LocalnetRule, destination: IpAddr, port: u16) -> bool {
    if let Some(rule_port) = rule.port
        && rule_port != port
    {
        return false;
    }

    match (rule.network, rule.mask, destination) {
        (IpAddr::V4(network), IpAddr::V4(mask), IpAddr::V4(destination)) => {
            let network = u32::from_be_bytes(network.octets());
            let mask = u32::from_be_bytes(mask.octets());
            let destination = u32::from_be_bytes(destination.octets());
            (network & mask) == (destination & mask)
        }
        (IpAddr::V6(network), IpAddr::V6(mask), IpAddr::V6(destination)) => {
            let network = u128::from_be_bytes(network.octets());
            let mask = u128::from_be_bytes(mask.octets());
            let destination = u128::from_be_bytes(destination.octets());
            (network & mask) == (destination & mask)
        }
        _ => false,
    }
}

fn validate_localnets_do_not_overlap_remote_dns_subnets(
    localnets: &[LocalnetRule],
    remote_dns_subnet: Option<u8>,
    remote_dns_subnet_6: Option<u8>,
) -> Result<()> {
    if let Some(subnet) = remote_dns_subnet {
        let remote_network = IpAddr::V4(Ipv4Addr::new(subnet, 0, 0, 0));
        let remote_mask = IpAddr::V4(Ipv4Addr::new(255, 0, 0, 0));
        validate_localnets_do_not_overlap_subnet(
            localnets,
            remote_network,
            remote_mask,
            format!("remote_dns_subnet {subnet}"),
        )?;
    }

    if let Some(subnet) = remote_dns_subnet_6 {
        let remote_network = IpAddr::V6(Ipv6Addr::from((subnet as u128) << 120));
        let remote_mask = IpAddr::V6(Ipv6Addr::from(u128::from(u8::MAX) << 120));
        validate_localnets_do_not_overlap_subnet(
            localnets,
            remote_network,
            remote_mask,
            format!("remote_dns_subnet_6 {subnet}"),
        )?;
    }

    Ok(())
}

fn validate_localnets_do_not_overlap_subnet(
    localnets: &[LocalnetRule],
    subnet_network: IpAddr,
    subnet_mask: IpAddr,
    subnet_name: String,
) -> Result<()> {
    for localnet in localnets {
        if masked_networks_overlap(localnet.network, localnet.mask, subnet_network, subnet_mask) {
            bail!("`localnet {localnet}` overlaps with synthetic DNS range `{subnet_name}`");
        }
    }

    Ok(())
}

fn masked_networks_overlap(
    left_network: IpAddr,
    left_mask: IpAddr,
    right_network: IpAddr,
    right_mask: IpAddr,
) -> bool {
    match (left_network, left_mask, right_network, right_mask) {
        (
            IpAddr::V4(left_network),
            IpAddr::V4(left_mask),
            IpAddr::V4(right_network),
            IpAddr::V4(right_mask),
        ) => {
            let left_network = u32::from_be_bytes(left_network.octets());
            let left_mask = u32::from_be_bytes(left_mask.octets());
            let right_network = u32::from_be_bytes(right_network.octets());
            let right_mask = u32::from_be_bytes(right_mask.octets());
            ((left_network ^ right_network) & left_mask & right_mask) == 0
        }
        (
            IpAddr::V6(left_network),
            IpAddr::V6(left_mask),
            IpAddr::V6(right_network),
            IpAddr::V6(right_mask),
        ) => {
            let left_network = u128::from_be_bytes(left_network.octets());
            let left_mask = u128::from_be_bytes(left_mask.octets());
            let right_network = u128::from_be_bytes(right_network.octets());
            let right_mask = u128::from_be_bytes(right_mask.octets());
            ((left_network ^ right_network) & left_mask & right_mask) == 0
        }
        _ => false,
    }
}

fn sample_random_chain(
    proxies: &[ProxyEntry],
    chain_len: usize,
    target: SocketAddr,
) -> Result<Vec<ProxyEntry>> {
    ensure!(
        chain_len > 0,
        "random proxy chains must contain at least one proxy"
    );
    ensure!(
        chain_len <= proxies.len(),
        "random proxy chain length {chain_len} exceeds configured proxy count {}",
        proxies.len()
    );

    let mut seed_hasher = SeedHasher::default();
    target.hash(&mut seed_hasher);
    proxies.len().hash(&mut seed_hasher);
    unsafe { GetTickCount64() }.hash(&mut seed_hasher);
    let mut seed = seed_hasher.finish();

    let requires_non_socks4_exit = target.is_ipv6();
    let mut indices = (0..proxies.len()).collect::<Vec<_>>();
    let mut sampled_indices = Vec::with_capacity(chain_len);

    if requires_non_socks4_exit {
        let exit_candidates = indices
            .iter()
            .copied()
            .filter(|&index| proxies[index].proxy_type != ProxyType::Socks4)
            .collect::<Vec<_>>();
        ensure!(
            !exit_candidates.is_empty(),
            "random proxy chain for IPv6 destination {target} requires at least one non-SOCKS4 exit proxy"
        );

        seed = seed
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        let exit_index = exit_candidates[seed as usize % exit_candidates.len()];
        let exit_position = indices
            .iter()
            .position(|&index| index == exit_index)
            .expect("selected exit proxy must exist in the candidate list");
        indices.swap_remove(exit_position);

        for i in 0..(chain_len - 1) {
            seed = seed
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            let j = i + (seed as usize % (indices.len() - i));
            indices.swap(i, j);
            sampled_indices.push(indices[i]);
        }

        sampled_indices.push(exit_index);
    } else {
        for i in 0..chain_len {
            seed = seed
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            let j = i + (seed as usize % (indices.len() - i));
            indices.swap(i, j);
            sampled_indices.push(indices[i]);
        }
    }

    Ok(sampled_indices
        .iter()
        .map(|&index| proxies[index].clone())
        .collect())
}

fn validate_proxy_packet_constraints(proxies: &[ProxyEntry]) -> Result<()> {
    for (index, proxy) in proxies.iter().enumerate() {
        if proxy.proxy_type == ProxyType::Socks5
            && let Some(credentials) = &proxy.credentials
        {
            ensure!(
                credentials.username.len() <= u8::MAX as usize,
                "proxy entry {} username exceeds 255 bytes and cannot be encoded in a SOCKS5 packet",
                index + 1
            );
            ensure!(
                credentials.password.len() <= u8::MAX as usize,
                "proxy entry {} password exceeds 255 bytes and cannot be encoded in a SOCKS5 packet",
                index + 1
            );
        }

        if index == 0 {
            continue;
        }

        let previous_proxy = &proxies[index - 1];
        let next_hop = &proxy.host;

        match previous_proxy.proxy_type {
            ProxyType::Socks4 => {
                ensure!(
                    !matches!(next_hop.parse::<IpAddr>(), Ok(IpAddr::V6(_))),
                    "proxy entry {} cannot be reached through SOCKS4 proxy entry {} because SOCKS4/SOCKS4a cannot encode IPv6 next-hop addresses",
                    index + 1,
                    index
                );
            }
            ProxyType::Socks5 => {
                if next_hop.parse::<IpAddr>().is_err() {
                    ensure!(
                        next_hop.len() <= u8::MAX as usize,
                        "proxy entry {} host exceeds 255 bytes and cannot be encoded in a SOCKS5 packet",
                        index + 1
                    );
                }
            }
        }
    }

    Ok(())
}

impl ChainType {
    fn as_str(self) -> &'static str {
        match self {
            ChainType::Dynamic => "dynamic_chain",
            ChainType::Strict => "strict_chain",
            ChainType::Random => "random_chain",
        }
    }
}

impl fmt::Display for ChainType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl fmt::Display for LocalnetRule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match (self.network, self.port) {
            (IpAddr::V6(network), Some(port)) => write!(f, "[{network}]:{port}/{}", self.mask),
            (_, Some(port)) => write!(f, "{}:{port}/{}", self.network, self.mask),
            (_, None) => write!(f, "{}/{}", self.network, self.mask),
        }
    }
}

impl fmt::Display for ProxyEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {} {}", self.proxy_type, self.host, self.port)?;
        if let Some(credentials) = &self.credentials {
            write!(f, " {credentials}")?;
        }
        Ok(())
    }
}

impl fmt::Display for ProxyType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            ProxyType::Socks4 => "socks4",
            ProxyType::Socks5 => "socks5",
        })
    }
}

impl fmt::Display for ProxyCredentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {}", self.username, self.password)
    }
}

fn parse_section(line: &str) -> Result<Section> {
    match line {
        "[ProxyList]" => Ok(Section::ProxyList),
        other => bail!("unsupported section `{other}`"),
    }
}

fn strip_comments(line: &str) -> &str {
    line.split('#').next().unwrap_or_default()
}

fn first_token(line: &str) -> &str {
    line.split_whitespace().next().unwrap_or(line)
}

fn ensure_no_arguments(line: &str, directive: &str) -> Result<()> {
    let rest = line
        .strip_prefix(directive)
        .ok_or_else(|| anyhow!("invalid directive `{line}`"))?
        .trim();
    ensure!(rest.is_empty(), "`{directive}` does not accept arguments");
    Ok(())
}

fn parse_single_value<T>(line: &str, directive: &str) -> Result<T>
where
    T: FromStr,
    T::Err: fmt::Display,
{
    let rest = line
        .strip_prefix(directive)
        .ok_or_else(|| anyhow!("invalid directive `{line}`"))?
        .trim();
    let rest = rest.strip_prefix('=').unwrap_or(rest).trim();
    ensure!(!rest.is_empty(), "missing value for `{directive}`");

    let mut parts = rest.split_whitespace();
    let value = parts
        .next()
        .ok_or_else(|| anyhow!("missing value for `{directive}`"))?;
    ensure!(
        parts.next().is_none(),
        "`{directive}` only accepts a single value"
    );

    value
        .parse::<T>()
        .map_err(|error| anyhow!("invalid value for `{directive}`: {error}"))
}

fn parse_localnet_rule(line: &str) -> Result<LocalnetRule> {
    let value = parse_single_value::<String>(line, "localnet")?;
    let (network_part, mask_part) = value
        .rsplit_once('/')
        .ok_or_else(|| anyhow!("`localnet` must be in the form `address[:port]/mask`"))?;

    let (network, port) = parse_localnet_endpoint(network_part)?;
    let mask = mask_part
        .parse::<IpAddr>()
        .with_context(|| format!("invalid localnet mask `{mask_part}`"))?;

    ensure!(
        network.is_ipv4() == mask.is_ipv4(),
        "`localnet` network `{network}` and mask `{mask}` must use the same IP family"
    );

    Ok(LocalnetRule {
        network,
        port,
        mask,
    })
}

fn parse_localnet_endpoint(network_part: &str) -> Result<(IpAddr, Option<u16>)> {
    if let Some(bracketed) = network_part.strip_prefix('[') {
        let (network, suffix) = bracketed
            .split_once(']')
            .ok_or_else(|| anyhow!("invalid bracketed localnet address `{network_part}`"))?;

        let network = network
            .parse::<IpAddr>()
            .with_context(|| format!("invalid localnet network `{network}`"))?;

        let port = if suffix.is_empty() {
            None
        } else {
            let port = suffix
                .strip_prefix(':')
                .ok_or_else(|| anyhow!("invalid localnet address `{network_part}`"))?;
            Some(
                port.parse::<u16>()
                    .with_context(|| format!("invalid localnet port `{port}`"))?,
            )
        };

        return Ok((network, port));
    }

    if let Ok(network) = network_part.parse::<IpAddr>() {
        return Ok((network, None));
    }

    let (network, port) = network_part
        .rsplit_once(':')
        .ok_or_else(|| anyhow!("invalid localnet address `{network_part}`"))?;
    let network = network
        .parse::<IpAddr>()
        .with_context(|| format!("invalid localnet network `{network}`"))?;
    ensure!(
        network.is_ipv4(),
        "IPv6 localnet addresses with ports must use `[address]:port` syntax"
    );
    let port = port
        .parse::<u16>()
        .with_context(|| format!("invalid localnet port `{port}`"))?;

    Ok((network, Some(port)))
}

#[cfg(test)]
mod tests {
    use super::{
        ChainType, LocalnetRule, ProxyCredentials, ProxyEntry, ProxyType, ProxychainsConfig,
        SAMPLE_PROXYCHAINS_CONFIG,
    };
    use std::{
        borrow::ToOwned,
        format,
        mem::size_of,
        net::{IpAddr, Ipv4Addr, Ipv6Addr},
        string::ToString,
        vec,
        vec::Vec,
    };
    use windows_sys::Win32::Networking::WinSock::{
        AF_INET, AF_INET6, IN_ADDR, IN_ADDR_0, IN_ADDR_0_0, IN6_ADDR, IN6_ADDR_0, SOCKADDR,
        SOCKADDR_IN, SOCKADDR_IN6, SOCKADDR_IN6_0,
    };

    #[test]
    fn parses_the_documented_sample_config() {
        let config = ProxychainsConfig::parse(SAMPLE_PROXYCHAINS_CONFIG)
            .expect("sample config should parse");

        assert_eq!(config.chain_type, ChainType::Strict);
        assert_eq!(config.chain_len, None);
        assert!(!config.quiet_mode);
        assert!(config.proxy_dns);
        assert_eq!(config.remote_dns_subnet, Some(224));
        assert_eq!(config.remote_dns_subnet_6, Some(252));
        assert_eq!(config.tcp_read_time_out, Some(15000));
        assert_eq!(config.tcp_connect_time_out, Some(8000));
        assert_eq!(config.localnets.len(), 1);
        assert_eq!(
            config.localnets[0].network,
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 0))
        );
        assert_eq!(config.localnets[0].port, None);
        assert_eq!(
            config.localnets[0].mask,
            IpAddr::V4(Ipv4Addr::new(255, 0, 0, 0))
        );
        assert_eq!(config.proxies.len(), 1);
        assert_eq!(config.proxies[0].proxy_type, ProxyType::Socks4);
        assert_eq!(config.proxies[0].host, "127.0.0.1");
        assert_eq!(config.proxies[0].port, 9050);
        assert!(config.proxies[0].credentials.is_none());
    }

    #[test]
    fn rejects_multiple_chain_modes() {
        let error = ProxychainsConfig::parse(
            "strict_chain\ndynamic_chain\n[ProxyList]\nsocks4 127.0.0.1 9050\n",
        )
        .expect_err("multiple chain modes must fail");

        assert!(format!("{error:#}").contains("multiple chain types configured"));
    }

    #[test]
    fn rejects_chain_len_without_random_chain() {
        let error = ProxychainsConfig::parse(
            "strict_chain\nchain_len = 2\n[ProxyList]\nsocks4 127.0.0.1 9050\n",
        )
        .expect_err("chain_len must be rejected outside random mode");

        assert!(format!("{error:#}").contains("only valid with `random_chain`"));
    }

    #[test]
    fn rejects_dnat_rules() {
        let error = ProxychainsConfig::parse(
            "strict_chain\ndnat 1.1.1.1 1.1.1.2\n[ProxyList]\nsocks4 127.0.0.1 9050\n",
        )
        .expect_err("dnat should be unsupported");

        assert!(format!("{error:#}").contains("unsupported directive `dnat`"));
    }

    #[test]
    fn rejects_http_proxies() {
        let error = ProxychainsConfig::parse("strict_chain\n[ProxyList]\nhttp 127.0.0.1 8080\n")
            .expect_err("http proxies should be unsupported");

        assert!(format!("{error:#}").contains("unsupported proxy type `http`"));
    }

    #[test]
    fn display_roundtrips_the_documented_sample_config() {
        let parsed = ProxychainsConfig::parse(SAMPLE_PROXYCHAINS_CONFIG)
            .expect("sample config should parse");
        let rendered = parsed.to_string();
        let reparsed =
            ProxychainsConfig::parse(&rendered).expect("canonicalized config should parse");

        assert_eq!(reparsed, parsed);
    }

    #[test]
    fn display_roundtrips_valid_configs_with_optional_fields() {
        let config = ProxychainsConfig {
            chain_type: ChainType::Random,
            chain_len: Some(2),
            quiet_mode: true,
            proxy_dns: true,
            remote_dns_subnet: Some(10),
            remote_dns_subnet_6: Some(252),
            tcp_read_time_out: Some(15_000),
            tcp_connect_time_out: Some(8_000),
            localnets: vec![
                LocalnetRule {
                    network: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 0)),
                    port: None,
                    mask: IpAddr::V4(Ipv4Addr::new(255, 0, 0, 0)),
                },
                LocalnetRule {
                    network: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 0)),
                    port: Some(80),
                    mask: IpAddr::V4(Ipv4Addr::new(255, 255, 255, 0)),
                },
                LocalnetRule {
                    network: IpAddr::V6(Ipv6Addr::LOCALHOST),
                    port: Some(443),
                    mask: IpAddr::V6(Ipv6Addr::new(
                        0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff,
                    )),
                },
            ],
            proxies: vec![
                ProxyEntry {
                    proxy_type: ProxyType::Socks4,
                    host: "127.0.0.1".to_owned(),
                    port: 9050,
                    credentials: None,
                },
                ProxyEntry {
                    proxy_type: ProxyType::Socks5,
                    host: "10.0.0.2".to_owned(),
                    port: 1080,
                    credentials: Some(ProxyCredentials {
                        username: "alice".to_owned(),
                        password: "secret".to_owned(),
                    }),
                },
                ProxyEntry {
                    proxy_type: ProxyType::Socks5,
                    host: "::1".to_owned(),
                    port: 1081,
                    credentials: None,
                },
            ],
        };

        let rendered = config.to_string();
        let reparsed =
            ProxychainsConfig::parse(&rendered).expect("canonicalized config should parse");

        assert_eq!(reparsed, config);
    }

    #[test]
    fn display_normalizes_chain_len_out_of_non_random_configs() {
        let config = ProxychainsConfig {
            chain_type: ChainType::Strict,
            chain_len: Some(2),
            quiet_mode: false,
            proxy_dns: false,
            remote_dns_subnet: None,
            remote_dns_subnet_6: None,
            tcp_read_time_out: None,
            tcp_connect_time_out: None,
            localnets: Vec::new(),
            proxies: vec![ProxyEntry {
                proxy_type: ProxyType::Socks4,
                host: "127.0.0.1".to_owned(),
                port: 9050,
                credentials: None,
            }],
        };

        let rendered = config.to_string();
        let reparsed =
            ProxychainsConfig::parse(&rendered).expect("canonicalized config should parse");

        assert!(!rendered.contains("chain_len"));
        assert_eq!(reparsed.chain_type, ChainType::Strict);
        assert_eq!(reparsed.chain_len, None);
    }

    #[test]
    fn parses_ipv6_localnet_and_proxy_hosts() {
        let config = ProxychainsConfig::parse(
            "random_chain\n\
             chain_len = 1\n\
             remote_dns_subnet_6 253\n\
             localnet ::1/ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff\n\
             localnet [2001:db8::1]:443/ffff:ffff:ffff:ffff::\n\
             [ProxyList]\n\
             socks5 ::1 1080\n\
             socks5 2001:db8::2 1081 user pass\n",
        )
        .expect("IPv6 addresses should parse");

        assert_eq!(config.localnets.len(), 2);
        assert_eq!(config.remote_dns_subnet_6, Some(253));
        assert_eq!(config.localnets[0].network, IpAddr::V6(Ipv6Addr::LOCALHOST));
        assert_eq!(
            config.localnets[0].mask,
            IpAddr::V6(Ipv6Addr::new(
                0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff,
            )),
        );
        assert_eq!(
            config.localnets[1].network,
            IpAddr::V6("2001:db8::1".parse::<Ipv6Addr>().expect("valid IPv6")),
        );
        assert_eq!(config.localnets[1].port, Some(443));
        assert_eq!(config.proxies[0].host, "::1");
        assert_eq!(config.proxies[1].host, "2001:db8::2");

        let rendered = config.to_string();
        assert!(rendered.contains("localnet [2001:db8::1]:443/ffff:ffff:ffff:ffff::"));
        let reparsed =
            ProxychainsConfig::parse(&rendered).expect("rendered IPv6 config should parse");
        assert_eq!(reparsed, config);
    }

    #[test]
    fn rejects_mixed_ip_families_in_localnet_rules() {
        let error = ProxychainsConfig::parse(
            "strict_chain\n\
             localnet ::1/255.0.0.0\n\
             [ProxyList]\n\
             socks4 127.0.0.1 9050\n",
        )
        .expect_err("mixed localnet families must fail");

        assert!(format!("{error:#}").contains("must use the same IP family"));
    }

    #[test]
    fn rejects_localnet_that_overlaps_remote_dns_subnet() {
        let error = ProxychainsConfig::parse(
            "strict_chain\n\
             remote_dns_subnet 224\n\
             localnet 224.0.0.0/255.0.0.0\n\
             [ProxyList]\n\
             socks4 127.0.0.1 9050\n",
        )
        .expect_err("overlapping IPv4 synthetic DNS subnet must fail");

        assert!(format!("{error:#}").contains("remote_dns_subnet 224"));
        assert!(format!("{error:#}").contains("localnet 224.0.0.0/255.0.0.0"));
    }

    #[test]
    fn rejects_localnet_that_contains_remote_dns_subnet_6() {
        let error = ProxychainsConfig::parse(
            "strict_chain\n\
             remote_dns_subnet_6 252\n\
             localnet fc00::/ff00::\n\
             [ProxyList]\n\
             socks5 ::1 1080\n",
        )
        .expect_err("containing IPv6 synthetic DNS subnet must fail");

        assert!(format!("{error:#}").contains("remote_dns_subnet_6 252"));
        assert!(format!("{error:#}").contains("localnet fc00::/ff00::"));
    }

    #[test]
    fn rejects_socks5_credentials_that_exceed_packet_limits() {
        let username = "u".repeat(256);
        let error = ProxychainsConfig::parse(&format!(
            "strict_chain\n\
             [ProxyList]\n\
             socks5 127.0.0.1 1080 {username} pass\n"
        ))
        .expect_err("oversized SOCKS5 usernames must fail");

        assert!(format!("{error:#}").contains("username exceeds 255 bytes"));
    }

    #[test]
    fn rejects_domain_next_hops_too_long_for_socks5() {
        let long_host = "a".repeat(256);
        let error = ProxychainsConfig::parse(&format!(
            "strict_chain\n\
             [ProxyList]\n\
             socks5 127.0.0.1 1080\n\
             socks5 {long_host} 1081\n"
        ))
        .expect_err("oversized SOCKS5 domain next hops must fail");

        assert!(format!("{error:#}").contains("host exceeds 255 bytes"));
    }

    #[test]
    fn rejects_ipv6_next_hops_behind_socks4() {
        let error = ProxychainsConfig::parse(
            "strict_chain\n\
             [ProxyList]\n\
             socks4 127.0.0.1 1080\n\
             socks5 ::1 1081\n",
        )
        .expect_err("SOCKS4 proxies cannot encode IPv6 next hops");

        assert!(format!("{error:#}").contains("cannot be reached through SOCKS4"));
    }

    #[test]
    fn rejects_random_chain_len_longer_than_proxy_list() {
        let error = ProxychainsConfig::parse(
            "random_chain\n\
             chain_len = 2\n\
             [ProxyList]\n\
             socks5 127.0.0.1 1080\n",
        )
        .expect_err("chain_len larger than proxy count must fail");

        assert!(format!("{error:#}").contains("cannot exceed the number of configured proxies"));
    }

    #[test]
    fn sample_chain_returns_strict_chain_and_ipv4_target() {
        let config = ProxychainsConfig::parse(
            "strict_chain\n\
             [ProxyList]\n\
             socks4 127.0.0.1 9050\n\
             socks5 10.0.0.2 1080\n",
        )
        .expect("config should parse");

        let address = SOCKADDR_IN {
            sin_family: AF_INET,
            sin_port: 8080u16.to_be(),
            sin_addr: IN_ADDR {
                S_un: IN_ADDR_0 {
                    S_un_b: IN_ADDR_0_0 {
                        s_b1: 1,
                        s_b2: 2,
                        s_b3: 3,
                        s_b4: 4,
                    },
                },
            },
            sin_zero: [0; 8],
        };

        let (name, port, chain) = config
            .sample_chain(
                &address as *const SOCKADDR_IN as *const SOCKADDR,
                size_of::<SOCKADDR_IN>() as i32,
            )
            .expect("sampling should succeed");

        assert_eq!(name, "1.2.3.4");
        assert_eq!(port, 8080);
        assert_eq!(chain, config.proxies);
    }

    #[test]
    fn sample_chain_respects_localnet_bypass() {
        let config = ProxychainsConfig::parse(
            "strict_chain\n\
             localnet 127.0.0.0/255.0.0.0\n\
             [ProxyList]\n\
             socks5 127.0.0.1 1080\n",
        )
        .expect("config should parse");

        let address = SOCKADDR_IN {
            sin_family: AF_INET,
            sin_port: 443u16.to_be(),
            sin_addr: IN_ADDR {
                S_un: IN_ADDR_0 {
                    S_un_b: IN_ADDR_0_0 {
                        s_b1: 127,
                        s_b2: 0,
                        s_b3: 0,
                        s_b4: 1,
                    },
                },
            },
            sin_zero: [0; 8],
        };

        let (_name, _port, chain) = config
            .sample_chain(
                &address as *const SOCKADDR_IN as *const SOCKADDR,
                size_of::<SOCKADDR_IN>() as i32,
            )
            .expect("sampling should succeed");

        assert!(chain.is_empty());
    }

    #[test]
    fn sample_chain_returns_random_subset_of_requested_length() {
        let config = ProxychainsConfig::parse(
            "random_chain\n\
             chain_len = 2\n\
             [ProxyList]\n\
             socks4 127.0.0.1 9050\n\
             socks5 10.0.0.2 1080\n\
             socks5 10.0.0.3 1081\n",
        )
        .expect("config should parse");

        let address = SOCKADDR_IN {
            sin_family: AF_INET,
            sin_port: 80u16.to_be(),
            sin_addr: IN_ADDR {
                S_un: IN_ADDR_0 {
                    S_un_b: IN_ADDR_0_0 {
                        s_b1: 8,
                        s_b2: 8,
                        s_b3: 8,
                        s_b4: 8,
                    },
                },
            },
            sin_zero: [0; 8],
        };

        let (_name, _port, chain) = config
            .sample_chain(
                &address as *const SOCKADDR_IN as *const SOCKADDR,
                size_of::<SOCKADDR_IN>() as i32,
            )
            .expect("sampling should succeed");

        assert_eq!(chain.len(), 2);
        assert!(chain.iter().all(|proxy| config.proxies.contains(proxy)));
    }

    #[test]
    fn sample_chain_never_returns_socks4_as_ipv6_random_exit() {
        let config = ProxychainsConfig::parse(
            "random_chain\n\
             chain_len = 2\n\
             [ProxyList]\n\
             socks4 127.0.0.1 9050\n\
             socks5 10.0.0.2 1080\n\
             socks4 10.0.0.3 1081\n",
        )
        .expect("config should parse");

        let address = SOCKADDR_IN6 {
            sin6_family: AF_INET6,
            sin6_port: 443u16.to_be(),
            sin6_flowinfo: 0,
            sin6_addr: IN6_ADDR {
                u: IN6_ADDR_0 {
                    Byte: Ipv6Addr::LOCALHOST.octets(),
                },
            },
            Anonymous: SOCKADDR_IN6_0 { sin6_scope_id: 0 },
        };

        let (_name, _port, chain) = config
            .sample_chain(
                &address as *const SOCKADDR_IN6 as *const SOCKADDR,
                size_of::<SOCKADDR_IN6>() as i32,
            )
            .expect("sampling should succeed");

        assert_eq!(chain.len(), 2);
        assert_ne!(chain.last().unwrap().proxy_type, ProxyType::Socks4);
    }

    #[test]
    fn sample_chain_rejects_ipv6_random_chain_without_non_socks4_exit() {
        let config = ProxychainsConfig::parse(
            "random_chain\n\
             chain_len = 1\n\
             [ProxyList]\n\
             socks4 127.0.0.1 9050\n",
        )
        .expect("config should parse");

        let address = SOCKADDR_IN6 {
            sin6_family: AF_INET6,
            sin6_port: 443u16.to_be(),
            sin6_flowinfo: 0,
            sin6_addr: IN6_ADDR {
                u: IN6_ADDR_0 {
                    Byte: Ipv6Addr::LOCALHOST.octets(),
                },
            },
            Anonymous: SOCKADDR_IN6_0 { sin6_scope_id: 0 },
        };

        let error = config
            .sample_chain(
                &address as *const SOCKADDR_IN6 as *const SOCKADDR,
                size_of::<SOCKADDR_IN6>() as i32,
            )
            .expect_err("IPv6 random chains need a non-SOCKS4 exit");

        assert!(format!("{error:#}").contains("requires at least one non-SOCKS4 exit proxy"));
    }

    #[test]
    fn sample_chain_allows_ipv6_target_for_late_final_hop_validation() {
        let config = ProxychainsConfig::parse(
            "strict_chain\n\
             [ProxyList]\n\
             socks4 127.0.0.1 9050\n",
        )
        .expect("config should parse");

        let address = SOCKADDR_IN6 {
            sin6_family: AF_INET6,
            sin6_port: 443u16.to_be(),
            sin6_flowinfo: 0,
            sin6_addr: IN6_ADDR {
                u: IN6_ADDR_0 {
                    Byte: Ipv6Addr::LOCALHOST.octets(),
                },
            },
            Anonymous: SOCKADDR_IN6_0 { sin6_scope_id: 0 },
        };

        let (name, port, chain) = config
            .sample_chain(
                &address as *const SOCKADDR_IN6 as *const SOCKADDR,
                size_of::<SOCKADDR_IN6>() as i32,
            )
            .expect("final-hop validation now happens in socks.rs");

        assert_eq!(name, "::1");
        assert_eq!(port, 443);
        assert_eq!(chain, config.proxies);
    }
}
