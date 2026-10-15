//! Read-only inspection of this host's network: the facts that setup plans are built from.
//! Nothing here changes system state; probes bind sockets only momentarily.

use std::{
    fs,
    io::ErrorKind,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener, UdpSocket},
    process::{Command, Stdio},
    time::{Duration, Instant},
};

use ipnet::IpNet;
use serde::Serialize;

#[derive(Debug, Serialize)]
pub struct NetworkFacts {
    pub platform: &'static str,
    /// Set when this host cannot be reached at its detected address by other LAN devices
    /// without extra steps: `wsl2` or `container`.
    pub environment: Option<&'static str>,
    pub lan_interface: Option<String>,
    pub lan_address: Option<IpAddr>,
    pub lan_network: Option<IpNet>,
    /// Unique-local IPv6 addresses on the LAN interface, usable as IPv6 DNS servers.
    pub lan_ipv6: Vec<Ipv6Addr>,
    /// The LAN interface has a global IPv6 address, so the router very likely advertises
    /// its own IPv6 DNS server to every client.
    pub global_ipv6: bool,
    /// Whether the LAN address was leased by DHCP and may change; `None` when unknown.
    pub address_dynamic: Option<bool>,
    pub default_gateway: Option<IpAddr>,
    pub current_resolvers: Vec<IpAddr>,
    pub search_domains: Vec<String>,
    pub resolver_manager: Option<&'static str>,
    pub vpn_interfaces: Vec<String>,
    /// Every address assigned to this host, used to keep it out of its own upstreams.
    pub host_addresses: Vec<IpAddr>,
    pub firewall: Option<&'static str>,
    pub port_53_available: bool,
}

/// Availability of one transport on a listen address.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum PortState {
    Available,
    InUse { owners: Vec<PortOwner> },
    PermissionRequired,
    AddressUnavailable,
    Error { message: String },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct PortOwner {
    pub protocol: &'static str,
    pub address: SocketAddr,
    pub process: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct PortProbe {
    pub address: SocketAddr,
    pub udp: PortState,
    pub tcp: PortState,
}

pub fn inspect_network() -> NetworkFacts {
    let interfaces = if_addrs::get_if_addrs().unwrap_or_default();
    let default_gateway = detect_default_gateway();
    let routed = routed_address();
    let lan = select_lan(&interfaces, routed, default_gateway);
    let lan_interface = lan.as_ref().map(|(name, _, _)| name.clone());
    let lan_address = lan.as_ref().map(|(_, address, _)| IpAddr::V4(*address));
    let lan_network = lan.as_ref().map(|(_, _, network)| *network);
    let on_lan = |interface: &if_addrs::Interface| Some(&interface.name) == lan_interface.as_ref();
    let lan_ipv6 = interfaces
        .iter()
        .filter(|interface| on_lan(interface))
        .filter_map(|interface| match interface.ip() {
            IpAddr::V6(ip) if ip.is_unique_local() => Some(ip),
            _ => None,
        })
        .collect();
    let global_ipv6 = interfaces
        .iter()
        .filter(|i| on_lan(i))
        .any(|interface| matches!(interface.ip(), IpAddr::V6(ip) if is_global_v6(ip)));
    let vpn_interfaces: Vec<String> = interfaces
        .iter()
        .filter(|interface| is_vpn_interface(&interface.name))
        .map(|interface| interface.name.clone())
        .collect();
    let vpn_interfaces = unique(vpn_interfaces);
    let host_addresses = interfaces.iter().map(if_addrs::Interface::ip).collect();
    let (current_resolvers, search_domains, resolver_manager) = detect_resolvers();
    let port_53_available = lan_address
        .and_then(|ip| UdpSocket::bind(SocketAddr::new(ip, 53)).ok())
        .is_some();
    let environment = detect_environment();
    NetworkFacts {
        platform: std::env::consts::OS,
        environment,
        // WSL mirrors Windows' addresses without their DHCP state.
        address_dynamic: match (&lan_interface, lan_address, environment) {
            (_, _, Some("wsl2")) => None,
            (Some(name), Some(address), _) => address_dynamic(name, address),
            _ => None,
        },
        lan_interface,
        lan_address,
        lan_network,
        lan_ipv6,
        global_ipv6,
        default_gateway,
        current_resolvers,
        search_domains,
        resolver_manager,
        vpn_interfaces,
        host_addresses,
        firewall: detect_firewall(),
        port_53_available,
    }
}

/// The source address the host would use for Internet traffic. With a full-tunnel VPN this
/// is the tunnel address, so it is only a hint for choosing among LAN interfaces.
fn routed_address() -> Option<Ipv4Addr> {
    let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).ok()?;
    socket.connect((Ipv4Addr::new(1, 1, 1, 1), 53)).ok()?;
    match socket.local_addr().ok()?.ip() {
        IpAddr::V4(address) => Some(address),
        IpAddr::V6(_) => None,
    }
}

/// Choose the interface other LAN devices reach this host on: a private IPv4 address on
/// a physical interface, preferring the routed one, then the gateway's subnet.
fn select_lan(
    interfaces: &[if_addrs::Interface],
    routed: Option<Ipv4Addr>,
    gateway: Option<IpAddr>,
) -> Option<(String, Ipv4Addr, IpNet)> {
    let candidates: Vec<(String, Ipv4Addr, IpNet)> = interfaces
        .iter()
        .filter(|interface| !is_vpn_interface(&interface.name))
        .filter(|interface| !is_virtual_interface(&interface.name))
        .filter_map(|interface| match &interface.addr {
            if_addrs::IfAddr::V4(v4) if v4.ip.is_private() => {
                let network = ipnet::Ipv4Net::new(v4.ip, v4.prefixlen).ok()?.trunc();
                Some((interface.name.clone(), v4.ip, IpNet::V4(network)))
            }
            _ => None,
        })
        .collect();
    routed
        .and_then(|routed| candidates.iter().find(|(_, address, _)| *address == routed))
        .or_else(|| {
            gateway.and_then(|gateway| {
                candidates
                    .iter()
                    .find(|(_, _, network)| network.contains(&gateway))
            })
        })
        .or_else(|| candidates.first())
        .cloned()
}

fn is_global_v6(ip: Ipv6Addr) -> bool {
    !(ip.is_loopback()
        || ip.is_unspecified()
        || ip.is_unique_local()
        || ip.is_unicast_link_local()
        || ip.is_multicast())
}

/// Tunnel interfaces of common VPNs and overlay networks.
pub fn is_vpn_interface(name: &str) -> bool {
    let name = name.to_ascii_lowercase();
    [
        "tun",
        "tap",
        "wg",
        "utun",
        "ppp",
        "ipsec",
        "tailscale",
        "zt",
        "nordlynx",
        "proton",
        "mullvad",
        "wireguard",
        "openvpn",
    ]
    .iter()
    .any(|prefix| name.starts_with(prefix))
        || name.contains("vpn")
}

/// Container bridges and hypervisor adapters, which LAN devices cannot reach directly.
fn is_virtual_interface(name: &str) -> bool {
    let name = name.to_ascii_lowercase();
    [
        "lo",
        "docker",
        "br-",
        "veth",
        "virbr",
        "vmnet",
        "vboxnet",
        "cni",
        "flannel",
        "podman",
        "lxc",
        "lxdbr",
        "vethernet",
        "virtualbox",
        "vmware",
        "hyper-v",
    ]
    .iter()
    .any(|prefix| name.starts_with(prefix))
}

fn detect_environment() -> Option<&'static str> {
    // Containers first: Docker Desktop runs them on WSL's kernel.
    if fs::metadata("/.dockerenv").is_ok() || fs::metadata("/run/.containerenv").is_ok() {
        return Some("container");
    }
    if fs::read_to_string("/proc/sys/kernel/osrelease")
        .is_ok_and(|release| release.to_ascii_lowercase().contains("microsoft"))
    {
        return Some("wsl2");
    }
    None
}

/// Remove repeated values, keeping the first occurrence of each.
fn unique<T: PartialEq>(values: Vec<T>) -> Vec<T> {
    let mut kept = Vec::with_capacity(values.len());
    for value in values {
        if !kept.contains(&value) {
            kept.push(value);
        }
    }
    kept
}

/// Probe whether localname could bind `address` over UDP and TCP right now.
pub fn probe_port(address: SocketAddr) -> PortProbe {
    let classify = |result: std::io::Result<()>, protocol: &'static str| match result {
        Ok(()) => PortState::Available,
        Err(error) => match error.kind() {
            ErrorKind::AddrInUse => PortState::InUse {
                owners: port_owners(address.port())
                    .into_iter()
                    .filter(|owner| owner.protocol == protocol && overlaps(owner.address, address))
                    .collect(),
            },
            ErrorKind::PermissionDenied => PortState::PermissionRequired,
            ErrorKind::AddrNotAvailable => PortState::AddressUnavailable,
            _ => PortState::Error {
                message: error.to_string(),
            },
        },
    };
    PortProbe {
        address,
        udp: classify(UdpSocket::bind(address).map(drop), "udp"),
        tcp: classify(TcpListener::bind(address).map(drop), "tcp"),
    }
}

/// Whether a socket bound to `owner` prevents binding `wanted` (same port; same or
/// wildcard address).
fn overlaps(owner: SocketAddr, wanted: SocketAddr) -> bool {
    owner.port() == wanted.port()
        && (owner.ip() == wanted.ip()
            || owner.ip().is_unspecified()
            || wanted.ip().is_unspecified())
}

/// Sockets listening on `port`, with the owning process when the platform reveals it.
#[cfg(target_os = "linux")]
pub fn port_owners(port: u16) -> Vec<PortOwner> {
    use std::collections::HashMap;

    let mut sockets: Vec<(u64, PortOwner)> = Vec::new();
    for (file, protocol, listening_state) in [
        ("/proc/net/udp", "udp", "07"),
        ("/proc/net/udp6", "udp", "07"),
        ("/proc/net/tcp", "tcp", "0A"),
        ("/proc/net/tcp6", "tcp", "0A"),
    ] {
        let Ok(text) = fs::read_to_string(file) else {
            continue;
        };
        for line in text.lines().skip(1) {
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.len() < 10 || fields[3] != listening_state {
                continue;
            }
            let Some(address) = parse_proc_address(fields[1]) else {
                continue;
            };
            if address.port() != port {
                continue;
            }
            if let Ok(inode) = fields[9].parse::<u64>() {
                sockets.push((
                    inode,
                    PortOwner {
                        protocol,
                        address,
                        process: None,
                    },
                ));
            }
        }
    }
    if sockets.is_empty() {
        return Vec::new();
    }
    // Map socket inodes to processes. Other users' descriptors are unreadable without
    // privileges; those owners stay unknown.
    let mut processes: HashMap<u64, String> = HashMap::new();
    if let Ok(entries) = fs::read_dir("/proc") {
        for entry in entries.flatten() {
            let pid = entry.file_name();
            if !pid
                .to_string_lossy()
                .bytes()
                .all(|byte| byte.is_ascii_digit())
            {
                continue;
            }
            let Ok(descriptors) = fs::read_dir(entry.path().join("fd")) else {
                continue;
            };
            for descriptor in descriptors.flatten() {
                let Ok(target) = fs::read_link(descriptor.path()) else {
                    continue;
                };
                let target = target.to_string_lossy();
                if let Some(inode) = target
                    .strip_prefix("socket:[")
                    .and_then(|rest| rest.strip_suffix(']'))
                    .and_then(|inode| inode.parse::<u64>().ok())
                    && sockets.iter().any(|(wanted, _)| *wanted == inode)
                {
                    let name = fs::read_to_string(entry.path().join("comm"))
                        .map(|name| name.trim().to_owned())
                        .unwrap_or_default();
                    processes.insert(inode, format!("{name} (pid {})", pid.to_string_lossy()));
                }
            }
        }
    }
    let mut owners: Vec<PortOwner> = sockets
        .into_iter()
        .map(|(inode, mut owner)| {
            owner.process = processes.get(&inode).cloned();
            owner
        })
        .collect();
    owners.dedup();
    owners
}

/// `/proc/net` addresses are hex in host byte order: `0100007F:0035` is 127.0.0.1:53.
#[cfg(target_os = "linux")]
fn parse_proc_address(text: &str) -> Option<SocketAddr> {
    let (address, port) = text.split_once(':')?;
    let port = u16::from_str_radix(port, 16).ok()?;
    let ip = match address.len() {
        8 => IpAddr::V4(Ipv4Addr::from(
            u32::from_str_radix(address, 16).ok()?.swap_bytes(),
        )),
        32 => {
            let mut octets = [0_u8; 16];
            for (word, chunk) in address.as_bytes().chunks(8).enumerate() {
                let value = u32::from_str_radix(std::str::from_utf8(chunk).ok()?, 16).ok()?;
                octets[word * 4..word * 4 + 4].copy_from_slice(&value.to_le_bytes());
            }
            IpAddr::V6(Ipv6Addr::from(octets))
        }
        _ => return None,
    };
    Some(SocketAddr::new(ip, port))
}

#[cfg(windows)]
pub fn port_owners(port: u16) -> Vec<PortOwner> {
    let script = format!(
        "Get-NetUDPEndpoint -LocalPort {port} -ErrorAction SilentlyContinue | ForEach-Object {{ 'udp ' + $_.LocalAddress + ' ' + (Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName }}; \
         Get-NetTCPConnection -State Listen -LocalPort {port} -ErrorAction SilentlyContinue | ForEach-Object {{ 'tcp ' + $_.LocalAddress + ' ' + (Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName }}"
    );
    powershell(&script)
        .unwrap_or_default()
        .lines()
        .filter_map(|line| {
            let mut words = line.split_whitespace();
            let protocol = match words.next()? {
                "udp" => "udp",
                "tcp" => "tcp",
                _ => return None,
            };
            let ip: IpAddr = words.next()?.parse().ok()?;
            Some(PortOwner {
                protocol,
                address: SocketAddr::new(ip, port),
                process: words.next().map(str::to_owned),
            })
        })
        .collect()
}

#[cfg(not(any(target_os = "linux", windows)))]
pub fn port_owners(_port: u16) -> Vec<PortOwner> {
    Vec::new()
}

/// Run a short read-only command, giving up after twenty seconds.
fn command_output(program: &str, arguments: &[&str]) -> Option<String> {
    let mut child = Command::new(program)
        .args(arguments)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(20)),
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                return None;
            }
        }
    }
    let output = child.wait_with_output().ok()?;
    output
        .status
        .success()
        .then(|| String::from_utf8_lossy(&output.stdout).into_owned())
}

#[cfg(windows)]
fn powershell(script: &str) -> Option<String> {
    command_output(
        "powershell.exe",
        &[
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            &format!("[Console]::OutputEncoding = [Text.Encoding]::UTF8; {script}"),
        ],
    )
}

/// Everything setup needs from Windows, gathered by one PowerShell process: each start
/// costs about a second, and several under load could exceed their timeout.
#[cfg(windows)]
#[derive(Default, serde::Deserialize)]
struct WindowsFacts {
    #[serde(default)]
    gateway: Option<String>,
    #[serde(default)]
    resolvers: Vec<String>,
    #[serde(default)]
    suffixes: Vec<String>,
    #[serde(default)]
    dhcp: Vec<String>,
}

#[cfg(windows)]
fn windows_facts() -> &'static WindowsFacts {
    static FACTS: std::sync::OnceLock<WindowsFacts> = std::sync::OnceLock::new();
    FACTS.get_or_init(|| {
        let script = "$r = [ordered]@{}; \
            $r.gateway = [string](Get-NetRoute -DestinationPrefix 0.0.0.0/0 -ErrorAction SilentlyContinue | Sort-Object RouteMetric | Select-Object -First 1).NextHop; \
            $r.resolvers = @(Get-DnsClientServerAddress -ErrorAction SilentlyContinue | ForEach-Object { $_.ServerAddresses }); \
            $r.suffixes = @(@((Get-DnsClientGlobalSetting).SuffixSearchList) + @(Get-DnsClient | ForEach-Object { $_.ConnectionSpecificSuffix }) | Where-Object { $_ }); \
            $r.dhcp = @(Get-NetIPAddress -PrefixOrigin Dhcp -ErrorAction SilentlyContinue | ForEach-Object { $_.IPAddress }); \
            $r | ConvertTo-Json -Compress";
        powershell(script)
            .and_then(|text| serde_json::from_str(text.trim()).ok())
            .unwrap_or_default()
    })
}

fn detect_default_gateway() -> Option<IpAddr> {
    #[cfg(target_os = "linux")]
    {
        // /proc works in minimal containers that lack iproute2.
        let text = fs::read_to_string("/proc/net/route").ok()?;
        text.lines().skip(1).find_map(|line| {
            let fields: Vec<&str> = line.split_whitespace().collect();
            (fields.len() > 2 && fields[1] == "00000000")
                .then(|| u32::from_str_radix(fields[2], 16).ok())
                .flatten()
                .filter(|gateway| *gateway != 0)
                .map(|gateway| IpAddr::V4(Ipv4Addr::from(gateway.swap_bytes())))
        })
    }
    #[cfg(target_os = "macos")]
    {
        let text = command_output("route", &["-n", "get", "default"])?;
        text.lines()
            .find_map(|line| line.trim().strip_prefix("gateway:"))
            .and_then(|gateway| gateway.trim().parse().ok())
    }
    #[cfg(windows)]
    {
        windows_facts().gateway.as_deref()?.trim().parse().ok()
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
    {
        None
    }
}

/// Resolvers, search domains, and the service managing them.
fn detect_resolvers() -> (Vec<IpAddr>, Vec<String>, Option<&'static str>) {
    #[cfg(windows)]
    {
        let facts = windows_facts();
        let addresses: Vec<IpAddr> = facts
            .resolvers
            .iter()
            .filter_map(|line| line.trim().parse().ok())
            .filter(|address: &IpAddr| !is_windows_placeholder(*address))
            .collect();
        let addresses = unique(addresses);
        let domains: Vec<String> = facts
            .suffixes
            .iter()
            .map(|suffix| suffix.trim().to_owned())
            .filter(|suffix| !suffix.is_empty())
            .collect();
        let domains = unique(domains);
        (addresses, domains, Some("windows"))
    }
    #[cfg(not(windows))]
    {
        let (resolvers, domains) = parse_resolv_conf("/etc/resolv.conf");
        let stub = |address: &IpAddr| matches!(address, IpAddr::V4(ip) if ip.octets()[..3] == [127, 0, 0] && ip.octets()[3] >= 53);
        if !resolvers.is_empty() && resolvers.iter().all(stub) {
            let (upstream, upstream_domains) =
                parse_resolv_conf("/run/systemd/resolve/resolv.conf");
            if !upstream.is_empty() {
                let mut domains = domains;
                domains.extend(upstream_domains);
                return (upstream, unique(domains), Some("systemd-resolved"));
            }
        }
        (resolvers, domains, None)
    }
}

/// Windows lists `fec0:0:0:ffff::1` site-local placeholders when no IPv6 DNS is set.
#[cfg(windows)]
fn is_windows_placeholder(address: IpAddr) -> bool {
    matches!(address, IpAddr::V6(ip) if ip.segments()[..4] == [0xfec0, 0, 0, 0xffff])
}

#[cfg(not(windows))]
fn parse_resolv_conf(path: &str) -> (Vec<IpAddr>, Vec<String>) {
    let Ok(text) = fs::read_to_string(path) else {
        return (Vec::new(), Vec::new());
    };
    let mut resolvers = Vec::new();
    let mut domains = Vec::new();
    for line in text.lines() {
        let mut words = line.split_whitespace();
        match words.next() {
            Some("nameserver") => {
                // Scoped IPv6 resolvers carry `%interface`; the zone index is not routable here.
                if let Some(address) = words
                    .next()
                    .and_then(|word| word.split('%').next())
                    .and_then(|word| word.parse().ok())
                {
                    resolvers.push(address);
                }
            }
            Some("search" | "domain") => {
                domains.extend(words.filter(|word| *word != ".").map(str::to_owned));
            }
            _ => {}
        }
    }
    (unique(resolvers), unique(domains))
}

/// Whether the address was leased by DHCP (and may change unless reserved).
#[allow(unused_variables, clippy::unnecessary_wraps)]
fn address_dynamic(interface: &str, address: IpAddr) -> Option<bool> {
    #[cfg(target_os = "linux")]
    {
        let text = command_output("ip", &["-o", "addr", "show", "dev", interface])?;
        let needle = format!("inet {address}/");
        let line = text.lines().find(|line| line.contains(&needle))?;
        Some(line.split_whitespace().any(|word| word == "dynamic"))
    }
    #[cfg(target_os = "macos")]
    {
        Some(
            command_output("ipconfig", &["getoption", interface, "server_identifier"])
                .is_some_and(|server| !server.trim().is_empty()),
        )
    }
    #[cfg(windows)]
    {
        Some(
            windows_facts()
                .dhcp
                .iter()
                .any(|dhcp| dhcp.parse::<IpAddr>().is_ok_and(|ip| ip == address)),
        )
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
    {
        None
    }
}

#[allow(clippy::unnecessary_wraps)]
fn detect_firewall() -> Option<&'static str> {
    #[cfg(target_os = "linux")]
    {
        if fs::read_to_string("/etc/ufw/ufw.conf")
            .is_ok_and(|text| text.lines().any(|line| line.trim() == "ENABLED=yes"))
        {
            return Some("ufw");
        }
        if fs::metadata("/run/firewalld").is_ok() {
            return Some("firewalld");
        }
        None
    }
    #[cfg(target_os = "macos")]
    {
        command_output(
            "/usr/libexec/ApplicationFirewall/socketfilterfw",
            &["--getglobalstate"],
        )
        .filter(|state| state.contains("enabled"))
        .map(|_| "macos-application-firewall")
    }
    #[cfg(windows)]
    {
        Some("windows-defender-firewall")
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
    {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vpn_and_virtual_interfaces_are_recognized() {
        for name in [
            "tun0",
            "wg0",
            "tailscale0",
            "utun3",
            "ProtonVPN",
            "nordlynx",
        ] {
            assert!(is_vpn_interface(name), "{name}");
        }
        for name in [
            "docker0",
            "br-1a2b",
            "veth12",
            "vEthernet (WSL)",
            "virbr0",
            "lo",
        ] {
            assert!(is_virtual_interface(name), "{name}");
        }
        for name in ["eth0", "enp3s0", "wlan0", "en0", "Wi-Fi"] {
            assert!(
                !is_vpn_interface(name) && !is_virtual_interface(name),
                "{name}"
            );
        }
    }

    #[test]
    fn wildcard_sockets_conflict_with_specific_addresses() {
        let wildcard: SocketAddr = "0.0.0.0:53".parse().unwrap();
        let lan: SocketAddr = "192.168.1.10:53".parse().unwrap();
        let stub: SocketAddr = "127.0.0.53:53".parse().unwrap();
        assert!(overlaps(wildcard, lan));
        assert!(!overlaps(stub, lan));
        assert!(overlaps(lan, lan));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn proc_addresses_decode_in_host_order() {
        assert_eq!(
            parse_proc_address("3500007F:0035"),
            Some("127.0.0.53:53".parse().unwrap())
        );
        assert_eq!(
            parse_proc_address("00000000000000000000000001000000:0035"),
            Some("[::1]:53".parse().unwrap())
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn occupied_ports_report_the_owning_process() {
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let address = socket.local_addr().unwrap();
        let probe = probe_port(address);
        let PortState::InUse { owners } = probe.udp else {
            panic!("expected the port to be in use: {probe:?}");
        };
        assert!(
            owners.iter().any(|owner| owner
                .process
                .as_deref()
                .is_some_and(|name| name.contains("pid"))),
            "{owners:?}"
        );
    }
}
