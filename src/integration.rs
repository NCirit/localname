use std::{
    fs,
    net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket},
};

use serde::Serialize;

#[derive(Debug, Serialize)]
pub struct NetworkFacts {
    pub lan_address: Option<IpAddr>,
    pub default_gateway: Option<IpAddr>,
    pub current_resolvers: Vec<IpAddr>,
    pub port_53_available: bool,
    pub platform: &'static str,
}

pub fn inspect_network() -> NetworkFacts {
    let lan_address = detect_lan_address();
    let default_gateway = detect_default_gateway();
    let current_resolvers = resolvers_from_resolv_conf();
    let port_53_available = lan_address
        .and_then(|ip| UdpSocket::bind(SocketAddr::new(ip, 53)).ok())
        .is_some();
    NetworkFacts {
        lan_address,
        default_gateway,
        current_resolvers,
        port_53_available,
        platform: std::env::consts::OS,
    }
}

fn detect_lan_address() -> Option<IpAddr> {
    let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).ok()?;
    socket.connect((Ipv4Addr::new(1, 1, 1, 1), 53)).ok()?;
    Some(socket.local_addr().ok()?.ip())
}

fn detect_default_gateway() -> Option<IpAddr> {
    #[cfg(target_os = "linux")]
    {
        let output = std::process::Command::new("ip")
            .args(["route", "show", "default"])
            .output()
            .ok()?;
        let text = String::from_utf8(output.stdout).ok()?;
        let mut words = text.split_whitespace();
        while let Some(word) = words.next() {
            if word == "via" {
                return words.next()?.parse().ok();
            }
        }
    }
    None
}

fn resolvers_from_resolv_conf() -> Vec<IpAddr> {
    let Ok(text) = fs::read_to_string("/etc/resolv.conf") else {
        return Vec::new();
    };
    text.lines()
        .filter_map(|line| {
            let mut words = line.split_whitespace();
            (words.next()? == "nameserver")
                .then(|| words.next()?.parse().ok())
                .flatten()
        })
        .collect()
}
