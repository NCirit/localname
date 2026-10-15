//! Special-use names (RFC 6761, RFC 6303, RFC 8375) that must never reach public resolvers.

use std::net::{Ipv4Addr, Ipv6Addr};

/// How a name outside the configured zone must be handled before ordinary forwarding.
#[derive(Debug, PartialEq, Eq)]
pub enum Special {
    /// `localhost.` and its subdomains: loopback answers generated locally.
    Localhost,
    /// `invalid.`: always nonexistent.
    Invalid,
    /// A zone that only has meaning inside this network. Queries may go to on-link
    /// resolvers (such as the router) but are answered locally when only public
    /// upstreams exist. The value is the zone apex.
    LocallyServed(String),
    /// Firefox's canary domain: NXDOMAIN tells it not to enable DNS over HTTPS by
    /// default, which would bypass this resolver and its local names.
    DohCanary,
}

pub const DOH_CANARY: &str = "use-application-dns.net.";

/// Classify a lowercase, fully qualified name.
pub fn classify(name: &str) -> Option<Special> {
    if name == "localhost." || name.ends_with(".localhost.") {
        return Some(Special::Localhost);
    }
    if name == "invalid." || name.ends_with(".invalid.") {
        return Some(Special::Invalid);
    }
    if name == DOH_CANARY {
        return Some(Special::DohCanary);
    }
    for apex in ["home.arpa.", "local."] {
        if name == apex || name.ends_with(&format!(".{apex}")) {
            return Some(Special::LocallyServed(apex.into()));
        }
    }
    if let Some(prefix) = strip_zone(name, "in-addr.arpa.") {
        return ipv4_reverse_apex(prefix).map(Special::LocallyServed);
    }
    if let Some(prefix) = strip_zone(name, "ip6.arpa.") {
        return ipv6_reverse_apex(prefix).map(Special::LocallyServed);
    }
    None
}

fn strip_zone<'a>(name: &'a str, zone: &str) -> Option<&'a str> {
    if name == zone {
        return Some("");
    }
    name.strip_suffix(zone)?.strip_suffix('.')
}

/// Reverse zones for private, loopback, link-local, and unspecified IPv4 space (RFC 6303 §4.2-4.3).
fn ipv4_reverse_apex(prefix: &str) -> Option<String> {
    // Labels are in reverse order: "4.3.2.1" for 1.2.3.4.
    let octets: Vec<u8> = prefix
        .split('.')
        .filter(|label| !label.is_empty())
        .rev()
        .map(str::parse)
        .collect::<Result<_, _>>()
        .ok()?;
    let apex = |count: usize| {
        let labels: Vec<String> = octets[..count].iter().rev().map(u8::to_string).collect();
        Some(format!("{}.in-addr.arpa.", labels.join(".")))
    };
    match octets.as_slice() {
        [0 | 10 | 127, ..] => apex(1),
        [169, 254, ..] | [192, 168, ..] => apex(2),
        [172, second, ..] if (16..=31).contains(second) => apex(2),
        [255, 255, 255, 255] => apex(4),
        _ => None,
    }
}

/// Reverse zones for ULA, link-local, loopback, and unspecified IPv6 space (RFC 6303 §4.4-4.6).
fn ipv6_reverse_apex(prefix: &str) -> Option<String> {
    let nibbles: Vec<u8> = prefix
        .split('.')
        .filter(|label| !label.is_empty())
        .rev()
        .map(|label| {
            u8::from_str_radix(label, 16)
                .ok()
                .filter(|_| label.len() == 1)
        })
        .collect::<Option<_>>()?;
    let apex = |count: usize| {
        let labels: Vec<String> = nibbles[..count]
            .iter()
            .rev()
            .map(|nibble| format!("{nibble:x}"))
            .collect();
        Some(format!("{}.ip6.arpa.", labels.join(".")))
    };
    match nibbles.as_slice() {
        [0xf, 0xc | 0xd, ..] => apex(2),
        [0xf, 0xe, 0x8..=0xb, ..] => apex(3),
        all if all.len() == 32 => {
            let mut octets = [0_u8; 16];
            for (index, pair) in all.chunks(2).enumerate() {
                octets[index] = (pair[0] << 4) | pair[1];
            }
            let address = Ipv6Addr::from(octets);
            (address.is_loopback() || address.is_unspecified()).then(|| apex(32))?
        }
        _ => None,
    }
}

pub const LOCALHOST_V4: Ipv4Addr = Ipv4Addr::LOCALHOST;
pub const LOCALHOST_V6: Ipv6Addr = Ipv6Addr::LOCALHOST;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_private_reverse_space() {
        for (name, apex) in [
            ("20.1.168.192.in-addr.arpa.", "168.192.in-addr.arpa."),
            ("1.0.0.10.in-addr.arpa.", "10.in-addr.arpa."),
            ("5.5.20.172.in-addr.arpa.", "20.172.in-addr.arpa."),
            ("1.1.254.169.in-addr.arpa.", "254.169.in-addr.arpa."),
            ("168.192.in-addr.arpa.", "168.192.in-addr.arpa."),
            (
                "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.d.f.ip6.arpa.",
                "d.f.ip6.arpa.",
            ),
            (
                "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.e.f.ip6.arpa.",
                "8.e.f.ip6.arpa.",
            ),
        ] {
            assert_eq!(
                classify(name),
                Some(Special::LocallyServed(apex.into())),
                "{name}"
            );
        }
    }

    #[test]
    fn public_reverse_and_ordinary_names_are_forwarded() {
        for name in [
            "8.8.8.8.in-addr.arpa.",
            "1.32.172.in-addr.arpa.",
            "in-addr.arpa.",
            "example.com.",
            "evilhome.arpa.",
            "8.b.d.0.1.0.0.2.ip6.arpa.",
            "x.in-addr.arpa.",
        ] {
            assert_eq!(classify(name), None, "{name}");
        }
    }

    #[test]
    fn classifies_fixed_names() {
        assert_eq!(classify("localhost."), Some(Special::Localhost));
        assert_eq!(classify("app.localhost."), Some(Special::Localhost));
        assert_eq!(classify("x.invalid."), Some(Special::Invalid));
        assert_eq!(
            classify("use-application-dns.net."),
            Some(Special::DohCanary)
        );
        assert_eq!(classify("x.use-application-dns.net."), None);
        assert_eq!(
            classify("printer.local."),
            Some(Special::LocallyServed("local.".into()))
        );
        assert_eq!(
            classify("nas.home.arpa."),
            Some(Special::LocallyServed("home.arpa.".into()))
        );
        let loopback = format!("1.{}ip6.arpa.", "0.".repeat(31));
        assert_eq!(
            classify(&loopback),
            Some(Special::LocallyServed(loopback.clone()))
        );
    }
}
