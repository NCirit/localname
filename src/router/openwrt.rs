//! OpenWrt (decision 23): the LAN DHCP section's option 6 hands out localname as DNS
//! server, and odhcpd announces localname's IPv6 address, or stops announcing the router,
//! for IPv6 DNS. Changes go through UCI, so they persist across reboots.

use std::{
    collections::BTreeMap,
    net::{Ipv4Addr, Ipv6Addr},
};

use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};

use super::{Connection, shell_quote};
use crate::error::{ErrorCode, coded};

/// The UCI values localname manages in the LAN DHCP section. `None` means unset.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DhcpSettings {
    pub section: String,
    pub dhcp_option: Option<Vec<String>>,
    pub dns: Option<Vec<String>>,
    pub dns_service: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct Detected {
    pub release: String,
    pub model: String,
    pub odhcpd: bool,
    /// SHA-256 of `uci show dhcp`, computed on the router; apply refuses if it changed.
    pub fingerprint: String,
    pub uncommitted_changes: bool,
    pub settings: DhcpSettings,
    /// `dhcp-option=` lines dnsmasq is running with.
    pub runtime: Vec<String>,
}

/// What localname should hand out.
#[derive(Clone, Copy, Debug, Serialize)]
pub struct Desired {
    pub dns: Ipv4Addr,
    pub dns6: Option<Ipv6Addr>,
    /// Leave the router's IPv6 DNS announcements alone when localname has no IPv6.
    pub keep_ipv6_dns: bool,
}

const DETECT: &str = r#"if [ ! -f /etc/openwrt_release ]; then echo 'localname-error=not-openwrt'; exit 0; fi
command -v uci >/dev/null 2>&1 || { echo 'localname-error=no-uci'; exit 0; }
. /etc/openwrt_release
echo "release=$DISTRIB_RELEASE"
echo "model=$(cat /tmp/sysinfo/model 2>/dev/null)"
if [ -x /etc/init.d/odhcpd ]; then echo odhcpd=1; else echo odhcpd=0; fi
echo "uncommitted=$(uci changes dhcp | wc -l)"
echo "fingerprint=$(uci -q show dhcp | sha256sum | cut -d' ' -f1)"
grep -h '^dhcp-option=' /var/etc/dnsmasq.conf.* 2>/dev/null | sed 's/^/runtime=/'
echo '--- uci'
uci -q show dhcp
"#;

pub fn detect(connection: &Connection) -> Result<Detected> {
    parse_detect(&connection.run(DETECT)?)
}

pub fn parse_detect(output: &str) -> Result<Detected> {
    let (head, uci) = output.split_once("--- uci\n").unwrap_or((output, ""));
    let mut facts = BTreeMap::new();
    let mut runtime = Vec::new();
    for line in head.lines() {
        if let Some((key, value)) = line.split_once('=') {
            if key == "runtime" {
                runtime.push(value.to_owned());
            } else {
                facts.insert(key, value);
            }
        }
    }
    if let Some(error) = facts.get("localname-error") {
        return Err(coded(
            ErrorCode::Unavailable,
            match *error {
                "not-openwrt" => {
                    "unsupported router: /etc/openwrt_release is missing; this adapter supports OpenWrt only"
                }
                _ => "unsupported router: uci is not available",
            },
        ));
    }
    let values = parse_uci(uci);
    let section = values
        .iter()
        .find_map(|(key, value)| {
            let (section, option) = key.strip_prefix("dhcp.")?.split_once('.')?;
            (option == "interface" && value.first().is_some_and(|value| value == "lan"))
                .then(|| section.to_owned())
        })
        .ok_or_else(|| {
            coded(
                ErrorCode::Unavailable,
                "unsupported router configuration: no DHCP section serves the lan interface",
            )
        })?;
    let get = |option: &str| values.get(&format!("dhcp.{section}.{option}")).cloned();
    Ok(Detected {
        release: facts.get("release").copied().unwrap_or_default().to_owned(),
        model: facts.get("model").copied().unwrap_or_default().to_owned(),
        odhcpd: facts.get("odhcpd") == Some(&"1"),
        fingerprint: facts
            .get("fingerprint")
            .copied()
            .unwrap_or_default()
            .to_owned(),
        uncommitted_changes: facts
            .get("uncommitted")
            .is_some_and(|count| count.trim() != "0"),
        settings: DhcpSettings {
            dhcp_option: get("dhcp_option"),
            dns: get("dns"),
            dns_service: get("dns_service").and_then(|values| values.into_iter().next()),
            section,
        },
        runtime,
    })
}

/// Parse `uci show` output: `key='value'` or, for lists, `key='a' 'b'`. UCI escapes a
/// single quote inside a value as `'\''`.
pub fn parse_uci(text: &str) -> BTreeMap<String, Vec<String>> {
    let mut values = BTreeMap::new();
    for line in text.lines() {
        let Some((key, raw)) = line.split_once('=') else {
            continue;
        };
        let mut items = Vec::new();
        let mut current = String::new();
        let mut quoted = false;
        let mut chars = raw.chars().peekable();
        let mut any = false;
        while let Some(character) = chars.next() {
            match character {
                '\'' if quoted => quoted = false,
                '\'' => {
                    quoted = true;
                    any = true;
                }
                '\\' if !quoted && chars.peek() == Some(&'\'') => {
                    chars.next();
                    current.push('\'');
                }
                ' ' if !quoted => {
                    if any {
                        items.push(std::mem::take(&mut current));
                        any = false;
                    }
                }
                other => {
                    current.push(other);
                    any = true;
                }
            }
        }
        if any {
            items.push(current);
        }
        values.insert(key.to_owned(), items);
    }
    values
}

/// The settings that make the LAN DHCP server hand out localname, keeping every
/// unrelated DHCP option.
pub fn desired_settings(current: &DhcpSettings, desired: &Desired, odhcpd: bool) -> DhcpSettings {
    let mut options: Vec<String> = current
        .dhcp_option
        .clone()
        .unwrap_or_default()
        .into_iter()
        .filter(|option| !is_dns_option(option))
        .collect();
    options.push(format!("6,{}", desired.dns));
    let (dns, dns_service) = match (desired.dns6, odhcpd && !desired.keep_ipv6_dns) {
        (Some(dns6), _) => (Some(vec![dns6.to_string()]), current.dns_service.clone()),
        // Without an IPv6 address for localname, stop announcing the router as IPv6 DNS
        // server, or IPv6-preferring devices would bypass localname.
        (None, true) => (None, Some("0".into())),
        (None, false) => (current.dns.clone(), current.dns_service.clone()),
    };
    DhcpSettings {
        section: current.section.clone(),
        dhcp_option: Some(options),
        dns,
        dns_service,
    }
}

fn is_dns_option(option: &str) -> bool {
    let code = option.split(',').next().unwrap_or_default().trim();
    code == "6" || code == "option:dns-server"
}

/// Human-readable UCI commands that turn `from` into `to`.
pub fn changes(from: &DhcpSettings, to: &DhcpSettings) -> Vec<String> {
    commands(from, to)
        .into_iter()
        .map(|command| command.trim_end_matches(" || true").to_owned())
        .collect()
}

fn commands(from: &DhcpSettings, to: &DhcpSettings) -> Vec<String> {
    let section = &to.section;
    let mut commands = Vec::new();
    for (option, before, after) in [
        ("dhcp_option", &from.dhcp_option, &to.dhcp_option),
        ("dns", &from.dns, &to.dns),
    ] {
        if before == after {
            continue;
        }
        commands.push(format!("uci -q delete dhcp.{section}.{option} || true"));
        for value in after.iter().flatten() {
            commands.push(format!(
                "uci add_list dhcp.{section}.{option}={}",
                shell_quote(value)
            ));
        }
    }
    if from.dns_service != to.dns_service {
        match &to.dns_service {
            Some(value) => commands.push(format!(
                "uci set dhcp.{section}.dns_service={}",
                shell_quote(value)
            )),
            None => commands.push(format!("uci -q delete dhcp.{section}.dns_service || true")),
        }
    }
    commands
}

/// Apply `to`, refusing unless the router's DHCP configuration still has `fingerprint`
/// and no uncommitted UCI changes. The check and the change run in one shell.
pub fn apply(
    connection: &Connection,
    fingerprint: &str,
    from: &DhcpSettings,
    to: &DhcpSettings,
) -> Result<()> {
    if !fingerprint
        .chars()
        .all(|character| character.is_ascii_hexdigit())
    {
        bail!("invalid state fingerprint");
    }
    let script = format!(
        "set -e
fp=$(uci -q show dhcp | sha256sum | cut -d' ' -f1)
if [ \"$fp\" != '{fingerprint}' ]; then echo \"localname-conflict=changed $fp\"; exit 0; fi
if [ -n \"$(uci changes dhcp)\" ]; then echo 'localname-conflict=uncommitted'; exit 0; fi
{}
uci commit dhcp
/etc/init.d/dnsmasq reload >/dev/null 2>&1 || /etc/init.d/dnsmasq restart >/dev/null 2>&1
if [ -x /etc/init.d/odhcpd ]; then /etc/init.d/odhcpd reload >/dev/null 2>&1 || /etc/init.d/odhcpd restart >/dev/null 2>&1; fi
echo localname-applied
",
        commands(from, to).join("\n")
    );
    let output = connection.run(&script)?;
    if let Some(conflict) = output
        .lines()
        .find_map(|line| line.strip_prefix("localname-conflict="))
    {
        return Err(coded(
            ErrorCode::Conflict,
            if conflict == "uncommitted" {
                "conflict: the router has uncommitted UCI changes to dhcp; commit or revert them first".to_owned()
            } else {
                "stale state conflict: the router's DHCP configuration changed since it was inspected; run the plan again".to_owned()
            },
        ));
    }
    if !output.lines().any(|line| line == "localname-applied") {
        bail!("router did not confirm the change: {}", output.trim());
    }
    Ok(())
}

/// Whether dnsmasq's running configuration hands out `dns` as DNS server.
pub fn runtime_serves(detected: &Detected, dns: Option<Ipv4Addr>) -> bool {
    let options: Vec<&str> = detected
        .runtime
        .iter()
        .filter_map(|line| line.strip_prefix("dhcp-option="))
        .filter(|line| {
            let mut fields = line.split(',');
            let _tag = fields.next();
            matches!(fields.next(), Some("6" | "option:dns-server"))
        })
        .collect();
    match dns {
        Some(dns) => options.iter().any(|line| {
            line.split(',')
                .skip(2)
                .any(|value| value == dns.to_string())
        }),
        None => options.is_empty(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "release=24.10.3\nmodel=QEMU Standard PC\nodhcpd=1\nuncommitted=0\nfingerprint=abc123\nruntime=dhcp-option=lan,6,10.0.0.9\n--- uci\ndhcp.@dnsmasq[0]=dnsmasq\ndhcp.lan=dhcp\ndhcp.lan.interface='lan'\ndhcp.lan.dhcp_option='42,10.0.0.1' '6,10.0.0.9'\ndhcp.lan.ra_flags='managed-config' 'other-config'\ndhcp.wan.interface='wan'\n";

    #[test]
    fn detection_finds_the_lan_section_and_lists() {
        let detected = parse_detect(SAMPLE).unwrap();
        assert_eq!(detected.release, "24.10.3");
        assert!(detected.odhcpd);
        assert!(!detected.uncommitted_changes);
        assert_eq!(detected.settings.section, "lan");
        assert_eq!(
            detected.settings.dhcp_option,
            Some(vec!["42,10.0.0.1".into(), "6,10.0.0.9".into()])
        );
        assert_eq!(detected.settings.dns, None);
        assert!(runtime_serves(&detected, Some("10.0.0.9".parse().unwrap())));
        assert!(!runtime_serves(
            &detected,
            Some("10.0.0.8".parse().unwrap())
        ));
    }

    #[test]
    fn non_openwrt_hosts_are_unsupported() {
        let error = parse_detect("localname-error=not-openwrt\n").unwrap_err();
        assert!(format!("{error}").contains("OpenWrt only"));
    }

    #[test]
    fn uci_values_with_quotes_and_spaces_parse() {
        let values = parse_uci("a.b.c='it'\\''s' 'two words'\na.b.d='x'\n");
        assert_eq!(values["a.b.c"], ["it's", "two words"]);
        assert_eq!(values["a.b.d"], ["x"]);
    }

    #[test]
    fn desired_settings_replace_only_the_dns_option() {
        let current = DhcpSettings {
            section: "lan".into(),
            dhcp_option: Some(vec!["42,10.0.0.1".into(), "6,8.8.8.8".into()]),
            dns: Some(vec!["fd00::1".into()]),
            dns_service: None,
        };
        let desired = Desired {
            dns: "10.0.0.20".parse().unwrap(),
            dns6: None,
            keep_ipv6_dns: false,
        };
        let next = desired_settings(&current, &desired, true);
        assert_eq!(
            next.dhcp_option,
            Some(vec!["42,10.0.0.1".into(), "6,10.0.0.20".into()])
        );
        assert_eq!(next.dns, None);
        assert_eq!(next.dns_service.as_deref(), Some("0"));
        let changes = changes(&current, &next);
        assert!(changes.contains(&"uci add_list dhcp.lan.dhcp_option='6,10.0.0.20'".to_owned()));
        assert!(changes.contains(&"uci set dhcp.lan.dns_service='0'".to_owned()));
        // Applying the result again changes nothing.
        assert!(commands(&next, &desired_settings(&next, &desired, true)).is_empty());
        // Restoring the captured state is the reverse change.
        let back = commands(&next, &current);
        assert!(back.contains(&"uci add_list dhcp.lan.dhcp_option='6,8.8.8.8'".to_owned()));
        assert!(back.contains(&"uci add_list dhcp.lan.dns='fd00::1'".to_owned()));
        assert!(back.contains(&"uci -q delete dhcp.lan.dns_service || true".to_owned()));
    }
}
