//! End-to-end verification of whole-home setup. Run on a second device, it finds
//! localname through that device's own DNS settings, which proves the router change took
//! effect, then checks UDP, TCP, and the operating system's resolver.

use std::{
    net::{IpAddr, SocketAddr},
    time::Duration,
};

use anyhow::Result;
use clap::Args;
use hickory_proto::rr::RecordType;
use serde::Serialize;
use serde_json::json;

use super::{ReportedError, print_result, setup::HOST_RECORD};
use crate::{
    ConfigStore, Transport,
    control::{self, Request},
    error::ErrorCode,
    integration::inspect_network,
    output::{Envelope, OutputFormat},
    query_with,
};

#[derive(Debug, Args)]
pub struct VerifyArgs {
    /// localname's address. Defaults to this host's configured listener, or on another
    /// device to whichever of its DNS servers serves the zone.
    #[arg(long)]
    server: Option<IpAddr>,
    #[arg(long, default_value_t = 53)]
    port: u16,
    /// Zone to check. Defaults to the local configuration's zone, then home.arpa.
    #[arg(long)]
    zone: Option<String>,
    /// Name to resolve, relative to the zone.
    #[arg(long, default_value = HOST_RECORD)]
    name: String,
    #[arg(long, default_value_t = 2_000)]
    timeout_ms: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum Status {
    Pass,
    Warn,
    Fail,
    Skipped,
}

#[derive(Debug, Serialize)]
struct Check {
    id: &'static str,
    status: Status,
    detail: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    remedy: Option<String>,
}

#[derive(Debug, Serialize)]
struct VerifyData {
    scope: &'static str,
    server: Option<SocketAddr>,
    discovered_by: &'static str,
    zone: String,
    name: String,
    addresses: Vec<IpAddr>,
    resolvers: Vec<IpAddr>,
    checks: Vec<Check>,
    passed: bool,
}

const UNREACHABLE: &str = "Check that this device is on the same network (not a guest network), that client/AP isolation is off, and that the localname host's firewall allows UDP and TCP 53.";

#[allow(clippy::too_many_lines)]
pub async fn verify(output: OutputFormat, store: &ConfigStore, args: &VerifyArgs) -> Result<()> {
    let timeout = Duration::from_millis(args.timeout_ms);
    let facts = inspect_network();
    let config = store.exists().then(|| store.load()).transpose()?;
    let zone = crate::config::canonical_zone(
        args.zone
            .as_deref()
            .or(config.as_ref().map(|config| config.zone.as_str()))
            .unwrap_or("home.arpa"),
    )?;
    let name = crate::config::canonical_name(&args.name, &zone)?;
    // Human-readable forms, without the root label's trailing dot.
    let zone_text = zone.trim_end_matches('.').to_owned();
    let name_text = name.trim_end_matches('.').to_owned();
    let mut checks = Vec::new();

    // Find the server: explicit, this host's listener, or the device's own resolvers.
    let (server, discovered_by) = if let Some(server) = args.server {
        (Some(SocketAddr::new(server, args.port)), "argument")
    } else if let Some(config) = &config {
        let listener = config
            .listen
            .iter()
            .find(|address| !address.ip().is_loopback())
            .or_else(|| config.listen.first())
            .copied();
        (listener, "configuration")
    } else {
        let mut found = None;
        for resolver in &facts.current_resolvers {
            let address = SocketAddr::new(*resolver, args.port);
            if serves_zone(address, &zone, timeout).await {
                found = Some(address);
                break;
            }
        }
        (found, "system_resolver")
    };
    let scope = match server {
        Some(server)
            if server.ip().is_loopback() || facts.host_addresses.contains(&server.ip()) =>
        {
            "this_host"
        }
        _ => "second_client",
    };
    let Some(server) = server else {
        checks.push(Check {
            id: "discovery",
            status: Status::Fail,
            detail: format!(
                "None of this device's DNS servers ({}) serve {zone_text}.",
                list(&facts.current_resolvers)
            ),
            remedy: Some("Make the router change from `localname setup` (LAN/DHCP DNS server = the localname host), then reconnect this device or renew its DHCP lease. If the device uses Private DNS, a VPN, or a manually set DNS server, switch that off for this network. You can also pass --server.".into()),
        });
        return finish(
            output,
            VerifyData {
                scope,
                server: None,
                discovered_by,
                zone,
                name,
                addresses: Vec::new(),
                resolvers: facts.current_resolvers,
                checks,
                passed: false,
            },
        );
    };
    if discovered_by == "system_resolver" {
        checks.push(Check {
            id: "discovery",
            status: Status::Pass,
            detail: format!("This device's DNS settings point at localname ({server})."),
            remedy: None,
        });
    }

    let mut addresses = Vec::new();
    for (id, transport) in [("udp", Transport::Udp), ("tcp", Transport::Tcp)] {
        let check = match transport_check(server, &zone, &name, timeout, transport).await {
            Ok(found) => {
                let detail = if found.is_empty() {
                    format!(
                        "{server} answers for {zone_text} over {}; {name_text} has no address.",
                        id.to_uppercase()
                    )
                } else {
                    format!("{name_text} → {} over {}.", list(&found), id.to_uppercase())
                };
                if addresses.is_empty() {
                    addresses = found;
                }
                Check {
                    id,
                    status: Status::Pass,
                    detail,
                    remedy: None,
                }
            }
            Err(error) => Check {
                id,
                status: Status::Fail,
                detail: format!("{} query to {server} failed: {error:#}", id.to_uppercase()),
                remedy: Some(UNREACHABLE.into()),
            },
        };
        checks.push(check);
    }

    // The operating system's resolver: what applications actually use.
    let system = system_lookup(&name, timeout).await;
    checks.push(match (&system, addresses.is_empty()) {
        (Ok(found), false) if found.iter().any(|address| addresses.contains(address)) => Check {
            id: "system_resolver",
            status: Status::Pass,
            detail: format!(
                "The system resolver returns {} for {name_text}.",
                list(found)
            ),
            remedy: None,
        },
        (_, true) => Check {
            id: "system_resolver",
            status: Status::Skipped,
            detail: format!("{name_text} has no address to compare."),
            remedy: None,
        },
        (Ok(found), false) => Check {
            id: "system_resolver",
            status: if scope == "this_host" {
                Status::Warn
            } else {
                Status::Fail
            },
            detail: format!(
                "The system resolver returns {} instead of {}.",
                list(found),
                list(&addresses)
            ),
            remedy: Some(bypass_remedy(scope)),
        },
        (Err(error), false) => Check {
            id: "system_resolver",
            status: if scope == "this_host" {
                Status::Warn
            } else {
                Status::Fail
            },
            detail: format!("The system resolver cannot resolve {name_text}: {error:#}"),
            remedy: Some(bypass_remedy(scope)),
        },
    });

    // Other resolvers this device may use instead (secondary DNS, IPv6 RDNSS).
    if scope == "second_client" {
        let mut bypass = Vec::new();
        for resolver in facts
            .current_resolvers
            .iter()
            .filter(|resolver| **resolver != server.ip())
        {
            if !serves_zone(SocketAddr::new(*resolver, 53), &zone, timeout).await {
                bypass.push(*resolver);
            }
        }
        checks.push(if bypass.is_empty() {
            Check {
                id: "bypass",
                status: Status::Pass,
                detail: "Every DNS server this device uses serves local names.".into(),
                remedy: None,
            }
        } else {
            let ipv6 = bypass.iter().any(IpAddr::is_ipv6);
            Check {
                id: "bypass",
                status: Status::Warn,
                detail: format!(
                    "This device also uses {}, which does not serve {zone_text}; some lookups may miss local names.",
                    list(&bypass)
                ),
                remedy: Some(if ipv6 {
                    "In the router, set the IPv6 DNS server (RDNSS/DHCPv6) to localname's IPv6 address or stop announcing the router as IPv6 DNS server.".into()
                } else {
                    "In the router's DHCP settings, remove the secondary DNS server or set it to localname's address.".into()
                }),
            }
        });
    }

    // On the server host, the daemon reports forwarding loops it has detected.
    if config.is_some()
        && let Ok(Some(response)) = control::send_if_running(store, &Request::Status)
        && let Some(status) = response.status
    {
        checks.push(if status.metrics.loops == 0 {
            Check {
                id: "forwarding_loop",
                status: Status::Pass,
                detail: "No forwarding loops detected.".into(),
                remedy: None,
            }
        } else {
            Check {
                id: "forwarding_loop",
                status: Status::Warn,
                detail: format!("The daemon detected {} forwarding loop(s).", status.metrics.loops),
                remedy: Some("An upstream forwards queries back to localname. Set the router's Internet (WAN) DNS to automatic instead of the localname host.".into()),
            }
        });
    }

    let passed = checks.iter().all(|check| check.status != Status::Fail);
    finish(
        output,
        VerifyData {
            scope,
            server: Some(server),
            discovered_by,
            zone,
            name,
            addresses,
            resolvers: facts.current_resolvers,
            checks,
            passed,
        },
    )
}

fn bypass_remedy(scope: &str) -> String {
    if scope == "this_host" {
        "This host does not use localname as its own resolver; that is fine for the server. Run `localname setup verify` on a second device.".into()
    } else {
        "Renew this device's DHCP lease or reconnect it. Turn off Private DNS / Secure DNS, VPN DNS, or a manually configured DNS server for this network.".into()
    }
}

/// Whether `server` answers authoritatively for `zone` with localname's SOA.
async fn serves_zone(server: SocketAddr, zone: &str, timeout: Duration) -> bool {
    query_with(server, zone, RecordType::SOA, timeout, Transport::Udp)
        .await
        .is_ok_and(|result| {
            result.authoritative
                && result.response_code == "NoError"
                && result.records.iter().any(|record| {
                    record.record_type == "SOA" && record.value.starts_with(&format!("ns1.{zone}"))
                })
        })
}

/// Query the zone SOA, then `name`, over one transport. Returns the name's addresses.
async fn transport_check(
    server: SocketAddr,
    zone: &str,
    name: &str,
    timeout: Duration,
    transport: Transport,
) -> Result<Vec<IpAddr>> {
    let soa = query_with(server, zone, RecordType::SOA, timeout, transport).await?;
    anyhow::ensure!(
        soa.authoritative && soa.response_code == "NoError",
        "{server} is not authoritative for {zone} (response {})",
        soa.response_code
    );
    let mut addresses = Vec::new();
    for record_type in [RecordType::A, RecordType::AAAA] {
        let result = query_with(server, name, record_type, timeout, transport).await?;
        addresses.extend(
            result
                .records
                .iter()
                .filter_map(|record| record.value.parse::<IpAddr>().ok()),
        );
    }
    Ok(addresses)
}

async fn system_lookup(name: &str, timeout: Duration) -> Result<Vec<IpAddr>> {
    let host = name.trim_end_matches('.').to_owned();
    let addresses = tokio::time::timeout(timeout * 2, tokio::net::lookup_host((host, 0)))
        .await
        .map_err(|_| anyhow::anyhow!("lookup timed out"))??;
    let mut found: Vec<IpAddr> = addresses.map(|address| address.ip()).collect();
    found.dedup();
    Ok(found)
}

fn list(addresses: &[IpAddr]) -> String {
    if addresses.is_empty() {
        return "none".into();
    }
    addresses
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(", ")
}

fn finish(output: OutputFormat, data: VerifyData) -> Result<()> {
    let human = data
        .checks
        .iter()
        .map(|check| {
            let mark = match check.status {
                Status::Pass => "✓",
                Status::Warn => "!",
                Status::Fail => "✗",
                Status::Skipped => "·",
            };
            match (&check.remedy, check.status) {
                (Some(remedy), Status::Warn | Status::Fail) => {
                    format!("{mark} {}\n    {remedy}", check.detail)
                }
                _ => format!("{mark} {}", check.detail),
            }
        })
        .collect::<Vec<_>>()
        .join("\n");
    let verification = json!({
        "status": if data.passed { "passed" } else { "failed" },
        "scope": data.scope,
    });
    if !data.passed {
        let failed: Vec<&Check> = data
            .checks
            .iter()
            .filter(|check| check.status == Status::Fail)
            .collect();
        let message = format!(
            "verification failed: {}",
            failed
                .iter()
                .map(|check| check.detail.as_str())
                .collect::<Vec<_>>()
                .join("; ")
        );
        let next_actions = failed
            .iter()
            .filter_map(|check| check.remedy.clone())
            .collect();
        return Err(ReportedError {
            command: "setup verify",
            code: ErrorCode::VerificationFailed,
            data: serde_json::to_value(&data)?,
            verification: Some(verification),
            next_actions,
            message,
            human,
        }
        .into());
    }
    let scope = data.scope;
    let mut envelope = Envelope::success("setup verify", false, None, data);
    envelope.verification = Some(verification);
    if scope == "this_host" {
        envelope.next_actions.push(
            "Run `localname setup verify` on a second device to confirm whole-home resolution."
                .into(),
        );
    }
    print_result(output, envelope, || human)
}
