//! Guided whole-home setup: detect, plan, apply, and roll back (decision 8). Router
//! changes stay manual here; the plan reduces them to one page of exact settings.

use std::{
    fmt::Write as _,
    fs,
    net::{IpAddr, Ipv6Addr, SocketAddr},
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result};
use clap::{Args, Subcommand};
use serde::{Deserialize, Serialize};
use serde_json::json;

use super::{ReportedError, print_result, private_client_networks, verify};
use crate::{
    Config, ConfigStore, RecordConfig,
    control::{self, Request},
    error::{ErrorCode, coded},
    integration::{NetworkFacts, PortProbe, PortState, inspect_network, probe_port},
    output::{Envelope, OutputFormat},
};

/// Name that setup gives this host, used by `setup verify` on other devices.
pub const HOST_RECORD: &str = "localname";

#[derive(Debug, Args)]
#[command(args_conflicts_with_subcommands = true)]
pub struct SetupArgs {
    #[command(subcommand)]
    action: Option<SetupAction>,
    #[command(flatten)]
    plan: PlanArgs,
}

#[derive(Debug, Subcommand)]
enum SetupAction {
    /// Check resolution end to end. On a second device this finds localname through the
    /// network's DNS and checks UDP, TCP, and the operating system's resolver.
    Verify(verify::VerifyArgs),
    /// Undo the last `setup --apply`, restoring the configuration that existed before it.
    Rollback(RollbackArgs),
}

#[derive(Debug, Args)]
#[allow(clippy::struct_excessive_bools)]
struct PlanArgs {
    /// Namespace for short device names (`lan`, `home.arpa`, or a domain you own).
    #[arg(long, default_value = crate::config::DEFAULT_ZONE)]
    zone: String,
    /// Only inspect; exit unsuccessfully if a blocking problem is found.
    #[arg(long, conflicts_with = "apply")]
    check: bool,
    /// Write the proposed localname configuration. Router changes remain manual.
    #[arg(long)]
    apply: bool,
    /// Prepare an unprivileged loopback instance for development.
    #[arg(long)]
    local: bool,
    /// Listen on these private addresses instead of the detected LAN address (repeatable).
    #[arg(long, conflicts_with = "local")]
    listen: Vec<SocketAddr>,
    /// LAN address clients should use when the listener is behind a published port.
    #[arg(long, conflicts_with = "local")]
    advertise: Option<IpAddr>,
    /// Forward other names to these resolvers instead of the detected ones (repeatable).
    #[arg(long)]
    upstream: Vec<SocketAddr>,
    /// Do not listen on the host's unique-local IPv6 address.
    #[arg(long)]
    no_ipv6: bool,
    /// When updating an existing configuration, refuse unless it is at this revision.
    #[arg(long)]
    expect_revision: Option<u64>,
}

#[derive(Debug, Args)]
struct RollbackArgs {
    /// Show what would be restored without changing anything.
    #[arg(long)]
    dry_run: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum Status {
    Pass,
    Info,
    Warn,
    Fail,
}

#[derive(Debug, Serialize)]
struct Check {
    id: &'static str,
    status: Status,
    summary: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    remedy: Option<String>,
}

impl Check {
    fn new(id: &'static str, status: Status, summary: impl Into<String>) -> Self {
        Self {
            id,
            status,
            summary: summary.into(),
            remedy: None,
        }
    }

    fn remedy(mut self, remedy: impl Into<String>) -> Self {
        self.remedy = Some(remedy.into());
        self
    }
}

/// The single manual router change, written as the exact settings on one page.
#[derive(Debug, Serialize)]
struct RouterAction {
    summary: String,
    dns_server: IpAddr,
    ipv6_dns_server: Option<Ipv6Addr>,
    steps: Vec<String>,
    restore: String,
}

#[derive(Debug, Serialize)]
struct SetupPlan {
    plan_id: String,
    facts: NetworkFacts,
    config_path: String,
    existing_revision: Option<u64>,
    listen: Vec<SocketAddr>,
    upstreams: Vec<SocketAddr>,
    rebind_allowed_domains: Vec<String>,
    router_dns_value: Option<IpAddr>,
    host_record: Option<String>,
    ports: Vec<PortProbe>,
    checks: Vec<Check>,
    router_action: Option<RouterAction>,
    verification: Vec<String>,
    actions: Vec<String>,
    warnings: Vec<String>,
    applied: bool,
    rollback: Option<String>,
}

/// Captured prior state of an applied setup, kept beside the configuration so rollback
/// can restore exactly what existed before.
#[derive(Debug, Serialize, Deserialize)]
struct SetupRecord {
    version: u32,
    plan_id: String,
    applied_at: u64,
    created_configuration: bool,
    previous_revision: Option<u64>,
    revision: u64,
    router_dns_value: Option<IpAddr>,
    previous_resolvers: Vec<IpAddr>,
}

fn record_path(store: &ConfigStore) -> PathBuf {
    store.path().with_extension("setup.json")
}

pub async fn setup(output: OutputFormat, store: &ConfigStore, args: &SetupArgs) -> Result<()> {
    match &args.action {
        Some(SetupAction::Verify(verify_args)) => verify::verify(output, store, verify_args).await,
        Some(SetupAction::Rollback(rollback_args)) => rollback(output, store, rollback_args),
        None => plan_or_apply(output, store, &args.plan),
    }
}

#[allow(clippy::too_many_lines)]
fn plan_or_apply(output: OutputFormat, store: &ConfigStore, args: &PlanArgs) -> Result<()> {
    let facts = inspect_network();
    if let Some(address) = args.advertise
        && (!crate::config::is_private_address(address) || address.is_loopback())
    {
        return Err(coded(
            ErrorCode::InvalidInput,
            "invalid advertised address: select a private LAN address",
        ));
    }
    let existing = if store.exists() {
        Some(store.load()?)
    } else {
        None
    };
    let daemon = existing
        .as_ref()
        .and_then(|_| {
            control::send_if_running(store, &Request::Status)
                .ok()
                .flatten()
        })
        .and_then(|response| response.status);

    let listen = choose_listeners(args, &facts);
    let advertise = if args.local {
        None
    } else {
        args.advertise
            .or_else(|| listen.iter().map(SocketAddr::ip).find(IpAddr::is_ipv4))
            .or_else(|| listen.first().map(SocketAddr::ip))
    };
    let ipv6_advertise = listen.iter().find_map(|address| match address.ip() {
        IpAddr::V6(ip) if ip.is_unique_local() => Some(ip),
        _ => None,
    });
    let mut checks = Vec::new();
    let (upstreams, skipped) = if args.upstream.is_empty() {
        choose_upstreams(&facts, &listen, advertise, existing.as_ref())
    } else {
        (args.upstream.clone(), Vec::new())
    };
    let rebind_allowed_domains = allowed_search_domains(&facts, &args.zone);

    // Ports: a socket held by this configuration's running daemon is expected.
    let served_by_daemon = |address: &SocketAddr| {
        daemon.is_some()
            && existing
                .as_ref()
                .is_some_and(|config| config.listen.contains(address))
    };
    let ports: Vec<PortProbe> = listen
        .iter()
        .filter(|address| !served_by_daemon(address))
        .map(|address| probe_port(*address))
        .collect();
    // A loopback address means "this device" to every client: a router cannot hand it out.
    let this_host_only = !args.local && advertise.is_some_and(|ip| ip.is_loopback());
    if args.local {
        checks.push(Check::new(
            "lan_address",
            Status::Info,
            "Loopback development instance; other devices cannot use it.",
        ));
    } else if this_host_only {
        let lan = facts
            .lan_address
            .map_or_else(|| "its LAN address".to_owned(), |ip| format!("{ip}:53"));
        checks.push(
            Check::new(
                "lan_address",
                Status::Info,
                format!(
                    "{} is a loopback address: only this device can use localname, and no router change applies.",
                    advertise.map_or_else(String::new, |ip| ip.to_string())
                ),
            )
            .remedy(format!(
                "Point this device at it with `localname client setup --server 127.0.0.1 --apply`. For other devices, listen on the LAN instead (`--listen {lan}`)."
            )),
        );
    } else if listen.is_empty() {
        checks.push(
            Check::new("lan_address", Status::Fail, "No private LAN address was detected.")
                .remedy("Connect this host to the home network (Ethernet or Wi-Fi), or pass --listen with its private address."),
        );
    } else {
        checks.push(Check::new(
            "lan_address",
            Status::Pass,
            format!(
                "Devices will reach localname at {}{}.",
                advertise.map_or_else(String::new, |ip| ip.to_string()),
                facts
                    .lan_interface
                    .as_ref()
                    .map_or_else(String::new, |name| format!(" (interface {name})"))
            ),
        ));
    }
    for address in listen.iter().filter(|address| served_by_daemon(address)) {
        checks.push(Check::new(
            "port",
            Status::Pass,
            format!("{address} is served by this configuration's running localname daemon."),
        ));
    }
    for probe in &ports {
        checks.extend(port_checks(probe));
    }
    if !args.local {
        checks.push(address_check(&facts, advertise));
        checks.extend(environment_check(&facts, advertise));
        checks.push(ipv6_check(&facts, ipv6_advertise, args.no_ipv6));
        checks.push(loop_check(&facts, &upstreams, &skipped));
        checks.extend(vpn_check(&facts));
        checks.push(isolation_check(&facts, advertise));
        checks.push(rebinding_check(&rebind_allowed_domains));
        checks.push(private_dns_check());
    }
    if let Some(config) = &existing {
        let changed = config.listen != listen && !args.local;
        checks.push(Check::new(
            "existing_configuration",
            Status::Info,
            format!(
                "Configuration revision {} exists; applying updates listeners and upstreams as a new revision{}.",
                config.revision,
                if changed { " (restart the service afterwards)" } else { "" }
            ),
        ));
    }

    let router_action = advertise
        .filter(|_| !args.local && !this_host_only)
        .map(|address| router_action(&facts, address, ipv6_advertise, &upstreams));
    let zone = crate::config::canonical_zone(&args.zone)?;
    let host_record = advertise.map(|_| format!("{HOST_RECORD}.{zone}"));
    let verification = verification_steps(advertise, host_record.as_deref(), &args.zone);
    let mut actions = Vec::new();
    if let Some(first) = listen.first() {
        actions.push(format!("Start localname on {first}."));
    }
    if let Some(action) = &router_action {
        actions.push(action.summary.clone());
        actions.extend(verification.iter().take(1).cloned());
    }
    let warnings: Vec<String> = checks
        .iter()
        .filter(|check| matches!(check.status, Status::Warn | Status::Fail))
        .map(|check| check.summary.clone())
        .collect();
    let plan_id = format!(
        "setup-{}-{}",
        unix_time(),
        advertise.map_or_else(
            || "local".into(),
            |ip| ip.to_string().replace([':', '.'], "-")
        )
    );
    let mut plan = SetupPlan {
        plan_id,
        config_path: store.path().display().to_string(),
        existing_revision: existing.as_ref().map(|config| config.revision),
        listen: listen.clone(),
        upstreams: upstreams.clone(),
        rebind_allowed_domains: rebind_allowed_domains.clone(),
        router_dns_value: advertise,
        host_record,
        ports,
        checks,
        router_action,
        verification,
        actions,
        warnings,
        applied: false,
        rollback: None,
        facts,
    };

    let blocking: Vec<&Check> = plan
        .checks
        .iter()
        .filter(|check| check.status == Status::Fail)
        .collect();
    if (args.apply || args.check) && !blocking.is_empty() {
        let code = if blocking.iter().any(|check| check.id.starts_with("port")) {
            ErrorCode::Conflict
        } else {
            ErrorCode::InvalidInput
        };
        let message = format!(
            "setup blocked: {}",
            blocking
                .iter()
                .map(|check| check.summary.as_str())
                .collect::<Vec<_>>()
                .join("; ")
        );
        let next_actions = blocking
            .iter()
            .filter_map(|check| check.remedy.clone())
            .collect();
        return Err(ReportedError {
            command: "setup",
            code,
            human: render_human(&plan, args),
            data: serde_json::to_value(&plan)?,
            verification: None,
            next_actions,
            rollback: None,
            message,
        }
        .into());
    }

    let mut revision = existing.as_ref().map(|config| config.revision);
    if args.apply {
        let mut candidate = Config {
            listen: listen.clone(),
            zone: args.zone.clone(),
            upstreams: upstreams.clone(),
            allowed_clients: if args.local {
                Config::default().allowed_clients
            } else {
                private_client_networks()
            },
            rebind_allowed_domains: rebind_allowed_domains.clone(),
            ..Config::default()
        };
        if let Some(address) = advertise {
            candidate.records = host_records(address, ipv6_advertise);
        }
        candidate.validate()?;
        let record = if let Some(config) = &existing {
            super::check_revision(args.expect_revision, config.revision)?;
            if daemon.is_some() {
                return Err(coded(
                    ErrorCode::Conflict,
                    "stale state conflict: stop the running localname service before applying setup to an existing configuration",
                ));
            }
            let _guard = store.acquire_offline_lock()?;
            let (previous, next) = store.mutate(args.expect_revision, |config| {
                if config.zone != candidate.zone {
                    return Err(coded(
                        ErrorCode::InvalidInput,
                        format!(
                            "invalid zone change: the configuration serves {}; setup does not move existing records to another zone",
                            config.zone
                        ),
                    ));
                }
                config.listen.clone_from(&candidate.listen);
                config.upstreams.clone_from(&candidate.upstreams);
                config.allowed_clients.clone_from(&candidate.allowed_clients);
                for domain in &candidate.rebind_allowed_domains {
                    if !config.rebind_allowed_domains.contains(domain) {
                        config.rebind_allowed_domains.push(domain.clone());
                    }
                }
                let host = format!("{HOST_RECORD}.{}", config.zone);
                if !candidate.records.is_empty() {
                    config.records.retain(|record| record.name != host);
                    config.records.extend(candidate.records.iter().cloned());
                }
                Ok(())
            })?;
            revision = Some(next.revision);
            SetupRecord {
                version: 1,
                plan_id: plan.plan_id.clone(),
                applied_at: unix_time(),
                created_configuration: false,
                previous_revision: Some(previous.revision),
                revision: next.revision,
                router_dns_value: advertise,
                previous_resolvers: plan.facts.current_resolvers.clone(),
            }
        } else {
            store.initialize(&candidate)?;
            revision = Some(0);
            SetupRecord {
                version: 1,
                plan_id: plan.plan_id.clone(),
                applied_at: unix_time(),
                created_configuration: true,
                previous_revision: None,
                revision: 0,
                router_dns_value: advertise,
                previous_resolvers: plan.facts.current_resolvers.clone(),
            }
        };
        write_record(store, &record)?;
        plan.applied = true;
        plan.rollback = Some(setup_rollback_command(store));
    }

    let human = render_human(&plan, args);
    let mut envelope = Envelope::success("setup", plan.applied, revision, plan);
    envelope.warnings.clone_from(&envelope.data.warnings);
    envelope.next_actions.clone_from(&envelope.data.actions);
    envelope.rollback.clone_from(&envelope.data.rollback);
    print_result(output, envelope, move || human)
}

/// Loopback address for a development instance: port 5354, or the next free port up to
/// 5399 when another program (such as an mDNS helper) already holds it.
fn local_listener() -> SocketAddr {
    (5354..=5399)
        .map(|port| SocketAddr::from(([127, 0, 0, 1], port)))
        .find(|address| {
            let probe = probe_port(*address);
            probe.udp == PortState::Available && probe.tcp == PortState::Available
        })
        .unwrap_or_else(|| SocketAddr::from(([127, 0, 0, 1], 5354)))
}

fn choose_listeners(args: &PlanArgs, facts: &NetworkFacts) -> Vec<SocketAddr> {
    if args.local {
        return vec![local_listener()];
    }
    if !args.listen.is_empty() {
        return args.listen.clone();
    }
    let mut listen: Vec<SocketAddr> = facts
        .lan_address
        .map(|address| SocketAddr::new(address, 53))
        .into_iter()
        .collect();
    if !args.no_ipv6
        && let Some(ula) = facts.lan_ipv6.first()
    {
        listen.push(SocketAddr::new(IpAddr::V6(*ula), 53));
    }
    listen
}

/// Upstreams from the host's current resolvers, minus anything that would loop back to
/// this host or only works while a VPN is connected. Returns the skipped resolvers too.
fn choose_upstreams(
    facts: &NetworkFacts,
    listen: &[SocketAddr],
    advertise: Option<IpAddr>,
    existing: Option<&Config>,
) -> (Vec<SocketAddr>, Vec<(IpAddr, &'static str)>) {
    let tailscale: ipnet::IpNet = "100.64.0.0/10".parse().expect("constant CIDR");
    let mut skipped = Vec::new();
    let mut upstreams = Vec::new();
    for address in &facts.current_resolvers {
        let reason = if address.is_loopback() || facts.host_addresses.contains(address) {
            Some("this host")
        } else if Some(*address) == advertise || listen.iter().any(|l| l.ip() == *address) {
            Some("localname itself")
        } else if matches!(address, IpAddr::V6(ip) if ip.is_unicast_link_local()) {
            Some("link-local address")
        } else if tailscale.contains(address) {
            Some("VPN resolver")
        } else {
            None
        };
        if let Some(reason) = reason {
            skipped.push((*address, reason));
        } else {
            let upstream = SocketAddr::new(*address, 53);
            if !upstreams.contains(&upstream) {
                upstreams.push(upstream);
            }
        }
    }
    if upstreams.is_empty() {
        upstreams = existing.map_or_else(
            || Config::default().upstreams,
            |config| config.upstreams.clone(),
        );
    }
    (upstreams, skipped)
}

/// Search domains served by the router (such as `lan` or `fritz.box`) may answer with
/// private addresses; they are exempt from rebinding protection.
fn allowed_search_domains(facts: &NetworkFacts, zone: &str) -> Vec<String> {
    let zone = crate::config::canonical_zone(zone).unwrap_or_default();
    let mut domains = Vec::new();
    for domain in &facts.search_domains {
        let Ok(domain) = crate::config::canonical_zone(domain) else {
            continue;
        };
        if domain == zone
            || crate::config::name_in_zone(&domain, &zone)
            || crate::config::name_in_zone(&domain, "home.arpa.")
            || crate::config::name_in_zone(&domain, "local.")
            || domains.contains(&domain)
        {
            continue;
        }
        domains.push(domain);
    }
    domains
}

fn host_records(address: IpAddr, ipv6: Option<Ipv6Addr>) -> Vec<RecordConfig> {
    std::iter::once(address)
        .chain(ipv6.map(IpAddr::V6).filter(|ip| *ip != address))
        .map(|address| RecordConfig {
            name: HOST_RECORD.into(),
            value: address.to_string(),
            ttl: 60,
        })
        .collect()
}

fn port_checks(probe: &PortProbe) -> Vec<Check> {
    let address = probe.address;
    let mut checks = Vec::new();
    for (transport, state) in [("UDP", &probe.udp), ("TCP", &probe.tcp)] {
        let check = match state {
            PortState::Available => Check::new(
                "port",
                Status::Pass,
                format!("{transport} {address} is free."),
            ),
            PortState::PermissionRequired => Check::new(
                "port_permission",
                Status::Warn,
                format!("{transport} {address} needs permission to bind a port below 1024."),
            )
            .remedy("Run localname as the packaged service (it keeps only CAP_NET_BIND_SERVICE), start it as root with `localname serve --user localname`, or grant the binary `cap_net_bind_service`."),
            PortState::InUse { owners } => {
                let owner = owners
                    .iter()
                    .find_map(|owner| owner.process.clone())
                    .unwrap_or_else(|| "another program".into());
                Check::new(
                    "port_conflict",
                    Status::Fail,
                    format!("{transport} {address} is already used by {owner}."),
                )
                .remedy(port_remedy(&owner, address))
            }
            PortState::AddressUnavailable => Check::new(
                "port_address",
                Status::Fail,
                format!("{address} is not assigned to this host."),
            )
            .remedy("Choose one of this host's private addresses with --listen."),
            PortState::Error { message } => Check::new(
                "port_error",
                Status::Fail,
                format!("{transport} {address} could not be tested: {message}"),
            ),
        };
        checks.push(check);
    }
    checks
}

fn port_remedy(owner: &str, address: SocketAddr) -> String {
    let name = owner.split_whitespace().next().unwrap_or(owner);
    match name {
        "systemd-resolve" | "systemd-resolved" => "systemd-resolved listens on this address. Set `DNSStubListener=no` (or remove the matching `DNSStubListenerExtra=`) in /etc/systemd/resolved.conf, then `sudo systemctl restart systemd-resolved`.".into(),
        "dnsmasq" => "dnsmasq already serves DNS here. Stop it (`sudo systemctl disable --now dnsmasq`) or, if NetworkManager starts it, set `dns=default` in NetworkManager.conf; alternatively make dnsmasq bind only to other interfaces (`bind-interfaces`).".into(),
        "named" | "unbound" | "pihole-FTL" | "AdGuardHome" | "coredns" | "pdns_server" => format!(
            "{name} already provides DNS on {address}. Stop it, move it to another address, or run localname with --listen on a different private address."
        ),
        "docker-proxy" | "com.docker.backend" | "rootlessport" => "A container publishes port 53 on this address. Stop that container or publish it on another address.".into(),
        "localname" => "Another localname instance (for a different configuration) already serves this address. Stop it or select its configuration with --config.".into(),
        _ => format!(
            "Stop {owner} or choose a different private address with --listen; DNS clients require port 53."
        ),
    }
}

fn address_check(facts: &NetworkFacts, advertise: Option<IpAddr>) -> Check {
    let Some(address) = advertise else {
        return Check::new("address_stable", Status::Info, "No LAN address to reserve.");
    };
    match facts.address_dynamic {
        Some(true) if facts.lan_address == Some(address) => Check::new(
            "address_stable",
            Status::Warn,
            format!("{address} was assigned by DHCP and could change."),
        )
        .remedy(format!(
            "Reserve {address} for this device in the router's DHCP settings (part of the router step below)."
        )),
        Some(false) => Check::new(
            "address_stable",
            Status::Pass,
            format!("{address} is statically configured."),
        ),
        _ => Check::new(
            "address_stable",
            Status::Info,
            format!("Could not tell whether {address} is reserved; reserve it in the router to be safe."),
        ),
    }
}

/// Hyper-V firewall creator ID of WSL virtual machines.
const WSL_VM_CREATOR: &str = "{40E0AC32-46A5-438A-A0B2-2B479E8F2E90}";

fn environment_check(facts: &NetworkFacts, advertise: Option<IpAddr>) -> Option<Check> {
    let address = advertise.map_or_else(|| "this address".into(), |ip| ip.to_string());
    match facts.environment {
        // WSL's NAT mode places the VM in 172.16.0.0/12; mirrored mode shares the host's
        // LAN address but still filters inbound traffic in the Hyper-V firewall.
        Some("wsl2") if advertise.is_some_and(|ip| matches!(ip, IpAddr::V4(v4) if v4.octets()[0] == 172 && (16..32).contains(&v4.octets()[1]))) => Some(
            Check::new(
                "environment",
                Status::Warn,
                format!("Running inside WSL 2 with NAT networking: other devices cannot reach {address}."),
            )
            .remedy("Enable mirrored networking (`networkingMode=mirrored` under [wsl2] in %UserProfile%\\.wslconfig, then `wsl --shutdown`) and run setup again, or run localname on Windows or another always-on device."),
        ),
        Some("wsl2") => Some(
            Check::new(
                "environment",
                Status::Warn,
                "Running inside WSL 2 with mirrored networking: the Hyper-V firewall blocks inbound DNS by default.",
            )
            .remedy(format!("In an administrator PowerShell on Windows, allow UDP and TCP 53 for WSL: `New-NetFirewallHyperVRule -Name localname-dns-udp -DisplayName 'localname DNS (UDP)' -Direction Inbound -VMCreatorId '{WSL_VM_CREATOR}' -Protocol UDP -LocalPorts 53; New-NetFirewallHyperVRule -Name localname-dns-tcp -DisplayName 'localname DNS (TCP)' -Direction Inbound -VMCreatorId '{WSL_VM_CREATOR}' -Protocol TCP -LocalPorts 53`. Also reserve {address} in the router, because WSL cannot see whether Windows leased it by DHCP.")),
        ),
        Some("container") if advertise.is_some_and(|ip| facts.lan_address == Some(ip)) => Some(
            Check::new(
                "environment",
                Status::Warn,
                format!("Running in a container: {address} is the container's address, not the host's."),
            )
            .remedy("Publish UDP and TCP 53 on the host's LAN address and pass --listen with the container address and --advertise with the host's LAN address (the bundled compose.yml does this)."),
        ),
        _ => None,
    }
}

/// An IPv6 resolver (often the router's link-local address) shows that the router
/// announces IPv6 DNS even when this host has no routable IPv6 address.
fn network_uses_ipv6(facts: &NetworkFacts) -> bool {
    facts.global_ipv6
        || !facts.lan_ipv6.is_empty()
        || facts.current_resolvers.iter().any(IpAddr::is_ipv6)
}

fn ipv6_check(facts: &NetworkFacts, ipv6: Option<Ipv6Addr>, disabled: bool) -> Check {
    match (ipv6, network_uses_ipv6(facts)) {
        (Some(address), _) => Check::new(
            "ipv6_dns",
            Status::Pass,
            format!("localname also listens on {address} so IPv6 DNS can point at it."),
        ),
        (None, true) => Check::new(
            "ipv6_dns",
            Status::Warn,
            if disabled {
                "IPv6 listening is disabled, but this network uses IPv6; devices may prefer the router's IPv6 DNS server.".to_owned()
            } else {
                "This network uses IPv6 but this host has no unique-local (fd00::/8) address for an IPv6 DNS server.".to_owned()
            },
        )
        .remedy("In the router's IPv6/RA settings, stop announcing the router as IPv6 DNS server (RDNSS / DHCPv6 DNS), or enable a ULA prefix and run setup again so localname can be announced instead."),
        (None, false) => Check::new("ipv6_dns", Status::Pass, "No IPv6 on this network; IPv4 DNS covers every device."),
    }
}

fn loop_check(
    facts: &NetworkFacts,
    upstreams: &[SocketAddr],
    skipped: &[(IpAddr, &'static str)],
) -> Check {
    let list = upstreams
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(", ");
    let mut summary = format!("Other names are forwarded to {list}.");
    if !skipped.is_empty() {
        let _ = write!(
            summary,
            " Skipped {} to avoid loops.",
            skipped
                .iter()
                .map(|(address, reason)| format!("{address} ({reason})"))
                .collect::<Vec<_>>()
                .join(", ")
        );
    }
    let check = Check::new("forwarding_loop", Status::Pass, summary);
    match facts.default_gateway {
        Some(gateway) if upstreams.iter().any(|upstream| upstream.ip() == gateway) => check.remedy(
            format!(
                "Keep the router's own Internet (WAN) DNS automatic: localname forwards to {gateway}, so pointing the router's upstream at localname would loop. localname detects such loops and answers SERVFAIL."
            ),
        ),
        _ => check,
    }
}

fn vpn_check(facts: &NetworkFacts) -> Option<Check> {
    (!facts.vpn_interfaces.is_empty()).then(|| {
        Check::new(
            "vpn",
            Status::Warn,
            format!(
                "VPN interfaces are active on this host ({}).",
                facts.vpn_interfaces.join(", ")
            ),
        )
        .remedy("Allow LAN access in the VPN client (disable 'block local network' or the kill switch for the LAN), or LAN devices cannot reach this host. VPN-only resolvers are not used as upstreams.")
    })
}

fn isolation_check(facts: &NetworkFacts, advertise: Option<IpAddr>) -> Check {
    let network = facts
        .lan_network
        .map_or_else(|| "your LAN subnet".into(), |network| network.to_string());
    let firewall = match facts.firewall {
        Some("ufw") => Some(format!(
            "sudo ufw allow from {network} to any port 53 proto udp && sudo ufw allow from {network} to any port 53 proto tcp"
        )),
        Some("firewalld") => Some("sudo firewall-cmd --permanent --add-service=dns && sudo firewall-cmd --reload".into()),
        Some("windows-defender-firewall") => Some(
            "New-NetFirewallRule -DisplayName 'localname DNS (UDP)' -Direction Inbound -Protocol UDP -LocalPort 53 -RemoteAddress LocalSubnet -Action Allow; New-NetFirewallRule -DisplayName 'localname DNS (TCP)' -Direction Inbound -Protocol TCP -LocalPort 53 -RemoteAddress LocalSubnet -Action Allow".into(),
        ),
        Some("macos-application-firewall") => Some(
            "sudo /usr/libexec/ApplicationFirewall/socketfilterfw --add \"$(command -v localname)\" && sudo /usr/libexec/ApplicationFirewall/socketfilterfw --unblockapp \"$(command -v localname)\"".into(),
        ),
        _ => None,
    };
    let address = advertise.map_or_else(|| "this host".into(), |ip| ip.to_string());
    let base = format!(
        "If a second device cannot reach {address}: make sure it is not on a guest network and that client/AP isolation is off."
    );
    match firewall {
        Some(command) => Check::new(
            "isolation",
            Status::Warn,
            format!(
                "A host firewall ({}) is active and may block DNS from the LAN.",
                facts.firewall.unwrap_or_default()
            ),
        )
        .remedy(format!("Allow DNS from {network}: `{command}`. {base}")),
        None => {
            Check::new("isolation", Status::Info, "No host firewall was detected.").remedy(base)
        }
    }
}

fn rebinding_check(allowed: &[String]) -> Check {
    let exempt = if allowed.is_empty() {
        String::new()
    } else {
        format!(
            " Router domains allowed to return private addresses: {}.",
            allowed.join(", ")
        )
    };
    Check::new(
        "rebinding",
        Status::Pass,
        format!("localname removes private addresses from public answers (DNS rebinding protection).{exempt}"),
    )
    .remedy("Devices should use localname directly (the router step below). If you instead make the router forward to localname, allow your zone in the router's rebind protection: OpenWrt 'Network › DHCP and DNS › Domain whitelist' (rebind_domain), dnsmasq `rebind-domain-ok=/home.arpa/`, FRITZ!Box 'Home Network › Network › Network Settings › DNS Rebind Protection'.")
}

fn private_dns_check() -> Check {
    Check::new(
        "private_dns",
        Status::Info,
        "Devices using their own encrypted DNS ignore the router's DNS setting and cannot see local names.",
    )
    .remedy("Android: Settings › Network & internet › Private DNS › Automatic or Off. Chrome/Edge: Settings › Privacy › Use secure DNS › With your current service provider. iOS/macOS: turn off DNS profiles or VPN apps' DNS, and iCloud Private Relay for this network. Firefox stays on network DNS because localname answers its DoH canary domain.")
}

fn router_action(
    facts: &NetworkFacts,
    address: IpAddr,
    ipv6: Option<Ipv6Addr>,
    upstreams: &[SocketAddr],
) -> RouterAction {
    let gateway = facts.default_gateway;
    let mut steps = vec![match gateway {
        Some(gateway) => {
            format!("Open the router's admin page (usually http://{gateway}) and sign in.")
        }
        None => "Open the router's admin page and sign in.".into(),
    }];
    steps.push(
        "Go to the LAN or DHCP server settings (also called Network, LAN setup, or DHCP).".into(),
    );
    if facts.address_dynamic == Some(true) && facts.lan_address == Some(address) {
        steps.push(format!(
            "Reserve {address} for this device (DHCP reservation or static lease) so its address never changes."
        ));
    }
    steps.push(format!(
        "Set the DNS server that DHCP gives devices to {address}. Leave the secondary DNS server empty or set it to the same address: devices use any listed server and would miss local names."
    ));
    if let Some(ipv6) = ipv6 {
        steps.push(format!(
            "If there is an IPv6 DNS server setting (RDNSS or DHCPv6), set it to {ipv6}."
        ));
    } else if network_uses_ipv6(facts) {
        steps.push("If the router announces an IPv6 DNS server (RDNSS or DHCPv6), turn that off so devices do not bypass localname over IPv6.".into());
    }
    if let Some(gateway) = gateway.filter(|gateway| upstreams.iter().any(|u| u.ip() == *gateway)) {
        steps.push(format!(
            "Do not enter {address} as the router's own Internet (WAN) DNS server: localname forwards to {gateway}, so that would create a loop."
        ));
    }
    steps.push("Save, then reconnect one device to the network (or renew its DHCP lease) and run the verification.".into());
    let previous = if facts.current_resolvers.is_empty() {
        "automatic".into()
    } else {
        facts
            .current_resolvers
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(", ")
    };
    RouterAction {
        summary: format!("Set the router's LAN/DHCP DNS server to {address}."),
        dns_server: address,
        ipv6_dns_server: ipv6,
        steps,
        restore: format!(
            "Set the router's LAN/DHCP DNS server back to automatic (devices previously used {previous}) and save."
        ),
    }
}

fn verification_steps(advertise: Option<IpAddr>, host: Option<&str>, zone: &str) -> Vec<String> {
    let (Some(address), Some(host)) = (advertise, host) else {
        return vec![
            "Run `localname setup verify` on this host after starting the service.".into(),
        ];
    };
    let name = host.trim_end_matches('.');
    let zone_argument = if crate::config::canonical_zone(zone)
        .is_ok_and(|zone| zone.trim_end_matches('.') == crate::config::DEFAULT_ZONE)
    {
        String::new()
    } else {
        format!(" --zone {zone}")
    };
    vec![
        format!(
            "On a second device run `localname setup verify{zone_argument}`: it finds localname through the network's DNS and checks UDP, TCP, and the system resolver."
        ),
        format!(
            "Without localname on that device: `nslookup {name}` must answer {address} (system resolver), and `nslookup -vc {name} {address}` checks TCP."
        ),
    ]
}

fn render_human(plan: &SetupPlan, args: &PlanArgs) -> String {
    let mut lines = Vec::new();
    for check in &plan.checks {
        let mark = match check.status {
            Status::Pass => "✓",
            Status::Info => "·",
            Status::Warn => "!",
            Status::Fail => "✗",
        };
        lines.push(format!("{mark} {}", check.summary));
        if matches!(check.status, Status::Warn | Status::Fail)
            && let Some(remedy) = &check.remedy
        {
            lines.push(format!("    {remedy}"));
        }
    }
    if plan.applied && args.local {
        lines.push(String::new());
        lines.push(format!(
            "Loopback configuration created at {}. Start `localname serve`.",
            plan.listen
                .first()
                .map_or_else(String::new, ToString::to_string)
        ));
        return lines.join("\n");
    }
    if let Some(action) = &plan.router_action {
        lines.push(String::new());
        lines.push(format!("Router (one change): {}", action.summary));
        for (index, step) in action.steps.iter().enumerate() {
            lines.push(format!("  {}. {step}", index + 1));
        }
    }
    if !plan.verification.is_empty() {
        lines.push(String::new());
        lines.push("Verify:".into());
        lines.extend(plan.verification.iter().map(|step| format!("  {step}")));
    }
    lines.push(String::new());
    if plan.applied {
        lines.push(format!(
            "Configuration written to {}. Start `localname serve` (or the installed service), then make the router change. Undo with `{}`.",
            plan.config_path,
            plan.rollback.as_deref().unwrap_or("localname setup rollback")
        ));
    } else if args.check {
        lines.push("Setup check complete.".into());
    } else {
        lines.push("Run again with --apply to write this configuration.".into());
    }
    lines.join("\n")
}

fn rollback(output: OutputFormat, store: &ConfigStore, args: &RollbackArgs) -> Result<()> {
    let path = record_path(store);
    let text = fs::read_to_string(&path).map_err(|_| {
        coded(
            ErrorCode::InvalidInput,
            format!(
                "invalid request: no applied setup is recorded for {}",
                store.path().display()
            ),
        )
    })?;
    let record: SetupRecord = serde_json::from_str(&text)
        .with_context(|| format!("failed to parse {}", path.display()))?;
    let current = store.load()?;
    if current.revision != record.revision {
        return Err(coded(
            ErrorCode::Conflict,
            format!(
                "stale revision conflict: the configuration changed after setup (revision {} is now {}); review `localname revisions` and use `localname rollback` instead",
                record.revision, current.revision
            ),
        ));
    }
    let restore = format!(
        "Set the router's LAN/DHCP DNS server back to automatic (devices previously used {}).",
        if record.previous_resolvers.is_empty() {
            "the router's default".into()
        } else {
            record
                .previous_resolvers
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(", ")
        }
    );
    let mut data = json!({
        "plan_id": record.plan_id,
        "config_path": store.path(),
        "removes_configuration": record.created_configuration,
        "restores_revision": record.previous_revision,
        "router_restore": restore,
    });
    if args.dry_run {
        data["preview"] = json!(true);
        let summary = if record.created_configuration {
            format!(
                "Would remove the configuration created by setup at {}.",
                store.path().display()
            )
        } else {
            format!(
                "Would restore revision {} as a new revision.",
                record.previous_revision.unwrap_or_default()
            )
        };
        let mut envelope = Envelope::success("setup rollback", true, Some(current.revision), data);
        envelope.next_actions = vec![restore];
        return print_result(output, envelope, || summary);
    }
    if control::send_if_running(store, &Request::Status)?.is_some() {
        return Err(coded(
            ErrorCode::Conflict,
            "stale state conflict: stop the running localname service before rolling back setup",
        ));
    }
    let guard = store.acquire_offline_lock()?;
    let revision = if record.created_configuration {
        // Nothing changed since setup created it (checked above), so nothing is lost.
        fs::remove_file(store.path())?;
        let revisions = store.path().with_file_name(format!(
            "{}.revisions",
            store
                .path()
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("config.toml")
        ));
        if revisions.exists() {
            fs::remove_dir_all(&revisions)?;
        }
        None
    } else {
        let previous = record.previous_revision.unwrap_or_default();
        let (_, next) = store.rollback_expected(previous, Some(record.revision))?;
        Some(next.revision)
    };
    drop(guard);
    fs::remove_file(&path)?;
    let human = if record.created_configuration {
        format!("Removed the configuration created by setup.\n{restore}")
    } else {
        format!(
            "Restored revision {} as revision {}.\n{restore}",
            record.previous_revision.unwrap_or_default(),
            revision.unwrap_or_default()
        )
    };
    let mut envelope = Envelope::success("setup rollback", true, revision, data);
    envelope.next_actions = vec![restore];
    print_result(output, envelope, || human)
}

fn write_record(store: &ConfigStore, record: &SetupRecord) -> Result<()> {
    let path = record_path(store);
    let directory = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or(std::path::Path::new("."));
    let mut temporary = tempfile::Builder::new()
        .prefix(".localname-")
        .suffix(".tmp")
        .tempfile_in(directory)?;
    serde_json::to_writer_pretty(&mut temporary, record)?;
    temporary.as_file().sync_all()?;
    temporary.persist(&path).map_err(|error| error.error)?;
    Ok(())
}

fn setup_rollback_command(store: &ConfigStore) -> String {
    let command = super::rollback_command(store.path(), 0);
    command
        .strip_suffix(" rollback 0")
        .map_or(command.clone(), |prefix| format!("{prefix} setup rollback"))
}

fn unix_time() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
