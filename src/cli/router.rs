//! `localname router`: the OpenWrt adapter's detect, plan, apply, status, and rollback.

use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    path::PathBuf,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result};
use clap::{Args, Subcommand};
use serde_json::json;

use super::{ReportedError, print_result, setup::HOST_RECORD};
use crate::{
    ConfigStore,
    error::{ErrorCode, coded},
    output::{Envelope, OutputFormat},
    router::{
        self, Connection, RouterRecord,
        openwrt::{self, Desired, Detected, DhcpSettings},
    },
};

#[derive(Debug, Subcommand)]
pub enum RouterCommand {
    /// Inspect the router without changing it.
    Detect(ConnectArgs),
    /// Show the exact router changes that hand out localname as DNS server.
    Plan(PlanArgs),
    /// Make the planned change; requires the state fingerprint from `router plan`.
    Apply(ApplyArgs),
    /// Check that the router still hands out localname.
    Status(ConnectArgs),
    /// Restore the router settings captured before the first apply.
    Rollback(RollbackArgs),
}

#[derive(Debug, Args)]
pub struct ConnectArgs {
    /// Router address or SSH host alias.
    #[arg(long)]
    host: String,
    #[arg(long, default_value = "root")]
    user: String,
    #[arg(long, default_value_t = 22)]
    port: u16,
    /// SSH private key; by default ssh uses your agent and ~/.ssh configuration.
    #[arg(long)]
    identity: Option<PathBuf>,
    /// Trust the router's host key on first connection (only on a network you trust).
    #[arg(long)]
    accept_new_host_key: bool,
}

#[derive(Debug, Args)]
pub struct TargetArgs {
    /// IPv4 address to hand out as DNS server. Defaults to this host's localname record.
    #[arg(long)]
    dns: Option<Ipv4Addr>,
    /// IPv6 address to announce as DNS server. Defaults to this host's unique-local record.
    #[arg(long)]
    dns6: Option<Ipv6Addr>,
    /// Leave the router's IPv6 DNS announcements unchanged.
    #[arg(long)]
    keep_ipv6_dns: bool,
}

#[derive(Debug, Args)]
pub struct PlanArgs {
    #[command(flatten)]
    connect: ConnectArgs,
    #[command(flatten)]
    target: TargetArgs,
}

#[derive(Debug, Args)]
pub struct ApplyArgs {
    #[command(flatten)]
    connect: ConnectArgs,
    #[command(flatten)]
    target: TargetArgs,
    /// State fingerprint from `router plan`; apply refuses if the router changed since.
    #[arg(long)]
    expect_state: String,
}

#[derive(Debug, Args)]
pub struct RollbackArgs {
    #[command(flatten)]
    connect: ConnectArgs,
    #[arg(long)]
    dry_run: bool,
}

pub async fn run(
    output: OutputFormat,
    non_interactive: bool,
    store: &ConfigStore,
    command: RouterCommand,
) -> Result<()> {
    let batch = non_interactive || matches!(output, OutputFormat::Json);
    let store = store.clone();
    // SSH sessions block; keep them off the async runtime.
    tokio::task::spawn_blocking(move || match command {
        RouterCommand::Detect(args) => detect(output, &connection(&args, batch)),
        RouterCommand::Plan(args) => plan(
            output,
            &store,
            &connection(&args.connect, batch),
            &args.target,
        ),
        RouterCommand::Apply(args) => {
            apply(output, &store, &connection(&args.connect, batch), &args)
        }
        RouterCommand::Status(args) => status(output, &store, &connection(&args, batch)),
        RouterCommand::Rollback(args) => rollback(
            output,
            &store,
            &connection(&args.connect, batch),
            args.dry_run,
        ),
    })
    .await?
}

fn connection(args: &ConnectArgs, batch: bool) -> Connection {
    Connection {
        host: args.host.clone(),
        user: args.user.clone(),
        port: args.port,
        identity: args.identity.clone(),
        accept_new_host_key: args.accept_new_host_key,
        batch,
    }
}

fn detect(output: OutputFormat, connection: &Connection) -> Result<()> {
    let detected = openwrt::detect(connection)?;
    let human = format!(
        "OpenWrt {} ({}) · DHCP section {} · DNS option {}",
        detected.release,
        if detected.model.is_empty() {
            "unknown model"
        } else {
            &detected.model
        },
        detected.settings.section,
        dns_option(&detected.settings).unwrap_or_else(|| "router default".into())
    );
    print_result(
        output,
        Envelope::success(
            "router detect",
            false,
            None,
            json!({"adapter": "openwrt", "detected": detected}),
        ),
        || human,
    )
}

/// DNS values to hand out: explicit flags, else this host's localname records.
fn desired(store: &ConfigStore, target: &TargetArgs) -> Result<Desired> {
    let records = store
        .exists()
        .then(|| store.load())
        .transpose()?
        .map(|config| {
            let host = format!("{HOST_RECORD}.{}", config.zone);
            config
                .records
                .into_iter()
                .filter(move |record| record.name == host)
                .filter_map(|record| record.value.parse::<IpAddr>().ok())
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let dns = target
        .dns
        .or_else(|| {
            records.iter().find_map(|address| match address {
                IpAddr::V4(v4) => Some(*v4),
                IpAddr::V6(_) => None,
            })
        })
        .ok_or_else(|| {
            coded(
                ErrorCode::InvalidInput,
                "invalid request: pass --dns with localname's LAN address (or run `localname setup --apply` on this host first)",
            )
        })?;
    let dns6 = target.dns6.or_else(|| {
        records.iter().find_map(|address| match address {
            IpAddr::V6(v6) if v6.is_unique_local() => Some(*v6),
            _ => None,
        })
    });
    Ok(Desired {
        dns,
        dns6,
        keep_ipv6_dns: target.keep_ipv6_dns,
    })
}

fn plan(
    output: OutputFormat,
    store: &ConfigStore,
    connection: &Connection,
    target: &TargetArgs,
) -> Result<()> {
    let desired = desired(store, target)?;
    let detected = openwrt::detect(connection)?;
    let next = openwrt::desired_settings(&detected.settings, &desired, detected.odhcpd);
    let changes = openwrt::changes(&detected.settings, &next);
    let mut warnings = Vec::new();
    if detected.uncommitted_changes {
        warnings.push("The router has uncommitted UCI changes to dhcp; apply will refuse until they are committed or reverted.".to_owned());
    }
    let apply_command = format!(
        "localname router apply --host {} --expect-state {}",
        connection.host, detected.fingerprint
    );
    let human = if changes.is_empty() {
        format!(
            "The router already hands out {} as DNS server.",
            desired.dns
        )
    } else {
        format!(
            "Router changes (UCI, persistent):\n  {}\nApply with `{apply_command}`.",
            changes.join("\n  ")
        )
    };
    let pending = !changes.is_empty();
    let mut envelope = Envelope::success(
        "router plan",
        pending,
        None,
        json!({
            "adapter": "openwrt",
            "connection": connection,
            "detected": detected,
            "desired": desired,
            "settings": next,
            "changes": changes,
            "fingerprint": detected.fingerprint,
        }),
    );
    envelope.warnings = warnings;
    if pending {
        envelope.next_actions = vec![apply_command];
    }
    print_result(output, envelope, || human)
}

/// Re-read the router until committed and running state match `settings`.
fn wait_for(
    connection: &Connection,
    settings: &DhcpSettings,
    dns: Option<Ipv4Addr>,
    serving: bool,
) -> Result<(bool, Detected)> {
    let mut detected = openwrt::detect(connection)?;
    for _ in 0..20 {
        if detected.settings == *settings && openwrt::runtime_serves(&detected, dns) == serving {
            return Ok((true, detected));
        }
        std::thread::sleep(Duration::from_millis(500));
        detected = openwrt::detect(connection)?;
    }
    Ok((false, detected))
}

fn apply(
    output: OutputFormat,
    store: &ConfigStore,
    connection: &Connection,
    args: &ApplyArgs,
) -> Result<()> {
    let desired = desired(store, &args.target)?;
    let detected = openwrt::detect(connection)?;
    if detected.fingerprint != args.expect_state {
        return Err(coded(
            ErrorCode::Conflict,
            "stale state conflict: the router's DHCP configuration changed since the plan; run `localname router plan` again",
        ));
    }
    let next = openwrt::desired_settings(&detected.settings, &desired, detected.odhcpd);
    let path = router::record_path(store.path(), &connection.host);
    let existing: Option<RouterRecord> = read_record(&path)?;
    let changed = next != detected.settings;
    if changed {
        openwrt::apply(connection, &detected.fingerprint, &detected.settings, &next)?;
    }
    // The first apply captures the router's original values; later applies keep them so
    // rollback always returns to the state before localname.
    let record = RouterRecord {
        version: 1,
        adapter: "openwrt".into(),
        connection: connection.clone(),
        applied_at: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
        captured: existing.map_or_else(|| detected.settings.clone(), |record| record.captured),
        applied: next.clone(),
    };
    if changed || !path.exists() {
        write_record(&path, &record)?;
    }
    let (passed, after) = wait_for(connection, &next, Some(desired.dns), true)?;
    let rollback = format!("localname router rollback --host {}", connection.host);
    let data = json!({
        "adapter": "openwrt",
        "connection": connection,
        "settings": next,
        "changes": openwrt::changes(&detected.settings, &next),
        "fingerprint": after.fingerprint,
        "record": path,
    });
    let verification = json!({"status": if passed { "passed" } else { "failed" }, "scope": "router_configuration"});
    if !passed {
        return Err(ReportedError {
            command: "router apply",
            code: ErrorCode::VerificationFailed,
            message: "router changed, but dnsmasq does not serve the new DNS option".into(),
            human: String::new(),
            data,
            verification: Some(verification),
            next_actions: vec![format!("Undo with `{rollback}`.")],
            rollback: Some(rollback),
        }
        .into());
    }
    let human = if changed {
        format!(
            "✓ The router now hands out {} as DNS server (committed and running). Reconnect a device and run `localname setup verify` on it. Undo with `{rollback}`.",
            desired.dns
        )
    } else {
        format!(
            "✓ The router already hands out {} as DNS server.",
            desired.dns
        )
    };
    let mut envelope = Envelope::success("router apply", changed, None, data);
    envelope.verification = Some(verification);
    envelope.rollback = Some(rollback);
    envelope.next_actions = vec![
        "Reconnect a device (or renew its DHCP lease) and run `localname setup verify` on it."
            .into(),
    ];
    print_result(output, envelope, || human)
}

fn status(output: OutputFormat, store: &ConfigStore, connection: &Connection) -> Result<()> {
    let detected = openwrt::detect(connection)?;
    let record = read_record(&router::record_path(store.path(), &connection.host))?;
    let (state, human) = match &record {
        None => (
            "not_applied",
            "localname has not changed this router.".to_owned(),
        ),
        Some(record) if record.applied == detected.settings => {
            let dns = dns_option(&record.applied).and_then(|value| value.parse().ok());
            if openwrt::runtime_serves(&detected, dns) {
                (
                    "applied",
                    format!(
                        "✓ The router hands out {} as DNS server (committed and running).",
                        dns_option(&record.applied).unwrap_or_default()
                    ),
                )
            } else {
                ("not_running", "! The router's configuration is committed, but dnsmasq does not serve it; restart dnsmasq on the router.".to_owned())
            }
        }
        Some(_) => (
            "changed",
            "! The router's DHCP settings changed after localname applied them.".to_owned(),
        ),
    };
    print_result(
        output,
        Envelope::success(
            "router status",
            false,
            None,
            json!({"state": state, "detected": detected, "record": record}),
        ),
        || human,
    )
}

fn rollback(
    output: OutputFormat,
    store: &ConfigStore,
    connection: &Connection,
    dry_run: bool,
) -> Result<()> {
    let path = router::record_path(store.path(), &connection.host);
    let record = read_record(&path)?.ok_or_else(|| {
        coded(
            ErrorCode::InvalidInput,
            format!(
                "invalid request: no localname change is recorded for router {}",
                connection.host
            ),
        )
    })?;
    let detected = openwrt::detect(connection)?;
    if detected.settings != record.applied {
        return Err(coded(
            ErrorCode::Conflict,
            format!(
                "stale state conflict: the router's DHCP settings changed after localname applied them (now {:?}); restore them manually or apply again",
                detected.settings
            ),
        ));
    }
    let changes = openwrt::changes(&detected.settings, &record.captured);
    let data = json!({"adapter": "openwrt", "connection": connection, "restores": record.captured, "changes": changes});
    if dry_run {
        let human = format!("Would restore:\n  {}", changes.join("\n  "));
        return print_result(
            output,
            Envelope::success("router rollback", !changes.is_empty(), None, data),
            || human,
        );
    }
    if !changes.is_empty() {
        openwrt::apply(
            connection,
            &detected.fingerprint,
            &detected.settings,
            &record.captured,
        )?;
    }
    let applied_dns = dns_option(&record.applied).and_then(|value| value.parse().ok());
    let (passed, _) = wait_for(connection, &record.captured, applied_dns, false)?;
    if !passed {
        return Err(coded(
            ErrorCode::VerificationFailed,
            "verification failed: the router did not return to its captured DHCP settings",
        ));
    }
    std::fs::remove_file(&path)?;
    let mut envelope = Envelope::success("router rollback", !changes.is_empty(), None, data);
    envelope.verification = Some(json!({"status": "passed", "scope": "router_configuration"}));
    print_result(output, envelope, || {
        "✓ Restored the router's DHCP DNS settings from before localname.".into()
    })
}

fn dns_option(settings: &DhcpSettings) -> Option<String> {
    settings.dhcp_option.iter().flatten().find_map(|option| {
        let (code, value) = option.split_once(',')?;
        (code.trim() == "6" || code.trim() == "option:dns-server").then(|| value.trim().to_owned())
    })
}

fn read_record(path: &std::path::Path) -> Result<Option<RouterRecord>> {
    match std::fs::read_to_string(path) {
        Ok(text) => {
            Ok(Some(serde_json::from_str(&text).with_context(|| {
                format!("failed to parse {}", path.display())
            })?))
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}

fn write_record(path: &std::path::Path, record: &RouterRecord) -> Result<()> {
    let directory = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or(std::path::Path::new("."));
    std::fs::create_dir_all(directory)?;
    let mut temporary = tempfile::Builder::new()
        .prefix(".localname-")
        .suffix(".tmp")
        .tempfile_in(directory)?;
    serde_json::to_writer_pretty(&mut temporary, record)?;
    temporary.as_file().sync_all()?;
    temporary.persist(path).map_err(|error| error.error)?;
    Ok(())
}
