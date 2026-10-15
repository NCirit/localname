//! `localname client`: reversible per-device DNS for the localname zone (M3b).

use std::{net::IpAddr, time::Duration};

use anyhow::Result;
use clap::{Args, Subcommand};
use serde::Serialize;
use serde_json::json;

use super::{
    ReportedError, print_result,
    setup::HOST_RECORD,
    verify::{system_lookup, transport_check},
};
use crate::{
    Transport,
    client::{self, ClientState, Target},
    error::{ErrorCode, coded},
    output::{Envelope, OutputFormat},
};

#[derive(Debug, Subcommand)]
pub enum ClientCommand {
    /// Show how this device sends the zone's queries.
    Status(ZoneArgs),
    /// Plan, or with --apply make, this device send only the zone's queries to localname.
    Setup(SetupArgs),
    /// Remove localname's DNS configuration from this device.
    Rollback(RollbackArgs),
}

#[derive(Debug, Args)]
pub struct ZoneArgs {
    #[arg(long, default_value = "home.arpa")]
    zone: String,
}

#[derive(Debug, Args)]
pub struct SetupArgs {
    /// Address of the localname server.
    #[arg(long)]
    server: IpAddr,
    /// Server port (Windows supports only 53).
    #[arg(long, default_value_t = 53)]
    port: u16,
    #[arg(long, default_value = "home.arpa")]
    zone: String,
    /// Change this device's DNS configuration (requires root or administrator).
    #[arg(long)]
    apply: bool,
    /// Name used to verify resolution, relative to the zone.
    #[arg(long, default_value = HOST_RECORD)]
    name: String,
    #[arg(long, default_value_t = 2_000)]
    timeout_ms: u64,
}

#[derive(Debug, Args)]
pub struct RollbackArgs {
    #[arg(long, default_value = "home.arpa")]
    zone: String,
    /// Show what would be removed without changing anything.
    #[arg(long)]
    dry_run: bool,
}

#[derive(Debug, Serialize)]
struct Check {
    id: &'static str,
    passed: bool,
    detail: String,
}

#[derive(Debug, Serialize)]
struct ClientData {
    zone: String,
    target: Option<Target>,
    state: ClientState,
    checks: Vec<Check>,
    applied: bool,
}

pub async fn run(output: OutputFormat, command: &ClientCommand) -> Result<()> {
    match command {
        ClientCommand::Status(args) => status(output, args).await,
        ClientCommand::Setup(args) => setup(output, args).await,
        ClientCommand::Rollback(args) => rollback(output, args),
    }
}

fn rollback_command(zone: &str) -> String {
    format!(
        "localname client rollback --zone {}",
        zone.trim_end_matches('.')
    )
}

async fn status(output: OutputFormat, args: &ZoneArgs) -> Result<()> {
    let zone = crate::config::canonical_zone(&args.zone)?;
    let state = blocking_detect(zone.clone()).await?;
    let name = format!("{HOST_RECORD}.{zone}");
    let lookup = system_lookup(&name, Duration::from_secs(2)).await;
    let human = match (&state.unsupported, &state.managed) {
        (Some(reason), _) => format!("Unsupported: {reason}"),
        (None, Some(target)) => format!(
            "{} sends {} queries to {} ({}).",
            state.backend,
            target.domain(),
            target.address(),
            state.artifact
        ),
        (None, None) => format!(
            "This device has no localname configuration for {} ({}).",
            zone.trim_end_matches('.'),
            state.backend
        ),
    };
    let data = json!({
        "zone": zone,
        "state": state,
        "system_resolver": match lookup {
            Ok(addresses) => json!({"name": name, "addresses": addresses}),
            Err(error) => json!({"name": name, "error": format!("{error:#}")}),
        },
    });
    print_result(
        output,
        Envelope::success("client status", false, None, data),
        || human,
    )
}

#[allow(clippy::too_many_lines)]
async fn setup(output: OutputFormat, args: &SetupArgs) -> Result<()> {
    let zone = crate::config::canonical_zone(&args.zone)?;
    let target = Target {
        server: args.server,
        port: args.port,
        zone: zone.clone(),
    };
    let timeout = Duration::from_millis(args.timeout_ms);
    let name = crate::config::canonical_name(&args.name, &zone)?;
    let before = blocking_detect(zone.clone()).await?;
    let mut checks = Vec::new();

    // The server must answer before this device depends on it.
    let mut expected = Vec::new();
    for (id, transport) in [
        ("server_udp", Transport::Udp),
        ("server_tcp", Transport::Tcp),
    ] {
        match transport_check(target.address(), &zone, &name, timeout, transport).await {
            Ok(addresses) => {
                checks.push(Check {
                    id,
                    passed: true,
                    detail: format!(
                        "{} serves {} over {}.",
                        target.address(),
                        target.domain(),
                        id[7..].to_uppercase()
                    ),
                });
                if expected.is_empty() {
                    expected = addresses;
                }
            }
            Err(error) => checks.push(Check {
                id,
                passed: false,
                detail: format!(
                    "{} does not serve {}: {error:#}",
                    target.address(),
                    target.domain()
                ),
            }),
        }
    }
    if let Some(reason) = &before.unsupported {
        checks.push(Check {
            id: "supported",
            passed: false,
            detail: reason.clone(),
        });
    }
    for conflict in &before.conflicts {
        checks.push(Check {
            id: "conflict",
            passed: false,
            detail: conflict.clone(),
        });
    }
    if args.port != 53 && before.backend == "windows-nrpt" {
        checks.push(Check {
            id: "port",
            passed: false,
            detail: "Windows NRPT rules only support DNS servers on port 53.".into(),
        });
    }
    let unchanged = before.managed.as_ref() == Some(&target);
    let blocking: Vec<&Check> = checks.iter().filter(|check| !check.passed).collect();
    let summary = if unchanged {
        format!(
            "{} already sends {} queries to {}.",
            before.artifact,
            target.domain(),
            target.address()
        )
    } else {
        format!(
            "Write {} so only {} queries go to {}; other DNS settings stay as they are.",
            before.artifact,
            target.domain(),
            target.address()
        )
    };

    if !blocking.is_empty() {
        let message = format!(
            "client setup blocked: {}",
            blocking
                .iter()
                .map(|check| check.detail.as_str())
                .collect::<Vec<_>>()
                .join("; ")
        );
        let code = if before.unsupported.is_some() {
            ErrorCode::Unavailable
        } else if !before.conflicts.is_empty() {
            ErrorCode::Conflict
        } else if blocking.iter().any(|check| check.id == "port") {
            ErrorCode::InvalidInput
        } else {
            ErrorCode::Unavailable
        };
        let human = render(&checks, "");
        return Err(ReportedError {
            command: "client setup",
            code,
            data: serde_json::to_value(ClientData {
                zone,
                target: Some(target),
                state: before,
                checks,
                applied: false,
            })?,
            verification: None,
            next_actions: vec![
                "Make sure localname runs and this device can reach it, or make the router advertise localname instead (`localname setup`).".into(),
            ],
            rollback: None,
            message,
            human,
        }
        .into());
    }

    if !args.apply {
        let human = format!(
            "{}\n{summary}\nRun again with --apply (as root or administrator) to make the change.",
            render(&checks, "")
        );
        let mut envelope = Envelope::success(
            "client setup",
            !unchanged,
            None,
            ClientData {
                zone: zone.clone(),
                target: Some(target),
                state: before,
                checks,
                applied: false,
            },
        );
        envelope.next_actions = vec![summary];
        return print_result(output, envelope, || human);
    }

    client::require_privileges()?;
    let changed = {
        let target = target.clone();
        tokio::task::spawn_blocking(move || client::apply(&target)).await??
    };
    let after = blocking_detect(zone.clone()).await?;

    // Verify through the operating system's resolver, which applications use.
    let mut resolved = Err(anyhow::anyhow!("not attempted"));
    for _ in 0..25 {
        resolved = system_lookup(&name, timeout).await;
        if resolved.as_ref().is_ok_and(|found| {
            expected.is_empty() || found.iter().any(|address| expected.contains(address))
        }) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    let name_text = name.trim_end_matches('.');
    checks.push(match &resolved {
        _ if expected.is_empty() => Check {
            id: "system_resolver",
            passed: true,
            detail: format!(
                "{name_text} has no address on the server; resolver routing was not compared."
            ),
        },
        Ok(found) if found.iter().any(|address| expected.contains(address)) => Check {
            id: "system_resolver",
            passed: true,
            detail: format!(
                "The system resolver returns {} for {name_text}.",
                join(found)
            ),
        },
        Ok(found) => Check {
            id: "system_resolver",
            passed: false,
            detail: format!(
                "The system resolver returns {} for {name_text}, expected {}.",
                join(found),
                join(&expected)
            ),
        },
        Err(error) => Check {
            id: "system_resolver",
            passed: false,
            detail: format!("The system resolver cannot resolve {name_text}: {error:#}"),
        },
    });
    checks.push(preserved_check(&before, &after));
    let passed = checks.iter().all(|check| check.passed);
    let rollback = rollback_command(&zone);
    let human = render(&checks, &summary);
    let verification =
        json!({"status": if passed { "passed" } else { "failed" }, "scope": "this_device"});
    let data = ClientData {
        zone,
        target: Some(target),
        state: after,
        checks,
        applied: true,
    };
    if !passed {
        return Err(ReportedError {
            command: "client setup",
            code: ErrorCode::VerificationFailed,
            message: "client DNS changed, but verification failed".into(),
            data: serde_json::to_value(&data)?,
            verification: Some(verification),
            next_actions: vec![format!("Undo the change with `{rollback}`.")],
            rollback: Some(rollback),
            human,
        }
        .into());
    }
    let mut envelope = Envelope::success("client setup", changed, None, data);
    envelope.verification = Some(verification);
    envelope.rollback = Some(rollback);
    print_result(output, envelope, || human)
}

fn rollback(output: OutputFormat, args: &RollbackArgs) -> Result<()> {
    let zone = crate::config::canonical_zone(&args.zone)?;
    let before = client::detect(&zone)?;
    let domain = zone.trim_end_matches('.').to_owned();
    if args.dry_run {
        let summary = match &before.managed {
            Some(target) => format!(
                "Would remove {} (sends {domain} to {}).",
                before.artifact,
                target.address()
            ),
            None => format!("This device has no localname configuration for {domain}."),
        };
        let changed = before.managed.is_some();
        let mut data = serde_json::to_value(ClientData {
            zone,
            target: None,
            state: before,
            checks: Vec::new(),
            applied: false,
        })?;
        data["preview"] = json!(true);
        return print_result(
            output,
            Envelope::success("client rollback", changed, None, data),
            || summary,
        );
    }
    if before.managed.is_some() {
        client::require_privileges()?;
    }
    let changed = client::remove(&zone)?;
    let after = client::detect(&zone)?;
    let mut checks = vec![preserved_check(&before, &after)];
    checks.push(Check {
        id: "removed",
        passed: after.managed.is_none(),
        detail: if after.managed.is_none() {
            format!("{} is gone.", after.artifact)
        } else {
            format!("{} is still present.", after.artifact)
        },
    });
    let passed = checks.iter().all(|check| check.passed);
    let human = render(
        &checks,
        &if changed {
            format!("Removed localname's {domain} configuration.")
        } else {
            format!("Nothing to roll back for {domain}.")
        },
    );
    let data = ClientData {
        zone,
        target: None,
        state: after,
        checks,
        applied: changed,
    };
    if !passed {
        return Err(coded(
            ErrorCode::VerificationFailed,
            format!(
                "verification failed after rollback: {}",
                serde_json::to_string(&data.checks)?
            ),
        ));
    }
    let mut envelope = Envelope::success("client rollback", changed, None, data);
    envelope.verification = Some(json!({"status": "passed", "scope": "this_device"}));
    print_result(output, envelope, || human)
}

/// Unrelated resolver state must be identical before and after a change.
fn preserved_check(before: &ClientState, after: &ClientState) -> Check {
    let added: Vec<&String> = after
        .preserved
        .iter()
        .filter(|line| !before.preserved.contains(line))
        .collect();
    let removed: Vec<&String> = before
        .preserved
        .iter()
        .filter(|line| !after.preserved.contains(line))
        .collect();
    if added.is_empty() && removed.is_empty() {
        Check {
            id: "preserved",
            passed: true,
            detail: format!(
                "{} unrelated DNS settings (VPN, interfaces, search domains) are unchanged.",
                before.preserved.len()
            ),
        }
    } else {
        Check {
            id: "preserved",
            passed: false,
            detail: format!(
                "Unrelated DNS settings changed: added {added:?}, removed {removed:?}."
            ),
        }
    }
}

async fn blocking_detect(zone: String) -> Result<ClientState> {
    tokio::task::spawn_blocking(move || client::detect(&zone)).await?
}

fn render(checks: &[Check], summary: &str) -> String {
    let mut lines: Vec<String> = checks
        .iter()
        .map(|check| format!("{} {}", if check.passed { "✓" } else { "✗" }, check.detail))
        .collect();
    if !summary.is_empty() {
        lines.push(summary.to_owned());
    }
    lines.join("\n")
}

fn join(addresses: &[IpAddr]) -> String {
    addresses
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(", ")
}
