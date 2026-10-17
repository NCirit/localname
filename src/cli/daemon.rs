//! `localname daemon`: run localname as a system service that starts at boot (M6).

use std::{
    fmt::Write,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

use anyhow::Result;
use clap::{Args, Subcommand};
use serde::Serialize;
use serde_json::{Value, json};

use super::{ReportedError, health::probe, print_result};
use crate::{
    ConfigStore,
    daemon::{self, DaemonState},
    error::{ErrorCode, classify},
    output::{Envelope, OutputFormat},
};

#[derive(Debug, Subcommand)]
pub enum DaemonCommand {
    /// Show whether the service is installed, starts at boot, and is running.
    Status,
    /// Plan, or with --apply make, localname a service that starts at boot and restarts on
    /// failure (requires root or administrator).
    Install(InstallArgs),
    /// Stop and remove the service; the configuration and its revisions are kept.
    Uninstall(UninstallArgs),
    /// Start the installed service and check that it answers.
    Start,
    /// Stop the installed service; it starts again at the next boot.
    Stop,
    /// Run as a Windows service (started by the Service Control Manager).
    #[command(hide = true)]
    Run,
}

#[derive(Debug, Args)]
pub struct InstallArgs {
    /// Make the change (requires root or administrator).
    #[arg(long)]
    apply: bool,
}

#[derive(Debug, Args)]
pub struct UninstallArgs {
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
struct DaemonData {
    state: DaemonState,
    checks: Vec<Check>,
    steps: Vec<String>,
    applied: bool,
}

const UNINSTALL: &str = "localname daemon uninstall";
/// How long a started service may take to answer DNS.
const READY_TIMEOUT: Duration = Duration::from_secs(20);

/// Run the Windows service dispatcher on the main thread; elsewhere `daemon run` is an error.
#[cfg_attr(not(windows), allow(clippy::needless_pass_by_value))]
pub fn run_service(config: Option<PathBuf>) -> std::process::ExitCode {
    #[cfg(windows)]
    let result =
        daemon::windows::run_dispatcher(config.unwrap_or_else(daemon::service_config_path));
    #[cfg(not(windows))]
    let result: Result<()> = {
        let _ = config;
        Err(crate::error::coded(
            ErrorCode::InvalidInput,
            "invalid use: `localname daemon run` exists only for the Windows Service Control Manager; use `localname daemon start`",
        ))
    };
    match result {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("localname: {error:#}");
            std::process::ExitCode::from(classify(&error).exit_code())
        }
    }
}

pub async fn run(output: OutputFormat, store: &ConfigStore, command: DaemonCommand) -> Result<()> {
    let warnings = config_warning(store.path());
    match command {
        DaemonCommand::Status => status(output, warnings).await,
        DaemonCommand::Install(args) => install(output, warnings, &args).await,
        DaemonCommand::Uninstall(args) => uninstall(output, warnings, &args).await,
        DaemonCommand::Start => start(output, warnings).await,
        DaemonCommand::Stop => stop(output, warnings).await,
        DaemonCommand::Run => unreachable!("handled before the runtime starts"),
    }
}

/// The service always uses the platform's service configuration.
fn config_warning(selected: &Path) -> Vec<String> {
    let service = daemon::service_config_path();
    if selected == service {
        return Vec::new();
    }
    vec![format!(
        "The service uses {}, not {}.",
        service.display(),
        selected.display()
    )]
}

async fn detect() -> Result<DaemonState> {
    tokio::task::spawn_blocking(daemon::detect).await?
}

/// The running binary, in the ordinary path form.
fn current_binary() -> Result<PathBuf> {
    let path = std::env::current_exe()?;
    let path = path.canonicalize().unwrap_or(path);
    #[cfg(windows)]
    let path = path
        .to_str()
        .and_then(|text| text.strip_prefix(r"\\?\"))
        .filter(|rest| !rest.starts_with("UNC\\"))
        .map_or(path.clone(), PathBuf::from);
    Ok(path)
}

fn describe(state: &DaemonState) -> String {
    if let Some(reason) = &state.unsupported {
        return format!("Unsupported: {reason}.");
    }
    if !state.installed {
        return format!(
            "localname is not installed as a service ({}). Preview with `localname daemon install`.",
            state.manager
        );
    }
    format!(
        "{} ({}): {}, {}{}.\nBinary {}, configuration {}, account {}, log: {}.",
        state.service,
        state.manager,
        if state.enabled {
            "starts at boot"
        } else {
            "does not start at boot"
        },
        if state.running { "running" } else { "stopped" },
        state
            .pid
            .map(|pid| format!(" (pid {pid})"))
            .unwrap_or_default(),
        state.binary.display(),
        state.config.display(),
        state.account,
        state.log,
    )
}

fn render(checks: &[Check], tail: &str) -> String {
    let mut lines: Vec<String> = checks
        .iter()
        .map(|check| format!("{} {}", if check.passed { "✓" } else { "✗" }, check.detail))
        .collect();
    if !tail.is_empty() {
        lines.push(tail.to_owned());
    }
    lines.join("\n")
}

async fn status(output: OutputFormat, warnings: Vec<String>) -> Result<()> {
    let state = detect().await?;
    let mut human = describe(&state);
    let dns = if state.running {
        match ConfigStore::new(&state.config).load() {
            Ok(config) => {
                let (healthy, detail, _) = probe(&config).await;
                let _ = write!(human, "\n{} {detail}", if healthy { "✓" } else { "✗" });
                json!({"healthy": healthy, "detail": detail})
            }
            Err(error) => json!({"healthy": null, "detail": format!("{error:#}")}),
        }
    } else {
        Value::Null
    };
    let mut envelope = Envelope::success(
        "daemon status",
        false,
        None,
        json!({"state": state, "dns": dns}),
    );
    envelope.warnings = warnings;
    print_result(output, envelope, || human)
}

/// Whether the service configuration exists and loads; the detail says how to fix it.
fn configuration_check(state: &DaemonState) -> (Check, Option<String>) {
    let path = &state.config;
    match ConfigStore::new(path).load() {
        Ok(config) => {
            let listeners: Vec<String> = config.listen.iter().map(ToString::to_string).collect();
            let warning = config
                .listen
                .iter()
                .all(|address| address.ip().is_loopback())
                .then(|| {
                    format!(
                        "{} listens only on loopback, so other devices cannot use it; run `localname setup` for whole-home setup.",
                        path.display()
                    )
                });
            (
                Check {
                    id: "configuration",
                    passed: true,
                    detail: format!(
                        "{} is valid (revision {}, zone {}, listens on {}).",
                        path.display(),
                        config.revision,
                        config.zone.trim_end_matches('.'),
                        listeners.join(", ")
                    ),
                },
                warning,
            )
        }
        Err(error) if !path.exists() && classify(&error) != ErrorCode::PermissionRequired => (
            Check {
                id: "configuration",
                passed: false,
                detail: format!(
                    "No configuration at {path}. Create it first: `localname --config {quoted} setup --apply` ({elevated}).",
                    path = path.display(),
                    quoted = quote(path),
                    elevated = if cfg!(windows) {
                        "in an administrator PowerShell"
                    } else {
                        "with sudo"
                    },
                ),
            },
            None,
        ),
        Err(error) => (
            Check {
                id: "configuration",
                passed: false,
                detail: format!("{} cannot be used: {error:#}", path.display()),
            },
            None,
        ),
    }
}

fn quote(path: &Path) -> String {
    let text = path.to_string_lossy();
    if cfg!(windows) {
        format!("'{}'", text.replace('\'', "''"))
    } else {
        format!("'{}'", text.replace('\'', "'\\''"))
    }
}

/// Wait for the service to run and answer DNS on its configured listener.
async fn verify_running(config: &Path) -> (DaemonState, Vec<Check>) {
    let deadline = Instant::now() + READY_TIMEOUT;
    let mut state = None;
    let mut dns = (false, "the service did not start".to_owned());
    while Instant::now() < deadline {
        match detect().await {
            Ok(current) if current.running => {
                match ConfigStore::new(config).load() {
                    Ok(loaded) => {
                        let (healthy, detail, _) = probe(&loaded).await;
                        dns = (healthy, detail);
                    }
                    Err(error) => dns = (false, format!("{error:#}")),
                }
                let done = dns.0;
                state = Some(current);
                if done {
                    break;
                }
            }
            Ok(current) => state = Some(current),
            Err(error) => dns = (false, format!("{error:#}")),
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    let state = match state {
        Some(state) => state,
        None => match detect().await {
            Ok(state) => state,
            Err(_) => return (placeholder(config), vec![failed_dns(dns.1)]),
        },
    };
    let checks = vec![
        Check {
            id: "enabled",
            passed: state.enabled,
            detail: if state.enabled {
                format!("{} starts at boot.", state.service)
            } else {
                format!("{} does not start at boot.", state.service)
            },
        },
        Check {
            id: "running",
            passed: state.running,
            detail: if state.running {
                format!(
                    "{} is running{}.",
                    state.service,
                    state
                        .pid
                        .map(|pid| format!(" (pid {pid})"))
                        .unwrap_or_default()
                )
            } else {
                format!("{} is not running; see {}.", state.service, state.log)
            },
        },
        Check {
            id: "dns",
            passed: dns.0,
            detail: dns.1,
        },
    ];
    (state, checks)
}

fn not_installed() -> anyhow::Error {
    crate::error::coded(
        ErrorCode::Unavailable,
        "service unavailable: localname is not installed as a service; preview with `localname daemon install`",
    )
}

fn failed_dns(detail: String) -> Check {
    Check {
        id: "dns",
        passed: false,
        detail,
    }
}

fn placeholder(config: &Path) -> DaemonState {
    DaemonState {
        manager: "none",
        unsupported: None,
        service: String::new(),
        definition: String::new(),
        installed: false,
        managed: false,
        enabled: false,
        running: false,
        pid: None,
        binary: PathBuf::new(),
        config: config.to_path_buf(),
        account: String::new(),
        log: String::new(),
        conflicts: Vec::new(),
    }
}

#[allow(clippy::too_many_lines)]
async fn install(
    output: OutputFormat,
    mut warnings: Vec<String>,
    args: &InstallArgs,
) -> Result<()> {
    let source = current_binary()?;
    let state = detect().await?;
    let mut checks = Vec::new();
    if let Some(reason) = &state.unsupported {
        checks.push(Check {
            id: "supported",
            passed: false,
            detail: reason.clone(),
        });
    }
    for conflict in &state.conflicts {
        checks.push(Check {
            id: "conflict",
            passed: false,
            detail: conflict.clone(),
        });
    }
    if state.unsupported.is_none() {
        let (check, warning) = configuration_check(&state);
        checks.push(check);
        warnings.extend(warning);
    }
    let steps = daemon::plan_install(&state, &source);
    let blocking: Vec<&Check> = checks.iter().filter(|check| !check.passed).collect();
    if !blocking.is_empty() {
        let code = if state.unsupported.is_some() {
            ErrorCode::Unavailable
        } else if !state.conflicts.is_empty() {
            ErrorCode::Conflict
        } else if blocking
            .iter()
            .any(|check| check.detail.contains("ermission") || check.detail.contains("denied"))
        {
            ErrorCode::PermissionRequired
        } else {
            ErrorCode::InvalidInput
        };
        let message = format!(
            "daemon install blocked: {}",
            blocking
                .iter()
                .map(|check| check.detail.as_str())
                .collect::<Vec<_>>()
                .join("; ")
        );
        let human = render(&checks, "");
        return Err(ReportedError {
            command: "daemon install",
            code,
            next_actions: blocking.iter().map(|check| check.detail.clone()).collect(),
            data: serde_json::to_value(DaemonData {
                state,
                checks,
                steps,
                applied: false,
            })?,
            verification: None,
            rollback: None,
            message,
            human,
        }
        .into());
    }

    let up_to_date = state.installed
        && state.enabled
        && state.running
        && (!state.managed || daemon_binary_matches(&state, &source));
    if !args.apply {
        let human = format!(
            "{}\n{}\nRun again with --apply ({}) to make the change.",
            render(&checks, ""),
            steps
                .iter()
                .map(|step| format!("- {step}"))
                .collect::<Vec<_>>()
                .join("\n"),
            if cfg!(windows) {
                "in an administrator PowerShell"
            } else {
                "with sudo"
            }
        );
        let mut envelope = Envelope::success(
            "daemon install",
            !up_to_date,
            None,
            DaemonData {
                state,
                checks,
                steps: steps.clone(),
                applied: false,
            },
        );
        envelope.warnings = warnings;
        envelope.next_actions = steps;
        return print_result(output, envelope, || human);
    }

    daemon::require_privileges()?;
    let taken = {
        let source = source.clone();
        tokio::task::spawn_blocking(move || daemon::install(&source)).await??
    };
    let (after, verification_checks) = verify_running(&state.config).await;
    checks.extend(verification_checks);
    let passed = checks.iter().all(|check| check.passed);
    let human = render(
        &checks,
        &taken
            .iter()
            .map(|step| format!("- {step}"))
            .collect::<Vec<_>>()
            .join("\n"),
    );
    let verification = json!({
        "status": if passed { "passed" } else { "failed" },
        "scope": "configured_listener",
    });
    let data = DaemonData {
        state: after,
        checks,
        steps: taken,
        applied: true,
    };
    if !passed {
        let log = data.state.log.clone();
        return Err(ReportedError {
            command: "daemon install",
            code: ErrorCode::VerificationFailed,
            message: "the service was installed, but verification failed".into(),
            data: serde_json::to_value(&data)?,
            verification: Some(verification),
            next_actions: vec![
                format!("Check the service log ({log})."),
                format!("Remove the service with `{UNINSTALL}`."),
            ],
            rollback: Some(UNINSTALL.into()),
            human,
        }
        .into());
    }
    let mut envelope = Envelope::success("daemon install", !up_to_date, None, data);
    envelope.warnings = warnings;
    envelope.verification = Some(verification);
    envelope.rollback = Some(UNINSTALL.into());
    print_result(output, envelope, || human)
}

fn daemon_binary_matches(state: &DaemonState, source: &Path) -> bool {
    std::fs::read(source)
        .ok()
        .zip(std::fs::read(&state.binary).ok())
        .is_some_and(|(source, installed)| source == installed)
}

async fn uninstall(
    output: OutputFormat,
    warnings: Vec<String>,
    args: &UninstallArgs,
) -> Result<()> {
    let state = detect().await?;
    if args.dry_run || !state.installed {
        let summary = if state.installed {
            format!(
                "Would stop {} and remove it ({}). The configuration in {} is kept.",
                state.service,
                state.definition,
                state.config.display()
            )
        } else {
            "localname is not installed as a service; nothing to remove.".into()
        };
        let changed = state.installed;
        let mut envelope = Envelope::success(
            "daemon uninstall",
            changed && args.dry_run,
            None,
            json!({"state": state, "preview": args.dry_run, "steps": [], "applied": false}),
        );
        envelope.warnings = warnings;
        return print_result(output, envelope, || summary);
    }
    daemon::require_privileges()?;
    let steps = tokio::task::spawn_blocking(daemon::uninstall).await??;
    let after = detect().await?;
    let checks = vec![Check {
        id: "removed",
        passed: !after.running && !after.enabled,
        detail: if after.running || after.enabled {
            format!("{} is still running or enabled.", after.service)
        } else {
            format!("{} is stopped and does not start at boot.", after.service)
        },
    }];
    let passed = checks[0].passed;
    let human = render(
        &checks,
        &steps
            .iter()
            .map(|step| format!("- {step}"))
            .collect::<Vec<_>>()
            .join("\n"),
    );
    let data = DaemonData {
        state: after,
        checks,
        steps,
        applied: true,
    };
    if !passed {
        return Err(ReportedError {
            command: "daemon uninstall",
            code: ErrorCode::VerificationFailed,
            message: "the service was removed, but verification failed".into(),
            data: serde_json::to_value(&data)?,
            verification: Some(json!({"status": "failed", "scope": "this_host"})),
            next_actions: Vec::new(),
            rollback: None,
            human,
        }
        .into());
    }
    let mut envelope = Envelope::success("daemon uninstall", true, None, data);
    envelope.warnings = warnings;
    envelope.verification = Some(json!({"status": "passed", "scope": "this_host"}));
    print_result(output, envelope, || human)
}

async fn start(output: OutputFormat, warnings: Vec<String>) -> Result<()> {
    let before = detect().await?;
    if before.unsupported.is_none() && !before.installed {
        return Err(not_installed());
    }
    daemon::require_privileges()?;
    tokio::task::spawn_blocking(daemon::start).await??;
    let (after, checks) = verify_running(&before.config).await;
    let passed = checks
        .iter()
        .all(|check| check.passed || check.id == "enabled");
    let human = render(&checks, "");
    let verification = json!({
        "status": if passed { "passed" } else { "failed" },
        "scope": "configured_listener",
    });
    let data = DaemonData {
        state: after,
        checks,
        steps: Vec::new(),
        applied: true,
    };
    if !passed {
        let log = data.state.log.clone();
        return Err(ReportedError {
            command: "daemon start",
            code: ErrorCode::VerificationFailed,
            message: "the service was started, but it does not answer".into(),
            data: serde_json::to_value(&data)?,
            verification: Some(verification),
            next_actions: vec![format!("Check the service log ({log}).")],
            rollback: None,
            human,
        }
        .into());
    }
    let mut envelope = Envelope::success("daemon start", !before.running, None, data);
    envelope.warnings = warnings;
    envelope.verification = Some(verification);
    print_result(output, envelope, || human)
}

async fn stop(output: OutputFormat, warnings: Vec<String>) -> Result<()> {
    let before = detect().await?;
    if before.unsupported.is_none() && !before.installed {
        return Err(not_installed());
    }
    daemon::require_privileges()?;
    tokio::task::spawn_blocking(daemon::stop).await??;
    let deadline = Instant::now() + READY_TIMEOUT;
    let mut after = detect().await?;
    while after.running && Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(200)).await;
        after = detect().await?;
    }
    let check = Check {
        id: "stopped",
        passed: !after.running,
        detail: if after.running {
            format!("{} is still running.", after.service)
        } else if after.enabled {
            format!(
                "{} is stopped; it starts again at the next boot.",
                after.service
            )
        } else {
            format!("{} is stopped.", after.service)
        },
    };
    let passed = check.passed;
    let human = render(std::slice::from_ref(&check), "");
    let data = DaemonData {
        state: after,
        checks: vec![check],
        steps: Vec::new(),
        applied: true,
    };
    if !passed {
        return Err(ReportedError {
            command: "daemon stop",
            code: ErrorCode::VerificationFailed,
            message: "the service did not stop".into(),
            data: serde_json::to_value(&data)?,
            verification: Some(json!({"status": "failed", "scope": "this_host"})),
            next_actions: Vec::new(),
            rollback: None,
            human,
        }
        .into());
    }
    let mut envelope = Envelope::success("daemon stop", before.running, None, data);
    envelope.warnings = warnings;
    envelope.verification = Some(json!({"status": "passed", "scope": "this_host"}));
    print_result(output, envelope, || human)
}
