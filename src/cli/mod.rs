mod backup;
mod client;
mod daemon;
mod health;
#[cfg(feature = "https")]
mod https;
mod records;
mod router;
mod services;
mod setup;
mod verify;

use std::{
    env,
    net::{IpAddr, SocketAddr},
    path::{Path, PathBuf},
    process::ExitCode,
};

use anyhow::Result;
use clap::{Args, CommandFactory, Parser, Subcommand, ValueEnum};
use hickory_proto::rr::RecordType;
use serde::Serialize;
use serde_json::{Value, json};
use tokio::sync::watch;
use tracing_subscriber::EnvFilter;

use crate::{
    ConfigStore, DnsServer,
    error::{ErrorCode, classify, coded},
    output::{Envelope, ErrorBody, OutputFormat},
};

#[derive(Debug, Parser)]
#[command(name = "localname", version, about, propagate_version = true)]
pub struct Cli {
    /// Configuration file. Defaults to `LOCALNAME_CONFIG` or the platform config directory.
    #[arg(long, global = true, env = "LOCALNAME_CONFIG")]
    config: Option<PathBuf>,

    /// Output format for scripts and agents.
    #[arg(long, global = true, value_enum, default_value = "human")]
    output: OutputFormat,

    /// Disable all interactive behavior.
    #[arg(long, global = true)]
    non_interactive: bool,

    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Print build and schema information.
    Version,
    /// Print the JSON Schema for structured command output.
    Schema,
    /// Print the version-matched agent skill and generated CLI reference.
    Skill,
    /// Inspect the host and create or verify a safe DNS setup.
    Setup(setup::SetupArgs),
    /// Run the DNS service.
    Serve(ServeArgs),
    /// Show service and resolution health.
    Status {
        /// Exit unsuccessfully unless the configured DNS listener is healthy.
        #[arg(long)]
        check: bool,
    },
    /// Diagnose each DNS and network layer.
    Diagnose,
    /// Query a DNS server.
    Resolve(health::ResolveArgs),
    /// Add a local name.
    Add(records::ChangeArgs),
    /// Remove a local name, or one of its values.
    Remove(records::RemoveArgs),
    /// List local records.
    List,
    /// List configuration revisions that can be restored.
    Revisions,
    /// Restore a previous configuration revision as a new revision.
    Rollback(records::RollbackArgs),
    /// Route service names to LAN backends through the optional HTTP proxy.
    Service {
        #[command(subcommand)]
        command: services::ServiceCommand,
    },
    /// Serve proxied services over HTTPS with an explicit trust mode.
    #[cfg(feature = "https")]
    Https {
        #[command(subcommand)]
        command: https::HttpsCommand,
    },
    /// Turn the optional HTTP/WebSocket proxy on or off.
    Proxy {
        #[command(subcommand)]
        command: services::ProxyCommand,
    },
    /// Point this device at localname when the router cannot advertise it.
    Client {
        #[command(subcommand)]
        command: client::ClientCommand,
    },
    /// Point the home router's DHCP DNS setting at localname (OpenWrt, over SSH).
    Router {
        #[command(subcommand)]
        command: router::RouterCommand,
    },
    /// Back up or restore the configuration, its revisions, and integration records.
    Backup {
        #[command(subcommand)]
        command: backup::BackupCommand,
    },
    /// Run localname as a system service that starts at boot and restarts on failure.
    Daemon {
        #[command(subcommand)]
        command: daemon::DaemonCommand,
    },
    /// Validate configuration.
    Config {
        #[command(subcommand)]
        command: ConfigCommand,
    },
}

#[derive(Debug, Args)]
struct ServeArgs {
    /// Bind listeners, then permanently switch to this account before reading client data
    /// (Unix; requires starting as root). The configuration directory must be writable by it.
    #[arg(long)]
    user: Option<String>,
}

#[derive(Debug, Subcommand)]
enum ConfigCommand {
    /// Validate a configuration file without changing it.
    Check { path: Option<PathBuf> },
    /// Print the active configuration.
    Show,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
pub(crate) enum QueryType {
    A,
    Aaaa,
    Cname,
    Ptr,
    Any,
    Soa,
}

impl From<QueryType> for RecordType {
    fn from(value: QueryType) -> Self {
        match value {
            QueryType::A => Self::A,
            QueryType::Aaaa => Self::AAAA,
            QueryType::Cname => Self::CNAME,
            QueryType::Ptr => Self::PTR,
            QueryType::Any => Self::ANY,
            QueryType::Soa => Self::SOA,
        }
    }
}

/// A committed change whose read-back failed. Output still reports the new revision and
/// the exact rollback command, because the change cannot be assumed absent.
#[derive(Debug, thiserror::Error)]
#[error("change committed at revision {revision}, but verification failed: {message}")]
pub(crate) struct VerificationError {
    pub command: &'static str,
    pub data: Value,
    pub revision: u64,
    pub previous_revision: u64,
    pub message: String,
}

/// A failed command whose output still carries its data, such as a blocked setup plan or
/// a failed end-to-end check, so agents can act on the details.
#[derive(Debug, thiserror::Error)]
#[error("{message}")]
pub(crate) struct ReportedError {
    pub command: &'static str,
    pub code: ErrorCode,
    pub data: Value,
    pub verification: Option<Value>,
    pub next_actions: Vec<String>,
    pub rollback: Option<String>,
    pub message: String,
    /// Printed before the error line in human output.
    pub human: String,
}

/// Parse arguments, run the command, and render errors in the selected format.
pub fn main() -> ExitCode {
    let cli = Cli::parse();
    if let Command::Daemon {
        command: daemon::DaemonCommand::Run,
    } = cli.command
    {
        return daemon::run_service(cli.config.clone());
    }
    // The service gets a small worker pool; one-shot commands need only one thread.
    let runtime = if matches!(cli.command, Command::Serve(_)) {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(
                std::thread::available_parallelism()
                    .map_or(2, std::num::NonZero::get)
                    .clamp(2, 4),
            )
            .enable_all()
            .build()
    } else {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
    };
    match runtime {
        Ok(runtime) => runtime.block_on(run(cli)),
        Err(error) => {
            eprintln!("localname: failed to start runtime: {error}");
            ExitCode::from(ErrorCode::Internal.exit_code())
        }
    }
}

async fn run(cli: Cli) -> ExitCode {
    let output = cli.output;
    init_tracing(matches!(cli.output, OutputFormat::Json));
    let path = cli.config.clone().unwrap_or_else(default_config_path);
    match execute(cli, ConfigStore::new(path.clone())).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            let verification = error.downcast_ref::<VerificationError>();
            let reported = error.downcast_ref::<ReportedError>();
            let code = if verification.is_some() {
                ErrorCode::VerificationFailed
            } else if let Some(reported) = reported {
                reported.code
            } else {
                classify(&error)
            };
            if matches!(output, OutputFormat::Json) {
                let mut envelope = Envelope::success("error", false, None, Value::Null);
                envelope.ok = false;
                if let Some(verification) = verification {
                    envelope.command = verification.command;
                    envelope.changed = true;
                    envelope.revision = Some(verification.revision);
                    envelope.data = verification.data.clone();
                    envelope.verification =
                        Some(json!({"status": "failed", "scope": "configured_listener"}));
                    envelope.rollback =
                        Some(rollback_command(&path, verification.previous_revision));
                }
                if let Some(reported) = reported {
                    envelope.command = reported.command;
                    envelope.data = reported.data.clone();
                    envelope.verification.clone_from(&reported.verification);
                    envelope.next_actions.clone_from(&reported.next_actions);
                    envelope.rollback.clone_from(&reported.rollback);
                    envelope.changed = reported.rollback.is_some();
                }
                envelope.error = Some(ErrorBody {
                    code: code.as_str(),
                    message: format!("{error:#}"),
                });
                if let Ok(text) = serde_json::to_string(&envelope) {
                    println!("{text}");
                }
            } else {
                if let Some(reported) = reported
                    && !reported.human.is_empty()
                {
                    println!("{}", reported.human);
                }
                eprintln!("localname: {error:#}");
            }
            ExitCode::from(code.exit_code())
        }
    }
}

fn init_tracing(json_output: bool) {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("warn"));
    let builder = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false);
    if json_output {
        builder.with_writer(std::io::stderr).compact().init();
    } else {
        builder.compact().init();
    }
}

async fn execute(cli: Cli, store: ConfigStore) -> Result<()> {
    let output = cli.output;
    let non_interactive = cli.non_interactive;
    match cli.command {
        Command::Version => {
            let data = json!({
                "version": env!("CARGO_PKG_VERSION"),
                "config_schema": crate::config::CURRENT_SCHEMA,
                "json_schema": "1",
                "control_protocol": crate::control::PROTOCOL_VERSION,
                "rust_msrv": env!("CARGO_PKG_RUST_VERSION"),
            });
            print_result(
                output,
                Envelope::success("version", false, None, data),
                || {
                    format!(
                        "localname {} (config schema {})",
                        env!("CARGO_PKG_VERSION"),
                        crate::config::CURRENT_SCHEMA
                    )
                },
            )
        }
        Command::Schema => {
            println!("{OUTPUT_SCHEMA}");
            Ok(())
        }
        Command::Skill => {
            let data = json!({
                "version": env!("CARGO_PKG_VERSION"),
                "instructions": SKILL,
                "cli_reference": command_reference(),
                "output_schema": serde_json::from_str::<Value>(OUTPUT_SCHEMA)?
            });
            print_result(
                output,
                Envelope::success("skill", false, None, data),
                || SKILL.into(),
            )
        }
        Command::Setup(args) => setup::setup(output, &store, &args).await,
        Command::Serve(args) => serve(store, args).await,
        Command::Status { check } => health::status(output, &store, check).await,
        Command::Diagnose => health::diagnose(output, &store).await,
        Command::Resolve(args) => health::resolve(output, &store, args).await,
        Command::Add(args) => records::add(output, &store, &args).await,
        Command::Remove(args) => records::remove(output, &store, &args).await,
        Command::List => records::list(output, &store),
        Command::Revisions => records::revisions(output, &store),
        Command::Rollback(args) => records::rollback(output, &store, &args).await,
        Command::Service { command } => services::service(output, &store, command).await,
        Command::Proxy { command } => services::proxy(output, &store, &command),
        #[cfg(feature = "https")]
        Command::Https { command } => https::run(output, non_interactive, &store, command).await,
        Command::Client { command } => client::run(output, &command).await,
        Command::Router { command } => router::run(output, non_interactive, &store, command).await,
        Command::Backup { command } => backup::run(output, &store, &command),
        Command::Daemon { command } => daemon::run(output, &store, command).await,
        Command::Config { command } => config_command(output, &store, command),
    }
}

pub const OUTPUT_SCHEMA: &str = include_str!("../../schemas/output.schema.json");
pub const SKILL: &str = include_str!("../../skills/localname/SKILL.md");

/// Recursively rendered help for every command, so agents never scrape human output.
pub fn command_reference() -> Vec<Value> {
    fn walk(mut command: clap::Command, path: &str, references: &mut Vec<Value>) {
        references.push(json!({"command": path, "help": command.render_long_help().to_string()}));
        for child in command.get_subcommands() {
            let child_path = format!("{path} {}", child.get_name());
            walk(child.clone(), &child_path, references);
        }
    }
    let mut references = Vec::new();
    walk(Cli::command(), "localname", &mut references);
    references
}

async fn serve(store: ConfigStore, args: ServeArgs) -> Result<()> {
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    tokio::spawn(async move {
        #[cfg(unix)]
        {
            if let Ok(mut terminate) =
                tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            {
                tokio::select! {
                    _ = tokio::signal::ctrl_c() => {},
                    _ = terminate.recv() => {},
                }
            } else {
                let _ = tokio::signal::ctrl_c().await;
            }
        }
        #[cfg(not(unix))]
        let _ = tokio::signal::ctrl_c().await;
        let _ = shutdown_tx.send(true);
    });
    serve_until(store, args.user.as_deref(), shutdown_rx, || {}).await
}

/// Bind the listeners, drop privileges, call `ready`, and serve until `shutdown` fires.
pub(crate) async fn serve_until(
    store: ConfigStore,
    user: Option<&str>,
    shutdown: watch::Receiver<bool>,
    ready: impl FnOnce(),
) -> Result<()> {
    let config = store.load()?;
    let listeners = crate::Listeners::bind_config(&config).await?;
    if let Some(user) = user {
        crate::privilege::drop_to(user)?;
        tracing::info!(%user, "dropped root privileges after binding listeners");
    } else if crate::privilege::is_root() {
        tracing::warn!(
            "running as root; use --user, a service account with CAP_NET_BIND_SERVICE, or an unprivileged port"
        );
    }
    let server = DnsServer::new(store, config)?;
    ready();
    server.run_with(listeners, shutdown).await
}

fn config_command(output: OutputFormat, store: &ConfigStore, command: ConfigCommand) -> Result<()> {
    match command {
        ConfigCommand::Check { path } => {
            let selected = path.map_or_else(|| store.clone(), ConfigStore::new);
            let config = selected.load()?;
            print_result(
                output,
                Envelope::success(
                    "config check",
                    false,
                    Some(config.revision),
                    json!({"path": selected.path(), "valid": true}),
                ),
                || {
                    format!(
                        "✓ {} is valid (revision {})",
                        selected.path().display(),
                        config.revision
                    )
                },
            )
        }
        ConfigCommand::Show => {
            let config = store.load()?;
            let text = toml::to_string_pretty(&config)?;
            match output {
                OutputFormat::Human => {
                    print!("{text}");
                    Ok(())
                }
                OutputFormat::Json => print_result(
                    output,
                    Envelope::success("config show", false, Some(config.revision), config),
                    String::new,
                ),
            }
        }
    }
}

#[allow(clippy::needless_pass_by_value)]
pub(crate) fn print_result<T, F>(
    format: OutputFormat,
    envelope: Envelope<T>,
    human: F,
) -> Result<()>
where
    T: Serialize,
    F: FnOnce() -> String,
{
    match format {
        OutputFormat::Human => println!("{}", human()),
        OutputFormat::Json => println!("{}", serde_json::to_string(&envelope)?),
    }
    Ok(())
}

/// `LOCALNAME_CONFIG`, else this user's configuration if it exists, else the installed
/// service's configuration if this account can see it, else this user's path.
fn default_config_path() -> PathBuf {
    if let Some(path) = env::var_os("LOCALNAME_CONFIG") {
        return path.into();
    }
    let user = dirs::config_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("localname")
        .join("config.toml");
    let service = crate::daemon::service_config_path();
    if !user.exists() && service.exists() {
        return service;
    }
    user
}

pub(crate) fn check_revision(expected: Option<u64>, current: u64) -> Result<()> {
    if let Some(expected) = expected
        && expected != current
    {
        return Err(coded(
            ErrorCode::Conflict,
            format!("stale revision: expected {expected}, current is {current}"),
        ));
    }
    Ok(())
}

/// A shell command that restores `revision` for the exact configuration that was changed.
pub(crate) fn rollback_command(path: &Path, revision: u64) -> String {
    let absolute = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
    // Windows canonical paths are verbatim (`\\?\C:\...`); show the ordinary form.
    #[cfg(windows)]
    let absolute = absolute
        .to_str()
        .and_then(|text| text.strip_prefix(r"\\?\"))
        .filter(|rest| !rest.starts_with("UNC\\"))
        .map_or(absolute.clone(), std::path::PathBuf::from);
    #[cfg(unix)]
    let quoted = format!("'{}'", absolute.to_string_lossy().replace('\'', "'\\''"));
    #[cfg(not(unix))]
    let quoted = format!("'{}'", absolute.to_string_lossy().replace('\'', "''"));
    format!("localname --config {quoted} rollback {revision}")
}

pub(crate) fn private_client_networks() -> Vec<ipnet::IpNet> {
    crate::config::PRIVATE_NETWORKS
        .iter()
        .map(|network| network.parse().expect("constant CIDR"))
        .collect()
}

pub(crate) fn record_kind(value: &str) -> RecordType {
    match value.parse::<IpAddr>() {
        Ok(IpAddr::V4(_)) => RecordType::A,
        Ok(IpAddr::V6(_)) => RecordType::AAAA,
        Err(_) => RecordType::CNAME,
    }
}

pub(crate) fn first_listener(config: &crate::Config) -> SocketAddr {
    config.listen[0]
}
