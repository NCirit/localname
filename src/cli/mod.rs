mod health;
mod records;
mod setup;

use std::{
    env,
    net::{IpAddr, SocketAddr},
    path::{Path, PathBuf},
    process::ExitCode,
};

use anyhow::Result;
use clap::{CommandFactory, Parser, Subcommand, ValueEnum};
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
    Serve,
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
    /// Validate configuration.
    Config {
        #[command(subcommand)]
        command: ConfigCommand,
    },
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

/// Parse arguments, run the command, and render errors in the selected format.
pub async fn run() -> ExitCode {
    let cli = Cli::parse();
    let output = cli.output;
    init_tracing(matches!(cli.output, OutputFormat::Json));
    let path = cli.config.clone().unwrap_or_else(default_config_path);
    match execute(cli, ConfigStore::new(path.clone())).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            let verification = error.downcast_ref::<VerificationError>();
            let code = if verification.is_some() {
                ErrorCode::VerificationFailed
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
                envelope.error = Some(ErrorBody {
                    code: code.as_str(),
                    message: format!("{error:#}"),
                });
                if let Ok(text) = serde_json::to_string(&envelope) {
                    println!("{text}");
                }
            } else {
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
        Command::Setup(args) => setup::setup(output, &store, &args),
        Command::Serve => serve(store).await,
        Command::Status { check } => health::status(output, &store, check).await,
        Command::Diagnose => health::diagnose(output, &store).await,
        Command::Resolve(args) => health::resolve(output, &store, args).await,
        Command::Add(args) => records::add(output, &store, &args).await,
        Command::Remove(args) => records::remove(output, &store, &args).await,
        Command::List => records::list(output, &store),
        Command::Revisions => records::revisions(output, &store),
        Command::Rollback(args) => records::rollback(output, &store, &args).await,
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

async fn serve(store: ConfigStore) -> Result<()> {
    let config = store.load()?;
    let server = DnsServer::new(store, config)?;
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
    server.run(shutdown_rx).await
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

fn default_config_path() -> PathBuf {
    if let Some(path) = env::var_os("LOCALNAME_CONFIG") {
        return path.into();
    }
    dirs::config_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("localname")
        .join("config.toml")
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
