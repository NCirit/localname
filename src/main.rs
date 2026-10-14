use std::{
    env,
    net::{IpAddr, SocketAddr},
    path::PathBuf,
    process::ExitCode,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::{Result, anyhow, bail};
use clap::{Args, CommandFactory, Parser, Subcommand, ValueEnum};
use hickory_proto::rr::RecordType;
use ipnet::IpNet;
use localname::{
    Config, ConfigStore, DnsServer, RecordConfig,
    control::{self, Request},
    integration::{NetworkFacts, inspect_network},
    output::{Envelope, ErrorBody, OutputFormat},
    query_server,
};
use serde::Serialize;
use serde_json::{Value, json};
use tokio::sync::watch;
use tracing_subscriber::EnvFilter;

#[derive(Debug, Parser)]
#[command(name = "localname", version, about, propagate_version = true)]
struct Cli {
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
    Setup(SetupArgs),
    /// Run the DNS service.
    Serve,
    /// Show service and resolution health.
    Status,
    /// Diagnose each DNS and network layer.
    Diagnose,
    /// Query a DNS server.
    Resolve(ResolveArgs),
    /// Add a local name.
    Add(ChangeArgs),
    /// Remove a local name and all its values.
    Remove(RemoveArgs),
    /// List local records.
    List,
    /// Restore a previous configuration revision.
    Rollback { revision: u64 },
    /// Validate configuration.
    Config {
        #[command(subcommand)]
        command: ConfigCommand,
    },
}

#[derive(Debug, Args)]
struct SetupArgs {
    /// Only inspect the current state.
    #[arg(long, conflicts_with = "apply")]
    check: bool,
    /// Write the proposed localname configuration. Router changes remain manual.
    #[arg(long)]
    apply: bool,
    /// Prepare an unprivileged loopback instance for development.
    #[arg(long)]
    local: bool,
}

#[derive(Debug, Args)]
struct ResolveArgs {
    name: String,
    #[arg(long, value_enum, default_value = "a")]
    record_type: QueryType,
    #[arg(long)]
    server: Option<SocketAddr>,
    #[arg(long, default_value_t = 2_000)]
    timeout_ms: u64,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum QueryType {
    A,
    Aaaa,
    Cname,
    Ptr,
    Any,
}

impl From<QueryType> for RecordType {
    fn from(value: QueryType) -> Self {
        match value {
            QueryType::A => Self::A,
            QueryType::Aaaa => Self::AAAA,
            QueryType::Cname => Self::CNAME,
            QueryType::Ptr => Self::PTR,
            QueryType::Any => Self::ANY,
        }
    }
}

#[derive(Debug, Args)]
struct ChangeArgs {
    name: String,
    target: String,
    #[arg(long, default_value_t = 60)]
    ttl: u32,
    #[arg(long)]
    dry_run: bool,
    #[arg(long)]
    expect_revision: Option<u64>,
}

#[derive(Debug, Args)]
struct RemoveArgs {
    name: String,
    #[arg(long)]
    dry_run: bool,
    #[arg(long)]
    expect_revision: Option<u64>,
}

#[derive(Debug, Subcommand)]
enum ConfigCommand {
    Check { path: Option<PathBuf> },
    Show,
}

#[derive(Debug, Serialize)]
struct SetupPlan {
    plan_id: String,
    facts: NetworkFacts,
    config_path: String,
    listen: Option<SocketAddr>,
    router_dns_value: Option<IpAddr>,
    actions: Vec<String>,
    warnings: Vec<String>,
    applied: bool,
}

#[derive(Debug, Serialize)]
struct StatusData {
    installed: bool,
    config_path: String,
    revision: Option<u64>,
    zone: Option<String>,
    listeners: Vec<SocketAddr>,
    healthy: bool,
    detail: String,
}

#[derive(Debug, Serialize)]
struct DiagnoseData {
    network: NetworkFacts,
    configuration: Value,
    resolution: Value,
}

#[tokio::main(worker_threads = 2)]
async fn main() -> ExitCode {
    let cli = Cli::parse();
    let output = cli.output;
    init_tracing(matches!(cli.output, OutputFormat::Json));
    let path = cli.config.clone().unwrap_or_else(default_config_path);
    match execute(cli, ConfigStore::new(path)).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            let code = classify_exit(&error);
            if matches!(output, OutputFormat::Json) {
                let mut envelope = Envelope::success("error", false, None, Value::Null);
                envelope.ok = false;
                envelope.error = Some(ErrorBody {
                    code: match code {
                        3 => "INVALID_INPUT",
                        4 => "PERMISSION_REQUIRED",
                        5 => "CONFLICT",
                        6 => "UNAVAILABLE",
                        _ => "INTERNAL_ERROR",
                    },
                    message: format!("{error:#}"),
                });
                if let Ok(text) = serde_json::to_string(&envelope) {
                    println!("{text}");
                }
            } else {
                eprintln!("localname: {error:#}");
            }
            ExitCode::from(code)
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
    match cli.command {
        Command::Version => {
            let data = json!({
                "version": env!("CARGO_PKG_VERSION"),
                "config_schema": localname::config::CURRENT_SCHEMA,
                "json_schema": "1",
                "rust_msrv": "1.88"
            });
            print_result(
                cli.output,
                Envelope::success("version", false, None, data),
                || format!("localname {} (config schema 1)", env!("CARGO_PKG_VERSION")),
            )
        }
        Command::Schema => {
            println!("{}", include_str!("../schemas/output.schema.json"));
            Ok(())
        }
        Command::Skill => {
            let instructions = include_str!("../skills/localname/SKILL.md");
            let data = json!({
                "version": env!("CARGO_PKG_VERSION"),
                "instructions": instructions,
                "cli_reference": command_reference(Cli::command(), "localname"),
                "output_schema": serde_json::from_str::<Value>(include_str!("../schemas/output.schema.json"))?
            });
            print_result(
                cli.output,
                Envelope::success("skill", false, None, data),
                || instructions.into(),
            )
        }
        Command::Setup(args) => setup(cli.output, &store, &args),
        Command::Serve => serve(store).await,
        Command::Status => status(cli.output, &store).await,
        Command::Diagnose => diagnose(cli.output, &store).await,
        Command::Resolve(args) => resolve(cli.output, &store, args).await,
        Command::Add(args) => add(cli.output, &store, &args),
        Command::Remove(args) => remove(cli.output, &store, &args),
        Command::List => list(cli.output, &store),
        Command::Rollback { revision } => rollback(cli.output, &store, revision),
        Command::Config { command } => config_command(cli.output, &store, command),
    }
}

fn command_reference(mut command: clap::Command, path: &str) -> Vec<Value> {
    let mut references =
        vec![json!({"command": path, "help": command.render_long_help().to_string()})];
    for child in command.get_subcommands() {
        let child_path = format!("{path} {}", child.get_name());
        references.extend(command_reference(child.clone(), &child_path));
    }
    references
}

#[allow(clippy::too_many_lines)]
fn setup(output: OutputFormat, store: &ConfigStore, args: &SetupArgs) -> Result<()> {
    let facts = inspect_network();
    let listen = if args.local {
        Some("127.0.0.1:5354".parse()?)
    } else {
        facts
            .lan_address
            .map(|address| SocketAddr::new(address, 53))
    };
    let mut warnings = Vec::new();
    if facts.lan_address.is_none() {
        warnings
            .push("No LAN address was detected; connect this host to the target network.".into());
    }
    if !facts.port_53_available {
        warnings
            .push("UDP port 53 is unavailable or requires elevated service permissions.".into());
    }
    let actions = facts.lan_address.map_or_else(
        || vec!["Resolve LAN connectivity, then run setup again.".into()],
        |address| {
            vec![
                format!("Start localname on {address}:53."),
                format!("Set the router LAN/DHCP DNS server to {address}."),
                "Renew one client's network lease and run localname status from that client."
                    .into(),
            ]
        },
    );
    let plan_id = format!(
        "setup-{}-{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
        facts.lan_address.map_or_else(
            || "unknown".into(),
            |ip| ip.to_string().replace([':', '.'], "-")
        )
    );
    let mut plan = SetupPlan {
        plan_id,
        router_dns_value: facts.lan_address,
        facts,
        config_path: store.path().display().to_string(),
        listen,
        actions,
        warnings,
        applied: false,
    };

    if args.apply {
        let listen = plan
            .listen
            .ok_or_else(|| anyhow!("cannot apply setup without a detected LAN address"))?;
        let mut config = Config {
            listen: vec![listen],
            allowed_clients: if args.local {
                Config::default().allowed_clients
            } else {
                private_client_networks()
            },
            ..Config::default()
        };
        let discovered: Vec<SocketAddr> = plan
            .facts
            .current_resolvers
            .iter()
            .copied()
            .filter(|address| {
                !address.is_loopback()
                    && *address != listen.ip()
                    && !matches!(address, IpAddr::V6(ip) if ip.is_unicast_link_local())
            })
            .map(|address| SocketAddr::new(address, 53))
            .collect();
        if !discovered.is_empty() {
            config.upstreams = discovered;
        }
        config.validate()?;
        if store.exists() {
            bail!("configuration already exists; use config check or explicit record commands");
        }
        store.initialize(&config)?;
        plan.applied = true;
    }

    let human_applied = plan.applied;
    let human_address = plan.router_dns_value;
    let human_actions = plan.actions.clone();
    let mut envelope = Envelope::success("setup", plan.applied, plan.applied.then_some(0), plan);
    envelope.warnings.clone_from(&envelope.data.warnings);
    envelope.next_actions.clone_from(&human_actions);
    print_result(output, envelope, move || {
        if human_applied && args.local {
            "Loopback configuration created at 127.0.0.1:5354. Start `localname serve`.".into()
        } else if human_applied {
            format!(
                "Configuration created. Set your router's LAN/DHCP DNS server to {} and then start `localname serve`.",
                human_address.map_or_else(|| "the detected address".into(), |ip| ip.to_string())
            )
        } else if args.check {
            format!("Setup check complete.\n{}", human_actions.join("\n"))
        } else {
            format!(
                "Setup plan:\n{}\nRun again with --apply to create the configuration.",
                human_actions.join("\n")
            )
        }
    })
}

fn private_client_networks() -> Vec<IpNet> {
    [
        "127.0.0.0/8",
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "::1/128",
        "fc00::/7",
        "fe80::/10",
    ]
    .into_iter()
    .map(|network| network.parse().expect("constant CIDR"))
    .collect()
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

async fn status(output: OutputFormat, store: &ConfigStore) -> Result<()> {
    if !store.exists() {
        let data = StatusData {
            installed: false,
            config_path: store.path().display().to_string(),
            revision: None,
            zone: None,
            listeners: Vec::new(),
            healthy: false,
            detail: "configuration is not initialized".into(),
        };
        return print_result(
            output,
            Envelope::success("status", false, None, data),
            || "localname is not configured; run `localname setup`".into(),
        );
    }
    let config = store.load()?;
    let health = query_server(
        config.listen[0],
        &config.zone,
        RecordType::SOA,
        Duration::from_millis(750),
    )
    .await;
    let (healthy, detail) = match health {
        Ok(result) => (
            true,
            format!("DNS listener answered in {:.2} ms", result.elapsed_ms),
        ),
        Err(error) => (false, format!("DNS listener did not answer: {error:#}")),
    };
    let data = StatusData {
        installed: true,
        config_path: store.path().display().to_string(),
        revision: Some(config.revision),
        zone: Some(config.zone),
        listeners: config.listen,
        healthy,
        detail: detail.clone(),
    };
    print_result(
        output,
        Envelope::success("status", false, data.revision, data),
        || detail,
    )
}

async fn diagnose(output: OutputFormat, store: &ConfigStore) -> Result<()> {
    let network = inspect_network();
    let (configuration, resolution, revision) = if store.exists() {
        match store.load() {
            Ok(config) => {
                let result = query_server(
                    config.listen[0],
                    &config.zone,
                    RecordType::SOA,
                    Duration::from_millis(750),
                )
                .await;
                (
                    json!({"status": "valid", "path": store.path(), "revision": config.revision, "zone": config.zone, "listeners": config.listen}),
                    match result {
                        Ok(result) => json!({"status": "passed", "result": result}),
                        Err(error) => json!({"status": "failed", "error": format!("{error:#}")}),
                    },
                    Some(config.revision),
                )
            }
            Err(error) => (
                json!({"status": "invalid", "error": format!("{error:#}")}),
                json!({"status": "skipped"}),
                None,
            ),
        }
    } else {
        (
            json!({"status": "missing", "path": store.path()}),
            json!({"status": "skipped"}),
            None,
        )
    };
    let data = DiagnoseData {
        network,
        configuration,
        resolution,
    };
    print_result(
        output,
        Envelope::success("diagnose", false, revision, data),
        || "Diagnosis complete. Use --output json for layer-by-layer details.".into(),
    )
}

async fn resolve(output: OutputFormat, store: &ConfigStore, args: ResolveArgs) -> Result<()> {
    let config = store.load()?;
    let name = config.fqdn(&args.name)?;
    let server = args.server.unwrap_or(config.listen[0]);
    let result = query_server(
        server,
        &name,
        args.record_type.into(),
        Duration::from_millis(args.timeout_ms),
    )
    .await?;
    let human = format!(
        "{} {}: {}",
        result.name,
        result.record_type,
        if result.answers.is_empty() {
            result.response_code.clone()
        } else {
            result.answers.join(", ")
        }
    );
    print_result(
        output,
        Envelope::success("resolve", false, Some(config.revision), result),
        || human,
    )
}

fn add(output: OutputFormat, store: &ConfigStore, args: &ChangeArgs) -> Result<()> {
    let current = store.load()?;
    let name = current.fqdn(&args.name)?;
    let mut preview = current.clone();
    upsert_record(&mut preview, &name, &args.target, args.ttl);
    preview.validate()?;
    let changed = preview != current;
    if args.dry_run {
        let data = json!({"name": name, "value": args.target, "ttl": args.ttl, "preview": true});
        return print_result(
            output,
            Envelope::success("add", changed, Some(current.revision), data),
            || {
                if changed {
                    format!("Would add {name} → {}", args.target)
                } else {
                    format!("{name} already has the requested value")
                }
            },
        );
    }
    let target = args.target.parse::<IpAddr>().map_or_else(
        |_| current.fqdn(&args.target),
        |address| Ok(address.to_string()),
    )?;
    let record = preview
        .records
        .iter()
        .find(|record| record.name == name && record.value == target)
        .cloned()
        .ok_or_else(|| anyhow!("record preview missing"))?;
    let request = Request::Add {
        record,
        expected_revision: args.expect_revision.unwrap_or(current.revision),
    };
    let next = control::request_if_running(store, &request)?
        .map_or_else(|| control::apply(store, request), Ok)?;
    let changed = next.revision != current.revision;
    let data = json!({"name": name, "value": args.target, "ttl": args.ttl});
    let mut envelope = Envelope::success("add", changed, Some(next.revision), data);
    if changed {
        envelope.rollback = Some(format!("localname rollback {}", current.revision));
    }
    print_result(output, envelope, || {
        if changed {
            format!("✓ {name} → {}", args.target)
        } else {
            format!("✓ {name} already configured")
        }
    })
}

fn upsert_record(config: &mut Config, name: &str, target: &str, ttl: u32) {
    let target = target.parse::<IpAddr>().map_or_else(
        |_| config.fqdn(target).unwrap_or_else(|_| target.to_owned()),
        |address| address.to_string(),
    );
    let candidate = RecordConfig {
        name: name.into(),
        value: target,
        ttl,
    };
    if let Some(record) = config
        .records
        .iter_mut()
        .find(|record| record.name == candidate.name && record.value == candidate.value)
    {
        record.ttl = ttl;
        return;
    }
    if !config.records.contains(&candidate) {
        config.records.push(candidate);
    }
}

fn remove(output: OutputFormat, store: &ConfigStore, args: &RemoveArgs) -> Result<()> {
    let current = store.load()?;
    let name = current.fqdn(&args.name)?;
    let existing = current
        .records
        .iter()
        .filter(|record| record.name == name)
        .count();
    if args.dry_run {
        let data = json!({"name": name, "records_removed": existing, "preview": true});
        return print_result(
            output,
            Envelope::success("remove", existing > 0, Some(current.revision), data),
            || format!("Would remove {existing} record(s) for {name}"),
        );
    }
    let request = Request::Remove {
        name: name.clone(),
        expected_revision: args.expect_revision.unwrap_or(current.revision),
    };
    let next = control::request_if_running(store, &request)?
        .map_or_else(|| control::apply(store, request), Ok)?;
    let changed = next.revision != current.revision;
    let data = json!({"name": name, "records_removed": existing});
    let mut envelope = Envelope::success("remove", changed, Some(next.revision), data);
    if changed {
        envelope.rollback = Some(format!("localname rollback {}", current.revision));
    }
    print_result(output, envelope, || {
        format!("Removed {existing} record(s) for {name}")
    })
}

fn list(output: OutputFormat, store: &ConfigStore) -> Result<()> {
    let config = store.load()?;
    let records = config.records.clone();
    let human_records = records.clone();
    print_result(
        output,
        Envelope::success("list", false, Some(config.revision), records),
        move || {
            if human_records.is_empty() {
                "No local records configured.".into()
            } else {
                human_records
                    .iter()
                    .map(|record| format!("{}\t{}\t{}s", record.name, record.value, record.ttl))
                    .collect::<Vec<_>>()
                    .join("\n")
            }
        },
    )
}

fn rollback(output: OutputFormat, store: &ConfigStore, revision: u64) -> Result<()> {
    let current = store.load()?;
    let request = Request::Rollback {
        revision,
        expected_revision: current.revision,
    };
    let config = control::request_if_running(store, &request)?
        .map_or_else(|| control::apply(store, request), Ok)?;
    print_result(
        output,
        Envelope::success(
            "rollback",
            true,
            Some(config.revision),
            json!({"restored_from": revision}),
        ),
        || {
            format!(
                "Restored revision {revision} as new revision {}",
                config.revision
            )
        },
    )
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
fn print_result<T, F>(format: OutputFormat, envelope: Envelope<T>, human: F) -> Result<()>
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

fn classify_exit(error: &anyhow::Error) -> u8 {
    let message = format!("{error:#}").to_ascii_lowercase();
    if message.contains("permission") || message.contains("access denied") {
        4
    } else if message.contains("stale")
        || message.contains("conflict")
        || message.contains("already exists")
    {
        5
    } else if message.contains("timed out")
        || message.contains("unavailable")
        || message.contains("not found")
    {
        6
    } else if message.contains("invalid")
        || message.contains("unsupported")
        || message.contains("required")
    {
        3
    } else {
        70
    }
}
