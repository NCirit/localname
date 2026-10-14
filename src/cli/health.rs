use std::{net::SocketAddr, time::Duration};

use anyhow::Result;
use clap::Args;
use hickory_proto::rr::RecordType;
use serde::Serialize;
use serde_json::{Value, json};

use super::{QueryType, first_listener, print_result};
use crate::{
    Config, ConfigStore,
    control::{self, DaemonStatus, Request},
    error::{ErrorCode, coded},
    integration::{NetworkFacts, inspect_network},
    output::{Envelope, OutputFormat},
    query_server,
};

#[derive(Debug, Args)]
pub struct ResolveArgs {
    name: String,
    #[arg(long, value_enum, default_value = "a")]
    record_type: QueryType,
    /// Query this server instead of the configured listener.
    #[arg(long)]
    server: Option<SocketAddr>,
    #[arg(long, default_value_t = 2_000)]
    timeout_ms: u64,
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
    daemon: Option<DaemonStatus>,
}

#[derive(Debug, Serialize)]
struct DiagnoseData {
    network: NetworkFacts,
    configuration: Value,
    daemon: Value,
    resolution: Value,
}

/// Query the zone SOA from the first listener. Healthy means an authoritative positive answer.
async fn probe(config: &Config) -> (bool, String, Value) {
    match query_server(
        first_listener(config),
        &config.zone,
        RecordType::SOA,
        Duration::from_millis(750),
    )
    .await
    {
        Ok(result)
            if result.authoritative
                && result.response_code == "NoError"
                && !result.answers.is_empty() =>
        {
            (
                true,
                format!("DNS listener answered in {:.2} ms", result.elapsed_ms),
                json!(result),
            )
        }
        Ok(result) => (
            false,
            format!(
                "DNS listener returned an unexpected {} response",
                result.response_code
            ),
            json!(result),
        ),
        Err(error) => (
            false,
            format!("DNS listener did not answer: {error:#}"),
            Value::Null,
        ),
    }
}

fn daemon_status(store: &ConfigStore) -> Result<Option<DaemonStatus>> {
    Ok(control::send_if_running(store, &Request::Status)?.and_then(|response| response.status))
}

pub async fn status(output: OutputFormat, store: &ConfigStore, check: bool) -> Result<()> {
    if !store.exists() {
        if check {
            return Err(coded(
                ErrorCode::Unavailable,
                "DNS service unavailable: configuration is not initialized",
            ));
        }
        let data = StatusData {
            installed: false,
            config_path: store.path().display().to_string(),
            revision: None,
            zone: None,
            listeners: Vec::new(),
            healthy: false,
            detail: "configuration is not initialized".into(),
            daemon: None,
        };
        return print_result(
            output,
            Envelope::success("status", false, None, data),
            || "localname is not configured; run `localname setup`".into(),
        );
    }
    let config = store.load()?;
    let (healthy, detail, _) = probe(&config).await;
    // A control failure must not hide DNS health; status reports what it could observe.
    let daemon = daemon_status(store).unwrap_or(None);
    let mut warnings = Vec::new();
    if let Some(daemon) = &daemon
        && daemon.revision != config.revision
    {
        warnings.push(format!(
            "daemon serves revision {} but configuration is at revision {}",
            daemon.revision, config.revision
        ));
    }
    if check && !healthy {
        return Err(coded(
            ErrorCode::Unavailable,
            format!("DNS service unavailable: {detail}"),
        ));
    }
    let human = match &daemon {
        Some(daemon) => format!(
            "{detail}\nrevision {} · {} queries ({} local, {} forwarded, {} cached, {} refused, {} errors) · up {}s",
            daemon.revision,
            daemon.metrics.queries,
            daemon.metrics.local,
            daemon.metrics.forwarded,
            daemon.metrics.cache_hits,
            daemon.metrics.refused,
            daemon.metrics.errors,
            daemon.uptime_seconds
        ),
        None => detail.clone(),
    };
    let data = StatusData {
        installed: true,
        config_path: store.path().display().to_string(),
        revision: Some(config.revision),
        zone: Some(config.zone.clone()),
        listeners: config.listen.clone(),
        healthy,
        detail,
        daemon,
    };
    let mut envelope = Envelope::success("status", false, data.revision, data);
    envelope.warnings = warnings;
    print_result(output, envelope, || human)
}

pub async fn diagnose(output: OutputFormat, store: &ConfigStore) -> Result<()> {
    let network = inspect_network();
    let mut next_actions = Vec::new();
    let (configuration, daemon, resolution, revision) = if store.exists() {
        match store.load() {
            Ok(config) => {
                let (healthy, detail, result) = probe(&config).await;
                let daemon = match daemon_status(store) {
                    Ok(Some(status)) => json!({"status": "running", "detail": status}),
                    Ok(None) => json!({"status": "not_running"}),
                    Err(error) => json!({"status": "unreachable", "error": format!("{error:#}")}),
                };
                if !healthy {
                    next_actions.push(
                        "Start the service with `localname serve` (or the installed service) and check that the listener port is free.".into(),
                    );
                }
                (
                    json!({"status": "valid", "path": store.path(), "revision": config.revision, "zone": config.zone, "listeners": config.listen}),
                    daemon,
                    json!({"status": if healthy { "passed" } else { "failed" }, "detail": detail, "result": result}),
                    Some(config.revision),
                )
            }
            Err(error) => {
                next_actions.push(
                    "Fix the configuration or restore a previous revision with `localname rollback`.".into(),
                );
                (
                    json!({"status": "invalid", "error": format!("{error:#}")}),
                    json!({"status": "skipped"}),
                    json!({"status": "skipped"}),
                    None,
                )
            }
        }
    } else {
        next_actions.push("Run `localname setup` to create a configuration.".into());
        (
            json!({"status": "missing", "path": store.path()}),
            json!({"status": "skipped"}),
            json!({"status": "skipped"}),
            None,
        )
    };
    let data = DiagnoseData {
        network,
        configuration,
        daemon,
        resolution,
    };
    let human = format!(
        "configuration: {}\ndaemon: {}\nresolution: {}",
        data.configuration["status"].as_str().unwrap_or("unknown"),
        data.daemon["status"].as_str().unwrap_or("unknown"),
        data.resolution["status"].as_str().unwrap_or("unknown"),
    );
    let mut envelope = Envelope::success("diagnose", false, revision, data);
    envelope.next_actions = next_actions;
    print_result(output, envelope, || human)
}

pub async fn resolve(output: OutputFormat, store: &ConfigStore, args: ResolveArgs) -> Result<()> {
    let config = if args.server.is_some() {
        store.load_or_default()?
    } else {
        store.load()?
    };
    let name = config.query_name(&args.name)?;
    let server = args.server.unwrap_or_else(|| first_listener(&config));
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
    let revision = store.exists().then_some(config.revision);
    print_result(
        output,
        Envelope::success("resolve", false, revision, result),
        || human,
    )
}
