//! `localname service` and `localname proxy`: opt-in host-to-port HTTP routing (M4a).

use std::{net::SocketAddr, time::Duration};

use anyhow::Result;
use clap::{Args, Subcommand};
use hickory_proto::rr::RecordType;
use serde_json::{Value, json};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    time,
};

use super::{
    VerificationError, check_revision, first_listener, print_result, records::commit,
    rollback_command,
};
use crate::{
    Config, ConfigStore, ServiceConfig,
    control::{self, Request},
    error::{ErrorCode, coded},
    output::{Envelope, OutputFormat},
    query_server,
};

#[derive(Debug, Subcommand)]
pub enum ServiceCommand {
    /// Route NAME to a backend: `localname service add photos 192.168.1.20:2342`.
    Add(AddArgs),
    /// Stop routing a service name.
    Remove(RemoveArgs),
    /// List routed services.
    List,
}

#[derive(Debug, Args)]
pub struct AddArgs {
    /// Short or fully qualified name; it resolves to the proxy.
    name: String,
    /// Backend address and port on the LAN.
    target: SocketAddr,
    #[arg(long)]
    dry_run: bool,
    #[arg(long)]
    expect_revision: Option<u64>,
}

#[derive(Debug, Args)]
pub struct RemoveArgs {
    name: String,
    #[arg(long)]
    dry_run: bool,
    #[arg(long)]
    expect_revision: Option<u64>,
}

#[derive(Debug, Subcommand)]
pub enum ProxyCommand {
    /// Turn on the HTTP/WebSocket proxy (the service must be stopped; start it afterwards).
    Enable(EnableArgs),
    /// Turn off the proxy, returning to DNS-only mode. Remove services first.
    Disable(RevisionArgs),
}

#[derive(Debug, Args)]
pub struct EnableArgs {
    /// Proxy addresses (repeatable). Defaults to port 80 on each DNS listener address.
    #[arg(long)]
    listen: Vec<SocketAddr>,
    #[arg(long)]
    dry_run: bool,
    #[arg(long)]
    expect_revision: Option<u64>,
}

#[derive(Debug, Args)]
pub struct RevisionArgs {
    #[arg(long)]
    dry_run: bool,
    #[arg(long)]
    expect_revision: Option<u64>,
}

pub async fn service(
    output: OutputFormat,
    store: &ConfigStore,
    command: ServiceCommand,
) -> Result<()> {
    match command {
        ServiceCommand::Add(args) => add(output, store, &args).await,
        ServiceCommand::Remove(args) => remove(output, store, &args).await,
        ServiceCommand::List => list(output, store),
    }
}

pub fn proxy(output: OutputFormat, store: &ConfigStore, command: &ProxyCommand) -> Result<()> {
    match command {
        ProxyCommand::Enable(args) => enable(output, store, args),
        ProxyCommand::Disable(args) => disable(output, store, args),
    }
}

/// Send one `HEAD /` through the proxy with `Host: name` and return the status code.
async fn probe(proxy: SocketAddr, name: &str) -> Result<u16> {
    let mut stream = time::timeout(Duration::from_secs(2), TcpStream::connect(proxy)).await??;
    let host = name.trim_end_matches('.');
    stream
        .write_all(
            format!("HEAD / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n").as_bytes(),
        )
        .await?;
    let mut response = Vec::new();
    // Backend timeouts take up to 65 s in the proxy; the status line is all that matters.
    time::timeout(Duration::from_secs(70), async {
        let mut buffer = [0_u8; 256];
        while !response.windows(2).any(|window| window == b"\r\n") {
            let read = stream.read(&mut buffer).await?;
            if read == 0 {
                break;
            }
            response.extend_from_slice(&buffer[..read]);
        }
        Ok::<_, std::io::Error>(())
    })
    .await??;
    let line = String::from_utf8_lossy(&response);
    line.split_whitespace()
        .nth(1)
        .and_then(|code| code.parse().ok())
        .ok_or_else(|| anyhow::anyhow!("proxy sent no HTTP status line"))
}

fn daemon_running(store: &ConfigStore) -> Result<bool> {
    Ok(control::send_if_running(store, &Request::Status)?.is_some())
}

#[allow(clippy::too_many_lines)]
async fn add(output: OutputFormat, store: &ConfigStore, args: &AddArgs) -> Result<()> {
    let current = store.load()?;
    check_revision(args.expect_revision, current.revision)?;
    let service = ServiceConfig {
        name: current.fqdn(&args.name)?,
        target: args.target,
        https: false,
    };
    let mut preview = current.clone();
    match preview
        .services
        .iter_mut()
        .find(|existing| existing.name == service.name)
    {
        Some(existing) => *existing = service.clone(),
        None => preview.services.push(service.clone()),
    }
    preview.validate()?;
    let changed = preview != current;
    let mut data = json!({"name": service.name, "target": service.target, "proxy": current.proxy_listen, "config_path": store.path()});
    if args.dry_run {
        data["preview"] = json!(true);
        let name = service.name.clone();
        return print_result(
            output,
            Envelope::success("service add", changed, Some(current.revision), data),
            || format!("Would route {name} → {}", args.target),
        );
    }
    let (applied, running) = commit(
        store,
        Request::AddService {
            service: service.clone(),
            expected_revision: args.expect_revision,
        },
    )?;
    let next = applied.config;
    let changed = applied.previous_revision != next.revision;
    let mut warnings = Vec::new();
    let verification = if running {
        let failure = |message: String| VerificationError {
            command: "service add",
            data: data.clone(),
            revision: next.revision,
            previous_revision: applied.previous_revision,
            message,
        };
        let answer = query_server(
            first_listener(&next),
            &service.name,
            RecordType::A,
            Duration::from_secs(1),
        )
        .await
        .map_err(|error| failure(format!("{error:#}")))?;
        let proxy = next.proxy_listen[0];
        if !next
            .proxy_listen
            .iter()
            .filter(|address| address.is_ipv4())
            .all(|address| {
                answer
                    .records
                    .iter()
                    .any(|record| record.value == address.ip().to_string())
            })
        {
            return Err(failure(format!("{} does not resolve to the proxy", service.name)).into());
        }
        let status = probe(proxy, &service.name)
            .await
            .map_err(|error| failure(format!("proxy did not answer: {error:#}")))?;
        if status == 404 {
            return Err(failure("the proxy does not route the new service".into()).into());
        }
        if matches!(status, 502 | 504) {
            warnings.push(format!(
                "The backend {} is not reachable right now (proxy answered {status}); requests fail until it is.",
                service.target
            ));
        }
        json!({"status": "passed", "scope": "configured_listener", "proxy_status": status})
    } else {
        json!({"status": "not_running", "scope": "configuration_only"})
    };
    let mut envelope = Envelope::success("service add", changed, Some(next.revision), data);
    envelope.verification = Some(verification);
    envelope.warnings = warnings;
    if changed {
        envelope.rollback = Some(rollback_command(store.path(), applied.previous_revision));
    }
    let name = service.name.trim_end_matches('.').to_owned();
    let first = next.proxy_listen[0];
    print_result(output, envelope, || {
        let port = if first.port() == 80 {
            String::new()
        } else {
            format!(":{}", first.port())
        };
        format!("✓ http://{name}{port}/ → {}", args.target)
    })
}

async fn remove(output: OutputFormat, store: &ConfigStore, args: &RemoveArgs) -> Result<()> {
    let current = store.load()?;
    check_revision(args.expect_revision, current.revision)?;
    let name = current.fqdn(&args.name)?;
    let exists = current.services.iter().any(|service| service.name == name);
    let mut data = json!({"name": name, "removed": exists, "config_path": store.path()});
    if args.dry_run {
        data["preview"] = json!(true);
        return print_result(
            output,
            Envelope::success("service remove", exists, Some(current.revision), data),
            || {
                if exists {
                    format!("Would stop routing {name}")
                } else {
                    format!("{name} is not a service")
                }
            },
        );
    }
    let (applied, running) = commit(
        store,
        Request::RemoveService {
            name: name.clone(),
            expected_revision: args.expect_revision,
        },
    )?;
    let next = applied.config;
    let changed = applied.previous_revision != next.revision;
    let verification = if running && !next.proxy_listen.is_empty() {
        let status = probe(next.proxy_listen[0], &name).await.unwrap_or(0);
        if status != 404 {
            return Err(VerificationError {
                command: "service remove",
                data,
                revision: next.revision,
                previous_revision: applied.previous_revision,
                message: format!("the proxy still routes {name} (status {status})"),
            }
            .into());
        }
        json!({"status": "passed", "scope": "configured_listener"})
    } else if running {
        json!({"status": "passed", "scope": "configured_listener"})
    } else {
        json!({"status": "not_running", "scope": "configuration_only"})
    };
    let mut envelope = Envelope::success("service remove", changed, Some(next.revision), data);
    envelope.verification = Some(verification);
    if changed {
        envelope.rollback = Some(rollback_command(store.path(), applied.previous_revision));
    }
    print_result(output, envelope, || format!("Stopped routing {name}"))
}

fn list(output: OutputFormat, store: &ConfigStore) -> Result<()> {
    let config = store.load()?;
    let human = if config.proxy_listen.is_empty() {
        "The proxy is off (DNS-only mode). Turn it on with `localname proxy enable`.".to_owned()
    } else if config.services.is_empty() {
        format!(
            "The proxy listens on {}; no services yet.",
            join(&config.proxy_listen)
        )
    } else {
        config
            .services
            .iter()
            .map(|service| format!("{}\t{}", service.name, service.target))
            .collect::<Vec<_>>()
            .join("\n")
    };
    let data = json!({"proxy_listen": config.proxy_listen, "services": config.services});
    print_result(
        output,
        Envelope::success("service list", false, Some(config.revision), data),
        || human,
    )
}

/// Proxy listener changes need a restart, so they are made only while the service is
/// stopped, under the offline writer lock.
fn change_listeners(
    output: OutputFormat,
    store: &ConfigStore,
    command: &'static str,
    dry_run: bool,
    expected: Option<u64>,
    listen: &[SocketAddr],
) -> Result<()> {
    let current = store.load()?;
    check_revision(expected, current.revision)?;
    let mut preview = current.clone();
    preview.proxy_listen = listen.to_vec();
    preview.validate()?;
    let changed = preview != current;
    let data: Value = json!({"proxy_listen": listen, "config_path": store.path()});
    if dry_run || !changed {
        let mut data = data;
        data["preview"] = json!(dry_run);
        return print_result(
            output,
            Envelope::success(command, changed, Some(current.revision), data),
            || {
                if changed {
                    format!("Would set proxy listeners to [{}]", join(listen))
                } else {
                    "No change.".into()
                }
            },
        );
    }
    if daemon_running(store)? {
        return Err(coded(
            ErrorCode::Conflict,
            "conflict: proxy listener changes need a restart; stop the localname service, run this again, then start it",
        ));
    }
    let _guard = store.acquire_offline_lock()?;
    let (previous, next) = store.mutate(expected, |config| {
        config.proxy_listen = listen.to_vec();
        Ok(())
    })?;
    let mut envelope = Envelope::success(command, true, Some(next.revision), data);
    envelope.verification = Some(json!({"status": "not_running", "scope": "configuration_only"}));
    envelope.rollback = Some(rollback_command(store.path(), previous.revision));
    envelope.next_actions = vec!["Start the localname service to apply the change.".into()];
    print_result(output, envelope, || {
        if listen.is_empty() {
            "Proxy turned off: DNS-only mode. Start the service to apply.".into()
        } else {
            format!(
                "Proxy will listen on {}. Start the service to apply.",
                join(listen)
            )
        }
    })
}

fn enable(output: OutputFormat, store: &ConfigStore, args: &EnableArgs) -> Result<()> {
    let config: Config = store.load()?;
    let listen: Vec<SocketAddr> = if args.listen.is_empty() {
        config
            .listen
            .iter()
            .map(|address| SocketAddr::new(address.ip(), 80))
            .collect()
    } else {
        args.listen.clone()
    };
    change_listeners(
        output,
        store,
        "proxy enable",
        args.dry_run,
        args.expect_revision,
        &listen,
    )
}

fn disable(output: OutputFormat, store: &ConfigStore, args: &RevisionArgs) -> Result<()> {
    let config = store.load()?;
    if !config.services.is_empty() {
        return Err(coded(
            ErrorCode::InvalidInput,
            format!(
                "invalid request: remove the {} service(s) first (`localname service list`)",
                config.services.len()
            ),
        ));
    }
    change_listeners(
        output,
        store,
        "proxy disable",
        args.dry_run,
        args.expect_revision,
        &[],
    )
}

fn join(addresses: &[SocketAddr]) -> String {
    addresses
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(", ")
}
