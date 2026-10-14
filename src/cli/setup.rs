use std::{
    net::{IpAddr, SocketAddr},
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{Result, anyhow, bail};
use clap::Args;
use serde::Serialize;

use super::{print_result, private_client_networks};
use crate::{
    Config, ConfigStore,
    integration::{NetworkFacts, inspect_network},
    output::{Envelope, OutputFormat},
};

#[derive(Debug, Args)]
pub struct SetupArgs {
    /// Namespace for short device names.
    #[arg(long, default_value = "home.arpa")]
    zone: String,
    /// Only inspect the current state.
    #[arg(long, conflicts_with = "apply")]
    check: bool,
    /// Write the proposed localname configuration. Router changes remain manual.
    #[arg(long)]
    apply: bool,
    /// Prepare an unprivileged loopback instance for development.
    #[arg(long)]
    local: bool,
    /// Select a specific private DNS interface and port.
    #[arg(long, conflicts_with = "local")]
    listen: Option<SocketAddr>,
    /// LAN address clients should use when the listener is behind a published port.
    #[arg(long, conflicts_with = "local")]
    advertise: Option<IpAddr>,
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

#[allow(clippy::too_many_lines)]
pub fn setup(output: OutputFormat, store: &ConfigStore, args: &SetupArgs) -> Result<()> {
    let facts = inspect_network();
    if let Some(address) = args.advertise
        && (!crate::config::is_private_address(address) || address.is_loopback())
    {
        bail!("invalid advertised address: select a private LAN address");
    }
    let listen = if args.local {
        Some("127.0.0.1:5354".parse()?)
    } else {
        args.listen.or_else(|| {
            facts
                .lan_address
                .map(|address| SocketAddr::new(address, 53))
        })
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
        router_dns_value: if args.local {
            None
        } else {
            args.advertise
                .or_else(|| listen.map(|address| address.ip()))
        },
        facts,
        config_path: store.path().display().to_string(),
        listen,
        actions,
        warnings,
        applied: false,
    };
    if let Some(listen) = plan.listen {
        let mut candidate = Config {
            listen: vec![listen],
            zone: args.zone.clone(),
            ..Config::default()
        };
        candidate.validate()?;
        plan.actions = vec![format!("Start localname on {listen}.")];
        if let Some(advertise) = plan.router_dns_value {
            plan.actions.push(format!(
                "Set the router LAN/DHCP DNS server to {advertise}."
            ));
            plan.actions.push(format!(
                "Verify a local name from a second device using DNS server {advertise}:53."
            ));
        }
    }

    if args.apply {
        let listen = plan
            .listen
            .ok_or_else(|| anyhow!("cannot apply setup without a detected LAN address"))?;
        let mut config = Config {
            listen: vec![listen],
            zone: args.zone.clone(),
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
