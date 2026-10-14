use std::{net::IpAddr, time::Duration};

use anyhow::Result;
use clap::Args;
use hickory_proto::rr::RecordType;
use serde_json::{Value, json};

use super::{
    VerificationError, check_revision, first_listener, print_result, record_kind, rollback_command,
};
use crate::{
    Config, ConfigStore, RecordConfig,
    control::{self, Request},
    error::{ErrorCode, coded},
    output::{Envelope, OutputFormat},
    query_server,
};

#[derive(Debug, Args)]
pub struct ChangeArgs {
    /// Short name (expanded beneath the zone) or fully qualified name.
    name: String,
    /// IPv4/IPv6 address, or another local name to create an alias.
    target: String,
    #[arg(long, default_value_t = 60)]
    ttl: u32,
    /// Show the result without changing configuration.
    #[arg(long)]
    dry_run: bool,
    /// Refuse the change unless the configuration is still at this revision.
    #[arg(long)]
    expect_revision: Option<u64>,
}

#[derive(Debug, Args)]
pub struct RemoveArgs {
    name: String,
    /// Remove only this address or alias target; other values for the name remain.
    #[arg(long)]
    value: Option<String>,
    #[arg(long)]
    dry_run: bool,
    #[arg(long)]
    expect_revision: Option<u64>,
}

#[derive(Debug, Args)]
pub struct RollbackArgs {
    /// Revision whose contents become the new configuration.
    revision: u64,
    #[arg(long)]
    dry_run: bool,
    #[arg(long)]
    expect_revision: Option<u64>,
}

enum Expectation<'a> {
    Present {
        name: &'a str,
        value: &'a str,
    },
    Absent {
        name: &'a str,
        value: Option<&'a str>,
    },
    Serial,
}

/// Read the committed change back from the live listener.
async fn verify(
    command: &'static str,
    next: &Config,
    previous_revision: u64,
    data: &Value,
    expectation: Expectation<'_>,
) -> Result<Value> {
    let failure = |message: String| VerificationError {
        command,
        data: data.clone(),
        revision: next.revision,
        previous_revision,
        message,
    };
    let listener = first_listener(next);
    let timeout = Duration::from_secs(1);
    // The SOA serial carries the revision, so it proves the listener serves this exact commit.
    let soa = query_server(listener, &next.zone, RecordType::SOA, timeout)
        .await
        .map_err(|error| failure(format!("{error:#}")))?;
    let serial = soa
        .records
        .iter()
        .find(|record| record.record_type == "SOA")
        .and_then(|record| record.value.split_whitespace().nth(2)?.parse::<u64>().ok());
    if serial != Some(next.revision.min(u64::from(u32::MAX))) {
        return Err(failure(format!(
            "listener serves serial {serial:?}, expected revision {}",
            next.revision
        ))
        .into());
    }
    let result = match expectation {
        Expectation::Serial => soa,
        Expectation::Present { name, value } => {
            let result = query_server(listener, name, record_kind(value), timeout)
                .await
                .map_err(|error| failure(format!("{error:#}")))?;
            if result.response_code != "NoError"
                || !result
                    .records
                    .iter()
                    .any(|record| record.name == name && record.value == value)
            {
                return Err(failure("listener did not return the committed record".into()).into());
            }
            result
        }
        Expectation::Absent { name, value } => {
            let result = query_server(listener, name, RecordType::ANY, timeout)
                .await
                .map_err(|error| failure(format!("{error:#}")))?;
            let still_present = result.records.iter().any(|record| {
                record.name == name && value.is_none_or(|value| record.value == value)
            });
            if still_present {
                return Err(failure("listener still returned the removed value".into()).into());
            }
            result
        }
    };
    Ok(json!({"status": "passed", "scope": "configured_listener", "result": result}))
}

fn not_running() -> Value {
    json!({"status": "not_running", "scope": "configuration_only"})
}

/// Apply through the daemon when it runs, otherwise under the offline writer lock.
fn commit(store: &ConfigStore, request: Request) -> Result<(Config, bool)> {
    match control::request_if_running(store, &request)? {
        Some(config) => Ok((config, true)),
        None => Ok((control::apply_offline(store, request)?, false)),
    }
}

fn canonical_value(config: &Config, value: &str) -> Result<String> {
    value
        .parse::<IpAddr>()
        .map_or_else(|_| config.fqdn(value), |address| Ok(address.to_string()))
}

pub async fn add(output: OutputFormat, store: &ConfigStore, args: &ChangeArgs) -> Result<()> {
    let current = store.load()?;
    check_revision(args.expect_revision, current.revision)?;
    let name = current.fqdn(&args.name)?;
    let target = canonical_value(&current, &args.target)?;
    let record = RecordConfig {
        name: name.clone(),
        value: target.clone(),
        ttl: args.ttl,
    };
    let mut preview = current.clone();
    match preview
        .records
        .iter_mut()
        .find(|existing| existing.name == name && existing.value == target)
    {
        Some(existing) => existing.ttl = args.ttl,
        None => preview.records.push(record.clone()),
    }
    preview.validate()?;
    let changed = preview != current;
    let mut data =
        json!({"name": name, "value": target, "ttl": args.ttl, "config_path": store.path()});
    if args.dry_run {
        data["preview"] = json!(true);
        return print_result(
            output,
            Envelope::success("add", changed, Some(current.revision), data),
            || {
                if changed {
                    format!("Would add {name} → {target}")
                } else {
                    format!("{name} already has the requested value")
                }
            },
        );
    }
    let (next, running) = commit(
        store,
        Request::Add {
            record,
            expected_revision: current.revision,
        },
    )?;
    let changed = next.revision != current.revision;
    let mut envelope = Envelope::success("add", changed, Some(next.revision), data.clone());
    envelope.verification = Some(if running {
        verify(
            "add",
            &next,
            current.revision,
            &data,
            Expectation::Present {
                name: &name,
                value: &target,
            },
        )
        .await?
    } else {
        not_running()
    });
    if changed {
        envelope.rollback = Some(rollback_command(store.path(), current.revision));
    }
    print_result(output, envelope, || {
        if changed {
            format!("✓ {name} → {target}")
        } else {
            format!("✓ {name} already configured")
        }
    })
}

pub async fn remove(output: OutputFormat, store: &ConfigStore, args: &RemoveArgs) -> Result<()> {
    let current = store.load()?;
    check_revision(args.expect_revision, current.revision)?;
    let name = current.fqdn(&args.name)?;
    let value = args
        .value
        .as_deref()
        .map(|value| canonical_value(&current, value))
        .transpose()?;
    let matching = current
        .records
        .iter()
        .filter(|record| {
            record.name == name && value.as_ref().is_none_or(|value| &record.value == value)
        })
        .count();
    let mut data = json!({"name": name, "value": value, "records_removed": matching, "config_path": store.path()});
    if args.dry_run {
        data["preview"] = json!(true);
        return print_result(
            output,
            Envelope::success("remove", matching > 0, Some(current.revision), data),
            || format!("Would remove {matching} record(s) for {name}"),
        );
    }
    let (next, running) = commit(
        store,
        Request::Remove {
            name: name.clone(),
            value: value.clone(),
            expected_revision: current.revision,
        },
    )?;
    let changed = next.revision != current.revision;
    let mut envelope = Envelope::success("remove", changed, Some(next.revision), data.clone());
    envelope.verification = Some(if running {
        verify(
            "remove",
            &next,
            current.revision,
            &data,
            Expectation::Absent {
                name: &name,
                value: value.as_deref(),
            },
        )
        .await?
    } else {
        not_running()
    });
    if changed {
        envelope.rollback = Some(rollback_command(store.path(), current.revision));
    }
    print_result(output, envelope, || {
        format!("Removed {matching} record(s) for {name}")
    })
}

pub fn list(output: OutputFormat, store: &ConfigStore) -> Result<()> {
    let config = store.load()?;
    let records = config.records.clone();
    print_result(
        output,
        Envelope::success("list", false, Some(config.revision), &records),
        || {
            if records.is_empty() {
                "No local records configured.".into()
            } else {
                records
                    .iter()
                    .map(|record| format!("{}\t{}\t{}s", record.name, record.value, record.ttl))
                    .collect::<Vec<_>>()
                    .join("\n")
            }
        },
    )
}

pub fn revisions(output: OutputFormat, store: &ConfigStore) -> Result<()> {
    let current = store.load()?;
    let mut rows = Vec::new();
    for revision in store.revisions()? {
        let config = store.load_revision(revision)?;
        rows.push(
            json!({"revision": revision, "records": config.records.len(), "zone": config.zone}),
        );
    }
    let human = rows
        .iter()
        .map(|row| format!("{}\t{} record(s)", row["revision"], row["records"]))
        .chain(std::iter::once(format!(
            "{}\t{} record(s) (current)",
            current.revision,
            current.records.len()
        )))
        .collect::<Vec<_>>()
        .join("\n");
    print_result(
        output,
        Envelope::success(
            "revisions",
            false,
            Some(current.revision),
            json!({"current": current.revision, "restorable": rows}),
        ),
        || human,
    )
}

pub async fn rollback(
    output: OutputFormat,
    store: &ConfigStore,
    args: &RollbackArgs,
) -> Result<()> {
    let current = store.load()?;
    check_revision(args.expect_revision, current.revision)?;
    if args.revision == current.revision {
        return Err(coded(
            ErrorCode::InvalidInput,
            format!("invalid revision: {} is already current", args.revision),
        ));
    }
    let target = store.load_revision(args.revision)?;
    let added: Vec<_> = target
        .records
        .iter()
        .filter(|record| !current.records.contains(record))
        .collect();
    let removed: Vec<_> = current
        .records
        .iter()
        .filter(|record| !target.records.contains(record))
        .collect();
    let mut data = json!({
        "restored_from": args.revision,
        "records_added": added,
        "records_removed": removed,
        "config_path": store.path(),
    });
    if args.dry_run {
        data["preview"] = json!(true);
        let summary = format!(
            "Would restore revision {}: {} record(s) added, {} removed",
            args.revision,
            added.len(),
            removed.len()
        );
        return print_result(
            output,
            Envelope::success("rollback", true, Some(current.revision), data),
            || summary,
        );
    }
    let (next, running) = commit(
        store,
        Request::Rollback {
            revision: args.revision,
            expected_revision: current.revision,
        },
    )?;
    let changed = next.revision != current.revision;
    let mut envelope = Envelope::success("rollback", changed, Some(next.revision), data.clone());
    envelope.verification = Some(if running {
        verify(
            "rollback",
            &next,
            current.revision,
            &data,
            Expectation::Serial,
        )
        .await?
    } else {
        not_running()
    });
    if changed {
        envelope.rollback = Some(rollback_command(store.path(), current.revision));
    }
    let revision = next.revision;
    print_result(output, envelope, || {
        format!(
            "Restored revision {} as new revision {revision}",
            args.revision
        )
    })
}
