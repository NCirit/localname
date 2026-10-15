//! `localname backup create|restore`: one versioned file with the configuration, its
//! revision history, and setup and router records. TLS keys are never included: the
//! local CA key does not leave its host (decision 29), and certificates are reissued.

use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result};
use clap::{Args, Subcommand};
use serde::{Deserialize, Serialize};
use serde_json::json;

use super::{print_result, rollback_command};
use crate::{
    ConfigStore,
    config::Config,
    control::{self, Request},
    error::{ErrorCode, coded},
    output::{Envelope, OutputFormat},
};

const FORMAT: &str = "localname-backup";
const VERSION: u32 = 1;

#[derive(Debug, Subcommand)]
pub enum BackupCommand {
    /// Write the configuration, revisions, and records to one file.
    Create(CreateArgs),
    /// Restore a backup as a new revision (or as the configuration, if none exists).
    Restore(RestoreArgs),
}

#[derive(Debug, Args)]
pub struct CreateArgs {
    /// Backup file to write (it must not exist).
    #[arg(long)]
    out: PathBuf,
}

#[derive(Debug, Args)]
pub struct RestoreArgs {
    file: PathBuf,
    #[arg(long)]
    dry_run: bool,
    #[arg(long)]
    expect_revision: Option<u64>,
}

#[derive(Debug, Serialize, Deserialize)]
struct Backup {
    format: String,
    version: u32,
    localname_version: String,
    created_unix: u64,
    /// The configuration file's text, exactly as stored.
    config: String,
    /// Restorable revisions, by number.
    revisions: BTreeMap<u64, String>,
    /// Sidecar records (`config.setup.json`, `config.router-*.json`, ...), by suffix.
    records: BTreeMap<String, String>,
}

pub fn run(output: OutputFormat, store: &ConfigStore, command: &BackupCommand) -> Result<()> {
    match command {
        BackupCommand::Create(args) => create(output, store, &args.out),
        BackupCommand::Restore(args) => restore(output, store, args),
    }
}

/// Sidecar files next to the configuration that describe applied integrations.
fn sidecars(store: &ConfigStore) -> Result<Vec<(String, PathBuf)>> {
    let path = store.path();
    let stem = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("config.toml")
        .trim_end_matches(".toml")
        .to_owned();
    let directory = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let mut found = Vec::new();
    for entry in std::fs::read_dir(directory)? {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().into_owned();
        if let Some(suffix) = name.strip_prefix(&format!("{stem}."))
            && Path::new(suffix)
                .extension()
                .is_some_and(|extension| extension.eq_ignore_ascii_case("json"))
        {
            found.push((suffix.to_owned(), entry.path()));
        }
    }
    found.sort();
    Ok(found)
}

fn create(output: OutputFormat, store: &ConfigStore, out: &Path) -> Result<()> {
    let config = store.load()?;
    let text = std::fs::read_to_string(store.path())?;
    let mut revisions = BTreeMap::new();
    for revision in store.revisions()? {
        revisions.insert(
            revision,
            toml::to_string_pretty(&store.load_revision(revision)?)?,
        );
    }
    let mut records = BTreeMap::new();
    for (suffix, path) in sidecars(store)? {
        records.insert(suffix, std::fs::read_to_string(path)?);
    }
    let backup = Backup {
        format: FORMAT.into(),
        version: VERSION,
        localname_version: env!("CARGO_PKG_VERSION").into(),
        created_unix: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
        config: text,
        revisions,
        records,
    };
    let bytes = serde_json::to_vec_pretty(&backup)?;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(out)
        .map_err(|error| match error.kind() {
            std::io::ErrorKind::AlreadyExists => coded(
                ErrorCode::Conflict,
                format!("conflict: {} already exists", out.display()),
            ),
            _ => error.into(),
        })?;
    std::io::Write::write_all(&mut file, &bytes)?;
    file.sync_all()?;
    let data = json!({
        "path": out,
        "revision": config.revision,
        "revisions": backup.revisions.len(),
        "records": backup.records.keys().collect::<Vec<_>>(),
        "excludes": ["TLS keys and certificates (reissued after restore; trust the local CA again if it is recreated)"],
    });
    let human = format!(
        "Backed up revision {} with {} earlier revision(s) to {}. TLS keys are not included.",
        config.revision,
        backup.revisions.len(),
        out.display()
    );
    print_result(
        output,
        Envelope::success("backup create", false, Some(config.revision), data),
        || human,
    )
}

fn restore(output: OutputFormat, store: &ConfigStore, args: &RestoreArgs) -> Result<()> {
    let text = std::fs::read_to_string(&args.file)
        .with_context(|| format!("failed to read {}", args.file.display()))?;
    let backup: Backup = serde_json::from_str(&text)
        .map_err(|error| coded(ErrorCode::InvalidInput, format!("invalid backup: {error}")))?;
    if backup.format != FORMAT {
        return Err(coded(
            ErrorCode::InvalidInput,
            "invalid backup: not a localname backup file",
        ));
    }
    if backup.version > VERSION {
        return Err(coded(
            ErrorCode::InvalidInput,
            format!(
                "invalid backup: format {} was written by a newer localname ({}); upgrade first",
                backup.version, backup.localname_version
            ),
        ));
    }
    // Validate through the same parser and migrations as the live configuration.
    let scratch = tempfile::tempdir()?;
    let scratch_store = ConfigStore::new(scratch.path().join("config.toml"));
    std::fs::write(scratch_store.path(), &backup.config)?;
    let restored: Config = scratch_store.load()?;
    let exists = store.exists();
    let current = exists.then(|| store.load()).transpose()?;
    if let Some(current) = &current {
        super::check_revision(args.expect_revision, current.revision)?;
    }
    let data = json!({
        "file": args.file,
        "backup_revision": restored.revision,
        "backup_version": backup.localname_version,
        "records": restored.records.len(),
        "services": restored.services.len(),
        "creates_configuration": !exists,
        "revisions_imported": if exists { 0 } else { backup.revisions.len() },
    });
    if args.dry_run {
        let mut data = data;
        data["preview"] = json!(true);
        return print_result(
            output,
            Envelope::success(
                "backup restore",
                true,
                current.as_ref().map(|config| config.revision),
                data,
            ),
            || {
                format!(
                    "Would restore revision {} ({} records) from {}.",
                    restored.revision,
                    restored.records.len(),
                    args.file.display()
                )
            },
        );
    }
    if control::send_if_running(store, &Request::Status)?.is_some() {
        return Err(coded(
            ErrorCode::Conflict,
            "conflict: stop the localname service before restoring a backup",
        ));
    }
    let _guard = store.acquire_offline_lock()?;
    let (revision, rollback) = if let Some(current) = current {
        // Keep this host's history: the backup becomes a new revision.
        let (previous, next) = store.mutate(args.expect_revision, |config| {
            let revision = config.revision;
            *config = restored.clone();
            config.revision = revision;
            Ok(())
        })?;
        let _ = current;
        (
            next.revision,
            Some(rollback_command(store.path(), previous.revision)),
        )
    } else {
        // A fresh host takes the backup's history and records too.
        import_history(store, &backup, &restored)?;
        (restored.revision, None)
    };
    let mut envelope = Envelope::success("backup restore", true, Some(revision), data);
    envelope.rollback = rollback;
    envelope.next_actions =
        vec!["Start the localname service. HTTPS certificates are reissued automatically.".into()];
    print_result(output, envelope, || {
        format!("Restored the backup as revision {revision}.")
    })
}

/// Recreate the backup's configuration, revision history, and records on a host that has
/// no configuration yet.
fn import_history(store: &ConfigStore, backup: &Backup, restored: &Config) -> Result<()> {
    let file_name = store
        .path()
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("config.toml")
        .to_owned();
    let history = store
        .path()
        .with_file_name(format!("{file_name}.revisions"));
    for (revision, text) in &backup.revisions {
        crate::config::write_private(&history.join(format!("{revision}.toml")), text.as_bytes())?;
    }
    store.initialize(restored)?;
    let stem = store.path().with_extension("");
    for (suffix, text) in &backup.records {
        // Only plain `name.json` suffixes; never a path.
        if suffix.contains(['/', '\\']) || suffix.contains("..") {
            continue;
        }
        let path = PathBuf::from(format!("{}.{suffix}", stem.display()));
        crate::config::write_private(&path, text.as_bytes())?;
    }
    Ok(())
}
