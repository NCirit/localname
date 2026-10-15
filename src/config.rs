use std::{
    collections::{HashMap, HashSet},
    fs::{self, OpenOptions},
    io::Write,
    net::{IpAddr, SocketAddr},
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, anyhow, bail};
use fs2::FileExt;
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use tempfile::NamedTempFile;

use crate::error::{ErrorCode, coded};

pub const CURRENT_SCHEMA: u32 = 2;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub schema: u32,
    pub revision: u64,
    pub zone: String,
    pub listen: Vec<SocketAddr>,
    pub upstreams: Vec<SocketAddr>,
    pub allowed_clients: Vec<IpNet>,
    pub cache_entries: usize,
    pub upstream_timeout_ms: u64,
    /// Remove private, loopback, and link-local addresses from forwarded public answers, so
    /// a public name cannot be used to reach devices on the LAN (DNS rebinding).
    pub rebind_protection: bool,
    /// Domains whose forwarded answers may contain private addresses, such as the router's
    /// own DHCP host domain.
    pub rebind_allowed_domains: Vec<String>,
    /// Answer Firefox's DNS-over-HTTPS canary domain with NXDOMAIN so it keeps using this
    /// resolver.
    pub firefox_doh_canary: bool,
    pub records: Vec<RecordConfig>,
    pub services: Vec<ServiceConfig>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct RecordConfig {
    pub name: String,
    pub value: String,
    #[serde(default = "default_ttl")]
    pub ttl: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ServiceConfig {
    pub name: String,
    pub target: SocketAddr,
    #[serde(default)]
    pub https: bool,
}

const fn default_ttl() -> u32 {
    60
}

impl Default for Config {
    fn default() -> Self {
        Self {
            schema: CURRENT_SCHEMA,
            revision: 0,
            zone: "home.arpa".into(),
            listen: vec![SocketAddr::from(([127, 0, 0, 1], 5354))],
            upstreams: vec![
                SocketAddr::from(([1, 1, 1, 1], 53)),
                SocketAddr::from(([9, 9, 9, 9], 53)),
            ],
            allowed_clients: vec![
                "127.0.0.0/8".parse().expect("constant CIDR"),
                "::1/128".parse().expect("constant CIDR"),
            ],
            cache_entries: 4096,
            upstream_timeout_ms: 2_000,
            rebind_protection: true,
            rebind_allowed_domains: Vec::new(),
            firefox_doh_canary: true,
            records: Vec::new(),
            services: Vec::new(),
        }
    }
}

impl Config {
    pub fn validate(&mut self) -> Result<()> {
        self.validate_inner().map_err(|error| {
            coded(
                ErrorCode::InvalidInput,
                format!("invalid configuration: {error:#}"),
            )
        })
    }

    #[allow(clippy::too_many_lines)]
    fn validate_inner(&mut self) -> Result<()> {
        if self.schema != CURRENT_SCHEMA {
            bail!(
                "unsupported configuration schema {}; expected {CURRENT_SCHEMA}",
                self.schema
            );
        }
        self.zone = canonical_zone(&self.zone)?;
        if name_in_zone(&self.zone, "local.") {
            bail!(".local is reserved for multicast DNS; use home.arpa or a domain you control");
        }
        if self.listen.is_empty() {
            bail!("at least one listen address is required");
        }
        if self.upstreams.is_empty() {
            bail!("at least one upstream resolver is required");
        }
        if !self.services.is_empty() {
            bail!("service proxying is not supported in this release");
        }
        for listen in &self.listen {
            if listen.port() == 0 || !is_private_address(listen.ip()) {
                bail!(
                    "listen addresses must select a private or loopback interface and nonzero port"
                );
            }
            if self.upstreams.contains(listen) {
                bail!("forwarding loop: upstream matches a listener");
            }
        }
        if self.allowed_clients.is_empty()
            || self
                .allowed_clients
                .iter()
                .any(|net| !is_private_network(net))
        {
            bail!("allowed_clients must contain only private or loopback subnets");
        }
        if self.cache_entries > 1_000_000 {
            bail!("cache_entries exceeds the safety limit of 1000000");
        }
        if !(100..=60_000).contains(&self.upstream_timeout_ms) {
            bail!("upstream_timeout_ms must be between 100 and 60000");
        }
        let mut allowed = Vec::with_capacity(self.rebind_allowed_domains.len());
        for domain in &self.rebind_allowed_domains {
            let domain = canonical_zone(domain)?;
            if !allowed.contains(&domain) {
                allowed.push(domain);
            }
        }
        self.rebind_allowed_domains = allowed;

        let mut by_name: HashMap<String, HashSet<&'static str>> = HashMap::new();
        let mut cname_counts = HashMap::new();
        let zone = self.zone.clone();
        for record in &mut self.records {
            record.name = canonical_name(&record.name, &zone)?;
            if !name_in_zone(&record.name, &zone) {
                bail!("record {} is outside configured zone {zone}", record.name);
            }
            if record.ttl == 0 || record.ttl > 604_800 {
                bail!(
                    "TTL for {} must be between 1 and 604800 seconds",
                    record.name
                );
            }
            let kind = if let Ok(address) = record.value.parse::<IpAddr>() {
                record.value = address.to_string();
                "address"
            } else {
                record.value = canonical_name(&record.value, &zone)?;
                let count = cname_counts.entry(record.name.clone()).or_insert(0);
                *count += 1;
                if *count > 1 {
                    bail!("{} may have only one CNAME record", record.name);
                }
                "cname"
            };
            let kinds = by_name.entry(record.name.clone()).or_default();
            kinds.insert(kind);
            if kinds.len() > 1 {
                bail!("{} cannot have both CNAME and address records", record.name);
            }
        }

        let cname_targets: HashMap<&str, &str> = self
            .records
            .iter()
            .filter(|record| record.value.parse::<IpAddr>().is_err())
            .map(|record| (record.name.as_str(), record.value.as_str()))
            .collect();
        for start in cname_targets.keys() {
            let mut seen = HashSet::new();
            let mut current = *start;
            while let Some(next) = cname_targets.get(current) {
                if !seen.insert(current) {
                    bail!("CNAME loop detected at {current}");
                }
                if seen.len() > 16 {
                    bail!("CNAME chains may contain at most 16 aliases");
                }
                current = next;
            }
        }

        for (name, target) in &cname_targets {
            if name_in_zone(target, &zone) && !by_name.contains_key(*target) {
                bail!(
                    "alias {name} points to {target}, which is not a configured name; end external targets with a dot (for example tv.example.com.)"
                );
            }
        }

        let mut service_names = HashSet::new();
        for service in &mut self.services {
            service.name = canonical_name(&service.name, &zone)?;
            if !service_names.insert(service.name.clone()) {
                bail!("duplicate service name {}", service.name);
            }
        }
        Ok(())
    }

    pub fn fqdn(&self, name: &str) -> Result<String> {
        canonical_name(name, &self.zone)
    }

    pub fn query_name(&self, name: &str) -> Result<String> {
        query_name(name, &self.zone)
    }
}

pub fn name_in_zone(name: &str, zone: &str) -> bool {
    name == zone
        || name
            .strip_suffix(zone)
            .is_some_and(|prefix| prefix.ends_with('.'))
}

pub fn is_private_address(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(ip) => ip.is_private() || ip.is_loopback() || ip.is_link_local(),
        IpAddr::V6(ip) => ip.is_loopback() || ip.is_unique_local() || ip.is_unicast_link_local(),
    }
}

/// Loopback, RFC 1918, link-local, and unique-local ranges: the only clients a home resolver serves.
pub const PRIVATE_NETWORKS: [&str; 8] = [
    "127.0.0.0/8",
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "169.254.0.0/16",
    "::1/128",
    "fc00::/7",
    "fe80::/10",
];

fn is_private_network(network: &IpNet) -> bool {
    PRIVATE_NETWORKS
        .iter()
        .filter_map(|value| value.parse::<IpNet>().ok())
        .any(|private| private.contains(network))
}

pub fn canonical_zone(zone: &str) -> Result<String> {
    let value = zone.trim().trim_end_matches('.').to_ascii_lowercase();
    validate_labels(&value)?;
    Ok(format!("{value}."))
}

/// Expand a record name or alias target with zone-file semantics: a trailing dot or the
/// zone suffix makes a name absolute; anything else is relative to `zone`.
pub fn canonical_name(name: &str, zone: &str) -> Result<String> {
    let value = name.trim().to_ascii_lowercase();
    let zone = zone.trim_end_matches('.');
    let absolute = if let Some(stripped) = value.strip_suffix('.') {
        stripped.to_owned()
    } else if value == zone || value.ends_with(&format!(".{zone}")) {
        value
    } else if value.is_empty() {
        String::new()
    } else {
        format!("{value}.{zone}")
    };
    if absolute.is_empty() {
        bail!("invalid DNS name: name cannot be empty");
    }
    validate_labels(&absolute)?;
    Ok(format!("{absolute}."))
}

/// Expand a name to query: single labels are relative to `zone`; dotted names are absolute.
pub fn query_name(name: &str, zone: &str) -> Result<String> {
    let value = name.trim().trim_end_matches('.');
    if value.contains('.') {
        canonical_name(&format!("{value}."), zone)
    } else {
        canonical_name(value, zone)
    }
}

fn validate_labels(value: &str) -> Result<()> {
    if value.len() > 253 {
        bail!("DNS name is longer than 253 bytes");
    }
    for label in value.split('.') {
        if label.is_empty() || label.len() > 63 {
            bail!("invalid DNS label in {value}");
        }
        if label.starts_with('-')
            || label.ends_with('-')
            || !label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        {
            bail!("invalid DNS label {label:?}");
        }
    }
    Ok(())
}

#[derive(Clone, Debug)]
pub struct ConfigStore {
    path: PathBuf,
}

impl ConfigStore {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn exists(&self) -> bool {
        self.path.exists()
    }

    fn parent(&self) -> &Path {
        self.path
            .parent()
            .filter(|path| !path.as_os_str().is_empty())
            .unwrap_or(Path::new("."))
    }

    /// Open (creating if needed) a lock file beside the configuration.
    fn lock_file(&self, extension: &str) -> Result<fs::File> {
        let path = self.path.with_extension(extension);
        fs::create_dir_all(self.parent())?;
        let file = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(path)?;
        adopt_owner(&file, self.parent())?;
        Ok(file)
    }

    /// Held exclusively for the daemon's lifetime. Offline writers hold it shared, so a
    /// daemon never starts in the middle of an offline change (it waits briefly instead).
    pub(crate) fn acquire_daemon_lock(&self) -> Result<fs::File> {
        let lock = self.lock_file("daemon.lock")?;
        for _ in 0..100 {
            if lock.try_lock_exclusive().is_ok() {
                return Ok(lock);
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        Err(coded(
            ErrorCode::Unavailable,
            "DNS service unavailable: another daemon owns this configuration",
        ))
    }

    /// Shared hold for an offline change; fails while a daemon owns the configuration.
    pub(crate) fn acquire_offline_lock(&self) -> Result<fs::File> {
        let lock = self.lock_file("daemon.lock")?;
        FileExt::try_lock_shared(&lock).map_err(|_| {
            coded(
                ErrorCode::Unavailable,
                "DNS service unavailable: a daemon owns this configuration but its control endpoint did not answer",
            )
        })?;
        Ok(lock)
    }

    pub fn load(&self) -> Result<Config> {
        let text = fs::read_to_string(&self.path)
            .with_context(|| format!("failed to read {}", self.path.display()))?;
        let mut config =
            parse(&text).with_context(|| format!("failed to parse {}", self.path.display()))?;
        config.validate()?;
        Ok(config)
    }

    pub fn load_or_default(&self) -> Result<Config> {
        if self.exists() {
            self.load()
        } else {
            let mut config = Config::default();
            config.validate()?;
            Ok(config)
        }
    }

    pub fn initialize(&self, config: &Config) -> Result<()> {
        if self.exists() {
            return Err(coded(
                ErrorCode::Conflict,
                format!("configuration already exists at {}", self.path.display()),
            ));
        }
        self.write_atomic(config, false)
    }

    /// Apply `mutation` to the latest revision under an exclusive lock. With
    /// `expected_revision`, refuse unless the configuration is still at that revision.
    /// Returns the previous and resulting configurations; an unchanged result is not a
    /// new revision.
    pub fn mutate<F>(&self, expected_revision: Option<u64>, mutation: F) -> Result<(Config, Config)>
    where
        F: FnOnce(&mut Config) -> Result<()>,
    {
        let lock = self.lock_file("lock")?;
        lock.lock_exclusive()?;
        let result = (|| {
            self.remove_stale_temporaries();
            let previous = self.load()?;
            if let Some(expected) = expected_revision
                && previous.revision != expected
            {
                return Err(coded(
                    ErrorCode::Conflict,
                    format!(
                        "stale revision: expected {expected}, current is {}",
                        previous.revision
                    ),
                ));
            }
            let mut next = previous.clone();
            mutation(&mut next)?;
            next.revision = previous.revision;
            next.validate()?;
            if next == previous {
                return Ok((previous.clone(), previous));
            }
            next.revision = previous
                .revision
                .checked_add(1)
                .ok_or_else(|| anyhow!("revision overflow"))?;
            // The backup is durable before the live file changes, so a crash at any point
            // leaves either the old revision or the new one, never a gap.
            self.backup(&previous)?;
            self.write_atomic(&next, true)?;
            Ok((previous, next))
        })();
        FileExt::unlock(&lock)?;
        result
    }

    pub fn rollback(&self, revision: u64) -> Result<Config> {
        Ok(self.rollback_expected(revision, None)?.1)
    }

    /// Restore the contents of `revision` as a new revision.
    pub fn rollback_expected(
        &self,
        revision: u64,
        expected_revision: Option<u64>,
    ) -> Result<(Config, Config)> {
        let restored = self.load_revision(revision)?;
        self.mutate(expected_revision, |config| {
            *config = restored;
            Ok(())
        })
    }

    fn backup(&self, config: &Config) -> Result<()> {
        let path = self.backup_path(config.revision);
        let directory = path
            .parent()
            .ok_or_else(|| anyhow!("backup directory is missing"))?;
        if !directory.exists() {
            fs::create_dir_all(directory)?;
            // Windows cannot open directories as files; ownership adoption is Unix-only.
            #[cfg(unix)]
            adopt_owner(&fs::File::open(directory)?, self.parent())?;
        }
        if path.exists() {
            return Ok(());
        }
        let text = toml::to_string_pretty(config)?;
        let temporary = self.temporary_in(directory, text.as_bytes())?;
        temporary
            .persist_noclobber(&path)
            .map_err(|error| error.error)?;
        sync_parent(directory)
    }

    /// Load the stored contents of a previous revision without validating it against today's rules.
    pub fn load_revision(&self, revision: u64) -> Result<Config> {
        let path = self.backup_path(revision);
        let text = fs::read_to_string(&path).map_err(|_| {
            coded(
                ErrorCode::InvalidInput,
                format!("invalid revision: revision {revision} was not found"),
            )
        })?;
        parse(&text).with_context(|| format!("failed to parse {}", path.display()))
    }

    /// Revisions that can be restored, oldest first.
    pub fn revisions(&self) -> Result<Vec<u64>> {
        let directory = self.backup_path(0);
        let Some(directory) = directory.parent() else {
            return Ok(Vec::new());
        };
        let entries = match fs::read_dir(directory) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(error) => return Err(error.into()),
        };
        let mut revisions = Vec::new();
        for entry in entries {
            let name = entry?.file_name();
            if let Some(revision) = name
                .to_str()
                .and_then(|name| name.strip_suffix(".toml"))
                .and_then(|stem| stem.parse().ok())
            {
                revisions.push(revision);
            }
        }
        revisions.sort_unstable();
        Ok(revisions)
    }

    fn backup_path(&self, revision: u64) -> PathBuf {
        let file_name = self
            .path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("config.toml");
        self.path
            .with_file_name(format!("{file_name}.revisions"))
            .join(format!("{revision}.toml"))
    }

    /// A synced temporary file with a recognizable name, owned like the configuration.
    fn temporary_in(&self, directory: &Path, contents: &[u8]) -> Result<NamedTempFile> {
        let mut temporary = tempfile::Builder::new()
            .prefix(TEMPORARY_PREFIX)
            .suffix(".tmp")
            .tempfile_in(directory)?;
        temporary.write_all(contents)?;
        temporary.as_file().sync_all()?;
        adopt_owner(temporary.as_file(), self.parent())?;
        Ok(temporary)
    }

    /// Temporaries left by a writer that crashed before renaming. Only called under the
    /// write lock, so no live writer owns them.
    fn remove_stale_temporaries(&self) {
        let directories = [
            self.parent().to_path_buf(),
            self.backup_path(0)
                .parent()
                .map(Path::to_path_buf)
                .unwrap_or_default(),
        ];
        for directory in directories {
            let Ok(entries) = fs::read_dir(&directory) else {
                continue;
            };
            for entry in entries.flatten() {
                let path = entry.path();
                let ours = path
                    .file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| name.starts_with(TEMPORARY_PREFIX))
                    && path.extension().is_some_and(|extension| extension == "tmp");
                if ours {
                    let _ = fs::remove_file(&path);
                }
            }
        }
    }

    fn write_atomic(&self, config: &Config, overwrite: bool) -> Result<()> {
        let mut checked = config.clone();
        checked.validate()?;
        let text = toml::to_string_pretty(&checked)?;
        let parent = self.parent();
        fs::create_dir_all(parent)?;
        let temporary = self.temporary_in(parent, text.as_bytes())?;
        if overwrite {
            temporary.persist(&self.path).map_err(|error| error.error)?;
        } else {
            temporary
                .persist_noclobber(&self.path)
                .map_err(|error| error.error)?;
        }
        sync_parent(parent)
    }
}

const TEMPORARY_PREFIX: &str = ".localname-";

/// Parse a configuration, refusing schemas from newer releases instead of guessing.
fn parse(text: &str) -> Result<Config> {
    let mut table: toml::Table = toml::from_str(text)?;
    let schema = match table.get("schema") {
        None => CURRENT_SCHEMA,
        Some(toml::Value::Integer(schema)) => u32::try_from(*schema).map_err(|_| {
            coded(
                ErrorCode::InvalidInput,
                format!("invalid configuration schema {schema}"),
            )
        })?,
        Some(_) => {
            return Err(coded(
                ErrorCode::InvalidInput,
                "invalid configuration schema: expected an integer",
            ));
        }
    };
    if schema == 0 {
        return Err(coded(
            ErrorCode::InvalidInput,
            "invalid configuration schema 0",
        ));
    }
    if schema > CURRENT_SCHEMA {
        return Err(coded(
            ErrorCode::InvalidInput,
            format!(
                "unsupported configuration schema {schema}: written by a newer localname (this release reads schema {CURRENT_SCHEMA}); upgrade localname or restore an older revision"
            ),
        ));
    }
    for step in &MIGRATIONS[usize::try_from(schema - 1)
        .unwrap_or(usize::MAX)
        .min(MIGRATIONS.len())..]
    {
        step(&mut table);
    }
    table.insert("schema".into(), toml::Value::Integer(CURRENT_SCHEMA.into()));
    Ok(table.try_into()?)
}

/// `MIGRATIONS[n - 1]` upgrades schema `n` to `n + 1`. Steps are pure table rewrites so a
/// migrated file is only persisted by the next ordinary, backed-up write.
type Migration = fn(&mut toml::Table);
const MIGRATIONS: [Migration; CURRENT_SCHEMA as usize - 1] = [migrate_1_to_2];

/// Schema 2 adds rebinding protection and the Firefox DNS-over-HTTPS canary, both enabled.
fn migrate_1_to_2(table: &mut toml::Table) {
    for key in ["rebind_protection", "firefox_doh_canary"] {
        table.entry(key).or_insert(toml::Value::Boolean(true));
    }
}

/// When running as root on Unix, give a newly created file to the owner of `directory`, so
/// an administrator's offline edit never leaves files the service account cannot replace.
#[cfg(unix)]
fn adopt_owner(file: &fs::File, directory: &Path) -> Result<()> {
    use std::os::unix::fs::MetadataExt;
    if !crate::privilege::is_root() {
        return Ok(());
    }
    let owner = fs::metadata(directory)?;
    if owner.uid() != 0 {
        std::os::unix::fs::fchown(file, Some(owner.uid()), Some(owner.gid()))?;
    }
    Ok(())
}

#[cfg(not(unix))]
#[allow(clippy::unnecessary_wraps)]
fn adopt_owner(_file: &fs::File, _directory: &Path) -> Result<()> {
    Ok(())
}

#[cfg(unix)]
fn sync_parent(parent: &Path) -> Result<()> {
    std::fs::File::open(parent)?.sync_all()?;
    Ok(())
}

/// Windows cannot open directories for syncing; `MoveFileEx` replacement is already durable.
#[cfg(not(unix))]
#[allow(clippy::unnecessary_wraps)]
fn sync_parent(_parent: &Path) -> Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expands_short_names() {
        assert_eq!(
            canonical_name("NAS", "home.arpa.").unwrap(),
            "nas.home.arpa."
        );
    }

    #[test]
    fn record_names_use_zone_file_semantics() {
        for (input, expected) in [
            ("printer.office", "printer.office.home.arpa."),
            ("nas.home.arpa", "nas.home.arpa."),
            ("home.arpa", "home.arpa."),
            ("tv.example.com.", "tv.example.com."),
            ("nas.home.arpa.", "nas.home.arpa."),
        ] {
            assert_eq!(
                canonical_name(input, "home.arpa.").unwrap(),
                expected,
                "{input}"
            );
        }
        assert!(canonical_name("", "home.arpa.").is_err());
        assert!(canonical_name(".", "home.arpa.").is_err());
        assert_eq!(
            query_name("example.com", "home.arpa.").unwrap(),
            "example.com."
        );
        assert_eq!(query_name("nas", "home.arpa.").unwrap(), "nas.home.arpa.");
    }

    #[test]
    fn rejects_dangling_local_alias_but_allows_external_targets() {
        let alias = |target: &str| Config {
            records: vec![RecordConfig {
                name: "files".into(),
                value: target.into(),
                ttl: 60,
            }],
            ..Config::default()
        };
        assert!(alias("missing").validate().is_err());
        assert!(alias("tv.example.com.").validate().is_ok());
    }

    #[test]
    fn rejects_local_zone() {
        let mut config = Config {
            zone: "local".into(),
            ..Config::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn zone_membership_uses_label_boundaries() {
        assert!(name_in_zone("nas.home.arpa.", "home.arpa."));
        assert!(name_in_zone("home.arpa.", "home.arpa."));
        assert!(!name_in_zone("evilhome.arpa.", "home.arpa."));
    }

    #[test]
    fn rejects_open_resolver_and_forwarding_loop() {
        let mut config = Config {
            listen: vec!["0.0.0.0:53".parse().unwrap()],
            ..Config::default()
        };
        assert!(config.validate().is_err());
        config.listen = vec!["127.0.0.1:5354".parse().unwrap()];
        config.upstreams = config.listen.clone();
        assert!(config.validate().is_err());
    }

    #[test]
    fn detects_cname_loop() {
        let mut config = Config {
            records: vec![
                RecordConfig {
                    name: "a".into(),
                    value: "b".into(),
                    ttl: 60,
                },
                RecordConfig {
                    name: "b".into(),
                    value: "a".into(),
                    ttl: 60,
                },
            ],
            ..Config::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn schema_1_files_load_with_schema_2_defaults() {
        let schema_1 = r#"
schema = 1
revision = 4
zone = "home.arpa."
listen = ["127.0.0.1:5354"]
upstreams = ["1.1.1.1:53"]
allowed_clients = ["127.0.0.0/8"]
cache_entries = 4096
upstream_timeout_ms = 2000
services = []

[[records]]
name = "nas.home.arpa."
value = "192.168.1.20"
ttl = 60
"#;
        let mut config = parse(schema_1).unwrap();
        config.validate().unwrap();
        assert_eq!(config.schema, CURRENT_SCHEMA);
        assert_eq!(config.revision, 4);
        assert!(config.rebind_protection);
        assert!(config.firefox_doh_canary);
        assert!(config.rebind_allowed_domains.is_empty());
        assert_eq!(config.records.len(), 1);
    }

    #[test]
    fn rebind_allowed_domains_are_canonical_and_unique() {
        let mut config = Config {
            rebind_allowed_domains: vec!["LAN".into(), "lan.".into(), "fritz.box".into()],
            ..Config::default()
        };
        config.validate().unwrap();
        assert_eq!(config.rebind_allowed_domains, ["lan.", "fritz.box."]);
    }

    #[test]
    fn revision_round_trip_and_rollback() {
        let dir = tempfile::tempdir().unwrap();
        let store = ConfigStore::new(dir.path().join("config.toml"));
        store.initialize(&Config::default()).unwrap();
        let (_, changed) = store
            .mutate(Some(0), |config| {
                config.records.push(RecordConfig {
                    name: "nas".into(),
                    value: "192.168.1.20".into(),
                    ttl: 60,
                });
                Ok(())
            })
            .unwrap();
        assert_eq!(changed.revision, 1);
        assert_eq!(store.rollback(0).unwrap().records.len(), 0);
    }
}
