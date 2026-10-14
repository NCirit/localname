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

pub const CURRENT_SCHEMA: u32 = 1;

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
    pub(crate) fn acquire_daemon_lock(&self) -> Result<std::fs::File> {
        let path = self.path.with_extension("daemon.lock");
        if let Some(parent) = path.parent().filter(|path| !path.as_os_str().is_empty()) {
            fs::create_dir_all(parent)?;
        }
        let lock = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(path)?;
        lock.try_lock_exclusive().map_err(|_| {
            coded(
                ErrorCode::Unavailable,
                "DNS service unavailable: another daemon or offline writer owns this configuration",
            )
        })?;
        Ok(lock)
    }

    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn exists(&self) -> bool {
        self.path.exists()
    }

    pub fn load(&self) -> Result<Config> {
        let text = fs::read_to_string(&self.path)
            .with_context(|| format!("failed to read {}", self.path.display()))?;
        let mut config: Config = toml::from_str(&text)
            .with_context(|| format!("failed to parse {}", self.path.display()))?;
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
            bail!("configuration already exists at {}", self.path.display());
        }
        self.write_atomic(config, false)
    }

    pub fn mutate<F>(&self, expected_revision: Option<u64>, mutation: F) -> Result<(Config, Config)>
    where
        F: FnOnce(&mut Config) -> Result<()>,
    {
        let lock_path = self.path.with_extension("lock");
        if let Some(parent) = lock_path
            .parent()
            .filter(|path| !path.as_os_str().is_empty())
        {
            fs::create_dir_all(parent)?;
        }
        let lock = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(false)
            .open(&lock_path)?;
        lock.lock_exclusive()?;

        let result = (|| {
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
            next.validate()?;
            if next == previous {
                return Ok((previous.clone(), previous));
            }
            next.revision = previous
                .revision
                .checked_add(1)
                .ok_or_else(|| anyhow!("revision overflow"))?;
            self.backup(&previous)?;
            self.write_atomic(&next, true)?;
            Ok((previous, next))
        })();
        FileExt::unlock(&lock)?;
        result
    }

    pub fn rollback(&self, revision: u64) -> Result<Config> {
        self.rollback_expected(revision, None)
    }

    pub fn rollback_expected(
        &self,
        revision: u64,
        expected_revision: Option<u64>,
    ) -> Result<Config> {
        let restored = self.load_revision(revision)?;
        let (_, next) = self.mutate(expected_revision, |config| {
            let current_revision = config.revision;
            *config = restored;
            config.revision = current_revision;
            Ok(())
        })?;
        Ok(next)
    }

    fn backup(&self, config: &Config) -> Result<()> {
        let path = self.backup_path(config.revision);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        if !path.exists() {
            let text = toml::to_string_pretty(config)?;
            let parent = path
                .parent()
                .ok_or_else(|| anyhow!("backup directory is missing"))?;
            let mut temporary = NamedTempFile::new_in(parent)?;
            temporary.write_all(text.as_bytes())?;
            temporary.as_file().sync_all()?;
            temporary
                .persist_noclobber(&path)
                .map_err(|error| error.error)?;
            sync_parent(parent)?;
        }
        Ok(())
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
        toml::from_str(&text).with_context(|| format!("failed to parse {}", path.display()))
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

    fn write_atomic(&self, config: &Config, overwrite: bool) -> Result<()> {
        let mut checked = config.clone();
        checked.validate()?;
        let text = toml::to_string_pretty(&checked)?;
        let parent = self
            .path
            .parent()
            .filter(|path| !path.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        fs::create_dir_all(parent)?;
        let mut temp = NamedTempFile::new_in(parent)?;
        temp.write_all(text.as_bytes())?;
        temp.as_file().sync_all()?;
        if !overwrite && self.path.exists() {
            bail!("configuration already exists at {}", self.path.display());
        }
        if overwrite {
            temp.persist(&self.path).map_err(|error| error.error)?;
        } else {
            temp.persist_noclobber(&self.path)
                .map_err(|error| error.error)?;
        }
        sync_parent(parent)?;
        Ok(())
    }
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
