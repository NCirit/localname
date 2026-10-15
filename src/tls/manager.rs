//! Keeps a valid certificate for every HTTPS service: loads stored ones at startup,
//! issues missing ones, renews inside the renewal window, and serves them by SNI.

use std::{
    collections::{BTreeMap, HashMap},
    path::PathBuf,
    sync::{Arc, Mutex, PoisonError},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::Result;
use arc_swap::ArcSwap;
use rustls::{
    server::{ClientHello, ResolvesServerCert},
    sign::CertifiedKey,
};
use serde::{Deserialize, Serialize};
use tokio::sync::{Notify, watch};
use tracing::{info, warn};

use super::{
    CertificateInfo, LocalCa, acme, certificate_paths, certified_key, inspect, write_file,
};
use crate::config::{Config, HttpsConfig, HttpsMode};

const CHECK_INTERVAL: Duration = Duration::from_secs(3_600);
const RETRY_INTERVAL: Duration = Duration::from_secs(600);

/// Per-service certificate state reported by `localname status` and `https status`.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct CertStatus {
    pub name: String,
    pub certificate: Option<CertificateInfo>,
    pub last_error: Option<String>,
    pub last_attempt_unix: Option<u64>,
    /// Issuance attempts since the daemon started.
    #[serde(default)]
    pub attempts: u64,
}

struct Desired {
    https: HttpsConfig,
    names: Vec<String>,
}

pub struct CertManager {
    config_path: PathBuf,
    desired: ArcSwap<Desired>,
    certs: ArcSwap<HashMap<String, Arc<CertifiedKey>>>,
    status: Mutex<BTreeMap<String, CertStatus>>,
    force: std::sync::atomic::AtomicBool,
    wake: Notify,
}

impl std::fmt::Debug for CertManager {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CertManager")
            .field("names", &self.desired.load().names)
            .finish_non_exhaustive()
    }
}

fn desired(config: &Config) -> Option<Desired> {
    let https = config.https.clone()?;
    Some(Desired {
        https,
        names: config
            .services
            .iter()
            .filter(|service| service.https)
            .map(|service| service.name.clone())
            .collect(),
    })
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

impl CertManager {
    /// Build the manager for a configuration with HTTPS, loading stored certificates so
    /// TLS works immediately after a restart.
    pub fn new(config_path: PathBuf, config: &Config) -> Option<Arc<Self>> {
        let desired = desired(config)?;
        let manager = Arc::new(Self {
            config_path,
            desired: ArcSwap::from_pointee(desired),
            certs: ArcSwap::from_pointee(HashMap::new()),
            status: Mutex::new(BTreeMap::new()),
            force: std::sync::atomic::AtomicBool::new(false),
            wake: Notify::new(),
        });
        let names = manager.desired.load().names.clone();
        for name in names {
            if let Some((key, info)) = manager.stored(&name) {
                manager.publish(&name, key, info);
            }
        }
        Some(manager)
    }

    pub fn install(&self, config: &Config) {
        if let Some(next) = desired(config) {
            self.desired.store(Arc::new(next));
            self.wake.notify_one();
        }
    }

    /// Renew every certificate now, regardless of its expiry.
    pub fn renew_now(&self) {
        self.force.store(true, std::sync::atomic::Ordering::SeqCst);
        self.wake.notify_one();
    }

    pub fn status(&self) -> Vec<CertStatus> {
        let desired = self.desired.load();
        let status = self.status.lock().unwrap_or_else(PoisonError::into_inner);
        desired
            .names
            .iter()
            .map(|name| {
                status.get(name).cloned().unwrap_or_else(|| CertStatus {
                    name: name.clone(),
                    ..CertStatus::default()
                })
            })
            .collect()
    }

    fn update(&self, name: &str, change: impl FnOnce(&mut CertStatus)) {
        let mut status = self.status.lock().unwrap_or_else(PoisonError::into_inner);
        let entry = status.entry(name.to_owned()).or_insert_with(|| CertStatus {
            name: name.to_owned(),
            ..CertStatus::default()
        });
        change(entry);
    }

    fn publish(&self, name: &str, key: CertifiedKey, info: CertificateInfo) {
        let mut certs = (**self.certs.load()).clone();
        certs.insert(
            name.trim_end_matches('.').to_ascii_lowercase(),
            Arc::new(key),
        );
        self.certs.store(Arc::new(certs));
        self.update(name, |status| {
            status.certificate = Some(info);
            status.last_error = None;
        });
    }

    /// A stored certificate for `name` that this mode would have issued.
    fn stored(&self, name: &str) -> Option<(CertifiedKey, CertificateInfo)> {
        let (chain_path, key_path) = certificate_paths(&self.config_path, name);
        let chain = std::fs::read_to_string(chain_path).ok()?;
        let key = std::fs::read_to_string(key_path).ok()?;
        let info = inspect(&chain).ok()?;
        let desired = self.desired.load();
        let from_local_ca = info.issuer.contains("localname CA for");
        if from_local_ca != (desired.https.mode == HttpsMode::LocalCa) {
            return None;
        }
        Some((certified_key(&chain, &key).ok()?, info))
    }

    async fn issue(&self, name: &str) -> Result<(String, String)> {
        let desired = self.desired.load_full();
        match desired.https.mode {
            HttpsMode::LocalCa => {
                let config = self.config_path.clone();
                let name = name.to_owned();
                tokio::task::spawn_blocking(move || LocalCa::load(&config)?.issue(&name)).await?
            }
            HttpsMode::AcmeDns01 => acme::issue(&self.config_path, &desired.https, name).await,
        }
    }

    /// Bring every certificate up to date; returns when the next check is due.
    async fn ensure(&self) -> Duration {
        let force = self.force.swap(false, std::sync::atomic::Ordering::SeqCst);
        let desired = self.desired.load_full();
        let mut next = CHECK_INTERVAL;
        for name in &desired.names {
            let current = self.stored(name);
            if let Some((key, info)) = &current
                && !force
                && !info.needs_renewal(desired.https.renew_before_days)
            {
                if !self.certs.load().contains_key(name.trim_end_matches('.')) {
                    self.publish(name, key.clone(), info.clone());
                }
                continue;
            }
            let attempted = now();
            match self.issue(name).await {
                Ok((chain, key_pem)) => match (inspect(&chain), certified_key(&chain, &key_pem)) {
                    (Ok(info), Ok(key)) => {
                        let (chain_path, key_path) = certificate_paths(&self.config_path, name);
                        if let Err(error) = write_file(&key_path, key_pem.as_bytes(), true)
                            .and_then(|()| write_file(&chain_path, chain.as_bytes(), false))
                        {
                            warn!(%error, %name, "failed to store certificate");
                        }
                        info!(%name, "issued certificate");
                        self.publish(name, key, info);
                        self.update(name, |status| {
                            status.last_attempt_unix = Some(attempted);
                            status.attempts += 1;
                        });
                    }
                    (Err(error), _) | (_, Err(error)) => {
                        self.failed(name, attempted, &error);
                        next = next.min(RETRY_INTERVAL);
                    }
                },
                Err(error) => {
                    self.failed(name, attempted, &error);
                    next = next.min(RETRY_INTERVAL);
                }
            }
        }
        next
    }

    fn failed(&self, name: &str, attempted: u64, error: &anyhow::Error) {
        warn!(error = %format!("{error:#}"), %name, "certificate issuance failed");
        self.update(name, |status| {
            status.last_error = Some(format!("{error:#}"));
            status.last_attempt_unix = Some(attempted);
            status.attempts += 1;
        });
    }

    pub async fn maintain(self: Arc<Self>, mut shutdown: watch::Receiver<bool>) -> Result<()> {
        loop {
            let delay = self.ensure().await;
            tokio::select! {
                _ = shutdown.changed() => break,
                () = tokio::time::sleep(delay) => {},
                () = self.wake.notified() => {},
            }
        }
        Ok(())
    }
}

impl ResolvesServerCert for CertManager {
    fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        let name = client_hello
            .server_name()?
            .trim_end_matches('.')
            .to_ascii_lowercase();
        self.certs.load().get(&name).cloned()
    }
}
