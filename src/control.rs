use std::path::{Path, PathBuf};

use anyhow::Result;
#[cfg(unix)]
use anyhow::bail;
use serde::{Deserialize, Serialize};

use crate::{Config, ConfigStore, RecordConfig};

#[cfg(unix)]
const MAX_FRAME: usize = 32 * 1_048_576;

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case")]
pub enum Request {
    Add {
        record: RecordConfig,
        expected_revision: u64,
    },
    Remove {
        name: String,
        expected_revision: u64,
    },
    Rollback {
        revision: u64,
        expected_revision: u64,
    },
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Response {
    pub config: Option<Config>,
    pub error: Option<String>,
}

pub fn socket_path(config_path: &Path) -> PathBuf {
    config_path.with_extension("sock")
}

#[cfg(unix)]
pub fn request_if_running(store: &ConfigStore, request: &Request) -> Result<Option<Config>> {
    use std::{
        io::{Read, Write},
        os::unix::net::UnixStream,
        time::Duration,
    };

    let path = socket_path(store.path());
    if !path.exists() {
        return Ok(None);
    }
    let mut socket = UnixStream::connect(path)?;
    socket.set_read_timeout(Some(Duration::from_secs(5)))?;
    socket.set_write_timeout(Some(Duration::from_secs(5)))?;
    let frame = serde_json::to_vec(request)?;
    socket.write_all(&u32::try_from(frame.len())?.to_be_bytes())?;
    socket.write_all(&frame)?;
    let mut length = [0; 4];
    socket.read_exact(&mut length)?;
    let length = usize::try_from(u32::from_be_bytes(length))?;
    if length > MAX_FRAME {
        bail!("control response exceeds maximum frame size");
    }
    let mut bytes = vec![0; length];
    socket.read_exact(&mut bytes)?;
    let response: Response = serde_json::from_slice(&bytes)?;
    if let Some(error) = response.error {
        bail!("{error}");
    }
    response
        .config
        .map(Some)
        .ok_or_else(|| anyhow::anyhow!("control response has no configuration"))
}

#[cfg(not(unix))]
pub fn request_if_running(_store: &ConfigStore, _request: &Request) -> Result<Option<Config>> {
    Ok(None)
}

pub fn apply(store: &ConfigStore, request: Request) -> Result<Config> {
    match request {
        Request::Add {
            record,
            expected_revision,
        } => {
            let (_, config) =
                store.mutate(Some(expected_revision), |config| {
                    if let Some(existing) = config.records.iter_mut().find(|existing| {
                        existing.name == record.name && existing.value == record.value
                    }) {
                        existing.ttl = record.ttl;
                    } else {
                        config.records.push(record);
                    }
                    Ok(())
                })?;
            Ok(config)
        }
        Request::Remove {
            name,
            expected_revision,
        } => {
            let (_, config) = store.mutate(Some(expected_revision), |config| {
                config.records.retain(|record| record.name != name);
                Ok(())
            })?;
            Ok(config)
        }
        Request::Rollback {
            revision,
            expected_revision,
        } => store.rollback_expected(revision, Some(expected_revision)),
    }
}

#[cfg(unix)]
pub(crate) async fn serve(
    store: ConfigStore,
    snapshot: std::sync::Arc<arc_swap::ArcSwap<crate::DnsSnapshot>>,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) -> Result<()> {
    use fs2::FileExt;
    use std::{
        fs,
        fs::OpenOptions,
        os::unix::fs::{FileTypeExt, PermissionsExt},
        sync::Arc,
    };
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::UnixListener,
        time::{Duration, timeout},
    };

    let path = socket_path(store.path());
    let lock = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(store.path().with_extension("daemon.lock"))?;
    lock.try_lock_exclusive().map_err(|_| {
        anyhow::anyhow!("a localname daemon is already running for this configuration")
    })?;
    if path.exists() {
        if !fs::symlink_metadata(&path)?.file_type().is_socket() {
            bail!("control socket path is occupied by a non-socket file");
        }
        fs::remove_file(&path)?;
    }
    let listener = UnixListener::bind(&path)?;
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
    let _cleanup = SocketCleanup(path);
    loop {
        let mut stream = tokio::select! {
            _ = shutdown.changed() => break,
            connection = listener.accept() => connection?.0,
        };
        let result = timeout(Duration::from_secs(2), async {
            let length = usize::try_from(stream.read_u32().await?)?;
            if length > MAX_FRAME {
                bail!("control request exceeds maximum frame size");
            }
            let mut bytes = vec![0; length];
            stream.read_exact(&mut bytes).await?;
            serde_json::from_slice::<Request>(&bytes).map_err(Into::into)
        })
        .await;
        let response = match result {
            Ok(Ok(request)) => {
                let request_store = store.clone();
                match tokio::task::spawn_blocking(move || apply(&request_store, request)).await? {
                    Ok(config) => {
                        snapshot.store(Arc::new(crate::DnsSnapshot::from_config(&config)?));
                        Response {
                            config: Some(config),
                            error: None,
                        }
                    }
                    Err(error) => Response {
                        config: None,
                        error: Some(format!("{error:#}")),
                    },
                }
            }
            Ok(Err(error)) => Response {
                config: None,
                error: Some(format!("{error:#}")),
            },
            Err(_) => continue,
        };
        let frame = serde_json::to_vec(&response)?;
        let _ = timeout(Duration::from_secs(2), async {
            stream.write_u32(u32::try_from(frame.len())?).await?;
            stream.write_all(&frame).await?;
            Ok::<_, anyhow::Error>(())
        })
        .await;
    }
    Ok(())
}

#[cfg(unix)]
struct SocketCleanup(PathBuf);

#[cfg(unix)]
impl Drop for SocketCleanup {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}
