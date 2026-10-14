use std::path::{Path, PathBuf};

use anyhow::Result;
#[cfg(unix)]
use anyhow::bail;
use serde::{Deserialize, Serialize};

use crate::{
    Config, ConfigStore, RecordConfig,
    dns::MetricsSnapshot,
    error::{CodedError, ErrorCode, coded},
};

const MAX_FRAME: usize = 32 * 1_048_576;

/// Control protocol version. Increment when a request or response changes incompatibly.
pub const PROTOCOL_VERSION: u32 = 1;

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case")]
pub enum Request {
    Add {
        record: RecordConfig,
        expected_revision: u64,
    },
    Remove {
        name: String,
        #[serde(default)]
        value: Option<String>,
        expected_revision: u64,
    },
    Rollback {
        revision: u64,
        expected_revision: u64,
    },
    Status,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Frame<T> {
    pub protocol: u32,
    #[serde(flatten)]
    pub body: T,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct Response {
    pub config: Option<Config>,
    pub status: Option<DaemonStatus>,
    pub error: Option<String>,
    #[serde(default)]
    pub error_code: Option<ErrorCode>,
}

/// Live daemon state. Counters are aggregates only; no query names or clients are retained.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DaemonStatus {
    pub pid: u32,
    pub version: String,
    pub revision: u64,
    pub uptime_seconds: u64,
    pub cache_entries: usize,
    pub metrics: MetricsSnapshot,
}

pub fn socket_path(config_path: &Path) -> PathBuf {
    config_path.with_extension("sock")
}

/// Send a request to the daemon that owns `store`, or return `None` when no daemon is running.
pub fn send_if_running(store: &ConfigStore, request: &Request) -> Result<Option<Response>> {
    let Some(mut stream) = connect(store)? else {
        return Ok(None);
    };
    send_frame(&mut stream, request).map(Some)
}

/// A missing endpoint means no daemon only when the daemon lock is also free; otherwise a
/// daemon is starting or stopping and the caller must not fall back to offline writes.
fn daemon_absent(store: &ConfigStore, error: &std::io::Error) -> Result<()> {
    let lock = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(store.path().with_extension("daemon.lock"))?;
    if fs2::FileExt::try_lock_exclusive(&lock).is_ok() {
        return Ok(());
    }
    Err(coded(
        ErrorCode::Unavailable,
        format!("DNS service unavailable: daemon control endpoint is not ready ({error})"),
    ))
}

#[cfg(unix)]
fn connect(store: &ConfigStore) -> Result<Option<std::os::unix::net::UnixStream>> {
    let path = socket_path(store.path());
    if !path.exists() {
        return Ok(None);
    }
    match std::os::unix::net::UnixStream::connect(path) {
        Ok(socket) => {
            socket.set_read_timeout(Some(std::time::Duration::from_secs(5)))?;
            socket.set_write_timeout(Some(std::time::Duration::from_secs(5)))?;
            Ok(Some(socket))
        }
        Err(error)
            if matches!(
                error.kind(),
                std::io::ErrorKind::ConnectionRefused | std::io::ErrorKind::NotFound
            ) =>
        {
            daemon_absent(store, &error).map(|()| None)
        }
        Err(error) => Err(error.into()),
    }
}

#[cfg(windows)]
fn connect(store: &ConfigStore) -> Result<Option<std::fs::File>> {
    let name = pipe_name(store.path());
    for _ in 0..50 {
        match std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&name)
        {
            Ok(file) => return Ok(Some(file)),
            // ERROR_PIPE_BUSY: every instance is serving a client; retry briefly.
            Err(error) if error.raw_os_error() == Some(231) => {
                std::thread::sleep(std::time::Duration::from_millis(20));
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return daemon_absent(store, &error).map(|()| None);
            }
            Err(error) => return Err(error.into()),
        }
    }
    Err(coded(
        ErrorCode::Unavailable,
        "DNS service unavailable: daemon control pipe stayed busy",
    ))
}

#[cfg(not(any(unix, windows)))]
fn connect(_store: &ConfigStore) -> Result<Option<std::fs::File>> {
    Ok(None)
}

fn send_frame<S: std::io::Read + std::io::Write>(
    stream: &mut S,
    request: &Request,
) -> Result<Response> {
    let frame = serde_json::to_vec(&Frame {
        protocol: PROTOCOL_VERSION,
        body: request,
    })?;
    stream.write_all(&u32::try_from(frame.len())?.to_be_bytes())?;
    stream.write_all(&frame)?;
    stream.flush()?;
    let mut length = [0; 4];
    stream.read_exact(&mut length)?;
    let length = usize::try_from(u32::from_be_bytes(length))?;
    if length > MAX_FRAME {
        anyhow::bail!("control response exceeds maximum frame size");
    }
    let mut bytes = vec![0; length];
    stream.read_exact(&mut bytes)?;
    let response: Response = serde_json::from_slice(&bytes)?;
    if let Some(error) = response.error {
        return Err(CodedError {
            code: response.error_code.unwrap_or(ErrorCode::Internal),
            message: error,
        }
        .into());
    }
    Ok(response)
}

/// Apply a configuration change through the running daemon when present.
pub fn request_if_running(store: &ConfigStore, request: &Request) -> Result<Option<Config>> {
    send_if_running(store, request)?
        .map(|response| {
            response
                .config
                .ok_or_else(|| anyhow::anyhow!("control response has no configuration"))
        })
        .transpose()
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
            value,
            expected_revision,
        } => {
            let (_, config) = store.mutate(Some(expected_revision), |config| {
                config.records.retain(|record| {
                    record.name != name
                        || value.as_ref().is_some_and(|value| &record.value != value)
                });
                Ok(())
            })?;
            Ok(config)
        }
        Request::Rollback {
            revision,
            expected_revision,
        } => store.rollback_expected(revision, Some(expected_revision)),
        Request::Status => Err(coded(
            ErrorCode::Unavailable,
            "DNS service unavailable: status requires a running daemon",
        )),
    }
}

pub fn apply_offline(store: &ConfigStore, request: Request) -> Result<Config> {
    let _guard = store.acquire_daemon_lock()?;
    apply(store, request)
}

/// Read one framed request, apply it, and write one framed response.
async fn exchange<S>(server: &crate::DnsServer, stream: &mut S, authorized: bool) -> Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    use tokio::{
        io::AsyncReadExt,
        time::{Duration, timeout},
    };

    if !authorized {
        let response = error_response(&coded(
            ErrorCode::PermissionRequired,
            "permission denied: control peer is not the daemon owner",
        ));
        return write_frame(stream, &response).await;
    }
    let Ok(result) = timeout(Duration::from_secs(2), async {
        let length = usize::try_from(stream.read_u32().await?)?;
        if length > MAX_FRAME {
            anyhow::bail!("control request exceeds maximum frame size");
        }
        let mut bytes = vec![0; length];
        stream.read_exact(&mut bytes).await?;
        serde_json::from_slice::<Frame<Request>>(&bytes).map_err(Into::into)
    })
    .await
    else {
        return Ok(());
    };
    let response = match result {
        Ok(frame) if frame.protocol != PROTOCOL_VERSION => error_response(&coded(
            ErrorCode::Conflict,
            format!(
                "control protocol conflict: daemon speaks {PROTOCOL_VERSION}, client sent {}; restart the daemon after upgrading",
                frame.protocol
            ),
        )),
        Ok(Frame {
            body: Request::Status,
            ..
        }) => Response {
            status: Some(server.daemon_status()),
            ..Response::default()
        },
        Ok(frame) => {
            let request_store = server.store().clone();
            match tokio::task::spawn_blocking(move || apply(&request_store, frame.body)).await? {
                Ok(config) => match server.install(&config) {
                    Ok(()) => Response {
                        config: Some(config),
                        ..Response::default()
                    },
                    Err(error) => error_response(&error),
                },
                Err(error) => error_response(&error),
            }
        }
        Err(error) => error_response(&error),
    };
    let _ = timeout(Duration::from_secs(2), write_frame(stream, &response)).await;
    Ok(())
}

async fn write_frame<S>(stream: &mut S, response: &Response) -> Result<()>
where
    S: tokio::io::AsyncWrite + Unpin,
{
    use tokio::io::AsyncWriteExt;
    let frame = serde_json::to_vec(response)?;
    stream.write_u32(u32::try_from(frame.len())?).await?;
    stream.write_all(&frame).await?;
    stream.flush().await?;
    Ok(())
}

fn error_response(error: &anyhow::Error) -> Response {
    Response {
        error: Some(format!("{error:#}")),
        error_code: Some(crate::error::classify(error)),
        ..Response::default()
    }
}

#[cfg(unix)]
pub(crate) async fn serve(
    server: std::sync::Arc<crate::DnsServer>,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) -> Result<()> {
    use std::{
        fs,
        os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt},
    };
    use tokio::net::UnixListener;

    let path = socket_path(server.store().path());
    if path.exists() {
        if !fs::symlink_metadata(&path)?.file_type().is_socket() {
            bail!("control socket path is occupied by a non-socket file");
        }
        fs::remove_file(&path)?;
    }
    let listener = UnixListener::bind(&path)?;
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
    let owner = fs::metadata(&path)?.uid();
    let _cleanup = SocketCleanup(path);
    loop {
        let mut stream = tokio::select! {
            _ = shutdown.changed() => break,
            connection = listener.accept() => connection?.0,
        };
        // File permissions already restrict the socket; the credential check also covers
        // permissive umasks, inherited descriptors, and platforms that ignore socket modes.
        let authorized = stream
            .peer_cred()
            .is_ok_and(|credentials| credentials.uid() == owner || credentials.uid() == 0);
        exchange(&server, &mut stream, authorized).await?;
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

/// Named pipe for a configuration path. The name is derived from the canonical path so
/// separate configurations on one host get separate daemons.
#[cfg(windows)]
pub fn pipe_name(config_path: &Path) -> String {
    let canonical = config_path
        .canonicalize()
        .unwrap_or_else(|_| config_path.to_path_buf())
        .to_string_lossy()
        .to_lowercase();
    // FNV-1a: stable across releases and platforms, unlike the standard library hasher.
    let hash = canonical
        .bytes()
        .fold(0xcbf2_9ce4_8422_2325_u64, |hash, byte| {
            (hash ^ u64::from(byte)).wrapping_mul(0x0100_0000_01b3)
        });
    format!(r"\\.\pipe\localname-{hash:016x}")
}

#[cfg(windows)]
pub(crate) async fn serve(
    server: std::sync::Arc<crate::DnsServer>,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) -> Result<()> {
    use tokio::net::windows::named_pipe::ServerOptions;

    let name = pipe_name(server.store().path());
    // The default pipe DACL grants write access only to the creator owner, SYSTEM, and
    // administrators; remote clients are rejected outright.
    let mut pipe = ServerOptions::new()
        .first_pipe_instance(true)
        .reject_remote_clients(true)
        .create(&name)?;
    loop {
        tokio::select! {
            _ = shutdown.changed() => break,
            connected = pipe.connect() => connected?,
        }
        let mut connection = std::mem::replace(
            &mut pipe,
            ServerOptions::new()
                .reject_remote_clients(true)
                .create(&name)?,
        );
        exchange(&server, &mut connection, true).await?;
    }
    Ok(())
}
