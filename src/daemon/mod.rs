//! Run localname as a system service that starts at boot and restarts on failure (M6,
//! decision 31). Each platform uses its native service manager: systemd on Linux, launchd
//! on macOS, and the Service Control Manager on Windows. The service always runs its own
//! copy of the binary from a location only administrators can write, and always uses the
//! platform's service configuration path.

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(windows)]
pub mod windows;

use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

use anyhow::{Context, Result, anyhow};
use serde::Serialize;

use crate::error::{ErrorCode, coded};

/// What the platform's service manager knows about the localname service.
#[derive(Clone, Debug, Serialize)]
#[allow(clippy::struct_excessive_bools)]
pub struct DaemonState {
    /// `systemd`, `launchd`, `windows-scm`, or `none`.
    pub manager: &'static str,
    /// Why this host cannot run the service, when it cannot.
    pub unsupported: Option<String>,
    /// Unit name, launchd label, or Windows service name.
    pub service: String,
    /// Where the service definition lives.
    pub definition: String,
    pub installed: bool,
    /// The definition was written by `localname daemon install` (not a package).
    pub managed: bool,
    /// Starts at boot.
    pub enabled: bool,
    pub running: bool,
    pub pid: Option<u32>,
    /// The binary the service runs.
    pub binary: PathBuf,
    /// The configuration the service uses.
    pub config: PathBuf,
    /// The account the service runs as.
    pub account: String,
    /// Where the service's log goes.
    pub log: String,
    /// Existing definitions with the same name that localname did not write. They block
    /// install and are never overwritten.
    pub conflicts: Vec<String>,
}

pub fn detect() -> Result<DaemonState> {
    backend::detect()
}

/// The configuration path the service uses on this platform.
pub fn service_config_path() -> PathBuf {
    backend::config_path()
}

/// What `install` would do from `source` (the running binary), in order.
pub fn plan_install(state: &DaemonState, source: &Path) -> Vec<String> {
    backend::plan_install(state, source)
}

/// Install or update the service, enable it at boot, and start (or restart) it.
/// Returns the steps taken.
pub fn install(source: &Path) -> Result<Vec<String>> {
    let state = detect()?;
    refuse_unusable(&state)?;
    backend::install(&state, source)
}

/// Stop and remove the service; configuration and data stay. Returns the steps taken.
pub fn uninstall() -> Result<Vec<String>> {
    let state = detect()?;
    if !state.installed {
        return Ok(Vec::new());
    }
    if !state.conflicts.is_empty() {
        return Err(conflict(&state));
    }
    backend::uninstall(&state)
}

pub fn start() -> Result<()> {
    let state = require_installed()?;
    backend::start(&state)
}

pub fn stop() -> Result<()> {
    let state = require_installed()?;
    backend::stop(&state)
}

fn require_installed() -> Result<DaemonState> {
    let state = detect()?;
    refuse_unusable(&state)?;
    if !state.installed {
        return Err(coded(
            ErrorCode::Unavailable,
            "service unavailable: localname is not installed as a service; run `localname daemon install`",
        ));
    }
    Ok(state)
}

fn refuse_unusable(state: &DaemonState) -> Result<()> {
    if let Some(reason) = &state.unsupported {
        return Err(coded(
            ErrorCode::Unavailable,
            format!("unsupported host: {reason}"),
        ));
    }
    if !state.conflicts.is_empty() {
        return Err(conflict(state));
    }
    Ok(())
}

fn conflict(state: &DaemonState) -> anyhow::Error {
    coded(
        ErrorCode::Conflict,
        format!("conflict: {}", state.conflicts.join("; ")),
    )
}

/// Refuse early, with the platform's elevation hint, when not running privileged.
pub fn require_privileges() -> Result<()> {
    #[cfg(unix)]
    if !crate::privilege::is_root() {
        return Err(coded(
            ErrorCode::PermissionRequired,
            "permission required: managing the system service requires root; run with sudo",
        ));
    }
    Ok(())
}

/// Header written into service definitions localname owns.
pub fn marker() -> String {
    format!(
        "{}: remove with `localname daemon uninstall`.",
        crate::client::MARKER
    )
}

/// Run a program, returning whether it succeeded and its stdout, for probes whose failure
/// is an answer (such as "not loaded").
#[cfg_attr(windows, allow(dead_code))]
pub(crate) fn probe(program: &str, arguments: &[&str]) -> Result<(bool, String)> {
    let output = Command::new(program)
        .args(arguments)
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .map_err(|error| anyhow!("failed to run {program}: {error}"))?;
    Ok((
        output.status.success(),
        String::from_utf8_lossy(&output.stdout).into_owned(),
    ))
}

/// Whether `target` already holds exactly the bytes of `source`.
pub(crate) fn same_contents(source: &Path, target: &Path) -> bool {
    match (fs::read(source), fs::read(target)) {
        (Ok(source), Ok(target)) => source == target,
        _ => false,
    }
}

/// Whether `path` already holds exactly `text`.
#[cfg_attr(windows, allow(dead_code))]
pub(crate) fn same_text(path: &Path, text: &str) -> bool {
    fs::read_to_string(path).is_ok_and(|current| current == text)
}

/// Replace `target` with `bytes` atomically: write a sibling temporary file, set its mode,
/// sync, and rename it into place.
pub(crate) fn replace_file(target: &Path, bytes: &[u8], mode: u32) -> Result<()> {
    let directory = target
        .parent()
        .ok_or_else(|| anyhow!("{} has no parent directory", target.display()))?;
    fs::create_dir_all(directory)
        .with_context(|| format!("failed to create {}", directory.display()))?;
    let mut temporary = tempfile::NamedTempFile::new_in(directory)
        .with_context(|| format!("failed to write in {}", directory.display()))?;
    temporary.write_all(bytes)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        temporary
            .as_file()
            .set_permissions(fs::Permissions::from_mode(mode))?;
    }
    #[cfg(not(unix))]
    let _ = mode;
    temporary.as_file().sync_all()?;
    temporary
        .persist(target)
        .map_err(|error| anyhow!("failed to replace {}: {}", target.display(), error.error))?;
    Ok(())
}

/// Remove a file if present; returns whether it existed.
pub(crate) fn remove_file(path: &Path) -> Result<bool> {
    match fs::remove_file(path) {
        Ok(()) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error).with_context(|| format!("failed to remove {}", path.display())),
    }
}

#[cfg(target_os = "linux")]
use linux as backend;
#[cfg(target_os = "macos")]
use macos as backend;
#[cfg(windows)]
use windows as backend;

#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
mod backend {
    use std::path::{Path, PathBuf};

    use anyhow::{Result, bail};

    use super::DaemonState;

    pub fn config_path() -> PathBuf {
        PathBuf::from("/var/lib/localname/config.toml")
    }

    pub fn detect() -> Result<DaemonState> {
        Ok(DaemonState {
            manager: "none",
            unsupported: Some(format!(
                "{} has no supported service manager",
                std::env::consts::OS
            )),
            service: String::new(),
            definition: String::new(),
            installed: false,
            managed: false,
            enabled: false,
            running: false,
            pid: None,
            binary: PathBuf::new(),
            config: config_path(),
            account: String::new(),
            log: String::new(),
            conflicts: Vec::new(),
        })
    }

    pub fn plan_install(_state: &DaemonState, _source: &Path) -> Vec<String> {
        Vec::new()
    }

    pub fn install(_state: &DaemonState, _source: &Path) -> Result<Vec<String>> {
        bail!("unsupported platform")
    }

    pub fn uninstall(_state: &DaemonState) -> Result<Vec<String>> {
        bail!("unsupported platform")
    }

    pub fn start(_state: &DaemonState) -> Result<()> {
        bail!("unsupported platform")
    }

    pub fn stop(_state: &DaemonState) -> Result<()> {
        bail!("unsupported platform")
    }
}
