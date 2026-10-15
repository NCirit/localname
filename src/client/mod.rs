//! Per-device DNS configuration for networks whose router cannot advertise localname
//! (decision 7). Each platform routes only the localname zone to the server through its
//! native split-DNS mechanism, so VPN routing and search domains stay untouched.

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(windows)]
mod windows;

use std::{
    net::{IpAddr, SocketAddr},
    process::{Command, Stdio},
    time::{Duration, Instant},
};

use anyhow::{Result, anyhow};
use serde::Serialize;

use crate::error::{ErrorCode, coded};

/// Marker written into every artifact localname owns; anything without it is foreign.
pub const MARKER: &str = "Managed by localname";

/// Where this device should send queries for `zone`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Target {
    pub server: IpAddr,
    pub port: u16,
    /// Canonical zone with a trailing dot.
    pub zone: String,
}

impl Target {
    pub fn address(&self) -> SocketAddr {
        SocketAddr::new(self.server, self.port)
    }

    /// The zone without its trailing dot, as operating systems spell domains.
    pub fn domain(&self) -> &str {
        self.zone.trim_end_matches('.')
    }
}

/// What a backend found on this device for one zone.
#[derive(Clone, Debug, Serialize)]
pub struct ClientState {
    pub backend: &'static str,
    /// Why this device cannot be configured, when it cannot.
    pub unsupported: Option<String>,
    /// The file or rule localname writes for the zone.
    pub artifact: String,
    /// localname's current configuration for the zone, if any.
    pub managed: Option<Target>,
    /// Existing configuration that the change would override or that would capture the
    /// zone's queries. Present conflicts block apply.
    pub conflicts: Vec<String>,
    /// Unrelated resolver state (other interfaces, VPN domains, search domains, other
    /// rules), compared before and after every change.
    pub preserved: Vec<String>,
}

pub fn detect(zone: &str) -> Result<ClientState> {
    backend::detect(zone)
}

/// Configure the zone; returns whether anything changed.
pub fn apply(target: &Target) -> Result<bool> {
    let state = detect(&target.zone)?;
    if let Some(reason) = &state.unsupported {
        return Err(coded(
            ErrorCode::Unavailable,
            format!("unsupported device: {reason}"),
        ));
    }
    if !state.conflicts.is_empty() {
        return Err(coded(
            ErrorCode::Conflict,
            format!("conflict: {}", state.conflicts.join("; ")),
        ));
    }
    if state.managed.as_ref() == Some(target) {
        return Ok(false);
    }
    backend::apply(target)?;
    Ok(true)
}

/// Remove localname's configuration for the zone; returns whether anything changed.
pub fn remove(zone: &str) -> Result<bool> {
    let state = detect(zone)?;
    if state.managed.is_none() {
        return Ok(false);
    }
    backend::remove(zone)?;
    Ok(true)
}

#[cfg(target_os = "linux")]
use linux as backend;
#[cfg(target_os = "macos")]
use macos as backend;
#[cfg(windows)]
use windows as backend;

#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
mod backend {
    use super::{ClientState, Target};
    use anyhow::{Result, bail};

    pub fn detect(_zone: &str) -> Result<ClientState> {
        Ok(ClientState {
            backend: "none",
            unsupported: Some(format!(
                "{} has no supported split-DNS mechanism",
                std::env::consts::OS
            )),
            artifact: String::new(),
            managed: None,
            conflicts: Vec::new(),
            preserved: Vec::new(),
        })
    }

    pub fn apply(_target: &Target) -> Result<()> {
        bail!("unsupported platform")
    }

    pub fn remove(_zone: &str) -> Result<()> {
        bail!("unsupported platform")
    }
}

/// Run a system command, returning stdout or an error that carries stderr. Access errors
/// keep their wording so they classify as `PERMISSION_REQUIRED`.
pub(crate) fn run(program: &str, arguments: &[&str]) -> Result<String> {
    let mut child = Command::new(program)
        .args(arguments)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| anyhow!("failed to run {program}: {error}"))?;
    let deadline = Instant::now() + Duration::from_secs(60);
    while child.try_wait()?.is_none() {
        if Instant::now() > deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Err(coded(
                ErrorCode::Unavailable,
                format!("{program} timed out (unavailable)"),
            ));
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    let output = child.wait_with_output()?;
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    if output.status.success() {
        return Ok(stdout);
    }
    let stderr = String::from_utf8_lossy(&output.stderr);
    let detail = stderr.trim();
    let lowered = detail.to_ascii_lowercase();
    let code = if lowered.contains("access") && lowered.contains("denied")
        || lowered.contains("permission denied")
        || lowered.contains("not permitted")
        || lowered.contains("administrator")
    {
        ErrorCode::PermissionRequired
    } else {
        ErrorCode::Internal
    };
    Err(coded(
        code,
        format!(
            "{program} failed ({}): {}",
            output.status,
            if detail.is_empty() {
                stdout.trim()
            } else {
                detail
            }
        ),
    ))
}

/// Refuse early, with the platform's elevation hint, when not running privileged.
pub fn require_privileges() -> Result<()> {
    #[cfg(unix)]
    if !crate::privilege::is_root() {
        return Err(coded(
            ErrorCode::PermissionRequired,
            "permission required: changing this device's DNS settings requires root; run with sudo",
        ));
    }
    Ok(())
}

/// Header written into managed files.
pub fn header(zone: &str) -> String {
    format!(
        "# {MARKER}: sends {zone} queries to localname. Remove with `localname client rollback --zone {zone}`."
    )
}
