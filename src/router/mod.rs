//! Automated router adapters (decision 8): read-only detection, an exact plan, explicit
//! apply guarded by a state fingerprint, verification, and rollback of captured state.
//! Credentials never pass through localname: adapters use the user's SSH client, keys,
//! agent, and known hosts.

pub mod openwrt;

use std::{
    io::Write,
    path::PathBuf,
    process::{Command, Stdio},
    time::{Duration, Instant},
};

use anyhow::{Result, anyhow};
use serde::{Deserialize, Serialize};

use crate::error::{ErrorCode, coded};

/// How to reach the router's shell. Authentication is SSH's business.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Connection {
    pub host: String,
    pub user: String,
    pub port: u16,
    #[serde(skip)]
    pub identity: Option<PathBuf>,
    #[serde(skip)]
    pub accept_new_host_key: bool,
    #[serde(skip)]
    pub batch: bool,
}

impl Connection {
    fn destination(&self) -> String {
        format!("{}@{}", self.user, self.host)
    }

    /// Run `script` with the router's POSIX shell and return its standard output.
    pub fn run(&self, script: &str) -> Result<String> {
        let mut command = Command::new("ssh");
        command
            .arg("-T")
            .args(["-p", &self.port.to_string()])
            .args(["-o", "ConnectTimeout=10"])
            .args(["-o", "ServerAliveInterval=5"]);
        if self.batch {
            command.args(["-o", "BatchMode=yes"]);
        }
        if self.accept_new_host_key {
            command.args(["-o", "StrictHostKeyChecking=accept-new"]);
        }
        if let Some(identity) = &self.identity {
            command.arg("-i").arg(identity);
        }
        command
            .arg(self.destination())
            .arg("sh -s")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = command.spawn().map_err(|error| {
            coded(
                ErrorCode::Unavailable,
                format!("unavailable: cannot start the ssh client ({error}); install OpenSSH"),
            )
        })?;
        child
            .stdin
            .take()
            .ok_or_else(|| anyhow!("ssh stdin is unavailable"))?
            .write_all(script.as_bytes())?;
        let deadline = Instant::now() + Duration::from_secs(90);
        while child.try_wait()?.is_none() {
            if Instant::now() > deadline {
                let _ = child.kill();
                let _ = child.wait();
                return Err(coded(
                    ErrorCode::Unavailable,
                    format!("router unavailable: {} timed out", self.destination()),
                ));
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        let output = child.wait_with_output()?;
        if output.status.success() {
            return Ok(String::from_utf8_lossy(&output.stdout).into_owned());
        }
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_owned();
        let lowered = stderr.to_ascii_lowercase();
        let (code, hint) = if lowered.contains("host key verification failed")
            || lowered.contains("remote host identification has changed")
        {
            (
                ErrorCode::PermissionRequired,
                "permission required: the router's host key is unknown or changed; connect once with `ssh` to verify it, or pass --accept-new-host-key on a network you trust",
            )
        } else if lowered.contains("permission denied") {
            (
                ErrorCode::PermissionRequired,
                "permission required: SSH authentication failed; add your public key to the router (System › Administration › SSH-Keys) or use an agent",
            )
        } else if output.status.code() == Some(255) {
            (
                ErrorCode::Unavailable,
                "router unavailable: SSH connection failed",
            )
        } else {
            (ErrorCode::Internal, "router command failed")
        };
        Err(coded(
            code,
            format!("{hint} ({}: {stderr})", self.destination()),
        ))
    }
}

/// Quote a value for a POSIX shell.
pub fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

/// Captured state for one router, stored beside the configuration. It holds what was
/// changed and the values it replaced, never credentials.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RouterRecord {
    pub version: u32,
    pub adapter: String,
    pub connection: Connection,
    pub applied_at: u64,
    pub captured: openwrt::DhcpSettings,
    pub applied: openwrt::DhcpSettings,
}

pub fn record_path(config: &std::path::Path, host: &str) -> PathBuf {
    let safe: String = host
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || character == '.' || character == '-' {
                character
            } else {
                '_'
            }
        })
        .collect();
    config.with_extension(format!("router-{safe}.json"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shell_quoting_survives_quotes() {
        assert_eq!(shell_quote("6,10.0.0.1"), "'6,10.0.0.1'");
        assert_eq!(shell_quote("it's"), "'it'\\''s'");
    }

    #[test]
    fn record_paths_are_safe_for_any_host() {
        let path = record_path(std::path::Path::new("/x/config.toml"), "fd00::1");
        assert_eq!(path, PathBuf::from("/x/config.router-fd00__1.json"));
    }
}
