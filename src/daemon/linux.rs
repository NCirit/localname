//! Linux: the hardened systemd unit from `packaging/systemd`. A package already installs
//! the unit, account, and state directory, so install only enables it. Without a package,
//! install copies the binary to `/usr/local/lib/localname` and writes the unit, sysusers,
//! and tmpfiles entries under `/etc`, each marked as localname's.

use std::{
    fs,
    path::{Path, PathBuf},
};

use anyhow::Result;

use super::{DaemonState, marker, probe, remove_file, replace_file, same_contents, same_text};
use crate::client::{MARKER, run};

const UNIT: &str = "localname.service";
const PACKAGED_UNIT: &str = "/usr/lib/systemd/system/localname.service";
const PACKAGED_BINARY: &str = "/usr/bin/localname";
const MANAGED_UNIT: &str = "/etc/systemd/system/localname.service";
const MANAGED_SYSUSERS: &str = "/etc/sysusers.d/localname.conf";
const MANAGED_TMPFILES: &str = "/etc/tmpfiles.d/localname.conf";
const MANAGED_BINARY: &str = "/usr/local/lib/localname/localname";
const STATE_DIRECTORY: &str = "/var/lib/localname";
const ACCOUNT: &str = "localname";

const UNIT_TEMPLATE: &str = include_str!("../../packaging/systemd/localname.service");
const SYSUSERS: &str = include_str!("../../packaging/systemd/localname.sysusers");
const TMPFILES: &str = include_str!("../../packaging/systemd/localname.tmpfiles");

pub fn config_path() -> PathBuf {
    Path::new(STATE_DIRECTORY).join("config.toml")
}

/// The packaged unit with the binary path replaced, under localname's marker.
fn unit_text(binary: &str) -> String {
    format!(
        "# {}\n{}",
        marker(),
        UNIT_TEMPLATE.replace(PACKAGED_BINARY, binary)
    )
}

fn marked(text: &str) -> String {
    format!("# {}\n{text}", marker())
}

fn is_ours(path: &str) -> Option<bool> {
    fs::read_to_string(path).ok().map(|text| {
        text.lines()
            .next()
            .is_some_and(|line| line.contains(MARKER))
    })
}

/// Whether the package's files are used, rather than localname's own under `/etc`.
fn packaged(state: &DaemonState) -> bool {
    state.installed && !state.managed
}

pub fn detect() -> Result<DaemonState> {
    let mut state = DaemonState {
        manager: "systemd",
        unsupported: None,
        service: UNIT.into(),
        definition: PACKAGED_UNIT.into(),
        installed: false,
        managed: false,
        enabled: false,
        running: false,
        pid: None,
        binary: MANAGED_BINARY.into(),
        config: config_path(),
        account: ACCOUNT.into(),
        log: format!("journalctl -u {UNIT}"),
        conflicts: Vec::new(),
    };
    if !Path::new("/run/systemd/system").is_dir() {
        state.unsupported = Some("this host does not run systemd".into());
        return Ok(state);
    }
    match is_ours(MANAGED_UNIT) {
        Some(true) => {
            state.installed = true;
            state.managed = true;
            state.definition = MANAGED_UNIT.into();
        }
        Some(false) => state.conflicts.push(format!(
            "{MANAGED_UNIT} exists and was not written by localname"
        )),
        None if Path::new(PACKAGED_UNIT).is_file() => {
            state.installed = true;
            state.binary = PACKAGED_BINARY.into();
        }
        None => {}
    }
    for path in [MANAGED_SYSUSERS, MANAGED_TMPFILES] {
        if is_ours(path) == Some(false) {
            state
                .conflicts
                .push(format!("{path} exists and was not written by localname"));
        }
    }
    let (_, properties) = probe(
        "systemctl",
        &["show", UNIT, "--property=ActiveState,MainPID,UnitFileState"],
    )?;
    for line in properties.lines() {
        match line.split_once('=') {
            Some(("ActiveState", value)) => {
                state.running = matches!(value, "active" | "activating" | "reloading");
            }
            Some(("MainPID", value)) => state.pid = value.parse().ok().filter(|pid| *pid != 0),
            Some(("UnitFileState", value)) => {
                state.enabled = matches!(value, "enabled" | "enabled-runtime");
            }
            _ => {}
        }
    }
    Ok(state)
}

pub fn plan_install(state: &DaemonState, source: &Path) -> Vec<String> {
    let mut steps = Vec::new();
    if packaged(state) {
        steps.push(format!(
            "Use the packaged unit {PACKAGED_UNIT} and binary {PACKAGED_BINARY}."
        ));
    } else {
        if !same_contents(source, Path::new(MANAGED_BINARY)) {
            steps.push(format!("Copy {} to {MANAGED_BINARY}.", source.display()));
        }
        steps.push(format!(
            "Write {MANAGED_UNIT}, {MANAGED_SYSUSERS}, and {MANAGED_TMPFILES}."
        ));
    }
    steps.push(format!(
        "Create the {ACCOUNT} account and {STATE_DIRECTORY}, owned by it."
    ));
    steps.push(format!(
        "Enable {UNIT} at boot and start it (restarts on failure)."
    ));
    steps
}

pub fn install(state: &DaemonState, source: &Path) -> Result<Vec<String>> {
    let mut steps = Vec::new();
    let mut changed = false;
    let (sysusers, tmpfiles) = if packaged(state) {
        steps.push(format!("Using the packaged unit {PACKAGED_UNIT}."));
        ("localname.conf", "localname.conf")
    } else {
        let binary = Path::new(MANAGED_BINARY);
        if !same_contents(source, binary) {
            replace_file(binary, &fs::read(source)?, 0o755)?;
            steps.push(format!("Copied {} to {MANAGED_BINARY}.", source.display()));
            changed = true;
        }
        for (path, text) in [
            (MANAGED_SYSUSERS, marked(SYSUSERS)),
            (MANAGED_TMPFILES, marked(TMPFILES)),
            (MANAGED_UNIT, unit_text(MANAGED_BINARY)),
        ] {
            if !same_text(Path::new(path), &text) {
                replace_file(Path::new(path), text.as_bytes(), 0o644)?;
                steps.push(format!("Wrote {path}."));
                changed = true;
            }
        }
        (MANAGED_SYSUSERS, MANAGED_TMPFILES)
    };
    run("systemd-sysusers", &[sysusers])?;
    run("systemd-tmpfiles", &["--create", tmpfiles])?;
    // Setup run as root before the account existed leaves root-owned files behind.
    run(
        "chown",
        &["-R", &format!("{ACCOUNT}:{ACCOUNT}"), STATE_DIRECTORY],
    )?;
    steps.push(format!(
        "Ensured the {ACCOUNT} account and {STATE_DIRECTORY}."
    ));
    run("systemctl", &["daemon-reload"])?;
    run("systemctl", &["enable", UNIT])?;
    steps.push(format!("Enabled {UNIT} at boot."));
    if state.running && changed {
        run("systemctl", &["restart", UNIT])?;
        steps.push(format!("Restarted {UNIT} on the new definition."));
    } else {
        run("systemctl", &["start", UNIT])?;
        steps.push(format!("Started {UNIT}."));
    }
    Ok(steps)
}

pub fn uninstall(state: &DaemonState) -> Result<Vec<String>> {
    let mut steps = Vec::new();
    run("systemctl", &["disable", "--now", UNIT])?;
    steps.push(format!("Stopped {UNIT} and disabled it at boot."));
    if packaged(state) {
        steps.push(format!(
            "Kept the packaged unit {PACKAGED_UNIT}; remove the package to delete it."
        ));
        return Ok(steps);
    }
    for path in [MANAGED_UNIT, MANAGED_SYSUSERS, MANAGED_TMPFILES] {
        if is_ours(path) == Some(true) && remove_file(Path::new(path))? {
            steps.push(format!("Removed {path}."));
        }
    }
    if remove_file(Path::new(MANAGED_BINARY))? {
        let _ = fs::remove_dir(Path::new(MANAGED_BINARY).parent().unwrap_or(Path::new("/")));
        steps.push(format!("Removed {MANAGED_BINARY}."));
    }
    run("systemctl", &["daemon-reload"])?;
    steps.push(format!("Kept {STATE_DIRECTORY} and the {ACCOUNT} account."));
    Ok(steps)
}

pub fn start(_state: &DaemonState) -> Result<()> {
    run("systemctl", &["start", UNIT]).map(drop)
}

pub fn stop(_state: &DaemonState) -> Result<()> {
    run("systemctl", &["stop", UNIT]).map(drop)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn managed_unit_runs_the_copied_binary_under_the_marker() {
        let text = unit_text(MANAGED_BINARY);
        assert!(text.starts_with(&format!("# {MARKER}")));
        assert!(text.contains(&format!("ExecStart={MANAGED_BINARY} serve")));
        assert!(text.contains(&format!("ExecStartPre={MANAGED_BINARY} config check")));
        assert!(!text.contains(PACKAGED_BINARY));
        assert!(text.contains("WantedBy=multi-user.target"));
        assert!(text.contains("Restart=on-failure"));
    }
}
