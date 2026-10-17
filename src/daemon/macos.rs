//! macOS: a launch daemon that starts at boot and is relaunched when it exits. It runs as
//! root: macOS reserves ports below 1024 on specific addresses for root, and localname
//! cannot drop supplementary groups safely there (see `privilege`). The binary and
//! configuration live in a root-only directory.

use std::{
    fs,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

use anyhow::Result;

use super::{DaemonState, marker, probe, remove_file, replace_file, same_contents, same_text};
use crate::client::{MARKER, run};

const LABEL: &str = "io.github.ncirit.localname";
const PLIST: &str = "/Library/LaunchDaemons/io.github.ncirit.localname.plist";
const DIRECTORY: &str = "/Library/Application Support/localname";
const LOG: &str = "/Library/Logs/localname.log";

fn binary_path() -> PathBuf {
    Path::new(DIRECTORY).join("bin").join("localname")
}

pub fn config_path() -> PathBuf {
    Path::new(DIRECTORY).join("config.toml")
}

fn target() -> String {
    format!("system/{LABEL}")
}

fn escape(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

fn plist_text(binary: &Path, config: &Path) -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<!-- {marker} -->
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>{LABEL}</string>
	<key>ProgramArguments</key>
	<array>
		<string>{binary}</string>
		<string>serve</string>
	</array>
	<key>EnvironmentVariables</key>
	<dict>
		<key>LOCALNAME_CONFIG</key>
		<string>{config}</string>
	</dict>
	<key>RunAtLoad</key>
	<true/>
	<key>KeepAlive</key>
	<true/>
	<key>ThrottleInterval</key>
	<integer>5</integer>
	<key>Umask</key>
	<integer>63</integer>
	<key>StandardErrorPath</key>
	<string>{LOG}</string>
</dict>
</plist>
"#,
        marker = escape(&marker()).replace("--", "- -"),
        binary = escape(&binary.to_string_lossy()),
        config = escape(&config.to_string_lossy()),
    )
}

/// `launchctl print` output: whether the job is running, and its pid. Nested sections
/// (endpoints, event triggers) carry their own `state =` lines, so only the first one
/// describes the job; a pid also means it runs.
fn parse_print(text: &str) -> (bool, Option<u32>) {
    let mut state = None;
    let mut pid = None;
    for line in text.lines().map(str::trim) {
        if let Some(value) = line.strip_prefix("state = ") {
            state.get_or_insert(value);
        } else if let Some(value) = line.strip_prefix("pid = ") {
            pid = pid.or_else(|| value.parse().ok());
        }
    }
    (state == Some("running") || pid.is_some(), pid)
}

/// `launchctl print-disabled system` lists `"label" => disabled` (or `=> true` on older
/// releases) for jobs that must not load at boot.
fn parse_disabled(text: &str) -> bool {
    text.lines().any(|line| {
        let line = line.trim();
        line.starts_with(&format!("\"{LABEL}\""))
            && (line.ends_with("disabled") || line.ends_with("true"))
    })
}

fn loaded() -> Result<Option<String>> {
    let (loaded, text) = probe("launchctl", &["print", &target()])?;
    Ok(loaded.then_some(text))
}

pub fn detect() -> Result<DaemonState> {
    let mut state = DaemonState {
        manager: "launchd",
        unsupported: None,
        service: LABEL.into(),
        definition: PLIST.into(),
        installed: false,
        managed: false,
        enabled: false,
        running: false,
        pid: None,
        binary: binary_path(),
        config: config_path(),
        account: "root".into(),
        log: LOG.into(),
        conflicts: Vec::new(),
    };
    match fs::read_to_string(PLIST) {
        Ok(text) if text.contains(MARKER) => {
            state.installed = true;
            state.managed = true;
        }
        Ok(_) => state
            .conflicts
            .push(format!("{PLIST} exists and was not written by localname")),
        Err(_) => {}
    }
    if let Some(text) = loaded()? {
        (state.running, state.pid) = parse_print(&text);
    }
    if state.installed {
        let (_, disabled) = probe("launchctl", &["print-disabled", "system"])?;
        state.enabled = !parse_disabled(&disabled);
    }
    Ok(state)
}

pub fn plan_install(_state: &DaemonState, source: &Path) -> Vec<String> {
    let binary = binary_path();
    let mut steps = Vec::new();
    if !same_contents(source, &binary) {
        steps.push(format!(
            "Copy {} to {}.",
            source.display(),
            binary.display()
        ));
    }
    steps.push(format!("Restrict {DIRECTORY} to root, and write {PLIST}."));
    steps.push(format!(
        "Load {LABEL} with launchctl so it starts at boot and is relaunched if it exits."
    ));
    steps
}

/// Load the job, retrying while a previous bootout finishes.
fn bootstrap() -> Result<()> {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        match run("launchctl", &["bootstrap", "system", PLIST]) {
            Ok(_) => return Ok(()),
            Err(_) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(250)),
            Err(error) => return Err(error),
        }
    }
}

fn bootout() -> Result<()> {
    if loaded()?.is_none() {
        return Ok(());
    }
    run("launchctl", &["bootout", &target()])?;
    let deadline = Instant::now() + Duration::from_secs(10);
    while loaded()?.is_some() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(100));
    }
    Ok(())
}

pub fn install(_state: &DaemonState, source: &Path) -> Result<Vec<String>> {
    let mut steps = Vec::new();
    let mut changed = false;
    let binary = binary_path();
    fs::create_dir_all(DIRECTORY)?;
    run("chown", &["root:wheel", DIRECTORY])?;
    run("chmod", &["0700", DIRECTORY])?;
    if !same_contents(source, &binary) {
        replace_file(&binary, &fs::read(source)?, 0o755)?;
        steps.push(format!(
            "Copied {} to {}.",
            source.display(),
            binary.display()
        ));
        changed = true;
    }
    let text = plist_text(&binary, &config_path());
    if !same_text(Path::new(PLIST), &text) {
        replace_file(Path::new(PLIST), text.as_bytes(), 0o644)?;
        run("chown", &["root:wheel", PLIST])?;
        steps.push(format!("Wrote {PLIST}."));
        changed = true;
    }
    run("launchctl", &["enable", &target()])?;
    if changed {
        bootout()?;
    }
    if loaded()?.is_none() {
        bootstrap()?;
        steps.push(format!("Loaded {LABEL}; it starts at boot."));
    } else {
        run("launchctl", &["kickstart", &target()])?;
        steps.push(format!("{LABEL} is loaded and starts at boot."));
    }
    Ok(steps)
}

pub fn uninstall(_state: &DaemonState) -> Result<Vec<String>> {
    let mut steps = Vec::new();
    bootout()?;
    steps.push(format!("Stopped and unloaded {LABEL}."));
    if remove_file(Path::new(PLIST))? {
        steps.push(format!("Removed {PLIST}."));
    }
    let binary = binary_path();
    if remove_file(&binary)? {
        let _ = fs::remove_dir(binary.parent().unwrap_or(Path::new("/")));
        steps.push(format!("Removed {}.", binary.display()));
    }
    steps.push(format!("Kept the configuration in {DIRECTORY}."));
    Ok(steps)
}

pub fn start(_state: &DaemonState) -> Result<()> {
    if loaded()?.is_none() {
        bootstrap()
    } else {
        run("launchctl", &["kickstart", &target()]).map(drop)
    }
}

/// Unload the job so launchd does not relaunch it; it loads again at the next boot.
pub fn stop(_state: &DaemonState) -> Result<()> {
    bootout()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plist_escapes_paths_and_keeps_the_job_alive() {
        let text = plist_text(Path::new("/opt/a&b/localname"), &config_path());
        assert!(text.contains("<string>/opt/a&amp;b/localname</string>"));
        assert!(
            text.contains("<string>/Library/Application Support/localname/config.toml</string>")
        );
        assert!(text.contains("<key>RunAtLoad</key>\n\t<true/>"));
        assert!(text.contains("<key>KeepAlive</key>\n\t<true/>"));
        assert!(text.contains(MARKER));
        // XML comments may not contain "--".
        let comment = text.lines().find(|line| line.starts_with("<!--")).unwrap();
        assert!(!comment[4..comment.len() - 3].contains("--"));
    }

    #[test]
    fn launchctl_output_parses() {
        let print = "system/io.github.ncirit.localname = {\n\tactive count = 1\n\tstate = running\n\tpid = 412\n}";
        assert_eq!(parse_print(print), (true, Some(412)));
        assert_eq!(parse_print("\tstate = not running\n"), (false, None));
        let nested = "\tstate = running\n\tpid = 9\n\tendpoints = {\n\t\tstate = inactive\n\t}\n";
        assert_eq!(parse_print(nested), (true, Some(9)));
        assert!(parse_disabled(
            "disabled services = {\n\t\"io.github.ncirit.localname\" => disabled\n}"
        ));
        assert!(parse_disabled("\t\"io.github.ncirit.localname\" => true"));
        assert!(!parse_disabled(
            "\t\"io.github.ncirit.localname\" => enabled"
        ));
        assert!(!parse_disabled("\t\"com.example.other\" => disabled"));
    }
}
