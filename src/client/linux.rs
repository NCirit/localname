//! systemd-resolved: a drop-in adds localname as a global DNS server with a routing-only
//! domain (`~home.arpa`). Routing domains on other links, including a VPN's `~.`, still
//! win for their names, and no search domain is added.

use std::{
    fs,
    io::Write,
    net::IpAddr,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result};

use super::{ClientState, MARKER, Target, header, run};

const DROP_IN_DIRECTORY: &str = "/etc/systemd/resolved.conf.d";
/// Configuration resolved reads, in its documented search order.
const CONFIG_FILES: &str = "/etc/systemd/resolved.conf";
const DROP_IN_DIRECTORIES: [&str; 4] = [
    "/etc/systemd/resolved.conf.d",
    "/run/systemd/resolved.conf.d",
    "/usr/local/lib/systemd/resolved.conf.d",
    "/usr/lib/systemd/resolved.conf.d",
];

fn artifact(zone: &str) -> PathBuf {
    Path::new(DROP_IN_DIRECTORY).join(format!("60-localname-{}.conf", zone.trim_end_matches('.')))
}

#[allow(clippy::unnecessary_wraps)]
pub fn detect(zone: &str) -> Result<ClientState> {
    let path = artifact(zone);
    let mut state = ClientState {
        backend: "systemd-resolved",
        unsupported: None,
        artifact: path.display().to_string(),
        managed: None,
        conflicts: Vec::new(),
        preserved: Vec::new(),
    };
    if !Path::new("/run/systemd/resolve").exists() {
        state.unsupported = Some(
            "systemd-resolved is not running; split DNS needs it on Linux (or make the router advertise localname)".into(),
        );
        return Ok(state);
    }
    if !resolv_conf_uses_resolved() {
        state.unsupported = Some(
            "/etc/resolv.conf does not point at systemd-resolved, so applications would bypass it; link it to /run/systemd/resolve/stub-resolv.conf first".into(),
        );
        return Ok(state);
    }
    state.managed = fs::read_to_string(&path)
        .ok()
        .and_then(|text| parse_drop_in(&text, zone));
    if path.exists() && state.managed.is_none() {
        state.conflicts.push(format!(
            "{} exists and is not managed by localname",
            path.display()
        ));
    }
    for (file, servers) in global_servers() {
        if file == path {
            continue;
        }
        let ours = fs::read_to_string(&file).is_ok_and(|text| text.contains(MARKER));
        if ours {
            state.conflicts.push(format!(
                "{} routes another zone to localname; roll it back first",
                file.display()
            ));
        } else {
            state.conflicts.push(format!(
                "{} sets global DNS servers ({}); systemd-resolved would also send {zone} queries to them",
                file.display(),
                servers.join(" ")
            ));
        }
    }
    state.preserved = snapshot(state.managed.as_ref());
    Ok(state)
}

pub fn apply(target: &Target) -> Result<()> {
    let path = artifact(&target.zone);
    fs::create_dir_all(DROP_IN_DIRECTORY)?;
    let mut temporary = tempfile::Builder::new()
        .prefix(".localname-")
        .tempfile_in(DROP_IN_DIRECTORY)?;
    temporary.write_all(render_drop_in(target).as_bytes())?;
    temporary.as_file().sync_all()?;
    let file = temporary.persist(&path).map_err(|error| error.error)?;
    let mut permissions = file.metadata()?.permissions();
    std::os::unix::fs::PermissionsExt::set_mode(&mut permissions, 0o644);
    fs::set_permissions(&path, permissions)?;
    reload()
}

pub fn remove(zone: &str) -> Result<()> {
    fs::remove_file(artifact(zone))?;
    reload()
}

fn reload() -> Result<()> {
    run("systemctl", &["try-reload-or-restart", "systemd-resolved"])
        .context("failed to reload systemd-resolved")?;
    // Answers cached before the change would otherwise linger for their TTL.
    let _ = run("resolvectl", &["flush-caches"]);
    Ok(())
}

pub fn render_drop_in(target: &Target) -> String {
    let server = match (target.server, target.port) {
        (address, 53) => address.to_string(),
        (IpAddr::V4(address), port) => format!("{address}:{port}"),
        (IpAddr::V6(address), port) => format!("[{address}]:{port}"),
    };
    format!(
        "{}\n[Resolve]\nDNS={server}\nDomains=~{}\n",
        header(target.domain()),
        target.domain()
    )
}

/// Read back a drop-in localname wrote; anything else is not ours.
pub fn parse_drop_in(text: &str, zone: &str) -> Option<Target> {
    if !text.contains(MARKER) {
        return None;
    }
    let mut server = None;
    let mut domain = None;
    for line in text.lines().map(str::trim) {
        if let Some(value) = line.strip_prefix("DNS=") {
            server = Some(value.to_owned());
        } else if let Some(value) = line.strip_prefix("Domains=~") {
            domain = Some(value.to_owned());
        }
    }
    if domain? != zone.trim_end_matches('.') {
        return None;
    }
    let server = server?;
    let (address, port) = if let Ok(address) = server.parse::<IpAddr>() {
        (address, 53)
    } else {
        let socket: std::net::SocketAddr = server.parse().ok()?;
        (socket.ip(), socket.port())
    };
    Some(Target {
        server: address,
        port,
        zone: zone.to_owned(),
    })
}

fn resolv_conf_uses_resolved() -> bool {
    if fs::read_link("/etc/resolv.conf")
        .is_ok_and(|target| target.to_string_lossy().contains("systemd/resolve"))
    {
        return true;
    }
    fs::read_to_string("/etc/resolv.conf").is_ok_and(|text| {
        text.lines()
            .any(|line| line.split_whitespace().eq(["nameserver", "127.0.0.53"]))
    })
}

/// Files that set `DNS=` in the `[Resolve]` section, with their servers.
fn global_servers() -> Vec<(PathBuf, Vec<String>)> {
    let mut files = vec![PathBuf::from(CONFIG_FILES)];
    for directory in DROP_IN_DIRECTORIES {
        if let Ok(entries) = fs::read_dir(directory) {
            let mut found: Vec<PathBuf> = entries
                .flatten()
                .map(|entry| entry.path())
                .filter(|path| {
                    path.extension()
                        .is_some_and(|extension| extension == "conf")
                })
                .collect();
            found.sort();
            files.extend(found);
        }
    }
    files
        .into_iter()
        .filter_map(|file| {
            let text = fs::read_to_string(&file).ok()?;
            let servers = dns_assignments(&text);
            (!servers.is_empty()).then_some((file, servers))
        })
        .collect()
}

fn dns_assignments(text: &str) -> Vec<String> {
    let mut in_resolve = false;
    let mut servers = Vec::new();
    for line in text.lines().map(str::trim) {
        if line.starts_with('[') {
            in_resolve = line == "[Resolve]";
        } else if in_resolve && let Some(value) = line.strip_prefix("DNS=") {
            // An empty assignment resets the list.
            if value.trim().is_empty() {
                servers.clear();
            } else {
                servers.extend(value.split_whitespace().map(str::to_owned));
            }
        }
    }
    servers
}

/// Per-link and global DNS servers and domains, minus localname's own entries.
fn snapshot(managed: Option<&Target>) -> Vec<String> {
    let ours_server = managed.map(|target| {
        render_drop_in(target)
            .lines()
            .find_map(|line| line.strip_prefix("DNS=").map(str::to_owned))
            .unwrap_or_default()
    });
    let ours_domain = managed.map(|target| format!("~{}", target.domain()));
    let mut lines = Vec::new();
    for (kind, ours) in [("dns", &ours_server), ("domain", &ours_domain)] {
        let Ok(text) = run("resolvectl", &[kind]) else {
            continue;
        };
        for line in text.lines() {
            let Some((scope, values)) = line.split_once(':') else {
                continue;
            };
            let mut values: Vec<&str> = values
                .split_whitespace()
                .filter(|value| Some(*value) != ours.as_deref())
                .collect();
            values.sort_unstable();
            lines.push(format!("{kind} {}: {}", scope.trim(), values.join(" ")));
        }
    }
    lines.sort();
    lines
}

#[cfg(test)]
mod tests {
    use super::*;

    fn target(port: u16) -> Target {
        Target {
            server: "192.168.1.10".parse().unwrap(),
            port,
            zone: "home.arpa.".into(),
        }
    }

    #[test]
    fn drop_ins_round_trip_and_ignore_foreign_files() {
        for port in [53, 5354] {
            let text = render_drop_in(&target(port));
            assert!(text.contains("Domains=~home.arpa\n"));
            assert_eq!(parse_drop_in(&text, "home.arpa."), Some(target(port)));
            assert_eq!(parse_drop_in(&text, "dev.test."), None);
        }
        assert_eq!(
            parse_drop_in(
                "[Resolve]\nDNS=192.168.1.10\nDomains=~home.arpa\n",
                "home.arpa."
            ),
            None
        );
        let v6 = Target {
            server: "fd00::10".parse().unwrap(),
            port: 5354,
            zone: "home.arpa.".into(),
        };
        assert!(render_drop_in(&v6).contains("DNS=[fd00::10]:5354\n"));
        assert_eq!(parse_drop_in(&render_drop_in(&v6), "home.arpa."), Some(v6));
    }

    #[test]
    fn dns_assignments_follow_reset_semantics() {
        let text = "[Resolve]\nDNS=1.1.1.1 9.9.9.9\n#DNS=8.8.8.8\n[Other]\nDNS=5.5.5.5\n";
        assert_eq!(dns_assignments(text), ["1.1.1.1", "9.9.9.9"]);
        assert_eq!(
            dns_assignments("[Resolve]\nDNS=1.1.1.1\nDNS=\n"),
            [] as [&str; 0]
        );
        assert_eq!(
            dns_assignments("[Resolve]\n#DNS=\nDomains=lan\n"),
            [] as [&str; 0]
        );
    }
}
