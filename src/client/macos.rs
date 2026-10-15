//! macOS: `/etc/resolver/<zone>` makes mDNSResponder send only that zone's queries to
//! localname. Other resolver files, VPN DNS, and search domains are untouched.

use std::{
    fmt::Write as _,
    fs,
    io::Write,
    net::IpAddr,
    path::{Path, PathBuf},
};

use anyhow::Result;

use super::{ClientState, MARKER, Target, header, run};

const RESOLVER_DIRECTORY: &str = "/etc/resolver";

fn artifact(zone: &str) -> PathBuf {
    Path::new(RESOLVER_DIRECTORY).join(zone.trim_end_matches('.'))
}

pub fn detect(zone: &str) -> Result<ClientState> {
    let path = artifact(zone);
    let mut state = ClientState {
        backend: "macos-resolver",
        unsupported: None,
        artifact: path.display().to_string(),
        managed: None,
        conflicts: Vec::new(),
        preserved: Vec::new(),
    };
    match fs::read_to_string(&path) {
        Ok(text) => {
            state.managed = parse_resolver(&text, zone);
            if state.managed.is_none() {
                state.conflicts.push(format!(
                    "{} exists and is not managed by localname",
                    path.display()
                ));
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    state.preserved = snapshot(&path);
    Ok(state)
}

pub fn apply(target: &Target) -> Result<()> {
    fs::create_dir_all(RESOLVER_DIRECTORY)?;
    let path = artifact(&target.zone);
    let mut temporary = tempfile::Builder::new()
        .prefix(".localname-")
        .tempfile_in(RESOLVER_DIRECTORY)?;
    temporary.write_all(render_resolver(target).as_bytes())?;
    temporary.as_file().sync_all()?;
    temporary.persist(&path).map_err(|error| error.error)?;
    let mut permissions = fs::metadata(&path)?.permissions();
    std::os::unix::fs::PermissionsExt::set_mode(&mut permissions, 0o644);
    fs::set_permissions(&path, permissions)?;
    flush();
    Ok(())
}

pub fn remove(zone: &str) -> Result<()> {
    fs::remove_file(artifact(zone))?;
    flush();
    Ok(())
}

fn flush() {
    let _ = run("dscacheutil", &["-flushcache"]);
    let _ = run("killall", &["-HUP", "mDNSResponder"]);
}

pub fn render_resolver(target: &Target) -> String {
    let mut text = format!(
        "{}\nnameserver {}\n",
        header(target.domain()),
        target.server
    );
    if target.port != 53 {
        let _ = writeln!(text, "port {}", target.port);
    }
    text
}

pub fn parse_resolver(text: &str, zone: &str) -> Option<Target> {
    if !text.contains(MARKER) {
        return None;
    }
    let mut server = None;
    let mut port = 53;
    for line in text.lines() {
        let mut words = line.split_whitespace();
        match words.next() {
            Some("nameserver") => server = words.next()?.parse::<IpAddr>().ok(),
            Some("port") => port = words.next()?.parse().ok()?,
            _ => {}
        }
    }
    Some(Target {
        server: server?,
        port,
        zone: zone.to_owned(),
    })
}

/// Other resolver files and the search domains macOS reports.
fn snapshot(ours: &Path) -> Vec<String> {
    let mut lines = Vec::new();
    if let Ok(entries) = fs::read_dir(RESOLVER_DIRECTORY) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path == ours
                || path
                    .file_name()
                    .is_some_and(|name| name.to_string_lossy().starts_with('.'))
            {
                continue;
            }
            let content = fs::read_to_string(&path).unwrap_or_default();
            lines.push(format!(
                "resolver {}: {}",
                path.display(),
                content.split_whitespace().collect::<Vec<_>>().join(" ")
            ));
        }
    }
    if let Ok(text) = run("scutil", &["--dns"]) {
        let ours_server = fs::read_to_string(ours)
            .ok()
            .and_then(|text| parse_resolver(&text, "x."))
            .map(|target| target.server.to_string());
        for line in text.lines().map(str::trim) {
            if line.starts_with("search domain") {
                if let Some((_, domain)) = line.split_once(':') {
                    lines.push(format!("search {}", domain.trim()));
                }
            } else if line.starts_with("nameserver")
                && let Some((_, server)) = line.split_once(':')
                && Some(server.trim().to_owned()) != ours_server
            {
                lines.push(format!("nameserver {}", server.trim()));
            }
        }
    }
    lines.sort();
    lines.dedup();
    lines
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolver_files_round_trip() {
        let target = Target {
            server: "192.168.1.10".parse().unwrap(),
            port: 5354,
            zone: "home.arpa.".into(),
        };
        let text = render_resolver(&target);
        assert!(text.contains("nameserver 192.168.1.10\nport 5354\n"));
        assert_eq!(parse_resolver(&text, "home.arpa."), Some(target));
        assert_eq!(parse_resolver("nameserver 10.0.0.1\n", "home.arpa."), None);
    }
}
