//! Windows: a Name Resolution Policy Table rule sends only `.zone` queries to localname.
//! VPN clients use their own NRPT rules and interface DNS servers, which stay untouched.

use anyhow::{Result, anyhow, bail};
use serde::Deserialize;

use super::{ClientState, Target, run};

const COMMENT: &str = "Managed by localname";

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Rule {
    name: String,
    #[serde(default, deserialize_with = "one_or_many")]
    namespace: Vec<String>,
    #[serde(default, deserialize_with = "one_or_many")]
    name_servers: Vec<String>,
    #[serde(default)]
    comment: Option<String>,
}

/// `ConvertTo-Json` emits a single value instead of a one-element array.
fn one_or_many<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Value {
        One(String),
        Many(Vec<String>),
        Null(()),
    }
    Ok(match Value::deserialize(deserializer)? {
        Value::One(value) => vec![value],
        Value::Many(values) => values,
        Value::Null(()) => Vec::new(),
    })
}

fn powershell(script: &str) -> Result<String> {
    run(
        "powershell.exe",
        &[
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            // UTF-8 output: interface names are localized and the OEM code page mangles them.
            &format!(
                "[Console]::OutputEncoding = [Text.Encoding]::UTF8; $ErrorActionPreference = 'Stop'; {script}"
            ),
        ],
    )
}

fn rules() -> Result<Vec<Rule>> {
    let text = powershell(
        "@(Get-DnsClientNrptRule | Select-Object Name, Namespace, NameServers, Comment) | ConvertTo-Json -Depth 3 -Compress",
    )?;
    let text = text.trim();
    if text.is_empty() {
        return Ok(Vec::new());
    }
    if text.starts_with('[') {
        Ok(serde_json::from_str(text)?)
    } else {
        Ok(vec![serde_json::from_str(text)?])
    }
}

fn namespace(zone: &str) -> String {
    format!(".{}", zone.trim_end_matches('.'))
}

fn is_ours(rule: &Rule) -> bool {
    rule.comment.as_deref() == Some(COMMENT)
}

pub fn detect(zone: &str) -> Result<ClientState> {
    let wanted = namespace(zone);
    let rules = rules()?;
    let mut state = ClientState {
        backend: "windows-nrpt",
        unsupported: None,
        artifact: format!("NRPT rule for {wanted}"),
        managed: None,
        conflicts: Vec::new(),
        preserved: Vec::new(),
    };
    for rule in &rules {
        let covers = rule
            .namespace
            .iter()
            .any(|namespace| namespace.eq_ignore_ascii_case(&wanted));
        if !covers {
            continue;
        }
        if is_ours(rule) {
            state.managed = rule
                .name_servers
                .first()
                .and_then(|server| server.parse().ok())
                .map(|server| Target {
                    server,
                    port: 53,
                    zone: zone.to_owned(),
                });
        } else {
            state.conflicts.push(format!(
                "NRPT rule {} already routes {wanted} to {}",
                rule.name,
                rule.name_servers.join(", ")
            ));
        }
    }
    state.preserved = snapshot(&rules, &wanted)?;
    Ok(state)
}

pub fn apply(target: &Target) -> Result<()> {
    if target.port != 53 {
        bail!("invalid port: Windows NRPT rules only support DNS servers on port 53");
    }
    let wanted = namespace(&target.zone);
    // Replace localname's own rule for the zone; foreign rules were refused in detect.
    let script = format!(
        "Get-DnsClientNrptRule | Where-Object {{ $_.Comment -eq '{COMMENT}' -and $_.Namespace -contains '{wanted}' }} | ForEach-Object {{ Remove-DnsClientNrptRule -Name $_.Name -Force }}; \
         Add-DnsClientNrptRule -Namespace '{wanted}' -NameServers '{}' -Comment '{COMMENT}' -DisplayName 'localname {}' | Out-Null; \
         Clear-DnsClientCache",
        target.server,
        target.domain()
    );
    powershell(&script).map(drop)
}

pub fn remove(zone: &str) -> Result<()> {
    let wanted = namespace(zone);
    powershell(&format!(
        "Get-DnsClientNrptRule | Where-Object {{ $_.Comment -eq '{COMMENT}' -and $_.Namespace -contains '{wanted}' }} | ForEach-Object {{ Remove-DnsClientNrptRule -Name $_.Name -Force }}; Clear-DnsClientCache"
    ))
    .map(drop)
}

/// Other NRPT rules, per-interface DNS servers and suffixes, and the global suffix list.
fn snapshot(rules: &[Rule], wanted: &str) -> Result<Vec<String>> {
    let mut lines: Vec<String> = rules
        .iter()
        .filter(|rule| !(is_ours(rule) && rule.namespace.iter().any(|n| n == wanted)))
        .map(|rule| {
            format!(
                "nrpt {} -> {}",
                rule.namespace.join(","),
                rule.name_servers.join(",")
            )
        })
        .collect();
    let interfaces = powershell(
        "Get-DnsClient | ForEach-Object { $servers = (Get-DnsClientServerAddress -InterfaceIndex $_.InterfaceIndex -ErrorAction SilentlyContinue).ServerAddresses -join ','; 'interface ' + $_.InterfaceAlias + ' suffix=' + $_.ConnectionSpecificSuffix + ' dns=' + $servers }; 'search ' + ((Get-DnsClientGlobalSetting).SuffixSearchList -join ',')",
    )
    .map_err(|error| anyhow!("failed to read DNS client settings: {error:#}"))?;
    lines.extend(
        interfaces
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty())
            .map(str::to_owned),
    );
    lines.sort();
    lines.dedup();
    Ok(lines)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_and_multiple_rule_json_parse() {
        let one: Rule = serde_json::from_str(
            r#"{"Name":"{1}","Namespace":".home.arpa","NameServers":"192.168.1.10","Comment":"Managed by localname"}"#,
        )
        .unwrap();
        assert_eq!(one.namespace, [".home.arpa"]);
        assert!(is_ours(&one));
        let many: Vec<Rule> = serde_json::from_str(
            r#"[{"Name":"{2}","Namespace":[".corp.example","corp.example"],"NameServers":["10.8.0.1"],"Comment":null}]"#,
        )
        .unwrap();
        assert_eq!(many[0].namespace.len(), 2);
        assert!(!is_ours(&many[0]));
    }
}
