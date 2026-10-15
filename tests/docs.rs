//! CLI, output schema, documentation, and the agent skill must agree (M5). Docs may only
//! name commands and flags that exist; every command is documented; the shipped skill and
//! schema are what the binary serves; and real outputs match the schema. The docs cover
//! the full default build, so this runs only with every feature enabled.
#![cfg(all(feature = "proxy", feature = "https"))]

use std::{collections::BTreeSet, path::Path, process::Command};

use localname::error::ErrorCode;
use serde_json::Value;

fn localname(arguments: &[&str]) -> Value {
    let output = Command::new(env!("CARGO_BIN_EXE_localname"))
        .args(arguments)
        .output()
        .unwrap();
    serde_json::from_slice(&output.stdout)
        .unwrap_or_else(|error| panic!("{arguments:?}: {error}: {output:?}"))
}

/// (command path without "localname", help text) for every command.
fn reference() -> Vec<(Vec<String>, String)> {
    localname(&["skill", "--output", "json"])["data"]["cli_reference"]
        .as_array()
        .unwrap()
        .iter()
        .map(|entry| {
            let path = entry["command"]
                .as_str()
                .unwrap()
                .split_whitespace()
                .skip(1)
                .map(str::to_owned)
                .collect();
            (path, entry["help"].as_str().unwrap().to_owned())
        })
        .collect()
}

fn documents() -> Vec<(&'static str, String)> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    ["README.md", "skills/localname/SKILL.md"]
        .into_iter()
        .map(|name| (name, std::fs::read_to_string(root.join(name)).unwrap()))
        .collect()
}

/// Every `localname ...` invocation in inline code spans and console blocks.
fn invocations(text: &str) -> Vec<String> {
    let mut found = Vec::new();
    let mut in_block = false;
    for line in text.lines() {
        if line.trim_start().starts_with("```") {
            in_block = !in_block;
            continue;
        }
        if in_block {
            let line = line.trim();
            let line = line
                .strip_prefix("sudo -E ")
                .or_else(|| line.strip_prefix("sudo "))
                .unwrap_or(line);
            if line.starts_with("localname ") {
                found.push(line.to_owned());
            }
            continue;
        }
        for span in line.split('`').skip(1).step_by(2) {
            let span = span.strip_prefix("sudo ").unwrap_or(span);
            if span.starts_with("localname ") {
                found.push(span.to_owned());
            }
        }
    }
    found
}

/// The command a documented invocation names, and the flags it uses.
fn parse(
    invocation: &str,
    commands: &[(Vec<String>, String)],
) -> Option<(Vec<String>, Vec<String>)> {
    let words: Vec<&str> = invocation
        .split('#')
        .next()?
        .split_whitespace()
        .skip(1)
        .collect();
    let mut path = Vec::new();
    let mut flags = Vec::new();
    let mut skip_value = false;
    for word in words {
        if skip_value {
            skip_value = false;
            continue;
        }
        if let Some(flag) = word.strip_prefix("--") {
            let flag = flag.split('=').next().unwrap_or(flag).to_owned();
            if ["config", "output"].contains(&flag.as_str()) {
                skip_value = !word.contains('=');
                continue;
            }
            flags.push(flag);
            continue;
        }
        let mut candidate = path.clone();
        candidate.push(word.to_owned());
        if flags.is_empty() && commands.iter().any(|(command, _)| *command == candidate) {
            path = candidate;
        }
    }
    (!path.is_empty()).then_some((path, flags))
}

#[test]
fn documented_commands_and_flags_exist() {
    let commands = reference();
    let global = &commands.iter().find(|(path, _)| path.is_empty()).unwrap().1;
    let mut problems = Vec::new();
    for (document, text) in documents() {
        for invocation in invocations(&text) {
            let Some((path, flags)) = parse(&invocation, &commands) else {
                problems.push(format!(
                    "{document}: `{invocation}` names no localname command"
                ));
                continue;
            };
            let help = &commands
                .iter()
                .find(|(command, _)| *command == path)
                .unwrap()
                .1;
            for flag in flags {
                let spelled = format!("--{flag}");
                if !help.contains(&spelled) && !global.contains(&spelled) {
                    problems.push(format!(
                        "{document}: `{invocation}` uses {spelled}, which `localname {}` lacks",
                        path.join(" ")
                    ));
                }
            }
        }
    }
    assert!(
        problems.is_empty(),
        "documentation disagrees with the CLI:\n{}",
        problems.join("\n")
    );
}

#[test]
fn every_command_is_documented() {
    let text: String = documents().into_iter().map(|(_, text)| text).collect();
    let documented: BTreeSet<String> = invocations(&text)
        .iter()
        .filter_map(|invocation| invocation.split_whitespace().nth(1).map(str::to_owned))
        .collect();
    let missing: Vec<String> = reference()
        .into_iter()
        .filter(|(path, _)| path.len() == 1 && path[0] != "help")
        .map(|(path, _)| path[0].clone())
        .filter(|command| !documented.contains(command))
        .collect();
    assert!(
        missing.is_empty(),
        "commands missing from README.md and SKILL.md: {missing:?}"
    );
}

#[test]
fn the_binary_serves_the_shipped_skill_and_schema() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let skill = localname(&["skill", "--output", "json"]);
    assert_eq!(
        skill["data"]["instructions"],
        std::fs::read_to_string(root.join("skills/localname/SKILL.md")).unwrap()
    );
    let schema: Value = serde_json::from_str(
        &std::fs::read_to_string(root.join("schemas/output.schema.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(skill["data"]["output_schema"], schema);
    assert_eq!(skill["data"]["version"], env!("CARGO_PKG_VERSION"));
}

fn every_error_code() -> Vec<ErrorCode> {
    // An exhaustive match: adding a code without listing it here fails to compile.
    let all = [
        ErrorCode::InvalidInput,
        ErrorCode::PermissionRequired,
        ErrorCode::Conflict,
        ErrorCode::Unavailable,
        ErrorCode::VerificationFailed,
        ErrorCode::Internal,
    ];
    for code in all {
        match code {
            ErrorCode::InvalidInput
            | ErrorCode::PermissionRequired
            | ErrorCode::Conflict
            | ErrorCode::Unavailable
            | ErrorCode::VerificationFailed
            | ErrorCode::Internal => {}
        }
    }
    all.to_vec()
}

fn check_envelope(schema: &Value, envelope: &Value, context: &str) {
    let required: BTreeSet<&str> = schema["required"]
        .as_array()
        .unwrap()
        .iter()
        .map(|key| key.as_str().unwrap())
        .collect();
    let keys: BTreeSet<&str> = envelope
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    assert_eq!(
        keys, required,
        "{context}: envelope keys differ from the schema"
    );
    assert_eq!(envelope["schema_version"], "1", "{context}");
    assert!(
        envelope["ok"].is_boolean() && envelope["changed"].is_boolean(),
        "{context}"
    );
    assert!(
        envelope["revision"].is_null() || envelope["revision"].is_u64(),
        "{context}"
    );
    for key in ["warnings", "next_actions"] {
        assert!(
            envelope[key]
                .as_array()
                .unwrap()
                .iter()
                .all(Value::is_string),
            "{context}: {key}"
        );
    }
    assert!(
        envelope["verification"].is_null() || envelope["verification"].is_object(),
        "{context}"
    );
    assert!(
        envelope["rollback"].is_null() || envelope["rollback"].is_string(),
        "{context}"
    );
    let codes: Vec<&str> = schema["properties"]["error"]["properties"]["code"]["enum"]
        .as_array()
        .unwrap()
        .iter()
        .map(|code| code.as_str().unwrap())
        .collect();
    match &envelope["error"] {
        Value::Null => assert_eq!(envelope["ok"], true, "{context}"),
        error => {
            assert_eq!(envelope["ok"], false, "{context}");
            assert!(
                codes.contains(&error["code"].as_str().unwrap()),
                "{context}: unknown code {error}"
            );
            assert!(error["message"].is_string(), "{context}");
        }
    }
}

#[test]
fn outputs_match_the_schema() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let schema: Value = serde_json::from_str(
        &std::fs::read_to_string(root.join("schemas/output.schema.json")).unwrap(),
    )
    .unwrap();
    let codes: BTreeSet<String> = schema["properties"]["error"]["properties"]["code"]["enum"]
        .as_array()
        .unwrap()
        .iter()
        .map(|code| code.as_str().unwrap().to_owned())
        .collect();
    let known: BTreeSet<String> = every_error_code()
        .into_iter()
        .map(|code| code.as_str().to_owned())
        .collect();
    assert_eq!(codes, known, "schema error codes differ from ErrorCode");

    let directory = tempfile::tempdir().unwrap();
    let config = directory.path().join("config.toml");
    let config = config.to_str().unwrap();
    let missing = directory.path().join("missing.toml");
    let missing = missing.to_str().unwrap();
    for arguments in [
        vec!["version"],
        vec!["--config", missing, "status"],
        vec!["--config", missing, "list"],
        vec!["--config", config, "setup", "--local", "--apply"],
        vec!["--config", config, "add", "nas", "192.168.1.20"],
        vec![
            "--config",
            config,
            "add",
            "nas",
            "192.168.1.20",
            "--expect-revision",
            "0",
        ],
        vec!["--config", config, "list"],
        vec!["--config", config, "revisions"],
        vec!["--config", config, "rollback", "0", "--dry-run"],
        vec!["--config", config, "service", "list"],
        vec!["--config", config, "client", "status"],
        vec!["--config", config, "diagnose"],
        vec![
            "--config",
            config,
            "setup",
            "verify",
            "--server",
            "127.0.0.1",
            "--port",
            "9",
            "--timeout-ms",
            "200",
        ],
    ] {
        let mut full = arguments.clone();
        full.extend(["--output", "json"]);
        check_envelope(&schema, &localname(&full), &arguments.join(" "));
    }
}
