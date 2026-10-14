use std::process::{Command, Output};

use serde_json::Value;

fn run(path: &std::path::Path, arguments: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_localname"))
        .arg("--config")
        .arg(path)
        .args(arguments)
        .arg("--output")
        .arg("json")
        .output()
        .unwrap()
}

fn json(output: &Output) -> Value {
    serde_json::from_slice(&output.stdout).unwrap()
}

#[test]
fn record_workflow_is_idempotent_and_reversible() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.toml");
    assert!(
        run(&path, &["setup", "--local", "--apply"])
            .status
            .success()
    );
    let preview = run(&path, &["add", "nas", "192.168.1.20", "--dry-run"]);
    assert!(preview.status.success());
    assert_eq!(json(&run(&path, &["list"]))["revision"], 0);
    let added = run(
        &path,
        &["add", "nas", "192.168.1.20", "--expect-revision", "0"],
    );
    assert!(added.status.success());
    assert_eq!(json(&added)["revision"], 1);
    let repeated = run(&path, &["add", "NAS", "192.168.1.20"]);
    assert!(repeated.status.success());
    assert_eq!(json(&repeated)["changed"], false);
    let stale = run(&path, &["remove", "nas", "--expect-revision", "0"]);
    assert_eq!(stale.status.code(), Some(5));
    assert_eq!(json(&stale)["error"]["code"], "CONFLICT");
    let restored = run(&path, &["rollback", "0"]);
    assert!(restored.status.success());
    assert_eq!(json(&run(&path, &["list"]))["data"], serde_json::json!([]));
}

#[test]
fn errors_are_machine_readable() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("missing.toml");
    let result = run(&path, &["list"]);
    assert!(!result.status.success());
    assert_eq!(json(&result)["ok"], false);
}

#[test]
fn cname_repeated_add_does_not_duplicate_canonical_target() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.toml");
    assert!(
        run(&path, &["setup", "--local", "--apply"])
            .status
            .success()
    );
    assert!(run(&path, &["add", "nas", "192.168.1.20"]).status.success());
    assert!(run(&path, &["add", "storage", "nas"]).status.success());
    let result = run(&path, &["add", "storage", "nas"]);
    assert!(result.status.success());
    assert_eq!(json(&result)["changed"], false);
}
