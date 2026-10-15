//! Backup and restore (M5): one file carries the configuration, revisions, and records;
//! restores keep local history; TLS keys never enter a backup; old formats migrate.

use std::{
    path::Path,
    process::{Command, Output},
};

use serde_json::Value;

fn run(path: &Path, arguments: &[&str]) -> Output {
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
    serde_json::from_slice(&output.stdout).unwrap_or_else(|error| panic!("{error}: {output:?}"))
}

fn ok(path: &Path, arguments: &[&str]) -> Value {
    let output = run(path, arguments);
    assert!(output.status.success(), "{arguments:?}: {output:?}");
    json(&output)
}

#[test]
fn backups_round_trip_and_exclude_keys() {
    let source = tempfile::tempdir().unwrap();
    let config = source.path().join("config.toml");
    ok(&config, &["setup", "--local", "--apply"]);
    ok(&config, &["add", "nas", "192.168.1.20"]);
    ok(&config, &["add", "storage", "nas"]);
    // Key material beside the configuration must never be copied.
    std::fs::create_dir_all(source.path().join("config.tls")).unwrap();
    std::fs::write(
        source.path().join("config.tls/ca.key"),
        "-----BEGIN PRIVATE KEY-----\nsecret\n",
    )
    .unwrap();

    let file = source.path().join("home.localname-backup");
    let created = ok(
        &config,
        &["backup", "create", "--out", file.to_str().unwrap()],
    );
    assert_eq!(created["data"]["revisions"], 2);
    assert!(
        created["data"]["records"]
            .as_array()
            .unwrap()
            .iter()
            .any(|record| record == "setup.json")
    );
    let text = std::fs::read_to_string(&file).unwrap();
    assert!(!text.contains("PRIVATE KEY") && !text.contains("secret"));
    let again = run(
        &config,
        &["backup", "create", "--out", file.to_str().unwrap()],
    );
    assert_eq!(again.status.code(), Some(5));

    // A fresh host takes the configuration, history, and records.
    let target = tempfile::tempdir().unwrap();
    let restored_path = target.path().join("config.toml");
    let preview = ok(
        &restored_path,
        &["backup", "restore", file.to_str().unwrap(), "--dry-run"],
    );
    assert_eq!(preview["data"]["creates_configuration"], true);
    assert!(!restored_path.exists());
    ok(
        &restored_path,
        &["backup", "restore", file.to_str().unwrap()],
    );
    assert_eq!(
        ok(&restored_path, &["list"])["data"],
        ok(&config, &["list"])["data"]
    );
    assert_eq!(
        ok(&restored_path, &["revisions"])["data"],
        ok(&config, &["revisions"])["data"]
    );
    assert!(target.path().join("config.setup.json").exists());
    assert!(!target.path().join("config.tls").exists());
    // The imported history is usable.
    let rolled = ok(&restored_path, &["rollback", "1"]);
    assert_eq!(rolled["revision"], 3);

    // Restoring over an existing configuration is a new, reversible revision.
    ok(&config, &["remove", "storage"]);
    ok(&config, &["remove", "nas"]);
    let restored = ok(
        &config,
        &[
            "backup",
            "restore",
            file.to_str().unwrap(),
            "--expect-revision",
            "4",
        ],
    );
    assert_eq!(restored["revision"], 5);
    assert_eq!(ok(&config, &["list"])["data"].as_array().unwrap().len(), 2);
    let undo = restored["rollback"].as_str().unwrap().to_owned();
    assert!(undo.ends_with("rollback 4"), "{undo}");
    let stale = run(
        &config,
        &[
            "backup",
            "restore",
            file.to_str().unwrap(),
            "--expect-revision",
            "4",
        ],
    );
    assert_eq!(stale.status.code(), Some(5));
}

#[test]
fn old_and_foreign_backups() {
    let directory = tempfile::tempdir().unwrap();
    let config = directory.path().join("config.toml");
    let schema_1 = serde_json::json!({
        "format": "localname-backup",
        "version": 1,
        "localname_version": "0.1.0",
        "created_unix": 0,
        "config": "schema = 1\nrevision = 3\nzone = \"home.arpa.\"\nlisten = [\"127.0.0.1:5354\"]\nupstreams = [\"1.1.1.1:53\"]\nallowed_clients = [\"127.0.0.0/8\"]\ncache_entries = 4096\nupstream_timeout_ms = 2000\nservices = []\n\n[[records]]\nname = \"nas.home.arpa.\"\nvalue = \"192.168.1.20\"\nttl = 60\n",
        "revisions": {},
        "records": {},
    });
    let old = directory.path().join("old.json");
    std::fs::write(&old, schema_1.to_string()).unwrap();
    ok(&config, &["backup", "restore", old.to_str().unwrap()]);
    let shown = ok(&config, &["config", "show"]);
    assert_eq!(shown["data"]["schema"], 2);
    assert_eq!(shown["data"]["rebind_protection"], true);
    assert_eq!(shown["revision"], 3);

    let future = directory.path().join("future.json");
    let mut newer = schema_1.clone();
    newer["version"] = 99.into();
    std::fs::write(&future, newer.to_string()).unwrap();
    assert_eq!(
        run(&config, &["backup", "restore", future.to_str().unwrap()])
            .status
            .code(),
        Some(3)
    );
    let junk = directory.path().join("junk.json");
    std::fs::write(&junk, "{\"format\":\"other\"}").unwrap();
    assert_eq!(
        run(&config, &["backup", "restore", junk.to_str().unwrap()])
            .status
            .code(),
        Some(3)
    );
}
