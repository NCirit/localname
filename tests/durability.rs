//! Decision 13 gates for the TOML store: concurrency, interrupted writes, schema handling,
//! and 10,000-record scale.

use std::{
    path::Path,
    process::{Command, Stdio},
    time::{Duration, Instant},
};

use localname::{Config, ConfigStore, RecordConfig};

fn localname(path: &Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_localname"));
    command
        .arg("--config")
        .arg(path)
        .arg("--output")
        .arg("json")
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    command
}

fn initialize(path: &Path) {
    ConfigStore::new(path)
        .initialize(&Config::default())
        .unwrap();
}

/// Every stored revision is valid and records the history: revision N holds N hosts.
fn assert_consistent(path: &Path) -> Config {
    let store = ConfigStore::new(path);
    let config = store.load().expect("live configuration stays valid");
    assert_eq!(config.records.len() as u64, config.revision);
    for revision in store.revisions().unwrap() {
        let mut stored = store.load_revision(revision).unwrap();
        stored.validate().unwrap();
        assert_eq!(stored.revision, revision);
        assert_eq!(stored.records.len() as u64, revision);
    }
    config
}

#[test]
fn concurrent_writers_never_lose_updates() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("config.toml");
    initialize(&path);
    let writers: Vec<_> = (0..16)
        .map(|index| {
            localname(&path)
                .args(["add", &format!("host{index}"), &format!("10.0.0.{index}")])
                .spawn()
                .unwrap()
        })
        .collect();
    for mut writer in writers {
        assert!(writer.wait().unwrap().success());
    }
    let config = assert_consistent(&path);
    assert_eq!(config.revision, 16);
    assert_eq!(
        ConfigStore::new(&path).revisions().unwrap(),
        (0..16).collect::<Vec<_>>()
    );
}

#[test]
fn pinned_concurrent_writers_conflict_instead_of_overwriting() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("config.toml");
    initialize(&path);
    let writers: Vec<_> = (0..8)
        .map(|index| {
            localname(&path)
                .args(["add", &format!("host{index}"), &format!("10.0.0.{index}")])
                .args(["--expect-revision", "0"])
                .spawn()
                .unwrap()
        })
        .collect();
    let succeeded = writers
        .into_iter()
        .map(|mut writer| writer.wait().unwrap())
        .filter(|status| {
            assert!(status.success() || status.code() == Some(5), "{status}");
            status.success()
        })
        .count();
    assert_eq!(succeeded, 1);
    assert_eq!(assert_consistent(&path).revision, 1);
}

#[cfg(unix)]
#[test]
fn killed_writers_leave_a_valid_revision() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("config.toml");
    initialize(&path);
    for index in 0..60_u64 {
        let mut writer = localname(&path)
            .args(["add", &format!("host{index}"), "10.0.0.1"])
            .spawn()
            .unwrap();
        std::thread::sleep(Duration::from_micros((index * 397) % 12_000));
        // SIGKILL: no destructors, no cleanup, possibly mid-write.
        let _ = writer.kill();
        let _ = writer.wait();
        assert_consistent(&path);
    }
    // A later successful write removes temporaries abandoned by killed writers.
    assert!(
        localname(&path)
            .args(["add", "final", "10.0.0.2"])
            .status()
            .unwrap()
            .success()
    );
    assert_consistent(&path);
    let leftovers: Vec<_> = std::fs::read_dir(directory.path())
        .unwrap()
        .chain(std::fs::read_dir(directory.path().join("config.toml.revisions")).unwrap())
        .filter_map(Result::ok)
        .filter(|entry| entry.file_name().to_string_lossy().ends_with(".tmp"))
        .collect();
    assert!(leftovers.is_empty(), "{leftovers:?}");
}

#[test]
fn newer_schemas_are_refused_without_modification() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("config.toml");
    let text = "schema = 2\nzone = \"home.arpa\"\nfuture_setting = true\n";
    std::fs::write(&path, text).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_localname"))
        .arg("--config")
        .arg(&path)
        .args(["add", "nas", "192.168.1.20", "--output", "json"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(3));
    let result: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(
        result["error"]["message"]
            .as_str()
            .unwrap()
            .contains("newer localname")
    );
    assert_eq!(std::fs::read_to_string(&path).unwrap(), text);
}

#[test]
fn ten_thousand_records_round_trip() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("config.toml");
    let store = ConfigStore::new(&path);
    let config = Config {
        records: (0..10_000)
            .map(|index: u32| RecordConfig {
                name: format!("host{index}"),
                value: format!(
                    "10.{}.{}.{}",
                    index >> 16,
                    (index >> 8) & 0xff,
                    index & 0xff
                ),
                ttl: 60,
            })
            .collect(),
        ..Config::default()
    };
    store.initialize(&config).unwrap();
    let started = Instant::now();
    let (_, next) = store
        .mutate(Some(0), |config| {
            config.records.push(RecordConfig {
                name: "extra".into(),
                value: "10.255.0.1".into(),
                ttl: 60,
            });
            Ok(())
        })
        .unwrap();
    let elapsed = started.elapsed();
    assert_eq!(next.records.len(), 10_001);
    assert_eq!(store.load().unwrap().records.len(), 10_001);
    assert_eq!(store.rollback(0).unwrap().records.len(), 10_000);
    // Generous bound for unoptimized CI builds; release builds are far faster.
    assert!(
        elapsed < Duration::from_secs(10),
        "mutation took {elapsed:?}"
    );
    eprintln!("10,000-record mutation: {elapsed:?}");
}
