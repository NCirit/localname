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
fn setup_rejects_public_advertisements_before_writing_state() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory
        .path()
        .join("agent's device settings")
        .join("config.toml");
    let output = run(
        &path,
        &[
            "setup",
            "--apply",
            "--listen",
            "127.0.0.1:5354",
            "--advertise",
            "8.8.8.8",
        ],
    );
    assert_eq!(output.status.code(), Some(3));
    assert!(!path.exists());
}

#[test]
fn agent_bundle_is_available_without_configuration() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("missing.toml");
    let result = run(&path, &["skill"]);
    assert!(result.status.success());
    let data = json(&result);
    assert_eq!(data["data"]["version"], env!("CARGO_PKG_VERSION"));
    assert_eq!(
        data["data"]["output_schema"]["properties"]["schema_version"]["const"],
        "1"
    );
    assert!(
        data["data"]["cli_reference"]
            .as_array()
            .unwrap()
            .iter()
            .any(|entry| entry["command"] == "localname add")
    );
    assert!(!path.exists());
}

#[test]
fn custom_namespace_is_used_by_record_commands() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("config.toml");
    assert!(
        run(
            &path,
            &["setup", "--local", "--zone", "dev.test", "--apply"]
        )
        .status
        .success()
    );
    let output = run(&path, &["add", "api", "127.0.0.1"]);
    assert!(output.status.success());
    assert_eq!(json(&output)["data"]["name"], "api.dev.test.");
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

#[cfg(unix)]
#[test]
fn committed_change_with_failed_dns_readback_returns_rollback_data() {
    use localname::{
        Config, ConfigStore,
        control::{self, Request, Response},
    };
    use std::{
        io::{Read, Write},
        os::unix::net::UnixListener,
    };
    let directory = tempfile::tempdir().unwrap();
    let path = directory
        .path()
        .join("agent's device settings")
        .join("config.toml");
    let store = ConfigStore::new(&path);
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    store
        .initialize(&Config {
            listen: vec![format!("127.0.0.1:{port}").parse().unwrap()],
            ..Config::default()
        })
        .unwrap();
    let socket = UnixListener::bind(control::socket_path(&path)).unwrap();
    let server = std::thread::spawn(move || {
        let (mut stream, _) = socket.accept().unwrap();
        let mut size = [0; 4];
        stream.read_exact(&mut size).unwrap();
        let mut bytes = vec![0; u32::from_be_bytes(size) as usize];
        stream.read_exact(&mut bytes).unwrap();
        let frame: control::Frame<Request> = serde_json::from_slice(&bytes).unwrap();
        let config = control::apply(&store, frame.body).unwrap();
        let frame = serde_json::to_vec(&Response {
            config: Some(config),
            ..Response::default()
        })
        .unwrap();
        stream
            .write_all(&u32::try_from(frame.len()).unwrap().to_be_bytes())
            .unwrap();
        stream.write_all(&frame).unwrap();
    });
    let output = run(&path, &["add", "nas", "192.168.1.20"]);
    server.join().unwrap();
    assert_eq!(output.status.code(), Some(7));
    let result = json(&output);
    assert_eq!(result["changed"], true);
    assert_eq!(result["revision"], 1);
    assert_eq!(result["verification"]["status"], "failed");
    let rollback = result["rollback"].as_str().unwrap();
    let binary_directory = std::path::Path::new(env!("CARGO_BIN_EXE_localname"))
        .parent()
        .unwrap();
    let paths = std::iter::once(binary_directory.to_path_buf())
        .chain(std::env::split_paths(
            &std::env::var_os("PATH").unwrap_or_default(),
        ))
        .collect::<Vec<_>>();
    let restored = Command::new("sh")
        .arg("-c")
        .arg(rollback)
        .env("PATH", std::env::join_paths(paths).unwrap())
        .output()
        .unwrap();
    assert!(
        restored.status.success(),
        "{}",
        String::from_utf8_lossy(&restored.stderr)
    );
    assert!(ConfigStore::new(&path).load().unwrap().records.is_empty());
    assert_eq!(result["error"]["code"], "VERIFICATION_FAILED");
}

fn run_human(path: &std::path::Path, arguments: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_localname"))
        .arg("--config")
        .arg(path)
        .args(arguments)
        .output()
        .unwrap()
}

#[test]
fn human_and_json_flows_create_identical_state() {
    let steps: &[&[&str]] = &[
        &["setup", "--local", "--apply"],
        &["add", "nas", "192.168.1.20"],
        &["add", "nas", "fd00::20"],
        &["add", "storage", "nas"],
        &["remove", "nas", "--value", "fd00::20"],
        &["rollback", "1"],
    ];
    let human = tempfile::tempdir().unwrap();
    let machine = tempfile::tempdir().unwrap();
    let human_path = human.path().join("config.toml");
    let machine_path = machine.path().join("config.toml");
    for step in steps {
        let interactive = run_human(&human_path, step);
        assert!(interactive.status.success(), "{step:?}: {interactive:?}");
        let automated = run(&machine_path, &[step, &["--non-interactive"][..]].concat());
        assert!(automated.status.success(), "{step:?}: {automated:?}");
        assert_eq!(json(&automated)["ok"], true);
    }
    assert_eq!(
        std::fs::read_to_string(&human_path).unwrap(),
        std::fs::read_to_string(&machine_path).unwrap()
    );
    for revision in 0..5 {
        let name = format!("config.toml.revisions/{revision}.toml");
        assert_eq!(
            std::fs::read_to_string(human.path().join(&name)).unwrap(),
            std::fs::read_to_string(machine.path().join(&name)).unwrap(),
            "revision {revision}"
        );
    }
}

#[test]
fn rollback_previews_and_checks_revisions() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.toml");
    assert!(
        run(&path, &["setup", "--local", "--apply"])
            .status
            .success()
    );
    assert!(run(&path, &["add", "nas", "192.168.1.20"]).status.success());
    assert!(
        run(&path, &["add", "printer", "192.168.1.30"])
            .status
            .success()
    );
    let preview = json(&run(&path, &["rollback", "0", "--dry-run"]));
    assert_eq!(preview["data"]["preview"], true);
    assert_eq!(
        preview["data"]["records_removed"].as_array().unwrap().len(),
        2
    );
    assert_eq!(preview["revision"], 2);
    let stale = run(&path, &["rollback", "0", "--expect-revision", "1"]);
    assert_eq!(stale.status.code(), Some(5));
    let missing = run(&path, &["rollback", "99"]);
    assert_eq!(missing.status.code(), Some(3));
    assert_eq!(json(&missing)["error"]["code"], "INVALID_INPUT");
    let history = json(&run(&path, &["revisions"]));
    assert_eq!(history["data"]["current"], 2);
    assert_eq!(history["data"]["restorable"].as_array().unwrap().len(), 2);
    let restored = json(&run(&path, &["rollback", "1", "--expect-revision", "2"]));
    assert_eq!(restored["revision"], 3);
    assert_eq!(
        restored["data"]["records_removed"][0]["name"],
        "printer.home.arpa."
    );
    assert!(
        restored["rollback"]
            .as_str()
            .unwrap()
            .ends_with("rollback 2")
    );
    let records = json(&run(&path, &["list"]));
    assert_eq!(records["data"].as_array().unwrap().len(), 1);
}

struct Daemon(std::process::Child);

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn live_daemon_mutations_are_verified_and_status_reports_counters() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.toml");
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let config = format!(
        "zone = \"home.arpa\"\nlisten = [\"127.0.0.1:{port}\"]\nupstreams = [\"127.0.0.1:9\"]\nallowed_clients = [\"127.0.0.0/8\"]\n"
    );
    std::fs::write(&path, config).unwrap();
    let _daemon = Daemon(
        Command::new(env!("CARGO_BIN_EXE_localname"))
            .arg("--config")
            .arg(&path)
            .arg("serve")
            .spawn()
            .unwrap(),
    );
    for _ in 0..100 {
        let status = run(&path, &["status", "--check"]);
        if status.status.success() && !json(&status)["data"]["daemon"].is_null() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    let added = json(&run(&path, &["add", "nas", "192.168.1.20"]));
    assert_eq!(added["verification"]["status"], "passed", "{added}");
    let alias = json(&run(&path, &["add", "files", "nas"]));
    assert_eq!(alias["verification"]["status"], "passed", "{alias}");
    let removed = json(&run(&path, &["remove", "files"]));
    assert_eq!(removed["verification"]["status"], "passed", "{removed}");
    let restored = json(&run(&path, &["rollback", "0"]));
    assert_eq!(restored["verification"]["status"], "passed", "{restored}");
    assert_eq!(restored["revision"], 4);
    let status = json(&run(&path, &["status"]));
    assert_eq!(status["data"]["healthy"], true);
    assert_eq!(status["data"]["daemon"]["revision"], 4);
    assert!(
        status["data"]["daemon"]["metrics"]["local"]
            .as_u64()
            .unwrap()
            >= 4
    );
    let diagnosis = json(&run(&path, &["diagnose"]));
    assert_eq!(diagnosis["data"]["daemon"]["status"], "running");
    assert_eq!(diagnosis["data"]["resolution"]["status"], "passed");
    let offline_writer = run(
        &path,
        &["add", "late", "192.168.1.99", "--expect-revision", "3"],
    );
    assert_eq!(offline_writer.status.code(), Some(5));
}
