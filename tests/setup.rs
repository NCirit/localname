//! Guided setup: plan, apply, rollback of captured state, blocking checks, and
//! end-to-end verification against a live daemon (decision 8).

use std::{
    net::UdpSocket,
    path::Path,
    process::{Command, Output},
    time::Duration,
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
    serde_json::from_slice(&output.stdout)
        .unwrap_or_else(|error| panic!("{error}: {}", String::from_utf8_lossy(&output.stdout)))
}

fn free_port() -> u16 {
    // A port free for both transports, as the listener needs UDP and TCP.
    loop {
        let tcp = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = tcp.local_addr().unwrap().port();
        if UdpSocket::bind(("127.0.0.1", port)).is_ok() {
            return port;
        }
    }
}

fn apply(path: &Path, port: u16) -> Output {
    let listen = format!("127.0.0.1:{port}");
    run(
        path,
        &[
            "setup",
            "--apply",
            "--listen",
            &listen,
            "--advertise",
            "192.168.1.10",
        ],
    )
}

struct Daemon(std::process::Child);

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn start(path: &Path) -> Daemon {
    let daemon = Daemon(
        Command::new(env!("CARGO_BIN_EXE_localname"))
            .arg("--config")
            .arg(path)
            .arg("serve")
            .spawn()
            .unwrap(),
    );
    for _ in 0..100 {
        let status = run(path, &["status", "--check"]);
        if status.status.success() && !json(&status)["data"]["daemon"].is_null() {
            return daemon;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    panic!("daemon did not become ready");
}

#[test]
fn plan_names_one_router_action_and_changes_nothing() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("config.toml");
    let listen = format!("127.0.0.1:{}", free_port());
    let output = run(
        &path,
        &["setup", "--listen", &listen, "--advertise", "192.168.1.10"],
    );
    assert!(output.status.success(), "{output:?}");
    let plan = json(&output);
    assert_eq!(plan["changed"], false);
    assert!(!path.exists());
    let action = &plan["data"]["router_action"];
    assert_eq!(action["dns_server"], "192.168.1.10");
    assert!(
        action["summary"]
            .as_str()
            .unwrap()
            .contains("LAN/DHCP DNS server to 192.168.1.10")
    );
    assert!(action["restore"].as_str().unwrap().contains("automatic"));
    let checks: Vec<&str> = plan["data"]["checks"]
        .as_array()
        .unwrap()
        .iter()
        .map(|check| check["id"].as_str().unwrap())
        .collect();
    for id in [
        "lan_address",
        "port",
        "ipv6_dns",
        "forwarding_loop",
        "isolation",
        "rebinding",
        "private_dns",
    ] {
        assert!(checks.contains(&id), "missing {id} in {checks:?}");
    }
    assert_eq!(plan["data"]["host_record"], "localname.home.arpa.");
}

#[test]
fn applied_setup_rolls_back_to_no_configuration() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("config.toml");
    let applied = apply(&path, free_port());
    assert!(applied.status.success(), "{applied:?}");
    let applied = json(&applied);
    assert_eq!(applied["changed"], true);
    assert_eq!(applied["revision"], 0);
    assert!(
        applied["rollback"]
            .as_str()
            .unwrap()
            .ends_with("setup rollback")
    );
    let records = json(&run(&path, &["list"]));
    assert_eq!(records["data"][0]["name"], "localname.home.arpa.");
    assert_eq!(records["data"][0]["value"], "192.168.1.10");

    let preview = json(&run(&path, &["setup", "rollback", "--dry-run"]));
    assert_eq!(preview["data"]["removes_configuration"], true);
    assert!(path.exists());
    let rolled_back = run(&path, &["setup", "rollback"]);
    assert!(rolled_back.status.success(), "{rolled_back:?}");
    assert!(
        json(&rolled_back)["next_actions"][0]
            .as_str()
            .unwrap()
            .contains("back to automatic")
    );
    assert!(!path.exists());
    assert!(!path.with_extension("setup.json").exists());
    let again = run(&path, &["setup", "rollback"]);
    assert_eq!(again.status.code(), Some(3));
}

#[test]
fn rollback_refuses_after_later_changes() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("config.toml");
    assert!(apply(&path, free_port()).status.success());
    assert!(run(&path, &["add", "nas", "192.168.1.20"]).status.success());
    let refused = run(&path, &["setup", "rollback"]);
    assert_eq!(refused.status.code(), Some(5));
    assert_eq!(json(&refused)["error"]["code"], "CONFLICT");
    assert!(path.exists());
}

#[test]
fn reapplying_updates_existing_configuration_and_rolls_back_as_revision() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("config.toml");
    assert!(
        run(&path, &["setup", "--local", "--apply"])
            .status
            .success()
    );
    assert!(run(&path, &["add", "nas", "192.168.1.20"]).status.success());
    let local = json(&run(&path, &["config", "show"]))["data"]["listen"][0].clone();
    let port = free_port();
    let applied = json(&apply(&path, port));
    assert_eq!(applied["revision"], 2);
    let config = json(&run(&path, &["config", "show"]));
    assert_eq!(config["data"]["listen"][0], format!("127.0.0.1:{port}"));
    assert_eq!(config["data"]["records"].as_array().unwrap().len(), 2);
    let stale = run(
        &path,
        &[
            "setup",
            "--apply",
            "--listen",
            &format!("127.0.0.1:{}", free_port()),
            "--expect-revision",
            "1",
        ],
    );
    assert_eq!(stale.status.code(), Some(5));

    let rolled_back = json(&run(&path, &["setup", "rollback"]));
    assert_eq!(rolled_back["revision"], 3);
    let config = json(&run(&path, &["config", "show"]));
    assert_eq!(config["data"]["listen"][0], local);
    assert_eq!(config["data"]["records"].as_array().unwrap().len(), 1);
}

#[test]
fn port_conflicts_block_apply_with_a_specific_remedy() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("config.toml");
    let holder = UdpSocket::bind("127.0.0.1:0").unwrap();
    let port = holder.local_addr().unwrap().port();
    let output = apply(&path, port);
    assert_eq!(output.status.code(), Some(5), "{output:?}");
    let result = json(&output);
    assert_eq!(result["ok"], false);
    assert_eq!(result["error"]["code"], "CONFLICT");
    let conflict = result["data"]["checks"]
        .as_array()
        .unwrap()
        .iter()
        .find(|check| check["id"] == "port_conflict")
        .unwrap_or_else(|| panic!("{result}"));
    assert_eq!(conflict["status"], "fail");
    assert!(conflict["summary"].as_str().unwrap().contains("UDP"));
    assert!(!result["next_actions"].as_array().unwrap().is_empty());
    assert!(!path.exists());
    drop(holder);
}

#[test]
fn verify_checks_udp_and_tcp_against_the_live_listener() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("config.toml");
    let port = free_port();
    assert!(apply(&path, port).status.success());
    let _daemon = start(&path);

    // From the server's own configuration.
    let local = run(&path, &["setup", "verify"]);
    assert!(local.status.success(), "{local:?}");
    let local = json(&local);
    assert_eq!(local["verification"]["status"], "passed");
    assert_eq!(local["data"]["scope"], "this_host");
    assert_eq!(local["data"]["addresses"][0], "192.168.1.10");
    let status = |id: &str| {
        local["data"]["checks"]
            .as_array()
            .unwrap()
            .iter()
            .find(|check| check["id"] == id)
            .unwrap_or_else(|| panic!("missing {id}: {local}"))["status"]
            .clone()
    };
    assert_eq!(status("udp"), "pass");
    assert_eq!(status("tcp"), "pass");
    assert_eq!(status("forwarding_loop"), "pass");

    // As a device without configuration, pointed at the server.
    let elsewhere = tempfile::tempdir().unwrap();
    let other = elsewhere.path().join("absent.toml");
    let port_text = port.to_string();
    let remote = run(
        &other,
        &[
            "setup",
            "verify",
            "--server",
            "127.0.0.1",
            "--port",
            &port_text,
        ],
    );
    assert!(remote.status.success(), "{remote:?}");
    assert!(!other.exists());
}

#[test]
fn verify_fails_with_remedies_when_unreachable() {
    let directory = tempfile::tempdir().unwrap();
    let other = directory.path().join("absent.toml");
    let port = free_port().to_string();
    let output = run(
        &other,
        &[
            "setup",
            "verify",
            "--server",
            "127.0.0.1",
            "--port",
            &port,
            "--timeout-ms",
            "300",
        ],
    );
    assert_eq!(output.status.code(), Some(7), "{output:?}");
    let result = json(&output);
    assert_eq!(result["error"]["code"], "VERIFICATION_FAILED");
    assert_eq!(result["verification"]["status"], "failed");
    assert_eq!(result["data"]["checks"][0]["status"], "fail");
    assert!(
        result["next_actions"][0]
            .as_str()
            .unwrap()
            .contains("isolation")
    );
}
