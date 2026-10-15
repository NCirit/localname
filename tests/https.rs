//! HTTPS with the local CA trust mode (M4b): plan without side effects, explicit trust,
//! TLS by SNI through the proxy, redirects, renewal, restart persistence, and rollback.
//! Private key material must never appear in any command's output.
#![cfg(feature = "https")]

use std::{
    io::{BufRead, BufReader, Write},
    net::{SocketAddr, TcpListener, UdpSocket},
    path::{Path, PathBuf},
    process::{Command, Output},
    sync::{Arc, Mutex},
    time::Duration,
};

use serde_json::Value;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Every command's output, checked for key material at the end.
static OUTPUTS: Mutex<Vec<String>> = Mutex::new(Vec::new());

fn run(path: &Path, arguments: &[&str]) -> Output {
    let output = Command::new(env!("CARGO_BIN_EXE_localname"))
        .arg("--config")
        .arg(path)
        .args(arguments)
        .arg("--output")
        .arg("json")
        .output()
        .unwrap();
    OUTPUTS.lock().unwrap().push(format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    ));
    output
}

fn json(output: &Output) -> Value {
    serde_json::from_slice(&output.stdout).unwrap_or_else(|error| panic!("{error}: {output:?}"))
}

fn free_port() -> u16 {
    loop {
        let tcp = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = tcp.local_addr().unwrap().port();
        if UdpSocket::bind(("127.0.0.1", port)).is_ok() {
            return port;
        }
    }
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

/// An HTTP backend that records request headers and answers 200.
fn backend() -> (SocketAddr, Arc<Mutex<Vec<String>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let log = Arc::clone(&seen);
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            let log = Arc::clone(&log);
            std::thread::spawn(move || {
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                loop {
                    let mut line = String::new();
                    if reader.read_line(&mut line).unwrap_or(0) == 0 || line == "\r\n" {
                        break;
                    }
                    log.lock()
                        .unwrap()
                        .push(line.trim_end().to_ascii_lowercase());
                }
                let mut stream = stream;
                let _ = stream.write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\nConnection: close\r\n\r\nsecret",
                );
            });
        }
    });
    (address, seen)
}

fn certificate_of(path: &Path, name: &str) -> Value {
    let status = json(&run(path, &["https", "status"]));
    status["data"]["certificates"]
        .as_array()
        .unwrap_or_else(|| panic!("{status}"))
        .iter()
        .find(|certificate| certificate["name"] == name)
        .unwrap_or_else(|| panic!("{status}"))
        .clone()
}

fn ca_file(path: &Path) -> PathBuf {
    path.with_extension("tls").join("ca.crt")
}

/// GET over TLS with SNI, trusting only `ca`. Returns the response text.
async fn https_get(address: SocketAddr, name: &str, ca: &Path) -> anyhow::Result<String> {
    let mut roots = rustls::RootCertStore::empty();
    for certificate in rustls_pemfile::certs(&mut std::fs::read(ca)?.as_slice()) {
        roots.add(certificate?)?;
    }
    let config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()?
    .with_root_certificates(roots)
    .with_no_client_auth();
    let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
    let stream = tokio::net::TcpStream::connect(address).await?;
    let mut stream = connector
        .connect(
            rustls::pki_types::ServerName::try_from(name.to_owned())?,
            stream,
        )
        .await?;
    stream
        .write_all(
            format!("GET /x HTTP/1.1\r\nHost: {name}\r\nConnection: close\r\n\r\n").as_bytes(),
        )
        .await?;
    let mut response = String::new();
    let _ = stream.read_to_string(&mut response).await;
    Ok(response)
}

fn http_get(address: SocketAddr, name: &str) -> String {
    let mut stream = std::net::TcpStream::connect(address).unwrap();
    write!(
        stream,
        "GET /x?y=1 HTTP/1.1\r\nHost: {name}\r\nConnection: close\r\n\r\n"
    )
    .unwrap();
    let mut response = String::new();
    let _ = std::io::Read::read_to_string(&mut stream, &mut response);
    response
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[allow(clippy::too_many_lines)]
async fn local_ca_serves_trusted_https_and_rolls_back() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("config.toml");
    let (dns, proxy, https) = (free_port(), free_port(), free_port());
    let (target, seen) = backend();
    std::fs::write(
        &path,
        format!(
            "zone = \"home.arpa\"\nlisten = [\"127.0.0.1:{dns}\"]\nupstreams = [\"192.0.2.1:53\"]\nallowed_clients = [\"127.0.0.0/8\"]\nproxy_listen = [\"127.0.0.1:{proxy}\"]\n[[services]]\nname = \"photos\"\ntarget = \"{target}\"\n[[services]]\nname = \"plain\"\ntarget = \"{target}\"\n"
        ),
    )
    .unwrap();
    let listen = format!("127.0.0.1:{https}");
    let options = [
        "--mode",
        "local-ca",
        "--listen",
        &listen,
        "--service",
        "photos",
    ];

    // The plan changes nothing and promises no trust-store change.
    let plan = json(&run(&path, &[&["https", "plan"][..], &options].concat()));
    assert_eq!(plan["data"]["creates_ca"], true, "{plan}");
    assert_eq!(plan["data"]["trust_store_changes"], serde_json::json!([]));
    assert!(!path.with_extension("tls").exists());

    let applied = run(&path, &[&["https", "apply"][..], &options].concat());
    assert!(applied.status.success(), "{applied:?}");
    assert!(
        json(&applied)["rollback"]
            .as_str()
            .unwrap()
            .ends_with("https rollback")
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(path.with_extension("tls").join("ca.key"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    // Trust-store changes are never made without explicit confirmation.
    let unconfirmed = run(&path, &["https", "trust", "install"]);
    assert_eq!(unconfirmed.status.code(), Some(4), "{unconfirmed:?}");
    assert_eq!(json(&unconfirmed)["error"]["code"], "PERMISSION_REQUIRED");
    assert!(!path.with_extension("trust.json").exists());
    let preview = run(&path, &["https", "trust", "install", "--dry-run"]);
    if preview.status.success() {
        assert!(
            !json(&preview)["data"]["commands"]
                .as_array()
                .unwrap()
                .is_empty()
        );
    }

    let ca = json(&run(&path, &["https", "ca-cert"]));
    assert!(
        ca["data"]["pem"]
            .as_str()
            .unwrap()
            .contains("BEGIN CERTIFICATE")
    );

    let daemon = start(&path);
    let verified = run(&path, &["https", "verify", "--timeout-seconds", "20"]);
    assert!(verified.status.success(), "{verified:?}");
    assert_eq!(json(&verified)["verification"]["status"], "passed");

    let address: SocketAddr = listen.parse().unwrap();
    let response = https_get(address, "photos.home.arpa", &ca_file(&path))
        .await
        .unwrap();
    assert!(response.starts_with("HTTP/1.1 200"), "{response}");
    assert!(response.ends_with("secret"), "{response}");
    assert!(
        seen.lock()
            .unwrap()
            .iter()
            .any(|header| header == "x-forwarded-proto: https")
    );
    // Names without HTTPS have no certificate.
    assert!(
        https_get(address, "plain.home.arpa", &ca_file(&path))
            .await
            .is_err()
    );

    let proxy_address: SocketAddr = format!("127.0.0.1:{proxy}").parse().unwrap();
    let redirect = http_get(proxy_address, "photos.home.arpa");
    assert!(redirect.starts_with("HTTP/1.1 308"), "{redirect}");
    assert!(
        redirect
            .to_ascii_lowercase()
            .contains(&format!("location: https://photos.home.arpa:{https}/x?y=1")),
        "{redirect}"
    );
    assert!(http_get(proxy_address, "plain.home.arpa").starts_with("HTTP/1.1 200"));

    // With HTTPS configured, a new service gets a certificate without further steps.
    let added = run(&path, &["service", "add", "music", &target.to_string()]);
    assert!(added.status.success(), "{added:?}");
    let mut issued = false;
    for _ in 0..50 {
        if !certificate_of(&path, "music.home.arpa.")["certificate"].is_null() {
            issued = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    assert!(issued, "new service has no certificate");
    let response = https_get(address, "music.home.arpa", &ca_file(&path))
        .await
        .unwrap();
    assert!(response.starts_with("HTTP/1.1 200"), "{response}");
    let http_only = run(
        &path,
        &[
            "service",
            "add",
            "plain2",
            &target.to_string(),
            "--no-https",
        ],
    );
    assert!(http_only.status.success(), "{http_only:?}");
    assert!(http_get(proxy_address, "plain2.home.arpa").starts_with("HTTP/1.1 200"));

    // Forced renewal replaces the certificate.
    let before = certificate_of(&path, "photos.home.arpa.");
    let renewed = run(&path, &["https", "renew"]);
    assert!(renewed.status.success(), "{renewed:?}");
    let after = certificate_of(&path, "photos.home.arpa.");
    assert_ne!(
        before["certificate"]["sha256"],
        after["certificate"]["sha256"]
    );

    // A restart reuses the stored certificate.
    drop(daemon);
    let daemon = start(&path);
    assert_eq!(
        certificate_of(&path, "photos.home.arpa.")["certificate"]["sha256"],
        after["certificate"]["sha256"]
    );
    drop(daemon);

    // A certificate inside the renewal window is replaced automatically at startup.
    let ca = localname::tls::LocalCa::load(&path).unwrap();
    let (chain, key) = ca.issue_for_days("photos.home.arpa.", 1).unwrap();
    let (chain_path, key_path) = localname::tls::certificate_paths(&path, "photos.home.arpa.");
    localname::tls::write_file(&key_path, key.as_bytes(), true).unwrap();
    localname::tls::write_file(&chain_path, chain.as_bytes(), false).unwrap();
    let daemon = start(&path);
    let mut renewed_days = 0;
    for _ in 0..50 {
        let certificate = certificate_of(&path, "photos.home.arpa.");
        let remaining = certificate["certificate"]["not_after_unix"]
            .as_i64()
            .unwrap_or(0)
            - i64::try_from(
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
            )
            .unwrap();
        renewed_days = remaining / 86_400;
        if renewed_days > 80 {
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    assert!(
        renewed_days > 80,
        "certificate was not renewed: {renewed_days} days left"
    );
    let still = run(&path, &["https", "verify", "--timeout-seconds", "10"]);
    assert!(still.status.success(), "{still:?}");

    // Rollback needs the service stopped, then restores everything apply created.
    let running = run(&path, &["https", "rollback"]);
    assert_eq!(running.status.code(), Some(5), "{running:?}");
    drop(daemon);
    let rolled_back = run(&path, &["https", "rollback"]);
    assert!(rolled_back.status.success(), "{rolled_back:?}");
    assert!(!path.with_extension("tls").exists());
    let config = json(&run(&path, &["config", "show"]));
    assert!(config["data"]["https"].is_null(), "{config}");
    assert!(
        config["data"]["services"]
            .as_array()
            .unwrap()
            .iter()
            .all(|service| service["https"] == false)
    );

    let outputs = OUTPUTS.lock().unwrap();
    assert!(
        outputs.iter().all(|output| !output.contains("PRIVATE KEY")),
        "key material leaked into output"
    );
}

#[test]
fn acme_mode_needs_an_owned_domain_terms_and_a_hook() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("config.toml");
    std::fs::write(
        &path,
        format!(
            "zone = \"home.arpa\"\nlisten = [\"127.0.0.1:{}\"]\nupstreams = [\"192.0.2.1:53\"]\nallowed_clients = [\"127.0.0.0/8\"]\nproxy_listen = [\"127.0.0.1:{}\"]\n",
            free_port(),
            free_port()
        ),
    )
    .unwrap();
    let private = run(
        &path,
        &[
            "https",
            "plan",
            "--mode",
            "acme-dns01",
            "--dns01-hook",
            "/bin/true",
            "--agree-tos",
        ],
    );
    assert_eq!(private.status.code(), Some(3), "{private:?}");
    assert!(
        json(&private)["error"]["message"]
            .as_str()
            .unwrap()
            .contains("public domain you own")
    );
}
