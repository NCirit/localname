//! Optional service proxy (M4a): DNS-only mode has no proxy listener; enabled, the proxy
//! routes by Host, upgrades WebSocket connections, and fails backends in documented ways.
#![cfg(feature = "proxy")]

use std::{
    io::{BufRead, BufReader, Read, Write},
    net::{SocketAddr, TcpListener, TcpStream, UdpSocket},
    path::Path,
    process::{Command, Output},
    sync::{Arc, Mutex},
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

fn configure(path: &Path, dns_port: u16, extra: &str) {
    std::fs::write(
        path,
        format!(
            "zone = \"home.arpa\"\nlisten = [\"127.0.0.1:{dns_port}\"]\nupstreams = [\"192.0.2.1:53\"]\nallowed_clients = [\"127.0.0.0/8\"]\n{extra}"
        ),
    )
    .unwrap();
}

/// Listening TCP ports owned by `pid`, from /proc.
#[cfg(target_os = "linux")]
fn listening_ports(pid: u32) -> Vec<u16> {
    let mut inodes = Vec::new();
    for entry in std::fs::read_dir(format!("/proc/{pid}/fd"))
        .unwrap()
        .flatten()
    {
        if let Ok(target) = std::fs::read_link(entry.path()) {
            let target = target.to_string_lossy().into_owned();
            if let Some(inode) = target
                .strip_prefix("socket:[")
                .and_then(|rest| rest.strip_suffix(']'))
            {
                inodes.push(inode.to_owned());
            }
        }
    }
    let mut ports = Vec::new();
    for file in ["/proc/net/tcp", "/proc/net/tcp6"] {
        for line in std::fs::read_to_string(file).unwrap().lines().skip(1) {
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields[3] == "0A" && inodes.iter().any(|inode| inode == fields[9]) {
                let port = fields[1].rsplit(':').next().unwrap();
                ports.push(u16::from_str_radix(port, 16).unwrap());
            }
        }
    }
    ports.sort_unstable();
    ports.dedup();
    ports
}

/// A listener whose accept queue is full: further connection attempts hang (Linux drops
/// the SYN), which exercises the proxy's connect timeout.
#[cfg(target_os = "linux")]
fn black_hole() -> (SocketAddr, TcpListener, Vec<TcpStream>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let mut held = Vec::new();
    // std listens with a backlog of 128; the queue holds backlog + 1 connections.
    for _ in 0..140 {
        match TcpStream::connect_timeout(&address, Duration::from_millis(200)) {
            Ok(stream) => held.push(stream),
            Err(_) => break,
        }
    }
    (address, listener, held)
}

/// A tiny HTTP backend that answers every request with the headers it received.
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
                let mut headers = Vec::new();
                loop {
                    let mut line = String::new();
                    if reader.read_line(&mut line).unwrap_or(0) == 0 || line == "\r\n" {
                        break;
                    }
                    headers.push(line.trim_end().to_owned());
                }
                let upgrade = headers
                    .iter()
                    .any(|h| h.eq_ignore_ascii_case("upgrade: websocket"));
                log.lock().unwrap().extend(headers.iter().cloned());
                let mut stream = stream;
                if upgrade {
                    stream
                        .write_all(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: test\r\n\r\n")
                        .unwrap();
                    // Echo raw bytes until the client closes.
                    let mut buffer = [0_u8; 1024];
                    while let Ok(read) = reader.read(&mut buffer) {
                        if read == 0 || stream.write_all(&buffer[..read]).is_err() {
                            break;
                        }
                    }
                } else {
                    let body = "hello from backend";
                    let _ = write!(
                        stream,
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nKeep-Alive: timeout=5\r\nConnection: keep-alive\r\n\r\n{body}",
                        body.len()
                    );
                }
            });
        }
    });
    (address, seen)
}

/// Send a request through the proxy and return (status, headers, body).
fn request(proxy: SocketAddr, host: Option<&str>) -> (u16, String, String) {
    let mut stream = TcpStream::connect(proxy).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(20)))
        .unwrap();
    let host = host.map_or_else(String::new, |host| format!("Host: {host}\r\n"));
    write!(stream, "GET /path?q=1 HTTP/1.1\r\n{host}X-Forwarded-For: 10.9.9.9\r\nConnection: close, x-private\r\nX-Private: secret\r\n\r\n").unwrap();
    let mut response = String::new();
    let _ = stream.read_to_string(&mut response);
    let (head, body) = response.split_once("\r\n\r\n").unwrap_or((&response, ""));
    let status = head
        .split_whitespace()
        .nth(1)
        .and_then(|code| code.parse().ok())
        .unwrap_or(0);
    (status, head.to_owned(), body.to_owned())
}

#[cfg(target_os = "linux")]
#[test]
fn dns_only_mode_opens_no_proxy_listener() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("config.toml");
    let port = free_port();
    configure(&path, port, "");
    let daemon = start(&path);
    assert_eq!(listening_ports(daemon.0.id()), vec![port]);
    let status = json(&run(&path, &["status"]));
    assert!(status["data"]["daemon"]["proxy"].is_null(), "{status}");
}

#[test]
#[allow(clippy::too_many_lines)]
fn proxy_routes_by_host_and_reports_backend_failures() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("config.toml");
    let dns_port = free_port();
    let proxy_port = free_port();
    let (target, seen) = backend();
    let closed = free_port();
    #[cfg(target_os = "linux")]
    let (slow, _hole, _held) = black_hole();
    #[cfg(not(target_os = "linux"))]
    let slow: SocketAddr = "10.255.255.1:80".parse().unwrap();
    configure(
        &path,
        dns_port,
        &format!(
            "proxy_listen = [\"127.0.0.1:{proxy_port}\"]\n[[services]]\nname = \"photos\"\ntarget = \"{target}\"\n[[services]]\nname = \"down\"\ntarget = \"127.0.0.1:{closed}\"\n[[services]]\nname = \"slow\"\ntarget = \"{slow}\"\n"
        ),
    );
    let daemon = start(&path);
    #[cfg(target_os = "linux")]
    assert_eq!(listening_ports(daemon.0.id()), {
        let mut ports = vec![dns_port, proxy_port];
        ports.sort_unstable();
        ports
    });
    let proxy: SocketAddr = format!("127.0.0.1:{proxy_port}").parse().unwrap();

    // DNS sends the service name to the proxy.
    let dns = format!("127.0.0.1:{dns_port}");
    let resolved = json(&run(&path, &["resolve", "photos", "--server", &dns]));
    assert_eq!(
        resolved["data"]["answers"][0], "photos.home.arpa. 60 IN A 127.0.0.1",
        "{resolved}"
    );

    let (status, head, body) = request(proxy, Some("Photos.Home.Arpa"));
    assert_eq!(status, 200, "{head}");
    assert_eq!(body, "hello from backend");
    assert!(
        !head.to_ascii_lowercase().contains("keep-alive: timeout"),
        "{head}"
    );
    {
        let seen = seen.lock().unwrap();
        let has = |wanted: &str| {
            seen.iter()
                .any(|header| header.eq_ignore_ascii_case(wanted))
        };
        assert!(seen[0].starts_with("GET /path?q=1 HTTP/1.1"), "{seen:?}");
        assert!(has("host: Photos.Home.Arpa"), "{seen:?}");
        assert!(has("x-forwarded-for: 10.9.9.9, 127.0.0.1"), "{seen:?}");
        assert!(has("x-forwarded-proto: http"), "{seen:?}");
        assert!(has("x-forwarded-host: photos.home.arpa"), "{seen:?}");
        assert!(
            !seen
                .iter()
                .any(|header| header.to_ascii_lowercase().starts_with("x-private")),
            "{seen:?}"
        );
    }

    assert_eq!(request(proxy, Some("unknown.home.arpa")).0, 404);
    assert_eq!(request(proxy, None).0, 400);
    let (status, _, body) = request(proxy, Some("down.home.arpa"));
    assert_eq!(status, 502);
    assert!(body.contains("unreachable"), "{body}");
    // A connect timeout is 504 when the network black-holes the backend (Linux test).
    if cfg!(target_os = "linux") {
        let (status, _, body) = request(proxy, Some("slow.home.arpa:80"));
        assert_eq!(status, 504);
        assert!(body.contains("5 s"), "{body}");
    }

    // Live changes go through the daemon and are verified end to end.
    let added = json(&run(
        &path,
        &["service", "add", "music", &target.to_string()],
    ));
    assert_eq!(added["verification"]["status"], "passed", "{added}");
    assert_eq!(request(proxy, Some("music.home.arpa")).0, 200);
    let removed = json(&run(&path, &["service", "remove", "music"]));
    assert_eq!(removed["verification"]["status"], "passed", "{removed}");
    assert_eq!(request(proxy, Some("music.home.arpa")).0, 404);
    let warned = json(&run(
        &path,
        &["service", "add", "gone", &format!("127.0.0.1:{closed}")],
    ));
    assert_eq!(warned["verification"]["status"], "passed", "{warned}");
    assert!(
        warned["warnings"][0]
            .as_str()
            .unwrap()
            .contains("not reachable"),
        "{warned}"
    );

    let status = json(&run(&path, &["status"]));
    let proxy_status = &status["data"]["daemon"]["proxy"];
    assert_eq!(proxy_status["services"], 4, "{status}");
    assert!(
        proxy_status["backend_errors"].as_u64().unwrap() >= 2,
        "{status}"
    );
    assert!(proxy_status["not_found"].as_u64().unwrap() >= 2, "{status}");

    // Listener changes are refused while the daemon runs.
    let enable = run(&path, &["proxy", "enable", "--listen", "127.0.0.1:1"]);
    assert_eq!(enable.status.code(), Some(5), "{enable:?}");
    drop(daemon);
}

#[test]
fn websocket_upgrades_relay_both_directions() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("config.toml");
    let dns_port = free_port();
    let proxy_port = free_port();
    let (target, _) = backend();
    configure(
        &path,
        dns_port,
        &format!(
            "proxy_listen = [\"127.0.0.1:{proxy_port}\"]\n[[services]]\nname = \"chat\"\ntarget = \"{target}\"\n"
        ),
    );
    let _daemon = start(&path);
    let mut stream = TcpStream::connect(("127.0.0.1", proxy_port)).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    stream
        .write_all(b"GET /socket HTTP/1.1\r\nHost: chat.home.arpa\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n")
        .unwrap();
    let mut reader = BufReader::new(stream.try_clone().unwrap());
    let mut status = String::new();
    reader.read_line(&mut status).unwrap();
    assert!(status.starts_with("HTTP/1.1 101"), "{status}");
    let mut upgrade = false;
    loop {
        let mut line = String::new();
        reader.read_line(&mut line).unwrap();
        if line == "\r\n" {
            break;
        }
        upgrade |= line.eq_ignore_ascii_case("upgrade: websocket\r\n");
    }
    assert!(upgrade);
    for message in [&b"ping"[..], &b"second message"[..]] {
        stream.write_all(message).unwrap();
        let mut echoed = vec![0_u8; message.len()];
        reader.read_exact(&mut echoed).unwrap();
        assert_eq!(echoed, message);
    }
}

#[test]
fn proxy_enable_and_disable_change_listeners_offline() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("config.toml");
    configure(&path, free_port(), "");
    let without = run(&path, &["service", "add", "photos", "192.168.1.20:2342"]);
    assert_eq!(without.status.code(), Some(3), "{without:?}");
    let proxy = format!("127.0.0.1:{}", free_port());
    let enabled = json(&run(&path, &["proxy", "enable", "--listen", &proxy]));
    assert_eq!(enabled["changed"], true, "{enabled}");
    assert!(
        run(&path, &["service", "add", "photos", "192.168.1.20:2342"])
            .status
            .success()
    );
    assert_eq!(run(&path, &["proxy", "disable"]).status.code(), Some(3));
    assert!(
        run(&path, &["service", "remove", "photos"])
            .status
            .success()
    );
    let disabled = json(&run(&path, &["proxy", "disable"]));
    assert_eq!(disabled["changed"], true, "{disabled}");
    let listed = json(&run(&path, &["service", "list"]));
    assert_eq!(listed["data"]["proxy_listen"], serde_json::json!([]));
}
