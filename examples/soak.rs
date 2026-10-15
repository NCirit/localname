//! Sustained reliability test (M5): the release binary under mixed load for a while.
//!
//! Load: paced local UDP queries (answers checked), forwarded queries to an upstream that
//! drops 10% of them, TCP queries, HTTP requests through the proxy, and a live record
//! change every second read back through DNS. Memory is sampled throughout.
//!
//! Environment: `LOCALNAME_SOAK_SECONDS` (60), `LOCALNAME_SOAK_RATE` local queries/s (2000),
//! `LOCALNAME_SOAK_PARTS` (`local,forward,tcp,http,changes`) to select the load,
//! `LOCALNAME_SOAK_BUDGET=1` to fail when a budget is exceeded: no failed local query, TCP
//! query, proxied request, or change; p99 local latency at most 10 ms; RSS growth after
//! warmup at most 16 MiB and RSS at most 64 MiB.

use std::{
    net::SocketAddr,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    str::FromStr,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

use anyhow::{Context, Result, bail, ensure};
use hickory_proto::{
    op::{Message, MessageType, Query},
    rr::{Name, RData, Record, RecordType, rdata::A},
};
use localname::{Config, ConfigStore, RecordConfig, ServiceConfig, Transport, query_with};
use serde::Serialize;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
    task::JoinSet,
    time,
};

#[derive(Default)]
struct Counters {
    local: AtomicU64,
    local_failed: AtomicU64,
    forwarded: AtomicU64,
    forwarded_hung: AtomicU64,
    tcp: AtomicU64,
    tcp_failed: AtomicU64,
    http: AtomicU64,
    http_failed: AtomicU64,
    changes: AtomicU64,
    changes_failed: AtomicU64,
}

#[derive(Serialize)]
struct Report {
    seconds: u64,
    local_queries: u64,
    local_failed: u64,
    local_p50_ms: f64,
    local_p99_ms: f64,
    forwarded_queries: u64,
    forwarded_hung: u64,
    tcp_queries: u64,
    tcp_failed: u64,
    http_requests: u64,
    http_failed: u64,
    changes: u64,
    changes_failed: u64,
    rss_after_warmup_kb: u64,
    rss_max_kb: u64,
    rss_end_kb: u64,
}

struct Server(std::process::Child);

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn main() -> Result<()> {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()?
        .block_on(run())
}

fn port() -> Result<u16> {
    loop {
        let tcp = std::net::TcpListener::bind("127.0.0.1:0")?;
        let port = tcp.local_addr()?.port();
        if std::net::UdpSocket::bind(("127.0.0.1", port)).is_ok() {
            return Ok(port);
        }
    }
}

fn binary() -> Result<PathBuf> {
    if let Some(path) = std::env::var_os("LOCALNAME_BIN") {
        return Ok(path.into());
    }
    let examples = std::env::current_exe()?;
    let profile = examples
        .parent()
        .and_then(Path::parent)
        .context("cannot locate target directory")?;
    Ok(profile.join(format!("localname{}", std::env::consts::EXE_SUFFIX)))
}

/// An upstream that answers A queries after a short delay and ignores 10% of them.
async fn upstream(socket: UdpSocket) {
    let socket = Arc::new(socket);
    let mut buffer = vec![0_u8; 4096];
    let mut count = 0_u64;
    while let Ok((size, peer)) = socket.recv_from(&mut buffer).await {
        count += 1;
        if count.is_multiple_of(10) {
            continue;
        }
        let Ok(request) = Message::from_vec(&buffer[..size]) else {
            continue;
        };
        let socket = Arc::clone(&socket);
        tokio::spawn(async move {
            time::sleep(Duration::from_millis(count % 7)).await;
            let mut response = Message::response(request.id, request.op_code);
            response.metadata.message_type = MessageType::Response;
            response.metadata.recursion_desired = request.recursion_desired;
            response.metadata.recursion_available = true;
            response.add_queries(request.queries.iter().cloned());
            if let Some(query) = request.queries.first() {
                response.add_answer(Record::from_rdata(
                    query.name().clone(),
                    30,
                    RData::A(A::new(203, 0, 113, 7)),
                ));
            }
            if let Ok(bytes) = response.to_vec() {
                let _ = socket.send_to(&bytes, peer).await;
            }
        });
    }
}

/// An HTTP backend that answers every request with 200.
async fn backend(listener: TcpListener) {
    while let Ok((mut stream, _)) = listener.accept().await {
        tokio::spawn(async move {
            let mut buffer = [0_u8; 2048];
            let mut request = Vec::new();
            while !request.windows(4).any(|window| window == b"\r\n\r\n") {
                match stream.read(&mut buffer).await {
                    Ok(0) | Err(_) => return,
                    Ok(read) => request.extend_from_slice(&buffer[..read]),
                }
            }
            let _ = stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
                .await;
        });
    }
}

fn resident_kb(pid: u32) -> Option<u64> {
    let status = std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    status
        .lines()
        .find_map(|line| line.strip_prefix("VmRSS:"))?
        .split_whitespace()
        .next()?
        .parse()
        .ok()
}

fn env_u64(name: &str, default: u64) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(default)
}

#[allow(
    clippy::too_many_lines,
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss
)]
async fn run() -> Result<()> {
    let seconds = env_u64("LOCALNAME_SOAK_SECONDS", 60).max(10);
    let rate = env_u64("LOCALNAME_SOAK_RATE", 2_000).max(1);
    let upstream_socket = UdpSocket::bind("127.0.0.1:0").await?;
    let upstream_address = upstream_socket.local_addr()?;
    tokio::spawn(upstream(upstream_socket));
    let backend_listener = TcpListener::bind("127.0.0.1:0").await?;
    let backend_address = backend_listener.local_addr()?;
    tokio::spawn(backend(backend_listener));

    let listen: SocketAddr = format!("127.0.0.1:{}", port()?).parse()?;
    let proxy: SocketAddr = format!("127.0.0.1:{}", port()?).parse()?;
    let config = Config {
        listen: vec![listen],
        upstreams: vec![upstream_address],
        upstream_timeout_ms: 300,
        cache_entries: 1_024,
        proxy_listen: vec![proxy],
        records: (0..1_000)
            .map(|index| RecordConfig {
                name: format!("host{index}"),
                value: format!("10.0.{}.{}", index / 250, index % 250 + 1),
                ttl: 60,
            })
            .collect(),
        services: vec![ServiceConfig {
            name: "app".into(),
            target: backend_address,
            https: false,
        }],
        ..Config::default()
    };
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("config.toml");
    ConfigStore::new(&path).initialize(&config)?;
    let binary = binary()?;
    ensure!(
        binary.exists(),
        "{} not found; build the release binary first",
        binary.display()
    );
    let server = Server(
        Command::new(&binary)
            .arg("--config")
            .arg(&path)
            .arg("serve")
            .stdout(Stdio::null())
            .spawn()?,
    );
    for _ in 0..200 {
        if localname::query_server(listen, "lan.", RecordType::SOA, Duration::from_millis(100))
            .await
            .is_ok()
        {
            break;
        }
        time::sleep(Duration::from_millis(25)).await;
    }
    // The control socket opens after DNS; changes need it.
    time::sleep(Duration::from_millis(500)).await;

    let parts = std::env::var("LOCALNAME_SOAK_PARTS")
        .unwrap_or_else(|_| "local,forward,tcp,http,changes".into());
    let enabled = |part: &str| parts.split(',').any(|item| item.trim() == part);
    let counters = Arc::new(Counters::default());
    let stop = Arc::new(AtomicBool::new(false));
    let latencies = Arc::new(std::sync::Mutex::new(Vec::<f64>::new()));
    let mut tasks = JoinSet::new();

    // Paced local queries from 8 sockets.
    for worker in (0..8_u64).filter(|_| enabled("local")) {
        let (counters, stop, latencies) = (
            Arc::clone(&counters),
            Arc::clone(&stop),
            Arc::clone(&latencies),
        );
        tasks.spawn(async move {
            let socket = UdpSocket::bind("127.0.0.1:0").await?;
            socket.connect(listen).await?;
            let mut interval = time::interval(Duration::from_secs_f64(8.0 / rate as f64));
            interval.set_missed_tick_behavior(time::MissedTickBehavior::Delay);
            let mut buffer = vec![0_u8; 4096];
            let mut index = worker;
            while !stop.load(Ordering::Relaxed) {
                interval.tick().await;
                index = (index + 8) % 1_000;
                let mut request = Message::query();
                request.metadata.id = u16::try_from(index).unwrap_or(0);
                request.add_query(Query::query(
                    Name::from_str(&format!("host{index}.lan."))?,
                    RecordType::A,
                ));
                let started = Instant::now();
                socket.send(&request.to_vec()?).await?;
                counters.local.fetch_add(1, Ordering::Relaxed);
                let expected = format!("10.0.{}.{}", index / 250, index % 250 + 1);
                let correct =
                    match time::timeout(Duration::from_secs(1), socket.recv(&mut buffer)).await {
                        Ok(Ok(size)) => Message::from_vec(&buffer[..size]).is_ok_and(|response| {
                            response.id == request.id
                                && response
                                    .answers
                                    .iter()
                                    .any(|answer| answer.data.to_string() == expected)
                        }),
                        _ => false,
                    };
                if correct {
                    latencies
                        .lock()
                        .expect("latency lock")
                        .push(started.elapsed().as_secs_f64() * 1_000.0);
                } else {
                    counters.local_failed.fetch_add(1, Ordering::Relaxed);
                }
            }
            Ok::<_, anyhow::Error>(())
        });
    }
    // Forwarded queries from pre-bound sockets (creating a socket per query is slow on
    // some hosts and would stall this client, not the server). Every query must end with
    // an answer or SERVFAIL; none may hang.
    for worker in (0..16_u16).filter(|_| enabled("forward")) {
        let (counters, stop) = (Arc::clone(&counters), Arc::clone(&stop));
        tasks.spawn(async move {
            let socket = UdpSocket::bind("127.0.0.1:0").await?;
            socket.connect(listen).await?;
            let mut interval = time::interval(Duration::from_millis(80));
            interval.set_missed_tick_behavior(time::MissedTickBehavior::Delay);
            let mut buffer = vec![0_u8; 4096];
            let mut index = u64::from(worker);
            while !stop.load(Ordering::Relaxed) {
                interval.tick().await;
                index += 16;
                let mut request = Message::query();
                request.metadata.id = u16::try_from(index % 65_536).unwrap_or(0);
                request.metadata.recursion_desired = true;
                request.add_query(Query::query(
                    Name::from_str(&format!("site{}.example.", index % 500))?,
                    RecordType::A,
                ));
                socket.send(&request.to_vec()?).await?;
                counters.forwarded.fetch_add(1, Ordering::Relaxed);
                let answered = time::timeout(Duration::from_secs(2), async {
                    loop {
                        let size = socket.recv(&mut buffer).await?;
                        if Message::from_vec(&buffer[..size])
                            .is_ok_and(|response| response.id == request.id)
                        {
                            return Ok::<_, std::io::Error>(());
                        }
                    }
                })
                .await;
                if !matches!(answered, Ok(Ok(()))) {
                    counters.forwarded_hung.fetch_add(1, Ordering::Relaxed);
                }
            }
            Ok::<_, anyhow::Error>(())
        });
    }
    // TCP queries.
    if enabled("tcp") {
        let (counters, stop) = (Arc::clone(&counters), Arc::clone(&stop));
        tasks.spawn(async move {
            let mut interval = time::interval(Duration::from_millis(20));
            while !stop.load(Ordering::Relaxed) {
                interval.tick().await;
                counters.tcp.fetch_add(1, Ordering::Relaxed);
                let ok = query_with(
                    listen,
                    "host7.lan.",
                    RecordType::A,
                    Duration::from_secs(1),
                    Transport::Tcp,
                )
                .await
                .is_ok_and(|result| !result.answers.is_empty());
                if !ok {
                    counters.tcp_failed.fetch_add(1, Ordering::Relaxed);
                }
            }
            Ok(())
        });
    }
    // HTTP through the proxy.
    if enabled("http") {
        let (counters, stop) = (Arc::clone(&counters), Arc::clone(&stop));
        tasks.spawn(async move {
            let mut interval = time::interval(Duration::from_millis(20));
            while !stop.load(Ordering::Relaxed) {
                interval.tick().await;
                counters.http.fetch_add(1, Ordering::Relaxed);
                let ok = time::timeout(Duration::from_secs(2), async {
                    let mut stream = TcpStream::connect(proxy).await?;
                    stream
                        .write_all(b"GET / HTTP/1.1\r\nHost: app.lan\r\nConnection: close\r\n\r\n")
                        .await?;
                    let mut response = Vec::new();
                    stream.read_to_end(&mut response).await?;
                    Ok::<_, std::io::Error>(response.starts_with(b"HTTP/1.1 200"))
                })
                .await
                .is_ok_and(|result| result.unwrap_or(false));
                if !ok {
                    counters.http_failed.fetch_add(1, Ordering::Relaxed);
                }
            }
            Ok(())
        });
    }
    // A live change every second, read back by the CLI's own verification.
    if enabled("changes") {
        let (counters, stop) = (Arc::clone(&counters), Arc::clone(&stop));
        let (binary, path) = (binary.clone(), path.clone());
        tasks.spawn(async move {
            let mut index = 0_u64;
            while !stop.load(Ordering::Relaxed) {
                time::sleep(Duration::from_secs(1)).await;
                index += 1;
                let (binary, path) = (binary.clone(), path.clone());
                let name = format!("change{}", index % 20);
                let action = if index % 40 < 20 { "add" } else { "remove" };
                let output = tokio::task::spawn_blocking(move || {
                    let mut command = Command::new(&binary);
                    command.arg("--config").arg(&path).arg(action).arg(&name);
                    if action == "add" {
                        command.arg("192.168.50.1");
                    }
                    command.args(["--output", "json"]).output()
                })
                .await??;
                counters.changes.fetch_add(1, Ordering::Relaxed);
                let passed = output.status.success()
                    && String::from_utf8_lossy(&output.stdout).contains("\"status\":\"passed\"");
                if !passed {
                    counters.changes_failed.fetch_add(1, Ordering::Relaxed);
                }
            }
            Ok(())
        });
    }

    let pid = server.0.id();
    let started = Instant::now();
    let warmup = Duration::from_secs(seconds / 5);
    let mut rss_after_warmup = 0;
    let mut rss_max = 0;
    while started.elapsed() < Duration::from_secs(seconds) {
        time::sleep(Duration::from_secs(1)).await;
        let rss = resident_kb(pid).unwrap_or(0);
        rss_max = rss_max.max(rss);
        if rss_after_warmup == 0 && started.elapsed() >= warmup {
            rss_after_warmup = rss;
        }
    }
    stop.store(true, Ordering::Relaxed);
    while let Some(result) = tasks.join_next().await {
        result??;
    }
    // Let in-flight forwarded queries finish.
    time::sleep(Duration::from_secs(3)).await;
    let rss_end = resident_kb(pid).unwrap_or(0);

    let mut latencies = latencies.lock().expect("latency lock").clone();
    latencies.sort_by(f64::total_cmp);
    let percentile = |fraction: f64| {
        latencies
            .get(
                ((latencies.len() as f64 * fraction) as usize)
                    .min(latencies.len().saturating_sub(1)),
            )
            .copied()
            .unwrap_or(0.0)
    };
    let load = |counter: &AtomicU64| counter.load(Ordering::Relaxed);
    let report = Report {
        seconds,
        local_queries: load(&counters.local),
        local_failed: load(&counters.local_failed),
        local_p50_ms: percentile(0.50),
        local_p99_ms: percentile(0.99),
        forwarded_queries: load(&counters.forwarded),
        forwarded_hung: load(&counters.forwarded_hung),
        tcp_queries: load(&counters.tcp),
        tcp_failed: load(&counters.tcp_failed),
        http_requests: load(&counters.http),
        http_failed: load(&counters.http_failed),
        changes: load(&counters.changes),
        changes_failed: load(&counters.changes_failed),
        rss_after_warmup_kb: rss_after_warmup,
        rss_max_kb: rss_max,
        rss_end_kb: rss_end,
    };
    println!("{}", serde_json::to_string(&report)?);
    if std::env::var("LOCALNAME_SOAK_BUDGET").is_ok_and(|value| value == "1") {
        let mut failures = Vec::new();
        for (what, count) in [
            ("local queries", report.local_failed),
            ("forwarded queries that hung", report.forwarded_hung),
            ("TCP queries", report.tcp_failed),
            ("proxied requests", report.http_failed),
            ("changes", report.changes_failed),
        ] {
            if count > 0 {
                failures.push(format!("{count} failed {what}"));
            }
        }
        if report.local_p99_ms > 10.0 {
            failures.push(format!("p99 {:.2} ms exceeds 10 ms", report.local_p99_ms));
        }
        if report.rss_max_kb > 64 * 1_024 {
            failures.push(format!("RSS {} KiB exceeds 64 MiB", report.rss_max_kb));
        }
        if report.rss_end_kb.saturating_sub(report.rss_after_warmup_kb) > 16 * 1_024 {
            failures.push(format!(
                "RSS grew {} KiB after warmup",
                report.rss_end_kb - report.rss_after_warmup_kb
            ));
        }
        if !failures.is_empty() {
            bail!("soak budgets exceeded: {}", failures.join("; "));
        }
    }
    Ok(())
}
