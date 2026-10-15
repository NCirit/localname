//! Local-answer latency and throughput benchmark.
//!
//! The server runs as a separate `localname serve` process so client load does not share its
//! scheduler. Build it first: `cargo build --release && cargo run --release --example benchmark`.
//!
//! Environment:
//! - `LOCALNAME_BENCH_RECORDS` (10000), `LOCALNAME_BENCH_QUERIES` (20000),
//!   `LOCALNAME_BENCH_WORKERS` (64), `LOCALNAME_BENCH_RATE` queries/s (10000; 0 = unpaced)
//! - `LOCALNAME_BENCH_BUDGET_P99_MS`, `LOCALNAME_BENCH_BUDGET_RSS_MB`: fail when exceeded
//! - `LOCALNAME_BIN`: server binary (defaults to the `localname` beside the examples directory)

use std::{
    net::SocketAddr,
    path::PathBuf,
    process::{Child, Command, Stdio},
    str::FromStr,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

use anyhow::{Context, Result, bail, ensure};
use hickory_proto::{
    op::{Message, Query},
    rr::{Name, RecordType},
};
use localname::{Config, ConfigStore, RecordConfig, query_server};
use serde::Serialize;
use tokio::{net::UdpSocket, task::JoinSet, time};

#[derive(Serialize)]
struct ResultRow {
    arch: &'static str,
    os: &'static str,
    records: usize,
    queries: usize,
    workers: usize,
    target_queries_per_second: usize,
    elapsed_ms: f64,
    queries_per_second: f64,
    p50_ms: f64,
    p99_ms: f64,
    p999_ms: f64,
    errors: usize,
    server_rss_kb: Option<u64>,
}

struct Server(Child);

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

#[allow(clippy::too_many_lines, clippy::cast_precision_loss)]
async fn run() -> Result<()> {
    let record_count = env_usize("LOCALNAME_BENCH_RECORDS", 10_000);
    let query_count = env_usize("LOCALNAME_BENCH_QUERIES", 20_000);
    let worker_count = env_usize("LOCALNAME_BENCH_WORKERS", 64).max(1);
    let target_rate = env_usize("LOCALNAME_BENCH_RATE", 10_000);
    ensure!(
        record_count > 0 && query_count > 0,
        "record and query counts must be positive"
    );
    let port = std::net::TcpListener::bind("127.0.0.1:0")?
        .local_addr()?
        .port();
    let listen: SocketAddr = format!("127.0.0.1:{port}").parse()?;
    let config = Config {
        listen: vec![listen],
        records: (0..record_count)
            .map(|index| RecordConfig {
                name: format!("host{index}"),
                value: format!(
                    "10.{}.{}.{}",
                    (index >> 16) & 0xff,
                    (index >> 8) & 0xff,
                    index & 0xff
                ),
                ttl: 60,
            })
            .collect(),
        ..Config::default()
    };
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("config.toml");
    ConfigStore::new(&path).initialize(&config)?;
    let binary = std::env::var_os("LOCALNAME_BIN").map_or_else(
        || -> Result<PathBuf> {
            let examples = std::env::current_exe()?;
            let profile = examples
                .parent()
                .and_then(std::path::Path::parent)
                .context("cannot locate target directory")?;
            Ok(profile.join(format!("localname{}", std::env::consts::EXE_SUFFIX)))
        },
        |path| Ok(path.into()),
    )?;
    ensure!(
        binary.exists(),
        "{} not found; run `cargo build --release` first or set LOCALNAME_BIN",
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
    wait_until_ready(listen).await?;

    let next = Arc::new(AtomicUsize::new(0));
    let mut tasks = JoinSet::new();
    let started = Instant::now();
    for _ in 0..worker_count {
        let next = Arc::clone(&next);
        tasks.spawn(async move {
            let mut rows = Vec::new();
            let socket = UdpSocket::bind("127.0.0.1:0").await?;
            socket.connect(listen).await?;
            let mut response_bytes = vec![0_u8; 4096];
            loop {
                let index = next.fetch_add(1, Ordering::Relaxed);
                if index >= query_count {
                    break;
                }
                if target_rate > 0 {
                    let offset = Duration::from_secs_f64(index as f64 / target_rate as f64);
                    time::sleep_until(time::Instant::from_std(started + offset)).await;
                }
                let host = index % record_count;
                let mut request = Message::query();
                request.metadata.id = u16::try_from(index & usize::from(u16::MAX))?;
                request.add_query(Query::query(
                    Name::from_str(&format!("host{host}.lan."))?,
                    RecordType::A,
                ));
                let bytes = request.to_vec()?;
                let query_started = Instant::now();
                let result = async {
                    socket.send(&bytes).await?;
                    let size =
                        time::timeout(Duration::from_secs(2), socket.recv(&mut response_bytes))
                            .await??;
                    let response = Message::from_vec(&response_bytes[..size])?;
                    ensure!(
                        response.id == request.id && response.answers.len() == 1,
                        "invalid response"
                    );
                    Ok::<_, anyhow::Error>(query_started.elapsed().as_secs_f64() * 1_000.0)
                }
                .await;
                rows.push(result);
            }
            Ok::<_, anyhow::Error>(rows)
        });
    }
    let mut latencies = Vec::with_capacity(query_count);
    let mut errors = 0;
    while let Some(result) = tasks.join_next().await {
        for row in result?? {
            match row {
                Ok(latency) => latencies.push(latency),
                Err(_) => errors += 1,
            }
        }
    }
    let elapsed = started.elapsed();
    let server_rss_kb = resident_kb(server.0.id());
    drop(server);
    latencies.sort_by(f64::total_cmp);
    let percentile = |per_mille: usize| -> f64 {
        latencies
            .get((latencies.len().saturating_sub(1) * per_mille) / 1_000)
            .copied()
            .unwrap_or(0.0)
    };
    let row = ResultRow {
        arch: std::env::consts::ARCH,
        os: std::env::consts::OS,
        records: record_count,
        queries: query_count,
        workers: worker_count,
        target_queries_per_second: target_rate,
        elapsed_ms: elapsed.as_secs_f64() * 1_000.0,
        queries_per_second: query_count as f64 / elapsed.as_secs_f64(),
        p50_ms: percentile(500),
        p99_ms: percentile(990),
        p999_ms: percentile(999),
        errors,
        server_rss_kb,
    };
    println!("{}", serde_json::to_string(&row)?);
    if errors > 0 {
        bail!("benchmark had {errors} failed queries");
    }
    if let Some(budget) = env_f64("LOCALNAME_BENCH_BUDGET_P99_MS")
        && row.p99_ms > budget
    {
        bail!("p99 {:.3} ms exceeds budget {budget} ms", row.p99_ms);
    }
    if let (Some(budget), Some(rss)) = (env_f64("LOCALNAME_BENCH_BUDGET_RSS_MB"), server_rss_kb)
        && rss as f64 / 1024.0 > budget
    {
        bail!("server RSS {rss} KiB exceeds budget {budget} MiB");
    }
    Ok(())
}

/// Resident memory of the server process (Linux only).
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

async fn wait_until_ready(address: SocketAddr) -> Result<()> {
    for _ in 0..200 {
        if query_server(address, "lan.", RecordType::SOA, Duration::from_millis(100))
            .await
            .is_ok()
        {
            return Ok(());
        }
        time::sleep(Duration::from_millis(25)).await;
    }
    bail!("server did not start")
}

fn env_usize(name: &str, default: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(default)
}

fn env_f64(name: &str) -> Option<f64> {
    std::env::var(name).ok()?.parse().ok()
}
