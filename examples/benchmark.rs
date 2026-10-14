use std::{
    net::SocketAddr,
    str::FromStr,
    sync::Arc,
    time::{Duration, Instant},
};

use hickory_proto::{
    op::{Message, Query},
    rr::{Name, RecordType},
};
use localname::{Config, ConfigStore, DnsServer, RecordConfig};
use serde::Serialize;
use tokio::{
    net::{TcpStream, UdpSocket},
    sync::watch,
    task::JoinSet,
    time,
};

#[derive(Serialize)]
struct ResultRow {
    records: usize,
    queries: usize,
    workers: usize,
    elapsed_ms: f64,
    queries_per_second: f64,
    p50_ms: f64,
    p99_ms: f64,
    errors: usize,
    target_queries_per_second: usize,
}

#[tokio::main(worker_threads = 2)]
#[allow(clippy::too_many_lines)]
async fn main() -> anyhow::Result<()> {
    let record_count = env_usize("LOCALNAME_BENCH_RECORDS", 10_000);
    let query_count = env_usize("LOCALNAME_BENCH_QUERIES", 20_000);
    let worker_count = env_usize("LOCALNAME_BENCH_WORKERS", 128).max(1);
    let target_rate = env_usize("LOCALNAME_BENCH_RATE", 10_000);
    anyhow::ensure!(
        record_count > 0 && query_count > 0,
        "record and query counts must be positive"
    );
    let port = std::net::TcpListener::bind("127.0.0.1:0")?
        .local_addr()?
        .port();
    let listen: SocketAddr = format!("127.0.0.1:{port}").parse()?;
    let mut config = Config {
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
    config.validate()?;
    let directory = tempfile::tempdir()?;
    let store = ConfigStore::new(directory.path().join("config.toml"));
    store.initialize(&config)?;
    let server = DnsServer::new(store, config)?;
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    tokio::spawn(server.run(shutdown_rx));
    wait_until_ready(listen).await?;

    let next = Arc::new(std::sync::atomic::AtomicUsize::new(0));
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
                let index = next.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                if index >= query_count {
                    break;
                }
                if target_rate > 0 {
                    let offset = Duration::from_secs_f64(
                        f64::from(u32::try_from(index)?) / f64::from(u32::try_from(target_rate)?),
                    );
                    time::sleep_until(time::Instant::from_std(started + offset)).await;
                }
                let host = index % record_count;
                let mut request = Message::query();
                request.metadata.id = u16::try_from(index & usize::from(u16::MAX))?;
                request.add_query(Query::query(
                    Name::from_str(&format!("host{host}.home.arpa."))?,
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
                    anyhow::ensure!(
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
    shutdown_tx.send(true)?;
    latencies.sort_by(f64::total_cmp);
    let percentile = |numerator: usize| -> f64 {
        latencies
            .get((latencies.len().saturating_sub(1) * numerator) / 100)
            .copied()
            .unwrap_or(0.0)
    };
    let query_count_f64 = f64::from(u32::try_from(query_count)?);
    let row = ResultRow {
        records: record_count,
        queries: query_count,
        workers: worker_count,
        elapsed_ms: elapsed.as_secs_f64() * 1_000.0,
        queries_per_second: query_count_f64 / elapsed.as_secs_f64(),
        p50_ms: percentile(50),
        p99_ms: percentile(99),
        errors,
        target_queries_per_second: target_rate,
    };
    println!("{}", serde_json::to_string(&row)?);
    if errors > 0 {
        anyhow::bail!("benchmark had {errors} failed queries");
    }
    Ok(())
}

async fn wait_until_ready(address: SocketAddr) -> anyhow::Result<()> {
    for _ in 0..100 {
        if TcpStream::connect(address).await.is_ok() {
            return Ok(());
        }
        time::sleep(Duration::from_millis(10)).await;
    }
    anyhow::bail!("server did not start")
}

fn env_usize(name: &str, default: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(default)
}
