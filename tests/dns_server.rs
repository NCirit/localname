use std::{net::SocketAddr, str::FromStr, time::Duration};

use hickory_proto::{
    op::{Message, Query},
    rr::{Name, RData, Record, RecordType, rdata::A},
};
use localname::{Config, ConfigStore, DnsServer, RecordConfig, query_server};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpStream, UdpSocket},
    sync::watch,
    time,
};

fn unused_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

async fn start_server(mut config: Config) -> (tempfile::TempDir, SocketAddr, watch::Sender<bool>) {
    let port = unused_port();
    let listen: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    config.listen = vec![listen];
    config.validate().unwrap();
    let dir = tempfile::tempdir().unwrap();
    let store = ConfigStore::new(dir.path().join("config.toml"));
    store.initialize(&config).unwrap();
    let server = DnsServer::new(store, config).unwrap();
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    tokio::spawn(server.run(shutdown_rx));
    for _ in 0..50 {
        if TcpStream::connect(listen).await.is_ok() {
            return (dir, listen, shutdown_tx);
        }
        time::sleep(Duration::from_millis(10)).await;
    }
    panic!("DNS server did not start");
}

#[tokio::test]
async fn answers_udp_and_tcp() {
    let mut config = Config::default();
    config.records.push(RecordConfig {
        name: "nas".into(),
        value: "192.168.1.20".into(),
        ttl: 60,
    });
    let (_dir, listen, shutdown) = start_server(config).await;

    let udp = query_server(
        listen,
        "nas.home.arpa.",
        RecordType::A,
        Duration::from_secs(1),
    )
    .await
    .unwrap();
    assert_eq!(udp.answers.len(), 1);
    assert!(udp.authoritative);

    let mut query = Message::query();
    query.metadata.recursion_desired = true;
    query.add_query(Query::query(
        Name::from_str("nas.home.arpa.").unwrap(),
        RecordType::A,
    ));
    let bytes = query.to_vec().unwrap();
    let mut tcp = TcpStream::connect(listen).await.unwrap();
    tcp.write_u16(u16::try_from(bytes.len()).unwrap())
        .await
        .unwrap();
    tcp.write_all(&bytes).await.unwrap();
    let length = tcp.read_u16().await.unwrap();
    let mut response = vec![0_u8; length as usize];
    tcp.read_exact(&mut response).await.unwrap();
    let response = Message::from_vec(&response).unwrap();
    assert_eq!(response.answers.len(), 1);
    assert!(response.authoritative);
    shutdown.send(true).unwrap();
}

#[tokio::test]
async fn local_negatives_work_without_upstream_and_malformed_packets_do_not_crash() {
    let mut config = Config {
        upstreams: vec!["127.0.0.1:1".parse().unwrap()],
        ..Config::default()
    };
    config.records.push(RecordConfig {
        name: "nas".into(),
        value: "192.168.1.20".into(),
        ttl: 60,
    });
    let (_dir, listen, shutdown) = start_server(config).await;
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    for bytes in [vec![], vec![0], vec![0xff; 32]] {
        socket.send_to(&bytes, listen).await.unwrap();
    }
    for (name, kind, expected) in [
        ("missing.home.arpa.", RecordType::A, "NXDomain"),
        ("nas.home.arpa.", RecordType::AAAA, "NoError"),
        ("home.arpa.", RecordType::SOA, "NoError"),
    ] {
        let result = query_server(listen, name, kind, Duration::from_secs(1))
            .await
            .unwrap();
        assert_eq!(result.response_code, expected);
        assert!(result.authoritative);
    }
    shutdown.send(true).unwrap();
}

#[tokio::test]
async fn forwards_and_caches_external_answer() {
    let upstream = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let upstream_address = upstream.local_addr().unwrap();
    let upstream_task = tokio::spawn(async move {
        let mut bytes = [0_u8; 4096];
        let (size, peer) = upstream.recv_from(&mut bytes).await.unwrap();
        let request = Message::from_vec(&bytes[..size]).unwrap();
        let query = request.queries[0].clone();
        let mut response = Message::response(request.id, request.op_code);
        response.metadata.recursion_available = true;
        response.add_query(query.clone());
        response.add_answer(Record::from_rdata(
            query.name().clone(),
            60,
            RData::A(A::new(203, 0, 113, 7)),
        ));
        upstream
            .send_to(&response.to_vec().unwrap(), peer)
            .await
            .unwrap();
    });

    let config = Config {
        upstreams: vec![upstream_address],
        ..Config::default()
    };
    let (_dir, listen, shutdown) = start_server(config).await;
    let first = query_server(
        listen,
        "example.test.",
        RecordType::A,
        Duration::from_secs(1),
    )
    .await
    .unwrap();
    assert_eq!(first.answers.len(), 1);
    upstream_task.await.unwrap();

    let cached = query_server(
        listen,
        "example.test.",
        RecordType::A,
        Duration::from_secs(1),
    )
    .await
    .unwrap();
    assert_eq!(cached.answers, first.answers);
    shutdown.send(true).unwrap();
}

#[tokio::test]
async fn udp_size_limit_sets_truncation_and_tcp_returns_complete_answer() {
    let config = Config {
        records: (1..=60)
            .map(|index| RecordConfig {
                name: "cluster".into(),
                value: format!("10.0.0.{index}"),
                ttl: 60,
            })
            .collect(),
        ..Config::default()
    };
    let (_dir, listen, shutdown) = start_server(config).await;
    let mut query = Message::query();
    query.add_query(Query::query(
        Name::from_str("cluster.home.arpa.").unwrap(),
        RecordType::A,
    ));
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    socket
        .send_to(&query.to_vec().unwrap(), listen)
        .await
        .unwrap();
    let mut buffer = [0; 4096];
    let (size, _) = time::timeout(Duration::from_secs(1), socket.recv_from(&mut buffer))
        .await
        .unwrap()
        .unwrap();
    assert!(size <= 512);
    assert!(Message::from_vec(&buffer[..size]).unwrap().truncation);
    let complete = query_server(
        listen,
        "cluster.home.arpa.",
        RecordType::A,
        Duration::from_secs(1),
    )
    .await
    .unwrap();
    assert_eq!(complete.answers.len(), 60);
    shutdown.send(true).unwrap();
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn live_control_change_is_immediately_visible() {
    use localname::control::{self, Request};
    let (dir, listen, shutdown) = start_server(Config::default()).await;
    let store = ConfigStore::new(dir.path().join("config.toml"));
    for _ in 0..50 {
        if control::socket_path(store.path()).exists() {
            break;
        }
        time::sleep(Duration::from_millis(10)).await;
    }
    let next = tokio::task::spawn_blocking(move || {
        control::request_if_running(
            &store,
            &Request::Add {
                record: RecordConfig {
                    name: "live.home.arpa.".into(),
                    value: "192.168.1.44".into(),
                    ttl: 60,
                },
                expected_revision: Some(0),
            },
        )
        .unwrap()
        .unwrap()
    })
    .await
    .unwrap();
    assert_eq!(next.config.revision, 1);
    let result = query_server(
        listen,
        "live.home.arpa.",
        RecordType::A,
        Duration::from_secs(1),
    )
    .await
    .unwrap();
    assert_eq!(result.answers.len(), 1);
    shutdown.send(true).unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn external_edits_reload_and_invalid_edits_keep_the_previous_revision() {
    let (dir, listen, shutdown) = start_server(Config::default()).await;
    let path = dir.path().join("config.toml");
    let mut edited = ConfigStore::new(&path).load().unwrap();
    edited.revision = 1;
    edited.records.push(RecordConfig {
        name: "edited.home.arpa.".into(),
        value: "192.168.1.50".into(),
        ttl: 60,
    });
    std::fs::write(&path, toml::to_string(&edited).unwrap()).unwrap();
    let mut served = false;
    for _ in 0..40 {
        let result = query_server(
            listen,
            "edited.home.arpa.",
            RecordType::A,
            Duration::from_secs(1),
        )
        .await
        .unwrap();
        if result.answers.len() == 1 {
            served = true;
            break;
        }
        time::sleep(Duration::from_millis(100)).await;
    }
    assert!(served, "valid external edit was not reloaded");

    std::fs::write(&path, "zone = \"home.arpa\"\nlisten = [\"8.8.8.8:53\"]\n").unwrap();
    time::sleep(Duration::from_millis(2_500)).await;
    let result = query_server(
        listen,
        "edited.home.arpa.",
        RecordType::A,
        Duration::from_secs(1),
    )
    .await
    .unwrap();
    assert_eq!(
        result.answers.len(),
        1,
        "invalid edit replaced the served revision"
    );
    shutdown.send(true).unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn local_answers_stay_fast_while_upstreams_are_down() {
    // An upstream that accepts packets and never answers: forwarded queries hang until timeout.
    let blackhole = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let mut config = Config {
        upstreams: vec![blackhole.local_addr().unwrap()],
        upstream_timeout_ms: 2_000,
        ..Config::default()
    };
    config.records.push(RecordConfig {
        name: "nas".into(),
        value: "192.168.1.20".into(),
        ttl: 60,
    });
    let (dir, listen, shutdown) = start_server(config).await;
    // Pre-bound client sockets: socket creation is slow on some hosts and would measure
    // the test client rather than the server.
    let flood = std::sync::Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    // Drain SERVFAILs concurrently: 500 timeouts expire together, and a burst that size
    // overflows default loopback socket buffers before a sequential reader catches up.
    let failures = tokio::spawn({
        let flood = std::sync::Arc::clone(&flood);
        async move {
            let mut buffer = [0_u8; 512];
            let mut failures = 0;
            while failures < 500 {
                let Ok(Ok(size)) =
                    time::timeout(Duration::from_secs(3), flood.recv(&mut buffer)).await
                else {
                    break;
                };
                if Message::from_vec(&buffer[..size]).unwrap().response_code
                    == hickory_proto::op::ResponseCode::ServFail
                {
                    failures += 1;
                }
            }
            failures
        }
    });
    for index in 0..500_u16 {
        let mut request = Message::query();
        request.metadata.id = index;
        request.metadata.recursion_desired = true;
        request.add_query(Query::query(
            Name::from_str(&format!("site{index}.example.")).unwrap(),
            RecordType::A,
        ));
        flood
            .send_to(&request.to_vec().unwrap(), listen)
            .await
            .unwrap();
        // Spread the burst over ~200 ms so the upstream timeouts do not all fire at once.
        if index % 50 == 49 {
            time::sleep(Duration::from_millis(20)).await;
        }
    }
    time::sleep(Duration::from_millis(50)).await;
    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    client.connect(listen).await.unwrap();
    let mut buffer = [0_u8; 512];
    let mut slowest = Duration::ZERO;
    for index in 0..50_u16 {
        let mut request = Message::query();
        request.metadata.id = 10_000 + index;
        request.add_query(Query::query(
            Name::from_str("nas.home.arpa.").unwrap(),
            RecordType::A,
        ));
        let started = std::time::Instant::now();
        client.send(&request.to_vec().unwrap()).await.unwrap();
        let size = time::timeout(Duration::from_secs(1), client.recv(&mut buffer))
            .await
            .expect("local answer while upstream is down")
            .unwrap();
        slowest = slowest.max(started.elapsed());
        let response = Message::from_vec(&buffer[..size]).unwrap();
        assert_eq!(response.id, 10_000 + index);
        assert_eq!(response.answers.len(), 1);
    }
    assert!(
        slowest < Duration::from_millis(100),
        "slowest local answer {slowest:?}"
    );
    // Every flooded query ends in SERVFAIL instead of hanging: the server counts each failed
    // forward. Loopback UDP can still drop some replies in a burst this size.
    let received = failures.await.unwrap();
    let store = ConfigStore::new(dir.path().join("config.toml"));
    let status = tokio::task::spawn_blocking(move || {
        localname::control::send_if_running(&store, &localname::control::Request::Status)
    })
    .await
    .unwrap()
    .unwrap()
    .and_then(|response| response.status)
    .expect("daemon status");
    assert_eq!(
        status.metrics.errors, 500,
        "SERVFAIL for every forwarded query"
    );
    assert!(received > 0, "no SERVFAIL replies arrived");
    drop(blackhole);
    shutdown.send(true).unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mutual_forwarding_loop_fails_fast() {
    // A forwards to B and B forwards to A; the loop must end in SERVFAIL, not a timeout storm.
    let port_a = unused_port();
    let port_b = unused_port();
    let a: SocketAddr = format!("127.0.0.1:{port_a}").parse().unwrap();
    let b: SocketAddr = format!("127.0.0.1:{port_b}").parse().unwrap();
    let mut servers = Vec::new();
    for (listen, upstream) in [(a, b), (b, a)] {
        let mut config = Config {
            listen: vec![listen],
            upstreams: vec![upstream],
            upstream_timeout_ms: 3_000,
            ..Config::default()
        };
        config.validate().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let store = ConfigStore::new(dir.path().join("config.toml"));
        store.initialize(&config).unwrap();
        let server = DnsServer::new(store, config).unwrap();
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        tokio::spawn(server.run(shutdown_rx));
        servers.push((dir, shutdown_tx));
    }
    for address in [a, b] {
        for _ in 0..50 {
            if TcpStream::connect(address).await.is_ok() {
                break;
            }
            time::sleep(Duration::from_millis(10)).await;
        }
    }
    let started = std::time::Instant::now();
    let result = query_server(a, "loop.example.", RecordType::A, Duration::from_secs(5))
        .await
        .unwrap();
    assert_eq!(result.response_code, "ServFail");
    assert!(
        started.elapsed() < Duration::from_secs(1),
        "{:?}",
        started.elapsed()
    );
    for (_, shutdown) in servers {
        shutdown.send(true).unwrap();
    }
}
