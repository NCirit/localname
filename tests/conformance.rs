//! Fixture-driven DNS conformance: every case in `fixtures/conformance.toml` must hold over
//! both UDP and TCP against a live listener.

use std::{net::SocketAddr, time::Duration};

use hickory_proto::rr::RecordType;
use localname::{Config, ConfigStore, DnsServer, Transport, query_with};
use serde::Deserialize;
use tokio::{net::TcpStream, sync::watch, time};

#[derive(Deserialize)]
struct Fixture {
    config: toml::Table,
    case: Vec<Case>,
}

#[derive(Deserialize)]
struct Case {
    about: String,
    name: String,
    #[serde(rename = "type")]
    record_type: String,
    rcode: String,
    aa: bool,
    answers: Vec<String>,
    #[serde(default)]
    soa_authority: bool,
}

fn record_type(text: &str) -> RecordType {
    text.parse()
        .unwrap_or_else(|_| panic!("unknown type {text}"))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn fixtures_hold_over_udp_and_tcp() {
    let fixture: Fixture =
        toml::from_str(include_str!("fixtures/conformance.toml")).expect("valid fixture file");
    let port = dual_port();
    let listen: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    let mut config: Config = fixture.config.try_into().expect("fixture config");
    config.listen = vec![listen];
    config.validate().unwrap();
    let directory = tempfile::tempdir().unwrap();
    let store = ConfigStore::new(directory.path().join("config.toml"));
    store.initialize(&config).unwrap();
    let server = DnsServer::new(store, config).unwrap();
    let (shutdown, receiver) = watch::channel(false);
    let running = tokio::spawn(server.run(receiver));
    let mut ready = false;
    for _ in 0..100 {
        if TcpStream::connect(listen).await.is_ok() {
            ready = true;
            break;
        }
        assert!(
            !running.is_finished(),
            "DNS server stopped: {:?}",
            running.await
        );
        time::sleep(Duration::from_millis(10)).await;
    }
    assert!(ready, "DNS server did not start on {listen}");

    let mut failures = Vec::new();
    for case in &fixture.case {
        for transport in [Transport::Udp, Transport::Tcp] {
            let result = query_with(
                listen,
                &case.name,
                record_type(&case.record_type),
                Duration::from_secs(2),
                transport,
            )
            .await
            .unwrap_or_else(|error| panic!("{} ({transport:?}): {error:#}", case.about));
            let answers: Vec<String> = result
                .records
                .iter()
                .map(|record| format!("{} {}", record.record_type, record.value))
                .collect();
            let soa = result
                .authorities
                .iter()
                .any(|record| record.record_type == "SOA");
            if result.response_code != case.rcode
                || result.authoritative != case.aa
                || answers != case.answers
                || soa != case.soa_authority
            {
                failures.push(format!(
                    "{} ({transport:?}): rcode {} aa {} answers {answers:?} soa {soa}",
                    case.about, result.response_code, result.authoritative
                ));
            }
        }
    }
    shutdown.send(true).unwrap();
    assert!(
        failures.is_empty(),
        "conformance failures:\n{}",
        failures.join("\n")
    );
}

/// A loopback port free for both UDP and TCP: DNS listens on both, and a port free for
/// one transport can be taken for the other.
fn dual_port() -> u16 {
    loop {
        let tcp = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = tcp.local_addr().unwrap().port();
        if std::net::UdpSocket::bind(("127.0.0.1", port)).is_ok() {
            return port;
        }
    }
}
