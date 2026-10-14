use std::{net::SocketAddr, time::Duration};

use hickory_proto::rr::RecordType;
use localname::query_server;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let server: SocketAddr = std::env::var("LOCALNAME_TEST_SERVER")?.parse()?;
    for _ in 0..30 {
        if let Ok(answer) = query_server(
            server,
            "nas.home.arpa.",
            RecordType::A,
            Duration::from_secs(1),
        )
        .await
            && answer
                .answers
                .iter()
                .any(|record| record.contains("192.168.1.20"))
        {
            let external = query_server(
                server,
                "remote.external.test.",
                RecordType::A,
                Duration::from_secs(1),
            )
            .await?;
            anyhow::ensure!(
                external
                    .answers
                    .iter()
                    .any(|record| record.contains("203.0.113.8")),
                "external forwarding failed"
            );
            let negative = query_server(
                server,
                "missing.home.arpa.",
                RecordType::A,
                Duration::from_secs(1),
            )
            .await?;
            anyhow::ensure!(
                negative.response_code == "NXDomain",
                "local negative answer failed"
            );
            println!("router → localname → upstream: all DNS checks passed");
            return Ok(());
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    anyhow::bail!("network DNS did not become ready")
}
