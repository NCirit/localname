//! A small stub client used by status, verification, and tests.

use std::{
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
    str::FromStr,
    time::{Duration, Instant},
};

use anyhow::{Context, Result};
use hickory_proto::{
    op::{Message, Query},
    rr::{Name, Record, RecordType},
};
use serde::Serialize;
use tokio::{net::UdpSocket, time};

use super::{
    MAX_UDP_PACKET,
    forward::{query_upstream_tcp, validate_response},
};

#[derive(Debug, Serialize)]
pub struct QueryResult {
    pub name: String,
    pub record_type: String,
    pub response_code: String,
    pub authoritative: bool,
    pub truncated: bool,
    pub transport: &'static str,
    pub answers: Vec<String>,
    pub records: Vec<Answer>,
    pub authorities: Vec<Answer>,
    pub elapsed_ms: f64,
}

#[derive(Debug, Serialize)]
pub struct Answer {
    pub name: String,
    pub record_type: String,
    pub ttl: u32,
    pub value: String,
}

impl From<&Record> for Answer {
    fn from(record: &Record) -> Self {
        Self {
            name: record.name.to_ascii(),
            record_type: format!("{:?}", record.record_type()),
            ttl: record.ttl,
            value: record.data.to_string(),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Transport {
    /// UDP, retrying over TCP when the answer is truncated.
    Udp,
    Tcp,
}

/// Query over UDP and fall back to TCP on truncation.
pub async fn query_server(
    server: SocketAddr,
    name: &str,
    record_type: RecordType,
    timeout: Duration,
) -> Result<QueryResult> {
    query_with(server, name, record_type, timeout, Transport::Udp).await
}

pub async fn query_with(
    server: SocketAddr,
    name: &str,
    record_type: RecordType,
    timeout: Duration,
    transport: Transport,
) -> Result<QueryResult> {
    let name = Name::from_str(name)?;
    let mut request = Message::query();
    request.metadata.recursion_desired = true;
    request.add_query(Query::query(name.clone(), record_type));
    let bytes = request.to_vec()?;
    let started = Instant::now();
    let (response, used) = if transport == Transport::Tcp {
        let bytes = query_upstream_tcp(&bytes, server, timeout).await?;
        (Message::from_vec(&bytes)?, "tcp")
    } else {
        let bind = match server {
            SocketAddr::V4(_) => SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)),
            SocketAddr::V6(_) => SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0)),
        };
        let socket = UdpSocket::bind(bind).await?;
        socket.connect(server).await?;
        socket.send(&bytes).await?;
        let mut response_bytes = vec![0_u8; MAX_UDP_PACKET];
        let size = time::timeout(timeout, socket.recv(&mut response_bytes))
            .await
            .context("DNS query timed out")??;
        response_bytes.truncate(size);
        let response = Message::from_vec(&response_bytes)?;
        validate_response(&request, &response)?;
        if response.truncation {
            let bytes = query_upstream_tcp(&bytes, server, timeout).await?;
            (Message::from_vec(&bytes)?, "tcp")
        } else {
            (response, "udp")
        }
    };
    Ok(QueryResult {
        name: name.to_ascii(),
        record_type: format!("{record_type:?}"),
        response_code: format!("{:?}", response.response_code),
        authoritative: response.authoritative,
        truncated: response.truncation,
        transport: used,
        answers: response.answers.iter().map(ToString::to_string).collect(),
        records: response.answers.iter().map(Answer::from).collect(),
        authorities: response.authorities.iter().map(Answer::from).collect(),
        elapsed_ms: started.elapsed().as_secs_f64() * 1_000.0,
    })
}
