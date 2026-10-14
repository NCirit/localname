use std::{
    collections::{HashMap, HashSet},
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    str::FromStr,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant, SystemTime},
};

use anyhow::{Context, Result, anyhow, bail};
use arc_swap::ArcSwap;
use hickory_proto::{
    op::{Message, MessageType, OpCode, Query, ResponseCode},
    rr::{
        DNSClass, Name, RData, Record, RecordType,
        rdata::{A, AAAA, CNAME, PTR, SOA},
    },
};
use serde::Serialize;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
    sync::{Mutex, Semaphore, watch},
    task::JoinSet,
    time,
};
use tracing::{debug, error, info, warn};

use crate::config::{Config, ConfigStore, RecordConfig, name_in_zone};

const MAX_UDP_PACKET: usize = 4096;
const MAX_TCP_PACKET: usize = u16::MAX as usize;

#[derive(Clone)]
pub struct DnsSnapshot {
    zone_text: String,
    records: HashMap<(String, RecordType), Vec<Record>>,
    known_names: HashSet<String>,
    soa: Record,
    allowed_clients: Vec<ipnet::IpNet>,
    upstreams: Vec<SocketAddr>,
    upstream_timeout: Duration,
    cache_entries: usize,
}

impl DnsSnapshot {
    pub fn from_config(config: &Config) -> Result<Self> {
        let zone = Name::from_str(&config.zone).context("invalid zone")?;
        let mut records: HashMap<(String, RecordType), Vec<Record>> = HashMap::new();
        let mut known_names = HashSet::new();
        for entry in &config.records {
            insert_record(&mut records, &mut known_names, entry)?;
            let mut parent = entry.name.as_str();
            while let Some((_, next)) = parent.split_once('.') {
                if !name_in_zone(next, &config.zone) {
                    break;
                }
                known_names.insert(next.to_owned());
                parent = next;
            }
        }

        let ns_name = Name::from_str(&format!("ns1.{}", config.zone))?;
        let hostmaster = Name::from_str(&format!("hostmaster.{}", config.zone))?;
        let soa = Record::from_rdata(
            zone.clone(),
            60,
            RData::SOA(SOA::new(
                ns_name,
                hostmaster,
                u32::try_from(config.revision).unwrap_or(u32::MAX),
                3600,
                600,
                86_400,
                60,
            )),
        );
        Ok(Self {
            zone_text: config.zone.clone(),
            records,
            known_names,
            soa,
            allowed_clients: config.allowed_clients.clone(),
            upstreams: config.upstreams.clone(),
            upstream_timeout: Duration::from_millis(config.upstream_timeout_ms),
            cache_entries: config.cache_entries,
        })
    }

    fn is_local_name(&self, name: &str) -> bool {
        name_in_zone(name, &self.zone_text) || self.known_names.contains(name)
    }

    fn client_allowed(&self, address: IpAddr) -> bool {
        self.allowed_clients
            .iter()
            .any(|network| network.contains(&address))
    }
}

fn insert_record(
    records: &mut HashMap<(String, RecordType), Vec<Record>>,
    known_names: &mut HashSet<String>,
    entry: &RecordConfig,
) -> Result<()> {
    let name = Name::from_str(&entry.name)?;
    let name_text = entry.name.to_ascii_lowercase();
    known_names.insert(name_text.clone());
    let (record_type, data) = match entry.value.parse::<IpAddr>() {
        Ok(IpAddr::V4(address)) => (RecordType::A, RData::A(A(address))),
        Ok(IpAddr::V6(address)) => (RecordType::AAAA, RData::AAAA(AAAA(address))),
        Err(_) => (
            RecordType::CNAME,
            RData::CNAME(CNAME(
                Name::from_str(&entry.value).context("invalid CNAME target")?,
            )),
        ),
    };
    records
        .entry((name_text.clone(), record_type))
        .or_default()
        .push(Record::from_rdata(name, entry.ttl, data));

    if let Ok(address) = entry.value.parse::<IpAddr>() {
        let reverse = reverse_name(address);
        let reverse_name = Name::from_str(&reverse)?;
        known_names.insert(reverse.clone());
        records
            .entry((reverse, RecordType::PTR))
            .or_default()
            .push(Record::from_rdata(
                reverse_name,
                entry.ttl,
                RData::PTR(PTR(Name::from_str(&entry.name)?)),
            ));
    }
    Ok(())
}

fn reverse_name(address: IpAddr) -> String {
    match address {
        IpAddr::V4(address) => {
            let octets = address.octets();
            format!(
                "{}.{}.{}.{}.in-addr.arpa.",
                octets[3], octets[2], octets[1], octets[0]
            )
        }
        IpAddr::V6(address) => {
            let nibbles = address
                .octets()
                .iter()
                .rev()
                .flat_map(|byte| [format!("{:x}", byte & 0x0f), format!("{:x}", byte >> 4)])
                .collect::<Vec<_>>()
                .join(".");
            format!("{nibbles}.ip6.arpa.")
        }
    }
}

#[derive(Default)]
struct Metrics {
    queries: AtomicU64,
    local: AtomicU64,
    forwarded: AtomicU64,
    cache_hits: AtomicU64,
    refused: AtomicU64,
    errors: AtomicU64,
}

#[derive(Debug, Serialize)]
pub struct MetricsSnapshot {
    pub queries: u64,
    pub local: u64,
    pub forwarded: u64,
    pub cache_hits: u64,
    pub refused: u64,
    pub errors: u64,
}

impl Metrics {
    fn snapshot(&self) -> MetricsSnapshot {
        MetricsSnapshot {
            queries: self.queries.load(Ordering::Relaxed),
            local: self.local.load(Ordering::Relaxed),
            forwarded: self.forwarded.load(Ordering::Relaxed),
            cache_hits: self.cache_hits.load(Ordering::Relaxed),
            refused: self.refused.load(Ordering::Relaxed),
            errors: self.errors.load(Ordering::Relaxed),
        }
    }
}

#[derive(Clone, Debug, Hash, PartialEq, Eq)]
struct CacheKey {
    name: String,
    record_type: RecordType,
    checking_disabled: bool,
    dnssec_ok: bool,
}

struct CacheEntry {
    bytes: Vec<u8>,
    inserted: Instant,
    expires: Instant,
}

struct Forwarder {
    cache: Mutex<HashMap<CacheKey, CacheEntry>>,
    metrics: Arc<Metrics>,
}

impl Forwarder {
    fn new(metrics: Arc<Metrics>) -> Self {
        Self {
            cache: Mutex::new(HashMap::new()),
            metrics,
        }
    }

    async fn resolve(
        &self,
        request: &[u8],
        message: &Message,
        snapshot: &DnsSnapshot,
    ) -> Result<Vec<u8>> {
        let query = message
            .queries
            .first()
            .ok_or_else(|| anyhow!("query has no question"))?;
        let key = CacheKey {
            name: query.name().to_ascii().to_ascii_lowercase(),
            record_type: query.query_type(),
            checking_disabled: message.checking_disabled,
            dnssec_ok: message
                .edns
                .as_ref()
                .is_some_and(|edns| edns.flags().dnssec_ok),
        };
        let now = Instant::now();
        let cacheable = message.signature.is_none()
            && message
                .edns
                .as_ref()
                .is_none_or(|edns| edns.options().options.is_empty());
        {
            let mut cache = self.cache.lock().await;
            if let Some(entry) = cache.get(&key)
                && cacheable
                && entry.expires > now
            {
                self.metrics.cache_hits.fetch_add(1, Ordering::Relaxed);
                let mut cached = Message::from_vec(&entry.bytes)?;
                cached.metadata.id = message.id;
                cached.queries.clone_from(&message.queries);
                let elapsed = u32::try_from(entry.inserted.elapsed().as_secs()).unwrap_or(u32::MAX);
                for record in cached
                    .answers
                    .iter_mut()
                    .chain(cached.authorities.iter_mut())
                    .chain(cached.additionals.iter_mut())
                {
                    record.ttl = record.ttl.saturating_sub(elapsed);
                }
                return Ok(cached.to_vec()?);
            }
            cache.remove(&key);
        }

        let mut last_error = None;
        for upstream in &snapshot.upstreams {
            match query_upstream(request, *upstream, snapshot.upstream_timeout).await {
                Ok(bytes) => {
                    let ttl = response_ttl(&bytes).unwrap_or(0).min(86_400);
                    let mut cached = bytes.clone();
                    cached[..2].copy_from_slice(&0_u16.to_be_bytes());
                    let mut cache = self.cache.lock().await;
                    if cacheable && snapshot.cache_entries > 0 && ttl > 0 {
                        if cache.len() >= snapshot.cache_entries {
                            cache.retain(|_, entry| entry.expires > now);
                            if cache.len() >= snapshot.cache_entries
                                && let Some(oldest) = cache
                                    .iter()
                                    .min_by_key(|(_, entry)| entry.expires)
                                    .map(|(key, _)| key.clone())
                            {
                                cache.remove(&oldest);
                            }
                        }
                        cache.insert(
                            key,
                            CacheEntry {
                                bytes: cached,
                                inserted: Instant::now(),
                                expires: now + Duration::from_secs(u64::from(ttl)),
                            },
                        );
                    }
                    return Ok(bytes);
                }
                Err(error) => last_error = Some(error),
            }
        }
        Err(last_error.unwrap_or_else(|| anyhow!("no upstream resolver configured")))
    }
}

fn response_ttl(bytes: &[u8]) -> Option<u32> {
    let response = Message::from_vec(bytes).ok()?;
    if !matches!(
        response.response_code,
        ResponseCode::NoError | ResponseCode::NXDomain
    ) {
        return None;
    }
    let ttl = response
        .answers
        .iter()
        .chain(response.authorities.iter())
        .map(|record| record.ttl)
        .min()?;
    if response.answers.is_empty() {
        let negative_ttl = response.authorities.iter().find_map(|record| {
            if let RData::SOA(soa) = &record.data {
                Some(record.ttl.min(soa.minimum))
            } else {
                None
            }
        })?;
        Some(ttl.min(negative_ttl))
    } else {
        Some(ttl)
    }
}

async fn query_upstream(
    request: &[u8],
    upstream: SocketAddr,
    timeout: Duration,
) -> Result<Vec<u8>> {
    let bind = match upstream {
        SocketAddr::V4(_) => SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)),
        SocketAddr::V6(_) => SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0)),
    };
    let socket = UdpSocket::bind(bind).await?;
    socket.connect(upstream).await?;
    socket.send(request).await?;
    let mut buffer = vec![0_u8; MAX_UDP_PACKET];
    let size = time::timeout(timeout, socket.recv(&mut buffer))
        .await
        .context("upstream UDP timeout")??;
    buffer.truncate(size);
    let response = Message::from_vec(&buffer).context("invalid upstream response")?;
    let request_message = Message::from_vec(request)?;
    validate_response(&request_message, &response)?;
    if response.truncation {
        return query_upstream_tcp(request, upstream, timeout).await;
    }
    Ok(buffer)
}

async fn query_upstream_tcp(
    request: &[u8],
    upstream: SocketAddr,
    timeout: Duration,
) -> Result<Vec<u8>> {
    let mut stream = time::timeout(timeout, TcpStream::connect(upstream))
        .await
        .context("upstream TCP connect timeout")??;
    let length = u16::try_from(request.len())
        .map_err(|_| anyhow!("DNS request exceeds TCP framing limit"))?;
    let bytes = time::timeout(timeout, async {
        stream.write_all(&length.to_be_bytes()).await?;
        stream.write_all(request).await?;
        let response_length = stream.read_u16().await? as usize;
        if response_length > MAX_TCP_PACKET {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "oversized DNS response",
            ));
        }
        let mut response = vec![0_u8; response_length];
        stream.read_exact(&mut response).await?;
        Ok::<_, io::Error>(response)
    })
    .await
    .context("upstream TCP timeout")?
    .map_err(anyhow::Error::from)?;
    validate_response(&Message::from_vec(request)?, &Message::from_vec(&bytes)?)?;
    Ok(bytes)
}

fn validate_response(request: &Message, response: &Message) -> Result<()> {
    if response.id != request.id
        || response.message_type != MessageType::Response
        || response.op_code != request.op_code
        || response.queries != request.queries
    {
        bail!("upstream response did not match query");
    }
    Ok(())
}

pub struct DnsServer {
    config_store: ConfigStore,
    config: Config,
    snapshot: Arc<ArcSwap<DnsSnapshot>>,
    metrics: Arc<Metrics>,
    forwarder: Arc<Forwarder>,
    concurrency: Arc<Semaphore>,
}

impl DnsServer {
    pub fn new(config_store: ConfigStore, mut config: Config) -> Result<Self> {
        config.validate()?;
        let snapshot = Arc::new(DnsSnapshot::from_config(&config)?);
        let metrics = Arc::new(Metrics::default());
        Ok(Self {
            config_store,
            config,
            snapshot: Arc::new(ArcSwap::from(snapshot)),
            forwarder: Arc::new(Forwarder::new(Arc::clone(&metrics))),
            metrics,
            concurrency: Arc::new(Semaphore::new(1024)),
        })
    }

    pub fn metrics(&self) -> MetricsSnapshot {
        self.metrics.snapshot()
    }

    pub async fn run(self, mut shutdown: watch::Receiver<bool>) -> Result<()> {
        let self_arc = Arc::new(self);
        let mut tasks = JoinSet::new();
        for listen in &self_arc.config.listen {
            let udp = UdpSocket::bind(listen)
                .await
                .with_context(|| format!("failed to bind UDP {listen}"))?;
            let tcp = TcpListener::bind(listen)
                .await
                .with_context(|| format!("failed to bind TCP {listen}"))?;
            info!(address = %listen, "DNS listener ready");
            tasks.spawn(run_udp(Arc::clone(&self_arc), udp, shutdown.clone()));
            tasks.spawn(run_tcp(Arc::clone(&self_arc), tcp, shutdown.clone()));
        }
        tasks.spawn(run_reload(Arc::clone(&self_arc), shutdown.clone()));
        #[cfg(unix)]
        tasks.spawn(crate::control::serve(
            self_arc.config_store.clone(),
            Arc::clone(&self_arc.snapshot),
            shutdown.clone(),
        ));

        tokio::select! {
            result = async {
                while let Some(result) = tasks.join_next().await {
                    result??;
                }
                Ok::<_, anyhow::Error>(())
            } => result?,
            _ = shutdown.changed() => {}
        }
        tasks.abort_all();
        Ok(())
    }

    async fn process(&self, request: &[u8], peer: SocketAddr) -> Result<Vec<u8>> {
        self.metrics.queries.fetch_add(1, Ordering::Relaxed);
        let message = Message::from_vec(request).context("malformed DNS message")?;
        if message.message_type != MessageType::Query
            || message.op_code != OpCode::Query
            || message.queries.len() != 1
        {
            return encode_error(&message, ResponseCode::FormErr);
        }
        let snapshot = self.snapshot.load();
        if !snapshot.client_allowed(peer.ip()) {
            self.metrics.refused.fetch_add(1, Ordering::Relaxed);
            return encode_error(&message, ResponseCode::Refused);
        }
        let query = &message.queries[0];
        if query.query_class() != DNSClass::IN {
            return encode_error(&message, ResponseCode::Refused);
        }
        let name = query.name().to_ascii().to_ascii_lowercase();
        if snapshot.is_local_name(&name) {
            self.metrics.local.fetch_add(1, Ordering::Relaxed);
            return local_response(&message, &snapshot);
        }
        if !message.recursion_desired {
            return encode_error(&message, ResponseCode::Refused);
        }
        self.metrics.forwarded.fetch_add(1, Ordering::Relaxed);
        match self.forwarder.resolve(request, &message, &snapshot).await {
            Ok(response) => Ok(response),
            Err(error) => {
                self.metrics.errors.fetch_add(1, Ordering::Relaxed);
                warn!(%error, %peer, "upstream resolution failed");
                encode_error(&message, ResponseCode::ServFail)
            }
        }
    }
}

async fn run_udp(
    server: Arc<DnsServer>,
    socket: UdpSocket,
    mut shutdown: watch::Receiver<bool>,
) -> Result<()> {
    let socket = Arc::new(socket);
    let mut buffer = vec![0_u8; MAX_UDP_PACKET];
    loop {
        tokio::select! {
            _ = shutdown.changed() => break,
            received = socket.recv_from(&mut buffer) => {
                let (size, peer) = received?;
                let request = buffer[..size].to_vec();
                let max_payload = Message::from_vec(&request)
                    .map_or(512, |message| usize::from(message.max_payload()).min(MAX_UDP_PACKET));
                let server = Arc::clone(&server);
                let socket = Arc::clone(&socket);
                let Ok(permit) = Arc::clone(&server.concurrency).try_acquire_owned() else {
                    debug!(%peer, "dropping DNS query at concurrency limit");
                    continue;
                };
                tokio::spawn(async move {
                    let _permit = permit;
                    match server.process(&request, peer).await {
                        Ok(response) => {
                            let response = if response.len() > max_payload {
                                truncate_response(&response).unwrap_or(response)
                            } else {
                                response
                            };
                            if let Err(error) = socket.send_to(&response, peer).await {
                                debug!(%error, %peer, "failed to send UDP response");
                            }
                        }
                        Err(error) => debug!(%error, %peer, "failed to process UDP query"),
                    }
                });
            }
        }
    }
    Ok(())
}

async fn run_tcp(
    server: Arc<DnsServer>,
    listener: TcpListener,
    mut shutdown: watch::Receiver<bool>,
) -> Result<()> {
    loop {
        tokio::select! {
            _ = shutdown.changed() => break,
            accepted = listener.accept() => {
                let (stream, peer) = accepted?;
                let Ok(permit) = Arc::clone(&server.concurrency).try_acquire_owned() else {
                    continue;
                };
                let server = Arc::clone(&server);
                tokio::spawn(async move {
                    let _permit = permit;
                    if let Err(error) = handle_tcp(server, stream, peer).await {
                        debug!(%error, %peer, "TCP DNS session failed");
                    }
                });
            }
        }
    }
    Ok(())
}

async fn handle_tcp(server: Arc<DnsServer>, mut stream: TcpStream, peer: SocketAddr) -> Result<()> {
    loop {
        let length = match time::timeout(Duration::from_secs(10), stream.read_u16()).await {
            Ok(Ok(length)) => length as usize,
            Ok(Err(error)) if error.kind() == io::ErrorKind::UnexpectedEof => return Ok(()),
            Ok(Err(error)) => return Err(error.into()),
            Err(_) => bail!("TCP client idle timeout"),
        };
        if length == 0 || length > MAX_TCP_PACKET {
            bail!("invalid TCP DNS frame length");
        }
        let mut request = vec![0_u8; length];
        time::timeout(Duration::from_secs(5), stream.read_exact(&mut request)).await??;
        let response = server.process(&request, peer).await?;
        let response_length =
            u16::try_from(response.len()).map_err(|_| anyhow!("DNS response too large"))?;
        stream.write_all(&response_length.to_be_bytes()).await?;
        stream.write_all(&response).await?;
    }
}

async fn run_reload(server: Arc<DnsServer>, mut shutdown: watch::Receiver<bool>) -> Result<()> {
    let mut modified = modified_time(server.config_store.path());
    let mut ticker = time::interval(Duration::from_secs(1));
    loop {
        tokio::select! {
            _ = shutdown.changed() => break,
            _ = ticker.tick() => {
                let current = modified_time(server.config_store.path());
                if current != modified {
                    modified = current;
                    match server.config_store.load().and_then(|config| {
                        if config.listen != server.config.listen {
                            bail!("listener changes require a service restart");
                        }
                        DnsSnapshot::from_config(&config)
                    }) {
                        Ok(snapshot) => {
                            server.forwarder.cache.lock().await.clear();
                            server.snapshot.store(Arc::new(snapshot));
                            info!("reloaded DNS configuration");
                        }
                        Err(error) => error!(%error, "configuration reload rejected; retaining previous revision"),
                    }
                }
            }
        }
    }
    Ok(())
}

fn modified_time(path: &std::path::Path) -> Option<SystemTime> {
    std::fs::metadata(path).ok()?.modified().ok()
}

fn local_response(request: &Message, snapshot: &DnsSnapshot) -> Result<Vec<u8>> {
    let query = &request.queries[0];
    let name = query.name().to_ascii().to_ascii_lowercase();
    let mut response = Message::response(request.id, request.op_code);
    response.metadata.recursion_desired = request.recursion_desired;
    response.metadata.recursion_available = true;
    response.metadata.authoritative = true;
    response.add_query(query.clone());
    if request.edns.is_some() {
        let mut edns = hickory_proto::op::Edns::new();
        edns.set_max_payload(request.max_payload().min(4096));
        response.set_edns(edns);
        if request.version() != 0 {
            response.metadata.response_code = ResponseCode::BADVERS;
            return Ok(response.to_vec()?);
        }
    }

    let exists = snapshot.known_names.contains(&name) || name == snapshot.zone_text;
    let mut answers = Vec::new();
    match query.query_type() {
        RecordType::SOA if name == snapshot.zone_text => answers.push(snapshot.soa.clone()),
        RecordType::ANY => {
            for ((record_name, _), values) in &snapshot.records {
                if record_name == &name {
                    answers.extend(values.iter().cloned());
                }
            }
        }
        requested => {
            if let Some(values) = snapshot.records.get(&(name.clone(), requested)) {
                answers.extend(values.iter().cloned());
            } else if requested != RecordType::CNAME {
                let mut current = name.clone();
                for _ in 0..16 {
                    let Some(values) = snapshot.records.get(&(current, RecordType::CNAME)) else {
                        break;
                    };
                    answers.extend(values.iter().cloned());
                    let Some(RData::CNAME(target)) = values.first().map(|value| &value.data) else {
                        break;
                    };
                    current = target.0.to_ascii().to_ascii_lowercase();
                    if let Some(values) = snapshot.records.get(&(current.clone(), requested)) {
                        answers.extend(values.iter().cloned());
                        break;
                    }
                }
            }
        }
    }

    if answers.is_empty() {
        if !exists {
            response.metadata.response_code = ResponseCode::NXDomain;
        }
        response.add_authority(snapshot.soa.clone());
    } else {
        response.add_answers(answers);
    }
    response.to_vec().map_err(Into::into)
}

fn encode_error(request: &Message, code: ResponseCode) -> Result<Vec<u8>> {
    let mut response = Message::error_msg(request.id, request.op_code, code);
    response.metadata.recursion_desired = request.recursion_desired;
    response.add_queries(request.queries.iter().cloned());
    response.to_vec().map_err(Into::into)
}

fn truncate_response(bytes: &[u8]) -> Result<Vec<u8>> {
    let response = Message::from_vec(bytes)?;
    response.truncate().to_vec().map_err(Into::into)
}

#[derive(Debug, Serialize)]
pub struct QueryResult {
    pub name: String,
    pub record_type: String,
    pub response_code: String,
    pub authoritative: bool,
    pub truncated: bool,
    pub answers: Vec<String>,
    pub elapsed_ms: f64,
}

pub async fn query_server(
    server: SocketAddr,
    name: &str,
    record_type: RecordType,
    timeout: Duration,
) -> Result<QueryResult> {
    let name = Name::from_str(name)?;
    let mut request = Message::query();
    request.metadata.recursion_desired = true;
    request.add_query(Query::query(name.clone(), record_type));
    let bytes = request.to_vec()?;
    let started = Instant::now();
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
    let mut response = Message::from_vec(&response_bytes)?;
    validate_response(&request, &response)?;
    if response.truncation {
        response = Message::from_vec(&query_upstream_tcp(&bytes, server, timeout).await?)?;
    }
    Ok(QueryResult {
        name: name.to_ascii(),
        record_type: format!("{record_type:?}"),
        response_code: format!("{:?}", response.response_code),
        authoritative: response.authoritative,
        truncated: response.truncation,
        answers: response.answers.iter().map(ToString::to_string).collect(),
        elapsed_ms: started.elapsed().as_secs_f64() * 1_000.0,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(1000))]
        #[test]
        fn arbitrary_wire_messages_do_not_panic(bytes in proptest::collection::vec(any::<u8>(), 0..2048)) {
            if let Ok(message) = Message::from_vec(&bytes) {
                let _ = message.to_vec();
            }
        }
    }

    #[tokio::test]
    async fn cached_ttl_counts_down() {
        let metrics = Arc::new(Metrics::default());
        let forwarder = Forwarder::new(metrics);
        let config = config_with_record();
        let snapshot = DnsSnapshot::from_config(&config).unwrap();
        let mut query = Message::query();
        query.add_query(Query::query(
            Name::from_str("example.test.").unwrap(),
            RecordType::A,
        ));
        let mut response = Message::response(query.id, query.op_code);
        response.add_query(query.queries[0].clone());
        response.add_answer(Record::from_rdata(
            Name::from_str("example.test.").unwrap(),
            60,
            RData::A(A::new(203, 0, 113, 1)),
        ));
        forwarder.cache.lock().await.insert(
            CacheKey {
                name: "example.test.".into(),
                record_type: RecordType::A,
                checking_disabled: false,
                dnssec_ok: false,
            },
            CacheEntry {
                bytes: response.to_vec().unwrap(),
                inserted: Instant::now().checked_sub(Duration::from_secs(20)).unwrap(),
                expires: Instant::now() + Duration::from_secs(40),
            },
        );
        let bytes = forwarder
            .resolve(&query.to_vec().unwrap(), &query, &snapshot)
            .await
            .unwrap();
        let cached = Message::from_vec(&bytes).unwrap();
        assert!(cached.answers[0].ttl <= 40);
        assert_eq!(cached.id, query.id);
    }

    fn config_with_record() -> Config {
        let mut config = Config::default();
        config.records.push(RecordConfig {
            name: "nas".into(),
            value: "192.168.1.20".into(),
            ttl: 60,
        });
        config.validate().unwrap();
        config
    }

    #[test]
    fn answers_local_a_and_ptr() {
        let snapshot = DnsSnapshot::from_config(&config_with_record()).unwrap();
        for (name, kind) in [
            ("nas.home.arpa.", RecordType::A),
            ("20.1.168.192.in-addr.arpa.", RecordType::PTR),
        ] {
            let mut request = Message::query();
            request.add_query(Query::query(Name::from_str(name).unwrap(), kind));
            let bytes = local_response(&request, &snapshot).unwrap();
            let response = Message::from_vec(&bytes).unwrap();
            assert_eq!(response.response_code, ResponseCode::NoError);
            assert_eq!(response.answers.len(), 1);
            assert!(response.authoritative);
        }
    }

    #[test]
    fn local_unknown_is_nxdomain() {
        let snapshot = DnsSnapshot::from_config(&config_with_record()).unwrap();
        let mut request = Message::query();
        request.add_query(Query::query(
            Name::from_str("missing.home.arpa.").unwrap(),
            RecordType::A,
        ));
        let response = Message::from_vec(&local_response(&request, &snapshot).unwrap()).unwrap();
        assert_eq!(response.response_code, ResponseCode::NXDomain);
        assert_eq!(response.authorities.len(), 1);
    }

    #[test]
    fn local_cname_chain_includes_target_address() {
        let mut config = config_with_record();
        config.records.push(RecordConfig {
            name: "storage".into(),
            value: "nas".into(),
            ttl: 60,
        });
        config.validate().unwrap();
        let snapshot = DnsSnapshot::from_config(&config).unwrap();
        let mut request = Message::query();
        request.add_query(Query::query(
            Name::from_str("storage.home.arpa.").unwrap(),
            RecordType::A,
        ));
        let response = Message::from_vec(&local_response(&request, &snapshot).unwrap()).unwrap();
        assert_eq!(response.answers.len(), 2);
        assert_eq!(response.answers[0].record_type(), RecordType::CNAME);
        assert_eq!(response.answers[1].record_type(), RecordType::A);
    }

    #[test]
    fn ipv6_reverse_name_is_correct_length() {
        let name = reverse_name("2001:db8::1".parse().unwrap());
        assert!(name.ends_with(".ip6.arpa."));
        assert_eq!(name.matches('.').count(), 34);
    }
}
