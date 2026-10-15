//! UDP/TCP listeners, admission control, query dispatch, and live reload.

use std::{
    collections::HashMap,
    io,
    net::{IpAddr, SocketAddr},
    sync::{Arc, Mutex, PoisonError},
    time::{Duration, Instant, SystemTime},
};

use anyhow::{Context, Result, anyhow, bail};
use arc_swap::ArcSwap;
use hickory_proto::op::{Message, MessageType, OpCode, ResponseCode};
use hickory_proto::rr::DNSClass;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
    sync::{Semaphore, watch},
    task::JoinSet,
    time,
};
use tracing::{debug, error, info, warn};

use super::{
    DnsSnapshot, MAX_TCP_PACKET, MAX_UDP_PACKET, Metrics, MetricsSnapshot, encode_error,
    forward::{Forwarder, Upstreams},
    local_response, localhost_response, nonexistent_response,
    special::{self, Special},
    strip_private_answers, truncate_response,
};
use crate::config::{Config, ConfigStore};

/// Concurrent forwarded queries across all transports.
const MAX_FORWARDS: usize = 1024;
/// Concurrent TCP connections in total and from one client address.
const MAX_TCP_CONNECTIONS: usize = 256;
const MAX_TCP_PER_CLIENT: usize = 16;
const TCP_IDLE: Duration = Duration::from_secs(10);

/// Sockets bound before the server starts, so a privileged parent can bind port 53 and
/// then drop privileges before any configuration or client data is processed.
pub struct Listeners {
    bound: Vec<(SocketAddr, UdpSocket, TcpListener)>,
    /// Service proxy listeners; empty in DNS-only mode.
    proxy: Vec<(SocketAddr, TcpListener)>,
    /// HTTPS proxy listeners; empty unless an HTTPS trust mode is configured.
    https: Vec<(SocketAddr, TcpListener)>,
}

impl Listeners {
    pub async fn bind(addresses: &[SocketAddr]) -> Result<Self> {
        let mut bound = Vec::new();
        for address in addresses {
            let udp = UdpSocket::bind(address)
                .await
                .with_context(|| format!("failed to bind UDP {address}"))?;
            let tcp = TcpListener::bind(address)
                .await
                .with_context(|| format!("failed to bind TCP {address}"))?;
            bound.push((*address, udp, tcp));
        }
        Ok(Self {
            bound,
            proxy: Vec::new(),
            https: Vec::new(),
        })
    }

    /// Bind DNS listeners and, only when the configuration enables it, the proxy.
    pub async fn bind_config(config: &Config) -> Result<Self> {
        let mut listeners = Self::bind(&config.listen).await?;
        for address in &config.proxy_listen {
            let tcp = TcpListener::bind(address)
                .await
                .with_context(|| format!("failed to bind proxy TCP {address}"))?;
            listeners.proxy.push((*address, tcp));
        }
        for address in https_listen(config) {
            let tcp = TcpListener::bind(address)
                .await
                .with_context(|| format!("failed to bind HTTPS TCP {address}"))?;
            listeners.https.push((address, tcp));
        }
        Ok(listeners)
    }

    pub fn addresses(&self) -> Vec<SocketAddr> {
        self.bound.iter().map(|(address, _, _)| *address).collect()
    }

    pub fn proxy_addresses(&self) -> Vec<SocketAddr> {
        self.proxy.iter().map(|(address, _)| *address).collect()
    }

    pub fn https_addresses(&self) -> Vec<SocketAddr> {
        self.https.iter().map(|(address, _)| *address).collect()
    }
}

fn https_listen(config: &Config) -> Vec<SocketAddr> {
    config
        .https
        .as_ref()
        .map(|https| https.listen.clone())
        .unwrap_or_default()
}

pub struct DnsServer {
    _daemon_lock: std::fs::File,
    started: Instant,
    /// Modification time of the configuration read at startup. Taken before the read, so
    /// an edit racing with startup is seen as a change and reloaded.
    loaded_modified: Option<SystemTime>,
    config_store: ConfigStore,
    listen: Vec<SocketAddr>,
    snapshot: ArcSwap<DnsSnapshot>,
    metrics: Arc<Metrics>,
    forwarder: Forwarder,
    forwards: Arc<Semaphore>,
    tcp_connections: Arc<Semaphore>,
    tcp_clients: Mutex<HashMap<IpAddr, usize>>,
    proxy_listen: Vec<SocketAddr>,
    https_listen: Vec<SocketAddr>,
    /// Present only when an HTTPS trust mode is configured.
    #[cfg(feature = "https")]
    certificates: Option<Arc<crate::tls::manager::CertManager>>,
    /// Present only when the configuration enables the proxy.
    #[cfg(feature = "proxy")]
    proxy: Option<Arc<crate::proxy::Proxy>>,
}

enum Outcome {
    Answer(Vec<u8>),
    Forward(Forward),
    Drop,
}

/// A question to send upstream, the servers that may receive it, and whether private
/// addresses must be removed from the answer.
struct Forward {
    message: Message,
    upstreams: Vec<SocketAddr>,
    rebind_protected: bool,
}

/// Largest UDP response the client accepts (RFC 6891 §6.2.5; 512 without EDNS).
fn udp_limit(message: &Message) -> usize {
    if message.edns.is_some() {
        usize::from(message.max_payload()).clamp(512, MAX_UDP_PACKET)
    } else {
        512
    }
}

impl DnsServer {
    /// Take ownership of the configuration. The latest committed revision on disk wins over
    /// `config`, so a stale caller cannot roll the service back.
    pub fn new(config_store: ConfigStore, mut config: Config) -> Result<Self> {
        let daemon_lock = config_store.acquire_daemon_lock()?;
        let loaded_modified = modified_time(config_store.path());
        if config_store.exists() {
            config = config_store.load()?;
        }
        config.validate()?;
        let snapshot = DnsSnapshot::from_config(&config)?;
        let metrics = Arc::new(Metrics::default());
        #[cfg(feature = "https")]
        let certificates =
            crate::tls::manager::CertManager::new(config_store.path().to_path_buf(), &config);
        Ok(Self {
            _daemon_lock: daemon_lock,
            started: Instant::now(),
            loaded_modified,
            config_store,
            listen: config.listen.clone(),
            snapshot: ArcSwap::from_pointee(snapshot),
            forwarder: Forwarder::new(Arc::clone(&metrics)),
            metrics,
            forwards: Arc::new(Semaphore::new(MAX_FORWARDS)),
            tcp_connections: Arc::new(Semaphore::new(MAX_TCP_CONNECTIONS)),
            tcp_clients: Mutex::new(HashMap::new()),
            proxy_listen: config.proxy_listen.clone(),
            https_listen: https_listen(&config),
            #[cfg(feature = "https")]
            certificates,
            #[cfg(feature = "proxy")]
            proxy: (!config.proxy_listen.is_empty())
                .then(|| Arc::new(crate::proxy::Proxy::new(&config))),
        })
    }

    pub fn metrics(&self) -> MetricsSnapshot {
        self.metrics.snapshot()
    }

    pub(crate) fn store(&self) -> &ConfigStore {
        &self.config_store
    }

    /// Atomically publish a committed configuration to the query path.
    pub(crate) fn install(&self, config: &Config) -> Result<()> {
        if config.listen != self.listen {
            bail!("listener changes require a service restart");
        }
        if config.proxy_listen != self.proxy_listen || https_listen(config) != self.https_listen {
            bail!("proxy listener changes require a service restart");
        }
        #[cfg(feature = "https")]
        if config.https.is_some() != self.certificates.is_some() {
            bail!("enabling or disabling HTTPS requires a service restart");
        }
        let snapshot = DnsSnapshot::from_config(config)?;
        self.forwarder.reset(&config.upstreams);
        #[cfg(feature = "proxy")]
        if let Some(proxy) = &self.proxy {
            proxy.install(config);
        }
        #[cfg(feature = "https")]
        if let Some(certificates) = &self.certificates {
            certificates.install(config);
        }
        self.snapshot.store(Arc::new(snapshot));
        Ok(())
    }

    pub(crate) fn daemon_status(&self) -> crate::control::DaemonStatus {
        crate::control::DaemonStatus {
            pid: std::process::id(),
            version: env!("CARGO_PKG_VERSION").into(),
            revision: self.snapshot.load().revision,
            uptime_seconds: self.started.elapsed().as_secs(),
            cache_entries: self.forwarder.cache_len(),
            metrics: self.metrics.snapshot(),
            #[cfg(feature = "proxy")]
            proxy: self.proxy.as_ref().map(|proxy| proxy.status()),
            #[cfg(not(feature = "proxy"))]
            proxy: None,
            #[cfg(feature = "https")]
            certificates: self.certificates.as_ref().map(|manager| manager.status()),
            #[cfg(not(feature = "https"))]
            certificates: None,
        }
    }

    /// Renew every HTTPS certificate now. Returns false without an HTTPS trust mode.
    #[cfg_attr(not(feature = "https"), allow(clippy::unused_self))]
    pub(crate) fn renew_certificates(&self) -> bool {
        #[cfg(feature = "https")]
        if let Some(certificates) = &self.certificates {
            certificates.renew_now();
            return true;
        }
        false
    }

    pub async fn run(self, shutdown: watch::Receiver<bool>) -> Result<()> {
        let mut listeners = Listeners::bind(&self.listen).await?;
        for address in &self.proxy_listen {
            listeners
                .proxy
                .push((*address, TcpListener::bind(address).await?));
        }
        for address in &self.https_listen {
            listeners
                .https
                .push((*address, TcpListener::bind(address).await?));
        }
        self.run_with(listeners, shutdown).await
    }

    /// Whether the service proxy runs; false in DNS-only mode.
    pub fn proxy_active(&self) -> bool {
        #[cfg(feature = "proxy")]
        return self.proxy.is_some();
        #[cfg(not(feature = "proxy"))]
        false
    }

    pub async fn run_with(
        self,
        listeners: Listeners,
        mut shutdown: watch::Receiver<bool>,
    ) -> Result<()> {
        if listeners.addresses() != self.listen
            || listeners.proxy_addresses() != self.proxy_listen
            || listeners.https_addresses() != self.https_listen
        {
            bail!("bound listeners do not match the configuration");
        }
        let server = Arc::new(self);
        let receivers = std::thread::available_parallelism()
            .map_or(1, std::num::NonZero::get)
            .clamp(1, 4);
        let mut tasks = JoinSet::new();
        for (address, udp, tcp) in listeners.bound {
            info!(%address, "DNS listener ready");
            let udp = Arc::new(udp);
            for _ in 0..receivers {
                tasks.spawn(run_udp(
                    Arc::clone(&server),
                    Arc::clone(&udp),
                    shutdown.clone(),
                ));
            }
            tasks.spawn(run_tcp(Arc::clone(&server), tcp, shutdown.clone()));
        }
        #[cfg(feature = "proxy")]
        if let Some(proxy) = &server.proxy {
            for (address, listener) in listeners.proxy {
                info!(%address, "service proxy ready");
                tasks.spawn(crate::proxy::serve(
                    Arc::clone(proxy),
                    listener,
                    shutdown.clone(),
                ));
            }
            #[cfg(feature = "https")]
            if let Some(certificates) = &server.certificates {
                tasks.spawn(Arc::clone(certificates).maintain(shutdown.clone()));
                for (address, listener) in listeners.https {
                    info!(%address, "HTTPS proxy ready");
                    tasks.spawn(crate::proxy::serve_tls(
                        Arc::clone(proxy),
                        listener,
                        Arc::clone(certificates),
                        shutdown.clone(),
                    ));
                }
            }
        }
        tasks.spawn(run_reload(Arc::clone(&server), shutdown.clone()));
        #[cfg(any(unix, windows))]
        tasks.spawn(crate::control::serve(Arc::clone(&server), shutdown.clone()));

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
        while tasks.join_next().await.is_some() {}
        Ok(())
    }

    /// Classify one request without awaiting. Local answers are produced here so they never
    /// wait behind upstream traffic.
    fn decide(&self, request: &[u8], peer: SocketAddr) -> (Outcome, usize) {
        Metrics::add(&self.metrics.queries);
        let Ok(message) = Message::from_vec(request) else {
            Metrics::add(&self.metrics.dropped);
            return (Outcome::Drop, 512);
        };
        let limit = udp_limit(&message);
        // Never answer responses: two misconfigured servers could otherwise loop forever.
        if message.message_type != MessageType::Query {
            Metrics::add(&self.metrics.dropped);
            return (Outcome::Drop, limit);
        }
        let snapshot = self.snapshot.load();
        let answer = |code| {
            (
                encode_error(&message, code).map_or(Outcome::Drop, Outcome::Answer),
                limit,
            )
        };
        if !snapshot.client_allowed(peer.ip()) {
            Metrics::add(&self.metrics.refused);
            return answer(ResponseCode::Refused);
        }
        if message.op_code != OpCode::Query {
            return answer(ResponseCode::NotImp);
        }
        if message.queries.len() != 1 {
            return answer(ResponseCode::FormErr);
        }
        let query = &message.queries[0];
        if query.query_class() != DNSClass::IN {
            return answer(ResponseCode::Refused);
        }
        let name = query.name().to_ascii().to_ascii_lowercase();
        if snapshot.is_local_name(&name) {
            Metrics::add(&self.metrics.local);
            return (
                local_response(&message, &snapshot).map_or(Outcome::Drop, Outcome::Answer),
                limit,
            );
        }
        let mut rebind_protected = snapshot.rebind_protected(&name);
        let upstreams = match special::classify(&name) {
            Some(Special::Localhost) => {
                Metrics::add(&self.metrics.local);
                return (
                    localhost_response(&message).map_or(Outcome::Drop, Outcome::Answer),
                    limit,
                );
            }
            Some(Special::Invalid) => {
                Metrics::add(&self.metrics.local);
                return (
                    nonexistent_response(&message, "invalid.")
                        .map_or(Outcome::Drop, Outcome::Answer),
                    limit,
                );
            }
            Some(Special::DohCanary) if snapshot.firefox_doh_canary => {
                Metrics::add(&self.metrics.local);
                return (
                    nonexistent_response(&message, special::DOH_CANARY)
                        .map_or(Outcome::Drop, Outcome::Answer),
                    limit,
                );
            }
            Some(Special::LocallyServed(apex)) => {
                // Locally served zones legitimately hold private addresses.
                rebind_protected = false;
                let private = snapshot.private_upstreams();
                if private.is_empty() {
                    Metrics::add(&self.metrics.local);
                    return (
                        nonexistent_response(&message, &apex)
                            .map_or(Outcome::Drop, Outcome::Answer),
                        limit,
                    );
                }
                private
            }
            Some(Special::DohCanary) | None => snapshot.upstreams.clone(),
        };
        if !message.recursion_desired {
            return answer(ResponseCode::Refused);
        }
        if self
            .forwarder
            .is_loop(&message, peer.ip(), &snapshot.upstreams)
        {
            Metrics::add(&self.metrics.loops);
            warn!(%peer, "forwarding loop detected: an upstream forwards this question back");
            return answer(ResponseCode::ServFail);
        }
        (
            Outcome::Forward(Forward {
                message,
                upstreams,
                rebind_protected,
            }),
            limit,
        )
    }

    async fn forward(&self, request: &[u8], forward: &Forward) -> Vec<u8> {
        Metrics::add(&self.metrics.forwarded);
        let snapshot = self.snapshot.load();
        let settings = Upstreams {
            servers: &forward.upstreams,
            timeout: snapshot.upstream_timeout,
            cache_entries: snapshot.cache_entries,
        };
        let message = &forward.message;
        match self.forwarder.resolve(request, message, &settings).await {
            Ok(response) if forward.rebind_protected => match strip_private_answers(&response) {
                Ok(None) => response,
                Ok(Some(stripped)) => {
                    Metrics::add(&self.metrics.rebind_blocked);
                    debug!("removed private addresses from a forwarded answer");
                    stripped
                }
                Err(error) => {
                    Metrics::add(&self.metrics.errors);
                    debug!(%error, "invalid upstream answer");
                    encode_error(message, ResponseCode::ServFail).unwrap_or_default()
                }
            },
            Ok(response) => response,
            Err(error) => {
                Metrics::add(&self.metrics.errors);
                debug!(%error, "upstream resolution failed");
                encode_error(message, ResponseCode::ServFail).unwrap_or_default()
            }
        }
    }

    /// Process one request end to end; used by TCP and by tests.
    pub(crate) async fn handle(
        &self,
        request: &[u8],
        peer: SocketAddr,
    ) -> Option<(Vec<u8>, usize)> {
        match self.decide(request, peer) {
            (Outcome::Answer(bytes), limit) => Some((bytes, limit)),
            (Outcome::Forward(forward), limit) => {
                let _permit = Arc::clone(&self.forwards).try_acquire_owned().ok()?;
                Some((self.forward(request, &forward).await, limit))
            }
            (Outcome::Drop, _) => None,
        }
    }

    fn admit_tcp(&self, peer: IpAddr) -> bool {
        let mut clients = self
            .tcp_clients
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let count = clients.entry(peer).or_default();
        if *count >= MAX_TCP_PER_CLIENT {
            return false;
        }
        *count += 1;
        true
    }

    fn release_tcp(&self, peer: IpAddr) {
        let mut clients = self
            .tcp_clients
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if let Some(count) = clients.get_mut(&peer) {
            *count -= 1;
            if *count == 0 {
                clients.remove(&peer);
            }
        }
    }
}

fn fit_udp(response: Vec<u8>, limit: usize) -> Vec<u8> {
    if response.len() > limit {
        truncate_response(&response).unwrap_or(response)
    } else {
        response
    }
}

async fn run_udp(
    server: Arc<DnsServer>,
    socket: Arc<UdpSocket>,
    mut shutdown: watch::Receiver<bool>,
) -> Result<()> {
    let mut buffer = vec![0_u8; MAX_UDP_PACKET];
    // Forwards run as detached tasks bounded by the semaphore and the upstream timeout.
    // Keeping a JoinSet in this select! starved the loop after tokio's cooperative budget
    // was spent (128 receives), stalling local answers behind slow upstreams.
    loop {
        let (size, peer) = tokio::select! {
            _ = shutdown.changed() => break,
            received = socket.recv_from(&mut buffer) => match received {
                Ok(received) => received,
                // ICMP port-unreachable from an earlier reply surfaces here on some platforms.
                Err(error) if error.kind() == io::ErrorKind::ConnectionReset => continue,
                Err(error) => return Err(error.into()),
            },
        };
        let request = &buffer[..size];
        match server.decide(request, peer) {
            (Outcome::Answer(response), limit) => {
                if let Err(error) = socket.send_to(&fit_udp(response, limit), peer).await {
                    debug!(%error, %peer, "failed to send UDP response");
                }
            }
            (Outcome::Forward(forward), limit) => {
                let Ok(permit) = Arc::clone(&server.forwards).try_acquire_owned() else {
                    Metrics::add(&server.metrics.dropped);
                    continue;
                };
                let request = request.to_vec();
                let server = Arc::clone(&server);
                let socket = Arc::clone(&socket);
                tokio::spawn(async move {
                    let _permit = permit;
                    let response = server.forward(&request, &forward).await;
                    if let Err(error) = socket.send_to(&fit_udp(response, limit), peer).await {
                        debug!(%error, %peer, "failed to send UDP response");
                    }
                });
            }
            (Outcome::Drop, _) => {}
        }
    }
    Ok(())
}

async fn run_tcp(
    server: Arc<DnsServer>,
    listener: TcpListener,
    mut shutdown: watch::Receiver<bool>,
) -> Result<()> {
    let mut tasks = JoinSet::new();
    loop {
        tokio::select! {
            _ = shutdown.changed() => break,
            _ = tasks.join_next(), if !tasks.is_empty() => {},
            accepted = listener.accept() => {
                let Ok((stream, peer)) = accepted else {
                    continue;
                };
                let Ok(permit) = Arc::clone(&server.tcp_connections).try_acquire_owned() else {
                    Metrics::add(&server.metrics.dropped);
                    continue;
                };
                if !server.admit_tcp(peer.ip()) {
                    Metrics::add(&server.metrics.dropped);
                    continue;
                }
                let server = Arc::clone(&server);
                tasks.spawn(async move {
                    let _permit = permit;
                    if let Err(error) = handle_tcp(&server, stream, peer).await {
                        debug!(%error, %peer, "TCP DNS session ended");
                    }
                    server.release_tcp(peer.ip());
                });
            }
        }
    }
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
    Ok(())
}

async fn handle_tcp(server: &DnsServer, mut stream: TcpStream, peer: SocketAddr) -> Result<()> {
    loop {
        let length = match time::timeout(TCP_IDLE, stream.read_u16()).await {
            Ok(Ok(length)) => length as usize,
            Ok(Err(error)) if error.kind() == io::ErrorKind::UnexpectedEof => return Ok(()),
            Ok(Err(error)) => return Err(error.into()),
            Err(_) => return Ok(()),
        };
        if length == 0 || length > MAX_TCP_PACKET {
            bail!("invalid TCP DNS frame length");
        }
        let mut request = vec![0_u8; length];
        time::timeout(Duration::from_secs(5), stream.read_exact(&mut request)).await??;
        let Some((response, _)) = server.handle(&request, peer).await else {
            return Ok(());
        };
        let response_length =
            u16::try_from(response.len()).map_err(|_| anyhow!("DNS response too large"))?;
        time::timeout(Duration::from_secs(5), async {
            stream.write_all(&response_length.to_be_bytes()).await?;
            stream.write_all(&response).await
        })
        .await??;
    }
}

/// Pick up configuration edits made outside the control API. Invalid files are rejected and
/// the previous snapshot keeps serving.
async fn run_reload(server: Arc<DnsServer>, mut shutdown: watch::Receiver<bool>) -> Result<()> {
    let mut modified = server.loaded_modified;
    let mut ticker = time::interval(Duration::from_secs(1));
    loop {
        tokio::select! {
            _ = shutdown.changed() => break,
            _ = ticker.tick() => {
                let current = modified_time(server.config_store.path());
                if current == modified {
                    continue;
                }
                modified = current;
                match server.config_store.load() {
                    Ok(config) if config.revision == server.snapshot.load().revision => {}
                    Ok(config) => match server.install(&config) {
                        Ok(()) => info!(revision = config.revision, "reloaded DNS configuration"),
                        Err(error) => error!(%error, "configuration reload rejected; retaining previous revision"),
                    },
                    Err(error) => error!(%error, "configuration reload rejected; retaining previous revision"),
                }
            }
        }
    }
    Ok(())
}

fn modified_time(path: &std::path::Path) -> Option<SystemTime> {
    std::fs::metadata(path).ok()?.modified().ok()
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use hickory_proto::{
        op::{Edns, Query},
        rr::{Name, RecordType},
    };
    use proptest::prelude::*;

    use super::*;
    use crate::RecordConfig;

    fn server_with(config: Config) -> (tempfile::TempDir, DnsServer) {
        let directory = tempfile::tempdir().unwrap();
        let store = ConfigStore::new(directory.path().join("config.toml"));
        store.initialize(&config).unwrap();
        let server = DnsServer::new(store, config).unwrap();
        (directory, server)
    }

    fn test_server() -> (tempfile::TempDir, DnsServer) {
        let mut config = Config::default();
        config.records.push(RecordConfig {
            name: "nas".into(),
            value: "192.168.1.20".into(),
            ttl: 60,
        });
        config.validate().unwrap();
        server_with(config)
    }

    fn peer() -> SocketAddr {
        "127.0.0.1:40000".parse().unwrap()
    }

    fn query(name: &str, kind: RecordType) -> Message {
        let mut message = Message::query();
        message.metadata.recursion_desired = true;
        message.add_query(Query::query(Name::from_str(name).unwrap(), kind));
        message
    }

    fn answer(server: &DnsServer, message: &Message) -> Option<Message> {
        match server.decide(&message.to_vec().unwrap(), peer()).0 {
            Outcome::Answer(bytes) => Some(Message::from_vec(&bytes).unwrap()),
            Outcome::Forward(..) => panic!("unexpected forward"),
            Outcome::Drop => None,
        }
    }

    #[test]
    fn responses_are_never_answered() {
        let (_dir, server) = test_server();
        let mut message = query("nas.home.arpa.", RecordType::A);
        message.metadata.message_type = MessageType::Response;
        assert!(answer(&server, &message).is_none());
    }

    #[test]
    fn open_resolver_gate_refuses_outside_clients() {
        let (_dir, server) = test_server();
        let message = query("example.com.", RecordType::A);
        for outsider in [
            "8.8.8.8:5000",
            "[2001:db8::1]:5000",
            "[::ffff:8.8.8.8]:5000",
        ] {
            match server
                .decide(&message.to_vec().unwrap(), outsider.parse().unwrap())
                .0
            {
                Outcome::Answer(bytes) => assert_eq!(
                    Message::from_vec(&bytes).unwrap().response_code,
                    ResponseCode::Refused,
                    "{outsider}"
                ),
                _ => panic!("{outsider} was not refused"),
            }
        }
        assert_eq!(server.metrics().refused, 3);
    }

    #[test]
    fn unsupported_opcode_is_notimp() {
        let (_dir, server) = test_server();
        let mut message = query("nas.home.arpa.", RecordType::A);
        message.metadata.op_code = OpCode::Update;
        assert_eq!(
            answer(&server, &message).unwrap().response_code,
            ResponseCode::NotImp
        );
    }

    #[test]
    fn special_use_names_never_reach_public_upstreams() {
        let (_dir, server) = test_server();
        let localhost = answer(&server, &query("app.localhost.", RecordType::A)).unwrap();
        assert_eq!(localhost.answers.len(), 1);
        for name in [
            "1.0.0.10.in-addr.arpa.",
            "printer.local.",
            "x.invalid.",
            "9.9.168.192.in-addr.arpa.",
        ] {
            let response = answer(&server, &query(name, RecordType::PTR)).unwrap();
            assert_eq!(response.response_code, ResponseCode::NXDomain, "{name}");
            assert_eq!(response.authorities.len(), 1, "{name}");
        }
    }

    #[test]
    fn locally_served_zones_use_only_private_upstreams() {
        let mut config = Config {
            upstreams: vec![
                "192.168.1.1:53".parse().unwrap(),
                "1.1.1.1:53".parse().unwrap(),
            ],
            ..Config::default()
        };
        config.validate().unwrap();
        let (_dir, server) = server_with(config);
        let message = query("9.9.168.192.in-addr.arpa.", RecordType::PTR);
        match server.decide(&message.to_vec().unwrap(), peer()).0 {
            Outcome::Forward(forward) => {
                assert_eq!(forward.upstreams, vec!["192.168.1.1:53".parse().unwrap()]);
                assert!(!forward.rebind_protected);
            }
            _ => panic!("expected forward to the private upstream"),
        }
    }

    fn forwarded(server: &DnsServer, name: &str) -> Forward {
        match server
            .decide(&query(name, RecordType::A).to_vec().unwrap(), peer())
            .0
        {
            Outcome::Forward(forward) => forward,
            _ => panic!("expected {name} to be forwarded"),
        }
    }

    #[test]
    fn public_names_are_rebind_protected_except_allowed_domains() {
        let mut config = Config {
            rebind_allowed_domains: vec!["lan".into()],
            ..Config::default()
        };
        config.validate().unwrap();
        let (_dir, server) = server_with(config);
        assert!(forwarded(&server, "example.com.").rebind_protected);
        assert!(!forwarded(&server, "printer.lan.").rebind_protected);
    }

    #[test]
    fn doh_canary_is_answered_locally_unless_disabled() {
        let (_dir, server) = test_server();
        let response = answer(&server, &query(special::DOH_CANARY, RecordType::A)).unwrap();
        assert_eq!(response.response_code, ResponseCode::NXDomain);
        let mut config = Config {
            firefox_doh_canary: false,
            ..Config::default()
        };
        config.validate().unwrap();
        let (_dir, server) = server_with(config);
        assert!(forwarded(&server, special::DOH_CANARY).rebind_protected);
    }

    #[test]
    fn edns_answers_respect_requested_payload() {
        let (_dir, server) = test_server();
        let mut message = query("nas.home.arpa.", RecordType::A);
        let mut edns = Edns::new();
        edns.set_max_payload(1232);
        message.set_edns(edns);
        let (_, limit) = server.decide(&message.to_vec().unwrap(), peer());
        assert_eq!(limit, 1232);
        assert!(answer(&server, &message).unwrap().edns.is_some());
    }

    #[test]
    fn tcp_admission_is_per_client() {
        let (_dir, server) = test_server();
        let client: IpAddr = "192.168.1.9".parse().unwrap();
        for _ in 0..MAX_TCP_PER_CLIENT {
            assert!(server.admit_tcp(client));
        }
        assert!(!server.admit_tcp(client));
        assert!(server.admit_tcp("192.168.1.10".parse().unwrap()));
        server.release_tcp(client);
        assert!(server.admit_tcp(client));
    }

    fn shared_server() -> &'static DnsServer {
        static SERVER: std::sync::OnceLock<(tempfile::TempDir, DnsServer)> =
            std::sync::OnceLock::new();
        &SERVER.get_or_init(test_server).1
    }

    fn arbitrary_query() -> impl Strategy<Value = Vec<u8>> {
        let labels = proptest::collection::vec("[a-z0-9-]{1,12}", 1..4);
        let kinds = prop::sample::select(vec![
            RecordType::A,
            RecordType::AAAA,
            RecordType::CNAME,
            RecordType::PTR,
            RecordType::SOA,
            RecordType::ANY,
            RecordType::TXT,
            RecordType::MX,
        ]);
        let suffixes = prop::sample::select(vec![
            "home.arpa.",
            "in-addr.arpa.",
            "localhost.",
            "invalid.",
            "local.",
            "ip6.arpa.",
        ]);
        (
            labels,
            kinds,
            suffixes,
            any::<bool>(),
            any::<u16>(),
            proptest::collection::vec((any::<usize>(), any::<u8>()), 0..4),
        )
            .prop_map(|(labels, kind, suffix, edns, payload, mutations)| {
                let name = format!("{}.{suffix}", labels.join("."));
                let mut message = Message::query();
                message.metadata.recursion_desired = false;
                if let Ok(name) = Name::from_str(&name) {
                    message.add_query(Query::query(name, kind));
                }
                if edns {
                    let mut options = Edns::new();
                    options.set_max_payload(payload);
                    message.set_edns(options);
                }
                let mut bytes = message.to_vec().unwrap_or_default();
                for (index, value) in mutations {
                    if !bytes.is_empty() {
                        let index = index % bytes.len();
                        bytes[index] = value;
                    }
                }
                bytes
            })
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(2000))]

        /// Structure-aware fuzzing of the full decision path: valid queries with random
        /// names, types, EDNS sizes, and byte mutations must never panic, and every answer
        /// must parse, echo the ID, and set QR.
        #[test]
        fn decision_path_handles_mutated_queries(bytes in arbitrary_query()) {
            let server = shared_server();
            if let (Outcome::Answer(response), limit) = server.decide(&bytes, peer()) {
                let parsed = Message::from_vec(&response).unwrap();
                prop_assert_eq!(parsed.message_type, MessageType::Response);
                prop_assert_eq!(parsed.id, u16::from_be_bytes([bytes[0], bytes[1]]));
                let fitted = Message::from_vec(&fit_udp(response, limit)).unwrap();
                prop_assert_eq!(fitted.id, parsed.id);
            }
        }

        #[test]
        fn arbitrary_bytes_never_panic(bytes in proptest::collection::vec(any::<u8>(), 0..1024)) {
            let server = shared_server();
            let _ = server.decide(&bytes, peer());
        }
    }

    #[test]
    fn startup_uses_latest_revision_and_excludes_offline_writers() {
        let directory = tempfile::tempdir().unwrap();
        let store = ConfigStore::new(directory.path().join("config.toml"));
        store.initialize(&Config::default()).unwrap();
        let stale = store.load().unwrap();
        let request = crate::control::Request::Add {
            record: RecordConfig {
                name: "nas.home.arpa.".into(),
                value: "192.168.1.20".into(),
                ttl: 60,
            },
            expected_revision: Some(0),
        };
        crate::control::apply_offline(&store, request).unwrap();
        let server = DnsServer::new(store.clone(), stale).unwrap();
        assert_eq!(server.snapshot.load().revision, 1);
        let remove = crate::control::Request::Remove {
            name: "nas.home.arpa.".into(),
            value: None,
            expected_revision: Some(1),
        };
        assert!(crate::control::apply_offline(&store, remove).is_err());
        assert_eq!(store.load().unwrap().records.len(), 1);
    }
}
