//! Optional HTTP/1.1 and WebSocket service proxy (decision 10). It exists only when
//! `proxy_listen` is configured; in DNS-only mode no listener, task, or HTTP state is
//! created. Requests are routed by `Host` to the service's backend.
//!
//! Backend failure behavior:
//! - unknown `Host`: 404; missing `Host`: 400; client outside `allowed_clients`: 403
//! - backend refuses or resets the connection: 502 Bad Gateway
//! - backend does not accept the connection within 5 s, or send response headers within
//!   60 s: 504 Gateway Timeout
//! - backend fails mid-response: the client connection is closed (truncated response)
//! - WebSocket: the backend's handshake response is passed through; after 101 both
//!   directions are copied until either side closes.

use std::{
    collections::HashMap,
    convert::Infallible,
    net::{IpAddr, SocketAddr},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use anyhow::Result;
use arc_swap::ArcSwap;
use http_body_util::{BodyExt, Full, combinators::BoxBody};
use hyper::{
    Request, Response, StatusCode,
    body::{Bytes, Incoming},
    header::{self, HeaderMap, HeaderName, HeaderValue},
    server::conn::http1,
    service::service_fn,
};
use hyper_util::rt::{TokioIo, TokioTimer};
use serde::{Deserialize, Serialize};
use tokio::{
    net::{TcpListener, TcpStream},
    sync::{Semaphore, watch},
    task::JoinSet,
    time,
};
use tracing::debug;

use crate::config::Config;

const MAX_CONNECTIONS: usize = 512;
const HEADER_TIMEOUT: Duration = Duration::from_secs(10);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const RESPONSE_TIMEOUT: Duration = Duration::from_secs(60);
const MAX_HEADER_BYTES: usize = 64 * 1024;

type Body = BoxBody<Bytes, hyper::Error>;

struct Route {
    target: SocketAddr,
    https: bool,
}

struct Routes {
    services: HashMap<String, Route>,
    allowed_clients: Vec<ipnet::IpNet>,
    /// Port of the first HTTPS listener, used to redirect HTTPS services.
    https_port: Option<u16>,
}

impl Routes {
    fn from_config(config: &Config) -> Self {
        Self {
            services: config
                .services
                .iter()
                .map(|service| {
                    (
                        service.name.clone(),
                        Route {
                            target: service.target,
                            https: service.https,
                        },
                    )
                })
                .collect(),
            allowed_clients: config.allowed_clients.clone(),
            https_port: config
                .https
                .as_ref()
                .and_then(|https| https.listen.first())
                .map(SocketAddr::port),
        }
    }
}

#[derive(Default)]
struct Metrics {
    requests: AtomicU64,
    upgrades: AtomicU64,
    not_found: AtomicU64,
    refused: AtomicU64,
    backend_errors: AtomicU64,
}

/// Aggregate proxy counters; no request history is retained (decision 11).
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ProxyStatus {
    pub listen: Vec<SocketAddr>,
    pub services: usize,
    pub requests: u64,
    pub upgrades: u64,
    pub not_found: u64,
    pub refused: u64,
    pub backend_errors: u64,
}

pub struct Proxy {
    listen: Vec<SocketAddr>,
    routes: ArcSwap<Routes>,
    metrics: Metrics,
    connections: Arc<Semaphore>,
}

impl Proxy {
    pub fn new(config: &Config) -> Self {
        Self {
            listen: config.proxy_listen.clone(),
            routes: ArcSwap::from_pointee(Routes::from_config(config)),
            metrics: Metrics::default(),
            connections: Arc::new(Semaphore::new(MAX_CONNECTIONS)),
        }
    }

    pub fn listen(&self) -> &[SocketAddr] {
        &self.listen
    }

    /// Publish a committed configuration's services.
    pub fn install(&self, config: &Config) {
        self.routes.store(Arc::new(Routes::from_config(config)));
    }

    pub fn status(&self) -> ProxyStatus {
        let load = |counter: &AtomicU64| counter.load(Ordering::Relaxed);
        ProxyStatus {
            listen: self.listen.clone(),
            services: self.routes.load().services.len(),
            requests: load(&self.metrics.requests),
            upgrades: load(&self.metrics.upgrades),
            not_found: load(&self.metrics.not_found),
            refused: load(&self.metrics.refused),
            backend_errors: load(&self.metrics.backend_errors),
        }
    }
}

fn add(counter: &AtomicU64) {
    counter.fetch_add(1, Ordering::Relaxed);
}

pub async fn serve(
    proxy: Arc<Proxy>,
    listener: TcpListener,
    shutdown: watch::Receiver<bool>,
) -> Result<()> {
    serve_with(proxy, listener, None, shutdown).await
}

/// Serve HTTPS on `listener`, choosing certificates by SNI.
#[cfg(feature = "https")]
pub async fn serve_tls(
    proxy: Arc<Proxy>,
    listener: TcpListener,
    certificates: Arc<crate::tls::manager::CertManager>,
    shutdown: watch::Receiver<bool>,
) -> Result<()> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut config = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()?
        .with_no_client_auth()
        .with_cert_resolver(certificates);
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
    serve_with(proxy, listener, Some(acceptor), shutdown).await
}

#[cfg(not(feature = "https"))]
type Acceptor = std::convert::Infallible;
#[cfg(feature = "https")]
type Acceptor = tokio_rustls::TlsAcceptor;

#[cfg(feature = "https")]
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

async fn serve_with(
    proxy: Arc<Proxy>,
    listener: TcpListener,
    acceptor: Option<Acceptor>,
    mut shutdown: watch::Receiver<bool>,
) -> Result<()> {
    let mut connections = JoinSet::new();
    loop {
        tokio::select! {
            _ = shutdown.changed() => break,
            _ = connections.join_next(), if !connections.is_empty() => {},
            accepted = listener.accept() => {
                let Ok((stream, peer)) = accepted else { continue };
                let Ok(permit) = Arc::clone(&proxy.connections).try_acquire_owned() else {
                    add(&proxy.metrics.refused);
                    continue;
                };
                let proxy = Arc::clone(&proxy);
                #[cfg_attr(not(feature = "https"), allow(clippy::clone_on_copy))]
                let acceptor = acceptor.clone();
                connections.spawn(async move {
                    let _permit = permit;
                    match acceptor {
                        None => serve_connection(proxy, peer, stream, false).await,
                        #[cfg(feature = "https")]
                        Some(acceptor) => match time::timeout(HANDSHAKE_TIMEOUT, acceptor.accept(stream)).await {
                            Ok(Ok(stream)) => serve_connection(proxy, peer, stream, true).await,
                            Ok(Err(error)) => debug!(%error, %peer, "TLS handshake failed"),
                            Err(_) => debug!(%peer, "TLS handshake timed out"),
                        },
                        #[cfg(not(feature = "https"))]
                        Some(never) => match never {},
                    }
                });
            }
        }
    }
    connections.abort_all();
    while connections.join_next().await.is_some() {}
    Ok(())
}

async fn serve_connection<S>(proxy: Arc<Proxy>, peer: SocketAddr, stream: S, secure: bool)
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let service = service_fn(move |request| handle(Arc::clone(&proxy), peer, request, secure));
    let connection = http1::Builder::new()
        .timer(TokioTimer::new())
        .header_read_timeout(HEADER_TIMEOUT)
        .max_buf_size(MAX_HEADER_BYTES)
        .serve_connection(TokioIo::new(stream), service)
        .with_upgrades();
    if let Err(error) = connection.await {
        debug!(%error, %peer, "proxy connection ended");
    }
}

fn text(status: StatusCode, message: String) -> Response<Body> {
    let mut response = Response::new(
        Full::new(Bytes::from(message + "\n"))
            .map_err(|never| match never {})
            .boxed(),
    );
    *response.status_mut() = status;
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    response
}

/// The requested service: `Host` without port, lowercase, as an absolute name.
fn requested_host(headers: &HeaderMap, uri: &hyper::Uri) -> Option<String> {
    let host = headers
        .get(header::HOST)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned)
        .or_else(|| uri.host().map(str::to_owned))?;
    let host = if host.starts_with('[') {
        host.split_once(']').map(|(name, _)| format!("{name}]"))?
    } else {
        host.rsplit_once(':')
            .filter(|(_, port)| port.bytes().all(|byte| byte.is_ascii_digit()))
            .map_or(host.as_str(), |(name, _)| name)
            .to_owned()
    };
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    (!host.is_empty()).then(|| format!("{host}."))
}

fn canonical_peer(address: IpAddr) -> IpAddr {
    match address {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(address, IpAddr::V4),
        IpAddr::V4(_) => address,
    }
}

async fn handle(
    proxy: Arc<Proxy>,
    peer: SocketAddr,
    request: Request<Incoming>,
    secure: bool,
) -> Result<Response<Body>, Infallible> {
    add(&proxy.metrics.requests);
    let routes = proxy.routes.load();
    let client = canonical_peer(peer.ip());
    if !routes
        .allowed_clients
        .iter()
        .any(|network| network.contains(&client))
    {
        add(&proxy.metrics.refused);
        return Ok(text(
            StatusCode::FORBIDDEN,
            "localname: this client is not allowed to use the proxy".into(),
        ));
    }
    let Some(host) = requested_host(request.headers(), request.uri()) else {
        return Ok(text(
            StatusCode::BAD_REQUEST,
            "localname: the request has no Host header".into(),
        ));
    };
    let Some(route) = routes.services.get(&host) else {
        add(&proxy.metrics.not_found);
        return Ok(text(
            StatusCode::NOT_FOUND,
            format!(
                "localname: no service is named {}",
                host.trim_end_matches('.')
            ),
        ));
    };
    let target = route.target;
    let name = host.trim_end_matches('.').to_owned();
    // HTTPS services are reached over HTTP only to be redirected.
    if route.https && !secure {
        let port = routes
            .https_port
            .filter(|port| *port != 443)
            .map_or_else(String::new, |port| format!(":{port}"));
        let path = request
            .uri()
            .path_and_query()
            .map_or("/", |path| path.as_str());
        let mut response = text(
            StatusCode::PERMANENT_REDIRECT,
            format!("localname: {name} is served over HTTPS"),
        );
        if let Ok(location) = HeaderValue::from_str(&format!("https://{name}{port}{path}")) {
            response.headers_mut().insert(header::LOCATION, location);
        }
        return Ok(response);
    }
    drop(routes);
    Ok(
        match forward(&proxy, peer, &name, target, request, secure).await {
            Ok(response) => response,
            Err(failure) => {
                add(&proxy.metrics.backend_errors);
                debug!(service = %name, %target, error = %failure.detail, "backend failed");
                text(
                    failure.status,
                    format!(
                        "localname: backend for {name} ({target}) {}",
                        failure.detail
                    ),
                )
            }
        },
    )
}

struct Failure {
    status: StatusCode,
    detail: String,
}

impl Failure {
    fn bad_gateway(detail: impl Into<String>) -> Self {
        Self {
            status: StatusCode::BAD_GATEWAY,
            detail: detail.into(),
        }
    }

    fn timeout(detail: impl Into<String>) -> Self {
        Self {
            status: StatusCode::GATEWAY_TIMEOUT,
            detail: detail.into(),
        }
    }
}

fn is_upgrade(headers: &HeaderMap) -> bool {
    headers.contains_key(header::UPGRADE)
        && headers
            .get_all(header::CONNECTION)
            .iter()
            .filter_map(|value| value.to_str().ok())
            .flat_map(|value| value.split(','))
            .any(|token| token.trim().eq_ignore_ascii_case("upgrade"))
}

/// Remove hop-by-hop headers (RFC 9110 §7.6.1), including any the `Connection` header
/// names. An upgrade keeps `Upgrade` and `Connection: upgrade`.
fn strip_hop_by_hop(headers: &mut HeaderMap, upgrade: bool) {
    let named: Vec<HeaderName> = headers
        .get_all(header::CONNECTION)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .filter_map(|token| HeaderName::from_bytes(token.trim().as_bytes()).ok())
        .collect();
    for name in named {
        if !(upgrade && name == header::UPGRADE) {
            headers.remove(&name);
        }
    }
    for name in [
        header::CONNECTION,
        header::TE,
        header::TRAILER,
        header::TRANSFER_ENCODING,
        header::PROXY_AUTHENTICATE,
        header::PROXY_AUTHORIZATION,
    ] {
        headers.remove(name);
    }
    headers.remove("keep-alive");
    headers.remove("proxy-connection");
    if upgrade {
        headers.insert(header::CONNECTION, HeaderValue::from_static("upgrade"));
    } else {
        headers.remove(header::UPGRADE);
    }
}

async fn forward(
    proxy: &Proxy,
    peer: SocketAddr,
    name: &str,
    target: SocketAddr,
    mut request: Request<Incoming>,
    secure: bool,
) -> Result<Response<Body>, Failure> {
    let upgrade = is_upgrade(request.headers());
    let client_upgrade = upgrade.then(|| hyper::upgrade::on(&mut request));
    let stream = match time::timeout(CONNECT_TIMEOUT, TcpStream::connect(target)).await {
        Ok(Ok(stream)) => stream,
        Ok(Err(error)) => return Err(Failure::bad_gateway(format!("is unreachable: {error}"))),
        Err(_) => return Err(Failure::timeout("did not accept a connection within 5 s")),
    };
    let _ = stream.set_nodelay(true);
    let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
        .await
        .map_err(|error| Failure::bad_gateway(format!("failed the HTTP handshake: {error}")))?;
    tokio::spawn(async move {
        if let Err(error) = connection.with_upgrades().await {
            debug!(%error, "backend connection ended");
        }
    });

    // Origin-form target; Host is kept so backends see the name the user typed.
    let path = request
        .uri()
        .path_and_query()
        .map_or("/", |path| path.as_str())
        .to_owned();
    *request.uri_mut() = path
        .parse()
        .map_err(|_| Failure::bad_gateway("rejected an invalid request path"))?;
    let headers = request.headers_mut();
    strip_hop_by_hop(headers, upgrade);
    let client = canonical_peer(peer.ip()).to_string();
    let forwarded_for = match headers
        .get("x-forwarded-for")
        .and_then(|value| value.to_str().ok())
    {
        Some(previous) => format!("{previous}, {client}"),
        None => client,
    };
    if let Ok(value) = HeaderValue::from_str(&forwarded_for) {
        headers.insert("x-forwarded-for", value);
    }
    if let Ok(value) = HeaderValue::from_str(name) {
        headers.insert("x-forwarded-host", value);
    }
    headers.insert(
        "x-forwarded-proto",
        HeaderValue::from_static(if secure { "https" } else { "http" }),
    );

    let mut response = match time::timeout(RESPONSE_TIMEOUT, sender.send_request(request)).await {
        Ok(Ok(response)) => response,
        Ok(Err(error)) => {
            return Err(Failure::bad_gateway(format!(
                "closed the connection: {error}"
            )));
        }
        Err(_) => return Err(Failure::timeout("sent no response within 60 s")),
    };

    if let Some(client_upgrade) = client_upgrade
        && response.status() == StatusCode::SWITCHING_PROTOCOLS
    {
        add(&proxy.metrics.upgrades);
        let backend_upgrade = hyper::upgrade::on(&mut response);
        tokio::spawn(async move {
            match tokio::try_join!(client_upgrade, backend_upgrade) {
                Ok((client, backend)) => {
                    let mut client = TokioIo::new(client);
                    let mut backend = TokioIo::new(backend);
                    if let Err(error) =
                        tokio::io::copy_bidirectional(&mut client, &mut backend).await
                    {
                        debug!(%error, "upgraded connection ended");
                    }
                }
                Err(error) => debug!(%error, "upgrade failed"),
            }
        });
        let (mut parts, _) = response.into_parts();
        strip_hop_by_hop(&mut parts.headers, true);
        return Ok(Response::from_parts(
            parts,
            Full::new(Bytes::new())
                .map_err(|never| match never {})
                .boxed(),
        ));
    }
    let (mut parts, body) = response.into_parts();
    strip_hop_by_hop(&mut parts.headers, false);
    Ok(Response::from_parts(parts, body.boxed()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hop_by_hop_headers_are_removed() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::CONNECTION,
            HeaderValue::from_static("keep-alive, x-secret"),
        );
        headers.insert("x-secret", HeaderValue::from_static("1"));
        headers.insert("keep-alive", HeaderValue::from_static("timeout=5"));
        headers.insert(header::UPGRADE, HeaderValue::from_static("websocket"));
        headers.insert(header::ACCEPT, HeaderValue::from_static("*/*"));
        let mut upgraded = headers.clone();
        strip_hop_by_hop(&mut headers, false);
        assert_eq!(headers.len(), 1);
        assert!(headers.contains_key(header::ACCEPT));
        strip_hop_by_hop(&mut upgraded, true);
        assert_eq!(upgraded[header::CONNECTION], "upgrade");
        assert_eq!(upgraded[header::UPGRADE], "websocket");
        assert!(!upgraded.contains_key("x-secret"));
    }

    #[test]
    fn hosts_are_normalized() {
        let host = |value: &str| {
            let mut headers = HeaderMap::new();
            headers.insert(header::HOST, HeaderValue::from_str(value).unwrap());
            requested_host(&headers, &"/".parse().unwrap())
        };
        assert_eq!(
            host("Photos.Home.Arpa:8080").as_deref(),
            Some("photos.home.arpa.")
        );
        assert_eq!(
            host("photos.home.arpa.").as_deref(),
            Some("photos.home.arpa.")
        );
        assert_eq!(host("[fd00::1]:80").as_deref(), Some("[fd00::1]."));
        assert_eq!(
            requested_host(
                &HeaderMap::new(),
                &"http://nas.home.arpa/x".parse().unwrap()
            )
            .as_deref(),
            Some("nas.home.arpa.")
        );
        assert_eq!(
            requested_host(&HeaderMap::new(), &"/".parse().unwrap()),
            None
        );
    }

    #[test]
    fn upgrades_need_both_headers() {
        let mut headers = HeaderMap::new();
        headers.insert(header::UPGRADE, HeaderValue::from_static("websocket"));
        assert!(!is_upgrade(&headers));
        headers.insert(
            header::CONNECTION,
            HeaderValue::from_static("keep-alive, Upgrade"),
        );
        assert!(is_upgrade(&headers));
    }
}
