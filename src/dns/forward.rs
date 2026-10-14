//! Bounded forwarding to upstream resolvers with a TTL-aging response cache.

use std::{
    collections::{HashMap, HashSet, VecDeque},
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::{Arc, Mutex, PoisonError},
    time::{Duration, Instant},
};

use anyhow::{Context, Result, anyhow, bail};
use hickory_proto::{
    op::{Message, MessageType, ResponseCode},
    rr::{RData, RecordType},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpStream, UdpSocket},
    time,
};

use super::{MAX_TCP_PACKET, MAX_UDP_PACKET, Metrics};

#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub(crate) struct CacheKey {
    pub name: String,
    pub record_type: RecordType,
    pub checking_disabled: bool,
    pub dnssec_ok: bool,
}

pub(crate) struct CacheEntry {
    pub bytes: Vec<u8>,
    pub inserted: Instant,
    pub expires: Instant,
}

/// FIFO-evicting cache. Eviction is O(1) amortized, so a full cache never scans.
#[derive(Default)]
pub(crate) struct Cache {
    entries: HashMap<CacheKey, CacheEntry>,
    order: VecDeque<CacheKey>,
}

impl Cache {
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn clear(&mut self) {
        self.entries.clear();
        self.order.clear();
    }

    pub fn insert(&mut self, key: CacheKey, entry: CacheEntry, capacity: usize) {
        if capacity == 0 {
            return;
        }
        if self.entries.insert(key.clone(), entry).is_none() {
            self.order.push_back(key);
        }
        while self.entries.len() > capacity {
            let Some(oldest) = self.order.pop_front() else {
                break;
            };
            self.entries.remove(&oldest);
        }
        // Keys of entries removed on expiry linger in `order`; compact before they dominate.
        if self.order.len() > capacity.saturating_mul(2).max(64) {
            self.order.retain(|key| self.entries.contains_key(key));
        }
    }

    fn get(&mut self, key: &CacheKey, now: Instant) -> Option<&CacheEntry> {
        if self
            .entries
            .get(key)
            .is_some_and(|entry| entry.expires <= now)
        {
            self.entries.remove(key);
            return None;
        }
        self.entries.get(key)
    }
}

/// Questions currently being forwarded. A query for one of them arriving *from* an
/// upstream means the upstream forwards back to us: a forwarding loop.
#[derive(Default)]
struct InFlight(Mutex<HashMap<(String, RecordType), usize>>);

struct InFlightGuard<'a> {
    set: &'a InFlight,
    key: (String, RecordType),
}

impl InFlight {
    fn enter(&self, key: (String, RecordType)) -> InFlightGuard<'_> {
        *self
            .0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .entry(key.clone())
            .or_default() += 1;
        InFlightGuard { set: self, key }
    }

    fn contains(&self, key: &(String, RecordType)) -> bool {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .contains_key(key)
    }
}

impl Drop for InFlightGuard<'_> {
    fn drop(&mut self) {
        let mut map = self.set.0.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(count) = map.get_mut(&self.key) {
            *count -= 1;
            if *count == 0 {
                map.remove(&self.key);
            }
        }
    }
}

pub(crate) struct Forwarder {
    pub cache: Mutex<Cache>,
    in_flight: InFlight,
    metrics: Arc<Metrics>,
}

pub(crate) struct Upstreams<'a> {
    pub servers: &'a [SocketAddr],
    pub timeout: Duration,
    pub cache_entries: usize,
}

impl Forwarder {
    pub fn new(metrics: Arc<Metrics>) -> Self {
        Self {
            cache: Mutex::new(Cache::default()),
            in_flight: InFlight::default(),
            metrics,
        }
    }

    pub fn clear(&self) {
        self.cache_lock().clear();
    }

    pub fn cache_len(&self) -> usize {
        self.cache_lock().len()
    }

    fn cache_lock(&self) -> std::sync::MutexGuard<'_, Cache> {
        self.cache.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// True when `peer` is an upstream asking us a question we are currently forwarding.
    pub fn is_loop(&self, message: &Message, peer: IpAddr, upstreams: &[SocketAddr]) -> bool {
        let Some(query) = message.queries.first() else {
            return false;
        };
        upstreams.iter().any(|upstream| upstream.ip() == peer)
            && self.in_flight.contains(&(
                query.name().to_ascii().to_ascii_lowercase(),
                query.query_type(),
            ))
    }

    pub async fn resolve(
        &self,
        request: &[u8],
        message: &Message,
        upstreams: &Upstreams<'_>,
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
        // Option-bearing and signed queries can produce client-specific answers.
        let cacheable = message.signature.is_none()
            && message
                .edns
                .as_ref()
                .is_none_or(|edns| edns.options().options.is_empty());
        if cacheable {
            let cached = {
                let mut cache = self.cache_lock();
                cache
                    .get(&key, now)
                    .map(|entry| (entry.bytes.clone(), entry.inserted))
            };
            if let Some((bytes, inserted)) = cached {
                self.metrics.cache_hit();
                let mut cached = Message::from_vec(&bytes)?;
                cached.metadata.id = message.id;
                cached.queries.clone_from(&message.queries);
                let elapsed = u32::try_from(inserted.elapsed().as_secs()).unwrap_or(u32::MAX);
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
        }

        let _in_flight = self.in_flight.enter((key.name.clone(), key.record_type));
        let mut last_error = None;
        for upstream in upstreams.servers {
            match query_upstream(request, *upstream, upstreams.timeout).await {
                Ok(bytes) => {
                    let ttl = response_ttl(&bytes).unwrap_or(0).min(86_400);
                    if cacheable && ttl > 0 {
                        let mut stored = bytes.clone();
                        stored[..2].copy_from_slice(&0_u16.to_be_bytes());
                        self.cache_lock().insert(
                            key,
                            CacheEntry {
                                bytes: stored,
                                inserted: Instant::now(),
                                expires: now + Duration::from_secs(u64::from(ttl)),
                            },
                            upstreams.cache_entries,
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

/// Cache lifetime: the smallest record TTL, bounded by the SOA minimum for negative answers.
pub(crate) fn response_ttl(bytes: &[u8]) -> Option<u32> {
    let response = Message::from_vec(bytes).ok()?;
    if !matches!(
        response.response_code,
        ResponseCode::NoError | ResponseCode::NXDomain
    ) || response.truncation
    {
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

pub(crate) async fn query_upstream(
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
    let request_message = Message::from_vec(request)?;
    let mut buffer = vec![0_u8; MAX_UDP_PACKET];
    let deadline = time::Instant::now() + timeout;
    // A connected socket only accepts datagrams from the upstream; still ignore
    // mismatched responses rather than failing, so a stray packet cannot cancel the query.
    loop {
        let size = time::timeout_at(deadline, socket.recv(&mut buffer))
            .await
            .context("upstream UDP timeout")??;
        let Ok(response) = Message::from_vec(&buffer[..size]) else {
            continue;
        };
        if validate_response(&request_message, &response).is_err() {
            continue;
        }
        if response.truncation {
            return query_upstream_tcp(request, upstream, timeout).await;
        }
        buffer.truncate(size);
        return Ok(buffer);
    }
}

pub(crate) async fn query_upstream_tcp(
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

/// Accept only a response to exactly the question we asked.
pub(crate) fn validate_response(request: &Message, response: &Message) -> Result<()> {
    let questions = |message: &Message| -> HashSet<(String, RecordType, u16)> {
        message
            .queries
            .iter()
            .map(|query| {
                (
                    query.name().to_ascii().to_ascii_lowercase(),
                    query.query_type(),
                    u16::from(query.query_class()),
                )
            })
            .collect()
    };
    if response.id != request.id
        || response.message_type != MessageType::Response
        || response.op_code != request.op_code
        || questions(response) != questions(request)
    {
        bail!("upstream response did not match query");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(index: usize) -> CacheKey {
        CacheKey {
            name: format!("host{index}.example."),
            record_type: RecordType::A,
            checking_disabled: false,
            dnssec_ok: false,
        }
    }

    fn entry(seconds: u64) -> CacheEntry {
        CacheEntry {
            bytes: Vec::new(),
            inserted: Instant::now(),
            expires: Instant::now() + Duration::from_secs(seconds),
        }
    }

    #[test]
    fn cache_is_bounded_and_evicts_oldest() {
        let mut cache = Cache::default();
        for index in 0..1_000 {
            cache.insert(key(index), entry(60), 100);
        }
        assert_eq!(cache.len(), 100);
        assert!(cache.get(&key(0), Instant::now()).is_none());
        assert!(cache.get(&key(999), Instant::now()).is_some());
        assert!(cache.order.len() <= 200);
    }

    #[test]
    fn expired_entries_are_not_served() {
        let mut cache = Cache::default();
        cache.insert(key(1), entry(0), 10);
        assert!(cache.get(&key(1), Instant::now()).is_none());
        assert_eq!(cache.len(), 0);
    }

    #[test]
    fn in_flight_tracking_is_released() {
        let set = InFlight::default();
        let question = ("a.example.".to_owned(), RecordType::A);
        {
            let _first = set.enter(question.clone());
            let _second = set.enter(question.clone());
            assert!(set.contains(&question));
        }
        assert!(!set.contains(&question));
    }
}
