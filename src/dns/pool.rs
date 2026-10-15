//! Pre-bound, rotating UDP sockets for upstream queries.
//!
//! Creating a socket per query puts blocking `socket`/`bind`/`connect` syscalls on the async
//! workers; on some hosts each costs milliseconds, which starved the listeners and stalled
//! local answers behind slow upstreams. Instead each upstream gets a few connected sockets,
//! created on the blocking pool, with random 16-bit query IDs multiplexed over them. Sockets
//! are replaced periodically so source ports keep changing, which preserves resistance to
//! off-path spoofing (connected sockets also discard datagrams from other sources).

use std::{
    collections::HashMap,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::{
        Arc, Mutex, PoisonError,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

use anyhow::{Context, Result, anyhow};
use tokio::{net::UdpSocket, sync::oneshot, time};

use super::MAX_UDP_PACKET;

const SOCKETS_PER_UPSTREAM: usize = 4;
const ROTATE_AFTER: Duration = Duration::from_secs(60);

type Pending = Mutex<HashMap<u16, oneshot::Sender<Vec<u8>>>>;

struct PooledSocket {
    socket: UdpSocket,
    pending: Pending,
    created: Instant,
    retired: AtomicBool,
}

impl PooledSocket {
    fn pending(&self) -> std::sync::MutexGuard<'_, HashMap<u16, oneshot::Sender<Vec<u8>>>> {
        self.pending.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Route responses to waiting queries by ID until retired and drained.
    async fn read(self: Arc<Self>) {
        let mut buffer = vec![0_u8; MAX_UDP_PACKET];
        loop {
            let received = tokio::select! {
                received = self.socket.recv(&mut buffer) => received,
                () = time::sleep(Duration::from_secs(1)) => {
                    if self.retired.load(Ordering::Relaxed) && self.pending().is_empty() {
                        return;
                    }
                    continue;
                }
            };
            let Ok(size) = received else {
                // Connection-refused errors (ICMP) are expected while an upstream is down.
                continue;
            };
            if size < 2 {
                continue;
            }
            let id = u16::from_be_bytes([buffer[0], buffer[1]]);
            if let Some(waiter) = self.pending().remove(&id) {
                let _ = waiter.send(buffer[..size].to_vec());
            }
        }
    }
}

struct Slots {
    sockets: Vec<Mutex<Arc<PooledSocket>>>,
    replacing: Vec<AtomicBool>,
    next: AtomicUsize,
}

#[derive(Default)]
pub(crate) struct UpstreamPool {
    upstreams: Mutex<HashMap<SocketAddr, Arc<tokio::sync::OnceCell<Slots>>>>,
}

async fn open(upstream: SocketAddr) -> Result<Arc<PooledSocket>> {
    let socket = tokio::task::spawn_blocking(move || -> std::io::Result<std::net::UdpSocket> {
        let bind = match upstream {
            SocketAddr::V4(_) => SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)),
            SocketAddr::V6(_) => SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0)),
        };
        let socket = std::net::UdpSocket::bind(bind)?;
        socket.connect(upstream)?;
        socket.set_nonblocking(true)?;
        Ok(socket)
    })
    .await??;
    let pooled = Arc::new(PooledSocket {
        socket: UdpSocket::from_std(socket)?,
        pending: Mutex::new(HashMap::new()),
        created: Instant::now(),
        retired: AtomicBool::new(false),
    });
    tokio::spawn(Arc::clone(&pooled).read());
    Ok(pooled)
}

fn random_id() -> u16 {
    let mut bytes = [0_u8; 2];
    // The OS generator does not fail on supported platforms; a fixed fallback would only
    // weaken spoofing resistance, so fall back to the clock rather than abort the query.
    if getrandom::fill(&mut bytes).is_err() {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .subsec_nanos()
            .to_le_bytes();
        bytes = [nanos[0], nanos[1]];
    }
    u16::from_be_bytes(bytes)
}

impl UpstreamPool {
    async fn slots(&self, upstream: SocketAddr) -> Result<Arc<tokio::sync::OnceCell<Slots>>> {
        let cell = Arc::clone(
            self.upstreams
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .entry(upstream)
                .or_default(),
        );
        cell.get_or_try_init(|| async {
            let mut sockets = Vec::with_capacity(SOCKETS_PER_UPSTREAM);
            for _ in 0..SOCKETS_PER_UPSTREAM {
                sockets.push(Mutex::new(open(upstream).await?));
            }
            Ok::<_, anyhow::Error>(Slots {
                replacing: (0..SOCKETS_PER_UPSTREAM)
                    .map(|_| AtomicBool::new(false))
                    .collect(),
                sockets,
                next: AtomicUsize::new(0),
            })
        })
        .await?;
        Ok(cell)
    }

    /// Pick a socket, starting a background replacement when it is due for rotation.
    async fn socket(&self, upstream: SocketAddr) -> Result<Arc<PooledSocket>> {
        let cell = self.slots(upstream).await?;
        let slots = cell
            .get()
            .ok_or_else(|| anyhow!("upstream pool is not ready"))?;
        let index = slots.next.fetch_add(1, Ordering::Relaxed) % slots.sockets.len();
        let socket = Arc::clone(
            &slots.sockets[index]
                .lock()
                .unwrap_or_else(PoisonError::into_inner),
        );
        if socket.created.elapsed() > ROTATE_AFTER
            && !slots.replacing[index].swap(true, Ordering::AcqRel)
        {
            let cell = Arc::clone(&cell);
            tokio::spawn(async move {
                let Some(slots) = cell.get() else { return };
                if let Ok(fresh) = open(upstream).await {
                    let old = std::mem::replace(
                        &mut *slots.sockets[index]
                            .lock()
                            .unwrap_or_else(PoisonError::into_inner),
                        fresh,
                    );
                    old.retired.store(true, Ordering::Relaxed);
                }
                slots.replacing[index].store(false, Ordering::Release);
            });
        }
        Ok(socket)
    }

    /// Send `request` to `upstream` and return the response datagram, with the client's
    /// original ID restored. The caller validates the response against the question.
    pub async fn query(
        &self,
        request: &[u8],
        upstream: SocketAddr,
        timeout: Duration,
    ) -> Result<Vec<u8>> {
        if request.len() < 12 {
            return Err(anyhow!("DNS request is too short"));
        }
        let socket = self.socket(upstream).await?;
        let (sender, receiver) = oneshot::channel();
        let id = {
            let mut pending = socket.pending();
            let mut id = random_id();
            while pending.contains_key(&id) {
                id = random_id();
            }
            pending.insert(id, sender);
            id
        };
        let mut outbound = request.to_vec();
        outbound[..2].copy_from_slice(&id.to_be_bytes());
        let result = async {
            socket.socket.send(&outbound).await?;
            time::timeout(timeout, receiver)
                .await
                .context("upstream UDP timeout")?
                .map_err(|_| anyhow!("upstream socket closed"))
        }
        .await;
        socket.pending().remove(&id);
        let mut response = result?;
        response[..2].copy_from_slice(&request[..2]);
        Ok(response)
    }

    /// Retire sockets for upstreams that are no longer configured.
    pub fn retain(&self, upstreams: &[SocketAddr]) {
        self.upstreams
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .retain(|upstream, cell| {
                let keep = upstreams.contains(upstream);
                if !keep && let Some(slots) = cell.get() {
                    for slot in &slots.sockets {
                        slot.lock()
                            .unwrap_or_else(PoisonError::into_inner)
                            .retired
                            .store(true, Ordering::Relaxed);
                    }
                }
                keep
            });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn multiplexes_queries_and_restores_client_ids() {
        let upstream = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address = upstream.local_addr().unwrap();
        // Echo server that answers in reverse order of arrival.
        tokio::spawn(async move {
            let mut received = Vec::new();
            let mut buffer = [0_u8; 512];
            while received.len() < 3 {
                let (size, peer) = upstream.recv_from(&mut buffer).await.unwrap();
                received.push((buffer[..size].to_vec(), peer));
            }
            for (bytes, peer) in received.into_iter().rev() {
                upstream.send_to(&bytes, peer).await.unwrap();
            }
        });
        let pool = Arc::new(UpstreamPool::default());
        let mut queries = Vec::new();
        for client_id in [7_u16, 8, 9] {
            let pool = Arc::clone(&pool);
            queries.push(tokio::spawn(async move {
                let mut request = vec![0_u8; 12];
                request[..2].copy_from_slice(&client_id.to_be_bytes());
                request[11] = u8::try_from(client_id).unwrap();
                let response = pool
                    .query(&request, address, Duration::from_secs(2))
                    .await
                    .unwrap();
                assert_eq!(response, request);
            }));
        }
        for query in queries {
            query.await.unwrap();
        }
    }

    #[tokio::test]
    async fn silent_upstream_times_out_and_releases_the_id() {
        let silent = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let pool = UpstreamPool::default();
        let error = pool
            .query(
                &[0; 12],
                silent.local_addr().unwrap(),
                Duration::from_millis(100),
            )
            .await
            .unwrap_err();
        assert!(format!("{error:#}").contains("timeout"));
        let cell = pool.slots(silent.local_addr().unwrap()).await.unwrap();
        for slot in &cell.get().unwrap().sockets {
            assert!(slot.lock().unwrap().pending().is_empty());
        }
    }
}
