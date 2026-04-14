use crate::auth::engine::{AuthEngine, AuthResult};
use crate::cache::entry::CacheKey;
use crate::cache::CacheStore;
use crate::protocol::message::Message;
use crate::resolver::Resolver;
use crate::rpz::RpzEngine;
use crate::security::acl::RecursionAcl;
use crate::security::rate_limit::RateLimiter;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;
use parking_lot::Mutex;
use tokio::net::UdpSocket;
use tokio::sync::Semaphore;

const MAX_UDP_RECV: usize = 4096;
const MAX_UDP_INFLIGHT: usize = 4096;

/// Simple DNS Response Rate Limiting (RRL).
/// Throttles identical responses to the same source prefix.
struct ResponseRateLimiter {
    /// (source /24 prefix, qname hash, rcode) -> (count, window_start)
    state: Mutex<HashMap<(u32, u64, u8), (u32, Instant)>>,
    /// Max identical responses per second per /24
    limit: u32,
}

impl ResponseRateLimiter {
    fn new(limit: u32) -> Self {
        Self {
            state: Mutex::new(HashMap::new()),
            limit,
        }
    }

    /// Check if this response should be sent. Returns false if rate-limited.
    fn check(&self, src: &std::net::SocketAddr, qname_hash: u64, rcode: u8) -> bool {
        if self.limit == 0 {
            return true;
        }
        let prefix = match src.ip() {
            std::net::IpAddr::V4(v4) => {
                let o = v4.octets();
                u32::from_be_bytes([o[0], o[1], o[2], 0])
            }
            std::net::IpAddr::V6(v6) => {
                let o = v6.octets();
                u32::from_be_bytes([o[0], o[1], o[2], o[3]])
            }
        };
        let key = (prefix, qname_hash, rcode);
        let now = Instant::now();
        let mut state = self.state.lock();
        // Cap entries to prevent memory exhaustion
        const MAX_RRL_ENTRIES: usize = 100_000;
        if state.len() >= MAX_RRL_ENTRIES && !state.contains_key(&key) {
            return false;
        }
        let entry = state.entry(key).or_insert((0, now));
        if now.duration_since(entry.1).as_secs() >= 1 {
            entry.0 = 1;
            entry.1 = now;
            return true;
        }
        entry.0 += 1;
        entry.0 <= self.limit
    }

    fn evict_stale(&self) {
        let cutoff = Instant::now() - std::time::Duration::from_secs(10);
        let mut state = self.state.lock();
        state.retain(|_, (_, ts)| *ts > cutoff);
    }
}

/// Shared context for all UDP query handlers.
struct QueryContext {
    cache: CacheStore,
    resolver: Option<Resolver>,
    auth: Option<AuthEngine>,
    rpz: RpzEngine,
    rate_limiter: RateLimiter,
    acl: RecursionAcl,
    inflight: Arc<Semaphore>,
    rrl: ResponseRateLimiter,
}

pub async fn serve(
    addr: SocketAddr,
    cache: CacheStore,
    resolver: Option<Resolver>,
    auth: Option<AuthEngine>,
    rpz: RpzEngine,
    rate_limiter: RateLimiter,
    acl: RecursionAcl,
) -> anyhow::Result<()> {
    let ctx = Arc::new(QueryContext {
        cache,
        resolver,
        auth,
        rpz,
        rate_limiter,
        acl,
        inflight: Arc::new(Semaphore::new(MAX_UDP_INFLIGHT)),
        rrl: ResponseRateLimiter::new(10), // 10 identical responses per /24 per second
    });

    let num_workers = (num_cpus() / 2).clamp(2, 16);

    // Try SO_REUSEPORT: each worker gets its own socket, kernel distributes
    // packets, zero contention. Use standard tokio recv_from (not recvmmsg).
    let mut sockets = Vec::with_capacity(num_workers);
    let mut reuseport = true;

    for _ in 0..num_workers {
        match bind_reuseport(addr) {
            Ok(s) => sockets.push(s),
            Err(_) => {
                reuseport = false;
                break;
            }
        }
    }

    let mut handles = Vec::with_capacity(num_workers);

    if reuseport && sockets.len() == num_workers {
        tracing::info!(%addr, workers = num_workers, "UDP listeners bound (SO_REUSEPORT)");
        for socket in sockets {
            let ctx = ctx.clone();
            handles.push(tokio::spawn(recv_loop(Arc::new(socket), ctx)));
        }
    } else {
        // Fallback: shared socket with multiple recv tasks
        drop(sockets);
        let socket = Arc::new(UdpSocket::bind(addr).await?);
        tracing::info!(%addr, workers = num_workers, "UDP listener bound (shared)");
        for _ in 0..num_workers {
            let socket = socket.clone();
            let ctx = ctx.clone();
            handles.push(tokio::spawn(recv_loop(socket, ctx)));
        }
    }

    // Spawn RRL cleanup task
    let rrl_ref = ctx.clone();
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(std::time::Duration::from_secs(10));
        loop {
            ticker.tick().await;
            rrl_ref.rrl.evict_stale();
        }
    });

    for h in handles {
        h.await.ok();
    }
    Ok(())
}

/// Main receive loop — cache hits handled inline, misses spawn a task.
async fn recv_loop(socket: Arc<UdpSocket>, ctx: Arc<QueryContext>) {
    let mut buf = [0u8; MAX_UDP_RECV];

    loop {
        let (len, src) = match socket.recv_from(&mut buf).await {
            Ok(v) => v,
            Err(e) => {
                tracing::debug!(error = %e, "UDP recv_from error");
                tokio::time::sleep(std::time::Duration::from_millis(1)).await;
                continue;
            }
        };

        // Rate limit check — drop packet silently if over limit
        if !ctx.rate_limiter.check(src.ip()) {
            continue;
        }

        let recursion_allowed = ctx.acl.is_allowed(src.ip());

        // Sync fast path: cache hit, auth, RPZ — no task spawn
        if let Some(mut response) = try_handle_sync(&buf[..len], &ctx, recursion_allowed) {
            if !response.is_empty() {
                super::truncate_udp_response(&mut response);
                // RRL check before sending
                let qname_hash = qname_hash_from_buf(&buf[..len]);
                let rcode = if response.len() >= 4 { response[3] & 0x0F } else { 0 };
                if ctx.rrl.check(&src, qname_hash, rcode) {
                    let _ = socket.send_to(&response, src).await;
                }
            }
            // Empty response = RPZ Drop — silently discard
            continue;
        }

        // Cache miss — spawn async task for resolution
        let permit = match ctx.inflight.clone().try_acquire_owned() {
            Ok(p) => p,
            Err(_) => continue, // At capacity, drop query
        };

        let query_data = buf[..len].to_vec();
        let socket = socket.clone();
        let ctx = ctx.clone();
        tokio::spawn(async move {
            let _permit = permit;
            let mut resp = super::handle_query(
                &query_data,
                &ctx.cache,
                &ctx.resolver,
                &ctx.auth,
                &ctx.rpz,
                recursion_allowed,
            )
            .await;
            if !resp.is_empty() {
                super::truncate_udp_response(&mut resp);
                // RRL check before sending
                let qname_hash = qname_hash_from_buf(&query_data);
                let rcode = if resp.len() >= 4 { resp[3] & 0x0F } else { 0 };
                if ctx.rrl.check(&src, qname_hash, rcode) {
                    let _ = socket.send_to(&resp, src).await;
                }
            }
        });
    }
}

/// Synchronous fast path for cache hits, auth answers, RPZ blocks.
#[inline(always)]
fn try_handle_sync(buf: &[u8], ctx: &QueryContext, recursion_allowed: bool) -> Option<Vec<u8>> {
    let (name, qtype, qclass, id, rd) = super::parse_query_fast(buf)?;

    // RPZ
    if let Some(action) = ctx.rpz.check(&name) {
        // Drop action: return empty vec (caller must not send anything)
        if action == crate::rpz::policy::PolicyAction::Drop {
            return Some(Vec::new());
        }
        if let Ok(query) = Message::decode(buf) {
            if let Some(response) = ctx.rpz.apply_action(&action, &query) {
                return Some(response.encode());
            }
        }
    }

    // Authoritative (always allowed)
    if let Some(ref auth_engine) = ctx.auth {
        match auth_engine.query(&name, qtype, qclass) {
            AuthResult::Answer(mut response) => {
                response.header.id = id;
                response.header.rd = rd;
                return Some(response.encode());
            }
            AuthResult::NotAuthoritative => {}
        }
    }

    // If recursion is not allowed, don't check cache from resolver or fall through to resolver
    if !recursion_allowed && ctx.resolver.is_some() {
        return Some(super::build_refused_fast(id, rd, &name, qtype, qclass));
    }

    // Cache
    let key = CacheKey::new(name.clone(), qtype, qclass);
    if let Some(entry) = ctx.cache.lookup(&key) {
        return Some(super::build_cached_response_fast(
            &entry, id, rd, &name, qtype, qclass,
        ));
    }

    if ctx.resolver.is_none() {
        return Some(super::build_servfail_fast(id, rd, &name, qtype, qclass));
    }

    None
}

/// Bind a UDP socket with SO_REUSEPORT using the safe socket2 wrappers.
fn bind_reuseport(addr: SocketAddr) -> anyhow::Result<UdpSocket> {
    use socket2::{Domain, Protocol, Socket, Type};

    let domain = if addr.is_ipv4() { Domain::IPV4 } else { Domain::IPV6 };
    let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))
        .map_err(|e| anyhow::anyhow!("socket(): {}", e))?;

    socket.set_nonblocking(true)
        .map_err(|e| anyhow::anyhow!("set_nonblocking: {}", e))?;
    // O_CLOEXEC is set by default on Linux by socket2 >= 0.5.

    if let Err(e) = socket.set_reuse_address(true) {
        tracing::warn!("Failed to set SO_REUSEADDR: {}", e);
    }

    socket.set_reuse_port(true)
        .map_err(|e| anyhow::anyhow!("SO_REUSEPORT not supported: {}", e))?;

    // Increase receive buffer for burst absorption
    if let Err(e) = socket.set_recv_buffer_size(4 * 1024 * 1024) {
        tracing::debug!("Could not set SO_RCVBUF to 4MB: {}", e);
    }

    socket.bind(&addr.into())
        .map_err(|e| anyhow::anyhow!("bind(): {}", e))?;

    let std_socket: std::net::UdpSocket = socket.into();
    Ok(UdpSocket::from_std(std_socket)?)
}

/// Quick hash of the QNAME from a raw DNS query buffer for RRL keying.
fn qname_hash_from_buf(buf: &[u8]) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    // Hash the question section bytes (starting at offset 12)
    if buf.len() > 12 {
        let qsection = &buf[12..buf.len().min(128)];
        qsection.hash(&mut hasher);
    }
    hasher.finish()
}

fn num_cpus() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4)
}
