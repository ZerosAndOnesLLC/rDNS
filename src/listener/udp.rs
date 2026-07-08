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
/// Datagrams to drain per `recvmmsg`/`sendmmsg` syscall on Linux. Matches the
/// batch module's internal cap; one reactor wakeup amortizes up to this many
/// packets.
#[cfg(target_os = "linux")]
const UDP_BATCH_SIZE: usize = 64;

/// Hard ceiling on how long a single UDP query's resolution may take before
/// its task is cancelled and its inflight permit released. Without this,
/// recursive resolution (which can legitimately touch multiple upstream
/// servers with 5 s timeouts each, per level, up to `max_recursion_depth`)
/// can hold a permit for minutes on a single slow or adversarial query. A
/// sustained cache-miss flood (classic DNS water torture) then pins every
/// permit and the server appears to hang even though it is alive — the
/// symptom the "hangs after ~15 min" reports describe. 3 s is below the
/// typical DNS stub-resolver first retry (5 s on glibc / BSD libc / dig),
/// so a client that doesn't get an answer in this window will retry before
/// its own deadline rather than timing out on the user.
const UDP_QUERY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(3);

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
        // RRL defends against external amplification attacks (a spoofed source
        // gets flooded by our replies). It must NOT throttle trusted LAN
        // traffic: a home or office can legitimately see many devices on the
        // same /24 resolving the same popular name (google.com, apple.com,
        // update servers) within the same second. With the prior blanket
        // default of 10/s, a busy household could have its own devices race
        // each other and silently starve — exactly the symptom behind the
        // "DNS hangs under load" reports. Skip RRL for loopback and RFC 1918 /
        // ULA ranges; keep it for public sources where amplification matters.
        let is_trusted = match src.ip() {
            std::net::IpAddr::V4(v4) => v4.is_loopback() || v4.is_private(),
            std::net::IpAddr::V6(v6) => v6.is_loopback() || (v6.segments()[0] & 0xfe00) == 0xfc00,
        };
        if is_trusted {
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
        // RRL defends public-facing resolvers against amplification; LAN
        // sources are exempted inside check(). 100/s per public /24 per
        // (qname, rcode) is still tight enough to blunt amplification while
        // leaving legitimate remote clients unaffected — BIND and Unbound
        // default to 0 (disabled) here, so 100 is conservative.
        rrl: ResponseRateLimiter::new(100),
    });

    let num_workers = udp_worker_count();

    // Try SO_REUSEPORT: each worker gets its own socket, kernel distributes
    // packets, zero contention. On Linux each worker drains its socket with
    // recvmmsg/sendmmsg (see recv_loop_batched); elsewhere it falls back to
    // per-datagram recv_from/send_to.
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
            handles.push(spawn_recv_worker(Arc::new(socket), ctx));
        }
    } else {
        // Fallback: shared socket with multiple recv tasks
        drop(sockets);
        let socket = Arc::new(UdpSocket::bind(addr).await?);
        tracing::info!(%addr, workers = num_workers, "UDP listener bound (shared)");
        for _ in 0..num_workers {
            let socket = socket.clone();
            let ctx = ctx.clone();
            handles.push(spawn_recv_worker(socket, ctx));
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

/// Spawn one receive worker for `socket`. On Linux this drives batched
/// recvmmsg/sendmmsg; on other platforms it uses the per-datagram loop.
fn spawn_recv_worker(
    socket: Arc<UdpSocket>,
    ctx: Arc<QueryContext>,
) -> tokio::task::JoinHandle<()> {
    #[cfg(target_os = "linux")]
    {
        // Batched recvmmsg/sendmmsg is the default on Linux. RDNS_UDP_BATCH
        // tunes it: "0" forces the per-datagram loop; "N" sets the batch size
        // (clamped to 1..=UDP_BATCH_SIZE); unset uses the default.
        match udp_batch_setting() {
            Some(0) => tokio::spawn(recv_loop(socket, ctx)),
            Some(n) => tokio::spawn(recv_loop_batched(socket, ctx, n)),
            None => tokio::spawn(recv_loop_batched(socket, ctx, UDP_BATCH_SIZE)),
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        tokio::spawn(recv_loop(socket, ctx))
    }
}

/// Main receive loop — cache hits handled inline, misses spawn a task.
/// On Linux this is superseded by [`recv_loop_batched`]; kept for other
/// platforms and as the shared-socket reference implementation.
#[cfg_attr(target_os = "linux", allow(dead_code))]
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

        // EDNS / buffer-size negotiation — parsed once and reused for the
        // fast-path fall-through and truncation.
        let client_edns = super::parse_edns_from_query(&buf[..len]);
        let effective_size = super::effective_udp_response_size(client_edns.as_ref());
        let server_opt = if client_edns.is_some() {
            Some(super::server_edns_opt())
        } else {
            None
        };

        // Sync fast path: cache hit, auth, RPZ — no task spawn
        if let Some(mut response) = try_handle_sync(&buf[..len], &ctx, recursion_allowed, client_edns.as_ref()) {
            if !response.is_empty() {
                super::truncate_udp_response(&mut response, effective_size, server_opt.as_ref());
                // RRL check before sending
                let qname_hash = qname_hash_from_buf(&buf[..len]);
                let rcode = if response.len() >= 4 { response[3] & 0x0F } else { 0 };
                if ctx.rrl.check(&src, qname_hash, rcode) {
                    let _ = socket.send_to(&response, src).await;
                    super::log_query(src, &buf[..len], &response, "udp");
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
            let mut resp = match tokio::time::timeout(
                super::effective_query_timeout(UDP_QUERY_TIMEOUT),
                super::handle_query(
                    &query_data,
                    &ctx.cache,
                    &ctx.resolver,
                    &ctx.auth,
                    &ctx.rpz,
                    recursion_allowed,
                ),
            )
            .await
            {
                Ok(r) => r,
                Err(_) => {
                    // Resolution exceeded the UDP ceiling. Drop silently —
                    // the permit releases as this task returns, the client
                    // will retry, and we avoid pinning permits on slow or
                    // adversarial queries.
                    tracing::debug!("UDP query resolution timed out");
                    return;
                }
            };
            if !resp.is_empty() {
                super::truncate_udp_response(&mut resp, effective_size, server_opt.as_ref());
                // RRL check before sending
                let qname_hash = qname_hash_from_buf(&query_data);
                let rcode = if resp.len() >= 4 { resp[3] & 0x0F } else { 0 };
                if ctx.rrl.check(&src, qname_hash, rcode) {
                    let _ = socket.send_to(&resp, src).await;
                    super::log_query(src, &query_data, &resp, "udp");
                }
            }
        });
    }
}

/// Batched receive loop (Linux). One `recvmmsg` drains up to
/// [`UDP_BATCH_SIZE`] datagrams per reactor wakeup; each is run through the
/// same fast path as [`recv_loop`], and every cache-hit response is sent back
/// in a single `sendmmsg`. This amortizes the per-datagram syscall and
/// reactor-wakeup overhead that dominated the profile after the hot-path
/// allocation/hashing fixes. Behaviour per datagram is identical to
/// `recv_loop`; only the I/O is batched.
#[cfg(target_os = "linux")]
async fn recv_loop_batched(socket: Arc<UdpSocket>, ctx: Arc<QueryContext>, batch_size: usize) {
    use super::udp_batch::{self, SendPacket};
    use std::os::fd::AsRawFd;
    use tokio::io::Interest;

    let batch_size = batch_size.clamp(1, UDP_BATCH_SIZE);
    let fd = socket.as_raw_fd();
    let mut recv_batch = udp_batch::alloc_recv_batch(batch_size);
    let mut send_batch: Vec<SendPacket> = Vec::with_capacity(batch_size);

    loop {
        // Block (via the reactor) until at least one datagram is ready, then
        // drain up to UDP_BATCH_SIZE of them in one syscall.
        let n = match socket
            .async_io(Interest::READABLE, || {
                udp_batch::recvmmsg_batch(fd, &mut recv_batch)
            })
            .await
        {
            Ok(n) => n,
            Err(e) => {
                tracing::debug!(error = %e, "UDP recvmmsg error");
                tokio::time::sleep(std::time::Duration::from_millis(1)).await;
                continue;
            }
        };

        send_batch.clear();
        for pkt in recv_batch.iter().take(n) {
            let len = pkt.len;
            let src = pkt.src;
            let buf = &pkt.buf[..len];

            // Rate limit — drop silently if over limit.
            if !ctx.rate_limiter.check(src.ip()) {
                continue;
            }

            let recursion_allowed = ctx.acl.is_allowed(src.ip());
            let client_edns = super::parse_edns_from_query(buf);
            let effective_size = super::effective_udp_response_size(client_edns.as_ref());
            let server_opt = if client_edns.is_some() {
                Some(super::server_edns_opt())
            } else {
                None
            };

            // Sync fast path: cache hit, auth, RPZ — queue the reply for the
            // batched send instead of sending it inline.
            if let Some(mut response) =
                try_handle_sync(buf, &ctx, recursion_allowed, client_edns.as_ref())
            {
                if !response.is_empty() {
                    super::truncate_udp_response(&mut response, effective_size, server_opt.as_ref());
                    let qname_hash = qname_hash_from_buf(buf);
                    let rcode = if response.len() >= 4 { response[3] & 0x0F } else { 0 };
                    if ctx.rrl.check(&src, qname_hash, rcode) {
                        super::log_query(src, buf, &response, "udp");
                        send_batch.push(SendPacket { data: response, dest: src });
                    }
                }
                // Empty response = RPZ Drop — silently discard.
                continue;
            }

            // Cache miss — spawn an async task for resolution (sends inline).
            let permit = match ctx.inflight.clone().try_acquire_owned() {
                Ok(p) => p,
                Err(_) => continue, // At capacity, drop query
            };
            let query_data = buf.to_vec();
            let socket = socket.clone();
            let ctx = ctx.clone();
            tokio::spawn(async move {
                let _permit = permit;
                let mut resp = match tokio::time::timeout(
                    super::effective_query_timeout(UDP_QUERY_TIMEOUT),
                    super::handle_query(
                        &query_data,
                        &ctx.cache,
                        &ctx.resolver,
                        &ctx.auth,
                        &ctx.rpz,
                        recursion_allowed,
                    ),
                )
                .await
                {
                    Ok(r) => r,
                    Err(_) => {
                        tracing::debug!("UDP query resolution timed out");
                        return;
                    }
                };
                if !resp.is_empty() {
                    super::truncate_udp_response(&mut resp, effective_size, server_opt.as_ref());
                    let qname_hash = qname_hash_from_buf(&query_data);
                    let rcode = if resp.len() >= 4 { resp[3] & 0x0F } else { 0 };
                    if ctx.rrl.check(&src, qname_hash, rcode) {
                        let _ = socket.send_to(&resp, src).await;
                        super::log_query(src, &query_data, &resp, "udp");
                    }
                }
            });
        }

        // Batch-send all queued cache-hit responses. sendmmsg may send fewer
        // than requested under pressure; loop over the remainder.
        let mut sent = 0;
        while sent < send_batch.len() {
            match socket
                .async_io(Interest::WRITABLE, || {
                    udp_batch::sendmmsg_batch(fd, &send_batch[sent..])
                })
                .await
            {
                Ok(0) => break, // avoid spinning if nothing progressed
                Ok(c) => sent += c,
                Err(e) => {
                    tracing::debug!(error = %e, "UDP sendmmsg error");
                    break;
                }
            }
        }
    }
}

/// Synchronous fast path for cache hits, auth answers, RPZ blocks.
/// BADVERS (unsupported EDNS version) is also handled here so we avoid the
/// task-spawn cost on obviously-short responses.
#[inline(always)]
fn try_handle_sync(
    buf: &[u8],
    ctx: &QueryContext,
    recursion_allowed: bool,
    client_edns: Option<&crate::protocol::edns::EdnsOpt>,
) -> Option<Vec<u8>> {
    let (name, qtype, qclass, id, rd) = super::parse_query_fast(buf)?;

    // BADVERS short-circuit — no point consulting auth / cache / resolver.
    if let Some(opt) = client_edns {
        if opt.is_unsupported_version() {
            return Some(super::build_badvers_fast(id, &name, qtype, qclass));
        }
    }

    // RPZ
    if let Some(action) = ctx.rpz.check(&name) {
        // Drop action: return empty vec (caller must not send anything)
        if action == crate::rpz::policy::PolicyAction::Drop {
            return Some(Vec::new());
        }
        if let Ok(query) = Message::decode(buf) {
            if let Some(mut response) = ctx.rpz.apply_action(&action, &query) {
                if client_edns.is_some() {
                    response.edns = Some(super::server_edns_opt());
                }
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
                if client_edns.is_some() {
                    response.edns = Some(super::server_edns_opt());
                }
                return Some(response.encode());
            }
            AuthResult::NotAuthoritative => {}
        }
    }

    // If recursion is not allowed, don't check cache from resolver or fall through to resolver
    if !recursion_allowed && ctx.resolver.is_some() {
        return Some(super::build_refused_fast(id, rd, &name, qtype, qclass, client_edns));
    }

    // Cache
    let key = CacheKey::new(name.clone(), qtype, qclass);
    if let Some(entry) = ctx.cache.lookup(&key) {
        return Some(super::build_cached_response_fast(
            &entry, id, rd, &name, qtype, qclass, client_edns,
        ));
    }

    if ctx.resolver.is_none() {
        return Some(super::build_servfail_fast(id, rd, &name, qtype, qclass, client_edns));
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

/// Parse `RDNS_UDP_BATCH`: `Some(0)` = per-datagram loop, `Some(n)` = batch
/// size n, `None` = use the default batch size. Only consulted on Linux.
#[cfg(target_os = "linux")]
fn udp_batch_setting() -> Option<usize> {
    std::env::var("RDNS_UDP_BATCH")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
}

/// Number of SO_REUSEPORT recv workers to spawn per UDP listen address.
///
/// Defaults to ~3/4 of the cores. The cached hot path is CPU-bound, so the
/// prior `cores/2` (capped at 16 → 12 on a 24-core box) left throughput on
/// the table; but benchmarking showed one-worker-per-core *regresses* under
/// load — the recv workers then contend with tokio's runtime threads, the
/// cache-miss resolution tasks, and the OS for the last cores. Three quarters
/// is the measured sweet spot: it uses most of the machine while leaving
/// headroom for everything else. Operators can override with
/// `RDNS_UDP_WORKERS` to pin an exact count (e.g. to share a box with other
/// services, or to match a specific core layout).
fn udp_worker_count() -> usize {
    if let Ok(v) = std::env::var("RDNS_UDP_WORKERS") {
        if let Ok(n) = v.parse::<usize>() {
            if n >= 1 {
                return n.min(256);
            }
        }
    }
    (num_cpus() * 3 / 4).clamp(2, 32)
}
