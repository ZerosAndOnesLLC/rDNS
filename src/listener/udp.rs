use crate::auth::engine::{AuthEngine, AuthResult};
use crate::cache::entry::CacheKey;
use crate::cache::CacheStore;
use crate::protocol::message::Message;
use crate::resolver::Resolver;
use crate::rpz::RpzEngine;
use crate::security::acl::RecursionAcl;
use crate::security::rate_limit::RateLimiter;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;

const MAX_UDP_RECV: usize = 4096;

/// Shared context for all UDP query handlers.
struct QueryContext {
    cache: CacheStore,
    resolver: Option<Resolver>,
    auth: Option<AuthEngine>,
    rpz: RpzEngine,
    rate_limiter: RateLimiter,
    acl: RecursionAcl,
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
            Err(_) => continue,
        };

        // Rate limit check — drop packet silently if over limit
        if !ctx.rate_limiter.check(src.ip()) {
            continue;
        }

        let recursion_allowed = ctx.acl.is_allowed(src.ip());

        // Sync fast path: cache hit, auth, RPZ — no task spawn
        if let Some(mut response) = try_handle_sync(&buf[..len], &ctx, recursion_allowed) {
            super::truncate_udp_response(&mut response);
            let _ = socket.send_to(&response, src).await;
            continue;
        }

        // Cache miss — spawn async task for resolution
        let query_data = buf[..len].to_vec();
        let socket = socket.clone();
        let ctx = ctx.clone();
        tokio::spawn(async move {
            let mut resp = super::handle_query(
                &query_data,
                &ctx.cache,
                &ctx.resolver,
                &ctx.auth,
                &ctx.rpz,
                recursion_allowed,
            )
            .await;
            super::truncate_udp_response(&mut resp);
            let _ = socket.send_to(&resp, src).await;
        });
    }
}

/// Synchronous fast path for cache hits, auth answers, RPZ blocks.
#[inline(always)]
fn try_handle_sync(buf: &[u8], ctx: &QueryContext, recursion_allowed: bool) -> Option<Vec<u8>> {
    let (name, qtype, qclass, id, rd) = super::parse_query_fast(buf)?;

    // RPZ
    if let Some(action) = ctx.rpz.check(&name) {
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

/// Bind a UDP socket with SO_REUSEPORT via raw libc.
fn bind_reuseport(addr: SocketAddr) -> anyhow::Result<UdpSocket> {
    use std::os::fd::FromRawFd;

    let domain = if addr.is_ipv4() { libc::AF_INET } else { libc::AF_INET6 };

    let fd = unsafe { libc::socket(domain, libc::SOCK_DGRAM | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC, 0) };
    if fd < 0 {
        anyhow::bail!("socket(): {}", std::io::Error::last_os_error());
    }

    unsafe {
        let enable: libc::c_int = 1;
        let sz = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
        libc::setsockopt(fd, libc::SOL_SOCKET, libc::SO_REUSEADDR, &enable as *const _ as _, sz);
        libc::setsockopt(fd, libc::SOL_SOCKET, libc::SO_REUSEPORT, &enable as *const _ as _, sz);

        // Increase receive buffer for burst absorption
        let rcvbuf: libc::c_int = 4 * 1024 * 1024; // 4 MB
        libc::setsockopt(fd, libc::SOL_SOCKET, libc::SO_RCVBUF, &rcvbuf as *const _ as _, sz);
    }

    let (sockaddr, socklen) = super::udp_batch::socketaddr_to_sockaddr_raw(&addr);
    let ret = unsafe { libc::bind(fd, &sockaddr as *const _ as *const libc::sockaddr, socklen) };
    if ret < 0 {
        let err = std::io::Error::last_os_error();
        unsafe { libc::close(fd) };
        anyhow::bail!("bind(): {}", err);
    }

    let std_socket = unsafe { std::net::UdpSocket::from_raw_fd(fd) };
    Ok(UdpSocket::from_std(std_socket)?)
}

fn num_cpus() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4)
}
