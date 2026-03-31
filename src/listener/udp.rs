use crate::auth::engine::{AuthEngine, AuthResult};
use crate::cache::entry::CacheKey;
use crate::cache::CacheStore;
use crate::protocol::message::Message;
use crate::resolver::Resolver;
use crate::rpz::RpzEngine;
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
}

pub async fn serve(
    addr: SocketAddr,
    cache: CacheStore,
    resolver: Option<Resolver>,
    auth: Option<AuthEngine>,
    rpz: RpzEngine,
) -> anyhow::Result<()> {
    let socket = Arc::new(UdpSocket::bind(addr).await?);
    tracing::info!(%addr, "UDP listener bound");

    let ctx = Arc::new(QueryContext {
        cache,
        resolver,
        auth,
        rpz,
    });

    // One tight recv loop per 3 CPUs — more than that causes contention
    let num_workers = (num_cpus() / 3).clamp(1, 8);
    let mut handles = Vec::with_capacity(num_workers);

    for _ in 0..num_workers {
        let socket = socket.clone();
        let ctx = ctx.clone();
        handles.push(tokio::spawn(async move {
            recv_loop(socket, ctx).await;
        }));
    }

    for h in handles {
        h.await.ok();
    }

    Ok(())
}

/// Main receive loop — cache hits handled inline, misses spawn a task.
#[inline(never)]
async fn recv_loop(socket: Arc<UdpSocket>, ctx: Arc<QueryContext>) {
    let mut buf = [0u8; MAX_UDP_RECV];

    loop {
        let (len, src) = match socket.recv_from(&mut buf).await {
            Ok(v) => v,
            Err(_) => continue,
        };

        // Sync fast path: cache hit, auth, RPZ — no task spawn
        if let Some(response) = try_handle_sync(&buf[..len], &ctx) {
            let _ = socket.send_to(&response, src).await;
            continue;
        }

        // Cache miss — spawn async task for resolution
        let query_data = buf[..len].to_vec();
        let socket = socket.clone();
        let ctx = ctx.clone();
        tokio::spawn(async move {
            let resp = super::handle_query(
                &query_data,
                &ctx.cache,
                &ctx.resolver,
                &ctx.auth,
                &ctx.rpz,
            )
            .await;
            let _ = socket.send_to(&resp, src).await;
        });
    }
}

/// Synchronous fast path for cache hits, auth answers, RPZ blocks.
#[inline(always)]
fn try_handle_sync(buf: &[u8], ctx: &QueryContext) -> Option<Vec<u8>> {
    let (name, qtype, qclass, id, rd) = super::parse_query_fast(buf)?;

    // RPZ
    if let Some(action) = ctx.rpz.check(&name) {
        if let Ok(query) = Message::decode(buf) {
            if let Some(response) = ctx.rpz.apply_action(&action, &query) {
                return Some(response.encode());
            }
        }
    }

    // Authoritative
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

fn num_cpus() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4)
}
