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

    let num_workers = num_cpus().max(2);
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

/// Main receive loop. Handles cache hits inline (no task spawn),
/// only spawns tasks for cache misses that require async resolution.
async fn recv_loop(socket: Arc<UdpSocket>, ctx: Arc<QueryContext>) {
    let mut buf = vec![0u8; MAX_UDP_RECV];

    loop {
        let (len, src) = match socket.recv_from(&mut buf).await {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(error = %e, "UDP recv error");
                continue;
            }
        };

        // Fast path: try to handle synchronously (cache hit, auth hit, RPZ)
        if let Some(response) = try_handle_sync(&buf[..len], &ctx) {
            if let Err(e) = socket.send_to(&response, src).await {
                tracing::warn!(%src, error = %e, "Failed to send UDP response");
            }
            continue;
        }

        // Slow path: needs async resolution — spawn a task
        let query_data = buf[..len].to_vec();
        let socket = socket.clone();
        let ctx = ctx.clone();

        tokio::spawn(async move {
            let response = super::handle_query(
                &query_data,
                &ctx.cache,
                &ctx.resolver,
                &ctx.auth,
                &ctx.rpz,
            )
            .await;
            if let Err(e) = socket.send_to(&response, src).await {
                tracing::warn!(%src, error = %e, "Failed to send UDP response");
            }
        });
    }
}

/// Try to handle a query synchronously (no async, no task spawn).
/// Returns Some(response_bytes) for cache hits, auth answers, and RPZ blocks.
/// Returns None if async resolution is needed.
fn try_handle_sync(buf: &[u8], ctx: &QueryContext) -> Option<Vec<u8>> {
    let (name, qtype, qclass, id, rd) = super::parse_query_fast(buf)?;

    // RPZ check
    if let Some(action) = ctx.rpz.check(&name) {
        if let Ok(query) = Message::decode(buf) {
            if let Some(response) = ctx.rpz.apply_action(&action, &query) {
                return Some(response.encode());
            }
        }
        // Passthru — fall through
    }

    // Authoritative check (synchronous)
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

    // Cache check (synchronous — the resolver also checks cache, but this avoids
    // spawning a task entirely for cache hits)
    if ctx.resolver.is_some() {
        let key = CacheKey::new(name.clone(), qtype, qclass);
        if let Some(entry) = ctx.cache.lookup(&key) {
            return Some(super::build_cached_response_fast(&entry, id, rd, &name, qtype, qclass));
        }
    } else {
        // No resolver — cache-only mode
        let key = CacheKey::new(name.clone(), qtype, qclass);
        if let Some(entry) = ctx.cache.lookup(&key) {
            return Some(super::build_cached_response_fast(&entry, id, rd, &name, qtype, qclass));
        }
        return Some(super::build_servfail_fast(id, rd, &name, qtype, qclass));
    }

    // Cache miss — needs async resolution
    None
}

fn num_cpus() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4)
}
