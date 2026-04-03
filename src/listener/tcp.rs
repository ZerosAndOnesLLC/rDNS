use crate::auth::AuthEngine;
use crate::cache::CacheStore;
use crate::resolver::Resolver;
use crate::rpz::RpzEngine;
use crate::security::acl::RecursionAcl;
use crate::security::rate_limit::RateLimiter;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::Semaphore;

/// Maximum concurrent TCP connections.
const MAX_TCP_CONNECTIONS: usize = 512;

/// Idle timeout for TCP connections waiting for the next query.
const TCP_IDLE_TIMEOUT: Duration = Duration::from_secs(10);

/// Timeout for reading a single DNS query payload after the length prefix.
const TCP_READ_TIMEOUT: Duration = Duration::from_secs(5);

pub async fn serve(
    addr: SocketAddr,
    cache: CacheStore,
    resolver: Option<Resolver>,
    auth: Option<AuthEngine>,
    rpz: RpzEngine,
    rate_limiter: RateLimiter,
    acl: RecursionAcl,
) -> anyhow::Result<()> {
    let listener = TcpListener::bind(addr).await?;
    let semaphore = Arc::new(Semaphore::new(MAX_TCP_CONNECTIONS));
    let acl = Arc::new(acl);
    tracing::info!(%addr, max_connections = MAX_TCP_CONNECTIONS, "TCP listener bound");

    loop {
        let (stream, src) = listener.accept().await?;
        if !rate_limiter.check(src.ip()) {
            drop(stream);
            continue;
        }

        let permit = match semaphore.clone().try_acquire_owned() {
            Ok(permit) => permit,
            Err(_) => {
                tracing::debug!(%src, "TCP connection rejected: at capacity");
                drop(stream);
                continue;
            }
        };

        let cache = cache.clone();
        let resolver = resolver.clone();
        let auth = auth.clone();
        let rpz = rpz.clone();
        let recursion_allowed = acl.is_allowed(src.ip());
        tokio::spawn(async move {
            let _permit = permit; // held until task completes
            if let Err(e) = handle_connection_inner(stream, &cache, &resolver, &auth, &rpz, recursion_allowed).await {
                tracing::debug!(%src, error = %e, "TCP connection error");
            }
        });
    }
}

async fn handle_connection_inner(
    mut stream: tokio::net::TcpStream,
    cache: &CacheStore,
    resolver: &Option<Resolver>,
    auth: &Option<AuthEngine>,
    rpz: &RpzEngine,
    recursion_allowed: bool,
) -> anyhow::Result<()> {
    loop {
        // Idle timeout: wait for next query length prefix
        let len = match tokio::time::timeout(TCP_IDLE_TIMEOUT, stream.read_u16()).await {
            Ok(Ok(len)) => len as usize,
            Ok(Err(e)) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(()),
            Ok(Err(e)) => return Err(e.into()),
            Err(_) => return Ok(()), // idle timeout — close cleanly
        };

        if len == 0 || len > 65535 {
            return Ok(());
        }

        // Read timeout: don't let a slow client hold the connection
        let mut buf = vec![0u8; len];
        match tokio::time::timeout(TCP_READ_TIMEOUT, stream.read_exact(&mut buf)).await {
            Ok(Ok(_)) => {}
            Ok(Err(e)) => return Err(e.into()),
            Err(_) => {
                anyhow::bail!("TCP read timeout");
            }
        }

        let response = super::handle_query(&buf, cache, resolver, auth, rpz, recursion_allowed).await;

        stream.write_u16(response.len() as u16).await?;
        stream.write_all(&response).await?;
        stream.flush().await?;
    }
}
