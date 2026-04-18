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

/// Timeout for writing a response back to the client.
const TCP_WRITE_TIMEOUT: Duration = Duration::from_secs(5);

/// Timeout for overall query resolution.
const TCP_QUERY_TIMEOUT: Duration = Duration::from_secs(30);

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
    let rate_limiter = Arc::new(rate_limiter);
    tracing::info!(%addr, max_connections = MAX_TCP_CONNECTIONS, "TCP listener bound");

    loop {
        let (stream, src) = match listener.accept().await {
            Ok(pair) => pair,
            Err(e) if super::is_transient_accept_error(&e) => {
                tracing::warn!(%addr, error = %e, "Transient accept() error; continuing");
                if super::is_resource_exhaustion(&e) {
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
                continue;
            }
            Err(e) => return Err(e.into()),
        };
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
        let rate_limiter = rate_limiter.clone();
        let recursion_allowed = acl.is_allowed(src.ip());
        tokio::spawn(async move {
            let _permit = permit; // held until task completes
            if let Err(e) = handle_connection_inner(stream, &cache, &resolver, &auth, &rpz, recursion_allowed, &rate_limiter, src).await {
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
    rate_limiter: &RateLimiter,
    src: SocketAddr,
) -> anyhow::Result<()> {
    loop {
        // Per-query rate limit check
        if !rate_limiter.check(src.ip()) {
            // Rate limited — close connection
            return Ok(());
        }

        // Idle timeout: wait for next query length prefix
        let len = match tokio::time::timeout(TCP_IDLE_TIMEOUT, stream.read_u16()).await {
            Ok(Ok(len)) => len as usize,
            Ok(Err(e)) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(()),
            Ok(Err(e)) => return Err(e.into()),
            Err(_) => return Ok(()), // idle timeout — close cleanly
        };

        if len == 0 || len > 16384 {
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

        let response = match tokio::time::timeout(super::effective_query_timeout(TCP_QUERY_TIMEOUT), super::handle_query(&buf, cache, resolver, auth, rpz, recursion_allowed)).await {
            Ok(resp) => resp,
            Err(_) => {
                tracing::debug!("TCP query resolution timed out");
                continue; // Skip this query, wait for next
            }
        };

        // Empty response = RPZ Drop — close connection silently
        if response.is_empty() {
            return Ok(());
        }

        match tokio::time::timeout(TCP_WRITE_TIMEOUT, async {
            stream.write_u16(response.len() as u16).await?;
            stream.write_all(&response).await?;
            stream.flush().await?;
            Ok::<(), std::io::Error>(())
        }).await {
            Ok(Ok(())) => {}
            Ok(Err(e)) => return Err(e.into()),
            Err(_) => anyhow::bail!("TCP write timeout"),
        }

        super::log_query(src, &buf, &response, "tcp");
    }
}
