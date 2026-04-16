use crate::auth::AuthEngine;
use crate::cache::CacheStore;
use crate::resolver::Resolver;
use crate::rpz::RpzEngine;
use crate::security::acl::RecursionAcl;
use crate::security::rate_limit::RateLimiter;
use rustls::ServerConfig;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use tokio_rustls::TlsAcceptor;

/// Maximum concurrent DoT connections.
const MAX_DOT_CONNECTIONS: usize = 256;

/// Timeout for TLS handshake completion.
const TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);

/// Idle timeout for DoT connections waiting for the next query.
const DOT_IDLE_TIMEOUT: Duration = Duration::from_secs(10);

/// Timeout for reading a single DNS query payload.
const DOT_READ_TIMEOUT: Duration = Duration::from_secs(5);

/// Timeout for writing a response back to the client.
const DOT_WRITE_TIMEOUT: Duration = Duration::from_secs(5);

/// Timeout for overall query resolution.
const DOT_QUERY_TIMEOUT: Duration = Duration::from_secs(30);

/// Load TLS certificate and key, returning a configured TlsAcceptor.
pub fn build_tls_acceptor(cert_path: &Path, key_path: &Path) -> anyhow::Result<TlsAcceptor> {
    use rustls::pki_types::pem::PemObject;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer};

    let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_file_iter(cert_path)
        .map_err(|e| anyhow::anyhow!("Failed to read cert {}: {}", cert_path.display(), e))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| anyhow::anyhow!("Failed to parse cert {}: {}", cert_path.display(), e))?;

    if certs.is_empty() {
        anyhow::bail!("No certificates found in {}", cert_path.display());
    }

    let key = PrivateKeyDer::from_pem_file(key_path)
        .map_err(|e| anyhow::anyhow!("Failed to read key {}: {}", key_path.display(), e))?;

    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)?;

    Ok(TlsAcceptor::from(Arc::new(config)))
}

/// Serve DNS-over-TLS (RFC 7858) on the given address.
pub async fn serve(
    addr: SocketAddr,
    acceptor: TlsAcceptor,
    cache: CacheStore,
    resolver: Option<Resolver>,
    auth: Option<AuthEngine>,
    rpz: RpzEngine,
    rate_limiter: RateLimiter,
    acl: RecursionAcl,
) -> anyhow::Result<()> {
    let listener = TcpListener::bind(addr).await?;
    let semaphore = Arc::new(Semaphore::new(MAX_DOT_CONNECTIONS));
    let acl = Arc::new(acl);
    let rate_limiter = Arc::new(rate_limiter);
    tracing::info!(%addr, max_connections = MAX_DOT_CONNECTIONS, "DNS-over-TLS listener bound");

    loop {
        let (stream, src) = listener.accept().await?;
        if !rate_limiter.check(src.ip()) {
            drop(stream);
            continue;
        }

        let permit = match semaphore.clone().try_acquire_owned() {
            Ok(permit) => permit,
            Err(_) => {
                tracing::debug!(%src, "DoT connection rejected: at capacity");
                drop(stream);
                continue;
            }
        };

        let acceptor = acceptor.clone();
        let cache = cache.clone();
        let resolver = resolver.clone();
        let auth = auth.clone();
        let rpz = rpz.clone();
        let rate_limiter = rate_limiter.clone();
        let recursion_allowed = acl.is_allowed(src.ip());

        tokio::spawn(async move {
            let _permit = permit; // held until task completes

            // Timeout the TLS handshake
            let tls_stream = match tokio::time::timeout(
                TLS_HANDSHAKE_TIMEOUT,
                acceptor.accept(stream),
            )
            .await
            {
                Ok(Ok(s)) => s,
                Ok(Err(e)) => {
                    tracing::debug!(%src, error = %e, "TLS handshake failed");
                    return;
                }
                Err(_) => {
                    tracing::debug!(%src, "TLS handshake timed out");
                    return;
                }
            };

            if let Err(e) =
                handle_tls_connection(tls_stream, &cache, &resolver, &auth, &rpz, recursion_allowed, &rate_limiter, src).await
            {
                tracing::debug!(%src, error = %e, "DoT connection error");
            }
        });
    }
}

async fn handle_tls_connection(
    mut stream: tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
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

        // Idle timeout: wait for next query
        let len = match tokio::time::timeout(DOT_IDLE_TIMEOUT, stream.read_u16()).await {
            Ok(Ok(len)) => len as usize,
            Ok(Err(e)) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(()),
            Ok(Err(e)) => return Err(e.into()),
            Err(_) => return Ok(()), // idle timeout
        };

        if len == 0 || len > 16384 {
            return Ok(());
        }

        let mut buf = vec![0u8; len];
        match tokio::time::timeout(DOT_READ_TIMEOUT, stream.read_exact(&mut buf)).await {
            Ok(Ok(_)) => {}
            Ok(Err(e)) => return Err(e.into()),
            Err(_) => {
                anyhow::bail!("DoT read timeout");
            }
        }

        let response = match tokio::time::timeout(DOT_QUERY_TIMEOUT, super::handle_query(&buf, cache, resolver, auth, rpz, recursion_allowed)).await {
            Ok(resp) => resp,
            Err(_) => {
                tracing::debug!("DoT query resolution timed out");
                continue; // Skip this query, wait for next
            }
        };

        // Empty response = RPZ Drop — close connection silently
        if response.is_empty() {
            return Ok(());
        }

        match tokio::time::timeout(DOT_WRITE_TIMEOUT, async {
            stream.write_u16(response.len() as u16).await?;
            stream.write_all(&response).await?;
            stream.flush().await?;
            Ok::<(), std::io::Error>(())
        }).await {
            Ok(Ok(())) => {}
            Ok(Err(e)) => return Err(e.into()),
            Err(_) => anyhow::bail!("DoT write timeout"),
        }
    }
}
