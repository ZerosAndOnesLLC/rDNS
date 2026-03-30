use crate::auth::AuthEngine;
use crate::cache::CacheStore;
use crate::resolver::Resolver;
use crate::rpz::RpzEngine;
use rustls::ServerConfig;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

/// Load TLS certificate and key, returning a configured TlsAcceptor.
pub fn build_tls_acceptor(cert_path: &Path, key_path: &Path) -> anyhow::Result<TlsAcceptor> {
    use rustls_pemfile::{certs, pkcs8_private_keys};
    use std::io::BufReader;

    let cert_file = std::fs::File::open(cert_path)
        .map_err(|e| anyhow::anyhow!("Failed to open cert {}: {}", cert_path.display(), e))?;
    let key_file = std::fs::File::open(key_path)
        .map_err(|e| anyhow::anyhow!("Failed to open key {}: {}", key_path.display(), e))?;

    let certs: Vec<_> = certs(&mut BufReader::new(cert_file))
        .collect::<Result<Vec<_>, _>>()?;

    let keys: Vec<_> = pkcs8_private_keys(&mut BufReader::new(key_file))
        .collect::<Result<Vec<_>, _>>()?;

    let key = keys
        .into_iter()
        .next()
        .ok_or_else(|| anyhow::anyhow!("No private key found in {}", key_path.display()))?;

    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, rustls::pki_types::PrivateKeyDer::Pkcs8(key))?;

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
) -> anyhow::Result<()> {
    let listener = TcpListener::bind(addr).await?;
    tracing::info!(%addr, "DNS-over-TLS listener bound");

    loop {
        let (stream, src) = listener.accept().await?;
        let acceptor = acceptor.clone();
        let cache = cache.clone();
        let resolver = resolver.clone();
        let auth = auth.clone();
        let rpz = rpz.clone();

        tokio::spawn(async move {
            match acceptor.accept(stream).await {
                Ok(tls_stream) => {
                    if let Err(e) =
                        handle_tls_connection(tls_stream, &cache, &resolver, &auth, &rpz).await
                    {
                        tracing::debug!(%src, error = %e, "DoT connection error");
                    }
                }
                Err(e) => {
                    tracing::debug!(%src, error = %e, "TLS handshake failed");
                }
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
) -> anyhow::Result<()> {
    loop {
        let len = match stream.read_u16().await {
            Ok(len) => len as usize,
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(()),
            Err(e) => return Err(e.into()),
        };

        if len == 0 || len > 65535 {
            return Ok(());
        }

        let mut buf = vec![0u8; len];
        stream.read_exact(&mut buf).await?;

        let response = super::handle_query(&buf, cache, resolver, auth, rpz).await;

        stream.write_u16(response.len() as u16).await?;
        stream.write_all(&response).await?;
        stream.flush().await?;
    }
}
