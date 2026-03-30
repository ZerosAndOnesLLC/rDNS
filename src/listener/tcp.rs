use crate::auth::AuthEngine;
use crate::cache::CacheStore;
use crate::resolver::Resolver;
use std::net::SocketAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

pub async fn serve(
    addr: SocketAddr,
    cache: CacheStore,
    resolver: Option<Resolver>,
    auth: Option<AuthEngine>,
) -> anyhow::Result<()> {
    let listener = TcpListener::bind(addr).await?;
    tracing::info!(%addr, "TCP listener bound");

    loop {
        let (stream, src) = listener.accept().await?;
        let cache = cache.clone();
        let resolver = resolver.clone();
        let auth = auth.clone();
        tokio::spawn(handle_connection(stream, src, cache, resolver, auth));
    }
}

async fn handle_connection(
    mut stream: tokio::net::TcpStream,
    src: SocketAddr,
    cache: CacheStore,
    resolver: Option<Resolver>,
    auth: Option<AuthEngine>,
) {
    if let Err(e) = handle_connection_inner(&mut stream, src, &cache, &resolver, &auth).await {
        tracing::debug!(%src, error = %e, "TCP connection error");
    }
}

async fn handle_connection_inner(
    stream: &mut tokio::net::TcpStream,
    src: SocketAddr,
    cache: &CacheStore,
    resolver: &Option<Resolver>,
    auth: &Option<AuthEngine>,
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

        let response = super::handle_query(&buf, cache, resolver, auth).await;

        stream.write_u16(response.len() as u16).await?;
        stream.write_all(&response).await?;
        stream.flush().await?;
    }
}
