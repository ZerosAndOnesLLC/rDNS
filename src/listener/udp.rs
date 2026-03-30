use crate::auth::AuthEngine;
use crate::cache::CacheStore;
use crate::resolver::Resolver;
use crate::rpz::RpzEngine;
use std::net::SocketAddr;
use tokio::net::UdpSocket;

const MAX_UDP_RECV: usize = 4096;

pub async fn serve(
    addr: SocketAddr,
    cache: CacheStore,
    resolver: Option<Resolver>,
    auth: Option<AuthEngine>,
    rpz: RpzEngine,
) -> anyhow::Result<()> {
    let socket = UdpSocket::bind(addr).await?;
    tracing::info!(%addr, "UDP listener bound");

    let mut buf = vec![0u8; MAX_UDP_RECV];

    loop {
        let (len, src) = socket.recv_from(&mut buf).await?;

        let query_data = buf[..len].to_vec();
        let response = super::handle_query(&query_data, &cache, &resolver, &auth, &rpz).await;

        if let Err(e) = socket.send_to(&response, src).await {
            tracing::warn!(%src, error = %e, "Failed to send UDP response");
        }
    }
}
