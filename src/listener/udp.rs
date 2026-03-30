use crate::auth::AuthEngine;
use crate::cache::CacheStore;
use crate::resolver::Resolver;
use crate::rpz::RpzEngine;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;

const MAX_UDP_RECV: usize = 4096;

pub async fn serve(
    addr: SocketAddr,
    cache: CacheStore,
    resolver: Option<Resolver>,
    auth: Option<AuthEngine>,
    rpz: RpzEngine,
) -> anyhow::Result<()> {
    let socket = Arc::new(UdpSocket::bind(addr).await?);
    tracing::info!(%addr, "UDP listener bound");

    // Spawn multiple receive tasks to process queries concurrently.
    // Each task shares the socket via Arc and spawns a handler task per query.
    let num_workers = num_cpus().max(2);
    let mut handles = Vec::with_capacity(num_workers);

    for _ in 0..num_workers {
        let socket = socket.clone();
        let cache = cache.clone();
        let resolver = resolver.clone();
        let auth = auth.clone();
        let rpz = rpz.clone();

        handles.push(tokio::spawn(async move {
            let mut buf = vec![0u8; MAX_UDP_RECV];
            loop {
                let (len, src) = match socket.recv_from(&mut buf).await {
                    Ok(v) => v,
                    Err(e) => {
                        tracing::warn!(error = %e, "UDP recv error");
                        continue;
                    }
                };

                let query_data = buf[..len].to_vec();
                let socket = socket.clone();
                let cache = cache.clone();
                let resolver = resolver.clone();
                let auth = auth.clone();
                let rpz = rpz.clone();

                // Spawn a task per query so the recv loop is never blocked
                tokio::spawn(async move {
                    let response =
                        super::handle_query(&query_data, &cache, &resolver, &auth, &rpz).await;
                    if let Err(e) = socket.send_to(&response, src).await {
                        tracing::warn!(%src, error = %e, "Failed to send UDP response");
                    }
                });
            }
        }));
    }

    // Wait for all workers (they run forever unless the task is aborted)
    for h in handles {
        h.await.ok();
    }

    Ok(())
}

fn num_cpus() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4)
}
