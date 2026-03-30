use crate::cache::CacheStore;
use crate::config::{Config, ServerMode};
use crate::listener;
use crate::resolver::Resolver;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::signal;
use tracing::info;

pub async fn run(cfg: Config) -> anyhow::Result<()> {
    // Initialize cache
    let cache = CacheStore::new(
        cfg.cache.max_entries,
        cfg.cache.min_ttl,
        cfg.cache.max_ttl,
        cfg.cache.negative_ttl,
    );

    // Spawn cache expiry background task (sweep every 60s)
    let _expiry_handle = cache.clone().spawn_expiry_task(Duration::from_secs(60));

    // Parse forwarder addresses
    let forwarders: Vec<SocketAddr> = cfg
        .resolver
        .forwarders
        .iter()
        .filter_map(|s| {
            // Support formats: "1.1.1.1", "1.1.1.1:53"
            if s.contains(':') {
                s.parse().ok()
            } else {
                format!("{}:53", s).parse().ok()
            }
        })
        .collect();

    // Create resolver (used in resolver and both modes)
    let resolver = match cfg.server.mode {
        ServerMode::Resolver | ServerMode::Both => {
            Some(Resolver::new(
                cache.clone(),
                forwarders,
                cfg.resolver.max_recursion_depth,
            ))
        }
        ServerMode::Authoritative => None,
    };

    let mut handles = Vec::new();

    // Start UDP listeners
    for addr in &cfg.listeners.udp {
        let addr = *addr;
        let resolver = resolver.clone();
        let cache = cache.clone();
        handles.push(tokio::spawn(async move {
            if let Err(e) = listener::udp::serve(addr, cache, resolver).await {
                tracing::error!(%addr, error = %e, "UDP listener failed");
            }
        }));
        info!(%addr, "UDP listener started");
    }

    // Start TCP listeners
    for addr in &cfg.listeners.tcp {
        let addr = *addr;
        let resolver = resolver.clone();
        let cache = cache.clone();
        handles.push(tokio::spawn(async move {
            if let Err(e) = listener::tcp::serve(addr, cache, resolver).await {
                tracing::error!(%addr, error = %e, "TCP listener failed");
            }
        }));
        info!(%addr, "TCP listener started");
    }

    info!("rDNS ready");

    // Wait for shutdown signal
    shutdown_signal().await;
    info!("Shutting down");

    for handle in handles {
        handle.abort();
    }

    Ok(())
}

async fn shutdown_signal() {
    let ctrl_c = signal::ctrl_c();
    #[cfg(unix)]
    let mut sigterm = signal::unix::signal(signal::unix::SignalKind::terminate())
        .expect("failed to install SIGTERM handler");

    #[cfg(unix)]
    tokio::select! {
        _ = ctrl_c => {},
        _ = sigterm.recv() => {},
    }

    #[cfg(not(unix))]
    ctrl_c.await.ok();
}
