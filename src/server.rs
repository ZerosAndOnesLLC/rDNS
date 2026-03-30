use crate::auth::{AuthEngine, ZoneCatalog};
use crate::cache::CacheStore;
use crate::config::{AuthSource, Config, ServerMode};
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
            if s.contains(':') {
                s.parse().ok()
            } else {
                format!("{}:53", s).parse().ok()
            }
        })
        .collect();

    // Create resolver (used in resolver and both modes)
    let resolver = match cfg.server.mode {
        ServerMode::Resolver | ServerMode::Both => Some(Resolver::new(
            cache.clone(),
            forwarders,
            cfg.resolver.max_recursion_depth,
        )),
        ServerMode::Authoritative => None,
    };

    // Create authoritative engine (used in authoritative and both modes)
    let auth_engine = match cfg.server.mode {
        ServerMode::Authoritative | ServerMode::Both => {
            let catalog = ZoneCatalog::new();

            if cfg.authoritative.source == AuthSource::ZoneFiles {
                let count = catalog.load_directory(&cfg.authoritative.directory)?;
                info!(zones = count, "Loaded zone files");
            }

            Some(AuthEngine::new(catalog))
        }
        ServerMode::Resolver => None,
    };

    let mut handles = Vec::new();

    // Start UDP listeners
    for addr in &cfg.listeners.udp {
        let addr = *addr;
        let resolver = resolver.clone();
        let cache = cache.clone();
        let auth = auth_engine.clone();
        handles.push(tokio::spawn(async move {
            if let Err(e) = listener::udp::serve(addr, cache, resolver, auth).await {
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
        let auth = auth_engine.clone();
        handles.push(tokio::spawn(async move {
            if let Err(e) = listener::tcp::serve(addr, cache, resolver, auth).await {
                tracing::error!(%addr, error = %e, "TCP listener failed");
            }
        }));
        info!(%addr, "TCP listener started");
    }

    // Start TLS listeners (DNS-over-TLS)
    if let Some(ref tls_cfg) = cfg.listeners.tls {
        let acceptor = listener::tls::build_tls_acceptor(&tls_cfg.cert, &tls_cfg.key)?;
        for addr in &tls_cfg.addresses {
            let addr = *addr;
            let acceptor = acceptor.clone();
            let resolver = resolver.clone();
            let cache = cache.clone();
            let auth = auth_engine.clone();
            handles.push(tokio::spawn(async move {
                if let Err(e) =
                    listener::tls::serve(addr, acceptor, cache, resolver, auth).await
                {
                    tracing::error!(%addr, error = %e, "DoT listener failed");
                }
            }));
            info!(%addr, "DNS-over-TLS listener started");
        }
    }

    info!("rDNS ready");

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
