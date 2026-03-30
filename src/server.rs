use crate::auth::{AuthEngine, ZoneCatalog};
use crate::cache::CacheStore;
use crate::config::{AuthSource, Config, ServerMode};
use crate::dnssec::DnssecValidator;
use crate::listener;
use crate::resolver::Resolver;
use crate::rpz::RpzEngine;
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

    // Create DNSSEC validator
    let dnssec_validator = DnssecValidator::new(cfg.resolver.dnssec);

    // Create resolver (used in resolver and both modes)
    let resolver = match cfg.server.mode {
        ServerMode::Resolver | ServerMode::Both => Some(Resolver::new(
            cache.clone(),
            forwarders,
            cfg.resolver.max_recursion_depth,
            dnssec_validator,
            cfg.resolver.qname_minimization,
        )),
        ServerMode::Authoritative => None,
    };

    // Create authoritative engine (used in authoritative and both modes)
    let auth_engine = match cfg.server.mode {
        ServerMode::Authoritative | ServerMode::Both => {
            let catalog = ZoneCatalog::new();

            match cfg.authoritative.source {
                AuthSource::ZoneFiles => {
                    let count = catalog.load_directory(&cfg.authoritative.directory)?;
                    info!(zones = count, "Loaded zone files");
                }
                AuthSource::Database => {
                    if let Some(ref db_cfg) = cfg.authoritative.database {
                        info!(connection = %db_cfg.connection, "Database backend configured (enable 'postgres' feature to use)");
                    }
                }
                AuthSource::None => {}
            }

            Some(AuthEngine::new(catalog))
        }
        ServerMode::Resolver => None,
    };

    // Create RPZ engine
    let rpz_engine = RpzEngine::new();
    // RPZ zones would be loaded here from config
    // For now the engine is empty but wired in

    if cfg.security.rate_limit > 0 {
        info!(rate_limit = cfg.security.rate_limit, "Per-source rate limit configured");
    }

    let mut handles = Vec::new();

    // Start UDP listeners
    for addr in &cfg.listeners.udp {
        let addr = *addr;
        let resolver = resolver.clone();
        let cache = cache.clone();
        let auth = auth_engine.clone();
        let rpz = rpz_engine.clone();
        handles.push(tokio::spawn(async move {
            if let Err(e) = listener::udp::serve(addr, cache, resolver, auth, rpz).await {
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
        let rpz = rpz_engine.clone();
        handles.push(tokio::spawn(async move {
            if let Err(e) = listener::tcp::serve(addr, cache, resolver, auth, rpz).await {
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
            let rpz = rpz_engine.clone();
            handles.push(tokio::spawn(async move {
                if let Err(e) =
                    listener::tls::serve(addr, acceptor, cache, resolver, auth, rpz).await
                {
                    tracing::error!(%addr, error = %e, "DoT listener failed");
                }
            }));
            info!(%addr, "DNS-over-TLS listener started");
        }
    }

    // Start control socket
    {
        let control = crate::control::ControlServer::new(cache.clone());
        let socket_path = cfg.control.socket.clone();
        handles.push(tokio::spawn(async move {
            if let Err(e) = control.serve(&socket_path).await {
                tracing::error!(error = %e, "Control socket failed");
            }
        }));
        info!(path = %cfg.control.socket.display(), "Control socket started");
    }

    // Start Prometheus metrics endpoint
    if cfg.metrics.enabled {
        let addr = cfg.metrics.address;
        let cache = cache.clone();
        handles.push(tokio::spawn(async move {
            if let Err(e) = crate::metrics::serve(addr, cache).await {
                tracing::error!(%addr, error = %e, "Metrics endpoint failed");
            }
        }));
        info!(addr = %cfg.metrics.address, "Prometheus metrics endpoint started");
    }

    // Write PID file
    crate::security::privilege::write_pidfile(&cfg.server.pidfile)?;

    // Drop privileges after all ports are bound
    if let Err(e) = crate::security::privilege::drop_privileges(&cfg.server.user, &cfg.server.group)
    {
        tracing::warn!(error = %e, "Could not drop privileges");
    }

    // Enter platform sandbox
    if cfg.security.sandbox {
        if let Err(e) = crate::security::sandbox::enter_sandbox() {
            tracing::warn!(error = %e, "Could not enter sandbox");
        }
    }

    info!("rDNS ready");

    shutdown_signal().await;
    info!("Shutting down");

    crate::security::privilege::remove_pidfile(&cfg.server.pidfile);

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
