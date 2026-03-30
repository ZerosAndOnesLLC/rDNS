use crate::cache::CacheStore;
use std::net::SocketAddr;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;

/// Serve Prometheus metrics over HTTP.
pub async fn serve(addr: SocketAddr, cache: CacheStore) -> anyhow::Result<()> {
    let listener = TcpListener::bind(addr).await?;
    tracing::info!(%addr, "Prometheus metrics endpoint started");

    loop {
        let (mut stream, _) = listener.accept().await?;
        let cache = cache.clone();

        tokio::spawn(async move {
            // Read the HTTP request (we don't need to parse it fully)
            let mut buf = vec![0u8; 4096];
            let _ = tokio::io::AsyncReadExt::read(&mut stream, &mut buf).await;

            let metrics = build_metrics(&cache);
            let response = format!(
                "HTTP/1.1 200 OK\r\n\
                 Content-Type: text/plain; version=0.0.4; charset=utf-8\r\n\
                 Content-Length: {}\r\n\
                 Connection: close\r\n\
                 \r\n\
                 {}",
                metrics.len(),
                metrics
            );

            let _ = stream.write_all(response.as_bytes()).await;
        });
    }
}

/// Build Prometheus-format metrics string.
fn build_metrics(cache: &CacheStore) -> String {
    let stats = cache.stats();

    format!(
        "# HELP rdns_cache_entries Current number of cache entries\n\
         # TYPE rdns_cache_entries gauge\n\
         rdns_cache_entries {}\n\
         \n\
         # HELP rdns_cache_max_entries Maximum cache capacity\n\
         # TYPE rdns_cache_max_entries gauge\n\
         rdns_cache_max_entries {}\n\
         \n\
         # HELP rdns_cache_hits_total Total cache hits\n\
         # TYPE rdns_cache_hits_total counter\n\
         rdns_cache_hits_total {}\n\
         \n\
         # HELP rdns_cache_misses_total Total cache misses\n\
         # TYPE rdns_cache_misses_total counter\n\
         rdns_cache_misses_total {}\n\
         \n\
         # HELP rdns_cache_insertions_total Total cache insertions\n\
         # TYPE rdns_cache_insertions_total counter\n\
         rdns_cache_insertions_total {}\n\
         \n\
         # HELP rdns_cache_evictions_total Total cache evictions\n\
         # TYPE rdns_cache_evictions_total counter\n\
         rdns_cache_evictions_total {}\n\
         \n\
         # HELP rdns_info rDNS server information\n\
         # TYPE rdns_info gauge\n\
         rdns_info{{version=\"{}\"}} 1\n",
        stats.entries,
        stats.max_entries,
        stats.hits,
        stats.misses,
        stats.insertions,
        stats.evictions,
        env!("CARGO_PKG_VERSION"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_metrics() {
        let cache = CacheStore::new(1000, 60, 86400, 300);
        let metrics = build_metrics(&cache);

        assert!(metrics.contains("rdns_cache_entries 0"));
        assert!(metrics.contains("rdns_cache_max_entries 1000"));
        assert!(metrics.contains("rdns_cache_hits_total 0"));
        assert!(metrics.contains("rdns_info"));
    }
}
