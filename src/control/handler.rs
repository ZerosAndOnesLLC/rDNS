use crate::cache::CacheStore;
use crate::rpz::{BlockEvents, RpzEngine};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixListener;

/// Unix socket control server for runtime management and live streaming.
#[derive(Clone)]
pub struct ControlServer {
    cache: CacheStore,
    rpz: Option<Arc<RpzEngine>>,
    events: Option<BlockEvents>,
}

impl ControlServer {
    pub fn new(cache: CacheStore) -> Self {
        Self {
            cache,
            rpz: None,
            events: None,
        }
    }

    /// Builder: attach the RPZ engine so `stats-json`, `top-blocked`, and
    /// `reload-rpz` can serve real data.
    pub fn with_rpz(mut self, rpz: Arc<RpzEngine>) -> Self {
        self.rpz = Some(rpz);
        self
    }

    /// Builder: attach the block-event sink so `tail-blocks` can stream.
    pub fn with_events(mut self, events: BlockEvents) -> Self {
        self.events = Some(events);
        self
    }

    /// Start listening on the unix control socket.
    pub async fn serve(&self, socket_path: &Path) -> anyhow::Result<()> {
        let _ = std::fs::remove_file(socket_path);
        if let Some(parent) = socket_path.parent() {
            std::fs::create_dir_all(parent).ok();
        }

        // Restrictive umask before binding to avoid TOCTOU on socket perms.
        #[cfg(unix)]
        let old_umask =
            nix::sys::stat::umask(nix::sys::stat::Mode::from_bits_truncate(0o117));

        let bind_result = UnixListener::bind(socket_path);

        #[cfg(unix)]
        {
            nix::sys::stat::umask(old_umask);
        }

        let listener = bind_result?;

        tracing::info!(path = %socket_path.display(), "Control socket listening");

        loop {
            let (stream, _) = listener.accept().await?;
            let server = self.clone();
            tokio::spawn(async move {
                if let Err(e) = server.handle_connection(stream).await {
                    tracing::debug!(error = %e, "Control connection error");
                }
            });
        }
    }

    async fn handle_connection(
        &self,
        stream: tokio::net::UnixStream,
    ) -> anyhow::Result<()> {
        let (reader, mut writer) = stream.into_split();
        let mut reader = BufReader::new(reader);
        let mut line = String::new();

        loop {
            line.clear();
            let n = reader.read_line(&mut line).await?;
            if n == 0 {
                return Ok(());
            }
            if line.len() > 4096 {
                writer.write_all(b"ERROR: command too long\n").await?;
                return Ok(());
            }

            let trimmed = line.trim();
            let parts: Vec<&str> = trimmed.split_whitespace().collect();
            if parts.is_empty() {
                writer.write_all(b"ERROR: empty command\n").await?;
                continue;
            }

            match parts[0].to_lowercase().as_str() {
                "watch" => {
                    let secs: u64 = parts.get(1).and_then(|s| s.parse().ok()).unwrap_or(1);
                    let secs = secs.clamp(1, 60);
                    self.cmd_watch(&mut writer, secs).await?;
                    return Ok(());
                }
                "tail-blocks" => {
                    let n: usize = parts.get(1).and_then(|s| s.parse().ok()).unwrap_or(0);
                    self.cmd_tail_blocks(&mut writer, n).await?;
                    return Ok(());
                }
                _ => {
                    let response = self.handle_command(trimmed);
                    writer.write_all(response.as_bytes()).await?;
                    writer.write_all(b"\n").await?;
                    writer.flush().await?;
                }
            }
        }
    }

    fn handle_command(&self, command: &str) -> String {
        let parts: Vec<&str> = command.split_whitespace().collect();
        if parts.is_empty() {
            return "ERROR: empty command".to_string();
        }

        match parts[0].to_lowercase().as_str() {
            "stats" => self.cmd_stats(),
            "stats-json" => self.cmd_stats_json(),
            "top-blocked" => {
                let n: usize = parts.get(1).and_then(|s| s.parse().ok()).unwrap_or(20);
                self.cmd_top_blocked(n)
            }
            "reload-rpz" => self.cmd_reload_rpz(),
            "flush" | "flush-cache" => self.cmd_flush_cache(),
            "flush-name" => {
                if parts.len() < 2 {
                    "ERROR: flush-name requires a domain name".to_string()
                } else {
                    self.cmd_flush_name(parts[1])
                }
            }
            "ping" => "PONG".to_string(),
            "version" => format!("rDNS {}", env!("CARGO_PKG_VERSION")),
            "help" => self.cmd_help(),
            _ => format!("ERROR: unknown command '{}'", parts[0]),
        }
    }

    fn cmd_stats(&self) -> String {
        let stats = self.cache.stats();
        format!(
            "cache.entries={}\n\
             cache.max_entries={}\n\
             cache.hits={}\n\
             cache.misses={}\n\
             cache.insertions={}\n\
             cache.evictions={}\n\
             cache.hit_rate={:.2}%\n\
             OK",
            stats.entries,
            stats.max_entries,
            stats.hits,
            stats.misses,
            stats.insertions,
            stats.evictions,
            if stats.hits + stats.misses > 0 {
                (stats.hits as f64 / (stats.hits + stats.misses) as f64) * 100.0
            } else {
                0.0
            }
        )
    }

    fn cmd_stats_json(&self) -> String {
        let snap = self.snapshot();
        serde_json::to_string(&snap).unwrap_or_else(|e| format!("ERROR: {}", e))
    }

    fn snapshot(&self) -> StatsSnapshot {
        let cache = self.cache.stats();
        let (rpz_total_hits, rpz_zones, rpz_rules, rpz_zone_count) = match &self.rpz {
            Some(rpz) => (
                rpz.total_hits(),
                rpz.zone_stats(),
                rpz.rule_count() as u64,
                rpz.zone_count() as u64,
            ),
            None => (0, Vec::new(), 0, 0),
        };

        let hit_rate = if cache.hits + cache.misses > 0 {
            (cache.hits as f64 / (cache.hits + cache.misses) as f64) * 100.0
        } else {
            0.0
        };

        StatsSnapshot {
            ts: now_ms(),
            cache: CacheSnapshot {
                entries: cache.entries as u64,
                max_entries: cache.max_entries as u64,
                hits: cache.hits,
                misses: cache.misses,
                insertions: cache.insertions,
                evictions: cache.evictions,
                hit_rate_pct: hit_rate,
            },
            rpz: RpzSnapshot {
                rules: rpz_rules,
                zones: rpz_zone_count,
                hits: rpz_total_hits,
                per_zone: rpz_zones
                    .into_iter()
                    .map(|z| ZoneSnapshot {
                        name: z.name,
                        rules: z.rules,
                        hits: z.hits,
                    })
                    .collect(),
            },
        }
    }

    fn cmd_top_blocked(&self, n: usize) -> String {
        let n = n.clamp(1, 1000);
        let items = match &self.events {
            Some(e) => e
                .top_blocked(n)
                .into_iter()
                .map(|(qname, hits)| TopItem { qname, hits })
                .collect(),
            None => Vec::new(),
        };
        serde_json::to_string(&TopResponse { items }).unwrap_or_else(|e| format!("ERROR: {}", e))
    }

    fn cmd_reload_rpz(&self) -> String {
        match &self.rpz {
            Some(rpz) => match rpz.reload_all() {
                Ok(n) => format!("{{\"ok\":true,\"rules\":{}}}", n),
                Err(e) => format!("{{\"ok\":false,\"error\":{:?}}}", e.to_string()),
            },
            None => "{\"ok\":false,\"error\":\"rpz not configured\"}".to_string(),
        }
    }

    async fn cmd_watch(
        &self,
        writer: &mut tokio::net::unix::OwnedWriteHalf,
        secs: u64,
    ) -> anyhow::Result<()> {
        let mut tick = tokio::time::interval(Duration::from_secs(secs));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tick.tick().await;
            let snap = self.snapshot();
            let mut line = match serde_json::to_string(&snap) {
                Ok(s) => s,
                Err(e) => format!("{{\"error\":{:?}}}", e.to_string()),
            };
            line.push('\n');
            if writer.write_all(line.as_bytes()).await.is_err() {
                return Ok(());
            }
            if writer.flush().await.is_err() {
                return Ok(());
            }
        }
    }

    async fn cmd_tail_blocks(
        &self,
        writer: &mut tokio::net::unix::OwnedWriteHalf,
        replay: usize,
    ) -> anyhow::Result<()> {
        let Some(events) = self.events.clone() else {
            writer
                .write_all(b"{\"error\":\"events not configured\"}\n")
                .await?;
            return Ok(());
        };

        // Subscribe BEFORE replaying so we don't miss anything between the two.
        let mut rx = events.subscribe();
        if replay > 0 {
            for ev in events.recent(replay) {
                let mut line = serde_json::to_string(&ev)?;
                line.push('\n');
                if writer.write_all(line.as_bytes()).await.is_err() {
                    return Ok(());
                }
            }
            writer.flush().await.ok();
        }

        loop {
            match rx.recv().await {
                Ok(ev) => {
                    let mut line = match serde_json::to_string(&ev) {
                        Ok(s) => s,
                        Err(_) => continue,
                    };
                    line.push('\n');
                    if writer.write_all(line.as_bytes()).await.is_err() {
                        return Ok(());
                    }
                    if writer.flush().await.is_err() {
                        return Ok(());
                    }
                }
                Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {
                    // Slow client — keep going, drop the missed events.
                    continue;
                }
                Err(tokio::sync::broadcast::error::RecvError::Closed) => return Ok(()),
            }
        }
    }

    fn cmd_flush_cache(&self) -> String {
        self.cache.flush();
        "OK: cache flushed".to_string()
    }

    fn cmd_flush_name(&self, name: &str) -> String {
        match crate::protocol::name::DnsName::from_str(name) {
            Ok(dns_name) => {
                self.cache.flush_name(&dns_name);
                format!("OK: flushed entries for {}", name)
            }
            Err(e) => format!("ERROR: invalid name '{}': {}", name, e),
        }
    }

    fn cmd_help(&self) -> String {
        "Commands:\n\
         stats             - Cache statistics (text)\n\
         stats-json        - Full snapshot as JSON (cache + RPZ + per-zone)\n\
         watch <secs>      - Stream stats-json every N seconds (1..60)\n\
         tail-blocks [N]   - Replay last N block events then live-tail (JSONL)\n\
         top-blocked [N]   - Top N blocked qnames (JSON)\n\
         reload-rpz        - Rebuild RPZ state from disk\n\
         flush-cache       - Flush all cache entries\n\
         flush-name <n>    - Flush cache entries for a domain\n\
         ping              - Liveness check\n\
         version           - Server version\n\
         help              - Show this help\n\
         OK"
        .to_string()
    }
}

#[derive(serde::Serialize)]
struct StatsSnapshot {
    ts: u64,
    cache: CacheSnapshot,
    rpz: RpzSnapshot,
}

#[derive(serde::Serialize)]
struct CacheSnapshot {
    entries: u64,
    max_entries: u64,
    hits: u64,
    misses: u64,
    insertions: u64,
    evictions: u64,
    hit_rate_pct: f64,
}

#[derive(serde::Serialize)]
struct RpzSnapshot {
    rules: u64,
    zones: u64,
    hits: u64,
    per_zone: Vec<ZoneSnapshot>,
}

#[derive(serde::Serialize)]
struct ZoneSnapshot {
    name: String,
    rules: u64,
    hits: u64,
}

#[derive(serde::Serialize)]
struct TopResponse {
    items: Vec<TopItem>,
}

#[derive(serde::Serialize)]
struct TopItem {
    qname: String,
    hits: u64,
}

fn now_ms() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_command_parsing() {
        let cache = CacheStore::new(1000, 60, 86400, 300);
        let server = ControlServer::new(cache);

        assert!(server.handle_command("ping").contains("PONG"));
        assert!(server.handle_command("version").contains("rDNS"));
        assert!(server.handle_command("stats").contains("cache.entries="));
        assert!(server.handle_command("flush-cache").contains("OK"));
        assert!(server.handle_command("help").contains("Commands:"));
        assert!(server.handle_command("unknown").contains("ERROR"));
        assert!(server.handle_command("flush-name").contains("ERROR"));
        assert!(server
            .handle_command("flush-name example.com")
            .contains("OK"));
    }

    #[test]
    fn test_stats_json_is_valid_json() {
        let cache = CacheStore::new(1000, 60, 86400, 300);
        let server = ControlServer::new(cache);
        let out = server.handle_command("stats-json");
        let v: serde_json::Value = serde_json::from_str(&out).expect("valid JSON");
        assert!(v["cache"]["max_entries"].is_number());
        assert!(v["rpz"]["rules"].is_number());
    }

    #[test]
    fn test_reload_rpz_without_engine() {
        let cache = CacheStore::new(1000, 60, 86400, 300);
        let server = ControlServer::new(cache);
        assert!(server.handle_command("reload-rpz").contains("not configured"));
    }

    #[test]
    fn test_top_blocked_empty() {
        let cache = CacheStore::new(1000, 60, 86400, 300);
        let server = ControlServer::new(cache);
        let out = server.handle_command("top-blocked 10");
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["items"].as_array().unwrap().len(), 0);
    }
}
