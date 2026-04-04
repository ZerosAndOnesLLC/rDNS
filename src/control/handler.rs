use crate::cache::CacheStore;
use std::path::Path;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixListener;

/// Unix socket control server for runtime management.
#[derive(Clone)]
pub struct ControlServer {
    cache: CacheStore,
}

impl ControlServer {
    pub fn new(cache: CacheStore) -> Self {
        Self { cache }
    }

    /// Start listening on the unix control socket.
    pub async fn serve(&self, socket_path: &Path) -> anyhow::Result<()> {
        // Remove existing socket file if present
        let _ = std::fs::remove_file(socket_path);

        // Ensure parent directory exists
        if let Some(parent) = socket_path.parent() {
            std::fs::create_dir_all(parent).ok();
        }

        // Set restrictive umask before binding to avoid TOCTOU race on socket permissions
        #[cfg(unix)]
        let old_umask = unsafe { libc::umask(0o117) }; // Creates socket with 0660

        let listener = UnixListener::bind(socket_path)?;

        #[cfg(unix)]
        unsafe {
            libc::umask(old_umask);
        } // Restore original umask

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
                return Ok(()); // Client disconnected
            }
            if line.len() > 4096 {
                writer.write_all(b"ERROR: command too long\n").await?;
                return Ok(());
            }

            let response = self.handle_command(line.trim());
            writer.write_all(response.as_bytes()).await?;
            writer.write_all(b"\n").await?;
            writer.flush().await?;
        }
    }

    fn handle_command(&self, command: &str) -> String {
        let parts: Vec<&str> = command.split_whitespace().collect();
        if parts.is_empty() {
            return "ERROR: empty command".to_string();
        }

        match parts[0].to_lowercase().as_str() {
            "stats" => self.cmd_stats(),
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
         stats          - Show cache statistics\n\
         flush-cache    - Flush all cache entries\n\
         flush-name <n> - Flush cache entries for a domain\n\
         ping           - Check if server is alive\n\
         version        - Show server version\n\
         help           - Show this help\n\
         OK"
        .to_string()
    }
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
}
