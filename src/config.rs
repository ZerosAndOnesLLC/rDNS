use serde::Deserialize;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use tracing_appender::non_blocking::WorkerGuard;
use tracing_subscriber::{fmt, EnvFilter};

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    pub server: ServerConfig,

    #[serde(default)]
    pub listeners: ListenersConfig,

    #[serde(default)]
    pub cache: CacheConfig,

    #[serde(default)]
    pub resolver: ResolverConfig,

    #[serde(default)]
    pub authoritative: AuthoritativeConfig,

    #[serde(default)]
    pub control: ControlConfig,

    #[serde(default)]
    pub metrics: MetricsConfig,

    #[serde(default)]
    pub logging: LoggingConfig,

    #[serde(default)]
    pub security: SecurityConfig,

    #[serde(default)]
    pub rpz: RpzConfig,

    #[serde(default)]
    pub edns: EdnsConfig,
}

#[derive(Debug, Clone, Deserialize)]
pub struct EdnsConfig {
    /// UDP payload size we advertise on OPT records — both on responses
    /// (telling clients how big an answer they can send us over UDP) and on
    /// outbound recursive queries (telling upstreams how big a response we
    /// can receive). 1232 is the DNS Flag Day 2020 recommendation. Values
    /// below 512 are clamped — RFC 6891 requires an EDNS responder to
    /// accept at least 512.
    #[serde(default = "default_edns_udp_payload_size")]
    pub udp_payload_size: u16,
}

impl Default for EdnsConfig {
    fn default() -> Self {
        Self {
            udp_payload_size: default_edns_udp_payload_size(),
        }
    }
}

fn default_edns_udp_payload_size() -> u16 {
    crate::protocol::edns::DEFAULT_UDP_PAYLOAD_SIZE
}

#[derive(Debug, Clone, Deserialize)]
pub struct ServerConfig {
    pub mode: ServerMode,

    #[serde(default = "default_user")]
    pub user: String,

    #[serde(default = "default_group")]
    pub group: String,

    #[serde(default = "default_pidfile")]
    pub pidfile: PathBuf,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ServerMode {
    Resolver,
    Authoritative,
    Both,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ListenersConfig {
    #[serde(default = "default_udp_addrs")]
    pub udp: Vec<SocketAddr>,

    #[serde(default = "default_tcp_addrs")]
    pub tcp: Vec<SocketAddr>,

    #[serde(default)]
    pub tls: Option<TlsListenerConfig>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct TlsListenerConfig {
    pub addresses: Vec<SocketAddr>,
    pub cert: PathBuf,
    pub key: PathBuf,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CacheConfig {
    #[serde(default = "default_max_entries")]
    pub max_entries: usize,

    #[serde(default = "default_max_ttl")]
    pub max_ttl: u32,

    #[serde(default = "default_min_ttl")]
    pub min_ttl: u32,

    #[serde(default = "default_negative_ttl")]
    pub negative_ttl: u32,

    /// Serve-stale (RFC 8767): when enabled, expired cache entries are
    /// retained for `stale_max_ttl` seconds and returned to clients when
    /// upstream resolution fails.
    #[serde(default = "default_true")]
    pub serve_stale: bool,

    /// How long an expired entry remains eligible for serve-stale. RFC
    /// 8767 suggests 1-3 days.
    #[serde(default = "default_stale_max_ttl")]
    pub stale_max_ttl: u32,

    /// TTL sent to clients on stale answers. Small values (default 30 s,
    /// matching RFC 8767) make clients re-query soon.
    #[serde(default = "default_stale_answer_ttl")]
    pub stale_answer_ttl: u32,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ResolverConfig {
    #[serde(default)]
    pub forwarders: Vec<String>,

    #[serde(default = "default_true")]
    pub dnssec: bool,

    #[serde(default = "default_true")]
    pub qname_minimization: bool,

    #[serde(default = "default_max_recursion_depth")]
    pub max_recursion_depth: u8,

    /// Per-domain forwarding: queries matching a zone name are forwarded
    /// to zone-specific upstream servers instead of the global forwarders.
    #[serde(default)]
    pub forward_zones: Vec<ForwardZoneConfig>,

    /// Wall-clock ceiling for a single client query's resolution. Applied
    /// uniformly across UDP/TCP/DoT listeners. Zero or unset → built-in
    /// per-transport defaults (UDP 3s, TCP/DoT 30s). Clients that time out
    /// under this ceiling will retry — keep it shorter than the stub
    /// resolver's first retry (5s on glibc/BSD libc) for UDP if you want
    /// the client retry to win over the server's slow answer.
    #[serde(default)]
    pub query_timeout_ms: u64,
}

/// Per-domain forwarding configuration.
#[derive(Debug, Clone, Deserialize)]
pub struct ForwardZoneConfig {
    /// Domain name to match (e.g. "corp.example.com").
    pub name: String,
    /// Upstream DNS servers for this domain (IP or IP:port).
    pub forwarders: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AuthoritativeConfig {
    #[serde(default = "default_auth_source")]
    pub source: AuthSource,

    #[serde(default = "default_zone_dir")]
    pub directory: PathBuf,

    #[serde(default)]
    pub database: Option<DatabaseConfig>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum AuthSource {
    ZoneFiles,
    Database,
    None,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DatabaseConfig {
    pub connection: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ControlConfig {
    #[serde(default = "default_control_socket")]
    pub socket: PathBuf,
}

#[derive(Debug, Clone, Deserialize)]
pub struct MetricsConfig {
    #[serde(default)]
    pub enabled: bool,

    #[serde(default = "default_metrics_addr")]
    pub address: SocketAddr,
}

#[derive(Debug, Clone, Deserialize)]
pub struct LoggingConfig {
    #[serde(default = "default_log_level")]
    pub level: String,

    #[serde(default = "default_log_format")]
    pub format: LogFormat,

    /// Emit one INFO line per resolved query (source, qname, qtype, rcode,
    /// transport). Off by default — busy resolvers can produce a lot of
    /// volume and operators should opt in.
    #[serde(default)]
    pub query_log: bool,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum LogFormat {
    Json,
    Text,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SecurityConfig {
    #[serde(default = "default_true")]
    pub sandbox: bool,

    #[serde(default = "default_rate_limit")]
    pub rate_limit: u32,

    /// CIDR ranges allowed to make recursive queries.
    /// If empty, all sources are allowed (open resolver — not recommended for public-facing servers).
    /// Example: ["127.0.0.0/8", "::1/128", "10.0.0.0/8", "192.168.0.0/16"]
    #[serde(default)]
    pub allow_recursion: Vec<String>,
}

// --- Defaults ---

fn default_user() -> String {
    "rdns".into()
}
fn default_group() -> String {
    "rdns".into()
}
fn default_pidfile() -> PathBuf {
    "/var/run/rdns/rdns.pid".into()
}
fn default_udp_addrs() -> Vec<SocketAddr> {
    vec!["0.0.0.0:53".parse().unwrap(), "[::]:53".parse().unwrap()]
}
fn default_tcp_addrs() -> Vec<SocketAddr> {
    vec!["0.0.0.0:53".parse().unwrap(), "[::]:53".parse().unwrap()]
}
fn default_max_entries() -> usize {
    1_000_000
}
fn default_max_ttl() -> u32 {
    86400
}
fn default_min_ttl() -> u32 {
    60
}
fn default_negative_ttl() -> u32 {
    300
}
fn default_stale_max_ttl() -> u32 {
    86400 // 1 day, RFC 8767 suggests 1-3
}
fn default_stale_answer_ttl() -> u32 {
    30 // RFC 8767 §5
}
fn default_true() -> bool {
    true
}
fn default_max_recursion_depth() -> u8 {
    30
}
fn default_auth_source() -> AuthSource {
    AuthSource::None
}
fn default_zone_dir() -> PathBuf {
    "/etc/rdns/zones".into()
}
fn default_control_socket() -> PathBuf {
    "/var/run/rdns/control.sock".into()
}
fn default_metrics_addr() -> SocketAddr {
    "127.0.0.1:9153".parse().unwrap()
}
fn default_log_level() -> String {
    "info".into()
}
fn default_log_format() -> LogFormat {
    LogFormat::Json
}
fn default_rate_limit() -> u32 {
    1000
}

// --- Default trait impls ---

impl Default for ListenersConfig {
    fn default() -> Self {
        Self {
            udp: default_udp_addrs(),
            tcp: default_tcp_addrs(),
            tls: None,
        }
    }
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            max_entries: default_max_entries(),
            max_ttl: default_max_ttl(),
            min_ttl: default_min_ttl(),
            negative_ttl: default_negative_ttl(),
            serve_stale: true,
            stale_max_ttl: default_stale_max_ttl(),
            stale_answer_ttl: default_stale_answer_ttl(),
        }
    }
}

impl Default for ResolverConfig {
    fn default() -> Self {
        Self {
            forwarders: Vec::new(),
            dnssec: true,
            qname_minimization: true,
            max_recursion_depth: 30,
            forward_zones: Vec::new(),
            query_timeout_ms: 0,
        }
    }
}

impl Default for AuthoritativeConfig {
    fn default() -> Self {
        Self {
            source: AuthSource::None,
            directory: default_zone_dir(),
            database: None,
        }
    }
}

impl Default for ControlConfig {
    fn default() -> Self {
        Self {
            socket: default_control_socket(),
        }
    }
}

impl Default for MetricsConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            address: default_metrics_addr(),
        }
    }
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: default_log_level(),
            format: LogFormat::Json,
            query_log: false,
        }
    }
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            sandbox: true,
            rate_limit: default_rate_limit(),
            allow_recursion: Vec::new(),
        }
    }
}

/// Response Policy Zone configuration.
#[derive(Debug, Clone, Deserialize, Default)]
pub struct RpzConfig {
    /// RPZ zone files to load at startup.
    #[serde(default)]
    pub zones: Vec<RpzZoneConfig>,
}

/// A single RPZ zone file reference.
#[derive(Debug, Clone, Deserialize)]
pub struct RpzZoneConfig {
    /// Policy zone name (e.g. "rpz.local").
    pub name: String,
    /// Path to the RPZ zone file.
    pub file: PathBuf,
}

impl Config {
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| anyhow::anyhow!("Failed to read config file {}: {}", path.display(), e))?;
        let config: Config = toml::from_str(&content)
            .map_err(|e| anyhow::anyhow!("Failed to parse config: {}", e))?;
        Ok(config)
    }
}

/// Initialise the tracing subscriber with a non-blocking writer.
///
/// Every `info!`/`debug!` goes through a bounded MPSC channel drained by a
/// dedicated background thread. When the channel fills, lines are dropped
/// instead of blocking the caller — DNS response paths must never stall on
/// log I/O. The returned `WorkerGuard` keeps the drain thread alive; it
/// must be bound to a `main`-lifetime variable (drop = flush + shutdown).
#[must_use = "drop the returned guard only when the process exits — losing it stops log output"]
pub fn init_logging(cfg: &LoggingConfig) -> WorkerGuard {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(&cfg.level));

    let (writer, guard) = tracing_appender::non_blocking(std::io::stdout());

    match cfg.format {
        LogFormat::Json => {
            fmt()
                .json()
                .with_env_filter(filter)
                .with_writer(writer)
                .init();
        }
        LogFormat::Text => {
            fmt()
                .with_env_filter(filter)
                .with_writer(writer)
                .init();
        }
    }

    guard
}
