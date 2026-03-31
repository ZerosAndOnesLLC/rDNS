use serde::Deserialize;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
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
        }
    }
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            sandbox: true,
            rate_limit: default_rate_limit(),
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

pub fn init_logging(cfg: &LoggingConfig) {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(&cfg.level));

    match cfg.format {
        LogFormat::Json => {
            fmt()
                .json()
                .with_env_filter(filter)
                .init();
        }
        LogFormat::Text => {
            fmt()
                .with_env_filter(filter)
                .init();
        }
    }
}
