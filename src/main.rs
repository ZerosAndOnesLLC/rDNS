mod auth;
mod cache;
mod config;
mod control;
mod dnssec;
mod listener;
mod metrics;
mod rpz;
mod security;
mod protocol;
mod resolver;
mod server;

use clap::Parser;
use std::path::PathBuf;
use tracing::info;

#[derive(Parser, Debug)]
#[command(name = "rdns", about = "High-performance DNS server")]
struct Args {
    /// Path to configuration file
    #[arg(short, long, default_value = "/etc/rdns/rdns.toml")]
    config: PathBuf,

    /// Validate config and exit
    #[arg(long)]
    check_config: bool,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    let cfg = config::Config::load(&args.config)?;

    if args.check_config {
        println!("Configuration OK");
        return Ok(());
    }

    // Hold guard for process lifetime — drops only on shutdown, which
    // flushes the async log drain thread. Never discard or shadow.
    let _log_guard = config::init_logging(&cfg.logging);
    listener::set_query_log_enabled(cfg.logging.query_log);
    listener::set_query_timeout_ms(cfg.resolver.query_timeout_ms);

    info!(
        version = env!("CARGO_PKG_VERSION"),
        mode = ?cfg.server.mode,
        "rDNS starting"
    );

    server::run(cfg).await
}
