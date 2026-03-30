use clap::{Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(name = "rdns-control", about = "rDNS control interface")]
struct Args {
    /// Path to control socket
    #[arg(short, long, default_value = "/var/run/rdns/control.sock")]
    socket: String,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Show server statistics
    Stats,
    /// Flush the cache
    FlushCache,
    /// Reload configuration
    Reload,
    /// Reload a specific zone
    ReloadZone { name: String },
}

fn main() {
    let args = Args::parse();
    println!("rdns-control: {:?} (not yet implemented)", args.command);
}
