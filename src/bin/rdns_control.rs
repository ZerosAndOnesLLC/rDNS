use clap::{Parser, Subcommand};
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(name = "rdns-control", about = "rDNS control interface")]
struct Args {
    /// Path to control socket
    #[arg(short, long, default_value = "/var/run/rdns/control.sock")]
    socket: PathBuf,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Show server statistics
    Stats,
    /// Flush the entire cache
    FlushCache,
    /// Flush cache entries for a specific domain
    FlushName { name: String },
    /// Ping the server
    Ping,
    /// Show server version
    Version,
}

fn main() {
    let args = Args::parse();

    let command_str = match &args.command {
        Command::Stats => "stats".to_string(),
        Command::FlushCache => "flush-cache".to_string(),
        Command::FlushName { name } => format!("flush-name {}", name),
        Command::Ping => "ping".to_string(),
        Command::Version => "version".to_string(),
    };

    match send_command(&args.socket, &command_str) {
        Ok(response) => {
            println!("{}", response);
        }
        Err(e) => {
            eprintln!("Error: {}", e);
            eprintln!(
                "Is rDNS running? Check socket path: {}",
                args.socket.display()
            );
            std::process::exit(1);
        }
    }
}

fn send_command(socket_path: &PathBuf, command: &str) -> Result<String, Box<dyn std::error::Error>> {
    let mut stream = UnixStream::connect(socket_path)?;
    stream.set_read_timeout(Some(std::time::Duration::from_secs(5)))?;

    writeln!(stream, "{}", command)?;
    stream.flush()?;

    let reader = BufReader::new(&stream);
    let mut response = String::new();

    for line in reader.lines() {
        let line = line?;
        response.push_str(&line);
        response.push('\n');
        if line.starts_with("OK") || line.starts_with("ERROR") || line.starts_with("PONG") {
            break;
        }
    }

    Ok(response.trim_end().to_string())
}
