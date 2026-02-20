pub mod api;
pub mod crypto;
pub mod dns;
pub mod manifest;
pub mod netlock;
pub mod recovery;
pub mod server;
pub mod wireguard;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "airvpn", about = "AirVPN WireGuard client")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Connect to AirVPN
    Connect {
        /// Server name (auto-select if omitted)
        #[arg(long)]
        server: Option<String>,
        /// Disable network lock
        #[arg(long)]
        no_lock: bool,
        /// Allow LAN traffic through lock
        #[arg(long)]
        allow_lan: bool,
    },
    /// Disconnect from AirVPN
    Disconnect,
    /// Show connection status
    Status,
    /// List available servers
    Servers {
        /// Sort by: latency, load, name
        #[arg(long, default_value = "latency")]
        sort: String,
    },
    /// Clean up stale state after crash
    Recover,
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Connect { server, no_lock, allow_lan } => {
            println!("connect: server={:?} no_lock={} allow_lan={}", server, no_lock, allow_lan);
        }
        Commands::Disconnect => println!("disconnect"),
        Commands::Status => println!("status"),
        Commands::Servers { sort } => println!("servers: sort={}", sort),
        Commands::Recover => println!("recover"),
    }
    Ok(())
}
