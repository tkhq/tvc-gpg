//! CLI argument parsing for the TVC GPG server.
use clap::Parser;

/// TVC GPG REST server.
#[derive(Parser, Debug)]
#[command(name = "tvc-gpg", version, about = "TVC GPG REST server")]
pub struct Cli {
    /// IP address to listen on
    #[arg(long, default_value = "127.0.0.1")]
    pub host: String,

    /// Port to listen on
    #[arg(long, default_value = "44020")]
    pub port: u16,

    /// Path to the quorum key file
    #[arg(long, default_value = qos_core::QUORUM_FILE)]
    pub quorum_file: String,

    /// Identifier for this app, included in signed receipts
    #[arg(long)]
    pub app_id: String,

    /// Print the app's public OpenPGP key and exit
    #[arg(long)]
    pub print_public_key: bool,
}
