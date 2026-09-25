//! TVC GPG REST server binary.

use clap::Parser;
use metrics::MetricsLayer;
use qos_p256::P256Pair;
use std::io;
use tracing_subscriber::EnvFilter;
use tvc_gpg::allowlist::Allowlist;
use tvc_gpg::cli::Cli;
use tvc_gpg::router::{self, AppState};
use tvc_gpg::team_key::{EXPECTED_SUBKEY_FINGERPRINT, TeamKey};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let cli = Cli::parse();

    let quorum_key = P256Pair::from_hex_file(cli.quorum_file)
        .map_err(|e| io::Error::other(format!("failed to load quorum key: {e:?}")))?;
    let team_key = TeamKey::derive(&quorum_key)?;

    let fingerprint = team_key.subkey_fingerprint();
    if let Some(expected) = EXPECTED_SUBKEY_FINGERPRINT
        && expected != fingerprint
    {
        tracing::error!("team key fingerprint mismatch: expected {expected}, got {fingerprint}");
        std::process::exit(1);
    }

    if cli.print_public_key {
        print!("{}", team_key.public_key_armored()?);
        return Ok(());
    }

    let metrics_layer = MetricsLayer::builder().namespace("tvc").build()?;
    let collector = metrics_layer.collector();

    let allowlist = Allowlist::embedded()?;
    if allowlist.is_empty() {
        tracing::error!("allowlist has no signing capable keys");
        std::process::exit(1);
    }
    tracing::info!(
        "team key subkey fingerprint {fingerprint}, {} allowlisted signing keys",
        allowlist.len()
    );
    let app_state = AppState::new(quorum_key, team_key, allowlist, cli.app_id);
    let app = router::router_with_state(app_state)
        .layer(metrics_layer)
        .route("/metrics", metrics::handler(collector));

    let addr = format!("{}:{}", cli.host, cli.port);
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    tracing::info!("Server listening on {addr}");
    axum::serve(listener, app).await?;
    Ok(())
}
