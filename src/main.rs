use anyhow::Result;
use std::sync::Arc;
use tokio::signal;
use tracing::{error, info};

mod config;
mod exports;
mod logging;
mod nfs;

#[tokio::main]
async fn main() -> Result<()> {
    // Load configuration first so logging can use config values
    let config = Arc::new(config::load_config()?);

    // Initialize logging using config (level, file path, etc.)
    logging::init(&config.logging)?;

    info!("RustNfsSvc starting...");
    info!("Configuration loaded successfully");

    // Initialize exports
    let exports = Arc::new(exports::ExportsManager::new(config.clone()));
    exports.reload_exports_async().await?;

    // Start NFS server
    info!("Starting NFS server in standalone mode");

    let nfs_server = nfs::NfsServer::new(exports);
    tokio::spawn(async move {
        if let Err(e) = nfs_server.start().await {
            error!("NFS server error: {}", e);
        }
    });

    info!("NFS server started. Press Ctrl+C to stop");

    // Wait for shutdown signal
    signal::ctrl_c().await?;
    info!("Received Ctrl+C, shutting down...");

    info!("RustNfsSvc stopped");
    Ok(())
}
