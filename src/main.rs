use anyhow::Result;
use tracing::{error, info};

mod config;
mod exports;
mod logging;
mod nfs;
mod service;

#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let subcommand = args.get(1).map(|s| s.as_str());

    match subcommand {
        Some("install") => {
            // Install mode: minimal logging to stderr, no file needed
            logging::init_stderr()?;
            service::install_service()?;
            println!("Service installed successfully!");
            println!("To start:     net start rustnfssvc");
            println!("To stop:      net stop rustnfssvc");
            println!("To uninstall: rustnfssvc.exe uninstall");
            return Ok(());
        }
        Some("uninstall") => {
            logging::init_stderr()?;
            service::uninstall_service()?;
            println!("Service uninstalled successfully!");
            return Ok(());
        }
        Some("service") => {
            // Running as a Windows Service (invoked by SCM)
            // Note: logging is initialized inside service_main() after SCM connection
            service::run_service()?;
            return Ok(());
        }
        Some(cmd) => {
            eprintln!("Unknown subcommand: {}", cmd);
            print_usage();
            std::process::exit(1);
        }
        None => {
            // Standalone / foreground mode
            let config = std::sync::Arc::new(config::load_config()?);
            logging::init(&config.logging)?;
            info!("RustNfsSvc starting in standalone mode...");
            info!("Configuration loaded successfully");

            let exports = std::sync::Arc::new(exports::ExportsManager::new(config.clone()));
            exports.reload_exports_async().await?;

            let nfs_server = nfs::NfsServer::new(exports);
            tokio::spawn(async move {
                if let Err(e) = nfs_server.start().await {
                    error!("NFS server error: {}", e);
                }
            });

            info!("NFS server started. Press Ctrl+C to stop.");

            tokio::signal::ctrl_c().await?;
            info!("Received Ctrl+C, shutting down...");
            info!("RustNfsSvc stopped");
            Ok(())
        }
    }
}

fn print_usage() {
    eprintln!("Usage:");
    eprintln!("  rustnfssvc.exe              Run in foreground (standalone mode)");
    eprintln!("  rustnfssvc.exe install      Install as Windows Service (requires Administrator)");
    eprintln!("  rustnfssvc.exe uninstall    Uninstall the Windows Service");
    eprintln!("  rustnfssvc.exe service      Run as Windows Service (invoked by SCM)");
}
