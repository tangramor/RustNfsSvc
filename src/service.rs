use anyhow::{Context, Result};
use std::ffi::OsString;
use std::sync::mpsc;
use std::time::Duration;
use tokio::runtime::Runtime;
use tracing::{error, info, warn};
use windows_service::define_windows_service;
use windows_service::service_control_handler::{register, ServiceControlHandlerResult};
use windows_service::service_dispatcher;
use windows_service::{
    service::{
        ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus,
        ServiceType,
    },
    Error as WsError,
};

use crate::config::load_config;
use crate::exports::ExportsManager;

const SERVICE_NAME: &str = "rustnfssvc";
const SERVICE_DISPLAY_NAME: &str = "Rust NFS Server Service";

/// Define the Windows Service entry point macro.
define_windows_service!(ffi_service_main, service_main);

/// The real service entry point, called by the dispatcher after SCM starts us.
fn service_main(_arguments: Vec<OsString>) {
    info!("SCM: service_main entered");

    // Create a channel to receive stop signal from the control handler
    let (stop_tx, stop_rx) = std::sync::mpsc::channel::<()>();

    // Register service control handler
    let status_handle = match register(SERVICE_NAME, move |control_event| {
        match control_event {
            ServiceControl::Stop | ServiceControl::Shutdown => {
                let _ = stop_tx.send(());
                ServiceControlHandlerResult::NoError
            }
            _ => ServiceControlHandlerResult::NotImplemented,
        }
    }) {
        Ok(handle) => handle,
        Err(e) => {
            error!("Failed to register service control handler: {}", e);
            return;
        }
    };

    // Report SERVICE_START_PENDING
    report_status(
        &status_handle,
        ServiceState::StartPending,
        ServiceExitCode::Win32(0),
        3000,
    );

    // Load config and initialize logging
    let config = match load_config() {
        Ok(c) => std::sync::Arc::new(c),
        Err(e) => {
            error!("Failed to load config: {}", e);
            report_status(
                &status_handle,
                ServiceState::Stopped,
                ServiceExitCode::Win32(1),
                0,
            );
            return;
        }
    };

    if let Err(e) = crate::logging::init(&config.logging) {
        eprintln!("WARNING: logging init failed: {}", e);
    }

    info!("RustNfsSvc Windows Service starting...");

    // Report SERVICE_RUNNING
    report_status(
        &status_handle,
        ServiceState::Running,
        ServiceExitCode::Win32(0),
        0,
    );

    info!("Service state: RUNNING");

    // Create a dedicated tokio Runtime for the NFS server
    let runtime = match Runtime::new() {
        Ok(rt) => rt,
        Err(e) => {
            error!("Failed to create tokio runtime: {}", e);
            report_status(
                &status_handle,
                ServiceState::Stopped,
                ServiceExitCode::Win32(1),
                0,
            );
            return;
        }
    };

    // Pre-load exports
    let exports = std::sync::Arc::new(ExportsManager::new(config.clone()));
    let exports_clone = std::sync::Arc::clone(&exports);

    runtime.block_on(async {
        if let Err(e) = exports_clone.reload_exports_async().await {
            error!("Failed to load exports: {}", e);
        }
    });

    let config_for_nfs = config.clone();
    let server_handle = runtime.spawn(async move {
        let nfs_server = crate::nfs::NfsServer::new(exports_clone, config_for_nfs);
        if let Err(e) = nfs_server.start().await {
            error!("NFS server error: {}", e);
        }
    });

    info!("NFS server started inside service runtime");

    // Wait for stop signal (blocks this thread)
    let _ = stop_rx.recv();

    info!("SCM: received stop/shutdown signal, shutting down...");

    // Report SERVICE_STOP_PENDING
    report_status(
        &status_handle,
        ServiceState::StopPending,
        ServiceExitCode::Win32(0),
        3000,
    );

    // Abort the server task
    server_handle.abort();

    let _ = runtime.shutdown_timeout(Duration::from_secs(5));

    info!("Service stopped");

    // Report SERVICE_STOPPED
    report_status(
        &status_handle,
        ServiceState::Stopped,
        ServiceExitCode::Win32(0),
        0,
    );
}

/// Helper: report service status to SCM.
fn report_status(
    status_handle: &windows_service::service_control_handler::ServiceStatusHandle,
    state: ServiceState,
    exit_code: ServiceExitCode,
    wait_hint: u32,
) {
    let status = ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: state,
        controls_accepted: if state == ServiceState::Running || state == ServiceState::StartPending {
            ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN
        } else {
            ServiceControlAccept::empty()
        },
        exit_code,
        checkpoint: 0,
        wait_hint: Duration::from_millis(wait_hint as u64),
        process_id: None,
    };

    if let Err(e) = status_handle.set_service_status(status) {
        error!("Failed to set service status ({:?}): {}", state, e);
    }
}

/// Run as a Windows Service.
pub fn run_service() -> Result<()> {
    info!("Entering Windows Service mode (calling service_dispatcher::start)");
    service_dispatcher::start(SERVICE_NAME, ffi_service_main)
        .context("Failed to start Windows Service dispatcher")?;
    info!("Windows Service dispatcher returned (service stopped)");
    Ok(())
}

/// Install as a Windows Service using `sc.exe`.
///
/// SEC-013: By default, Windows services run as LocalSystem (highest privilege).
/// This is dangerous for an NFS server that handles untrusted network input.
/// We recommend creating a dedicated service account with minimal permissions.
pub fn install_service() -> Result<()> {
    info!("Installing service {} via sc.exe", SERVICE_NAME);

    let exe_path = std::env::current_exe()
        .context("Failed to get current executable path")?
        .to_string_lossy()
        .to_string();

    let bin_path = format!("\"{}\" service", exe_path);

    // SEC-013: Warn about LocalSystem and recommend a dedicated account.
    // The user can pass account credentials via environment variables:
    //   RUSTNFSSVC_SERVICE_ACCOUNT=.\SvcUser
    //   RUSTNFSSVC_SERVICE_PASSWORD=Password123
    let mut sc_args = vec![
        "create".to_string(),
        SERVICE_NAME.to_string(),
        "binPath=".to_string(),
        bin_path.clone(),
        "start=".to_string(),
        "auto".to_string(),
        "DisplayName=".to_string(),
        SERVICE_DISPLAY_NAME.to_string(),
    ];

    if let Ok(account) = std::env::var("RUSTNFSSVC_SERVICE_ACCOUNT") {
        let password = std::env::var("RUSTNFSSVC_SERVICE_PASSWORD")
            .unwrap_or_default();
        info!("SEC-013: Using custom service account: {}", account);
        sc_args.push("obj=".to_string());
        sc_args.push(account);
        sc_args.push("password=".to_string());
        sc_args.push(password);
    } else {
        eprintln!("⚠️  SEC-013 WARNING: Service will run as LocalSystem (highest privilege).");
        eprintln!("   This is a security risk for an NFS server handling untrusted network input.");
        eprintln!("   To use a dedicated low-privilege account, set environment variables:");
        eprintln!("     RUSTNFSSVC_SERVICE_ACCOUNT=.\\NfsService");
        eprintln!("     RUSTNFSSVC_SERVICE_PASSWORD=<password>");
        eprintln!("   Then run 'rustnfssvc install' again.");
        eprintln!();
    }

    let output = std::process::Command::new("sc")
        .args(&sc_args)
        .output()
        .context("Failed to run sc.exe create")?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    if !output.status.success() {
        anyhow::bail!(
            "sc.exe create failed (exit {}): {} {}",
            output.status,
            stdout.trim(),
            stderr.trim()
        );
    }

    info!("Service {} installed successfully", SERVICE_NAME);
    info!("sc.exe output: {}", stdout.trim());
    Ok(())
}

/// Uninstall the Windows Service using `sc.exe`.
pub fn uninstall_service() -> Result<()> {
    info!("Uninstalling service {} via sc.exe", SERVICE_NAME);

    let _ = std::process::Command::new("sc")
        .args(["stop", SERVICE_NAME])
        .output();

    let output = std::process::Command::new("sc")
        .args(["delete", SERVICE_NAME])
        .output()
        .context("Failed to run sc.exe delete")?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    if !output.status.success() {
        anyhow::bail!(
            "sc.exe delete failed (exit {}): {} {}",
            output.status,
            stdout.trim(),
            stderr.trim()
        );
    }

    info!("Service {} uninstalled successfully", SERVICE_NAME);
    info!("sc.exe output: {}", stdout.trim());
    Ok(())
}
