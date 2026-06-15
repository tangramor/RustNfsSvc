use anyhow::{Context, Result};
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{error, info};
use windows_service::service::{ServiceControl, ServiceControlAccept};
use windows_service::service_control_handler::{self, ServiceControlHandlerResult};

use crate::exports::ExportsManager;

const SERVICE_NAME: &str = "RustNfsSvc";
const SERVICE_START_MODE: windows_service::service::ServiceStartType =
    windows_service::service::ServiceStartType::AutoStart;
const SERVICE_ERROR_CONTROL: windows_service::service::ServiceErrorControl =
    windows_service::service::ServiceErrorControl::Normal;

pub async fn run_service(exports: Arc<ExportsManager>) -> Result<()> {
    info!("Initializing Windows Service");

    let (shutdown_tx, mut shutdown_rx) = mpsc::channel::<()>(1);

    // Register service control handler with SCM
    let shutdown_tx_for_handler = shutdown_tx.clone();
    let service_name_str = SERVICE_NAME.to_string();
    let status_handle = service_control_handler::register(&service_name_str, move |control_event| {
        match control_event {
            ServiceControl::Stop | ServiceControl::Shutdown => {
                info!("SCM: received stop/shutdown event");
                let _ = shutdown_tx_for_handler.try_send(());
                ServiceControlHandlerResult::NoError
            }
            _ => ServiceControlHandlerResult::NoError,
        }
    }).context("Failed to register service control handler")?;

    // Set service status to running
    let service_status = windows_service::service::ServiceStatus {
        service_type: windows_service::service::ServiceType::OWN_PROCESS,
        current_state: windows_service::service::ServiceState::Running,
        controls_accepted: ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
        exit_code: windows_service::service::ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: std::time::Duration::default(),
        process_id: None,
    };
    status_handle.set_service_status(service_status)
        .context("Failed to set service status to running")?;

    // Start NFS server
    let exports_clone = Arc::clone(&exports);
    let mut server_handle = tokio::spawn(async move {
        let nfs_server = crate::nfs::NfsServer::new(exports_clone);
        if let Err(e) = nfs_server.start().await {
            error!("NFS server error: {}", e);
        }
    });

    info!("NFS server started");

    // Wait for shutdown
    tokio::select! {
        _ = shutdown_rx.recv() => {
            info!("Shutting down service...");
            server_handle.abort();
        }
        result = &mut server_handle => {
            if let Err(e) = result {
                error!("Server task error: {}", e);
            }
        }
    }

    // Set service status to stopped
    let stopped_status = windows_service::service::ServiceStatus {
        service_type: windows_service::service::ServiceType::OWN_PROCESS,
        current_state: windows_service::service::ServiceState::Stopped,
        controls_accepted: ServiceControlAccept::empty(),
        exit_code: windows_service::service::ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: std::time::Duration::default(),
        process_id: None,
    };
    let _ = status_handle.set_service_status(stopped_status);

    info!("Service stopped");
    Ok(())
}

pub fn install_service() -> Result<()> {
    info!("Installing service {}", SERVICE_NAME);

    let manager_access = windows_service::service_manager::ServiceManagerAccess::CONNECT
        | windows_service::service_manager::ServiceManagerAccess::CREATE_SERVICE;

    let service_manager = windows_service::service_manager::ServiceManager::local_computer(None::<&str>, manager_access)?;

    // Get current executable path
    let exe_path = std::env::current_exe()
        .context("Failed to get current executable path")?;

    let service_info = windows_service::service::ServiceInfo {
        name: std::ffi::OsString::from(SERVICE_NAME),
        display_name: std::ffi::OsString::from("Rust NFS Server Service"),
        service_type: windows_service::service::ServiceType::OWN_PROCESS,
        start_type: windows_service::service::ServiceStartType::AutoStart,
        error_control: windows_service::service::ServiceErrorControl::Normal,
        executable_path: exe_path,
        launch_arguments: vec![],
        dependencies: vec![],
        account_name: None,
        account_password: None,
    };

    let _service = service_manager
        .create_service(&service_info, windows_service::service::ServiceAccess::empty())
        .context("Failed to create service")?;

    info!("Service {} installed successfully", SERVICE_NAME);
    Ok(())
}

pub fn uninstall_service() -> Result<()> {
    info!("Uninstalling service {}", SERVICE_NAME);

    let manager_access = windows_service::service_manager::ServiceManagerAccess::CONNECT;
    let service_manager = windows_service::service_manager::ServiceManager::local_computer(None::<&str>, manager_access)?;

    let service_access = windows_service::service::ServiceAccess::DELETE
        | windows_service::service::ServiceAccess::STOP;

    let service = service_manager
        .open_service(SERVICE_NAME, service_access)
        .context("Failed to open service")?;

    // Stop service if running
    let _ = service.stop();

    // Delete service
    service.delete().context("Failed to delete service")?;

    info!("Service {} uninstalled successfully", SERVICE_NAME);
    Ok(())
}

pub fn start_service() -> Result<()> {
    info!("Starting service {}", SERVICE_NAME);

    let manager_access = windows_service::service_manager::ServiceManagerAccess::CONNECT;
    let service_manager = windows_service::service_manager::ServiceManager::local_computer(None::<&str>, manager_access)?;

    let service_access = windows_service::service::ServiceAccess::START;
    let service = service_manager
        .open_service(SERVICE_NAME, service_access)
        .context("Failed to open service")?;

    service.start(&[] as &[&str])
        .context("Failed to start service")?;

    info!("Service {} started successfully", SERVICE_NAME);
    Ok(())
}

pub fn stop_service() -> Result<()> {
    info!("Stopping service {}", SERVICE_NAME);

    let manager_access = windows_service::service_manager::ServiceManagerAccess::CONNECT;
    let service_manager = windows_service::service_manager::ServiceManager::local_computer(None::<&str>, manager_access)?;

    let service_access = windows_service::service::ServiceAccess::STOP;
    let service = service_manager
        .open_service(SERVICE_NAME, service_access)
        .context("Failed to open service")?;

    service.stop()
        .context("Failed to stop service")?;

    info!("Service {} stopped successfully", SERVICE_NAME);
    Ok(())
}
