use anyhow::{Context, Result};
use tracing::{error, info};

fn main() -> Result<()> {
    // Check if running as administrator
    if !is_admin() {
        eprintln!("Error: This program must be run as Administrator");
        std::process::exit(1);
    }

    info!("Uninstalling RustNfsSvc Windows Service");

    match uninstall_service() {
        Ok(_) => {
            println!("Service uninstalled successfully!");
            Ok(())
        }
        Err(e) => {
            error!("Failed to uninstall service: {}", e);
            Err(e)
        }
    }
}

fn uninstall_service() -> Result<()> {
    info!("Uninstalling service RustNfsSvc");

    use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};
    use windows_service::service::{ServiceAccess, ServiceControl};

    let manager_access = ServiceManagerAccess::CONNECT;
    let service_manager = ServiceManager::local_computer(None::<&str>, manager_access)?;

    let service_access = ServiceAccess::DELETE | ServiceAccess::STOP;
    let service = service_manager
        .open_service("RustNfsSvc", service_access)
        .context("Failed to open service")?;

    // Stop service if running
    let _ = service.stop();

    // Delete service
    service.delete().context("Failed to delete service")?;

    info!("Service uninstalled successfully");
    Ok(())
}

fn is_admin() -> bool {
    use windows::Win32::Security::*;
    use windows::Win32::Foundation::*;

    unsafe {
        let mut token = HANDLE::default();
        if !OpenProcessToken(windows::Win32::System::Threading::GetCurrentProcess(), TOKEN_QUERY, &mut token).as_bool() {
            return false;
        }

        let mut elevation = TOKEN_ELEVATION { TokenIsElevated: 0 };
        let mut return_length = 0u32;

        let result = GetTokenInformation(
            token,
            TokenElevation,
            Some(&mut elevation as *mut _ as *mut _),
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut return_length,
        );

        result.is_ok() && elevation.TokenIsElevated != 0
    }
}


