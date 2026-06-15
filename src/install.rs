use anyhow::{Context, Result};
use tracing::{error, info};

fn main() -> Result<()> {
    // Check if running as administrator
    if !is_admin() {
        eprintln!("Error: This program must be run as Administrator");
        std::process::exit(1);
    }

    info!("Installing RustNfsSvc Windows Service");

    match install_service() {
        Ok(_) => {
            println!("Service installed successfully!");
            println!("To start the service, run: net start rustnfssvc");
            println!("To stop the service, run: net stop rustnfssvc");
            Ok(())
        }
        Err(e) => {
            error!("Failed to install service: {}", e);
            Err(e)
        }
    }
}

fn install_service() -> Result<()> {
    info!("Installing service RustNfsSvc");

    use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};
    use windows_service::service::{ServiceAccess, ServiceErrorControl, ServiceInfo, ServiceStartType, ServiceType};

    let manager_access = ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE;
    let service_manager = ServiceManager::local_computer(None::<&str>, manager_access)?;

    let exe_path = std::env::current_exe()
        .context("Failed to get current executable path")?;

    let service_info = ServiceInfo {
        name: std::ffi::OsString::from("RustNfsSvc"),
        display_name: std::ffi::OsString::from("Rust NFS Server Service"),
        service_type: ServiceType::OWN_PROCESS,
        start_type: ServiceStartType::AutoStart,
        error_control: ServiceErrorControl::Normal,
        executable_path: exe_path,
        launch_arguments: vec![],
        dependencies: vec![],
        account_name: None,
        account_password: None,
    };

    let _service = service_manager
        .create_service(&service_info, ServiceAccess::empty())
        .context("Failed to create service")?;

    info!("Service installed successfully");
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


