@echo off
REM RustNfsSvc Installation Script
REM This script must be run as Administrator

echo.
echo ========================================
echo   RustNfsSvc Installation Script
echo ========================================
echo.

REM Check for administrator privileges
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo ERROR: This script must be run as Administrator.
    echo Right-click and select "Run as administrator"
    pause
    exit /b 1
)

echo Checking prerequisites...

REM Check if Rust is installed
rustc --version >nul 2>&1
if %errorLevel% neq 0 (
    echo ERROR: Rust is not installed.
    echo Please install Rust from https://rustup.rs/
    pause
    exit /b 1
)
echo [OK] Rust is installed

REM Create program data directory
set PROGRAM_DATA=C:\ProgramData\RustNfsSvc
if not exist "%PROGRAM_DATA%" (
    echo Creating %PROGRAM_DATA%...
    mkdir "%PROGRAM_DATA%"
)

REM Create logs directory
if not exist "%PROGRAM_DATA%\logs" (
    echo Creating %PROGRAM_DATA%\logs...
    mkdir "%PROGRAM_DATA%\logs"
)

REM Create configuration file if it doesn't exist
if not exist "%PROGRAM_DATA%\config.toml" (
    echo Creating default configuration...
    copy config.example.toml "%PROGRAM_DATA%\config.toml"
    if %errorLevel% equ 0 (
        echo [OK] Configuration file created
        echo Please edit %PROGRAM_DATA%\config.toml to configure exports
    ) else (
        echo WARNING: Failed to copy configuration file
    )
) else (
    echo [OK] Configuration file already exists
)

echo.
echo Building RustNfsSvc...
cargo build --release

if %errorLevel% neq 0 (
    echo.
    echo ERROR: Build failed!
    pause
    exit /b 1
)

echo.
echo [OK] Build successful
echo.

REM Install service using rustnfssvc.exe install subcommand
echo Installing Windows Service...
target\release\rustnfssvc.exe install

if %errorLevel% equ 0 (
    echo.
    echo ========================================
    echo   Installation Complete!
    echo ========================================
    echo.
    echo To start the service, run:
    echo   net start rustnfssvc
    echo.
    echo To stop the service, run:
    echo   net stop rustnfssvc
    echo.
    echo To uninstall the service, run:
    echo   uninstall.bat
    echo.
    echo Configuration file: %PROGRAM_DATA%\config.toml
    echo Log file: %PROGRAM_DATA%\logs\rustnfssvc.log
    echo.
) else (
    echo.
    echo ERROR: Service installation failed!
    echo.
    echo You can install the service manually:
    echo   target\release\rustnfssvc.exe install
    echo.
)

pause
