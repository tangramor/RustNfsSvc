@echo off
REM RustNfsSvc Uninstallation Script
REM This script must be run as Administrator

echo.
echo ========================================
echo   RustNfsSvc Uninstallation Script
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

REM Stop service if running
echo Stopping RustNfsSvc service...
net stop rustnfssvc >nul 2>&1
if %errorLevel% equ 0 (
    echo [OK] Service stopped
) else (
    echo [INFO] Service was not running
)

REM Uninstall service using rustnfssvc.exe uninstall subcommand
echo Uninstalling Windows Service...
target\release\rustnfssvc.exe uninstall

if %errorLevel% equ 0 (
    echo [OK] Service uninstalled
) else (
    echo [WARNING] Failed to uninstall service
)

echo.
echo ========================================
echo   Uninstallation Complete!
echo ========================================
echo.
echo Note: Configuration and log files in C:\ProgramData\RustNfsSvc are preserved.
echo To remove them manually, run:
echo   rmdir /s /q C:\ProgramData\RustNfsSvc
echo.

pause
