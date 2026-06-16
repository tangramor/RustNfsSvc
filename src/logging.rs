use anyhow::Result;
use std::path::Path;
use std::sync::OnceLock;
use tracing_subscriber::{
    fmt, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter, Layer,
};

use crate::config::LoggingConfig;

// Keep the guard alive for the entire process lifetime.
// tracing-appender's non_blocking worker thread is tied to the guard;
// dropping it stops log writing immediately.
static _LOG_GUARD: OnceLock<tracing_appender::non_blocking::WorkerGuard> = OnceLock::new();

/// Initialize logging using config values.
///
/// Uses `config.logging.level` as the default log level (overridable by `RUST_LOG` env var),
/// and `config.logging.file` as the log file path. Falls back to hardcoded directories
/// if the configured path is not writable.
pub fn init(config: &LoggingConfig) -> Result<()> {
    // Log level: RUST_LOG env var takes priority, then config, then "info"
    let env_filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(&config.level));

    // Create console layer (stderr so it doesn't pollute stdout)
    let console_layer = fmt::layer()
        .with_writer(std::io::stderr)
        .with_target(true)
        .with_thread_ids(false)
        .with_file(false)
        .with_line_number(false);

    // Try to set up file logging from config
    if let Some(log_dir) = resolve_log_dir(config) {
        let file_appender = tracing_appender::rolling::daily(&log_dir, "rustnfssvc");
        let (non_blocking, guard) = tracing_appender::non_blocking(file_appender);

        // Store guard so it lives as long as the process
        let _ = _LOG_GUARD.set(guard);

        let file_layer = fmt::layer()
            .with_writer(non_blocking)
            .with_target(true)
            .with_thread_ids(true)
            .with_file(true)
            .with_line_number(true)
            .with_ansi(false);

        tracing_subscriber::registry()
            .with(env_filter)
            .with(console_layer)
            .with(file_layer)
            .init();

        eprintln!("Logging to: {}\\rustnfssvc.<date>", log_dir);
        return Ok(());
    }

    // Fallback: console only
    eprintln!(
        "WARNING: Cannot create log directory from config path '{}', using console (stderr) only",
        config.file
    );
    tracing_subscriber::registry()
        .with(env_filter)
        .with(console_layer)
        .init();
    Ok(())
}

/// Initialize minimal stderr-only logging (for install/uninstall subcommands).
///
/// These subcommands run before any config is loaded, so we just use a simple
/// stderr subscriber with INFO level (overridable by `RUST_LOG`).
pub fn init_stderr() -> Result<()> {
    let env_filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info"));

    let console_layer = fmt::layer()
        .with_writer(std::io::stderr)
        .with_target(false)
        .with_thread_ids(false)
        .with_file(false)
        .with_line_number(false);

    tracing_subscriber::registry()
        .with(env_filter)
        .with(console_layer)
        .init();

    Ok(())
}

/// Resolve the log directory from config, with fallback.
///
/// Priority:
/// 1. Directory portion of `config.file` (from config.toml)
/// 2. `C:\ProgramData\RustNfsSvc\logs`
/// 3. `.\logs` (current directory)
///
/// Returns Some(dir) if writable, None if all fail.
fn resolve_log_dir(config: &LoggingConfig) -> Option<String> {
    // Extract directory from configured log file path
    let config_dir = Path::new(&config.file)
        .parent()
        .map(|p| p.to_string_lossy().to_string());

    // Build candidate list: config path first, then fallbacks
    let mut candidates: Vec<String> = Vec::new();
    if let Some(dir) = config_dir {
        candidates.push(dir);
    }
    candidates.push("C:\\ProgramData\\RustNfsSvc\\logs".to_string());
    candidates.push(".\\logs".to_string());

    for log_dir in &candidates {
        if std::fs::create_dir_all(log_dir).is_ok() {
            let test_path = format!("{}\\{}", log_dir, ".write_test");
            if std::fs::write(&test_path, b"test").is_ok() {
                let _ = std::fs::remove_file(&test_path);
                return Some(log_dir.clone());
            }
        }
    }

    None
}
