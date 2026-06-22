use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

// Import path extension utilities for long-path support.
// config.rs uses a path-local import because it cannot use `crate::path_ext`
// (it is compiled as part of the binary crate but loaded early before other
// modules are known).  We re-implement a tiny version inline.
#[cfg(windows)]
fn extended(path: &Path) -> PathBuf {
    let s = path.to_string_lossy();
    if s.starts_with(r"\\?\") { return path.to_path_buf(); }
    if path.is_absolute() {
        PathBuf::from(format!(r"\\?\{}", s.replace('/', "\\")))
    } else {
        path.to_path_buf()
    }
}
#[cfg(not(windows))]
#[inline]
fn extended(path: &Path) -> PathBuf { path.to_path_buf() }

const DEFAULT_CONFIG_PATH: &str = "C:\\ProgramData\\RustNfsSvc\\config.toml";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub nfs: NfsConfig,
    pub exports: ExportsConfig,
    pub logging: LoggingConfig,
    #[serde(default)]
    pub tls: TlsConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NfsConfig {
    #[serde(default = "default_listen_address")]
    pub listen_address: String,
    #[serde(default = "default_bind_ip")]
    pub bind_ip: String,
    #[serde(default = "default_enable_v3")]
    pub enable_v3: bool,
    #[serde(default = "default_enable_v4")]
    pub enable_v4: bool,
    #[serde(default = "default_threads")]
    pub threads: usize,
    /// SEC-025: Maximum concurrent TCP connections.
    /// New connections beyond this limit are rejected until existing ones close.
    /// Default: 128
    #[serde(default = "default_max_connections")]
    pub max_connections: usize,
    /// SEC-025: Maximum new connections per second from a single IP.
    /// Connections exceeding this rate are temporarily rejected.
    /// Default: 10
    #[serde(default = "default_max_conn_rate_per_ip")]
    pub max_conn_rate_per_ip: usize,
    /// SEC-026: Enable/disable UDP listener.
    /// UDP NFS is susceptible to source address spoofing and reflection attacks.
    /// Disable in production if only TCP is needed.
    /// Default: true (for backward compatibility)
    #[serde(default = "default_enable_udp")]
    pub enable_udp: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportsConfig {
    pub entries: Vec<ExportEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportEntry {
    pub path: String,
    #[serde(default)]
    pub alias: Option<String>,
    pub allowed_clients: Vec<String>,
    #[serde(default)]
    pub options: Vec<String>,
    #[serde(default)]
    pub description: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggingConfig {
    #[serde(default = "default_log_level")]
    pub level: String,
    #[serde(default = "default_log_file")]
    pub file: String,
    #[serde(default = "default_max_log_size_mb")]
    pub max_log_size_mb: usize,
    #[serde(default = "default_max_log_files")]
    pub max_log_files: usize,
}

/// SEC-015: TLS configuration for encrypted transport.
/// When enabled, all NFS traffic will be encrypted using TLS.
/// Currently a placeholder for future implementation — for now,
/// use VPN or SSH tunneling for encrypted transport.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub cert_path: Option<String>,
    #[serde(default)]
    pub key_path: Option<String>,
}

impl Default for TlsConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            cert_path: None,
            key_path: None,
        }
    }
}

// Default functions
fn default_listen_address() -> String {
    "0.0.0.0:2049".to_string()
}

fn default_bind_ip() -> String {
    "0.0.0.0".to_string()
}

fn default_enable_v3() -> bool {
    true
}

fn default_enable_v4() -> bool {
    true
}

fn default_threads() -> usize {
    4
}

fn default_max_connections() -> usize {
    128
}

fn default_max_conn_rate_per_ip() -> usize {
    60 // NFS clients open multiple TCP connections (portmap/mount/nfs) per mount; 10 is too low
}

fn default_enable_udp() -> bool {
    true
}

fn default_log_level() -> String {
    "info".to_string()
}

fn default_log_file() -> String {
    "C:\\ProgramData\\RustNfsSvc\\logs\\rustnfssvc.log".to_string()
}

fn default_max_log_size_mb() -> usize {
    100
}

fn default_max_log_files() -> usize {
    10
}

impl Default for Config {
    fn default() -> Self {
        Self {
            nfs: NfsConfig {
                listen_address: default_listen_address(),
                bind_ip: default_bind_ip(),
                enable_v3: default_enable_v3(),
                enable_v4: default_enable_v4(),
                threads: default_threads(),
                max_connections: default_max_connections(),
                max_conn_rate_per_ip: default_max_conn_rate_per_ip(),
                enable_udp: default_enable_udp(),
            },
            exports: ExportsConfig {
                entries: vec![],
            },
            logging: LoggingConfig {
                level: default_log_level(),
                file: default_log_file(),
                max_log_size_mb: default_max_log_size_mb(),
                max_log_files: default_max_log_files(),
            },
            tls: TlsConfig::default(),
        }
    }
}

/// SEC-023: Check config file permissions and warn if too permissive.
///
/// On Windows, the ideal is that config.toml is only accessible to
/// Administrators and the service account. Since we can't fully inspect
/// DACLs from pure Rust, we do:
/// 1. Check if the file has the read-only attribute set (good).
/// 2. If not, check if the parent directory is C:\ProgramData (standard
///    location) and warn about securing it.
/// 3. Always suggest running `icacls` to restrict permissions.
fn check_config_file_permissions(config_path: &Path) {
    if !config_path.exists() {
        return;
    }

    match fs::metadata(config_path) {
        Ok(metadata) => {
            #[cfg(windows)]
            {
                use std::os::windows::fs::MetadataExt;
                let attrs = metadata.file_attributes();
                const FILE_ATTRIBUTE_READONLY: u32 = 0x00000001;
                if attrs & FILE_ATTRIBUTE_READONLY != 0 {
                    // Read-only attribute is set — file cannot be accidentally modified
                    return;
                }
            }

            // File is not read-only; warn about permissions
            let path_str = config_path.display();
            eprintln!(
                "WARNING (SEC-023): Config file {} is not marked read-only. \
                 Recommend restricting permissions:\n  \
                 icacls \"{}\" /inheritance:r /grant Administrators:F /grant SYSTEM:F",
                path_str, path_str
            );
        }
        Err(e) => {
            eprintln!(
                "WARNING (SEC-023): Could not check config file permissions for {}: {}",
                config_path.display(), e
            );
        }
    }
}

pub fn load_config() -> Result<Config> {
    // Priority: RUSTNFSSVC_CONFIG env var > ./config.toml > default Windows path
    let (config_path, from_env) = if let Ok(env_path) = std::env::var("RUSTNFSSVC_CONFIG") {
        // SEC-024: Warn about config path override via environment variable.
        // In production, this could be used to redirect the service to a
        // malicious config file. Only use in development/testing.
        eprintln!(
            "WARNING (SEC-024): Config path overridden by RUSTNFSSVC_CONFIG environment variable: {}",
            env_path
        );
        eprintln!(
            "  If this is not intentional, remove the RUSTNFSSVC_CONFIG environment variable."
        );

        let path = PathBuf::from(&env_path);

        // SEC-024: Validate that the env-provided path is not obviously suspicious
        if env_path.contains("..") {
            eprintln!(
                "WARNING (SEC-024): Config path contains '..' which may indicate path traversal: {}",
                env_path
            );
        }

        // SEC-024: When running as a Windows Service (under SYSTEM),
        // environment variables may be injected. Warn more strongly.
        #[cfg(windows)]
        {
            // Check if we appear to be running as a service (no interactive session)
            if std::env::var("SESSIONNAME").is_err() {
                eprintln!(
                    "WARNING (SEC-024): Running in non-interactive session with RUSTNFSSVC_CONFIG set. \
                     This may indicate a service configuration attack."
                );
            }
        }

        (path, true)
    } else if PathBuf::from("config.toml").exists() {
        (PathBuf::from("config.toml"), false)
    } else {
        (PathBuf::from(DEFAULT_CONFIG_PATH), false)
    };

    // If config file doesn't exist, create default
    if !config_path.exists() {
        eprintln!(
            "WARNING: Config file not found at {}, using defaults",
            DEFAULT_CONFIG_PATH
        );
        return Ok(Config::default());
    }

    let _ = from_env; // used for security audit logging above

    // SEC-023: Check config file permissions.
    // On Windows, verify the file is not world-writable and warn if
    // permissions are too loose. A comprehensive ACL check requires
    // Win32 APIs; here we do a best-effort check.
    check_config_file_permissions(&config_path);

    let config_content = fs::read_to_string(extended(&config_path))
        .with_context(|| format!("Failed to read config file from {}", config_path.display()))?;

    let config: Config = toml::from_str(&config_content)
        .with_context(|| "Failed to parse config file")?;

    // Validate exports paths
    for entry in &config.exports.entries {
        let path = Path::new(&entry.path);
        if !path.exists() {
            eprintln!("WARNING: Export path does not exist: {}", entry.path);
        }
    }

    // SEC-015: Warn about unencrypted transport
    if !config.tls.enabled {
        eprintln!("WARNING: TLS is not enabled. All NFS traffic is unencrypted. \
                   Consider enabling TLS or using VPN/SSH tunneling for production use.");
    } else {
        // Validate TLS cert/key paths when TLS is enabled
        if config.tls.cert_path.is_none() || config.tls.key_path.is_none() {
            eprintln!("WARNING: TLS is enabled but cert_path or key_path is not configured. \
                       TLS will not be activated.");
        }
        if let Some(ref cert) = config.tls.cert_path {
            if !Path::new(cert).exists() {
                eprintln!("WARNING: TLS certificate file not found: {}", cert);
            }
        }
        if let Some(ref key) = config.tls.key_path {
            if !Path::new(key).exists() {
                eprintln!("WARNING: TLS key file not found: {}", key);
            }
        }
    }

    Ok(config)
}

pub fn create_default_config(config_path: &Path) -> Result<()> {
    let default_config = Config::default();
    let config_str = toml::to_string_pretty(&default_config)?;

    // Create parent directories if they don't exist
    if let Some(parent) = config_path.parent() {
        fs::create_dir_all(extended(parent)).with_context(|| {
            format!("Failed to create config directory {}", parent.display())
        })?;
    }

    fs::write(extended(config_path), config_str).with_context(|| {
        format!("Failed to write config file to {}", config_path.display())
    })?;

    // SEC-023: Attempt to restrict permissions on the newly created config file.
    // On Windows, set the read-only attribute as a basic protection.
    #[cfg(windows)]
    {
        // Set read-only attribute via attrib.exe
        let _ = std::process::Command::new("attrib")
            .args(["+R", &config_path.to_string_lossy()])
            .output();
        eprintln!(
            "INFO (SEC-023): Created config file {}. \
             Recommend restricting permissions:\n  \
             icacls \"{}\" /inheritance:r /grant Administrators:F /grant SYSTEM:F",
            config_path.display(),
            config_path.display()
        );
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = Config::default();
        assert_eq!(config.nfs.listen_address, "0.0.0.0:2049");
        assert_eq!(config.nfs.bind_ip, "0.0.0.0");
        assert!(config.nfs.enable_v3);
        assert!(config.nfs.enable_v4);
        assert_eq!(config.nfs.threads, 4);
    }

    #[test]
    fn test_parse_config() {
        let config_str = r#"
[[exports.entries]]
path = "C:\test_exports"
allowed_clients = ["*"]

[nfs]
listen_address = "0.0.0.0:2049"
bind_ip = "0.0.0.0"
enable_v3 = true
enable_v4 = false
threads = 8

[logging]
level = "debug"
file = "C:\test.log"
"#;

        let config: Config = toml::from_str(config_str).unwrap();
        assert_eq!(config.nfs.threads, 8);
        assert_eq!(config.nfs.bind_ip, "0.0.0.0");
        assert_eq!(config.logging.level, "debug");
    }
}
