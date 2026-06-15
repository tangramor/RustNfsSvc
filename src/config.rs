use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

const DEFAULT_CONFIG_PATH: &str = "C:\\ProgramData\\RustNfsSvc\\config.toml";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub nfs: NfsConfig,
    pub exports: ExportsConfig,
    pub logging: LoggingConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NfsConfig {
    #[serde(default = "default_listen_address")]
    pub listen_address: String,
    #[serde(default = "default_enable_v3")]
    pub enable_v3: bool,
    #[serde(default = "default_enable_v4")]
    pub enable_v4: bool,
    #[serde(default = "default_threads")]
    pub threads: usize,
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

// Default functions
fn default_listen_address() -> String {
    "0.0.0.0:2049".to_string()
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
                enable_v3: default_enable_v3(),
                enable_v4: default_enable_v4(),
                threads: default_threads(),
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
        }
    }
}

pub fn load_config() -> Result<Config> {
    // Priority: RUSTNFSSVC_CONFIG env var > ./config.toml > default Windows path
    let config_path = if let Ok(env_path) = std::env::var("RUSTNFSSVC_CONFIG") {
        PathBuf::from(env_path)
    } else if PathBuf::from("config.toml").exists() {
        PathBuf::from("config.toml")
    } else {
        PathBuf::from(DEFAULT_CONFIG_PATH)
    };

    // If config file doesn't exist, create default
    if !config_path.exists() {
        eprintln!(
            "WARNING: Config file not found at {}, using defaults",
            DEFAULT_CONFIG_PATH
        );
        return Ok(Config::default());
    }

    let config_content = fs::read_to_string(&config_path)
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

    Ok(config)
}

pub fn create_default_config(config_path: &Path) -> Result<()> {
    let default_config = Config::default();
    let config_str = toml::to_string_pretty(&default_config)?;

    // Create parent directories if they don't exist
    if let Some(parent) = config_path.parent() {
        fs::create_dir_all(parent).with_context(|| {
            format!("Failed to create config directory {}", parent.display())
        })?;
    }

    fs::write(config_path, config_str).with_context(|| {
        format!("Failed to write config file to {}", config_path.display())
    })?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = Config::default();
        assert_eq!(config.nfs.listen_address, "0.0.0.0:2049");
        assert!(config.nfs.enable_v3);
        assert!(config.nfs.enable_v4);
        assert_eq!(config.nfs.threads, 4);
    }

    #[test]
    fn test_parse_config() {
        let config_str = r#"
[[exports.entries]]
path = "C:\\test_exports"
allowed_clients = ["*"]

[nfs]
listen_address = "0.0.0.0:2049"
enable_v3 = true
enable_v4 = false
threads = 8

[logging]
level = "debug"
file = "C:\\test.log"
"#;

        let config: Config = toml::from_str(config_str).unwrap();
        assert_eq!(config.nfs.threads, 8);
        assert_eq!(config.logging.level, "debug");
    }
}
