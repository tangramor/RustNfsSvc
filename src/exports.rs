use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{error, info, warn};

use crate::config::{Config, ExportEntry};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Export {
    pub path: PathBuf,
    pub alias: Option<String>,
    pub allowed_clients: Vec<ipnet::IpNet>,
    pub options: ExportOptions,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportOptions {
    pub read_only: bool,
    pub sync: bool,
    pub no_subtree_check: bool,
    pub root_squash: bool,
    pub secure: bool,
    pub nohide: bool,
}

impl Default for ExportOptions {
    fn default() -> Self {
        Self {
            read_only: false,
            sync: true,
            no_subtree_check: true,
            root_squash: false, // easier for initial testing
            secure: false,      // accept connections from any port
            nohide: false,
        }
    }
}

/// File handle entry: maps a stable handle ID to a real filesystem path
#[derive(Debug, Clone)]
struct FhEntry {
    pub real_path: PathBuf,
    pub export_root: PathBuf,
    pub inode: u64,
    pub gen: u32,
}

/// Exports manager: holds export config and file handle mappings
pub struct ExportsManager {
    config: Arc<Config>,
    exports: Arc<RwLock<HashMap<String, Export>>>,
    /// file handle ID -> FhEntry
    fh_map: Arc<RwLock<HashMap<u64, FhEntry>>>,
    /// real_path -> file handle ID
    path_to_fhid: Arc<RwLock<HashMap<PathBuf, u64>>>,
    fh_counter: Arc<RwLock<u64>>,
}

impl ExportsManager {
    pub fn new(config: Arc<Config>) -> Self {
        Self {
            config,
            exports: Arc::new(RwLock::new(HashMap::new())),
            fh_map: Arc::new(RwLock::new(HashMap::new())),
            path_to_fhid: Arc::new(RwLock::new(HashMap::new())),
            fh_counter: Arc::new(RwLock::new(1u64)),
        }
    }

    pub async fn reload_exports_async(&self) -> Result<()> {
        info!("Reloading exports configuration");

        let mut new_exports = HashMap::new();

        for entry in &self.config.exports.entries {
            let export = self.parse_export_entry(entry)?;

            if !export.path.exists() {
                warn!("Export path does not exist, skipping: {}", export.path.display());
                continue;
            }

            if !export.path.is_dir() {
                warn!("Export path is not a directory, skipping: {}", export.path.display());
                continue;
            }

            let path_str = export.path.to_string_lossy().to_string();
            new_exports.insert(path_str.clone(), export);
            info!("Loaded export: {}", path_str);
        }

        {
            let mut exports_guard = self.exports.write().await;
            *exports_guard = new_exports;
            info!("Exports reloaded: {} active exports", exports_guard.len());
        }

        Ok(())
    }

    pub fn reload_exports(&self) -> Result<()> {
        Ok(())
    }

    fn parse_export_entry(&self, entry: &ExportEntry) -> Result<Export> {
        let path = PathBuf::from(&entry.path);
        let alias = entry.alias.clone();
        let mut options = ExportOptions::default();

        for opt in &entry.options {
            match opt.as_str() {
                "ro" | "read-only" => options.read_only = true,
                "rw" | "read-write" => options.read_only = false,
                "sync" => options.sync = true,
                "async" => options.sync = false,
                "no_subtree_check" => options.no_subtree_check = true,
                "subtree_check" => options.no_subtree_check = false,
                "no_root_squash" => options.root_squash = false,
                "root_squash" => options.root_squash = true,
                "secure" => options.secure = true,
                "insecure" => options.secure = false,
                "nohide" => options.nohide = true,
                "hide" => options.nohide = false,
                _ => warn!("Unknown export option: {}", opt),
            }
        }

        let mut allowed_clients = Vec::new();
        for client in &entry.allowed_clients {
            match client.parse::<ipnet::IpNet>() {
                Ok(net) => allowed_clients.push(net),
                Err(_) => {
                    if let Ok(addr) = client.parse::<std::net::IpAddr>() {
                        let net = match addr {
                            std::net::IpAddr::V4(v4) => {
                                ipnet::IpNet::V4(ipnet::Ipv4Net::new(v4, 32)?)
                            }
                            std::net::IpAddr::V6(v6) => {
                                ipnet::IpNet::V6(ipnet::Ipv6Net::new(v6, 128)?)
                            }
                        };
                        allowed_clients.push(net);
                    } else {
                        warn!("Cannot parse client address: {}", client);
                    }
                }
            }
        }

        if allowed_clients.is_empty() {
            allowed_clients.push("0.0.0.0/0".parse::<ipnet::IpNet>()?);
        }

        Ok(Export {
            path,
            alias,
            allowed_clients,
            options,
        })
    }

    /// Find export by NFS mount path (alias first, then directory name, then full path)
    pub async fn resolve_export_path(&self, nfs_path: &str) -> Option<Export> {
        let exports = self.exports.read().await;

        // 1. Exact alias match
        for export in exports.values() {
            if let Some(ref alias) = export.alias {
                if alias == nfs_path || format!("/{}", alias) == nfs_path {
                    return Some(export.clone());
                }
            }
        }

        // 2. Match by leading path component (Linux clients send e.g. "/exports")
        let stripped = nfs_path.trim_start_matches('/');
        for export in exports.values() {
            let dir_name = export.path.file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("");
            if dir_name == stripped {
                return Some(export.clone());
            }
            if let Some(ref alias) = export.alias {
                if alias == stripped {
                    return Some(export.clone());
                }
            }
        }

        // 3. Exact path
        if let Some(export) = exports.get(nfs_path) {
            return Some(export.clone());
        }

        None
    }

    pub async fn is_client_allowed(&self, client_ip: std::net::IpAddr, export_path: &str) -> bool {
        if let Some(export) = self.resolve_export_path(export_path).await {
            for net in &export.allowed_clients {
                if net.contains(&client_ip) {
                    info!("Client {} allowed for '{}'", client_ip, export_path);
                    return true;
                }
            }
            warn!("Client {} not in allowed list for '{}'", client_ip, export_path);
            false
        } else {
            warn!("Export '{}' not found while checking client {}", export_path, client_ip);
            false
        }
    }

    pub async fn get_export(&self, path: &str) -> Option<Export> {
        self.resolve_export_path(path).await
    }

    pub async fn list_exports(&self) -> Vec<String> {
        let exports = self.exports.read().await;
        exports.keys().cloned().collect()
    }

    /// Returns (real_path, alias) pairs
    pub async fn list_exports_with_aliases(&self) -> Vec<(String, Option<String>)> {
        let exports = self.exports.read().await;
        exports.values()
            .map(|e| (e.path.to_string_lossy().to_string(), e.alias.clone()))
            .collect()
    }

    pub async fn list_export_aliases(&self) -> Vec<String> {
        let exports = self.exports.read().await;
        exports.values().filter_map(|e| e.alias.clone()).collect()
    }

    /// Get the first export's root path, used as a reference for
    /// NFSv4 root handle attribute resolution (e.g., file type = directory).
    pub async fn get_first_export_root(&self) -> Option<PathBuf> {
        let exports = self.exports.read().await;
        exports.values().next().map(|e| e.path.clone())
    }

    /// Allocate or lookup a file handle ID for a real path.
    /// Returns a 32-byte file handle:
    ///   [0..8]   = fhid (u64 big-endian)
    ///   [8..16]  = inode (u64 big-endian)
    ///   [16..20] = generation (u32 big-endian)
    ///   [20..32] = zeros
    pub async fn create_file_handle(&self, export_path: &str) -> Vec<u8> {
        // Resolve export root
        let export = if let Some(e) = self.resolve_export_path(export_path).await {
            e
        } else {
            // Unknown path: allocate synthetic handle
            return self.alloc_synthetic_handle(export_path).await;
        };

        let real_path = export.path.clone();
        self.get_or_create_fh(real_path.clone(), real_path.clone()).await
    }

    /// Get or create file handle for a specific real path within an export
    pub async fn get_or_create_fh(&self, real_path: PathBuf, export_root: PathBuf) -> Vec<u8> {
        // Check if we already have a handle for this path
        {
            let map = self.path_to_fhid.read().await;
            if let Some(&fhid) = map.get(&real_path) {
                let fh_map = self.fh_map.read().await;
                if let Some(entry) = fh_map.get(&fhid) {
                    return Self::encode_handle(fhid, entry.inode, entry.gen);
                }
            }
        }

        // Allocate new handle
        let inode = self.get_inode(&real_path);
        let gen = 1u32;

        let fhid = {
            let mut counter = self.fh_counter.write().await;
            let id = *counter;
            *counter += 1;
            id
        };

        {
            let mut fh_map = self.fh_map.write().await;
            let mut path_map = self.path_to_fhid.write().await;
            fh_map.insert(fhid, FhEntry {
                real_path: real_path.clone(),
                export_root,
                inode,
                gen,
            });
            path_map.insert(real_path.clone(), fhid);
        }

        info!("Allocated FH id={} for '{}'", fhid, real_path.display());
        Self::encode_handle(fhid, inode, gen)
    }

    fn encode_handle(fhid: u64, inode: u64, gen: u32) -> Vec<u8> {
        let mut h = vec![0u8; 32];
        h[0..8].copy_from_slice(&fhid.to_be_bytes());
        h[8..16].copy_from_slice(&inode.to_be_bytes());
        h[16..20].copy_from_slice(&gen.to_be_bytes());
        h
    }

    pub fn get_inode(&self, path: &Path) -> u64 {
        // Use FNV-1a 64-bit hash of the path bytes for stable, deterministic inode IDs.
        // This ensures the same path always produces the same inode across restarts,
        // allowing try_rebuild_fh() to reconstruct mappings after a server restart.
        let path_bytes = path.to_string_lossy();
        let path_bytes = path_bytes.as_bytes();
        let mut hash: u64 = 0xcbf29ce484222325; // FNV offset basis
        for &b in path_bytes {
            hash ^= b as u64;
            hash = hash.wrapping_mul(0x100000001b3); // FNV prime
        }
        hash
    }

    async fn alloc_synthetic_handle(&self, path: &str) -> Vec<u8> {
        let inode = {
            // FNV-1a 64-bit hash for stable, deterministic inode IDs
            let mut hash: u64 = 0xcbf29ce484222325;
            for &b in path.as_bytes() {
                hash ^= b as u64;
                hash = hash.wrapping_mul(0x100000001b3);
            }
            hash
        };
        let fhid = {
            let mut counter = self.fh_counter.write().await;
            let id = *counter;
            *counter += 1;
            id
        };
        Self::encode_handle(fhid, inode, 1)
    }

    /// Decode handle bytes -> fhid
    pub fn decode_fhid(handle: &[u8]) -> Option<u64> {
        if handle.len() < 8 { return None; }
        Some(u64::from_be_bytes(handle[0..8].try_into().ok()?))
    }

    /// Resolve file handle to real filesystem path
    pub async fn resolve_fh(&self, handle: &[u8]) -> Option<PathBuf> {
        let fhid = Self::decode_fhid(handle)?;
        if fhid == 0 { return None; }
        let map = self.fh_map.read().await;
        map.get(&fhid).map(|e| e.real_path.clone())
    }

    /// Get the export root for a file handle
    pub async fn get_fh_export_root(&self, handle: &[u8]) -> Option<PathBuf> {
        let fhid = Self::decode_fhid(handle)?;
        if fhid == 0 { return None; }
        let map = self.fh_map.read().await;
        map.get(&fhid).map(|e| e.export_root.clone())
    }

    pub async fn validate_file_handle(&self, handle: &[u8]) -> bool {
        if handle.is_empty() { return false; }
        if handle.iter().all(|&b| b == 0) { return true; } // zero handle = root probe
        if handle.len() < 8 { return false; }
        let fhid = match Self::decode_fhid(handle) {
            Some(id) => id,
            None => return false,
        };
        if fhid == 0 || fhid == u64::MAX { return true; } // zero handle and root synthetic handle
        let map = self.fh_map.read().await;
        map.contains_key(&fhid)
    }

    /// Try to rebuild a file handle mapping from handle bytes.
    /// This is called from PUTFH after a server restart: the client has a
    /// previously-issued FH but our in-memory fh_map is empty.  We attempt
    /// to match the inode (bytes 8..16) against every path under every export
    /// so that subsequent GETATTR / READDIR calls can still resolve the path.
    /// This is a best-effort search; if we cannot find the path we leave the
    /// map untouched and the next resolve_fh() will return None → NFS4ERR_STALE.
    pub async fn try_rebuild_fh(&self, handle: &[u8]) {
        let fhid = match Self::decode_fhid(handle) {
            Some(id) => id,
            None => return,
        };
        // Root handle and known handles need no rebuild
        if fhid == u64::MAX || fhid == 0 {
            return;
        }
        {
            let map = self.fh_map.read().await;
            if map.contains_key(&fhid) {
                return;
            }
        }
        if handle.len() < 16 { return; }
        let stored_inode = u64::from_be_bytes(handle[8..16].try_into().unwrap_or([0u8; 8]));

        // Walk every export root looking for a path whose computed inode matches
        let export_roots: Vec<PathBuf> = {
            let exports = self.exports.read().await;
            exports.values().map(|e| e.path.clone()).collect()
        };

        for export_root in export_roots {
            // Walk the export tree (up to depth 8 to avoid runaway)
            if let Some(found_path) = Self::find_path_by_inode(&export_root, stored_inode, 0, 8) {
                info!("try_rebuild_fh: rebuilt fhid={} -> {}", fhid, found_path.display());
                let gen = 1u32;
                let mut fh_map = self.fh_map.write().await;
                let mut path_map = self.path_to_fhid.write().await;
                // Update counter if needed so future allocations don't collide
                {
                    let mut counter = self.fh_counter.write().await;
                    if fhid >= *counter {
                        *counter = fhid + 1;
                    }
                }
                fh_map.insert(fhid, FhEntry {
                    real_path: found_path.clone(),
                    export_root: export_root.clone(),
                    inode: stored_inode,
                    gen,
                });
                path_map.insert(found_path, fhid);
                return;
            }
        }
        // Not found — will surface as NFS4ERR_STALE at the next resolve_fh()
    }

    fn find_path_by_inode(dir: &Path, target_inode: u64, depth: usize, max_depth: usize) -> Option<PathBuf> {
        // Check the directory itself using FNV-1a hash (must match get_inode)
        fn fnv1a(path: &Path) -> u64 {
            let s = path.to_string_lossy();
            let mut hash: u64 = 0xcbf29ce484222325;
            for &b in s.as_bytes() {
                hash ^= b as u64;
                hash = hash.wrapping_mul(0x100000001b3);
            }
            hash
        }
        if fnv1a(dir) == target_inode {
            return Some(dir.to_path_buf());
        }
        if depth >= max_depth { return None; }
        let entries = std::fs::read_dir(dir).ok()?;
        for entry in entries.filter_map(|e| e.ok()) {
            let path = entry.path();
            if fnv1a(&path) == target_inode {
                return Some(path);
            }
            if path.is_dir() {
                if let Some(found) = Self::find_path_by_inode(&path, target_inode, depth + 1, max_depth) {
                    return Some(found);
                }
            }
        }
        None
    }

    /// Look up a child path within the directory identified by a file handle.
    /// Returns the child file handle bytes.
    pub async fn lookup_child(&self, dir_fh: &[u8], name: &str) -> Option<(Vec<u8>, PathBuf)> {
        let dir_path = self.resolve_fh(dir_fh).await?;
        let child_path = dir_path.join(name);
        if !child_path.exists() {
            return None;
        }
        // Find export root for this directory
        let export_root = self.get_fh_export_root(dir_fh).await
            .unwrap_or_else(|| dir_path.clone());
        let fh = self.get_or_create_fh(child_path.clone(), export_root).await;
        Some((fh, child_path))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_export_options_default() {
        let opts = ExportOptions::default();
        assert!(opts.sync);
        assert!(!opts.read_only);
    }
}
