use anyhow::Result;
use std::path::PathBuf;
use std::sync::Arc;
use tracing::{debug, info, warn};

use crate::exports::ExportsManager;

// RPC constants
const RPC_REPLY: u32 = 1;
const RPC_MSG_ACCEPTED: u32 = 0;
const ACC_SUCCESS: u32 = 0;

// NFS v3 Status Codes (RFC 1813)
const NFS3_OK: u32 = 0;
const NFS3ERR_PERM: u32 = 1;
const NFS3ERR_NOENT: u32 = 2;
const NFS3ERR_IO: u32 = 5;
const NFS3ERR_ACCES: u32 = 13;
const NFS3ERR_EXIST: u32 = 17;
const NFS3ERR_NOTDIR: u32 = 20;
const NFS3ERR_ISDIR: u32 = 21;
const NFS3ERR_INVAL: u32 = 22;
const NFS3ERR_NOSPC: u32 = 28;
const NFS3ERR_ROFS: u32 = 30;
const NFS3ERR_NAMETOOLONG: u32 = 63;
const NFS3ERR_NOTEMPTY: u32 = 66;
const NFS3ERR_STALE: u32 = 70;
const NFS3ERR_NOTSUPP: u32 = 10004;
const NFS3ERR_SERVERFAULT: u32 = 10006;

// NFS v3 File Types
const NF3REG: u32 = 1;
const NF3DIR: u32 = 2;
const NF3LNK: u32 = 5;

// NFS v3 Protocol (RFC 1813)
#[derive(Clone)]
pub struct NfsProtocolServer {
    exports: Arc<ExportsManager>,
}

impl NfsProtocolServer {
    pub fn new(exports: Arc<ExportsManager>) -> Self {
        Self { exports }
    }

    pub async fn handle_request(&self, request: &[u8], client_ip: std::net::IpAddr) -> Option<Vec<u8>> {
        if request.len() < 24 {
            warn!("NFS v3: request too short: {}", request.len());
            return None;
        }

        let xid = &request[0..4];
        let msg_type = u32::from_be_bytes([request[4], request[5], request[6], request[7]]);
        if msg_type != 0 { return None; } // not a CALL

        let procedure = u32::from_be_bytes([request[20], request[21], request[22], request[23]]);

        // Parse credentials + verifier to get args offset (SEC-012: overflow protection)
        let mut args_off = 24;
        if request.len() > args_off + 8 {
            let cred_len = u32::from_be_bytes([
                request[args_off+4], request[args_off+5], request[args_off+6], request[args_off+7],
            ]) as usize;
            // SEC-012: Limit cred length
            if cred_len > crate::nfs::MAX_XDR_OPAQUE {
                warn!("SEC-012: NFS3 cred_len {} exceeds max, rejecting", cred_len);
                return None;
            }
            let cred_padded = match cred_len.checked_add(3) {
                Some(v) => v & !3,
                None => return None,
            };
            args_off = match args_off.checked_add(8).and_then(|v| v.checked_add(cred_padded)) {
                Some(v) => v,
                None => return None,
            };
            if request.len() > args_off + 8 {
                let verif_len = u32::from_be_bytes([
                    request[args_off+4], request[args_off+5], request[args_off+6], request[args_off+7],
                ]) as usize;
                // SEC-012: Limit verif length
                if verif_len > crate::nfs::MAX_XDR_OPAQUE {
                    warn!("SEC-012: NFS3 verif_len {} exceeds max, rejecting", verif_len);
                    return None;
                }
                let verif_padded = match verif_len.checked_add(3) {
                    Some(v) => v & !3,
                    None => return None,
                };
                args_off = match args_off.checked_add(8).and_then(|v| v.checked_add(verif_padded)) {
                    Some(v) => v,
                    None => return None,
                };
            }
        }

        debug!("NFS v3: proc={}, client={}, args_off={}", procedure, client_ip, args_off);

        match procedure {
            0  => Some(self.handle_null(xid)),
            1  => self.handle_getattr(xid, request, args_off).await,
            2  => self.handle_setattr(xid, request, args_off).await,
            3  => self.handle_lookup(xid, request, args_off).await,
            4  => self.handle_access(xid, request, args_off).await,
            5  => self.handle_readlink(xid, request, args_off).await,
            6  => self.handle_read(xid, request, args_off).await,
            7  => self.handle_write(xid, request, args_off).await,
            8  => self.handle_create(xid, request, args_off).await,
            9  => self.handle_mkdir(xid, request, args_off).await,
            10 => Some(self.make_error_reply(xid, NFS3ERR_NOTSUPP)),
            11 => Some(self.make_error_reply(xid, NFS3ERR_NOTSUPP)),
            12 => self.handle_remove(xid, request, args_off).await,
            13 => self.handle_rmdir(xid, request, args_off).await,
            14 => self.handle_rename(xid, request, args_off).await,
            15 => Some(self.make_error_reply(xid, NFS3ERR_NOTSUPP)),
            16 => self.handle_readdir(xid, request, args_off).await,
            17 => self.handle_readdirplus(xid, request, args_off).await,
            18 => self.handle_fsstat(xid, request, args_off).await,
            19 => self.handle_fsinfo(xid, request, args_off).await,
            20 => self.handle_pathconf(xid, request, args_off).await,
            21 => self.handle_commit(xid, request, args_off).await,
            _  => {
                warn!("NFS v3: unknown procedure: {}", procedure);
                None
            }
        }
    }

    // ──────────────────────────────────────────────────────────────────────────
    // RPC reply helpers
    // ──────────────────────────────────────────────────────────────────────────
    fn make_rpc_reply(&self, xid: &[u8]) -> Vec<u8> {
        vec![
            xid[0], xid[1], xid[2], xid[3],
            0, 0, 0, 1, // msg_type = REPLY
            0, 0, 0, 0, // reply_stat = ACCEPTED
            // verifier: AUTH_NONE flavor=0, len=0
            0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, // accept_stat = SUCCESS
        ]
    }

    fn make_error_reply(&self, xid: &[u8], nfs_status: u32) -> Vec<u8> {
        let mut r = self.make_rpc_reply(xid);
        r.extend_from_slice(&nfs_status.to_be_bytes());
        // post_op_attr = FALSE
        r.extend_from_slice(&[0, 0, 0, 0]);
        r
    }

    // ──────────────────────────────────────────────────────────────────────────
    // Parse file handle from request at given offset
    // ──────────────────────────────────────────────────────────────────────────
    fn parse_fh<'a>(&self, request: &'a [u8], off: usize) -> Option<(&'a [u8], usize)> {
        if off + 4 > request.len() { return None; }
        let fh_len = u32::from_be_bytes([request[off], request[off+1], request[off+2], request[off+3]]) as usize;
        if off + 4 + fh_len > request.len() { return None; }
        Some((&request[off+4..off+4+fh_len], 4 + ((fh_len + 3) & !3)))
    }

    // ──────────────────────────────────────────────────────────────────────────
    // Build fattr3 from metadata
    // ──────────────────────────────────────────────────────────────────────────
    fn build_fattr3(&self, path: &PathBuf) -> Vec<u8> {
        let meta = std::fs::metadata(path);
        let is_dir = meta.as_ref().map(|m| m.is_dir()).unwrap_or(false);
        let size = meta.as_ref().map(|m| m.len()).unwrap_or(0);
        let mtime_secs = meta.ok()
            .and_then(|m| m.modified().ok())
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_secs())
            .unwrap_or(0);

        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        let mut h = DefaultHasher::new();
        path.hash(&mut h);
        let fileid = h.finish();

        let ftype: u32 = if is_dir { NF3DIR } else { NF3REG };
        let mode: u32  = if is_dir { 0o755 } else { 0o644 };
        let nlink: u32 = 1;
        let uid: u32   = 0;
        let gid: u32   = 0;
        let fsid: u64  = 1;

        let mut a = Vec::with_capacity(84);
        a.extend_from_slice(&ftype.to_be_bytes());
        a.extend_from_slice(&mode.to_be_bytes());
        a.extend_from_slice(&nlink.to_be_bytes());
        a.extend_from_slice(&uid.to_be_bytes());
        a.extend_from_slice(&gid.to_be_bytes());
        a.extend_from_slice(&size.to_be_bytes());      // size (8)
        a.extend_from_slice(&size.to_be_bytes());      // used (8)
        a.extend_from_slice(&[0u8; 8]);                // rdev (specdata3)
        a.extend_from_slice(&fsid.to_be_bytes());      // fsid (8)
        a.extend_from_slice(&fileid.to_be_bytes());    // fileid (8)
        // atime
        a.extend_from_slice(&(mtime_secs as u32).to_be_bytes());
        a.extend_from_slice(&0u32.to_be_bytes());
        // mtime
        a.extend_from_slice(&(mtime_secs as u32).to_be_bytes());
        a.extend_from_slice(&0u32.to_be_bytes());
        // ctime
        a.extend_from_slice(&(mtime_secs as u32).to_be_bytes());
        a.extend_from_slice(&0u32.to_be_bytes());
        a
    }

    fn make_post_op_attr(&self, path: &Option<PathBuf>) -> Vec<u8> {
        match path {
            None => vec![0,0,0,0], // attributes_follow = FALSE
            Some(p) => {
                let mut d = vec![0,0,0,1]; // attributes_follow = TRUE
                d.extend_from_slice(&self.build_fattr3(p));
                d
            }
        }
    }

    fn make_wcc_data(&self) -> Vec<u8> {
        let mut d = vec![0,0,0,0]; // pre-op: FALSE
        d.extend_from_slice(&[0,0,0,0]); // post-op: FALSE
        d
    }

    // ──────────────────────────────────────────────────────────────────────────
    // Procedure handlers
    // ──────────────────────────────────────────────────────────────────────────

    fn handle_null(&self, xid: &[u8]) -> Vec<u8> {
        self.make_rpc_reply(xid)
    }

    async fn handle_getattr(&self, xid: &[u8], request: &[u8], off: usize) -> Option<Vec<u8>> {
        let (fh_data, _) = self.parse_fh(request, off)?;
        let path = self.exports.resolve_fh(fh_data).await;

        let mut r = self.make_rpc_reply(xid);
        r.extend_from_slice(&NFS3_OK.to_be_bytes());
        let p = path.unwrap_or_else(|| PathBuf::from("."));
        r.extend_from_slice(&self.build_fattr3(&p));
        Some(r)
    }

    async fn handle_setattr(&self, xid: &[u8], request: &[u8], off: usize) -> Option<Vec<u8>> {
        let (fh_data, _) = self.parse_fh(request, off)?;

        // SEC-002: Reject setattr on read-only exports
        if self.exports.is_read_only(fh_data).await {
            let mut r = self.make_rpc_reply(xid);
            r.extend_from_slice(&NFS3ERR_ROFS.to_be_bytes());
            r.extend_from_slice(&self.make_wcc_data());
            return Some(r);
        }

        let mut r = self.make_rpc_reply(xid);
        r.extend_from_slice(&NFS3_OK.to_be_bytes());
        r.extend_from_slice(&self.make_wcc_data());
        Some(r)
    }

    async fn handle_lookup(&self, xid: &[u8], request: &[u8], off: usize) -> Option<Vec<u8>> {
        let (dir_fh, fh_consumed) = self.parse_fh(request, off)?;
        let name_off = off + fh_consumed;

        if name_off + 4 > request.len() { return None; }
        let name_len = u32::from_be_bytes([
            request[name_off], request[name_off+1], request[name_off+2], request[name_off+3],
        ]) as usize;
        if name_off + 4 + name_len > request.len() { return None; }
        let name = String::from_utf8_lossy(&request[name_off+4..name_off+4+name_len]).to_string();

        info!("NFS3 LOOKUP: name='{}'", name);

        match self.exports.lookup_child(dir_fh, &name).await {
            None => {
                let mut r = self.make_rpc_reply(xid);
                r.extend_from_slice(&NFS3ERR_NOENT.to_be_bytes());
                r.extend_from_slice(&[0,0,0,0]); // dir post-op: FALSE
                Some(r)
            }
            Some((child_fh, child_path)) => {
                let mut r = self.make_rpc_reply(xid);
                r.extend_from_slice(&NFS3_OK.to_be_bytes());
                // object file handle
                let fh_len = child_fh.len() as u32;
                r.extend_from_slice(&fh_len.to_be_bytes());
                r.extend_from_slice(&child_fh);
                // object attributes
                r.extend_from_slice(&self.make_post_op_attr(&Some(child_path)));
                // dir attributes
                let dir_path = self.exports.resolve_fh(dir_fh).await;
                r.extend_from_slice(&self.make_post_op_attr(&dir_path));
                Some(r)
            }
        }
    }

    async fn handle_access(&self, xid: &[u8], request: &[u8], off: usize) -> Option<Vec<u8>> {
        let (fh_data, _) = self.parse_fh(request, off)?;
        let path = self.exports.resolve_fh(fh_data).await;

        let mut r = self.make_rpc_reply(xid);
        r.extend_from_slice(&NFS3_OK.to_be_bytes());
        r.extend_from_slice(&self.make_post_op_attr(&path));
        // access_rights: all access granted (READ|LOOKUP|MODIFY|EXTEND|DELETE|EXECUTE)
        r.extend_from_slice(&0x3Fu32.to_be_bytes());
        Some(r)
    }

    async fn handle_readlink(&self, xid: &[u8], request: &[u8], off: usize) -> Option<Vec<u8>> {
        let (fh_data, _) = self.parse_fh(request, off)?;
        let path = self.exports.resolve_fh(fh_data).await;
        let mut r = self.make_rpc_reply(xid);
        r.extend_from_slice(&NFS3_OK.to_be_bytes());
        r.extend_from_slice(&self.make_post_op_attr(&path));
        // Empty link target
        r.extend_from_slice(&0u32.to_be_bytes());
        Some(r)
    }

    async fn handle_read(&self, xid: &[u8], request: &[u8], off: usize) -> Option<Vec<u8>> {
        let (fh_data, fh_consumed) = self.parse_fh(request, off)?;
        let args_off = off + fh_consumed;
        if args_off + 12 > request.len() { return None; }

        let file_offset = u64::from_be_bytes([
            request[args_off], request[args_off+1], request[args_off+2], request[args_off+3],
            request[args_off+4], request[args_off+5], request[args_off+6], request[args_off+7],
        ]);
        let count = u32::from_be_bytes([
            request[args_off+8], request[args_off+9], request[args_off+10], request[args_off+11],
        ]) as usize;

        let path = self.exports.resolve_fh(fh_data).await;

        let (data, eof) = if let Some(ref p) = path {
            match std::fs::read(p) {
                Ok(file_data) => {
                    let start = file_offset.min(file_data.len() as u64) as usize;
                    let end = (start + count).min(file_data.len());
                    let eof = end >= file_data.len();
                    (file_data[start..end].to_vec(), eof)
                }
                Err(_) => (vec![], true),
            }
        } else {
            (vec![], true)
        };

        let mut r = self.make_rpc_reply(xid);
        r.extend_from_slice(&NFS3_OK.to_be_bytes());
        r.extend_from_slice(&self.make_post_op_attr(&path));
        r.extend_from_slice(&(data.len() as u32).to_be_bytes()); // count
        r.extend_from_slice(&(eof as u32).to_be_bytes());        // eof
        // data opaque<>
        r.extend_from_slice(&(data.len() as u32).to_be_bytes());
        r.extend_from_slice(&data);
        let data_padded = (data.len() + 3) & !3;
        let pad = data_padded - data.len();
        r.resize(r.len() + pad, 0);
        Some(r)
    }

    async fn handle_write(&self, xid: &[u8], request: &[u8], off: usize) -> Option<Vec<u8>> {
        let (fh_data, fh_consumed) = self.parse_fh(request, off)?;

        // SEC-002: Reject writes to read-only exports
        if self.exports.is_read_only(fh_data).await {
            let mut r = self.make_rpc_reply(xid);
            r.extend_from_slice(&NFS3ERR_ROFS.to_be_bytes());
            r.extend_from_slice(&self.make_wcc_data());
            r.extend_from_slice(&0u32.to_be_bytes()); // count
            r.extend_from_slice(&2u32.to_be_bytes()); // committed = FILE_SYNC
            r.extend_from_slice(&[0u8; 8]);            // write verifier
            return Some(r);
        }

        let args_off = off + fh_consumed;
        if args_off + 20 > request.len() { return None; }

        let file_offset = u64::from_be_bytes([
            request[args_off], request[args_off+1], request[args_off+2], request[args_off+3],
            request[args_off+4], request[args_off+5], request[args_off+6], request[args_off+7],
        ]);
        let count = u32::from_be_bytes([
            request[args_off+8], request[args_off+9], request[args_off+10], request[args_off+11],
        ]) as usize;
        // stable(4) then data opaque<> with length prefix
        let data_off = args_off + 16;
        if data_off + 4 > request.len() { return None; }
        let data_len = u32::from_be_bytes([
            request[data_off], request[data_off+1], request[data_off+2], request[data_off+3],
        ]) as usize;
        if data_off + 4 + data_len > request.len() { return None; }
        let write_data = &request[data_off+4..data_off+4+data_len];

        let path = self.exports.resolve_fh(fh_data).await;
        let written = if let Some(ref p) = path {
            let mut file_data = match std::fs::read(p) {
                Ok(data) => data,
                Err(e) => {
                    warn!("NFS3 WRITE: failed to read {}: {}", p.display(), e);
                    return None;
                }
            };
            let end = file_offset as usize + data_len;
            if file_data.len() < end { file_data.resize(end, 0); }
            file_data[file_offset as usize..end].copy_from_slice(write_data);
            if std::fs::write(p, &file_data).is_ok() { data_len } else { 0 }
        } else { 0 };

        let mut r = self.make_rpc_reply(xid);
        r.extend_from_slice(&NFS3_OK.to_be_bytes());
        r.extend_from_slice(&self.make_wcc_data());
        r.extend_from_slice(&(written as u32).to_be_bytes()); // count
        r.extend_from_slice(&2u32.to_be_bytes());              // committed = FILE_SYNC
        r.extend_from_slice(&[0u8; 8]);                        // write verifier
        Some(r)
    }

    async fn handle_create(&self, xid: &[u8], request: &[u8], off: usize) -> Option<Vec<u8>> {
        let (dir_fh, fh_consumed) = self.parse_fh(request, off)?;

        // SEC-002: Reject creates on read-only exports
        if self.exports.is_read_only(dir_fh).await {
            let mut r = self.make_rpc_reply(xid);
            r.extend_from_slice(&NFS3ERR_ROFS.to_be_bytes());
            r.extend_from_slice(&self.make_wcc_data());
            return Some(r);
        }

        let args_off = off + fh_consumed;
        if args_off + 4 > request.len() { return None; }
        let name_len = u32::from_be_bytes([
            request[args_off], request[args_off+1], request[args_off+2], request[args_off+3],
        ]) as usize;
        if args_off + 4 + name_len > request.len() { return None; }
        let name = String::from_utf8_lossy(&request[args_off+4..args_off+4+name_len]).to_string();

        let dir_path = self.exports.resolve_fh(dir_fh).await;
        if let Some(ref dp) = dir_path {
            let new_file = dp.join(&name);
            let _ = std::fs::File::create(&new_file);
            let export_root = self.exports.get_fh_export_root(dir_fh).await
                .unwrap_or_else(|| dp.clone());
            let new_fh = self.exports.get_or_create_fh(new_file.clone(), export_root).await;
            let mut r = self.make_rpc_reply(xid);
            r.extend_from_slice(&NFS3_OK.to_be_bytes());
            // post_op_fh3: TRUE + fh
            r.extend_from_slice(&[0,0,0,1]);
            r.extend_from_slice(&(new_fh.len() as u32).to_be_bytes());
            r.extend_from_slice(&new_fh);
            r.extend_from_slice(&self.make_post_op_attr(&Some(new_file)));
            r.extend_from_slice(&self.make_wcc_data());
            return Some(r);
        }
        let mut r = self.make_rpc_reply(xid);
        r.extend_from_slice(&NFS3ERR_STALE.to_be_bytes());
        r.extend_from_slice(&self.make_wcc_data());
        Some(r)
    }

    async fn handle_mkdir(&self, xid: &[u8], request: &[u8], off: usize) -> Option<Vec<u8>> {
        let (dir_fh, fh_consumed) = self.parse_fh(request, off)?;

        // SEC-002: Reject mkdir on read-only exports
        if self.exports.is_read_only(dir_fh).await {
            let mut r = self.make_rpc_reply(xid);
            r.extend_from_slice(&NFS3ERR_ROFS.to_be_bytes());
            r.extend_from_slice(&self.make_wcc_data());
            return Some(r);
        }

        let args_off = off + fh_consumed;
        if args_off + 4 > request.len() { return None; }
        let name_len = u32::from_be_bytes([
            request[args_off], request[args_off+1], request[args_off+2], request[args_off+3],
        ]) as usize;
        if args_off + 4 + name_len > request.len() { return None; }
        let name = String::from_utf8_lossy(&request[args_off+4..args_off+4+name_len]).to_string();

        let dir_path = self.exports.resolve_fh(dir_fh).await;
        if let Some(ref dp) = dir_path {
            let new_dir = dp.join(&name);
            let _ = std::fs::create_dir_all(&new_dir);
            let export_root = self.exports.get_fh_export_root(dir_fh).await
                .unwrap_or_else(|| dp.clone());
            let new_fh = self.exports.get_or_create_fh(new_dir.clone(), export_root).await;
            let mut r = self.make_rpc_reply(xid);
            r.extend_from_slice(&NFS3_OK.to_be_bytes());
            r.extend_from_slice(&[0,0,0,1]); // post_op_fh3: TRUE
            r.extend_from_slice(&(new_fh.len() as u32).to_be_bytes());
            r.extend_from_slice(&new_fh);
            r.extend_from_slice(&self.make_post_op_attr(&Some(new_dir)));
            r.extend_from_slice(&self.make_wcc_data());
            return Some(r);
        }
        let mut r = self.make_rpc_reply(xid);
        r.extend_from_slice(&NFS3ERR_STALE.to_be_bytes());
        r.extend_from_slice(&self.make_wcc_data());
        Some(r)
    }

    async fn handle_remove(&self, xid: &[u8], request: &[u8], off: usize) -> Option<Vec<u8>> {
        let (dir_fh, fh_consumed) = self.parse_fh(request, off)?;

        // SEC-002: Reject removes on read-only exports
        if self.exports.is_read_only(dir_fh).await {
            let mut r = self.make_rpc_reply(xid);
            r.extend_from_slice(&NFS3ERR_ROFS.to_be_bytes());
            r.extend_from_slice(&self.make_wcc_data());
            return Some(r);
        }

        let args_off = off + fh_consumed;
        if args_off + 4 > request.len() { return None; }
        let name_len = u32::from_be_bytes([
            request[args_off], request[args_off+1], request[args_off+2], request[args_off+3],
        ]) as usize;
        if args_off + 4 + name_len > request.len() { return None; }
        let name = String::from_utf8_lossy(&request[args_off+4..args_off+4+name_len]).to_string();

        let dir_path = self.exports.resolve_fh(dir_fh).await;
        let status = if let Some(ref dp) = dir_path {
            let target = dp.join(&name);
            if target.exists() {
                if std::fs::remove_file(&target).is_ok() { NFS3_OK } else { NFS3ERR_IO }
            } else { NFS3ERR_NOENT }
        } else { NFS3ERR_STALE };

        let mut r = self.make_rpc_reply(xid);
        r.extend_from_slice(&status.to_be_bytes());
        r.extend_from_slice(&self.make_wcc_data());
        Some(r)
    }

    async fn handle_rmdir(&self, xid: &[u8], request: &[u8], off: usize) -> Option<Vec<u8>> {
        let (dir_fh, fh_consumed) = self.parse_fh(request, off)?;

        // SEC-002: Reject rmdir on read-only exports
        if self.exports.is_read_only(dir_fh).await {
            let mut r = self.make_rpc_reply(xid);
            r.extend_from_slice(&NFS3ERR_ROFS.to_be_bytes());
            r.extend_from_slice(&self.make_wcc_data());
            r.extend_from_slice(&self.make_wcc_data());
            return Some(r);
        }

        let args_off = off + fh_consumed;
        if args_off + 4 > request.len() { return None; }
        let name_len = u32::from_be_bytes([
            request[args_off], request[args_off+1], request[args_off+2], request[args_off+3],
        ]) as usize;
        if args_off + 4 + name_len > request.len() { return None; }
        let name = String::from_utf8_lossy(&request[args_off+4..args_off+4+name_len]).to_string();

        let dir_path = self.exports.resolve_fh(dir_fh).await;
        let status = if let Some(ref dp) = dir_path {
            let target = dp.join(&name);
            if target.exists() {
                if std::fs::remove_dir(&target).is_ok() { NFS3_OK } else { NFS3ERR_NOTEMPTY }
            } else { NFS3ERR_NOENT }
        } else { NFS3ERR_STALE };

        let mut r = self.make_rpc_reply(xid);
        r.extend_from_slice(&status.to_be_bytes());
        r.extend_from_slice(&self.make_wcc_data());
        r.extend_from_slice(&self.make_wcc_data());
        Some(r)
    }

    async fn handle_rename(&self, xid: &[u8], request: &[u8], off: usize) -> Option<Vec<u8>> {
        let (from_fh, fh1_consumed) = self.parse_fh(request, off)?;

        // SEC-002: Reject renames on read-only exports
        if self.exports.is_read_only(from_fh).await {
            let mut r = self.make_rpc_reply(xid);
            r.extend_from_slice(&NFS3ERR_ROFS.to_be_bytes());
            r.extend_from_slice(&self.make_wcc_data());
            r.extend_from_slice(&self.make_wcc_data());
            return Some(r);
        }

        let from_name_off = off + fh1_consumed;
        if from_name_off + 4 > request.len() { return None; }
        let from_name_len = u32::from_be_bytes([
            request[from_name_off], request[from_name_off+1],
            request[from_name_off+2], request[from_name_off+3],
        ]) as usize;
        let from_name = String::from_utf8_lossy(
            &request[from_name_off+4..from_name_off+4+from_name_len]
        ).to_string();
        let to_off = from_name_off + 4 + ((from_name_len + 3) & !3);

        let (to_fh, fh2_consumed) = self.parse_fh(request, to_off)?;
        let to_name_off = to_off + fh2_consumed;
        if to_name_off + 4 > request.len() { return None; }
        let to_name_len = u32::from_be_bytes([
            request[to_name_off], request[to_name_off+1],
            request[to_name_off+2], request[to_name_off+3],
        ]) as usize;
        let to_name = String::from_utf8_lossy(
            &request[to_name_off+4..to_name_off+4+to_name_len]
        ).to_string();

        let from_dir = self.exports.resolve_fh(from_fh).await;
        let to_dir = self.exports.resolve_fh(to_fh).await;

        let status = if let (Some(fd), Some(td)) = (from_dir, to_dir) {
            let src = fd.join(&from_name);
            let dst = td.join(&to_name);
            if std::fs::rename(&src, &dst).is_ok() { NFS3_OK } else { NFS3ERR_IO }
        } else { NFS3ERR_STALE };

        let mut r = self.make_rpc_reply(xid);
        r.extend_from_slice(&status.to_be_bytes());
        r.extend_from_slice(&self.make_wcc_data()); // fromdir
        r.extend_from_slice(&self.make_wcc_data()); // todir
        Some(r)
    }

    async fn handle_readdir(&self, xid: &[u8], request: &[u8], off: usize) -> Option<Vec<u8>> {
        let (fh_data, fh_consumed) = self.parse_fh(request, off)?;
        let path = self.exports.resolve_fh(fh_data).await;

        let mut r = self.make_rpc_reply(xid);
        r.extend_from_slice(&NFS3_OK.to_be_bytes());
        r.extend_from_slice(&self.make_post_op_attr(&path));
        r.extend_from_slice(&[0u8; 8]); // cookieverf

        if let Some(ref dir_path) = path {
            let export_root = self.exports.get_fh_export_root(fh_data).await
                .unwrap_or_else(|| dir_path.clone());

            if let Ok(entries) = std::fs::read_dir(dir_path) {
                for (idx, entry) in entries.flatten().enumerate() {
                    let name = entry.file_name().to_string_lossy().to_string();
                    let epath = entry.path();
                    let child_fh = self.exports.get_or_create_fh(epath, export_root.clone()).await;

                    use std::collections::hash_map::DefaultHasher;
                    use std::hash::{Hash, Hasher};
                    let mut h = DefaultHasher::new();
                    name.hash(&mut h);
                    let fileid = h.finish();

                    r.extend_from_slice(&[0,0,0,1]); // value_follows=TRUE
                    r.extend_from_slice(&fileid.to_be_bytes()); // fileid
                    let name_bytes = name.as_bytes();
                    let nlen = name_bytes.len() as u32;
                    r.extend_from_slice(&nlen.to_be_bytes());
                    r.extend_from_slice(name_bytes);
                    let name_padded = (name_bytes.len() + 3) & !3;
                    let pad = name_padded - name_bytes.len();
                    r.resize(r.len() + pad, 0);
                    r.extend_from_slice(&((idx + 1) as u64).to_be_bytes()); // cookie
                }
            }
        }

        r.extend_from_slice(&[0,0,0,0]); // value_follows=FALSE
        r.extend_from_slice(&[0,0,0,1]); // eof=TRUE
        Some(r)
    }

    async fn handle_readdirplus(&self, xid: &[u8], request: &[u8], off: usize) -> Option<Vec<u8>> {
        // Delegate to readdir (simplified - no extra attributes per entry)
        self.handle_readdir(xid, request, off).await
    }

    async fn handle_fsstat(&self, xid: &[u8], request: &[u8], off: usize) -> Option<Vec<u8>> {
        let (fh_data, _) = self.parse_fh(request, off)?;
        let path = self.exports.resolve_fh(fh_data).await;

        let mut r = self.make_rpc_reply(xid);
        r.extend_from_slice(&NFS3_OK.to_be_bytes());
        r.extend_from_slice(&self.make_post_op_attr(&path));

        // tbytes (total), fbytes (free), abytes (avail), tfiles, ffiles, invarsec
        let total: u64 = 100 * 1024 * 1024 * 1024; // 100 GB
        let free: u64  = 50  * 1024 * 1024 * 1024; // 50 GB
        r.extend_from_slice(&total.to_be_bytes());
        r.extend_from_slice(&free.to_be_bytes());
        r.extend_from_slice(&free.to_be_bytes());  // avail
        r.extend_from_slice(&1000000u64.to_be_bytes()); // tfiles
        r.extend_from_slice(&500000u64.to_be_bytes());  // ffiles
        r.extend_from_slice(&0u32.to_be_bytes());  // invarsec
        Some(r)
    }

    async fn handle_fsinfo(&self, xid: &[u8], request: &[u8], off: usize) -> Option<Vec<u8>> {
        let (fh_data, _) = self.parse_fh(request, off)?;
        let path = self.exports.resolve_fh(fh_data).await;

        let mut r = self.make_rpc_reply(xid);
        r.extend_from_slice(&NFS3_OK.to_be_bytes());
        r.extend_from_slice(&self.make_post_op_attr(&path));

        // RTMAX, RTPREF, RTMULT, WTMAX, WTPREF, WTMULT (all u32)
        let chunk: u32 = 65536;
        let mult: u32  = 4096;
        r.extend_from_slice(&chunk.to_be_bytes()); // RTMAX
        r.extend_from_slice(&chunk.to_be_bytes()); // RTPREF
        r.extend_from_slice(&mult.to_be_bytes());  // RTMULT
        r.extend_from_slice(&chunk.to_be_bytes()); // WTMAX
        r.extend_from_slice(&chunk.to_be_bytes()); // WTPREF
        r.extend_from_slice(&mult.to_be_bytes());  // WTMULT
        r.extend_from_slice(&chunk.to_be_bytes()); // DTPREF
        // max file size (u64)
        r.extend_from_slice(&u64::MAX.to_be_bytes());
        // time_delta: seconds=0, nanoseconds=1
        r.extend_from_slice(&0u32.to_be_bytes());
        r.extend_from_slice(&1u32.to_be_bytes());
        // properties: FSF3_LINK|FSF3_SYMLINK|FSF3_HOMOGENEOUS|FSF3_CANSETTIME = 0x1B
        r.extend_from_slice(&0x1Bu32.to_be_bytes());
        Some(r)
    }

    async fn handle_pathconf(&self, xid: &[u8], request: &[u8], off: usize) -> Option<Vec<u8>> {
        let (fh_data, _) = self.parse_fh(request, off)?;
        let path = self.exports.resolve_fh(fh_data).await;

        let mut r = self.make_rpc_reply(xid);
        r.extend_from_slice(&NFS3_OK.to_be_bytes());
        r.extend_from_slice(&self.make_post_op_attr(&path));

        r.extend_from_slice(&1024u32.to_be_bytes()); // linkmax
        r.extend_from_slice(&255u32.to_be_bytes());  // name_max
        r.extend_from_slice(&0u32.to_be_bytes());    // no_trunc=FALSE
        r.extend_from_slice(&0u32.to_be_bytes());    // chown_restricted=FALSE
        r.extend_from_slice(&1u32.to_be_bytes());    // case_insensitive=FALSE
        r.extend_from_slice(&1u32.to_be_bytes());    // case_preserving=TRUE
        Some(r)
    }

    async fn handle_commit(&self, xid: &[u8], request: &[u8], off: usize) -> Option<Vec<u8>> {
        let mut r = self.make_rpc_reply(xid);
        r.extend_from_slice(&NFS3_OK.to_be_bytes());
        r.extend_from_slice(&self.make_wcc_data());
        r.extend_from_slice(&[0u8; 8]); // write verifier
        Some(r)
    }
}
