// NFS v4 Protocol Implementation (RFC 7530 / RFC 5661)
// Implements the COMPOUND procedure which is the core of NFSv4

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, info, trace, warn};

use crate::exports::ExportsManager;
use crate::path_ext::to_extended_path;

// ─── RPC constants ────────────────────────────────────────────────────────────
const RPC_REPLY: u32 = 1;
const RPC_MSG_ACCEPTED: u32 = 0;
const ACC_SUCCESS: u32 = 0;

// ─── NFS4 op codes (RFC 7530 §14) ─────────────────────────────────────────────
const OP_ACCESS: u32 = 3;
const OP_CLOSE: u32 = 4;
const OP_COMMIT: u32 = 5;
const OP_CREATE: u32 = 6;
const OP_DELEGRETURN: u32 = 8;
const OP_GETATTR: u32 = 9;
const OP_GETFH: u32 = 10;
const OP_LINK: u32 = 11;
const OP_LOCK: u32 = 12;
const OP_LOCKT: u32 = 13;
const OP_LOCKU: u32 = 14;
const OP_LOOKUP: u32 = 15;
const OP_LOOKUPP: u32 = 16;
const OP_NVERIFY: u32 = 17;
const OP_OPEN: u32 = 18;
const OP_OPENATTR: u32 = 19;
const OP_OPEN_CONFIRM: u32 = 20;
const OP_OPEN_DOWNGRADE: u32 = 21;
const OP_PUTFH: u32 = 22;
const OP_PUTPUBFH: u32 = 23;
const OP_PUTROOTFH: u32 = 24;
const OP_READ: u32 = 25;
const OP_READDIR: u32 = 26;
const OP_READLINK: u32 = 27;
const OP_REMOVE: u32 = 28;
const OP_RENAME: u32 = 29;
const OP_RENEW: u32 = 30;
const OP_RESTOREFH: u32 = 31;
const OP_SAVEFH: u32 = 32;
const OP_SECINFO: u32 = 33;
const OP_SETATTR: u32 = 34;
const OP_SETCLIENTID: u32 = 35;
const OP_SETCLIENTID_CONFIRM: u32 = 36;
const OP_VERIFY: u32 = 37;
const OP_WRITE: u32 = 38;
const OP_RELEASE_LOCKOWNER: u32 = 39;
const OP_ILLEGAL: u32 = 10044;

// NFS v4.1 op codes (RFC 5661)
const OP_EXCHANGE_ID: u32 = 42;
const OP_CREATE_SESSION: u32 = 43;
const OP_DESTROY_SESSION: u32 = 44;
const OP_BIND_CONN_TO_SESSION: u32 = 45;
const OP_DESTROY_CLIENTID: u32 = 57; // RFC 5661 §18.50
const OP_SECINFO_NO_NAME: u32 = 52; // RFC 5661 §18.45
const OP_SEQUENCE: u32 = 53;       // RFC 5661 §18.46 — must be first op in each compound
const OP_RECLAIM_COMPLETE: u32 = 58; // RFC 5661 §18.51

// NFS v4.2 op codes (RFC 7862)
const OP_ALLOCATE: u32 = 59;
const OP_COPY: u32 = 60;
const OP_COPY_NOTIFY: u32 = 61;
const OP_DEALLOCATE: u32 = 62;
const OP_IO_ADVISE: u32 = 63;
const OP_LAYOUTERROR: u32 = 64;
const OP_LAYOUTSTATS: u32 = 65;
const OP_OFFLOAD_CANCEL: u32 = 66;
const OP_OFFLOAD_STATUS: u32 = 67;
const OP_READ_PLUS: u32 = 68;
const OP_SEEK: u32 = 69;
const OP_WRITE_SAME: u32 = 70;
const OP_CLONE: u32 = 71;

// ─── NFS4 status codes ────────────────────────────────────────────────────────
const NFS4_OK: u32 = 0;
const NFS4ERR_PERM: u32 = 1;
const NFS4ERR_NOENT: u32 = 2;
const NFS4ERR_IO: u32 = 5;
const NFS4ERR_ACCESS: u32 = 13;
const NFS4ERR_EXIST: u32 = 17;
const NFS4ERR_NOTDIR: u32 = 20;
const NFS4ERR_ISDIR: u32 = 21;
const NFS4ERR_INVAL: u32 = 22;
const NFS4ERR_FBIG: u32 = 27;
const NFS4ERR_NOSPC: u32 = 28;
const NFS4ERR_ROFS: u32 = 30;
const NFS4ERR_NAMETOOLONG: u32 = 63;
const NFS4ERR_NOTEMPTY: u32 = 66;
const NFS4ERR_STALE: u32 = 70;
const NFS4ERR_BADHANDLE: u32 = 10001;
const NFS4ERR_NOTSUPP: u32 = 10004;
const NFS4ERR_TOOSMALL: u32 = 10005;
const NFS4ERR_SERVERFAULT: u32 = 10006;
const NFS4ERR_BADTYPE: u32 = 10007;
const NFS4ERR_DELAY: u32 = 10008;
const NFS4ERR_SAME: u32 = 10009;
const NFS4ERR_DENIED: u32 = 10010;
const NFS4ERR_EXPIRED: u32 = 10011;
const NFS4ERR_LOCKED: u32 = 10012;
const NFS4ERR_GRACE: u32 = 10013;
const NFS4ERR_FHEXPIRED: u32 = 10014;
const NFS4ERR_SHARE_DENIED: u32 = 10015;
const NFS4ERR_WRONGSEC: u32 = 10016;
const NFS4ERR_CLID_INUSE: u32 = 10017;
const NFS4ERR_RESOURCE: u32 = 10018;
const NFS4ERR_MOVED: u32 = 10019;
const NFS4ERR_NOFILEHANDLE: u32 = 10020;
const NFS4ERR_MINOR_VERS_MISMATCH: u32 = 10021;
const NFS4ERR_STALE_CLIENTID: u32 = 10022;
const NFS4ERR_STALE_STATEID: u32 = 10023;
const NFS4ERR_OLD_STATEID: u32 = 10024;
const NFS4ERR_BAD_STATEID: u32 = 10025;
const NFS4ERR_BAD_SEQID: u32 = 10026;
const NFS4ERR_NOT_SAME: u32 = 10027;
const NFS4ERR_LOCK_RANGE: u32 = 10028;
const NFS4ERR_SYMLINK: u32 = 10029;
const NFS4ERR_RESTOREFH: u32 = 10030;
const NFS4ERR_LEASE_MOVED: u32 = 10031;
const NFS4ERR_ATTRNOTSUPP: u32 = 10032;
const NFS4ERR_NO_GRACE: u32 = 10033;
const NFS4ERR_RECLAIM_BAD: u32 = 10034;
const NFS4ERR_RECLAIM_CONFLICT: u32 = 10035;
const NFS4ERR_BADXDR: u32 = 10036;
const NFS4ERR_LOCKS_HELD: u32 = 10037;
const NFS4ERR_OPENMODE: u32 = 10038;
const NFS4ERR_BADOWNER: u32 = 10039;
const NFS4ERR_BADCHAR: u32 = 10040;
const NFS4ERR_BADNAME: u32 = 10041;
const NFS4ERR_BAD_RANGE: u32 = 10042;
const NFS4ERR_LOCK_NOTSUPP: u32 = 10043;
const NFS4ERR_OP_ILLEGAL: u32 = 10044;
const NFS4ERR_DEADLOCK: u32 = 10045;
const NFS4ERR_FILE_OPEN: u32 = 10046;
const NFS4ERR_ADMIN_REVOKED: u32 = 10047;
const NFS4ERR_CB_PATH_DOWN: u32 = 10048;
const NFS4ERR_BADSESSION: u32 = 10064;  // RFC 5661: session not found or invalid

// NFSv4.2 error codes (RFC 7862)
const NFS4ERR_UNION_NOTSUPP: u32 = 10028;  // RFC 7862 §13
const NFS4ERR_PARTNER_NO_AUTH: u32 = 10029;
const NFS4ERR_OFFLOAD_DENIED: u32 = 10030;
const NFS4ERR_WRONG_LFS: u32 = 10031;
const NFS4ERR_BADLABEL: u32 = 10032;

// ─── NFS4 file types ─────────────────────────────────────────────────────────
const NF4REG: u32 = 1;
const NF4DIR: u32 = 2;
const NF4LNK: u32 = 5;

// ─── Attribute bit positions (FATTR4) ────────────────────────────────────────
// Word 0 (bits 0-31)
const FATTR4_SUPPORTED_ATTRS: u32 = 0;
const FATTR4_TYPE: u32 = 1;
const FATTR4_CHANGE: u32 = 3;
const FATTR4_SIZE: u32 = 4;
const FATTR4_FSID: u32 = 8;
const FATTR4_FILEID: u32 = 20; // bit 20 in word 0, per RFC 5661 (was incorrectly 11)
const FATTR4_MODE: u32 = 33 - 32; // Word 1 bit 1
const FATTR4_NUMLINKS: u32 = 35 - 32;
const FATTR4_OWNER: u32 = 36 - 32;
const FATTR4_OWNER_GROUP: u32 = 37 - 32;
const FATTR4_SPACE_USED: u32 = 45 - 32;
const FATTR4_SPACE_FREED: u32 = 46 - 32; // NFSv4.2 (RFC 7862)
const FATTR4_TIME_ACCESS: u32 = 47 - 32;
const FATTR4_TIME_METADATA: u32 = 52 - 32;
const FATTR4_TIME_MODIFY: u32 = 53 - 32;

// ─── OPEN flags ──────────────────────────────────────────────────────────────
const OPEN4_SHARE_ACCESS_READ: u32 = 1;
const OPEN4_SHARE_ACCESS_WRITE: u32 = 2;
const OPEN4_SHARE_ACCESS_BOTH: u32 = 3;
const OPEN4_SHARE_DENY_NONE: u32 = 0;
const OPEN4_SHARE_DENY_READ: u32 = 1;
const OPEN4_SHARE_DENY_WRITE: u32 = 2;
const OPEN4_SHARE_DENY_BOTH: u32 = 3;

// OPEN4 claim types
const CLAIM_NULL: u32 = 0;
const CLAIM_PREVIOUS: u32 = 1;
const CLAIM_DELEGATE_CUR: u32 = 2;
const CLAIM_DELEGATE_PREV: u32 = 3;

// OPEN4 create modes
const UNCHECKED4: u32 = 0;
const GUARDED4: u32 = 1;
const EXCLUSIVE4: u32 = 2;

// OPEN4 open_how
const OPEN4_NOCREATE: u32 = 0;
const OPEN4_CREATE: u32 = 1;

// ─── NFS4 lock types (RFC 7530 §15.18) ──────────────────────────────────────
const READ_LT: u32 = 1;
const WRITE_LT: u32 = 2;
const READW_LT: u32 = 3;
const WRITEW_LT: u32 = 4;

// ─── Client state ─────────────────────────────────────────────────────────────
#[derive(Debug, Clone)]
struct ClientRecord {
    client_id: u64,
    verifier: [u8; 8],
    id_string: Vec<u8>,
    callback_program: u32,
    confirmed: bool,
    confirm_verifier: [u8; 8],
    sequence: u32,
    /// SEC-011: Timestamp of last operation on this client
    last_used: std::time::Instant,
}

/// Tracks an active NFSv4.1 session (created by CREATE_SESSION)
struct SessionRecord {
    session_id: [u8; 16],
    client_id: u64,
    sequence: u32,       // last sr_sequence seen
    highest_slot: u32,
    fore_max_ops: u32,
    fore_max_reqs: u32,
    /// SEC-011: Timestamp of last SEQUENCE operation on this session
    last_used: std::time::Instant,
}

/// Represents a byte-range lock held by a client
#[derive(Debug, Clone)]
struct FileLock {
    offset: u64,
    length: u64,
    lock_type: u32,
    lock_owner: Vec<u8>, // opaque owner bytes
    client_id: u64,
    lock_stateid: [u8; 12], // stateid other bytes (12 bytes, seqid always 1)
}

#[derive(Clone)]
pub struct Nfs4Server {
    exports: Arc<ExportsManager>,
    clients: Arc<RwLock<HashMap<u64, ClientRecord>>>,
    client_owner_map: Arc<RwLock<HashMap<Vec<u8>, u64>>>,
    client_counter: Arc<RwLock<u64>>,
    open_files: Arc<RwLock<HashMap<u64, PathBuf>>>, // stateid -> path
    open_counter: Arc<RwLock<u64>>,
    writeverf: [u8; 8], // write verifier, to detect server reboots
    /// File range locks: stateid_id -> list of locks on that file
    locks: Arc<RwLock<HashMap<u64, Vec<FileLock>>>>,
    lock_counter: Arc<RwLock<u64>>,
    /// NFSv4.1 sessions: session_id -> SessionRecord
    sessions: Arc<RwLock<HashMap<Vec<u8>, SessionRecord>>>,
}

// SEC-011: Lease timeout for session/client cleanup.
// NFSv4.1 spec recommends lease_time of at least 90 seconds.
// We use 5 minutes to be generous with slow clients.
const LEASE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(300);

impl Nfs4Server {
    pub fn new(exports: Arc<ExportsManager>) -> Self {
        // Generate server write verifier from current time + pid  
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default();
        let seed = (now.as_nanos() as u64) ^ (std::process::id() as u64);
        // Simple xorshift to mix the seed into 8 bytes
        let mut wv = [0u8; 8];
        let mut x = seed;
        for i in 0..8 {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            wv[i] = (x & 0xFF) as u8;
        }
        Self {
            exports,
            clients: Arc::new(RwLock::new(HashMap::new())),
            client_owner_map: Arc::new(RwLock::new(HashMap::new())),
            client_counter: Arc::new(RwLock::new(1u64)),
            open_files: Arc::new(RwLock::new(HashMap::new())),
            open_counter: Arc::new(RwLock::new(1u64)),
            writeverf: wv,
            locks: Arc::new(RwLock::new(HashMap::new())),
            lock_counter: Arc::new(RwLock::new(1u64)),
            sessions: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub async fn handle_request(&self, request: &[u8]) -> Option<Vec<u8>> {
        if request.len() < 24 {
            warn!("NFS4 request too short: {}", request.len());
            return None;
        }

        let xid_bytes = &request[0..4];
        let xid = u32::from_be_bytes([request[0], request[1], request[2], request[3]]);
        let msg_type = u32::from_be_bytes([request[4], request[5], request[6], request[7]]);
        let rpc_ver = u32::from_be_bytes([request[8], request[9], request[10], request[11]]);
        let prog = u32::from_be_bytes([request[12], request[13], request[14], request[15]]);
        let ver = u32::from_be_bytes([request[16], request[17], request[18], request[19]]);
        let procedure = u32::from_be_bytes([request[20], request[21], request[22], request[23]]);

        info!("NFS4 RPC: xid={}, prog={}, ver={}, proc={}", xid, prog, ver, procedure);
        // Hex dump for diagnostic purposes (first 256 bytes)
        let dump_len = request.len().min(256);
        let mut hex_lines = String::with_capacity(dump_len * 5);
        for (i, chunk) in request[..dump_len].chunks(16).enumerate() {
            use std::fmt::Write;
            let _ = write!(hex_lines, "\n  {:04x}: ", i * 16);
            for (j, b) in chunk.iter().enumerate() {
                if j == 8 { let _ = write!(hex_lines, " "); }
                let _ = write!(hex_lines, "{:02x} ", b);
            }
        }
        debug!("NFS4 RPC hex dump ({} bytes total, showing first {}):{}", request.len(), dump_len, hex_lines);

        // Parse cred + verifier (SEC-012: integer overflow protection)
        let mut offset = 24;
        // SEC-018: Extract cred flavor and data for root_squash check
        let caller_uid: u32 = if request.len() >= offset + 8 {
            let cred_flavor = u32::from_be_bytes([
                request[offset], request[offset+1], request[offset+2], request[offset+3],
            ]);
            let cred_len = u32::from_be_bytes([
                request[offset+4], request[offset+5], request[offset+6], request[offset+7],
            ]) as usize;
            if cred_len <= crate::nfs::MAX_XDR_OPAQUE {
                let cred_data_start = offset + 8;
                let cred_data_end = cred_data_start + cred_len;
                if cred_data_end <= request.len() {
                    ExportsManager::parse_auth_sys_uid(cred_flavor, &request[cred_data_start..cred_data_end])
                        .unwrap_or(u32::MAX) // unknown uid → not root
                } else {
                    u32::MAX
                }
            } else {
                u32::MAX
            }
        } else {
            u32::MAX
        };
        if request.len() < offset + 8 {
            return Some(make_rpc_accepted_reply(xid, ACC_SUCCESS, &self.make_compound_error(NFS4ERR_BADXDR)));
        }
        let cred_len = u32::from_be_bytes([
            request[offset+4], request[offset+5], request[offset+6], request[offset+7],
        ]) as usize;
        // SEC-012: Prevent integer overflow in padding and reject oversized cred
        if cred_len > crate::nfs::MAX_XDR_OPAQUE {
            warn!("SEC-012: cred_len {} exceeds max, rejecting", cred_len);
            return Some(make_rpc_accepted_reply(xid, 1, &[])); // GARBAGE_ARGS
        }
        let cred_padded = cred_len.checked_add(3).map(|v| v & !3);
        match cred_padded {
            Some(padded) => offset = offset.checked_add(8)?.checked_add(padded)?,
            None => {
                warn!("SEC-012: cred_len overflow in padding calculation");
                return Some(make_rpc_accepted_reply(xid, 1, &[]));
            }
        };
        if request.len() < offset + 8 {
            return Some(make_rpc_accepted_reply(xid, ACC_SUCCESS, &self.make_compound_error(NFS4ERR_BADXDR)));
        }
        let verif_len = u32::from_be_bytes([
            request[offset+4], request[offset+5], request[offset+6], request[offset+7],
        ]) as usize;
        // SEC-012: Prevent integer overflow in padding and reject oversized verif
        if verif_len > crate::nfs::MAX_XDR_OPAQUE {
            warn!("SEC-012: verif_len {} exceeds max, rejecting", verif_len);
            return Some(make_rpc_accepted_reply(xid, 1, &[]));
        }
        let verif_padded = verif_len.checked_add(3).map(|v| v & !3);
        match verif_padded {
            Some(padded) => offset = offset.checked_add(8)?.checked_add(padded)?,
            None => {
                warn!("SEC-012: verif_len overflow in padding calculation");
                return Some(make_rpc_accepted_reply(xid, 1, &[]));
            }
        };

        match procedure {
            0 => {
                // NULL procedure
                info!("NFS4 NULL");
                Some(make_rpc_accepted_reply(xid, ACC_SUCCESS, &[]))
            }
            1 => {
                // COMPOUND
                let result = self.handle_compound(xid, request, offset, caller_uid).await;
                Some(make_rpc_accepted_reply(xid, ACC_SUCCESS, &result))
            }
            _ => {
                warn!("NFS4 unknown procedure: {}", procedure);
                Some(make_rpc_accepted_reply(xid, 3, &[])) // PROC_UNAVAIL
            }
        }
    }

    // ──────────────────────────────────────────────────────────────────────────
    // COMPOUND handler
    // ──────────────────────────────────────────────────────────────────────────
    async fn handle_compound(&self, xid: u32, request: &[u8], args_start: usize, caller_uid: u32) -> Vec<u8> {
        let mut p = args_start;

        // tag (opaque<>)
        if p + 4 > request.len() {
            return self.make_compound_error(NFS4ERR_BADXDR);
        }
        let tag_len = u32::from_be_bytes([request[p], request[p+1], request[p+2], request[p+3]]) as usize;
        // SEC-012: Limit tag length to prevent overflow
        if tag_len > crate::nfs::MAX_XDR_OPAQUE {
            warn!("SEC-012: tag_len {} exceeds max, rejecting", tag_len);
            return self.make_compound_error(NFS4ERR_BADXDR);
        }
        p += 4;
        let tag_bytes = if p + tag_len <= request.len() {
            request[p..p+tag_len].to_vec()
        } else {
            return self.make_compound_error(NFS4ERR_BADXDR);
        };
        // SEC-012: Use checked_add for padding
        p += match tag_len.checked_add(3) {
            Some(v) => v & !3,
            None => return self.make_compound_error(NFS4ERR_BADXDR),
        };

        // minor_version
        if p + 4 > request.len() {
            return self.make_compound_error(NFS4ERR_BADXDR);
        }
        let minor_version = u32::from_be_bytes([request[p], request[p+1], request[p+2], request[p+3]]);
        p += 4;

        // We support minor versions 0, 1, and 2 (NFSv4.0, NFSv4.1, NFSv4.2)
        if minor_version > 2 {
            info!("NFS4 COMPOUND: unsupported minor_version={}", minor_version);
            return self.make_compound_error(NFS4ERR_MINOR_VERS_MISMATCH);
        }

        // opcount
        if p + 4 > request.len() {
            return self.make_compound_error(NFS4ERR_BADXDR);
        }
        let opcount = u32::from_be_bytes([request[p], request[p+1], request[p+2], request[p+3]]) as usize;
        p += 4;

        // SEC-008: Limit the number of operations per COMPOUND to prevent CPU exhaustion
        if opcount > crate::nfs::MAX_OPS_PER_COMPOUND {
            warn!("NFS4 COMPOUND: opcount={} exceeds max {}, rejecting", opcount, crate::nfs::MAX_OPS_PER_COMPOUND);
            return self.make_compound_error(NFS4ERR_RESOURCE);
        }

        // Dump first 64 bytes of compound args to see opcodes
        let dump_end = std::cmp::min(args_start + 64, request.len());
        let dump_hex: String = request[args_start..dump_end].chunks(4)
            .enumerate()
            .map(|(i, c)| {
                let val = c.iter().fold(0u32, |acc, &b| (acc << 8) | b as u32);
                format!("[{}]={:08x}", i*4, val)
            })
            .collect::<Vec<_>>()
            .join(" ");
        info!("NFS4 COMPOUND: tag_len={}, minor_version={}, opcount={}", tag_len, minor_version, opcount);
        debug!("NFS4 COMPOUND args_head: {}", dump_hex);

        // Context for stateful operations within this compound
        let mut current_fh: Option<Vec<u8>> = None; // current file handle
        let mut saved_fh: Option<Vec<u8>> = None;   // saved file handle

        let mut op_results: Vec<u8> = Vec::new();
        let mut compound_status = NFS4_OK;
        let mut res_op_count: u32 = 0;

        for op_idx in 0..opcount {
            if p + 4 > request.len() {
                compound_status = NFS4ERR_BADXDR;
                // Encode partial error
                op_results.extend_from_slice(&OP_ILLEGAL.to_be_bytes());
                op_results.extend_from_slice(&compound_status.to_be_bytes());
                break;
            }

            let opcode = u32::from_be_bytes([request[p], request[p+1], request[p+2], request[p+3]]);
            p += 4;

            debug!("NFS4 COMPOUND op[{}]: opcode={}", op_idx, opcode);

            // SEC-018: root_squash check for write operations.
            // If caller is root (uid=0) and the export has root_squash enabled,
            // reject the write operation with NFS4ERR_PERM.
            if caller_uid == 0 && Self::is_write_opcode(opcode) {
                if let Some(ref fh) = current_fh {
                    if self.exports.should_squash_root(fh, caller_uid).await {
                        warn!("SEC-018: root_squash blocking opcode={} from root user", opcode);
                        op_results.extend_from_slice(&opcode.to_be_bytes());
                        op_results.extend_from_slice(&NFS4ERR_PERM.to_be_bytes());
                        res_op_count += 1;
                        compound_status = NFS4ERR_PERM;
                        break;
                    }
                }
            }

            let (op_result, advance, new_fh, new_saved_fh, status) = self.dispatch_op(
                opcode,
                request,
                p,
                &current_fh,
                &saved_fh,
            ).await;

            // Write opcode + status + result
            op_results.extend_from_slice(&opcode.to_be_bytes());
            op_results.extend_from_slice(&status.to_be_bytes());
            if status == NFS4_OK {
                op_results.extend_from_slice(&op_result);
            }
            res_op_count += 1;

            p += advance;

            if let Some(fh) = new_fh {
                current_fh = Some(fh);
            }
            if let Some(sfh) = new_saved_fh {
                saved_fh = Some(sfh);
            }

            if status != NFS4_OK {
                compound_status = status;
                info!("NFS4 COMPOUND: op[{}] opcode={} failed with status={}", op_idx, opcode, status);
                // Stop processing further ops
                break;
            }
        }

        // Build final COMPOUND reply body:
        // status(4) + tag(xdr opaque) + rescount(4) + [op_results]
        let mut body = Vec::new();
        body.extend_from_slice(&compound_status.to_be_bytes());
        // echo back the tag as XDR opaque<>
        let tag_len_u32 = tag_bytes.len() as u32;
        body.extend_from_slice(&tag_len_u32.to_be_bytes());
        body.extend_from_slice(&tag_bytes);
        // XDR padding for tag
        let tag_actual_len = tag_bytes.len();
        let tag_padded = (tag_actual_len + 3) & !3;
        let tag_padding = tag_padded - tag_actual_len;
        for _ in 0..tag_padding { body.push(0); }

        // rescount: actual number of operation results returned
        body.extend_from_slice(&res_op_count.to_be_bytes());
        body.extend_from_slice(&op_results);

        // Debug: log the COMPOUND response body layout
        let body_hex: String = body.chunks(4)
            .enumerate()
            .map(|(i, c)| {
                let val = c.iter().fold(0u32, |acc, &b| (acc << 8) | b as u32);
                format!("[{}]={:08x}", i*4, val)
            })
            .collect::<Vec<_>>()
            .join(" ");
        debug!("COMPOUND body ({} bytes): {}", body.len(), body_hex);
        debug!("  status={} tag_len={} resarray_count={} op_results_len={}",
            compound_status, tag_bytes.len(), res_op_count, op_results.len());

        body
    }

    // ──────────────────────────────────────────────────────────────────────────
    // Dispatch individual NFS4 operations
    // Returns: (result_bytes, bytes_consumed_from_request, new_current_fh, new_saved_fh, status)
    // ──────────────────────────────────────────────────────────────────────────
    async fn dispatch_op(
        &self,
        opcode: u32,
        request: &[u8],
        p: usize,
        current_fh: &Option<Vec<u8>>,
        saved_fh: &Option<Vec<u8>>,
    ) -> (Vec<u8>, usize, Option<Vec<u8>>, Option<Vec<u8>>, u32) {
        match opcode {
            OP_PUTROOTFH => self.op_putrootfh(request, p).await,
            OP_PUTFH => self.op_putfh(request, p).await,
            OP_PUTPUBFH => self.op_putrootfh(request, p).await, // treat same as PUTROOTFH
            OP_GETFH => self.op_getfh(request, p, current_fh).await,
            OP_SAVEFH => self.op_savefh(request, p, current_fh).await,
            OP_RESTOREFH => self.op_restorefh(request, p, saved_fh).await,
            OP_GETATTR => self.op_getattr(request, p, current_fh).await,
            OP_LOOKUP => self.op_lookup(request, p, current_fh).await,
            OP_LOOKUPP => self.op_lookupp(request, p, current_fh).await,
            OP_ACCESS => self.op_access(request, p, current_fh).await,
            OP_OPEN => self.op_open(request, p, current_fh).await,
            OP_OPEN_CONFIRM => self.op_open_confirm(request, p, current_fh).await,
            OP_CLOSE => self.op_close(request, p, current_fh).await,
            OP_READ => self.op_read(request, p, current_fh).await,
            OP_WRITE => self.op_write(request, p, current_fh).await,
            OP_READDIR => self.op_readdir(request, p, current_fh).await,
            OP_READLINK => self.op_readlink(request, p, current_fh).await,
            OP_REMOVE => self.op_remove(request, p, current_fh).await,
            OP_RENAME => self.op_rename(request, p, current_fh, saved_fh).await,
            OP_SETATTR => self.op_setattr(request, p, current_fh).await,
            OP_CREATE => self.op_create(request, p, current_fh).await,
            OP_SETCLIENTID => self.op_setclientid(request, p).await,
            OP_SETCLIENTID_CONFIRM => self.op_setclientid_confirm(request, p).await,
            OP_RENEW => self.op_renew(request, p).await,
            OP_SECINFO => self.op_secinfo(request, p).await,
            // NFS v4.1 operations
            OP_EXCHANGE_ID => self.op_exchange_id(request, p).await,
            OP_CREATE_SESSION => self.op_create_session(request, p).await,
            OP_DESTROY_SESSION => self.op_destroy_session(request, p).await,
            OP_BIND_CONN_TO_SESSION => self.op_bind_conn_to_session(request, p).await,
            OP_DESTROY_CLIENTID => self.op_destroy_clientid(request, p).await,
            OP_SEQUENCE => self.op_sequence(request, p).await,
            OP_RECLAIM_COMPLETE => self.op_reclaim_complete(request, p).await,
            OP_SECINFO_NO_NAME => self.op_secinfo_no_name(request, p).await,
            OP_OPEN_DOWNGRADE => {
                // Stub: NFSv4.0 OPEN_DOWNGRADE — not implemented, but must not error
                info!("NFS4 OPEN_DOWNGRADE (stub)");
                // Parse seqid(4) + stateid(16) + share_access(4) + share_deny(4)
                // Return NFS4_OK with the same stateid
                if p + 28 > request.len() { return (vec![], 0, None, None, NFS4ERR_BADXDR); }
                let stateid = &request[p+4..p+20];
                let mut result = Vec::new();
                result.extend_from_slice(stateid); // return same stateid
                (result, 28, None, None, NFS4_OK)
            },
            OP_RELEASE_LOCKOWNER => {
                info!("NFS4 RELEASE_LOCKOWNER (stub)");
                // Parse lock_owner(20) — opaque id
                // Just acknowledge and return OK
                if p + 8 > request.len() { return (vec![], 0, None, None, NFS4ERR_BADXDR); }
                let owner_len = u32::from_be_bytes([request[p+4], request[p+5], request[p+6], request[p+7]]) as usize;
                let consumed = 8 + ((owner_len + 3) & !3);
                (vec![], consumed, None, None, NFS4_OK)
            },
            OP_NVERIFY | OP_VERIFY => self.op_verify(opcode, request, p, current_fh).await,
            OP_DELEGRETURN => self.op_delegreturn(request, p).await,
            OP_COMMIT => self.op_commit(request, p, current_fh).await,
            OP_LINK => self.op_link(request, p, current_fh, saved_fh).await,
            OP_LOCK => self.op_lock(request, p, current_fh).await,
            OP_LOCKT => self.op_lockt(request, p, current_fh).await,
            OP_LOCKU => self.op_locku(request, p, current_fh).await,
            OP_ILLEGAL => {
                warn!("NFS4 received OP_ILLEGAL in COMPOUND");
                (vec![], 0, None, None, NFS4ERR_OP_ILLEGAL)
            }
            // ─── NFS v4.2 operations ────────────────────────────────────
            OP_READ_PLUS => self.op_read_plus(request, p, current_fh).await,
            OP_COPY => self.op_copy(request, p, current_fh, saved_fh).await,
            OP_SEEK => self.op_seek(request, p, current_fh).await,
            OP_CLONE => self.op_clone(request, p, current_fh, saved_fh).await,
            OP_ALLOCATE | OP_DEALLOCATE | OP_IO_ADVISE |
            OP_LAYOUTERROR | OP_LAYOUTSTATS |
            OP_OFFLOAD_CANCEL | OP_OFFLOAD_STATUS |
            OP_WRITE_SAME | OP_COPY_NOTIFY => {
                debug!("NFS4.2 op {} not supported, returning NOTSUPP", opcode);
                (vec![], 0, None, None, NFS4ERR_NOTSUPP)
            }
            _ => {
                warn!("NFS4 unsupported op: {}", opcode);
                (vec![], 0, None, None, NFS4ERR_NOTSUPP)
            }
        }
    }

    // ──────────────────────────────────────────────────────────────────────────
    // Op implementations
    // ──────────────────────────────────────────────────────────────────────────

    async fn op_putrootfh(&self, _request: &[u8], _p: usize) 
        -> (Vec<u8>, usize, Option<Vec<u8>>, Option<Vec<u8>>, u32) 
    {
        info!("NFS4 PUTROOTFH");
        // Return a special root file handle that represents the NFS v4 pseudo-filesystem root "/"
        // This handle has fhid = u64::MAX to distinguish it from real file handles
        let root_fh = Self::encode_synthetic_handle(u64::MAX, b"nfs4root");
        (vec![], 0, Some(root_fh), None, NFS4_OK)
    }
    
    /// Encode a synthetic file handle for special paths (root, etc.)
    fn encode_synthetic_handle(fhid: u64, magic: &[u8]) -> Vec<u8> {
        let mut fh = Vec::with_capacity(32);
        fh.extend_from_slice(&fhid.to_be_bytes());  // 8 bytes
        fh.extend_from_slice(&1u64.to_be_bytes());  // inode = 1 for synthetic
        fh.extend_from_slice(&1u32.to_be_bytes()); // gen = 1
        fh.extend_from_slice(magic);                // magic bytes
        while fh.len() < 32 {
            fh.push(0);
        }
        fh.truncate(32);
        fh
    }
    
    /// Check if a file handle represents the NFS v4 root
    fn is_root_handle(fh: &[u8]) -> bool {
        if fh.len() < 16 { return false; }
        let fhid = u64::from_be_bytes([fh[0], fh[1], fh[2], fh[3], fh[4], fh[5], fh[6], fh[7]]);
        fhid == u64::MAX
    }
    
    /// Decode file handle ID from a 32-byte file handle
    fn decode_fhid(fh: &[u8]) -> Option<u64> {
        if fh.len() < 8 { return None; }
        Some(u64::from_be_bytes([fh[0], fh[1], fh[2], fh[3], fh[4], fh[5], fh[6], fh[7]]))
    }

    async fn op_putfh(&self, request: &[u8], p: usize)
        -> (Vec<u8>, usize, Option<Vec<u8>>, Option<Vec<u8>>, u32)
    {
        // fh: opaque<> with 4-byte length prefix
        if p + 4 > request.len() {
            return (vec![], 0, None, None, NFS4ERR_BADXDR);
        }
        let fh_len = u32::from_be_bytes([request[p], request[p+1], request[p+2], request[p+3]]) as usize;
        let p2 = p + 4;
        if p2 + fh_len > request.len() {
            return (vec![], p + 4, None, None, NFS4ERR_BADXDR);
        }
        let fh = request[p2..p2+fh_len].to_vec();
        let consumed = 4 + ((fh_len + 3) & !3);
        debug!("NFS4 PUTFH: fh_len={}", fh_len);

        // RFC 3530 §8.1.3: PUTFH sets the current filehandle.
        // We do minimal format validation here; if the FH is stale/unknown,
        // the subsequent operation (GETATTR, READDIR, etc.) will return
        // NFS4ERR_STALE when resolve_fh() returns None.
        // Doing full fh_map lookup here breaks after server restart because
        // previously-issued FHs are valid but not yet in the new in-memory map.
        // Instead we accept any FH with valid length and let the inode be
        // re-registered on first use via try_rebuild_fh().
        if fh_len == 0 {
            return (vec![], consumed, None, None, NFS4ERR_BADHANDLE);
        }
        // Try to rebuild the FH mapping from the handle bytes if not already known
        // (handles surviving across server restarts)
        self.exports.try_rebuild_fh(&fh).await;
        (vec![], consumed, Some(fh), None, NFS4_OK)
    }

    async fn op_getfh(&self, _request: &[u8], _p: usize, current_fh: &Option<Vec<u8>>)
        -> (Vec<u8>, usize, Option<Vec<u8>>, Option<Vec<u8>>, u32)
    {
        info!("NFS4 GETFH");
        match current_fh {
            None => (vec![], 0, None, None, NFS4ERR_NOFILEHANDLE),
            Some(fh) => {
                let result = Self::encode_fh_for_result(fh);
                (result, 0, None, None, NFS4_OK)
            }
        }
    }

    async fn op_savefh(&self, _request: &[u8], _p: usize, current_fh: &Option<Vec<u8>>)
        -> (Vec<u8>, usize, Option<Vec<u8>>, Option<Vec<u8>>, u32)
    {
        info!("NFS4 SAVEFH");
        match current_fh {
            None => (vec![], 0, None, None, NFS4ERR_NOFILEHANDLE),
            Some(fh) => (vec![], 0, None, Some(fh.clone()), NFS4_OK),
        }
    }

    async fn op_restorefh(&self, _request: &[u8], _p: usize, saved_fh: &Option<Vec<u8>>)
        -> (Vec<u8>, usize, Option<Vec<u8>>, Option<Vec<u8>>, u32)
    {
        info!("NFS4 RESTOREFH");
        match saved_fh {
            None => (vec![], 0, None, None, NFS4ERR_RESTOREFH),
            Some(fh) => (vec![], 0, Some(fh.clone()), None, NFS4_OK),
        }
    }

    async fn op_getattr(&self, request: &[u8], p: usize, current_fh: &Option<Vec<u8>>)
        -> (Vec<u8>, usize, Option<Vec<u8>>, Option<Vec<u8>>, u32)
    {
        info!("NFS4 GETATTR");
        let fh = match current_fh {
            None => return (vec![], 0, None, None, NFS4ERR_NOFILEHANDLE),
            Some(fh) => fh,
        };

        // Parse attr_request bitmap: count(4) + words...
        if p + 4 > request.len() {
            return (vec![], 0, None, None, NFS4ERR_BADXDR);
        }
        let bitmap_count = u32::from_be_bytes([request[p], request[p+1], request[p+2], request[p+3]]) as usize;
        let consumed = 4 + bitmap_count * 4;
        if p + consumed > request.len() {
            return (vec![], consumed, None, None, NFS4ERR_BADXDR);
        }
        let mut bitmap_words = vec![0u32; bitmap_count];
        for i in 0..bitmap_count {
            bitmap_words[i] = u32::from_be_bytes([
                request[p + 4 + i*4],
                request[p + 4 + i*4 + 1],
                request[p + 4 + i*4 + 2],
                request[p + 4 + i*4 + 3],
            ]);
        }
        debug!("NFS4 GETATTR: bitmap_words={:?}", bitmap_words);

        // Get file metadata.
        // For the NFSv4 root handle, resolve to the export root so that
        // the attributes include NF4DIR (directory type). The kernel
        // NFS client requires the root to be a directory for mount.
        let path = if Self::is_root_handle(fh) {
            // Use the first export root path as a directory reference
            self.exports.get_first_export_root().await
        } else {
            self.exports.resolve_fh(fh).await
        };

        // The default_type is used by build_fattr4 when metadata is unavailable.
        // For root handles we pass NF4DIR so that `type` is reported correctly
        // IF the client requests it. We do NOT force-inject bit 1 (type) into the
        // request bitmap: RFC 3530 §8.4 says the server MUST only return what
        // was requested. Adding unrequested attributes causes the client's XDR
        // parser to misalign and silently drop the connection.
        let is_root = Self::is_root_handle(fh);
        debug!("NFS4 GETATTR: is_root_handle={}, bitmap_words={:?}, fh_bytes[..8]={:?}", 
            is_root, bitmap_words, fh.get(..8));
        // DEBUG: extract and log inode from FH bytes for comparison with build_fattr4 fileid
        if fh.len() >= 16 {
            let fh_inode = u64::from_be_bytes(fh[8..16].try_into().unwrap_or([0u8; 8]));
            let fh_fhid = u64::from_be_bytes(fh[0..8].try_into().unwrap_or([0u8; 8]));
            debug!("NFS4 GETATTR: fh_fhid={}, fh_inode={:016x}, resolved_path={:?}",
                fh_fhid, fh_inode, path);
        }
        let default_type = if is_root { NF4DIR } else { NF4REG };
        let result = self.build_fattr4(&path, &bitmap_words, default_type, is_root).await;
        (result, consumed, None, None, NFS4_OK)
    }

    /// Encode a file handle as XDR opaque<> for LOOKUP/GETFH result
    fn encode_fh_for_result(fh: &[u8]) -> Vec<u8> {
        let mut result = Vec::new();
        let fh_len = fh.len() as u32;
        result.extend_from_slice(&fh_len.to_be_bytes());
        result.extend_from_slice(fh);
        let padded = (fh.len() + 3) & !3;
        let pad = padded - fh.len();
        result.resize(result.len() + pad, 0);
        result
    }

    async fn op_lookup(&self, request: &[u8], p: usize, current_fh: &Option<Vec<u8>>)
        -> (Vec<u8>, usize, Option<Vec<u8>>, Option<Vec<u8>>, u32)
    {
        let fh = match current_fh {
            None => return (vec![], 0, None, None, NFS4ERR_NOFILEHANDLE),
            Some(fh) => fh,
        };

        // component4: utf8str opaque<>
        if p + 4 > request.len() {
            return (vec![], 0, None, None, NFS4ERR_BADXDR);
        }
        let name_len = u32::from_be_bytes([request[p], request[p+1], request[p+2], request[p+3]]) as usize;
        let consumed = 4 + ((name_len + 3) & !3);
        if p + 4 + name_len > request.len() {
            return (vec![], consumed, None, None, NFS4ERR_BADXDR);
        }
        let name = String::from_utf8_lossy(&request[p+4..p+4+name_len]).to_string();
        info!("NFS4 LOOKUP: name='{}'", name);

        // Check if this is a lookup on the root directory
        if Self::is_root_handle(fh) {
            // On root, look up by export name or alias
            match self.exports.get_export(&name).await {
                Some(export) => {
                    let path_str = export.path.to_string_lossy().to_string();
                    // DEBUG: log fileid before creating FH to compare with READDIR
                    let pre_fileid = self.exports.get_inode(&export.path);
                    let path_hex: String = path_str.as_bytes().iter()
                        .map(|b| format!("{:02x}", b))
                        .collect::<Vec<_>>()
                        .join("");
                    let export_fh = self.exports.create_file_handle(
                        &path_str
                    ).await;
                    debug!("NFS4 LOOKUP: found export '{}' -> '{}', path_hex={}, pre_fileid={:016x}",
                        name, path_str, path_hex, pre_fileid);
                    // RFC 3530 §14.2.18: LOOKUP4res for NFS4_OK returns void.
                    // The new FH is set as current_fh via the third return value.
                    // The client retrieves it via GETFH, not from the LOOKUP response.
                    return (vec![], consumed, Some(export_fh), None, NFS4_OK);
                }
                None => {
                    info!("NFS4 LOOKUP: export '{}' not found", name);
                    return (vec![], consumed, None, None, NFS4ERR_NOENT);
                }
            }
        }

        // Normal lookup within a directory
        match self.exports.lookup_child(fh, &name).await {
            None => (vec![], consumed, None, None, NFS4ERR_NOENT),
            Some((child_fh, _child_path)) => {
                // RFC 3530 §14.2.18: LOOKUP4res for NFS4_OK returns void.
                // The new FH is set as current_fh via the third return value.
                (vec![], consumed, Some(child_fh), None, NFS4_OK)
            }
        }
    }

    async fn op_lookupp(&self, _request: &[u8], _p: usize, current_fh: &Option<Vec<u8>>)
        -> (Vec<u8>, usize, Option<Vec<u8>>, Option<Vec<u8>>, u32)
    {
        info!("NFS4 LOOKUPP");
        let fh = match current_fh {
            None => return (vec![], 0, None, None, NFS4ERR_NOFILEHANDLE),
            Some(fh) => fh,
        };
        // Root handle (fhid=u64::MAX) is synthetic; its parent is itself
        if Self::is_root_handle(fh) {
            info!("NFS4 LOOKUPP: root handle, returning self as parent");
            return (vec![], 0, Some(fh.clone()), None, NFS4_OK);
        }
        let path = match self.exports.resolve_fh(fh).await {
            None => return (vec![], 0, None, None, NFS4ERR_STALE),
            Some(p) => p,
        };
        let parent = match path.parent() {
            None => return (vec![], 0, None, None, NFS4ERR_NOENT),
            Some(p) => p.to_path_buf(),
        };
        // Check parent is still within an export
        let export_root = self.exports.get_fh_export_root(fh).await
            .unwrap_or_else(|| parent.clone());
        if !parent.starts_with(&export_root) {
            return (vec![], 0, None, None, NFS4ERR_NOENT);
        }
        let parent_fh = self.exports.get_or_create_fh(parent, export_root).await;
        (vec![], 0, Some(parent_fh), None, NFS4_OK)
    }

    async fn op_access(&self, request: &[u8], p: usize, current_fh: &Option<Vec<u8>>)
        -> (Vec<u8>, usize, Option<Vec<u8>>, Option<Vec<u8>>, u32)
    {
        info!("NFS4 ACCESS");
        if current_fh.is_none() {
            return (vec![], 4, None, None, NFS4ERR_NOFILEHANDLE);
        }
        let consumed = 4; // access4 is a single u32

        // Return all access bits as granted
        let access_supported: u32 = 0x3F; // READ|LOOKUP|MODIFY|EXTEND|DELETE|EXECUTE
        let access_rights: u32 = 0x3F;

        let mut result = Vec::new();
        result.extend_from_slice(&access_supported.to_be_bytes());
        result.extend_from_slice(&access_rights.to_be_bytes());
        (result, consumed, None, None, NFS4_OK)
    }

    async fn op_open(&self, request: &[u8], p: usize, current_fh: &Option<Vec<u8>>)
        -> (Vec<u8>, usize, Option<Vec<u8>>, Option<Vec<u8>>, u32)
    {
        info!("NFS4 OPEN");
        let dir_fh = match current_fh {
            None => return (vec![], 0, None, None, NFS4ERR_NOFILEHANDLE),
            Some(fh) => fh,
        };

        let mut pp = p;

        // seqid(4)
        if pp + 4 > request.len() { return (vec![], 0, None, None, NFS4ERR_BADXDR); }
        let seqid = u32::from_be_bytes([request[pp], request[pp+1], request[pp+2], request[pp+3]]);
        pp += 4;

        // share_access(4)
        if pp + 4 > request.len() { return (vec![], pp-p, None, None, NFS4ERR_BADXDR); }
        let share_access = u32::from_be_bytes([request[pp], request[pp+1], request[pp+2], request[pp+3]]);
        pp += 4;

        // share_deny(4)
        if pp + 4 > request.len() { return (vec![], pp-p, None, None, NFS4ERR_BADXDR); }
        let share_deny = u32::from_be_bytes([request[pp], request[pp+1], request[pp+2], request[pp+3]]);
        pp += 4;

        // owner: clientid(8) + owner opaque<>
        if pp + 8 > request.len() { return (vec![], pp-p, None, None, NFS4ERR_BADXDR); }
        let clientid = u64::from_be_bytes([
            request[pp], request[pp+1], request[pp+2], request[pp+3],
            request[pp+4], request[pp+5], request[pp+6], request[pp+7],
        ]);
        pp += 8;
        if pp + 4 > request.len() { return (vec![], pp-p, None, None, NFS4ERR_BADXDR); }
        let owner_len = u32::from_be_bytes([request[pp], request[pp+1], request[pp+2], request[pp+3]]) as usize;
        pp += 4 + ((owner_len + 3) & !3);

        // openflag: opentype(4)
        if pp + 4 > request.len() { return (vec![], pp-p, None, None, NFS4ERR_BADXDR); }
        let opentype = u32::from_be_bytes([request[pp], request[pp+1], request[pp+2], request[pp+3]]);
        pp += 4;

        info!("NFS4 OPEN: seqid={}, share_access={}, opentype={}", seqid, share_access, opentype);

        if opentype == OPEN4_CREATE {
            // createmode(4) + attrs
            if pp + 4 > request.len() { return (vec![], pp-p, None, None, NFS4ERR_BADXDR); }
            let createmode = u32::from_be_bytes([request[pp], request[pp+1], request[pp+2], request[pp+3]]);
            pp += 4;
            // skip attrs bitmap + attrs
            if pp + 4 > request.len() { return (vec![], pp-p, None, None, NFS4ERR_BADXDR); }
            let bm_count = u32::from_be_bytes([request[pp], request[pp+1], request[pp+2], request[pp+3]]) as usize;
            pp += 4 + bm_count * 4;
            if pp + 4 > request.len() { return (vec![], pp-p, None, None, NFS4ERR_BADXDR); }
            let attr_data_len = u32::from_be_bytes([request[pp], request[pp+1], request[pp+2], request[pp+3]]) as usize;
            pp += 4 + ((attr_data_len + 3) & !3);
        }

        // claim type(4)
        if pp + 4 > request.len() { return (vec![], pp-p, None, None, NFS4ERR_BADXDR); }
        let claim_type = u32::from_be_bytes([request[pp], request[pp+1], request[pp+2], request[pp+3]]);
        pp += 4;

        // For CLAIM_NULL: filename opaque<>
        let mut filename = String::new();
        if claim_type == CLAIM_NULL {
            if pp + 4 > request.len() { return (vec![], pp-p, None, None, NFS4ERR_BADXDR); }
            let name_len = u32::from_be_bytes([request[pp], request[pp+1], request[pp+2], request[pp+3]]) as usize;
            pp += 4;
            if pp + name_len > request.len() { return (vec![], pp-p, None, None, NFS4ERR_BADXDR); }
            filename = String::from_utf8_lossy(&request[pp..pp+name_len]).to_string();
            pp += (name_len + 3) & !3;
        }

        let consumed = pp - p;
        info!("NFS4 OPEN: filename='{}'", filename);

        // Resolve directory path
        let dir_path = match self.exports.resolve_fh(dir_fh).await {
            None => return (vec![], consumed, None, None, NFS4ERR_STALE),
            Some(p) => p,
        };

        let file_path = if filename.is_empty() {
            dir_path.clone()
        } else {
            dir_path.join(&filename)
        };

        // Create file if needed
        if opentype == OPEN4_CREATE {
            // SEC-002: Reject file creation on read-only exports
            if self.exports.is_read_only(dir_fh).await {
                warn!("NFS4 OPEN CREATE: rejected — export is read-only");
                return (vec![], consumed, None, None, NFS4ERR_ROFS);
            }
            if !file_path.exists() {
                if let Err(e) = std::fs::File::create(to_extended_path(&file_path)) {
                    warn!("NFS4 OPEN create failed: {}", e);
                    return (vec![], consumed, None, None, NFS4ERR_IO);
                }
            }
        }

        if !file_path.exists() {
            return (vec![], consumed, None, None, NFS4ERR_NOENT);
        }

        // Get/create FH for the file
        let export_root = self.exports.get_fh_export_root(dir_fh).await
            .unwrap_or_else(|| dir_path.clone());
        let file_fh = self.exports.get_or_create_fh(file_path.clone(), export_root).await;

        // Allocate stateid
        let stateid_id = {
            let mut ctr = self.open_counter.write().await;
            let id = *ctr;
            *ctr += 1;
            id
        };
        {
            let mut of = self.open_files.write().await;
            of.insert(stateid_id, file_path);
        }

        // Build OPEN4resok:
        // stateid4: seqid(4) + other(12)
        // cinfo: atomic(4) + before(8) + after(8)
        // rflags(4)
        // attrset bitmap
        // delegation: OPEN_DELEGATE_NONE(4)
        let mut result = Vec::new();
        // stateid
        result.extend_from_slice(&1u32.to_be_bytes()); // seqid=1
        let mut stateid_other = [0u8; 12];
        stateid_other[0..8].copy_from_slice(&stateid_id.to_be_bytes());
        result.extend_from_slice(&stateid_other);
        // cinfo: atomic=0, before=0, after=0
        result.extend_from_slice(&0u32.to_be_bytes()); // atomic
        result.extend_from_slice(&0u64.to_be_bytes()); // before
        result.extend_from_slice(&0u64.to_be_bytes()); // after
        // rflags: 0 (NFSv4.1 does NOT use OPEN4_RESULT_CONFIRM=2)
        result.extend_from_slice(&0u32.to_be_bytes());
        // attrset: empty bitmap
        result.extend_from_slice(&0u32.to_be_bytes()); // 0 bitmap words
        // delegation: OPEN_DELEGATE_NONE=0
        result.extend_from_slice(&0u32.to_be_bytes());

        (result, consumed, Some(file_fh), None, NFS4_OK)
    }

    async fn op_open_confirm(&self, request: &[u8], p: usize, current_fh: &Option<Vec<u8>>)
        -> (Vec<u8>, usize, Option<Vec<u8>>, Option<Vec<u8>>, u32)
    {
        info!("NFS4 OPEN_CONFIRM");
        if current_fh.is_none() {
            return (vec![], 16, None, None, NFS4ERR_NOFILEHANDLE);
        }
        // stateid(16) + seqid(4)
        let consumed = 20;
        // Return stateid (echo input stateid with incremented seqid)
        let mut result = Vec::new();
        if p + 16 <= request.len() {
            result.extend_from_slice(&[0,0,0,1]); // seqid=1
            result.extend_from_slice(&request[p+4..p+16]); // other = same as input
        } else {
            result.extend_from_slice(&[0u8; 16]);
        }
        (result, consumed, None, None, NFS4_OK)
    }

    async fn op_close(&self, request: &[u8], p: usize, current_fh: &Option<Vec<u8>>)
        -> (Vec<u8>, usize, Option<Vec<u8>>, Option<Vec<u8>>, u32)
    {
        info!("NFS4 CLOSE");
        // seqid(4) + stateid(16) = 20 bytes
        let consumed = 20;
        if current_fh.is_none() {
            return (vec![], consumed, None, None, NFS4ERR_NOFILEHANDLE);
        }
        // Parse stateid: seqid(4) + other(12), stateid_id is in other[0..8]
        if p + 20 <= request.len() {
            let stateid_id = u64::from_be_bytes([
                request[p+4], request[p+5], request[p+6], request[p+7],
                request[p+8], request[p+9], request[p+10], request[p+11],
            ]);
            let mut of = self.open_files.write().await;
            of.remove(&stateid_id);
            info!("NFS4 CLOSE: removed stateid_id={}", stateid_id);
        }
        // Return special stateid (all zeros = CLOSED)
        let result = vec![0u8; 16];
        (result, consumed, None, None, NFS4_OK)
    }

    async fn op_read(&self, request: &[u8], p: usize, current_fh: &Option<Vec<u8>>)
        -> (Vec<u8>, usize, Option<Vec<u8>>, Option<Vec<u8>>, u32)
    {
        info!("NFS4 READ");
        let fh = match current_fh {
            None => return (vec![], 24, None, None, NFS4ERR_NOFILEHANDLE),
            Some(fh) => fh,
        };

        // stateid(16) + offset(8) + count(4) = 28 bytes
        let consumed = 28;
        if p + consumed > request.len() {
            return (vec![], consumed, None, None, NFS4ERR_BADXDR);
        }

        let offset = u64::from_be_bytes([
            request[p+16], request[p+17], request[p+18], request[p+19],
            request[p+20], request[p+21], request[p+22], request[p+23],
        ]);
        let count = u32::from_be_bytes([
            request[p+24], request[p+25], request[p+26], request[p+27],
        ]) as usize;

        info!("NFS4 READ: offset={}, count={}", offset, count);

        let path = match self.exports.resolve_fh(fh).await {
            None => return (vec![], consumed, None, None, NFS4ERR_STALE),
            Some(p) => p,
        };

        // Read file data — use extended path to handle files in long-path directories.
        let data = match std::fs::read(to_extended_path(&path)) {
            Err(e) => {
                warn!("NFS4 READ: failed to read {}: {}", path.display(), e);
                return (vec![], consumed, None, None, NFS4ERR_IO);
            }
            Ok(d) => d,
        };

        let file_size = data.len() as u64;
        let start = offset.min(file_size) as usize;
        let end = (start + count).min(data.len());
        let read_data = &data[start..end];
        let eof = end >= data.len();

        // READ4resok: eof(4) + data opaque<>
        let mut result = Vec::new();
        result.extend_from_slice(&(eof as u32).to_be_bytes());
        let data_len = read_data.len() as u32;
        result.extend_from_slice(&data_len.to_be_bytes());
        result.extend_from_slice(read_data);
        // XDR pad
        let padded = (read_data.len() + 3) & !3;
        let pad = padded - read_data.len();
        result.resize(result.len() + pad, 0);

        (result, consumed, None, None, NFS4_OK)
    }

    async fn op_write(&self, request: &[u8], p: usize, current_fh: &Option<Vec<u8>>)
        -> (Vec<u8>, usize, Option<Vec<u8>>, Option<Vec<u8>>, u32)
    {
        info!("NFS4 WRITE");
        let fh = match current_fh {
            None => return (vec![], 0, None, None, NFS4ERR_NOFILEHANDLE),
            Some(fh) => fh,
        };

        // SEC-002: Reject writes to read-only exports
        if self.exports.is_read_only(fh).await {
            warn!("NFS4 WRITE: rejected — export is read-only");
            return (vec![], 0, None, None, NFS4ERR_ROFS);
        }

        // stateid(16) + offset(8) + stable(4) + data opaque<>
        let mut pp = p;
        if pp + 28 > request.len() { return (vec![], 0, None, None, NFS4ERR_BADXDR); }
        pp += 16; // skip stateid
        let offset = u64::from_be_bytes([
            request[pp], request[pp+1], request[pp+2], request[pp+3],
            request[pp+4], request[pp+5], request[pp+6], request[pp+7],
        ]);
        pp += 8;
        let stable = u32::from_be_bytes([request[pp], request[pp+1], request[pp+2], request[pp+3]]);
        pp += 4;
        if pp + 4 > request.len() { return (vec![], pp-p, None, None, NFS4ERR_BADXDR); }
        let data_len = u32::from_be_bytes([request[pp], request[pp+1], request[pp+2], request[pp+3]]) as usize;
        pp += 4;
        if pp + data_len > request.len() { return (vec![], pp-p, None, None, NFS4ERR_BADXDR); }
        let write_data = &request[pp..pp+data_len];
        pp += (data_len + 3) & !3;
        let consumed = pp - p;

        info!("NFS4 WRITE: offset={}, data_len={}", offset, data_len);

        let path = match self.exports.resolve_fh(fh).await {
            None => return (vec![], consumed, None, None, NFS4ERR_STALE),
            Some(p) => p,
        };

        // SEC-019: Use seek+write instead of read-all-modify-write-all.
        // This avoids race conditions with concurrent writes and reduces
        // memory usage by not loading the entire file into memory.
        let written = match std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .open(to_extended_path(&path))
        {
            Ok(mut file) => {
                use std::io::{Seek, SeekFrom};
                // Seek to the write offset
                if let Err(e) = file.seek(SeekFrom::Start(offset)) {
                    warn!("NFS4 WRITE: seek failed for {}: {}", path.display(), e);
                    return (vec![], consumed, None, None, NFS4ERR_IO);
                }
                // Write data at the specified offset
                match std::io::Write::write_all(&mut file, write_data) {
                    Ok(()) => {
                        // Sync to disk if FILE_SYNC requested
                        if stable == 2 { // FILE_SYNC4
                            let _ = file.sync_all();
                        }
                        data_len
                    }
                    Err(e) => {
                        warn!("NFS4 WRITE: write failed for {}: {}", path.display(), e);
                        return (vec![], consumed, None, None, NFS4ERR_IO);
                    }
                }
            }
            Err(e) => {
                warn!("NFS4 WRITE: failed to open {}: {}", path.display(), e);
                return (vec![], consumed, None, None, NFS4ERR_IO);
            }
        };

        // WRITE4resok: count(4) + committed(4) + writeverf(8)
        let mut result = Vec::new();
        result.extend_from_slice(&(data_len as u32).to_be_bytes());
        result.extend_from_slice(&2u32.to_be_bytes()); // FILE_SYNC4=2
        result.extend_from_slice(&self.writeverf); // server write verifier
        (result, consumed, None, None, NFS4_OK)
    }

    async fn op_readdir(&self, request: &[u8], p: usize, current_fh: &Option<Vec<u8>>)
        -> (Vec<u8>, usize, Option<Vec<u8>>, Option<Vec<u8>>, u32)
    {
        info!("NFS4 READDIR");
        let fh = match current_fh {
            None => return (vec![], 0, None, None, NFS4ERR_NOFILEHANDLE),
            Some(fh) => fh,
        };

        // Check if this is the root directory
        if Self::is_root_handle(fh) {
            return self.op_readdir_root(request, p).await;
        }

        // cookie(8) + cookieverf(8) + dircount(4) + maxcount(4) + attr_request bitmap
        let mut pp = p;
        if pp + 20 > request.len() { return (vec![], 0, None, None, NFS4ERR_BADXDR); }
        let cookie = u64::from_be_bytes([
            request[pp], request[pp+1], request[pp+2], request[pp+3],
            request[pp+4], request[pp+5], request[pp+6], request[pp+7],
        ]);
        pp += 8;
        let cookieverf = request[pp..pp+8].to_vec();
        pp += 8;
        let dircount = u32::from_be_bytes([request[pp], request[pp+1], request[pp+2], request[pp+3]]);
        pp += 4;
        let maxcount = u32::from_be_bytes([request[pp], request[pp+1], request[pp+2], request[pp+3]]);
        pp += 4;

        // attr_request bitmap
        if pp + 4 > request.len() { return (vec![], pp-p, None, None, NFS4ERR_BADXDR); }
        let bm_count = u32::from_be_bytes([request[pp], request[pp+1], request[pp+2], request[pp+3]]) as usize;
        pp += 4;
        let mut req_bitmap: Vec<u32> = Vec::with_capacity(bm_count);
        for i in 0..bm_count {
            if pp + 4 > request.len() { return (vec![], pp-p, None, None, NFS4ERR_BADXDR); }
            req_bitmap.push(u32::from_be_bytes([request[pp], request[pp+1], request[pp+2], request[pp+3]]));
            pp += 4;
        }
        let consumed = pp - p;

        let bm_log: Vec<String> = req_bitmap.iter().enumerate()
            .map(|(i, v)| format!("word{}={:#010x}", i, v))
            .collect();
        info!("NFS4 READDIR: cookie={}, dircount={}, maxcount={}, attr_req=[{}]",
            cookie, dircount, maxcount, bm_log.join(", "));

        let dir_path = match self.exports.resolve_fh(fh).await {
            None => return (vec![], consumed, None, None, NFS4ERR_STALE),
            Some(p) => p,
        };
        let fh_preview: Vec<String> = fh.iter().take(8).map(|b| format!("{:02x}", b)).collect();
        debug!("NFS4 READDIR: fh_preview=[{}], dir_path='{}'", fh_preview.join(""), dir_path.display());

        // Read directory entries — use extended path for long-path directories.
        let entries = match std::fs::read_dir(to_extended_path(&dir_path)) {
            Err(e) => {
                warn!("NFS4 READDIR: failed to read dir {}: {}", dir_path.display(), e);
                return (vec![], consumed, None, None, NFS4ERR_IO);
            }
            Ok(e) => e,
        };

        let export_root = self.exports.get_fh_export_root(fh).await
            .unwrap_or_else(|| dir_path.clone());

        let mut result = Vec::new();
        // cookieverf (8 bytes) - use stable non-zero value
        result.extend_from_slice(&[0x01u8, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01]);

        let mut dir_entries: Vec<(String, PathBuf)> = entries
            .filter_map(|e| e.ok())
            .map(|e| (e.file_name().to_string_lossy().to_string(), e.path()))
            .collect();
        dir_entries.sort_by(|a, b| a.0.cmp(&b.0));

        // Skip entries before cookie
        // Cookie convention: Linux kernel NFSv4 client reserves cookies 1,2
        // for VFS-synthesised '.' and '..' dentries. We offset real entries to
        // start from 3 to avoid d_off collisions that cause infinite getdents64 loops.
        const COOKIE_BASE: u64 = 3;
        let start_idx = if cookie == 0 {
            0
        } else if cookie >= COOKIE_BASE {
            // RFC 5661: cookie is the entry immediately BEFORE where to resume.
            // We skip entries from 0..=last_index and resume at last_index+1.
            ((cookie - COOKIE_BASE) + 1) as usize
        } else {
            0 // bogus cookie (e.g. 1,2 from kernel reset) → restart
        };
        let entries_slice = &dir_entries[start_idx.min(dir_entries.len())..];

        // Track response size against maxcount. RFC 5661: each entry in
        // the response must fit within maxcount bytes. If the next entry
        // would push us over, stop and set eof=false.
        let mut added_count = 0usize;
        let cookieverf_offset = result.len(); // Remember where cookieverf was

        for (idx, (name, path)) in entries_slice.iter().enumerate() {
            let entry_cookie = COOKIE_BASE + (start_idx + idx) as u64;
            // Keep FH registration so lookups work after READDIR
            let _child_fh = self.exports.get_or_create_fh(path.clone(), export_root.clone()).await;

            // Compute this entry's size before adding it
            let name_bytes = name.as_bytes();
            let name_padded = (name_bytes.len() + 3) & !3;
            let default_type = if path.is_dir() { NF4DIR } else { NF4REG };
            let fattr_bytes = self.build_fattr4(&Some(path.clone()), &req_bitmap, default_type, false).await;
            // entry frame: value_follows(4) + cookie(8) + name_len(4) + name + padding + fattr
            let entry_size = 4 + 8 + 4 + name_padded + fattr_bytes.len();
            // Total: cookieverf(8) + value_follows=0(4) + eof(4) = 16 bytes overhead
            let total_size = 8 + (result.len() - cookieverf_offset) + entry_size + 4 + 4;

            if total_size > maxcount as usize {
                info!("NFS4 READDIR: maxcount={} exceeded (entry '{}' would make total={}), stopping with eof=false",
                    maxcount, name, total_size);
                break;
            }

            debug!("NFS4 READDIR entry: name='{}', entry_size={}", name, entry_size);

            result.extend_from_slice(&[0,0,0,1]); // value_follows=TRUE
            result.extend_from_slice(&entry_cookie.to_be_bytes()); // cookie
            result.extend_from_slice(&(name_bytes.len() as u32).to_be_bytes());
            result.extend_from_slice(name_bytes);
            result.resize(result.len() + (name_padded - name_bytes.len()), 0);
            result.extend_from_slice(&fattr_bytes);
            added_count += 1;
        }
        result.extend_from_slice(&[0,0,0,0]); // value_follows=FALSE (end)
        // eof: true if all entries were included (covering empty dir case where added_count=0)
        let eof = start_idx + added_count >= dir_entries.len();
        result.extend_from_slice(&(eof as u32).to_be_bytes()); // eof

        info!("NFS4 READDIR: returning {} entries, eof={}, resp_size={}", added_count, eof, result.len());
        // Log response XDR (first 200 bytes) for debug
        let resp_hex: String = result.iter().take(200)
            .enumerate()
            .map(|(i, b)| format!("[{}]={:02x}", i, b))
            .collect::<Vec<_>>().join(" ");
        debug!("NFS4 READDIR response XDR ({} bytes): {}", result.len().min(200), resp_hex);

        (result, consumed, None, None, NFS4_OK)
    }

    /// Handle READDIR on the NFS v4 root (returns export list as directory entries)
    async fn op_readdir_root(&self, request: &[u8], p: usize)
        -> (Vec<u8>, usize, Option<Vec<u8>>, Option<Vec<u8>>, u32)
    {
        info!("NFS4 READDIR on root");
        
        let mut pp = p;
        if pp + 20 > request.len() { return (vec![], 0, None, None, NFS4ERR_BADXDR); }
        let cookie = u64::from_be_bytes([
            request[pp], request[pp+1], request[pp+2], request[pp+3],
            request[pp+4], request[pp+5], request[pp+6], request[pp+7],
        ]);
        pp += 8;
        pp += 8; // skip cookieverf
        let dircount = u32::from_be_bytes([request[pp], request[pp+1], request[pp+2], request[pp+3]]);
        pp += 4;
        let maxcount = u32::from_be_bytes([request[pp], request[pp+1], request[pp+2], request[pp+3]]);
        pp += 4;

        // attr_request bitmap
        if pp + 4 > request.len() { return (vec![], pp-p, None, None, NFS4ERR_BADXDR); }
        let bm_count = u32::from_be_bytes([request[pp], request[pp+1], request[pp+2], request[pp+3]]) as usize;
        pp += 4;
        let mut req_bitmap: Vec<u32> = Vec::with_capacity(bm_count);
        for _i in 0..bm_count {
            if pp + 4 > request.len() { break; }
            req_bitmap.push(u32::from_be_bytes([request[pp], request[pp+1], request[pp+2], request[pp+3]]));
            pp += 4;
        }
        let consumed = pp - p;

        let exports = self.exports.list_exports_with_aliases().await;
        info!("NFS4 READDIR root: {} exports, cookie={}, maxcount={}", exports.len(), cookie, maxcount);

        let mut result = Vec::new();
        // cookieverf (8 bytes) - stable non-zero value
        result.extend_from_slice(&[0x01u8, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01]);

        // Build directory entries from export list.
        // Same COOKIE_BASE convention as op_readdir: offset from 3 to avoid
        // kernel-synthesised '.' (cookie=1) and '..' (cookie=2) conflicts.
        const COOKIE_BASE: u64 = 3;
        let mut result_idx = 0usize;
        let mut returned_count = 0usize;
        for (real_path, alias) in &exports {
            let entry_cookie = COOKIE_BASE + result_idx as u64;
            result_idx += 1;
            if entry_cookie <= cookie {
                continue;
            }
            returned_count += 1;
            let name = alias.clone().unwrap_or_else(|| {
                std::path::Path::new(real_path)
                    .file_name()
                    .map(|n| n.to_string_lossy().to_string())
                    .unwrap_or_else(|| real_path.clone())
            });

            debug!("NFS4 READDIR root entry: name='{}'", name);

            result.extend_from_slice(&[0,0,0,1]); // value_follows=TRUE
            result.extend_from_slice(&entry_cookie.to_be_bytes()); // cookie
            // name as component4 (opaque<>)
            let name_bytes = name.as_bytes();
            let name_padded = (name_bytes.len() + 3) & !3;
            let name_pad = name_padded - name_bytes.len();
            result.extend_from_slice(&(name_bytes.len() as u32).to_be_bytes());
            result.extend_from_slice(name_bytes);
            result.resize(result.len() + name_pad, 0);

            // Build full fattr4 using same logic as GETATTR (export dirs are always NF4DIR)
            let entry_path = Some(PathBuf::from(real_path));
            let fattr_bytes = self.build_fattr4(&entry_path, &req_bitmap, NF4DIR, false).await;
            result.extend_from_slice(&fattr_bytes);
        }
        
        result.extend_from_slice(&[0,0,0,0]); // value_follows=FALSE (end)
        result.extend_from_slice(&1u32.to_be_bytes()); // eof=TRUE

        info!("NFS4 READDIR root: returning {} entries, eof=true", returned_count);

        (result, consumed, None, None, NFS4_OK)
    }

    async fn op_readlink(&self, _request: &[u8], _p: usize, current_fh: &Option<Vec<u8>>)
        -> (Vec<u8>, usize, Option<Vec<u8>>, Option<Vec<u8>>, u32)
    {
        info!("NFS4 READLINK");
        let fh = match current_fh {
            None => return (vec![], 0, None, None, NFS4ERR_NOFILEHANDLE),
            Some(fh) => fh,
        };
        let path = match self.exports.resolve_fh(fh).await {
            None => return (vec![], 0, None, None, NFS4ERR_STALE),
            Some(p) => p,
        };
        // Return empty linktext
        let mut result = Vec::new();
        result.extend_from_slice(&0u32.to_be_bytes()); // len=0
        (result, 0, None, None, NFS4_OK)
    }

    async fn op_remove(&self, request: &[u8], p: usize, current_fh: &Option<Vec<u8>>)
        -> (Vec<u8>, usize, Option<Vec<u8>>, Option<Vec<u8>>, u32)
    {
        info!("NFS4 REMOVE");
        let dir_fh = match current_fh {
            None => return (vec![], 0, None, None, NFS4ERR_NOFILEHANDLE),
            Some(fh) => fh,
        };

        // SEC-002: Reject removes on read-only exports
        if self.exports.is_read_only(dir_fh).await {
            warn!("NFS4 REMOVE: rejected — export is read-only");
            return (vec![], 0, None, None, NFS4ERR_ROFS);
        }
        if p + 4 > request.len() { return (vec![], 0, None, None, NFS4ERR_BADXDR); }
        let name_len = u32::from_be_bytes([request[p], request[p+1], request[p+2], request[p+3]]) as usize;
        let consumed = 4 + ((name_len + 3) & !3);
        if p + 4 + name_len > request.len() { return (vec![], consumed, None, None, NFS4ERR_BADXDR); }
        let name = String::from_utf8_lossy(&request[p+4..p+4+name_len]).to_string();

        let dir_path = match self.exports.resolve_fh(dir_fh).await {
            None => return (vec![], consumed, None, None, NFS4ERR_STALE),
            Some(p) => p,
        };
        let target = dir_path.join(&name);
        if !target.exists() { return (vec![], consumed, None, None, NFS4ERR_NOENT); }

        let res = if target.is_dir() {
            // Check if directory is non-empty per RFC 7530 §14.2.34
            let dir_empty = match std::fs::read_dir(to_extended_path(&target)) {
                Ok(mut entries) => entries.next().is_none(),
                Err(_) => false,
            };
            if !dir_empty {
                warn!("NFS4 REMOVE: directory not empty: {}", target.display());
                return (vec![], consumed, None, None, NFS4ERR_NOTEMPTY);
            }
            std::fs::remove_dir(to_extended_path(&target))
        } else {
            std::fs::remove_file(to_extended_path(&target))
        };
        if let Err(e) = res {
            warn!("NFS4 REMOVE failed: {}", e);
            return (vec![], consumed, None, None, NFS4ERR_IO);
        }

        // change_info4: atomic(4) + before(8) + after(8)
        let mut result = Vec::new();
        result.extend_from_slice(&1u32.to_be_bytes()); // atomic
        result.extend_from_slice(&0u64.to_be_bytes()); // before
        result.extend_from_slice(&1u64.to_be_bytes()); // after
        (result, consumed, None, None, NFS4_OK)
    }

    async fn op_rename(&self, request: &[u8], p: usize, current_fh: &Option<Vec<u8>>, saved_fh: &Option<Vec<u8>>)
        -> (Vec<u8>, usize, Option<Vec<u8>>, Option<Vec<u8>>, u32)
    {
        info!("NFS4 RENAME");
        let sfh = match saved_fh {
            None => return (vec![], 0, None, None, NFS4ERR_RESTOREFH),
            Some(fh) => fh,
        };

        // SEC-002: Reject renames on read-only exports
        if let Some(cur_fh) = current_fh {
            if self.exports.is_read_only(cur_fh).await {
                warn!("NFS4 RENAME: rejected — export is read-only");
                return (vec![], 0, None, None, NFS4ERR_ROFS);
            }
        }
        let dfh = match current_fh {
            None => return (vec![], 0, None, None, NFS4ERR_NOFILEHANDLE),
            Some(fh) => fh,
        };
        let mut pp = p;
        // oldname
        if pp + 4 > request.len() { return (vec![], 0, None, None, NFS4ERR_BADXDR); }
        let old_len = u32::from_be_bytes([request[pp], request[pp+1], request[pp+2], request[pp+3]]) as usize;
        pp += 4;
        if pp + old_len > request.len() { return (vec![], pp-p, None, None, NFS4ERR_BADXDR); }
        let oldname = String::from_utf8_lossy(&request[pp..pp+old_len]).to_string();
        pp += (old_len + 3) & !3;
        // newname
        if pp + 4 > request.len() { return (vec![], pp-p, None, None, NFS4ERR_BADXDR); }
        let new_len = u32::from_be_bytes([request[pp], request[pp+1], request[pp+2], request[pp+3]]) as usize;
        pp += 4;
        if pp + new_len > request.len() { return (vec![], pp-p, None, None, NFS4ERR_BADXDR); }
        let newname = String::from_utf8_lossy(&request[pp..pp+new_len]).to_string();
        pp += (new_len + 3) & !3;
        let consumed = pp - p;

        let src_dir = match self.exports.resolve_fh(sfh).await {
            None => return (vec![], consumed, None, None, NFS4ERR_STALE),
            Some(p) => p,
        };
        let dst_dir = match self.exports.resolve_fh(dfh).await {
            None => return (vec![], consumed, None, None, NFS4ERR_STALE),
            Some(p) => p,
        };

        let src = src_dir.join(&oldname);
        let dst = dst_dir.join(&newname);

        if !src.exists() {
            warn!("NFS4 RENAME: source does not exist: {}", src.display());
            return (vec![], consumed, None, None, NFS4ERR_NOENT);
        }

        if let Err(e) = std::fs::rename(to_extended_path(&src), to_extended_path(&dst)) {
            warn!("NFS4 RENAME failed: {}", e);
            return (vec![], consumed, None, None, NFS4ERR_IO);
        }

        let mut result = Vec::new();
        // source_cinfo
        result.extend_from_slice(&1u32.to_be_bytes());
        result.extend_from_slice(&0u64.to_be_bytes());
        result.extend_from_slice(&1u64.to_be_bytes());
        // target_cinfo
        result.extend_from_slice(&1u32.to_be_bytes());
        result.extend_from_slice(&0u64.to_be_bytes());
        result.extend_from_slice(&1u64.to_be_bytes());
        (result, consumed, None, None, NFS4_OK)
    }

    async fn op_setattr(&self, request: &[u8], p: usize, current_fh: &Option<Vec<u8>>)
        -> (Vec<u8>, usize, Option<Vec<u8>>, Option<Vec<u8>>, u32)
    {
        info!("NFS4 SETATTR");
        if current_fh.is_none() {
            return (vec![], 0, None, None, NFS4ERR_NOFILEHANDLE);
        }
        let fh = current_fh.as_ref().unwrap();

        // SEC-002: Reject setattr on read-only exports
        if self.exports.is_read_only(fh).await {
            warn!("NFS4 SETATTR: rejected — export is read-only");
            return (vec![], 0, None, None, NFS4ERR_ROFS);
        }
        
        // stateid(16) + attr bitmap + attr_vals
        let mut pp = p;
        pp += 16; // skip stateid
        if pp + 4 > request.len() { return (vec![], pp-p, None, None, NFS4ERR_BADXDR); }
        let bm_count = u32::from_be_bytes([request[pp], request[pp+1], request[pp+2], request[pp+3]]) as usize;
        pp += 4;
        let bm_start = pp;
        if pp + bm_count * 4 > request.len() { return (vec![], pp-p, None, None, NFS4ERR_BADXDR); }
        let bm0 = if bm_count > 0 { u32::from_be_bytes([request[pp], request[pp+1], request[pp+2], request[pp+3]]) } else { 0 };
        pp += 4;
        let bm1 = if bm_count > 1 { u32::from_be_bytes([request[pp], request[pp+1], request[pp+2], request[pp+3]]) } else { 0 };
        pp += 4;
        // skip remaining bitmap words
        for _ in 2..bm_count { pp += 4; }
        
        if pp + 4 > request.len() { return (vec![], pp-p, None, None, NFS4ERR_BADXDR); }
        let attr_len = u32::from_be_bytes([request[pp], request[pp+1], request[pp+2], request[pp+3]]) as usize;
        pp += 4;
        if pp + attr_len > request.len() { return (vec![], pp-p, None, None, NFS4ERR_BADXDR); }
        let attr_data = &request[pp..pp+attr_len];
        pp += (attr_len + 3) & !3;
        let consumed = pp - p;
        
        // Resolve path
        let path = match self.exports.resolve_fh(fh).await {
            None => return (vec![], consumed, None, None, NFS4ERR_STALE),
            Some(p) => p,
        };
        
        // Track which attributes were actually set
        let mut bm0_set: u32 = 0;
        let mut bm1_set: u32 = 0;
        let mut attr_offset: usize = 0;
        
        // Process attributes by iterating through all 64 bits systematically.
        // This prevents offset drift when unhandled bits appear in the bitmap.
        for bit in 0..64 {
            let word_idx = bit / 32;
            let bit_in_word = bit % 32;
            let word = if word_idx == 0 { bm0 } else { bm1 };
            if word & (1u32 << bit_in_word) == 0 {
                continue;
            }
            
            match bit {
                // TYPE (bit 1): 4 bytes (nfs_ftype4) — unable to change, skip
                1 => {
                    attr_offset += 4;
                }
                // MODE (global bit 33 = word1 bit 1): 8 bytes (mode4 uint32 + must_be_zero uint32)
                33 => {
                    attr_offset += 8;
                }
                // SIZE (bit 4): 8 bytes (length4 uint64)
                4 => {
                    if attr_offset + 8 > attr_data.len() { return (vec![], consumed, None, None, NFS4ERR_BADXDR); }
                    let new_size = u64::from_be_bytes([
                        attr_data[attr_offset], attr_data[attr_offset+1], attr_data[attr_offset+2], attr_data[attr_offset+3],
                        attr_data[attr_offset+4], attr_data[attr_offset+5], attr_data[attr_offset+6], attr_data[attr_offset+7],
                    ]);
                    attr_offset += 8;
                    if let Ok(f) = std::fs::OpenOptions::new().write(true).open(to_extended_path(&path)) {
                        if f.set_len(new_size).is_ok() {
                            bm0_set |= 1 << 4;
                            info!("NFS4 SETATTR: set size={} for {}", new_size, path.display());
                        }
                    }
                }
                // OWNER (global bit 36 = word1 bit 4): opaque — read length + skip data
                36 => {
                    if attr_offset + 4 > attr_data.len() { return (vec![], consumed, None, None, NFS4ERR_BADXDR); }
                    let o_len = u32::from_be_bytes([
                        attr_data[attr_offset], attr_data[attr_offset+1], attr_data[attr_offset+2], attr_data[attr_offset+3],
                    ]) as usize;
                    attr_offset += 4 + ((o_len + 3) & !3);
                }
                // OWNER_GROUP (global bit 37 = word1 bit 5): opaque — read length + skip data
                37 => {
                    if attr_offset + 4 > attr_data.len() { return (vec![], consumed, None, None, NFS4ERR_BADXDR); }
                    let o_len = u32::from_be_bytes([
                        attr_data[attr_offset], attr_data[attr_offset+1], attr_data[attr_offset+2], attr_data[attr_offset+3],
                    ]) as usize;
                    attr_offset += 4 + ((o_len + 3) & !3);
                }
                // TIME_ACCESS_SET (global bit 53 = word1 bit 21): settime4 (4 bytes) + possibly 12 more
                53 => {
                    if attr_offset + 4 > attr_data.len() { return (vec![], consumed, None, None, NFS4ERR_BADXDR); }
                    let set_how = u32::from_be_bytes([
                        attr_data[attr_offset], attr_data[attr_offset+1], attr_data[attr_offset+2], attr_data[attr_offset+3],
                    ]);
                    attr_offset += 4;
                    if set_how == 0 {
                        // SET_TO_CLIENT_TIME4: secs(8) + nsecs(4)
                        attr_offset += 12;
                    } else {
                        // SET_TO_SERVER_TIME4: just the set_how
                    }
                }
                // TIME_MODIFY_SET (global bit 54 = word1 bit 22): settime4
                54 => {
                    if attr_offset + 4 > attr_data.len() { return (vec![], consumed, None, None, NFS4ERR_BADXDR); }
                    let set_how = u32::from_be_bytes([
                        attr_data[attr_offset], attr_data[attr_offset+1], attr_data[attr_offset+2], attr_data[attr_offset+3],
                    ]);
                    attr_offset += 4;
                    if set_how == 0 {
                        // SET_TO_CLIENT_TIME4: secs(8) + nsecs(4)
                        if attr_offset + 12 > attr_data.len() { return (vec![], consumed, None, None, NFS4ERR_BADXDR); }
                        let secs = u64::from_be_bytes([
                            attr_data[attr_offset], attr_data[attr_offset+1], attr_data[attr_offset+2], attr_data[attr_offset+3],
                            attr_data[attr_offset+4], attr_data[attr_offset+5], attr_data[attr_offset+6], attr_data[attr_offset+7],
                        ]);
                        let nsecs = u32::from_be_bytes([
                            attr_data[attr_offset+8], attr_data[attr_offset+9], attr_data[attr_offset+10], attr_data[attr_offset+11],
                        ]);
                        attr_offset += 12;
                        let new_time = std::time::UNIX_EPOCH + std::time::Duration::new(secs, nsecs);
                        if let Ok(f) = std::fs::OpenOptions::new().write(true).open(to_extended_path(&path)) {
                            if f.set_modified(new_time).is_ok() {
                                bm1_set |= 1 << (54-32);
                                info!("NFS4 SETATTR: set mtime for {}", path.display());
                            }
                        }
                    } else {
                        // SET_TO_SERVER_TIME4: set to current time
                        let now = std::time::SystemTime::now();
                        if let Ok(f) = std::fs::OpenOptions::new().write(true).open(to_extended_path(&path)) {
                            if f.set_modified(now).is_ok() {
                                bm1_set |= 1 << (54-32);
                                info!("NFS4 SETATTR: set mtime to server time for {}", path.display());
                            }
                        }
                    }
                }
                // Unhandled attribute bit: we can't determine the size, log and skip
                // This is a safety net — bits we know about are handled above
                _ => {
                    info!("NFS4 SETATTR: skipping unknown attribute bit {}", bit);
                    // For safety, skip 4 bytes as minimum increment
                    if attr_offset + 4 > attr_data.len() { return (vec![], consumed, None, None, NFS4ERR_BADXDR); }
                    attr_offset += 4;
                }
            }
        }
        
        // Return attrsset bitmap: which attributes were actually set
        let mut result = Vec::new();
        result.extend_from_slice(&2u32.to_be_bytes()); // 2 bitmap words
        result.extend_from_slice(&bm0_set.to_be_bytes());
        result.extend_from_slice(&bm1_set.to_be_bytes());
        (result, consumed, None, None, NFS4_OK)
    }

    async fn op_create(&self, request: &[u8], p: usize, current_fh: &Option<Vec<u8>>)
        -> (Vec<u8>, usize, Option<Vec<u8>>, Option<Vec<u8>>, u32)
    {
        info!("NFS4 CREATE");
        let dir_fh = match current_fh {
            None => return (vec![], 0, None, None, NFS4ERR_NOFILEHANDLE),
            Some(fh) => fh,
        };

        // SEC-002: Reject creates on read-only exports
        if self.exports.is_read_only(dir_fh).await {
            warn!("NFS4 CREATE: rejected — export is read-only");
            return (vec![], 0, None, None, NFS4ERR_ROFS);
        }
        let mut pp = p;
        // objtype (4)
        if pp + 4 > request.len() { return (vec![], 0, None, None, NFS4ERR_BADXDR); }
        let objtype = u32::from_be_bytes([request[pp], request[pp+1], request[pp+2], request[pp+3]]);
        pp += 4;
        // For symlinks there's a linkdata here; skip based on type
        if objtype == NF4LNK {
            if pp + 4 > request.len() { return (vec![], pp-p, None, None, NFS4ERR_BADXDR); }
            let link_len = u32::from_be_bytes([request[pp], request[pp+1], request[pp+2], request[pp+3]]) as usize;
            pp += 4 + ((link_len + 3) & !3);
        }
        // objname
        if pp + 4 > request.len() { return (vec![], pp-p, None, None, NFS4ERR_BADXDR); }
        let name_len = u32::from_be_bytes([request[pp], request[pp+1], request[pp+2], request[pp+3]]) as usize;
        pp += 4;
        if pp + name_len > request.len() { return (vec![], pp-p, None, None, NFS4ERR_BADXDR); }
        let name = String::from_utf8_lossy(&request[pp..pp+name_len]).to_string();
        pp += (name_len + 3) & !3;
        // createattrs
        if pp + 4 > request.len() { return (vec![], pp-p, None, None, NFS4ERR_BADXDR); }
        let bm_count = u32::from_be_bytes([request[pp], request[pp+1], request[pp+2], request[pp+3]]) as usize;
        pp += 4 + bm_count * 4;
        if pp + 4 > request.len() { return (vec![], pp-p, None, None, NFS4ERR_BADXDR); }
        let attr_len = u32::from_be_bytes([request[pp], request[pp+1], request[pp+2], request[pp+3]]) as usize;
        pp += 4 + ((attr_len + 3) & !3);
        let consumed = pp - p;

        let dir_path = match self.exports.resolve_fh(dir_fh).await {
            None => {
                warn!("NFS4 CREATE: resolve_fh returned None for dir_fh (len={})", dir_fh.len());
                return (vec![], consumed, None, None, NFS4ERR_STALE);
            }
            Some(p) => p,
        };
        let new_path = dir_path.join(&name);
        debug!("NFS4 CREATE: name={}", name);

        if new_path.exists() {
            warn!("NFS4 CREATE: target already exists: {}", new_path.display());
            return (vec![], consumed, None, None, NFS4ERR_EXIST);
        }

        let create_res = match objtype {
            NF4DIR => std::fs::create_dir(to_extended_path(&new_path)).map(|_| ()),
            NF4REG => std::fs::File::create(to_extended_path(&new_path)).map(|_| ()),
            _ => return (vec![], consumed, None, None, NFS4ERR_BADTYPE),
        };
        if let Err(e) = create_res {
            warn!("NFS4 CREATE failed: {} for path {}", e, new_path.display());
            return (vec![], consumed, None, None, NFS4ERR_IO);
        }

        let export_root = self.exports.get_fh_export_root(dir_fh).await
            .unwrap_or_else(|| dir_path.clone());
        let new_fh = self.exports.get_or_create_fh(new_path, export_root).await;

        let mut result = Vec::new();
        // cinfo
        result.extend_from_slice(&1u32.to_be_bytes());
        result.extend_from_slice(&0u64.to_be_bytes());
        result.extend_from_slice(&1u64.to_be_bytes());
        // attrset: empty bitmap
        result.extend_from_slice(&0u32.to_be_bytes());
        (result, consumed, Some(new_fh), None, NFS4_OK)
    }

    async fn op_setclientid(&self, request: &[u8], p: usize)
        -> (Vec<u8>, usize, Option<Vec<u8>>, Option<Vec<u8>>, u32)
    {
        info!("NFS4 SETCLIENTID");
        let mut pp = p;

        // client verifier (8 bytes)
        if pp + 8 > request.len() { return (vec![], 0, None, None, NFS4ERR_BADXDR); }
        let mut client_verifier = [0u8; 8];
        client_verifier.copy_from_slice(&request[pp..pp+8]);
        pp += 8;

        // client id (opaque<>)
        if pp + 4 > request.len() { return (vec![], pp-p, None, None, NFS4ERR_BADXDR); }
        let id_len = u32::from_be_bytes([request[pp], request[pp+1], request[pp+2], request[pp+3]]) as usize;
        pp += 4;
        if pp + id_len > request.len() { return (vec![], pp-p, None, None, NFS4ERR_BADXDR); }
        let id_string = request[pp..pp+id_len].to_vec();
        pp += (id_len + 3) & !3;

        // callback: program(4) + netid opaque<> + addr opaque<>
        if pp + 4 > request.len() { return (vec![], pp-p, None, None, NFS4ERR_BADXDR); }
        let cb_program = u32::from_be_bytes([request[pp], request[pp+1], request[pp+2], request[pp+3]]);
        pp += 4;
        // netid
        if pp + 4 > request.len() { return (vec![], pp-p, None, None, NFS4ERR_BADXDR); }
        let netid_len = u32::from_be_bytes([request[pp], request[pp+1], request[pp+2], request[pp+3]]) as usize;
        pp += 4;
        if pp + netid_len > request.len() { return (vec![], pp-p, None, None, NFS4ERR_BADXDR); }
        pp += (netid_len + 3) & !3;
        // addr
        if pp + 4 > request.len() { return (vec![], pp-p, None, None, NFS4ERR_BADXDR); }
        let addr_len = u32::from_be_bytes([request[pp], request[pp+1], request[pp+2], request[pp+3]]) as usize;
        pp += 4;
        if pp + addr_len > request.len() { return (vec![], pp-p, None, None, NFS4ERR_BADXDR); }
        pp += (addr_len + 3) & !3;

        // callback_ident(4)
        if pp + 4 > request.len() { return (vec![], pp-p, None, None, NFS4ERR_BADXDR); }
        pp += 4;

        let consumed = pp - p;

        // Check for existing client with same id_string (NFSv4.0 duplicate detection)
        {
            let clients = self.clients.read().await;
            for record in clients.values() {
                if record.id_string == id_string {
                    if record.verifier == client_verifier {
                        // Client reconnect: return same client_id with new confirm_verifier
                        let client_id = record.client_id;
                        // SEC-021: Use cryptographic random for confirm_verifier
                        let mut confirm_verifier = [0u8; 8];
                        let now = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap_or_default();
                        let pid = std::process::id() as u64;
                        let mut seed = now.as_nanos() as u64 ^ pid ^ client_id;
                        for i in 0..8 {
                            seed ^= seed << 13;
                            seed ^= seed >> 7;
                            seed ^= seed << 17;
                            confirm_verifier[i] = (seed & 0xFF) as u8;
                        }

                        // Update the confirm_verifier in the client record
                        drop(clients);
                        {
                            let mut clients = self.clients.write().await;
                            if let Some(r) = clients.get_mut(&client_id) {
                                r.confirm_verifier = confirm_verifier;
                            }
                        }

                        debug!("NFS4 SETCLIENTID: reconnect existing client_id={}", client_id);

                        let mut result = Vec::new();
                        result.extend_from_slice(&client_id.to_be_bytes());
                        result.extend_from_slice(&confirm_verifier);
                        return (result, consumed, None, None, NFS4_OK);
                    } else {
                        // Different verifier for same owner: client ID in use
                        info!("NFS4 SETCLIENTID: CLID_INUSE (different verifier for same owner)");
                        return (vec![], consumed, None, None, NFS4ERR_CLID_INUSE);
                    }
                }
            }
        }

        // Allocate new client ID
        let client_id = {
            let mut ctr = self.client_counter.write().await;
            let id = *ctr;
            *ctr += 1;
            id
        };

        // Generate confirm verifier
        // SEC-021: Use cryptographic random for confirm_verifier
        let mut confirm_verifier = [0u8; 8];
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default();
        let pid = std::process::id() as u64;
        let mut seed = now.as_nanos() as u64 ^ pid ^ client_id;
        for i in 0..8 {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            confirm_verifier[i] = (seed & 0xFF) as u8;
        }

        {
            let mut clients = self.clients.write().await;
            clients.insert(client_id, ClientRecord {
                client_id,
                verifier: client_verifier,
                id_string,
                callback_program: cb_program,
                confirmed: false,
                confirm_verifier,
                sequence: 0,
                last_used: std::time::Instant::now(), // SEC-011
            });
        }

        debug!("NFS4 SETCLIENTID: allocated new client_id={}", client_id);

        // SETCLIENTID4resok: clientid(8) + setclientid_confirm(8)
        let mut result = Vec::new();
        result.extend_from_slice(&client_id.to_be_bytes());
        result.extend_from_slice(&confirm_verifier);
        (result, consumed, None, None, NFS4_OK)
    }

    async fn op_setclientid_confirm(&self, request: &[u8], p: usize)
        -> (Vec<u8>, usize, Option<Vec<u8>>, Option<Vec<u8>>, u32)
    {
        info!("NFS4 SETCLIENTID_CONFIRM");
        if p + 16 > request.len() { return (vec![], 16, None, None, NFS4ERR_BADXDR); }

        let client_id = u64::from_be_bytes([
            request[p], request[p+1], request[p+2], request[p+3],
            request[p+4], request[p+5], request[p+6], request[p+7],
        ]);

        let mut clients = self.clients.write().await;
        if let Some(client) = clients.get_mut(&client_id) {
            client.confirmed = true;
            debug!("NFS4 SETCLIENTID_CONFIRM: confirmed client_id={}", client_id);
        } else {
            warn!("NFS4 SETCLIENTID_CONFIRM: unknown client_id={}", client_id);
            return (vec![], 16, None, None, NFS4ERR_STALE_CLIENTID);
        }

        (vec![], 16, None, None, NFS4_OK)
    }

    async fn op_renew(&self, request: &[u8], p: usize)
        -> (Vec<u8>, usize, Option<Vec<u8>>, Option<Vec<u8>>, u32)
    {
        info!("NFS4 RENEW");
        let consumed = 8; // clientid(8)
        (vec![], consumed, None, None, NFS4_OK)
    }

    async fn op_secinfo(&self, request: &[u8], p: usize)
        -> (Vec<u8>, usize, Option<Vec<u8>>, Option<Vec<u8>>, u32)
    {
        info!("NFS4 SECINFO");
        if p + 4 > request.len() { return (vec![], 0, None, None, NFS4ERR_BADXDR); }
        let name_len = u32::from_be_bytes([request[p], request[p+1], request[p+2], request[p+3]]) as usize;
        let consumed = 4 + ((name_len + 3) & !3);

        // Return AUTH_SYS (flavor=1) as only security flavor
        let mut result = Vec::new();
        result.extend_from_slice(&1u32.to_be_bytes()); // count=1
        result.extend_from_slice(&1u32.to_be_bytes()); // AUTH_SYS=1 (RPCSEC_AUTH_UNIX)
        (result, consumed, None, None, NFS4_OK)
    }

    // SECINFO_NO_NAME (RFC 5661 §18.45) — NFS v4.1 operation
    // Request:  snn_style (4 bytes)
    // Response: SECINFO4res array — list of supported security flavors
    async fn op_secinfo_no_name(&self, request: &[u8], p: usize)
        -> (Vec<u8>, usize, Option<Vec<u8>>, Option<Vec<u8>>, u32)
    {
        info!("NFS4 SECINFO_NO_NAME");
        if p + 4 > request.len() { return (vec![], 0, None, None, NFS4ERR_BADXDR); }
        let _style = u32::from_be_bytes([request[p], request[p+1], request[p+2], request[p+3]]);

        // Return AUTH_SYS (1) as the only supported security flavor.
        // Format: SECINFO4res = count(4) + [flavor(4) + flavor_info opaque<>]*
        let mut result = Vec::new();
        result.extend_from_slice(&1u32.to_be_bytes()); // array count = 1
        result.extend_from_slice(&1u32.to_be_bytes()); // flavor = AUTH_SYS = 1
        result.extend_from_slice(&0u32.to_be_bytes()); // flavor_info length = 0 (opaque<>)
        (result, 4, None, None, NFS4_OK)
    }

    async fn op_verify(&self, opcode: u32, request: &[u8], p: usize, current_fh: &Option<Vec<u8>>)
        -> (Vec<u8>, usize, Option<Vec<u8>>, Option<Vec<u8>>, u32)
    {
        info!("NFS4 {}VERIFY", if opcode == OP_NVERIFY { "N" } else { "" });
        
        if current_fh.is_none() {
            return (vec![], 0, None, None, NFS4ERR_NOFILEHANDLE);
        }
        
        // Parse bitmap + attr_vals
        let mut pp = p;
        if pp + 4 > request.len() { return (vec![], 0, None, None, NFS4ERR_BADXDR); }
        let bm_count = u32::from_be_bytes([request[pp], request[pp+1], request[pp+2], request[pp+3]]) as usize;
        pp += 4 + bm_count * 4;
        if pp + 4 > request.len() { return (vec![], pp-p, None, None, NFS4ERR_BADXDR); }
        let attr_len = u32::from_be_bytes([request[pp], request[pp+1], request[pp+2], request[pp+3]]) as usize;
        pp += 4;
        if pp + attr_len > request.len() { return (vec![], pp-p, None, None, NFS4ERR_BADXDR); }
        let attr_data = &request[pp..pp+attr_len];
        pp += (attr_len + 3) & !3;
        let consumed = pp - p;
        
        // Read file metadata
        let fh = current_fh.as_ref().unwrap();
        let path = match self.exports.resolve_fh(fh).await {
            None => return (vec![], consumed, None, None, NFS4ERR_STALE),
            Some(p) => p,
        };
        let meta = std::fs::metadata(to_extended_path(&path)).ok();
        
        // Re-parse the bitmap from the request to know which attrs were requested
        let mut bm_p = p + 4;
        let bm0 = if bm_count > 0 { u32::from_be_bytes([request[bm_p], request[bm_p+1], request[bm_p+2], request[bm_p+3]]) } else { 0 };
        bm_p += 4;
        let bm1 = if bm_count > 1 { u32::from_be_bytes([request[bm_p], request[bm_p+1], request[bm_p+2], request[bm_p+3]]) } else { 0 };
        
        // Compare each requested attribute
        let mut offset = 0;
        let mut attrs_match = true;
        let mut unsupported = false;
        
        let compare_result = self.compare_attr_vals(
            &path, &meta, bm0, bm1, attr_data, &mut offset,
        );
        match compare_result {
            Ok(matched) => attrs_match = matched,
            Err(_) => unsupported = true,
        }
        
        if unsupported {
            return (vec![], consumed, None, None, NFS4ERR_ATTRNOTSUPP);
        }
        
        // VERIFY: NFS4_OK if match, NFS4ERR_NOT_SAME if differ
        // NVERIFY: NFS4ERR_SAME if match, NFS4_OK if differ
        let status = if opcode == OP_NVERIFY {
            if attrs_match { NFS4ERR_SAME } else { NFS4_OK }
        } else {
            if attrs_match { NFS4_OK } else { NFS4ERR_NOT_SAME }
        };
        (vec![], consumed, None, None, status)
    }
    
    /// Compare attr_vals from a VERIFY/NVERIFY request against actual file attrs.
    /// Returns Ok(true) if match, Ok(false) if differ, Err(()) if unsupported attr.
    fn compare_attr_vals(
        &self, _path: &PathBuf, meta: &Option<std::fs::Metadata>,
        bm0: u32, bm1: u32, attr_data: &[u8], offset: &mut usize,
    ) -> Result<bool, ()> {
        // Process attributes in bitmap order
        for bit in 0..64 {
            let (word, mask) = if bit < 32 {
                (bm0, 1u32 << bit)
            } else {
                (bm1, 1u32 << (bit - 32))
            };
            if word & mask == 0 { continue; }
            
            match bit {
                4 => {
                    // SIZE: uint64 (8 bytes)
                    if *offset + 8 > attr_data.len() { return Err(()); }
                    let req_size = u64::from_be_bytes([
                        attr_data[*offset], attr_data[*offset+1], attr_data[*offset+2], attr_data[*offset+3],
                        attr_data[*offset+4], attr_data[*offset+5], attr_data[*offset+6], attr_data[*offset+7],
                    ]);
                    *offset += 8;
                    let actual = meta.as_ref().map(|m| m.len()).unwrap_or(0);
                    if req_size != actual { return Ok(false); }
                }
                3 => {
                    // CHANGE: changeid4 (8 bytes)
                    if *offset + 8 > attr_data.len() { return Err(()); }
                    let req_change = u64::from_be_bytes([
                        attr_data[*offset], attr_data[*offset+1], attr_data[*offset+2], attr_data[*offset+3],
                        attr_data[*offset+4], attr_data[*offset+5], attr_data[*offset+6], attr_data[*offset+7],
                    ]);
                    *offset += 8;
                    let actual = meta.as_ref()
                        .and_then(|m| m.modified().ok())
                        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                        .map(|d| d.as_nanos() as u64)
                        .unwrap_or(0);
                    if req_change != actual { return Ok(false); }
                }
                53 => {
                    // TIME_MODIFY: nfstime4 (secs(8) + nsecs(4) = 12 bytes)
                    // In VERIFY/NVERIFY, the value is nfstime4 (not settime4 as in SETATTR)
                    if *offset + 12 > attr_data.len() { return Err(()); }
                    let req_secs = u64::from_be_bytes([
                        attr_data[*offset], attr_data[*offset+1], attr_data[*offset+2], attr_data[*offset+3],
                        attr_data[*offset+4], attr_data[*offset+5], attr_data[*offset+6], attr_data[*offset+7],
                    ]);
                    let req_nsecs = u32::from_be_bytes([
                        attr_data[*offset+8], attr_data[*offset+9], attr_data[*offset+10], attr_data[*offset+11],
                    ]);
                    *offset += 12;
                    let (actual_secs, actual_nsecs) = meta.as_ref()
                        .and_then(|m| m.modified().ok())
                        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                        .map(|d| (d.as_secs(), d.subsec_nanos()))
                        .unwrap_or((0, 0));
                    if req_secs != actual_secs || req_nsecs != actual_nsecs { return Ok(false); }
                }
                52 => {
                    // TIME_METADATA: nfstime4 (secs(8) + nsecs(4) = 12 bytes)
                    // In VERIFY/NVERIFY, the value is nfstime4 (not settime4 as in SETATTR)
                    if *offset + 12 > attr_data.len() { return Err(()); }
                    let req_secs = u64::from_be_bytes([
                        attr_data[*offset], attr_data[*offset+1], attr_data[*offset+2], attr_data[*offset+3],
                        attr_data[*offset+4], attr_data[*offset+5], attr_data[*offset+6], attr_data[*offset+7],
                    ]);
                    let req_nsecs = u32::from_be_bytes([
                        attr_data[*offset+8], attr_data[*offset+9], attr_data[*offset+10], attr_data[*offset+11],
                    ]);
                    *offset += 12;
                    // time_metadata = ctime; on Windows use created()
                    let (actual_secs, actual_nsecs) = meta.as_ref()
                        .and_then(|m| m.created().ok())
                        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                        .map(|d| (d.as_secs(), d.subsec_nanos()))
                        .unwrap_or((0, 0));
                    if req_secs != actual_secs || req_nsecs != actual_nsecs { return Ok(false); }
                }
                1 => {
                    // TYPE: 4 bytes
                    if *offset + 4 > attr_data.len() { return Err(()); }
                    let req_type = u32::from_be_bytes([
                        attr_data[*offset], attr_data[*offset+1], attr_data[*offset+2], attr_data[*offset+3],
                    ]);
                    *offset += 4;
                    let actual = meta.as_ref().map(|m| if m.is_dir() { NF4DIR } else { NF4REG }).unwrap_or(NF4REG);
                    if req_type != actual { return Ok(false); }
                }
                _ => {
                    // Unsupported attribute for verification — skip opaque value
                    // This is the tricky part: we need to know each attr's encoded size
                    // For now, fail verification
                    return Err(());
                }
            }
        }
        Ok(true)
    }

    async fn op_delegreturn(&self, request: &[u8], p: usize)
        -> (Vec<u8>, usize, Option<Vec<u8>>, Option<Vec<u8>>, u32)
    {
        info!("NFS4 DELEGRETURN");
        (vec![], 16, None, None, NFS4_OK) // stateid(16)
    }

    async fn op_commit(&self, request: &[u8], p: usize, current_fh: &Option<Vec<u8>>)
        -> (Vec<u8>, usize, Option<Vec<u8>>, Option<Vec<u8>>, u32)
    {
        info!("NFS4 COMMIT");
        if current_fh.is_none() {
            return (vec![], 12, None, None, NFS4ERR_NOFILEHANDLE);
        }
        // offset(8) + count(4) = 12 bytes
        let result = self.writeverf.to_vec(); // server write verifier
        (result, 12, None, None, NFS4_OK)
    }

    // ──────────────────────────────────────────────────────────────────────────
    // NFS v4.0: LINK — create hard link (RFC 7530 §15.14)
    // Uses saved_fh as target directory, current_fh as source file
    // ──────────────────────────────────────────────────────────────────────────
    async fn op_link(&self, request: &[u8], p: usize, current_fh: &Option<Vec<u8>>, saved_fh: &Option<Vec<u8>>)
        -> (Vec<u8>, usize, Option<Vec<u8>>, Option<Vec<u8>>, u32)
    {
        info!("NFS4 LINK");

        let src_fh = match current_fh {
            None => return (vec![], 0, None, None, NFS4ERR_NOFILEHANDLE),
            Some(fh) => fh,
        };
        let dir_fh = match saved_fh {
            None => return (vec![], 0, None, None, NFS4ERR_NOFILEHANDLE),
            Some(fh) => fh,
        };

        // SEC-002: Reject link on read-only exports
        if self.exports.is_read_only(dir_fh).await {
            warn!("NFS4 LINK: rejected — export is read-only");
            return (vec![], 0, None, None, NFS4ERR_ROFS);
        }
        
        // Parse new component name (opaque<>)
        let mut pp = p;
        if pp + 4 > request.len() { return (vec![], 0, None, None, NFS4ERR_BADXDR); }
        let name_len = u32::from_be_bytes([request[pp], request[pp+1], request[pp+2], request[pp+3]]) as usize;
        pp += 4;
        if pp + name_len > request.len() { return (vec![], pp-p, None, None, NFS4ERR_BADXDR); }
        let new_name = String::from_utf8_lossy(&request[pp..pp+name_len]).to_string();
        pp += (name_len + 3) & !3;
        let consumed = pp - p;
        
        info!("NFS4 LINK: new_name='{}'", new_name);
        
        // Resolve source file path
        let src_path = match self.exports.resolve_fh(src_fh).await {
            None => return (vec![], consumed, None, None, NFS4ERR_STALE),
            Some(p) => p,
        };
        
        // Resolve target directory path
        let dir_path = match self.exports.resolve_fh(dir_fh).await {
            None => return (vec![], consumed, None, None, NFS4ERR_STALE),
            Some(p) => p,
        };
        
        let target_path = dir_path.join(&new_name);
        
        // Create hard link — extended paths required for long-path files.
        match std::fs::hard_link(to_extended_path(&src_path), to_extended_path(&target_path)) {
            Ok(()) => info!("NFS4 LINK: created {}", target_path.display()),
            Err(e) => {
                warn!("NFS4 LINK failed: {} -> {}: {}", src_path.display(), target_path.display(), e);
                let status = match e.kind() {
                    std::io::ErrorKind::AlreadyExists => NFS4ERR_EXIST,
                    std::io::ErrorKind::NotFound => NFS4ERR_STALE,
                    _ => NFS4ERR_IO,
                };
                return (vec![], consumed, None, None, status);
            }
        }
        
        // LINK4resok: change_info4 = atomic(4) + before(8) + after(8)
        let mut result = Vec::new();
        result.extend_from_slice(&0u32.to_be_bytes()); // atomic=false
        result.extend_from_slice(&0u64.to_be_bytes()); // before change
        let after_change = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0);
        result.extend_from_slice(&after_change.to_be_bytes()); // after change
        (result, consumed, None, None, NFS4_OK)
    }

    // ──────────────────────────────────────────────────────────────────────────
    // NFS v4.0: LOCK/LOCKT/LOCKU — byte-range file locking (RFC 7530 §15.18-20)
    // Uses server-side in-memory lock manager for advisory byte-range locks.
    // ──────────────────────────────────────────────────────────────────────────
    
    /// Parse lock arguments from a LOCK/LOCKT/LOCKU request.
    /// Returns (locktype, reclaim, offset, length, consumed, locker_owner_bytes, client_id).
    /// locker4 union:
    ///   - new_lock_owner4 (is_new=TRUE): open_seqid(4)+open_stateid(16)+lock_seqid(4)
    ///     + lock_owner(clientid(8) + owner opaque<>)
    ///   - exist_lock_owner4 (is_new=FALSE): lock_stateid(16)+lock_seqid(4)
    ///     (no lock_owner, identified by stateid alone)
    fn parse_lock_args(&self, request: &[u8], mut p: usize) 
        -> Result<(u32, u32, u64, u64, usize, Vec<u8>, u64), usize>
    {
        let start_p = p;
        // locktype(4)
        if p + 4 > request.len() { return Err(start_p); }
        let lock_type = u32::from_be_bytes([request[p], request[p+1], request[p+2], request[p+3]]);
        p += 4;
        // reclaim(4)
        if p + 4 > request.len() { return Err(start_p); }
        let reclaim = u32::from_be_bytes([request[p], request[p+1], request[p+2], request[p+3]]);
        p += 4;
        // offset(8)
        if p + 8 > request.len() { return Err(start_p); }
        let offset = u64::from_be_bytes([
            request[p], request[p+1], request[p+2], request[p+3],
            request[p+4], request[p+5], request[p+6], request[p+7],
        ]);
        p += 8;
        // length(8)
        if p + 8 > request.len() { return Err(start_p); }
        let length = u64::from_be_bytes([
            request[p], request[p+1], request[p+2], request[p+3],
            request[p+4], request[p+5], request[p+6], request[p+7],
        ]);
        p += 8;

        // locker4 union: discriminated by is_new (XDR bool = 4 bytes)
        if p + 4 > request.len() { return Err(start_p); }
        let is_new = u32::from_be_bytes([request[p], request[p+1], request[p+2], request[p+3]]) != 0;
        p += 4;

        let (owner, client_id) = if is_new {
            // new_lock_owner4: open_seqid(4) + open_stateid(16) + lock_seqid(4)
            //                 + lock_owner(clientid(8) + owner opaque<>)
            if p + 24 > request.len() { return Err(start_p); }
            p += 24; // open_seqid(4) + open_stateid(16) + lock_seqid(4)
            // clientid(8)
            if p + 8 > request.len() { return Err(start_p); }
            let cid = u64::from_be_bytes([
                request[p], request[p+1], request[p+2], request[p+3],
                request[p+4], request[p+5], request[p+6], request[p+7],
            ]);
            p += 8;
            // owner opaque<>
            if p + 4 > request.len() { return Err(start_p); }
            let owner_len = u32::from_be_bytes([request[p], request[p+1], request[p+2], request[p+3]]) as usize;
            p += 4;
            if p + owner_len > request.len() { return Err(start_p); }
            let own = request[p..p+owner_len].to_vec();
            p += (owner_len + 3) & !3;
            (own, cid)
        } else {
            // exist_lock_owner4: lock_stateid(16) + lock_seqid(4) = 20 bytes
            // No lock_owner — identified by stateid alone
            if p + 20 > request.len() { return Err(start_p); }
            p += 20;
            (vec![], 0u64)
        };

        let consumed = p - start_p;
        Ok((lock_type, reclaim, offset, length, consumed, owner, client_id))
    }
    
    /// Check if a new lock conflicts with existing locks.
    /// Returns None if no conflict, or Some(conflicting_lock) if conflict.
    fn check_lock_conflict(existing: &[FileLock], new_type: u32, new_offset: u64, new_length: u64) 
        -> Option<&FileLock> 
    {
        let new_end = new_offset.saturating_add(new_length);
        let new_is_write = new_type == WRITE_LT || new_type == READW_LT || new_type == WRITEW_LT;
        
        for lock in existing {
            let lock_end = lock.offset.saturating_add(lock.length);
            // Check range overlap
            if new_offset < lock_end && lock.offset < new_end {
                // If either lock is a write lock, conflict
                let existing_is_write = lock.lock_type == WRITE_LT 
                    || lock.lock_type == READW_LT 
                    || lock.lock_type == WRITEW_LT;
                if new_is_write || existing_is_write {
                    return Some(lock);
                }
            }
        }
        None
    }
    
    async fn op_lock(&self, request: &[u8], p: usize, current_fh: &Option<Vec<u8>>)
        -> (Vec<u8>, usize, Option<Vec<u8>>, Option<Vec<u8>>, u32)
    {
        info!("NFS4 LOCK");
        if current_fh.is_none() {
            return (vec![], 0, None, None, NFS4ERR_NOFILEHANDLE);
        }
        
        let (lock_type, reclaim, offset, length, consumed, owner, client_id) = match self.parse_lock_args(request, p) {
            Ok(args) => args,
            Err(consumed) => return (vec![], consumed - p, None, None, NFS4ERR_BADXDR),
        };

        // Extract open_stateid from request (for is_new=true path)
        // After locktype(4)+reclaim(4)+offset(8)+length(8)+is_new(4) = 28 bytes from p
        // open_seqid(4) is at p+28, open_stateid at p+32
        // For is_new=false: lock_stateid at p+28, seqid at p+28, other at p+32
        let stateid_id = {
            let sid_offset = p + 24 + 4 + 4; // p + is_new(4) + open_seqid(4) or (lock_stateid seqid)
            if sid_offset + 8 <= request.len() {
                u64::from_be_bytes([
                    request[sid_offset], request[sid_offset+1], request[sid_offset+2], request[sid_offset+3],
                    request[sid_offset+4], request[sid_offset+5], request[sid_offset+6], request[sid_offset+7],
                ])
            } else {
                return (vec![], consumed, None, None, NFS4ERR_BADXDR);
            }
        };
        
        info!("NFS4 LOCK: type={}, offset={}, length={}, stateid_id={}", lock_type, offset, length, stateid_id);
        
        let mut locks = self.locks.write().await;
        let file_locks = locks.entry(stateid_id).or_insert_with(Vec::new);
        
        // Check for conflicts
        if let Some(conflicting) = Self::check_lock_conflict(file_locks, lock_type, offset, length) {
            // LOCK4denied: offset(8) + length(8) + locktype(4) + owner(opaque<>)
            let mut result = Vec::new();
            result.extend_from_slice(&conflicting.offset.to_be_bytes());
            result.extend_from_slice(&conflicting.length.to_be_bytes());
            result.extend_from_slice(&conflicting.lock_type.to_be_bytes());
            let olen = conflicting.lock_owner.len() as u32;
            result.extend_from_slice(&olen.to_be_bytes());
            result.extend_from_slice(&conflicting.lock_owner);
            let padded = (conflicting.lock_owner.len() + 3) & !3;
            let pad = padded - conflicting.lock_owner.len();
            for _ in 0..pad { result.push(0); }
            return (result, consumed, None, None, NFS4ERR_DENIED);
        }
        
        // Allocate lock_stateid
        let lock_stateid = {
            let mut ctr = self.lock_counter.write().await;
            let id = *ctr;
            *ctr += 1;
            let mut sid = [0u8; 12];
            sid[0..8].copy_from_slice(&id.to_be_bytes());
            sid
        };

        // Add the lock
        file_locks.push(FileLock {
            offset,
            length,
            lock_type,
            lock_owner: owner,
            client_id,
            lock_stateid,
        });
        info!("NFS4 LOCK: granted");
        
        // LOCK4resok: lock_stateid4 = seqid(4) + other(12) = 16 bytes
        let mut result = Vec::new();
        result.extend_from_slice(&1u32.to_be_bytes()); // seqid=1
        result.extend_from_slice(&lock_stateid);        // other(12)
        (result, consumed, None, None, NFS4_OK)
    }
    
    async fn op_lockt(&self, request: &[u8], p: usize, current_fh: &Option<Vec<u8>>)
        -> (Vec<u8>, usize, Option<Vec<u8>>, Option<Vec<u8>>, u32)
    {
        info!("NFS4 LOCKT");
        if current_fh.is_none() {
            return (vec![], 0, None, None, NFS4ERR_NOFILEHANDLE);
        }
        
        let (lock_type, _reclaim, offset, length, consumed, _owner, _client_id) = match self.parse_lock_args(request, p) {
            Ok(args) => args,
            Err(consumed) => return (vec![], consumed - p, None, None, NFS4ERR_BADXDR),
        };
        
        // Extract open_stateid from request (is_new=true: open_stateid at p+32; is_new=false: lock_stateid at p+28)
        let stateid_id = {
            let sid_offset = p + 24 + 4 + 4; // is_new(4) + seqid(4)
            if sid_offset + 8 <= request.len() {
                u64::from_be_bytes([
                    request[sid_offset], request[sid_offset+1], request[sid_offset+2], request[sid_offset+3],
                    request[sid_offset+4], request[sid_offset+5], request[sid_offset+6], request[sid_offset+7],
                ])
            } else {
                return (vec![], consumed, None, None, NFS4ERR_BADXDR);
            }
        };
        
        let locks_map = self.locks.read().await;
        let file_locks = locks_map.get(&stateid_id);

        // Check for conflicts (test only, no recording)
        if let Some(existing) = file_locks {
            if let Some(conflicting) = Self::check_lock_conflict(existing, lock_type, offset, length) {
                let mut result = Vec::new();
                result.extend_from_slice(&conflicting.offset.to_be_bytes());
                result.extend_from_slice(&conflicting.length.to_be_bytes());
                result.extend_from_slice(&conflicting.lock_type.to_be_bytes());
                let olen = conflicting.lock_owner.len() as u32;
                result.extend_from_slice(&olen.to_be_bytes());
                result.extend_from_slice(&conflicting.lock_owner);
                let padded = (conflicting.lock_owner.len() + 3) & !3;
                let pad = padded - conflicting.lock_owner.len();
                for _ in 0..pad { result.push(0); }
                return (result, consumed, None, None, NFS4ERR_DENIED);
            }
        }
        
        // No conflict
        (vec![], consumed, None, None, NFS4_OK)
    }
    
    async fn op_locku(&self, request: &[u8], p: usize, current_fh: &Option<Vec<u8>>)
        -> (Vec<u8>, usize, Option<Vec<u8>>, Option<Vec<u8>>, u32)
    {
        info!("NFS4 LOCKU");
        if current_fh.is_none() {
            return (vec![], 0, None, None, NFS4ERR_NOFILEHANDLE);
        }
        
        let (lock_type, _reclaim, offset, length, consumed, owner, _client_id) = match self.parse_lock_args(request, p) {
            Ok(args) => args,
            Err(consumed) => return (vec![], consumed - p, None, None, NFS4ERR_BADXDR),
        };
        
        // Extract open_stateid from request (is_new=true: open_stateid at p+32; is_new=false: lock_stateid at p+28)
        let stateid_id = {
            let sid_offset = p + 24 + 4 + 4; // is_new(4) + seqid(4)
            if sid_offset + 8 <= request.len() {
                u64::from_be_bytes([
                    request[sid_offset], request[sid_offset+1], request[sid_offset+2], request[sid_offset+3],
                    request[sid_offset+4], request[sid_offset+5], request[sid_offset+6], request[sid_offset+7],
                ])
            } else {
                return (vec![], consumed, None, None, NFS4ERR_BADXDR);
            }
        };
        
        info!("NFS4 LOCKU: type={}, offset={}, length={}, stateid_id={}", lock_type, offset, length, stateid_id);
        
        let mut locks = self.locks.write().await;
        let mut lock_stateid: Option<[u8; 12]> = None;
        if let Some(file_locks) = locks.get_mut(&stateid_id) {
            // Find and remove matching lock; capture its stateid for response
            let mut found_sid: Option<[u8; 12]> = None;
            file_locks.retain(|l| {
                if l.offset == offset && l.length == length && l.lock_type == lock_type && l.lock_owner == owner {
                    found_sid = Some(l.lock_stateid);
                    false // remove
                } else {
                    true // keep
                }
            });
            lock_stateid = found_sid;
            info!("NFS4 LOCKU: lock released");
        }
        
        // LOCKU4res: lock_stateid (16 bytes) — echo back stored stateid or zero
        let mut result = Vec::new();
        if let Some(sid) = lock_stateid {
            result.extend_from_slice(&1u32.to_be_bytes()); // seqid=1
            result.extend_from_slice(&sid);
        } else {
            // Lock not found — return zero stateid (seqid=0)
            result.extend_from_slice(&0u32.to_be_bytes());
            result.extend_from_slice(&[0u8; 12]);
        }
        (result, consumed, None, None, NFS4_OK)
    }

    // ──────────────────────────────────────────────────────────────────────────
    // NFS v4.1: EXCHANGE_ID (RFC 5662)
    // ──────────────────────────────────────────────────────────────────────────
    async fn op_exchange_id(&self, request: &[u8], p: usize)
        -> (Vec<u8>, usize, Option<Vec<u8>>, Option<Vec<u8>>, u32)
    {
        info!("NFS4 EXCHANGE_ID");
        
        // Debug: log the full request hex
        let request_hex = request.iter()
            .skip(p)
            .take(64)  // First 64 bytes should be enough
            .map(|b| format!("{:02x}", b))
            .collect::<Vec<_>>()
            .chunks(4)
            .map(|c| c.join(" "))
            .collect::<Vec<_>>()
            .join(" ");
        trace!("EXCHANGE_ID request[{}..]: {}", p, request_hex);
        
        let mut pp = p;

        // client verifier (8 bytes)
        if pp + 8 > request.len() { return (vec![], 0, None, None, NFS4ERR_BADXDR); }
        let _client_verifier = &request[pp..pp+8];
        pp += 8;

        // client id string (opaque<>)
        if pp + 4 > request.len() { return (vec![], 0, None, None, NFS4ERR_BADXDR); }
        let id_len = u32::from_be_bytes([request[pp], request[pp+1], request[pp+2], request[pp+3]]) as usize;
        pp += 4;
        if pp + id_len > request.len() { return (vec![], 0, None, None, NFS4ERR_BADXDR); }
        let client_owner = request[pp..pp+id_len].to_vec();
        pp += (id_len + 3) & !3;

        // flags (4 bytes)
        if pp + 4 > request.len() { return (vec![], 0, None, None, NFS4ERR_BADXDR); }
        let _client_flags = u32::from_be_bytes([request[pp], request[pp+1], request[pp+2], request[pp+3]]);
        pp += 4;

        // state_protect_how (4 bytes) - skip
        if pp + 4 > request.len() { return (vec![], 0, None, None, NFS4ERR_BADXDR); }
        let spa_how = u32::from_be_bytes([request[pp], request[pp+1], request[pp+2], request[pp+3]]);
        pp += 4;

        // Skip spa data based on spa_how
        if spa_how == 1 || spa_how == 2 { // SP4_MACH_CRED or SP4_SSV
            // spa_server_mechanisms (opaque<>)
            if pp + 4 > request.len() { return (vec![], 0, None, None, NFS4ERR_BADXDR); }
            let mech_len = u32::from_be_bytes([request[pp], request[pp+1], request[pp+2], request[pp+3]]) as usize;
            pp += 4;
            if pp + mech_len > request.len() { return (vec![], 0, None, None, NFS4ERR_BADXDR); }
            pp += (mech_len + 3) & !3;

            // spa_process_mechanisms (opaque<>)
            if pp + 4 > request.len() { return (vec![], 0, None, None, NFS4ERR_BADXDR); }
            let proc_len = u32::from_be_bytes([request[pp], request[pp+1], request[pp+2], request[pp+3]]) as usize;
            pp += 4;
            if pp + proc_len > request.len() { return (vec![], 0, None, None, NFS4ERR_BADXDR); }
            pp += (proc_len + 3) & !3;

            // spa_machine_cred (opaque<>)
            if pp + 4 > request.len() { return (vec![], 0, None, None, NFS4ERR_BADXDR); }
            let cred_len = u32::from_be_bytes([request[pp], request[pp+1], request[pp+2], request[pp+3]]) as usize;
            pp += 4;
            // SEC-012: Prevent integer overflow
            if cred_len > crate::nfs::MAX_XDR_OPAQUE { return (vec![], 0, None, None, NFS4ERR_BADXDR); }
            if pp + cred_len > request.len() { return (vec![], 0, None, None, NFS4ERR_BADXDR); }
            pp += (cred_len + 3) & !3;
        }

        // implid count (4 bytes) - usually 0 or 1
        if pp + 4 > request.len() { return (vec![], 0, None, None, NFS4ERR_BADXDR); }
        let implid_count = u32::from_be_bytes([request[pp], request[pp+1], request[pp+2], request[pp+3]]) as usize;
        pp += 4;

        // Skip implid if present
        for _ in 0..implid_count {
            // nii_domain (opaque<>)
            if pp + 4 > request.len() { return (vec![], 0, None, None, NFS4ERR_BADXDR); }
            let domain_len = u32::from_be_bytes([request[pp], request[pp+1], request[pp+2], request[pp+3]]) as usize;
            pp += 4;
            pp += (domain_len + 3) & !3;
            // nii_name (opaque<>)
            if pp + 4 > request.len() { return (vec![], 0, None, None, NFS4ERR_BADXDR); }
            let name_len = u32::from_be_bytes([request[pp], request[pp+1], request[pp+2], request[pp+3]]) as usize;
            pp += 4;
            pp += (name_len + 3) & !3;
            // nii_date (8 bytes)
            if pp + 8 > request.len() { return (vec![], 0, None, None, NFS4ERR_BADXDR); }
            pp += 8;
        }

        let consumed = pp - p;

        // RFC 5661 §18.35.3: When a client with the same client_owner calls
        // EXCHANGE_ID again, the server MUST return the SAME client_id.
        // This is critical for NFSv4.1 session handshake — without it,
        // CREATE_SESSION references a stale client_id and fails with
        // NFS4ERR_STALE_CLIENTID.
        let server_client_id = {
            let owner_map = self.client_owner_map.read().await;
            if let Some(&existing_id) = owner_map.get(&client_owner) {
                debug!("NFS4 EXCHANGE_ID: reusing existing client_id={} for owner",
                    existing_id);
                existing_id
            } else {
                drop(owner_map);
                let mut counter = self.client_counter.write().await;
                let new_id = *counter;
                *counter += 1;
                drop(counter);
                let mut owner_map = self.client_owner_map.write().await;
                owner_map.insert(client_owner.clone(), new_id);
                debug!("NFS4 EXCHANGE_ID: assigned new client_id={}",
                    new_id);
                new_id
            }
        };

        // Server verifier (8 bytes) - always zero for simplicity
        let server_verifier = [0u8; 8];

        // eir_flags — RFC 5661 §18.35.3, matching Linux uapi/linux/nfs4.h values:
        //   EXCHGID4_FLAG_SUPP_MOVED_REFER  = 0x00000001
        //   EXCHGID4_FLAG_CONFIRMED_R        = 0x80000000  ← returned by server when confirmed
        //   EXCHGID4_FLAG_USE_NON_PNFS       = 0x00010000  ← plain NFS, no pNFS
        //   EXCHGID4_FLAG_USE_PNFS_MDS       = 0x00020000
        //   EXCHGID4_FLAG_MASK_PNFS          = 0x00070000  ← must have at least one of these bits
        //   EXCHGID4_FLAG_MASK_R             = 0x80070103  ← only these bits are valid in response
        //
        // Linux nfs4_check_cl_exchange_flags() requires:
        //   1. (flags & ~EXCHGID4_FLAG_MASK_R) == 0   (no extra bits)
        //   2. (flags & EXCHGID4_FLAG_MASK_PNFS) != 0 (at least one pNFS role bit)
        const EXCHGID4_FLAG_CONFIRMED_R:  u32 = 0x80000000;
        const EXCHGID4_FLAG_USE_NON_PNFS: u32 = 0x00010000;
        const EXCHGID4_FLAG_SUPP_MOVED_REFER: u32 = 0x00000001;
        const EXCHGID4_FLAG_SUPP_MOVED_MIGR: u32 = 0x00000002;

        let eir_flags = EXCHGID4_FLAG_CONFIRMED_R | EXCHGID4_FLAG_USE_NON_PNFS
            | EXCHGID4_FLAG_SUPP_MOVED_REFER | EXCHGID4_FLAG_SUPP_MOVED_MIGR;

        // Server scope (opaque<>) - empty
        let server_scope: Vec<u8> = vec![];

        // Implementation ID - empty
        let implid_count_out = 0u32;

        // Build response
        let mut result = Vec::new();

        // RFC 5661 Section 18.57: EXCHANGE_ID4resok structure
        // Order: eir_clientid, eir_sequenceid, eir_flags, eir_state_protect,
        //        eir_server_owner, eir_server_scope, eir_server_impl_id
        
        // eir_clientid (8 bytes) - big endian client ID
        result.extend_from_slice(&server_client_id.to_be_bytes());

        // eir_sequenceid (4 bytes) - use stored sequence for reconnect,
        // start at 1 for new clients (RFC 5661 §18.35.3)
        let eir_seqid = {
            let clients = self.clients.read().await;
            clients.get(&server_client_id).map(|c| c.sequence).unwrap_or(1)
        };
        result.extend_from_slice(&eir_seqid.to_be_bytes());

        // eir_flags (4 bytes)
        result.extend_from_slice(&eir_flags.to_be_bytes());

        // eir_state_protect (union) - SP4_NONE = 0
        // For SP4_NONE: just the spa_how discriminant
        result.extend_from_slice(&0u32.to_be_bytes()); // spa_how = SP4_NONE

        // eir_server_owner
        // so_minor_id (8 bytes)
        result.extend_from_slice(&0u64.to_be_bytes());
        // so_major_id (opaque<>)
        let major_id = b"RustNfsSvc";
        result.extend_from_slice(&(major_id.len() as u32).to_be_bytes());
        result.extend_from_slice(major_id);
        let padding = (4 - (major_id.len() % 4)) % 4;
        result.extend_from_slice(&[0u8; 4][..padding]);

        // eir_server_scope (opaque<>)
        result.extend_from_slice(&0u32.to_be_bytes()); // empty

        // eir_server_impl_id (array) - empty
        result.extend_from_slice(&implid_count_out.to_be_bytes());


        // Store client in map
        let mut clients = self.clients.write().await;
        clients.insert(server_client_id, ClientRecord {
            client_id: server_client_id,
            verifier: server_verifier,
            id_string: vec![],
            callback_program: 0,
            confirmed: false,
            confirm_verifier: [0u8; 8],
            sequence: 1,
            last_used: std::time::Instant::now(), // SEC-011
        });

        // Debug: log EXCHANGE_ID result bytes
        let result_hex: String = result.chunks(4)
            .map(|c| c.iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join(" "))
            .collect::<Vec<_>>()
            .join(" | ");
        trace!("NFS4 EXCHANGE_ID result ({} bytes): {}", result.len(), result_hex);
        debug!("  eir_clientid=0x{:016x} eir_seqid={} eir_flags=0x{:08x}",
            server_client_id, 1u32, eir_flags);
        (result, consumed, None, None, NFS4_OK)
    }

    // ──────────────────────────────────────────────────────────────────────────
    // NFS v4.1: CREATE_SESSION (RFC 5661 §18.36)
    // ──────────────────────────────────────────────────────────────────────────
    async fn op_create_session(&self, request: &[u8], p: usize)
        -> (Vec<u8>, usize, Option<Vec<u8>>, Option<Vec<u8>>, u32)
    {
        info!("NFS4 CREATE_SESSION");
        let mut pp = p;

        // csa_clientid (8 bytes)
        if pp + 8 > request.len() { return (vec![], 0, None, None, NFS4ERR_BADXDR); }
        let client_id = u64::from_be_bytes([
            request[pp], request[pp+1], request[pp+2], request[pp+3],
            request[pp+4], request[pp+5], request[pp+6], request[pp+7]
        ]);
        pp += 8;

        // csa_sequence (4 bytes)
        if pp + 4 > request.len() { return (vec![], 0, None, None, NFS4ERR_BADXDR); }
        let _csa_sequence = u32::from_be_bytes([request[pp], request[pp+1], request[pp+2], request[pp+3]]);
        pp += 4;

        // csa_flags (4 bytes)
        if pp + 4 > request.len() { return (vec![], 0, None, None, NFS4ERR_BADXDR); }
        pp += 4;

        // Helper closure: parse channel_attrs4
        // channel_attrs4 = headerpadsize(4) + maxrequestsize(4) + maxresponsesize(4)
        //                + maxresponsesize_cached(4) + maxoperations(4) + maxrequests(4)
        //                + rdma_ird<> (4 + N*4 bytes)
        let parse_channel_attrs = |buf: &[u8], pos: usize| -> Option<(usize, u32, u32, u32, u32)> {
            let mut q = pos;
            if q + 24 > buf.len() { return None; }
            let _headerpad = u32::from_be_bytes([buf[q], buf[q+1], buf[q+2], buf[q+3]]); q += 4;
            let maxreq  = u32::from_be_bytes([buf[q], buf[q+1], buf[q+2], buf[q+3]]); q += 4;
            let maxresp = u32::from_be_bytes([buf[q], buf[q+1], buf[q+2], buf[q+3]]); q += 4;
            let maxresp_cached = u32::from_be_bytes([buf[q], buf[q+1], buf[q+2], buf[q+3]]); q += 4;
            let maxops  = u32::from_be_bytes([buf[q], buf[q+1], buf[q+2], buf[q+3]]); q += 4;
            let maxreqs = u32::from_be_bytes([buf[q], buf[q+1], buf[q+2], buf[q+3]]); q += 4;
            // ca_rdma_ird<> — array of uint32_t
            if q + 4 > buf.len() { return None; }
            let ird_count = u32::from_be_bytes([buf[q], buf[q+1], buf[q+2], buf[q+3]]) as usize; q += 4;
            q += ird_count * 4;
            Some((q, maxreq, maxresp, maxops, maxreqs))
        };

        // fore_channel_attrs
        let (pp2, fore_maxreq, fore_maxresp, fore_maxops, fore_maxreqs) =
            match parse_channel_attrs(request, pp) {
                None => return (vec![], pp-p, None, None, NFS4ERR_BADXDR),
                Some(v) => v,
            };
        pp = pp2;

        // back_channel_attrs
        let (pp3, _back_maxreq, _back_maxresp, _back_maxops, _back_maxreqs) =
            match parse_channel_attrs(request, pp) {
                None => return (vec![], pp-p, None, None, NFS4ERR_BADXDR),
                Some(v) => v,
            };
        pp = pp3;

        // csa_cb_program (4 bytes)
        if pp + 4 > request.len() { return (vec![], pp-p, None, None, NFS4ERR_BADXDR); }
        pp += 4;

        // csa_sec_parms<> — array of callback_sec_parms4, skip entire array
        if pp + 4 > request.len() { return (vec![], pp-p, None, None, NFS4ERR_BADXDR); }
        let sec_count = u32::from_be_bytes([request[pp], request[pp+1], request[pp+2], request[pp+3]]) as usize;
        pp += 4;
        for _ in 0..sec_count {
            // callback_sec_parms4: cb_secflavor(4) + flavor-specific data
            if pp + 4 > request.len() { return (vec![], pp-p, None, None, NFS4ERR_BADXDR); }
            let flavor = u32::from_be_bytes([request[pp], request[pp+1], request[pp+2], request[pp+3]]);
            pp += 4;
            match flavor {
                0 => {} // AUTH_NONE — no extra data
                1 => {} // AUTH_SYS is not valid here per RFC; skip
                _ => {
                    // Unknown flavor, can't parse; just bail gracefully
                    break;
                }
            }
        }

        let consumed = pp - p;

        // Generate session ID: 16 bytes derived from client_id
        let session_id: [u8; 16] = [
            (client_id >> 56) as u8, (client_id >> 48) as u8,
            (client_id >> 40) as u8, (client_id >> 32) as u8,
            (client_id >> 24) as u8, (client_id >> 16) as u8,
            (client_id >>  8) as u8,  client_id        as u8,
            0, 0, 0, 0, 0, 0, 0, 1,
        ];

        // Negotiate channel sizes — cap at our limits but honour client's request
        let max_req_sz   = fore_maxreq.min(1048576).max(4096);
        let max_resp_sz  = fore_maxresp.min(1048576).max(4096);
        let max_ops      = fore_maxops.min(100).max(1);
        let max_reqs     = fore_maxreqs.min(64).max(1);

        // BUILD CREATE_SESSION4resok:
        // csr_sessionid(16) + csr_sequence(4) + csr_flags(4)
        // + fore_channel_attrs(28) + back_channel_attrs(28)
        let mut result = Vec::new();

        // csr_sessionid (16 bytes)
        result.extend_from_slice(&session_id);

        // csr_sequence (4 bytes) — echo back 1
        result.extend_from_slice(&1u32.to_be_bytes());

        // csr_flags (4 bytes) — no special flags
        result.extend_from_slice(&0u32.to_be_bytes());

        // fore_channel_attrs4
        result.extend_from_slice(&0u32.to_be_bytes());          // ca_headerpadsize
        result.extend_from_slice(&max_req_sz.to_be_bytes());    // ca_maxrequestsize
        result.extend_from_slice(&max_resp_sz.to_be_bytes());   // ca_maxresponsesize
        result.extend_from_slice(&0u32.to_be_bytes());          // ca_maxresponsesize_cached
        result.extend_from_slice(&max_ops.to_be_bytes());       // ca_maxoperations
        result.extend_from_slice(&max_reqs.to_be_bytes());      // ca_maxrequests
        result.extend_from_slice(&0u32.to_be_bytes());          // ca_rdma_ird count=0

        // back_channel_attrs4 (minimal)
        result.extend_from_slice(&0u32.to_be_bytes());          // ca_headerpadsize
        result.extend_from_slice(&4096u32.to_be_bytes());       // ca_maxrequestsize
        result.extend_from_slice(&4096u32.to_be_bytes());       // ca_maxresponsesize
        result.extend_from_slice(&0u32.to_be_bytes());          // ca_maxresponsesize_cached
        result.extend_from_slice(&2u32.to_be_bytes());          // ca_maxoperations
        result.extend_from_slice(&1u32.to_be_bytes());          // ca_maxrequests
        result.extend_from_slice(&0u32.to_be_bytes());          // ca_rdma_ird count=0

        debug!("NFS4 CREATE_SESSION: client_id={}, session assigned", client_id);

        // Store session for later SEQUENCE validation
        {
            let mut sessions = self.sessions.write().await;
            sessions.insert(session_id.to_vec(), SessionRecord {
                session_id,
                client_id,
                sequence: 1,
                highest_slot: max_reqs - 1,
                fore_max_ops: max_ops,
                fore_max_reqs: max_reqs,
                last_used: std::time::Instant::now(), // SEC-011
            });
            info!("NFS4 CREATE_SESSION: stored session, total sessions={}", sessions.len());
        }

        (result, consumed, None, None, NFS4_OK)
    }

    // ──────────────────────────────────────────────────────────────────────────
    // NFS v4.1: DESTROY_SESSION
    // ──────────────────────────────────────────────────────────────────────────
    async fn op_destroy_session(&self, request: &[u8], p: usize)
        -> (Vec<u8>, usize, Option<Vec<u8>>, Option<Vec<u8>>, u32)
    {
        let consumed = 16; // sessionid
        if p + 16 > request.len() {
            return (vec![], 0, None, None, NFS4ERR_BADXDR);
        }
        let session_id = &request[p..p+16];
        {
            let mut sessions = self.sessions.write().await;
            sessions.remove(session_id);
            info!("NFS4 DESTROY_SESSION: removed session, remaining={}", sessions.len());
        }
        (vec![], consumed, None, None, NFS4_OK)
    }

    // ──────────────────────────────────────────────────────────────────────────
    // NFS v4.1: BIND_CONN_TO_SESSION (RFC 5661 §18.34)
    //   Request:  sessionid(16) + dir(4) + use_conn_in_rdma_mode(4) = 24 bytes
    //   Response: sessionid(16) + dir(4) + use_conn_in_rdma_mode(4) = 24 bytes
    //   The server MUST echo back the sessionid and dir — returning an empty
    //   response causes the Linux kernel's XDR decoder to fail with EINVAL.
    // ──────────────────────────────────────────────────────────────────────────
    async fn op_bind_conn_to_session(&self, request: &[u8], p: usize)
        -> (Vec<u8>, usize, Option<Vec<u8>>, Option<Vec<u8>>, u32)
    {
        info!("NFS4 BIND_CONN_TO_SESSION");
        if p + 24 > request.len() {
            return (vec![], 0, None, None, NFS4ERR_BADXDR);
        }

        // Parse args: sessionid(16) + dir(4) + rdma(4)
        let session_id = &request[p..p+16];
        let dir = u32::from_be_bytes([request[p+16], request[p+17], request[p+18], request[p+19]]);
        let rdma = u32::from_be_bytes([request[p+20], request[p+21], request[p+22], request[p+23]]);

        debug!("NFS4 BIND_CONN_TO_SESSION: dir={}, rdma={}", dir, rdma);

        // SEC-010: Validate session strictly
        {
            let sessions = self.sessions.read().await;
            if sessions.contains_key(session_id) {
                info!("NFS4 BIND_CONN_TO_SESSION: known session, {} active", sessions.len());
            } else {
                warn!("NFS4 BIND_CONN_TO_SESSION: unknown session, rejecting (SEC-010 strict mode)");
                return (vec![], 24, None, None, NFS4ERR_BADSESSION);
            }
        }

        // RFC 5661 §18.34: echo back sessionid + dir + rdma flag
        let mut result = Vec::with_capacity(24);
        result.extend_from_slice(session_id);
        result.extend_from_slice(&dir.to_be_bytes());
        result.extend_from_slice(&rdma.to_be_bytes());

        (result, 24, None, None, NFS4_OK)
    }

    // ──────────────────────────────────────────────────────────────────────────
    // NFS v4.1: DESTROY_CLIENTID
    // ──────────────────────────────────────────────────────────────────────────
    async fn op_destroy_clientid(&self, request: &[u8], p: usize)
        -> (Vec<u8>, usize, Option<Vec<u8>>, Option<Vec<u8>>, u32)
    {
        let consumed = 8; // clientid(8)
        if p + 8 <= request.len() {
            let client_id = u64::from_be_bytes([
                request[p], request[p+1], request[p+2], request[p+3],
                request[p+4], request[p+5], request[p+6], request[p+7]
            ]);
            // Remove all sessions belonging to this client
            let mut sessions = self.sessions.write().await;
            let before = sessions.len();
            sessions.retain(|_, s| s.client_id != client_id);
            debug!("NFS4 DESTROY_CLIENTID: cleaned {} sessions ({}→{})",
                before - sessions.len(), before, sessions.len());
        }
        (vec![], consumed, None, None, NFS4_OK)
    }

    // ──────────────────────────────────────────────────────────────────────────
    // NFS v4.1: SEQUENCE (RFC 5661 §18.46)
    //   MUST be the first operation in every NFSv4.1 COMPOUND (except
    //   EXCHANGE_ID and CREATE_SESSION compounds).
    //   Request:  sessionid(16) + sequenceid(4) + slotid(4) + highest_slotid(4)
    //             + cachethis(4)  = 32 bytes
    //   Response: sessionid(16) + sequenceid(4) + slotid(4) + highest_slotid(4)
    //             + target_highest_slotid(4) + status_flags(4) = 36 bytes
    // ──────────────────────────────────────────────────────────────────────────
    async fn op_sequence(&self, request: &[u8], p: usize)
        -> (Vec<u8>, usize, Option<Vec<u8>>, Option<Vec<u8>>, u32)
    {
        let consumed = 32; // sessionid(16) + sequenceid(4) + slotid(4) + highest_slotid(4) + cachethis(4)
        if p + consumed > request.len() {
            return (vec![], consumed, None, None, NFS4ERR_BADXDR);
        }

        let session_id = &request[p..p+16];
        let seq_id = u32::from_be_bytes([request[p+16], request[p+17], request[p+18], request[p+19]]);
        let slot_id = u32::from_be_bytes([request[p+20], request[p+21], request[p+22], request[p+23]]);
        let highest_slot_id = u32::from_be_bytes([request[p+24], request[p+25], request[p+26], request[p+27]]);

        // SEC-010: Strict session validation.
        // Unknown sessions are rejected with NFS4ERR_BADSESSION.
        // The client must re-establish via EXCHANGE_ID + CREATE_SESSION.
        // (Previously lenient mode allowed unknown sessions, which bypassed
        // session validation and could be exploited by attackers.)
        let echo_sid: &[u8];
        let echo_highest_slot;
        {
            let sessions = self.sessions.read().await;
            if let Some(s) = sessions.get(session_id) {
                if seq_id < s.sequence {
                    info!("NFS4 SEQUENCE: seqid {} < stored {}, rejecting",
                        seq_id, s.sequence);
                    return (vec![], consumed, None, None, NFS4ERR_BADSESSION);
                }
                // Drop read lock, acquire write lock to update
                drop(sessions);
                let mut w = self.sessions.write().await;
                if let Some(s) = w.get_mut(session_id) {
                    s.sequence = seq_id;
                    s.last_used = std::time::Instant::now(); // SEC-011
                    if highest_slot_id > s.highest_slot {
                        s.highest_slot = highest_slot_id;
                    }
                    echo_highest_slot = s.highest_slot;
                } else {
                    echo_highest_slot = highest_slot_id;
                }
                echo_sid = session_id;
                info!("NFS4 SEQUENCE: OK (known session) seqid={} slot={}",
                    seq_id, slot_id);
            } else {
                // SEC-010: Unknown session — strict rejection
                warn!("NFS4 SEQUENCE: unknown session, rejecting (SEC-010 strict mode) active_sessions={}",
                    sessions.len());
                return (vec![], consumed, None, None, NFS4ERR_BADSESSION);
            }
        }

        let mut result = Vec::with_capacity(36);
        result.extend_from_slice(echo_sid);
        result.extend_from_slice(&seq_id.to_be_bytes());
        result.extend_from_slice(&slot_id.to_be_bytes());
        result.extend_from_slice(&echo_highest_slot.to_be_bytes());
        result.extend_from_slice(&echo_highest_slot.to_be_bytes());
        result.extend_from_slice(&0u32.to_be_bytes());

        (result, consumed, None, None, NFS4_OK)
    }

    // ──────────────────────────────────────────────────────────────────────────
    // NFS v4.1: RECLAIM_COMPLETE (RFC 5661 §18.51)
    //   Request:  rca_one_fs(4)  = 4 bytes
    //   Response: (empty)
    // ──────────────────────────────────────────────────────────────────────────
    async fn op_reclaim_complete(&self, _request: &[u8], _p: usize)
        -> (Vec<u8>, usize, Option<Vec<u8>>, Option<Vec<u8>>, u32)
    {
        info!("NFS4 RECLAIM_COMPLETE");
        (vec![], 4, None, None, NFS4_OK)
    }

    // ──────────────────────────────────────────────────────────────────────────
    // SEC-011: Lease cleanup — expire idle sessions and clients
    // ──────────────────────────────────────────────────────────────────────────
    /// Remove sessions and clients that have been idle longer than LEASE_TIMEOUT.
    /// Should be called periodically (e.g. every 60 seconds) from a background task.
    pub async fn cleanup_expired(&self) {
        let now = std::time::Instant::now();

        // Clean expired sessions
        let expired_sessions: Vec<Vec<u8>> = {
            let sessions = self.sessions.read().await;
            sessions.iter()
                .filter(|(_, s)| now.duration_since(s.last_used) > LEASE_TIMEOUT)
                .map(|(id, _)| id.clone())
                .collect()
        };
        if !expired_sessions.is_empty() {
            let mut sessions = self.sessions.write().await;
            for sid in &expired_sessions {
                sessions.remove(sid);
            }
            info!("SEC-011: cleaned up {} expired sessions", expired_sessions.len());
        }

        // Clean expired clients (only those with no remaining sessions)
        let expired_clients: Vec<u64> = {
            let clients = self.clients.read().await;
            let sessions = self.sessions.read().await;
            let active_client_ids: std::collections::HashSet<u64> =
                sessions.values().map(|s| s.client_id).collect();
            clients.iter()
                .filter(|(id, c)| {
                    now.duration_since(c.last_used) > LEASE_TIMEOUT
                        && !active_client_ids.contains(id)
                })
                .map(|(id, _)| *id)
                .collect()
        };
        if !expired_clients.is_empty() {
            let mut clients = self.clients.write().await;
            let mut owner_map = self.client_owner_map.write().await;
            for cid in &expired_clients {
                if let Some(record) = clients.remove(cid) {
                    owner_map.remove(&record.id_string);
                }
            }
            info!("SEC-011: cleaned up {} expired clients", expired_clients.len());
        }
    }

    // ──────────────────────────────────────────────────────────────────────────
    // Build fattr4 (file attributes XDR)
    // ──────────────────────────────────────────────────────────────────────────
    async fn build_fattr4(&self, path: &Option<PathBuf>, requested_bitmap: &[u32], default_type: u32, is_root: bool) -> Vec<u8> {
        let path_str = path.as_ref().map(|p| p.to_string_lossy().to_string());
        let meta = path.as_ref().and_then(|p| std::fs::metadata(to_extended_path(p)).ok());
        debug!("NFS4 build_fattr4: path={:?}, meta={:?} (is_none={})", path_str, meta.is_some(), meta.is_none());
        // Debug: if meta is None, log the error
        // Determine which attrs we'll include
        // We only provide a useful subset
        let bm0_requested = requested_bitmap.get(0).copied().unwrap_or(0);
        let bm1_requested = requested_bitmap.get(1).copied().unwrap_or(0);

        // Supported attrs bitmap (words 0 and 1)
        // NFSv4.1 (RFC 5661) attribute numbers, matching Linux kernel nfs4.h
        // word0: type(1), change(3), size(4), fsid(8), fileid(20)
        // Also: link_support(5), symlink_support(6), named_attr(7),
        //       unique_handles(9), lease_time(10), fh_expire_type(2)
        //       space_free(13), space_total(14), space_avail(15)
        // word1: mode(33), numlinks(35), owner(36), owner_group(37),
        //        rawdev(41), space_used(45), time_access(47),
        //        time_metadata(52), time_modify(53)
        let bm0_provide: u32 = (1 << 0)  // supported_attrs
            | (1 << 1)  // type
            | (1 << 2)  // fh_expire_type
            | (1 << 3)  // change
            | (1 << 4)  // size
            | (1 << 5)  // link_support
            | (1 << 6)  // symlink_support
            | (1 << 7)  // named_attr
            | (1 << 8)  // fsid
            | (1 << 9)  // unique_handles
            | (1 << 10) // lease_time
            // NOTE: bits 13-15 are NOT advertised here because RFC 3530 (NFSv4.0)
            // and RFC 5661 (NFSv4.1) assign different semantics to these bits:
            //   bit 13: ACL (v4.0) vs space_free (v4.1) — we support neither
            //   bit 14: aclsupport (v4.0) vs space_total (v4.1) — we support neither
            //   bit 15: archive (v4.0) vs space_avail (v4.1) — we support neither
            // Advertising them as v4.1 space attributes when a v4.0 client requests
            // them causes XDR decoding errors and mount failures.
            | (1 << 20); // fileid (bit 20 in word 0, per RFC 5661)
        let bm1_provide: u32 = (1 << (33-32))  // mode
            | (1 << (35-32))  // numlinks
            | (1 << (36-32))  // owner
            | (1 << (37-32))  // owner_group
            | (1 << (41-32))  // rawdev (RECOMMENDED, specdev4)
            | (1 << (45-32))  // space_used (RECOMMENDED)
            | (1 << (46-32))  // space_freed (NFSv4.2, RFC 7862)
            | (1 << (47-32))  // time_access (RECOMMENDED)
            | (1 << (52-32))  // time_metadata
            | (1 << (53-32))  // time_modify
            | (1 << (55-32)); // mounted_on_fileid (RECOMMENDED, critical for Linux NFS client)

        // Intersect with requested
        let bm0_actual = bm0_requested & bm0_provide;
        let bm1_actual = bm1_requested & bm1_provide;

        debug!("NFS4 build_fattr4: bm0_req={:#034b}, bm0_provide={:#034b}, bm0_actual={:#034b} (has_type={})",
            bm0_requested, bm0_provide, bm0_actual, bm0_actual & (1 << 1) != 0);

        // Now build attr_vals
        let mut attr_vals: Vec<u8> = Vec::new();

        // supported_attrs (bit 0 of word 0) -> returns our supported bitmap
        if bm0_actual & (1 << 0) != 0 {
            attr_vals.extend_from_slice(&2u32.to_be_bytes()); // 2 bitmap words
            attr_vals.extend_from_slice(&bm0_provide.to_be_bytes());
            attr_vals.extend_from_slice(&bm1_provide.to_be_bytes());
        }

        // type (bit 1 word 0)
        if bm0_actual & (1 << 1) != 0 {
            let ftype = if let Some(ref m) = meta {
                if m.is_dir() { NF4DIR } else { NF4REG }
            } else { default_type };
            attr_vals.extend_from_slice(&ftype.to_be_bytes());
        }

        // fh_expire_type (bit 2 word 0) -> uint32_t (FH4_PERSISTENT = 0x1)
        if bm0_actual & (1 << 2) != 0 {
            attr_vals.extend_from_slice(&1u32.to_be_bytes()); // FH4_PERSISTENT
        }

        // change (bit 3 word 0) -> changeid4 (8 bytes)
        if bm0_actual & (1 << 3) != 0 {
            let mtime = meta.as_ref()
                .and_then(|m| m.modified().ok())
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|d| d.as_nanos() as u64)
                .unwrap_or(0);
            attr_vals.extend_from_slice(&mtime.to_be_bytes());
        }

        // size (bit 4 word 0)
        if bm0_actual & (1 << 4) != 0 {
            let size = meta.as_ref().map(|m| m.len()).unwrap_or(0);
            attr_vals.extend_from_slice(&size.to_be_bytes());
        }

        // link_support (bit 5 word 0) -> bool (uint32)
        if bm0_actual & (1 << 5) != 0 {
            attr_vals.extend_from_slice(&1u32.to_be_bytes()); // TRUE
        }

        // symlink_support (bit 6 word 0) -> bool (uint32)
        if bm0_actual & (1 << 6) != 0 {
            attr_vals.extend_from_slice(&1u32.to_be_bytes()); // TRUE
        }

        // named_attr (bit 7 word 0) -> bool (uint32)
        if bm0_actual & (1 << 7) != 0 {
            attr_vals.extend_from_slice(&0u32.to_be_bytes()); // FALSE
        }

        // fsid (bit 8 word 0) -> fsid4: major(8) + minor(8)
        if bm0_actual & (1 << 8) != 0 {
            attr_vals.extend_from_slice(&1u64.to_be_bytes()); // major=1
            attr_vals.extend_from_slice(&0u64.to_be_bytes()); // minor=0
        }

        // unique_handles (bit 9 word 0) -> bool (uint32)
        if bm0_actual & (1 << 9) != 0 {
            attr_vals.extend_from_slice(&1u32.to_be_bytes()); // TRUE
        }

        // lease_time (bit 10 word 0) -> uint32 (seconds)
        if bm0_actual & (1 << 10) != 0 {
            attr_vals.extend_from_slice(&90u32.to_be_bytes()); // 90s lease
        }

        // space_free (bit 13 word 0) -> uint64
        // NFSv4.1: FATTR4_SPACE_FREE = 13
        if bm0_actual & (1 << 13) != 0 {
            attr_vals.extend_from_slice(&(500u64 * 1024 * 1024 * 1024).to_be_bytes()); // 500 GB
        }

        // space_total (bit 14 word 0) -> uint64
        // NFSv4.1: FATTR4_SPACE_TOTAL = 14
        if bm0_actual & (1 << 14) != 0 {
            attr_vals.extend_from_slice(&(1024u64 * 1024 * 1024 * 1024).to_be_bytes()); // 1 TB
        }

        // space_avail (bit 15 word 0) -> uint64
        // NFSv4.1: FATTR4_SPACE_AVAIL = 15
        if bm0_actual & (1 << 15) != 0 {
            attr_vals.extend_from_slice(&(1024u64 * 1024 * 1024 * 1024).to_be_bytes()); // 1 TB
        }

        // fileid (bit 20 word 0)
        // MUST be deterministic and stable across calls for the same file handle.
        // The Linux NFS client caches fileid and returns EIO if it changes between
        // GETATTR calls on the same handle.
        //
        // CRITICAL: The NFSv4 pseudo root is a synthetic directory, NOT the same
        // inode as any export. Using the same fileid for root and its child entry
        // (e.g. "exports") causes the kernel client to detect a duplicate inode
        // and silently discard the READDIR entry. Root must have a unique fileid.
        if bm0_actual & (1 << 20) != 0 {
            let fileid: u64 = if is_root {
                // Root pseudo directory: use well-known NFS4_ROOT_FILEID (2).
                // This must be DIFFERENT from any export's fileid, otherwise
                // the client sees root_inode == exports_inode and discards
                // READDIR entries as duplicates.
                debug!("NFS4 build_fattr4 fileid: root → 2 (NFS4_ROOT_FILEID, is_root=true)");
                2
            } else {
                let path_bytes = path.as_ref()
                    .map(|p| p.to_string_lossy().into_owned().into_bytes())
                    .unwrap_or_default();
                if path_bytes.is_empty() {
                    2 // fallback: well-known NFS4_ROOT_FILEID
                } else {
                    let mut hash: u64 = 0xcbf29ce484222325;
                    for &b in &path_bytes {
                        hash ^= b as u64;
                        hash = hash.wrapping_mul(0x100000001b3);
                    }
                    let path_hex: String = path_bytes.iter()
                        .map(|b| format!("{:02x}", b))
                        .collect::<Vec<_>>()
                        .join("");
                    debug!("NFS4 build_fattr4 fileid: path_str='{}', path_hex={}, fileid={:016x}, is_root={}",
                        String::from_utf8_lossy(&path_bytes), path_hex, hash, is_root);
                    hash
                }
            };
            attr_vals.extend_from_slice(&fileid.to_be_bytes());
        }

        // mode (bit 1 of word 1, abs bit 33)
        if bm1_actual & (1 << (33-32)) != 0 {
            let mode: u32 = if meta.as_ref().map(|m| m.is_dir()).unwrap_or(false) { 0o755 } else { 0o644 };
            attr_vals.extend_from_slice(&mode.to_be_bytes());
        }

        // numlinks (bit 3 of word 1, abs bit 35)
        if bm1_actual & (1 << (35-32)) != 0 {
            attr_vals.extend_from_slice(&1u32.to_be_bytes());
        }

        // owner (bit 4 of word 1, abs bit 36) -> utf8str_mixed
        if bm1_actual & (1 << (36-32)) != 0 {
            let owner = b"root";
            let olen = owner.len() as u32;
            attr_vals.extend_from_slice(&olen.to_be_bytes());
            attr_vals.extend_from_slice(owner);
            let owner_padded = (owner.len() + 3) & !3;
            let pad = owner_padded - owner.len();
            attr_vals.resize(attr_vals.len() + pad, 0);
        }

        // owner_group (bit 5 of word 1, abs bit 37)
        if bm1_actual & (1 << (37-32)) != 0 {
            let group = b"root";
            let glen = group.len() as u32;
            attr_vals.extend_from_slice(&glen.to_be_bytes());
            attr_vals.extend_from_slice(group);
            let group_padded = (group.len() + 3) & !3;
            let pad = group_padded - group.len();
            attr_vals.resize(attr_vals.len() + pad, 0);
        }

        // rawdev (bit 9 of word 1, abs bit 41) -> specdev4: major(4) + minor(4)
        // RECOMMENDED attribute. Return 0,0 for non-device files.
        if bm1_actual & (1 << (41-32)) != 0 {
            let is_dev = meta.as_ref().map(|m| {
                #[cfg(windows)]
                { false } // Windows doesn't have block/char devices
                #[cfg(not(windows))]
                { use std::os::unix::fs::FileTypeExt;
                  let ft = m.file_type();
                  ft.is_block_device() || ft.is_char_device() }
            }).unwrap_or(false);
            // For regular files/dirs, return specdata1=0, specdata2=0 (NFS4 spec says these should be 0 for non-device files)
            attr_vals.extend_from_slice(&0u32.to_be_bytes()); // specdata1 (major)
            attr_vals.extend_from_slice(&0u32.to_be_bytes()); // specdata2 (minor)
        }

        // space_used (bit 13 of word 1, abs bit 45) -> uint64
        // RECOMMENDED. Number of bytes used by this file (rounded up to filesystem block size)
        if bm1_actual & (1 << (45-32)) != 0 {
            let size = meta.as_ref().map(|m| m.len()).unwrap_or(0);
            // Round up to 512-byte blocks (common allocation unit)
            let used = if size == 0 { 0u64 } else { ((size + 511) / 512) * 512 };
            attr_vals.extend_from_slice(&used.to_be_bytes());
        }

        // space_freed (bit 14 of word 1, abs bit 46) -> uint64 (NFSv4.2, RFC 7862)
        // RECOMMENDED for NFSv4.2. Number of bytes freed if this file were removed.
        // We don't truly compute this; return 0.
        if bm1_actual & (1 << (46-32)) != 0 {
            attr_vals.extend_from_slice(&0u64.to_be_bytes());
        }

        // time_access (bit 15 of word 1, abs bit 47) -> nfstime4: seconds(8) + nseconds(4)
        // RECOMMENDED. Use last access time if available, fall back to modified time.
        if bm1_actual & (1 << (47-32)) != 0 {
            let (secs, nsecs) = meta.as_ref()
                .and_then(|m| m.accessed().ok())
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|d| (d.as_secs(), d.subsec_nanos()))
                .unwrap_or_else(|| {
                    // Fallback to mtime
                    meta.as_ref()
                        .and_then(|m| m.modified().ok())
                        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                        .map(|d| (d.as_secs(), d.subsec_nanos()))
                        .unwrap_or((0, 0))
                });
            attr_vals.extend_from_slice(&secs.to_be_bytes());   // seconds (8 bytes)
            attr_vals.extend_from_slice(&nsecs.to_be_bytes());  // nseconds (4 bytes)
        }

        // time_metadata (bit 52-32=20 of word 1)
        // On Windows, use created() as ctime proxy (no native ctime)
        if bm1_actual & (1 << (52-32)) != 0 {
            let secs = meta.as_ref()
                .and_then(|m| m.created().ok())
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|d| d.as_secs())
                .unwrap_or(0);
            attr_vals.extend_from_slice(&secs.to_be_bytes()); // seconds
            attr_vals.extend_from_slice(&0u32.to_be_bytes());  // nseconds
        }

        // time_modify (bit 53-32=21 of word 1)
        if bm1_actual & (1 << (53-32)) != 0 {
            let secs = meta.as_ref()
                .and_then(|m| m.modified().ok())
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|d| d.as_secs())
                .unwrap_or(0);
            attr_vals.extend_from_slice(&secs.to_be_bytes()); // seconds
            attr_vals.extend_from_slice(&0u32.to_be_bytes());  // nseconds
        }

        // mounted_on_fileid (bit 55-32=23 of word 1)
        // RECOMMENDED by RFC 5661. The Linux NFS client uses this to detect
        // mount point boundaries. For non-root objects it equals the fileid;
        // for the root pseudo-dir it is a stable well-known value (2).
        if bm1_actual & (1 << (55-32)) != 0 {
            let mof: u64 = if is_root {
                2 // same as root's fileid
            } else {
                // Use same FNV hash as fileid to guarantee equality
                let path_bytes = path.as_ref()
                    .map(|p| p.to_string_lossy().into_owned().into_bytes())
                    .unwrap_or_default();
                if path_bytes.is_empty() {
                    2
                } else {
                    let mut hash: u64 = 0xcbf29ce484222325;
                    for &b in &path_bytes {
                        hash ^= b as u64;
                        hash = hash.wrapping_mul(0x100000001b3);
                    }
                    hash
                }
            };
            attr_vals.extend_from_slice(&mof.to_be_bytes());
        }

        // Log attr_vals hex for debug
        let av_hex: String = attr_vals.chunks(4)
            .enumerate()
            .map(|(i, c)| format!("[{}]={:08x}", i*4, u32::from_be_bytes([c[0], c[1], c[2], c[3]])))
            .collect::<Vec<_>>().join(" ");
        debug!("NFS4 build_fattr4: attr_vals ({} bytes): {}", attr_vals.len(), av_hex);

        // Now encode: bitmap + attr_vals as opaque<>
        let mut result = Vec::new();
        // bitmap: always 2 words
        result.extend_from_slice(&2u32.to_be_bytes());
        result.extend_from_slice(&bm0_actual.to_be_bytes());
        result.extend_from_slice(&bm1_actual.to_be_bytes());
        // attr_vals as opaque<>
        let av_len = attr_vals.len() as u32;
        result.extend_from_slice(&av_len.to_be_bytes());
        result.extend_from_slice(&attr_vals);
        let av_padded = (attr_vals.len() + 3) & !3;
        let pad = av_padded - attr_vals.len();
        result.resize(result.len() + pad, 0);

        result
    }

    fn make_compound_error(&self, status: u32) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&status.to_be_bytes());
        body.extend_from_slice(&0u32.to_be_bytes()); // tag_len=0
        body.extend_from_slice(&0u32.to_be_bytes()); // rescount=0
        body
    }

    // ──────────────────────────────────────────────────────────────────────────
    // NFS v4.2 Operations (RFC 7862)
    // ──────────────────────────────────────────────────────────────────────────

    /// READ_PLUS — NFSv4.2 enhanced read with sparse hole support (RFC 7862 §18.6)
    async fn op_read_plus(&self, request: &[u8], p: usize, current_fh: &Option<Vec<u8>>)
        -> (Vec<u8>, usize, Option<Vec<u8>>, Option<Vec<u8>>, u32)
    {
        info!("NFS4 READ_PLUS");
        let fh = match current_fh {
            None => return (vec![], 28, None, None, NFS4ERR_NOFILEHANDLE),
            Some(fh) => fh,
        };

        // stateid(16) + offset(8) + count(4) = 28 bytes
        let consumed = 28;
        if p + consumed > request.len() {
            return (vec![], consumed, None, None, NFS4ERR_BADXDR);
        }

        let offset = u64::from_be_bytes([
            request[p+16], request[p+17], request[p+18], request[p+19],
            request[p+20], request[p+21], request[p+22], request[p+23],
        ]);
        let count = u32::from_be_bytes([
            request[p+24], request[p+25], request[p+26], request[p+27],
        ]) as usize;

        info!("NFS4 READ_PLUS: offset={}, count={}", offset, count);

        let path = match self.exports.resolve_fh(fh).await {
            None => return (vec![], consumed, None, None, NFS4ERR_STALE),
            Some(p) => p,
        };

        // Get file size from metadata first (avoids reading entire file)
        let file_size = match std::fs::metadata(to_extended_path(&path)) {
            Err(e) => {
                warn!("NFS4 READ_PLUS: metadata error {}: {}", path.display(), e);
                return (vec![], consumed, None, None, NFS4ERR_IO);
            }
            Ok(m) => m.len(),
        };

        let mut result = Vec::new();

        // rpr_stateid — dummy all-zeros stateid (16 bytes)
        let stateid = [0u8; 16];
        result.extend_from_slice(&stateid);

        if offset >= file_size {
            // Beyond EOF → return HOLE
            let readable: u32 = 0;
            let eof: u32 = 1;
            result.extend_from_slice(&readable.to_be_bytes());
            result.extend_from_slice(&eof.to_be_bytes());
            // content4_type = HOLE4_TYPE(1)
            result.extend_from_slice(&1u32.to_be_bytes());
            // hole4: h_offset(8) + h_length(4)
            result.extend_from_slice(&offset.to_be_bytes());
            result.extend_from_slice(&0u32.to_be_bytes()); // h_length = 0
        } else {
            // Read only the needed range (seek + read), not the entire file
            let readable_len = (count as u64).min(file_size - offset) as usize;
            let read_data = match std::fs::OpenOptions::new()
                .read(true)
                .open(to_extended_path(&path))
            {
                Ok(f) => {
                    use std::io::{Read, Seek, SeekFrom};
                    let mut f = f;
                    if let Err(e) = f.seek(SeekFrom::Start(offset)) {
                        warn!("NFS4 READ_PLUS: seek error {}: {}", path.display(), e);
                        return (vec![], consumed, None, None, NFS4ERR_IO);
                    }
                    let mut buf = vec![0u8; readable_len];
                    match f.read(&mut buf) {
                        Ok(n) => {
                            buf.truncate(n);
                            buf
                        }
                        Err(e) => {
                            warn!("NFS4 READ_PLUS: read error {}: {}", path.display(), e);
                            return (vec![], consumed, None, None, NFS4ERR_IO);
                        }
                    }
                }
                Err(e) => {
                    warn!("NFS4 READ_PLUS: open error {}: {}", path.display(), e);
                    return (vec![], consumed, None, None, NFS4ERR_IO);
                }
            };

            let readable = read_data.len() as u32;
            let eof: u32 = if (offset + read_data.len() as u64) >= file_size { 1 } else { 0 };

            result.extend_from_slice(&readable.to_be_bytes());
            result.extend_from_slice(&eof.to_be_bytes());
            // content4_type = DATA4_TYPE(0)
            result.extend_from_slice(&0u32.to_be_bytes());
            // data4: d_offset(8) + d_length(4) + d_data opaque<>
            result.extend_from_slice(&offset.to_be_bytes());
            result.extend_from_slice(&readable.to_be_bytes());
            result.extend_from_slice(&readable.to_be_bytes()); // d_data length
            result.extend_from_slice(&read_data);
            // XDR pad
            let padded = (read_data.len() + 3) & !3;
            let pad = padded - read_data.len();
            result.resize(result.len() + pad, 0);
        }

        (result, consumed, None, None, NFS4_OK)
    }

    /// COPY — NFSv4.2 intra-server file copy (RFC 7862 §18.4)
    async fn op_copy(&self, request: &[u8], p: usize, current_fh: &Option<Vec<u8>>, saved_fh: &Option<Vec<u8>>)
        -> (Vec<u8>, usize, Option<Vec<u8>>, Option<Vec<u8>>, u32)
    {
        info!("NFS4 COPY");
        let sink_fh = match current_fh {
            None => return (vec![], 0, None, None, NFS4ERR_NOFILEHANDLE),
            Some(fh) => fh,
        };
        // COPY uses saved_fh as the source file handle (RFC 7862 §18.4.3)
        let source_fh = match saved_fh {
            None => {
                warn!("NFS4 COPY: no saved_fh (source file handle) available");
                return (vec![], 0, None, None, NFS4ERR_NOFILEHANDLE);
            }
            Some(fh) => fh,
        };

        let mut pp = p;

        // ca_source_stateid (16 bytes)
        // ca_source_fh — the source is passed as current filehandle; we use saved_fh
        // Actually, COPY expects source_fh in saved_fh and sink_fh in current_fh.
        // For now, parse the args: stateid(16) + offset(8) + count(4)
        if pp + 28 > request.len() { return (vec![], 0, None, None, NFS4ERR_BADXDR); }
        pp += 16; // skip source stateid
        let source_offset = u64::from_be_bytes([
            request[pp], request[pp+1], request[pp+2], request[pp+3],
            request[pp+4], request[pp+5], request[pp+6], request[pp+7],
        ]);
        pp += 8;
        let count = u32::from_be_bytes([
            request[pp], request[pp+1], request[pp+2], request[pp+3],
        ]) as usize;
        pp += 4;

        // ca_sink_stateid (16 bytes)
        if pp + 16 > request.len() { return (vec![], 0, None, None, NFS4ERR_BADXDR); }
        pp += 16;

        // ca_sink_offset (8 bytes)
        if pp + 8 > request.len() { return (vec![], 0, None, None, NFS4ERR_BADXDR); }
        let sink_offset = u64::from_be_bytes([
            request[pp], request[pp+1], request[pp+2], request[pp+3],
            request[pp+4], request[pp+5], request[pp+6], request[pp+7],
        ]);
        pp += 8;

        // ca_source_server (netloc4) — parse netloc type
        if pp + 4 > request.len() { return (vec![], 0, None, None, NFS4ERR_BADXDR); }
        let netloc_type = u32::from_be_bytes([
            request[pp], request[pp+1], request[pp+2], request[pp+3],
        ]);
        pp += 4;

        // NL4_NAME=1, NL4_URL=2, NL4_NETADDR=3
        // For inter-server: return NOTSUPP
        // For intra-server (NL4_NETADDR local): continue
        // For empty netloc (NL4_NETADDR with localhost): accepted
        let consumed = pp - p;
        match netloc_type {
            3 => {
                // NL4_NETADDR — parse addr string, but for intra-server we don't need to validate
                if pp + 4 > request.len() { return (vec![], 0, None, None, NFS4ERR_BADXDR); }
                let addr_len = u32::from_be_bytes([
                    request[pp], request[pp+1], request[pp+2], request[pp+3],
                ]) as usize;
                pp += 4;
                let padded = (addr_len + 3) & !3;
                if pp + padded > request.len() { return (vec![], 0, None, None, NFS4ERR_BADXDR); }
                pp += padded;
            }
            0 => {
                // NL4_NULL/empty — acceptable
            }
            _ => {
                debug!("NFS4 COPY: inter-server not supported, netloc_type={}", netloc_type);
                return (vec![], consumed, None, None, NFS4ERR_NOTSUPP);
            }
        }

        // ca_consecutive (4 bytes bool)
        if pp + 4 > request.len() { return (vec![], 0, None, None, NFS4ERR_BADXDR); }
        let _consecutive = u32::from_be_bytes([
            request[pp], request[pp+1], request[pp+2], request[pp+3],
        ]);
        pp += 4;

        // ca_synchronous (4 bytes bool)
        if pp + 4 > request.len() { return (vec![], 0, None, None, NFS4ERR_BADXDR); }
        let synchronous = u32::from_be_bytes([
            request[pp], request[pp+1], request[pp+2], request[pp+3],
        ]);
        pp += 4;

        let consumed = pp - p;

        // COPY requires source_fh in saved_fh — get it from saved_fh (available in compound)
        // But our handler signature doesn't have saved_fh. For now, we need to add saved_fh
        // to the dispatch. Since the COPY handler is called from dispatch_op which DOES have
        // saved_fh, we'll update the dispatch call to pass saved_fh.
        // For now, return NFS4ERR_NOTSUPP for COPY — it requires saved_fh access.
        // Actually, let's modify the approach: pass saved_fh to copy handler too.
        // We'll handle this by calling COPY from the dispatch with saved_fh.
        
        info!("NFS4 COPY: source_offset={}, sink_offset={}, count={}", source_offset, sink_offset, count);

        // Resolve sink path
        let sink_path = match self.exports.resolve_fh(sink_fh).await {
            None => return (vec![], consumed, None, None, NFS4ERR_BADHANDLE),
            Some(p) => p,
        };

        // Resolve source path
        let source_path = match self.exports.resolve_fh(source_fh).await {
            None => return (vec![], consumed, None, None, NFS4ERR_BADHANDLE),
            Some(p) => p,
        };

        // Read source data from source_offset
        let source_data = match std::fs::read(to_extended_path(&source_path)) {
            Err(e) => {
                warn!("NFS4 COPY: failed to read source {}: {}", source_path.display(), e);
                return (vec![], consumed, None, None, NFS4ERR_IO);
            }
            Ok(d) => d,
        };

        let source_len = source_data.len() as u64;
        if source_offset > source_len {
            return (vec![], consumed, None, None, NFS4ERR_INVAL);
        }

        let actual_count = count.min((source_len - source_offset) as usize);
        let copy_data = &source_data[source_offset as usize..(source_offset as usize + actual_count)];

        // Write to sink at sink_offset using OpenOptions + seek + write
        let written = match std::fs::OpenOptions::new()
            .write(true)
            .open(to_extended_path(&sink_path))
        {
            Ok(f) => {
                use std::io::{Seek, SeekFrom, Write};
                let mut f = f;
                if let Err(e) = f.seek(SeekFrom::Start(sink_offset)) {
                    warn!("NFS4 COPY: seek error on sink {}: {}", sink_path.display(), e);
                    return (vec![], consumed, None, None, NFS4ERR_IO);
                }
                match f.write_all(copy_data) {
                    Ok(_) => actual_count as u32,
                    Err(e) => {
                        warn!("NFS4 COPY: write error on sink {}: {}", sink_path.display(), e);
                        return (vec![], consumed, None, None, NFS4ERR_IO);
                    }
                }
            }
            Err(e) => {
                warn!("NFS4 COPY: failed to open sink {}: {}", sink_path.display(), e);
                return (vec![], consumed, None, None, NFS4ERR_IO);
            }
        };

        // Build response — for synchronous copy
        let mut result = Vec::new();
        // cr_length(4) + cr_synchronous(4 bytes bool)
        result.extend_from_slice(&written.to_be_bytes());
        result.extend_from_slice(&1u32.to_be_bytes()); // always synchronous

        info!("NFS4 COPY: copied {} bytes from offset {} to offset {}", written, source_offset, sink_offset);
        (result, consumed, None, None, NFS4_OK)
    }

    /// SEEK — NFSv4.2 find next data or hole (RFC 7862 §18.19)
    async fn op_seek(&self, request: &[u8], p: usize, current_fh: &Option<Vec<u8>>)
        -> (Vec<u8>, usize, Option<Vec<u8>>, Option<Vec<u8>>, u32)
    {
        info!("NFS4 SEEK");
        let fh = match current_fh {
            None => return (vec![], 0, None, None, NFS4ERR_NOFILEHANDLE),
            Some(fh) => fh,
        };

        // sa_stateid(16) + sa_offset(8) + sa_seek_type(4) = 28 bytes
        let consumed = 28;
        if p + consumed > request.len() {
            return (vec![], consumed, None, None, NFS4ERR_BADXDR);
        }

        let seek_offset = u64::from_be_bytes([
            request[p+16], request[p+17], request[p+18], request[p+19],
            request[p+20], request[p+21], request[p+22], request[p+23],
        ]);
        let seek_type = u32::from_be_bytes([
            request[p+24], request[p+25], request[p+26], request[p+27],
        ]);

        info!("NFS4 SEEK: offset={}, type={}", seek_offset, seek_type);

        let path = match self.exports.resolve_fh(fh).await {
            None => return (vec![], consumed, None, None, NFS4ERR_STALE),
            Some(p) => p,
        };

        let file_size = match std::fs::metadata(to_extended_path(&path)) {
            Err(e) => {
                warn!("NFS4 SEEK: metadata error {}: {}", path.display(), e);
                return (vec![], consumed, None, None, NFS4ERR_IO);
            }
            Ok(m) => m.len(),
        };

        // SEEK4_DATA = 0, SEEK4_HOLE = 1
        match seek_type {
            0 => {
                // SEEK4_DATA: find next data after seek_offset
                let mut result = Vec::new();
                if seek_offset < file_size {
                    // Data exists at seek_offset
                    result.extend_from_slice(&seek_offset.to_be_bytes()); // sr_offset
                    result.extend_from_slice(&(file_size - seek_offset).to_be_bytes()); // sr_length (till EOF)
                    result.extend_from_slice(&0u32.to_be_bytes()); // sr_eof = false
                } else {
                    // Past EOF — no data
                    result.extend_from_slice(&seek_offset.to_be_bytes()); // sr_offset
                    result.extend_from_slice(&0u32.to_be_bytes()); // sr_length
                    result.extend_from_slice(&1u32.to_be_bytes()); // sr_eof = true
                }
                (result, consumed, None, None, NFS4_OK)
            }
            1 => {
                // SEEK4_HOLE: find next hole after seek_offset
                let mut result = Vec::new();
                if seek_offset < file_size {
                    // On Windows without sparse detection, hole starts at file_size
                    result.extend_from_slice(&file_size.to_be_bytes()); // sr_offset = EOF
                    result.extend_from_slice(&0u32.to_be_bytes()); // sr_length
                    result.extend_from_slice(&1u32.to_be_bytes()); // sr_eof = true
                } else {
                    // Past EOF
                    result.extend_from_slice(&seek_offset.to_be_bytes());
                    result.extend_from_slice(&0u32.to_be_bytes());
                    result.extend_from_slice(&1u32.to_be_bytes());
                }
                (result, consumed, None, None, NFS4_OK)
            }
            _ => {
                debug!("NFS4 SEEK: unknown seek_type={}", seek_type);
                (vec![], consumed, None, None, NFS4ERR_INVAL)
            }
        }
    }

    /// CLONE — NFSv4.2 server-side clone (RFC 7862 §18.15.4)
    /// Simplified implementation: read source range + write to sink (no BlockClone API)
    async fn op_clone(&self, request: &[u8], p: usize, current_fh: &Option<Vec<u8>>, saved_fh: &Option<Vec<u8>>)
        -> (Vec<u8>, usize, Option<Vec<u8>>, Option<Vec<u8>>, u32)
    {
        info!("NFS4 CLONE");
        let sink_fh = match current_fh {
            None => return (vec![], 0, None, None, NFS4ERR_NOFILEHANDLE),
            Some(fh) => fh,
        };
        // CLONE uses saved_fh as the source file handle (RFC 7862 §18.15.4)
        let source_fh = match saved_fh {
            None => {
                warn!("NFS4 CLONE: no saved_fh (source file handle) available");
                return (vec![], 0, None, None, NFS4ERR_NOFILEHANDLE);
            }
            Some(fh) => fh,
        };

        let mut pp = p;

        // cl_source_stateid (16 bytes)
        if pp + 16 > request.len() { return (vec![], 0, None, None, NFS4ERR_BADXDR); }
        pp += 16;

        // cl_source_offset (8 bytes)
        if pp + 8 > request.len() { return (vec![], 0, None, None, NFS4ERR_BADXDR); }
        let source_offset = u64::from_be_bytes([
            request[pp], request[pp+1], request[pp+2], request[pp+3],
            request[pp+4], request[pp+5], request[pp+6], request[pp+7],
        ]);
        pp += 8;

        // cl_count (4 bytes)
        if pp + 4 > request.len() { return (vec![], 0, None, None, NFS4ERR_BADXDR); }
        let count = u32::from_be_bytes([
            request[pp], request[pp+1], request[pp+2], request[pp+3],
        ]) as usize;
        pp += 4;

        // cl_sink_stateid (16 bytes)
        if pp + 16 > request.len() { return (vec![], 0, None, None, NFS4ERR_BADXDR); }
        pp += 16;

        // cl_sink_offset (8 bytes)
        if pp + 8 > request.len() { return (vec![], 0, None, None, NFS4ERR_BADXDR); }
        let sink_offset = u64::from_be_bytes([
            request[pp], request[pp+1], request[pp+2], request[pp+3],
            request[pp+4], request[pp+5], request[pp+6], request[pp+7],
        ]);
        pp += 8;

        let consumed = pp - p;

        info!("NFS4 CLONE: source_offset={}, sink_offset={}, count={}", source_offset, sink_offset, count);

        // Resolve source and sink paths
        let source_path = match self.exports.resolve_fh(source_fh).await {
            None => return (vec![], consumed, None, None, NFS4ERR_BADHANDLE),
            Some(p) => p,
        };
        let sink_path = match self.exports.resolve_fh(sink_fh).await {
            None => return (vec![], consumed, None, None, NFS4ERR_BADHANDLE),
            Some(p) => p,
        };

        // Read source data from source_offset
        let source_data = match std::fs::read(to_extended_path(&source_path)) {
            Err(e) => {
                warn!("NFS4 CLONE: failed to read source {}: {}", source_path.display(), e);
                return (vec![], consumed, None, None, NFS4ERR_IO);
            }
            Ok(d) => d,
        };

        let source_len = source_data.len() as u64;
        if source_offset > source_len {
            return (vec![], consumed, None, None, NFS4ERR_INVAL);
        }

        let actual_count = count.min((source_len - source_offset) as usize);
        let clone_data = &source_data[source_offset as usize..(source_offset as usize + actual_count)];

        // Write to sink at sink_offset
        match std::fs::OpenOptions::new()
            .write(true)
            .open(to_extended_path(&sink_path))
        {
            Ok(f) => {
                use std::io::{Seek, SeekFrom, Write};
                let mut f = f;
                if let Err(e) = f.seek(SeekFrom::Start(sink_offset)) {
                    warn!("NFS4 CLONE: seek error on sink {}: {}", sink_path.display(), e);
                    return (vec![], consumed, None, None, NFS4ERR_IO);
                }
                if let Err(e) = f.write_all(clone_data) {
                    warn!("NFS4 CLONE: write error on sink {}: {}", sink_path.display(), e);
                    return (vec![], consumed, None, None, NFS4ERR_IO);
                }
            }
            Err(e) => {
                warn!("NFS4 CLONE: failed to open sink {}: {}", sink_path.display(), e);
                return (vec![], consumed, None, None, NFS4ERR_IO);
            }
        }

        info!("NFS4 CLONE: cloned {} bytes from offset {} to offset {}", actual_count, source_offset, sink_offset);
        (vec![], consumed, None, None, NFS4_OK)
    }

    /// SEC-018: Check if an opcode is a write operation that should be
    /// blocked by root_squash when the caller is root (uid=0).
    fn is_write_opcode(opcode: u32) -> bool {
        matches!(opcode,
            OP_WRITE | OP_CREATE | OP_REMOVE | OP_RENAME |
            OP_SETATTR | OP_LINK | OP_OPEN | OP_LOCK |
            OP_LOCKU | OP_CLOSE | OP_DELEGRETURN | OP_COMMIT |
            // NFSv4.2 write operations
            OP_COPY | OP_CLONE | OP_ALLOCATE | OP_DEALLOCATE | OP_WRITE_SAME
        )
    }
}

// ─── RPC reply builder ────────────────────────────────────────────────────────
fn make_rpc_accepted_reply(xid: u32, accept_stat: u32, body: &[u8]) -> Vec<u8> {
    let mut r = Vec::with_capacity(24 + body.len());
    r.extend_from_slice(&xid.to_be_bytes());
    r.extend_from_slice(&RPC_REPLY.to_be_bytes());
    r.extend_from_slice(&RPC_MSG_ACCEPTED.to_be_bytes());
    // verf: AUTH_NONE
    r.extend_from_slice(&0u32.to_be_bytes());
    r.extend_from_slice(&0u32.to_be_bytes());
    r.extend_from_slice(&accept_stat.to_be_bytes());
    r.extend_from_slice(body);
    r
}
