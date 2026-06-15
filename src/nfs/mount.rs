use anyhow::Result;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};
use tracing::{error, info, warn};

use crate::exports::ExportsManager;

// RPC constants
const RPC_CALL: u32 = 0;
const RPC_REPLY: u32 = 1;
const RPC_MSG_ACCEPTED: u32 = 0;
const SUCCESS: u32 = 0;
const PROC_UNAVAIL: u32 = 3;
const GARBAGE_ARGS: u32 = 4;

// MOUNT Procedures
const MOUNTPROC_NULL: u32 = 0;
const MOUNTPROC_MNT: u32 = 1;
const MOUNTPROC_DUMP: u32 = 2;
const MOUNTPROC_UMNT: u32 = 3;
const MOUNTPROC_UMNTALL: u32 = 4;
const MOUNTPROC_EXPORT: u32 = 5;

/// MOUNT protocol server (RFC 1813)
pub struct MountServer {
    exports: Arc<ExportsManager>,
}

impl MountServer {
    pub fn new(exports: Arc<ExportsManager>) -> Self {
        Self { exports }
    }

    pub async fn start(&self) -> Result<()> {
        info!("Starting MOUNT server on port 20048 (TCP+UDP)");

        let exports_udp = Arc::clone(&self.exports);
        let exports_tcp = Arc::clone(&self.exports);

        tokio::spawn(async move {
            if let Err(e) = Self::run_udp(exports_udp).await {
                error!("MOUNT UDP error: {}", e);
            }
        });

        Self::run_tcp(exports_tcp).await
    }

    async fn run_udp(exports: Arc<ExportsManager>) -> Result<()> {
        let socket = UdpSocket::bind("0.0.0.0:20048").await?;
        info!("MOUNT UDP listening on 0.0.0.0:20048");
        let mut buf = [0u8; 8192];
        loop {
            match socket.recv_from(&mut buf).await {
                Ok((len, addr)) => {
                    info!("MOUNT UDP from {} ({} bytes)", addr, len);
                    let data = buf[..len].to_vec();
                    let exports2 = Arc::clone(&exports);
                    if let Some(resp) = Self::handle_request(data, addr.ip(), exports2).await {
                        if let Err(e) = socket.send_to(&resp, addr).await {
                            error!("MOUNT UDP send error: {}", e);
                        }
                    }
                }
                Err(e) => error!("MOUNT UDP recv error: {}", e),
            }
        }
    }

    async fn run_tcp(exports: Arc<ExportsManager>) -> Result<()> {
        let listener = TcpListener::bind("0.0.0.0:20048").await?;
        info!("MOUNT TCP listening on 0.0.0.0:20048");
        loop {
            match listener.accept().await {
                Ok((mut stream, addr)) => {
                    info!("MOUNT TCP connection from {}", addr);
                    let exports2 = Arc::clone(&exports);
                    tokio::spawn(async move {
                        let mut buf = vec![0u8; 8192];
                        loop {
                            // Read record marking (4 bytes)
                            let mut hdr = [0u8; 4];
                            if stream.read_exact(&mut hdr).await.is_err() {
                                break;
                            }
                            let rm = u32::from_be_bytes(hdr);
                            let len = (rm & 0x7FFFFFFF) as usize;
                            if len == 0 || len > 65536 {
                                break;
                            }
                            if buf.len() < len {
                                buf.resize(len, 0);
                            }
                            if stream.read_exact(&mut buf[..len]).await.is_err() {
                                break;
                            }
                            let data = buf[..len].to_vec();
                            let exports3 = Arc::clone(&exports2);
                            if let Some(resp) = Self::handle_request(data, addr.ip(), exports3).await {
                                let rm_hdr = 0x80000000u32 | (resp.len() as u32);
                                let mut full = Vec::with_capacity(4 + resp.len());
                                full.extend_from_slice(&rm_hdr.to_be_bytes());
                                full.extend_from_slice(&resp);
                                if stream.write_all(&full).await.is_err() {
                                    break;
                                }
                            }
                        }
                    });
                }
                Err(e) => error!("MOUNT TCP accept error: {}", e),
            }
        }
    }

    async fn handle_request(
        request: Vec<u8>,
        client_ip: std::net::IpAddr,
        exports: Arc<ExportsManager>,
    ) -> Option<Vec<u8>> {
        if request.len() < 24 {
            warn!("MOUNT request too short: {}", request.len());
            return None;
        }

        let xid = u32::from_be_bytes([request[0], request[1], request[2], request[3]]);
        let msg_type = u32::from_be_bytes([request[4], request[5], request[6], request[7]]);

        if msg_type != RPC_CALL {
            return None;
        }

        let procedure = u32::from_be_bytes([request[20], request[21], request[22], request[23]]);
        info!("MOUNT: xid={}, proc={}, client={}", xid, procedure, client_ip);

        // Parse cred + verifier to get args offset
        let mut offset = 24;
        if request.len() < offset + 8 { return Some(make_accept_reply(xid, GARBAGE_ARGS, &[])); }
        let cred_len = u32::from_be_bytes([request[offset+4], request[offset+5], request[offset+6], request[offset+7]]) as usize;
        offset += 8 + ((cred_len + 3) & !3);
        if request.len() < offset + 8 { return Some(make_accept_reply(xid, GARBAGE_ARGS, &[])); }
        let verif_len = u32::from_be_bytes([request[offset+4], request[offset+5], request[offset+6], request[offset+7]]) as usize;
        offset += 8 + ((verif_len + 3) & !3);

        match procedure {
            MOUNTPROC_NULL => {
                info!("MOUNT NULL");
                Some(make_accept_reply(xid, SUCCESS, &[]))
            }
            MOUNTPROC_MNT => {
                // Parse path: len(4) + bytes (padded to 4)
                if request.len() < offset + 4 {
                    return Some(make_accept_reply(xid, GARBAGE_ARGS, &[]));
                }
                let path_len = u32::from_be_bytes([
                    request[offset], request[offset+1], request[offset+2], request[offset+3],
                ]) as usize;
                offset += 4;

                if request.len() < offset + path_len {
                    warn!("MOUNT MNT: path too short");
                    return Some(make_accept_reply(xid, GARBAGE_ARGS, &[]));
                }

                let path_bytes = &request[offset..offset + path_len];
                let path = String::from_utf8_lossy(path_bytes).to_string();
                info!("MOUNT MNT: path='{}' from {}", path, client_ip);

                // Check client permission
                if !exports.is_client_allowed(client_ip, &path).await {
                    warn!("MOUNT MNT: client {} denied for '{}'", client_ip, path);
                    // MNT3ERR_ACCES = 13
                    let mut body = Vec::new();
                    body.extend_from_slice(&13u32.to_be_bytes());
                    return Some(make_accept_reply(xid, SUCCESS, &body));
                }

                // Verify export exists
                if exports.get_export(&path).await.is_none() {
                    warn!("MOUNT MNT: export not found '{}'", path);
                    // MNT3ERR_NOENT = 2
                    let mut body = Vec::new();
                    body.extend_from_slice(&2u32.to_be_bytes());
                    return Some(make_accept_reply(xid, SUCCESS, &body));
                }

                // Generate root file handle for the export
                let fh = exports.create_file_handle(&path).await;
                info!("MOUNT MNT: success, fh len={}", fh.len());

                // MNT3_OK reply:
                // status(4) + fh_len(4) + fh_data + auth_flavors_count(4) + flavors...
                let mut body = Vec::new();
                body.extend_from_slice(&0u32.to_be_bytes()); // MNT3_OK
                let fh_len = fh.len() as u32;
                body.extend_from_slice(&fh_len.to_be_bytes());
                body.extend_from_slice(&fh);
                // Auth flavors: 1 flavor: AUTH_SYS=1
                body.extend_from_slice(&1u32.to_be_bytes());
                body.extend_from_slice(&1u32.to_be_bytes()); // AUTH_SYS
                Some(make_accept_reply(xid, SUCCESS, &body))
            }
            MOUNTPROC_DUMP => {
                info!("MOUNT DUMP");
                // Return empty mount list
                let body = [0u8, 0, 0, 0]; // no entries
                Some(make_accept_reply(xid, SUCCESS, &body))
            }
            MOUNTPROC_UMNT | MOUNTPROC_UMNTALL => {
                info!("MOUNT UMNT/UMNTALL");
                Some(make_accept_reply(xid, SUCCESS, &[]))
            }
            MOUNTPROC_EXPORT => {
                info!("MOUNT EXPORT");
                // Build export list
                let export_list = exports.list_exports_with_aliases().await;
                let mut body = Vec::new();
                for (path, alias) in &export_list {
                    body.extend_from_slice(&[0, 0, 0, 1]); // value_follows=TRUE
                    // export dir name (use alias if available, otherwise path)
                    let name = alias.as_deref().unwrap_or(path.as_str());
                    let name_bytes = name.as_bytes();
                    let name_len = name_bytes.len() as u32;
                    let name_pad = (4 - (name_bytes.len() % 4)) % 4;
                    body.extend_from_slice(&name_len.to_be_bytes());
                    body.extend_from_slice(name_bytes);
                    body.extend_from_slice(&vec![0u8; name_pad]);
                    // groups: empty (value_follows=FALSE)
                    body.extend_from_slice(&[0, 0, 0, 0]);
                }
                body.extend_from_slice(&[0, 0, 0, 0]); // export list end
                Some(make_accept_reply(xid, SUCCESS, &body))
            }
            _ => {
                warn!("MOUNT unknown procedure: {}", procedure);
                Some(make_accept_reply(xid, PROC_UNAVAIL, &[]))
            }
        }
    }
}

/// Build a standard RPC accepted reply
fn make_accept_reply(xid: u32, accept_stat: u32, body: &[u8]) -> Vec<u8> {
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
