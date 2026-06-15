use anyhow::Result;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::RwLock;
use tracing::{error, info, warn};

// PORTMAP / RPCBIND protocol (RFC 1833)
pub struct PortmapServer {
    mappings: Arc<RwLock<HashMap<u64, PortMapping>>>,
}

#[derive(Debug, Clone)]
struct PortMapping {
    program: u32,
    version: u32,
    protocol: u32, // IPPROTO_TCP=6 or IPPROTO_UDP=17
    port: u32,
}

// RPC Message Types
const RPC_CALL: u32 = 0;
const RPC_REPLY: u32 = 1;

// Reply Status
const RPC_MSG_ACCEPTED: u32 = 0;
const RPC_MSG_DENIED: u32 = 1;

// Accept Status
const SUCCESS: u32 = 0;
const PROG_UNAVAIL: u32 = 1;
const PROG_MISMATCH: u32 = 2;
const PROC_UNAVAIL: u32 = 3;
const GARBAGE_ARGS: u32 = 4;

// PORTMAP Program / Version
const PORTMAP_PROGRAM: u32 = 100000;
const PORTMAP_VERSION: u32 = 2;

// PORTMAP Procedures
const PMAPPROC_NULL: u32 = 0;
const PMAPPROC_SET: u32 = 1;
const PMAPPROC_UNSET: u32 = 2;
const PMAPPROC_GETPORT: u32 = 3;
const PMAPPROC_DUMP: u32 = 4;
const PMAPPROC_CALLIT: u32 = 5;

// Protocol numbers
const IPPROTO_TCP: u32 = 6;
const IPPROTO_UDP: u32 = 17;

impl PortmapServer {
    pub fn new() -> Self {
        let mappings = Arc::new(RwLock::new(HashMap::new()));
        let m = Arc::clone(&mappings);
        tokio::spawn(async move {
            Self::initialize_mappings(m).await;
        });
        Self { mappings }
    }

    async fn initialize_mappings(mappings: Arc<RwLock<HashMap<u64, PortMapping>>>) {
        let mut map = mappings.write().await;

        let entries = vec![
            // PORTMAP itself
            (PORTMAP_PROGRAM, 2, IPPROTO_TCP, 111u32),
            (PORTMAP_PROGRAM, 2, IPPROTO_UDP, 111u32),
            // MOUNT v3
            (100005, 3, IPPROTO_TCP, 20048),
            (100005, 3, IPPROTO_UDP, 20048),
            // MOUNT v1
            (100005, 1, IPPROTO_TCP, 20048),
            (100005, 1, IPPROTO_UDP, 20048),
            // NFS v3
            (100003, 3, IPPROTO_TCP, 2049),
            (100003, 3, IPPROTO_UDP, 2049),
            // NFS v4
            (100003, 4, IPPROTO_TCP, 2049),
            (100003, 4, IPPROTO_UDP, 2049),
        ];

        for (prog, ver, proto, port) in entries {
            let key = Self::make_key(prog, ver, proto);
            map.insert(key, PortMapping {
                program: prog,
                version: ver,
                protocol: proto,
                port,
            });
        }

        info!("Portmap: {} mappings initialized", map.len());
    }

    fn make_key(program: u32, version: u32, protocol: u32) -> u64 {
        ((program as u64) << 32) | ((version as u64) << 8) | (protocol as u64)
    }

    pub async fn start(&self) -> Result<()> {
        info!("Starting PORTMAP server on port 111 (TCP+UDP)");

        let mappings_udp = Arc::clone(&self.mappings);
        let mappings_tcp = Arc::clone(&self.mappings);

        // UDP listener
        tokio::spawn(async move {
            if let Err(e) = Self::run_udp(mappings_udp).await {
                error!("PORTMAP UDP error: {}", e);
            }
        });

        // TCP listener
        Self::run_tcp(mappings_tcp).await
    }

    async fn run_udp(mappings: Arc<RwLock<HashMap<u64, PortMapping>>>) -> Result<()> {
        let socket = UdpSocket::bind("0.0.0.0:111").await?;
        info!("PORTMAP UDP listening on 0.0.0.0:111");
        let mut buf = [0u8; 4096];
        loop {
            match socket.recv_from(&mut buf).await {
                Ok((len, addr)) => {
                    info!("PORTMAP UDP from {} ({} bytes)", addr, len);
                    let data = buf[..len].to_vec();
                    let m = Arc::clone(&mappings);
                    let resp = Self::handle_request_static(&data, &m).await;
                    if let Some(resp) = resp {
                        if let Err(e) = socket.send_to(&resp, addr).await {
                            error!("PORTMAP UDP send error: {}", e);
                        }
                    }
                }
                Err(e) => error!("PORTMAP UDP recv error: {}", e),
            }
        }
    }

    async fn run_tcp(mappings: Arc<RwLock<HashMap<u64, PortMapping>>>) -> Result<()> {
        let listener = TcpListener::bind("0.0.0.0:111").await?;
        info!("PORTMAP TCP listening on 0.0.0.0:111");
        loop {
            match listener.accept().await {
                Ok((mut stream, addr)) => {
                    info!("PORTMAP TCP connection from {}", addr);
                    let m = Arc::clone(&mappings);
                    tokio::spawn(async move {
                        let mut buf = vec![0u8; 4096];
                        loop {
                            // Read record marking header (4 bytes)
                            let mut hdr = [0u8; 4];
                            match stream.read_exact(&mut hdr).await {
                                Ok(_) => {}
                                Err(_) => break,
                            }
                            let rm = u32::from_be_bytes(hdr);
                            let _last = (rm & 0x80000000) != 0;
                            let len = (rm & 0x7FFFFFFF) as usize;
                            if len == 0 || len > 65536 {
                                break;
                            }
                            if buf.len() < len {
                                buf.resize(len, 0);
                            }
                            match stream.read_exact(&mut buf[..len]).await {
                                Ok(_) => {}
                                Err(_) => break,
                            }
                            let data = buf[..len].to_vec();
                            if let Some(resp) = Self::handle_request_static(&data, &m).await {
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
                Err(e) => error!("PORTMAP TCP accept error: {}", e),
            }
        }
    }

    async fn handle_request_static(
        request: &[u8],
        mappings: &Arc<RwLock<HashMap<u64, PortMapping>>>,
    ) -> Option<Vec<u8>> {
        if request.len() < 28 {
            warn!("PORTMAP request too short: {}", request.len());
            return None;
        }

        let xid = u32::from_be_bytes([request[0], request[1], request[2], request[3]]);
        let msg_type = u32::from_be_bytes([request[4], request[5], request[6], request[7]]);

        if msg_type != RPC_CALL {
            warn!("PORTMAP: not a CALL message, msg_type={}", msg_type);
            return None;
        }

        let _rpc_ver = u32::from_be_bytes([request[8], request[9], request[10], request[11]]);
        let program = u32::from_be_bytes([request[12], request[13], request[14], request[15]]);
        let version = u32::from_be_bytes([request[16], request[17], request[18], request[19]]);
        let procedure = u32::from_be_bytes([request[20], request[21], request[22], request[23]]);

        info!("PORTMAP: xid={}, prog={}, ver={}, proc={}", xid, program, version, procedure);

        // Parse credentials + verifier to find args offset
        let mut offset = 24;
        // credentials: flavor(4) + len(4) + data(len padded to 4)
        if request.len() < offset + 8 {
            return Some(Self::make_accept_reply(xid, GARBAGE_ARGS, &[]));
        }
        let cred_len = u32::from_be_bytes([
            request[offset + 4], request[offset + 5],
            request[offset + 6], request[offset + 7],
        ]) as usize;
        let cred_padded = (cred_len + 3) & !3;
        offset += 8 + cred_padded;

        // verifier: flavor(4) + len(4) + data(len padded to 4)
        if request.len() < offset + 8 {
            return Some(Self::make_accept_reply(xid, GARBAGE_ARGS, &[]));
        }
        let verif_len = u32::from_be_bytes([
            request[offset + 4], request[offset + 5],
            request[offset + 6], request[offset + 7],
        ]) as usize;
        let verif_padded = (verif_len + 3) & !3;
        offset += 8 + verif_padded;

        match procedure {
            PMAPPROC_NULL => {
                info!("PORTMAP NULL");
                Some(Self::make_accept_reply(xid, SUCCESS, &[]))
            }
            PMAPPROC_GETPORT => {
                if request.len() < offset + 16 {
                    return Some(Self::make_accept_reply(xid, GARBAGE_ARGS, &[]));
                }
                let args_prog = u32::from_be_bytes([
                    request[offset], request[offset + 1],
                    request[offset + 2], request[offset + 3],
                ]);
                let args_ver = u32::from_be_bytes([
                    request[offset + 4], request[offset + 5],
                    request[offset + 6], request[offset + 7],
                ]);
                let args_proto = u32::from_be_bytes([
                    request[offset + 8], request[offset + 9],
                    request[offset + 10], request[offset + 11],
                ]);
                info!("PORTMAP GETPORT: prog={}, ver={}, proto={}", args_prog, args_ver, args_proto);

                let key = Self::make_key(args_prog, args_ver, args_proto);
                let m = mappings.read().await;
                let port = if let Some(mapping) = m.get(&key) {
                    info!("PORTMAP GETPORT -> port {}", mapping.port);
                    mapping.port
                } else {
                    info!("PORTMAP GETPORT -> not found, returning 0");
                    0u32
                };
                Some(Self::make_accept_reply(xid, SUCCESS, &port.to_be_bytes()))
            }
            PMAPPROC_DUMP => {
                info!("PORTMAP DUMP");
                let m = mappings.read().await;
                let mut body = Vec::new();
                for mapping in m.values() {
                    body.extend_from_slice(&[0, 0, 0, 1]); // value_follows = TRUE
                    body.extend_from_slice(&mapping.program.to_be_bytes());
                    body.extend_from_slice(&mapping.version.to_be_bytes());
                    body.extend_from_slice(&mapping.protocol.to_be_bytes());
                    body.extend_from_slice(&mapping.port.to_be_bytes());
                }
                body.extend_from_slice(&[0, 0, 0, 0]); // value_follows = FALSE
                Some(Self::make_accept_reply(xid, SUCCESS, &body))
            }
            _ => {
                warn!("PORTMAP: unknown procedure {}", procedure);
                Some(Self::make_accept_reply(xid, PROC_UNAVAIL, &[]))
            }
        }
    }

    /// Build a standard RPC accepted reply.
    /// body is appended after the accept_status field.
    fn make_accept_reply(xid: u32, accept_stat: u32, body: &[u8]) -> Vec<u8> {
        let mut r = Vec::with_capacity(24 + body.len());
        r.extend_from_slice(&xid.to_be_bytes());          // XID
        r.extend_from_slice(&RPC_REPLY.to_be_bytes());    // msg_type = REPLY(1)
        r.extend_from_slice(&RPC_MSG_ACCEPTED.to_be_bytes()); // reply_stat = ACCEPTED(0)
        // verf: AUTH_NONE flavor=0, len=0
        r.extend_from_slice(&0u32.to_be_bytes());
        r.extend_from_slice(&0u32.to_be_bytes());
        r.extend_from_slice(&accept_stat.to_be_bytes());  // accept_stat
        r.extend_from_slice(body);
        r
    }
}
