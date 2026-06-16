pub mod mount;
pub mod nfs4;
pub mod portmap;
pub mod protocol;

use anyhow::Result;
use std::sync::Arc;
use tokio::net::{TcpListener, UdpSocket};
use tokio::io::AsyncReadExt;
use tokio::io::AsyncWriteExt;
use tracing::{debug, error, info, warn};

use crate::exports::ExportsManager;

// NFS program numbers
const NFS_PROGRAM: u32 = 100003;
const NFS_V3: u32 = 3;
const NFS_V4: u32 = 4;
const NFS_ACL_PROGRAM: u32 = 100227;

// SEC-005: Maximum TCP receive buffer size (4 MB).
// Prevents a malicious client from consuming unbounded memory
// by sending partial records that never complete.
const MAX_RECV_BUF: usize = 4 * 1024 * 1024;

// SEC-009: Maximum single NFS record length (1 MB).
// NFS over TCP record marking uses 31-bit length; in practice
// a single COMPOUND should never exceed 1 MB.
const MAX_RECORD_LENGTH: usize = 1024 * 1024;

// SEC-008: Maximum number of operations in a single COMPOUND request.
// Prevents CPU exhaustion from opcount=100000 style attacks.
// Linux kernel NFS client typically sends ≤16 ops per COMPOUND.
pub const MAX_OPS_PER_COMPOUND: usize = 64;

// SEC-012: Maximum size for any single XDR opaque<> field.
// Prevents integer overflow in `(len + 3) & !3` padding calculations
// and limits memory allocation for untrusted length values.
pub const MAX_XDR_OPAQUE: usize = 4 * 1024 * 1024; // 4MB

pub struct NfsServer {
    exports: Arc<ExportsManager>,
}

impl NfsServer {
    pub fn new(exports: Arc<ExportsManager>) -> Self {
        Self { exports }
    }

    // Clone needed for spawning separate tasks
    fn clone_v3(&self) -> protocol::NfsProtocolServer {
        protocol::NfsProtocolServer::new(Arc::clone(&self.exports))
    }

    fn clone_v4(&self) -> nfs4::Nfs4Server {
        nfs4::Nfs4Server::new(Arc::clone(&self.exports))
    }

    pub async fn start(&self) -> Result<()> {
        info!("Starting NFS Server");

        // Start PORTMAP server (port 111)
        let portmap_server = portmap::PortmapServer::new();
        tokio::spawn(async move {
            if let Err(e) = portmap_server.start().await {
                error!("PORTMAP server error: {}", e);
            }
        });

        // Start MOUNT server (port 20048)
        let exports_clone = Arc::clone(&self.exports);
        let mount_server = mount::MountServer::new(exports_clone);
        tokio::spawn(async move {
            if let Err(e) = mount_server.start().await {
                error!("MOUNT server error: {}", e);
            }
        });

        // Start unified NFS server (handles v3 and v4 on port 2049)
        let exports_clone = Arc::clone(&self.exports);
        let nfs_protocol_server = protocol::NfsProtocolServer::new(exports_clone.clone());
        let nfs4_server = nfs4::Nfs4Server::new(exports_clone);

        // SEC-011: Start background lease cleanup task (every 60 seconds)
        let cleanup_server = nfs4_server.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
            loop {
                interval.tick().await;
                cleanup_server.cleanup_expired().await;
            }
        });

        tokio::spawn(async move {
            if let Err(e) = Self::start_unified_nfs(nfs_protocol_server, nfs4_server).await {
                error!("NFS server error: {}", e);
            }
        });

        info!("NFS Server started successfully (v3 and v4 on port 2049)");
        Ok(())
    }

    async fn start_unified_nfs(
        v3_server: protocol::NfsProtocolServer,
        v4_server: nfs4::Nfs4Server,
    ) -> Result<()> {
        info!("Starting unified NFS server on port 2049");

        // Start UDP server for NFS v3
        let udp_socket = UdpSocket::bind("0.0.0.0:2049").await?;
        let mut udp_buf = [0u8; 65536];

        info!("NFS unified server listening on UDP 0.0.0.0:2049");

        // Start TCP listener for NFS v4
        let tcp_listener = tokio::net::TcpListener::bind("0.0.0.0:2049").await?;
        info!("NFS unified server listening on TCP 0.0.0.0:2049");

        // Spawn UDP handler
        let v3_udp = v3_server.clone();
        let v4_udp = v4_server.clone();

        tokio::spawn(async move {
            loop {
                match udp_socket.recv_from(&mut udp_buf).await {
                    Ok((len, addr)) => {
                        info!("Received UDP NFS request from {} ({} bytes)", addr, len);

                        if len < 20 {
                            warn!("Invalid NFS request length: {}", len);
                            continue;
                        }

                        let _rpc_version = u32::from_be_bytes([udp_buf[8], udp_buf[9], udp_buf[10], udp_buf[11]]);
                        let program = u32::from_be_bytes([udp_buf[12], udp_buf[13], udp_buf[14], udp_buf[15]]);
                        let version = u32::from_be_bytes([udp_buf[16], udp_buf[17], udp_buf[18], udp_buf[19]]);

                        info!("RPC header: program={}, version={}", program, version);

                        if program == NFS_PROGRAM {
                            if version == NFS_V3 {
                                info!("Routing to NFS v3 UDP handler");
                                if let Some(response) = v3_udp.handle_request(&udp_buf[..len], addr.ip()).await {
                                    info!("Sending NFS v3 UDP response ({} bytes)", response.len());
                                    if let Err(e) = udp_socket.send_to(&response, addr).await {
                                        error!("Failed to send NFS v3 UDP response: {}", e);
                                    }
                                }
                            } else if version == NFS_V4 {
                                info!("Routing to NFS v4 UDP handler");
                                if let Some(response) = v4_udp.handle_request(&udp_buf[..len]).await {
                                    info!("Sending NFS v4 UDP response ({} bytes)", response.len());
                                    if let Err(e) = udp_socket.send_to(&response, addr).await {
                                        error!("Failed to send NFS v4 UDP response: {}", e);
                                    }
                                }
                            } else {
                                warn!("Unsupported NFS version: {}", version);
                            }
                        } else if program == NFS_ACL_PROGRAM {
                            info!("NFS ACL program requested - not supported, returning error");
                            // Send RPC error response: procedure not supported
                            if let Some(response) = Self::make_rpc_error_reply(&udp_buf[..len], 1) {
                                info!("Sending NFS ACL error response ({} bytes)", response.len());
                                if let Err(e) = udp_socket.send_to(&response, addr).await {
                                    error!("Failed to send NFS ACL error response: {}", e);
                                }
                            }
                        } else {
                            warn!("Unsupported RPC program: {}", program);
                        }
                    }
                    Err(e) => {
                        error!("NFS UDP receive error: {}", e);
                    }
                }
            }
        });

        // Handle TCP connections
        loop {
            match tcp_listener.accept().await {
                Ok((mut stream, addr)) => {
                    info!("Accepted TCP NFS connection from {}", addr);

                    let v3_tcp = v3_server.clone();
                    let v4_tcp = v4_server.clone();

                    tokio::spawn(async move {
                        // TCP is a byte stream, not message-based.
                        // We must buffer incoming data and process complete NFS records.
                        // NFS over TCP uses RFC 1831 record marking: 4-byte header per record.
                        let mut recv_buf = Vec::with_capacity(65536);

                        loop {
                            // Try to process all complete records already in the buffer
                            while recv_buf.len() >= 4 {
                                let record_marking = u32::from_be_bytes([
                                    recv_buf[0], recv_buf[1], recv_buf[2], recv_buf[3],
                                ]);
                                let is_last_record = (record_marking & 0x80000000) != 0;
                                let record_length = (record_marking & 0x7FFFFFFF) as usize;

                                if !is_last_record {
                                    warn!("Multi-record fragments not supported, discarding connection");
                                    break;
                                }

                                if record_length < 20 {
                                    warn!("Invalid RPC record length: {}, discarding 4 bytes", record_length);
                                    recv_buf.drain(0..4);
                                    continue;
                                }

                                // SEC-009: Reject oversized records
                                if record_length > MAX_RECORD_LENGTH {
                                    warn!("Oversized NFS record: {} bytes (max {}), dropping connection", record_length, MAX_RECORD_LENGTH);
                                    return;
                                }

                                let total_msg_len = 4 + record_length;
                                if recv_buf.len() < total_msg_len {
                                    // Incomplete record — need more data
                                    break;
                                }

                                // Extract the complete record
                                let record_data: Vec<u8> = recv_buf.drain(0..total_msg_len).collect();
                                let rpc_data = &record_data[4..]; // skip record marking header

                                // Parse RPC header
                                if rpc_data.len() < 20 {
                                    continue;
                                }

                                let program = u32::from_be_bytes([
                                    rpc_data[12], rpc_data[13], rpc_data[14], rpc_data[15],
                                ]);
                                let version = u32::from_be_bytes([
                                    rpc_data[16], rpc_data[17], rpc_data[18], rpc_data[19],
                                ]);

                                info!("RPC header: program={}, version={}", program, version);

                                // Process the request
                                let response_opt = if program == NFS_PROGRAM {
                                    if version == NFS_V4 {
                                        info!("Routing to NFS v4 TCP handler");
                                        v4_tcp.handle_request(rpc_data).await
                                    } else if version == NFS_V3 {
                                        info!("Routing to NFS v3 TCP handler");
                                        v3_tcp.handle_request(rpc_data, addr.ip()).await
                                    } else {
                                        warn!("Unsupported NFS version: {}", version);
                                        None
                                    }
                                } else if program == NFS_ACL_PROGRAM {
                                    info!("NFS ACL program requested - not supported, returning error");
                                    Self::make_rpc_error_reply(rpc_data, 1)
                                } else {
                                    warn!("Unsupported RPC program: {}", program);
                                    None
                                };

                                // Send response with record marking
                                if let Some(response) = response_opt {
                                    let response_len = response.len() as u32;
                                    let rm = 0x80000000 | response_len; // last fragment flag
                                    let mut full_response = Vec::with_capacity(4 + response.len());
                                    full_response.extend_from_slice(&rm.to_be_bytes());
                                    full_response.extend_from_slice(&response);

                                    debug!("Sending NFS TCP response ({} bytes)", full_response.len());

                                    if let Err(e) = stream.write_all(&full_response).await {
                                        error!("Failed to send NFS TCP response: {}", e);
                                        return; // drop connection
                                    }
                                }
                            }

                            // Read more data from the TCP stream
                            let mut tmp = [0u8; 65536];
                            match stream.read(&mut tmp).await {
                                Ok(0) => {
                                    info!("TCP connection closed by {}", addr);
                                    return;
                                }
                                Ok(n) => {
                                    info!("Received TCP data from {} ({} bytes, buffer now {})", addr, n, recv_buf.len() + n);
                                    recv_buf.extend_from_slice(&tmp[..n]);
                                    // SEC-005: Drop connection if buffer exceeds maximum
                                    if recv_buf.len() > MAX_RECV_BUF {
                                        warn!("TCP recv buffer exceeded max ({} > {}), dropping connection from {}", recv_buf.len(), MAX_RECV_BUF, addr);
                                        return;
                                    }
                                }
                                Err(e) => {
                                    error!("TCP read error from {}: {}", addr, e);
                                    return;
                                }
                            }
                        }
                    });
                }
                Err(e) => {
                    error!("TCP accept error: {}", e);
                }
            }
        }
    }

    // Make an RPC error reply for unsupported procedures
    fn make_rpc_error_reply(request: &[u8], error_code: u32) -> Option<Vec<u8>> {
        if request.len() < 20 {
            return None;
        }

        // XID (4 bytes)
        let xid = [request[0], request[1], request[2], request[3]];

        // Build RPC reply message (rejected)
        // Format:
        // XID (4 bytes)
        // Message Type: REPLY (1)
        // Reply State: ACCEPTED (0)
        // Verifier: AUTH_NONE (0) + Length (0) + Padding (4)
        // Accept State: PROC_UNAVAIL (1) or similar

        let mut response = Vec::new();

        // XID
        response.extend_from_slice(&xid);

        // Message type: REPLY (1)
        response.extend_from_slice(&0u32.to_be_bytes());

        // Reply state: ACCEPTED (0)
        response.extend_from_slice(&0u32.to_be_bytes());

        // Verifier: AUTH_NONE (0)
        response.extend_from_slice(&0u32.to_be_bytes());

        // Verifier length: 0
        response.extend_from_slice(&0u32.to_be_bytes());

        // Accept state: PROC_UNAVAIL (1)
        response.extend_from_slice(&error_code.to_be_bytes());

        Some(response)
    }
}
