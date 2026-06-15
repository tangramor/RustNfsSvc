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

                    let mut buf = [0u8; 65536];
                    let v3_tcp = v3_server.clone();
                    let v4_tcp = v4_server.clone();

                    tokio::spawn(async move {
                        loop {
                            match stream.read(&mut buf).await {
                                Ok(0) => {
                                    info!("TCP connection closed by {}", addr);
                                    break;
                                }
                                Ok(len) => {
                                    info!("Received TCP NFS request from {} ({} bytes)", addr, len);

                                    // TCP RPC over record marking: 4-byte header + RPC message
                                    // Header: last flag (1 bit) | length (31 bits)
                                    if len < 4 {
                                        warn!("Invalid TCP RPC request: less than record marking header");
                                        continue;
                                    }

                                    // Parse record marking header
                                    let record_marking = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
                                    let is_last_record = (record_marking & 0x80000000) != 0;
                                    let record_length = (record_marking & 0x7FFFFFFF) as usize;

                                    if !is_last_record {
                                        warn!("Multi-record fragments not supported");
                                        continue;
                                    }

                                    if len < 4 + record_length || record_length < 20 {
                                        warn!("Invalid RPC record length: {} (total: {})", record_length, len);
                                        continue;
                                    }

                                    // RPC message starts after 4-byte record marking header
                                    let rpc_offset = 4;

                                    let _rpc_version = u32::from_be_bytes([buf[rpc_offset + 8], buf[rpc_offset + 9], buf[rpc_offset + 10], buf[rpc_offset + 11]]);
                                    let program = u32::from_be_bytes([buf[rpc_offset + 12], buf[rpc_offset + 13], buf[rpc_offset + 14], buf[rpc_offset + 15]]);
                                    let version = u32::from_be_bytes([buf[rpc_offset + 16], buf[rpc_offset + 17], buf[rpc_offset + 18], buf[rpc_offset + 19]]);

                                    info!("RPC header: program={}, version={}", program, version);

                                    if program == NFS_PROGRAM {
                                        if version == NFS_V4 {
                                            info!("Routing to NFS v4 TCP handler");
                                            // Pass the RPC message part (after record marking)
                                            if let Some(response) = v4_tcp.handle_request(&buf[rpc_offset..rpc_offset + record_length]).await {
                                                // Add record marking header to response
                                                // Format: last flag (1 bit) | length (31 bits)
                                                let response_len = response.len() as u32;
                                                let record_marking = 0x80000000 | response_len; // Set last fragment flag
                                                let mut full_response = Vec::with_capacity(4 + response.len());
                                                full_response.extend_from_slice(&record_marking.to_be_bytes());
                                                full_response.extend_from_slice(&response);

                                                let hex_str: Vec<String> = full_response.iter()
                                                    .map(|b| format!("{:02x}", b))
                                                    .collect();
                                                debug!("Sending NFS v4 TCP response ({} bytes): {}", full_response.len(), hex_str.join(" "));

                                                if let Err(e) = stream.write_all(&full_response).await {
                                                    error!("Failed to send NFS v4 TCP response: {}", e);
                                                    break;
                                                }
                                            }
                                        } else if version == NFS_V3 {
                                            info!("Routing to NFS v3 TCP handler");
                                            // Pass the RPC message part (after record marking)
                                            if let Some(response) = v3_tcp.handle_request(&buf[rpc_offset..rpc_offset + record_length], addr.ip()).await {
                                                // Add record marking header to response
                                                // Format: last flag (1 bit) | length (31 bits)
                                                let response_len = response.len() as u32;
                                                let record_marking = 0x80000000 | response_len; // Set last fragment flag
                                                let mut full_response = Vec::with_capacity(4 + response.len());
                                                full_response.extend_from_slice(&record_marking.to_be_bytes());
                                                full_response.extend_from_slice(&response);

                                                debug!("Sending NFS v3 TCP response ({} bytes)", full_response.len());
                                                if let Err(e) = stream.write_all(&full_response).await {
                                                    error!("Failed to send NFS v3 TCP response: {}", e);
                                                    break;
                                                }
                                            }
                                        } else {
                                            warn!("Unsupported NFS version: {}", version);
                                        }
                                    } else if program == NFS_ACL_PROGRAM {
                                        info!("NFS ACL program requested - not supported, returning error");
                                        // Send RPC error response: procedure not supported
                                        if let Some(response) = Self::make_rpc_error_reply(&buf[rpc_offset..rpc_offset + record_length], 1) {
                                            // Add record marking header to response
                                            let response_len = response.len() as u32;
                                            let record_marking = 0x80000000 | response_len;
                                            let mut full_response = Vec::with_capacity(4 + response.len());
                                            full_response.extend_from_slice(&record_marking.to_be_bytes());
                                            full_response.extend_from_slice(&response);

                                            debug!("Sending NFS ACL error response ({} bytes)", full_response.len());
                                            if let Err(e) = stream.write_all(&full_response).await {
                                                error!("Failed to send NFS ACL error response: {}", e);
                                                break;
                                            }
                                        }
                                    } else {
                                        warn!("Unsupported RPC program: {}", program);
                                    }
                                }
                                Err(e) => {
                                    error!("TCP read error from {}: {}", addr, e);
                                    break;
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
