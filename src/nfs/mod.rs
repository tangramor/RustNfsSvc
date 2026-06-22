pub mod mount;
pub mod nfs4;
pub mod portmap;
pub mod protocol;

use anyhow::Result;
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::net::{TcpListener, UdpSocket};
use tokio::io::AsyncReadExt;
use tokio::io::AsyncWriteExt;
use tokio::sync::Mutex;
use tracing::{debug, error, info, warn};

// SEC-015: TLS support
use rustls::ServerConfig;
use rustls_pemfile::{certs, pkcs8_private_keys, rsa_private_keys};
use tokio_rustls::TlsAcceptor;

/// Ensure the rustls CryptoProvider (ring) is installed as the process-level default.
/// Must be called before any `ServerConfig::builder()` invocation.
/// Safe to call multiple times — subsequent calls are no-ops.
fn ensure_crypto_provider() {
    // install_default() returns Err if a provider is already installed; that's fine.
    let _ = rustls::crypto::ring::default_provider().install_default();
}

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

// SEC-025: Connection rate limiter.
// Tracks the number of TCP connections per IP address within a time window.
struct ConnRateLimiter {
    /// (connection_count_in_window, window_start_instant, already_warned_this_window)
    per_ip: Mutex<HashMap<std::net::IpAddr, (usize, std::time::Instant, bool)>>,
    /// Rate limit window duration
    window: std::time::Duration,
    /// Max new connections per IP per window
    max_per_ip: usize,
}

impl ConnRateLimiter {
    fn new(max_per_ip: usize, window_secs: u64) -> Self {
        Self {
            per_ip: Mutex::new(HashMap::new()),
            window: std::time::Duration::from_secs(window_secs),
            max_per_ip,
        }
    }

    /// Returns true if the connection from this IP is allowed.
    /// Sets `first_reject` to true the first time an IP is rejected in a window
    /// (caller can use this to emit warn vs debug).
    async fn check(&self, ip: std::net::IpAddr) -> (bool, bool) {
        let mut map = self.per_ip.lock().await;
        let now = std::time::Instant::now();
        let entry = map.entry(ip).or_insert((0, now, false));

        // Reset counter if outside the window
        if now.duration_since(entry.1) > self.window {
            *entry = (1, now, false);
            return (true, false);
        }

        entry.0 += 1;
        if entry.0 <= self.max_per_ip {
            (true, false)
        } else {
            let first = !entry.2;
            entry.2 = true;
            (false, first)
        }
    }

    /// Periodically clean up stale entries to prevent unbounded growth.
    async fn cleanup(&self) {
        let mut map = self.per_ip.lock().await;
        let now = std::time::Instant::now();
        map.retain(|_, (count, start, _)| {
            now.duration_since(*start) <= self.window || *count > 0
        });
    }
}

// SEC-025: RAII guard that decrements the connection counter on drop.
struct ConnGuard(Arc<AtomicUsize>);

impl Drop for ConnGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
    }
}

// SEC-015: Load TLS server configuration from cert and key files.
fn load_tls_config(cert_path: &str, key_path: &str) -> anyhow::Result<Arc<ServerConfig>> {
    use crate::path_ext::to_extended_path;
    use std::io::BufReader;
    use std::path::Path;

    // Install ring as the process-level CryptoProvider (rustls 0.23 requirement)
    ensure_crypto_provider();

    let cert_file = std::fs::File::open(to_extended_path(Path::new(cert_path)))
        .map_err(|e| anyhow::anyhow!("Cannot open TLS cert '{}': {}", cert_path, e))?;
    let key_file = std::fs::File::open(to_extended_path(Path::new(key_path)))
        .map_err(|e| anyhow::anyhow!("Cannot open TLS key '{}': {}", key_path, e))?;

    let certs = certs(&mut BufReader::new(cert_file))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| anyhow::anyhow!("TLS cert parse error: {}", e))?;

    if certs.is_empty() {
        return Err(anyhow::anyhow!("No certificates found in '{}'", cert_path));
    }

    // Try PKCS8 first, then fall back to PKCS1 RSA
    let mut keys = pkcs8_private_keys(&mut BufReader::new(key_file))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| anyhow::anyhow!("TLS key parse error: {}", e))?;

    let key = if !keys.is_empty() {
        rustls::pki_types::PrivateKeyDer::Pkcs8(keys.remove(0))
    } else {
        // SEC-015: Fallback to RSA private keys if PKCS8 parsing yields nothing
        let key_file2 = std::fs::File::open(to_extended_path(Path::new(key_path)))
            .map_err(|e| anyhow::anyhow!("Cannot reopen TLS key '{}': {}", key_path, e))?;
        let mut rsa_keys = rsa_private_keys(&mut BufReader::new(key_file2))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| anyhow::anyhow!("TLS RSA key parse error: {}", e))?;
        if rsa_keys.is_empty() {
            return Err(anyhow::anyhow!(
                "No PKCS8 private key found in '{}'. \
                 Use 'openssl pkcs8 -topk8 -nocrypt' to convert if needed.",
                key_path
            ));
        }
        rustls::pki_types::PrivateKeyDer::Pkcs1(rsa_keys.remove(0))
    };

    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)?;

    Ok(Arc::new(config))
}

pub struct NfsServer {
    exports: Arc<ExportsManager>,
    config: Arc<crate::config::Config>,
}

impl NfsServer {
    pub fn new(exports: Arc<ExportsManager>, config: Arc<crate::config::Config>) -> Self {
        Self { exports, config }
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

        // SEC-015: Warn about unencrypted transport
        if !self.config.tls.enabled {
            warn!("SEC-015: TLS is not enabled. All NFS traffic is unencrypted. \
                   Use VPN or SSH tunneling for production environments.");
        }

        // SEC-015: Load TLS config if enabled
        let tls_acceptor: Option<TlsAcceptor> = if self.config.tls.enabled {
            let cert = self.config.tls.cert_path.as_deref()
                .ok_or_else(|| anyhow::anyhow!("TLS enabled but cert_path not set"))?;
            let key = self.config.tls.key_path.as_deref()
                .ok_or_else(|| anyhow::anyhow!("TLS enabled but key_path not set"))?;
            let tls_cfg = load_tls_config(cert, key)?;
            info!("SEC-015: TLS enabled, loaded certificate from '{}'", cert);
            Some(TlsAcceptor::from(tls_cfg))
        } else {
            warn!("SEC-015: TLS is not enabled. All NFS traffic is unencrypted.");
            None
        };

        let bind_ip = self.config.nfs.bind_ip.clone();

        // Start PORTMAP server (port 111)
        let portmap_server = portmap::PortmapServer::new(bind_ip.clone());
        tokio::spawn(async move {
            if let Err(e) = portmap_server.start().await {
                error!("PORTMAP server error: {}", e);
            }
        });

        // Start MOUNT server (port 20048)
        let exports_clone = Arc::clone(&self.exports);
        let mount_server = mount::MountServer::new(exports_clone, bind_ip.clone());
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

        let bind_ip_nfs = bind_ip.clone();
        let max_connections = self.config.nfs.max_connections;
        let max_conn_rate = self.config.nfs.max_conn_rate_per_ip;
        let enable_udp = self.config.nfs.enable_udp;
        let conn_count = Arc::new(AtomicUsize::new(0));
        let rate_limiter = Arc::new(ConnRateLimiter::new(max_conn_rate, 60)); // 60s window

        // SEC-025: Start background rate limiter cleanup (every 120 seconds)
        let cleanup_limiter = rate_limiter.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(120));
            loop {
                interval.tick().await;
                cleanup_limiter.cleanup().await;
            }
        });

        tokio::spawn(async move {
            if let Err(e) = Self::start_unified_nfs(
                nfs_protocol_server,
                nfs4_server,
                bind_ip_nfs,
                max_connections,
                enable_udp,
                conn_count,
                rate_limiter,
                tls_acceptor,
            ).await {
                error!("NFS server error: {}", e);
            }
        });

        info!("NFS Server started successfully (v3 and v4 on {} port 2049)", bind_ip);
        Ok(())
    }

    async fn start_unified_nfs(
        v3_server: protocol::NfsProtocolServer,
        v4_server: nfs4::Nfs4Server,
        bind_ip: String,
        max_connections: usize,
        enable_udp: bool,
        conn_count: Arc<AtomicUsize>,
        rate_limiter: Arc<ConnRateLimiter>,
        tls_acceptor: Option<TlsAcceptor>,
    ) -> Result<()> {
        let nfs_addr = format!("{}:2049", bind_ip);
        info!("Starting unified NFS server on {}", nfs_addr);

        // SEC-026: Conditionally start UDP server
        // UDP NFS is susceptible to source address spoofing and reflection attacks.
        // When disabled, only TCP connections are accepted (recommended for production).
        if enable_udp {
            // Start UDP server for NFS v3
            let udp_socket = UdpSocket::bind(&nfs_addr).await?;
            info!("NFS unified server listening on UDP {}", nfs_addr);

            // Spawn UDP handler
            let v3_udp = v3_server.clone();
            let v4_udp = v4_server.clone();

            tokio::spawn(async move {
                let mut udp_buf = [0u8; 65536];
                loop {
                    match udp_socket.recv_from(&mut udp_buf).await {
                        Ok((len, addr)) => {
                            debug!("Received UDP NFS request from {} ({} bytes)", addr, len);

                            // SEC-026: Anti-reflection — limit UDP response size.
                            // A legitimate NFS response is typically < 64KB.
                            // If the response would be much larger than the request,
                            // it could be used as a reflection/amplification attack.
                            const MAX_UDP_RESPONSE_SIZE: usize = 65536;
                            let _ = MAX_UDP_RESPONSE_SIZE; // used below in send checks

                            if len < 20 {
                                warn!("Invalid NFS request length: {}", len);
                                continue;
                            }

                            let _rpc_version = u32::from_be_bytes([udp_buf[8], udp_buf[9], udp_buf[10], udp_buf[11]]);
                            let program = u32::from_be_bytes([udp_buf[12], udp_buf[13], udp_buf[14], udp_buf[15]]);
                            let version = u32::from_be_bytes([udp_buf[16], udp_buf[17], udp_buf[18], udp_buf[19]]);

                            debug!("RPC header: program={}, version={}", program, version);

                            if program == NFS_PROGRAM {
                                if version == NFS_V3 {
                                    if let Some(response) = v3_udp.handle_request(&udp_buf[..len], addr.ip()).await {
                                        // SEC-026: Anti-amplification check
                                        if response.len() > MAX_UDP_RESPONSE_SIZE {
                                            warn!("SEC-026: Oversized UDP response ({} bytes), dropping to prevent amplification", response.len());
                                            continue;
                                        }
                                        if let Err(e) = udp_socket.send_to(&response, addr).await {
                                            error!("Failed to send NFS v3 UDP response: {}", e);
                                        }
                                    }
                                } else if version == NFS_V4 {
                                    if let Some(response) = v4_udp.handle_request(&udp_buf[..len]).await {
                                        // SEC-026: Anti-amplification check
                                        if response.len() > MAX_UDP_RESPONSE_SIZE {
                                            warn!("SEC-026: Oversized UDP response ({} bytes), dropping to prevent amplification", response.len());
                                            continue;
                                        }
                                        if let Err(e) = udp_socket.send_to(&response, addr).await {
                                            error!("Failed to send NFS v4 UDP response: {}", e);
                                        }
                                    }
                                } else {
                                    warn!("Unsupported NFS version: {}", version);
                                }
                            } else if program == NFS_ACL_PROGRAM {
                                if let Some(response) = Self::make_rpc_error_reply(&udp_buf[..len], 1) {
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
        } else {
            info!("SEC-026: UDP listener disabled. Only TCP connections will be accepted.");
        }

        // Start TCP listener for NFS v4
        let tcp_listener = tokio::net::TcpListener::bind(&nfs_addr).await?;
        info!("NFS unified server listening on TCP {}", nfs_addr);

        // Handle TCP connections
        loop {
            match tcp_listener.accept().await {
                Ok((stream, addr)) => {
                    // SEC-025: Per-IP connection rate limiting
                    let (allowed, first_reject) = rate_limiter.check(addr.ip()).await;
                    if !allowed {
                        if first_reject {
                            warn!("SEC-025: Connection rate limit exceeded for {}, rejecting (subsequent rejects silenced)", addr.ip());
                        } else {
                            debug!("SEC-025: Connection rate limit exceeded for {}, rejecting", addr.ip());
                        }
                        drop(stream);
                        continue;
                    }

                    // SEC-025: Global concurrent connection limit
                    let current = conn_count.fetch_add(1, Ordering::Relaxed);
                    if current >= max_connections {
                        conn_count.fetch_sub(1, Ordering::Relaxed);
                        warn!("SEC-025: Max connections ({}) reached, rejecting connection from {}", max_connections, addr);
                        drop(stream);
                        continue;
                    }

                    info!("Accepted TCP NFS connection from {} (active: {})", addr, current + 1);

                    let v3_tcp = v3_server.clone();
                    let v4_tcp = v4_server.clone();
                    let conn_count_clone = conn_count.clone();

                    let tls_acc = tls_acceptor.clone();

                    tokio::spawn(async move {
                        // SEC-025: Decrement connection counter on exit
                        let _conn_guard = ConnGuard(conn_count_clone);

                        if let Some(acceptor) = tls_acc {
                            // TLS path
                            match acceptor.accept(stream).await {
                                Ok(tls_stream) => {
                                    let (reader, writer) = tokio::io::split(tls_stream);
                                    Self::handle_nfs_stream(
                                        Box::new(reader), Box::new(writer),
                                        addr, v3_tcp, v4_tcp,
                                    ).await;
                                }
                                Err(e) => {
                                    warn!("TLS handshake failed from {}: {}", addr, e);
                                }
                            }
                        } else {
                            // Plain TCP path
                            let (reader, writer) = tokio::io::split(stream);
                            Self::handle_nfs_stream(
                                Box::new(reader), Box::new(writer),
                                addr, v3_tcp, v4_tcp,
                            ).await;
                        }
                    });
                }
                Err(e) => {
                    error!("TCP accept error: {}", e);
                }
            }
        }
    }

    // SEC-015: Handle an NFS stream (TLS or plain TCP) — shared between both paths.
    async fn handle_nfs_stream(
        mut reader: Box<dyn tokio::io::AsyncRead + Send + Unpin>,
        mut writer: Box<dyn tokio::io::AsyncWrite + Send + Unpin>,
        addr: std::net::SocketAddr,
        v3_server: protocol::NfsProtocolServer,
        v4_server: nfs4::Nfs4Server,
    ) {
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
                    return;
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
                        v4_server.handle_request(rpc_data).await
                    } else if version == NFS_V3 {
                        info!("Routing to NFS v3 TCP handler");
                        v3_server.handle_request(rpc_data, addr.ip()).await
                    } else {
                        warn!("Unsupported NFS version: {}", version);
                        None
                    }
                } else if program == NFS_ACL_PROGRAM {
                    info!("NFS ACL program requested - not supported, returning error");
                    NfsServer::make_rpc_error_reply(rpc_data, 1)
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

                    if let Err(e) = writer.write_all(&full_response).await {
                        error!("Failed to send NFS TCP response: {}", e);
                        return; // drop connection
                    }
                }
            }

            // Read more data from the TCP stream
            let mut tmp = [0u8; 65536];
            match reader.read(&mut tmp).await {
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
