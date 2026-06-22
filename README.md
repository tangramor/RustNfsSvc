# RustNfsSvc

English | [中文](./README_zh.md)

A high-performance NFS (Network File System) server for Windows, written in Rust. Supports both NFSv3 and NFSv4.1, enabling Linux/Unix clients to mount Windows directories transparently.

## Features

- **NFSv3** — Full protocol support (MOUNT, PORTMAP, NFSv3 procedures)
- **NFSv4.1** — COMPOUND operations, SEQUENCE, OPEN, CLOSE, READ, WRITE, READDIR, LOCK/LOCKU, SETATTR, and more
- **Native Windows Service** — Install/uninstall as a Windows Service with automatic startup
- **Dual-stack NFS** — Run NFSv3 and NFSv4.1 simultaneously on the same port (2049)
- **MOUNT protocol** — NFSv3 MOUNT protocol on port 20048
- **PORTMAP** — RPC portmapper on port 111 (TCP + UDP)
- **Async I/O** — Built on Tokio for high concurrency
- **Flexible configuration** — TOML-based config with per-export access control (CIDR)
- **TLS encryption** — Built-in TLS support (rustls) for encrypted NFS transport (SEC-015)
- **Structured logging** — Rolling log files with configurable level and rotation

## Project Structure

```
RustNfsSvc/
├── src/
│   ├── main.rs              # Entry point: CLI arg parsing (install/uninstall/service/standalone)
│   ├── path_ext.rs          # Windows \\?\ extended-path helper (MAX_PATH fix)
│   ├── service.rs           # Windows Service lifecycle (install/uninstall via sc.exe, run mode)
│   ├── config.rs            # Configuration loading and validation
│   ├── exports.rs           # Export directory management and file handle resolution
│   ├── logging.rs           # Log initialization and rotation
│   └── nfs/
│       ├── mod.rs           # Unified NFS server (TCP + UDP, v3 + v4, TLS)
│       ├── nfs4.rs          # NFSv4.1 protocol implementation (~3350 lines)
│       ├── protocol.rs      # NFSv3 protocol implementation
│       ├── mount.rs         # MOUNT protocol (v1/v3)
│       └── portmap.rs       # PORTMAP / RPCBIND service
├── build.rs                 # Build script
├── config.example.toml       # Example configuration
├── install.bat               # One-click install script
├── uninstall.bat             # One-click uninstall script
├── Cargo.toml                # Package manifest
├── README_zh.md              # Chinese README
└── README.md                 # This file
```

## Quick Start

### Prerequisites

- Rust 1.70+ (install from [rustup.rs](https://rustup.rs/))
- Windows 10/11 or Windows Server 2016+
- Visual Studio Build Tools (C++ workload)

### Build

```bash
cargo build --release
```

The binary is at `target/release/rustnfssvc.exe`.

### Configure

If there is configuration file `config.toml` just under the same folder of `rustnfssvc.exe`, it will be used as default config.

Copy the example config and edit it:

```bash
copy config.example.toml "C:\ProgramData\RustNfsSvc\config.toml"
```

Edit `C:\ProgramData\RustNfsSvc\config.toml` to set your export paths and client access rules.

### Run

**Standalone mode** (for testing):

```bash
rustnfssvc.exe
```

**As a Windows Service** (requires Administrator):

```batch
:: Install
install.bat

:: Start
net start rustnfssvc

:: Stop
net stop rustnfssvc

:: Uninstall
uninstall.bat
```

## Configuration

Configuration is loaded from `C:\ProgramData\RustNfsSvc\config.toml`. See `config.example.toml` for a complete reference.

```toml
[nfs]
listen_address = "0.0.0.0:2049"
enable_v3 = true
enable_v4 = true
threads = 4
bind_ip = "0.0.0.0"                # Bind to specific IP for security
max_connections = 128              # Global concurrent connection limit
max_conn_rate_per_ip = 60          # Per-IP rate limit (connections per 60s window)
enable_udp = true                  # Enable UDP (set false for production with TLS)

[tls]                              # SEC-015: TLS encryption
enabled = false
cert_path = ""                     # PEM certificate path (required when enabled)
key_path = ""                      # PEM private key path (PKCS8 or PKCS1 RSA)

[[exports.entries]]
path = "C:\\Shared"
alias = "shared"
allowed_clients = ["192.168.1.0/24"]
options = ["rw", "sync", "no_subtree_check"]

[logging]
level = "info"
file = "C:\\ProgramData\\RustNfsSvc\\logs\\rustnfssvc.log"
max_log_size_mb = 100
max_log_files = 10
```

### Export Options

| Option | Description |
|--------|-------------|
| `rw` | Read-write access (default) |
| `ro` | Read-only access |
| `sync` | Synchronous writes |
| `async` | Asynchronous writes |
| `no_subtree_check` | Disable subtree checking (better performance) |
| `insecure` | Allow connections from ports ≥ 1024 |
| `no_root_squash` | Allow root to access files as root |

### TLS Configuration

RustNfsSvc supports built-in TLS encryption for NFS traffic over TCP. When enabled, the server uses **rustls** (ring backend) to encrypt all NFS/MOUNT/PORTMAP TCP connections.

#### Enabling TLS

1. **Generate certificates** — Create a PEM certificate and private key for the server:

   ```bash
   # Using OpenSSL
   openssl req -x509 -newkey rsa:2048 -keyout server.key -out server.crt -days 365 -nodes \
     -subj "/CN=nfs-server" -addext "subjectAltName=IP:192.168.1.1"

   # Convert key to PKCS8 (preferred by rustls)
   openssl pkcs8 -topk8 -nocrypt -in server.key -out server.key.pkcs8
   ```

2. **Configure** — Edit `config.toml`:

   ```toml
   [tls]
   enabled = true
   cert_path = "C:/etc/rustnfssvc/server.crt"
   key_path  = "C:/etc/rustnfssvc/server.key"    # PKCS8 or PKCS1 RSA accepted
   ```

3. **Disable UDP** — TLS only works over TCP. Set `enable_udp = false` when using TLS.

4. **Restart** — Restart the service for TLS to take effect.

#### Client-side Mount with TLS

Linux NFS clients do not natively support TLS. Use **stunnel** to create an encrypted tunnel:

**On the client (Linux):**

1. Install stunnel:

   ```bash
   sudo apt install stunnel4    # Debian/Ubuntu
   sudo yum install stunnel     # RHEL/CentOS
   ```

2. Create `/etc/stunnel/nfs.conf`:

   ```ini
   [nfs]
   client = yes
   accept = 127.0.0.1:2049
   connect = <server-ip>:2049
   verifyChain = yes
   CApath = /etc/ssl/certs
   ; Or specify the server cert directly:
   ; CAfile = /path/to/server.crt
   ```

3. Start stunnel:

   ```bash
   sudo systemctl start stunnel4
   ```

4. Mount via the local tunnel:

   ```bash
   sudo mount -t nfs4 -o vers=4,minorversion=1 127.0.0.1:/<alias> /mnt/shared
   ```

> **Note:** When using stunnel on both sides, the NFS mount address is always `127.0.0.1` (the local tunnel endpoint), not the server's real IP.

#### Using stunnel on the Server Side (Alternative)

If you prefer not to use the built-in TLS, you can also run stunnel on the server side to wrap the NFS port:

**On the server (Windows):**

1. Download [stunnel for Windows](https://www.stunnel.org/downloads.html).
2. Create `stunnel.conf`:

   ```ini
   [nfs]
   accept = 2049
   connect = 127.0.0.1:12049
   cert = C:/etc/rustnfssvc/server.crt
   key = C:/etc/rustnfssvc/server.key
   ```

3. Configure RustNfsSvc to listen on the internal port:

   ```toml
   [nfs]
   listen_address = "127.0.0.1:12049"
   ```

4. Start stunnel, then start RustNfsSvc. Stunnel will encrypt traffic on port 2049 and forward to the internal NFS port.

## Client Mount

### NFSv4.1 (recommended)

```bash
sudo mount -t nfs4 -o vers=4,minorversion=1 <server-ip>:/<alias> /mnt/shared
```

### NFSv3

```bash
sudo mount -t nfs -o vers=3 <server-ip>:/<alias> /mnt/shared
```

### Verify

```bash
ls /mnt/shared
echo "hello from NFS" > /mnt/shared/test.txt
```

## Architecture

```
                        ┌─────────────────────┐
   Linux NFS Client ───│  NFSv4.1 (TCP/2049) │───┐
   Linux NFS Client ───│  NFSv3  (TCP/2049)  │───┤
   Linux NFS Client ───│  NFSv3  (UDP/2049)  │───┤
                        └─────────────────────┘   │
                        ┌─────────────────────┐   │
   mount.nfs ──────────│  MOUNT  (TCP/20048) │───┤
   mount.nfs ──────────│  MOUNT  (UDP/20048) │───┤
                        └─────────────────────┘   │
                        ┌─────────────────────┐   │
   rpcinfo ────────────│  PORTMAP (TCP/111)  │───┤
   rpcinfo ────────────│  PORTMAP (UDP/111)  │───┤
                        └─────────────────────┘   │
                                                   ▼
                                         ┌─────────────────┐
                                         │  ExportsManager │
                                         │  (C:\exports\...) │
                                         └─────────────────┘
```

- **Unified listener** — A single TCP/UDP listener on port 2049 handles both NFSv3 and NFSv4.1 requests, dispatching by RPC program version
- **ExportsManager** — Manages file handle resolution, directory enumeration, and file I/O against the local Windows filesystem
- **Session management** — NFSv4.1 sessions with slot/sequence tracking for exactly-once semantics

## Development

```bash
# Run in debug mode
cargo run

# Run tests
cargo test

# Format code
cargo fmt

# Lint
cargo clippy
```

## Protocol Compliance

| Protocol | RFC | Status |
|----------|-----|--------|
| NFSv3 | [RFC 1813](https://www.rfc-editor.org/rfc/rfc1813) | Supported |
| NFSv4.0 | [RFC 3010](https://www.rfc-editor.org/rfc/rfc3010) | Partial |
| NFSv4.1 | [RFC 5661](https://www.rfc-editor.org/rfc/rfc5661) | Supported |
| MOUNT v1 | [RFC 1094](https://www.rfc-editor.org/rfc/rfc1094) | Supported |
| MOUNT v3 | [RFC 1813](https://www.rfc-editor.org/rfc/rfc1813) | Supported |
| PORTMAP v2 | [RFC 1057](https://www.rfc-editor.org/rfc/rfc1057) | Supported |

## License

[GPL-3.0](LICENSE)
