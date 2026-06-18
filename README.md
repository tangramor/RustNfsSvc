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
- **Structured logging** — Rolling log files with configurable level and rotation

## Project Structure

```
RustNfsSvc/
├── src/
│   ├── main.rs              # Entry point: CLI arg parsing (install/uninstall/service/standalone)
│   ├── service.rs           # Windows Service lifecycle (install/uninstall via sc.exe, run mode)
│   ├── config.rs            # Configuration loading and validation
│   ├── exports.rs           # Export directory management and file handle resolution
│   ├── logging.rs           # Log initialization and rotation
│   ├── path_ext.rs          # Extended path handling (Windows-specific)
│   └── nfs/
│       ├── mod.rs           # Unified NFS server (TCP + UDP, v3 + v4)
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
bind_ip = "0.0.0.0"               # SEC-014
max_connections = 128             # SEC-025
max_conn_rate_per_ip = 10         # SEC-025
enable_udp = true                 # SEC-026 (Suggest false for production)

[tls]                             # SEC-015
enabled = false
cert_path = ""
key_path = ""

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

Administrator run the following command to enable the registry option to eliminate the path limit in combination with the manifest:

```powershell
New-ItemProperty `
  -Path "HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem" `
  -Name LongPathsEnabled -Value 1 -PropertyType DWORD -Force
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
