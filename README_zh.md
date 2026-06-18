# RustNfsSvc

[English](./README.md) | 中文

一个高性能的 Windows NFS（网络文件系统）服务器，使用 Rust 编写。同时支持 NFSv3 和 NFSv4.1，使 Linux/Unix 客户端能够透明挂载 Windows 目录。

## 功能特性

- **NFSv3** — 完整协议支持（MOUNT、PORTMAP、NFSv3 过程）
- **NFSv4.1** — COMPOUND 操作、SEQUENCE、OPEN、CLOSE、READ、WRITE、READDIR、LOCK/LOCKU、SETATTR 等
- **原生 Windows 服务** — 可安装/卸载为 Windows 服务，支持开机自启
- **双栈 NFS** — 在同一端口（2049）上同时运行 NFSv3 和 NFSv4.1
- **MOUNT 协议** — NFSv3 MOUNT 协议，端口 20048
- **PORTMAP** — RPC 端口映射服务，端口 111（TCP + UDP）
- **异步 I/O** — 基于 Tokio 构建，支持高并发
- **灵活配置** — 基于 TOML 的配置文件，支持按导出目录的访问控制（CIDR）
- **结构化日志** — 滚动日志文件，可配置日志级别和轮转策略

## 项目结构

```
RustNfsSvc/
├── src/
│   ├── main.rs              # 入口：CLI 参数解析（install/uninstall/service/独立运行）
│   ├── service.rs           # Windows 服务生命周期（通过 sc.exe 安装/卸载，运行模式）
│   ├── config.rs            # 配置加载与验证
│   ├── exports.rs           # 导出目录管理与文件句柄解析
│   ├── logging.rs           # 日志初始化与轮转
│   ├── path_ext.rs          # 扩展路径前缀（如 `\\?\`）
│   └── nfs/
│       ├── mod.rs           # 统一 NFS 服务器（TCP + UDP，v3 + v4）
│       ├── nfs4.rs          # NFSv4.1 协议实现（约 3350 行）
│       ├── protocol.rs      # NFSv3 协议实现
│       ├── mount.rs         # MOUNT 协议（v1/v3）
│       └── portmap.rs       # PORTMAP / RPCBIND 服务
├── build.rs                 # 构建脚本
├── config.example.toml       # 配置示例
├── install.bat               # 一键安装脚本
├── uninstall.bat             # 一键卸载脚本
├── Cargo.toml                # 包清单
├── README_zh.md              # 中文说明文档
└── README.md                 # 英文说明文档
```

## 快速开始

### 前置要求

- Rust 1.70+（从 [rustup.rs](https://rustup.rs/) 安装）
- Windows 10/11 或 Windows Server 2016+
- Visual Studio Build Tools（C++ 工作负载）

### 构建

```bash
cargo build --release
```

编译产物位于 `target/release/rustnfssvc.exe`。

### 配置

如果在 `rustnfssvc.exe` 同目录下存在 `config.toml`，将作为默认配置使用。

复制示例配置并编辑：

```bash
copy config.example.toml "C:\ProgramData\RustNfsSvc\config.toml"
```

编辑 `C:\ProgramData\RustNfsSvc\config.toml`，设置导出路径和客户端访问规则。

### 运行

**独立运行模式**（用于测试）：

```bash
rustnfssvc.exe
```

**作为 Windows 服务运行**（需要管理员权限）：

```batch
:: 安装
install.bat

:: 启动
net start rustnfssvc

:: 停止
net stop rustnfssvc

:: 卸载
uninstall.bat
```

## 配置说明

配置文件从 `C:\ProgramData\RustNfsSvc\config.toml` 加载。完整配置参考见 `config.example.toml`。

```toml
[nfs]
listen_address = "0.0.0.0:2049"
enable_v3 = true
enable_v4 = true
threads = 4
bind_ip = "0.0.0.0"               # SEC-014
max_connections = 128             # SEC-025
max_conn_rate_per_ip = 10         # SEC-025
enable_udp = true                 # SEC-026 (生产建议 false)

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

管理员运行以下命令开启注册表选项，配合 manifest 彻底消除路径限制：

```powershell
New-ItemProperty `
  -Path "HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem" `
  -Name LongPathsEnabled -Value 1 -PropertyType DWORD -Force
```

### 导出选项

| 选项 | 说明 |
|------|------|
| `rw` | 读写访问（默认） |
| `ro` | 只读访问 |
| `sync` | 同步写入 |
| `async` | 异步写入 |
| `no_subtree_check` | 禁用子树检查（性能更好） |
| `insecure` | 允许来自 ≥ 1024 端口的连接 |
| `no_root_squash` | 允许 root 用户以 root 身份访问文件 |

## 客户端挂载

### NFSv4.1（推荐）

```bash
sudo mount -t nfs4 -o vers=4,minorversion=1 <服务器IP>:/<别名> /mnt/shared
```

### NFSv3

```bash
sudo mount -t nfs -o vers=3 <服务器IP>:/<别名> /mnt/shared
```

### 验证

```bash
ls /mnt/shared
echo "hello from NFS" > /mnt/shared/test.txt
```

## 架构

```
                        ┌─────────────────────┐
   Linux NFS 客户端 ───│  NFSv4.1 (TCP/2049) │───┐
   Linux NFS 客户端 ───│  NFSv3  (TCP/2049)  │───┤
   Linux NFS 客户端 ───│  NFSv3  (UDP/2049)  │───┤
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

- **统一监听器** — 在端口 2049 上通过单个 TCP/UDP 监听器同时处理 NFSv3 和 NFSv4.1 请求，按 RPC 程序版本分发
- **ExportsManager** — 管理文件句柄解析、目录枚举和针对本地 Windows 文件系统的文件 I/O
- **会话管理** — NFSv4.1 会话使用槽位/序列跟踪，实现恰好一次语义

## 开发

```bash
# 以调试模式运行
cargo run

# 运行测试
cargo test

# 格式化代码
cargo fmt

# 代码检查
cargo clippy
```

## 协议合规性

| 协议 | RFC | 状态 |
|------|-----|------|
| NFSv3 | [RFC 1813](https://www.rfc-editor.org/rfc/rfc1813) | 已支持 |
| NFSv4.0 | [RFC 3010](https://www.rfc-editor.org/rfc/rfc3010) | 部分支持 |
| NFSv4.1 | [RFC 5661](https://www.rfc-editor.org/rfc/rfc5661) | 已支持 |
| MOUNT v1 | [RFC 1094](https://www.rfc-editor.org/rfc/rfc1094) | 已支持 |
| MOUNT v3 | [RFC 1813](https://www.rfc-editor.org/rfc/rfc1813) | 已支持 |
| PORTMAP v2 | [RFC 1057](https://www.rfc-editor.org/rfc/rfc1057) | 已支持 |

## 许可证

[GPL-3.0](LICENSE)
