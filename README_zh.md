# RustNfsSvc

[English](./README.md) | 中文

一个高性能的 Windows NFS（网络文件系统）服务器，使用 Rust 编写。支持 NFSv3、NFSv4.1 和 NFSv4.2，使 Linux/Unix 客户端能够透明挂载 Windows 目录。

## 功能特性

- **NFSv3** — 完整协议支持（MOUNT、PORTMAP、NFSv3 过程）
- **NFSv4.1** — COMPOUND 操作、SEQUENCE、OPEN、CLOSE、READ、WRITE、READDIR、LOCK/LOCKU、SETATTR 等
- **NFSv4.2** — READ_PLUS、COPY、SEEK、CLONE，以及 RFC 7862 定义的 9 个 stub 操作
- **原生 Windows 服务** — 可安装/卸载为 Windows 服务，支持开机自启
- **双栈 NFS** — 在同一端口（2049）上同时运行 NFSv3、NFSv4.1 和 NFSv4.2
- **MOUNT 协议** — NFSv3 MOUNT 协议，端口 20048
- **PORTMAP** — RPC 端口映射服务，端口 111（TCP + UDP）
- **异步 I/O** — 基于 Tokio 构建，支持高并发
- **灵活配置** — 基于 TOML 的配置文件，支持按导出目录的访问控制（CIDR）
- **TLS 加密** — 内置 TLS 支持（rustls），加密 NFS 传输流量（SEC-015）
- **结构化日志** — 滚动日志文件，可配置日志级别和轮转策略

## 项目结构

```
RustNfsSvc/
├── src/
│   ├── main.rs              # 入口：CLI 参数解析（install/uninstall/service/独立运行）
│   ├── path_ext.rs          # Windows \\?\ 扩展路径辅助（MAX_PATH 修复）
│   ├── service.rs           # Windows 服务生命周期（通过 sc.exe 安装/卸载，运行模式）
│   ├── config.rs            # 配置加载与验证
│   ├── exports.rs           # 导出目录管理与文件句柄解析
│   ├── logging.rs           # 日志初始化与轮转
│   └── nfs/
│       ├── mod.rs           # 统一 NFS 服务器（TCP + UDP，v3 + v4，TLS）
│       ├── nfs4.rs          # NFSv4.1/4.2 协议实现（约 4100 行）
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
bind_ip = "0.0.0.0"                # 绑定到特定 IP 以增强安全性
max_connections = 128              # 全局并发连接上限
max_conn_rate_per_ip = 60          # 单 IP 连接速率限制（每 60s 窗口）
enable_udp = true                  # 启用 UDP（使用 TLS 时建议设为 false）

[tls]                              # SEC-015：TLS 加密
enabled = false
cert_path = ""                     # PEM 证书路径（启用时必填）
key_path = ""                      # PEM 私钥路径（PKCS8 或 PKCS1 RSA 均可）

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

### TLS 加密配置

RustNfsSvc 支持内置 TLS 加密 NFS TCP 流量。启用后，服务器使用 **rustls**（ring 后端）加密所有 NFS/MOUNT/PORTMAP TCP 连接。

#### 启用 TLS

1. **生成证书** — 为服务器创建 PEM 格式的证书和私钥：

   ```bash
   # 使用 OpenSSL
   openssl req -x509 -newkey rsa:2048 -keyout server.key -out server.crt -days 365 -nodes \
     -subj "/CN=nfs-server" -addext "subjectAltName=IP:192.168.1.1"

   # 将密钥转为 PKCS8 格式（rustls 推荐）
   openssl pkcs8 -topk8 -nocrypt -in server.key -out server.key.pkcs8
   ```

2. **配置** — 编辑 `config.toml`：

   ```toml
   [tls]
   enabled = true
   cert_path = "C:/etc/rustnfssvc/server.crt"
   key_path  = "C:/etc/rustnfssvc/server.key"    # 接受 PKCS8 或 PKCS1 RSA 格式
   ```

3. **禁用 UDP** — TLS 仅支持 TCP。启用 TLS 时设置 `enable_udp = false`。

4. **重启服务** — 重启使 TLS 生效。

#### 客户端使用 stunnel 挂载

Linux NFS 客户端原生不支持 TLS。使用 **stunnel** 建立加密隧道：

**在客户端（Linux）上：**

1. 安装 stunnel：

   ```bash
   sudo apt install stunnel4    # Debian/Ubuntu
   sudo yum install stunnel     # RHEL/CentOS
   ```

2. 创建 `/etc/stunnel/nfs.conf`：

   ```ini
   [nfs]
   client = yes
   accept = 127.0.0.1:2049
   connect = <服务器IP>:2049
   verifyChain = yes
   CApath = /etc/ssl/certs
   ; 或直接指定服务器证书：
   ; CAfile = /path/to/server.crt
   ```

3. 启动 stunnel：

   ```bash
   sudo systemctl start stunnel4
   ```

4. 通过本地隧道挂载：

   ```bash
   sudo mount -t nfs4 -o vers=4,minorversion=1 127.0.0.1:/<别名> /mnt/shared
   ```

> **注意：** 使用 stunnel 时，NFS 挂载地址始终是 `127.0.0.1`（本地隧道端点），而非服务器的真实 IP。

#### 服务器端使用 stunnel（替代方案）

如果不使用内置 TLS，也可以在服务器端运行 stunnel 来包装 NFS 端口：

**在服务器（Windows）上：**

1. 从 [stunnel 官网](https://www.stunnel.org/downloads.html) 下载 Windows 版本。
2. 创建 `stunnel.conf`：

   ```ini
   [nfs]
   accept = 2049
   connect = 127.0.0.1:12049
   cert = C:/etc/rustnfssvc/server.crt
   key = C:/etc/rustnfssvc/server.key
   ```

3. 配置 RustNfsSvc 监听内部端口：

   ```toml
   [nfs]
   listen_address = "127.0.0.1:12049"
   ```

4. 先启动 stunnel，再启动 RustNfsSvc。stunnel 将加密端口 2049 上的流量，并转发到内部 NFS 端口。

## 客户端挂载

### NFSv4.2（推荐）

```bash
sudo mount -t nfs4 -o vers=4,minorversion=2 <服务器IP>:/<别名> /mnt/shared
```

### NFSv4.1

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
   Linux NFS 客户端 ───│  NFSv4.2 (TCP/2049) │───┐
   Linux NFS 客户端 ───│  NFSv4.1 (TCP/2049) │───┤
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

- **统一监听器** — 在端口 2049 上通过单个 TCP/UDP 监听器同时处理 NFSv3、NFSv4.1 和 NFSv4.2 请求，按 RPC 程序版本分发
- **ExportsManager** — 管理文件句柄解析、目录枚举和针对本地 Windows 文件系统的文件 I/O
- **会话管理** — NFSv4.1/4.2 会话使用槽位/序列跟踪，实现恰好一次语义

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
| NFSv4.2 | [RFC 7862](https://www.rfc-editor.org/rfc/rfc7862) | 已支持 |
| MOUNT v1 | [RFC 1094](https://www.rfc-editor.org/rfc/rfc1094) | 已支持 |
| MOUNT v3 | [RFC 1813](https://www.rfc-editor.org/rfc/rfc1813) | 已支持 |
| PORTMAP v2 | [RFC 1057](https://www.rfc-editor.org/rfc/rfc1057) | 已支持 |

### NFSv4.2 操作（RFC 7862）

| 操作 | 操作码 | 状态 | 说明 |
|------|--------|------|------|
| READ_PLUS | 68 | ✅ 已支持 | 增强读取，返回数据/空洞信息 |
| COPY | 60 | ✅ 已支持 | 服务器端文件复制（仅同服务器） |
| SEEK | 69 | ✅ 已支持 | 查找文件中下一个数据或空洞偏移 |
| CLONE | 71 | ✅ 已支持 | 服务器端文件范围克隆（读+写） |
| ALLOCATE | 59 | Stub | 返回 NOTSUPP |
| DEALLOCATE | 62 | Stub | 返回 NOTSUPP |
| IO_ADVISE | 63 | Stub | 返回 NOTSUPP |
| LAYOUTERROR | 64 | Stub | 返回 NOTSUPP |
| LAYOUTSTATS | 65 | Stub | 返回 NOTSUPP |
| OFFLOAD_CANCEL | 66 | Stub | 返回 NOTSUPP |
| OFFLOAD_STATUS | 67 | Stub | 返回 NOTSUPP |
| WRITE_SAME | 70 | Stub | 返回 NOTSUPP |
| COPY_NOTIFY | 61 | Stub | 返回 NOTSUPP |

> **注意：** Stub 操作返回 `NFS4ERR_NOTSUPP`。COPY 仅支持同服务器内复制，不支持跨服务器复制。CLONE 为简化的 read+write 实现（未使用 BlockClone API）。SEEK 使用简化模型（SEEK4_HOLE 返回文件大小），因为 Windows 不通过标准 API 暴露稀疏文件空洞信息。

## 许可证

[GPL-3.0](LICENSE)
