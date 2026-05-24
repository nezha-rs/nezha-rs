# Nezha Rust Rewrite

这是哪吒监控的 Rust 重构版，目标是在不依赖 Go 运行时代码的前提下，保持与上游 Nezha Dashboard / Agent 可见行为、gRPC 协议、HTTP API 和运维入口的兼容。

当前仓库包含 Rust Dashboard、Rust Agent、共享核心模型和 gRPC 协议生成代码，适合用于兼容性验证、二次开发和 Rust 版运行时预览。

## 功能状态

- Rust workspace 已拆分为 `nezha-dashboard`、`nezha-agent`、`nezha-core`、`nezha-proto`。
- Dashboard 支持 gRPC Agent 接入、HTTP API、管理员登录、JWT、SQLite 持久化、服务监控、告警、计划任务、通知、DDNS、NAT、WAF、TSDB、i18n 和前端模板回退。
- Agent 支持主机信息和状态上报、HTTP GET、TCP ping、ICMP ping、命令执行、终端、文件管理、NAT、配置上报/下发、GeoIP 上报、自更新、系统服务安装和交互式配置编辑。
- `protoc` 通过 `protoc-bin-vendored` 自动提供，源码构建时通常不需要单独安装 protobuf 编译器。
- 官方/第三方前端发布产物可同步到 `static/*-dist`，并在后续构建时嵌入 Dashboard 二进制。

更详细的兼容性记录见 [docs/parity.md](docs/parity.md)，迁移路线见 [docs/migration.md](docs/migration.md)。

## 环境要求

- Rust toolchain：`1.95` 或更新版本
- Cargo
- Windows、Linux 或 macOS
- Linux 上安装 Agent 系统服务需要 `systemd`
- macOS 上安装 Agent 系统服务使用 `launchd`

建议先确认 Rust 版本：

```bash
rustc --version
cargo --version
```

## 获取源码

```bash
git clone https://github.com/nezha-rs/nezha-rs.git
cd nezha-rs
```

如果你使用自己的 fork，请把仓库地址替换成你的 GitHub 地址。

## 构建

开发构建：

```bash
cargo build --workspace
```

发布构建：

```bash
cargo build --workspace --release
```

构建完成后，二进制位于：

- Debug：`target/debug/nezha-dashboard`、`target/debug/nezha-agent`
- Release：`target/release/nezha-dashboard`、`target/release/nezha-agent`
- Windows 下文件名带 `.exe` 后缀

## 同步前端资源

Dashboard 可以直接服务已经同步到 `static/` 的前端模板。首次发布或更新前端模板时，建议执行：

```bash
cargo run -p nezha-dashboard -- sync-frontends
```

同步完成后，`static/*-dist` 会被后续 Dashboard 构建嵌入到二进制中。这样部署时即使运行目录没有外部 `static/` 目录，Dashboard 仍可返回用户前台、管理后台和相关静态资源。

## 快速启动 Dashboard

开发环境可以直接用 `cargo run` 启动：

```bash
RUST_LOG=info cargo run -p nezha-dashboard -- \
  --bind 0.0.0.0:5555 \
  --http-bind 0.0.0.0:8008 \
  --client-secret secret \
  --admin-username admin \
  --admin-password admin \
  --jwt-secret change-me
```

PowerShell 示例：

```powershell
$env:RUST_LOG = "info"
cargo run -p nezha-dashboard -- `
  --bind 0.0.0.0:5555 `
  --http-bind 0.0.0.0:8008 `
  --client-secret secret `
  --admin-username admin `
  --admin-password admin `
  --jwt-secret change-me
```

启动后访问：

- 用户前台：`http://127.0.0.1:8008/`
- 管理后台：`http://127.0.0.1:8008/dashboard/`
- gRPC Agent 接入地址：`127.0.0.1:5555`

默认数据库文件为 `data/sqlite.db`。生产环境请务必替换 `--client-secret`、`--admin-password` 和 `--jwt-secret`。

## 使用 Release 二进制启动 Dashboard

Linux / macOS：

```bash
RUST_LOG=info ./target/release/nezha-dashboard \
  --bind 0.0.0.0:5555 \
  --http-bind 0.0.0.0:8008 \
  --client-secret secret \
  --admin-username admin \
  --admin-password admin \
  --jwt-secret change-me
```

Windows PowerShell：

```powershell
$env:RUST_LOG = "info"
.\target\release\nezha-dashboard.exe `
  --bind 0.0.0.0:5555 `
  --http-bind 0.0.0.0:8008 `
  --client-secret secret `
  --admin-username admin `
  --admin-password admin `
  --jwt-secret change-me
```

## Dashboard 常用参数

```text
--bind <ADDR>                 gRPC 监听地址，默认 0.0.0.0:5555
--http-bind <ADDR>            HTTP 监听地址，默认 0.0.0.0:8008
-c, --config <PATH>           Dashboard 配置文件，默认 data/config.yaml
--client-secret <SECRET>      Agent 接入密钥，也可用 NZ_CLIENT_SECRET
--data <PATH>                 SQLite 数据库路径，默认 data/sqlite.db
--admin-username <USER>       初始管理员用户名，默认 admin
--admin-password <PASSWORD>   初始管理员密码，默认 admin
--jwt-secret <SECRET>         JWT 签名密钥
--jwt-timeout <HOURS>         JWT 过期时间，默认 1
--site-name <NAME>            站点名称，默认 Nezha
--debug                       开启调试模式，调试模式下暴露 /swagger
--force-auth                  强制前台鉴权
--install-host <URL>          面板公开访问地址，用于安装提示和配置下发
--static-dir <PATH>           静态资源目录，默认 static
--geoip-db <PATH>             GeoIP 数据库路径，默认 data/geoip.db
```

也支持从 `data/config.yaml` 读取上游风格的部分配置，例如：

```yaml
agent_secret_key: secret
jwt_secret_key: change-me
jwt_timeout: 24
listen_host: 0.0.0.0
listen_port: 8008
site_name: Nezha
install_host: https://nezha.example.com
tls: false
force_auth: false
debug: false
```

## 启动 Agent

Agent 配置文件默认是 `config.yml`。最小配置如下：

```yaml
server: 127.0.0.1:5555
client_secret: secret
tls: false
report_delay: 3
```

运行 Agent：

```bash
RUST_LOG=info cargo run -p nezha-agent -- --config config.yml
```

PowerShell：

```powershell
$env:RUST_LOG = "info"
cargo run -p nezha-agent -- --config config.yml
```

也可以用环境变量覆盖配置文件：

```bash
NZ_SERVER=127.0.0.1:5555 \
NZ_CLIENT_SECRET=secret \
RUST_LOG=info \
cargo run -p nezha-agent -- --config config.yml
```

PowerShell：

```powershell
$env:NZ_SERVER = "127.0.0.1:5555"
$env:NZ_CLIENT_SECRET = "secret"
$env:RUST_LOG = "info"
cargo run -p nezha-agent -- --config config.yml
```

## Agent 配置项

常用配置：

```yaml
server: 127.0.0.1:5555
client_secret: secret
uuid: 00000000-0000-0000-0000-000000000000
debug: false
tls: false
insecure_tls: false
report_delay: 3
ip_report_period: 1800
self_update_period: 0
gpu: false
temperature: false
skip_connection_count: false
skip_procs_count: false
disable_auto_update: false
disable_force_update: false
disable_command_execute: false
disable_nat: false
disable_send_query: false
use_ipv6_country_code: false
use_gitee_to_upgrade: false
use_atomgit_to_upgrade: false
dns: []
custom_ip_api: []
hard_drive_partition_allowlist: []
nic_allowlist: {}
```

常用环境变量覆盖：

```text
NZ_SERVER
NZ_CLIENT_SECRET
NZ_UUID
NZ_DEBUG
NZ_TLS
NZ_INSECURE_TLS
NZ_REPORT_DELAY
NZ_IP_REPORT_PERIOD
NZ_SELF_UPDATE_PERIOD
NZ_GPU
NZ_TEMPERATURE
NZ_SKIP_CONNECTION_COUNT
NZ_SKIP_PROCS_COUNT
NZ_DISABLE_AUTO_UPDATE
NZ_DISABLE_FORCE_UPDATE
NZ_DISABLE_COMMAND_EXECUTE
NZ_DISABLE_NAT
NZ_DISABLE_SEND_QUERY
NZ_USE_IPV6_COUNTRY_CODE
NZ_USE_GITEE_TO_UPGRADE
NZ_USE_ATOMGIT_TO_UPGRADE
NZ_DNS
NZ_CUSTOM_IP_API
```

其中 `NZ_DNS` 和 `NZ_CUSTOM_IP_API` 使用英文逗号分隔多个值。

## Agent 交互式编辑

Agent 提供上游风格的交互式配置编辑命令：

```bash
cargo run -p nezha-agent -- --config config.yml edit
```

Release 二进制示例：

```bash
./target/release/nezha-agent --config /etc/nezha/config.yml edit
```

## 安装 Agent 系统服务

先准备好可执行文件和配置文件，然后执行：

```bash
./nezha-agent --config /etc/nezha/config.yml service install
./nezha-agent --config /etc/nezha/config.yml service start
```

可用动作：

```text
install
uninstall
start
stop
restart
```

Linux 使用 systemd unit，Windows 使用 `sc.exe`，macOS 使用 launchd plist。安装或卸载系统服务通常需要管理员/root 权限。

## API 文档

Dashboard 在 `--debug` 或 `NZ_DEBUG=true` 时启用 Swagger UI：

```bash
RUST_LOG=info cargo run -p nezha-dashboard -- \
  --client-secret secret \
  --admin-password admin \
  --jwt-secret change-me \
  --debug
```

访问：

```text
http://127.0.0.1:8008/swagger/
```

生产环境不建议开启 `--debug`。

## 反向代理提示

常见部署方式是：

- HTTP 管理面板代理到 `127.0.0.1:8008`
- gRPC Agent 入口代理到 `127.0.0.1:5555`
- 如果 Agent 通过 TLS 连接面板，Agent 配置中设置 `tls: true`
- 如果使用自签名证书或测试证书，可临时设置 `insecure_tls: true`

生产环境建议使用可信证书，并避免长期启用 `insecure_tls`。

## 开发验证

提交前建议运行：

```bash
cargo fmt --all -- --check
cargo check --workspace
cargo test --workspace
```

如果你刚同步过前端模板，并希望确认嵌入资源可用，可以在缺失外部静态目录的情况下启动 Dashboard：

```bash
./target/release/nezha-dashboard \
  --client-secret secret \
  --bind 127.0.0.1:5560 \
  --http-bind 127.0.0.1:8012 \
  --static-dir __missing_static_dir__
```

然后访问：

```text
http://127.0.0.1:8012/
http://127.0.0.1:8012/dashboard/login
```

## 仓库结构

```text
crates/
  nezha-agent/       Rust Agent
  nezha-core/        共享配置、任务类型和业务模型
  nezha-dashboard/   Rust Dashboard gRPC/HTTP 运行时
  nezha-proto/       Nezha gRPC proto 与 tonic/prost 生成入口
docs/
  migration.md       迁移计划
  parity.md          兼容性检查记录
static/
  *-dist/            已同步的前端模板发布产物
```

## 许可证

Apache-2.0
