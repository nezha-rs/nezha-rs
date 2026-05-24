# Migration Plan

## Phase 1: Protocol-Compatible Rust Runtime

目标是让 Rust Agent 和 Rust Dashboard 先通过现有 Nezha gRPC 协议跑通。

- 保持 `proto/nezha.proto` 字段和 RPC 名称兼容。
- Dashboard 先实现 gRPC 入口和内存状态。
- Agent 先实现 Host/State 上报和基础任务。

## Phase 2: Dashboard Domain Model

迁移 Go Dashboard 的核心业务对象。

- Server、ServerGroup、User、Service、Cron、AlertRule。
- 持久化层建议先接 SQLite/PostgreSQL 抽象，避免绑定单一数据库。
- 服务状态与历史指标写入独立 TSDB/metrics 模块。

## Phase 3: Control Plane

迁移控制面接口和鉴权。

- HTTP API、JWT、OAuth2、权限矩阵。
- 终端、文件管理、NAT 的 stream ownership 校验。
- WAF/IP block 逻辑。

## Phase 4: Agent Parity

补齐 Agent 能力。

- GPU、温度、连接数、进程数的跨平台采集。
- ICMP ping、系统服务安装、热重载配置。
- 自更新和区域镜像选择。
- Terminal、NAT、FM 的 IOStream 实现。

## Phase 5: Compatibility Testing

建立 Go/Rust 双向兼容矩阵。

- Go Dashboard + Rust Agent。
- Rust Dashboard + Go Agent。
- Rust Dashboard + Rust Agent。
- 协议 golden tests 和端到端 smoke tests。
