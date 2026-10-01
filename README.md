# Stepby Axum

![License](https://img.shields.io/badge/license-MIT-blue)
![Rust](https://img.shields.io/badge/Rust-1.8x-orange?logo=rust)
![Axum](https://img.shields.io/badge/axum-web%20framework-green)
![Tests](https://img.shields.io/badge/tests-1054%20passing-brightgreen)
![Build](https://img.shields.io/badge/build-passing-success)

Stepby 开源中后台管理系统的后端服务，基于 **Rust（axum + sea-orm + tokio）** 构建，提供完整的 RESTful API。配套前端仓库：[stepby-vue](https://github.com/stepbylabs/stepby-vue)。

## ✨ 核心特性

### 认证与安全

- **JWT 认证**：argon2 密码哈希、TOTP 双因子（2FA）、WebAuthn / Passkey 支持
- **权限 fail-closed**：默认拒绝，未显式授权一律拦截
- **敏感操作独立限流**：登录、改密等关键路径单独限流通道
- **日志脱敏**：敏感字段在日志输出前自动掩码
- **验证码开关**：`sys.account.captchaEnabled` 运行时参数控制

### 多租户

- 租户管理、套餐能力位、租户间权限与数据隔离

### SSO / OIDC Provider

- 标准授权码模式，RS256 签名的 id_token
- Refresh Token 轮换与重放拒绝
- SCIM Group 同步
- JWKS 公钥端点，供第三方应用独立验签

### 审批工作流

- 两级审批、超时自动扫描
- 提醒通知与防打扰机制

### 审计合规

- 操作日志差异对比（变更前后明细）
- 审计大屏可视化
- 合规报告导出

### SharedStore 双档共享态

`[cache].mode = auto | local | redis`：

| 档位 | 说明 |
| --- | --- |
| `local` | 业务同库纯 SQL 承载，**单文件零依赖部署**，无 Redis 也能跑 |
| `redis` | Redis + DB 权威层双写，启动回填，适合多实例横向扩展 |

档位切换无缝衔接，`auto` 模式按环境自动选择；`CACHE_MODE` 环境变量可覆盖配置文件。

### 可观测性

- Prometheus `/metrics` 端点
- 慢请求 / 错误日志聚合

## 🏗 架构

```mermaid
flowchart LR
    Browser[浏览器 / 前端 stepby-vue] --> MW[axum 中间件链]
    subgraph MW[axum 中间件链]
        A1[auth 认证]
        A2[permission 权限 fail-closed]
        A3[rate-limit 限流]
        A4[idempotency 幂等]
    end
    MW --> Handler[Handler]
    Handler --> Service[Service 层]
    Service --> Repo[Repository 层]
    Service --> SS[SharedStore]
    Repo --> DB[(SQLite / MySQL / PostgreSQL)]
    SS -->|local 档| DB
    SS -->|redis 档 双写| Redis[(Redis)]
    SS -->|redis 档 权威层| DB
```

## 🚀 快速开始

零配置单文件，3 步启动：

1. 编译或下载 `stepby-axum` 可执行文件（`cargo build --release`，rustls 实现无 OpenSSL 依赖）
2. 双击运行（Linux/macOS 直接执行）——自动创建 SQLite 数据库与 `data/secret.key` 引导密钥，无需任何配置
3. 访问 `http://localhost:8080/health` 验证服务就绪

默认账号：

```
账号：admin
密码：admin123
```

> 首次登录强制修改密码。验证码可通过参数 `sys.account.captchaEnabled` 开关。

### 编译

```bash
# 后端（Rust 1.8x）
cargo build --release

# 前端（Node 20+，pnpm 兼容），见 stepby-vue 仓库
npm install && npm run build:prod
```

## ⚙️ 配置

单文件零配置即可运行；需要定制时创建 `config.toml`（参考 `config.toml.example`）：

| 配置段 | 说明 |
| --- | --- |
| `[server]` | 监听地址与端口、文档开关等 |
| `[database]` | SQLite / MySQL / PostgreSQL 连接（SQLite 默认零配置） |
| `[redis]` | Redis 连接信息（redis 档需要） |
| `[cache]` | SharedStore 档位：`mode = auto \| local \| redis`，环境变量 `CACHE_MODE` 可覆盖 |
| `[features]` | SSO 等功能开关 |

### Docker

`docker-compose.yml` 提供 postgres / redis / mysql 测试基础设施：

```bash
docker compose up -d
```

## 🧪 测试

```bash
cargo test --lib    # 1054 个单元测试通过
```

前端 E2E（Playwright，75 个功能 / 三段）位于前端仓库 `tests/e2e/main.mjs`，详见 [stepby-vue](https://github.com/stepbylabs/stepby-vue)。

## 📄 License

[MIT](LICENSE) © 2026 Stepby
