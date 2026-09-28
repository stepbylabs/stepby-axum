# Stepby Axum Backend

Stepby 系统的后端服务，基于 **Rust (Axum + SeaORM + Redis)** 构建，为 Stepby 管理系统提供完整的 RESTful API 与实时能力。整体介绍与前端入口请见[根仓库 README](../README.md)。

## 核心能力

- **认证与权限**：JWT + Redis 在线状态、Argon2id 密码哈希、TOTP 多因子、RBAC 角色权限、数据权限
- **消息与通知**：邮件/站内信渠道 + 模板变量渲染 + 失败重试队列、消息偏好与免打扰
- **定时任务**：基于 `tokio-cron-scheduler` 的调度内核与任务管理
- **系统备份**：数据库备份日志与一套可恢复的备份能力
- **报表中心**：报表定义/快照 + 定时计算与邮件/站内信订阅推送
- **系统监控**：慢请求/错误日志聚合、Redis 指标、Prometheus `/metrics` 端点、实时日志查看
- **代码生成**：基于 Tera 模板的 8 类产物（entity/repository/service/handler/router/api/migration）生成
- **文件存储抽象**：`StorageBackend` 抽象，本地磁盘与 S3 兼容对象存储间无缝切换

## 快速开始

```bash
cp config/config.toml.example config/config.toml   # 填写数据库/Redis/JWT 等配置

cargo run -p migration    # 执行数据库迁移
cargo run                 # 启动服务，默认监听 http://0.0.0.0:8080
```

更完整的配置与环境变量说明、多数据库支持、Docker/Helm 部署指引，请参考根仓库 [`README.md`](../README.md)。

## 测试与质量

```bash
cargo test --workspace     # 单元测试 + 集成测试
cargo clippy -- -D warnings # 静态检查，0 告警
```

## SSO/OIDC Provider 全链路真实验证

`scripts/e2e_sso_oidc.py`（仅标准库）对运行中的服务执行 11 步真实 HTTP 验证：
login → client 创建（RS256 keygen）→ authorize(code) → token 兑换（RS256
id_token + refresh_token 30d）→ id_token claims（acr/amr/tid）→ JWKS 公钥
独立 RSA 验签 → userinfo → refresh 轮换 → 旧 RT 重放拒绝 → revoke 即时失效
→ /metrics SSO 事件序列。

```bash
# 前置：.env 配置 SSO_ENABLED=true / SSO_ISSUER=http://127.0.0.1:8080 / CONFIG_ENC_KEY
docker compose up -d redis && cargo run          # 终端 1
python scripts/e2e_sso_oidc.py                   # 终端 2（--base 可指定地址）
```

## License

[MIT](LICENSE)，Copyright (c) 2024-2026 Stepby。