# 工程脚手架与基础框架 任务分解（tasks.md）

> ⚠️ **本文档为初始任务记录，最新依赖以 `spec.md` / `Cargo.toml` 为准。**

> **阶段：** 第一阶段「工程脚手架与基础框架」
> **对应规范：** `docs/spec.md`
> **规则基线：** `axum-backend/.trae/rules/project-rules.md`
> **执行方式：** 按任务顺序逐个执行，每个任务完成后立即提交（frequent commits）

**Goal:** 搭建 axum-backend 工程脚手架，完成全部通用能力（响应/错误/配置/DB/Redis/日志/JWT/中间件/密码/验证码/树/initialize/migration），服务可编译运行并通过健康检查。

**Architecture:** 根 crate 为应用主体 + `migration/` 独立子 crate（workspace），Axum State 注入共享状态，SeaORM 管理数据库连接池，Redis 管理缓存，tracing 记录日志，initialize 模块编排初始化流程。

**Tech Stack:** Axum 0.8 + SeaORM 1.1 + tokio 1 + jsonwebtoken 10 + redis 1.3 + tower-http 0.7 + tracing

---

## 任务总览

| 任务 | 内容 | 产出 |
|------|------|------|
| Task 1 | Cargo.toml 依赖清单 + workspace | `Cargo.toml` |
| Task 2 | 配置文件 | `config/config.toml` |
| Task 3 | 配置管理模块 | `src/config/` |
| Task 4 | 统一响应结构体 | `src/common/response.rs` |
| Task 5 | 全局错误类型 | `src/common/error.rs` |
| Task 6 | 分页参数 + 系统常量 | `src/common/page.rs` `src/common/constants.rs` |
| Task 7 | 数据库连接池 | `src/db/pool.rs` |
| Task 8 | Redis 连接池 | `src/db/redis.rs` |
| Task 9 | 日志体系 | `src/logger.rs` |
| Task 10 | JWT 工具 | `src/jwt/claims.rs` |
| Task 11 | 密码工具 | `src/utils/password.rs` |
| Task 12 | 验证码工具 | `src/utils/captcha.rs` |
| Task 13 | 树构建工具 | `src/utils/tree.rs` |
| Task 14 | AppState 共享状态 | `src/state.rs` |
| Task 15 | 请求 ID 中间件 | `src/middleware/request_id.rs` |
| Task 16 | JWT 鉴权中间件 | `src/middleware/auth.rs` |
| Task 17 | 健康检查 Handler | `src/handler/health.rs` |
| Task 18 | 路由聚合 | `src/router/` |
| Task 19 | initialize 初始化编排 | `src/initialize/mod.rs` |
| Task 20 | 库入口与占位模块 | `src/lib.rs` + 占位模块 |
| Task 21 | 应用入口 main.rs | `src/main.rs` |
| Task 22 | migration 子 crate | `migration/` |
| Task 23 | 编译验证与冒烟测试 | 全项目编译 + 运行验证 |

---

### Task 1: Cargo.toml 依赖清单 + workspace + 基础文件

**Files:**
- Create: `axum-backend/Cargo.toml`
- Create: `axum-backend/src/main.rs`（最小占位版，Task 21 替换为完整版）
- Create: `axum-backend/src/lib.rs`（空占位，Task 20 补全模块声明）
- Create: `axum-backend/.gitignore`

- [ ] **Step 1: 编写完整 Cargo.toml**

```toml
[package]
name = "axum-backend"
version = "0.1.0"
edition = "2024"

[dependencies]
# Web 框架
axum = { version = "0.8", features = ["macros"] }
axum-extra = { version = "0.12", features = ["typed-header"] }

# ORM
sea-orm = { version = "1.1", features = [
    "runtime-tokio-rustls",
    "sqlx-mysql",
    "macros",
    "with-chrono",
    "debug-print",
] }

# 异步运行时
tokio = { version = "1", features = ["rt-multi-thread", "macros", "signal"] }

# JWT
jsonwebtoken = "10"

# 中间件
tower = "0.5"
tower-http = { version = "0.7", features = ["cors", "trace", "compression-gzip"] }

# 序列化
serde = { version = "1", features = ["derive"] }
serde_json = "1"

# 日志
tracing = "0.1"
tracing-subscriber = { version = "0.3", features = ["env-filter", "fmt"] }

# 时间
chrono = { version = "0.4", features = ["serde"] }

# 工具
uuid = { version = "1", features = ["v4"] }
toml = "0.8"
md-5 = "0.10"

# 错误处理
anyhow = "1"

# 校验
garde = { version = "0.23", features = ["derive"] }

# Redis
redis = { version = "1.3", features = ["tokio-comp"] }

# 验证码
captcha = "1.0"

[workspace]
members = ["migration"]

[profile.release]
opt-level = 3
lto = "fat"
codegen-units = 1
strip = true
```

> **依赖精简说明：** 移除 `base64`（captcha 1.0 内置）、`once_cell`（用 State 注入）、`thiserror`（AppError 手写）、`rand`（captcha 内部管理 RNG）。

- [ ] **Step 2: 创建最小占位 main.rs**

```rust
// axum-backend/src/main.rs（占位版，Task 21 替换为完整版）
fn main() {
    println!("axum-backend: 脚手架搭建中...");
}
```

- [ ] **Step 3: 创建空 lib.rs**

```rust
// axum-backend/src/lib.rs（占位，Task 20 补全所有模块声明）
// 在 Task 20 之前，各模块文件虽已创建但未被 lib.rs 引用，不会参与编译。
// 这是故意的增量策略：Task 1-19 各自独立创建文件，Task 20 一次性集成。
```

- [ ] **Step 4: 创建 .gitignore**

```gitignore
# Rust 编译产物
/target

# IDE
.idea/
.vscode/
*.swp
*.swo

# OS
.DS_Store
Thumbs.db

# 环境配置（含敏感信息，按需取消注释）
# config/config.toml
```

- [ ] **Step 5: 验证依赖可解析**

Run: `cd axum-backend && cargo check`
Expected: 输出 `Checking axum-backend v0.1.0` 且无 error（main.rs 为占位版，依赖已可解析）

- [ ] **Step 6: 提交**

```bash
cd axum-backend
git add Cargo.toml src/main.rs src/lib.rs .gitignore
git commit -m "feat: 添加 Cargo.toml 核心依赖清单、workspace 声明与基础文件"
```

---

### Task 2: 配置文件

**Files:**
- Create: `axum-backend/config/config.toml`

- [ ] **Step 1: 创建配置文件**

```toml
# axum-backend/config/config.toml

[server]
host = "0.0.0.0"
port = 8080

[database]
url = "mysql://root:password@127.0.0.1:3306/ry-vue"
max_connections = 100
min_connections = 5
connect_timeout = 8
idle_timeout = 8

[redis]
url = "redis://127.0.0.1:6379/"
max_connections = 10

[jwt]
secret = "axum-backend-secret-key-change-in-production"
expire_hours = 6
issuer = "axum-backend"

[log]
level = "info"
sql_logging = true
```

- [ ] **Step 2: 提交**

```bash
cd axum-backend
git add config/config.toml
git commit -m "feat: 添加运行配置文件 config.toml"
```

---

### Task 3: 配置管理模块

**Files:**
- Create: `axum-backend/src/config/mod.rs`
- Create: `axum-backend/src/config/settings.rs`

- [ ] **Step 1: 编写 settings.rs**

```rust
// axum-backend/src/config/settings.rs

use serde::Deserialize;

/// 全局配置根结构体
#[derive(Debug, Clone, Deserialize)]
pub struct Settings {
    pub server: ServerConfig,
    pub database: DatabaseConfig,
    pub redis: RedisConfig,
    pub jwt: JwtConfig,
    pub log: LogConfig,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DatabaseConfig {
    pub url: String,
    pub max_connections: u32,
    pub min_connections: u32,
    pub connect_timeout: u64,
    pub idle_timeout: u64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RedisConfig {
    pub url: String,
    pub max_connections: u32,
}

#[derive(Debug, Clone, Deserialize)]
pub struct JwtConfig {
    pub secret: String,
    pub expire_hours: i64,
    pub issuer: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct LogConfig {
    pub level: String,
    pub sql_logging: bool,
}

impl Settings {
    /// 从 toml 配置文件加载
    pub fn from_file(path: &str) -> anyhow::Result<Self> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| anyhow::anyhow!("读取配置文件 {} 失败: {}", path, e))?;
        let settings: Settings = toml::from_str(&content)
            .map_err(|e| anyhow::anyhow!("解析配置文件失败: {}", e))?;
        Ok(settings)
    }
}
```

- [ ] **Step 2: 编写 mod.rs**

```rust
// axum-backend/src/config/mod.rs

pub mod settings;

pub use settings::{
    DatabaseConfig, JwtConfig, LogConfig, RedisConfig, ServerConfig, Settings,
};
```

- [ ] **Step 3: 提交**

```bash
cd axum-backend
git add src/config/
git commit -m "feat: 添加配置管理模块 Settings（含 Redis 配置段）"
```

---

### Task 4: 统一响应结构体

**Files:**
- Create: `axum-backend/src/common/response.rs`
- Create: `axum-backend/src/common/mod.rs`

- [ ] **Step 1: 编写 response.rs**

```rust
// axum-backend/src/common/response.rs

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::{Deserialize, Serialize};

/// 普通接口响应（对齐前端 AjaxResult）
/// JSON: { "code": 200, "msg": "操作成功", "data": <T> }
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AjaxResult<T> {
    pub code: i32,
    pub msg: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<T>,
}

impl<T> AjaxResult<T> {
    /// 成功响应（带数据）
    pub fn success(data: T) -> Self {
        Self {
            code: 200,
            msg: "操作成功".to_string(),
            data: Some(data),
        }
    }

    /// 成功响应（仅消息）
    pub fn success_msg(msg: &str) -> Self {
        Self {
            code: 200,
            msg: msg.to_string(),
            data: None,
        }
    }

    /// 错误响应
    pub fn error(code: i32, msg: &str) -> Self {
        Self {
            code,
            msg: msg.to_string(),
            data: None,
        }
    }
}

/// AjaxResult 直接实现 IntoResponse
/// handler 可直接返回 `Result<AjaxResult<T>, AppError>`，无需手动包 Json
/// HTTP 状态码统一 200，业务错误由 body.code 表达
impl<T: Serialize> IntoResponse for AjaxResult<T> {
    fn into_response(self) -> Response {
        (StatusCode::OK, Json(self)).into_response()
    }
}

/// 分页接口响应（对齐前端 TableDataInfo）
/// JSON: { "code": 200, "msg": "查询成功", "total": 100, "rows": [...] }
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TableDataInfo<T> {
    pub code: i32,
    pub msg: String,
    pub total: u64,
    pub rows: Vec<T>,
}

impl<T> TableDataInfo<T> {
    /// 构造分页响应
    pub fn new(total: u64, rows: Vec<T>) -> Self {
        Self {
            code: 200,
            msg: "查询成功".to_string(),
            total,
            rows,
        }
    }
}

/// TableDataInfo 直接实现 IntoResponse
impl<T: Serialize> IntoResponse for TableDataInfo<T> {
    fn into_response(self) -> Response {
        (StatusCode::OK, Json(self)).into_response()
    }
}
```

- [ ] **Step 2: 编写 common/mod.rs（预留 error/page/constants 导出）**

```rust
// axum-backend/src/common/mod.rs

pub mod constants;
pub mod error;
pub mod page;
pub mod response;

pub use error::AppError;
pub use page::PageDomain;
pub use response::{AjaxResult, TableDataInfo};
```

- [ ] **Step 3: 提交**

```bash
cd axum-backend
git add src/common/response.rs src/common/mod.rs
git commit -m "feat: 添加统一响应结构体 AjaxResult/TableDataInfo"
```

---

### Task 5: 全局错误类型

**Files:**
- Create: `axum-backend/src/common/error.rs`

- [ ] **Step 1: 编写 error.rs**

```rust
// axum-backend/src/common/error.rs

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use crate::common::response::AjaxResult;

/// 全局错误类型
#[derive(Debug)]
pub struct AppError {
    pub code: i32,
    pub message: String,
}

impl AppError {
    pub fn new(code: i32, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }

    /// 401 未认证
    pub fn unauthorized(msg: &str) -> Self {
        Self::new(401, msg)
    }

    /// 400 参数错误
    pub fn bad_request(msg: &str) -> Self {
        Self::new(400, msg)
    }

    /// 404 未找到
    pub fn not_found(msg: &str) -> Self {
        Self::new(404, msg)
    }

    /// 500 内部错误
    pub fn internal(msg: &str) -> Self {
        Self::new(500, msg)
    }
}

impl IntoResponse for AppError {
    fn into_response(&self) -> Response {
        // HTTP 状态码始终 200，业务错误由 body.code 表达（对齐前端 request.ts 拦截器）
        let body = Json(AjaxResult::<()>::error(self.code, &self.message));
        (StatusCode::OK, body).into_response()
    }
}

/// SeaORM 数据库错误转换
impl From<sea_orm::DbErr> for AppError {
    fn from(err: sea_orm::DbErr) -> Self {
        match &err {
            sea_orm::DbErr::RecordNotFound | sea_orm::DbErr::RecordNotUpdated => {
                AppError::not_found(&err.to_string())
            }
            sea_orm::DbErr::ConnectionAcquire(_) => {
                AppError::new(503, "数据库连接获取失败")
            }
            sea_orm::DbErr::TryIntoErr(_) | sea_orm::DbErr::AttrNotSet(_) => {
                AppError::bad_request(&err.to_string())
            }
            _ => AppError::internal(&err.to_string()),
        }
    }
}

/// JWT 错误转换
impl From<jsonwebtoken::errors::Error> for AppError {
    fn from(_: jsonwebtoken::errors::Error) -> Self {
        AppError::unauthorized("无效的会话，或者会话已过期，请重新登录")
    }
}

/// Serde JSON 错误转换
impl From<serde_json::Error> for AppError {
    fn from(err: serde_json::Error) -> Self {
        AppError::internal(&format!("JSON 序列化错误: {}", err))
    }
}

/// IO 错误转换
impl From<std::io::Error> for AppError {
    fn from(err: std::io::Error) -> Self {
        AppError::internal(&format!("IO 错误: {}", err))
    }
}

/// Redis 错误转换
impl From<redis::RedisError> for AppError {
    fn from(err: redis::RedisError) -> Self {
        match err.kind() {
            redis::ErrorKind::AuthenticationFailed => {
                AppError::unauthorized("Redis 认证失败")
            }
            _ => AppError::internal(&format!("Redis 错误: {}", err)),
        }
    }
}

/// anyhow 错误转换（兜底）
impl From<anyhow::Error> for AppError {
    fn from(err: anyhow::Error) -> Self {
        AppError::internal(&err.to_string())
    }
}
```

- [ ] **Step 2: 提交**

```bash
cd axum-backend
git add src/common/error.rs
git commit -m "feat: 添加全局错误类型 AppError（含 SeaORM/JWT/Redis/anyhow 转换）"
```

---

### Task 6: 分页参数 + 系统常量

**Files:**
- Create: `axum-backend/src/common/page.rs`
- Create: `axum-backend/src/common/constants.rs`

- [ ] **Step 1: 编写 page.rs**

```rust
// axum-backend/src/common/page.rs

use serde::Deserialize;

/// 分页查询参数（对齐前端 PageDomain）
/// 前端通过 GET 查询串传递：?pageNum=1&pageSize=10&orderByColumn=createTime&isAsc=desc
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PageDomain {
    /// 页码，从 1 开始（默认 1）
    #[serde(default = "default_page_num")]
    pub page_num: u64,

    /// 每页条数（默认 10）
    #[serde(default = "default_page_size")]
    pub page_size: u64,

    /// 排序字段（可选）
    pub order_by_column: Option<String>,

    /// 排序方向：asc / desc（可选）
    pub is_asc: Option<String>,
}

fn default_page_num() -> u64 {
    1
}

fn default_page_size() -> u64 {
    10
}

impl PageDomain {
    /// 计算 offset（0-based）
    pub fn offset(&self) -> u64 {
        self.page_num.saturating_sub(1) * self.page_size
    }

    /// 获取 limit（即 page_size）
    pub fn limit(&self) -> u64 {
        self.page_size
    }
}

impl Default for PageDomain {
    fn default() -> Self {
        Self {
            page_num: default_page_num(),
            page_size: default_page_size(),
            order_by_column: None,
            is_asc: None,
        }
    }
}
```

- [ ] **Step 2: 编写 constants.rs**

```rust
// axum-backend/src/common/constants.rs

/// 业务状态码常量（对齐 ruoyi-vue3-ts 前端约定）
pub mod constants {
    pub const SUCCESS: i32 = 200;
    pub const BAD_REQUEST: i32 = 400;
    pub const UNAUTHORIZED: i32 = 401;
    pub const NOT_FOUND: i32 = 404;
    pub const INTERNAL_ERROR: i32 = 500;
    pub const WARNING: i32 = 601;

    /// 状态字段：正常
    pub const STATUS_NORMAL: &str = "0";
    /// 状态字段：停用
    pub const STATUS_DISABLED: &str = "1";

    /// 超级管理员角色 key
    pub const SUPER_ADMIN_ROLE: &str = "admin";
    /// 超级管理员权限标识
    pub const ALL_PERMISSIONS: &str = "*:*:*";

    /// 密码加盐密钥
    pub const PASSWORD_SALT: &str = "yebot_admin";
}
```

- [ ] **Step 3: 提交**

```bash
cd axum-backend
git add src/common/page.rs src/common/constants.rs
git commit -m "feat: 添加分页参数 PageDomain 与系统常量 constants"
```

---

### Task 7: 数据库连接池

**Files:**
- Create: `axum-backend/src/db/mod.rs`
- Create: `axum-backend/src/db/pool.rs`

- [ ] **Step 1: 编写 pool.rs**

```rust
// axum-backend/src/db/pool.rs

use std::time::Duration;
use sea_orm::{ConnectOptions, Database, DatabaseConnection};
use crate::config::DatabaseConfig;

/// 初始化数据库连接池
pub async fn init_database(config: &DatabaseConfig) -> anyhow::Result<DatabaseConnection> {
    let mut opt = ConnectOptions::new(&config.url);
    opt.max_connections(config.max_connections)
        .min_connections(config.min_connections)
        .connect_timeout(Duration::from_secs(config.connect_timeout))
        .idle_timeout(Duration::from_secs(config.idle_timeout))
        .sqlx_logging(config.sql_logging);

    let db = Database::connect(opt).await?;
    tracing::info!("数据库连接成功");
    Ok(db)
}
```

- [ ] **Step 2: 编写 db/mod.rs（预留 redis 导出）**

```rust
// axum-backend/src/db/mod.rs

pub mod pool;
pub mod redis;

pub use pool::init_database;
pub use redis::init_redis;
```

- [ ] **Step 3: 提交**

```bash
cd axum-backend
git add src/db/pool.rs src/db/mod.rs
git commit -m "feat: 添加数据库连接池初始化（SeaORM ConnectOptions）"
```

---

### Task 8: Redis 连接池

**Files:**
- Create: `axum-backend/src/db/redis.rs`

- [ ] **Step 1: 编写 redis.rs**

```rust
// axum-backend/src/db/redis.rs

use redis::aio::ConnectionManager;
use crate::config::RedisConfig;

/// 初始化 Redis 连接池（ConnectionManager，自动重连）
pub async fn init_redis(config: &RedisConfig) -> anyhow::Result<ConnectionManager> {
    let client = redis::Client::open(&config.url)?;
    let mut conn = ConnectionManager::new(client).await?;

    // 测试连接
    let pong: String = redis::cmd("PING").query_async(&mut conn).await?;
    tracing::info!("Redis 连接成功: {} (PING -> {})", config.url, pong);

    Ok(conn)
}
```

- [ ] **Step 2: 提交**

```bash
cd axum-backend
git add src/db/redis.rs
git commit -m "feat: 添加 Redis 连接池初始化（ConnectionManager）"
```

---

### Task 9: 日志体系

**Files:**
- Create: `axum-backend/src/logger.rs`

- [ ] **Step 1: 编写 logger.rs**

```rust
// axum-backend/src/logger.rs

use tracing_subscriber::{fmt, EnvFilter, prelude::*};
use crate::config::LogConfig;

/// 初始化日志体系（tracing + tracing-subscriber）
pub fn init_logger(log_config: &LogConfig) {
    let env_filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(&log_config.level));

    let fmt_layer = fmt::layer()
        .with_target(true)
        .with_ansi(true)
        .with_file(true)
        .with_line_number(true);

    tracing_subscriber::registry()
        .with(env_filter)
        .with(fmt_layer)
        .init();

    tracing::info!("日志系统初始化完成，级别: {}", log_config.level);
}
```

- [ ] **Step 2: 提交**

```bash
cd axum-backend
git add src/logger.rs
git commit -m "feat: 添加日志体系初始化（tracing-subscriber）"
```

---

### Task 10: JWT 工具

**Files:**
- Create: `axum-backend/src/jwt/mod.rs`
- Create: `axum-backend/src/jwt/claims.rs`

- [ ] **Step 1: 编写 claims.rs**

```rust
// axum-backend/src/jwt/claims.rs

use chrono::Utc;
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use crate::config::JwtConfig;

/// JWT Claims
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    /// 用户 ID
    pub sub: String,
    /// 用户名
    pub username: String,
    /// 过期时间戳（秒）
    pub exp: usize,
    /// 签发时间戳（秒）
    pub iat: usize,
    /// 签发者
    pub iss: String,
}

/// JWT 工具类
pub struct JwtUtils;

impl JwtUtils {
    /// 生成 JWT token
    pub fn generate_token(
        user_id: &str,
        username: &str,
        config: &JwtConfig,
    ) -> anyhow::Result<String> {
        let now = Utc::now();
        let exp = now + chrono::Duration::hours(config.expire_hours);
        let claims = Claims {
            sub: user_id.to_string(),
            username: username.to_string(),
            exp: exp.timestamp() as usize,
            iat: now.timestamp() as usize,
            iss: config.issuer.clone(),
        };
        let token = encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(config.secret.as_bytes()),
        )?;
        Ok(token)
    }

    /// 验证 JWT token 并返回 Claims
    pub fn verify_token(token: &str, config: &JwtConfig) -> anyhow::Result<Claims> {
        let mut validation = Validation::default();
        validation.set_issuer(&[&config.issuer]);
        let token_data = decode::<Claims>(
            token,
            &DecodingKey::from_secret(config.secret.as_bytes()),
            &validation,
        )?;
        Ok(token_data.claims)
    }
}
```

- [ ] **Step 2: 编写 jwt/mod.rs**

```rust
// axum-backend/src/jwt/mod.rs

pub mod claims;

pub use claims::{Claims, JwtUtils};
```

- [ ] **Step 3: 提交**

```bash
cd axum-backend
git add src/jwt/
git commit -m "feat: 添加 JWT 工具 Claims 与 token 生成/验证"
```

---

### Task 11: 密码工具

**Files:**
- Create: `axum-backend/src/utils/mod.rs`
- Create: `axum-backend/src/utils/password.rs`

- [ ] **Step 1: 编写 password.rs**

```rust
// axum-backend/src/utils/password.rs

use md5::{Digest, Md5};
use crate::common::constants::constants::PASSWORD_SALT;

/// 密码加盐 MD5（盐值 "yebot_admin"，不兼容 ref-salvo-admin 旧密码）
pub fn encrypt_password(password: &str) -> String {
    let salted = format!("{}{}", password, PASSWORD_SALT);
    let mut hasher = Md5::new();
    hasher.update(salted.as_bytes());
    format!("{:x}", hasher.finalize())
}

/// 验证密码
pub fn verify_password(password: &str, hashed: &str) -> bool {
    encrypt_password(password) == hashed
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_and_verify() {
        let password = "admin123";
        let hashed = encrypt_password(password);
        assert!(verify_password(password, &hashed));
        assert!(!verify_password("wrong", &hashed));
    }
}
```

- [ ] **Step 2: 编写 utils/mod.rs（预留 captcha/tree 导出）**

```rust
// axum-backend/src/utils/mod.rs

pub mod captcha;
pub mod password;
pub mod tree;

pub use password::{encrypt_password, verify_password};
```

- [ ] **Step 3: 运行单元测试验证**

> **注意：** 此时 `lib.rs` 尚未声明 `pub mod utils;`（Task 20 统一集成），`cargo test` 无法发现此测试。
> 可暂时在 `lib.rs` 中添加 `pub mod common; pub mod utils;` 来运行测试，验证后删除。
> 或跳过此步，在 Task 23 全量编译时统一验证。

Run（可选）: `cd axum-backend && cargo test test_encrypt_and_verify`
Expected: 1 passed（若已临时集成到 lib.rs）

- [ ] **Step 4: 提交**

```bash
cd axum-backend
git add src/utils/mod.rs src/utils/password.rs
git commit -m "feat: 添加密码加盐 MD5 工具（对齐 ref-salvo-admin）"
```

---

### Task 12: 验证码工具

**Files:**
- Create: `axum-backend/src/utils/captcha.rs`

- [ ] **Step 1: 编写 captcha.rs**

```rust
// axum-backend/src/utils/captcha.rs

use captcha::Captcha;
use captcha::filters::Noise;
use uuid::Uuid;

/// 验证码结果
pub struct CaptchaResult {
    /// 验证码 key（存 Redis，TTL 5 分钟）
    pub uuid: String,
    /// Base64 图片（不含 data:image/png;base64, 前缀）
    pub img_base64: String,
    /// 验证码明文（存 Redis 用于校验）
    pub code: String,
}

/// 生成 4 位字母数字验证码（使用 captcha 1.0 API）
/// captcha 1.0 关键变化：
/// - add_chars(n) 返回 &mut Self（不再返回 String），通过 chars_as_string() 获取明文
/// - view(w, h) 需要指定宽高
/// - as_base64() 直接返回 Option<String>（无需手动 base64 编码）
/// - Noise::new(strength) 需要强度参数
pub fn generate_captcha() -> CaptchaResult {
    let mut captcha = Captcha::new();
    captcha.set_chars(&"ABCDEFGHJKLMNPQRSTUVWXYZ23456789".chars().collect::<Vec<_>>());
    captcha.add_chars(4);
    captcha.apply_filter(Noise::new(0.3));
    captcha.view(220, 120);

    let code = captcha.chars_as_string();
    let img_base64 = captcha.as_base64().unwrap_or_default();
    let uuid = Uuid::new_v4().to_string();

    CaptchaResult {
        uuid,
        img_base64,
        code,
    }
}
```

- [ ] **Step 2: 提交**

```bash
cd axum-backend
git add src/utils/captcha.rs
git commit -m "feat: 添加验证码生成工具（base64 + uuid）"
```

---

### Task 13: 树构建工具

**Files:**
- Create: `axum-backend/src/utils/tree.rs`

- [ ] **Step 1: 编写 tree.rs**

```rust
// axum-backend/src/utils/tree.rs

/// 通用树节点 trait（对齐 ref-soybean-admin 的 tree_util）
pub trait TreeNode {
    /// 节点 ID
    fn id(&self) -> i64;
    /// 父节点 ID
    fn parent_id(&self) -> i64;
    /// 可变子节点列表
    fn children_mut(&mut self) -> &mut Option<Vec<Self>> where Self: Sized;
}

/// 将扁平列表构建为树结构
/// root_parent_id 为根节点的 parent_id（通常为 0）
pub fn build_tree<T: TreeNode + Clone>(list: &[T], root_parent_id: i64) -> Vec<T> {
    let mut roots: Vec<T> = list.iter()
        .filter(|n| n.parent_id() == root_parent_id)
        .cloned()
        .collect();
    for root in &mut roots {
        build_children(root, list);
    }
    roots
}

fn build_children<T: TreeNode + Clone>(node: &mut T, list: &[T]) {
    let node_id = node.id();
    let children: Vec<T> = list.iter()
        .filter(|n| n.parent_id() == node_id)
        .cloned()
        .collect();
    if children.is_empty() {
        return;
    }
    // 先挂载 children，再递归处理每个 child
    // 分两步避免同时持有 node 的可变引用与不可变引用
    if let Some(kids) = node.children_mut() {
        *kids = Some(children);
    }
    if let Some(kids) = node.children_mut() {
        if let Some(ref mut children) = kids {
            for kid in children.iter_mut() {
                build_children(kid, list);
            }
        }
    }
}
```

- [ ] **Step 2: 提交**

```bash
cd axum-backend
git add src/utils/tree.rs
git commit -m "feat: 添加通用树构建工具 TreeNode + build_tree"
```

---

### Task 14: AppState 共享状态

**Files:**
- Create: `axum-backend/src/state.rs`

- [ ] **Step 1: 编写 state.rs**

```rust
// axum-backend/src/state.rs

use std::sync::Arc;
use redis::aio::ConnectionManager;
use sea_orm::DatabaseConnection;
use crate::config::Settings;

/// 应用全局共享状态
/// 通过 Axum State<Arc<AppState>> 注入到所有 handler
#[derive(Clone)]
pub struct AppState {
    /// 数据库连接池
    pub db: DatabaseConnection,
    /// Redis 连接池
    pub redis: ConnectionManager,
    /// 全局配置
    pub config: Arc<Settings>,
}
```

- [ ] **Step 2: 提交**

```bash
cd axum-backend
git add src/state.rs
git commit -m "feat: 添加 AppState 共享状态（DB + Redis + Config）"
```

---

### Task 15: 请求 ID 中间件

**Files:**
- Create: `axum-backend/src/middleware/mod.rs`
- Create: `axum-backend/src/middleware/request_id.rs`

- [ ] **Step 1: 编写 request_id.rs**

```rust
// axum-backend/src/middleware/request_id.rs

use axum::extract::Request;
use axum::http::HeaderValue;
use axum::middleware::Next;
use axum::response::Response;

/// 请求 ID（注入到 request extensions，供 handler 提取）
#[derive(Clone, Debug)]
pub struct RequestId(pub String);

/// 请求 ID 中间件：为每个请求生成 UUID 并写入响应头 X-Request-Id
pub async fn request_id_middleware(mut req: Request, next: Next) -> Response {
    let request_id = uuid::Uuid::new_v4().to_string();
    req.extensions_mut().insert(RequestId(request_id.clone()));

    let mut response = next.run(req).await;
    if let Ok(val) = HeaderValue::from_str(&request_id) {
        response.headers_mut().insert("X-Request-Id", val);
    }
    response
}
```

- [ ] **Step 2: 编写 middleware/mod.rs（预留 auth 导出）**

```rust
// axum-backend/src/middleware/mod.rs

pub mod auth;
pub mod request_id;

pub use auth::auth_middleware;
pub use request_id::{request_id_middleware, RequestId};
```

- [ ] **Step 3: 提交**

```bash
cd axum-backend
git add src/middleware/
git commit -m "feat: 添加请求 ID 中间件"
```

---

### Task 16: JWT 鉴权中间件

**Files:**
- Create: `axum-backend/src/middleware/auth.rs`

- [ ] **Step 1: 编写 auth.rs**

```rust
// axum-backend/src/middleware/auth.rs

use std::sync::Arc;
use axum::extract::{Request, State};
use axum::http::header::AUTHORIZATION;
use axum::middleware::Next;
use axum::response::Response;
use crate::common::AppError;
use crate::jwt::JwtUtils;
use crate::state::AppState;

/// JWT 鉴权中间件（from_fn_with_state 模式）
/// 手动提取 Authorization header，缺失时返回 401（对齐前端 request.ts 拦截器）
/// 通过 axum::middleware::from_fn_with_state(state, auth_middleware) 挂载到受保护路由
pub async fn auth_middleware(
    State(state): State<Arc<AppState>>,
    mut req: Request,
    next: Next,
) -> Result<Response, AppError> {
    // 手动提取 Authorization header（缺失返回 401，而非 axum 默认的 400）
    let auth_header = req
        .headers()
        .get(&AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| AppError::unauthorized("请求未携带 token，请重新登录"))?;

    // 解析 Bearer token（格式：Bearer <token>）
    let token = auth_header
        .strip_prefix("Bearer ")
        .ok_or_else(|| AppError::unauthorized("token 格式错误，应为 Bearer <token>"))?;

    // 验证 token 并注入 Claims 到 request extensions
    let claims = JwtUtils::verify_token(token, &state.config.jwt)?;
    req.extensions_mut().insert(claims);
    Ok(next.run(req).await)
}
```

> **关键设计：** 手动提取 header 而非用 `TypedHeader` extractor 参数。当 token 缺失时返回 401（对齐前端拦截器跳转登录），而非 axum extractor 默认的 400。

- [ ] **Step 2: 提交**

```bash
cd axum-backend
git add src/middleware/auth.rs
git commit -m "feat: 添加 JWT 鉴权中间件（from_fn_with_state，手动提取 header）"
```

---

### Task 17: 健康检查 Handler

**Files:**
- Create: `axum-backend/src/handler/mod.rs`
- Create: `axum-backend/src/handler/health.rs`

- [ ] **Step 1: 编写 health.rs**

```rust
// axum-backend/src/handler/health.rs

use serde::Serialize;
use crate::common::{AjaxResult, AppError};

/// 健康检查响应体
#[derive(Serialize)]
pub struct HealthStatus {
    pub status: String,
    pub version: String,
}

/// GET /health
/// 健康检查接口（免鉴权）
/// AjaxResult 已实现 IntoResponse，handler 直接返回 Result<AjaxResult<T>, AppError>
pub async fn health() -> Result<AjaxResult<HealthStatus>, AppError> {
    let status = HealthStatus {
        status: "UP".to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
    };
    Ok(AjaxResult::success(status))
}
```

- [ ] **Step 2: 编写 handler/mod.rs**

```rust
// axum-backend/src/handler/mod.rs

pub mod health;

pub use health::health;
```

- [ ] **Step 3: 提交**

```bash
cd axum-backend
git add src/handler/
git commit -m "feat: 添加健康检查 handler /health"
```

---

### Task 18: 路由聚合

**Files:**
- Create: `axum-backend/src/router/mod.rs`
- Create: `axum-backend/src/router/public.rs`

- [ ] **Step 1: 编写 public.rs**

```rust
// axum-backend/src/router/public.rs

use std::sync::Arc;
use axum::Router;
use axum::routing::get;
use crate::handler;
use crate::state::AppState;

/// 构建公开路由（免鉴权）
pub fn public_routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/health", get(handler::health))
}
```

- [ ] **Step 2: 编写 mod.rs 路由聚合**

```rust
// axum-backend/src/router/mod.rs

pub mod public;

use std::sync::Arc;
use axum::Router;
use tower_http::compression::CompressionLayer;
use tower_http::cors::CorsLayer;
use tower_http::trace::TraceLayer;
use crate::middleware::request_id_middleware;
use crate::state::AppState;

/// 构建完整应用路由
pub fn build_app(state: Arc<AppState>) -> Router {
    let app = Router::new()
        .merge(public::public_routes())
        .with_state(state);

    // 叠加全局中间件（顺序：后添加的先执行）
    app.layer(CompressionLayer::new())
        .layer(CorsLayer::permissive())
        .layer(TraceLayer::new_for_http())
        .layer(axum::middleware::from_fn(request_id_middleware))
}
```

> **中间件叠加说明：** `CompressionLayer` 启用 gzip 压缩（对应 Cargo.toml 的 `compression-gzip` feature），`CorsLayer::permissive()` 允许跨域（开发期），`TraceLayer` 记录请求日志，`request_id_middleware` 注入请求 ID。

- [ ] **Step 3: 提交**

```bash
cd axum-backend
git add src/router/
git commit -m "feat: 添加路由聚合与全局中间件叠加（CORS/Trace/RequestId/Compression）"
```

---

### Task 19: initialize 初始化编排

**Files:**
- Create: `axum-backend/src/initialize/mod.rs`

- [ ] **Step 1: 编写 initialize/mod.rs**

```rust
// axum-backend/src/initialize/mod.rs

use std::sync::Arc;
use crate::config::Settings;
use crate::db;
use crate::logger;
use crate::state::AppState;

/// 初始化编排模块（对齐 ref-soybean-admin 的 server/initialize）
pub struct AppInitializer;

impl AppInitializer {
    /// 执行完整初始化流程，返回 AppState
    pub async fn run(config_path: &str) -> anyhow::Result<Arc<AppState>> {
        // 1. 加载配置
        let settings = Arc::new(Settings::from_file(config_path)?);

        // 2. 初始化日志
        logger::init_logger(&settings.log);

        tracing::info!("=== axum-backend 初始化中 ===");

        // 3. 初始化数据库
        let db = db::init_database(&settings.database).await?;

        // 4. 初始化 Redis
        let redis = db::init_redis(&settings.redis).await?;

        // 5. 构建 AppState
        let state = Arc::new(AppState {
            db,
            redis,
            config: settings,
        });

        tracing::info!("=== axum-backend 初始化完成 ===");
        Ok(state)
    }
}
```

- [ ] **Step 2: 提交**

```bash
cd axum-backend
git add src/initialize/
git commit -m "feat: 添加 initialize 初始化编排模块（对齐 ref-soybean-admin）"
```

---

### Task 20: 库入口集成与占位模块

**Files:**
- Modify: `axum-backend/src/lib.rs`（从空占位替换为完整模块声明）
- Create: `axum-backend/src/entity/mod.rs`
- Create: `axum-backend/src/repository/mod.rs`
- Create: `axum-backend/src/service/mod.rs`

> **关键集成点：** 本 Task 之前各模块文件虽已创建但未被 `lib.rs` 引用，不参与编译。
> 本 Task 一次性声明所有模块，此后 `cargo check` 将检查全部代码。
> 若前序 Task 有编译错误，将在此 Task 暴露。

- [ ] **Step 1: 编写 lib.rs**

```rust
// axum-backend/src/lib.rs

pub mod common;
pub mod config;
pub mod db;
pub mod entity;
pub mod handler;
pub mod initialize;
pub mod jwt;
pub mod logger;
pub mod middleware;
pub mod repository;
pub mod router;
pub mod service;
pub mod state;
pub mod utils;
```

- [ ] **Step 2: 编写占位模块**

```rust
// axum-backend/src/entity/mod.rs
//! SeaORM 实体层（业务阶段填充）
```

```rust
// axum-backend/src/repository/mod.rs
//! 数据访问层（业务阶段填充）
```

```rust
// axum-backend/src/service/mod.rs
//! 业务逻辑层（业务阶段填充）
```

- [ ] **Step 3: 首次全量编译验证**

> **关键：** 此步是第一次 `cargo check` 检查所有模块代码。若有编译错误，需逐个修复。

Run: `cd axum-backend && cargo check`
Expected: 编译通过（允许 unused warning）

- [ ] **Step 4: 提交**

```bash
cd axum-backend
git add src/lib.rs src/entity/ src/repository/ src/service/
git commit -m "feat: 集成库入口 lib.rs 声明所有模块 + 占位模块（entity/repository/service）"
```

---

### Task 21: 应用入口 main.rs

**Files:**
- Modify: `axum-backend/src/main.rs`

- [ ] **Step 1: 编写 main.rs**

```rust
// axum-backend/src/main.rs

use std::sync::Arc;
use axum_backend::initialize::AppInitializer;
use axum_backend::router;
use axum_backend::state::AppState;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // 1. 初始化编排（配置/日志/DB/Redis → AppState）
    let state: Arc<AppState> = AppInitializer::run("config/config.toml").await?;

    // 2. 从已加载的配置获取监听地址（避免重复加载配置）
    let addr = format!("{}:{}", state.config.server.host, state.config.server.port);

    // 3. 构建路由
    let app = router::build_app(state);

    // 4. 启动 HTTP 服务
    tracing::info!("服务启动于 http://{}", addr);
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}
```

> **设计要点：** 监听地址从 `AppInitializer::run` 返回的 `state.config` 获取，避免重复加载配置文件。

- [ ] **Step 2: 提交**

```bash
cd axum-backend
git add src/main.rs
git commit -m "feat: 添加应用入口 main.rs（通过 AppInitializer 编排初始化）"
```

---

### Task 22: migration 子 crate

**Files:**
- Create: `axum-backend/migration/Cargo.toml`
- Create: `axum-backend/migration/src/lib.rs`
- Create: `axum-backend/migration/src/main.rs`
- Create: `axum-backend/migration/src/m20250711_000001_init.rs`

- [ ] **Step 1: 编写 migration/Cargo.toml**

```toml
# axum-backend/migration/Cargo.toml

[package]
name = "migration"
version = "0.1.0"
edition = "2024"

[dependencies]
sea-orm-migration = { version = "1.1", features = ["runtime-tokio-rustls", "sqlx-mysql"] }
tokio = { version = "1", features = ["rt-multi-thread", "macros"] }
```

- [ ] **Step 2: 编写 migration/src/lib.rs**

```rust
// axum-backend/migration/src/lib.rs

pub use sea_orm_migration::prelude::*;

mod m20250711_000001_init;

pub struct Migrator;

#[async_trait::async_trait]
impl MigratorTrait for Migrator {
    fn migrations() -> Vec<Box<dyn MigrationTrait>> {
        vec![Box::new(m20250711_000001_init::Migration)]
    }
}
```

- [ ] **Step 3: 编写 migration/src/m20250711_000001_init.rs**

```rust
// axum-backend/migration/src/m20250711_000001_init.rs

use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, _manager: &SchemaManager) -> Result<(), DbErr> {
        // 本阶段为空骨架，业务阶段在此创建 sys_user 等表
        Ok(())
    }

    async fn down(&self, _manager: &SchemaManager) -> Result<(), DbErr> {
        Ok(())
    }
}
```

- [ ] **Step 4: 编写 migration/src/main.rs**

```rust
// axum-backend/migration/src/main.rs

use sea_orm_migration::prelude::*;
use migration::Migrator;

#[tokio::main]
async fn main() {
    let url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "mysql://root:password@127.0.0.1:3306/ry-vue".to_string());
    let db = Database::connect(&url).await.expect("数据库连接失败");
    Migrator::up(&db, None).await.expect("迁移执行失败");
    println!("迁移完成");
}
```

- [ ] **Step 5: 提交**

```bash
cd axum-backend
git add migration/
git commit -m "feat: 添加 migration 子 crate（sea-orm-migration 初始化骨架）"
```

---

### Task 23: 编译验证与冒烟测试

**Files:**
- 无新文件，全项目编译验证

- [ ] **Step 1: 全量编译检查**

Run: `cd axum-backend && cargo build`
Expected: 编译成功，无 error（允许 unused warning）

- [ ] **Step 2: 编译 migration 子 crate**

Run: `cd axum-backend && cargo build -p migration`
Expected: 编译成功

- [ ] **Step 3: 运行单元测试**

Run: `cd axum-backend && cargo test`
Expected: `test_encrypt_and_verify` 测试通过

- [ ] **Step 4: 若有编译错误，逐个修复**

常见问题排查：
- 模块导出路径不匹配 → 检查 `lib.rs` 与各 `mod.rs` 的 `pub use`
- axum-extra 版本不兼容 → 确认 axum-extra 0.12 对应 axum 0.8
- sea-orm feature 缺失 → 确认 `with-chrono` / `macros` 已启用
- captcha crate API → 确认 captcha 1.0 API：`Captcha::new()` / `set_chars` / `add_chars(n)` 返回 `&mut Self` / `apply_filter(Noise::new(strength))` / `view(w, h)` / `chars_as_string()` / `as_base64()`
- auth_middleware 不使用 TypedHeader extractor → 手动提取 `Authorization` header 并 `strip_prefix("Bearer ")`，token 缺失返回 401
- tree.rs borrow 检查 → `build_children` 分两步调用 `children_mut()`（先挂载 children，再递归），避免同时持有可变与不可变引用
- migration main.rs 使用 `#[tokio::main]`（非 `#[async_std::main]`），与主 crate 一致
- migration 表名为 `seaql_migrations`（非 `seql_migrations`）

- [ ] **Step 5: 运行服务冒烟测试（需 MySQL + Redis 可用）**

Run: `cd axum-backend && cargo run`
Expected:
- 日志输出 `数据库连接成功`
- 日志输出 `Redis 连接成功`
- 日志输出 `服务启动于 http://0.0.0.0:8080`
- 服务持续运行

- [ ] **Step 6: 测试健康检查接口**

另开终端运行：`curl http://localhost:8080/health`
Expected:
```json
{
  "code": 200,
  "msg": "操作成功",
  "data": {
    "status": "UP",
    "version": "0.1.0"
  }
}
```

- [ ] **Step 7: 验证响应头包含 X-Request-Id**

Run: `curl -i http://localhost:8080/health`
Expected: 响应头包含 `X-Request-Id: <uuid>`

- [ ] **Step 8: 验证 migration 可执行**

Run: `cd axum-backend && DATABASE_URL="mysql://root:password@127.0.0.1:3306/ry-vue" cargo run -p migration`
Expected: 输出 `迁移完成`

- [ ] **Step 9: 最终提交**

```bash
cd axum-backend
git add -A
git commit -m "feat: 完成第一阶段工程脚手架与基础框架"
```

---

## 自查结果

- [x] 所有任务文件路径明确，均在 `axum-backend/` 内
- [x] 每个任务包含完整代码块，无占位符
- [x] 依赖方向单向：handler → service → repository → entity
- [x] 响应结构体字段对齐 ruoyi-vue3-ts（code/msg/data/rows/total）
- [x] 错误处理 HTTP 状态码统一 200，业务错误由 body.code 表达
- [x] 无 salvo/rbatis 依赖
- [x] 版本号符合用户指定（Axum 0.8、SeaORM 1.1，全部升级到最新稳定版）
- [x] 配置外置（config/config.toml），支持 RUST_LOG 环境变量覆盖
- [x] migration 独立子 crate，含 sea-orm-migration 骨架
- [x] 通用能力完整：响应/错误/配置/DB/Redis/日志/JWT/中间件/密码/验证码/树/initialize/常量
- [x] ref-soybean-admin 架构对照：initialize 编排、State 注入、错误转换
