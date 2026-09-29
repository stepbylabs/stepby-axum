# 工程脚手架与基础框架 规范文档（spec.md）

> **阶段：** 第一阶段「工程脚手架与基础框架」
> **项目：** axum-backend（纯 Axum 0.8 + SeaORM 1.1 生产级后端服务）
> **规则基线：** 项目规则基线见根目录 `README.md` 与 `SECURITY.md`；Trae IDE 规则文件 `backend-axum/.trae/rules/project-rules.md`（IDE 内自动加载，非项目文档）
> **开发优先原则：** 接口契约对齐 frontend-vue 前端调用规范 ＞ 架构规范遵循 Axum 官方最佳实践 ＞ 同栈细节遵循 Axum + SeaORM 原生惯例

---

## 1. 概述与目标

### 1.1 本阶段目标

在 `backend-axum/` 目录下搭建可编译、可运行、可联调的工程脚手架，完成以下基础能力：

1. 完整分层目录结构（handler / service / repository / entity / common / config / migration / middleware）
2. Cargo.toml 核心依赖清单（稳定版本号）
3. 通用能力：统一响应结构体、全局错误类型、配置管理、数据库连接池、Redis 连接池、日志体系、JWT、中间件、密码工具、验证码工具、树工具
4. 应用入口 `main.rs` 通过 initialize 模块完成初始化编排并启动 HTTP 服务
5. migration 独立子 crate，含 sea-orm-migration 初始化与首个空迁移骨架
6. 健康检查接口 `/health` 可验证服务运行

### 1.2 非目标（持续优化项）

- 性能极限调优、分布式部署、多租户隔离

### 1.3 架构原则

| 原则 | 说明 |
|------|------|
| Workspace + 单应用 crate | 根 crate 为应用主体，`migration/` 为独立子 crate |
| 严格分层 | Handler → Service → Repository，单向依赖，禁止反向 |
| SeaORM 唯一 ORM | 全程使用 SeaORM，禁止混用其他 ORM |
| 配置外置 | 通过 `config/config.toml` 加载配置，支持 `RUST_LOG` 环境变量覆盖 |
| 接口契约第一 | 响应结构、字段命名、状态码 100% 对齐本项目前端 |
| initialize 编排 | 初始化流程集中在 `initialize` 模块，集中编排 DB/Redis/日志/路由初始化 |

### 1.4 核心模块设计对照

| 功能点 | axum-backend 对应实现 | 要点 |
|--------------------------|------------------------|----------|
| 统一响应结构 Res\<T\> | `src/common/response.rs` AjaxResult\<T\> + TableDataInfo\<T\> | 统一响应结构 + IntoResponse 实现 |
| 全局错误 AppError | `src/common/error.rs` AppError | 错误类型 + From 转换 + IntoResponse |
| 分页参数 PageRequest | `src/common/page.rs` PageDomain | 分页参数（字段名对齐前端 pageNum/pageSize） |
| JWT 工具 JwtUtils | `src/jwt/claims.rs` JwtUtils | JWT 生成/验证，Claims 结构 |
| JWT 中间件 | `src/middleware/auth.rs` auth_middleware | from_fn_with_state 中间件模式 |
| App 全局状态 | `src/state.rs` AppState | 使用 Axum State 注入（非全局静态） |
| 初始化编排 | `src/initialize/mod.rs` | 集中编排 DB/Redis/日志/路由初始化 |
| 配置加载 | `src/config/settings.rs` | 简化为 toml 单文件加载 |
| 数据实体 | `src/entity/` | SeaORM 实体（本阶段占位） |
| 业务服务 | `src/service/` | 业务逻辑层（本阶段占位） |
| Web Handler | `src/handler/` | Handler 层 |
| 路由聚合 | `src/router/` | 路由聚合 |

**关键差异（有意为之）：**
- 不使用 `OnceCell`/`Lazy` 全局静态存储 DB 连接，改用 `State<Arc<AppState>>` 注入（Axum 官方推荐，更易测试）
- 不引入 Casbin（本阶段不需要复杂 RBAC，JWT Claims 足够）
- 不引入 MongoDB/S3（不在本项目范围）
- 配置加载简化为 toml 单文件 + `RUST_LOG` 覆盖（不使用 config crate 的多源合并，降低复杂度）

---

## 2. 技术栈与稳定版本号

### 2.1 核心依赖清单（主 crate `axum-backend`）

> **edition：** 主 crate `Cargo.toml` 使用 `edition = "2024"`（需 Rust 1.96+，支持 let-chains 等稳定语法）。

| 依赖 | 版本 | features | 用途 |
|------|------|----------|------|
| **axum** | `0.8` | `macros, multipart, ws` | Web 框架 |
| axum-extra | `0.12` | `typed-header` | Authorization Bearer typed header |
| **sea-orm** | `1.1` | `runtime-tokio-rustls, sqlx-mysql, sqlx-postgres, sqlx-sqlite, macros, with-chrono` | ORM（多数据库支持） |
| **tokio** | `1` | `rt-multi-thread, macros, signal, process, io-util, time` | 异步运行时 |
| **jsonwebtoken** | `10` | `rust_crypto` | JWT 生成与验证 |
| tower | `0.5` | - | 中间件基础 |
| tower-http | `0.7` | `cors, trace, compression-gzip, fs, timeout` | HTTP 中间件 |
| serde | `1` | `derive` | 序列化框架 |
| serde_json | `1` | - | JSON 处理 |
| tracing | `0.1` | - | 分布式追踪 |
| tracing-subscriber | `0.3` | `env-filter, fmt, json` | 日志订阅者 |
| tracing-appender | `0.2` | - | 日志文件按日轮转 |
| chrono | `0.4` | `serde` | 时间处理 |
| uuid | `1` | `v4` | UUID 生成（请求 ID / 验证码 key） |
| anyhow | `1` | - | 通用错误处理 |
| thiserror | `2` | - | 自定义错误类型派生 `std::error::Error` / `Display` |
| toml | `1` | - | 配置文件解析 |
| redis | `1.3` | `tokio-comp, connection-manager` | Redis 客户端（token/captcha 缓存） |
| **argon2** | `0.5` | - | 密码哈希主算法（Argon2id + 随机盐） |
| md-5 | `0.10` | - | 旧密码哈希验证 fallback（兼容历史数据，不用于新密码） |
| sha2 | `0.10` | - | SHA-256 摘要（校验和等用途） |
| **garde** | `0.23` | `full` | 参数校验（T-01 迁移后替代 validator，0.23 起内置 i18n 模块） |
| captcha | `1.0` | - | 验证码图片生成 |
| rust-i18n | `3` | - | 国际化（编译期嵌入 locales/*.yml，T-05） |
| dotenvy | `0.15` | - | `.env` 环境变量加载 |
| async-trait | `0.1` | - | 异步 trait 宏（SeaORM ActiveModelBehavior） |
| futures | `0.3` | - | 异步 Future 工具（事务闭包 boxed()） |
| regex | `1` | - | 正则表达式（手机号格式校验、XSS 净化） |

> **依赖演进说明：**
> - `validator 0.20` 已于 T-01 迁移至 `garde 0.23`（garde 0.23 起内置 `garde::i18n` 模块用于校验错误消息本地化）
> - `thiserror` 已重新引入（版本 `2`），用于自定义错误类型自动派生 `std::error::Error` 和 `Display`，原"移除 thiserror"的说明作废
> - `md-5` 版本由 0.11 校正为 0.10（与 Cargo.toml 实际版本一致），仅保留作为旧哈希验证 fallback
> - `toml` 版本由 0.8 升至 1
> - 完整依赖清单（含 tokio-cron-scheduler/utoipa/maxminddb/lettre/rust-embed/totp-rs 等业务模块依赖）见 `backend-axum/Cargo.toml`

### 2.2 migration 子 crate 依赖

| 依赖 | 版本 | features | 用途 |
|------|------|----------|------|
| sea-orm-migration | `1.1` | `runtime-tokio-rustls, sqlx-mysql` | 数据库迁移 |
| tokio | `1` | `rt-multi-thread, macros` | 异步运行时 |

### 2.3 版本选型依据

- **Axum 0.8**（最新稳定 0.8.9）：`from_fn_with_state` 中间件、`IntoResponse` trait、TypeSafe 路由稳定。
- **SeaORM 1.1**（最新稳定 1.1.20）：`DeriveEntityModel`/`DeriveActiveModel`/`paginate` API 成熟，1.0 为重要里程碑版本，API 向下兼容 0.12 的核心用法。
- **jsonwebtoken 10**（最新稳定 10.4.0）：`EncodingKey`/`DecodingKey`/`Validation` API 稳定，10.x 新增 `CryptoProvider` trait 与 `crypto` 模块，核心 `encode`/`decode` 用法不变。
- **tower-http 0.7**（最新稳定 0.7.0）：与 axum 0.8 兼容的 `TraceLayer`/`CorsLayer`/`CompressionLayer`。
- **redis 1.3**（最新稳定 1.3.0）：1.0 为里程碑版本，`ConnectionManager` API 保持兼容，`tokio-comp` feature 启用 tokio 运行时支持。
- **captcha 1.0**（最新稳定 1.0.0）：API 完全重写，新增 `generate(Difficulty)` 便捷函数、`view(width, height)` 尺寸参数、`as_png()` 返回 `Option<Vec<u8>>`，`Noise::new(strength)` 需要强度参数。
- **axum-extra 0.12**（最新稳定 0.12.6）：匹配 axum 0.8，`TypedHeader` extractor API 保持兼容。
- **argon2 0.5**：密码哈希主算法（Argon2id），`Argon2::default()` + `SaltString::generate(&mut OsRng)` 生成带随机盐的 PHC 字符串。
- **md-5 0.10**：`Md5`/`Digest` trait API，仅保留作为旧哈希验证 fallback（兼容历史数据，不用于新密码加密）。
- **garde 0.23**（T-01 迁移后替代 validator 0.20）：`#[garde(...)]` 派生宏 API，0.23 起内置 `garde::i18n` 模块用于校验错误消息本地化。

---

## 3. 完整目录结构设计

```
backend-axum/
├── Cargo.toml                      # 主 crate 依赖清单 + [workspace] 声明
├── config/
│   └── config.toml                 # 运行配置文件
├── .gitignore
├── docs/
│   ├── spec.md                     # 本文档
│   ├── tasks.md                    # 任务分解
│   └── checklist.md                # 校验清单
│
├── src/                            # ===== 主应用 crate =====
│   ├── main.rs                     # 应用入口：调用 initialize 并启动 axum server
│   ├── lib.rs                      # 库入口：re-export 所有公开模块
│   │
│   ├── config/                     # 【配置管理】
│   │   ├── mod.rs
│   │   └── settings.rs             # Settings 结构体 + from_file 加载
│   │
│   ├── common/                     # 【通用能力】
│   │   ├── mod.rs
│   │   ├── response.rs             # AjaxResult / TableDataInfo（对齐前端）
│   │   ├── error.rs                # AppError + IntoResponse + From 转换
│   │   ├── page.rs                 # PageDomain 分页参数
│   │   └── constants.rs            # 系统常量（状态码、默认值）
│   │
│   ├── db/                         # 【数据连接】
│   │   ├── mod.rs
│   │   ├── pool.rs                 # SeaORM DatabaseConnection 初始化
│   │   └── redis.rs                # Redis 连接池初始化
│   │
│   ├── entity/                     # 【SeaORM 实体层】
│   │   └── mod.rs                  # 实体模块导出（本阶段占位）
│   │
│   ├── repository/                 # 【数据访问层】
│   │   └── mod.rs                  # Repository 模块导出（本阶段占位）
│   │
│   ├── service/                    # 【业务逻辑层】
│   │   └── mod.rs                  # Service 模块导出（本阶段占位）
│   │
│   ├── handler/                    # 【HTTP Handler 层】
│   │   ├── mod.rs
│   │   └── health.rs               # 健康检查 /health
│   │
│   ├── middleware/                 # 【中间件】
│   │   ├── mod.rs
│   │   ├── auth.rs                 # JWT 鉴权中间件（from_fn_with_state）
│   │   └── request_id.rs           # 请求 ID 注入中间件
│   │
│   ├── router/                     # 【路由定义】
│   │   ├── mod.rs                  # 路由聚合 + 全局中间件叠加
│   │   └── public.rs               # 公开路由（/health）
│   │
│   ├── jwt/                        # 【JWT 工具】
│   │   ├── mod.rs
│   │   └── claims.rs               # Claims + JwtUtils
│   │
│   ├── initialize/                 # 【初始化编排】
│   │   └── mod.rs                  # 集中编排：日志/配置/DB/Redis/路由
│   │
│   ├── utils/                      # 【通用工具】
│   │   ├── mod.rs
│   │   ├── password.rs             # 密码哈希（Argon2id + 旧 MD5 兼容验证）
│   │   ├── captcha.rs              # 验证码生成（base64 + uuid）
│   │   └── tree.rs                 # 通用树构建工具
│   │
│   ├── state.rs                    # AppState 共享状态
│   └── logger.rs                   # 日志体系初始化
│
└── migration/                      # ===== migration 子 crate =====
    ├── Cargo.toml                  # sea-orm-migration 依赖
    └── src/
        ├── lib.rs                  # MigratorTrait 实现
        ├── main.rs                 # 迁移命令行入口
        └── m20250711_000001_init.rs  # 首个空迁移骨架
```

### 3.1 各层职责

| 层级 | 目录 | 职责 | 禁止事项 |
|------|------|------|----------|
| Handler | `src/handler/` | 参数解析、调用 Service、结果封装为 `AjaxResult`/`TableDataInfo` | 禁止含业务逻辑 |
| Service | `src/service/` | 全部业务逻辑、事务控制、参数校验 | 禁止依赖 Web 类型 |
| Repository | `src/repository/` | 数据库查询封装，仅与 SeaORM 交互 | 禁止含业务逻辑 |
| Entity | `src/entity/` | SeaORM 实体定义（Model/ActiveModel/Column/Relation） | 禁止含查询逻辑 |
| Common | `src/common/` | 响应结构体、错误类型、分页参数、常量 | 无业务语义 |
| Config | `src/config/` | 配置结构体定义与加载 | 无副作用 |
| Migration | `migration/` | 数据库 schema 迁移（独立子 crate） | 禁止含业务逻辑 |
| Middleware | `src/middleware/` | JWT 鉴权、请求 ID 等横切关注 | 禁止含业务逻辑 |
| Initialize | `src/initialize/` | 初始化编排（日志/DB/Redis/路由） | 仅在启动时调用 |
| Utils | `src/utils/` | 密码、验证码、树构建等纯函数工具 | 无状态、无副作用 |

### 3.2 依赖方向

```
main.rs
  └── initialize ──→ router ──→ handler ──→ service ──→ repository ──→ entity
                       │            │            │            │
                       │            └────────────┴────────────┴──→ common
                       │
                       └──→ middleware ──→ jwt ──→ common
                       │
                       └──→ state ──→ db, config
                       │
                       └──→ utils（无依赖，纯函数）

migration（独立子 crate，不依赖主 crate）
  └──→ sea-orm-migration
```

**单向依赖规则：** handler → service → repository → entity，任何反向依赖视为违规。

---

## 4. 通用能力设计

### 4.1 统一响应结构体（对齐本项目前端）

> **契约来源：** 前端类型定义 `types/api/common.ts` + `utils/request.ts`

#### 4.1.1 普通响应 `AjaxResult<T>`

```rust
/// 普通接口响应（对齐前端 AjaxResult）
/// JSON: { "code": 200, "msg": "操作成功", "data": <T> }
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AjaxResult<T> {
    pub code: i32,
    pub msg: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<T>,
}
```

构造方法：
- `AjaxResult::success(data)` → `{ code: 200, msg: "操作成功", data: Some(data) }`
- `AjaxResult::success_msg(msg)` → `{ code: 200, msg, data: None }`
- `AjaxResult::error(code, msg)` → `{ code, msg, data: None }`

#### 4.1.2 分页响应 `TableDataInfo<T>`

```rust
/// 分页接口响应（对齐前端 TableDataInfo）
/// JSON: { "code": 200, "msg": "查询成功", "total": 100, "rows": [...] }
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TableDataInfo<T> {
    pub code: i32,
    pub msg: String,
    pub total: u64,
    pub rows: Vec<T>,
}
```

构造方法：
- `TableDataInfo::new(total, rows)` → `{ code: 200, msg: "查询成功", total, rows }`

#### 4.1.3 IntoResponse 实现

`AjaxResult<T>` 和 `TableDataInfo<T>` 均直接实现 `IntoResponse` trait，handler 无需手动包 `Json`：

```rust
impl<T: Serialize> IntoResponse for AjaxResult<T> {
    fn into_response(self) -> Response {
        (StatusCode::OK, Json(self)).into_response()
    }
}
```

**handler 返回类型简化对照：**

| 方式 | 返回类型 | 说明 |
|------|----------|------|
| ❌ 旧方式 | `Result<Json<AjaxResult<T>>, AppError>` | 需手动包 Json |
| ✅ 新方式 | `Result<AjaxResult<T>, AppError>` | 直接返回，IntoResponse 自动序列化 |

> **关键：** HTTP 状态码统一 200，业务错误由 body.code 表达。`AppError` 的 `IntoResponse` 也遵循此约定。

#### 4.1.4 状态码约定（前端 request.ts 拦截器行为）

| code | 含义 | 前端行为 |
|------|------|----------|
| `200` | 成功 | `resolve(res.data)`，业务层拿到整个响应体 |
| `401` | 未认证/会话过期 | 弹重新登录框，登出跳转 |
| `500` | 服务端错误 | `ElMessage.error(msg)` |
| `601` | 警告类错误 | `ElMessage.warning(msg)` |
| 其它非 200 | 通用错误 | `ElNotification.error({ title: msg })` |

> **关键：** HTTP 状态码统一返回 200，业务错误通过 body 中的 `code` 表达。`code` 必须是 `i32`。

### 4.2 全局错误类型

```rust
#[derive(Debug)]
pub struct AppError {
    pub code: i32,
    pub message: String,
}

impl AppError {
    pub fn new(code: i32, message: impl Into<String>) -> Self { ... }
    pub fn unauthorized(msg: &str) -> Self { Self::new(401, msg) }
    pub fn bad_request(msg: &str) -> Self { Self::new(400, msg) }
    pub fn not_found(msg: &str) -> Self { Self::new(404, msg) }
    pub fn internal(msg: &str) -> Self { Self::new(500, msg) }
}

impl IntoResponse for AppError {
    fn into_response(&self) -> Response {
        // HTTP 状态码始终 200，业务错误由 body.code 表达
        let body = Json(AjaxResult::<()>::error(self.code, &self.message));
        (StatusCode::OK, body).into_response()
    }
}
```

错误转换实现（`From` trait）完整对照表：

| 源错误 | 映射 code | 说明 |
|--------|-----------|------|
| `sea_orm::DbErr::RecordNotFound` | 404 | 记录不存在 |
| `sea_orm::DbErr::RecordNotUpdated` | 404 | 记录未更新 |
| `sea_orm::DbErr::ConnectionAcquire` | 503 | 连接池获取失败 |
| `sea_orm::DbErr::TryIntoErr` | 400 | 类型转换错误 |
| `sea_orm::DbErr::AttrNotSet` | 400 | 属性未设置 |
| `sea_orm::DbErr` (其它) | 500 | 数据库通用错误 |
| `jsonwebtoken::errors::Error` | 401 | JWT 验证失败 |
| `serde_json::Error` | 500 | 序列化错误 |
| `std::io::Error` | 500 | IO 错误 |
| `redis::RedisError` (AuthenticationFailed) | 401 | Redis 认证失败 |
| `redis::RedisError` (其它) | 500 | Redis 通用错误 |
| `anyhow::Error` | 500 | 通用错误兜底 |

### 4.3 配置管理

#### 4.3.1 配置结构体

```rust
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
    pub host: String,        // "0.0.0.0"
    pub port: u16,           // 8080
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
    pub url: String,              // "redis://127.0.0.1:6379/"
    pub max_connections: u32,     // 连接池大小
}

#[derive(Debug, Clone, Deserialize)]
pub struct JwtConfig {
    pub secret: String,
    pub expire_hours: i64,        // stepby 默认 24 小时
    pub issuer: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct LogConfig {
    pub level: String,            // "info" / "debug"
    pub sql_logging: bool,
}
```

#### 4.3.2 配置文件 `config/config.toml`

```toml
# ⚠️ 生产环境请务必修改 database.url 和 jwt.secret
# 此文件含敏感信息，生产环境建议加入 .gitignore

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
expire_hours = 24
issuer = "backend-axum"

[log]
level = "info"
sql_logging = true
```

#### 4.3.3 加载方式

```rust
impl Settings {
    pub fn from_file(path: &str) -> anyhow::Result<Self> {
        let content = std::fs::read_to_string(path)?;
        let settings: Settings = toml::from_str(&content)?;
        Ok(settings)
    }
}
```

配置加载后存入 `AppState`，通过 Axum `State` 注入。日志级别支持 `RUST_LOG` 环境变量覆盖。

### 4.4 数据库连接池

```rust
pub async fn init_database(config: &DatabaseConfig) -> anyhow::Result<DatabaseConnection> {
    let mut opt = ConnectOptions::new(&config.url);
    opt.max_connections(config.max_connections)
       .min_connections(config.min_connections)
       .connect_timeout(Duration::from_secs(config.connect_timeout))
       .idle_timeout(Duration::from_secs(config.idle_timeout))
       .sqlx_logging(config.sql_logging);
    let db = Database::connect(opt).await?;
    Ok(db)
}
```

**设计要点：**
- 使用 `ConnectOptions` 精细控制连接池参数
- 连接池实例存入 `AppState`，通过 `State<Arc<AppState>>` 注入
- 不使用 `OnceCell` 全局静态，统一采用 Axum State 注入共享状态

### 4.5 Redis 连接池

```rust
use redis::aio::ConnectionManager;

pub async fn init_redis(config: &RedisConfig) -> anyhow::Result<ConnectionManager> {
    let client = redis::Client::open(&config.url)?;
    let mut conn = ConnectionManager::new(client).await?;
    // 测试连接
    let pong: String = redis::cmd("PING").query_async(&mut conn).await?;
    tracing::info!("Redis 连接成功: {} (PING -> {})", config.url, pong);
    Ok(conn)
}
```

**设计要点：**
- 使用 `ConnectionManager`（自动重连，clone 成本低，内部 Arc 共享）
- 初始化时执行 PING 验证连通性
- `ConnectionManager` 实现了 `Clone`，可直接存入 `AppState` 并在 handler 间 clone
- 注意：`query_async` 接收 `&mut ConnectionManager`，无需 `conn.clone()`

**用途（本阶段预留，业务阶段启用）：**
- 验证码存储（`uuid -> code`，TTL 5 分钟）
- 登录 token 管理（`token -> user_id`，TTL 与 JWT 一致）
- 字典缓存

### 4.6 日志体系

```rust
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
}
```

**设计要点：**
- 基于 `tracing` + `tracing-subscriber`，与 Axum 的 `TraceLayer` 无缝集成
- 支持 `RUST_LOG` 环境变量覆盖配置文件级别
- SQL 日志由 `LogConfig.sql_logging` 控制（传递给 SeaORM `ConnectOptions`）
- 请求级追踪通过 `tower-http` 的 `TraceLayer` 实现

### 4.7 JWT 设计

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,        // 用户 ID
    pub username: String,   // 用户名
    pub exp: usize,         // 过期时间戳（秒）
    pub iat: usize,         // 签发时间戳（秒）
    pub iss: String,        // 签发者
}

pub struct JwtUtils;

impl JwtUtils {
    pub fn generate_token(user_id: &str, username: &str, config: &JwtConfig) -> anyhow::Result<String> {
        // HS 算法，密钥从 JwtConfig.secret
        let now = chrono::Utc::now();
        let exp = now + chrono::Duration::hours(config.expire_hours);
        let claims = Claims { sub: user_id.to_string(), username: username.to_string(),
                              exp: exp.timestamp() as usize, iat: now.timestamp() as usize,
                              iss: config.issuer.clone() };
        encode(&Header::default(), &claims, &EncodingKey::from_secret(config.secret.as_bytes()))?
    }

    pub fn verify_token(token: &str, config: &JwtConfig) -> anyhow::Result<Claims> {
        let mut validation = Validation::default();
        validation.set_issuer(&[&config.issuer]);
        let token_data = decode::<Claims>(token, &DecodingKey::from_secret(config.secret.as_bytes()), &validation)?;
        Ok(token_data.claims)
    }
}
```

### 4.8 中间件设计

#### 4.8.1 请求 ID 中间件

```rust
pub async fn request_id_middleware(mut req: Request, next: Next) -> Response {
    let request_id = uuid::Uuid::new_v4().to_string();
    req.extensions_mut().insert(RequestId(request_id.clone()));
    let mut response = next.run(req).await;
    response.headers_mut().insert("X-Request-Id", request_id.parse().unwrap());
    response
}
```

#### 4.8.2 JWT 鉴权中间件

```rust
use axum::extract::Request;
use axum::http::header::AUTHORIZATION;
use axum::middleware::Next;
use axum::response::Response;

/// JWT 鉴权中间件（from_fn_with_state 模式）
/// 手动提取 Authorization header，缺失时返回 401（对齐前端 request.ts 拦截器）
pub async fn auth_middleware(
    State(state): State<Arc<AppState>>,
    mut req: Request,
    next: Next,
) -> Result<Response, AppError> {
    // 手动提取 Authorization header（缺失返回 401，而非 400）
    let auth_header = req.headers().get(&AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| AppError::unauthorized("请求未携带 token，请重新登录"))?;

    // 解析 Bearer token（格式：Bearer <token>）
    let token = auth_header
        .strip_prefix("Bearer ")
        .ok_or_else(|| AppError::unauthorized("token 格式错误，应为 Bearer <token>"))?;

    // 验证 token 并注入 Claims
    let claims = JwtUtils::verify_token(token, &state.config.jwt)?;
    req.extensions_mut().insert(claims);
    Ok(next.run(req).await)
}
```

**挂载方式（在 router/mod.rs 中）：**

```rust
// 受保护路由通过 from_fn_with_state 挂载中间件
use axum::middleware::from_fn_with_state;
Router::new()
    .route("/system/user/list", get(handler::list_users))
    .layer(from_fn_with_state(state.clone(), auth_middleware))
```

> **关键设计：**
> - 手动提取 header 而非用 `TypedHeader` extractor 参数，确保 token 缺失时返回 401（对齐前端拦截器），而非 axum 默认的 400
> - 使用 `strip_prefix("Bearer ")` 解析 token，不依赖 `axum-extra` 的 `TypedHeader` extractor
> - 免鉴权路由（`/health`、`/login`、`/captchaImage`）不挂载此中间件

### 4.9 AppState 共享状态

```rust
#[derive(Clone)]
pub struct AppState {
    pub db: DatabaseConnection,
    pub redis: redis::aio::ConnectionManager,
    pub config: Arc<Settings>,
}
```

### 4.10 密码工具（Argon2id + 旧 MD5 兼容验证）

> **安全约束（与 `SECURITY.md` 一致）：** 密码使用 Argon2id 加盐哈希存储，禁用明文/可逆加密；MD5 仅作为旧哈希验证 fallback，用于兼容历史数据，新密码一律走 Argon2id。

#### 4.10.1 算法选型

| 算法 | 用途 | 说明 |
|------|------|------|
| **Argon2id** | 主算法（新密码加密与验证） | 2024 年密码哈希竞赛推荐，抗 GPU/ASIC 暴力破解；每用户独立随机盐（`SaltString::generate(&mut OsRng)`） |
| MD5 + 固定盐值 | 旧哈希验证 fallback（仅兼容历史数据） | 旧哈希格式为 32 位 hex（MD5 摘要），盐值常量 `LEGACY_SALT = "stepby_admin"`；不用于新密码加密 |

> **关键约束：** 旧 MD5 仅保留 `verify_legacy_md5` 一处使用点，禁止用于 `encrypt_password`。验证旧 MD5 哈希成功后，调用方应通过 `verify_password_with_upgrade_hint` 返回的 `needs_upgrade` 提示，将密码重新用 Argon2id 加密并落库，完成渐进式升级。

#### 4.10.2 encrypt_password（Argon2id + 随机盐）

```rust
use argon2::{
    password_hash::{rand_core::OsRng, PasswordHasher, SaltString},
    Argon2,
};

/// 加密密码（Argon2id + 随机盐）
///
/// 返回 Result 而非静默吞错，避免哈希失败时存入空密码。
/// 输出为 Argon2 标准编码字符串（以 `$argon2` 开头），含算法参数、盐值与哈希值。
pub fn encrypt_password(password: &str) -> Result<String, argon2::password_hash::Error> {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    let hash = argon2.hash_password(password.as_bytes(), &salt)?;
    Ok(hash.to_string())
}
```

#### 4.10.3 verify_password（自动识别哈希格式）

```rust
use argon2::{PasswordHash, PasswordVerifier, Argon2};

/// 密码验证结果（含是否需要升级哈希的提示）
pub struct PasswordVerifyResult {
    pub is_valid: bool,
    /// 若为 true，表示密码正确但使用的是旧 MD5 哈希，调用方应重新加密并存储
    pub needs_upgrade: bool,
}

/// 验证密码并返回是否需要升级哈希
///
/// 验证流程：
/// 1. 若 hashed 以 `$argon2` 开头 → 用 Argon2 验证（needs_upgrade = false）
/// 2. 否则 → 用旧 MD5 + 固定盐值验证，验证成功则 needs_upgrade = true
pub fn verify_password_with_upgrade_hint(password: &str, hashed: &str) -> PasswordVerifyResult {
    if hashed.is_empty() {
        return PasswordVerifyResult { is_valid: false, needs_upgrade: false };
    }
    if hashed.starts_with("$argon2") {
        if let Ok(parsed) = PasswordHash::new(hashed) {
            let is_valid = Argon2::default()
                .verify_password(password.as_bytes(), &parsed)
                .is_ok();
            return PasswordVerifyResult { is_valid, needs_upgrade: false };
        }
        return PasswordVerifyResult { is_valid: false, needs_upgrade: false };
    }
    // 旧格式：MD5 + 固定盐值
    let is_valid = verify_legacy_md5(password, hashed);
    PasswordVerifyResult { is_valid, needs_upgrade: is_valid }
}

/// 便捷包装：仅返回是否验证通过
pub fn verify_password(password: &str, hashed: &str) -> bool {
    verify_password_with_upgrade_hint(password, hashed).is_valid
}

/// 旧 MD5 + 固定盐值验证（仅用于兼容已存在的旧密码数据）
fn verify_legacy_md5(password: &str, hashed: &str) -> bool {
    use md5::{Digest, Md5};
    let salted = format!("{}{}", password, LEGACY_SALT);
    let mut hasher = Md5::new();
    hasher.update(salted.as_bytes());
    let computed: String = hasher.finalize().iter().map(|b| format!("{:02x}", b)).collect();
    computed == hashed
}
```

#### 4.10.4 密码复杂度策略（R19-1.3）

`validate_password_complexity` 在新增/重置/修改密码时强制校验：
- 必须包含至少 1 个字母（a-z 或 A-Z）
- 必须包含至少 1 个数字（0-9）
- 不得命中 Top 常见弱口令黑名单（`WEAK_PASSWORDS`，大小写不敏感，覆盖 admin123/password/123456 等 50+ 常见弱密码）
- 长度范围由 DTO 的 `#[garde(length(...))]` 保证

> **说明：** 数据库种子密码哈希直接写入（不经过 `validate_password_complexity`），故默认管理员 `admin123` 凭据初始化不受影响，但首次登录后应强制改密。`password_strength_score` 提供 0-4 评分供前端 UX 反馈。

### 4.11 验证码工具

```rust
use captcha::Captcha;
use captcha::filters::Noise;
use uuid::Uuid;

/// 验证码结果
pub struct CaptchaResult {
    pub uuid: String,       // 验证码 key（存 Redis）
    pub img_base64: String, // Base64 图片（不含 data:image/png;base64, 前缀）
    pub code: String,       // 验证码明文（存 Redis 用于校验）
}

/// 生成 4 位字母数字验证码（使用 captcha 1.0 API）
/// captcha 1.0 关键变化：
/// - add_chars(n) 返回 &mut Self（不再返回 String）
/// - view(w, h) 需要指定宽高
/// - as_base64() 直接返回 Option<String>（无需手动 base64 编码）
/// - chars_as_string() 获取验证码明文
/// - Noise::new(strength) 需要强度参数
pub fn generate_captcha() -> CaptchaResult {
    let mut captcha = Captcha::new();
    captcha.set_chars(&"ABCDEFGHJKLMNPQRSTUVWXYZ23456789".chars().collect::<Vec<_>>());

    // 5 位验证码（循环 add_char 直到达到 5 位，修复 captcha 1.0 字体跳过 bug）
    let target_len = 5usize;
    let mut retries = 0;
    while captcha.chars_as_string().len() < target_len && retries < 20 {
        captcha.add_char();
        retries += 1;
    }

    // 多重滤镜叠加：Noise(0.5) + Wave 扭曲 + Dots 干扰点
    captcha.apply_filter(Noise::new(0.5));
    captcha.apply_filter(Wave::new(2.0, 8.0).horizontal());
    captcha.apply_filter(Wave::new(3.0, 6.0).vertical());
    captcha.apply_filter(Dots::new(5).min_radius(2).max_radius(4));
    captcha.view(220, 120);

    let code = captcha.chars_as_string();
    let img_base64 = captcha.as_base64().unwrap_or_default();
    let uuid = Uuid::new_v4().to_string();

    CaptchaResult { uuid, img_base64, code }
}
```

### 4.12 树构建工具

```rust
/// 通用树节点 trait（通用树工具）
pub trait TreeNode {
    fn id(&self) -> i64;
    fn parent_id(&self) -> i64;
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

### 4.13 initialize 初始化编排

```rust
/// 初始化编排模块
pub struct AppInitializer;

impl AppInitializer {
    /// 执行完整初始化流程，返回 AppState
    pub async fn run(config_path: &str) -> anyhow::Result<Arc<AppState>> {
        // 1. 加载配置
        let settings = Arc::new(Settings::from_file(config_path)?);

        // 2. 初始化日志
        logger::init_logger(&settings.log);

        // 3. 初始化数据库
        let db = db::init_database(&settings.database).await?;

        // 4. 初始化 Redis
        let redis = db::init_redis(&settings.redis).await?;

        // 5. 构建 AppState
        Ok(Arc::new(AppState { db, redis, config: settings }))
    }
}
```

### 4.14 系统常量

```rust
/// 业务状态码常量（对齐本项目前端约定）
pub mod constants {
    pub const SUCCESS: i32 = 200;
    pub const UNAUTHORIZED: i32 = 401;
    pub const BAD_REQUEST: i32 = 400;
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
}
```

### 4.15 .gitignore 设计

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

> **安全提示：** `config/config.toml` 含数据库密码和 JWT 密钥。生产环境建议：
> 1. 将 `config/config.toml` 加入 `.gitignore`（取消注释）
> 2. 提供 `config/config.toml.example` 模板文件供新开发者参考
> 3. 生产环境通过环境变量覆盖敏感配置（本阶段暂不实现，留待后续扩展）

---

## 5. migration 子 crate 设计

> ⚠️ **本文档为第一阶段规格，仅描述首迁移骨架。** 后续迁移见 `migration/src/lib.rs` 注册表（截至 2026-08-04 共 31 个迁移，涵盖索引/字段调整/菜单/备份日志/任务/限流/i18n/IP 归属地/备份权限收紧/IP 库菜单父级修复等）。新增迁移请直接编辑 `migration/src/lib.rs` 的 `Migrator::migrations()` 注册表。

### 5.1 Cargo.toml

```toml
[package]
name = "migration"
version = "0.1.0"
edition = "2021"

[dependencies]
sea-orm-migration = { version = "1.1", features = ["runtime-tokio-rustls", "sqlx-mysql"] }
tokio = { version = "1", features = ["rt-multi-thread", "macros"] }
```

### 5.2 Migrator 结构

```rust
// migration/src/lib.rs
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

### 5.3 首个迁移骨架

```rust
// migration/src/m20250711_000001_init.rs
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

### 5.4 迁移命令行入口

```rust
// migration/src/main.rs
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

> **注意：** 使用 `#[tokio::main]`（与主 crate 一致），migration/Cargo.toml 已声明 tokio 依赖。sea-orm-migration 的 `prelude::*` 已包含 `Database`。

---

## 6. 接口契约对齐说明（与本项目前端）

### 6.1 响应格式

| 接口类型 | 响应结构 | 示例 |
|----------|----------|------|
| 普通接口 | `{ code, msg, data? }` | `{ "code": 200, "msg": "操作成功", "data": {...} }` |
| 分页接口 | `{ code, msg, total, rows }` | `{ "code": 200, "msg": "查询成功", "total": 100, "rows": [...] }` |

### 6.2 字段命名规范

- 序列化一律 **camelCase**：`#[serde(rename_all = "camelCase")]` 或逐字段 rename
- 主键命名：`userId` / `deptId` / `roleId` / `postId` / `menuId` / `dictId`
- 特殊字段：`phonenumber`（全小写，非 phoneNumber）
- 状态字段：`status` 取值 `'0'`（正常）/ `'1'`（停用），字符串类型
- 时间字段：`createTime` / `updateTime`，字符串格式 `"yyyy-MM-dd HH:mm:ss"`

### 6.3 Token 契约

- 请求头：`Authorization: Bearer <token>`
- 登录响应：`token` 字段位于顶层（与 `code`/`msg` 同级），非 `data.token`
- 标记 `isToken: false` 的接口后端不强制要求 token

### 6.4 分页参数

| 参数名 | 类型 | 说明 |
|--------|------|------|
| `pageNum` | number | 页码，1-based |
| `pageSize` | number | 每页条数 |
| `orderByColumn` | string | 排序字段（可选） |
| `isAsc` | string | `asc` / `desc`（可选） |
| `params[beginTime]` | string | 起始时间（嵌套展开） |
| `params[endTime]` | string | 结束时间（嵌套展开） |

### 6.5 服务端口

- 后端监听 **8080** 端口（对齐本项目前端的 vite proxy）
- 路由无全局前缀（`/login`、`/system/user/list` 直接生效）

---

## 7. 规则遵守声明

### 7.1 全局规则遵守

| 规则条目 | 本阶段遵守方式 |
|----------|----------------|
| 纯 Axum 0.8 + SeaORM 1.1 | Cargo.toml 仅声明指定版本，无 salvo/rbatis |
| 禁止复制外部源码 | 所有代码用 Axum + SeaORM 原生方式实现 |
| 单一 ORM | 仅使用 SeaORM，无其他 ORM |
| 单向分层 | handler → service → repository → entity，禁止反向 |
| 接口契约对齐 | 响应结构、字段命名、状态码 100% 对齐本项目前端 |
| 仅修改 axum-backend | 所有文件均在 backend-axum/ 内创建 |

### 7.2 开发优先原则执行

| 优先级 | 要点 | 本阶段应用场景 |
|--------|------|----------------|
| 第一 | 接口契约对齐前端 | 响应结构体字段名、状态码、Token 契约（密码算法改为 Argon2id，旧 MD5 fallback 用 LEGACY_SALT "stepby_admin"） |
| 第二 | Axum 官方最佳实践 | 分层架构、State 注入、initialize 编排、错误 IntoResponse、中间件 from_fn |
| 第三 | Axum + SeaORM 原生惯例 | SeaORM ConnectOptions 配置、paginate 分页查询模式 |
| 第四 | 业界通用做法 | 验证码接口设计（密码算法改为 Argon2id，旧 MD5 fallback 用 LEGACY_SALT "stepby_admin"） |

---

## 8. 交付物清单

| 文件 | 职责 |
|------|------|
| `Cargo.toml` | 主 crate 依赖清单 + workspace 声明 |
| `config/config.toml` | 运行配置文件 |
| `src/main.rs` | 应用入口 |
| `src/lib.rs` | 库入口，re-export 模块 |
| `src/config/settings.rs` | 配置结构体与加载 |
| `src/common/response.rs` | AjaxResult / TableDataInfo |
| `src/common/error.rs` | AppError + IntoResponse |
| `src/common/page.rs` | PageDomain |
| `src/common/constants.rs` | 系统常量 |
| `src/db/pool.rs` | 数据库连接池 |
| `src/db/redis.rs` | Redis 连接池 |
| `src/jwt/claims.rs` | Claims + JwtUtils |
| `src/middleware/auth.rs` | JWT 鉴权中间件 |
| `src/middleware/request_id.rs` | 请求 ID 中间件 |
| `src/initialize/mod.rs` | 初始化编排 |
| `src/utils/password.rs` | 密码哈希（Argon2id + 旧 MD5 兼容验证） |
| `src/utils/captcha.rs` | 验证码生成 |
| `src/utils/tree.rs` | 树构建工具 |
| `src/state.rs` | AppState |
| `src/logger.rs` | 日志初始化 |
| `src/handler/health.rs` | 健康检查 |
| `src/router/mod.rs` | 路由聚合 |
| `src/router/public.rs` | 公开路由 |
| `migration/Cargo.toml` | migration 子 crate 依赖 |
| `migration/src/lib.rs` | Migrator |
| `migration/src/main.rs` | 迁移入口 |
| `migration/src/m20250711_000001_init.rs` | 首个迁移骨架 |

---

✅ 自查结果：
- 无 salvo/rbatis 依赖引入 ✓
- 响应结构体字段（code/msg/data/rows/total）100% 对齐本项目前端 ✓
- 分层依赖单向（handler → service → repository → entity）✓
- 通用能力完整：响应/错误/配置/DB/Redis/日志/JWT/中间件/密码/验证码/树/initialize/常量 ✓
- migration 独立子 crate 已纳入设计 ✓
- 核心模块设计对照明确（initialize 编排、State 注入、错误转换）✓
- 版本号符合用户指定（Axum 0.8、SeaORM 1.1，全部升级到最新稳定版）✓
- 无违规点，无风险点 ✓
