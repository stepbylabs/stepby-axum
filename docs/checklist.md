# 工程脚手架与基础框架 校验清单（checklist.md）

> **阶段：** 第一阶段「工程脚手架与基础框架」
> **对应规范：** `docs/spec.md`
> **对应任务：** `docs/tasks.md`
> **规则基线：** `stepby-axum/.trae/rules/project-rules.md`
> **用途：** 执行完所有任务后，逐项核对验收。任一项未通过视为阶段未完成。

---

## 1. 全局规则合规性校验

### 1.1 绝对禁令核对

- [ ] Cargo.toml 中 **无 salvo 依赖**（搜索 `salvo` 无结果）
- [ ] Cargo.toml 中 **无 rbatis 依赖**（搜索 `rbatis` 无结果）
- [ ] 源码中 **无 `#[handler]` 宏** 使用
- [ ] 源码中 **无 Depot 容器** 使用
- [ ] 源码中 **无 Salvo 专属 Request/Response** 使用
- [ ] 源码中 **无 rbatis 注解式查询** 使用
- [ ] **未直接复制**外部源码（所有逻辑用 Axum + SeaORM 原生方式实现）
- [ ] **单一 ORM**：全程使用 SeaORM，无其他 ORM（diesel/sqlx 直接调用等）
- [ ] Service 层 **无 Axum/Web 类型**（搜索 `axum::http`、`axum::extract`、`axum::Json` 在 service/ 下无结果）
- [ ] Repository 层 **无 Web 类型**（同上）
- [ ] **未修改**任何外部项目或框架的源码

### 1.2 分层依赖校验

- [ ] Handler 层（`src/handler/`）仅做参数解析、服务调用、结果封装
- [ ] Service 层（`src/service/`）承载业务逻辑（本阶段为空，结构已就绪）
- [ ] Repository 层（`src/repository/`）仅与 SeaORM 交互（本阶段为空，结构已就绪）
- [ ] 依赖方向单向：`handler → service → repository → entity`
- [ ] 无反向依赖（entity 不引用 handler/service/repository）
- [ ] migration 子 crate **独立于主 crate**（不依赖 stepby-axum）

### 1.3 输出规范校验

- [ ] 所有文件均在 `stepby-axum/` 目录内
- [ ] 代码使用蛇形命名法（snake_case）
- [ ] 核心逻辑添加必要注释
- [ ] 错误处理完善（无 `unwrap()` 暴露到请求路径，`main.rs` 中的 `expect` 仅限启动阶段）

---

## 2. 目录结构校验

### 2.1 主 crate 必需目录与文件

- [ ] `stepby-axum/Cargo.toml` 存在且依赖完整 + `[workspace]` 声明
- [ ] `stepby-axum/config/config.toml` 存在
- [ ] `stepby-axum/.gitignore` 存在（忽略 `/target`）
- [ ] `stepby-axum/src/main.rs` 存在
- [ ] `stepby-axum/src/lib.rs` 存在（声明全部 17 个模块）
- [ ] `stepby-axum/src/config/mod.rs` 存在
- [ ] `stepby-axum/src/config/settings.rs` 存在
- [ ] `stepby-axum/src/common/mod.rs` 存在
- [ ] `stepby-axum/src/common/response.rs` 存在
- [ ] `stepby-axum/src/common/error.rs` 存在
- [ ] `stepby-axum/src/common/page.rs` 存在
- [ ] `stepby-axum/src/common/constants.rs` 存在
- [ ] `stepby-axum/src/db/mod.rs` 存在
- [ ] `stepby-axum/src/db/pool.rs` 存在
- [ ] `stepby-axum/src/db/redis.rs` 存在
- [ ] `stepby-axum/src/entity/mod.rs` 存在（占位）
- [ ] `stepby-axum/src/repository/mod.rs` 存在（占位）
- [ ] `stepby-axum/src/service/mod.rs` 存在（占位）
- [ ] `stepby-axum/src/handler/mod.rs` 存在
- [ ] `stepby-axum/src/handler/health.rs` 存在
- [ ] `stepby-axum/src/middleware/mod.rs` 存在
- [ ] `stepby-axum/src/middleware/auth.rs` 存在
- [ ] `stepby-axum/src/middleware/request_id.rs` 存在
- [ ] `stepby-axum/src/router/mod.rs` 存在
- [ ] `stepby-axum/src/router/public.rs` 存在
- [ ] `stepby-axum/src/jwt/mod.rs` 存在
- [ ] `stepby-axum/src/jwt/claims.rs` 存在
- [ ] `stepby-axum/src/initialize/mod.rs` 存在
- [ ] `stepby-axum/src/utils/mod.rs` 存在
- [ ] `stepby-axum/src/utils/password.rs` 存在
- [ ] `stepby-axum/src/utils/captcha.rs` 存在
- [ ] `stepby-axum/src/utils/tree.rs` 存在
- [ ] `stepby-axum/src/state.rs` 存在
- [ ] `stepby-axum/src/logger.rs` 存在

### 2.2 migration 子 crate 文件

- [ ] `stepby-axum/migration/Cargo.toml` 存在
- [ ] `stepby-axum/migration/src/lib.rs` 存在
- [ ] `stepby-axum/migration/src/main.rs` 存在
- [ ] `stepby-axum/migration/src/migrations/m20250711_000001_init.rs` 存在
      （迁移文件在批五十前后从 `migration/src/` 归拢到 `migration/src/migrations/`，检查单一直未跟着改，实测三处引用指向不存在的路径）

### 2.3 禁止存在的文件

- [ ] 无业务模块文件（`src/handler/sys_user.rs` 等业务阶段才创建）
- [ ] 无 `ref-` 项目被修改的痕迹

---

## 3. Cargo.toml 依赖校验

### 3.1 主 crate 核心依赖版本

- [ ] `axum = "0.8"`
- [ ] `axum-extra = "0.12"`（features 含 `typed-header`）
- [ ] `sea-orm = "1.1"`（features 含 `runtime-tokio-rustls, sqlx-mysql, macros, with-chrono, debug-print`）
- [ ] `tokio = "1"`（features 含 `rt-multi-thread, macros, signal`）
- [ ] `jsonwebtoken = "10"`
- [ ] `tower = "0.5"`
- [ ] `tower-http = "0.7"`（features 含 `cors, trace, compression-gzip`）
- [ ] `serde = "1"`（features 含 `derive`）
- [ ] `serde_json = "1"`
- [ ] `tracing = "0.1"`
- [ ] `tracing-subscriber = "0.3"`（features 含 `env-filter, fmt`）
- [ ] `chrono = "0.4"`（features 含 `serde`）
- [ ] `uuid = "1"`（features 含 `v4`）
- [ ] `redis = "1.3"`（features 含 `tokio-comp`）
- [ ] `md-5 = "0.10"`
- [ ] `captcha = "1.0"`
- [ ] `anyhow = "1"`
- [ ] `toml = "1"`
- [ ] `garde = "0.23"`（features 含 `full`）
- [ ] `[workspace]` 段含 `members = ["migration"]`

> **依赖说明：** `thiserror`（自定义错误类型派生）、`base64`（TOTP QR 码编码）、`rand`（AES-GCM nonce 生成）已重新引入并有实际用途；`once_cell` 已移除（用 State 注入）。

### 3.2 migration 子 crate 依赖

- [ ] `sea-orm-migration = "1.1"`（features 含 `runtime-tokio-rustls, sqlx-mysql`）
- [ ] `tokio = "1"`（features 含 `rt-multi-thread, macros`）

### 3.3 版本兼容性

- [ ] axum 0.8 与 axum-extra 0.12 兼容
- [ ] sea-orm 1.1 与 sea-orm-migration 1.1 兼容
- [ ] tower-http 0.7 与 axum 0.8 兼容
- [ ] redis 1.3 的 `tokio-comp` feature 启用
- [ ] captcha 1.0 API 适配（add_chars 返回 &mut Self、view 需宽高参数、as_base64 直接返回 Option<String>）

---

## 4. 通用能力校验

### 4.1 统一响应结构体

- [ ] `AjaxResult<T>` 含字段 `code: i32`、`msg: String`、`data: Option<T>`
- [ ] `AjaxResult::success(data)` 返回 `code: 200`、`msg: "操作成功"`
- [ ] `AjaxResult::error(code, msg)` 返回指定 code 与 msg
- [ ] `data` 字段使用 `#[serde(skip_serializing_if = "Option::is_none")]`
- [ ] `AjaxResult<T>` 实现 `IntoResponse`（`impl<T: Serialize> IntoResponse`）
- [ ] `TableDataInfo<T>` 含字段 `code: i32`、`msg: String`、`total: u64`、`rows: Vec<T>`
- [ ] `TableDataInfo::new(total, rows)` 返回 `code: 200`、`msg: "查询成功"`
- [ ] `TableDataInfo<T>` 实现 `IntoResponse`
- [ ] **分页响应不含 `data` 字段**（只有 `rows` + `total`）
- [ ] handler 直接返回 `Result<AjaxResult<T>, AppError>`（无需手动包 `Json`）

### 4.2 全局错误类型

- [ ] `AppError` 含 `code: i32`、`message: String`
- [ ] 实现 `IntoResponse` trait
- [ ] `into_response()` 返回 HTTP 200 + JSON body（业务错误由 `body.code` 表达）
- [ ] 实现 `From<sea_orm::DbErr>`（RecordNotFound/RecordNotUpdated → 404，ConnectionAcquire → 503，TryIntoErr/AttrNotSet → 400，其它 → 500）
- [ ] 实现 `From<jsonwebtoken::errors::Error>`（→ 401）
- [ ] 实现 `From<serde_json::Error>`（→ 500）
- [ ] 实现 `From<std::io::Error>`（→ 500）
- [ ] 实现 `From<redis::RedisError>`（AuthenticationFailed → 401，其它 → 500）
- [ ] 实现 `From<anyhow::Error>`（→ 500 兜底）

### 4.3 分页参数

- [ ] `PageDomain` 含 `page_num`、`page_size`、`order_by_column`、`is_asc`
- [ ] 使用 `#[serde(rename_all = "camelCase")]` 对齐前端 `pageNum`/`pageSize`
- [ ] `page_num` 默认值 1，`page_size` 默认值 10
- [ ] `offset()` 方法计算 `(page_num - 1) * page_size`
- [ ] `limit()` 方法返回 `page_size`

### 4.4 系统常量

- [ ] `constants` 模块含 `SUCCESS`/`BAD_REQUEST`/`UNAUTHORIZED`/`NOT_FOUND`/`INTERNAL_ERROR`/`WARNING`
- [ ] 含 `STATUS_NORMAL`（"0"）/ `STATUS_DISABLED`（"1"）
- [ ] 含 `SUPER_ADMIN_ROLE`（"admin"）/ `ALL_PERMISSIONS`（"*:*:*"）
- [ ] 含 `password.rs` 中 `LEGACY_SALT` 常量（"stepby_admin"，仅旧 MD5 验证用）

### 4.5 配置管理

- [ ] `Settings` 含 `server`、`database`、`redis`、`jwt`、`log` 五个配置段
- [ ] `ServerConfig` 含 `host: String`、`port: u16`
- [ ] `DatabaseConfig` 含 `url`、`max_connections`、`min_connections`、`connect_timeout`、`idle_timeout`
- [ ] `RedisConfig` 含 `url`、`max_connections`
- [ ] `JwtConfig` 含 `secret`、`expire_hours`、`issuer`
- [ ] `LogConfig` 含 `level`、`sql_logging`
- [ ] `Settings::from_file(path)` 可从 toml 文件加载
- [ ] `config/config.toml` 各字段与结构体匹配（含 `[redis]` 段）

### 4.6 数据库连接池

- [ ] `init_database()` 使用 `ConnectOptions` 配置连接池
- [ ] `max_connections` / `min_connections` 从配置读取
- [ ] `sqlx_logging` 受 `LogConfig.sql_logging` 控制
- [ ] 返回 `DatabaseConnection` 实例

### 4.7 Redis 连接池

- [ ] `init_redis()` 使用 `ConnectionManager`（自动重连）
- [ ] 初始化时执行 PING 测试
- [ ] 返回 `ConnectionManager` 实例
- [ ] 失败时返回 `anyhow::Error`

### 4.8 日志体系

- [ ] `init_logger()` 使用 `tracing_subscriber`
- [ ] 支持 `RUST_LOG` 环境变量覆盖（`EnvFilter::try_from_default_env`）
- [ ] 默认级别从 `LogConfig.level` 读取
- [ ] 输出包含模块路径（`with_target(true)`）、文件名（`with_file(true)`）、行号（`with_line_number(true)`）

### 4.9 JWT 工具

- [ ] `Claims` 含 `sub`、`username`、`exp`、`iat`、`iss`
- [ ] `JwtUtils::generate_token()` 生成 token（HS 算法，密钥从 `JwtConfig.secret`）
- [ ] `JwtUtils::verify_token()` 验证 token 并返回 `Claims`
- [ ] 过期时间从 `JwtConfig.expire_hours` 计算
- [ ] 验证时校验 issuer（`validation.set_issuer`）

### 4.10 密码工具

- [ ] `encrypt_password()` 使用 Argon2id + 随机盐（旧 MD5 仅作 fallback 验证）
- [ ] `verify_password()` 比对加密结果
- [ ] 单元测试 `test_encrypt_and_verify` 通过
- [ ] 旧 MD5 盐值常量 `LEGACY_SALT`（"stepby_admin"）仅用于旧密码验证（非新密码加密）

### 4.11 验证码工具

- [ ] `generate_captcha()` 返回 `CaptchaResult`（含 `uuid`、`img_base64`、`code`）
- [ ] 验证码字符集排除易混淆字符（`ABCDEFGHJKLMNPQRSTUVWXYZ23456789`）
- [ ] 验证码长度 5 位
- [ ] 图片输出为 Base64 编码
- [ ] uuid 使用 `Uuid::new_v4()`
- [ ] 使用 captcha 1.0 API：`set_chars` 设置字符集、`add_char()` 循环添加至 5 位
- [ ] `apply_filter(Noise::new(0.5))` 使用强度参数（非 0.0.9 的无参 Noise）
- [ ] `view(220, 120)` 指定宽高尺寸
- [ ] `chars_as_string()` 获取验证码明文
- [ ] `as_base64()` 直接返回 Base64 字符串（无需手动 base64 编码）

### 4.12 树构建工具

- [ ] `TreeNode` trait 含 `id()`、`parent_id()`、`children_mut()` 方法
- [ ] `build_tree()` 接收扁平列表与 `root_parent_id`，返回树结构
- [ ] 递归构建子节点

### 4.13 中间件

- [ ] `request_id_middleware` 为每个请求生成 UUID
- [ ] RequestId 注入到 `request.extensions_mut()`
- [ ] 响应头包含 `X-Request-Id`
- [ ] `auth_middleware` 使用 `State<Arc<AppState>>` 注入（from_fn_with_state 模式）
- [ ] `auth_middleware` **手动提取** Authorization header（非 TypedHeader extractor 参数）
- [ ] token 缺失时返回 401（对齐前端拦截器跳转登录，非 axum 默认 400）
- [ ] 解析 `Bearer <token>` 格式（`strip_prefix("Bearer ")`）
- [ ] 验证成功后 Claims 注入到 `request.extensions_mut()`
- [ ] 验证失败返回 `AppError::unauthorized`（code 401）

### 4.14 AppState

- [ ] `AppState` 含 `db: DatabaseConnection`、`redis: ConnectionManager`、`config: Arc<Settings>`
- [ ] 实现 `Clone`（`DatabaseConnection` 和 `ConnectionManager` 内部 Arc 所以可 Clone）
- [ ] 通过 `State<Arc<AppState>>` 注入到 handler

### 4.15 initialize 初始化编排

- [ ] `AppInitializer::run()` 集中编排初始化流程
- [ ] 初始化顺序：配置 → 日志 → DB → Redis → AppState
- [ ] 返回 `Arc<AppState>`

---

## 5. migration 子 crate 校验

- [ ] `Migrator` 实现 `MigratorTrait`
- [ ] `migrations()` 返回首个迁移 `m20250711_000001_init`
- [ ] 首个迁移 `up()` 和 `down()` 为空实现（骨架）
- [ ] `main.rs` 从 `DATABASE_URL` 环境变量读取连接串（有默认值）
- [ ] `cargo build -p migration` 编译成功
- [ ] `cargo run -p migration` 可执行（需数据库可用）

---

## 6. 接口契约对齐校验（与本项目前端）

### 6.1 响应格式

- [ ] 普通响应 JSON 字段名为 `code`、`msg`、`data`（非 `message`/`result`）
- [ ] 分页响应 JSON 字段名为 `code`、`msg`、`total`、`rows`（非 `list`/`records`）
- [ ] 成功 code = `200`（i32 类型）
- [ ] 401 code = `401`，500 code = `500`
- [ ] `msg` 为中文提示（"操作成功"/"查询成功"）

### 6.2 服务端口

- [ ] 默认监听 `0.0.0.0:8080`（对齐 vite proxy `http://localhost:8080`）
- [ ] 路由无全局前缀（`/health` 直接生效，非 `/api/health`）

### 6.3 字段命名

- [ ] 响应字段序列化使用 camelCase
- [ ] 分页参数字段名 `page_num`/`page_size` 反序列化时对齐前端 `pageNum`/`pageSize`（`#[serde(rename_all = "camelCase")]`）

### 6.4 密码兼容性

- [ ] 密码算法为 Argon2id + 随机盐（旧 MD5 仅作 fallback 验证）
- [ ] 初始数据密码使用 Argon2id 生成（不兼容旧密码）

---

## 7. 编译与运行校验

### 7.1 编译

- [ ] `cargo build` 成功，无 error
- [ ] `cargo build -p migration` 成功，无 error
- [ ] `cargo build --release` 成功
- [ ] 无 unused dependency 警告（或已说明原因）
- [ ] Task 1 创建的占位 `main.rs`（`fn main() {}`）可独立通过 `cargo check`
- [ ] Task 20 集成 `lib.rs` 后 `cargo check` 首次全量检查所有模块代码

### 7.2 单元测试

- [ ] `cargo test` 成功
- [ ] `test_encrypt_and_verify` 测试通过

### 7.3 运行（需 MySQL + Redis 可用）

- [ ] `cargo run` 启动成功
- [ ] 日志输出 `数据库连接成功`
- [ ] 日志输出 `Redis 连接成功`（含 PING 响应）
- [ ] 日志输出 `服务启动于 http://0.0.0.0:8080`
- [ ] 进程持续运行不退出

### 7.4 接口冒烟测试

- [ ] `curl http://localhost:8080/health` 返回 HTTP 200
- [ ] 响应 body 包含 `"code":200`
- [ ] 响应 body 包含 `"msg":"操作成功"`
- [ ] 响应 body 包含 `"data":{"status":"UP","version":"0.1.0"}`
- [ ] 响应头包含 `X-Request-Id` 字段
- [ ] 响应头包含 `Content-Type: application/json`

### 7.5 migration 验证

- [ ] `DATABASE_URL="..." cargo run -p migration` 输出 `迁移完成`
- [ ] 数据库 `seaql_migrations` 表记录迁移状态

### 7.6 日志验证

- [ ] 请求 `/health` 后，终端日志输出请求记录（含 method、uri、status、latency）
- [ ] 日志格式包含时间戳、模块路径、日志级别

---

## 8. 文档校验

- [ ] `docs/spec.md` 存在且内容完整（含目录结构、依赖清单、通用能力设计、migration 设计、核心模块设计对照）
- [ ] `docs/tasks.md` 存在且任务分解完整（23 个任务，每个含完整代码块）
- [ ] `docs/checklist.md` 存在（本文件）
- [ ] spec.md 含核心模块设计对照表
- [ ] tasks.md 每个任务包含完整代码块（无占位符、无 TBD/TODO）
- [ ] 文档中无 "TBD" / "待补充" 等占位标记

---

## 9. 自查结果模板

执行完所有任务后，填写以下自查结果：

```
✅ 自查结果

全局规则合规性：
- 无 salvo/rbatis 依赖：✓
- 单一 ORM（SeaORM）：✓
- 分层单向依赖：✓
- 未修改 ref- 项目：✓

目录结构：
- 主 crate 必需文件全部存在：✓
- migration 子 crate 文件全部存在：✓
- 无禁止文件：✓

依赖版本：
- Axum 0.8：✓
- SeaORM 1.1：✓
- Redis 1.3：✓
- captcha 1.0 API 适配：✓
- 版本兼容性：✓

通用能力：
- 统一响应结构体（AjaxResult/TableDataInfo）：✓
- 全局错误类型（AppError + IntoResponse + From 转换）：✓
- 配置管理（Settings + toml，含 Redis 配置段）：✓
- 数据库连接池（ConnectOptions）：✓
- Redis 连接池（ConnectionManager）：✓
- 日志体系（tracing-subscriber）：✓
- JWT 工具（Claims + JwtUtils）：✓
- 密码工具（Argon2id + 随机盐，旧 MD5 仅 fallback）：✓
- 验证码工具（captcha + base64）：✓
- 树构建工具（TreeNode + build_tree）：✓
- 中间件（request_id + auth）：✓
- AppState 共享状态（DB + Redis + Config）：✓
- initialize 初始化编排：✓
- 系统常量：✓

migration 子 crate：
- MigratorTrait 实现：✓
- 首个迁移骨架：✓
- 独立编译运行：✓

接口契约对齐：
- 响应字段名（code/msg/data/rows/total）：✓
- 状态码（200/401/500）：✓
- 服务端口（8080）：✓
- 密码算法 Argon2id（不兼容旧密码）：✓

编译运行：
- cargo build 成功：✓
- cargo build -p migration 成功：✓
- cargo test 通过：✓
- 服务启动成功：✓
- /health 接口正常：✓
- X-Request-Id 响应头：✓
- migration 可执行：✓

违规点：无
风险点：无
```

---

## 10. 阶段完成判定

**全部以下条件满足时，本阶段视为完成：**

1. 上述所有 `- [ ]` 项全部勾选为 `- [x]`
2. `cargo build` 零 error（主 crate + migration 子 crate）
3. `cargo test` 单元测试通过
4. `cargo run` 服务可启动（DB + Redis 可用时）
5. `/health` 接口返回符合预期的 JSON 响应
6. `X-Request-Id` 响应头存在
7. `cargo run -p migration` 可执行迁移
8. 自查结果无违规点、无风险点
9. 所有代码已提交到版本库
