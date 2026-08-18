# 鉴权体系任务清单（auth-tasks.md）

> **阶段：** 第四阶段「Axum 原生鉴权体系实现」
> **项目：** axum-backend
> **配套文档：** [auth-spec.md](./auth-spec.md)、[auth-checklist.md](./auth-checklist.md)
> **规则基线：** `axum-backend/.trae/rules/project-rules.md`（全程永久生效）

---

## 1. 任务总览

| 编号 | 任务 | 优先级 | 依赖 |
|------|------|--------|------|
| T00 | 改造 JWT 鉴权中间件（增加 Redis 黑名单校验） | P0 | — |
| T01 | 创建权限校验中间件（框架实现） | P0 | T00 |
| T02 | 创建 AuthService 认证服务（结构体 + 5 个方法） | P0 | — |
| T03 | 实现 AuthService 登录日志与浏览器/OS 解析辅助方法 | P0 | T02 |
| T04 | 实现 AuthService 菜单转路由函数 menu_to_router | P0 | T02 |
| T05 | 更新 service/mod.rs 声明 auth_service 模块 | P0 | T02, T03, T04 |
| T06 | 改造 AppState 注入 AuthService | P0 | T02 |
| T07 | 创建 auth_handler.rs（5 个接口 handler） | P0 | T02, T06 |
| T08 | 创建 auth_router.rs（公开 + 受保护两层路由） | P0 | T07 |
| T09 | 更新 handler/mod.rs 与 middleware/mod.rs 模块声明 | P0 | T07, T01 |
| T10 | 改造 router/public.rs 追加 /login、/captchaImage | P0 | T08 |
| T11 | 改造 router/mod.rs 合并 auth_router | P0 | T08, T10 |
| T12 | 编译验证 cargo check | P0 | T11 |
| T13 | 单元测试（菜单转路由、浏览器解析） | P1 | T12 |
| T14 | 前端接口契约对齐自查 | P0 | T12 |

---

## 2. 任务详细分解

### T00 改造 JWT 鉴权中间件

**文件：** `src/middleware/auth.rs`

**交付物：** 在现有 `auth_middleware` 基础上，于 JWT 签名验证通过后追加 Redis 黑名单校验。

**改造点：**
1. 现有流程：提取 Authorization header → 解析 Bearer token → `JwtUtils::verify_token` → 注入 Claims
2. 新增流程：在 `verify_token` 之后、注入 Claims 之前，插入 Redis 黑名单校验
3. **关键修正：** `verify_token` 返回 `anyhow::Result<Claims>`，直接用 `?` 会走 `From<anyhow::Error>` 映射为 500。必须用 `map_err` 显式映射为 401。

**关键代码：**

```rust
// JWT 验证（显式映射为 401，避免走 anyhow → 500）
let claims = JwtUtils::verify_token(token, &state.config.jwt)
    .map_err(|_| AppError::unauthorized("无效的会话，或者会话已过期，请重新登录"))?;

// 在 verify_token 成功后插入 Redis 黑名单校验
let blacklist_key = format!("blacklist:{}", token);
let mut redis = state.redis.clone();
let is_blacklisted: Option<String> = redis::cmd("GET")
    .arg(&blacklist_key)
    .query_async(&mut redis)
    .await
    .ok()
    .flatten();
if is_blacklisted.is_some() {
    return Err(AppError::unauthorized("会话已注销，请重新登录"));
}
```

**验收：**
- [ ] JWT 签名验证保留
- [ ] **JWT 验证失败显式 map_err 为 401**（不走 anyhow → 500）
- [ ] Redis 黑名单校验插入位置正确（verify_token 之后，insert Claims 之前）
- [ ] 黑名单命中返回 401「会话已注销，请重新登录」
- [ ] Redis 异常不阻断请求（`.ok().flatten()` 容错）
- [ ] `Operator` 提取器保持不变
- [ ] 无 `unwrap()` / `expect()` 调用

---

### T01 创建权限校验中间件

**文件：** `src/middleware/permission.rs`（新增）、`src/middleware/mod.rs`（追加导出）

**交付物：**
1. `RequirePerm` 结构体（权限标识载体）
2. `permission_middleware` 中间件函数
3. `mod.rs` 追加 `pub mod permission; pub use permission::{permission_middleware, RequirePerm};`

**关键代码：**

```rust
// src/middleware/permission.rs
use axum::extract::State;
use axum::middleware::Next;
use axum::response::Response;
use http::Request;

use crate::common::error::AppError;
use crate::jwt::claims::Claims;
use crate::state::AppState;
use std::sync::Arc;

/// 权限标识载体（通过 route_layer 注入 extensions）
#[derive(Debug, Clone)]
pub struct RequirePerm(pub &'static str);

/// 权限校验中间件
pub async fn permission_middleware(
    State(state): State<Arc<AppState>>,
    req: Request,
    next: Next,
) -> Result<Response, AppError> {
    // 1. 从 extensions 提取 Claims
    let claims = req.extensions().get::<Claims>().cloned()
        .ok_or_else(|| AppError::unauthorized("无法获取登录信息，请重新登录"))?;

    // 2. 从 extensions 提取 RequirePerm（无则放行）
    let required_perm = match req.extensions().get::<RequirePerm>() {
        Some(p) => p.0,
        None => return Ok(next.run(req).await),
    };

    // 3. 查询用户权限
    let user_id: i64 = claims.sub.parse()
        .map_err(|_| AppError::internal("用户 ID 解析失败"))?;
    let permissions = state.menu_service
        .get_permissions_by_user_id(user_id).await?;

    // 4. 超管短路
    if permissions.iter().any(|p| p == "*:*:*") {
        return Ok(next.run(req).await);
    }

    // 5. 权限匹配
    if permissions.iter().any(|p| p == required_perm) {
        Ok(next.run(req).await)
    } else {
        Err(AppError::new(403, "没有权限访问该资源"))
    }
}
```

**验收：**
- [ ] `RequirePerm` 结构体定义
- [ ] 中间件函数签名正确（`State<Arc<AppState>>` + `Request` + `Next`）
- [ ] 无 RequirePerm 时放行
- [ ] 超管短路（`*:*:*`）
- [ ] 权限不匹配返回 403
- [ ] `mod.rs` 导出完成
- [ ] 本阶段不在现有 CRUD 路由上叠加（仅框架实现）

---

### T02 创建 AuthService 认证服务

**文件：** `src/service/auth_service.rs`（新增）

**交付物：** `AuthService` 结构体 + 5 个核心方法

**结构体设计：**

```rust
pub struct AuthService {
    db: DatabaseConnection,
    user_service: SysUserService,
    role_service: SysRoleService,
    menu_service: SysMenuService,
    logininfor_repo: SysLogininforRepository,
    user_repo: SysUserRepository,  // 用于 update_login_info
}

impl AuthService {
    pub fn new(db: DatabaseConnection) -> Self {
        Self {
            user_service: SysUserService::new(db.clone()),
            role_service: SysRoleService::new(db.clone()),
            menu_service: SysMenuService::new(db.clone()),
            logininfor_repo: SysLogininforRepository::new(db.clone()),
            user_repo: SysUserRepository::new(db.clone()),
            db,
        }
    }
}
```

> **设计决策：** AuthService 持有 `SysUserRepository` 用于调用 `update_login_info`（该方法在 Repository 层，SysUserService 未暴露包装方法）。

**5 个核心方法签名：**

| 方法 | 签名 |
|------|------|
| `generate_captcha` | `async fn(&self, redis: &mut ConnectionManager) -> Result<CaptchaVo, AppError>` |
| `login` | `async fn(&self, dto: LoginDto, login_ip: &str, user_agent: &str, redis: &mut ConnectionManager, jwt_config: &JwtConfig) -> Result<LoginVo, AppError>` |
| `logout` | `async fn(&self, token: &str, redis: &mut ConnectionManager, jwt_config: &JwtConfig) -> Result<(), AppError>` |
| `get_info` | `async fn(&self, user_id: i64) -> Result<GetInfoVo, AppError>` |
| `get_routers` | `async fn(&self, user_id: i64) -> Result<Vec<RouterVo>, AppError>` |

> **注意：**
> - `login` 方法接收 `user_agent: &str` 用于解析浏览器/OS 写入登录日志
> - `get_info` 内部调用 `user_service.get_user_by_id` 返回 `UserVo`，需提取 `.user` 字段（`SysUserModel`）填入 `GetInfoVo.user`

**DTO/Vo 定义（同文件内，Service 层返回类型）：**

- `LoginDto`（登录请求，含 garde 注解）
- `LoginVo`（登录响应数据，仅 token 字段）
- `CaptchaVo`（验证码响应数据：captcha_enabled/img/uuid）
- `GetInfoVo`（用户信息响应数据：user/roles/permissions）
- `RouterVo`（路由节点）
- `MetaVo`（路由 meta 信息）

**Handler 层响应类型（在 auth_handler.rs 中定义，含 code/msg）：**

- `LoginResult` { code, msg, token } — token 在顶层
- `CaptchaResult` { code, msg, captcha_enabled, img, uuid } — 字段在顶层
- `GetInfoResult` { code, msg, user, roles, permissions } — 字段在顶层

> **关键设计：** Service 层返回 Vo（不含 code/msg），Handler 层包装为 Result（含 code/msg）并实现 `IntoResponse`。三个 Result 类型的业务字段在响应体**顶层**（非 `data` 内），对齐前端 `extends AjaxResult` 的契约。`getRouters` 和 `logout` 使用标准 `AjaxResult<T>` 包装。

**验收：**
- [ ] 结构体持有 5 个 Service/Repository + db（含 user_repo）
- [ ] 5 个方法签名完整
- [ ] DTO 使用 `#[serde(rename_all = "camelCase")]`
- [ ] DTO 使用 `#[derive(Validate)]` + garde 注解
- [ ] Service 不依赖 axum / tower 任何 Web 类型
- [ ] login 方法含 user_agent 参数
- [ ] get_info 方法从 UserVo 提取 .user 字段
- [ ] **get_info 方法清空 user.password = None**
- [ ] CaptchaResult/GetInfoResult/LoginResult 在 handler 层定义
- [ ] CaptchaResult/GetInfoResult/LoginResult 实现 IntoResponse
- [ ] CaptchaResult/GetInfoResult/LoginResult 字段在顶层（非 data 内）

---

### T03 实现登录日志与浏览器/OS 解析辅助方法

**文件：** `src/service/auth_service.rs`（T02 文件内追加）

**交付物：**
1. `write_login_log` 内部方法
2. `parse_browser` 辅助函数
3. `parse_os` 辅助函数

**关键代码：**

```rust
/// 写入登录日志
async fn write_login_log(
    &self,
    user_name: &str,
    login_ip: &str,
    status: &str,    // "0" 成功 / "1" 失败
    msg: &str,
    browser: &str,
    os: &str,
) -> Result<(), AppError> {
    let now = chrono::Local::now().naive_local();
    let am = sys_logininfor::ActiveModel {
        info_id: Set(0),  // 自增主键
        user_name: Set(Some(user_name.to_string())),
        ipaddr: Set(Some(login_ip.to_string())),
        login_location: Set(None),
        browser: Set(Some(browser.to_string())),
        os: Set(Some(os.to_string())),
        status: Set(Some(status.to_string())),
        msg: Set(Some(msg.to_string())),
        login_time: Set(Some(now)),
    };
    self.logininfor_repo.insert(am).await?;
    Ok(())
}

fn parse_browser(ua: &str) -> String {
    if ua.contains("Edge") { "Edge".into() }
    else if ua.contains("Chrome") { "Chrome".into() }
    else if ua.contains("Firefox") { "Firefox".into() }
    else if ua.contains("Safari") { "Safari".into() }
    else { "Unknown".into() }
}

fn parse_os(ua: &str) -> String {
    if ua.contains("Windows") { "Windows".into() }
    else if ua.contains("Mac OS") { "macOS".into() }
    else if ua.contains("Android") { "Android".into() }
    else if ua.contains("iPhone") || ua.contains("iPad") { "iOS".into() }
    else if ua.contains("Linux") { "Linux".into() }
    else { "Unknown".into() }
}
```

> **注意：** Edge 判断需在 Chrome 之前（Edge UA 含 Chrome 字符串）。

**验收：**
- [ ] `write_login_log` 正确构造 ActiveModel
- [ ] `info_id: Set(0)` 让数据库自增
- [ ] `parse_browser` Edge 优先于 Chrome
- [ ] `parse_os` 覆盖主流操作系统
- [ ] 无外部 UA 解析库依赖

---

### T04 实现 menu_to_router 转换函数

**文件：** `src/service/auth_service.rs`（T02 文件内追加）

**交付物：** `menu_to_router` 递归转换函数

**转换规则：**

| RouterVo 字段 | 转换规则 |
|---------------|----------|
| `name` | 优先 `route_name`，其次 `path`（前端不派生，直接使用后端返回值） |
| `path` | 顶级目录（parent_id==0 且 type=="M"）：`"/" + path`；其他：原样 |
| `hidden` | `status == "1"` |
| `redirect` | `is_frame==1 && type=="M"` → `"noRedirect"`；否则 None |
| `component` | None/空 → 顶级 `"Layout"` / 子级目录 `"ParentView"`；否则原样 |
| `always_show` | `visible=="0" && type!="C" && is_frame==1` → `Some(true)`；否则 None |
| `meta.title` | `menu_name` |
| `meta.icon` | `icon`（默认空字符串） |
| `meta.no_cache` | `is_cache == 1` |
| `meta.link` | `is_frame == 0` → `Some(path)`；否则 None |
| `children` | 递归转换，过滤 `menu_type == "F"`，空则 None |
| `query` | `menu.query` 原样 |

**验收：**
- [ ] 顶级目录 path 加 `/` 前缀
- [ ] component 默认值正确（Layout / ParentView）
- [ ] redirect 仅 M 类型且 is_frame==1 时为 noRedirect
- [ ] alwaysShow 条件正确
- [ ] **name 优先使用 route_name，其次 path**
- [ ] children 过滤 F 类型
- [ ] children 为空时返回 None
- [ ] 递归调用正确

---

### T05 更新 service/mod.rs 声明 auth_service 模块

**文件：** `src/service/mod.rs`

**交付物：**

```rust
//! 业务逻辑层（Service Layer）
pub mod sys_user_service;
pub mod sys_role_service;
pub mod sys_menu_service;
pub mod auth_service;  // 新增

pub use sys_user_service::SysUserService;
pub use sys_role_service::SysRoleService;
pub use sys_menu_service::SysMenuService;
pub use auth_service::AuthService;  // 新增
```

**验收：**
- [ ] 模块声明追加
- [ ] re-export AuthService

---

### T06 改造 AppState 注入 AuthService

**文件：** `src/state.rs`

**改造点：** AppState 新增 `auth_service: AuthService` 字段，构造函数中初始化。

**关键代码：**

```rust
pub struct AppState {
    pub db: DatabaseConnection,
    pub redis: ConnectionManager,
    pub config: Arc<Settings>,
    pub user_service: SysUserService,
    pub role_service: SysRoleService,
    pub menu_service: SysMenuService,
    pub auth_service: AuthService,  // 新增
}

impl AppState {
    pub fn new(db: DatabaseConnection, redis: ConnectionManager, config: Arc<Settings>) -> Self {
        Self {
            user_service: SysUserService::new(db.clone()),
            role_service: SysRoleService::new(db.clone()),
            menu_service: SysMenuService::new(db.clone()),
            auth_service: AuthService::new(db.clone()),  // 新增
            db, redis, config,
        }
    }
}
```

**验收：**
- [ ] AppState 新增 auth_service 字段
- [ ] 构造函数初始化 auth_service
- [ ] 不 derive(Clone)（通过 Arc<AppState> 共享）
- [ ] 编译通过

---

### T07 创建 auth_handler.rs

**文件：** `src/handler/auth_handler.rs`（新增）

**交付物：** 5 个接口的 handler 函数

| Handler 函数 | 路由 | 提取器 | 返回类型 |
|-------------|------|--------|----------|
| `captcha` | GET /captchaImage | State | `CaptchaResult`（字段在顶层） |
| `login` | POST /login | State + Json<LoginDto> | `LoginResult`（token 在顶层） |
| `logout` | POST /logout | State + Operator + HeaderMap | `AjaxResult<()>` |
| `get_info` | GET /getInfo | State + Operator | `GetInfoResult`（字段在顶层） |
| `get_routers` | GET /getRouters | State + Operator | `AjaxResult<Vec<RouterVo>>` |

**关键实现点：**

1. **captcha handler：**
   - 调用 `state.auth_service.generate_captcha(&mut state.redis.clone())`
   - 返回 `CaptchaResult { code: 200, msg: "操作成功", captcha_enabled: true, img, uuid }`

2. **login handler：**
   - 提取登录 IP（从 `X-Forwarded-For` 或 `X-Real-IP` 或连接地址）
   - 提取 User-Agent
   - 调用 `state.auth_service.login(dto, &login_ip, &user_agent, &mut redis, &state.config.jwt)`
   - 返回 `LoginResult { code: 200, msg: "操作成功".into(), token }`

3. **logout handler：**
   - 从 `Authorization` header 提取 Bearer token
   - 调用 `state.auth_service.logout(&token, &mut redis, &jwt_config)`
   - 返回 `AjaxResult::success_msg("退出成功")`

4. **get_info handler：**
   - 从 `Operator` 提取器获取 user_id
   - 调用 `state.auth_service.get_info(user_id)`（内部已清空 password）
   - 返回 `GetInfoResult { code: 200, msg: "操作成功", user, roles, permissions }`

5. **get_routers handler：**
   - 从 `Operator` 提取器获取 user_id
   - 调用 `state.auth_service.get_routers(user_id)`
   - 返回 `AjaxResult::success(routers)`

**LoginResult 结构体（token 在顶层）：**

```rust
#[derive(Serialize)]
pub struct LoginResult {
    pub code: i32,
    pub msg: String,
    pub token: String,
}

impl IntoResponse for LoginResult {
    fn into_response(self) -> Response {
        (StatusCode::OK, Json(self)).into_response()
    }
}
```

**login_ip 提取逻辑：**

```rust
fn extract_client_ip(headers: &HeaderMap) -> String {
    headers.get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.split(',').next())
        .map(|s| s.trim().to_string())
        .or_else(|| headers.get("x-real-ip")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string()))
        .unwrap_or_else(|| "127.0.0.1".to_string())
}
```

**验收：**
- [ ] 5 个 handler 函数实现
- [ ] login 返回 `LoginResult`（token 在顶层）
- [ ] logout 从 header 提取 token
- [ ] get_info / get_routers 使用 `Operator` 提取器
- [ ] login_ip 提取逻辑正确
- [ ] 无 `unwrap()` / `expect()`
- [ ] 错误自动转换为 `AppError`

---

### T08 创建 auth_router.rs

**文件：** `src/router/auth_router.rs`（新增）

**交付物：** 两个路由分组函数

```rust
use axum::routing::{get, post};
use axum::Router;

use crate::handler::auth_handler;
use crate::state::AppState;
use std::sync::Arc;

/// 公开路由（免鉴权）
pub fn public_auth_routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/captchaImage", get(auth_handler::captcha))
        .route("/login", post(auth_handler::login))
}

/// 受保护路由（需 auth_middleware）
pub fn protected_auth_routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/logout", post(auth_handler::logout))
        .route("/getInfo", get(auth_handler::get_info))
        .route("/getRouters", get(auth_handler::get_routers))
}
```

**验收：**
- [ ] 公开路由含 /captchaImage、/login
- [ ] 受保护路由含 /logout、/getInfo、/getRouters
- [ ] 返回类型为 `Router<Arc<AppState>>`
- [ ] 不在此处挂载 auth_middleware（由 router/mod.rs 统一挂载）

---

### T09 更新 handler/mod.rs 与 middleware/mod.rs 模块声明

**文件：** `src/handler/mod.rs`、`src/middleware/mod.rs`

**handler/mod.rs：**

```rust
pub mod auth_handler;  // 新增
pub mod sys_user_handler;
pub mod sys_role_handler;
pub mod sys_menu_handler;
```

**middleware/mod.rs：**

```rust
pub mod auth;
pub mod permission;  // 新增
pub mod request_id;

pub use auth::{auth_middleware, Operator};
pub use permission::{permission_middleware, RequirePerm};  // 新增
```

**验收：**
- [ ] handler/mod.rs 声明 auth_handler
- [ ] middleware/mod.rs 声明 permission 模块
- [ ] middleware/mod.rs 导出 RequirePerm

---

### T10 改造 router/public.rs 追加公开认证路由

**文件：** `src/router/public.rs`

**改造点：** 在现有 `/health` 基础上，merge auth_router 的公开路由。

```rust
use axum::routing::get;
use axum::Router;

use crate::handler;
use crate::router::auth_router;
use crate::state::AppState;
use std::sync::Arc;

pub fn public_routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/health", get(handler::health))
        .merge(auth_router::public_auth_routes())  // 新增
}
```

**验收：**
- [ ] /health 保留
- [ ] merge public_auth_routes
- [ ] 编译通过

---

### T11 改造 router/mod.rs 合并 auth_router

**文件：** `src/router/mod.rs`

**改造点：** protected 路由分组中 merge `protected_auth_routes`。

```rust
pub fn build_app(state: Arc<AppState>) -> Router {
    let protected = Router::new()
        .merge(auth_router::protected_auth_routes())  // 新增
        .merge(sys_user_router::user_routes())
        .merge(sys_role_router::role_routes())
        .merge(sys_menu_router::menu_routes())
        .layer(from_fn_with_state(state.clone(), auth_middleware));

    Router::new()
        .merge(public::public_routes())
        .merge(protected)
        .with_state(state)
        .layer(CompressionLayer::new())
        .layer(CorsLayer::permissive())
        .layer(TraceLayer::new_for_http())
        .layer(axum::middleware::from_fn(request_id_middleware))
}
```

**模块声明追加：**

```rust
pub mod auth_router;  // 新增
```

**验收：**
- [ ] protected 分组 merge protected_auth_routes
- [ ] auth_middleware 仅挂载在 protected 分组
- [ ] 全局中间件顺序不变（request_id 最外层）
- [ ] 编译通过

---

### T12 编译验证 cargo check

**命令：** `cargo check`、`cargo build`

**验收：**
- [ ] `cargo check` 通过，0 error
- [ ] `cargo build` 通过
- [ ] 无 warning（或 warning 可解释）
- [ ] 无 salvo / rbatis 依赖残留

---

### T13 单元测试编写

**文件：** `src/service/auth_service.rs` 内 `#[cfg(test)] mod tests`

**测试用例：**

1. **menu_to_router 转换测试：**
   - [ ] 顶级目录（parent_id=0, type=M）path 加 `/` 前缀
   - [ ] 顶级目录 component 默认为 "Layout"
   - [ ] 子级目录（parent_id!=0, type=M）component 默认为 "ParentView"
   - [ ] 菜单（type=C）component 原样保留
   - [ ] 按钮（type=F）从 children 中过滤
   - [ ] is_frame=0 时 meta.link 为 Some(path)
   - [ ] is_cache=1 时 meta.no_cache 为 true
   - [ ] status=1 时 hidden 为 true

2. **浏览器/OS 解析测试：**
   - [ ] `parse_browser` Chrome UA 返回 "Chrome"
   - [ ] `parse_browser` Edge UA 返回 "Edge"（Edge 优先）
   - [ ] `parse_browser` Firefox UA 返回 "Firefox"
   - [ ] `parse_os` Windows UA 返回 "Windows"
   - [ ] `parse_os` Mac UA 返回 "macOS"

**验收：**
- [ ] `cargo test` 通过
- [ ] 测试覆盖核心转换逻辑

---

### T14 前端接口契约对齐自查

**检查项：**

- [ ] `GET /captchaImage` 响应对齐前端 `CaptchaInfoResult`（captchaEnabled / img / uuid）
- [ ] `POST /login` 响应对齐前端 `LoginInfoResult`（token 在顶层）
- [ ] `POST /login` 请求体对齐前端 `login` 函数参数（username / password / code / uuid）
- [ ] `POST /logout` 响应对齐前端（code: 200, msg: "退出成功"）
- [ ] `GET /getInfo` 响应对齐前端 `UserInfoResult`（user / roles / permissions）
- [ ] `GET /getRouters` 响应对齐前端 `RouterVo`（name / path / hidden / redirect / component / alwaysShow / meta / query / children）
- [ ] `MetaVo` 字段对齐（title / icon / noCache / link）
- [ ] 用户信息中 password 字段不返回（或为空）
- [ ] roles 超管为 ["admin"]，普通用户为实际角色 key 列表
- [ ] permissions 超管为 ["*:*:*"]，普通用户为实际权限标识列表
- [ ] 所有响应 code=200 表示成功（对齐本项目前端，非旧框架的 code=0）
- [ ] 错误响应 code=500，msg 为错误信息

**验收：**
- [ ] 字段对齐报告输出
- [ ] 前端可无缝联调

---

## 3. 任务依赖关系

```
T00 (改造 JWT 中间件) ─┐
                       ├─→ T12 (编译验证)
T01 (权限中间件) ──────┤
                       │
T02 (AuthService) ─→ T03 (日志/解析) ─→ T05 (mod.rs)
                  ─→ T04 (menu_to_router) ─┘
                       │
T06 (AppState) ─→ T07 (auth_handler) ─→ T08 (auth_router) ─→ T11 (router/mod.rs) ─→ T12
                                       │
T09 (模块声明) ─────────────────────────┘
                                       │
T10 (public.rs) ──────────────────────┘
                                       │
T12 (编译验证) ─→ T13 (单元测试)
              ─→ T14 (契约对齐自查)
```

---

## 4. 文件变更清单

### 4.1 新增文件

| 文件 | 任务 | 说明 |
|------|------|------|
| `src/service/auth_service.rs` | T02, T03, T04 | 认证服务 + DTO/Vo + 辅助函数 |
| `src/handler/auth_handler.rs` | T07 | 5 个接口 handler |
| `src/router/auth_router.rs` | T08 | 公开 + 受保护路由分组 |
| `src/middleware/permission.rs` | T01 | 权限校验中间件 |

### 4.2 修改文件

| 文件 | 任务 | 改动点 |
|------|------|--------|
| `src/middleware/auth.rs` | T00 | 追加 Redis 黑名单校验 |
| `src/middleware/mod.rs` | T09 | 声明 permission 模块 |
| `src/service/mod.rs` | T05 | 声明 auth_service 模块 |
| `src/state.rs` | T06 | AppState 注入 AuthService |
| `src/handler/mod.rs` | T09 | 声明 auth_handler 模块 |
| `src/router/mod.rs` | T11 | 合并 auth_router |
| `src/router/public.rs` | T10 | merge public_auth_routes |

---

## 5. 验收里程碑

| 里程碑 | 对应任务 | 验收命令 |
|--------|----------|----------|
| 中间件就绪 | T00, T01 | `cargo check` |
| Service 层就绪 | T02-T05 | `cargo check` |
| Handler/Router 就绪 | T06-T11 | `cargo check` |
| 编译通过 | T12 | `cargo build` |
| 测试通过 | T13 | `cargo test` |
| 契约对齐 | T14 | 手动核对前端 TS 定义 |
