# Axum 原生鉴权体系设计文档（auth-spec.md）

> **阶段：** 第四阶段「Axum 原生鉴权体系实现」
> **项目：** axum-backend（纯 Axum 0.8 + SeaORM 1.1 生产级后端服务）
> **规则基线：** `axum-backend/.trae/rules/project-rules.md`（全程永久生效）
> **参考优先级：** 接口契约对齐 ref-salvo-admin ＞ 架构规范参考 ref-soybean-admin ＞ 同栈细节参考 ref-axum-admin

---

## 1. 概述与目标

### 1.1 本阶段目标

基于前三阶段已完成的数据库表结构、Entity/Repository 层、Service 业务层、Handler/Router 层，设计并实现完整的 Axum 原生鉴权体系，完成以下交付：

1. **JWT 鉴权中间件（Tower Layer 实现）**：支持白名单、token 解析、用户信息注入请求扩展
2. **权限校验中间件**：基于后端返回的权限标识做接口级权限拦截
3. **登录接口**：签发 token、返回用户信息与权限菜单
4. **状态管理**：用 State 注入全局认证服务
5. **接口 100% 对齐本项目前端规范**：`/login`、`/logout`、`/captchaImage`、`/getInfo`、`/getRouters` 五个端点

### 1.2 已有基础设施盘点

| 能力 | 文件 | 状态 | 备注 |
|------|------|------|------|
| JWT 签发/验证 | `src/jwt/claims.rs` | ✅ 已实现 | `JwtUtils::generate_token` / `verify_token`，Claims 含 sub/username/exp/iat/iss |
| JWT 鉴权中间件 | `src/middleware/auth.rs` | ✅ 已实现 | `auth_middleware`（from_fn_with_state 模式）+ `Operator` 提取器 |
| 密码加密校验 | `src/utils/password.rs` | ✅ 已实现 | Argon2id + 随机盐（旧 MD5 仅 fallback），`encrypt_password` / `verify_password` |
| 验证码生成 | `src/utils/captcha.rs` | ✅ 已实现 | `generate_captcha() -> CaptchaResult { uuid, img_base64, code }` |
| Redis 连接池 | `src/db/redis.rs` | ✅ 已实现 | `ConnectionManager`（自动重连），存入 `AppState.redis` |
| 用户 Service | `src/service/sys_user_service.rs` | ✅ 已实现 | `get_user_by_username`（不过滤 del_flag） |
| 角色 Service | `src/service/sys_role_service.rs` | ✅ 已实现 | `get_role_keys_by_user_id` 返回 `Vec<String>` |
| 菜单 Service | `src/service/sys_menu_service.rs` | ✅ 已实现 | `get_menu_tree_by_user_id`（超管短路 + 过滤按钮）、`get_permissions_by_user_id`（超管返回 `["*:*:*"]`） |
| 登录日志 Repository | `src/repository/sys_logininfor.rs` | ✅ 已实现 | `insert`、`find_page_desc`、`find_by_user_name` 等 |
| 用户登录信息更新 | `src/repository/sys_user.rs` | ✅ 已实现 | `update_login_info(user_id, login_ip)` 更新 login_ip + login_date |
| 路由聚合 | `src/router/mod.rs` | ✅ 已实现 | public + protected 分层，protected 挂 `auth_middleware` |
| 公开路由 | `src/router/public.rs` | ✅ 已实现 | 仅 `/health`，待追加登录相关路由 |

### 1.3 本阶段需新增/改造的内容

| 类型 | 内容 | 说明 |
|------|------|------|
| 新增 | `src/service/auth_service.rs` | 认证服务：登录、登出、验证码存取、登录日志 |
| 新增 | `src/handler/auth_handler.rs` | 登录/登出/验证码/getInfo/getRouters handler |
| 新增 | `src/router/auth_router.rs` | 认证路由注册（含公开 + 受保护两层） |
| 新增 | `src/middleware/permission.rs` | 权限校验中间件（基于 perms 标识拦截） |
| 改造 | `src/middleware/auth.rs` | JWT 中间件增加 Redis token 黑名单校验 |
| 改造 | `src/state.rs` | AppState 注入 `AuthService` |
| 改造 | `src/router/mod.rs` | 合并 auth_router，区分公开/受保护路由 |
| 改造 | `src/router/public.rs` | 追加 `/login`、`/captchaImage` 公开路由 |
| 改造 | `src/handler/mod.rs` | 声明 `auth_handler` 模块 |
| 改造 | `src/middleware/mod.rs` | 导出权限校验中间件 |
| 改造 | `src/service/mod.rs` | 声明 `auth_service` 模块 |

### 1.4 非目标（本阶段不实现）

- 用户注册接口（`/register`）—— 前端参考框架有此接口但非核心流程
- 锁屏解锁接口（`/unlockscreen`）—— 前端锁屏功能
- 初始密码/密码过期提示（`isDefaultModifyPwd` / `isPasswordExpired`）—— 非核心鉴权
- token 刷新机制（refresh_token）—— ref-salvo-admin 无此机制，保持一致
- Casbin 复杂 RBAC —— ref-soybean-admin 的 Casbin 方案过重，本阶段用 perms 标识做轻量权限拦截

---

## 2. 设计原则与决策

### 2.1 与 ref-salvo-admin 的关键差异（修正项）

| ref-salvo-admin 实现 | axum-backend 改进方案 | 修正理由 |
|----------------------|----------------------|----------|
| JWT 中间件**只查 Redis 不验 JWT 签名** | JWT 签名验证 + Redis 黑名单双重校验 | JWT 签名验证保证 token 不可伪造；Redis 黑名单支持主动登出 |
| JWT exp=6h 但 Redis TTL=1h，实际有效期 1h | JWT exp 与 Redis TTL 一致（均为配置的 `expire_hours`） | 消除不一致，避免「token 看似有效实则失效」的困惑 |
| 登录日志**未实现** | 登录成功/失败均写 `sys_logininfor` 表 | 对齐既有设计功能，安全审计需要 |
| `getInfo` 普通用户权限疑似 bug（传 `true` 跳过 WHERE） | 复用已实现的 `get_permissions_by_user_id`（正确按角色过滤） | 修复权限越权漏洞 |
| token 存 Redis（key=token, value=user_id） | token 不存 Redis（JWT 自包含）；仅登出时写黑名单 | 减少 Redis 读写，JWT 自包含验证更轻量 |
| 验证码存 Redis value 为小写 | 验证码存 Redis value 为小写，校验时大小写不敏感 | 对齐前端（用户可能输入大写），`to_lowercase` 比对 |
| `getRouters` 菜单转路由树用 `func::router_arr_to_tree2` | 复用已实现的 `build_tree` + 新增 `menu_to_router` 转换函数 | 统一树构建工具，避免重复递归逻辑 |

### 2.2 与 ref-soybean-admin 的架构借鉴

| ref-soybean-admin 设计 | axum-backend 对应实现 | 借鉴要点 |
|------------------------|----------------------|----------|
| `from_fn` + 闭包捕获参数 | `from_fn_with_state(state, auth_middleware)` | Axum 原生中间件模式（非手写 Tower Layer） |
| Extensions 作为中间件间通信通道 | `req.extensions_mut().insert(Claims)` | JWT 中间件写入 Claims，权限中间件读取 |
| `User` 实现 `FromRequest` 作为提取器 | `Operator` 提取器（已实现 `FromRequestParts`） | handler 直接提取当前操作人 |
| 白名单 = 路由分组 + 开关 | public_routes / protected 路由分组 | 不维护路径白名单，靠路由结构天然区分 |
| Layer 叠加顺序：JWT 最内层 | `protected.layer(auth_middleware).layer(permission_middleware)` | JWT 先执行写入 extensions，权限中间件后执行读取 |

### 2.3 鉴权流程总体设计

```
请求进入
  │
  ▼
全局中间件（request_id → trace → cors → compression）
  │
  ▼
路由匹配
  ├─ /health、/login、/captchaImage  →  公开路由（免鉴权）
  │                                        │
  │                                        ▼
  │                                    handler 直接处理
  │
  └─ /logout、/getInfo、/getRouters、/system/*  →  受保护路由
       │
       ▼
  auth_middleware（JWT 签名验证 + Redis 黑名单校验）
       │  失败 → 401
       │  成功 → 注入 Claims 到 extensions
       ▼
  permission_middleware（权限标识校验，可选）
       │  失败 → 403
       │  成功 → 放行
       ▼
  handler（通过 Operator 提取器获取当前用户）
```

### 2.4 token 生命周期设计

```
[登录 /login]
  │ 验证码校验（Redis GET uuid → 比对 → DEL）
  │ 用户查询 + 密码校验
  │ 状态检查（del_flag / status）
  │ JWT 签发（exp = now + expire_hours）
  │ 登录日志写入（status=0 成功）
  │ 更新 login_ip / login_date
  ▼
返回 { token: "xxx" }
  │
  │ 前端存 Cookie，后续请求携带 Authorization: Bearer <token>
  │
[每次请求 auth_middleware]
  │ 提取 Bearer token
  │ JWT 签名验证 + exp 过期校验
  │ Redis 黑名单校验（GET blacklist:<token> → 存在则拒绝）
  │ 注入 Claims 到 extensions
  ▼
[登出 /logout]
  │ 提取 Bearer token
  │ Redis 写入黑名单（SET blacklist:<token> 1 EX <剩余TTL>）
  ▼
返回成功
```

### 2.5 Redis key 命名规则与 TTL

| 用途 | key 格式 | value | TTL | 写入点 | 清除点 |
|------|----------|-------|-----|--------|--------|
| **验证码** | `captcha:{uuid}` | 小写验证码字符串 | 300s（5 分钟） | `GET /captchaImage` | `POST /login` 校验后 DEL |
| **token 黑名单** | `blacklist:{token}` | `"1"` | JWT 剩余有效期（秒） | `POST /logout` | TTL 自然过期 |

> **设计决策：** ref-salvo-admin 将 token 本身存 Redis 作为"存在性校验"，但这意味着每次请求都要查 Redis。本方案改为 JWT 自包含验证（无需 Redis），仅登出时写黑名单。黑名单 TTL 设为 JWT 剩余有效期，过期后自动清理。

### 2.6 权限校验中间件设计

权限校验中间件采用**声明式标注 + 运行时拦截**模式：

```rust
/// 权限标识提取器（通过路由扩展属性传递）
/// 在路由注册时通过 .route("/system/user/list", get(handler).route_layer(require_perm("system:user:list")))
/// 标注所需权限
pub struct RequirePerm(pub &'static str);
```

**校验逻辑：**
1. 从 extensions 提取 `Claims`（由 auth_middleware 注入）
2. 从 extensions 提取 `RequirePerm`（由 route_layer 注入）
3. 调用 `menu_service.get_permissions_by_user_id(user_id)` 查询用户权限标识列表
4. 超管短路：若用户权限列表含 `*:*:*`，直接放行
5. 权限匹配：若用户权限列表包含目标权限标识，放行
6. 否则返回 403

> **设计决策：**
> - 权限中间件为**可选层**，仅在需要权限控制的路由上叠加。大部分 CRUD 接口已有路由级鉴权（登录即可访问），仅高敏感操作需要额外权限校验。本阶段先实现中间件框架，具体接口的权限标注留待后续阶段。
> - **本阶段不做 Redis 权限缓存**，每次权限校验直接查 DB。原因：(1) 权限中间件仅在高敏感操作上叠加，调用频率低；(2) 缓存一致性维护复杂（角色菜单变更时需清缓存）；(3) 后续阶段如有性能需求再引入 `perms:{user_id}` 缓存。

### 2.7 菜单转路由树设计（getRouters 接口）

ref-salvo-admin 的 `router_arr_to_tree2` 将 `SysMenu` 转换为前端 `RouterVo` 结构。本方案拆分为两步：

1. **树形组装**：复用已实现的 `build_tree(&menus, 0)`（`SysMenuModel` 已实现 `TreeNode` trait）
2. **菜单转路由**：新增 `menu_to_router(menu: &SysMenuModel) -> RouterVo` 转换函数

**转换规则（对齐 ref-salvo-admin）：**

| RouterVo 字段 | 来源 / 转换规则 |
|---------------|----------------|
| `name` | `menu.path`（直接用路径作路由名） |
| `path` | 顶级目录（parent_id==0 且 menu_type=="M"）：`"/" + path`；其他：原样 |
| `hidden` | `menu.status == "1"`（禁用状态隐藏） |
| `redirect` | `menu.is_frame == 1 && menu_type == "M"` → `"noRedirect"`；否则 `None` |
| `component` | `None` 或空 → 顶级目录 `"Layout"`、子级目录 `"ParentView"`；否则原样 |
| `alwaysShow` | `menu.visible == "0" && menu_type != "C" && is_frame == 1` → `Some(true)`；否则 `None` |
| `meta.title` | `menu.menu_name` |
| `meta.icon` | `menu.icon` |
| `meta.noCache` | `menu.is_cache == 1`（true 表示不缓存） |
| `meta.link` | `menu.is_frame == 0`（外链）→ `Some(menu.path)`；否则 `None` |
| `children` | 递归转换子菜单，过滤 `menu_type == "F"`（按钮不进路由树） |

---

## 3. 接口清单与契约定义

### 3.1 接口总览

| 接口 | 方法 | 路径 | 鉴权 | 响应格式 | 说明 |
|------|------|------|------|----------|------|
| 验证码 | GET | `/captchaImage` | 否 | 顶层字段 | 生成验证码图片 |
| 登录 | POST | `/login` | 否 | 顶层 token | 签发 token |
| 登出 | POST | `/logout` | 是 | 标准 AjaxResult | token 加入黑名单 |
| 获取用户信息 | GET | `/getInfo` | 是 | 顶层字段 | 返回 user + roles + permissions |
| 获取路由树 | GET | `/getRouters` | 是 | AjaxResult\<Vec\<RouterVo\>\> | 返回前端路由树 |

> **响应格式说明：**
> - **顶层字段**：业务字段直接放在响应体顶层（与 `code`/`msg` 平级），对齐前端 `extends AjaxResult` 的类型定义（`CaptchaInfoResult`、`LoginInfoResult`、`UserInfoResult`）
> - **标准 AjaxResult\<T\>**：业务数据放在 `data` 字段内，前端通过 `res.data` 读取

### 3.2 GET /captchaImage — 验证码接口

**请求参数：** 无

**响应体（对齐前端 `CaptchaInfoResult extends AjaxResult`）：**

> **关键：** 前端 `CaptchaInfoResult extends AjaxResult`，`uuid`/`img`/`captchaEnabled` 字段在**响应体顶层**（与 `code`/`msg` 平级），**不在 `data` 内**。

```rust
/// 验证码响应体（字段在顶层，对齐前端 CaptchaInfoResult）
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CaptchaResult {
    pub code: i32,
    pub msg: String,
    /// 验证码开关（始终为 true，本阶段不支持关闭）
    pub captcha_enabled: bool,
    /// 验证码图片 Base64（不含 data:image/png;base64, 前缀，前端自行拼接）
    pub img: String,
    /// 验证码会话 UUID（登录时回传）
    pub uuid: String,
}

impl IntoResponse for CaptchaResult {
    fn into_response(self) -> Response {
        (StatusCode::OK, Json(self)).into_response()
    }
}
```

**JSON 响应：**
```json
{
  "code": 200,
  "msg": "操作成功",
  "captchaEnabled": true,
  "img": "iVBORw0KGgo...",
  "uuid": "a1b2c3d4-..."
}
```

**业务逻辑：**
1. 调用 `utils::captcha::generate_captcha()` 生成验证码
2. Redis 写入 `captcha:{uuid}` → 小写验证码，TTL 300s
3. 返回 `CaptchaResult { code: 200, msg: "操作成功", captcha_enabled: true, img, uuid }`

### 3.3 POST /login — 登录接口

**请求体（对齐前端 `login` 函数参数）：**

```rust
#[derive(Deserialize, Garde)]
#[serde(rename_all = "camelCase")]
pub struct LoginDto {
    #[garde(length(min = 2, max = 30, message = "用户名长度必须在2-30之间"))]
    pub username: String,
    #[garde(length(min = 5, max = 20, message = "密码长度必须在5-20之间"))]
    pub password: String,
    /// 验证码
    pub code: String,
    /// 验证码会话 UUID
    pub uuid: String,
}
```

**响应体（对齐前端 `LoginInfoResult`）：**

```rust
#[derive(Serialize)]
pub struct LoginVo {
    pub token: String,
}
```

**JSON 响应：**
```json
{
  "code": 200,
  "msg": "操作成功",
  "token": "eyJhbGciOiJIUzI1NiJ9..."
}
```

> **注意：** 前端 `LoginInfoResult extends AjaxResult`，`token` 字段在顶层而非 `data` 内。为兼容此前端约定，`AjaxResult<LoginVo>` 的 `data` 字段返回 `{ token: "xxx" }`，但前端实际从 `res.token` 取值——需确认前端类型定义。经查 `login.ts`，前端 `res.token` 取的是响应体顶层的 `token`。因此响应体需为 `{ code, msg, token }` 而非 `{ code, msg, data: { token } }`。
>
> **决策：** 新增 `AjaxResult` 的无 data 变体，或直接在 handler 中构造自定义响应体。本方案采用：handler 返回 `AjaxResult<serde_json::Value>`，其中 `data = Some(json!({ "token": token }))`。但前端 `res.token` 是从顶层取——需将 token 放顶层。
>
> **最终方案：** 登录接口返回结构为 `{ code: 200, msg: "操作成功", token: "xxx" }`，与前端 `LoginInfoResult` 完全对齐。通过自定义序列化结构体实现。

**业务逻辑（完整流程）：**

```
1. 参数校验（garde）
2. 验证码校验：
   a. Redis GET captcha:{uuid}
   b. 不存在 → 写登录日志（status=1, msg="验证码错误"）→ 返回 500 "验证码错误"
   c. 存在但不匹配（大小写不敏感）→ 同上
   d. 匹配 → Redis DEL captcha:{uuid}（一次性使用）
3. 用户查询：user_service.get_user_by_username(&username)
4. 用户状态校验：
   a. None → 写登录日志（status=1, msg="用户不存在/密码错误"）→ 返回 500 "用户不存在/密码错误"
   b. del_flag == "2" → 写登录日志 → 返回 500 "账号已删除，请联系管理员"
   c. status == "1" → 写登录日志 → 返回 500 "账号已停用，请联系管理员"
5. 密码校验：verify_password(&password, user.password)
   a. 失败 → 写登录日志（status=1, msg="用户不存在/密码错误"）→ 返回 500 "用户不存在/密码错误"
   b. 成功 → 继续
6. JWT 签发：JwtUtils::generate_token(&user_id, &username, &jwt_config)
7. 登录日志写入（status=0, msg="登录成功"）
8. 更新 login_ip / login_date：self.user_repo.update_login_info(user_id, login_ip)
9. 返回 { code: 200, msg: "操作成功", token: "xxx" }
```

> **安全说明：** 密码错误时返回"用户不存在/密码错误"而非"密码错误"，避免枚举攻击。

### 3.4 POST /logout — 登出接口

**请求参数：** 无（从 Authorization header 提取 token）

**响应体：**
```json
{ "code": 200, "msg": "退出成功" }
```

**业务逻辑：**
1. 从 Authorization header 提取 Bearer token
2. 计算 JWT 剩余有效期（exp - now）
3. 若剩余有效期 > 0：Redis SET `blacklist:{token}` "1" EX {剩余秒数}
4. 返回成功

### 3.5 GET /getInfo — 获取用户信息接口

**请求参数：** 无（从 Operator 提取器获取 user_id）

**响应体（对齐前端 `UserInfoResult extends AjaxResult`）：**

> **关键：** 前端 `UserInfoResult extends AjaxResult`，`user`/`roles`/`permissions` 字段在**响应体顶层**（与 `code`/`msg` 平级），**不在 `data` 内**。前端 store 直接读取 `res.user`、`res.roles`、`res.permissions`。

```rust
/// 用户信息响应体（字段在顶层，对齐前端 UserInfoResult）
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GetInfoResult {
    pub code: i32,
    pub msg: String,
    /// 用户信息（password 字段清空为 None，避免泄露密文）
    pub user: SysUserModel,
    /// 角色 key 列表（超管为 ["admin"]）
    pub roles: Vec<String>,
    /// 权限标识列表（超管为 ["*:*:*"]）
    pub permissions: Vec<String>,
}

impl IntoResponse for GetInfoResult {
    fn into_response(self) -> Response {
        (StatusCode::OK, Json(self)).into_response()
    }
}
```

**JSON 响应：**
```json
{
  "code": 200,
  "msg": "操作成功",
  "user": { "userId": 1, "userName": "admin", "nickName": "演示管理员", "password": null, ... },
  "roles": ["admin"],
  "permissions": ["*:*:*"]
}
```

**业务逻辑：**
1. 从 Operator 提取器获取 user_id
2. 查询用户详情：`user_service.get_user_by_id(user_id)` 返回 `UserVo { user, role_ids }`，提取其中的 `user: SysUserModel`
3. 查询角色 key 列表：`role_service.get_role_keys_by_user_id(user_id)`
4. 查询权限标识列表：`menu_service.get_permissions_by_user_id(user_id)`
5. **清空 user.password 字段**：`user.password = None`（SysUserModel 的 password 字段无 `#[serde(skip_serializing)]`，需手动置 None 避免泄露密文）
6. 返回 `GetInfoResult { code: 200, msg: "操作成功", user, roles, permissions }`

> **注意：**
> - `roles` 为空时前端兜底赋 `["ROLE_DEFAULT"]`，后端无需处理
> - `get_user_by_id` 返回的 `UserVo` 使用 `#[serde(flatten)]`，但 `GetInfoResult.user` 字段只需 `SysUserModel`（不含 role_ids），故需从 UserVo 中提取 `.user` 字段
> - **password 安全**：SysUserModel 的 `password: Option<String>` 字段未加 `#[serde(skip_serializing)]`，必须在返回前手动 `user.password = None`

### 3.6 GET /getRouters — 获取路由树接口

**请求参数：** 无（从 Operator 提取器获取 user_id）

**响应体（对齐前端 `RouterVo`）：**

```rust
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RouterVo {
    pub name: String,
    pub path: String,
    pub hidden: bool,
    pub redirect: Option<String>,
    pub component: String,
    pub always_show: Option<bool>,
    pub meta: MetaVo,
    pub query: Option<String>,
    pub children: Option<Vec<RouterVo>>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MetaVo {
    pub title: String,
    pub icon: String,
    pub no_cache: bool,
    pub link: Option<String>,
}
```

**JSON 响应：**
```json
{
  "code": 200,
  "msg": "操作成功",
  "data": [
    {
      "name": "system",
      "path": "/system",
      "hidden": false,
      "component": "Layout",
      "alwaysShow": true,
      "redirect": "noRedirect",
      "meta": { "title": "系统管理", "icon": "system", "noCache": false, "link": null },
      "children": [
        {
          "name": "user",
          "path": "user",
          "hidden": false,
          "component": "system/user/index",
          "meta": { "title": "用户管理", "icon": "user", "noCache": false, "link": null }
        }
      ]
    }
  ]
}
```

**业务逻辑：**
1. 从 Operator 提取器获取 user_id
2. 查询用户菜单树：`menu_service.get_menu_tree_by_user_id(user_id)`
3. 递归转换 `SysMenuModel` → `RouterVo`（调用 `menu_to_router` 函数）
4. 返回 `AjaxResult<Vec<RouterVo>>`

---

## 4. AuthService 设计

### 4.1 结构体设计

```rust
/// 认证服务（不依赖任何 Web 类型）
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

> **设计决策：** AuthService 持有 `SysUserRepository` 用于调用 `update_login_info`（该方法在 Repository 层，SysUserService 未暴露包装方法）。这与已有 `logininfor_repo` 持有模式一致。

### 4.2 方法清单

| 方法 | 签名 | 职责 |
|------|------|------|
| `generate_captcha` | `(&self, redis: &mut ConnectionManager) -> Result<CaptchaVo, AppError>` | 生成验证码并存入 Redis |
| `login` | `(&self, dto: LoginDto, login_ip: &str, user_agent: &str, redis: &mut ConnectionManager, jwt_config: &JwtConfig) -> Result<LoginVo, AppError>` | 登录认证全流程（含 UA 解析写日志） |
| `logout` | `(&self, token: &str, redis: &mut ConnectionManager, jwt_config: &JwtConfig) -> Result<(), AppError>` | token 加入黑名单 |
| `get_info` | `(&self, user_id: i64) -> Result<GetInfoVo, AppError>` | 获取用户信息 + 角色 + 权限 |
| `get_routers` | `(&self, user_id: i64) -> Result<Vec<RouterVo>, AppError>` | 获取用户路由树 |

> **注意：**
> - `login` 方法接收 `user_agent: &str` 参数，用于解析浏览器/操作系统写入登录日志
> - `get_info` 方法内部调用 `user_service.get_user_by_id(user_id)` 返回 `UserVo`（含 role_ids），需提取其中的 `user: SysUserModel` 字段填入 `GetInfoVo.user`
> - Service 层返回 Vo 类型（不含 code/msg），Handler 层负责包装为 `CaptchaResult`/`LoginResult`/`GetInfoResult`（含 code/msg，字段在顶层）并实现 `IntoResponse`。详见 3.2/3.3/3.5 节响应体定义

### 4.3 登录日志写入设计

```rust
/// 写入登录日志（内部方法）
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
        info_id: Set(0),  // 自增主键，Set(0) 让数据库自动分配
        user_name: Set(Some(user_name.to_string())),
        ipaddr: Set(Some(login_ip.to_string())),
        login_location: Set(None),  // 本阶段不实现 IP 归属地查询
        browser: Set(Some(browser.to_string())),
        os: Set(Some(os.to_string())),
        status: Set(Some(status.to_string())),
        msg: Set(Some(msg.to_string())),
        login_time: Set(Some(now)),
    };
    self.logininfor_repo.insert(am).await?;
    Ok(())
}
```

> **注意：** `sys_logininfor` 表的 `info_id` 为自增主键。SeaORM 中 `Set(0)` 会让数据库自动分配自增值（MySQL AUTO_INCREMENT 行为）。

### 4.4 浏览器/OS 解析设计

本阶段采用简化方案：从 `User-Agent` header 提取浏览器和操作系统名称，不引入额外解析库。

```rust
/// 从 User-Agent 简单提取浏览器名称
fn parse_browser(ua: &str) -> String {
    if ua.contains("Chrome") { "Chrome".to_string() }
    else if ua.contains("Firefox") { "Firefox".to_string() }
    else if ua.contains("Safari") { "Safari".to_string() }
    else if ua.contains("Edge") { "Edge".to_string() }
    else { "Unknown".to_string() }
}

/// 从 User-Agent 简单提取操作系统名称
fn parse_os(ua: &str) -> String {
    if ua.contains("Windows") { "Windows".to_string() }
    else if ua.contains("Mac OS") { "macOS".to_string() }
    else if ua.contains("Linux") { "Linux".to_string() }
    else if ua.contains("Android") { "Android".to_string() }
    else if ua.contains("iPhone") || ua.contains("iPad") { "iOS".to_string() }
    else { "Unknown".to_string() }
}
```

### 4.5 菜单转路由函数设计

```rust
/// 将 SysMenuModel 转换为 RouterVo（递归转换子节点）
fn menu_to_router(menu: &SysMenuModel) -> RouterVo {
    let menu_type = menu.menu_type.as_deref().unwrap_or("C");
    let is_frame = menu.is_frame.unwrap_or(1);
    let is_cache = menu.is_cache.unwrap_or(0);
    let visible = menu.visible.as_deref().unwrap_or("0");
    let status = menu.status.as_deref().unwrap_or("0");
    let parent_id = menu.parent_id.unwrap_or(0);

    // path 转换
    let path = if parent_id == 0 && menu_type == "M" {
        format!("/{}", menu.path.as_deref().unwrap_or(""))
    } else {
        menu.path.clone().unwrap_or_default()
    };

    // component 转换
    let component = match menu.component.as_deref() {
        None | Some("") => {
            if parent_id == 0 && menu_type == "M" { "Layout".to_string() }
            else if parent_id != 0 && menu_type == "M" { "ParentView".to_string() }
            else { String::new() }
        }
        Some(c) => c.to_string(),
    };

    // redirect 转换
    let redirect = if is_frame == 1 && menu_type == "M" {
        Some("noRedirect".to_string())
    } else {
        None
    };

    // alwaysShow 转换
    let always_show = if visible == "0" && menu_type != "C" && is_frame == 1 {
        Some(true)
    } else {
        None
    };

    // meta 转换
    let meta = MetaVo {
        title: menu.menu_name.clone(),
        icon: menu.icon.clone().unwrap_or_default(),
        no_cache: is_cache == 1,
        link: if is_frame == 0 { menu.path.clone() } else { None },
    };

    // children 递归转换（过滤 F 类型）
    let children = if let Some(ref kids) = menu.children {
        let router_kids: Vec<RouterVo> = kids.iter()
            .filter(|k| k.menu_type.as_deref() != Some("F"))
            .map(menu_to_router)
            .collect();
        if router_kids.is_empty() { None } else { Some(router_kids) }
    } else {
        None
    };

    RouterVo {
        // name 优先使用 route_name，其次用 path（前端不派生，直接使用后端返回值）
        name: menu.route_name.clone()
            .or_else(|| menu.path.clone())
            .unwrap_or_default(),
        path,
        hidden: status == "1",
        redirect,
        component,
        always_show,
        meta,
        query: menu.query.clone(),
        children,
    }
}
```

---

## 5. 中间件设计

### 5.1 JWT 鉴权中间件（改造现有 auth_middleware）

**改造点：** 在现有 JWT 签名验证基础上，增加 Redis 黑名单校验。

```rust
pub async fn auth_middleware(
    State(state): State<Arc<AppState>>,
    mut req: Request,
    next: Next,
) -> Result<Response, AppError> {
    // 1. 提取 Authorization header
    let auth_header = req.headers().get(&AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| AppError::unauthorized("请求未携带 token，请重新登录"))?;

    // 2. 解析 Bearer token
    let token = auth_header.strip_prefix("Bearer ")
        .ok_or_else(|| AppError::unauthorized("token 格式错误，应为 Bearer <token>"))?;

    // 3. JWT 签名验证 + exp 过期校验
    //    注意：verify_token 返回 anyhow::Result<Claims>，若直接用 ? 会走
    //    From<anyhow::Error> for AppError 映射为 500。需显式 map_err 为 401。
    let claims = JwtUtils::verify_token(token, &state.config.jwt)
        .map_err(|_| AppError::unauthorized("无效的会话，或者会话已过期，请重新登录"))?;

    // 4. Redis 黑名单校验
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

    // 5. 注入 Claims 到 extensions
    req.extensions_mut().insert(claims);
    Ok(next.run(req).await)
}
```

> **关键修正：** `JwtUtils::verify_token` 返回 `anyhow::Result<Claims>`，若直接使用 `?` 操作符，会命中 `From<anyhow::Error> for AppError` 转换为 500 内部错误。必须使用 `map_err(|_| AppError::unauthorized(...))` 显式映射为 401，确保 JWT 验证失败返回正确的业务错误码。

### 5.2 权限校验中间件（新增）

```rust
/// 权限校验中间件
/// 用法：在路由上叠加 .route_layer(from_fn_with_state(state.clone(), permission_middleware))
/// 并在路由扩展中注入 RequirePerm 标识
pub async fn permission_middleware(
    State(state): State<Arc<AppState>>,
    req: Request,
    next: Next,
) -> Result<Response, AppError> {
    // 1. 从 extensions 提取 Claims
    let claims = req.extensions().get::<Claims>().cloned()
        .ok_or_else(|| AppError::unauthorized("无法获取登录信息，请重新登录"))?;

    // 2. 从 extensions 提取 RequirePerm（由 route_layer 注入）
    //    若无 RequirePerm，说明该路由不需要权限校验，直接放行
    let required_perm = match req.extensions().get::<RequirePerm>() {
        Some(p) => p.0,
        None => return Ok(next.run(req).await),
    };

    // 3. 查询用户权限（优先 Redis 缓存）
    let user_id: i64 = claims.sub.parse()
        .map_err(|_| AppError::internal("用户 ID 解析失败"))?;

    let permissions = state.auth_service
        .get_permissions_cached(user_id, &state.redis).await?;

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

> **本阶段实现范围：** 权限中间件框架实现，但**不**在现有 CRUD 路由上叠加（现有路由仅需登录即可访问）。后续阶段需要细粒度权限控制时，通过 `route_layer` 按需叠加。

### 5.3 路由结构设计

```
build_app(state)
  │
  ├─ public_routes()  ← 免鉴权
  │    ├─ GET  /health
  │    ├─ GET  /captchaImage
  │    └─ POST /login
  │
  ├─ protected_routes()  ← auth_middleware
  │    ├─ POST /logout
  │    ├─ GET  /getInfo
  │    ├─ GET  /getRouters
  │    ├─ user_routes()    ← 用户 CRUD
  │    ├─ role_routes()    ← 角色 CRUD
  │    └─ menu_routes()    ← 菜单 CRUD
  │
  └─ 全局中间件
       ├─ request_id_middleware（最外层）
       ├─ TraceLayer
       ├─ CorsLayer
       └─ CompressionLayer（最内层）
```

### 5.4 登录响应体特殊处理

由于前端 `LoginInfoResult` 的 `token` 字段在顶层而非 `data` 内，需要自定义响应结构：

```rust
/// 登录响应体（token 在顶层，对齐前端 LoginInfoResult）
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

---

## 6. 状态管理设计

### 6.1 AppState 改造

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
```

### 6.2 operator 参数来源

```
JWT 中间件 → Claims 注入 extensions
     ↓
Operator 提取器（FromRequestParts）→ 从 extensions 提取 Claims
     ↓
Handler 函数签名：handler(State(state), Operator(operator), Json(dto))
     ↓
Service 方法调用：service.method(dto, operator.username())
```

---

## 7. 新增依赖

本阶段无需新增 crate 依赖，所有能力已在前序阶段就绪：
- JWT：`jsonwebtoken = "10"`
- Redis：`redis = "1.3"`（含 `connection-manager`）
- 验证码：`captcha = "1.0"`
- 密码：`md-5 = "0.10"`（旧 MD5 fallback）+ `argon2 = "0.5"`（主算法）

---

## 8. 验收标准

### 8.1 功能验收

| 验收项 | 验证方法 | 预期结果 |
|--------|----------|----------|
| 验证码生成 | `GET /captchaImage` | 返回 base64 图片 + uuid |
| 验证码 Redis 存储 | Redis `GET captcha:{uuid}` | 返回小写验证码字符串 |
| 登录成功 | `POST /login`（正确账密 + 正确验证码） | 返回 `{ code: 200, token: "xxx" }` |
| 登录失败（密码错误） | `POST /login`（错误密码） | 返回 `{ code: 500, msg: "用户不存在/密码错误" }` |
| 验证码一次性 | 重复使用同一 uuid 登录 | 第二次返回"验证码错误" |
| 登录日志写入 | 登录后查 `sys_logininfor` 表 | 有对应记录（status=0 成功 / status=1 失败） |
| login_ip 更新 | 登录后查 `sys_user` 表 | login_ip / login_date 已更新 |
| 登出 | `POST /logout`（携带 token） | 返回成功，Redis 黑名单有记录 |
| 登出后 token 失效 | 登出后携带原 token 访问受保护接口 | 返回 401 |
| 获取用户信息 | `GET /getInfo`（携带 token） | 返回 user + roles + permissions |
| 获取路由树 | `GET /getRouters`（携带 token） | 返回前端路由树结构 |
| 超管权限 | admin 用户 getInfo | roles=["admin"], permissions=["*:*:*"] |
| 普通用户权限 | 普通用户 getInfo | roles=["common"], permissions=["system:user:list", ...] |

### 8.2 架构验收

| 验收项 | 验证方法 | 预期结果 |
|--------|----------|----------|
| 纯 Axum 实现 | grep `salvo\|rbatis\|actix\|warp` | 零匹配（注释除外） |
| Service 层独立 | grep `axum\|tower` in service/ | 零匹配 |
| 无 unwrap | grep `unwrap()\|expect(` in handler/ | 零匹配 |
| 编译通过 | `cargo build` | 零错误零警告 |
| 测试通过 | `cargo test` | 全部通过 |

### 8.3 前端联调验收

| 验收项 | 验证方法 | 预期结果 |
|--------|----------|----------|
| 登录页验证码显示 | 前端访问 /login 页面 | 显示验证码图片 |
| 登录成功跳转 | 输入 admin/admin123 + 验证码 | 跳转到首页 |
| 首页菜单加载 | 登录后首页 | 显示侧边栏菜单 |
| 权限按钮显示 | admin 用户访问用户管理页 | 显示新增/编辑/删除按钮 |
| 登出跳转 | 点击退出登录 | 跳转回登录页 |
| 刷新保持登录 | 登录后刷新页面 | 保持登录态，不跳转登录页 |

---

## 9. 与 ref-salvo-admin 差异对照表

| 维度 | ref-salvo-admin | axum-backend |
|------|----------------|--------------|
| Web 框架 | Salvo | Axum 0.8 |
| ORM | rbatis | SeaORM 1.1 |
| JWT 中间件 | `#[handler]` + Depot | `from_fn_with_state` + Extensions |
| token 校验 | Redis 存在性校验（不验 JWT 签名） | JWT 签名验证 + Redis 黑名单 |
| token 存储 | Redis（key=token, value=user_id） | JWT 自包含，仅黑名单存 Redis |
| token 有效期 | JWT exp=6h, Redis TTL=1h（不一致） | JWT exp = Redis TTL = config.expire_hours |
| 登录日志 | 未实现 | 写入 `sys_logininfor` 表 |
| 验证码 | 5 位字符，小写存储 | 5 位字符（排除易混淆），小写存储 |
| getInfo 权限 | 普通用户疑似 bug（拿到全权限） | 正确按角色过滤 |
| 路由树构建 | `func::router_arr_to_tree2`（O(n²)） | `build_tree`（O(n)）+ `menu_to_router` |
| 用户信息注入 | `depot.insert("userId", user_id)` | `req.extensions_mut().insert(Claims)` |
| 提取器 | `depot.get::<i32>("userId")` | `Operator`（实现 `FromRequestParts`） |
| 登出 | `redis::del(token)` | `redis::set(blacklist:{token}, EX ttl)` |
| 密码盐值 | `"salvo_admin"` | `"yebot_admin"` |
| 响应码 | code=0 成功 | code=200 成功（对齐本项目前端） |
