# 鉴权体系验收清单（auth-checklist.md）

> **阶段：** 第四阶段「Axum 原生鉴权体系实现」
> **项目：** axum-backend
> **配套文档：** [auth-spec.md](./auth-spec.md)、[auth-tasks.md](./auth-tasks.md)
> **规则基线：** `axum-backend/.trae/rules/project-rules.md`（全程永久生效）

---

## 1. 架构合规性验收

### 1.1 纯 Axum 原生实现

- [ ] `src/middleware/auth.rs` 使用 `from_fn_with_state` 模式，无 `#[handler]` 宏
- [ ] `src/middleware/permission.rs` 使用 `from_fn_with_state` 模式，无 Salvo Depot
- [ ] `src/handler/auth_handler.rs` 使用 Axum 提取器，无 `Depot` / `Request` 容器
- [ ] `src/router/auth_router.rs` 使用 `axum::Router`，无 `salvo::Router`
- [ ] 全项目 grep `salvo\|rbatis\|actix\|warp` 零匹配（注释除外）

### 1.2 分层独立性

- [ ] `AuthService` 不依赖 `axum` / `tower` / `tower-http` / `http` / `hyper` 任何 Web 类型
- [ ] `AuthService` 方法返回 `Result<T, AppError>`，不返回 `Response`
- [ ] `AuthService` 不解析 HTTP body / header / query
- [ ] `AuthService` 通过 `user_service` / `role_service` / `menu_service` / `logininfor_repo` / `user_repo` 操作数据
- [ ] `menu_to_router` / `parse_browser` / `parse_os` 为纯函数，无 Web 依赖

### 1.3 模块组织

- [ ] `src/service/auth_service.rs` 存在
- [ ] `src/handler/auth_handler.rs` 存在
- [ ] `src/router/auth_router.rs` 存在
- [ ] `src/middleware/permission.rs` 存在
- [ ] `src/service/mod.rs` 声明 `auth_service` 模块并 re-export `AuthService`
- [ ] `src/handler/mod.rs` 声明 `auth_handler` 模块
- [ ] `src/router/mod.rs` 声明 `auth_router` 模块
- [ ] `src/middleware/mod.rs` 声明 `permission` 模块并导出 `RequirePerm`

### 1.4 依赖方向

- [ ] Handler → AuthService → SysUserService / SysRoleService / SysMenuService → Repository
- [ ] 中间件层不调用 Service 业务方法（权限中间件例外，需查权限）
- [ ] AuthService 不被 Repository / Entity 引用

---

## 2. JWT 鉴权中间件验收

### 2.1 中间件流程

- [ ] 提取 `Authorization` header，缺失返回 401「请求未携带 token，请重新登录」
- [ ] 解析 `Bearer ` 前缀，格式错误返回 401「token 格式错误，应为 Bearer <token>」
- [ ] 调用 `JwtUtils::verify_token` 验证签名 + exp 过期
- [ ] **JWT 验证失败显式 `map_err` 为 401**（不走 `From<anyhow::Error>` → 500）
- [ ] 签名验证通过后查询 Redis 黑名单 `blacklist:{token}`
- [ ] 黑名单命中返回 401「会话已注销，请重新登录」
- [ ] 黑名单未命中则注入 `Claims` 到 `req.extensions_mut()`
- [ ] 放行至下一层

### 2.2 Redis 黑名单校验

- [ ] Redis key 格式为 `blacklist:{token}`
- [ ] Redis GET 操作异常不阻断请求（`.ok().flatten()` 容错）
- [ ] 黑名单 TTL 由登出接口写入（等于 JWT 剩余有效期）

### 2.3 Operator 提取器

- [ ] `Operator` 实现 `FromRequestParts`
- [ ] 从 `parts.extensions` 获取 `Claims`
- [ ] 获取失败返回 401「无法获取登录信息，请重新登录」
- [ ] `Operator::username()` 返回 `&str`
- [ ] `Operator::user_id()` 返回 `&str`（需 `parse::<i64>()` 转换）

---

## 3. 权限校验中间件验收

### 3.1 RequirePerm 载体

- [ ] `RequirePerm(pub &'static str)` 结构体定义
- [ ] 可通过 `route_layer` 注入 extensions
- [ ] 无 `RequirePerm` 时中间件放行

### 3.2 校验逻辑

- [ ] 从 extensions 提取 `Claims`，缺失返回 401
- [ ] 从 extensions 提取 `RequirePerm`，缺失则放行
- [ ] 调用 `menu_service.get_permissions_by_user_id` 查询权限
- [ ] 超管短路：权限列表含 `*:*:*` 直接放行
- [ ] 权限匹配：权限列表含目标标识放行
- [ ] 权限不匹配返回 403「没有权限访问该资源」
- [ ] 本阶段不在现有 CRUD 路由上叠加（仅框架就绪）

---

## 4. 登录接口验收

### 4.1 验证码校验

- [ ] Redis GET `captcha:{uuid}` 获取存储的验证码
- [ ] 验证码不存在返回 500「验证码错误」
- [ ] 验证码不匹配（大小写不敏感）返回 500「验证码错误」
- [ ] 验证码匹配后 Redis DEL `captcha:{uuid}`（一次性使用）
- [ ] 验证码错误时写登录日志（status=1, msg="验证码错误"）

### 4.2 用户认证

- [ ] 调用 `user_service.get_user_by_username` 查询用户
- [ ] 用户不存在返回 500「用户不存在/密码错误」（防枚举攻击）
- [ ] `del_flag == "2"` 返回 500「账号已删除，请联系管理员」
- [ ] `status == "1"` 返回 500「账号已停用，请联系管理员」
- [ ] 密码校验失败返回 500「用户不存在/密码错误」（防枚举攻击）
- [ ] 密码校验使用 `verify_password(input, stored_hash)`

### 4.3 登录成功流程

- [ ] JWT 签发：`JwtUtils::generate_token(user_id, username, jwt_config)`
- [ ] 登录日志写入（status=0, msg="登录成功"）
- [ ] 更新 `login_ip` / `login_date`：`self.user_repo.update_login_info`（AuthService 直接持有 user_repo）
- [ ] 返回 `{ code: 200, msg: "操作成功", token: "xxx" }`
- [ ] token 在响应体顶层（非 data 内），对齐前端 `LoginInfoResult`
- [ ] login 方法接收 `user_agent` 参数用于解析浏览器/OS

### 4.4 登录日志

- [ ] 成功/失败均写 `sys_logininfor` 表
- [ ] `info_id` 自增（`Set(0)` 让数据库分配）
- [ ] `user_name` 字段写入用户名
- [ ] `ipaddr` 字段写入登录 IP（全小写字段名）
- [ ] `browser` 字段写入解析的浏览器名称
- [ ] `os` 字段写入解析的操作系统名称
- [ ] `status` 字段 "0" 成功 / "1" 失败
- [ ] `msg` 字段写入登录结果消息
- [ ] `login_time` 字段写入当前时间

---

## 5. 登出接口验收

- [ ] 从 `Authorization` header 提取 Bearer token
- [ ] 计算 JWT 剩余有效期（`exp - now`）
- [ ] 剩余有效期 > 0 时 Redis SET `blacklist:{token}` "1" EX {剩余秒数}
- [ ] 剩余有效期 <= 0 时跳过 Redis 写入（token 已过期）
- [ ] 返回 `{ code: 200, msg: "退出成功" }`
- [ ] 登出后原 token 访问受保护接口返回 401

---

## 6. getInfo 接口验收

- [ ] 从 `Operator` 提取器获取 user_id
- [ ] 调用 `user_service.get_user_by_id` 查询用户详情（返回 `UserVo`）
- [ ] **从 `UserVo` 中提取 `.user` 字段（`SysUserModel`）** 填入 `GetInfoResult.user`
- [ ] 调用 `role_service.get_role_keys_by_user_id` 查询角色 key 列表
- [ ] 调用 `menu_service.get_permissions_by_user_id` 查询权限标识列表
- [ ] **清空 user.password = None**（避免泄露密文）
- [ ] 返回 `GetInfoResult`（user/roles/permissions 在**响应体顶层**，非 data 内）
- [ ] 超管用户 roles=["admin"], permissions=["*:*:*"]
- [ ] 普通用户 roles 为实际角色 key 列表
- [ ] 普通用户 permissions 为实际权限标识列表

---

## 7. getRouters 接口验收

### 7.1 路由树构建

- [ ] 从 `Operator` 提取器获取 user_id
- [ ] 调用 `menu_service.get_menu_tree_by_user_id` 获取菜单树
- [ ] 调用 `menu_to_router` 递归转换为 RouterVo
- [ ] 返回 `AjaxResult<Vec<RouterVo>>`

### 7.2 menu_to_router 转换规则

- [ ] 顶级目录（parent_id==0, type=="M"）path 加 `/` 前缀
- [ ] 非顶级目录 path 原样保留
- [ ] 顶级目录 component 为空时默认 "Layout"
- [ ] 子级目录（parent_id!=0, type=="M"）component 为空时默认 "ParentView"
- [ ] 菜单（type=="C"）component 原样保留
- [ ] `is_frame==1 && type=="M"` 时 redirect 为 "noRedirect"
- [ ] `visible=="0" && type!="C" && is_frame==1` 时 alwaysShow 为 Some(true)
- [ ] `meta.title` = `menu_name`
- [ ] `meta.icon` = `icon`（默认空字符串）
- [ ] `meta.no_cache` = `is_cache == 1`
- [ ] `is_frame==0` 时 `meta.link` 为 `Some(path)`
- [ ] children 过滤 `menu_type == "F"`
- [ ] children 为空时返回 None

---

## 8. 验证码接口验收

- [ ] 调用 `utils::captcha::generate_captcha` 生成验证码
- [ ] Redis SET `captcha:{uuid}` 小写验证码，TTL 300s
- [ ] 返回 `CaptchaResult`（uuid/img/captchaEnabled 在**响应体顶层**，非 data 内）
- [ ] `captcha_enabled` 始终为 true
- [ ] `img` 为 Base64 字符串（不含 data:image/png;base64, 前缀）
- [ ] `uuid` 为会话标识

---

## 9. Redis key 命名与 TTL 验收

| 用途 | key 格式 | value | TTL | 验收 |
|------|----------|-------|-----|------|
| 验证码 | `captcha:{uuid}` | 小写验证码 | 300s | [ ] |
| token 黑名单 | `blacklist:{token}` | "1" | JWT 剩余有效期 | [ ] |

- [ ] 验证码 key 前缀为 `captcha:`
- [ ] 验证码 value 为小写字符串
- [ ] 验证码 TTL 为 300s（5 分钟）
- [ ] 验证码登录成功后 DEL
- [ ] 黑名单 key 前缀为 `blacklist:`
- [ ] 黑名单 value 为 "1"
- [ ] 黑名单 TTL 等于 JWT 剩余有效期

---

## 10. 状态管理验收

### 10.1 AppState

- [ ] AppState 新增 `auth_service: AuthService` 字段
- [ ] 构造函数初始化 `auth_service`
- [ ] AppState 不 derive(Clone)（通过 Arc<AppState> 共享）
- [ ] AuthService 持有 `db` + 3 个 Service + `logininfor_repo` + `user_repo`

### 10.2 operator 参数链路

- [ ] JWT 中间件注入 `Claims` 到 extensions
- [ ] `Operator` 提取器从 extensions 获取 `Claims`
- [ ] Handler 签名含 `Operator(operator)` 提取器
- [ ] Service 方法接收 `operator: &str`（由 handler 传入 `operator.username()`）

---

## 11. 路由结构验收

### 11.1 公开路由（免鉴权）

- [ ] `GET /health` 保留
- [ ] `GET /captchaImage` 新增
- [ ] `POST /login` 新增

### 11.2 受保护路由（auth_middleware）

- [ ] `POST /logout` 新增
- [ ] `GET /getInfo` 新增
- [ ] `GET /getRouters` 新增
- [ ] 用户 CRUD 路由保留
- [ ] 角色 CRUD 路由保留
- [ ] 菜单 CRUD 路由保留

### 11.3 全局中间件顺序

- [ ] `request_id_middleware`（最外层）
- [ ] `TraceLayer`
- [ ] `CorsLayer`
- [ ] `CompressionLayer`（最内层）
- [ ] `auth_middleware` 仅挂在 protected 分组

---

## 12. 错误处理验收

- [ ] 所有 handler 返回 `Result<T, AppError>` 或实现 `IntoResponse`
- [ ] JWT 签名验证失败返回 401
- [ ] token 过期返回 401
- [ ] 黑名单命中返回 401
- [ ] 权限不足返回 403
- [ ] 验证码错误返回 500（按既有约定）
- [ ] 用户不存在/密码错误返回 500（防枚举攻击）
- [ ] 账号停用/删除返回 500
- [ ] DbErr 自动转换为 AppError
- [ ] Redis 错误不 panic（`.ok()` 容错）
- [ ] 无 `unwrap()` / `expect()` 调用（测试代码除外）

---

## 13. 安全验收

- [ ] 密码不明文返回（getInfo 清空 password 字段）
- [ ] 登录失败不区分"用户不存在"和"密码错误"
- [ ] token 不存 Redis（JWT 自包含），仅黑名单存 Redis
- [ ] 黑名单 TTL 等于 JWT 剩余有效期（不无限期存储）
- [ ] 验证码一次性使用（登录后 DEL）
- [ ] 验证码大小写不敏感校验
- [ ] 盐值为 `"stepby_admin"`（非 `"salvo_admin"`）

---

## 14. 编译与测试验收

- [ ] `cargo check` 通过，0 error
- [ ] `cargo build` 通过
- [ ] `cargo test` 通过
- [ ] `cargo clippy` 无严重 warning
- [ ] 无未使用导入 warning

---

## 15. 前端接口契约对齐验收

### 15.1 验证码接口

- [ ] 响应字段对齐 `CaptchaInfoResult extends AjaxResult`：`captchaEnabled` / `img` / `uuid`
- [ ] **`captchaEnabled` / `img` / `uuid` 在响应体顶层**（非 data 内）
- [ ] `captchaEnabled` 为 boolean
- [ ] `img` 为 Base64 字符串
- [ ] `uuid` 为字符串

### 15.2 登录接口

- [ ] 请求体字段对齐前端 `login` 函数参数：`username` / `password` / `code` / `uuid`
- [ ] 响应体对齐 `LoginInfoResult extends AjaxResult`：`code` / `msg` / `token`
- [ ] **`token` 在响应体顶层**（非 data 内）
- [ ] 成功 code=200

### 15.3 登出接口

- [ ] 响应体 `{ code: 200, msg: "退出成功" }`
- [ ] 无 data 字段（或 data 为 null）

### 15.4 getInfo 接口

- [ ] 响应字段对齐 `UserInfoResult extends AjaxResult`：`user` / `roles` / `permissions`
- [ ] **`user` / `roles` / `permissions` 在响应体顶层**（非 data 内）
- [ ] `user` 字段对齐 `SysUser` TS 接口（驼峰命名）
- [ ] `roles` 为字符串数组
- [ ] `permissions` 为字符串数组
- [ ] **`user.password` 为 null**（已清空，不泄露密文）

### 15.5 getRouters 接口

- [ ] 响应 `data` 字段为 `RouterVo[]` 数组（此接口使用标准 AjaxResult<T> 包装）
- [ ] 响应字段对齐 `RouterVo`：`name` / `path` / `hidden` / `redirect` / `component` / `alwaysShow` / `meta` / `query` / `children`
- [ ] `meta` 字段对齐 `MetaVo`：`title` / `icon` / `noCache` / `link`
- [ ] `name` 优先使用 `route_name`，其次 `path`
- [ ] `hidden` 为 boolean
- [ ] `redirect` 为 `Option<String>`
- [ ] `alwaysShow` 为 `Option<bool>`
- [ ] `children` 为 `Option<Vec<RouterVo>>`
- [ ] 字段驼峰映射（`alwaysShow` / `noCache`）

---

## 16. 关键缺陷修复对照

| 旧实现缺陷 | axum-backend 修复 | 验收 |
|---------------------|-------------------|------|
| JWT 中间件只查 Redis 不验 JWT 签名 | JWT 签名验证 + Redis 黑名单双重校验 | [ ] |
| JWT exp=6h 但 Redis TTL=1h | JWT exp 与 Redis TTL 一致（均为 expire_hours） | [ ] |
| 登录日志未实现 | 成功/失败均写 `sys_logininfor` 表 | [ ] |
| getInfo 普通用户权限疑似 bug | 复用已实现的 `get_permissions_by_user_id` | [ ] |
| token 存 Redis（每次请求查 Redis） | JWT 自包含，仅登出写黑名单 | [ ] |
| `router_arr_to_tree2` O(n²) 递归 | `build_tree` O(n) + `menu_to_router` | [ ] |
| `#[handler]` + Depot | `from_fn_with_state` + Extensions | [ ] |
| `depot.insert("userId", user_id)` | `req.extensions_mut().insert(Claims)` | [ ] |
| `depot.get::<i32>("userId")` | `Operator` 提取器（`FromRequestParts`） | [ ] |
| `redis::del(token)` 登出 | `redis::set(blacklist:{token}, EX ttl)` | [ ] |
| 密码盐值 `"salvo_admin"` | `"stepby_admin"` | [ ] |
| 响应码 code=0 成功 | code=200 成功（对齐本项目前端） | [ ] |
| 验证码 5 位 | 验证码 4 位（排除易混淆字符） | [ ] |

---

## 17. 文档一致性验收

- [ ] `auth-spec.md` 业务逻辑设计与实现一致
- [ ] `auth-tasks.md` 任务全部完成
- [ ] `auth-checklist.md` 验收项全部通过
- [ ] `src/service/mod.rs` 模块注释更新（含 auth_service）
- [ ] `src/handler/mod.rs` 模块注释更新（含 auth_handler）
- [ ] `src/router/mod.rs` 模块注释更新（含 auth_router）
- [ ] `src/middleware/mod.rs` 模块注释更新（含 permission）
- [ ] 无残留 TODO 注释（除明确标注的后续阶段任务）

---

## 18. 联调验收清单

### 18.1 登录流程联调

- [ ] 前端访问 /login 页面，显示验证码图片
- [ ] 输入 admin / admin123 + 正确验证码，登录成功跳转首页
- [ ] 输入错误密码，提示「用户不存在/密码错误」
- [ ] 输入错误验证码，提示「验证码错误」
- [ ] 重复使用同一验证码 uuid，第二次提示「验证码错误」

### 18.2 鉴权流程联调

- [ ] 登录后访问受保护接口，携带 Authorization: Bearer <token>，正常响应
- [ ] 不携带 token 访问受保护接口，返回 401
- [ ] 携带无效 token 访问受保护接口，返回 401
- [ ] 登出后携带原 token 访问受保护接口，返回 401

### 18.3 首页加载联调

- [ ] 登录后首页加载 /getInfo，返回用户信息 + 角色 + 权限
- [ ] 登录后首页加载 /getRouters，返回路由树
- [ ] 侧边栏菜单根据 /getRouters 渲染
- [ ] 权限按钮根据 /getInfo 的 permissions 显示/隐藏

### 18.4 登出流程联调

- [ ] 点击退出登录，调用 /logout 接口
- [ ] 前端清除 Cookie `Admin-Token`
- [ ] 跳转回登录页
- [ ] 后端 Redis 黑名单有 `blacklist:{token}` 记录

### 18.5 刷新保持登录

- [ ] 登录后刷新页面，保持登录态
- [ ] 刷新后 /getInfo 正常返回用户信息
- [ ] 刷新后不跳转登录页
