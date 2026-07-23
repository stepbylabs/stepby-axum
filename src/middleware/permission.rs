// axum-backend/src/middleware/permission.rs
//! 权限校验中间件（Axum 原生 Tower Layer，from_fn_with_state 模式）
//!
//! 设计要点：
//! - 从 request extensions 提取 Claims（由 auth_middleware 注入）
//! - 从 request extensions 提取 MatchedPath（由 axum 路由匹配注入）
//! - 根据 HTTP 方法 + 匹配路径查表获取所需权限标识
//! - 无权限要求时直接放行（说明该路由仅需登录，不需细粒度权限）
//! - 超管短路：权限列表含 `*:*:*` 时放行
//! - 权限匹配：用户权限列表包含目标权限标识时放行，否则 403
//!
//! 实现方式：
//! - 使用 route_layer 挂载（路由匹配后执行，可访问 MatchedPath）
//! - 权限映射集中在 get_required_perm 函数中维护

use std::sync::Arc;

use axum::extract::{MatchedPath, Request, State};
use axum::middleware::Next;
use axum::response::Response;

use crate::common::AppError;
use crate::jwt::Claims;
use crate::state::AppState;

/// 权限校验中间件
///
/// 校验流程：
/// 1. 从 extensions 提取 Claims（无则 401，说明 auth_middleware 未执行）
/// 2. 从 extensions 提取 MatchedPath，结合 HTTP 方法查表获取所需权限
/// 3. 无权限要求则放行（profile、treeselect 等仅需登录的路由）
/// 4. 解析 user_id，查询用户权限标识列表
/// 5. 超管短路：权限列表含 `*:*:*` 时放行
/// 6. 权限匹配：包含目标权限标识则放行，否则 403
pub async fn permission_middleware(
    State(state): State<Arc<AppState>>,
    req: Request,
    next: Next,
) -> Result<Response, AppError> {
    // 1. 从 extensions 提取 Claims
    let claims = req
        .extensions()
        .get::<Claims>()
        .cloned()
        .ok_or_else(|| AppError::unauthorized("无法获取登录信息，请重新登录"))?;

    // 2. 获取匹配的路由路径和 HTTP 方法
    let method = req.method().clone();
    let matched_path = req
        .extensions()
        .get::<MatchedPath>()
        .cloned()
        .map(|p| p.as_str().to_string());

    // 3. 查表获取所需权限（无匹配路径或无权限要求则放行）
    let required_perm = match matched_path.as_deref() {
        Some(path) => get_required_perm(method.as_str(), path),
        None => None,
    };

    let required_perm = match required_perm {
        Some(p) => p,
        None => return Ok(next.run(req).await),
    };

    // 4. 解析 user_id，查询用户权限标识列表
    let user_id: i64 = claims
        .sub
        .parse()
        .map_err(|_| AppError::internal("用户 ID 解析失败"))?;

    let permissions = state
        .menu_service
        .get_permissions_by_user_id(user_id)
        .await?;

    // 5. 超管短路
    if permissions.iter().any(|p| p == "*:*:*") {
        return Ok(next.run(req).await);
    }

    // 6. 权限匹配
    if permissions.iter().any(|p| p == required_perm) {
        Ok(next.run(req).await)
    } else {
        Err(AppError::new(403, "没有权限访问该资源"))
    }
}

/// 路由权限映射表
///
/// 根据 HTTP 方法和匹配路径返回所需权限标识。
/// 不在此表中的路由视为仅需登录，不需细粒度权限。
///
/// 权限标识对齐 ruoyi-vue3-ts 前端菜单表的 perms 字段。
fn get_required_perm(method: &str, path: &str) -> Option<&'static str> {
    match (method, path) {
        // ===== 用户管理 =====
        ("GET", "/system/user/list") => Some("system:user:list"),
        ("GET", "/system/user/{id}") => Some("system:user:query"),
        ("POST", "/system/user") => Some("system:user:add"),
        ("PUT", "/system/user") => Some("system:user:edit"),
        ("PUT", "/system/user/changeStatus") => Some("system:user:edit"),
        ("PUT", "/system/user/resetPwd") => Some("system:user:resetPwd"),
        ("PUT", "/system/user/authRole") => Some("system:user:edit"),
        ("DELETE", "/system/user/{id}") => Some("system:user:remove"),
        ("POST", "/system/user/export") => Some("system:user:export"),
        // profile / 个人改密 / 角色下拉：仅需登录，不在此表

        // ===== 角色管理 =====
        ("GET", "/system/role/list") => Some("system:role:list"),
        ("GET", "/system/role/{id}") => Some("system:role:query"),
        ("POST", "/system/role") => Some("system:role:add"),
        ("PUT", "/system/role") => Some("system:role:edit"),
        ("PUT", "/system/role/changeStatus") => Some("system:role:edit"),
        ("PUT", "/system/role/dataScope") => Some("system:role:edit"),
        ("DELETE", "/system/role/{ids}") => Some("system:role:remove"),
        ("POST", "/system/role/export") => Some("system:role:export"),
        // authUser 系列接口：授权用户管理，使用 system:role:edit
        ("GET", "/system/role/authUser/allocatedList") => Some("system:role:list"),
        ("GET", "/system/role/authUser/unallocatedList") => Some("system:role:list"),
        ("PUT", "/system/role/authUser/cancel") => Some("system:role:edit"),
        ("PUT", "/system/role/authUser/cancelAll") => Some("system:role:edit"),
        ("PUT", "/system/role/authUser/selectAll") => Some("system:role:edit"),
        // deptTree：仅需登录，不在此表

        // ===== 菜单管理 =====
        ("GET", "/system/menu/list") => Some("system:menu:list"),
        ("GET", "/system/menu/{id}") => Some("system:menu:query"),
        ("POST", "/system/menu") => Some("system:menu:add"),
        ("PUT", "/system/menu") => Some("system:menu:edit"),
        ("PUT", "/system/menu/updateSort") => Some("system:menu:edit"),
        ("DELETE", "/system/menu/{id}") => Some("system:menu:remove"),
        // treeselect / roleMenuTreeselect：仅需登录，不在此表

        // ===== 部门管理 =====
        ("GET", "/system/dept/list") => Some("system:dept:list"),
        ("GET", "/system/dept/list/exclude/{deptId}") => Some("system:dept:list"),
        ("GET", "/system/dept/{deptId}") => Some("system:dept:query"),
        ("POST", "/system/dept") => Some("system:dept:add"),
        ("PUT", "/system/dept") => Some("system:dept:edit"),
        ("PUT", "/system/dept/updateSort") => Some("system:dept:edit"),
        ("DELETE", "/system/dept/{deptId}") => Some("system:dept:remove"),
        // treeselect：仅需登录，不在此表

        // ===== 定时任务管理 =====
        ("GET", "/monitor/job/list") => Some("monitor:job:list"),
        ("GET", "/monitor/job/{jobId}") => Some("monitor:job:query"),
        ("POST", "/monitor/job") => Some("monitor:job:add"),
        ("PUT", "/monitor/job") => Some("monitor:job:edit"),
        ("PUT", "/monitor/job/changeStatus") => Some("monitor:job:changeStatus"),
        ("PUT", "/monitor/job/run") => Some("monitor:job:changeStatus"),
        ("DELETE", "/monitor/job/{jobIds}") => Some("monitor:job:remove"),
        ("POST", "/monitor/job/export") => Some("monitor:job:export"),

        // ===== 定时任务日志 =====
        ("GET", "/monitor/jobLog/list") => Some("monitor:job:list"),
        ("DELETE", "/monitor/jobLog/{jobLogIds}") => Some("monitor:job:remove"),
        ("DELETE", "/monitor/jobLog/clean") => Some("monitor:job:remove"),
        ("POST", "/monitor/jobLog/export") => Some("monitor:job:export"),

        // ===== 字典管理 =====
        ("GET", "/system/dict/type/list") => Some("system:dict:list"),
        ("GET", "/system/dict/type/optionselect") => Some("system:dict:query"),
        ("GET", "/system/dict/type/{dictId}") => Some("system:dict:query"),
        ("POST", "/system/dict/type") => Some("system:dict:add"),
        ("PUT", "/system/dict/type") => Some("system:dict:edit"),
        ("DELETE", "/system/dict/type/refreshCache") => Some("system:dict:remove"),
        ("POST", "/system/dict/type/export") => Some("system:dict:export"),
        ("DELETE", "/system/dict/type/{dictIds}") => Some("system:dict:remove"),
        ("GET", "/system/dict/data/list") => Some("system:dict:list"),
        ("GET", "/system/dict/data/type/{dictType}") => Some("system:dict:query"),
        ("GET", "/system/dict/data/{dictCode}") => Some("system:dict:query"),
        ("POST", "/system/dict/data") => Some("system:dict:add"),
        ("PUT", "/system/dict/data") => Some("system:dict:edit"),
        ("DELETE", "/system/dict/data/{dictCodes}") => Some("system:dict:remove"),
        ("POST", "/system/dict/data/export") => Some("system:dict:export"),

        // ===== 通知公告 =====
        ("GET", "/system/notice/list") => Some("system:notice:list"),
        ("GET", "/system/notice/listTop") => Some("system:notice:list"),
        ("GET", "/system/notice/readUsers/list") => Some("system:notice:list"),
        ("GET", "/system/notice/{noticeId}") => Some("system:notice:query"),
        ("POST", "/system/notice") => Some("system:notice:add"),
        ("POST", "/system/notice/markRead") => None,
        ("POST", "/system/notice/markReadAll") => None,
        ("PUT", "/system/notice") => Some("system:notice:edit"),
        ("DELETE", "/system/notice/{noticeIds}") => Some("system:notice:remove"),

        // ===== 参数配置 =====
        ("GET", "/system/config/list") => Some("system:config:list"),
        ("GET", "/system/config/{configId}") => Some("system:config:query"),
        // /system/config/configKey/{configKey} 需 system:config:query 权限，防止任意已登录用户读取敏感配置（P0-R81-003）
        ("GET", "/system/config/configKey/{configKey}") => Some("system:config:query"),
        ("POST", "/system/config") => Some("system:config:add"),
        ("PUT", "/system/config") => Some("system:config:edit"),
        ("DELETE", "/system/config/refreshCache") => Some("system:config:remove"),
        ("DELETE", "/system/config/{configIds}") => Some("system:config:remove"),
        ("POST", "/system/config/export") => Some("system:config:export"),

        // ===== 岗位管理 =====
        ("GET", "/system/post/list") => Some("system:post:list"),
        ("GET", "/system/post/{postId}") => Some("system:post:query"),
        ("POST", "/system/post") => Some("system:post:add"),
        ("PUT", "/system/post") => Some("system:post:edit"),
        ("DELETE", "/system/post/{postIds}") => Some("system:post:remove"),
        ("POST", "/system/post/export") => Some("system:post:export"),
        // optionselect：仅需登录，不在此表

        // ===== 操作日志 =====
        ("GET", "/monitor/operlog/list") => Some("monitor:operlog:list"),
        ("DELETE", "/monitor/operlog/{operIds}") => Some("monitor:operlog:remove"),
        ("DELETE", "/monitor/operlog/clean") => Some("monitor:operlog:remove"),
        ("POST", "/monitor/operlog/export") => Some("monitor:operlog:export"),

        // ===== 登录日志 =====
        ("GET", "/monitor/logininfor/list") => Some("monitor:logininfor:list"),
        ("GET", "/monitor/logininfor/stats") => Some("monitor:logininfor:list"),
        ("DELETE", "/monitor/logininfor/{infoIds}") => Some("monitor:logininfor:remove"),
        ("GET", "/monitor/logininfor/unlock/{userName}") => Some("monitor:logininfor:unlock"),
        ("DELETE", "/monitor/logininfor/clean") => Some("monitor:logininfor:remove"),
        ("POST", "/monitor/logininfor/export") => Some("monitor:logininfor:export"),

        // ===== 在线用户 =====
        ("GET", "/monitor/online/list") => Some("monitor:online:list"),
        ("DELETE", "/monitor/online/{tokenId}") => Some("monitor:online:forceLogout"),

        // ===== 缓存监控 =====
        ("GET", "/monitor/cache") => Some("monitor:cache:list"),
        ("GET", "/monitor/cache/getNames") => Some("monitor:cache:list"),
        ("GET", "/monitor/cache/getKeys/{cacheName}") => Some("monitor:cache:list"),
        ("GET", "/monitor/cache/getValue/{cacheName}/{cacheKey}") => Some("monitor:cache:query"),
        ("DELETE", "/monitor/cache/clearCacheName/{cacheName}") => Some("monitor:cache:clear"),
        ("DELETE", "/monitor/cache/clearCacheKey/{cacheKey}") => Some("monitor:cache:clear"),
        ("DELETE", "/monitor/cache/clearCacheAll") => Some("monitor:cache:clear"),

        // ===== 服务器监控 =====
        ("GET", "/monitor/server") => Some("monitor:server:list"),

        // ===== 代码生成 =====
        ("GET", "/tool/gen/list") => Some("tool:gen:list"),
        ("GET", "/tool/gen/db/list") => Some("tool:gen:list"),
        ("GET", "/tool/gen/{tableId}") => Some("tool:gen:query"),
        ("POST", "/tool/gen/importTable") => Some("tool:gen:import"),
        ("POST", "/tool/gen/createTable") => Some("tool:gen:edit"),
        ("PUT", "/tool/gen") => Some("tool:gen:edit"),
        ("DELETE", "/tool/gen/{tableIds}") => Some("tool:gen:remove"),
        ("GET", "/tool/gen/preview/{tableId}") => Some("tool:gen:preview"),
        ("GET", "/tool/gen/genCode/{tableName}") => Some("tool:gen:code"),
        ("GET", "/tool/gen/synchDb/{tableName}") => Some("tool:gen:edit"),

        // ===== 文件管理 =====
        ("GET", "/system/file/list") => Some("system:file:list"),
        ("POST", "/system/file/upload") => Some("system:file:add"),
        ("DELETE", "/system/file/delete") => Some("system:file:remove"),

        // ===== 数据备份恢复 =====
        ("GET", "/system/backup/list") => Some("system:backup:list"),
        ("GET", "/system/backup/{backupId}") => Some("system:backup:query"),
        ("POST", "/system/backup") => Some("system:backup:add"),
        ("POST", "/system/backup/restore/{backupId}") => Some("system:backup:edit"),
        ("GET", "/system/backup/download/{backupId}") => Some("system:backup:query"),
        ("DELETE", "/system/backup/{backupIds}") => Some("system:backup:remove"),

        // ===== 任务进度中心 =====
        ("GET", "/system/task/list") => Some("system:task:list"),
        ("GET", "/system/task/{taskId}") => Some("system:task:query"),
        ("DELETE", "/system/task/{taskIds}") => Some("system:task:remove"),

        // ===== 审计日志大屏 =====
        // 权限标识与 sys_menu 菜单 120 (审计大屏) 的 perms=monitor:audit:list 对齐
        ("GET", "/monitor/operlog/stats") => Some("monitor:audit:list"),

        // ===== IP 归属地库管理 =====
        // 菜单 menu_id=121 (IP 库管理) 在系统监控目录下，perms=monitor:iplocation:list
        ("GET", "/system/ipLocation/status") => Some("monitor:iplocation:list"),
        ("GET", "/system/ipLocation/config") => Some("monitor:iplocation:list"),
        ("PUT", "/system/ipLocation/config") => Some("monitor:iplocation:edit"),
        ("POST", "/system/ipLocation/update") => Some("monitor:iplocation:edit"),
        ("POST", "/system/ipLocation/reload") => Some("monitor:iplocation:edit"),
        ("POST", "/system/ipLocation/reloadXdb") => Some("monitor:iplocation:edit"),

        _ => None,
    }
}
