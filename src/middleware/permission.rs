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
//! M-1：权限拒绝事件写入 sys_oper_log 审计日志（best-effort，不阻断 403 响应）。
//! 原方案 permission_middleware 拒绝时仅 tracing::warn，oper_log_middleware 因挂在
//! permission 之后而无法记录，导致权限越权尝试无审计痕迹。现拒绝时直接 spawn 写入。
//!
//! 实现方式：
//! - 使用 route_layer 挂载（路由匹配后执行，可访问 MatchedPath）
//! - 权限映射集中在 get_required_perm 函数中维护

use std::net::SocketAddr;
use std::panic::AssertUnwindSafe;
use std::sync::Arc;
use std::time::Duration;

use axum::extract::{ConnectInfo, MatchedPath, Request, State};
use axum::middleware::Next;
use axum::response::Response;
use futures::FutureExt;

use crate::common::AppError;
use crate::jwt::Claims;
use crate::middleware::oper_log::infer_module_title;
use crate::service::sys_oper_log_service::OperLogRecord;
use crate::state::AppState;
use crate::utils::ip::extract_client_ip;

/// 审计日志异步写入的超时上限（与 oper_log_middleware 对齐，R6-RUST-13）
const PERMISSION_AUDIT_LOG_TIMEOUT: Duration = Duration::from_secs(5);

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
        .ok_or_else(|| AppError::unauthorized(&crate::tr!("error.auth.login_info_missing")))?;

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
        None => {
            // 未登记权限映射的路由：依据 deny_by_default 策略处置
            match matched_path.as_deref() {
                Some(path) if state.config.permission_deny_by_default => {
                    if is_login_only_path(method.as_str(), path) {
                        // 合法"仅登录"路由（下拉树、个人资料、标记已读、登录态接口等）放行
                        tracing::debug!(
                            user_id = claims.sub,
                            method = %method,
                            path,
                            "仅登录路由放行（deny_by_default 模式）"
                        );
                        return Ok(next.run(req).await);
                    }
                    // 受保护路由未登记权限映射且不在仅登录白名单：拒绝（403）+ 审计
                    // 防止新增路由漏登记权限导致越权（fail-closed）。
                    tracing::warn!(
                        user_id = claims.sub,
                        method = %method,
                        path,
                        "权限拒绝（deny_by_default）：受保护路由未登记权限映射，不在仅登录白名单"
                    );
                    spawn_permission_denied_audit(
                        &state,
                        &claims,
                        &method,
                        path,
                        "<unmapped>",
                        &req,
                    );
                    return Err(AppError::new(
                        403,
                        crate::tr!("error.auth.permission_denied"),
                    ));
                }
                _ => {
                    // 默认 fail-open：放行（保持现有默认行为，零破坏性）
                    return Ok(next.run(req).await);
                }
            }
        }
    };

    // 4. 解析 user_id，查询用户权限标识列表
    let user_id: i64 = claims
        .sub
        .parse()
        .map_err(|_| AppError::internal(&crate::tr!("error.auth.user_id_parse_failed")))?;

    let permissions = state
        .menu_service
        .get_permissions_by_user_id(user_id)
        .await?;

    // 5. 超管短路
    if permissions.iter().any(|p| p == "*:*:*") {
        tracing::debug!(
            user_id,
            method = %method,
            path = ?matched_path,
            "超管访问放行"
        );
        return Ok(next.run(req).await);
    }

    // 6. 权限匹配
    if permissions.iter().any(|p| p == required_perm) {
        Ok(next.run(req).await)
    } else {
        tracing::warn!(
            user_id,
            method = %method,
            path = ?matched_path,
            required_perm,
            "权限拒绝：用户缺少所需权限"
        );

        // M-1：权限拒绝写入审计日志（best-effort，不阻断 403 响应）
        // 原 oper_log_middleware 挂在 permission 之后，拒绝时无法记录，导致越权尝试无审计痕迹。
        // 现在 permission_middleware 内直接 spawn 写入 sys_oper_log。
        spawn_permission_denied_audit(
            &state,
            &claims,
            &method,
            matched_path.as_deref().unwrap_or(""),
            required_perm,
            &req,
        );

        Err(AppError::new(
            403,
            crate::tr!("error.auth.permission_denied"),
        ))
    }
}

/// 异步写入权限拒绝审计日志（best-effort，不阻断 403 响应）
///
/// 与 oper_log_middleware 写入路径对齐：
/// - 使用 AssertUnwindSafe + catch_unwind 防 panic 击溃 worker
/// - tokio::time::timeout 5s 保护，避免日志写入卡死导致 spawn 任务累积
/// - 部门名称在 spawn 内查询（与 oper_log_middleware 一致）
fn spawn_permission_denied_audit(
    state: &Arc<AppState>,
    claims: &Claims,
    method: &axum::http::Method,
    matched_path: &str,
    required_perm: &str,
    req: &Request,
) {
    // 提取客户端真实 IP（含可信代理白名单 + XFF 链校验）
    let peer_ip = req
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ci| ci.0.ip())
        .unwrap_or_else(|| std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED));
    let headers = req.headers().clone();
    let oper_ip = extract_client_ip(&headers, peer_ip, &state.config.server.trusted_proxies);
    let oper_location = state.ip_locator.locate(&oper_ip);

    // 构造审计日志记录（business_type=0 其他，status=1 失败）
    let title = infer_module_title(matched_path);
    let oper_url = req
        .uri()
        .path_and_query()
        .map(|s| s.to_string())
        .unwrap_or_else(|| req.uri().path().to_string());
    let error_msg = crate::tr!("log.auth.permission_denied", perm = required_perm);

    let record = OperLogRecord {
        title,
        business_type: 0, // 0=其他（权限拒绝非业务写操作）
        method: matched_path.to_string(),
        request_method: method.to_string(),
        operator_type: 1, // 1=后台用户
        oper_name: claims.username.clone(),
        dept_name: String::new(), // spawn 内查询后填入
        oper_url,
        oper_ip,
        oper_location,
        oper_param: String::new(), // permission_middleware 不读请求体
        oper_before: String::new(),
        json_result: String::new(),
        status: "1".to_string(), // 1=失败
        error_msg,
        cost_time: 0, // 权限拒绝未执行业务，耗时无意义
    };

    let oper_log_service = state.oper_log_service.clone();
    let dept_service = state.dept_service.clone();
    let user_id_str = claims.sub.clone();
    tokio::spawn(async move {
        let result = AssertUnwindSafe(async {
            if let Err(_elapsed) = tokio::time::timeout(PERMISSION_AUDIT_LOG_TIMEOUT, async {
                // 查询操作人部门名称（通过 user_id → dept_id → dept_name）
                let dept_name = if !user_id_str.is_empty() {
                    match user_id_str.parse::<i64>() {
                        Ok(uid) => match dept_service.get_dept_name_by_user_id(uid).await {
                            Ok(name) => name,
                            Err(e) => {
                                tracing::warn!(
                                    user_id = uid,
                                    error = %e,
                                    "查询操作人部门名称失败（权限拒绝审计日志）"
                                );
                                String::new()
                            }
                        },
                        Err(_) => String::new(),
                    }
                } else {
                    String::new()
                };

                let mut record = record;
                record.dept_name = dept_name;
                oper_log_service.record_oper_log(record).await;
            })
            .await
            {
                tracing::warn!(
                    timeout_secs = PERMISSION_AUDIT_LOG_TIMEOUT.as_secs(),
                    "权限拒绝审计日志写入超时，已放弃本次记录"
                );
            }
        })
        .catch_unwind()
        .await;

        if let Err(panic_err) = result {
            tracing::error!("权限拒绝审计日志 spawn 内发生 panic: {:?}", panic_err);
        }
    });
}

/// 路由权限映射表
///
/// 根据 HTTP 方法和匹配路径返回所需权限标识。
/// 不在此表中的路由视为仅需登录，不需细粒度权限。
///
/// 权限标识对齐前端菜单表的 perms 字段。
fn get_required_perm(method: &str, path: &str) -> Option<&'static str> {
    match (method, path) {
        // ===== 用户管理 =====
        ("GET", "/system/user/list") => Some("system:user:list"),
        ("GET", "/system/user/{id}") => Some("system:user:query"),
        ("GET", "/system/user/") => Some("system:user:query"),
        ("GET", "/system/user/authRole/{userId}") => Some("system:user:query"),
        ("POST", "/system/user") => Some("system:user:add"),
        ("PUT", "/system/user") => Some("system:user:edit"),
        ("PUT", "/system/user/changeStatus") => Some("system:user:edit"),
        ("PUT", "/system/user/resetPwd") => Some("system:user:resetPwd"),
        ("PUT", "/system/user/authRole") => Some("system:user:edit"),
        ("DELETE", "/system/user/{id}") => Some("system:user:remove"),
        ("POST", "/system/user/export") => Some("system:user:export"),
        ("POST", "/system/user/importTemplate") => Some("system:user:import"),
        ("POST", "/system/user/importData") => Some("system:user:import"),
        // profile / 个人改密 / 角色下拉：仅需登录，不在此表

        // ===== 角色管理 =====
        ("GET", "/system/role/list") => Some("system:role:list"),
        ("GET", "/system/role/{id}") => Some("system:role:query"),
        ("POST", "/system/role") => Some("system:role:add"),
        ("PUT", "/system/role") => Some("system:role:edit"),
        ("PUT", "/system/role/changeStatus") => Some("system:role:edit"),
        ("PUT", "/system/role/dataScope") => Some("system:role:edit"),
        ("DELETE", "/system/role/{id}") => Some("system:role:remove"),
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
        ("DELETE", "/monitor/job/{jobId}") => Some("monitor:job:remove"),
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
        ("DELETE", "/system/dict/type/{dictId}") => Some("system:dict:remove"),
        ("GET", "/system/dict/data/list") => Some("system:dict:list"),
        ("GET", "/system/dict/data/type/{dictType}") => Some("system:dict:query"),
        ("GET", "/system/dict/data/{dictCode}") => Some("system:dict:query"),
        ("POST", "/system/dict/data") => Some("system:dict:add"),
        ("PUT", "/system/dict/data") => Some("system:dict:edit"),
        ("DELETE", "/system/dict/data/{dictCode}") => Some("system:dict:remove"),
        ("POST", "/system/dict/data/export") => Some("system:dict:export"),

        // ===== 通知公告 =====
        ("GET", "/system/notice/list") => Some("system:notice:list"),
        ("GET", "/system/notice/listTop") => Some("system:notice:list"),
        ("GET", "/system/notice/readUsers/list") => Some("system:notice:list"),
        ("GET", "/system/notice/{noticeId}") => Some("system:notice:query"),
        ("POST", "/system/notice") => Some("system:notice:add"),
        // markRead / markReadAll / markAllUnreadRead：标记本人已读为自助操作，仅需登录认证
        // 权限粒度由前端 v-hasPermi 控制按钮可见性，后端不做 RBAC 校验
        ("POST", "/system/notice/markRead") => None,
        ("POST", "/system/notice/markReadAll") => None,
        ("POST", "/system/notice/markAllUnreadRead") => None,
        ("PUT", "/system/notice") => Some("system:notice:edit"),
        ("DELETE", "/system/notice/{noticeId}") => Some("system:notice:remove"),

        // ===== 参数配置 =====
        ("GET", "/system/config/list") => Some("system:config:list"),
        ("GET", "/system/config/{configId}") => Some("system:config:query"),
        // /system/config/configKey/{configKey} 需 system:config:query 权限，防止任意已登录用户读取敏感配置（P0-R81-003）
        ("GET", "/system/config/configKey/{configKey}") => Some("system:config:query"),
        ("POST", "/system/config") => Some("system:config:add"),
        ("PUT", "/system/config") => Some("system:config:edit"),
        ("DELETE", "/system/config/refreshCache") => Some("system:config:remove"),
        ("DELETE", "/system/config/{configId}") => Some("system:config:remove"),
        ("POST", "/system/config/export") => Some("system:config:export"),

        // ===== 岗位管理 =====
        ("GET", "/system/post/list") => Some("system:post:list"),
        ("GET", "/system/post/{postId}") => Some("system:post:query"),
        ("POST", "/system/post") => Some("system:post:add"),
        ("PUT", "/system/post") => Some("system:post:edit"),
        ("DELETE", "/system/post/{postId}") => Some("system:post:remove"),
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
        // 路由定义见 sys_logininfor_router.rs：实际方法为 POST（解锁操作有副作用，GET 不规范）
        ("POST", "/monitor/logininfor/unlock/{userName}") => Some("monitor:logininfor:unlock"),
        ("DELETE", "/monitor/logininfor/clean") => Some("monitor:logininfor:remove"),
        ("POST", "/monitor/logininfor/export") => Some("monitor:logininfor:export"),

        // ===== 在线用户 =====
        // 路由定义见 monitor_online_router.rs：参数名为 {tokenHash}（P1-19 改造后从 tokenId 改为 tokenHash）
        ("GET", "/monitor/online/list") => Some("monitor:online:list"),
        ("DELETE", "/monitor/online/{tokenHash}") => Some("monitor:online:forceLogout"),

        // ===== 缓存监控 =====
        ("GET", "/monitor/cache") => Some("monitor:cache:list"),
        ("GET", "/monitor/cache/getNames") => Some("monitor:cache:list"),
        // hotKeys / prefixStats 与 getNames 同权（内存统计属只读监控，绑定列表查看权限）
        ("GET", "/monitor/cache/hotKeys") => Some("monitor:cache:list"),
        ("GET", "/monitor/cache/prefixStats") => Some("monitor:cache:list"),
        ("GET", "/monitor/cache/getKeys/{cacheName}") => Some("monitor:cache:list"),
        ("GET", "/monitor/cache/getValue/{cacheName}/{cacheKey}") => Some("monitor:cache:query"),
        // 缓存清除权限与 sys_menu 按钮种子 3022/3023 对齐（monitor:cache:clearName / clearKey）
        ("DELETE", "/monitor/cache/clearCacheName/{cacheName}") => Some("monitor:cache:clearName"),
        ("DELETE", "/monitor/cache/clearCacheKey/{cacheKey}") => Some("monitor:cache:clearKey"),
        // clearCacheAll 端点已从路由中移除（FLUSHDB 会误清业务键），权限映射随之删除

        // ===== 服务器监控 =====
        ("GET", "/monitor/server") => Some("monitor:server:list"),

        // ===== 实时日志监控 =====
        // 菜单 menu_id=135 (实时日志) 在系统监控目录下，perms=monitor:log:list
        ("GET", "/monitor/log/files") => Some("monitor:log:list"),
        ("GET", "/monitor/log/tail") => Some("monitor:log:list"),

        // ===== 代码生成 =====
        ("GET", "/tool/gen/list") => Some("tool:gen:list"),
        ("GET", "/tool/gen/db/list") => Some("tool:gen:list"),
        ("GET", "/tool/gen/{tableId}") => Some("tool:gen:query"),
        ("POST", "/tool/gen/importTable") => Some("tool:gen:import"),
        ("POST", "/tool/gen/createTable") => Some("tool:gen:edit"),
        ("PUT", "/tool/gen") => Some("tool:gen:edit"),
        ("DELETE", "/tool/gen/{tableId}") => Some("tool:gen:remove"),
        ("GET", "/tool/gen/preview/{tableId}") => Some("tool:gen:preview"),
        ("GET", "/tool/gen/genCode/{tableName}") => Some("tool:gen:code"),
        // P0-4 修复：synchDb 路由实际注册为 POST（见 tool_gen_router.rs:37），
        // 原映射为 GET 导致权限校验被绕过（get_required_perm 返回 None）
        ("POST", "/tool/gen/synchDb/{tableName}") => Some("tool:gen:edit"),
        // P1-6 修复：batchGenCode 批量生成代码未映射权限，任意登录用户可调用
        ("GET", "/tool/gen/batchGenCode") => Some("tool:gen:code"),

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
        ("DELETE", "/system/backup/{backupId}") => Some("system:backup:remove"),

        // ===== 任务进度中心 =====
        ("GET", "/system/task/list") => Some("system:task:list"),
        ("GET", "/system/task/{taskId}") => Some("system:task:query"),
        ("DELETE", "/system/task/{taskId}") => Some("system:task:remove"),

        // ===== API 限流配置 =====
        // P0-3 修复：原完全缺失权限映射，任意登录用户可增删改限流规则，
        // 可禁用登录接口限流导致暴力破解。权限标识对齐 sys_menu 表 rateLimit 菜单 perms 字段。
        ("GET", "/system/rateLimit/list") => Some("system:rateLimit:list"),
        ("GET", "/system/rateLimit/{id}") => Some("system:rateLimit:query"),
        ("POST", "/system/rateLimit") => Some("system:rateLimit:add"),
        ("PUT", "/system/rateLimit") => Some("system:rateLimit:edit"),
        ("DELETE", "/system/rateLimit/{id}") => Some("system:rateLimit:remove"),
        ("POST", "/system/rateLimit/export") => Some("system:rateLimit:export"),

        // ===== 消息渠道与模板管理 =====
        // 权限标识对齐 sys_menu 迁移种子（140 目录 / 141 渠道 / 142 模板 / 143 记录 及按钮 3101-3123，见 m20260818_000002_msg_module）
        ("GET", "/system/msg/channel/list") => Some("system:msg:channel:list"),
        ("GET", "/system/msg/channel/{channelId}") => Some("system:msg:channel:query"),
        ("POST", "/system/msg/channel") => Some("system:msg:channel:add"),
        ("PUT", "/system/msg/channel") => Some("system:msg:channel:edit"),
        ("DELETE", "/system/msg/channel/{channelId}") => Some("system:msg:channel:remove"),
        ("POST", "/system/msg/channel/test/{channelId}") => Some("system:msg:channel:test"),
        ("GET", "/system/msg/template/list") => Some("system:msg:template:list"),
        ("GET", "/system/msg/template/{templateId}") => Some("system:msg:template:query"),
        ("POST", "/system/msg/template") => Some("system:msg:template:add"),
        ("PUT", "/system/msg/template") => Some("system:msg:template:edit"),
        ("DELETE", "/system/msg/template/{templateId}") => Some("system:msg:template:remove"),
        ("GET", "/system/msg/log/list") => Some("system:msg:log:list"),
        ("DELETE", "/system/msg/log/{logIds}") => Some("system:msg:log:remove"),
        ("DELETE", "/system/msg/log/clean") => Some("system:msg:log:clean"),
        // 直接发送 / 重试 / 标记重试 / 批量重试均为"消息发出"类操作，统一对齐 log:retry 按钮权限（3123）
        ("POST", "/system/msg/send") => Some("system:msg:log:retry"),
        ("POST", "/system/msg/log/retry/{logIds}") => Some("system:msg:log:retry"),
        ("POST", "/system/msg/log/retryPending/{batch}") => Some("system:msg:log:retry"),
        ("POST", "/system/msg/log/markPending/{logIds}") => Some("system:msg:log:retry"),

        // ===== 审计日志大屏 =====
        // 权限标识与 sys_menu 菜单 120 (审计大屏) 的 perms=monitor:audit:list 对齐
        ("GET", "/monitor/operlog/stats") => Some("monitor:audit:list"),
        // 合规报告与审计大屏共享 monitor:audit:list 权限
        ("GET", "/monitor/operlog/compliance-report") => Some("monitor:audit:list"),
        // 异常操作告警状态检测，与审计大屏共享监控查看权限
        ("GET", "/monitor/operlog/alarm-status") => Some("monitor:audit:list"),
        // 操作日志类型统计（dashboard 首页图表专用聚合接口，与 /dashboard/stats 一致使用监控查看权限）
        ("GET", "/monitor/operlog/stats-by-type") => Some("monitor:server:list"),

        // ===== IP 归属地库管理 =====
        // 菜单 menu_id=121 (IP 库管理) 在系统监控目录下，perms=monitor:iplocation:list
        ("GET", "/system/ipLocation/status") => Some("monitor:iplocation:list"),
        ("GET", "/system/ipLocation/config") => Some("monitor:iplocation:list"),
        ("PUT", "/system/ipLocation/config") => Some("monitor:iplocation:edit"),
        ("POST", "/system/ipLocation/update") => Some("monitor:iplocation:edit"),
        ("POST", "/system/ipLocation/reload") => Some("monitor:iplocation:edit"),
        ("POST", "/system/ipLocation/reloadXdb") => Some("monitor:iplocation:edit"),

        // ===== 通用文件上传/下载 =====
        // /common/upload 已有 system:file:add 权限对齐文件管理模块，避免任意登录用户可上传
        ("POST", "/common/upload") => Some("system:file:add"),
        // 通用下载仅需登录（无敏感数据，但需登录态校验），不设细粒度权限
        // /common/download 和 /common/download/resource 不在此表

        // ===== 仪表盘统计 =====
        // 含操作日志聚合统计，需监控查看权限，避免任意登录用户获取全局统计
        ("GET", "/dashboard/stats") => Some("monitor:server:list"),
        ("GET", "/dashboard/user-stats") => Some("monitor:server:list"),

        _ => None,
    }
}

/// 仅登录白名单（deny_by_default 模式下用于区分"合法仅登录路由"与"漏登记权限映射"）
///
/// 这些路由在 `get_required_perm` 中返回 `None`（仅需登录认证，无细粒度 RBAC 权限），
/// 属于既有设计：下拉树、个人中心、标记已读、登录态相关接口等。
///
/// 当 `permission_deny_by_default=true`（生产 fail-closed）时，未登记权限映射的受保护路由
/// 默认拒绝（403），仅本表所列"明确仅登录"路由放行，防止新增路由漏登记权限导致越权。
///
/// 维护约定：若某路由确为"仅登录"（无需 RBAC），必须同时在此登记，
/// 否则开启 `deny_by_default` 后该接口会被误拦截（403）。
fn is_login_only_path(method: &str, path: &str) -> bool {
    matches!(
        (method, path),
        // ===== 登录态相关（protected_auth_routes，需 auth 无需 RBAC）=====
        ("POST", "/logout")
            | ("GET", "/getInfo")
            | ("GET", "/getRouters")
            | ("POST", "/unlockscreen")
        // ===== 通用下载（仅登录）=====
            | ("GET", "/common/download")
            | ("GET", "/common/download/resource")
        // ===== 个人中心（仅本人操作，仅需登录）=====
            | ("GET", "/system/user/profile")
            | ("PUT", "/system/user/profile")
            | ("PUT", "/system/user/profile/updatePwd")
            | ("POST", "/system/user/profile/avatar")
            | ("GET", "/system/user/deptTree")
        // ===== 下拉树 / 选项（仅登录）=====
            | ("GET", "/system/role/deptTree/{roleId}")
            | ("GET", "/system/menu/treeselect")
            | ("GET", "/system/menu/roleMenuTreeselect/{roleId}")
            | ("GET", "/system/dept/treeselect")
            | ("GET", "/system/post/optionselect")
        // ===== TOTP 多因子认证（个人自助操作，仅登录）=====
            | ("POST", "/system/user/totp/setup")
            | ("POST", "/system/user/totp/verify")
            | ("GET", "/system/user/totp/status")
            | ("POST", "/system/user/totp/disable")
        // ===== 公告标记已读（自助，仅登录）=====
            | ("POST", "/system/notice/markRead")
            | ("POST", "/system/notice/markReadAll")
            | ("POST", "/system/notice/markAllUnreadRead")
    )
}

#[cfg(test)]
mod tests {
    use super::{get_required_perm, is_login_only_path};

    // ===== 用户管理权限映射 =====
    #[test]
    fn test_user_list_perm() {
        assert_eq!(
            get_required_perm("GET", "/system/user/list"),
            Some("system:user:list")
        );
    }

    #[test]
    fn test_user_add_perm() {
        assert_eq!(
            get_required_perm("POST", "/system/user"),
            Some("system:user:add")
        );
    }

    #[test]
    fn test_user_edit_perm() {
        assert_eq!(
            get_required_perm("PUT", "/system/user"),
            Some("system:user:edit")
        );
    }

    #[test]
    fn test_user_reset_pwd_perm() {
        assert_eq!(
            get_required_perm("PUT", "/system/user/resetPwd"),
            Some("system:user:resetPwd")
        );
    }

    #[test]
    fn test_user_delete_perm() {
        assert_eq!(
            get_required_perm("DELETE", "/system/user/{id}"),
            Some("system:user:remove")
        );
    }

    #[test]
    fn test_user_export_perm() {
        assert_eq!(
            get_required_perm("POST", "/system/user/export"),
            Some("system:user:export")
        );
    }

    // ===== 仅需登录的路由（返回 None） =====
    #[test]
    fn test_profile_route_no_perm() {
        // profile 路由仅需登录，不在权限表中
        assert_eq!(get_required_perm("GET", "/system/user/profile"), None);
        assert_eq!(get_required_perm("PUT", "/system/user/profile"), None);
    }

    #[test]
    fn test_treeselect_no_perm() {
        assert_eq!(get_required_perm("GET", "/system/dept/treeselect"), None);
    }

    // ===== 角色管理权限映射 =====
    #[test]
    fn test_role_list_perm() {
        assert_eq!(
            get_required_perm("GET", "/system/role/list"),
            Some("system:role:list")
        );
    }

    #[test]
    fn test_role_add_perm() {
        assert_eq!(
            get_required_perm("POST", "/system/role"),
            Some("system:role:add")
        );
    }

    // ===== 监控模块权限映射 =====
    #[test]
    fn test_online_force_logout_perm() {
        assert_eq!(
            get_required_perm("DELETE", "/monitor/online/{tokenHash}"),
            Some("monitor:online:forceLogout")
        );
    }

    #[test]
    fn test_cache_clear_perm() {
        // clearCacheAll 端点已移除；清除权限与 sys_menu 按钮种子 3022/3023 对齐（P0-10）
        assert_eq!(
            get_required_perm("DELETE", "/monitor/cache/clearCacheName/{cacheName}"),
            Some("monitor:cache:clearName")
        );
        assert_eq!(
            get_required_perm("DELETE", "/monitor/cache/clearCacheKey/{cacheKey}"),
            Some("monitor:cache:clearKey")
        );
    }

    #[test]
    fn test_cache_stats_perm() {
        // hotKeys / prefixStats 为只读监控统计，与 getNames 同权 monitor:cache:list
        assert_eq!(
            get_required_perm("GET", "/monitor/cache/getNames"),
            Some("monitor:cache:list")
        );
        assert_eq!(
            get_required_perm("GET", "/monitor/cache/hotKeys"),
            Some("monitor:cache:list")
        );
        assert_eq!(
            get_required_perm("GET", "/monitor/cache/prefixStats"),
            Some("monitor:cache:list")
        );
        // 方法混淆不应命中（POST 不应获取热 key）
        assert_eq!(get_required_perm("POST", "/monitor/cache/hotKeys"), None);
        assert_eq!(
            get_required_perm("DELETE", "/monitor/cache/prefixStats"),
            None
        );
    }

    #[test]
    fn test_operlog_list_perm() {
        assert_eq!(
            get_required_perm("GET", "/monitor/operlog/list"),
            Some("monitor:operlog:list")
        );
    }

    // ===== 安全关键路由权限映射 =====
    #[test]
    fn test_rate_limit_add_perm() {
        // P0-3 修复：限流配置必须有权限校验
        assert_eq!(
            get_required_perm("POST", "/system/rateLimit"),
            Some("system:rateLimit:add")
        );
    }

    #[test]
    fn test_backup_restore_perm() {
        assert_eq!(
            get_required_perm("POST", "/system/backup/restore/{backupId}"),
            Some("system:backup:edit")
        );
    }

    #[test]
    fn test_ip_location_update_perm() {
        assert_eq!(
            get_required_perm("POST", "/system/ipLocation/update"),
            Some("monitor:iplocation:edit")
        );
    }

    #[test]
    fn test_gen_synchdb_perm() {
        // P0-4 修复：synchDb 必须为 POST 且有权限校验
        assert_eq!(
            get_required_perm("POST", "/tool/gen/synchDb/{tableName}"),
            Some("tool:gen:edit")
        );
        // GET 请求应返回 None（防止方法混淆绕过）
        assert_eq!(
            get_required_perm("GET", "/tool/gen/synchDb/{tableName}"),
            None
        );
    }

    #[test]
    fn test_config_configkey_perm() {
        // P0-R81-003: configKey 路由必须有权限校验
        assert_eq!(
            get_required_perm("GET", "/system/config/configKey/{configKey}"),
            Some("system:config:query")
        );
    }

    // ===== 未匹配路由返回 None =====
    #[test]
    fn test_unknown_route_no_perm() {
        assert_eq!(get_required_perm("GET", "/unknown/path"), None);
        assert_eq!(get_required_perm("POST", "/unknown"), None);
    }

    #[test]
    fn test_wrong_method_no_perm() {
        // DELETE /system/user/list 不在表中（list 仅 GET）
        assert_eq!(get_required_perm("DELETE", "/system/user/list"), None);
    }

    // ===== 通用上传权限 =====
    #[test]
    fn test_common_upload_perm() {
        assert_eq!(
            get_required_perm("POST", "/common/upload"),
            Some("system:file:add")
        );
    }

    // ===== 仪表盘统计权限 =====
    #[test]
    fn test_dashboard_stats_perm() {
        assert_eq!(
            get_required_perm("GET", "/dashboard/stats"),
            Some("monitor:server:list")
        );
    }

    // ===== 审计大屏权限 =====
    #[test]
    fn test_audit_stats_perm() {
        assert_eq!(
            get_required_perm("GET", "/monitor/operlog/stats"),
            Some("monitor:audit:list")
        );
        assert_eq!(
            get_required_perm("GET", "/monitor/operlog/alarm-status"),
            Some("monitor:audit:list")
        );
        assert_eq!(
            get_required_perm("POST", "/monitor/operlog/alarm-status"),
            None
        );
    }

    // ===== deny_by_default 仅登录白名单 =====
    #[test]
    fn test_login_only_paths_recognized() {
        // 登录态相关（protected_auth_routes）
        assert!(is_login_only_path("POST", "/logout"));
        assert!(is_login_only_path("GET", "/getInfo"));
        assert!(is_login_only_path("GET", "/getRouters"));
        assert!(is_login_only_path("POST", "/unlockscreen"));
        // 通用下载
        assert!(is_login_only_path("GET", "/common/download"));
        assert!(is_login_only_path("GET", "/common/download/resource"));
        // 个人中心
        assert!(is_login_only_path("GET", "/system/user/profile"));
        assert!(is_login_only_path("PUT", "/system/user/profile"));
        assert!(is_login_only_path("PUT", "/system/user/profile/updatePwd"));
        assert!(is_login_only_path("POST", "/system/user/profile/avatar"));
        assert!(is_login_only_path("GET", "/system/user/deptTree"));
        // 下拉树 / 选项
        assert!(is_login_only_path("GET", "/system/role/deptTree/{roleId}"));
        assert!(is_login_only_path("GET", "/system/menu/treeselect"));
        assert!(is_login_only_path(
            "GET",
            "/system/menu/roleMenuTreeselect/{roleId}"
        ));
        assert!(is_login_only_path("GET", "/system/dept/treeselect"));
        assert!(is_login_only_path("GET", "/system/post/optionselect"));
        // 公告标记已读
        assert!(is_login_only_path("POST", "/system/notice/markRead"));
        assert!(is_login_only_path("POST", "/system/notice/markReadAll"));
        assert!(is_login_only_path(
            "POST",
            "/system/notice/markAllUnreadRead"
        ));
    }

    #[test]
    fn test_login_only_paths_reject_wrong_method() {
        // 方法不匹配不应误判为仅登录（如 GET /logout 不存在）
        assert!(!is_login_only_path("GET", "/logout"));
        assert!(!is_login_only_path("POST", "/getInfo"));
    }

    #[test]
    fn test_login_only_paths_reject_unmapped() {
        // 未登记权限映射且不在白名单的路由（如新增漏登记路由）应被判定为非仅登录
        assert!(!is_login_only_path("GET", "/unknown/path"));
        assert!(!is_login_only_path("POST", "/system/user"));
        assert!(!is_login_only_path("GET", "/system/user/list"));
    }

    #[test]
    fn test_totp_routes_login_only() {
        // TOTP 为个人自助操作，仅需登录（deny_by_default=true 时也不应被 403 误伤）
        assert!(is_login_only_path("POST", "/system/user/totp/setup"));
        assert!(is_login_only_path("POST", "/system/user/totp/verify"));
        assert!(is_login_only_path("GET", "/system/user/totp/status"));
        assert!(is_login_only_path("POST", "/system/user/totp/disable"));
    }

    #[test]
    fn test_stats_by_type_perm_mapped() {
        // dashboard 首页操作日志类型统计需监控查看权限（P0-1 补充映射，此前 fail-open 裸奔）
        assert_eq!(
            get_required_perm("GET", "/monitor/operlog/stats-by-type"),
            Some("monitor:server:list")
        );
    }

    /// 受保护路由全量覆盖断言（P0-1 防回归）
    ///
    /// 清单与 src/router/*.rs 中注册的受保护路由逐一对应（方法 + MatchedPath 模板）。
    /// 断言：每个受保护路由要么有权限映射（get_required_perm 返回 Some），
    /// 要么显式登记为"仅登录"（is_login_only_path 为 true）。
    /// 该测试保证 permission_deny_by_default=true（fail-closed）不会误伤任何已登记路由，
    /// 同时防止新增路由漏登记权限导致 fail-open 越权。
    #[test]
    fn test_all_protected_routes_covered() {
        // (method, path) —— 与 router/mod.rs protected 子树各 router 注册保持一致
        const PROTECTED_ROUTES: &[(&str, &str)] = &[
            // auth_router::protected_auth_routes（仅登录）
            ("POST", "/logout"),
            ("GET", "/getInfo"),
            ("GET", "/getRouters"),
            ("POST", "/unlockscreen"),
            // common_router
            ("POST", "/common/upload"),
            ("GET", "/common/download"),
            ("GET", "/common/download/resource"),
            // dashboard
            ("GET", "/dashboard/stats"),
            ("GET", "/dashboard/user-stats"),
            // sys_user_router
            ("GET", "/system/user/list"),
            ("GET", "/system/user/{id}"),
            ("GET", "/system/user/"),
            ("GET", "/system/user/authRole/{userId}"),
            ("POST", "/system/user"),
            ("PUT", "/system/user"),
            ("PUT", "/system/user/changeStatus"),
            ("PUT", "/system/user/resetPwd"),
            ("PUT", "/system/user/authRole"),
            ("DELETE", "/system/user/{id}"),
            ("POST", "/system/user/export"),
            ("GET", "/system/user/profile"),
            ("PUT", "/system/user/profile"),
            ("PUT", "/system/user/profile/updatePwd"),
            ("POST", "/system/user/profile/avatar"),
            ("GET", "/system/user/deptTree"),
            // totp_router（仅登录）
            ("POST", "/system/user/totp/setup"),
            ("POST", "/system/user/totp/verify"),
            ("GET", "/system/user/totp/status"),
            ("POST", "/system/user/totp/disable"),
            // sys_role_router
            ("GET", "/system/role/list"),
            ("GET", "/system/role/{id}"),
            ("POST", "/system/role"),
            ("PUT", "/system/role"),
            ("PUT", "/system/role/changeStatus"),
            ("PUT", "/system/role/dataScope"),
            ("DELETE", "/system/role/{id}"),
            ("POST", "/system/role/export"),
            ("GET", "/system/role/authUser/allocatedList"),
            ("GET", "/system/role/authUser/unallocatedList"),
            ("PUT", "/system/role/authUser/cancel"),
            ("PUT", "/system/role/authUser/cancelAll"),
            ("PUT", "/system/role/authUser/selectAll"),
            ("GET", "/system/role/deptTree/{roleId}"),
            // sys_menu_router
            ("GET", "/system/menu/list"),
            ("GET", "/system/menu/{id}"),
            ("POST", "/system/menu"),
            ("PUT", "/system/menu"),
            ("PUT", "/system/menu/updateSort"),
            ("DELETE", "/system/menu/{id}"),
            ("GET", "/system/menu/treeselect"),
            ("GET", "/system/menu/roleMenuTreeselect/{roleId}"),
            // sys_notice_router
            ("GET", "/system/notice/list"),
            ("GET", "/system/notice/listTop"),
            ("GET", "/system/notice/readUsers/list"),
            ("GET", "/system/notice/{noticeId}"),
            ("POST", "/system/notice"),
            ("PUT", "/system/notice"),
            ("DELETE", "/system/notice/{noticeId}"),
            ("POST", "/system/notice/markRead"),
            ("POST", "/system/notice/markReadAll"),
            ("POST", "/system/notice/markAllUnreadRead"),
            // sys_dept_router
            ("GET", "/system/dept/list"),
            ("GET", "/system/dept/list/exclude/{deptId}"),
            ("GET", "/system/dept/{deptId}"),
            ("POST", "/system/dept"),
            ("PUT", "/system/dept"),
            ("PUT", "/system/dept/updateSort"),
            ("DELETE", "/system/dept/{deptId}"),
            ("GET", "/system/dept/treeselect"),
            // sys_job_router
            ("GET", "/monitor/job/list"),
            ("GET", "/monitor/job/{jobId}"),
            ("POST", "/monitor/job"),
            ("PUT", "/monitor/job"),
            ("PUT", "/monitor/job/changeStatus"),
            ("PUT", "/monitor/job/run"),
            ("DELETE", "/monitor/job/{jobId}"),
            ("POST", "/monitor/job/export"),
            // sys_job_log_router
            ("GET", "/monitor/jobLog/list"),
            ("DELETE", "/monitor/jobLog/{jobLogIds}"),
            ("DELETE", "/monitor/jobLog/clean"),
            ("POST", "/monitor/jobLog/export"),
            // sys_dict_router
            ("GET", "/system/dict/type/list"),
            ("GET", "/system/dict/type/optionselect"),
            ("GET", "/system/dict/type/{dictId}"),
            ("POST", "/system/dict/type"),
            ("PUT", "/system/dict/type"),
            ("DELETE", "/system/dict/type/{dictId}"),
            ("DELETE", "/system/dict/type/refreshCache"),
            ("POST", "/system/dict/type/export"),
            ("GET", "/system/dict/data/list"),
            ("GET", "/system/dict/data/type/{dictType}"),
            ("GET", "/system/dict/data/{dictCode}"),
            ("POST", "/system/dict/data"),
            ("PUT", "/system/dict/data"),
            ("DELETE", "/system/dict/data/{dictCode}"),
            ("POST", "/system/dict/data/export"),
            // sys_config_router
            ("GET", "/system/config/list"),
            ("GET", "/system/config/{configId}"),
            ("GET", "/system/config/configKey/{configKey}"),
            ("POST", "/system/config"),
            ("PUT", "/system/config"),
            ("DELETE", "/system/config/{configId}"),
            ("DELETE", "/system/config/refreshCache"),
            ("POST", "/system/config/export"),
            // sys_post_router
            ("GET", "/system/post/list"),
            ("GET", "/system/post/{postId}"),
            ("POST", "/system/post"),
            ("PUT", "/system/post"),
            ("DELETE", "/system/post/{postId}"),
            ("POST", "/system/post/export"),
            ("GET", "/system/post/optionselect"),
            // sys_rate_limit_router
            ("GET", "/system/rateLimit/list"),
            ("GET", "/system/rateLimit/{id}"),
            ("POST", "/system/rateLimit"),
            ("PUT", "/system/rateLimit"),
            ("DELETE", "/system/rateLimit/{id}"),
            ("POST", "/system/rateLimit/export"),
            // sys_oper_log_router
            ("GET", "/monitor/operlog/list"),
            ("DELETE", "/monitor/operlog/{operIds}"),
            ("DELETE", "/monitor/operlog/clean"),
            ("POST", "/monitor/operlog/export"),
            ("GET", "/monitor/operlog/stats"),
            ("GET", "/monitor/operlog/compliance-report"),
            ("GET", "/monitor/operlog/alarm-status"),
            ("GET", "/monitor/operlog/stats-by-type"),
            // sys_logininfor_router
            ("GET", "/monitor/logininfor/list"),
            ("GET", "/monitor/logininfor/stats"),
            ("DELETE", "/monitor/logininfor/{infoIds}"),
            ("POST", "/monitor/logininfor/unlock/{userName}"),
            ("DELETE", "/monitor/logininfor/clean"),
            ("POST", "/monitor/logininfor/export"),
            // monitor_online_router
            ("GET", "/monitor/online/list"),
            ("DELETE", "/monitor/online/{tokenHash}"),
            // monitor_cache_router
            ("GET", "/monitor/cache"),
            ("GET", "/monitor/cache/getNames"),
            ("GET", "/monitor/cache/hotKeys"),
            ("GET", "/monitor/cache/prefixStats"),
            ("GET", "/monitor/cache/getKeys/{cacheName}"),
            ("GET", "/monitor/cache/getValue/{cacheName}/{cacheKey}"),
            ("DELETE", "/monitor/cache/clearCacheName/{cacheName}"),
            ("DELETE", "/monitor/cache/clearCacheKey/{cacheKey}"),
            // monitor_server_router
            ("GET", "/monitor/server"),
            // monitor_log_router
            ("GET", "/monitor/log/files"),
            ("GET", "/monitor/log/tail"),
            // sys_backup_router
            ("GET", "/system/backup/list"),
            ("GET", "/system/backup/{backupId}"),
            ("POST", "/system/backup"),
            ("POST", "/system/backup/restore/{backupId}"),
            ("GET", "/system/backup/download/{backupId}"),
            ("DELETE", "/system/backup/{backupId}"),
            // sys_task_router
            ("GET", "/system/task/list"),
            ("GET", "/system/task/{taskId}"),
            ("DELETE", "/system/task/{taskId}"),
            // ip_location_router
            ("GET", "/system/ipLocation/status"),
            ("GET", "/system/ipLocation/config"),
            ("PUT", "/system/ipLocation/config"),
            ("POST", "/system/ipLocation/update"),
            ("POST", "/system/ipLocation/reload"),
            ("POST", "/system/ipLocation/reloadXdb"),
            // tool_gen_router
            ("GET", "/tool/gen/list"),
            ("GET", "/tool/gen/db/list"),
            ("GET", "/tool/gen/{tableId}"),
            ("POST", "/tool/gen/importTable"),
            ("POST", "/tool/gen/createTable"),
            ("PUT", "/tool/gen"),
            ("DELETE", "/tool/gen/{tableId}"),
            ("GET", "/tool/gen/preview/{tableId}"),
            ("GET", "/tool/gen/genCode/{tableName}"),
            ("POST", "/tool/gen/synchDb/{tableName}"),
            ("GET", "/tool/gen/batchGenCode"),
            // file_router
            ("GET", "/system/file/list"),
            ("POST", "/system/file/upload"),
            ("DELETE", "/system/file/delete"),
            // sys_msg_router
            ("GET", "/system/msg/channel/list"),
            ("GET", "/system/msg/channel/{channelId}"),
            ("POST", "/system/msg/channel"),
            ("PUT", "/system/msg/channel"),
            ("DELETE", "/system/msg/channel/{channelId}"),
            ("POST", "/system/msg/channel/test/{channelId}"),
            ("GET", "/system/msg/template/list"),
            ("GET", "/system/msg/template/{templateId}"),
            ("POST", "/system/msg/template"),
            ("PUT", "/system/msg/template"),
            ("DELETE", "/system/msg/template/{templateId}"),
            ("GET", "/system/msg/log/list"),
            ("DELETE", "/system/msg/log/{logIds}"),
            ("DELETE", "/system/msg/log/clean"),
            ("POST", "/system/msg/send"),
            ("POST", "/system/msg/log/retry/{logIds}"),
            ("POST", "/system/msg/log/retryPending/{batch}"),
            ("POST", "/system/msg/log/markPending/{logIds}"),
        ];

        let mut uncovered: Vec<(&str, &str)> = Vec::new();
        for &(method, path) in PROTECTED_ROUTES {
            if get_required_perm(method, path).is_none() && !is_login_only_path(method, path) {
                uncovered.push((method, path));
            }
        }
        assert!(
            uncovered.is_empty(),
            "以下受保护路由未登记权限映射且不在仅登录白名单（deny_by_default=true 下会被 403 误伤，fail-open 下存在越权风险）: {:?}",
            uncovered
        );
    }

    #[test]
    fn test_delete_param_names_match_router() {
        // P0-1 回归：10 个 DELETE 接口的路径参数名必须与 router 注册一致（MatchedPath 精确匹配），
        // 否则 get_required_perm 返回 None，fail-open 下仅需登录即可删除。
        assert_eq!(
            get_required_perm("DELETE", "/system/role/{id}"),
            Some("system:role:remove")
        );
        assert_eq!(
            get_required_perm("DELETE", "/monitor/job/{jobId}"),
            Some("monitor:job:remove")
        );
        assert_eq!(
            get_required_perm("DELETE", "/system/dict/type/{dictId}"),
            Some("system:dict:remove")
        );
        assert_eq!(
            get_required_perm("DELETE", "/system/dict/data/{dictCode}"),
            Some("system:dict:remove")
        );
        assert_eq!(
            get_required_perm("DELETE", "/system/notice/{noticeId}"),
            Some("system:notice:remove")
        );
        assert_eq!(
            get_required_perm("DELETE", "/system/config/{configId}"),
            Some("system:config:remove")
        );
        assert_eq!(
            get_required_perm("DELETE", "/system/post/{postId}"),
            Some("system:post:remove")
        );
        assert_eq!(
            get_required_perm("DELETE", "/tool/gen/{tableId}"),
            Some("tool:gen:remove")
        );
        assert_eq!(
            get_required_perm("DELETE", "/system/backup/{backupId}"),
            Some("system:backup:remove")
        );
        assert_eq!(
            get_required_perm("DELETE", "/system/task/{taskId}"),
            Some("system:task:remove")
        );
    }

    // ===== 消息渠道与模板管理权限映射 =====
    #[test]
    fn test_msg_channel_perms() {
        assert_eq!(
            get_required_perm("GET", "/system/msg/channel/list"),
            Some("system:msg:channel:list")
        );
        assert_eq!(
            get_required_perm("GET", "/system/msg/channel/{channelId}"),
            Some("system:msg:channel:query")
        );
        assert_eq!(
            get_required_perm("POST", "/system/msg/channel"),
            Some("system:msg:channel:add")
        );
        assert_eq!(
            get_required_perm("PUT", "/system/msg/channel"),
            Some("system:msg:channel:edit")
        );
        assert_eq!(
            get_required_perm("DELETE", "/system/msg/channel/{channelId}"),
            Some("system:msg:channel:remove")
        );
        assert_eq!(
            get_required_perm("POST", "/system/msg/channel/test/{channelId}"),
            Some("system:msg:channel:test")
        );
    }

    #[test]
    fn test_msg_template_perms() {
        assert_eq!(
            get_required_perm("GET", "/system/msg/template/list"),
            Some("system:msg:template:list")
        );
        assert_eq!(
            get_required_perm("GET", "/system/msg/template/{templateId}"),
            Some("system:msg:template:query")
        );
        assert_eq!(
            get_required_perm("POST", "/system/msg/template"),
            Some("system:msg:template:add")
        );
        assert_eq!(
            get_required_perm("PUT", "/system/msg/template"),
            Some("system:msg:template:edit")
        );
        assert_eq!(
            get_required_perm("DELETE", "/system/msg/template/{templateId}"),
            Some("system:msg:template:remove")
        );
    }

    #[test]
    fn test_msg_log_perms() {
        assert_eq!(
            get_required_perm("GET", "/system/msg/log/list"),
            Some("system:msg:log:list")
        );
        assert_eq!(
            get_required_perm("DELETE", "/system/msg/log/{logIds}"),
            Some("system:msg:log:remove")
        );
        assert_eq!(
            get_required_perm("DELETE", "/system/msg/log/clean"),
            Some("system:msg:log:clean")
        );
        // 发送 / 重试 / 标记重试 / 批量重试对齐 log:retry 按钮权限
        assert_eq!(
            get_required_perm("POST", "/system/msg/send"),
            Some("system:msg:log:retry")
        );
        assert_eq!(
            get_required_perm("POST", "/system/msg/log/retry/{logIds}"),
            Some("system:msg:log:retry")
        );
        assert_eq!(
            get_required_perm("POST", "/system/msg/log/retryPending/{batch}"),
            Some("system:msg:log:retry")
        );
        assert_eq!(
            get_required_perm("POST", "/system/msg/log/markPending/{logIds}"),
            Some("system:msg:log:retry")
        );
    }

    #[test]
    fn test_msg_wrong_method_no_perm() {
        // 方法混淆不应命中（如 DELETE channel/list、GET channel 新增），防绕过
        assert_eq!(
            get_required_perm("DELETE", "/system/msg/channel/list"),
            None
        );
        assert_eq!(get_required_perm("POST", "/system/msg/channel/list"), None);
        assert_eq!(get_required_perm("GET", "/system/msg/log/clean"), None);
        assert_eq!(get_required_perm("GET", "/system/msg/send"), None);
    }
}
