// backend-axum/src/middleware/permission.rs
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
use crate::middleware::normalize_api_prefix;
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
    //
    // 同源部署时 `/prod-api`、`/dev-api`、`/stage-api` 通过 `Router::nest` 挂载，
    // axum 会把 nest 前缀并入 `MatchedPath`（如 `/prod-api/getInfo`）；而权限映射表
    // 与仅登录白名单均以**去前缀**的路由模板登记 ⇒ 必须先归一化，否则查表必然失败。
    //
    // 历史缺陷（本轮修复）：此前未归一化，叠加 deny_by_default=false 时，带前缀请求会走
    // "未登记权限映射即放行"分支，导致 `/prod-api/*` 下的请求**整体绕过 RBAC**
    // （超管判定与细粒度权限均不生效）；deny_by_default=true 时则全部 403。
    let method = req.method().clone();
    let matched_path = req
        .extensions()
        .get::<MatchedPath>()
        .cloned()
        .map(|p| normalize_api_prefix(p.as_str()).to_string());

    // 3. 查表获取所需权限（无匹配路径或无权限要求则放行）
    let required_perm = match matched_path.as_deref() {
        Some(path) => get_required_perm(method.as_str(), path),
        None => None,
    };

    // Tier-S #3：令牌管理类接口禁止由 PAT 调用（防止作用域令牌自我签发 / 扩权 / 续期）。
    // 该检查置于“无权限要求即放行”之前，因为自助令牌接口本身是“仅登录”路由。
    if claims.pat_scopes.is_some()
        && let Some(p) = matched_path.as_deref()
        && is_pat_management_path(p)
    {
        tracing::warn!(
            user_id = claims.sub,
            method = %method,
            path = p,
            "拒绝：访问令牌不得管理令牌本身"
        );
        return Err(AppError::new(
            403,
            crate::tr!("error.pat.forbidden_pat_usage"),
        ));
    }

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

    // 5. 超管短路：权限列表含 `*:*:*` 时放行
    //    Tier-S #3：仅对非 PAT 生效——PAT 即使属主为超管，也必须受自身 scope 约束，
    //    否则细粒度 scope 形同虚设。
    let is_pat = claims.pat_scopes.is_some();
    let is_superadmin = permissions.iter().any(|p| p == "*:*:*");
    if !is_pat && is_superadmin {
        tracing::debug!(
            user_id,
            method = %method,
            path = ?matched_path,
            "超管访问放行"
        );
        return Ok(next.run(req).await);
    }

    // 6. 权限匹配
    //    - 用户维度：超管（*:*:*）或权限列表显式包含 required_perm；
    //    - 令牌维度（仅 PAT）：required_perm 需被令牌 scope 按段通配覆盖。
    //    两者取交集，即为 PAT 请求的有效权限（scope ∩ 用户当前权限）。
    let user_has = is_superadmin || permissions.iter().any(|p| p == required_perm);
    let scope_ok = match &claims.pat_scopes {
        Some(scopes) => crate::service::sys_pat_service::scope_allows(scopes, required_perm),
        None => true,
    };

    if user_has && scope_ok {
        Ok(next.run(req).await)
    } else {
        tracing::warn!(
            user_id,
            method = %method,
            path = ?matched_path,
            required_perm,
            via_pat = is_pat,
            "权限拒绝：用户缺少所需权限或超出令牌 scope"
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
        tenant_id: claims.tid,
        target_tenant_id: None, // 权限拒绝未进入 handler，无目标资源租户上下文
        dept_name: String::new(), // spawn 内查询后填入
        oper_url,
        oper_ip,
        oper_location,
        oper_param: String::new(), // permission_middleware 不读请求体
        oper_before: String::new(),
        oper_diff: String::new(),
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

/// 路由权限映射表（method, path, perm 三元组）。
///
/// 每个条目表示：访问 `method + path` 路由时需要 `perm` 权限。
/// 与前端 sys_menu 表的 perms 字段逐一对齐；不在表中的路由视为仅需登录。
///
/// 采用 const 表存储，作为权限映射的单一数据源：
/// - `get_required_perm` 在表内线性查找返回所需权限；
/// - `all_required_perm_keys` 汇总全部权限标识，供集成测试与 sys_menu.perms 比对，
///   实现「后端所需权限 ⊆ 菜单可授予权限」契约，杜绝权限键漂移。
#[rustfmt::skip]
const PERM_ROUTE_TABLE: &[(&str, &str, &str)] = &[
    // ===== AI 助手（NL2SQL v4.1：能力位 ai.copilot + ai:chat）=====
    ("POST", "/ai/chat", "ai:chat"),
    ("GET", "/ai/tables", "ai:chat"),
    // ===== 用户管理 =====
    ("GET", "/system/user/list", "system:user:list"),
    ("GET", "/system/user/{id}", "system:user:query"),
    ("GET", "/system/user/", "system:user:query"),
    ("GET", "/system/user/authRole/{userId}", "system:user:query"),
    ("POST", "/system/user", "system:user:add"),
    ("PUT", "/system/user", "system:user:edit"),
    ("PUT", "/system/user/changeStatus", "system:user:edit"),
    ("PUT", "/system/user/resetPwd", "system:user:resetPwd"),
    ("PUT", "/system/user/authRole", "system:user:edit"),
    ("DELETE", "/system/user/{id}", "system:user:remove"),
    ("POST", "/system/user/export", "system:user:export"),
    ("POST", "/system/user/importTemplate", "system:user:import"),
    ("POST", "/system/user/importData", "system:user:import"),
    // GDPR 被遗忘权 / 用户匿名化：**复用既有** `system:user:remove`（不新造 perm、不新增菜单
    // 迁移，避免"菜单可见但请求 403"的假入口）；`privacy.user_erasure` 能力位与服务层
    // 平台归属守卫在 **服务层** 收口（能力位关/非平台 ⇒ 404）。路由参数名须与
    // router/sys_user_router.rs 注册**逐字一致**（`{userId}`）。
    ("GET", "/system/user/{userId}/anonymize/precheck", "system:user:remove"),
    ("POST", "/system/user/{userId}/anonymize", "system:user:remove"),
    // profile / 个人改密 / 角色下拉：仅需登录，不在此表

    // ===== SCIM 组管理（v5-D12 Group） =====
    ("GET", "/system/scimGroup/list", "system:scimgroup:list"),
    ("GET", "/system/scimGroup/{id}", "system:scimgroup:query"),
    ("PUT", "/system/scimGroup/{id}", "system:scimgroup:edit"),
    ("DELETE", "/system/scimGroup/{id}", "system:scimgroup:remove"),

    // ===== 角色管理 =====
    ("GET", "/system/role/list", "system:role:list"),
    ("GET", "/system/role/{id}", "system:role:query"),
    ("POST", "/system/role", "system:role:add"),
    ("PUT", "/system/role", "system:role:edit"),
    ("PUT", "/system/role/changeStatus", "system:role:edit"),
    ("PUT", "/system/role/dataScope", "system:role:edit"),
    ("DELETE", "/system/role/{id}", "system:role:remove"),
    ("POST", "/system/role/export", "system:role:export"),
    // authUser 系列接口：授权用户管理，使用 system:role:edit
    ("GET", "/system/role/authUser/allocatedList", "system:role:list"),
    ("GET", "/system/role/authUser/unallocatedList", "system:role:list"),
    ("PUT", "/system/role/authUser/cancel", "system:role:edit"),
    ("PUT", "/system/role/authUser/cancelAll", "system:role:edit"),
    ("PUT", "/system/role/authUser/selectAll", "system:role:edit"),
    // deptTree：仅需登录，不在此表

    // ===== 菜单管理 =====
    ("GET", "/system/menu/list", "system:menu:list"),
    ("GET", "/system/menu/{id}", "system:menu:query"),
    ("POST", "/system/menu", "system:menu:add"),
    ("PUT", "/system/menu", "system:menu:edit"),
    ("PUT", "/system/menu/updateSort", "system:menu:edit"),
    ("DELETE", "/system/menu/{id}", "system:menu:remove"),
    // treeselect / roleMenuTreeselect：仅需登录，不在此表

    // ===== 部门管理 =====
    ("GET", "/system/dept/list", "system:dept:list"),
    ("GET", "/system/dept/list/exclude/{deptId}", "system:dept:list"),
    ("GET", "/system/dept/{deptId}", "system:dept:query"),
    ("POST", "/system/dept", "system:dept:add"),
    ("PUT", "/system/dept", "system:dept:edit"),
    ("PUT", "/system/dept/updateSort", "system:dept:edit"),
    ("DELETE", "/system/dept/{deptId}", "system:dept:remove"),
    // treeselect：仅需登录，不在此表

    // ===== 租户管理（多租户 Phase 3：主键 tenantId，事实源 sys_tenant） =====
    ("GET", "/system/tenant/list", "system:tenant:list"),
    ("GET", "/system/tenant/package/options", "system:tenant:list"),
    // 套餐能力位（三层开关中间层）：读写走租户管理权限，服务层再校验仅平台操作者
    (
        "GET",
        "/system/tenant/package/{packageId}/features",
        "system:tenant:list",
    ),
    (
        "PUT",
        "/system/tenant/package/features",
        "system:tenant:edit",
    ),
    ("GET", "/system/tenant/{tenantId}", "system:tenant:query"),
    ("POST", "/system/tenant", "system:tenant:add"),
    ("PUT", "/system/tenant", "system:tenant:edit"),
    ("PUT", "/system/tenant/changeStatus", "system:tenant:edit"),
    ("PUT", "/system/tenant/restore/{tenantId}", "system:tenant:edit"),
    ("DELETE", "/system/tenant/{tenantId}", "system:tenant:remove"),

    // ===== 租户域名管理（多租户 Phase 3 域名链路：仅平台操作者可写，RBAC 之外服务层再校验） =====
    ("GET", "/system/tenant/domain/list", "system:tenant:domain:list"),
    ("POST", "/system/tenant/domain", "system:tenant:domain:add"),
    ("POST", "/system/tenant/domain/verify/{domainId}", "system:tenant:domain:verify"),
    ("PUT", "/system/tenant/domain/primary", "system:tenant:domain:edit"),
    ("PUT", "/system/tenant/domain/changeStatus", "system:tenant:domain:edit"),
    ("DELETE", "/system/tenant/domain/{domainId}", "system:tenant:domain:remove"),

    // ===== 租户自建导航 L3（批次 3 / MT-1：能力位 nav.l3 门控，服务层按档位+租户收窄） =====
    // perms 属平台专属前缀 `system:tenantMenu:`，仅由能力位 `nav.l3` 逐条解锁
    // （注册表 `governance::Item::unlocked`：view_only ⇒ list；full ⇒ add/edit/remove）。
    ("GET", "/system/tenant/menu/list", "system:tenantMenu:list"),
    ("GET", "/system/tenant/menu/options", "system:tenantMenu:list"),
    ("POST", "/system/tenant/menu", "system:tenantMenu:add"),
    ("PUT", "/system/tenant/menu", "system:tenantMenu:edit"),
    ("DELETE", "/system/tenant/menu/{l3Id}", "system:tenantMenu:remove"),

    // ===== 定时任务管理 =====
    ("GET", "/monitor/job/list", "monitor:job:list"),
    ("GET", "/monitor/job/{jobId}", "monitor:job:query"),
    ("POST", "/monitor/job", "monitor:job:add"),
    ("PUT", "/monitor/job", "monitor:job:edit"),
    ("PUT", "/monitor/job/changeStatus", "monitor:job:changeStatus"),
    ("PUT", "/monitor/job/run", "monitor:job:changeStatus"),
    ("DELETE", "/monitor/job/{jobId}", "monitor:job:remove"),
    ("POST", "/monitor/job/export", "monitor:job:export"),

    // ===== 定时任务日志 =====
    ("GET", "/monitor/jobLog/list", "monitor:job:list"),
    ("DELETE", "/monitor/jobLog/{jobLogIds}", "monitor:job:remove"),
    ("DELETE", "/monitor/jobLog/clean", "monitor:job:remove"),
    ("POST", "/monitor/jobLog/export", "monitor:job:export"),

    // ===== 字典管理 =====
    ("GET", "/system/dict/type/list", "system:dict:list"),
    ("GET", "/system/dict/type/optionselect", "system:dict:query"),
    ("GET", "/system/dict/type/{dictId}", "system:dict:query"),
    ("POST", "/system/dict/type", "system:dict:add"),
    ("PUT", "/system/dict/type", "system:dict:edit"),
    ("DELETE", "/system/dict/type/refreshCache", "system:dict:remove"),
    ("POST", "/system/dict/type/export", "system:dict:export"),
    ("DELETE", "/system/dict/type/{dictId}", "system:dict:remove"),
    ("GET", "/system/dict/data/list", "system:dict:list"),
    ("GET", "/system/dict/data/type/{dictType}", "system:dict:query"),
    ("GET", "/system/dict/data/{dictCode}", "system:dict:query"),
    ("POST", "/system/dict/data", "system:dict:add"),
    ("PUT", "/system/dict/data", "system:dict:edit"),
    ("DELETE", "/system/dict/data/{dictCode}", "system:dict:remove"),
    ("POST", "/system/dict/data/export", "system:dict:export"),

    // ===== 通知公告 =====
    ("GET", "/system/notice/list", "system:notice:list"),
    ("GET", "/system/notice/listTop", "system:notice:list"),
    ("GET", "/system/notice/readUsers/list", "system:notice:list"),
    ("GET", "/system/notice/{noticeId}", "system:notice:query"),
    ("POST", "/system/notice", "system:notice:add"),
    // markRead / markReadAll / markAllUnreadRead：标记本人已读为自助操作，仅需登录认证
    // 权限粒度由前端 v-hasPermi 控制按钮可见性，后端不做 RBAC 校验
    ("PUT", "/system/notice", "system:notice:edit"),
    ("DELETE", "/system/notice/{noticeId}", "system:notice:remove"),

    // ===== 参数配置 =====
    ("GET", "/system/config/list", "system:config:list"),
    ("GET", "/system/config/{configId}", "system:config:query"),
    // /system/config/configKey/{configKey} 需 system:config:query 权限，防止任意已登录用户读取敏感配置（P0-R81-003）
    ("GET", "/system/config/configKey/{configKey}", "system:config:query"),
    ("POST", "/system/config", "system:config:add"),
    ("PUT", "/system/config", "system:config:edit"),
    ("DELETE", "/system/config/refreshCache", "system:config:remove"),
    ("DELETE", "/system/config/{configId}", "system:config:remove"),
    ("POST", "/system/config/export", "system:config:export"),

    // ===== 岗位管理 =====
    ("GET", "/system/post/list", "system:post:list"),
    ("GET", "/system/post/{postId}", "system:post:query"),
    ("POST", "/system/post", "system:post:add"),
    ("PUT", "/system/post", "system:post:edit"),
    ("DELETE", "/system/post/{postId}", "system:post:remove"),
    ("POST", "/system/post/export", "system:post:export"),
    // optionselect：仅需登录，不在此表

    // ===== 操作日志 =====
    ("GET", "/monitor/operlog/list", "monitor:operlog:list"),
    ("DELETE", "/monitor/operlog/{operIds}", "monitor:operlog:remove"),
    ("DELETE", "/monitor/operlog/clean", "monitor:operlog:remove"),
    ("POST", "/monitor/operlog/export", "monitor:operlog:export"),

    // ===== 前端异常监控（Tier-S #1）=====
    // report 端点仅需登录（见 is_login_only_path），不在此表
    ("GET", "/monitor/frontendError/list", "monitor:frontendError:list"),
    ("GET", "/monitor/frontendError/stats", "monitor:frontendError:list"),
    ("GET", "/monitor/frontendError/{id}", "monitor:frontendError:list"),
    ("DELETE", "/monitor/frontendError/{id}", "monitor:frontendError:remove"),
    ("DELETE", "/monitor/frontendError/clean", "monitor:frontendError:remove"),

    // ===== 登录日志 =====
    ("GET", "/monitor/logininfor/list", "monitor:logininfor:list"),
    ("GET", "/monitor/logininfor/stats", "monitor:logininfor:list"),
    ("DELETE", "/monitor/logininfor/{infoIds}", "monitor:logininfor:remove"),
    // 路由定义见 sys_logininfor_router.rs：实际方法为 POST（解锁操作有副作用，GET 不规范）
    ("POST", "/monitor/logininfor/unlock/{userName}", "monitor:logininfor:unlock"),
    ("DELETE", "/monitor/logininfor/clean", "monitor:logininfor:remove"),
    ("POST", "/monitor/logininfor/export", "monitor:logininfor:export"),

    // ===== 在线用户 =====
    // 路由定义见 monitor_online_router.rs：参数名为 {tokenHash}（P1-19 改造后从 tokenId 改为 tokenHash）
    ("GET", "/monitor/online/list", "monitor:online:list"),
    ("DELETE", "/monitor/online/{tokenHash}", "monitor:online:forceLogout"),

    // ===== 缓存监控 =====
    ("GET", "/monitor/cache", "monitor:cache:list"),
    ("GET", "/monitor/cache/getNames", "monitor:cache:list"),
    // hotKeys / prefixStats 与 getNames 同权（内存统计属只读监控，绑定列表查看权限）
    ("GET", "/monitor/cache/hotKeys", "monitor:cache:list"),
    ("GET", "/monitor/cache/prefixStats", "monitor:cache:list"),
    ("GET", "/monitor/cache/getKeys/{cacheName}", "monitor:cache:list"),
    ("GET", "/monitor/cache/getValue/{cacheName}/{cacheKey}", "monitor:cache:query"),
    // 缓存清除权限与 sys_menu 按钮种子 3022/3023 对齐（monitor:cache:clearName / clearKey）
    ("DELETE", "/monitor/cache/clearCacheName/{cacheName}", "monitor:cache:clearName"),
    ("DELETE", "/monitor/cache/clearCacheKey/{cacheKey}", "monitor:cache:clearKey"),
    // clearCacheAll 端点已从路由中移除（FLUSHDB 会误清业务键），权限映射随之删除

    // ===== 服务器监控 =====
    // 服务监控菜单(m112)已并入健康检查(m133)，该 API 由健康检查页面调用，权限对齐 monitor:health:list
    ("GET", "/monitor/server", "monitor:health:list"),

    // ===== 可观测性监控（慢请求 / 错误聚合 / Redis 指标）=====
    // 慢请求面板（列表 + 聚合 + 清空）共用一个查看权限，运算符粒度与面板按钮一致。
    // 注意：MatchedPath 模板中连字符 "-" 原样保留（axum 不做 shell 转义）。
    ("GET", "/monitor/slow-sql/list", "monitor:slowSql:list"),
    ("GET", "/monitor/slow-sql/stats", "monitor:slowSql:list"),
    ("DELETE", "/monitor/slow-sql/clear", "monitor:slowSql:list"),
    // 错误聚合面板（列表 + 统计 + 清空）与慢请求同属"运行监控"单一面板，
    // 共用查看权限 monitor:slowSql:list（m20260819_000006 观察面板 perms）
    ("GET", "/monitor/error-log/list", "monitor:slowSql:list"),
    ("GET", "/monitor/error-log/stats", "monitor:slowSql:list"),
    ("DELETE", "/monitor/error-log/clear", "monitor:slowSql:list"),
    // Redis 运行指标：与缓存监控同权（monitor:cache:list），复用缓存菜单入口
    ("GET", "/monitor/redis/stats", "monitor:cache:list"),

    // ===== 实时日志监控 =====
    // 菜单 menu_id=135 (实时日志) 在系统监控目录下，perms=monitor:log:list
    ("GET", "/monitor/log/files", "monitor:log:list"),
    ("GET", "/monitor/log/tail", "monitor:log:list"),

    // ===== 代码生成 =====
    ("GET", "/tool/gen/list", "tool:gen:list"),
    ("GET", "/tool/gen/db/list", "tool:gen:list"),
    ("GET", "/tool/gen/{tableId}", "tool:gen:query"),
    ("POST", "/tool/gen/importTable", "tool:gen:import"),
    ("POST", "/tool/gen/createTable", "tool:gen:edit"),
    ("PUT", "/tool/gen", "tool:gen:edit"),
    ("DELETE", "/tool/gen/{tableId}", "tool:gen:remove"),
    ("GET", "/tool/gen/preview/{tableId}", "tool:gen:preview"),
    ("GET", "/tool/gen/genCode/{tableName}", "tool:gen:code"),
    // P0-4 修复：synchDb 路由实际注册为 POST（见 tool_gen_router.rs:37），
    // 原映射为 GET 导致权限校验被绕过（get_required_perm 返回 None）
    ("POST", "/tool/gen/synchDb/{tableName}", "tool:gen:edit"),
    // P1-6 修复：batchGenCode 批量生成代码未映射权限，任意登录用户可调用
    ("GET", "/tool/gen/batchGenCode", "tool:gen:code"),

    // ===== 在线 HTTP 调试器 =====
    // 权限对齐 sys_menu 迁移种子（tool/http-debugger/index 页面，perms=tool:httpDebug:list，
    // 见 m20260819_000002_http_debugger_menu）。执行与查看同权，避免开发/运维自行加按钮。
    ("POST", "/tool/http-debug/execute", "tool:httpDebug:list"),

    // ===== 文件管理 =====
    ("GET", "/system/file/list", "system:file:list"),
    // 上传权限对齐 sys_menu 按钮种子 3012（system:file:upload，见 m20260802_000004），
    // 此前用 system:file:add 但菜单只有 upload，导致该权限永远无法被角色授予
    ("POST", "/system/file/upload", "system:file:upload"),
    ("DELETE", "/system/file/delete", "system:file:remove"),

    // ===== 数据备份恢复 =====
    ("GET", "/system/backup/list", "system:backup:list"),
    ("GET", "/system/backup/{backupId}", "system:backup:query"),
    ("POST", "/system/backup", "system:backup:add"),
    ("POST", "/system/backup/restore/{backupId}", "system:backup:edit"),
    // 批次 2（MT-7 权限粒度化）：下载**独立**成 perms。
    // 原与"详情查询"共用 `system:backup:query` ⇒ 授予 query 等于授予整库下载；
    // 拆分后能力位 `backup.visibility` 才能安全地把只读子集（`view_only` 档）下放给租户、
    // 并把下载面单独留在 `full` 档（服务层再按
    // `backup_type='tenant_export' AND tenant_id=自己` 行级收窄）。
    ("GET", "/system/backup/download/{backupId}", "system:backup:download"),
    // 租户数据包导出（F-2）：平台为**指定租户**导出，独立 perms（不复用只读 query）
    (
        "POST",
        "/system/backup/tenant-export/{tenantId}",
        "system:backup:export",
    ),
    // 租户**自助**导出（批次 2）：无租户参数，服务层强制用操作者所属租户
    // ⇒ 不存在"传他租户 id"的越权面；由能力位 `backup.tenant_self_export` 门控
    (
        "POST",
        "/system/backup/self-export",
        "system:backup:export",
    ),
    ("DELETE", "/system/backup/{backupId}", "system:backup:remove"),

    // ===== 任务进度中心 =====
    ("GET", "/system/task/list", "system:task:list"),
    ("GET", "/system/task/{taskId}", "system:task:query"),
    ("DELETE", "/system/task/{taskId}", "system:task:remove"),

    // ===== API 限流配置 =====
    // P0-3 修复：原完全缺失权限映射，任意登录用户可增删改限流规则，
    // 可禁用登录接口限流导致暴力破解。权限标识对齐 sys_menu 表 rateLimit 菜单 perms 字段。
    ("GET", "/system/rateLimit/list", "system:rateLimit:list"),
    ("GET", "/system/rateLimit/{id}", "system:rateLimit:query"),
    ("POST", "/system/rateLimit", "system:rateLimit:add"),
    ("PUT", "/system/rateLimit", "system:rateLimit:edit"),
    ("DELETE", "/system/rateLimit/{id}", "system:rateLimit:remove"),
    ("POST", "/system/rateLimit/export", "system:rateLimit:export"),

    // ===== 消息渠道与模板管理 =====
    // 权限标识对齐 sys_menu 迁移种子（140 目录 / 141 渠道 / 142 模板 / 143 记录 及按钮 3101-3123，见 m20260818_000002_msg_module）
    ("GET", "/system/msg/channel/list", "system:msg:channel:list"),
    // 渠道详情与列表同权（msg 菜单仅注册 add/edit/remove/test，无独立 query 按钮）
    ("GET", "/system/msg/channel/{channelId}", "system:msg:channel:list"),
    ("POST", "/system/msg/channel", "system:msg:channel:add"),
    ("PUT", "/system/msg/channel", "system:msg:channel:edit"),
    ("DELETE", "/system/msg/channel/{channelId}", "system:msg:channel:remove"),
    ("POST", "/system/msg/channel/test/{channelId}", "system:msg:channel:test"),
    ("GET", "/system/msg/template/list", "system:msg:template:list"),
    // 模板详情与列表同权（msg 菜单仅注册 add/edit/remove，无独立 query 按钮）
    ("GET", "/system/msg/template/{templateId}", "system:msg:template:list"),
    ("POST", "/system/msg/template", "system:msg:template:add"),
    ("PUT", "/system/msg/template", "system:msg:template:edit"),
    ("DELETE", "/system/msg/template/{templateId}", "system:msg:template:remove"),
    ("GET", "/system/msg/log/list", "system:msg:log:list"),
    ("DELETE", "/system/msg/log/{logIds}", "system:msg:log:remove"),
    ("DELETE", "/system/msg/log/clean", "system:msg:log:clean"),
    // 直接发送 / 重试 / 标记重试 / 批量重试均为"消息发出"类操作，统一对齐 log:retry 按钮权限（3123）
    ("POST", "/system/msg/send", "system:msg:log:retry"),
    ("POST", "/system/msg/log/retry/{logIds}", "system:msg:log:retry"),
    ("POST", "/system/msg/log/retryPending/{batch}", "system:msg:log:retry"),
    ("POST", "/system/msg/log/markPending/{logIds}", "system:msg:log:retry"),

    // ===== 第三方登录 / OAuth2 / OIDC =====
    // 权限对齐 sys_menu 迁移种子（145 目录 / 146 页面 perms=system:oauth:provider:list，
    // 按钮 3261-3264 分别为 add/edit/remove/toggle，见 m20260819_000001_oauth_module）
    ("GET", "/system/oauth/provider/list", "system:oauth:provider:list"),
    // 详情查询与列表查看同权（无独立 query 按钮，页面以 list 为准）
    ("GET", "/system/oauth/provider/{providerId}", "system:oauth:provider:list"),
    ("POST", "/system/oauth/provider", "system:oauth:provider:add"),
    ("PUT", "/system/oauth/provider", "system:oauth:provider:edit"),
    // 参数名须与 router/sys_oauth_router.rs 注册**逐字一致**：该行曾误写 `{providerIds}`（复数），
    // 与路由 `{providerId}` 不匹配 ⇒ 查表失败静默 fail-open（deny_by_default=false 时整体绕过 RBAC）
    ("DELETE", "/system/oauth/provider/{providerId}", "system:oauth:provider:remove"),
    ("PUT", "/system/oauth/provider/{providerId}/status", "system:oauth:provider:toggle"),

    // ===== 单点登录 / OIDC Provider 客户端管理 =====
    // 权限对齐 sys_menu 迁移种子（145 目录 / 147 页面 perms=system:oauth:client:list，
    // 按钮 3265-3268 分别为 add/edit/remove/toggle，见 m20260922_000001_sso_module）。
    // 路由参数名与 sso_router 完全一致：详情/删除均为 /system/oauth/client/{id}。
    ("GET", "/system/oauth/client/list", "system:oauth:client:list"),
    ("GET", "/system/oauth/client/{id}", "system:oauth:client:list"),
    ("POST", "/system/oauth/client", "system:oauth:client:add"),
    ("PUT", "/system/oauth/client", "system:oauth:client:edit"),
    ("DELETE", "/system/oauth/client/{id}", "system:oauth:client:remove"),
    ("PUT", "/system/oauth/client/{id}/status", "system:oauth:client:toggle"),
    // SSO D9：client_secret 轮换与"结束读取期"均属**凭据编辑**语义，复用 `edit` 权限，
    // 不新造 perm ⇒ 不会产生"菜单无此按钮但接口可用"或"菜单可见但 403"的假入口。
    (
        "POST",
        "/system/oauth/client/{id}/rotate-secret",
        "system:oauth:client:edit",
    ),
    (
        "DELETE",
        "/system/oauth/client/{id}/rotate-secret",
        "system:oauth:client:edit",
    ),

    // ===== 报表中心 + 定时订阅推送 =====
    // 权限标识与 sys_menu 迁移种子（m20260819_000003_report_module）对齐：
    // 报表定义 system:report:list/query/add/edit/remove/status/preview
    // 报表订阅 system:report:sub:list/query/add/edit/remove/status/run
    ("GET", "/system/report/list", "system:report:list"),
    // 详情与列表查看同权（无独立 query 按钮，页面以 list 为准）
    ("GET", "/system/report/{reportId}", "system:report:list"),
    ("POST", "/system/report", "system:report:add"),
    ("PUT", "/system/report", "system:report:edit"),
    ("DELETE", "/system/report/{reportId}", "system:report:remove"),
    ("PUT", "/system/report/{reportId}/status", "system:report:status"),
    ("POST", "/system/report/{reportId}/preview", "system:report:preview"),
    ("GET", "/system/report/sub/list", "system:report:sub:list"),
    // 订阅详情与列表同权
    ("GET", "/system/report/sub/{subId}", "system:report:sub:list"),
    ("POST", "/system/report/sub", "system:report:sub:add"),
    ("PUT", "/system/report/sub", "system:report:sub:edit"),
    ("DELETE", "/system/report/sub/{subId}", "system:report:sub:remove"),
    ("PUT", "/system/report/sub/{subId}/status", "system:report:sub:status"),
    ("POST", "/system/report/sub/{subId}/run", "system:report:sub:run"),

    // ===== WebHook 事件订阅 =====
    // 权限标识与 sys_menu 迁移种子（m20260820_000002_web_hook_module）对齐：
    // 回调配置 system:webHook:list/query/add/edit/remove/status/test
    // 推送记录 system:webHook:log:list/query/remove/clean/retry
    ("GET", "/monitor/webHook/list", "system:webHook:list"),
    // 导出与回调查询同权（无独立导出按钮，复用 3531 query）
    ("POST", "/monitor/webHook/export", "system:webHook:query"),
    ("PUT", "/monitor/webHook/{id}/status", "system:webHook:status"),
    ("POST", "/monitor/webHook/{id}/test", "system:webHook:test"),
    // 详情与列表查看同权（无独立 query 按钮，页面以 list 为准）
    ("GET", "/monitor/webHook/{id}", "system:webHook:list"),
    ("DELETE", "/monitor/webHook/{id}", "system:webHook:remove"),
    ("POST", "/monitor/webHook", "system:webHook:add"),
    ("PUT", "/monitor/webHook", "system:webHook:edit"),
    ("GET", "/monitor/webHook/log/list", "system:webHook:log:list"),
    // 推送记录导出与记录查询同权
    ("POST", "/monitor/webHook/log/export", "system:webHook:log:query"),
    ("DELETE", "/monitor/webHook/log/clean", "system:webHook:log:clean"),
    ("POST", "/monitor/webHook/log/{ids}/retry", "system:webHook:log:retry"),
    // 记录详情与列表同权
    ("GET", "/monitor/webHook/log/{id}", "system:webHook:log:list"),
    ("DELETE", "/monitor/webHook/log/{id}", "system:webHook:log:remove"),

    // ===== 审计日志大屏 =====
    // 权限标识与 sys_menu 菜单 120 (审计大屏) 的 perms=monitor:audit:list 对齐
    ("GET", "/monitor/operlog/stats", "monitor:audit:list"),
    // 合规报告与审计大屏共享 monitor:audit:list 权限
    ("GET", "/monitor/operlog/compliance-report", "monitor:audit:list"),
    // 异常操作告警状态检测，与审计大屏共享监控查看权限
    ("GET", "/monitor/operlog/alarm-status", "monitor:audit:list"),
    // 操作日志类型统计（dashboard 首页图表专用聚合接口，与 /dashboard/stats 一致使用看板查看权限）
    ("GET", "/monitor/operlog/stats-by-type", "monitor:dashboard:list"),

    // ===== IP 归属地库管理 =====
    // 菜单 menu_id=121 (IP 库管理) 在系统监控目录下，perms=monitor:iplocation:list
    ("GET", "/system/ipLocation/status", "monitor:iplocation:list"),
    ("GET", "/system/ipLocation/config", "monitor:iplocation:list"),
    ("PUT", "/system/ipLocation/config", "monitor:iplocation:edit"),
    ("POST", "/system/ipLocation/update", "monitor:iplocation:edit"),
    ("POST", "/system/ipLocation/reload", "monitor:iplocation:edit"),
    ("POST", "/system/ipLocation/reloadXdb", "monitor:iplocation:edit"),

    // ===== 通用文件上传/下载 =====
    // /common/upload 权限对齐文件管理按钮 system:file:upload（种子 3012），避免任意登录用户可上传
    ("POST", "/common/upload", "system:file:upload"),
    // 通用下载仅需登录（无敏感数据，但需登录态校验），不设细粒度权限
    // /common/download 和 /common/download/resource 不在此表

    // ===== 仪表盘统计 =====
    // 数据看板为所有登录用户默认首页，权限对齐看板菜单 perms=monitor:dashboard:list（m132）
    // 此前误用已删除的 monitor:server:list，导致非超管用户看板统计全部 403
    ("GET", "/dashboard/stats", "monitor:dashboard:list"),
    ("GET", "/dashboard/user-stats", "monitor:dashboard:list"),

    // ===== 个人访问令牌管理（Tier-S #3，管理员统一查看 / 吊销）=====
    ("GET", "/monitor/pat/list", "monitor:pat:list"),
    ("DELETE", "/monitor/pat/{patId}", "monitor:pat:revoke"),

    // ===== 审批工作流（方案 B′；管理视图；个人数据接口走仅登录白名单）=====
    ("GET", "/system/flow/list", "system:flow:list"),
    // 导出（W-11）：复用列表权限键——可见范围与 list 完全一致（租户 + data_scope），
    // 避免"列表看不到但导出能拿到"的数据泄露旁路
    ("POST", "/system/flow/export", "system:flow:list"),
];

/// 根据 HTTP 方法和匹配路径返回所需权限标识。
/// 不在此表中的路由视为仅需登录，不需细粒度权限。
///
/// 权限标识对齐前端菜单表的 perms 字段。
fn get_required_perm(method: &str, path: &str) -> Option<&'static str> {
    PERM_ROUTE_TABLE
        .iter()
        .find_map(|(m, p, perm)| (*m == method && *p == path).then_some(*perm))
}

/// 返回路由权限映射表中出现的全部权限标识（去重、排序），供契约测试与 sys_menu.perms 比对。
///
/// 这是权限契约测试（integration_tests/menu_perm_contract.rs）的单一数据源：
/// 断言「后端所需权限订阅 ⊆ sys_menu.perms」，确保每个受保护能力都能被菜单/角色授予。
/// 仅测试构建使用（integration_tests 挂在 `#[cfg(test)]`），避免正常构建 dead_code 告警。
#[cfg(test)]
pub(crate) fn all_required_perm_keys() -> std::collections::BTreeSet<&'static str> {
    PERM_ROUTE_TABLE.iter().map(|(_, _, perm)| *perm).collect()
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
        // ===== 个人消息偏好 / 免打扰（仅本人操作，仅需登录）=====
            | ("GET", "/system/profile/pref")
            | ("PUT", "/system/profile/pref")
        // ===== 个人访问令牌自助管理（仅本人操作，仅需登录；PAT 本身被禁，见 is_pat_management_path）=====
            | ("GET", "/system/user/profile/tokens")
            | ("GET", "/system/user/profile/tokens/scopes")
            | ("POST", "/system/user/profile/tokens")
            | ("DELETE", "/system/user/profile/tokens/{patId}")
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
        // ===== WebAuthn / Passkey 自助（本人操作，仅登录；能力位 auth.webauthn 门控）=====
        // 参数名须与 router/webauthn_router.rs 注册逐字一致（`{credId}`），
        // 否则 fail-closed 下自助删除会被误拦为 403。
            | ("POST", "/system/user/webauthn/register/start")
            | ("POST", "/system/user/webauthn/register/finish")
            | ("GET", "/system/user/webauthn/credentials")
            | ("DELETE", "/system/user/webauthn/credentials/{credId}")
        // ===== 公告标记已读（自助，仅登录）=====
            | ("POST", "/system/notice/markRead")
            | ("POST", "/system/notice/markReadAll")
            | ("POST", "/system/notice/markAllUnreadRead")
        // ===== 第三方登录绑定（自助管理本人绑定，仅登录）=====
            | ("GET", "/oauth2/my-bindings")
            | ("POST", "/oauth2/bind")
            | ("DELETE", "/oauth2/unbind")
        // ===== 单点登录授权同意（本人登录态下批准/拒绝，仅登录，无需 RBAC）=====
            | ("POST", "/sso/consent")
        // ===== 用户自助管理本人 SSO 授权（v2-I7：查看已授权应用 / 撤销同意，仅本人，无需 RBAC）=====
            | ("GET", "/system/user/profile/sso-grants")
            // 参数名须与 router/sso_router.rs 注册逐字一致（`{client_id}`，非 `{clientId}`），
            // 否则 fail-closed 下自助撤销授权会被误拦为 403
            | ("DELETE", "/system/user/profile/sso-grants/{client_id}")
        // ===== 前端异常/性能上报（任何已登录用户皆可上报，无需 RBAC，Tier-S #1）=====
            | ("POST", "/monitor/frontendError/report")
        // ===== 审批工作流个人数据接口（归属校验在 service 层：待办=assignee、我发起=applicant；V2-P0-2）=====
            | ("GET", "/system/flow/todo")
            | ("GET", "/system/flow/mine")
            | ("GET", "/system/flow/done")
            | ("GET", "/system/flow/pending-count")
            | ("GET", "/system/flow/task/{taskId}")
            | ("POST", "/system/flow/demo/submit")
            | ("POST", "/system/flow/demo/{docId}/resubmit")
            | ("POST", "/system/flow/demo/{docId}/withdraw")
            | ("POST", "/system/flow/task/{taskId}/action")
            // 加签（W-3）：写动作，与 action 同口径（service 层归属 + PAT 校验）
            | ("POST", "/system/flow/task/{taskId}/countersign-add")
        // ===== 个人会话管理（v5-N5：自助查看/注销本人会话，属主校验在 handler；仅登录）=====
            | ("GET", "/monitor/my-session/list")
            | ("DELETE", "/monitor/my-session/{tokenHash}")
    )
}

/// Tier-S #3：判断某路径是否为“令牌管理类”路径（自助 + 管理端）。
///
/// 无论是否已登记权限映射，PAT 认证的请求一律禁止访问这些路径，防止一枚被窃的作用域令牌
/// 自我签发更宽的令牌、吊销他人令牌或续期。匹配使用路径前缀（覆盖 `{patId}` 参数化模板）。
fn is_pat_management_path(path: &str) -> bool {
    // v2-P0-C：`/sso/*` 受保护面（授权同意等）对 PAT 一律禁止——窄作用域的 PAT 不得代表用户
    // 批准 SSO 授权（否则等于用作用域令牌为第三方签发完整身份令牌，scope 逃逸）。
    // 公开的协议端点（/sso/authorize 等）不经过本中间件，不受影响。
    path.starts_with("/sso/")
        || path.starts_with("/system/user/profile/tokens")
        || path.starts_with("/monitor/pat")
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

    /// GDPR 用户匿名化：复用 `system:user:remove`，且参数名与 router 注册逐字一致（`{userId}`）
    #[test]
    fn test_user_erasure_perms_and_param_names() {
        assert_eq!(
            get_required_perm("GET", "/system/user/{userId}/anonymize/precheck"),
            Some("system:user:remove")
        );
        assert_eq!(
            get_required_perm("POST", "/system/user/{userId}/anonymize"),
            Some("system:user:remove")
        );
        // 参数名不匹配 ⇒ 查表失败（fail-closed 下 404/403 错判），故钉死
        assert_eq!(
            get_required_perm("GET", "/system/user/{id}/anonymize/precheck"),
            None
        );
        // 方法混淆不应命中
        assert_eq!(
            get_required_perm("POST", "/system/user/{userId}/anonymize/precheck"),
            None
        );
        assert_eq!(
            get_required_perm("GET", "/system/user/{userId}/anonymize"),
            None
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

    // ===== 可观测性监控权限映射 =====
    #[test]
    fn test_observability_perms() {
        assert_eq!(
            get_required_perm("GET", "/monitor/slow-sql/list"),
            Some("monitor:slowSql:list")
        );
        assert_eq!(
            get_required_perm("GET", "/monitor/slow-sql/stats"),
            Some("monitor:slowSql:list")
        );
        assert_eq!(
            get_required_perm("DELETE", "/monitor/slow-sql/clear"),
            Some("monitor:slowSql:list")
        );
        assert_eq!(
            get_required_perm("GET", "/monitor/error-log/list"),
            Some("monitor:slowSql:list")
        );
        assert_eq!(
            get_required_perm("GET", "/monitor/error-log/stats"),
            Some("monitor:slowSql:list")
        );
        assert_eq!(
            get_required_perm("DELETE", "/monitor/error-log/clear"),
            Some("monitor:slowSql:list")
        );
        assert_eq!(
            get_required_perm("GET", "/monitor/redis/stats"),
            Some("monitor:cache:list")
        );
        // 方法混淆不应命中（GET clear、DELETE list 均不匹配）
        assert_eq!(get_required_perm("GET", "/monitor/slow-sql/clear"), None);
        assert_eq!(get_required_perm("DELETE", "/monitor/error-log/list"), None);
        // 服务器监控已并入健康检查，权限对齐 monitor:health:list
        assert_eq!(
            get_required_perm("GET", "/monitor/server"),
            Some("monitor:health:list")
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
            Some("system:file:upload")
        );
        assert_eq!(
            get_required_perm("POST", "/system/file/upload"),
            Some("system:file:upload")
        );
    }

    // ===== 仪表盘统计权限 =====
    #[test]
    fn test_dashboard_stats_perm() {
        assert_eq!(
            get_required_perm("GET", "/dashboard/stats"),
            Some("monitor:dashboard:list")
        );
        assert_eq!(
            get_required_perm("GET", "/dashboard/user-stats"),
            Some("monitor:dashboard:list")
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
    fn test_pref_routes_login_only() {
        // 个人消息偏好 / 免打扰为本人自助操作，仅需登录
        assert!(is_login_only_path("GET", "/system/profile/pref"));
        assert!(is_login_only_path("PUT", "/system/profile/pref"));
        assert!(!is_login_only_path("POST", "/system/profile/pref"));
    }

    #[test]
    fn test_stats_by_type_perm_mapped() {
        // dashboard 首页操作日志类型统计需看板查看权限（P0-1 补充映射，此前 fail-open 裸奔）
        assert_eq!(
            get_required_perm("GET", "/monitor/operlog/stats-by-type"),
            Some("monitor:dashboard:list")
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
            ("GET", "/system/user/{userId}/anonymize/precheck"),
            ("POST", "/system/user/{userId}/anonymize"),
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
            // sys_tenant_router
            ("GET", "/system/tenant/list"),
            ("GET", "/system/tenant/package/options"),
            ("GET", "/system/tenant/package/{packageId}/features"),
            ("PUT", "/system/tenant/package/features"),
            ("GET", "/system/tenant/{tenantId}"),
            ("POST", "/system/tenant"),
            ("PUT", "/system/tenant"),
            ("PUT", "/system/tenant/changeStatus"),
            ("PUT", "/system/tenant/restore/{tenantId}"),
            ("DELETE", "/system/tenant/{tenantId}"),
            // sys_tenant_domain_router（多租户 Phase 3 域名链路）
            ("GET", "/system/tenant/domain/list"),
            ("POST", "/system/tenant/domain"),
            ("POST", "/system/tenant/domain/verify/{domainId}"),
            ("PUT", "/system/tenant/domain/primary"),
            ("PUT", "/system/tenant/domain/changeStatus"),
            ("DELETE", "/system/tenant/domain/{domainId}"),
            // sys_tenant_nav_router（批次 3：L3 租户自建导航）
            ("GET", "/system/tenant/menu/list"),
            ("GET", "/system/tenant/menu/options"),
            ("POST", "/system/tenant/menu"),
            ("PUT", "/system/tenant/menu"),
            ("DELETE", "/system/tenant/menu/{l3Id}"),
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
            // v5-N5：个人会话管理（仅登录白名单）
            ("GET", "/monitor/my-session/list"),
            ("DELETE", "/monitor/my-session/{tokenHash}"),
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
            // monitor_observability_router
            ("GET", "/monitor/slow-sql/list"),
            ("GET", "/monitor/slow-sql/stats"),
            ("DELETE", "/monitor/slow-sql/clear"),
            ("GET", "/monitor/error-log/list"),
            ("GET", "/monitor/error-log/stats"),
            ("DELETE", "/monitor/error-log/clear"),
            ("GET", "/monitor/redis/stats"),
            // sys_backup_router
            ("GET", "/system/backup/list"),
            ("GET", "/system/backup/{backupId}"),
            ("POST", "/system/backup"),
            ("POST", "/system/backup/restore/{backupId}"),
            ("GET", "/system/backup/download/{backupId}"),
            ("POST", "/system/backup/tenant-export/{tenantId}"),
            ("POST", "/system/backup/self-export"),
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
            // sys_report_router
            ("GET", "/system/report/list"),
            ("GET", "/system/report/{reportId}"),
            ("POST", "/system/report"),
            ("PUT", "/system/report"),
            ("DELETE", "/system/report/{reportId}"),
            ("PUT", "/system/report/{reportId}/status"),
            ("POST", "/system/report/{reportId}/preview"),
            ("GET", "/system/report/sub/list"),
            ("GET", "/system/report/sub/{subId}"),
            ("POST", "/system/report/sub"),
            ("PUT", "/system/report/sub"),
            ("DELETE", "/system/report/sub/{subId}"),
            ("PUT", "/system/report/sub/{subId}/status"),
            ("POST", "/system/report/sub/{subId}/run"),
            // sys_web_hook_router
            ("GET", "/monitor/webHook/list"),
            ("POST", "/monitor/webHook/export"),
            ("PUT", "/monitor/webHook/{id}/status"),
            ("POST", "/monitor/webHook/{id}/test"),
            ("GET", "/monitor/webHook/{id}"),
            ("DELETE", "/monitor/webHook/{id}"),
            ("POST", "/monitor/webHook"),
            ("PUT", "/monitor/webHook"),
            ("GET", "/monitor/webHook/log/list"),
            ("POST", "/monitor/webHook/log/export"),
            ("DELETE", "/monitor/webHook/log/clean"),
            ("POST", "/monitor/webHook/log/{ids}/retry"),
            ("GET", "/monitor/webHook/log/{id}"),
            ("DELETE", "/monitor/webHook/log/{id}"),
            // sys_flow_router（审批工作流：管理视图走权限表，个人数据走仅登录白名单）
            ("GET", "/system/flow/list"),
            ("GET", "/system/flow/todo"),
            ("GET", "/system/flow/mine"),
            ("GET", "/system/flow/done"),
            ("GET", "/system/flow/pending-count"),
            ("GET", "/system/flow/task/{taskId}"),
            ("POST", "/system/flow/demo/submit"),
            ("POST", "/system/flow/demo/{docId}/resubmit"),
            ("POST", "/system/flow/demo/{docId}/withdraw"),
            ("POST", "/system/flow/task/{taskId}/action"),
            ("POST", "/system/flow/task/{taskId}/countersign-add"),
            ("POST", "/system/flow/export"),
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

    /// W-15：flow 带参路径的参数名必须与 router 注册**逐字一致**
    ///
    /// V6-E3 的失效模式：参数名不一致 ⇒ 查表失败 ⇒ fail-open 静默放行 / fail-closed 误拦 403。
    /// 本用例把 flow 全部带参路由钉在测试里，后续改名会立即红。
    #[test]
    fn test_flow_param_names_match_router() {
        for (method, path) in [
            ("GET", "/system/flow/task/{taskId}"),
            ("POST", "/system/flow/demo/{docId}/resubmit"),
            ("POST", "/system/flow/demo/{docId}/withdraw"),
            ("POST", "/system/flow/task/{taskId}/action"),
            ("POST", "/system/flow/task/{taskId}/countersign-add"),
        ] {
            assert!(
                is_login_only_path(method, path),
                "flow 仅登录路由未登记或参数名与 router 不一致（静默 fail-open/403 风险）: {method} {path}"
            );
        }
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

    /// O-5：源码级"路由注册 ⊆ 权限登记"守卫（权威完整性检查）
    ///
    /// 与 `test_all_protected_routes_covered`（手写清单，便于人读）不同，本用例**直接扫描源码**：
    /// `router/mod.rs` 的 `protected` 子树 merge 清单 → 各 router 函数体 → 全部 `.route(...)`。
    /// 由此消除"新增路由漏登记 ⇒ 测试假绿 + 运行时 403（fail-closed）/ 越权（fail-open）"的结构性弱点。
    #[test]
    fn test_scanned_protected_routes_are_registered() {
        let scanned = scan_protected_routes();
        assert!(
            scanned.len() > 250,
            "扫描到的受保护路由数异常偏少（{}），疑似解析器失效",
            scanned.len()
        );
        let mut uncovered: Vec<String> = Vec::new();
        for (method, path) in &scanned {
            if get_required_perm(method, path).is_none() && !is_login_only_path(method, path) {
                uncovered.push(format!("{method} {path}"));
            }
        }
        uncovered.sort();
        uncovered.dedup();
        assert!(
            uncovered.is_empty(),
            "以下受保护路由未登记权限映射且不在仅登录白名单（fail-closed 下 403 生产事故 / fail-open 下越权）：{uncovered:#?}"
        );
    }

    /// 扫描 `src/router` 中注册于 `protected` 子树内的全部 `.route(...)`，返回 (METHOD, path)
    ///
    /// axum 的 `Router` 不支持运行时枚举，故以源码解析代替：
    /// ① 从 `router/mod.rs` 的 `let protected = Router::new() ... .merge(<mod>::<fn>())` 取目标函数；
    /// ② 从对应文件的函数体做花括号配平截取；
    /// ③ 对每个 `.route(` 取括号内首字符串字面量为路径，取 `get/post/put/delete/patch` 为方法。
    fn scan_protected_routes() -> Vec<(String, String)> {
        let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/src/router");
        let mod_rs =
            std::fs::read_to_string(format!("{dir}/mod.rs")).expect("读取 router/mod.rs 失败");
        let seg_start = mod_rs
            .find("let protected = Router::new()")
            .expect("未找到 protected 子树起始");
        let seg_rest = &mod_rs[seg_start..];
        let seg_end = seg_rest
            .find("oper_log_middleware")
            .expect("未找到 protected 子树结束标记");
        let seg = &seg_rest[..seg_end];

        // ① 抽取 `.merge(<module>::<fn>())` 目标
        let mut targets: Vec<(String, String)> = Vec::new();
        let mut rest = seg;
        while let Some(i) = rest.find(".merge(") {
            rest = &rest[i + ".merge(".len()..];
            let close = rest.find(')').expect("merge 调用未闭合");
            let arg = rest[..close].trim();
            if let Some((m, f)) = arg.split_once("::") {
                // arg 形如 `auth_router::protected_auth_routes(`（首个 ')' 前的调用前缀）
                targets.push((
                    m.trim().to_string(),
                    f.trim().trim_end_matches('(').trim().to_string(),
                ));
            }
        }
        assert!(
            targets.len() > 30,
            "protected 子树 merge 清单解析异常（{} 项）",
            targets.len()
        );

        let mut out: Vec<(String, String)> = Vec::new();
        for (module, func) in targets {
            let src = std::fs::read_to_string(format!("{dir}/{module}.rs"))
                .unwrap_or_else(|e| panic!("读取 {module}.rs 失败: {e}"));
            let body = extract_fn_body(&src, &func)
                .unwrap_or_else(|| panic!("在 {module}.rs 中未找到函数 {func}"));
            let mut r = body.as_str();
            while let Some(i) = r.find(".route(") {
                let from_call = &r[i + ".route(".len() - 1..];
                let (args, consumed) = take_balanced_parens(from_call)
                    .unwrap_or_else(|| panic!("{module}::{func} 的 .route( 未闭合"));
                let path = first_string_literal(args).unwrap_or_else(|| {
                    panic!("{module}::{func} 的 .route 首参不是字符串字面量: {args}")
                });
                let methods = extract_http_methods(args);
                assert!(
                    !methods.is_empty(),
                    "{module}::{func} 路由 {path} 未识别到 HTTP 方法: {args}"
                );
                for m in methods {
                    out.push((m, path.clone()));
                }
                r = &from_call[consumed..];
            }
        }
        out
    }

    /// 取 `src` 的函数体（`fn <name>` 起第一个 `{` 到配平 `}`），支持 `pub`/`pub(crate)` 前缀
    fn extract_fn_body(src: &str, name: &str) -> Option<String> {
        let needle = format!("fn {name}(");
        let start = src.find(&needle)?;
        let after = &src[start..];
        let brace = after.find('{')?;
        let body = &after[brace..];
        let bytes = body.as_bytes();
        let mut depth = 0usize;
        let mut in_str = false;
        let mut i = 0usize;
        while i < bytes.len() {
            let b = bytes[i];
            // 行注释：跳到行尾（避免注释里的括号干扰配平）
            if !in_str && b == b'/' && bytes.get(i + 1) == Some(&b'/') {
                while i < bytes.len() && bytes[i] != b'\n' {
                    i += 1;
                }
                continue;
            }
            match b {
                b'"' => in_str = !in_str,
                b'{' if !in_str => depth += 1,
                b'}' if !in_str => {
                    depth -= 1;
                    if depth == 0 {
                        return Some(body[..=i].to_string());
                    }
                }
                _ => {}
            }
            i += 1;
        }
        None
    }

    /// 取以 `(` 起始的平衡括号内容，返回 (内部文本, 含括号总长度)
    fn take_balanced_parens(s: &str) -> Option<(&str, usize)> {
        let bytes = s.as_bytes();
        if bytes.first() != Some(&b'(') {
            return None;
        }
        let mut depth = 0usize;
        let mut in_str = false;
        for (i, &b) in bytes.iter().enumerate() {
            match b {
                b'"' => in_str = !in_str,
                b'(' if !in_str => depth += 1,
                b')' if !in_str => {
                    depth -= 1;
                    if depth == 0 {
                        return Some((&s[1..i], i + 1));
                    }
                }
                _ => {}
            }
        }
        None
    }

    /// 取首个双引号字符串字面量内容
    fn first_string_literal(s: &str) -> Option<String> {
        let start = s.find('"')?;
        let rest = &s[start + 1..];
        let end = rest.find('"')?;
        Some(rest[..end].to_string())
    }

    /// 抽取 axum 方法路由器标识符（`get(...)` / `post(...)` / `put(...)` / `delete(...)` / `patch(...)`）
    fn extract_http_methods(args: &str) -> Vec<String> {
        const METHODS: [&str; 5] = ["get", "post", "put", "delete", "patch"];
        let bytes = args.as_bytes();
        let mut out: Vec<String> = Vec::new();
        let mut i = 0usize;
        while i < bytes.len() {
            if bytes[i].is_ascii_alphabetic() {
                let start = i;
                while i < bytes.len() && (bytes[i].is_ascii_alphanumeric() || bytes[i] == b'_') {
                    i += 1;
                }
                let word = &args[start..i];
                let mut j = i;
                while j < bytes.len() && (bytes[j] as char).is_whitespace() {
                    j += 1;
                }
                if j < bytes.len()
                    && bytes[j] == b'('
                    && METHODS.contains(&word)
                    && !out.iter().any(|x| x.eq_ignore_ascii_case(word))
                {
                    out.push(word.to_ascii_uppercase());
                }
                continue;
            }
            i += 1;
        }
        out
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
            Some("system:msg:channel:list")
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
            Some("system:msg:template:list")
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

    /// 批次 3：L3 租户自建导航的权限映射 + 参数名逐字一致（`{l3Id}` 与 router 注册一致）
    #[test]
    fn test_tenant_nav_perms_and_param_names() {
        assert_eq!(
            get_required_perm("GET", "/system/tenant/menu/list"),
            Some("system:tenantMenu:list")
        );
        assert_eq!(
            get_required_perm("GET", "/system/tenant/menu/options"),
            Some("system:tenantMenu:list")
        );
        assert_eq!(
            get_required_perm("POST", "/system/tenant/menu"),
            Some("system:tenantMenu:add")
        );
        assert_eq!(
            get_required_perm("PUT", "/system/tenant/menu"),
            Some("system:tenantMenu:edit")
        );
        assert_eq!(
            get_required_perm("DELETE", "/system/tenant/menu/{l3Id}"),
            Some("system:tenantMenu:remove")
        );
        // 参数名不匹配 ⇒ 查表失败 ⇒ fail-open 下越权 / fail-closed 下误拦，故钉死
        assert_eq!(
            get_required_perm("DELETE", "/system/tenant/menu/{id}"),
            None,
            "参数名必须与 router 注册逐字一致（{{l3Id}}）"
        );
        // 方法混淆不应命中
        assert_eq!(get_required_perm("GET", "/system/tenant/menu"), None);
        assert_eq!(get_required_perm("POST", "/system/tenant/menu/list"), None);
    }
}
