//! 认证模块 Handler（Axum 原生实现）
//!
//! 接口路径与返回格式对齐 yebot-ui 前端调用规范：
//! - GET  /captchaImage  生成验证码（字段在顶层）
//! - POST /login         登录（token 在顶层）
//! - POST /logout        登出（标准 AjaxResult）
//! - GET  /getInfo       获取用户信息（字段在顶层）
//! - GET  /getRouters    获取路由树（标准 AjaxResult<Vec<RouterVo>>）
//!
//! 响应格式说明：
//! - CaptchaResult / LoginResult / GetInfoResult：业务字段在响应体顶层（对齐前端 extends AjaxResult）
//! - logout / getRouters：使用标准 AjaxResult<T> 包装

use std::sync::Arc;

use axum::Json;
use axum::extract::{ConnectInfo, State};
use axum::http::HeaderMap;
use serde::Serialize;
use std::net::SocketAddr;
use utoipa::ToSchema;

use crate::common::{AjaxResult, AppError};
use crate::middleware::{HostTenant, Operator};
use crate::service::auth_service::{
    CaptchaVo, GetInfoVo, LoginDto, RegisterDto, RouterVo, UnlockScreenDto,
};
use crate::state::AppState;
use crate::utils::ip::extract_client_ip;

// ==================== Handler 层响应结构体（字段在顶层） ====================

/// 验证码响应体（字段在顶层，对齐前端 CaptchaInfoResult extends AjaxResult）
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct CaptchaResult {
    pub code: i32,
    pub msg: String,
    pub captcha_enabled: bool,
    pub img: String,
    pub uuid: String,
    /// 注册开关（前端据此控制"立即注册"链接显示）
    pub register_enabled: bool,
}

/// 登录响应体（token 在顶层，对齐前端 LoginInfoResult extends AjaxResult）
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct LoginResult {
    pub code: i32,
    pub msg: String,
    pub token: String,
}

/// 用户信息响应体（字段在顶层，对齐前端 UserInfoResult extends AjaxResult）
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct GetInfoResult {
    pub code: i32,
    pub msg: String,
    pub user: serde_json::Value,
    pub roles: Vec<String>,
    pub permissions: Vec<String>,
    /// 密码加密类型
    pub pwd_chrtype: Option<String>,
    /// 是否初始密码未修改
    pub is_default_modify_pwd: bool,
    /// 密码是否已过期
    pub is_password_expired: bool,
    /// 用户管理页是否提供「匿名化（GDPR）」入口（服务端按能力位 `privacy.user_erasure`
    /// + 操作者是否平台算好后下发；前端只消费不推断）
    pub show_user_erasure: bool,
}

crate::impl_into_response!(CaptchaResult, LoginResult, GetInfoResult);

// ==================== Handler 实现 ====================

/// GET /captchaImage
/// 生成验证码图片
#[utoipa::path(
    get,
    path = "/captchaImage",
    responses(
        (status = 200, description = "验证码生成成功", body = CaptchaResult),
        (status = 500, description = "服务器错误"),
    ),
    security(()),
    tag = "auth"
)]
pub async fn captcha(
    State(state): State<Arc<AppState>>,
    ConnectInfo(peer_addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    host_tenant: HostTenant,
) -> Result<CaptchaResult, AppError> {
    // 提取客户端 IP，用于验证码绑定（防止跨 IP 重放）
    let ip = extract_client_ip(
        &headers,
        peer_addr.ip(),
        &state.config.server.trusted_proxies,
    );
    let mut redis = state.redis.clone();
    // 多租户 Phase 3：透传 host 解析出的租户上下文（匿名路径无登录态）
    let vo: CaptchaVo = state
        .auth_service
        .generate_captcha(&mut redis, &ip, host_tenant.tid())
        .await?;
    Ok(CaptchaResult {
        code: 200,
        msg: crate::tr!("msg.success.default"),
        captcha_enabled: vo.captcha_enabled,
        img: vo.img,
        uuid: vo.uuid,
        register_enabled: vo.register_enabled,
    })
}

/// POST /login
/// 登录认证
#[utoipa::path(
    post,
    path = "/login",
    request_body = LoginDto,
    responses(
        (status = 200, description = "登录成功", body = LoginResult),
        (status = 400, description = "参数错误或验证码失效"),
        (status = 500, description = "服务器错误"),
    ),
    security(()),
    tag = "auth"
)]
pub async fn login(
    State(state): State<Arc<AppState>>,
    ConnectInfo(peer_addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    host_tenant: HostTenant,
    Json(dto): Json<LoginDto>,
) -> Result<LoginResult, AppError> {
    let login_ip = extract_client_ip(
        &headers,
        peer_addr.ip(),
        &state.config.server.trusted_proxies,
    );
    let user_agent = headers
        .get("user-agent")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    let mut redis = state.redis.clone();
    let username = dto.username.clone();
    let vo = state
        .auth_service
        .login(
            dto,
            &login_ip,
            user_agent,
            &mut redis,
            &state.config.jwt,
            &state.ip_locator,
            host_tenant.tid(),
        )
        .await;

    // WebHook 事件分发（G5）：登录成功 / 失败均异步通知订阅方，失败含原因供外部风控。
    // 仅借用 vo 而非消费，随后以 `?` 按值传播错误，避免对非 Clone 的 AppError 做 clone。
    match &vo {
        Ok(v) => {
            state.web_hook_service.dispatch_event(
                crate::service::sys_web_hook_service::EVENT_LOGIN_SUCCESS,
                serde_json::json!({
                    "username": username,
                    "ip": login_ip,
                    "time": crate::common::datetime::now_naive().to_string(),
                }),
                v.tenant_id,
            );
        }
        Err(err) => {
            state.web_hook_service.dispatch_event(
                crate::service::sys_web_hook_service::EVENT_LOGIN_FAILURE,
                serde_json::json!({
                    "username": username,
                    "ip": login_ip,
                    "reason": err.to_string(),
                    "time": crate::common::datetime::now_naive().to_string(),
                }),
                0,
            );
        }
    }

    let vo = vo?;
    Ok(LoginResult {
        code: 200,
        msg: crate::tr!("msg.success.default"),
        token: vo.token,
    })
}

/// POST /register
/// 用户注册（公开接口，免鉴权）
///
/// 审计链路（P1-AUDIT-01）：register 位于 public_auth_routes，不经过 oper_log_middleware，
/// 需手动记录 oper_log，确保注册事件可审计（用户名、IP、归属地、成功/失败状态）。
/// - title: module.auth（与 oper_log_middleware::infer_module_title 对齐）
/// - business_type: 1（新增，POST 创建用户）
/// - operator_type: 0（匿名注册，非后台用户操作）
/// - 失败时仍记录（status=1），便于追踪注册刷接口/暴力注册行为
#[utoipa::path(
    post,
    path = "/register",
    request_body = RegisterDto,
    responses(
        (status = 200, description = "注册成功", body = AjaxResult<serde_json::Value>),
        (status = 400, description = "参数错误、验证码失效或用户名已存在"),
    ),
    security(()),
    tag = "auth"
)]
pub async fn register(
    State(state): State<Arc<AppState>>,
    ConnectInfo(peer_addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    host_tenant: HostTenant,
    Json(dto): Json<RegisterDto>,
) -> Result<AjaxResult<()>, AppError> {
    let start = std::time::Instant::now();
    // 提取客户端 IP，用于验证码绑定校验（与生成时一致）
    let ip = extract_client_ip(
        &headers,
        peer_addr.ip(),
        &state.config.server.trusted_proxies,
    );
    let oper_location = state.ip_locator.locate(&ip);

    // 执行注册，捕获结果用于审计日志（成功/失败均记录）
    let username = dto.username.clone();
    let mut redis = state.redis.clone();
    // 多租户 Phase 3：透传 host 解析出的租户上下文（匿名路径无登录态）
    let result = state
        .auth_service
        .register(dto, &ip, &mut redis, host_tenant.tid())
        .await;

    let cost_time = start.elapsed().as_millis() as i64;
    let (status, error_msg, json_result) = match &result {
        Ok(_) => (
            "0".to_string(),
            String::new(),
            crate::tr!("msg.success.register").to_string(),
        ),
        Err(e) => ("1".to_string(), e.to_string(), String::new()),
    };

    // 异步写入 oper_log，不阻断响应（与 oper_log_middleware spawn 模式一致）
    // 使用 AssertUnwindSafe + catch_unwind 防 panic 击溃 worker
    let oper_log_service = state.oper_log_service.clone();
    let oper_name = username.clone();
    tokio::spawn(async move {
        use futures::FutureExt;
        use std::panic::AssertUnwindSafe;

        let record = crate::service::sys_oper_log_service::OperLogRecord {
            title: "module.auth".to_string(),
            business_type: 1, // 新增
            method: "/register".to_string(),
            request_method: "POST".to_string(),
            operator_type: 0, // 匿名注册
            oper_name,
            tenant_id: 0,           // 匿名注册无租户上下文
            target_tenant_id: None, // 匿名注册无目标资源租户
            dept_name: String::new(),
            oper_url: "/register".to_string(),
            oper_ip: ip.to_string(),
            oper_location,
            // 不记录密码等敏感字段，仅记录用户名（脱敏）
            // P1-5 修复：改用 serde_json::json! 避免手拼 JSON 导致的注入风险
            oper_param: serde_json::json!({ "username": username }).to_string(),
            oper_before: String::new(),
            oper_diff: String::new(),
            json_result,
            status,
            error_msg,
            cost_time,
        };

        let res = AssertUnwindSafe(async {
            // 超时保护（与 oper_log_middleware::OPER_LOG_TIMEOUT 一致）
            if let Err(_elapsed) = tokio::time::timeout(
                std::time::Duration::from_secs(5),
                oper_log_service.record_oper_log(record),
            )
            .await
            {
                tracing::warn!("register oper_log 写入超时，已放弃本次日志记录");
            }
        })
        .catch_unwind()
        .await;

        if let Err(panic_err) = res {
            tracing::error!("register oper_log spawn 内发生 panic: {:?}", panic_err);
        }
    });

    // 传播原结果给客户端（保持原有错误码与消息不变）
    result?;
    Ok(AjaxResult::success_msg(&crate::tr!("msg.success.register")))
}

/// POST /logout
/// 登出（token 加入黑名单）
#[utoipa::path(
    post,
    path = "/logout",
    responses(
        (status = 200, description = "登出成功", body = AjaxResult<serde_json::Value>),
        (status = 401, description = "未授权或 token 缺失"),
    ),
    tag = "auth"
)]
pub async fn logout(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<AjaxResult<()>, AppError> {
    // 从 Authorization header 提取 Bearer token
    let auth_header = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| AppError::unauthorized(&crate::tr!("error.auth.token_missing")))?;

    let token = auth_header
        .strip_prefix("Bearer ")
        .ok_or_else(|| AppError::unauthorized(&crate::tr!("error.auth.token_invalid")))?;

    let mut redis = state.redis.clone();
    state
        .auth_service
        .logout(token, &mut redis, &state.config.jwt)
        .await?;

    Ok(AjaxResult::success_msg(&crate::tr!("msg.success.logout")))
}

/// GET /getInfo
/// 获取用户信息（user + roles + permissions）
#[utoipa::path(
    get,
    path = "/getInfo",
    responses(
        (status = 200, description = "用户信息", body = GetInfoResult),
        (status = 401, description = "未授权"),
    ),
    tag = "auth"
)]
pub async fn get_info(
    State(state): State<Arc<AppState>>,
    operator: Operator,
) -> Result<GetInfoResult, AppError> {
    let user_id: i64 = operator
        .user_id()
        .parse()
        .map_err(|_| AppError::internal(&crate::tr!("error.auth.user_id_parse_failed")))?;

    let vo: GetInfoVo = state
        .auth_service
        .get_info(user_id, operator.tenant_id())
        .await?;

    // 将 user 序列化为 json::Value（password 已在 Service 层清空为 None）
    let user_value = serde_json::to_value(&vo.user)?;

    Ok(GetInfoResult {
        code: 200,
        msg: crate::tr!("msg.success.default"),
        user: user_value,
        roles: vo.roles,
        permissions: vo.permissions,
        pwd_chrtype: vo.pwd_chrtype,
        is_default_modify_pwd: vo.is_default_modify_pwd,
        is_password_expired: vo.is_password_expired,
        show_user_erasure: vo.show_user_erasure,
    })
}

/// GET /getRouters
/// 获取用户路由树
#[utoipa::path(
    get,
    path = "/getRouters",
    responses(
        (status = 200, description = "用户路由树", body = AjaxResult<Vec<RouterVo>>),
        (status = 401, description = "未授权"),
    ),
    tag = "auth"
)]
pub async fn get_routers(
    State(state): State<Arc<AppState>>,
    operator: Operator,
) -> Result<AjaxResult<Vec<RouterVo>>, AppError> {
    let user_id: i64 = operator
        .user_id()
        .parse()
        .map_err(|_| AppError::internal(&crate::tr!("error.auth.user_id_parse_failed")))?;

    // §27.6 生效点②：调用者租户用于 `套餐 ∩ 角色授权` 求交（平台操作者 tid=0 不裁剪）
    let routers: Vec<RouterVo> = state
        .auth_service
        .get_routers(user_id, operator.tenant_id())
        .await?;
    Ok(AjaxResult::success(routers))
}

/// POST /unlockscreen
/// 锁屏解锁（需登录态，校验当前用户密码）
#[utoipa::path(
    post,
    path = "/unlockscreen",
    request_body = UnlockScreenDto,
    responses(
        (status = 200, description = "解锁成功", body = AjaxResult<serde_json::Value>),
        (status = 400, description = "密码错误"),
        (status = 401, description = "未授权"),
    ),
    tag = "auth"
)]
pub async fn unlock_screen(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    Json(dto): Json<UnlockScreenDto>,
) -> Result<AjaxResult<()>, AppError> {
    let user_id: i64 = operator
        .user_id()
        .parse()
        .map_err(|_| AppError::internal(&crate::tr!("error.auth.user_id_parse_failed")))?;
    state.auth_service.unlock_screen(user_id, dto).await?;
    Ok(AjaxResult::success_msg(&crate::tr!("msg.success.unlock")))
}

// 注：extract_client_ip / is_trusted_proxy / ip_in_cidr 已迁移至 utils/ip.rs（P1-17）
// 消除 middleware → handler 的反向依赖。本文件通过 use crate::utils::ip::extract_client_ip 调用。
