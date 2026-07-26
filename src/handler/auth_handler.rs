//! 认证模块 Handler（Axum 原生实现）
//!
//! 接口路径与返回格式对齐 ref-salvo-admin / ruoyi-vue3-ts：
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

use axum::extract::{ConnectInfo, State};
use axum::http::HeaderMap;
use axum::Json;
use serde::Serialize;
use std::net::SocketAddr;
use utoipa::ToSchema;

use crate::common::{AjaxResult, AppError};
use crate::middleware::Operator;
use crate::service::auth_service::{
    CaptchaVo, GetInfoVo, LoginDto, LoginVo, RegisterDto, RouterVo, UnlockScreenDto,
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
    tag = "auth"
)]
pub async fn captcha(
    State(state): State<Arc<AppState>>,
    ConnectInfo(peer_addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> Result<CaptchaResult, AppError> {
    // 提取客户端 IP，用于验证码绑定（防止跨 IP 重放）
    let ip = extract_client_ip(&headers, peer_addr.ip(), &state.config.server.trusted_proxies);
    let mut redis = state.redis.clone();
    let vo: CaptchaVo = state.auth_service.generate_captcha(&mut redis, &ip).await?;
    Ok(CaptchaResult {
        code: 200,
        msg: crate::tr!("msg.success.default"),
        captcha_enabled: vo.captcha_enabled,
        img: vo.img,
        uuid: vo.uuid,
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
    tag = "auth"
)]
pub async fn login(
    State(state): State<Arc<AppState>>,
    ConnectInfo(peer_addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(dto): Json<LoginDto>,
) -> Result<LoginResult, AppError> {
    let login_ip = extract_client_ip(&headers, peer_addr.ip(), &state.config.server.trusted_proxies);
    let user_agent = headers
        .get("user-agent")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    let mut redis = state.redis.clone();
    let vo: LoginVo = state
        .auth_service
        .login(dto, &login_ip, user_agent, &mut redis, &state.config.jwt, &state.ip_locator)
        .await?;

    Ok(LoginResult {
        code: 200,
        msg: crate::tr!("msg.success.default"),
        token: vo.token,
    })
}

/// POST /register
/// 用户注册（公开接口，免鉴权）
pub async fn register(
    State(state): State<Arc<AppState>>,
    ConnectInfo(peer_addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(dto): Json<RegisterDto>,
) -> Result<AjaxResult<()>, AppError> {
    // 提取客户端 IP，用于验证码绑定校验（与生成时一致）
    let ip = extract_client_ip(&headers, peer_addr.ip(), &state.config.server.trusted_proxies);
    let mut redis = state.redis.clone();
    state.auth_service.register(dto, &ip, &mut redis).await?;
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

    let vo: GetInfoVo = state.auth_service.get_info(user_id).await?;

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
    })
}

/// GET /getRouters
/// 获取用户路由树
pub async fn get_routers(
    State(state): State<Arc<AppState>>,
    operator: Operator,
) -> Result<AjaxResult<Vec<RouterVo>>, AppError> {
    let user_id: i64 = operator
        .user_id()
        .parse()
        .map_err(|_| AppError::internal(&crate::tr!("error.auth.user_id_parse_failed")))?;

    let routers: Vec<RouterVo> = state.auth_service.get_routers(user_id).await?;
    Ok(AjaxResult::success(routers))
}

/// POST /unlockscreen
/// 锁屏解锁（需登录态，校验当前用户密码）
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
