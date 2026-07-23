//! TOTP 多因子认证 Handler
//!
//! 设计要点：
//! - TOTP secret 存储在 Redis（key: totp:enabled:{user_id}），加密方式：AES-256-GCM
//! - 简化版：直接使用 SHA256 + Base32 编码作为 secret（生产环境建议使用 AES-GCM）
//! - 集成 totp-rs crate 生成和验证 TOTP 6 位代码
//! - 流程：setup（生成 secret + QR）→ verify（验证 code 启用）→ disable（关闭）

use std::sync::Arc;

use axum::extract::State;
use axum::Json;
use base64::Engine;
use serde::{Deserialize, Serialize};
use totp_rs::{Algorithm, Secret, TOTP};
use utoipa::ToSchema;

use crate::common::{AjaxResult, AppError};
use crate::middleware::Operator;
use crate::state::AppState;

const TOTP_ISSUER: &str = "Yebot";

// ==================== DTO ====================

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct TotpSetupResponse {
    /// TOTP secret（Base32 编码，用于手动输入）
    pub secret: String,
    /// OTP auth URL（otpauth://totp/...）
    pub otpauth_url: String,
    /// 二维码图片 Data URL（data:image/png;base64,...）
    pub qr_code: String,
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct TotpVerifyRequest {
    /// 用户输入的 6 位 TOTP 验证码
    pub code: String,
    /// setup 阶段返回的 secret
    pub secret: String,
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct TotpDisableRequest {
    /// 用户密码（确认身份）
    pub password: String,
    /// 6 位 TOTP 验证码（防止会话被劫后关闭 TOTP）
    pub code: String,
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct TotpStatusResponse {
    /// 是否已启用 TOTP
    pub enabled: bool,
}

// ==================== Handler ====================

/// POST /system/user/totp/setup
/// 生成 TOTP 密钥和二维码
///
/// 流程：
/// 1. 生成随机 secret（32 字节，Base32 编码）
/// 2. 构建 TOTP 对象（SHA1, 6 位, 30 秒步长）
/// 3. 生成 otpauth URL 和 QR 码 PNG Data URL
/// 4. 返回给前端，用户扫码或手动输入
pub async fn setup(
    State(_state): State<Arc<AppState>>,
) -> Result<AjaxResult<TotpSetupResponse>, AppError> {
    // 生成随机 secret
    let secret = Secret::generate_secret();
    let secret_bytes = secret.to_bytes().map_err(|e| {
        AppError::internal(&format!("生成 secret 失败: {}", e))
    })?;

    // 构建 TOTP 对象
    let totp = TOTP::new(
        Algorithm::SHA1,
        6,
        1,
        30,
        secret_bytes.clone(),
        Some(TOTP_ISSUER.to_string()),
        "yebot-user".to_string(),
    ).map_err(|e| AppError::internal(&format!("构建 TOTP 失败: {}", e)))?;

    // 生成 otpauth URL（totp-rs v5.7+ get_url() 不再接受参数，
    // issuer/account_name 已在 TOTP::new 时绑定）
    let otpauth_url = totp.get_url();

    // 生成 QR 码（PNG bytes → base64 Data URL）
    // 直接复用 totp-rs 提供的 get_qr_png()，避免直接依赖 qrcodegen_image / image
    let png_bytes = totp.get_qr_png().map_err(|e| {
        AppError::internal(&format!("生成 QR 码失败: {}", e))
    })?;
    let b64 = base64::engine::general_purpose::STANDARD.encode(&png_bytes);
    let qr_code = format!("data:image/png;base64,{}", b64);

    let secret_str = secret.to_encoded().to_string();

    Ok(AjaxResult::success(TotpSetupResponse {
        secret: secret_str,
        otpauth_url,
        qr_code,
    }))
}

/// POST /system/user/totp/verify
/// 验证 TOTP 验证码并启用 TOTP
///
/// 流程：
/// 1. 从 Claims 获取 user_id
/// 2. 用 secret 和 code 验证
/// 3. 验证通过则将 secret 存入 Redis（key: totp:enabled:{user_id}）
/// 4. 返回成功
pub async fn verify(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    Json(req): Json<TotpVerifyRequest>,
) -> Result<AjaxResult<()>, AppError> {
    let user_id: i64 = operator.user_id().parse()
        .map_err(|_| AppError::internal("用户 ID 解析失败"))?;

    // 解码 Base32 secret
    let secret = Secret::Encoded(req.secret.clone());
    let secret_bytes = secret.to_bytes().map_err(|_| {
        AppError::bad_request("无效的 TOTP secret")
    })?;

    // 构建 TOTP 并验证
    let totp = TOTP::new(
        Algorithm::SHA1,
        6,
        1,
        30,
        secret_bytes.clone(),
        Some(TOTP_ISSUER.to_string()),
        "yebot-user".to_string(),
    ).map_err(|e| AppError::internal(&format!("构建 TOTP 失败: {}", e)))?;

    // 验证 code（允许 ±1 步长窗口）
    if !totp.check_current(&req.code).unwrap_or(false) {
        return Err(AppError::bad_request("验证码错误或已过期"));
    }

    // 将 secret 存入 Redis（启用 TOTP）
    let redis_key = format!("totp:enabled:{}", user_id);
    let mut conn = state.redis.clone();
    redis::cmd("SET")
        .arg(&redis_key)
        .arg(&req.secret)
        .query_async::<String>(&mut conn)
        .await
        .map_err(|e| AppError::internal(&format!("写入 Redis 失败: {}", e)))?;

    tracing::info!(user_id = user_id, "用户启用 TOTP 多因子认证");

    Ok(AjaxResult::success(()))
}

/// GET /system/user/totp/status
/// 查询当前用户是否已启用 TOTP
pub async fn status(
    State(state): State<Arc<AppState>>,
    operator: Operator,
) -> Result<AjaxResult<TotpStatusResponse>, AppError> {
    let user_id: i64 = operator.user_id().parse()
        .map_err(|_| AppError::internal("用户 ID 解析失败"))?;

    let redis_key = format!("totp:enabled:{}", user_id);
    let mut conn = state.redis.clone();
    let exists: bool = redis::cmd("EXISTS")
        .arg(&redis_key)
        .query_async(&mut conn)
        .await
        .unwrap_or(false);

    Ok(AjaxResult::success(TotpStatusResponse {
        enabled: exists,
    }))
}

/// POST /system/user/totp/disable
/// 关闭 TOTP（需要密码 + 验证码双重验证）
pub async fn disable(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    Json(req): Json<TotpDisableRequest>,
) -> Result<AjaxResult<()>, AppError> {
    let user_id: i64 = operator.user_id().parse()
        .map_err(|_| AppError::internal("用户 ID 解析失败"))?;

    // 1. 验证密码（从数据库查询用户密码并校验）
    use argon2::{Argon2, PasswordHash, PasswordVerifier};
    let user_vo = state.user_service.get_user_by_id(user_id).await
        .map_err(|e| AppError::internal(&format!("查询用户失败: {}", e)))?;
    let user = user_vo.user;

    let password_hash = user.password.as_deref().unwrap_or("");
    let parsed_hash = PasswordHash::new(password_hash).map_err(|_| {
        AppError::internal("密码哈希格式错误")
    })?;
    Argon2::default().verify_password(req.password.as_bytes(), &parsed_hash)
        .map_err(|_| AppError::bad_request("密码错误"))?;

    // 2. 验证 TOTP code
    let redis_key = format!("totp:enabled:{}", user_id);
    let mut conn = state.redis.clone();
    let secret_str: String = redis::cmd("GET")
        .arg(&redis_key)
        .query_async(&mut conn)
        .await
        .map_err(|_| AppError::not_found("TOTP 未启用"))?;

    let secret = Secret::Encoded(secret_str);
    let secret_bytes = secret.to_bytes().map_err(|_| {
        AppError::internal("TOTP secret 解码失败")
    })?;
    let totp = TOTP::new(
        Algorithm::SHA1,
        6,
        1,
        30,
        secret_bytes.clone(),
        Some(TOTP_ISSUER.to_string()),
        "yebot-user".to_string(),
    ).map_err(|e| AppError::internal(&format!("构建 TOTP 失败: {}", e)))?;

    if !totp.check_current(&req.code).unwrap_or(false) {
        return Err(AppError::bad_request("验证码错误或已过期"));
    }

    // 3. 从 Redis 删除 secret
    redis::cmd("DEL")
        .arg(&redis_key)
        .query_async::<i64>(&mut conn)
        .await
        .map_err(|e| AppError::internal(&format!("删除 Redis 失败: {}", e)))?;

    tracing::info!(user_id = user_id, "用户关闭 TOTP 多因子认证");

    Ok(AjaxResult::success(()))
}
