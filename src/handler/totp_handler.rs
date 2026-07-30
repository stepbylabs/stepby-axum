//! TOTP 多因子认证 Handler
//!
//! 设计要点：
//! - TOTP secret 存储在 Redis（key: totp:enabled:{user_id}），加密方式：AES-256-GCM
//! - 使用 CONFIG_ENC_KEY 作为主密钥，通过 crate::utils::crypto::encrypt_config_value 加密
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
    let secret_bytes = secret.to_bytes().map_err(|_| {
        AppError::internal(&crate::tr!("error.totp.secret_gen_failed"))
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
    ).map_err(|_| AppError::internal(&crate::tr!("error.totp.totp_build_failed")))?;

    // 生成 otpauth URL（totp-rs v5.7+ get_url() 不再接受参数，
    // issuer/account_name 已在 TOTP::new 时绑定）
    let otpauth_url = totp.get_url();

    // 生成 QR 码（PNG bytes → base64 Data URL）
    // 直接复用 totp-rs 提供的 get_qr_png()，避免直接依赖 qrcodegen_image / image
    let png_bytes = totp.get_qr_png().map_err(|_| {
        AppError::internal(&crate::tr!("error.totp.qr_gen_failed"))
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
        .map_err(|_| AppError::internal(&crate::tr!("error.totp.user_id_parse_failed")))?;

    // 解码 Base32 secret
    let secret = Secret::Encoded(req.secret.clone());
    let secret_bytes = secret.to_bytes().map_err(|_| {
        AppError::bad_request(&crate::tr!("error.totp.secret_invalid"))
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
    ).map_err(|_| AppError::internal(&crate::tr!("error.totp.totp_build_failed")))?;

    // 验证 code（允许 ±1 步长窗口）
    if !totp.check_current(&req.code).unwrap_or(false) {
        return Err(AppError::bad_request(&crate::tr!("error.totp.code_invalid")));
    }

    // C2-3 安全修复：使用 AES-256-GCM 加密 TOTP secret 后存入 Redis
    // 原实现直接存储明文 secret，若 Redis 被入侵或快照泄露，攻击者可获取 TOTP secret 绕过 MFA
    let master_key = &state.config.config_enc_key;
    if master_key.is_empty() {
        tracing::error!("CONFIG_ENC_KEY 未配置，无法加密 TOTP secret（fail-closed 拒绝）");
        return Err(AppError::internal(&crate::tr!("error.totp.enc_key_missing")));
    }
    let encrypted_secret = crate::utils::crypto::encrypt_config_value(&req.secret, master_key)
        .map_err(|_| AppError::internal(&crate::tr!("error.totp.encrypt_failed")))?;

    // 将加密后的 secret 存入 Redis（启用 TOTP）
    let redis_key = format!("totp:enabled:{}", user_id);
    let mut conn = state.redis.clone();
    redis::cmd("SET")
        .arg(&redis_key)
        .arg(&encrypted_secret)
        .query_async::<String>(&mut conn)
        .await
        .map_err(|_| AppError::internal(&crate::tr!("error.totp.redis_write_failed")))?;

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
        .map_err(|_| AppError::internal(&crate::tr!("error.totp.user_id_parse_failed")))?;

    let redis_key = format!("totp:enabled:{}", user_id);
    let mut conn = state.redis.clone();
    // P2 修复: 原 unwrap_or(false) 为 fail-open，Redis 故障时误报 TOTP 未启用，
    // 可能导致前端跳过 MFA 验证流程。改为 fail-closed：Redis 故障时返回 503。
    let exists: bool = redis::cmd("EXISTS")
        .arg(&redis_key)
        .query_async(&mut conn)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, user_id = user_id, "TOTP status: Redis EXISTS 失败，fail-closed 返回 503");
            AppError::new(503, crate::tr!("error.totp.status_check_failed"))
        })?;

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
        .map_err(|_| AppError::internal(&crate::tr!("error.totp.user_id_parse_failed")))?;

    // 1. 验证密码（从数据库查询用户密码并校验）
    use argon2::{Argon2, PasswordHash, PasswordVerifier};
    let user_vo = state.user_service.get_user_by_id(user_id).await
        .map_err(|_| AppError::internal(&crate::tr!("error.totp.user_query_failed")))?;
    let user = user_vo.user;

    let password_hash = user.password.as_deref().unwrap_or("");
    let parsed_hash = PasswordHash::new(password_hash).map_err(|_| {
        AppError::internal(&crate::tr!("error.totp.password_hash_invalid"))
    })?;
    Argon2::default().verify_password(req.password.as_bytes(), &parsed_hash)
        .map_err(|_| AppError::bad_request(&crate::tr!("error.totp.password_wrong")))?;

    // 2. 验证 TOTP code
    let redis_key = format!("totp:enabled:{}", user_id);
    let mut conn = state.redis.clone();
    let encrypted_secret: String = redis::cmd("GET")
        .arg(&redis_key)
        .query_async(&mut conn)
        .await
        .map_err(|_| AppError::not_found(&crate::tr!("error.totp.not_enabled")))?;

    // C2-3 安全修复：解密从 Redis 读取的 TOTP secret
    let master_key = &state.config.config_enc_key;
    if master_key.is_empty() {
        tracing::error!("CONFIG_ENC_KEY 未配置，无法解密 TOTP secret（fail-closed 拒绝）");
        return Err(AppError::internal(&crate::tr!("error.totp.enc_key_missing")));
    }
    // decrypt_config_value 兼容明文（不带 enc: 前缀直接返回），支持旧数据平滑迁移
    let secret_str = crate::utils::crypto::decrypt_config_value(&encrypted_secret, master_key)
        .map_err(|_| AppError::internal(&crate::tr!("error.totp.decrypt_failed")))?;

    let secret = Secret::Encoded(secret_str);
    let secret_bytes = secret.to_bytes().map_err(|_| {
        AppError::internal(&crate::tr!("error.totp.secret_decode_failed"))
    })?;
    let totp = TOTP::new(
        Algorithm::SHA1,
        6,
        1,
        30,
        secret_bytes.clone(),
        Some(TOTP_ISSUER.to_string()),
        "yebot-user".to_string(),
    ).map_err(|_| AppError::internal(&crate::tr!("error.totp.totp_build_failed")))?;

    if !totp.check_current(&req.code).unwrap_or(false) {
        return Err(AppError::bad_request(&crate::tr!("error.totp.code_invalid")));
    }

    // 3. 从 Redis 删除 secret
    redis::cmd("DEL")
        .arg(&redis_key)
        .query_async::<i64>(&mut conn)
        .await
        .map_err(|_| AppError::internal(&crate::tr!("error.totp.redis_delete_failed")))?;

    tracing::info!(user_id = user_id, "用户关闭 TOTP 多因子认证");

    Ok(AjaxResult::success(()))
}
