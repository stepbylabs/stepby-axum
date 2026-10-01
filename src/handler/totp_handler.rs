//! TOTP 多因子认证 Handler
//!
//! 设计要点：
//! - TOTP secret 存储在共享态存储（key: totp:enabled:{user_id}），加密方式：AES-256-GCM
//! - 使用 CONFIG_ENC_KEY 作为主密钥，通过 crate::utils::crypto::encrypt_config_value 加密
//! - 集成 totp-rs crate 生成和验证 TOTP 6 位代码
//! - 流程：setup（生成 secret + QR）→ verify（验证 code 启用）→ disable（关闭）

use std::sync::Arc;

use axum::Json;
use axum::extract::State;
use base64::Engine;
use garde::Validate;
use serde::{Deserialize, Serialize};
use totp_rs::{Algorithm, Builder, Secret};
use utoipa::ToSchema;

use crate::common::{AjaxResult, AppError};
use crate::middleware::Operator;
use crate::state::AppState;

const TOTP_ISSUER: &str = "Stepby";

/// pending secret 缓存 TTL（秒，10 分钟）：setup 后需在有效期内完成 verify
const TOTP_PENDING_TTL_SECS: u64 = 600;
/// verify / disable 验证码失败次数上限（10 分钟窗口，防暴力枚举）
const MAX_TOTP_VERIFY_FAIL: i64 = 5;
/// 失败计数 TTL（秒，10 分钟）
const TOTP_FAIL_TTL_SECS: u64 = 600;
/// enabled 键写入 TTL（秒，10 年）
///
/// 原实现为无 TTL 永久键（SET）；trait 仅提供 `set_ex`（必带 TTL），以远超业务
/// 生命周期（MFA 绑定的人工更换周期）的超长 TTL 等价承载，disable 时主动删除。
const TOTP_ENABLED_TTL_SECS: u64 = 10 * 365 * 24 * 3600;

// 原子化失败计数脚本（原 TOTP_FAIL_SCRIPT：INCR + 首次 EXPIRE，防计数永不过期）
// 已收敛为 `store.incr_with_ttl(key, ttl)`（与原脚本语义逐字等价，实现封入 shared_store）。

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

#[derive(Debug, Deserialize, Validate, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct TotpVerifyRequest {
    /// 用户输入的 6 位 TOTP 验证码
    #[garde(length(min = 6, max = 6))]
    pub code: String,
    /// setup 阶段返回的 secret
    #[garde(length(min = 1, max = 128))]
    pub secret: String,
}

#[derive(Debug, Deserialize, Validate, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct TotpDisableRequest {
    /// 用户密码（确认身份）
    #[garde(length(min = 1, max = 64))]
    pub password: String,
    /// 6 位 TOTP 验证码（防止会话被劫后关闭 TOTP）
    #[garde(length(min = 6, max = 6))]
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
#[utoipa::path(
    post,
    path = "/system/user/totp/setup",
    responses(
        (status = 200, description = "TOTP secret + otpauth URL + 二维码", body = AjaxResult<TotpSetupResponse>),
        (status = 500, description = "服务端密钥生成/Redis 写入失败"),
    ),
    tag = "auth"
)]
pub async fn setup(
    State(state): State<Arc<AppState>>,
    operator: Operator,
) -> Result<AjaxResult<TotpSetupResponse>, AppError> {
    let user_id: i64 = operator
        .user_id()
        .parse()
        .map_err(|_| AppError::internal(&crate::tr!("error.totp.user_id_parse_failed")))?;

    // 生成随机 secret（totp-rs 6 新 API：Secret::generate + Builder）
    let secret = Secret::generate();

    // 构建 TOTP 对象
    let totp = Builder::new()
        .with_algorithm(Algorithm::SHA1)
        .with_digits(6)
        .with_skew(1)
        .with_step_duration(30)
        .with_secret(secret.clone())
        .with_issuer(Some(TOTP_ISSUER))
        .with_account_name("stepby-user")
        .build()
        .map_err(|_| AppError::internal(&crate::tr!("error.totp.totp_build_failed")))?;

    // 生成 otpauth URL（issuer/account_name 已在 Builder 绑定）
    // totp-rs 6：to_url() 返回 Result（get_url 的非 Result 旧签名已废弃）
    let otpauth_url = totp
        .to_url()
        .map_err(|_| AppError::internal(&crate::tr!("error.totp.totp_build_failed")))?;

    // 生成 QR 码（PNG bytes → base64 Data URL）
    // 直接复用 totp-rs 提供的 get_qr_png()，避免直接依赖 qrcodegen_image / image
    let png_bytes = totp
        .to_qr_png()
        .map_err(|_| AppError::internal(&crate::tr!("error.totp.qr_gen_failed")))?;
    let b64 = base64::engine::general_purpose::STANDARD.encode(&png_bytes);
    let qr_code = format!("data:image/png;base64,{}", b64);

    let secret_str = secret.to_base32();

    // P0-4 安全修复：服务端缓存 pending secret（绑定当前用户），verify 时校验一致，
    // 杜绝"客户端自报 secret+code 自签通过"的绕过。TTL 10 分钟，超时需重新 setup。
    let master_key = &state.config.config_enc_key;
    if master_key.is_empty() {
        tracing::error!("CONFIG_ENC_KEY 未配置，无法缓存 TOTP secret（fail-closed 拒绝）");
        return Err(AppError::internal(&crate::tr!(
            "error.totp.enc_key_missing"
        )));
    }
    let encrypted_secret = crate::utils::crypto::encrypt_config_value(&secret_str, master_key)
        .map_err(|_| AppError::internal(&crate::tr!("error.totp.encrypt_failed")))?;
    let pending_key = format!("totp:pending:{}", user_id);
    state
        .store
        .set_ex(&pending_key, &encrypted_secret, TOTP_PENDING_TTL_SECS)
        .await
        .map_err(|_| AppError::internal(&crate::tr!("error.totp.redis_write_failed")))?;

    Ok(AjaxResult::success(TotpSetupResponse {
        secret: secret_str,
        otpauth_url,
        qr_code,
    }))
}

/// POST /system/user/totp/verify
/// 验证 TOTP 验证码并启用 TOTP
///
/// 流程（P0-4 安全修复）：
/// 1. 从 Claims 获取 user_id
/// 2. 读取服务端缓存的 pending secret（setup 时生成并绑定用户；缺失/过期 → 400）
/// 3. 校验验证码必须与 pending secret 匹配（拒绝客户端自报 secret 的自签绕过）
/// 4. 已启用 TOTP 的用户不可重复 verify（防攻击者覆盖接管 MFA，需先 disable）
/// 5. 验证通过则删除 pending，将 secret 加密存入 Redis（key: totp:enabled:{user_id}）
/// 6. 失败限流：10 分钟窗口 ≥5 次失败锁定
#[utoipa::path(
    post,
    path = "/system/user/totp/verify",
    request_body = TotpVerifyRequest,
    responses(
        (status = 200, description = "验证通过并启用 TOTP", body = AjaxResult<serde_json::Value>),
        (status = 400, description = "验证码错误 / pending 已过期 / 已启用"),
        (status = 503, description = "Redis 查询失败（fail-closed）"),
    ),
    tag = "auth"
)]
pub async fn verify(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    Json(req): Json<TotpVerifyRequest>,
) -> Result<AjaxResult<()>, AppError> {
    crate::common::i18n::validate(&req)?;
    let user_id: i64 = operator
        .user_id()
        .parse()
        .map_err(|_| AppError::internal(&crate::tr!("error.totp.user_id_parse_failed")))?;

    // 1. 失败限流检查（防暴力枚举）
    let fail_key = format!("totp:verify_fail:{}", user_id);
    let fail_count = state
        .store
        .get(&fail_key)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, user_id = user_id, "TOTP verify 失败计数查询失败（fail-closed）");
            AppError::new(503, crate::tr!("error.totp.status_check_failed"))
        })?
        .and_then(|v| v.parse::<i64>().ok());
    if let Some(count) = fail_count
        && count >= MAX_TOTP_VERIFY_FAIL
    {
        return Err(AppError::bad_request(&crate::tr!(
            "error.totp.login_locked"
        )));
    }

    // 2. 已启用检查：已启用用户必须走 disable 后再重新绑定，防止 MFA 被接管
    //    （原 EXISTS → get().is_some()，共享态存储均为 string KV，语义等价）
    let enabled_key = format!("totp:enabled:{}", user_id);
    let enabled = state
        .store
        .get(&enabled_key)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, user_id = user_id, "TOTP enabled 查询失败（fail-closed）");
            AppError::new(503, crate::tr!("error.totp.status_check_failed"))
        })?
        .is_some();
    if enabled {
        return Err(AppError::bad_request(&crate::tr!(
            "error.totp.already_enabled"
        )));
    }

    // 3. 读取 pending secret（setup 时服务端生成并加密缓存）
    let pending_key = format!("totp:pending:{}", user_id);
    let encrypted = state
        .store
        .get(&pending_key)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, user_id = user_id, "TOTP pending 查询失败（fail-closed）");
            AppError::new(503, crate::tr!("error.totp.status_check_failed"))
        })?;
    let encrypted = encrypted
        .ok_or_else(|| AppError::bad_request(&crate::tr!("error.totp.pending_expired")))?;

    let master_key = &state.config.config_enc_key;
    if master_key.is_empty() {
        tracing::error!("CONFIG_ENC_KEY 未配置，无法解密 TOTP secret（fail-closed 拒绝）");
        return Err(AppError::internal(&crate::tr!(
            "error.totp.enc_key_missing"
        )));
    }
    let secret_str = crate::utils::crypto::decrypt_config_value(&encrypted, master_key)
        .map_err(|_| AppError::internal(&crate::tr!("error.totp.decrypt_failed")))?;

    // 4. 用 pending secret 校验验证码（不再信任客户端自报 secret）
    let secret = Secret::try_from_base32(&secret_str)
        .map_err(|_| AppError::bad_request(&crate::tr!("error.totp.secret_invalid")))?;
    let totp = Builder::new()
        .with_algorithm(Algorithm::SHA1)
        .with_digits(6)
        .with_skew(1)
        .with_step_duration(30)
        .with_secret(secret)
        .with_issuer(Some(TOTP_ISSUER))
        .with_account_name("stepby-user")
        .build()
        .map_err(|_| AppError::internal(&crate::tr!("error.totp.totp_build_failed")))?;

    if totp.check_current(&req.code).is_none() {
        // 失败计数（best-effort：incr_with_ttl 原子 INCR + 首次 EXPIRE，失败不阻断）
        let _ = state
            .store
            .incr_with_ttl(&fail_key, TOTP_FAIL_TTL_SECS)
            .await
            .unwrap_or(0);
        return Err(AppError::bad_request(&crate::tr!(
            "error.totp.code_invalid"
        )));
    }

    // 5. 删除 pending，加密写入 enabled（启用 TOTP）
    let _ = state
        .store
        .del(std::slice::from_ref(&pending_key))
        .await
        .unwrap_or(0);
    let encrypted_enabled = crate::utils::crypto::encrypt_config_value(&secret_str, master_key)
        .map_err(|_| AppError::internal(&crate::tr!("error.totp.encrypt_failed")))?;
    state
        .store
        .set_ex(&enabled_key, &encrypted_enabled, TOTP_ENABLED_TTL_SECS)
        .await
        .map_err(|_| AppError::internal(&crate::tr!("error.totp.redis_write_failed")))?;

    tracing::info!(user_id = user_id, "用户启用 TOTP 多因子认证");

    Ok(AjaxResult::success(()))
}

/// GET /system/user/totp/status
/// 查询当前用户是否已启用 TOTP
#[utoipa::path(
    get,
    path = "/system/user/totp/status",
    responses(
        (status = 200, description = "是否已启用 TOTP", body = AjaxResult<TotpStatusResponse>),
        (status = 503, description = "Redis 查询失败（fail-closed）"),
    ),
    tag = "auth"
)]
pub async fn status(
    State(state): State<Arc<AppState>>,
    operator: Operator,
) -> Result<AjaxResult<TotpStatusResponse>, AppError> {
    let user_id: i64 = operator
        .user_id()
        .parse()
        .map_err(|_| AppError::internal(&crate::tr!("error.totp.user_id_parse_failed")))?;

    let redis_key = format!("totp:enabled:{}", user_id);
    // P2 修复: 原 unwrap_or(false) 为 fail-open，存储故障时误报 TOTP 未启用，
    // 可能导致前端跳过 MFA 验证流程。改为 fail-closed：故障时返回 503。
    // （原 EXISTS → get().is_some()，共享态存储均为 string KV，语义等价）
    let enabled = state
        .store
        .get(&redis_key)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, user_id = user_id, "TOTP status: 键存在性查询失败，fail-closed 返回 503");
            AppError::new(503, crate::tr!("error.totp.status_check_failed"))
        })?
        .is_some();

    Ok(AjaxResult::success(TotpStatusResponse { enabled }))
}

/// POST /system/user/totp/disable
/// 关闭 TOTP（需要密码 + 验证码双重验证）
#[utoipa::path(
    post,
    path = "/system/user/totp/disable",
    request_body = TotpDisableRequest,
    responses(
        (status = 200, description = "已关闭 TOTP", body = AjaxResult<serde_json::Value>),
        (status = 400, description = "密码或验证码错误 / 未启用 TOTP"),
        (status = 503, description = "Redis 查询失败（fail-closed）"),
    ),
    tag = "auth"
)]
pub async fn disable(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    Json(req): Json<TotpDisableRequest>,
) -> Result<AjaxResult<()>, AppError> {
    crate::common::i18n::validate(&req)?;
    let user_id: i64 = operator
        .user_id()
        .parse()
        .map_err(|_| AppError::internal(&crate::tr!("error.totp.user_id_parse_failed")))?;

    // P0-4：失败限流检查（密码/TOTP 码错误均计数，10 分钟 ≥5 次锁定）
    let fail_key = format!("totp:disable_fail:{}", user_id);
    let fail_count = state
        .store
        .get(&fail_key)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, user_id = user_id, "TOTP disable 失败计数查询失败（fail-closed）");
            AppError::new(503, crate::tr!("error.totp.status_check_failed"))
        })?
        .and_then(|v| v.parse::<i64>().ok());
    if let Some(count) = fail_count
        && count >= MAX_TOTP_VERIFY_FAIL
    {
        return Err(AppError::bad_request(&crate::tr!(
            "error.totp.login_locked"
        )));
    }

    // 1. 验证密码（从数据库查询用户密码并校验）
    use argon2::{Argon2, PasswordHash, PasswordVerifier};
    let user_vo = state
        .user_service
        .get_user_by_id(user_id)
        .await
        .map_err(|_| AppError::internal(&crate::tr!("error.totp.user_query_failed")))?;
    let user = user_vo.user;

    // P0-4 修复：密码为空时直接返回"密码错误"（原实现 PasswordHash::new("") 返回 500）
    let password_hash = user.password.as_deref().unwrap_or("");
    if password_hash.is_empty() {
        return Err(AppError::bad_request(&crate::tr!(
            "error.totp.password_wrong"
        )));
    }
    let parsed_hash = PasswordHash::new(password_hash)
        .map_err(|_| AppError::internal(&crate::tr!("error.totp.password_hash_invalid")))?;
    if Argon2::default()
        .verify_password(req.password.as_bytes(), &parsed_hash)
        .is_err()
    {
        let _ = state
            .store
            .incr_with_ttl(&fail_key, TOTP_FAIL_TTL_SECS)
            .await
            .unwrap_or(0);
        return Err(AppError::bad_request(&crate::tr!(
            "error.totp.password_wrong"
        )));
    }

    // 2. 验证 TOTP code
    let redis_key = format!("totp:enabled:{}", user_id);
    // 键不存在（未启用）与读取失败均收敛为 404（与原 GET nil → not_found 口径一致）
    let encrypted_secret = state
        .store
        .get(&redis_key)
        .await
        .map_err(|_| AppError::not_found(&crate::tr!("error.totp.not_enabled")))?
        .ok_or_else(|| AppError::not_found(&crate::tr!("error.totp.not_enabled")))?;

    // C2-3 安全修复：解密从 Redis 读取的 TOTP secret
    let master_key = &state.config.config_enc_key;
    if master_key.is_empty() {
        tracing::error!("CONFIG_ENC_KEY 未配置，无法解密 TOTP secret（fail-closed 拒绝）");
        return Err(AppError::internal(&crate::tr!(
            "error.totp.enc_key_missing"
        )));
    }
    // decrypt_config_value 兼容明文（不带 enc: 前缀直接返回），支持旧数据平滑迁移
    let secret_str = crate::utils::crypto::decrypt_config_value(&encrypted_secret, master_key)
        .map_err(|_| AppError::internal(&crate::tr!("error.totp.decrypt_failed")))?;

    let secret = Secret::try_from_base32(&secret_str)
        .map_err(|_| AppError::internal(&crate::tr!("error.totp.secret_decode_failed")))?;
    let totp = Builder::new()
        .with_algorithm(Algorithm::SHA1)
        .with_digits(6)
        .with_skew(1)
        .with_step_duration(30)
        .with_secret(secret)
        .with_issuer(Some(TOTP_ISSUER))
        .with_account_name("stepby-user")
        .build()
        .map_err(|_| AppError::internal(&crate::tr!("error.totp.totp_build_failed")))?;

    if totp.check_current(&req.code).is_none() {
        // P0-4：失败计数（防暴力枚举；best-effort，失败不阻断）
        let _ = state
            .store
            .incr_with_ttl(&fail_key, TOTP_FAIL_TTL_SECS)
            .await
            .unwrap_or(0);
        return Err(AppError::bad_request(&crate::tr!(
            "error.totp.code_invalid"
        )));
    }

    // 3. 从共享态存储删除 secret
    state
        .store
        .del(std::slice::from_ref(&redis_key))
        .await
        .map_err(|_| AppError::internal(&crate::tr!("error.totp.redis_delete_failed")))?;

    tracing::info!(user_id = user_id, "用户关闭 TOTP 多因子认证");

    Ok(AjaxResult::success(()))
}
