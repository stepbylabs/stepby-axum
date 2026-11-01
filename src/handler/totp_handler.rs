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

/// `totp:enabled:{user_id}` 读取结果的**唯一映射点**（b144 A1）。
///
/// ## 为什么必须有单一实现
///
/// 「没有启用」与「读不出有没有启用」是两种事实：前者是业务态（404 未启用，用户可以去
/// 启用），后者是服务态（503，用户什么都做不了，只能等或找运维）。改造前三处调用点各有
/// 一套口径——`status` 与 `verify` 把同一个读失败映射成 503
/// `error.totp.status_check_failed`，而 `disable` 把它映射成 404
/// `error.totp.not_enabled`：Redis 抖动时用户看到"你本来就没开 2FA"，而 2FA 实际仍在
/// 生效，关闭 MFA 这个动作于是**静默失败**（用户以为已经关掉，下次登录仍被要求验证码）。
/// 判据不能散在三个 handler 里各写一遍（同 AGENTS C.8 错误契约、C.10 敏感操作口径）。
///
/// 返回值刻意保留 `Option`：**只有** `Ok(None)` 才代表"确实未启用"，调用方据此再决定
/// 是 `is_some()`（status/verify 的存在性判定）还是 `ok_or_else(not_found)`（disable 需要
/// 取出 secret 本体）。
fn map_enabled_lookup(
    result: Result<Option<String>, crate::shared_store::StoreError>,
    user_id: i64,
    operation: &str,
) -> Result<Option<String>, AppError> {
    result.map_err(|e| {
        tracing::error!(
            error = %e,
            user_id = user_id,
            operation = operation,
            "TOTP enabled 键读取失败（fail-closed 返回 503，不伪装成未启用）"
        );
        AppError::new(503, crate::tr!("error.totp.status_check_failed"))
    })
}

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
        // b83（AGENTS C.8/C.10）：文案本身就是"请 10 分钟后再试"⇒ 这是"稍后再试"，
        // 不是"你的请求有问题"。此前用 400 呈现，客户端与监控都无法区分
        // "参数错"与"被锁定"，只能靠猜来退避。剩余秒数取键的真实 TTL（读不到回落窗口上限）。
        let retry = crate::shared_store::lockout_retry_after_secs(
            state.store.as_ref(),
            &fail_key,
            TOTP_FAIL_TTL_SECS,
        )
        .await;
        return Err(
            AppError::new(429, crate::tr!("error.totp.login_locked")).with_retry_after(retry)
        );
    }

    // 2. 已启用检查：已启用用户必须走 disable 后再重新绑定，防止 MFA 被接管
    //    （原 EXISTS → get().is_some()，共享态存储均为 string KV，语义等价）
    let enabled_key = format!("totp:enabled:{}", user_id);
    let enabled =
        map_enabled_lookup(state.store.get(&enabled_key).await, user_id, "verify")?.is_some();
    if enabled {
        return Err(AppError::bad_request(&crate::tr!(
            "error.totp.already_enabled"
        )));
    }

    // 3. 读取 pending secret（setup 时服务端生成并加密缓存）
    let pending_key = format!("totp:pending:{}", user_id);
    let encrypted = state.store.get(&pending_key).await.map_err(|e| {
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
        if let Err(err) = state
            .store
            .incr_with_ttl(&fail_key, TOTP_FAIL_TTL_SECS)
            .await
        {
            tracing::warn!(error = ?err, "TOTP 失败计数写入失败（防暴力限流降级）");
        }
        return Err(AppError::bad_request(&crate::tr!(
            "error.totp.code_invalid"
        )));
    }

    // 5. 删除 pending，加密写入 enabled（启用 TOTP）
    if let Err(err) = state.store.del(std::slice::from_ref(&pending_key)).await {
        tracing::debug!(error = ?err, "TOTP pending 键删除失败（键会随 TTL 过期，不阻断启用）");
    }
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
    // b144 A1：映射口径收进 `map_enabled_lookup` 单一实现（disable 曾把同一故障报成 404）。
    let enabled =
        map_enabled_lookup(state.store.get(&redis_key).await, user_id, "status")?.is_some();

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
        // 与 verify 分支同口径（同一计数键、同一窗口）：429 + Retry-After，不再以 400 呈现。
        let retry = crate::shared_store::lockout_retry_after_secs(
            state.store.as_ref(),
            &fail_key,
            TOTP_FAIL_TTL_SECS,
        )
        .await;
        return Err(
            AppError::new(429, crate::tr!("error.totp.login_locked")).with_retry_after(retry)
        );
    }

    // 1. 验证密码（从数据库查询用户密码并校验；参数实现在 `utils::password`，此处只解析）
    use argon2::PasswordHash;
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
    // 先解析一次：存储侧哈希串本身不可解析属**服务端数据问题**（500），不能伪装成"密码错误"
    PasswordHash::new(password_hash)
        .map_err(|_| AppError::internal(&crate::tr!("error.totp.password_hash_invalid")))?;
    // 校验走 `utils::password` 统一入口——Argon2 参数的唯一实现点与凭据校验指标的唯一记录点。
    // 这里刻意再解析一遍：解析是微秒级，相比 Argon2 的几十毫秒可忽略，换来"参数只有一处"。
    if !crate::utils::password::verify_password(&req.password, password_hash) {
        if let Err(err) = state
            .store
            .incr_with_ttl(&fail_key, TOTP_FAIL_TTL_SECS)
            .await
        {
            tracing::warn!(error = ?err, "TOTP 失败计数写入失败（防暴力限流降级）");
        }
        return Err(AppError::bad_request(&crate::tr!(
            "error.totp.password_wrong"
        )));
    }

    // 2. 取已启用的 secret
    //    b144 A1：读失败一律 503（口径与 status/verify 同源）。改造前这里是
    //    `map_err(|_| not_found("未启用"))`——Redis 抖动时"关闭 2FA"这个动作静默失败，
    //    用户以为已经关掉，下次登录照旧被要求验证码，而屏幕上写的是"你根本没启用"。
    let redis_key = format!("totp:enabled:{}", user_id);
    let encrypted_secret =
        map_enabled_lookup(state.store.get(&redis_key).await, user_id, "disable")?
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
        if let Err(err) = state
            .store
            .incr_with_ttl(&fail_key, TOTP_FAIL_TTL_SECS)
            .await
        {
            tracing::warn!(error = ?err, "TOTP 失败计数写入失败（防暴力限流降级）");
        }
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

#[cfg(test)]
mod tests {
    use crate::common::prod_scan::{Scan, prod_file};

    fn silent_state_drop_lines(text: &str) -> Vec<usize> {
        text.lines()
            .enumerate()
            .filter(|(_, line)| line.contains("let _ = state"))
            .map(|(i, _)| i + 1)
            .collect()
    }

    /// b91：TOTP 的三处失败计数是防暴力的 best-effort 写。写失败不阻断业务是对的，
    /// 但**必须留痕**——否则限流降级时运维只会看到"验证码总是错"，看不到存储故障。
    /// pending 删除失败只记 DEBUG（键会随 TTL 过期，不构成安全面）。
    #[test]
    fn totp_best_effort_writes_must_leave_a_trace() {
        let text = prod_file("src/handler/totp_handler.rs", &Scan::default()).text();
        let hits = silent_state_drop_lines(&text);
        assert!(hits.is_empty(), "TOTP 写失败不得静默，命中行: {hits:?}");
        assert_eq!(
            text.matches("TOTP 失败计数写入失败").count(),
            3,
            "三处失败计数都必须留痕（少一处就是有一条分支降级无人知）"
        );
        assert_eq!(
            text.matches("TOTP pending 键删除失败").count(),
            1,
            "pending 删除失败必须留 DEBUG 痕"
        );
        assert!(
            text.matches("incr_with_ttl(&fail_key").count() >= 3,
            "采集面里必须能看到三处失败计数调用"
        );
        assert!(
            text.contains(".del(std::slice::from_ref(&pending_key))"),
            "采集面里必须能看到 pending 删除调用"
        );

        // 合成双向
        assert_eq!(
            silent_state_drop_lines("let _ = state\n    .store"),
            vec![1]
        );
        assert!(silent_state_drop_lines("if let Err(err) = state\n    .store").is_empty());
    }

    /// 「存储故障 → 404 未启用」这一形状必须全仓不存在（b144 A1）。
    ///
    /// 判据取 `map_err(` 起往后 200 字符窗口内是否出现 `error.totp.not_enabled`：
    /// 404 只能由 `Ok(None)`（确实没启用）产生，不能由 `Err`（读不出来）产生。
    fn store_error_mapped_to_not_enabled(text: &str) -> usize {
        let stripped: Vec<&str> = text
            .lines()
            .filter(|l| !l.trim_start().starts_with("//"))
            .collect();
        let flat: String = stripped
            .join("\n")
            .chars()
            .map(|c| if c.is_whitespace() { ' ' } else { c })
            .collect();
        let needle = "map_err(";
        let mut hits = 0usize;
        let mut from = 0usize;
        while let Some(rel) = flat[from..].find(needle) {
            let abs = from + rel;
            let window: String = flat[abs..].chars().take(200).collect();
            if window.contains("error.totp.not_enabled") {
                hits += 1;
            }
            from = abs + needle.len();
        }
        hits
    }

    /// enabled 键的直接读取（不经映射点）逐行点名——"存在一次映射调用"不能证明
    /// **每个**读取点都接了线（b134 的"存在一次 ≠ 每个入口"在 handler 面上的断面）。
    fn enabled_reads_bypassing_the_mapping(text: &str) -> Vec<String> {
        text.lines()
            .filter(|l| !l.trim_start().starts_with("//"))
            .filter(|l| l.contains(".get(&enabled_key)") || l.contains(".get(&redis_key)"))
            .filter(|l| !l.contains("map_enabled_lookup("))
            .map(|l| l.trim().to_string())
            .collect()
    }

    /// `enabled` 键的读取口径必须只有 `map_enabled_lookup` 一处实现：
    /// 三个调用点全部经它，且旧的"Err 折成 404"形状必须不存在（含活性正控）。
    #[test]
    fn enabled_key_lookup_has_a_single_fail_closed_mapping() {
        let text = prod_file("src/handler/totp_handler.rs", &Scan::default()).text();

        // 1) 唯一实现 + 三个调用点（status / verify / disable）
        assert_eq!(
            text.matches("map_enabled_lookup(").count(),
            4,
            "enabled 键读取必须经 map_enabled_lookup 单一映射点（定义 1 + 调用 3）"
        );
        let unwired = enabled_reads_bypassing_the_mapping(&text);
        assert!(
            unwired.is_empty(),
            "所有 enabled 键读取都必须走映射点，绕过者: {unwired:?}"
        );

        // 2) 真实树：Err → 404 的形状必须为 0 处
        assert_eq!(
            store_error_mapped_to_not_enabled(&text),
            0,
            "存储故障不得伪装成「未启用」"
        );

        // 3) 活性正控：缺陷形状必须被抓到
        let defective = r#"
            let secret = state
                .store
                .get(&redis_key)
                .await
                .map_err(|_| AppError::not_found(&crate::tr!("error.totp.not_enabled")))?
                .ok_or_else(|| AppError::not_found(&crate::tr!("error.totp.not_enabled")))?;
        "#;
        assert_eq!(
            store_error_mapped_to_not_enabled(defective),
            1,
            "把读失败折成 404 的旧形状必须被这条判据抓到（否则它就是虚锁）"
        );

        // 4) 反证：合规形状（Err → 503、None → 404）不得报
        let compliant = r#"
            let secret = map_enabled_lookup(state.store.get(&redis_key).await, user_id, "disable")?
                .ok_or_else(|| AppError::not_found(&crate::tr!("error.totp.not_enabled")))?;
        "#;
        assert_eq!(
            store_error_mapped_to_not_enabled(compliant),
            0,
            "None 分支给 404 是正确语义，不得判红"
        );

        // 5) 接线反查的活性：旧的裸读形状必须被点名
        assert_eq!(
            enabled_reads_bypassing_the_mapping(
                "let e = state.store.get(&redis_key).await.unwrap_or_default();"
            )
            .len(),
            1,
            "绕过映射点的裸读必须被抓到"
        );
    }
}
