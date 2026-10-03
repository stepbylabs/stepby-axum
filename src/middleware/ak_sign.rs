// stepby-axum/src/middleware/ak_sign.rs
//! 开放 API AK/SK 签名中间件（HMAC-SHA256 请求签名）
//!
//! 面向第三方/脚本机器调用：以 `access_key` 标识 + `secret_key` 签名替代 Bearer 令牌。
//!
//! # 协议
//!
//! 请求头：
//! - `X-CA-Key`：access_key（"ak" + 24 hex）
//! - `X-CA-Timestamp`：Unix 秒（±300s 窗口，防重放的第一道）
//! - `X-CA-Nonce`：UUID 等一次性随机串（SharedStore `set_nx_ex` 一次性抢占，防重放第二道）
//! - `X-CA-Signature`：hex(HMAC-SHA256(SK, string_to_sign))
//!
//! string_to_sign（各段以 "\n" 连接）：
//! `METHOD + "\n" + PATH + "\n" + TIMESTAMP + "\n" + NONCE + "\n" + hex(SHA256(body))`
//!
//! # 安全设计
//!
//! - SK 存储：AES-256-GCM v2 信封加密（`seal_sensitive_value`，与 oauth client_secret
//!   同机制）——验签需要 SK 原文参与 HMAC，故采用**可逆**信封加密而非单向哈希；
//! - 验签先于 nonce 消耗：错签请求不烧毁 nonce，防止攻击者用垃圾请求 DoS 受害者的 nonce 槽；
//! - 签名比较 constant-time（逐字节异或累积，与 subtle crate 的 ConstantTimeEq 语义一致）；
//! - 属主存活校验与 `verify_token`（PAT Bearer 链路）同口径：属主删除/停用 → 立即失效；
//! - 组件内建 Prometheus 指标：请求总量 / 耗时直方图 / 验签失败计数
//!   （经 `observability::metrics::MetricsRegistry` 既有注册范式输出到 /metrics）；
//! - 失败响应统一契约：`401 {"code":401,"msg":"<error.ak.* 本地化文案>"}`。
//!
//! # 挂载方式
//!
//! `ak_protected_routes()` 返回自带 `ak_sign_middleware` 的 Router（`Router<Arc<AppState>>`），
//! 由 router/mod.rs 主线程 merge。注意：AK 签名本身就是鉴权凭据，**不得**再叠加
//! auth_middleware（无 Bearer 会被其 401 拦截），应与公开路由同层挂载。

use axum::Router;
use axum::body::Body;
use axum::extract::{Request, State};
use axum::middleware::Next;
use axum::response::Response;
use axum::routing::get;
use hmac::{Hmac, KeyInit, Mac};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use std::time::Instant;

use crate::common::error::AppError;
use crate::service::sys_pat_service::{AkLookup, VerifiedAk};
use crate::state::AppState;

/// 时间戳允许窗口（±300 秒）：容纳时钟偏移的同时限制签名重放窗口
const TIMESTAMP_WINDOW_SECS: i64 = 300;

/// nonce 一次性槽位 TTL（秒）：须大于 2×时间戳窗口，保证窗口内重放必被拦截
const NONCE_TTL_SECS: u64 = 640;

/// AK 请求体读取上限（1 MiB）：开放 API 机器调用不需要更大报文
const MAX_AK_BODY_BYTES: usize = 1024 * 1024;

/// AK 验签通过后注入请求扩展的身份信息（供下游 handler 使用）
#[derive(Debug, Clone)]
pub struct AkIdentity {
    pub pat_id: String,
    pub user_id: i64,
    pub tenant_id: i64,
    pub access_key: String,
}

/// 签名验算（纯函数）：string_to_sign → HMAC-SHA256 hex
///
/// 公开给集成测试复用同一实现，避免测试自签一套算法造成口径漂移。
pub fn sign_string(secret: &str, string_to_sign: &str) -> String {
    let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(secret.as_bytes())
        .expect("HMAC 接受任意长度密钥，构造不会失败");
    mac.update(string_to_sign.as_bytes());
    crate::utils::crypto::hex_encode_digest(&mac.finalize().into_bytes())
}

/// SHA-256 hex（请求体摘要）
fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    crate::utils::crypto::hex_encode_digest(&hasher.finalize())
}

/// constant-time 字节串比较（等价 subtle::ConstantTimeEq 语义：逐字节异或累积，
/// 总耗时只与长度有关、与差异位置无关，防时序侧信道逐位猜签名）
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        // 长度差异本身公开无害（签名长度是固定协议常量）
        return false;
    }
    let mut diff: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// 验签失败构造宏：401 + 统一契约 body（code/msg，msg 为 error.ak.* 本地化文案），
/// 同时从 key 字面量派生指标失败原因标签（如 "error.ak.nonce_reused" → "nonce_reused"），
/// 保证标签与 i18n key 永远同步（单一来源）。
macro_rules! ak_fail {
    ($key:literal) => {{
        let outcome: &'static str = $key.strip_prefix("error.ak.").unwrap_or("unknown");
        (outcome, $crate::common::error::AppError::new(401, $crate::tr!($key)))
    }};
}

/// 验签结果（错误携带失败原因标签，供 Prometheus 失败计数归类）
type VerifyOutcome = Result<(VerifiedAk, Vec<u8>), (&'static str, AppError)>;

/// AK 签名中间件
///
/// 流程：读头 → 时间戳窗口 → 查库验凭据（status/过期/属主）→ 验签（constant-time）
/// → nonce 一次性抢占（SharedStore，禁止裸 Redis）→ 注入 AkIdentity → 放行。
/// 每请求记录组件指标（总量/耗时/失败原因）。
pub async fn ak_sign_middleware(
    State(state): State<Arc<AppState>>,
    req: Request,
    next: Next,
) -> Result<Response, AppError> {
    let started = Instant::now();
    let (mut parts, body) = req.into_parts();
    let path = parts.uri.path().to_string();

    // 统一出口：无论成败都记录（总量 / 耗时 / 失败原因）组件指标
    let result = verify_and_inject(&state, &mut parts, body).await;
    let (outcome, inner) = match result {
        Ok((verified, bytes)) => ("ok", Ok((verified, bytes))),
        Err((reason, err)) => (reason, Err(err)),
    };
    state
        .observability
        .metrics
        .record_ak_request(&path, outcome, started.elapsed().as_secs_f64());

    let (verified, body_bytes) = inner?;
    // best-effort 更新 PAT 最近使用时间（失败忽略，与 Bearer 链路同口径）
    let pat_id = verified.pat_id.clone();
    tokio::spawn(async move {
        state.pat_service.touch_last_used(&pat_id).await;
    });

    parts.extensions.insert(AkIdentity {
        pat_id: verified.pat_id,
        user_id: verified.user_id,
        tenant_id: verified.tenant_id,
        access_key: verified.access_key,
    });
    let req = Request::from_parts(parts, Body::from(body_bytes));
    Ok(next.run(req).await)
}

/// 验签主流程：全部通过则返回凭据 + 缓冲的请求体字节
///
/// Err 第一项为失败原因标签（与 i18n key 后缀一致），供指标计数归类。
async fn verify_and_inject(
    state: &Arc<AppState>,
    parts: &mut axum::http::request::Parts,
    body: Body,
) -> VerifyOutcome {
    // ---- 1. 提取请求头（缺失/非法统一按对应失败归类）----
    let ak_header = parts
        .headers
        .get("x-ca-key")
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| ak_fail!("error.ak.ak_not_found"))?
        .to_string();
    let ts_raw = parts
        .headers
        .get("x-ca-timestamp")
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| ak_fail!("error.ak.timestamp_out_of_window"))?
        .to_string();
    let nonce = parts
        .headers
        .get("x-ca-nonce")
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|s| !s.is_empty() && s.len() <= 128)
        .ok_or_else(|| ak_fail!("error.ak.invalid_signature"))?
        .to_string();
    let provided_sig = parts
        .headers
        .get("x-ca-signature")
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| ak_fail!("error.ak.invalid_signature"))?
        .to_string();

    // ---- 2. 时间戳窗口校验（防重放第一道）----
    let ts: i64 = ts_raw
        .parse()
        .map_err(|_| ak_fail!("error.ak.timestamp_out_of_window"))?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    if (now - ts).abs() > TIMESTAMP_WINDOW_SECS {
        return Err(ak_fail!("error.ak.timestamp_out_of_window"));
    }

    // ---- 3. 缓冲请求体（签名覆盖 body 摘要，必须先读出）----
    let body_bytes = axum::body::to_bytes(body, MAX_AK_BODY_BYTES)
        .await
        .map(|b| b.to_vec())
        .map_err(|_| {
            // body 不可读 → 无法计算摘要 → 无法验签，按签名无效处理
            ak_fail!("error.ak.invalid_signature")
        })?;

    // ---- 4. 查库校验凭据（状态 / 过期 / 属主存活，与 Bearer 链路同口径）----
    let lookup = state
        .pat_service
        .verify_ak(&ak_header, &state.config.config_enc_key)
        .await
        .map_err(|e| {
            // 查库故障：503 fail-closed（与 auth 链路的 auth_unavailable 同哲学）
            (
                "store_unavailable",
                AppError::new(503, crate::tr!("error.ak.store_unavailable")).with_source(e),
            )
        })?;
    let verified = match lookup {
        AkLookup::Valid(v) => v,
        AkLookup::NotFound => return Err(ak_fail!("error.ak.ak_not_found")),
        AkLookup::Revoked => return Err(ak_fail!("error.ak.ak_revoked")),
        AkLookup::Expired => return Err(ak_fail!("error.ak.expired")),
        AkLookup::OwnerDisabled => return Err(ak_fail!("error.ak.owner_disabled")),
    };

    // ---- 5. 验签（constant-time；错签不消耗 nonce，防 DoS nonce 槽位）----
    let string_to_sign = format!(
        "{}\n{}\n{}\n{}\n{}",
        parts.method.as_str(),
        parts.uri.path(),
        ts_raw,
        nonce,
        sha256_hex(&body_bytes)
    );
    let expected = sign_string(&verified.secret_plain, &string_to_sign);
    if !constant_time_eq(expected.as_bytes(), provided_sig.to_lowercase().as_bytes()) {
        return Err(ak_fail!("error.ak.invalid_signature"));
    }

    // ---- 6. nonce 一次性抢占（SharedStore set_nx_ex；防重放第二道）----
    let nonce_key = format!("ak:nonce:{}", nonce);
    let first = state
        .store
        .set_nx_ex(&nonce_key, "1", NONCE_TTL_SECS)
        .await
        .map_err(|e| {
            tracing::error!("AK nonce 抢占失败（fail-closed）: {}", e);
            (
                "store_unavailable",
                AppError::new(503, crate::tr!("error.ak.store_unavailable")),
            )
        })?;
    if !first {
        return Err(ak_fail!("error.ak.nonce_reused"));
    }

    Ok((verified, body_bytes))
}

/// GET /open/v1/profile：AK 身份画像（真实查库）
///
/// 返回凭据归属：PAT 名称 / 属主用户名 / 租户 / PAT 过期时间。
#[utoipa::path(
    get,
    path = "/open/v1/profile",
    responses(
        (status = 200, description = "AK 身份画像（凭据归属：PAT 名称/属主/租户/过期时间）", body = crate::common::response::AjaxResult<crate::service::sys_pat_service::OpenProfileVo>),
        (status = 401, description = "签名校验失败/凭据无效/已吊销"),
        (status = 404, description = "令牌不存在"),
    ),
    tag = "pat"
)]
pub(crate) async fn open_profile(
    axum::extract::Extension(ak): axum::extract::Extension<AkIdentity>,
    State(state): State<Arc<AppState>>,
) -> Result<axum::Json<serde_json::Value>, AppError> {
    let profile = state
        .pat_service
        .open_profile(&ak.pat_id)
        .await?
        .ok_or_else(|| AppError::new(404, crate::tr!("error.pat.not_found")))?;
    Ok(axum::Json(serde_json::json!({
        "code": 200,
        "msg": crate::tr!("msg.success.query"),
        "data": profile,
    })))
}

/// AK 签名保护的开放 API 路由（自带 ak_sign_middleware，主线程 merge 到 build_app）
///
/// 挂载注意：
/// 1. axum 0.8 的 `from_fn` 不支持 `State` 提取器，中间件须经 `from_fn_with_state`
///    注入 AppState，故本函数接收 `Arc<AppState>` 并返回已收口的 `Router`；
/// 2. 必须与公开路由同层 merge（不得落入 auth_middleware 的 route_layer 覆盖范围——
///    AK 请求无 Bearer，会被 auth 中间件 401 拦截）：
///    `.merge(ak_protected_routes(state.clone()))`。
/// 3. 返回 `Router<Arc<AppState>>`（`with_state` 收口后泛型参数仍可显式指定），
///    与 build_app 的 api 链（`Router<Arc<AppState>>`）类型一致才能 `merge`。
pub fn ak_protected_routes(state: Arc<AppState>) -> Router<Arc<AppState>> {
    Router::new()
        .route("/open/v1/profile", get(open_profile))
        .route_layer(axum::middleware::from_fn_with_state(
            state.clone(),
            ak_sign_middleware,
        ))
        .with_state(state)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::StatusCode;
    use axum::response::IntoResponse;

    /// 签名算法对齐外部已知向量：string_to_sign 各段 \n 连接 + HMAC-SHA256
    #[test]
    fn test_sign_string_known_vector() {
        // HMAC-SHA256("key", "The quick brown fox jumps over the lazy dog")（RFC 2104 用例）
        assert_eq!(
            sign_string("key", "The quick brown fox jumps over the lazy dog"),
            "f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8"
        );
    }

    #[test]
    fn test_constant_time_eq() {
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"abcd"));
        assert!(!constant_time_eq(b"", b"a"));
        assert!(constant_time_eq(b"", b""));
        // 大小写敏感（调用方已统一 lower）
        assert!(!constant_time_eq(b"AB", b"ab"));
    }

    #[test]
    fn test_sha256_hex_empty() {
        // SHA-256("") 已知向量
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    /// 时间戳窗口常量与 nonce TTL 的关系约束（TTL 必须 > 2×窗口，保证窗口内重放可拦）
    #[test]
    fn test_nonce_ttl_covers_window() {
        assert!(NONCE_TTL_SECS > 2 * TIMESTAMP_WINDOW_SECS as u64);
    }

    /// 中间件错误响应映射：401 + 本地化 msg（防止误改统一契约构造路径）
    #[test]
    fn test_ak_fail_macro_shape() {
        let (outcome, e) = ak_fail!("error.ak.invalid_signature");
        assert_eq!(outcome, "invalid_signature");
        assert_eq!(e.code, 401);
        assert!(!e.message.is_empty());
        let resp = e.into_response();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }
}
