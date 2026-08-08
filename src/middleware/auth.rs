// axum-backend/src/middleware/auth.rs

use std::sync::Arc;
use std::time::Duration;
use axum::extract::{FromRequestParts, Request, State};
use axum::http::header::AUTHORIZATION;
use axum::http::HeaderMap;
use axum::http::request::Parts;
use axum::middleware::Next;
use axum::response::Response;
use crate::common::AppError;
use crate::jwt::{Claims, JwtUtils};
use crate::middleware::request_id::RequestId;
use crate::state::AppState;

/// JWT 鉴权中间件（from_fn_with_state 模式，纯 Axum 原生 Tower Layer）
///
/// 校验流程：
/// 1. 提取 Authorization header（缺失返回 401）
/// 2. 解析 Bearer token（格式错误返回 401）
/// 3. JWT 签名验证 + exp 过期校验（显式 map_err 为 401，不走 anyhow → 500）
/// 4. Redis 黑名单校验（登出的 token 拒绝访问）
/// 5. 注入 Claims 到 request extensions
///
/// 白名单通过路由结构实现：公开路由（/health, /login, /captchaImage）不挂载此中间件，
/// 受保护路由通过 .layer(from_fn_with_state(state, auth_middleware)) 挂载。

/// 从请求头提取 Bearer token（纯函数，便于脱离 AppState 单测）
///
/// 安全关键决策点（P0 鉴权第一/二关）：
/// - 缺失 Authorization header → 401（token_missing）
/// - 非 `Bearer ` 前缀格式 → 401（token_invalid）
///
/// 抽成纯函数后，中间件与单元测试均可复用，且不依赖 Redis / DB 即可验证「无 token 拒绝」。
pub fn extract_bearer_token(headers: &HeaderMap) -> Result<&str, AppError> {
    let auth_header = headers
        .get(&AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| AppError::unauthorized(&crate::tr!("error.auth.token_missing")))?;

    let token = auth_header
        .strip_prefix("Bearer ")
        .ok_or_else(|| AppError::unauthorized(&crate::tr!("error.auth.token_invalid")))?;

    Ok(token)
}

pub async fn auth_middleware(
    State(state): State<Arc<AppState>>,
    mut req: Request,
    next: Next,
) -> Result<Response, AppError> {
    // 1+2. 提取 Bearer token（纯函数，见 extract_bearer_token）
    let token = extract_bearer_token(req.headers())?;

    // 3. JWT 签名验证 + exp 过期校验
    //    verify_token 返回 Result<Claims, JwtError>，通过 From<JwtError> for AppError 自动转为 401
    let claims = JwtUtils::verify_token(token, &state.config.jwt)?;

    // P2-11：提取 request_id 用于错误日志结构化字段（request_id_middleware 在本中间件之前执行）
    let request_id = req
        .extensions()
        .get::<RequestId>()
        .map(|r| r.0.clone())
        .unwrap_or_default();

    // 4+5. Redis 黑名单 + 改密校验（合并为单次 Pipeline，减少 RTT）
    //    fail-closed 策略：Redis 异常时拒绝请求，避免已登出 token 继续访问
    //    使用 token 的 SHA-256 哈希作为 blacklist key，节省 Redis 内存
    let blacklist_key = format!("blacklist:{}", crate::utils::crypto::token_hash(token));
    let pwd_changed_key = format!("pwd_changed:{}", claims.sub);
    let mut redis = state.redis.clone();
    // Pipeline：一次 RTT 同时查询 blacklist 和 pwd_changed
    // R11：命令级超时（REDIS_CMD_TIMEOUT_SECS=3s），fail-closed：超时返回 503 拒绝请求
    let (is_blacklisted, pwd_changed): (Option<String>, Option<i64>) = tokio::time::timeout(
        Duration::from_secs(crate::db::redis::REDIS_CMD_TIMEOUT_SECS),
        redis::pipe()
            .cmd("GET").arg(&blacklist_key)
            .cmd("GET").arg(&pwd_changed_key)
            .query_async(&mut redis),
    )
    .await
    .map_err(|_| {
        tracing::error!(
            request_id = %request_id,
            user_id = %claims.sub,
            "Redis 黑名单/pwd_changed 查询超时（fail-closed 拒绝请求）"
        );
        AppError::new(503, crate::tr!("error.auth.auth_unavailable"))
    })?
    .map_err(|e| {
        tracing::error!(
            request_id = %request_id,
            user_id = %claims.sub,
            error = %e,
            "Redis 黑名单/pwd_changed 查询失败（fail-closed 拒绝请求）"
        );
        AppError::new(503, crate::tr!("error.auth.auth_unavailable"))
    })?;
    if is_blacklisted.is_some() {
        return Err(AppError::unauthorized(&crate::tr!("error.auth.token_revoked")));
    }

    // 改密后旧 token 失效校验（P0-R81-007）
    if let Some(changed_at) = pwd_changed
        && changed_at > i64::try_from(claims.iat).unwrap_or(0)
    {
        return Err(AppError::unauthorized(&crate::tr!("error.auth.password_changed")));
    }

    // 6. 注入 Claims 到 request extensions，供下游 handler/中间件使用
    req.extensions_mut().insert(claims);
    Ok(next.run(req).await)
}

/// 操作人提取器（从 request extensions 中提取 Claims）
///
/// 用法：`handler(State(state): State<Arc<AppState>>, operator: Operator)`
/// 中间件已将 Claims 注入 extensions，此处直接取出
///
/// R5-TYPE-16：封装内部 Claims 字段，外部统一通过 `username()`/`user_id()` 访问，
/// 避免 `operator.0.xxx` 直接穿透封装。
#[derive(Debug, Clone)]
pub struct Operator(Claims);

impl<S> FromRequestParts<S> for Operator
where
    S: Send + Sync,
{
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        parts
            .extensions
            .get::<Claims>()
            .cloned()
            .map(Operator)
            .ok_or_else(|| AppError::unauthorized(&crate::tr!("error.auth.login_info_missing")))
    }
}

impl Operator {
    /// 获取操作人用户名（作为业务层的 operator 参数）
    pub fn username(&self) -> &str {
        &self.0.username
    }

    /// 获取操作人用户 ID
    pub fn user_id(&self) -> &str {
        &self.0.sub
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    #[test]
    fn test_extract_bearer_token_missing_header() {
        let headers = HeaderMap::new();
        let err = extract_bearer_token(&headers).unwrap_err();
        assert_eq!(
            err.code, 401,
            "缺失 Authorization header 必须返回 401（token_missing）"
        );
    }

    #[test]
    fn test_extract_bearer_token_non_bearer_prefix() {
        let mut headers = HeaderMap::new();
        // 形如 Basic / 无 Bearer 前缀 → 401（token_invalid）
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_static("Basic abcdef123456"),
        );
        let err = extract_bearer_token(&headers).unwrap_err();
        assert_eq!(
            err.code, 401,
            "非 Bearer 前缀必须返回 401（token_invalid）"
        );
    }

    #[test]
    fn test_extract_bearer_token_empty_bearer() {
        // "Bearer " 后无 token：strip_prefix 成功但 remainder 为空 → 返回 Ok("")
        // 注意：空 token 不会在此阶段被拒，但会在后续 verify_token（解码失败）处返回 401，
        // 整体请求仍被拒绝。此处仅断言前缀解析阶段的纯行为。
        let mut headers = HeaderMap::new();
        headers.insert(AUTHORIZATION, HeaderValue::from_static("Bearer "));
        assert_eq!(extract_bearer_token(&headers).unwrap(), "");
    }

    #[test]
    fn test_extract_bearer_token_ok() {
        let mut headers = HeaderMap::new();
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_static("Bearer eyJhbGciOiJIUzI1NiJ9.payload.sig"),
        );
        assert_eq!(
            extract_bearer_token(&headers).unwrap(),
            "eyJhbGciOiJIUzI1NiJ9.payload.sig"
        );
    }

    #[tokio::test]
    async fn test_operator_rejects_when_claims_absent() {
        // 未经过 auth_middleware（extensions 中没有 Claims）→ Operator 提取必须 401
        let req = axum::http::Request::builder().body(()).unwrap();
        let (mut parts, _body) = req.into_parts();
        let err = Operator::from_request_parts(&mut parts, &())
            .await
            .unwrap_err();
        assert_eq!(
            err.code, 401,
            "缺少 Claims 时 Operator 提取必须返回 401（login_info_missing）"
        );
    }

    #[tokio::test]
    async fn test_operator_extracts_claims() {
        let req = axum::http::Request::builder().body(()).unwrap();
        let (mut parts, _body) = req.into_parts();
        let claims = Claims {
            sub: "42".to_string(),
            username: "alice".to_string(),
            exp: 0,
            iat: 0,
            iss: "yebot".to_string(),
            aud: "yebot".to_string(),
            jti: "jti-1".to_string(),
        };
        parts.extensions.insert(claims);
        let operator = Operator::from_request_parts(&mut parts, &()).await.unwrap();
        assert_eq!(operator.user_id(), "42");
        assert_eq!(operator.username(), "alice");
    }
}
