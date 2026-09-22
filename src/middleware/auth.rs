// axum-backend/src/middleware/auth.rs

use crate::common::AppError;
use crate::jwt::{Claims, JwtUtils};
use crate::middleware::request_id::RequestId;
use crate::state::AppState;
use axum::extract::{FromRequestParts, Request, State};
use axum::http::HeaderMap;
use axum::http::header::AUTHORIZATION;
use axum::http::request::Parts;
use axum::middleware::Next;
use axum::response::Response;
use std::sync::Arc;
use std::time::Duration;

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

    // Tier-S #3：个人访问令牌（PAT）分支。
    // 以配置前缀（默认 "ybt_"）区分于登录 JWT（其头以 "eyJ" base64 开头，永不冲突）。
    // 命中前缀即走 PAT 鉴权：按摘要查库校验有效性，合成带 pat_scopes 的 Claims 注入 extensions，
    // 跳过 JWT 专属的 blacklist / pwd_ver（PAT 吊销靠每请求查库即时生效）；下游全部无感复用。
    if !state.config.pat.prefix.is_empty() && token.starts_with(&state.config.pat.prefix) {
        let claims = authenticate_pat(&state, token, req.extensions().get::<RequestId>().map(|r| r.0.clone())).await?;
        req.extensions_mut().insert(claims);
        return Ok(next.run(req).await);
    }

    // 3. JWT 签名验证 + exp 过期校验
    //    verify_token 返回 Result<Claims, JwtError>，通过 From<JwtError> for AppError 自动转为 401
    let claims = JwtUtils::verify_token(token, &state.config.jwt)?;

    // P2-11：提取 request_id 用于错误日志结构化字段（request_id_middleware 在本中间件之前执行）
    let request_id = req
        .extensions()
        .get::<RequestId>()
        .map(|r| r.0.clone())
        .unwrap_or_default();

    // 4+5. Redis 黑名单 + 密码版本号校验（合并为单次 Pipeline，减少 RTT）
    //    fail-closed 策略：Redis 异常时拒绝请求，避免已登出 token 继续访问
    //    使用 token 的 SHA-256 哈希作为 blacklist key，节省 Redis 内存
    let blacklist_key = format!("blacklist:{}", crate::utils::crypto::token_hash(token));
    // P0-R81-007 密码版本号：改密/重置/停用/删除时对 pwd_ver:{user_id} INCR，
    // 登录时写入 claim；若 Redis 当前版本 > claim 版本，说明 token 签发后发生过密码变更 → 拒绝。
    let pwd_ver_key = format!("pwd_ver:{}", claims.sub);
    let mut redis = state.redis.clone();
    // Pipeline：一次 RTT 同时查询 blacklist 和 pwd_ver
    // R11：命令级超时（REDIS_CMD_TIMEOUT_SECS=3s），fail-closed：超时返回 503 拒绝请求
    let (is_blacklisted, pwd_ver): (Option<String>, Option<u64>) = tokio::time::timeout(
        Duration::from_secs(crate::db::redis::REDIS_CMD_TIMEOUT_SECS),
        redis::pipe()
            .cmd("GET")
            .arg(&blacklist_key)
            .cmd("GET")
            .arg(&pwd_ver_key)
            .query_async(&mut redis),
    )
    .await
    .map_err(|_| {
        tracing::error!(
            request_id = %request_id,
            user_id = %claims.sub,
            "Redis 黑名单/pwd_ver 查询超时（fail-closed 拒绝请求）"
        );
        AppError::new(503, crate::tr!("error.auth.auth_unavailable"))
    })?
    .map_err(|e| {
        tracing::error!(
            request_id = %request_id,
            user_id = %claims.sub,
            error = %e,
            "Redis 黑名单/pwd_ver 查询失败（fail-closed 拒绝请求）"
        );
        AppError::new(503, crate::tr!("error.auth.auth_unavailable"))
    })?;
    if is_blacklisted.is_some() {
        return Err(AppError::unauthorized(&crate::tr!(
            "error.auth.token_revoked"
        )));
    }

    // 改密后旧 token 失效校验（P0-R81-007 版本号机制）
    // 版本号单调递增，无秒级时间戳同秒竞态：即使登录与改密发生在同一秒，版本号也已 +1，
    // 旧 token（版本较低）立即失效；改密后新登录的 token 携带最新版本号，不受影响。
    if let Some(current_ver) = pwd_ver
        && current_ver > claims.pwd_ver
    {
        return Err(AppError::unauthorized(&crate::tr!(
            "error.auth.password_changed"
        )));
    }

    // 6. 注入 Claims 到 request extensions，供下游 handler/中间件使用
    req.extensions_mut().insert(claims);
    Ok(next.run(req).await)
}

/// Tier-S #3：个人访问令牌（PAT）鉴权——校验并合成 Claims
///
/// 校验：功能启用 → 摘要命中有效令牌（status='0' 且未过期）→ 合成携带 `pat_scopes` 的 Claims。
/// 最近使用时间以 best-effort `tokio::spawn` 异步更新，不阻塞请求。
async fn authenticate_pat(
    state: &Arc<AppState>,
    token: &str,
    request_id: Option<String>,
) -> Result<Claims, AppError> {
    if !state.config.pat.enabled {
        // PAT 关闭：携带令牌前缀的请求一律拒绝（不回退到 JWT 分支）
        return Err(AppError::unauthorized(&crate::tr!(
            "error.auth.token_invalid"
        )));
    }
    let request_id = request_id.unwrap_or_default();
    let verified = state
        .pat_service
        .verify_token(token)
        .await
        .map_err(|e| {
            tracing::error!(
                request_id = %request_id,
                error = %e,
                "PAT 鉴权查库失败（fail-closed 拒绝请求）"
            );
            AppError::new(503, crate::tr!("error.auth.auth_unavailable"))
        })?;
    let Some(v) = verified else {
        // 未命中 / 已吊销 / 已过期 → 401
        return Err(AppError::unauthorized(&crate::tr!(
            "error.auth.token_revoked"
        )));
    };
    // best-effort 更新最近使用时间（失败仅记 debug，不影响请求）
    let svc = state.pat_service.clone();
    let pat_id = v.pat_id.clone();
    tokio::spawn(async move {
        svc.touch_last_used(&pat_id).await;
    });
    Ok(Claims {
        sub: v.user_id.to_string(),
        username: v.username,
        exp: 0,
        iat: 0,
        iss: state.config.pat.prefix.clone(),
        aud: state.config.pat.prefix.clone(),
        jti: v.pat_id,
        pwd_ver: 0,
        pat_scopes: Some(v.scopes),
    })
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
        assert_eq!(err.code, 401, "非 Bearer 前缀必须返回 401（token_invalid）");
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
            pwd_ver: 0,
            pat_scopes: None,
        };
        parts.extensions.insert(claims);
        let operator = Operator::from_request_parts(&mut parts, &()).await.unwrap();
        assert_eq!(operator.user_id(), "42");
        assert_eq!(operator.username(), "alice");
    }
}
