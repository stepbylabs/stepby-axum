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

    // P2-11：提取 request_id / 方法 / 路径（结构化日志 + 租户宽限期只读判定）
    let request_id = req
        .extensions()
        .get::<RequestId>()
        .map(|r| r.0.clone())
        .unwrap_or_default();
    let req_is_write = is_write_method(req.method());
    let req_path = req.uri().path().to_string();

    // Tier-S #3：个人访问令牌（PAT）分支。
    // 以配置前缀（默认 "ybt_"）区分于登录 JWT（其头以 "eyJ" base64 开头，永不冲突）。
    // 命中前缀即走 PAT 鉴权：按摘要查库校验有效性，合成带 pat_scopes 的 Claims 注入 extensions，
    // 跳过 JWT 专属的 blacklist / pwd_ver（PAT 吊销靠每请求查库即时生效）；下游全部无感复用。
    if !state.config.pat.prefix.is_empty() && token.starts_with(&state.config.pat.prefix) {
        let claims = authenticate_pat(&state, token, Some(request_id.clone())).await?;
        // Phase 3：PAT 同样受租户生命周期闸门约束（否则租户停用后凭 PAT 仍可长期访问）
        if claims.tid != 0 {
            let runtime = load_tenant_runtime_state(&state, claims.tid, &request_id).await?;
            enforce_tenant_runtime(runtime, claims.tid, req_is_write, &req_path, &request_id)?;
        }
        // Phase 3 域名链路：PAT 会话同样校验 host 归属与 token tid 一致性
        ensure_host_tenant_consistent(host_tenant_of(&req), claims.tid)?;
        req.extensions_mut().insert(claims);
        return Ok(next.run(req).await);
    }

    // 3. JWT 签名验证 + exp 过期校验
    //    verify_token 返回 Result<Claims, JwtError>，通过 From<JwtError> for AppError 自动转为 401
    let claims = JwtUtils::verify_token(token, &state.config.jwt)?;

    // 4+5. Redis 黑名单 + 密码版本号 + SSO 过渡阻断 + 租户运行时状态
    //    （合并为单次 Pipeline，减少 RTT；租户键仅租户用户追加查询，平台租户零开销）
    //    fail-closed 策略：Redis 异常时拒绝请求，避免已登出 token 继续访问
    //    使用 token 的 SHA-256 哈希作为 blacklist key，节省 Redis 内存
    let blacklist_key = format!("blacklist:{}", crate::utils::crypto::token_hash(token));
    // P0-R81-007 密码版本号：改密/重置/停用/删除时对 pwd_ver:{user_id} INCR，
    // 登录时写入 claim；若 Redis 当前版本 > claim 版本，说明 token 签发后发生过密码变更 → 拒绝。
    let pwd_ver_key = format!("pwd_ver:{}", claims.sub);
    // v4-F1 过渡阻断：该 JWT 的哈希命中 `sso:at:{hash}` 绑定 → 是历史阶段由 SSO token 端点
    // 签发的平台同构 JWT → 其持有者本应只被允许调 /sso/userinfo，必须拒绝进入业务路由
    // （历史越权止血，见 docs/optimization/topic-sso-multitenant-v4-final-2026-09-23.md §13-F1）。
    // 【移除条件】A 形态（不透明 access_token）上线且历史令牌全部过期（一个 JWT TTL 周期）后，
    // 此分支成为死代码（不透明串在 verify_token 即失败），可安全删除。
    let sso_at_key = format!("sso:at:{}", crate::utils::crypto::token_hash(token));
    // 多租户 Phase 3：租户生命周期运行时键（§27.4）——不依赖 JWT 声明即可让存量令牌
    // 随租户停用/删除/超期立即失效，并支持「宽限期只读」非二值状态。
    let tenant_tid = claims.tid;
    let check_tenant = tenant_tid != 0;
    let tenant_state_key = crate::common::tenant::tenant_state_key(tenant_tid);
    let tenant_exp_key = crate::common::tenant::tenant_expire_key(tenant_tid);
    let mut redis = state.redis.clone();
    let mut pipe = redis::pipe();
    pipe.cmd("GET")
        .arg(&blacklist_key)
        .cmd("GET")
        .arg(&pwd_ver_key)
        .cmd("GET")
        .arg(&sso_at_key);
    if check_tenant {
        pipe.cmd("GET")
            .arg(&tenant_state_key)
            .cmd("GET")
            .arg(&tenant_exp_key);
    }
    // Pipeline：一次 RTT 同时查询 blacklist / pwd_ver / sso:at [ / tenant:state / tenant:exp ]
    // R11：命令级超时（REDIS_CMD_TIMEOUT_SECS=3s），fail-closed：超时返回 503 拒绝请求
    let vals: Vec<Option<String>> = tokio::time::timeout(
        Duration::from_secs(crate::db::redis::REDIS_CMD_TIMEOUT_SECS),
        pipe.query_async(&mut redis),
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
    let is_blacklisted = vals.first().cloned().flatten();
    let pwd_ver: Option<u64> = vals
        .get(1)
        .cloned()
        .flatten()
        .and_then(|s| s.parse::<u64>().ok());
    let legacy_sso_at = vals.get(2).cloned().flatten();
    if is_blacklisted.is_some() {
        return Err(AppError::unauthorized(&crate::tr!(
            "error.auth.token_revoked"
        )));
    }

    // v4-F1 过渡阻断（见上方注释）：SSO 签发的历史 JWT 型 access_token 禁止进入业务路由。
    // SSO 令牌只应被 /sso/userinfo 消费（该端点自行校验绑定，不经过本中间件）。
    if legacy_sso_at.is_some() {
        tracing::warn!(user_id = %claims.sub, "SSO 历史访问令牌尝试访问业务路由（过渡阻断拒绝）");
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

    // 6. 多租户 Phase 3：租户生命周期闸门（逐请求判定，存量 JWT 同样受控）
    if check_tenant {
        let state_raw = vals.get(3).cloned().flatten();
        let expire_epoch: i64 = vals
            .get(4)
            .cloned()
            .flatten()
            .and_then(|s| s.parse::<i64>().ok())
            .unwrap_or(0);
        let runtime = crate::common::tenant::eval_tenant_runtime_state(
            state_raw.as_deref(),
            expire_epoch,
            chrono::Utc::now().timestamp(),
        );
        enforce_tenant_runtime(runtime, tenant_tid, req_is_write, &req_path, &request_id)?;
    }

    // 7. 多租户 Phase 3 域名链路：host 归属租户与 JWT tid 必须一致（以 token 为准，禁止静默降级）
    ensure_host_tenant_consistent(host_tenant_of(&req), claims.tid)?;

    // 8. 注入 Claims 到 request extensions，供下游 handler/中间件使用
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
    let verified = state.pat_service.verify_token(token).await.map_err(|e| {
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
    // Phase 3：PAT 同样受租户生命周期闸门约束（否则租户停用后凭 PAT 仍可长期访问）
    let pat_tid = v.tenant_id;
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
        // v5-N2 Phase 3：PAT 合成 Claims 的 tid 随令牌行带出（PAT 属用户级凭据，租户随用户）
        tid: pat_tid,
    })
}

/// 查询租户运行时状态（PAT 路径；JWT 路径在同一 Pipeline 中已内联查询以省 RTT）。
/// Redis 异常 → 503 fail-closed（拒绝请求，不静默放行）。
async fn load_tenant_runtime_state(
    state: &Arc<AppState>,
    tenant_id: i64,
    request_id: &str,
) -> Result<crate::common::tenant::TenantRuntimeState, AppError> {
    if tenant_id == 0 {
        return Ok(crate::common::tenant::TenantRuntimeState::Active);
    }
    let state_key = crate::common::tenant::tenant_state_key(tenant_id);
    let exp_key = crate::common::tenant::tenant_expire_key(tenant_id);
    let mut redis = state.redis.clone();
    let vals: Vec<Option<String>> = match tokio::time::timeout(
        Duration::from_secs(crate::db::redis::REDIS_CMD_TIMEOUT_SECS),
        redis::pipe()
            .cmd("GET")
            .arg(&state_key)
            .cmd("GET")
            .arg(&exp_key)
            .query_async(&mut redis),
    )
    .await
    {
        Ok(Ok(v)) => v,
        Ok(Err(e)) => {
            tracing::error!(
                request_id = %request_id,
                tenant_id,
                error = %e,
                "租户运行时键查询失败（fail-closed 拒绝请求）"
            );
            return Err(AppError::new(
                503,
                crate::tr!("error.auth.auth_unavailable"),
            ));
        }
        Err(_) => {
            tracing::error!(
                request_id = %request_id,
                tenant_id,
                "租户运行时键查询超时（fail-closed 拒绝请求）"
            );
            return Err(AppError::new(
                503,
                crate::tr!("error.auth.auth_unavailable"),
            ));
        }
    };
    let state_raw = vals.first().cloned().flatten();
    let expire_epoch = vals
        .get(1)
        .cloned()
        .flatten()
        .and_then(|s| s.parse::<i64>().ok())
        .unwrap_or(0);
    Ok(crate::common::tenant::eval_tenant_runtime_state(
        state_raw.as_deref(),
        expire_epoch,
        chrono::Utc::now().timestamp(),
    ))
}

/// 请求方法是否写操作（宽限期「只读」判定；只放行 GET/HEAD/OPTIONS）
fn is_write_method(m: &axum::http::Method) -> bool {
    !matches!(
        *m,
        axum::http::Method::GET | axum::http::Method::HEAD | axum::http::Method::OPTIONS
    )
}

/// 取出 host 归属租户（由 `tenant_host_middleware` 注入；缺失视为无上下文）
fn host_tenant_of(req: &Request) -> Option<i64> {
    req.extensions()
        .get::<crate::middleware::HostTenant>()
        .and_then(|h| h.tid())
}

/// 多租户 Phase 3 域名链路一致性校验（安全关键）：
/// - 无 host 租户上下文（`None`）→ 放行（平台 host / 未绑定域名 / 来源不可信）；
/// - host 归属 == token tid → 放行；
/// - host 归属 != token tid → **403**（以 token 为准，绝不静默改用 host 的 tid）。
pub fn ensure_host_tenant_consistent(
    host_tid: Option<i64>,
    token_tid: i64,
) -> Result<(), AppError> {
    if let Some(host) = host_tid
        && host != token_tid
    {
        tracing::warn!(
            host_tenant_id = host,
            token_tenant_id = token_tid,
            "请求 host 归属租户与登录令牌 tid 不一致（拒绝访问，禁止静默降级）"
        );
        return Err(AppError::forbidden(&crate::tr!(
            "error.tenant.host_mismatch"
        )));
    }
    Ok(())
}

/// 按租户运行时状态执行闸门（JWT 与 PAT 两条链路共用，保证行为一致）：
/// - `Active`：放行；
/// - `Grace`：仅放行读请求与登出（`*/logout`），其余写请求 403 `expired_readonly`；
/// - `Disabled`：403 `tenant.disabled` 拒绝全部请求。
fn enforce_tenant_runtime(
    runtime: crate::common::tenant::TenantRuntimeState,
    tenant_id: i64,
    is_write: bool,
    path: &str,
    request_id: &str,
) -> Result<(), AppError> {
    use crate::common::tenant::TenantRuntimeState as Rt;
    match runtime {
        Rt::Active => Ok(()),
        Rt::Grace => {
            if is_write && !path.ends_with("/logout") {
                tracing::info!(
                    request_id = %request_id,
                    tenant_id,
                    path = %path,
                    "租户处于到期宽限期：拒绝写请求（只读模式）"
                );
                Err(AppError::new(
                    403,
                    crate::tr!("error.tenant.expired_readonly"),
                ))
            } else {
                Ok(())
            }
        }
        Rt::Disabled => {
            tracing::warn!(
                request_id = %request_id,
                tenant_id,
                path = %path,
                "租户已停用/超期：拒绝请求"
            );
            Err(AppError::new(403, crate::tr!("error.tenant.disabled")))
        }
    }
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

    /// 用户认证时刻（JWT iat，UTC 秒；v3 P1'-1：consent 批准路径的 auth_time 数据源）
    pub fn iat(&self) -> usize {
        self.0.iat
    }

    /// 是否 PAT 会话（V7-E1 方案 S：审批写动作要求本人 JWT 会话，禁 PAT 代持）
    pub fn is_pat(&self) -> bool {
        self.0.pat_scopes.is_some()
    }

    /// v5-N2 Phase 1：获取租户 ID（当前恒 0 = 平台单租户；
    /// 多租户 Phase 2 立项后 Repository 过滤层据此注入 tid 条件）
    pub fn tenant_id(&self) -> i64 {
        self.0.tid
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
            iss: "stepby".to_string(),
            aud: "stepby".to_string(),
            jti: "jti-1".to_string(),
            pwd_ver: 0,
            pat_scopes: None,
            tid: 0,
        };
        parts.extensions.insert(claims);
        let operator = Operator::from_request_parts(&mut parts, &()).await.unwrap();
        assert_eq!(operator.user_id(), "42");
        assert_eq!(operator.username(), "alice");
        assert_eq!(operator.tenant_id(), 0, "v5-N2 Phase 1：tid 默认平台租户 0");
    }
}
