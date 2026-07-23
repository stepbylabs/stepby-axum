// axum-backend/src/middleware/idempotency.rs
//
// R5-IDEMP-33：幂等性中间件（Idempotency-Key）
//
// 实现：基于 Redis SETNX 的请求去重
// - 客户端在 POST/PUT/DELETE 请求中携带 `Idempotency-Key: <uuid>` 头
// - 中间件以 `idempotency:{user_id}:{key}` 为 Redis key 执行 `SET ... NX EX <ttl>`
// - SET 成功（首次请求）：放行
// - SET 失败（重复请求）：返回 409 Conflict
// - 缺失 Idempotency-Key 头：放行（幂等性为可选特性，不强制）
//
// 适用场景：
// - 前端按钮重复点击（网络抖动导致用户多次提交）
// - 网关重试（超时后网关重发同一请求）
// - 客户端重试逻辑（如支付、下单等关键写操作）
//
// 注意：
// - 仅对写操作（POST/PUT/DELETE）生效，GET 请求直接放行
// - key 作用域为 `per-user`，不同用户的相同 key 不冲突
// - TTL 24 小时，覆盖绝大多数业务场景的重复检测窗口
// - Redis 故障时 fail-open（放行），因 auth 中间件已 fail-closed 保证 Redis 可用性
//   若 Redis 真的故障，auth 中间件会先返回 503，不会到达此中间件

use std::sync::Arc;

use axum::extract::{Request, State};
use axum::http::{HeaderName, Method, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::Json;

use crate::jwt::Claims;
use crate::state::AppState;

/// 幂等性请求头名称
const IDEMPOTENCY_HEADER: HeaderName = HeaderName::from_static("idempotency-key");

/// 幂等 key 前缀（Redis 中格式：idempotency:{user_id}:{key}）
const IDEMPOTENCY_REDIS_PREFIX: &str = "idempotency:";

/// 幂等 key TTL（秒，24 小时）
///
/// 覆盖客户端重试窗口（HTTP/2 连接复用、网关重试、用户重复点击）。
/// 24 小时后自动清理，避免 Redis 无限增长。
const IDEMPOTENCY_TTL_SECS: u64 = 24 * 60 * 60;

/// 幂等 key 最大长度（UUID 36 字符 + 少量余量，限制恶意超长 key）
const IDEMPOTENCY_KEY_MAX_LEN: usize = 128;

/// 幂等 key 允许的字符集（字母、数字、连字符、下划线）
///
/// 限制字符集防止 Redis key 注入与异常字符导致的存储问题。
/// UUID v4 默认包含 `[0-9a-f-]`，符合此字符集。
const IDEMPOTENCY_KEY_ALLOWED_CHARS: &str =
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_";

/// 幂等性中间件
///
/// 挂载位置：在 auth_middleware 之后（需要 Claims 获取 user_id）
/// 仅对 POST/PUT/DELETE 生效，GET/OPTIONS/HEAD 直接放行
pub async fn idempotency_middleware(
    State(state): State<Arc<AppState>>,
    req: Request,
    next: Next,
) -> Response {
    // 1. 仅写操作需要幂等性校验
    let method = req.method().clone();
    if !matches!(method, Method::POST | Method::PUT | Method::DELETE) {
        return next.run(req).await;
    }

    // 2. 提取 Idempotency-Key 头（缺失则放行，幂等性为可选特性）
    let idempotency_key = match req.headers().get(&IDEMPOTENCY_HEADER) {
        Some(value) => match value.to_str() {
            Ok(s) => s.trim().to_string(),
            Err(_) => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({
                        "code": 400,
                        "msg": "Idempotency-Key 头包含非 ASCII 字符"
                    })),
                )
                    .into_response();
            }
        },
        None => return next.run(req).await,
    };

    // 3. 校验 key 格式（非空、长度、字符集）
    if idempotency_key.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "code": 400,
                "msg": "Idempotency-Key 头不能为空"
            })),
        )
            .into_response();
    }
    if idempotency_key.len() > IDEMPOTENCY_KEY_MAX_LEN {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "code": 400,
                "msg": format!("Idempotency-Key 长度不能超过 {} 字符", IDEMPOTENCY_KEY_MAX_LEN)
            })),
        )
            .into_response();
    }
    if !idempotency_key
        .chars()
        .all(|c| IDEMPOTENCY_KEY_ALLOWED_CHARS.contains(c))
    {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "code": 400,
                "msg": "Idempotency-Key 包含非法字符（仅允许字母、数字、连字符、下划线）"
            })),
        )
            .into_response();
    }

    // 4. 从 request extensions 提取 user_id（auth_middleware 已注入 Claims）
    //    key 作用域为 per-user，防止不同用户使用相同 UUID 导致互相拦截
    let user_id = req
        .extensions()
        .get::<Claims>()
        .map(|c| c.sub.clone())
        .unwrap_or_else(|| "anonymous".to_string());

    // 5. Redis SETNX 抢占幂等槽位
    let redis_key = format!("{}{}:{}", IDEMPOTENCY_REDIS_PREFIX, user_id, idempotency_key);
    let mut redis = state.redis.clone();
    let set_result: Result<Option<String>, _> = redis::cmd("SET")
        .arg(&redis_key)
        .arg("1")
        .arg("NX")
        .arg("EX")
        .arg(IDEMPOTENCY_TTL_SECS)
        .query_async(&mut redis)
        .await;

    let acquired = match set_result {
        Ok(Some(_)) => true,  // SET NX 成功，首次请求
        Ok(None) => false,    // key 已存在，重复请求
        Err(e) => {
            // Redis 故障：fail-open 放行
            // 因 auth_middleware 已 fail-closed（Redis 故障时返回 503 阻断请求），
            // 能到达此中间件说明 Redis 可用，此分支理论上不会触发。
            // 但仍保留 fail-open 作为防御性处理，避免中间件耦合 Redis 可用性假设。
            tracing::warn!(
                error = %e,
                redis_key = %redis_key,
                "Redis 幂等性校验失败，fail-open 放行请求（auth 中间件应已保证 Redis 可用）"
            );
            true
        }
    };

    if !acquired {
        // 重复请求：返回 409 Conflict
        return (
            StatusCode::CONFLICT,
            Json(serde_json::json!({
                "code": 409,
                "msg": "重复的幂等性请求，请勿重复提交"
            })),
        )
            .into_response();
    }

    // 6. 首次请求，放行执行
    //    注意：不缓存响应结果（简化实现）。如需缓存，可在 next.run(req).await 后
    //    将响应体存入 Redis，重复请求时直接返回缓存响应。
    //    当前实现仅做"拦截重复请求"，符合防重复提交的核心目标。
    next.run(req).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_allowed_chars_valid() {
        // 标准 UUID v4
        let key = "550e8400-e29b-41d4-a716-446655440000";
        assert!(key.chars().all(|c| IDEMPOTENCY_KEY_ALLOWED_CHARS.contains(c)));
    }

    #[test]
    fn test_key_allowed_chars_custom() {
        // 自定义 key
        let key = "order_create_20260718_001";
        assert!(key.chars().all(|c| IDEMPOTENCY_KEY_ALLOWED_CHARS.contains(c)));
    }

    #[test]
    fn test_key_allowed_chars_invalid() {
        // 包含空格
        let key = "550e8400 e29b";
        assert!(!key.chars().all(|c| IDEMPOTENCY_KEY_ALLOWED_CHARS.contains(c)));
        // 包含特殊字符
        let key = "order@create!";
        assert!(!key.chars().all(|c| IDEMPOTENCY_KEY_ALLOWED_CHARS.contains(c)));
    }

    #[test]
    fn test_key_max_length() {
        let key = "a".repeat(IDEMPOTENCY_KEY_MAX_LEN);
        assert!(key.len() == IDEMPOTENCY_KEY_MAX_LEN);
        let key_too_long = "a".repeat(IDEMPOTENCY_KEY_MAX_LEN + 1);
        assert!(key_too_long.len() > IDEMPOTENCY_KEY_MAX_LEN);
    }
}
