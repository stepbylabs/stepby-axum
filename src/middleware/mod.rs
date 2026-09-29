// backend-axum/src/middleware/mod.rs

pub mod auth;
pub mod idempotency;
pub mod locale;
pub mod oper_log;
pub mod permission;
pub mod platform_guard;
pub mod rate_limit;
pub mod request_id;
pub mod response_cache;
pub mod security_headers;
pub mod spa_fallback;
pub mod tenant_host;

pub use auth::{Operator, auth_middleware};
pub use idempotency::idempotency_middleware;
pub use locale::{locale_middleware, negotiate};
pub use oper_log::{TargetTenant, oper_log_middleware};
pub use permission::permission_middleware;
pub use rate_limit::{RateLimitConfig, RateLimiter, rate_limit_bucket_key, rate_limit_middleware};
pub use request_id::{RequestId, request_id_middleware};
pub use response_cache::{ResponseCache, response_cache_middleware};
pub use security_headers::security_headers;
pub use spa_fallback::spa_fallback_middleware;
pub use tenant_host::{HostTenant, tenant_host_middleware};

/// 同源部署的 API 路径前缀（与 `router::build_app` 的 `Router::nest` 挂载一致）
pub const API_PATH_PREFIXES: [&str; 3] = ["/prod-api", "/dev-api", "/stage-api"];

/// 剥离同源部署 API 前缀，返回路由模板的"本体路径"
///
/// 背景：axum 的 `MatchedPath` 会把 `nest` 前缀并入模板（如 `/prod-api/getInfo`），
/// 而权限映射表（`PERM_ROUTE_TABLE`）、仅登录白名单、操作日志模块推断、指标标签，
/// 全部以**去前缀**的路由模板为准 ⇒ 消费者必须先归一化。
///
/// 仅当剩余部分为空或以 `/` 开头时才视为命中，避免误伤 `/prod-apixyz` 这类同前缀路径。
pub fn normalize_api_prefix(path: &str) -> &str {
    for p in API_PATH_PREFIXES {
        if let Some(rest) = path.strip_prefix(p)
            && (rest.is_empty() || rest.starts_with('/'))
        {
            return rest;
        }
    }
    path
}

#[cfg(test)]
mod tests {
    use super::normalize_api_prefix;

    #[test]
    fn test_normalize_api_prefix() {
        // 三类前缀均剥离
        assert_eq!(normalize_api_prefix("/prod-api/getInfo"), "/getInfo");
        assert_eq!(
            normalize_api_prefix("/dev-api/system/user/list"),
            "/system/user/list"
        );
        assert_eq!(
            normalize_api_prefix("/stage-api/system/flow/task/1"),
            "/system/flow/task/1"
        );
        // 无前缀：原样返回
        assert_eq!(normalize_api_prefix("/getInfo"), "/getInfo");
        // 同前缀不同路径：不得误剥离
        assert_eq!(normalize_api_prefix("/prod-apixyz"), "/prod-apixyz");
    }
}
