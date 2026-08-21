// axum-backend/src/middleware/mod.rs

pub mod auth;
pub mod idempotency;
pub mod locale;
pub mod oper_log;
pub mod permission;
pub mod rate_limit;
pub mod request_id;
pub mod response_cache;
pub mod security_headers;
pub mod spa_fallback;

pub use auth::{Operator, auth_middleware};
pub use idempotency::idempotency_middleware;
pub use locale::{locale_middleware, negotiate};
pub use oper_log::oper_log_middleware;
pub use permission::permission_middleware;
pub use rate_limit::{RateLimitConfig, RateLimiter, rate_limit_middleware};
pub use request_id::{RequestId, request_id_middleware};
pub use response_cache::{ResponseCache, response_cache_middleware};
pub use security_headers::security_headers;
pub use spa_fallback::spa_fallback_middleware;
