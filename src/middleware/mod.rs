// axum-backend/src/middleware/mod.rs

pub mod auth;
pub mod idempotency;
pub mod oper_log;
pub mod permission;
pub mod rate_limit;
pub mod request_id;
pub mod security_headers;
pub mod spa_fallback;

pub use auth::{auth_middleware, Operator};
pub use idempotency::idempotency_middleware;
pub use oper_log::oper_log_middleware;
pub use permission::permission_middleware;
pub use rate_limit::{rate_limit_middleware, RateLimiter, RateLimitConfig};
pub use request_id::{request_id_middleware, RequestId};
pub use security_headers::security_headers;
pub use spa_fallback::spa_fallback_middleware;
