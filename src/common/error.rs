// axum-backend/src/common/error.rs
//! 全局错误类型
//!
//! 分层设计：
//! - ServiceError：Service 层错误（纯业务，不依赖 Web 框架）
//! - AppError：Handler 层错误（含 IntoResponse 实现，依赖 axum）
//! - AppError 实现 From<ServiceError>，Handler 层通过 ? 自动转换
//!
//! thiserror 集成：
//! - ServiceError / AppError 使用 `#[derive(thiserror::Error)]` 自动派生
//!   `std::error::Error` 和 `std::fmt::Display`，避免手写 impl。
//! - 保留原有的 struct 结构（code + message），所有构造方法与 From impl 保持兼容。

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use thiserror::Error;
use crate::common::response::AjaxResult;

// ==================== Service 层错误（不依赖 Web 框架） ====================

/// Service 层错误类型（纯业务错误，不依赖 axum / tower 等 Web 框架）
///
/// Service 层全部返回 `Result<T, ServiceError>`，
/// Handler 层通过 `From<ServiceError> for AppError` 自动转换。
///
/// 使用 thiserror 自动派生 Display 和 std::error::Error，
/// Display 输出格式与原手写实现保持一致。
#[derive(Debug, Error)]
#[error("ServiceError(code={code}, message={message})")]
pub struct ServiceError {
    pub code: i32,
    pub message: String,
}

impl ServiceError {
    pub fn new(code: i32, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }

    /// 401 未认证
    pub fn unauthorized(msg: &str) -> Self {
        Self::new(401, msg)
    }

    /// 400 参数错误
    pub fn bad_request(msg: &str) -> Self {
        Self::new(400, msg)
    }

    /// 404 未找到
    pub fn not_found(msg: &str) -> Self {
        Self::new(404, msg)
    }

    /// 403 禁止访问
    pub fn forbidden(msg: &str) -> Self {
        Self::new(403, msg)
    }

    /// 500 内部错误
    pub fn internal(msg: &str) -> Self {
        Self::new(500, msg)
    }
}

/// SeaORM 数据库错误转换为 ServiceError（脱敏：内部错误返回通用文案，详情写日志）
impl From<sea_orm::DbErr> for ServiceError {
    fn from(err: sea_orm::DbErr) -> Self {
        match &err {
            sea_orm::DbErr::RecordNotFound(_) | sea_orm::DbErr::RecordNotUpdated => {
                ServiceError::not_found(&crate::tr!("error.common.not_found"))
            }
            sea_orm::DbErr::ConnectionAcquire(_) => {
                tracing::error!("数据库连接获取失败: {}", err);
                ServiceError::new(503, &crate::tr!("error.common.db_acquire"))
            }
            sea_orm::DbErr::TryIntoErr { .. } | sea_orm::DbErr::AttrNotSet(_) => {
                tracing::error!("数据转换错误: {}", err);
                ServiceError::bad_request(&crate::tr!("error.common.bad_format"))
            }
            _ => {
                // 检测唯一约束冲突（P0-R17-001）
                // 不同数据库的错误消息不同：
                //   PostgreSQL: "duplicate key value violates unique constraint"
                //   MySQL: "Duplicate entry 'xxx' for key"
                //   SQLite: "UNIQUE constraint failed"
                let err_str = err.to_string().to_lowercase();
                if err_str.contains("unique constraint")
                    || err_str.contains("duplicate entry")
                    || err_str.contains("duplicate key")
                {
                    tracing::warn!("唯一约束冲突: {}", err);
                    ServiceError::bad_request(&crate::tr!("error.common.duplicate"))
                } else {
                    tracing::error!("数据库错误: {}", err);
                    ServiceError::internal(&crate::tr!("error.common.db_failed"))
                }
            }
        }
    }
}

/// SeaORM 事务错误转换
impl From<sea_orm::TransactionError<sea_orm::DbErr>> for ServiceError {
    fn from(err: sea_orm::TransactionError<sea_orm::DbErr>) -> Self {
        match err {
            sea_orm::TransactionError::Transaction(db_err) => ServiceError::from(db_err),
            other => {
                tracing::error!("事务错误: {}", other);
                ServiceError::internal(&crate::tr!("error.common.tx_failed"))
            }
        }
    }
}

/// garde 参数校验错误转换（T-01：validator → garde）
///
/// Report 迭代产出 (字段路径, 错误消息)，消息语言由
/// `common::i18n::validate` 按请求 locale 经 `with_i18n` 决定。
impl From<garde::Report> for ServiceError {
    fn from(report: garde::Report) -> Self {
        let msg = report
            .iter()
            .map(|(path, err)| format!("{path}: {err}"))
            .collect::<Vec<_>>()
            .join("; ");
        if msg.is_empty() {
            ServiceError::bad_request(&crate::tr!("error.common.validate_failed"))
        } else {
            ServiceError::bad_request(&msg)
        }
    }
}

/// JWT 错误转换（类型化，区分过期/签名/格式/claims）
impl From<crate::jwt::JwtError> for ServiceError {
    fn from(err: crate::jwt::JwtError) -> Self {
        use crate::jwt::JwtError;
        match err {
            JwtError::Expired => {
                tracing::info!("JWT 验证失败: token 已过期");
                ServiceError::unauthorized(&crate::tr!("error.common.session_expired"))
            }
            JwtError::InvalidSignature => {
                tracing::warn!("JWT 验证失败: 签名无效（token 可能被篡改）");
                ServiceError::unauthorized(&crate::tr!("error.common.session_invalid"))
            }
            JwtError::Malformed => {
                tracing::info!("JWT 验证失败: token 格式错误");
                ServiceError::unauthorized(&crate::tr!("error.common.session_invalid"))
            }
            JwtError::InvalidClaims => {
                tracing::info!("JWT 验证失败: claims 校验不通过");
                ServiceError::unauthorized(&crate::tr!("error.common.session_invalid"))
            }
            JwtError::GenerateFailed => {
                tracing::error!("JWT 签发失败");
                ServiceError::internal(&crate::tr!("error.common.token_failed"))
            }
        }
    }
}

/// Serde JSON 错误转换（脱敏）
impl From<serde_json::Error> for ServiceError {
    fn from(err: serde_json::Error) -> Self {
        tracing::error!("JSON 序列化错误: {}", err);
        ServiceError::internal(&crate::tr!("error.common.process_failed"))
    }
}

/// Argon2 密码哈希错误转换（脱敏）
impl From<argon2::password_hash::Error> for ServiceError {
    fn from(err: argon2::password_hash::Error) -> Self {
        tracing::error!("密码加密失败: {}", err);
        ServiceError::internal(&crate::tr!("error.common.password_encrypt_failed"))
    }
}

/// IO 错误转换（脱敏）
impl From<std::io::Error> for ServiceError {
    fn from(err: std::io::Error) -> Self {
        tracing::error!("IO 错误: {}", err);
        ServiceError::internal(&crate::tr!("error.common.io_error"))
    }
}

/// Redis 错误转换（脱敏）
impl From<redis::RedisError> for ServiceError {
    fn from(err: redis::RedisError) -> Self {
        tracing::error!("Redis 错误: {}", err);
        match err.kind() {
            redis::ErrorKind::AuthenticationFailed => {
                ServiceError::unauthorized(&crate::tr!("error.common.cache_auth_failed"))
            }
            _ => ServiceError::internal(&crate::tr!("error.common.cache_failed")),
        }
    }
}

/// anyhow 错误转换（脱敏：返回通用文案，详情写日志）
impl From<anyhow::Error> for ServiceError {
    fn from(err: anyhow::Error) -> Self {
        tracing::error!("内部错误: {}", err);
        ServiceError::internal(&crate::tr!("error.common.internal"))
    }
}

// ==================== Handler 层错误（含 IntoResponse） ====================

/// Handler 层错误类型（含 HTTP 响应转换）
///
/// 通过 `From<ServiceError>` 自动转换，Handler 层使用 `Result<T, AppError>`。
///
/// 使用 thiserror 自动派生 Display 和 std::error::Error，
/// 便于与其他支持 `std::error::Error` 的生态库协作。
///
/// R8-CONC-016：保留可选的错误链 source，便于 tracing 记录根因。
/// R19-4.3：IntoResponse 按 code 映射 HTTP 状态码（保留 body.code 兼容前端）。
#[derive(Debug, Error)]
#[error("AppError(code={code}, message={message})")]
pub struct AppError {
    pub code: i32,
    pub message: String,
    /// 错误链 source（可选），用于 tracing 记录根因
    ///
    /// 通过 `with_source` 链式构造，IntoResponse 时若 source 存在则记 tracing::error
    #[source]
    pub source: Option<Box<dyn std::error::Error + Send + Sync>>,
}

impl AppError {
    pub fn new(code: i32, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            source: None,
        }
    }

    /// 链式附加错误链 source（R8-CONC-016）
    ///
    /// 用于在 Handler 层捕获底层错误时保留根因，便于排查。
    /// source 仅写入 tracing 日志，不会暴露给客户端（避免内部信息泄漏）。
    pub fn with_source<E: std::error::Error + Send + Sync + 'static>(mut self, source: E) -> Self {
        self.source = Some(Box::new(source));
        self
    }

    /// 401 未认证
    pub fn unauthorized(msg: &str) -> Self {
        Self::new(401, msg)
    }

    /// 400 参数错误
    pub fn bad_request(msg: &str) -> Self {
        Self::new(400, msg)
    }

    /// 404 未找到
    pub fn not_found(msg: &str) -> Self {
        Self::new(404, msg)
    }

    /// 403 禁止访问
    pub fn forbidden(msg: &str) -> Self {
        Self::new(403, msg)
    }

    /// 500 内部错误
    pub fn internal(msg: &str) -> Self {
        Self::new(500, msg)
    }
}

/// ServiceError → AppError 自动转换（Handler 层 ? 操作符使用）
impl From<ServiceError> for AppError {
    fn from(err: ServiceError) -> Self {
        AppError {
            code: err.code,
            message: err.message,
            source: None,
        }
    }
}

/// 兼容：SeaORM DbErr → AppError（经 ServiceError 中转）
impl From<sea_orm::DbErr> for AppError {
    fn from(err: sea_orm::DbErr) -> Self {
        AppError::from(ServiceError::from(err))
    }
}

/// 兼容：TransactionError → AppError
impl From<sea_orm::TransactionError<sea_orm::DbErr>> for AppError {
    fn from(err: sea_orm::TransactionError<sea_orm::DbErr>) -> Self {
        AppError::from(ServiceError::from(err))
    }
}

/// 兼容：garde Report → AppError
impl From<garde::Report> for AppError {
    fn from(report: garde::Report) -> Self {
        AppError::from(ServiceError::from(report))
    }
}

/// 兼容：serde_json::Error → AppError
impl From<serde_json::Error> for AppError {
    fn from(err: serde_json::Error) -> Self {
        AppError::from(ServiceError::from(err))
    }
}

/// 兼容：RedisError → AppError
impl From<redis::RedisError> for AppError {
    fn from(err: redis::RedisError) -> Self {
        AppError::from(ServiceError::from(err))
    }
}

/// 兼容：JwtError → AppError（中间件 ? 操作符使用）
impl From<crate::jwt::JwtError> for AppError {
    fn from(err: crate::jwt::JwtError) -> Self {
        AppError::from(ServiceError::from(err))
    }
}

/// 兼容：Argon2 密码哈希错误 → AppError
impl From<argon2::password_hash::Error> for AppError {
    fn from(err: argon2::password_hash::Error) -> Self {
        AppError::from(ServiceError::from(err))
    }
}

/// 兼容：anyhow::Error → AppError
impl From<anyhow::Error> for AppError {
    fn from(err: anyhow::Error) -> Self {
        AppError::from(ServiceError::from(err))
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        // R19-4.3：按 error code 映射 HTTP 状态码（保留 body.code 兼容前端拦截器）
        //
        // 兼容性说明：
        // - 前端 request.ts 同时处理 HTTP 错误状态码（error 拦截器）和 body.code（success 拦截器）
        // - 改为返回真实 HTTP 状态码后，4xx/5xx 会进入 error 拦截器，前端已处理 401/403/503
        // - body 中仍保留 code 字段，前端 success 拦截器逻辑备用（双重保险）
        //
        // 映射规则：
        // - 400 → 400 Bad Request
        // - 401 → 401 Unauthorized
        // - 403 → 403 Forbidden
        // - 404 → 404 Not Found
        // - 409 → 409 Conflict
        // - 422 → 422 Unprocessable Entity
        // - 429 → 429 Too Many Requests（登录频率限制）
        // - 500 → 500 Internal Server Error
        // - 503 → 503 Service Unavailable
        // - 其他（含 200/自定义业务码）→ 200 OK（保持原行为，避免破坏非标准业务码）
        let http_status = match self.code {
            400 => StatusCode::BAD_REQUEST,
            401 => StatusCode::UNAUTHORIZED,
            403 => StatusCode::FORBIDDEN,
            404 => StatusCode::NOT_FOUND,
            409 => StatusCode::CONFLICT,
            422 => StatusCode::UNPROCESSABLE_ENTITY,
            429 => StatusCode::TOO_MANY_REQUESTS,
            500 => StatusCode::INTERNAL_SERVER_ERROR,
            503 => StatusCode::SERVICE_UNAVAILABLE,
            _ => StatusCode::OK,
        };

        // R8-CONC-016：若存在错误链 source，记录根因到 tracing（不暴露给客户端）
        if let Some(ref src) = self.source {
            tracing::error!(
                code = self.code,
                message = %self.message,
                error = %src,
                "AppError 含错误链 source（根因已记录，不暴露给客户端）"
            );
        }

        let body = Json(AjaxResult::<()>::error(self.code, &self.message));
        (http_status, body).into_response()
    }
}
