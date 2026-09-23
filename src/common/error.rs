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

use crate::common::response::AjaxResult;
use axum::Json;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use thiserror::Error;

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
                ServiceError::new(503, crate::tr!("error.common.db_acquire"))
            }
            sea_orm::DbErr::TryIntoErr { .. } | sea_orm::DbErr::AttrNotSet(_) => {
                tracing::error!("数据转换错误: {}", err);
                ServiceError::bad_request(&crate::tr!("error.common.bad_format"))
            }
            _ => {
                // 检测唯一约束冲突（P0-R17-001 / B6）
                // 优先使用 SeaORM 1.1 结构化的 `sql_err()` API，覆盖
                // PostgreSQL(23505) / MySQL(1062,1169,1586,1022) / SQLite(1555,2067)，
                // 直接按数据库错误码分派，比纯字符串匹配稳健，且能拿到约束信息。
                // （原 TODO(M-3) 已随 SeaORM 1.1 落地——`sql_err()` 内部即按错误码判定，
                //  无需再依赖易误判/漏判的字符串匹配。）
                if let Some(sea_orm::SqlErr::UniqueConstraintViolation(msg)) = err.sql_err() {
                    tracing::warn!("唯一约束冲突: {}", msg);
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

/// 批量生成 `impl From<$T> for AppError`：统一经 `ServiceError` 中转。
///
/// `AppError` 的 `From` 实现均为纯委托（`AppError::from(ServiceError::from(e))`），
/// 抽成宏消除 8+ 处重复样板，并保证新增错误类型时不会漏写 `AppError` 侧转换。
///
/// 注：`ServiceError` 侧各自的 `From` 实现含脱敏/错误码/日志等定制逻辑，无法批量化，
/// 仍保持手写；本宏仅收敛 `AppError` 这一层机械委托。
macro_rules! impl_app_error_from {
    ($($t:ty),* $(,)?) => {
        $(
            impl From<$t> for AppError {
                fn from(err: $t) -> Self {
                    AppError::from(ServiceError::from(err))
                }
            }
        )*
    };
}

impl_app_error_from!(
    sea_orm::DbErr,
    sea_orm::TransactionError<sea_orm::DbErr>,
    garde::Report,
    serde_json::Error,
    redis::RedisError,
    crate::jwt::JwtError,
    argon2::password_hash::Error,
    anyhow::Error,
);

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

#[cfg(test)]
mod tests {
    //! 覆盖意图：错误类型两层的构造函数与 Display、各 From 转换（sea_orm / garde /
    //! JWT / serde_json / redis / anyhow / io / argon2）、ServiceError→AppError 委托、
    //! IntoResponse 的 HTTP 状态码映射（含未知业务码回退 200）与错误链 source 记录。

    use super::*;

    // ---------- 构造函数与 Display ----------

    #[test]
    fn service_error_constructors_and_display() {
        let e = ServiceError::new(418, "teapot");
        assert_eq!((e.code, e.message.as_str()), (418, "teapot"));
        assert_eq!(format!("{e}"), "ServiceError(code=418, message=teapot)");
        assert_eq!(ServiceError::unauthorized("u").code, 401);
        assert_eq!(ServiceError::bad_request("b").code, 400);
        assert_eq!(ServiceError::not_found("n").code, 404);
        assert_eq!(ServiceError::forbidden("f").code, 403);
        assert_eq!(ServiceError::internal("i").code, 500);
    }

    #[test]
    fn app_error_constructors_source_and_display() {
        let e = AppError::new(418, "teapot");
        assert_eq!((e.code, e.message.as_str()), (418, "teapot"));
        assert!(e.source.is_none());
        assert_eq!(format!("{e}"), "AppError(code=418, message=teapot)");

        // with_source 链式附加根因
        let inner = std::io::Error::other("root cause");
        let with = AppError::new(500, "wrap").with_source(inner);
        assert_eq!(with.code, 500);
        assert!(with.source.is_some());

        assert_eq!(AppError::unauthorized("u").code, 401);
        assert_eq!(AppError::bad_request("b").code, 400);
        assert_eq!(AppError::not_found("n").code, 404);
        assert_eq!(AppError::forbidden("f").code, 403);
        assert_eq!(AppError::internal("i").code, 500);
    }

    // ---------- From 转换 ----------

    #[test]
    fn from_seaorm_dberr_maps_codes() {
        // 未找到 → 404
        let e: ServiceError = sea_orm::DbErr::RecordNotFound("id".into()).into();
        assert_eq!(e.code, 404);
        let e: ServiceError = sea_orm::DbErr::RecordNotUpdated.into();
        assert_eq!(e.code, 404);
        // 连接获取失败 → 503
        let e: ServiceError =
            sea_orm::DbErr::ConnectionAcquire(sea_orm::error::ConnAcquireErr::Timeout).into();
        assert_eq!(e.code, 503);
        // 类型转换 / 属性未设置 → 400
        let e: ServiceError = sea_orm::DbErr::TryIntoErr {
            from: "u64",
            into: "u8",
            source: Box::new(std::io::Error::new(std::io::ErrorKind::InvalidData, "conv")),
        }
        .into();
        assert_eq!(e.code, 400);
        let e: ServiceError = sea_orm::DbErr::AttrNotSet("name".into()).into();
        assert_eq!(e.code, 400);
        // 其它（普通执行错误）→ 500
        let e: ServiceError =
            sea_orm::DbErr::Exec(sea_orm::RuntimeErr::Internal("boom".into())).into();
        assert_eq!(e.code, 500);
    }

    #[test]
    fn from_seaorm_transaction_error() {
        // Transaction 内层 DbErr 委托转换（RecordNotFound → 404）
        let e: ServiceError =
            sea_orm::TransactionError::Transaction(sea_orm::DbErr::RecordNotFound("id".into()))
                .into();
        assert_eq!(e.code, 404);
        // 其它（Connection）→ 500 tx_failed
        let e: ServiceError = sea_orm::TransactionError::Connection(sea_orm::DbErr::Exec(
            sea_orm::RuntimeErr::Internal("conn".into()),
        ))
        .into();
        assert_eq!(e.code, 500);
    }

    #[test]
    fn from_garde_report_joins_messages() {
        // 非空 report：以 "; " 拼接 path: error
        let mut report = garde::Report::new();
        report.append(
            garde::Path::new("name"),
            garde::Error::new("长度不能少于 2"),
        );
        report.append(
            garde::Path::new("age"),
            garde::Error::new("数值不能大于 100"),
        );
        let e: ServiceError = report.into();
        assert_eq!(e.code, 400);
        assert_eq!(e.message, "name: 长度不能少于 2; age: 数值不能大于 100");

        // 空 report → 400 validate_failed
        let e: ServiceError = garde::Report::new().into();
        assert_eq!(e.code, 400);
        assert_eq!(e.message, crate::tr!("error.common.validate_failed"));
    }

    #[test]
    fn from_jwt_error_maps_codes() {
        use crate::jwt::JwtError;
        assert_eq!(ServiceError::from(JwtError::Expired).code, 401);
        assert_eq!(ServiceError::from(JwtError::InvalidSignature).code, 401);
        assert_eq!(ServiceError::from(JwtError::Malformed).code, 401);
        assert_eq!(ServiceError::from(JwtError::InvalidClaims).code, 401);
        assert_eq!(ServiceError::from(JwtError::GenerateFailed).code, 500);
    }

    #[test]
    fn from_serde_json_error_is_internal() {
        let err = serde_json::from_str::<i32>("not a number").unwrap_err();
        let e: ServiceError = err.into();
        assert_eq!(e.code, 500);
        assert_eq!(e.message, crate::tr!("error.common.process_failed"));
    }

    #[test]
    fn from_redis_error_distinguishes_auth() {
        // 认证失败 → 401
        let e: ServiceError =
            redis::RedisError::from((redis::ErrorKind::AuthenticationFailed, "auth failed")).into();
        assert_eq!(e.code, 401);
        assert_eq!(e.message, crate::tr!("error.common.cache_auth_failed"));
        // 其它 → 500
        let e: ServiceError = redis::RedisError::from((redis::ErrorKind::Io, "io")).into();
        assert_eq!(e.code, 500);
        assert_eq!(e.message, crate::tr!("error.common.cache_failed"));
    }

    #[test]
    fn from_anyhow_io_argon2_are_internal() {
        let e: ServiceError = anyhow::anyhow!("boom").into();
        assert_eq!(e.code, 500);
        assert_eq!(e.message, crate::tr!("error.common.internal"));

        let io = std::io::Error::new(std::io::ErrorKind::PermissionDenied, "denied");
        let e: ServiceError = io.into();
        assert_eq!(e.code, 500);
        assert_eq!(e.message, crate::tr!("error.common.io_error"));

        let e: ServiceError = argon2::password_hash::Error::Password.into();
        assert_eq!(e.code, 500);
        assert_eq!(
            e.message,
            crate::tr!("error.common.password_encrypt_failed")
        );
    }

    #[test]
    fn app_error_from_service_error_copies_fields() {
        let se = ServiceError::new(403, "forbidden");
        let ae: AppError = se.into();
        assert_eq!((ae.code, ae.message.as_str()), (403, "forbidden"));
        assert!(ae.source.is_none());
    }

    #[test]
    fn app_error_from_other_errors_delegates() {
        // 宏生成的委托路径：AppError::from(DbErr) == AppError::from(ServiceError::from(db_err))
        let ae: AppError = sea_orm::DbErr::RecordNotFound("x".into()).into();
        assert_eq!(ae.code, 404);
        assert_eq!(ae.message, crate::tr!("error.common.not_found"));

        let ae: AppError = crate::jwt::JwtError::GenerateFailed.into();
        assert_eq!(ae.code, 500);
    }

    // ---------- IntoResponse 状态码映射 ----------

    fn status_for(code: i32) -> StatusCode {
        AppError::new(code, "m").into_response().status()
    }

    #[test]
    fn into_response_maps_known_codes() {
        assert_eq!(status_for(400), StatusCode::BAD_REQUEST);
        assert_eq!(status_for(401), StatusCode::UNAUTHORIZED);
        assert_eq!(status_for(403), StatusCode::FORBIDDEN);
        assert_eq!(status_for(404), StatusCode::NOT_FOUND);
        assert_eq!(status_for(409), StatusCode::CONFLICT);
        assert_eq!(status_for(422), StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(status_for(429), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(status_for(500), StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(status_for(503), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[test]
    fn into_response_falls_back_to_200_for_unknown_codes() {
        // 200 / 自定义业务码 / 600 → 200 OK（保留 body.code 兼容前端）
        assert_eq!(status_for(200), StatusCode::OK);
        assert_eq!(status_for(600), StatusCode::OK);
        assert_eq!(status_for(-1), StatusCode::OK);
    }

    #[tokio::test]
    async fn into_response_body_carries_code_and_message() {
        let err = AppError::new(400, "参数错误");
        let resp = err.into_response();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let body = axum::body::to_bytes(resp.into_body(), 4096)
            .await
            .expect("读取响应体失败");
        let json: serde_json::Value = serde_json::from_slice(&body).expect("响应体应为 JSON");
        assert_eq!(json["code"], 400);
        assert_eq!(json["msg"], "参数错误");
        assert!(json["data"].is_null());
    }

    #[test]
    fn into_response_with_source_records_log_but_returns_same_body() {
        // source 存在时不应影响响应结构（仅写 tracing 日志）
        let err = AppError::new(500, "内部错误").with_source(std::io::Error::other("root"));
        let resp = err.into_response();
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }
}
