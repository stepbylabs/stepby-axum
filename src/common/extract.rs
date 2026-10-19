//! 自定义请求提取器
//!
//! 当前提供：
//! - [`ValidatedJson`]：自动校验的 JSON 提取器（P1-24）
//!
//! T-01：校验框架由 validator 迁移为 garde，
//! 校验经 `common::i18n::validate` 按请求 locale 生成错误消息。

use axum::Json;
use axum::extract::FromRequest;
use axum::extract::Request;
use serde::de::DeserializeOwned;

use crate::common::AppError;
use crate::common::i18n;

/// 自动校验的 JSON 提取器（P1-24）
///
/// 在解析 JSON 后自动调用 garde 校验，校验失败返回 400。
/// 替代 handler 层 `Json(dto): Json<T>` + 手动校验的样板代码。
///
/// # 示例
/// ```ignore
/// pub async fn add(
///     State(state): State<Arc<AppState>>,
///     ValidatedJson(dto): ValidatedJson<NoticeAddDto>,
/// ) -> Result<AjaxResult<()>, AppError> {
///     // 无需手动调用 dto.validate()
///     state.notice_service.add_notice(dto, ...).await?;
///     Ok(AjaxResult::success_msg("新增成功"))
/// }
/// ```
#[derive(Debug)]
pub struct ValidatedJson<T>(pub T);

impl<T, S> FromRequest<S> for ValidatedJson<T>
where
    T: DeserializeOwned + garde::Validate<Context = ()>,
    S: Send + Sync,
{
    type Rejection = AppError;

    async fn from_request(req: Request, state: &S) -> Result<Self, Self::Rejection> {
        let Json(value) = Json::<T>::from_request(req, state).await.map_err(|e| {
            // P3 修复: JSON 解析错误可能包含字段路径/类型等内部细节，仅写日志
            tracing::warn!(error = %e, "JSON 请求体解析失败");
            AppError::bad_request(&crate::tr!("error.common.parse_failed"))
        })?;
        i18n::validate(&value).map_err(AppError::from)?;
        Ok(ValidatedJson(value))
    }
}

/// 自动校验的**查询串**提取器（批七十四 B2）
///
/// 与 [`ValidatedJson`] 同源同口径：反序列化后调用 garde，失败返回 400（错误消息按
/// 请求 locale 生成）。存在的理由是一个**形状缺陷**：`#[derive(Validate)]` + `#[garde(..)]`
/// 只是声明，只有提取器真的调用 `validate()` 才生效——本仓 `ValidatedJson` 早已接线，
/// 而 `Query<T>` 侧此前**一处都没有**，于是挂在查询 DTO 上的约束等于注释
/// （实测唯一命中点：`AssignAuthRoleDto.user_id` 的 `range(min = 1)`，`user_id=0/-5`
/// 会一路打到仓储层）。
///
/// 反向差集由 `handler::api_contract_guard::guarded_dtos_are_extracted_through_validated_extractors`
/// 钉住：凡带 `#[garde(..)]` 的 DTO，其提取点必须全部是 `ValidatedJson`/`ValidatedQuery`。
#[derive(Debug)]
pub struct ValidatedQuery<T>(pub T);

impl<T, S> FromRequest<S> for ValidatedQuery<T>
where
    T: DeserializeOwned + garde::Validate<Context = ()>,
    S: Send + Sync,
{
    type Rejection = AppError;

    async fn from_request(req: Request, state: &S) -> Result<Self, Self::Rejection> {
        let value = axum::extract::Query::<T>::from_request(req, state)
            .await
            .map_err(|e| {
                // 与 JSON 侧同口径：解析细节只进日志，对外统一文案（C.8/C.9）
                tracing::warn!(error = %e, "查询串解析失败");
                AppError::bad_request(&crate::tr!("error.common.parse_failed"))
            })?;
        i18n::validate(&value.0).map_err(AppError::from)?;
        Ok(ValidatedQuery(value.0))
    }
}

#[cfg(test)]
mod tests {
    //! 覆盖意图：`ValidatedJson` 提取器三条路径——合法 JSON 且校验通过（Ok）、
    //! JSON 解析失败（400 parse_failed）、合法 JSON 但 garde 校验失败（400）。
    use super::*;
    use axum::body::Body;
    use axum::extract::FromRequest;
    use axum::http::{Request, header};
    use serde::Deserialize;

    #[derive(Debug, Deserialize, garde::Validate)]
    struct TestDto {
        #[garde(length(min = 2, max = 8))]
        name: String,
        #[garde(range(min = 1, max = 120))]
        age: i32,
    }

    fn json_request(body: &str) -> Request<Body> {
        Request::builder()
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(body.to_string()))
            .expect("构造请求失败")
    }

    #[tokio::test]
    async fn valid_json_and_validation_ok() {
        let req = json_request(r#"{"name":"Alice","age":30}"#);
        let ValidatedJson(dto) = ValidatedJson::<TestDto>::from_request(req, &())
            .await
            .expect("合法 JSON 且校验通过应成功");
        assert_eq!(dto.name, "Alice");
        assert_eq!(dto.age, 30);
    }

    #[tokio::test]
    async fn malformed_json_returns_bad_request() {
        // 非法 JSON（缺少闭合）→ 400 parse_failed，不泄漏解析细节
        let req = json_request(r#"{"name":"Alice","age":}"#);
        let err = ValidatedJson::<TestDto>::from_request(req, &())
            .await
            .expect_err("非法 JSON 应失败");
        assert_eq!(err.code, 400);
        assert_eq!(err.message, crate::tr!("error.common.parse_failed"));
    }

    #[tokio::test]
    async fn missing_content_type_is_rejected() {
        // 无 Content-Type → axum Json 拒绝 → 400 parse_failed
        let req = Request::builder()
            .body(Body::from(r#"{"name":"Alice","age":30}"#))
            .expect("构造请求失败");
        let err = ValidatedJson::<TestDto>::from_request(req, &())
            .await
            .expect_err("缺少 Content-Type 应失败");
        assert_eq!(err.code, 400);
    }

    #[tokio::test]
    async fn validation_failure_returns_400() {
        // 结构合法但校验不过（name 过短、age 超界）→ 400
        let req = json_request(r#"{"name":"A","age":200}"#);
        let err = ValidatedJson::<TestDto>::from_request(req, &())
            .await
            .expect_err("校验失败应返回错误");
        assert_eq!(err.code, 400);
        // 消息包含字段路径与失败原因（默认 locale zh-CN）
        assert!(err.message.contains("name"), "实际消息: {}", err.message);
        assert!(err.message.contains("age"), "实际消息: {}", err.message);
    }

    // ---------- ValidatedQuery（b74 B2）：与 JSON 侧三条路径同判据 ----------

    fn query_request(qs: &str) -> Request<Body> {
        Request::builder()
            .method("GET")
            .uri(format!("/x?{qs}"))
            .body(Body::empty())
            .expect("构造请求失败")
    }

    #[tokio::test]
    async fn valid_query_passes_validation() {
        let ValidatedQuery(dto) =
            ValidatedQuery::<TestDto>::from_request(query_request("name=Alice&age=30"), &())
                .await
                .expect("合法查询串且校验通过应成功");
        assert_eq!(dto.name, "Alice");
        assert_eq!(dto.age, 30);
    }

    #[tokio::test]
    async fn query_validation_failure_returns_400() {
        // 对照组的反面：age 越界必须被拒（若这里放行，说明查询侧仍是"声明即校验"的假象）
        let err = ValidatedQuery::<TestDto>::from_request(query_request("name=Alice&age=999"), &())
            .await
            .expect_err("越界查询参数应被校验拒绝");
        assert_eq!(err.code, 400);
        assert!(err.message.contains("age"), "实际消息: {}", err.message);
    }

    #[tokio::test]
    async fn query_type_error_returns_400_without_leaking_parser_detail() {
        // age 传非数字 → serde 失败 → 统一文案，且不得把 serde 细节（字段类型/路径）带进响应
        let err = ValidatedQuery::<TestDto>::from_request(query_request("name=Alice&age=abc"), &())
            .await
            .expect_err("类型不符应失败");
        assert_eq!(err.code, 400);
        assert_eq!(err.message, crate::tr!("error.common.parse_failed"));
    }

    #[tokio::test]
    async fn missing_query_field_is_rejected() {
        // 缺 required 字段 → serde 失败（不是"静默用默认值"）
        let err = ValidatedQuery::<TestDto>::from_request(query_request("name=Alice"), &())
            .await
            .expect_err("缺字段应失败");
        assert_eq!(err.code, 400);
    }
}
