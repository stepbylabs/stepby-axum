//! 自定义请求提取器
//!
//! 当前提供：
//! - [`ValidatedJson`]：自动校验的 JSON 提取器（P1-24）
//!
//! T-01：校验框架由 validator 迁移为 garde，
//! 校验经 `common::i18n::validate` 按请求 locale 生成错误消息。

use axum::extract::FromRequest;
use axum::extract::Request;
use axum::Json;
use serde::de::DeserializeOwned;

use crate::common::i18n;
use crate::common::AppError;

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
pub struct ValidatedJson<T>(pub T);

impl<T, S> FromRequest<S> for ValidatedJson<T>
where
    T: DeserializeOwned + garde::Validate<Context = ()>,
    S: Send + Sync,
{
    type Rejection = AppError;

    async fn from_request(req: Request, state: &S) -> Result<Self, Self::Rejection> {
        let Json(value) = Json::<T>::from_request(req, state)
            .await
            .map_err(|e| {
                // P3 修复: JSON 解析错误可能包含字段路径/类型等内部细节，仅写日志
                tracing::warn!(error = %e, "JSON 请求体解析失败");
                AppError::bad_request(&crate::tr!("error.common.parse_failed"))
            })?;
        i18n::validate(&value).map_err(AppError::from)?;
        Ok(ValidatedJson(value))
    }
}
