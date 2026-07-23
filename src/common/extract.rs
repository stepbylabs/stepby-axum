//! 自定义请求提取器
//!
//! 当前提供：
//! - [`ValidatedJson`]：自动校验的 JSON 提取器（P1-24）

use axum::extract::FromRequest;
use axum::extract::Request;
use axum::Json;
use serde::de::DeserializeOwned;
use validator::Validate;

use crate::common::AppError;

/// 自动校验的 JSON 提取器（P1-24）
///
/// 在解析 JSON 后自动调用 `T::validate()`，校验失败返回 400。
/// 替代 handler 层 `Json(dto): Json<T>` + 手动 `dto.validate()?` 的样板代码，
/// 消除 19 处重复的 validate 调用。
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
    T: DeserializeOwned + Validate,
    S: Send + Sync,
{
    type Rejection = AppError;

    async fn from_request(req: Request, state: &S) -> Result<Self, Self::Rejection> {
        let Json(value) = Json::<T>::from_request(req, state)
            .await
            .map_err(|e| AppError::bad_request(&format!("请求参数解析失败: {e}")))?;
        value
            .validate()
            .map_err(|e| AppError::bad_request(&format!("请求参数校验失败: {e}")))?;
        Ok(ValidatedJson(value))
    }
}
