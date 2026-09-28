//! 用户消息偏好 / 免打扰 Handler（Axum 原生实现）
//!
//! 接口路径（受保护，仅需登录即可，操作对象恒为当前登录用户，无需 RBAC）：
//! - GET  /system/profile/pref   查询当前用户消息偏好
//! - PUT  /system/profile/pref   更新当前用户消息偏好 / 免打扰

use std::sync::Arc;

use axum::Json;
use axum::extract::State;

use crate::common::{AjaxResult, AppError};
use crate::middleware::Operator;
use crate::service::sys_user_pref_service::{PrefUpdateDto, PrefVo};
use crate::state::AppState;

/// 解析 Operator 携带的 user_id（JWT sub，字符串）为 i64
fn parse_user_id(sub: &str) -> Result<i64, AppError> {
    sub.parse::<i64>()
        .map_err(|_| AppError::unauthorized(&crate::tr!("error.auth.login_info_missing")))
}

/// GET /system/profile/pref — 查询当前用户消息偏好
#[utoipa::path(
    get,
    path = "/system/profile/pref",
    responses(
        (status = 200, description = "当前用户消息偏好", body = AjaxResult<PrefVo>),
        (status = 401, description = "未授权"),
    ),
    tag = "system-user"
)]
pub async fn get_pref(
    State(state): State<Arc<AppState>>,
    operator: Operator,
) -> Result<AjaxResult<PrefVo>, AppError> {
    let user_id = parse_user_id(operator.user_id())?;
    let vo = state.user_pref_service.get(user_id).await?;
    Ok(AjaxResult::success(vo))
}

/// PUT /system/profile/pref — 更新当前用户消息偏好 / 免打扰
#[utoipa::path(
    put,
    path = "/system/profile/pref",
    request_body = PrefUpdateDto,
    responses(
        (status = 200, description = "更新后的消息偏好", body = AjaxResult<PrefVo>),
        (status = 400, description = "参数错误（取值非 '0'/'1' 或时间格式非法）"),
        (status = 401, description = "未授权"),
    ),
    tag = "system-user"
)]
pub async fn update_pref(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    Json(dto): Json<PrefUpdateDto>,
) -> Result<AjaxResult<PrefVo>, AppError> {
    let user_id = parse_user_id(operator.user_id())?;
    let vo = state
        .user_pref_service
        .update(user_id, operator.tenant_id(), dto)
        .await?;
    Ok(AjaxResult::success(vo))
}
