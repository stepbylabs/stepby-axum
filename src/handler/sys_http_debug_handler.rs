//! 在线 HTTP 调试器 Handler（/tool/http-debug/execute）
//!
//! 受保护接口（需 auth_middleware + permission_middleware，权限 tool:httpDebug:list）。
//! 由服务端转发用户指定的目标接口并返回状态码/响应头/响应体/耗时等调试信息。
//! SSRF 防护位于 Service 层（见 sys_http_debug_service / common::ssrf）。

use std::sync::Arc;

use axum::Json;
use axum::extract::State;

use crate::common::{AjaxResult, AppError};
use crate::middleware::Operator;
use crate::service::sys_http_debug_service::{HttpDebugDto, HttpDebugVo};
use crate::state::AppState;

/// POST /tool/http-debug/execute — 执行一次调试请求
///
/// 返回 200 + AjaxResult；传输层错误（连接失败/超时等）不视为 HTTP 错误，
/// 而是通过 `error` 字段返回（status=0），便于前端在不产生 HTTP 4xx/5xx 的前提下
/// 统一展示调试结果。SSRF 违规/参数非法则以 400 直接拒绝。
pub async fn execute(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    Json(dto): Json<HttpDebugDto>,
) -> Result<AjaxResult<HttpDebugVo>, AppError> {
    tracing::info!(
        user = operator.username(),
        method = %dto.method,
        url = %dto.url,
        "在线 HTTP 调试器转发请求"
    );
    let vo = state.http_debug_service.execute(dto).await?;
    Ok(AjaxResult::success(vo))
}
