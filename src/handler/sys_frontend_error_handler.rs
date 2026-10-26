//! 前端异常与性能监控 Handler（Tier-S #1）
//!
//! 接口路径对齐前端调用规范：
//! - POST   /monitor/frontendError/report   批量上报（仅登录，无需 RBAC，前端 errorReporter/web-vitals 调用）
//! - GET    /monitor/frontendError/list     分页查询
//! - GET    /monitor/frontendError/{id}     详情
//! - DELETE /monitor/frontendError/{ids}    批量删除
//! - DELETE /monitor/frontendError/clean    清空（保留期 / 按时间范围）
//! - GET    /monitor/frontendError/stats    概览统计（来源分布 + 每日 error 趋势）

use axum::extract::{Json, Path, Query, State};
use std::sync::Arc;

use crate::common::constants::MAX_BATCH_DELETE_SIZE;
use crate::common::{AjaxResult, AppError, TableDataInfo};
use crate::entity::sys_frontend_error::Model as SysFrontendErrorModel;
use crate::middleware::Operator;
use crate::service::sys_frontend_error_service::{
    FrontendErrorQueryDto, FrontendErrorStatsVo, FrontendReportDto,
};
use crate::state::AppState;
use crate::utils::parse_id_list;

/// 前端异常清理保留最近 N 天（无时间参数时按保留期清理）
const FRONTEND_ERROR_CLEAN_RETAIN_DAYS: i64 = 30;

/// POST /monitor/frontendError/report
/// 批量上报前端异常与性能指标（仅需登录，落库前服务端截断/归一化）
#[utoipa::path(
    post,
    path = "/monitor/frontendError/report",
    request_body = FrontendReportDto,
    responses(
        (status = 200, description = "上报成功", body = AjaxResult<serde_json::Value>),
        (status = 401, description = "未登录"),
        (status = 500, description = "服务器错误"),
    ),
    tag = "monitor-frontend-error"
)]
pub async fn report(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    Json(body): Json<FrontendReportDto>,
) -> Result<AjaxResult<serde_json::Value>, AppError> {
    let reported = state
        .frontend_error_service
        .report(
            body.items,
            Some(operator.username().to_string()),
            operator.tenant_id(),
        )
        .await?;
    Ok(AjaxResult::success(
        serde_json::json!({ "reported": reported }),
    ))
}

/// GET /monitor/frontendError/list
#[utoipa::path(
    get,
    path = "/monitor/frontendError/list",
    params(FrontendErrorQueryDto),
    responses(
        (status = 200, description = "查询成功", body = TableDataInfo<SysFrontendErrorModel>),
        (status = 500, description = "服务器错误"),
    ),
    tag = "monitor-frontend-error"
)]
pub async fn list(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    Query(query): Query<FrontendErrorQueryDto>,
) -> Result<TableDataInfo<SysFrontendErrorModel>, AppError> {
    // 多租户：租户操作者仅见本租户记录；平台（tenant_id=0）全量
    let (rows, total) = state
        .frontend_error_service
        .get_page(
            query,
            crate::common::tenant::tenant_scope(operator.tenant_id()),
        )
        .await?;
    Ok(TableDataInfo::new(total, rows))
}

/// GET /monitor/frontendError/{id}
#[utoipa::path(
    get,
    path = "/monitor/frontendError/{id}",
    params(("id" = i64, Path, description = "记录 ID")),
    responses(
        (status = 200, description = "查询成功", body = AjaxResult<SysFrontendErrorModel>),
        (status = 404, description = "记录不存在"),
    ),
    tag = "monitor-frontend-error"
)]
pub async fn info(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    Path(id): Path<i64>,
) -> Result<AjaxResult<SysFrontendErrorModel>, AppError> {
    let model = state
        .frontend_error_service
        .get_by_id(id, operator.tenant_id())
        .await?;
    Ok(AjaxResult::success(model))
}

/// DELETE /monitor/frontendError/{ids}
#[utoipa::path(
    delete,
    path = "/monitor/frontendError/{ids}",
    params(("ids" = String, Path, description = "记录 ID 列表（逗号分隔）")),
    responses(
        (status = 200, description = "删除成功", body = AjaxResult<serde_json::Value>),
        (status = 400, description = "ID 不合法"),
    ),
    tag = "monitor-frontend-error"
)]
pub async fn remove(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    Path(ids): Path<String>,
) -> Result<AjaxResult<()>, AppError> {
    let ids: Vec<i64> = parse_id_list::<i64>(&ids)?;
    if ids.is_empty() {
        return Err(AppError::bad_request(&crate::tr!(
            "error.frontend_error.not_found"
        )));
    }
    if ids.len() > MAX_BATCH_DELETE_SIZE {
        return Err(AppError::bad_request(&crate::tr!(
            "error.common.batch_size_exceeded",
            max = MAX_BATCH_DELETE_SIZE
        )));
    }
    state
        .frontend_error_service
        .remove(
            ids,
            crate::common::tenant::tenant_scope(operator.tenant_id()),
        )
        .await?;
    Ok(AjaxResult::success_msg(&crate::tr!("msg.success.delete")))
}

/// 清理查询参数（兼容前端 addDateRange 嵌套格式 `params[beginTime]`/`params[endTime]`）
#[derive(Debug, serde::Deserialize, utoipa::IntoParams)]
#[serde(rename_all = "camelCase")]
pub struct FrontendErrorCleanQuery {
    #[serde(alias = "params[beginTime]", default)]
    pub begin_time: Option<String>,
    #[serde(alias = "params[endTime]", default)]
    pub end_time: Option<String>,
}

/// DELETE /monitor/frontendError/clean
/// 清空前端异常记录：传时间范围则按范围清理，否则保留最近 30 天
#[utoipa::path(
    delete,
    path = "/monitor/frontendError/clean",
    params(FrontendErrorCleanQuery),
    responses(
        (status = 200, description = "清空成功", body = AjaxResult<serde_json::Value>),
        (status = 500, description = "服务器错误"),
    ),
    tag = "monitor-frontend-error"
)]
pub async fn clean(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    Query(query): Query<FrontendErrorCleanQuery>,
) -> Result<AjaxResult<serde_json::Value>, AppError> {
    let _gate = crate::common::resource_gate::try_enter(
        crate::common::resource_gate::HeavyEntry::BulkDelete,
    )?;
    // 多租户：租户操作者仅清理本租户记录；平台（tenant_id=0）全量
    let tenant_scope = crate::common::tenant::tenant_scope(operator.tenant_id());
    let affected = if query.begin_time.is_some() || query.end_time.is_some() {
        tracing::warn!(
            "前端异常清理（按时间范围）：begin={:?} end={:?}，操作者={}",
            query.begin_time,
            query.end_time,
            operator.username()
        );
        state
            .frontend_error_service
            .clean_by_range(
                query.begin_time.clone(),
                query.end_time.clone(),
                tenant_scope,
            )
            .await?
    } else {
        let days = FRONTEND_ERROR_CLEAN_RETAIN_DAYS;
        tracing::warn!("前端异常清理：仅删除 {} 天前记录", days);
        state
            .frontend_error_service
            .clean(days, tenant_scope)
            .await?
    };
    Ok(AjaxResult::success(
        serde_json::json!({ "affected": affected }),
    ))
}

/// 统计查询参数
#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FrontendErrorStatsQuery {
    pub days: Option<i64>,
}

/// GET /monitor/frontendError/stats
#[utoipa::path(
    get,
    path = "/monitor/frontendError/stats",
    params(
        ("days" = Option<i64>, Query, description = "每日趋势统计天数（默认 30）")
    ),
    responses(
        (status = 200, description = "查询成功", body = AjaxResult<FrontendErrorStatsVo>),
        (status = 500, description = "服务器错误"),
    ),
    tag = "monitor-frontend-error"
)]
pub async fn stats(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    Query(params): Query<FrontendErrorStatsQuery>,
) -> Result<AjaxResult<FrontendErrorStatsVo>, AppError> {
    let days = params.days.unwrap_or(30).clamp(1, 365);
    let tenant_scope = crate::common::tenant::tenant_scope(operator.tenant_id());
    let vo = state
        .frontend_error_service
        .get_stats(days, tenant_scope)
        .await?;
    Ok(AjaxResult::success(vo))
}
