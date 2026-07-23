// axum-backend/src/handler/sys_job_log_handler.rs
//! 定时任务日志 Handler（Axum 原生实现）
//!
//! 接口路径对齐 ruoyi-vue3-ts 前端：
//! - GET    /monitor/jobLog/list           分页查询任务日志
//! - DELETE /monitor/jobLog/{jobLogIds}    批量删除任务日志
//! - DELETE /monitor/jobLog/clean          清空任务日志
//! - POST   /monitor/jobLog/export         导出任务日志列表

use std::sync::Arc;
use axum::extract::{Form, Path, Query, State};
use axum::response::Response;

use crate::common::excel::{export_to_excel, ExcelColumn};
use crate::common::{AjaxResult, AppError, TableDataInfo};
use crate::entity::sys_job_log::Model as SysJobLogModel;
use crate::service::sys_job_service::JobLogQueryDto;
use crate::state::AppState;
use crate::utils::parse_id_list;

/// GET /monitor/jobLog/list
/// 分页查询任务日志
#[utoipa::path(
    get,
    path = "/monitor/jobLog/list",
    params(JobLogQueryDto),
    responses(
        (status = 200, description = "查询成功", body = TableDataInfo<SysJobLogModel>),
        (status = 500, description = "服务器错误"),
    ),
    tag = "monitor-joblog"
)]
pub async fn list(
    State(state): State<Arc<AppState>>,
    Query(query): Query<JobLogQueryDto>,
) -> Result<TableDataInfo<SysJobLogModel>, AppError> {
    let (rows, total) = state.job_service.get_job_log_page(query).await?;
    Ok(TableDataInfo::new(total, rows))
}

/// DELETE /monitor/jobLog/{jobLogIds}
/// 批量删除任务日志（jobLogIds 为逗号分隔的 ID 字符串）
#[utoipa::path(
    delete,
    path = "/monitor/jobLog/{jobLogIds}",
    params(
        ("jobLogIds" = String, Path, description = "任务日志 ID 列表（逗号分隔）")
    ),
    responses(
        (status = 200, description = "删除成功", body = AjaxResult<serde_json::Value>),
        (status = 400, description = "日志 ID 不合法"),
    ),
    tag = "monitor-joblog"
)]
pub async fn remove(
    State(state): State<Arc<AppState>>,
    Path(job_log_ids): Path<String>,
) -> Result<AjaxResult<()>, AppError> {
    let ids: Vec<i64> = parse_id_list::<i64>(&job_log_ids);

    if ids.is_empty() {
        return Err(AppError::bad_request("日志 ID 不合法"));
    }

    state.job_service.delete_job_logs(ids).await?;
    Ok(AjaxResult::success_msg("删除成功"))
}

/// DELETE /monitor/jobLog/clean
/// 清空全部任务日志
#[utoipa::path(
    delete,
    path = "/monitor/jobLog/clean",
    responses(
        (status = 200, description = "清空成功", body = AjaxResult<serde_json::Value>),
        (status = 500, description = "服务器错误"),
    ),
    tag = "monitor-joblog"
)]
pub async fn clean(
    State(state): State<Arc<AppState>>,
) -> Result<AjaxResult<()>, AppError> {
    state.job_service.clean_job_logs().await?;
    Ok(AjaxResult::success_msg("清空成功"))
}

/// POST /monitor/jobLog/export
/// 导出任务日志列表为 Excel（返回二进制 xlsx 流，对齐前端 proxy.download 的 blob 期望）
///
/// 前端 download() 发送 application/x-www-form-urlencoded，使用 Form 提取器
#[utoipa::path(
    post,
    path = "/monitor/jobLog/export",
    params(JobLogQueryDto),
    responses(
        (status = 200, description = "导出成功", content_type = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"),
        (status = 500, description = "服务器错误"),
    ),
    tag = "monitor-joblog"
)]
pub async fn export(
    State(state): State<Arc<AppState>>,
    Form(query): Form<JobLogQueryDto>,
) -> Result<Response, AppError> {
    let rows = state.job_service.export_job_logs(query).await?;

    let columns = [
        ExcelColumn { header: "日志编号", getter: |r: &SysJobLogModel| r.job_log_id.to_string().into() },
        ExcelColumn { header: "任务名称", getter: |r: &SysJobLogModel| r.job_name.clone().into() },
        ExcelColumn { header: "任务组名", getter: |r: &SysJobLogModel| r.job_group.clone().into() },
        ExcelColumn { header: "调用目标字符串", getter: |r: &SysJobLogModel| r.invoke_target.clone().into() },
        ExcelColumn { header: "日志信息", getter: |r: &SysJobLogModel| r.job_message.clone().unwrap_or_default().into() },
        ExcelColumn { header: "执行状态", getter: |r: &SysJobLogModel| r.status.clone().unwrap_or_default().into() },
        ExcelColumn { header: "异常信息", getter: |r: &SysJobLogModel| r.exception_info.clone().unwrap_or_default().into() },
        ExcelColumn {
            header: "执行时间",
            getter: |r: &SysJobLogModel| {
                r.create_time
                    .map(|dt| dt.format("%Y-%m-%d %H:%M:%S").to_string())
                    .unwrap_or_default()
                    .into()
            }
        },
    ];

    export_to_excel("调度日志", "job_log", &columns, &rows)
}
