// backend-axum/src/handler/sys_job_handler.rs
//! 定时任务管理 Handler（Axum 原生实现）
//!
//! 接口路径对齐前端调用规范：
//! - GET    /monitor/job/list           分页查询任务
//! - GET    /monitor/job/{jobId}        查询任务详情
//! - POST   /monitor/job                新增任务
//! - PUT    /monitor/job                修改任务
//! - DELETE /monitor/job/{jobIds}       批量删除任务
//! - PUT    /monitor/job/changeStatus   切换任务状态
//! - PUT    /monitor/job/run            手动执行一次
//! - POST   /monitor/job/export         导出任务列表

use axum::extract::{Form, Path, Query, State};
use axum::response::Response;
use std::sync::Arc;

use crate::common::ValidatedJson;
use crate::common::constants::MAX_BATCH_DELETE_SIZE;
use crate::common::excel::{CellValue, ExcelColumn, export_to_excel};
use crate::common::{AjaxResult, AppError, TableDataInfo};
use crate::middleware::Operator;
use crate::service::sys_job_service::{
    JobAddDto, JobEditDto, JobQueryDto, JobRunDto, JobStatusDto, JobVo,
};
use crate::state::AppState;
use crate::utils::parse_id_list;

/// GET /monitor/job/list
/// 分页查询任务
#[utoipa::path(
    get,
    path = "/monitor/job/list",
    params(JobQueryDto),
    responses(
        (status = 200, description = "查询成功", body = TableDataInfo<JobVo>),
        (status = 500, description = "服务器错误"),
    ),
    tag = "monitor-job"
)]
pub async fn list(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    Query(query): Query<JobQueryDto>,
) -> Result<TableDataInfo<JobVo>, AppError> {
    let (rows, total) = state
        .job_service
        .get_job_page(
            query,
            crate::common::tenant::tenant_scope(operator.tenant_id()),
        )
        .await?;
    Ok(TableDataInfo::new(total, rows))
}

/// GET /monitor/job/{jobId}
/// 查询任务详情
#[utoipa::path(
    get,
    path = "/monitor/job/{jobId}",
    params(
        ("jobId" = i64, Path, description = "任务 ID")
    ),
    responses(
        (status = 200, description = "查询成功", body = AjaxResult<JobVo>),
        (status = 404, description = "任务不存在"),
    ),
    tag = "monitor-job"
)]
pub async fn get_info_by_id(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    Path(job_id): Path<i64>,
) -> Result<AjaxResult<JobVo>, AppError> {
    let vo = state
        .job_service
        .get_job_by_id_scoped(
            job_id,
            crate::common::tenant::tenant_scope(operator.tenant_id()),
        )
        .await?;
    Ok(AjaxResult::success(vo))
}

/// POST /monitor/job
/// 新增任务
#[utoipa::path(
    post,
    path = "/monitor/job",
    request_body = JobAddDto,
    responses(
        (status = 200, description = "新增成功", body = AjaxResult<serde_json::Value>),
        (status = 400, description = "参数错误或 cron 表达式不合法"),
    ),
    tag = "monitor-job"
)]
pub async fn add(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    ValidatedJson(dto): ValidatedJson<JobAddDto>,
) -> Result<AjaxResult<()>, AppError> {
    state
        .job_service
        .add_job(dto, operator.username(), operator.tenant_id())
        .await?;
    Ok(AjaxResult::success_msg(&crate::tr!("msg.success.add")))
}

/// PUT /monitor/job
/// 修改任务
#[utoipa::path(
    put,
    path = "/monitor/job",
    request_body = JobEditDto,
    responses(
        (status = 200, description = "修改成功", body = AjaxResult<serde_json::Value>),
        (status = 400, description = "参数错误"),
        (status = 404, description = "任务不存在"),
    ),
    tag = "monitor-job"
)]
pub async fn edit(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    ValidatedJson(dto): ValidatedJson<JobEditDto>,
) -> Result<AjaxResult<()>, AppError> {
    state
        .job_service
        .edit_job(dto, operator.username(), operator.tenant_id())
        .await?;
    Ok(AjaxResult::success_msg(&crate::tr!("msg.success.edit")))
}

/// DELETE /monitor/job/{jobIds}
/// 批量删除任务（jobIds 为逗号分隔的 ID 字符串）
#[utoipa::path(
    delete,
    path = "/monitor/job/{jobIds}",
    params(
        ("jobIds" = String, Path, description = "任务 ID 列表（逗号分隔）")
    ),
    responses(
        (status = 200, description = "删除成功", body = AjaxResult<serde_json::Value>),
        (status = 400, description = "任务 ID 不合法"),
    ),
    tag = "monitor-job"
)]
pub async fn remove(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    Path(job_ids): Path<String>,
) -> Result<AjaxResult<()>, AppError> {
    let ids: Vec<i64> = parse_id_list::<i64>(&job_ids);

    if ids.is_empty() {
        return Err(AppError::bad_request(&crate::tr!("error.job.id_invalid")));
    }
    if ids.len() > MAX_BATCH_DELETE_SIZE {
        return Err(AppError::bad_request(&crate::tr!(
            "error.common.batch_size_exceeded",
            max = MAX_BATCH_DELETE_SIZE
        )));
    }

    state
        .job_service
        .delete_jobs(ids, operator.tenant_id())
        .await?;
    Ok(AjaxResult::success_msg(&crate::tr!("msg.success.delete")))
}

/// PUT /monitor/job/changeStatus
/// 切换任务状态
#[utoipa::path(
    put,
    path = "/monitor/job/changeStatus",
    request_body = JobStatusDto,
    responses(
        (status = 200, description = "状态修改成功", body = AjaxResult<serde_json::Value>),
        (status = 400, description = "参数错误"),
    ),
    tag = "monitor-job"
)]
pub async fn change_status(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    ValidatedJson(dto): ValidatedJson<JobStatusDto>,
) -> Result<AjaxResult<()>, AppError> {
    state
        .job_service
        .change_status(dto, operator.tenant_id())
        .await?;
    Ok(AjaxResult::success_msg(&crate::tr!(
        "msg.success.status_change"
    )))
}

/// PUT /monitor/job/run
/// 手动执行一次
#[utoipa::path(
    put,
    path = "/monitor/job/run",
    request_body = JobRunDto,
    responses(
        (status = 200, description = "执行成功", body = AjaxResult<serde_json::Value>),
        (status = 400, description = "参数错误"),
        (status = 404, description = "任务不存在"),
    ),
    tag = "monitor-job"
)]
pub async fn run(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    ValidatedJson(dto): ValidatedJson<JobRunDto>,
) -> Result<AjaxResult<()>, AppError> {
    state
        .job_service
        .run_job_once(dto, operator.tenant_id())
        .await?;
    Ok(AjaxResult::success_msg(&crate::tr!("msg.success.execute")))
}

/// POST /monitor/job/export
/// 导出任务列表为 Excel（返回二进制 xlsx 流，对齐前端 proxy.download 的 blob 期望）
///
/// 前端 download() 发送 application/x-www-form-urlencoded，使用 Form 提取器
#[utoipa::path(
    post,
    path = "/monitor/job/export",
    params(JobQueryDto),
    responses(
        (status = 200, description = "导出成功", content_type = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"),
        (status = 500, description = "服务器错误"),
    ),
    tag = "monitor-job"
)]
pub async fn export(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    Form(query): Form<JobQueryDto>,
) -> Result<Response, AppError> {
    let rows = state
        .job_service
        .export_jobs(
            query,
            crate::common::tenant::tenant_scope(operator.tenant_id()),
        )
        .await?;

    let columns = [
        ExcelColumn {
            key: "jobId",
            header: ("任务编号", "Job ID"),
            getter: |r: &JobVo| CellValue::Number(r.job.job_id as f64),
        },
        ExcelColumn {
            key: "jobName",
            header: ("任务名称", "Job Name"),
            getter: |r: &JobVo| CellValue::Text(r.job.job_name.clone().into()),
        },
        ExcelColumn {
            key: "jobGroup",
            header: ("任务组名", "Job Group"),
            getter: |r: &JobVo| CellValue::Text(r.job.job_group.clone().into()),
        },
        ExcelColumn {
            key: "invokeTarget",
            header: ("调用目标字符串", "Invoke Target"),
            getter: |r: &JobVo| CellValue::Text(r.job.invoke_target.clone().into()),
        },
        ExcelColumn {
            key: "cronExpression",
            header: ("cron表达式", "Cron Expression"),
            getter: |r: &JobVo| {
                CellValue::Text(r.job.cron_expression.clone().unwrap_or_default().into())
            },
        },
        ExcelColumn {
            key: "misfirePolicy",
            header: ("错误策略", "Misfire Policy"),
            getter: |r: &JobVo| {
                CellValue::Text(
                    match r.job.misfire_policy.as_deref() {
                        Some("0") => crate::tr!("common.job.misfire_default"),
                        Some("1") => crate::tr!("common.job.misfire_immediate"),
                        Some("2") => crate::tr!("common.job.misfire_once"),
                        Some("3") => crate::tr!("common.job.misfire_give_up"),
                        _ => String::new(),
                    }
                    .into(),
                )
            },
        },
        ExcelColumn {
            key: "concurrent",
            header: ("并发执行", "Concurrent"),
            getter: |r: &JobVo| {
                CellValue::Text(
                    match r.job.concurrent.as_deref() {
                        Some("0") => crate::tr!("common.job.concurrent_allow"),
                        Some("1") => crate::tr!("common.job.concurrent_forbid"),
                        _ => String::new(),
                    }
                    .into(),
                )
            },
        },
        ExcelColumn {
            key: "status",
            header: ("状态", "Status"),
            getter: |r: &JobVo| {
                CellValue::Text(
                    if r.job.status.as_deref() == Some("0") {
                        crate::tr!("common.status.normal")
                    } else {
                        crate::tr!("common.status.disabled")
                    }
                    .into(),
                )
            },
        },
        ExcelColumn {
            key: "nextValidTime",
            header: ("下次执行时间", "Next Run Time"),
            getter: |r: &JobVo| {
                CellValue::Text(r.next_valid_time.clone().unwrap_or_default().into())
            },
        },
        ExcelColumn {
            key: "remark",
            header: ("备注", "Remark"),
            getter: |r: &JobVo| CellValue::Text(r.job.remark.clone().unwrap_or_default().into()),
        },
    ];

    export_to_excel(&crate::tr!("excel.sheet.job"), "job", &columns, &rows).await
}
