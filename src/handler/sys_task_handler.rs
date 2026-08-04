//! 任务进度中心 Handler（Axum 原生实现）
//!
//! 接口路径对齐 yebot-ui 前端：
//! - GET    /system/task/list          分页查询任务
//! - GET    /system/task/{taskId}      查询任务详情
//! - DELETE /system/task/{taskIds}     批量删除任务
//!
//! 任务创建/进度更新由其他业务模块（如 oper_log export >1000 行时）调用 SysTaskService。

use std::sync::Arc;
use axum::extract::{Path, Query, State};

use crate::common::{AjaxResult, AppError, TableDataInfo};
use crate::entity::sys_task::Model as SysTaskModel;
use crate::service::sys_task_service::TaskQueryDto;
use crate::state::AppState;
use crate::common::constants::MAX_BATCH_DELETE_SIZE;
use crate::utils::parse_id_list;

/// GET /system/task/list
/// 分页查询任务
#[utoipa::path(
    get,
    path = "/system/task/list",
    params(TaskQueryDto),
    responses(
        (status = 200, description = "查询成功", body = TableDataInfo<SysTaskModel>),
        (status = 500, description = "服务器错误"),
    ),
    tag = "system-task"
)]
pub async fn list(
    State(state): State<Arc<AppState>>,
    Query(query): Query<TaskQueryDto>,
) -> Result<TableDataInfo<SysTaskModel>, AppError> {
    let (rows, total) = state.task_service.get_task_page(query).await?;
    Ok(TableDataInfo::new(total, rows))
}

/// GET /system/task/{taskId}
/// 查询任务详情
#[utoipa::path(
    get,
    path = "/system/task/{taskId}",
    params(
        ("taskId" = i64, Path, description = "任务 ID")
    ),
    responses(
        (status = 200, description = "查询成功", body = AjaxResult<SysTaskModel>),
        (status = 404, description = "任务不存在"),
    ),
    tag = "system-task"
)]
pub async fn get_info(
    State(state): State<Arc<AppState>>,
    Path(task_id): Path<i64>,
) -> Result<AjaxResult<SysTaskModel>, AppError> {
    let model = state.task_service.get_task_by_id(task_id).await?;
    Ok(AjaxResult::success(model))
}

/// DELETE /system/task/{taskIds}
/// 批量删除任务（逗号分隔的 ID 字符串）
#[utoipa::path(
    delete,
    path = "/system/task/{taskIds}",
    params(
        ("taskIds" = String, Path, description = "任务 ID 列表（逗号分隔）")
    ),
    responses(
        (status = 200, description = "删除成功", body = AjaxResult<serde_json::Value>),
        (status = 400, description = "ID 不合法"),
    ),
    tag = "system-task"
)]
pub async fn remove(
    State(state): State<Arc<AppState>>,
    Path(task_ids): Path<String>,
) -> Result<AjaxResult<()>, AppError> {
    let ids: Vec<i64> = parse_id_list::<i64>(&task_ids);

    if ids.is_empty() {
        return Err(AppError::bad_request(&crate::tr!("error.task.id_invalid")));
    }
    if ids.len() > MAX_BATCH_DELETE_SIZE {
        return Err(AppError::bad_request(&crate::tr!(
            "error.common.batch_size_exceeded",
            max = MAX_BATCH_DELETE_SIZE
        )));
    }

    state.task_service.delete_tasks(ids).await?;
    Ok(AjaxResult::success_msg(&crate::tr!("msg.success.delete")))
}
