//! 数据备份/恢复 Handler（Axum 原生实现）
//!
//! 接口路径对齐 yebot-ui 前端：
//! - GET    /system/backup/list            分页查询备份日志
//! - GET    /system/backup/{backupId}      查询备份日志详情
//! - POST   /system/backup                 创建手动备份
//! - POST   /system/backup/restore/{id}    恢复指定备份
//! - GET    /system/backup/download/{id}   下载备份文件
//! - DELETE /system/backup/{backupIds}     批量删除备份日志及文件

use std::sync::Arc;
use axum::extract::{Path, Query, State};
use axum::response::Response;

use crate::common::{AjaxResult, AppError, TableDataInfo};
use crate::entity::sys_backup_log::Model as SysBackupLogModel;
use crate::middleware::Operator;
use crate::service::sys_backup_service::{BackupLogQueryDto, BackupCreateVo};
use crate::state::AppState;
use crate::utils::parse_id_list;
use axum::http::{header, HeaderValue, StatusCode};

/// GET /system/backup/list
/// 分页查询备份日志
#[utoipa::path(
    get,
    path = "/system/backup/list",
    params(BackupLogQueryDto),
    responses(
        (status = 200, description = "查询成功", body = TableDataInfo<SysBackupLogModel>),
        (status = 500, description = "服务器错误"),
    ),
    tag = "system-backup"
)]
pub async fn list(
    State(state): State<Arc<AppState>>,
    Query(query): Query<BackupLogQueryDto>,
) -> Result<TableDataInfo<SysBackupLogModel>, AppError> {
    let (rows, total) = state.backup_service.get_backup_log_page(query).await?;
    Ok(TableDataInfo::new(total, rows))
}

/// GET /system/backup/{backupId}
/// 查询备份日志详情
#[utoipa::path(
    get,
    path = "/system/backup/{backupId}",
    params(
        ("backupId" = i64, Path, description = "备份日志 ID")
    ),
    responses(
        (status = 200, description = "查询成功", body = AjaxResult<SysBackupLogModel>),
        (status = 404, description = "备份记录不存在"),
    ),
    tag = "system-backup"
)]
pub async fn get_info(
    State(state): State<Arc<AppState>>,
    Path(backup_id): Path<i64>,
) -> Result<AjaxResult<SysBackupLogModel>, AppError> {
    let model = state.backup_service.get_backup_by_id(backup_id).await?;
    Ok(AjaxResult::success(model))
}

/// POST /system/backup
/// 创建手动数据库备份
///
/// 调用 pg_dump / mysqldump / sqlite3 子进程生成备份文件，5 分钟超时保护
#[utoipa::path(
    post,
    path = "/system/backup",
    responses(
        (status = 200, description = "备份成功", body = AjaxResult<BackupCreateVo>),
        (status = 500, description = "备份失败"),
    ),
    tag = "system-backup"
)]
pub async fn create(
    State(state): State<Arc<AppState>>,
    operator: Operator,
) -> Result<AjaxResult<BackupCreateVo>, AppError> {
    let vo = state.backup_service.create_backup(operator.username()).await?;
    Ok(AjaxResult::success(vo))
}

/// POST /system/backup/restore/{backupId}
/// 恢复指定备份
///
/// 调用 psql / mysql / sqlite3 .read 子进程恢复数据库，5 分钟超时保护
#[utoipa::path(
    post,
    path = "/system/backup/restore/{backupId}",
    params(
        ("backupId" = i64, Path, description = "备份日志 ID")
    ),
    responses(
        (status = 200, description = "恢复成功", body = AjaxResult<serde_json::Value>),
        (status = 400, description = "备份记录状态不允许恢复"),
        (status = 404, description = "备份记录或文件不存在"),
        (status = 500, description = "恢复失败"),
    ),
    tag = "system-backup"
)]
pub async fn restore(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    Path(backup_id): Path<i64>,
) -> Result<AjaxResult<()>, AppError> {
    state
        .backup_service
        .restore_backup(backup_id, operator.username())
        .await?;
    Ok(AjaxResult::success_msg(&crate::tr!("msg.success.restore")))
}

/// GET /system/backup/download/{backupId}
/// 下载备份文件
#[utoipa::path(
    get,
    path = "/system/backup/download/{backupId}",
    params(
        ("backupId" = i64, Path, description = "备份日志 ID")
    ),
    responses(
        (status = 200, description = "下载成功", content_type = "application/octet-stream"),
        (status = 400, description = "备份状态不允许下载"),
        (status = 404, description = "备份记录或文件不存在"),
    ),
    tag = "system-backup"
)]
pub async fn download(
    State(state): State<Arc<AppState>>,
    Path(backup_id): Path<i64>,
) -> Result<Response, AppError> {
    let (bytes, file_name) = state.backup_service.read_backup_file(backup_id).await?;

    let content_disposition = format!(
        "attachment; filename=\"{}\"",
        file_name.replace('"', "")
    );

    let mut response = Response::new(bytes.into());
    *response.status_mut() = StatusCode::OK;
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/octet-stream"),
    );
    response.headers_mut().insert(
        header::CONTENT_DISPOSITION,
        HeaderValue::from_str(&content_disposition)
            .unwrap_or_else(|_| HeaderValue::from_static("attachment; filename=backup")),
    );

    Ok(response)
}

/// DELETE /system/backup/{backupIds}
/// 批量删除备份日志及文件（逗号分隔的 ID 字符串）
#[utoipa::path(
    delete,
    path = "/system/backup/{backupIds}",
    params(
        ("backupIds" = String, Path, description = "备份日志 ID 列表（逗号分隔）")
    ),
    responses(
        (status = 200, description = "删除成功", body = AjaxResult<serde_json::Value>),
        (status = 400, description = "ID 不合法"),
    ),
    tag = "system-backup"
)]
pub async fn remove(
    State(state): State<Arc<AppState>>,
    Path(backup_ids): Path<String>,
) -> Result<AjaxResult<()>, AppError> {
    let ids: Vec<i64> = parse_id_list::<i64>(&backup_ids);

    if ids.is_empty() {
        return Err(AppError::bad_request("备份 ID 不合法"));
    }

    state.backup_service.delete_backups(ids).await?;
    Ok(AjaxResult::success_msg(&crate::tr!("msg.success.delete")))
}
