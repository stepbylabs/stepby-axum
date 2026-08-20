//! 数据备份/恢复 Handler（Axum 原生实现）
//!
//! 接口路径对齐 yebot-ui 前端：
//! - GET    /system/backup/list            分页查询备份日志
//! - GET    /system/backup/{backupId}      查询备份日志详情
//! - POST   /system/backup                 创建手动备份
//! - POST   /system/backup/restore/{id}    恢复指定备份
//! - GET    /system/backup/download/{id}   下载备份文件
//! - DELETE /system/backup/{backupIds}     批量删除备份日志及文件

use axum::extract::{Path, Query, State};
use axum::response::Response;
use std::sync::Arc;

use crate::common::constants::MAX_BATCH_DELETE_SIZE;
use crate::common::{AjaxResult, AppError, TableDataInfo};
use crate::entity::sys_backup_log::Model as SysBackupLogModel;
use crate::middleware::Operator;
use crate::service::sys_backup_service::{BackupCreateVo, BackupLogQueryDto};
use crate::state::AppState;
use crate::utils::parse_id_list;
use axum::http::{HeaderValue, StatusCode, header};

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
    // P1 修复：手动备份限流（60s 最小间隔），防反复触发耗尽磁盘空间
    let lock_key = format!("backup:create:{}", operator.user_id());
    let mut conn = state.redis.clone();
    let acquired: bool = redis::cmd("SET")
        .arg(&lock_key)
        .arg("1")
        .arg("NX")
        .arg("EX")
        .arg(60i64)
        .query_async(&mut conn)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "备份限流锁写入失败（fail-closed 拒绝）");
            AppError::new(503, crate::tr!("error.backup.service_unavailable"))
        })?;
    if !acquired {
        return Err(AppError::bad_request(&crate::tr!(
            "error.backup.too_frequent"
        )));
    }

    let vo = state
        .backup_service
        .create_backup(operator.username())
        .await?;
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
    // P1 修复：恢复为高危操作，加 Redis 互斥锁（10 分钟 TTL 防卡死），
    // 防止两个并发 restore 互相覆盖（此前无并发控制）
    let restore_lock_key = "backup:restore:lock";
    let lock_value = uuid::Uuid::new_v4().to_string();
    let mut redis = state.redis.clone();
    let acquired: bool = redis::cmd("SET")
        .arg(restore_lock_key)
        .arg(&lock_value)
        .arg("NX")
        .arg("EX")
        .arg(600i64)
        .query_async(&mut redis)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "恢复互斥锁写入失败（fail-closed 拒绝）");
            AppError::new(503, crate::tr!("error.backup.service_unavailable"))
        })?;
    if !acquired {
        return Err(AppError::bad_request(&crate::tr!(
            "error.backup.restore_in_progress"
        )));
    }

    let result = state
        .backup_service
        .restore_backup(backup_id, operator.username())
        .await;

    // 释放锁（CAS：仅当 value 匹配时删除，避免误删其他恢复任务的锁）
    let _: i64 = redis::cmd("EVAL")
        .arg(r#"if redis.call('GET', KEYS[1]) == ARGV[1] then return redis.call('DEL', KEYS[1]) else return 0 end"#)
        .arg(1)
        .arg(restore_lock_key)
        .arg(&lock_value)
        .query_async(&mut redis)
        .await
        .unwrap_or(0);
    result?;

    // 恢复成功后清理 Redis 业务缓存，避免缓存与恢复后的数据库数据不一致
    // 清理范围：字典缓存(dict:*)、系统配置缓存(config:*)、限流配置缓存(rate_limit:config:*)
    // 不清理：blacklist/online/pwd_ver/captcha 等会话/安全相关 key（清理会导致用户登出）
    clear_business_caches(&state).await;

    // P0-H2 修复：同时清理限流服务的进程内 local_cache（10s TTL）
    // clear_business_caches 只清理 Redis 中的 rate_limit:config:*，但 SysRateLimitService
    // 还有进程内 local_cache，恢复后 ≤10s 内仍使用旧配置，多实例部署时影响面放大。
    state.rate_limit_service.invalidate_all_cache().await;

    Ok(AjaxResult::success_msg(&crate::tr!("msg.success.restore")))
}

/// 清理业务相关 Redis 缓存（恢复备份后调用）
async fn clear_business_caches(state: &Arc<AppState>) {
    let patterns = ["dict:*", "config:*", "rate_limit:config:*"];
    let mut redis = state.redis.clone();
    for pattern in &patterns {
        // 使用 SCAN 迭代匹配的 key 并批量删除（比 KEYS 更安全，不阻塞 Redis）
        let mut cursor: u64 = 0;
        loop {
            let result: (u64, Vec<String>) = match redis::cmd("SCAN")
                .arg(cursor)
                .arg("MATCH")
                .arg(pattern)
                .arg("COUNT")
                .arg(100i64)
                .query_async(&mut redis)
                .await
            {
                Ok(r) => r,
                Err(e) => {
                    tracing::warn!(error = %e, pattern = %pattern, "缓存清理 SCAN 失败，跳过");
                    break;
                }
            };
            let (next_cursor, keys) = result;
            if !keys.is_empty() {
                let mut pipe = redis::pipe();
                for key in &keys {
                    pipe.cmd("DEL").arg(key);
                }
                let _: redis::RedisResult<()> = pipe.query_async(&mut redis).await;
                tracing::info!(pattern = %pattern, count = keys.len(), "已清理缓存 key");
            }
            if next_cursor == 0 {
                break;
            }
            cursor = next_cursor;
        }
    }
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

    let content_disposition = format!("attachment; filename=\"{}\"", file_name.replace('"', ""));

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
        return Err(AppError::bad_request(&crate::tr!(
            "error.backup.id_invalid"
        )));
    }
    if ids.len() > MAX_BATCH_DELETE_SIZE {
        return Err(AppError::bad_request(&crate::tr!(
            "error.common.batch_size_exceeded",
            max = MAX_BATCH_DELETE_SIZE
        )));
    }

    state.backup_service.delete_backups(ids).await?;
    Ok(AjaxResult::success_msg(&crate::tr!("msg.success.delete")))
}
