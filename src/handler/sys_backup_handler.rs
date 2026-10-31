//! 数据备份/恢复 Handler（Axum 原生实现）
//!
//! 接口路径对齐 stepby-vue 前端：
//! - GET    /system/backup/list            分页查询备份日志
//! - GET    /system/backup/{backupId}      查询备份日志详情
//! - POST   /system/backup                 创建手动备份
//! - POST   /system/backup/restore/{id}    恢复指定备份
//! - GET    /system/backup/download/{id}   下载备份文件
//! - DELETE /system/backup/{backupIds}     批量删除备份日志及文件

use axum::body::{Body, Bytes};
use axum::extract::{ConnectInfo, Path, Query, State};
use axum::response::Response;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::AsyncReadExt;

use crate::common::constants::MAX_BATCH_DELETE_SIZE;
use crate::common::{AjaxResult, AppError, TableDataInfo};
use crate::entity::sys_backup_log::Model as SysBackupLogModel;
use crate::middleware::Operator;
use crate::service::sys_backup_service::{BackupCreateVo, BackupLogQueryDto, OpenedBackupFile};
use crate::state::AppState;
use crate::utils::ip::extract_client_ip;
use crate::utils::parse_id_list;
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};

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
    operator: Operator,
    Query(query): Query<BackupLogQueryDto>,
) -> Result<TableDataInfo<SysBackupLogModel>, AppError> {
    let (rows, total) = state
        .backup_service
        .get_backup_log_page(query, operator.tenant_id())
        .await?;
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
    operator: Operator,
    Path(backup_id): Path<i64>,
) -> Result<AjaxResult<SysBackupLogModel>, AppError> {
    let model = state
        .backup_service
        .get_backup_by_id(backup_id, operator.tenant_id())
        .await?;
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
    acquire_rate_lock(&state, &format!("backup:create:{}", operator.user_id()), 60).await?;
    // 全局并发上限（A-2）：上面的锁只封"同一人 60 秒一次"，两个管理员同时点照样各起一路
    // pg_dump/mysqldump/sqlite3 子进程——整库 dump 是 CPU+IO+磁盘三重成本，故取 1。
    let _gate = crate::common::resource_gate::try_enter(
        crate::common::resource_gate::HeavyEntry::BackupCreate,
    )?;

    let vo = state
        .backup_service
        .create_backup(operator.username())
        .await?;
    Ok(AjaxResult::success(vo))
}

/// POST /system/backup/tenant-export/{tenantId}
/// 导出指定租户的数据包（JSON，落盘后登记为一条 tenant_export 备份日志）
///
/// 台账 F-2 定案：整库备份保留 + 新增「租户数据包导出」，不做租户级恢复。
/// 导出后可在备份列表中下载 / 删除（复用既有链路与清理逻辑）。
/// 平台专属：整组 `/system/backup/*` 挂 `platform_only_guard`，租户操作者一律 403。
#[utoipa::path(
    post,
    path = "/system/backup/tenant-export/{tenantId}",
    params(
        ("tenantId" = i64, Path, description = "租户 ID")
    ),
    responses(
        (status = 200, description = "导出成功", body = AjaxResult<BackupCreateVo>),
        (status = 400, description = "操作过于频繁"),
        (status = 404, description = "租户不存在"),
        (status = 500, description = "导出失败"),
    ),
    tag = "system-backup"
)]
pub async fn export_tenant(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    Path(tenant_id): Path<i64>,
) -> Result<AjaxResult<BackupCreateVo>, AppError> {
    // 与手动备份同款限流（60s 最小间隔），防反复导出耗尽磁盘空间
    acquire_rate_lock(
        &state,
        &format!("backup:tenant-export:{}", operator.user_id()),
        60,
    )
    .await?;
    // 数据包导出与自助导出**共用一路闸**（同一类成本：整租户 JSON 流式落盘，2 permits）
    let _gate = crate::common::resource_gate::try_enter(
        crate::common::resource_gate::HeavyEntry::BackupExport,
    )?;

    let vo = state
        .backup_service
        .export_tenant_package(tenant_id, operator.username())
        .await?;
    Ok(AjaxResult::success(vo))
}

/// POST /system/backup/self-export
/// **租户自助**导出本租户数据包（批次 2，能力位 `backup.tenant_self_export`）
///
/// 与平台版 `tenant-export/{tenantId}` 的差别：**无租户路径参数**——归属租户由
/// 服务端强制取操作者所属租户（`operator.tenant_id()`），因此不存在"传他租户 id"
/// 的越权面（结构上不可表达），也无需再做一次归属校验。
///
/// 门控（三层缺一不可）：① 平台 `[features].backup.tenant_self_export = on`
/// （`platform_only_guard` 放行）→ ② 套餐 `features` 同键非 `off`（决定
/// `system:backup:export` 是否可授予租户角色）→ ③ 角色持有 `system:backup:export`。
#[utoipa::path(
    post,
    path = "/system/backup/self-export",
    responses(
        (status = 200, description = "导出成功", body = AjaxResult<BackupCreateVo>),
        (status = 400, description = "操作过于频繁"),
        (status = 403, description = "未开启租户自助导出能力位"),
        (status = 500, description = "导出失败"),
    ),
    tag = "system-backup"
)]
pub async fn self_export(
    State(state): State<Arc<AppState>>,
    operator: Operator,
) -> Result<AjaxResult<BackupCreateVo>, AppError> {
    // 与平台导出同款限流（60s 最小间隔），防反复导出耗尽磁盘空间
    acquire_rate_lock(
        &state,
        &format!("backup:self-export:{}", operator.user_id()),
        60,
    )
    .await?;
    // 与平台版 tenant-export 同一路闸：成本同类，分闸等于把上限翻倍（b72 F71 那条
    // "同一族入口混桶会互相饿死"的反面形态——这里是"同一族必须同桶"）
    let _gate = crate::common::resource_gate::try_enter(
        crate::common::resource_gate::HeavyEntry::BackupExport,
    )?;

    let vo = state
        .backup_service
        .export_tenant_package(operator.tenant_id(), operator.username())
        .await?;
    Ok(AjaxResult::success(vo))
}

/// 获取限流锁（原 SET NX EX 语义 → `store.set_nx_ex`）；未获取到 → 400「操作过于频繁」，
/// 共享态存储异常 → fail-closed 503（备份类接口不可在无锁保护下执行）
async fn acquire_rate_lock(
    state: &Arc<AppState>,
    key: &str,
    ttl_secs: i64,
) -> Result<(), AppError> {
    let acquired = state
        .store
        .set_nx_ex(key, "1", ttl_secs.max(1) as u64)
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
    Ok(())
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
    // P1 修复：恢复为高危操作，加共享态互斥锁（10 分钟 TTL 防卡死），
    // 防止两个并发 restore 互相覆盖（此前无并发控制）。
    // 原 SET NX EX + UUID value + EVAL CAS 释放 → 收敛为 `store.lock_acquire/lock_release`
    // （UUID fencing token 由实现内置）。
    let restore_lock_key = "backup:restore:lock";
    let lock_handle = state
        .store
        .lock_acquire(restore_lock_key, 600)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "恢复互斥锁写入失败（fail-closed 拒绝）");
            AppError::new(503, crate::tr!("error.backup.service_unavailable"))
        })?;
    let Some(lock_handle) = lock_handle else {
        return Err(AppError::bad_request(&crate::tr!(
            "error.backup.restore_in_progress"
        )));
    };

    let result = state
        .backup_service
        .restore_backup(backup_id, operator.username())
        .await;

    // 释放锁（CAS：仅当 fencing token 匹配时删除，避免误删其他恢复任务的锁；best-effort）
    if let Err(e) = state.store.lock_release(&lock_handle).await {
        tracing::warn!(error = %e, "恢复互斥锁释放失败（TTL 到期后其他任务可抢占）");
    }
    result?;

    // 恢复成功后清理业务缓存，避免缓存与恢复后的数据库数据不一致
    // 清理范围：字典(dict:*)、系统配置(config:*)、限流配置(rate_limit:config:*)、
    //          用户权限(perm:user:*，走 perm_cache 单一实现——Redis 档下它是恢复前
    //          DB 算出来的派生数据，恢复后继续命中会放行已不存在的权限)
    // 不清理：blacklist/online/pwd_ver/captcha 等会话/安全相关 key（清理会导致用户登出）
    clear_business_caches(&state).await;
    crate::common::perm_cache::invalidate_all_perm_cache(&state.store, "备份恢复").await;

    // P0-H2 修复：同时清理限流服务的进程内 local_cache（10s TTL）
    // clear_business_caches 只清理 Redis 中的 rate_limit:config:*，但 SysRateLimitService
    // 还有进程内 local_cache，恢复后 ≤10s 内仍使用旧配置，多实例部署时影响面放大。
    state.rate_limit_service.invalidate_all_cache().await;

    Ok(AjaxResult::success_msg(&crate::tr!("msg.success.restore")))
}

/// 清理业务相关缓存（恢复备份后调用）
async fn clear_business_caches(state: &Arc<AppState>) {
    let patterns = ["dict:*", "config:*", "rate_limit:config:*"];
    for pattern in &patterns {
        // 全量扫描（不截断）后删除——恢复后必须清干净，否则缓存与恢复后的 DB 不一致；
        // 单次 SCAN 失败仅告警并跳过该 pattern（与原游标循环失败 break 语义一致）
        let keys = match state.store.scan(pattern, None).await {
            Ok(k) => k,
            Err(e) => {
                tracing::warn!(error = %e, pattern = %pattern, "缓存清理 SCAN 失败，跳过");
                continue;
            }
        };
        if keys.is_empty() {
            continue;
        }
        // 分批删除（保持原 DEL_BATCH_SIZE 批次语义，防单条超长 DEL 长时间占用后端）
        for chunk in keys.chunks(crate::utils::redis::DEL_BATCH_SIZE) {
            if let Err(e) = state.store.del(chunk).await {
                tracing::warn!(error = %e, pattern = %pattern, "缓存清理 DEL 失败（本批跳过）");
            }
        }
        tracing::info!(pattern = %pattern, count = keys.len(), "已清理缓存 key");
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
        (status = 429, description = "备份下载繁忙，请稍后重试"),
    ),
    tag = "system-backup"
)]
pub async fn download(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    ConnectInfo(peer_addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(backup_id): Path<i64>,
) -> Result<Response, AppError> {
    // b140：GB 级快照流式读盘此前没有任何并发上限（`backup:export` 那把闸管的是**生成**
    // 数据包，不是把已存在的文件读出流）。下载是人类可重来的动作 ⇒ 取拒绝（A.2）。
    // 取闸排在打开文件之前：闸满时不得先把句柄与体积校验的成本付掉。
    let _gate = crate::common::resource_gate::try_enter(
        crate::common::resource_gate::HeavyEntry::BackupDownload,
    )?;
    // 流式下载：备份是整库快照（可达 GB 级），把整个文件读进内存再回包会让
    // 每次下载的 RSS 峰值等于文件大小；这里只持有文件句柄，按 64KB 分块出流。
    let opened = state
        .backup_service
        .open_backup_file(backup_id, operator.tenant_id())
        .await?;
    let OpenedBackupFile {
        file,
        size,
        file_name,
        tenant_id: backup_tenant_id,
        backup_type,
    } = opened;

    // b137：整库/整租户快照下载是**数据外带面**，而 oper_log 中间件只记写方法（GET 不记）
    // ⇒ 此前"谁在什么时候把多少数据带走"在审计面上整段空白。此处只在文件已打开、
    // 体积校验已通过之后留痕（失败路径不落审计，见 common/egress_audit 模块文档）。
    let client_ip = extract_client_ip(
        &headers,
        peer_addr.ip(),
        &state.config.server.trusted_proxies,
    );
    crate::common::egress_audit::record_egress(
        &state,
        &operator,
        &client_ip,
        crate::common::egress_audit::EgressEvent {
            kind: crate::common::egress_audit::EgressKind::BackupDownload,
            // 查询串不进审计（本路由无查询参数，保持与中间件 same 口径只用路径）
            oper_url: format!("/system/backup/download/{backup_id}"),
            oper_param: serde_json::json!({ "backupId": backup_id }),
            detail: serde_json::json!({
                "fileName": file_name,
                "backupType": backup_type,
                "size": size,
            }),
            // 平台代管他租户数据包时记下目标租户；同租户时不重复（与中间件口径一致）
            target_tenant_id: (backup_tenant_id != operator.tenant_id())
                .then_some(backup_tenant_id),
        },
    );

    // b139：走单一实现。此前 `HeaderValue::from_str` 失败会静默回落到固定名 `backup`，
    // 用户从"文件名叫 xxx.sql"变成"backup"，而服务端没有任何信号。
    let content_disposition =
        crate::common::http_download::content_disposition_header(&file_name, "backup.sql");

    let stream = futures::stream::try_unfold(file, |mut file| async move {
        let mut buf = vec![0u8; 64 * 1024];
        let n = file.read(&mut buf).await?;
        if n == 0 {
            return Ok(None);
        }
        buf.truncate(n);
        Ok::<_, std::io::Error>(Some((Bytes::from(buf), file)))
    });
    let mut response = Response::new(Body::from_stream(stream));
    *response.status_mut() = StatusCode::OK;
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/octet-stream"),
    );
    response.headers_mut().insert(
        header::CONTENT_LENGTH,
        HeaderValue::from_str(&size.to_string()).unwrap_or_else(|_| HeaderValue::from_static("0")),
    );
    response
        .headers_mut()
        .insert(header::CONTENT_DISPOSITION, content_disposition);

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
    let ids: Vec<i64> = parse_id_list::<i64>(&backup_ids)?;

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
