// stepby-axum/src/handler/upload_chunk_handler.rs
//! 分片上传/断点续传 Handler（G-10，方案深审 2026-10-06）
//!
//! 链路：`init`（校验+建会话）→ `part`×N（逐片落暂存区，断点续传可查已收索引）
//! → `complete`（Semaphore 占位 → 拼接 → 整对象校验 → ensure_clean 扫描 →
//! StorageBackend.save → 清理暂存）。三约束见 [`crate::common::upload_chunk`] 模块注释。
//!
//! 安全：session_id UUID 形态校验（防路径穿越/键注入）；会话键含租户维度
//! （防跨租户操作）；扩展名 init 冻结（防中途换名绕过白名单）；
//! part 字段流式限长（复用 `read_field_limited`，防 OOM）。

use std::sync::Arc;

use axum::extract::{Multipart, Path as AxumPath, State};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::common::upload::{read_field_limited, resolve_upload_dir};
use crate::common::upload_chunk::{
    ChunkSession, chunk_dir, cleanup_chunk_dir, complete_semaphore, merge_parts, part_file_name,
    validate_init, validate_session_id,
};
use crate::common::{AjaxResult, AppError};
use crate::handler::common_handler::CommonUploadResult;
use crate::middleware::auth::Operator;
use crate::state::AppState;

/// init 请求体
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChunkInitDto {
    /// 原始文件名（取扩展名做白名单校验；complete 后回显）
    pub file_name: String,
    /// 分片总数
    pub total_parts: u32,
    /// 文件总字节数
    pub total_size: u64,
    /// 客户端单片大小提示（可选，一致性校验用）
    #[serde(default)]
    pub part_size: u64,
}

/// init 响应
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ChunkInitVo {
    /// 会话 ID（UUID，后续 part/complete/session/abort 均凭此操作）
    pub session_id: String,
    /// 服务端推导的单片期望大小（客户端可据此切分校验）
    pub chunk_size: u64,
    /// 会话 TTL（秒）
    pub ttl_secs: u64,
}

/// part/complete 响应（已收分片状态）
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ChunkProgressVo {
    pub session_id: String,
    /// 已收分片数
    pub received: u32,
    /// 分片总数
    pub total_parts: u32,
    /// 是否全部收齐（true = 可 complete）
    pub complete: bool,
    /// 已收分片索引列表（仅 session 断点续传查询端点返回——客户端据此只补传缺失片；
    /// 批次十八修复：此前仅返回数量，"仅补传缺失"的续传承诺无法落地）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub received_indexes: Option<Vec<u32>>,
}

/// POST /common/upload/chunk/init —— 创建分片会话
pub async fn chunk_init(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    axum::Json(dto): axum::Json<ChunkInitDto>,
) -> Result<AjaxResult<ChunkInitVo>, AppError> {
    let cfg = &state.config.upload;
    let body_limit = crate::router::DEFAULT_BODY_LIMIT_BYTES;
    let ext = validate_init(
        &dto.file_name,
        dto.total_parts,
        dto.total_size,
        dto.part_size,
        body_limit,
        cfg,
    )?;

    let session_id = uuid::Uuid::new_v4().to_string();
    let session = ChunkSession {
        file_name: dto.file_name.clone(),
        ext,
        total_parts: dto.total_parts,
        // 批次十八：记录总大小——merge 预分配容量来源（防 1GB 级多次 realloc）
        total_size: dto.total_size,
        received: Default::default(),
        tenant_id: operator.tenant_id(),
    };
    state
        .store
        .set_ex(
            &ChunkSession::store_key(operator.tenant_id(), &session_id),
            &session.serialize(),
            cfg.chunk_session_ttl_secs,
        )
        .await
        .map_err(|e| {
            tracing::error!("分片会话创建失败（共享态存储不可用，fail-closed）: {e}");
            AppError::internal(&crate::tr!("error.common_handler.chunk_store_unavailable"))
        })?;

    let chunk_size = dto.total_size.div_ceil(dto.total_parts as u64);
    Ok(AjaxResult::success(ChunkInitVo {
        session_id,
        chunk_size,
        ttl_secs: cfg.chunk_session_ttl_secs,
    }))
}

/// POST /common/upload/chunk/part —— 上传单片
///
/// multipart 字段：`sessionId` / `partIndex` / `file`（流式限长 ≤ 单请求 body 上限）。
pub async fn chunk_part(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    mut multipart: Multipart,
) -> Result<AjaxResult<ChunkProgressVo>, AppError> {
    let cfg = &state.config.upload;
    let mut session_id = String::new();
    let mut part_index: Option<u32> = None;
    let mut part_bytes: Option<Vec<u8>> = None;

    while let Some(mut field) = multipart.next_field().await.map_err(|e| {
        AppError::bad_request(&crate::tr!("error.file.multipart_parse_failed", e = e))
    })? {
        match field.name() {
            Some("sessionId") => {
                session_id = field.text().await.unwrap_or_default();
            }
            Some("partIndex") => {
                part_index = field.text().await.ok().and_then(|t| t.trim().parse().ok());
            }
            Some("file") => {
                // 单片 ≤ 全局 body limit；流式限长读取防 OOM
                let (bytes, _, _) =
                    read_field_limited(&mut field, crate::router::DEFAULT_BODY_LIMIT_BYTES).await?;
                part_bytes = Some(bytes);
            }
            _ => {}
        }
    }

    validate_session_id(&session_id)?;
    let index = part_index.ok_or_else(|| {
        AppError::bad_request(&crate::tr!("error.common_handler.chunk_index_missing"))
    })?;
    let bytes = part_bytes.ok_or_else(|| {
        AppError::bad_request(&crate::tr!("error.common_handler.field_not_found_file"))
    })?;

    // 会话读取（TTL 过期/不存在 → 400 要求重新 init）
    let key = ChunkSession::store_key(operator.tenant_id(), &session_id);
    let raw = state
        .store
        .get(&key)
        .await
        .map_err(|e| {
            tracing::error!("分片会话读取失败（共享态存储不可用）: {e}");
            AppError::internal(&crate::tr!("error.common_handler.chunk_store_unavailable"))
        })?
        .ok_or_else(|| {
            AppError::bad_request(&crate::tr!("error.common_handler.chunk_session_missing"))
        })?;
    let mut session = ChunkSession::parse(&raw)?;

    // 分片落暂存区（本地盘；目录不存在则创建）
    let root = resolve_upload_dir("uploads").await;
    let dir = chunk_dir(&root, operator.tenant_id(), &session_id);
    let path = dir.join(part_file_name(index));
    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent)
            .await
            .map_err(|e| AppError::internal(&format!("分片暂存目录创建失败: {e}")))?;
    }
    tokio::fs::write(&path, &bytes)
        .await
        .map_err(|e| AppError::internal(&format!("分片写入失败: {e}")))?;

    if session.received.insert(index) {
        // 刷新 TTL（滑动过期：持续上传的会话不因中途停顿被清）
        state
            .store
            .set_ex(&key, &session.serialize(), cfg.chunk_session_ttl_secs)
            .await
            .map_err(|e| {
                tracing::error!("分片会话更新失败（共享态存储不可用）: {e}");
                AppError::internal(&crate::tr!("error.common_handler.chunk_store_unavailable"))
            })?;
    }

    Ok(AjaxResult::success(ChunkProgressVo {
        session_id,
        received: session.received.len() as u32,
        total_parts: session.total_parts,
        complete: session.received.len() == session.total_parts as usize,
        received_indexes: None,
    }))
}

/// GET /common/upload/chunk/session/{sessionId} —— 断点续传查询（已收分片索引）
pub async fn chunk_session(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    AxumPath(session_id): AxumPath<String>,
) -> Result<AjaxResult<ChunkProgressVo>, AppError> {
    validate_session_id(&session_id)?;
    let raw = state
        .store
        .get(&ChunkSession::store_key(operator.tenant_id(), &session_id))
        .await
        .map_err(|e| {
            tracing::error!("分片会话查询失败（共享态存储不可用）: {e}");
            AppError::internal(&crate::tr!("error.common_handler.chunk_store_unavailable"))
        })?
        .ok_or_else(|| {
            AppError::bad_request(&crate::tr!("error.common_handler.chunk_session_missing"))
        })?;
    let session = ChunkSession::parse(&raw)?;
    Ok(AjaxResult::success(ChunkProgressVo {
        session_id,
        received: session.received.len() as u32,
        total_parts: session.total_parts,
        complete: session.received.len() == session.total_parts as usize,
        // 断点续传核心：返回已收索引列表，客户端据此只补传缺失片
        received_indexes: Some(session.received.into_iter().collect()),
    }))
}

/// POST /common/upload/chunk/complete —— 拼接 + 整对象校验/扫描 + 落最终存储
///
/// 校验链与单文件上传完全一致（`save_upload_bytes`：白名单/magic bytes/UUID 命名）
/// + `ensure_clean` 扫描闸门（分片阶段不扫描，**merge 后整对象扫描**——深审约束 1）。
pub async fn chunk_complete(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    axum::Json(dto): axum::Json<ChunkCompleteDto>,
) -> Result<AjaxResult<CommonUploadResult>, AppError> {
    validate_session_id(&dto.session_id)?;
    let cfg = &state.config.upload;

    // G-10 约束 3：并发硬上限（fail-closed 快速失败，不排队占连接）
    let _permit = complete_semaphore()
        .try_acquire()
        .map_err(|_| AppError::new(429, crate::tr!("error.common_handler.chunk_busy")))?;

    let key = ChunkSession::store_key(operator.tenant_id(), &dto.session_id);
    let raw = state
        .store
        .get(&key)
        .await
        .map_err(|e| {
            tracing::error!("分片会话读取失败（共享态存储不可用）: {e}");
            AppError::internal(&crate::tr!("error.common_handler.chunk_store_unavailable"))
        })?
        .ok_or_else(|| {
            AppError::bad_request(&crate::tr!("error.common_handler.chunk_session_missing"))
        })?;
    let session = ChunkSession::parse(&raw)?;

    let root = resolve_upload_dir("uploads").await;
    let dir = chunk_dir(&root, operator.tenant_id(), &dto.session_id);
    // 拼接（内存语义：总上限 × 并发许可；见 upload_chunk 模块注释）
    let bytes = merge_parts(&dir, &session).await?;

    // 整对象扫描（merge 后唯一有效扫描点；分片阶段刻意不扫）
    crate::common::upload_scan::ensure_clean(&state.config.upload_scan, &session.file_name, &bytes)
        .await?;

    // 统一校验链 + 落最终存储（白名单/magic bytes/UUID 命名/backend.save）
    // 批次十八：kind 用 CommonChunked——大小上限走 common_chunk_max_total_size（1GB），
    // 否则合并对象 >common_max_size(10MB) 必被拒（G-10 死能力缺陷，curl 复现实证）
    let storage = state.resolve_storage().await?;
    let saved = crate::common::upload::save_upload_bytes(
        storage.as_ref(),
        &bytes,
        Some(&session.ext),
        Some(&session.file_name),
        cfg,
        operator.tenant_id(),
        crate::common::upload::UploadKind::CommonChunked,
    )
    .await?;

    // 清理会话与暂存分片（先删会话键防重复 complete，再删文件）
    // 删会话键失败会让分片会话残留至 TTL，期间重复 complete 可再次读已清目录 → 需可观测
    if let Err(e) = state.store.del(std::slice::from_ref(&key)).await {
        tracing::warn!(key = %key, error = %e, "分片上传会话键删除失败，分片会话将残留至 TTL 过期")
    }
    cleanup_chunk_dir(&dir).await;

    tracing::info!(
        tenant_id = operator.tenant_id(),
        file = %session.file_name,
        size = bytes.len(),
        "分片上传完成"
    );
    Ok(AjaxResult::success(CommonUploadResult {
        code: 200,
        msg: crate::tr!("error.common_handler.upload_success").to_string(),
        url: saved.url.clone(),
        file_name: saved.url,
        new_file_name: saved.new_filename,
        original_filename: saved.original_filename.unwrap_or_default(),
    }))
}

/// complete 请求体
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChunkCompleteDto {
    pub session_id: String,
}

/// DELETE /common/upload/chunk/{sessionId} —— 主动放弃（清理会话与暂存分片）
pub async fn chunk_abort(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    AxumPath(session_id): AxumPath<String>,
) -> Result<axum::Json<serde_json::Value>, AppError> {
    validate_session_id(&session_id)?;
    let _ = state
        .store
        .del(&[ChunkSession::store_key(operator.tenant_id(), &session_id)])
        .await;
    let root = resolve_upload_dir("uploads").await;
    cleanup_chunk_dir(&chunk_dir(&root, operator.tenant_id(), &session_id)).await;
    Ok(axum::Json(serde_json::json!({ "code": 200, "msg": "ok" })))
}
