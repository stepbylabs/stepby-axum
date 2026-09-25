//! 文件管理 Handler（OSS 集成抽象）
//!
//! 设计要点：
//! - 抽象 StorageBackend trait，支持本地存储 + S3 兼容存储
//! - 当前默认实现为 LocalStorage（复用 common_dir）
//! - 提供 list / upload / delete 三个接口
//! - 文件列表支持按扩展名、文件名前缀、时间范围筛选

use std::sync::Arc;

use axum::Json;
use axum::extract::{Multipart, Query, State};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};

use crate::common::{AjaxResult, AppError};
use crate::middleware::Operator;
use crate::state::AppState;

// ==================== DTO ====================

#[derive(Debug, Deserialize, IntoParams)]
#[serde(rename_all = "camelCase")]
pub struct FileListQuery {
    /// 文件名前缀（模糊查询）
    pub file_name: Option<String>,
    /// 扩展名（如 jpg/png/pdf）
    pub ext: Option<String>,
    /// 页码
    #[serde(default = "default_page")]
    pub page_num: u64,
    /// 每页条数
    #[serde(default = "default_size")]
    pub page_size: u64,
}

fn default_page() -> u64 {
    1
}
fn default_size() -> u64 {
    20
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct FileInfo {
    pub file_name: String,
    pub file_size: u64,
    /// 文件大小（人类可读，如 1.5MB）
    pub file_size_str: String,
    pub ext: String,
    /// 可访问 URL
    pub url: String,
    pub last_modified: String,
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct FileListResponse {
    pub rows: Vec<FileInfo>,
    pub total: u64,
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct FileUploadResponse {
    pub url: String,
    pub file_name: String,
    pub file_size: u64,
    pub ext: String,
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct FileDeleteRequest {
    pub file_name: String,
}

// ==================== Handler ====================

/// GET /system/file/list
/// 文件列表（分页）
pub async fn list(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    Query(params): Query<FileListQuery>,
) -> Result<AjaxResult<FileListResponse>, AppError> {
    let upload_cfg = &state.config.upload;
    // 安全（R10）：page_num 设上界 10000，防止 (page_num-1)*page_size 在 u64 乘法时溢出
    // 导致 debug panic / release 回绕后返回错误切片范围
    let page_num = params.page_num.clamp(1, 10_000);
    let page_size = params.page_size.clamp(1, 100);

    // 统一走存储后端列举（local 读目录 / s3 ListObjectsV2），URL 由后端生成；
    // 目录带操作者租户维度，仅可见本租户文件
    let objects = state
        .storage
        .list(
            &upload_cfg.common_dir,
            operator.tenant_id(),
            &upload_cfg.common_url_prefix,
        )
        .await?;

    let mut files: Vec<FileInfo> = Vec::new();
    for obj in objects {
        let ext = std::path::Path::new(&obj.name)
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("")
            .to_lowercase();

        // 筛选：文件名前缀
        if let Some(prefix) = &params.file_name
            && !prefix.is_empty()
            && !obj.name.contains(prefix)
        {
            continue;
        }
        // 筛选：扩展名
        if let Some(target_ext) = &params.ext
            && !target_ext.is_empty()
            && ext != target_ext.to_lowercase()
        {
            continue;
        }

        let modified = chrono::DateTime::<chrono::Local>::from(
            std::time::UNIX_EPOCH + std::time::Duration::from_secs(obj.modified_secs as u64),
        )
        .format("%Y-%m-%d %H:%M:%S")
        .to_string();

        files.push(FileInfo {
            file_name: obj.name.clone(),
            file_size: obj.size,
            file_size_str: format_file_size(obj.size),
            ext,
            url: obj.url,
            last_modified: modified,
        });
    }

    // 按修改时间倒序
    files.sort_by(|a, b| b.last_modified.cmp(&a.last_modified));
    let total = files.len() as u64;
    let start = ((page_num - 1) * page_size) as usize;
    let end = (start + page_size as usize).min(files.len());
    let rows = if start < files.len() {
        files.drain(start..end).collect()
    } else {
        Vec::new()
    };

    Ok(AjaxResult::success(FileListResponse { rows, total }))
}

/// POST /system/file/upload
/// 文件上传（复用 common_upload 的安全策略，P0-3 统一走 save_upload_bytes）
pub async fn upload(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    mut multipart: Multipart,
) -> Result<AjaxResult<FileUploadResponse>, AppError> {
    let upload_cfg = &state.config.upload;
    let mut file_bytes: Option<Vec<u8>> = None;
    let mut original_filename: Option<String> = None;
    let mut file_ext: Option<String> = None;

    // P0-3 OOM 修复：流式限长读取，不再整读内存后校验大小
    while let Some(mut field) = multipart
        .next_field()
        .await
        .map_err(|_| AppError::bad_request(&crate::tr!("error.file.multipart_parse_failed")))?
    {
        if field.name() == Some("file") {
            let (bytes, ext, original) =
                crate::common::upload::read_field_limited(&mut field, upload_cfg.common_max_size)
                    .await?;
            file_ext = ext;
            original_filename = original;
            file_bytes = Some(bytes);
        }
    }

    // P0-3：统一校验 + 保存（扩展名白名单、危险类型拒绝、magic bytes 严格化、UUID 文件名、写盘）
    let saved = crate::common::upload::save_upload_bytes(
        state.storage.as_ref(),
        file_bytes
            .as_deref()
            .ok_or_else(|| AppError::bad_request(&crate::tr!("error.file.field_not_found")))?,
        file_ext.as_deref(),
        original_filename.as_deref(),
        upload_cfg,
        operator.tenant_id(),
        crate::common::upload::UploadKind::Common,
    )
    .await?;

    tracing::info!(
        original = ?saved.original_filename,
        new = %saved.new_filename,
        size = saved.size,
        "文件上传成功"
    );

    Ok(AjaxResult::success(FileUploadResponse {
        url: saved.url,
        file_name: saved.new_filename,
        file_size: saved.size,
        ext: saved.ext,
    }))
}

/// DELETE /system/file/delete
/// 删除文件（按服务器端文件名）
pub async fn delete(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    Json(req): Json<FileDeleteRequest>,
) -> Result<AjaxResult<()>, AppError> {
    let file_name = req.file_name.trim();
    // 路径穿越校验
    if file_name.is_empty()
        || file_name.contains('/')
        || file_name.contains('\\')
        || file_name.contains("..")
        || file_name.contains('\0')
    {
        return Err(AppError::bad_request(&crate::tr!(
            "error.file.invalid_name"
        )));
    }

    let upload_cfg = &state.config.upload;
    // 统一走存储后端删除（local 本地删盘带根目录前缀校验 / s3 DeleteObject，幂等）；
    // 目录带操作者租户维度，无法删除其它租户文件
    state
        .storage
        .delete(&upload_cfg.common_dir, operator.tenant_id(), file_name)
        .await?;

    tracing::info!(file_name = %file_name, "文件已删除");

    Ok(AjaxResult::success(()))
}

// ==================== 辅助函数 ====================

/// 格式化文件大小（人类可读）
fn format_file_size(size: u64) -> String {
    const UNITS: &[&str] = &["B", "KB", "MB", "GB", "TB"];
    if size == 0 {
        return "0 B".to_string();
    }
    let mut s = size as f64;
    let mut i = 0;
    while s >= 1024.0 && i < UNITS.len() - 1 {
        s /= 1024.0;
        i += 1;
    }
    if i == 0 {
        format!("{} {}", size, UNITS[i])
    } else {
        format!("{:.2} {}", s, UNITS[i])
    }
}
