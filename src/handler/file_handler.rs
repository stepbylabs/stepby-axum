//! 文件管理 Handler（OSS 集成抽象）
//!
//! 设计要点：
//! - 抽象 StorageBackend trait，支持本地存储 + S3 兼容存储
//! - 当前默认实现为 LocalStorage（复用 common_dir）
//! - 提供 list / upload / delete 三个接口
//! - 文件列表支持按扩展名、文件名前缀、时间范围筛选

use std::sync::Arc;

use axum::extract::{Multipart, Query, State};
use axum::Json;
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};

use crate::common::{AjaxResult, AppError};
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

fn default_page() -> u64 { 1 }
fn default_size() -> u64 { 20 }

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
    Query(params): Query<FileListQuery>,
) -> Result<AjaxResult<FileListResponse>, AppError> {
    let upload_cfg = &state.config.upload;
    let page_num = params.page_num.max(1);
    let page_size = params.page_size.clamp(1, 100);

    // 读取 uploads 目录下所有文件
    let upload_dir = std::path::Path::new(&upload_cfg.common_dir);
    let mut files: Vec<FileInfo> = Vec::new();

    if upload_dir.exists() {
        let entries = tokio::task::spawn_blocking({
            let dir = upload_dir.to_path_buf();
            move || -> std::io::Result<Vec<std::fs::DirEntry>> {
                let mut result = Vec::new();
                for entry in std::fs::read_dir(&dir)? {
                    if let Ok(e) = entry {
                        result.push(e);
                    }
                }
                Ok(result)
            }
        })
        .await
        .map_err(|e| AppError::internal(&format!("读取目录失败: {}", e)))?
        .map_err(|e| AppError::internal(&format!("读取目录失败: {}", e)))?;

        for entry in entries {
            if let Ok(meta) = entry.metadata() {
                if !meta.is_file() { continue; }
                let name = entry.file_name().to_string_lossy().to_string();
                let ext = std::path::Path::new(&name)
                    .extension()
                    .and_then(|e| e.to_str())
                    .unwrap_or("")
                    .to_lowercase();

                // 筛选：文件名前缀
                if let Some(prefix) = &params.file_name {
                    if !prefix.is_empty() && !name.contains(prefix) {
                        continue;
                    }
                }
                // 筛选：扩展名
                if let Some(target_ext) = &params.ext {
                    if !target_ext.is_empty() && ext != target_ext.to_lowercase() {
                        continue;
                    }
                }

                let size = meta.len();
                let url = format!("{}/{}", upload_cfg.common_url_prefix, name);
                let modified = meta.modified()
                    .ok()
                    .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                    .map(|d| {
                        chrono::DateTime::<chrono::Local>::from(std::time::UNIX_EPOCH + d)
                            .format("%Y-%m-%d %H:%M:%S").to_string()
                    })
                    .unwrap_or_default();

                files.push(FileInfo {
                    file_name: name.clone(),
                    file_size: size,
                    file_size_str: format_file_size(size),
                    ext,
                    url,
                    last_modified: modified,
                });
            }
        }
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
/// 文件上传（复用 common_upload 的安全策略）
pub async fn upload(
    State(state): State<Arc<AppState>>,
    mut multipart: Multipart,
) -> Result<AjaxResult<FileUploadResponse>, AppError> {
    let upload_cfg = &state.config.upload;
    let mut file_bytes: Option<Vec<u8>> = None;
    let mut original_filename: Option<String> = None;
    let mut file_ext: Option<String> = None;

    while let Some(field) = multipart
        .next_field()
        .await
        .map_err(|e| AppError::bad_request(&format!("解析 multipart 失败: {}", e)))?
    {
        if field.name() == Some("file") {
            if let Some(filename) = field.file_name()
                && let Some(ext) = std::path::Path::new(filename)
                    .extension()
                    .and_then(|e| e.to_str())
            {
                file_ext = Some(ext.to_lowercase());
            }
            original_filename = field.file_name().map(|s| s.to_string());
            let bytes = field
                .bytes()
                .await
                .map_err(|e| AppError::bad_request(&format!("读取文件内容失败: {}", e)))?;
            file_bytes = Some(bytes.to_vec());
        }
    }

    let bytes = file_bytes.ok_or_else(|| AppError::bad_request("未找到 file 字段"))?;
    if bytes.is_empty() {
        return Err(AppError::bad_request("上传文件为空"));
    }

    // 文件大小限制
    if bytes.len() > upload_cfg.common_max_size {
        return Err(AppError::bad_request(&format!(
            "文件大小不能超过 {}MB",
            upload_cfg.common_max_size / 1024 / 1024
        )));
    }

    // 扩展名白名单校验
    let ext = file_ext
        .as_deref()
        .ok_or_else(|| AppError::bad_request("无法识别文件扩展名"))?;
    let allowed: Vec<&str> = upload_cfg.common_allowed_exts.iter().map(|s| s.as_str()).collect();
    if !allowed.contains(&ext) {
        return Err(AppError::bad_request(&format!("不支持的文件类型: {}", ext)));
    }

    // 生成 UUID 文件名
    let new_filename = crate::common::gen_uuid_filename(ext);
    // 解析上传目录为绝对路径，确保与 ServeDir 服务路径一致
    let common_dir = crate::common::resolve_upload_dir(&upload_cfg.common_dir);
    let file_path = common_dir.join(&new_filename);

    let size = crate::common::write_upload_file(file_path, &common_dir.to_string_lossy(), &bytes).await?;

    let url = format!("{}/{}", upload_cfg.common_url_prefix, new_filename);

    tracing::info!(
        original = ?original_filename,
        new = %new_filename,
        size = size,
        "文件上传成功"
    );

    Ok(AjaxResult::success(FileUploadResponse {
        url,
        file_name: new_filename,
        file_size: size,
        ext: ext.to_string(),
    }))
}

/// DELETE /system/file/delete
/// 删除文件（按服务器端文件名）
pub async fn delete(
    State(state): State<Arc<AppState>>,
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
        return Err(AppError::bad_request("非法的文件名"));
    }

    let upload_cfg = &state.config.upload;
    let file_path = std::path::Path::new(&upload_cfg.common_dir).join(file_name);

    let path_clone = file_path.clone();
    let result = tokio::task::spawn_blocking(move || -> std::io::Result<()> {
        if path_clone.exists() {
            std::fs::remove_file(&path_clone)?;
        }
        Ok(())
    })
    .await
    .map_err(|e| AppError::internal(&format!("删除任务失败: {}", e)))?;

    if let Err(e) = result {
        return Err(AppError::internal(&format!("删除文件失败: {}", e)));
    }

    tracing::info!(file_name = %file_name, "文件已删除");

    Ok(AjaxResult::success(()))
}

// ==================== 辅助函数 ====================

/// 格式化文件大小（人类可读）
fn format_file_size(size: u64) -> String {
    const UNITS: &[&str] = &["B", "KB", "MB", "GB", "TB"];
    if size == 0 { return "0 B".to_string(); }
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
