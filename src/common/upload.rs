//! 文件上传通用工具
//!
//! 提供 `write_upload_file` 公共函数，消除 handler 层多处重复的
//! `spawn_blocking + create_dir_all + write` 模板代码。

use std::path::PathBuf;

use axum::extract::multipart::Field;

use crate::common::error::AppError;
use crate::config::UploadConfig;

/// 危险扩展名黑名单（P0-3 上传安全加固）
///
/// 即使运维在 `common_allowed_exts` / `avatar_allowed_exts` 中放行，也**强制拒绝**：
/// 这些类型经 `/uploads/*` 静态托管后可能被浏览器按 HTML/SVG 执行，构成存储型 XSS
/// （SVG 可内嵌脚本，HTML 可直接渲染），或为服务端可执行脚本（php/jsp 等）。
const DANGEROUS_EXTS: &[&str] = &[
    "html", "htm", "shtml", "svg", "xml", "xhtml", "js", "mjs", "cjs", "php", "php3", "php4",
    "php5", "phtml", "jsp", "jspx", "asp", "aspx", "asax", "ashx", "asmx", "exe", "com", "bat",
    "cmd", "sh", "ps1", "hta", "asis", "pl", "py",
];

/// 上传类型（决定白名单/大小/目录/URL 前缀）
#[derive(Debug, Clone, Copy)]
pub enum UploadKind {
    /// 通用文件（common_dir / common_allowed_exts / common_max_size）
    Common,
    /// 头像（avatar_dir / avatar_allowed_exts / avatar_max_size）
    Avatar,
}

impl UploadKind {
    fn config<'a>(&self, cfg: &'a UploadConfig) -> (&'a [String], usize, &'a str, &'a str) {
        match self {
            UploadKind::Common => (
                &cfg.common_allowed_exts,
                cfg.common_max_size,
                &cfg.common_dir,
                &cfg.common_url_prefix,
            ),
            UploadKind::Avatar => (
                &cfg.avatar_allowed_exts,
                cfg.avatar_max_size,
                &cfg.avatar_dir,
                &cfg.avatar_url_prefix,
            ),
        }
    }
}

/// 上传成功后的文件信息（统一由 `save_upload_bytes` 返回）
#[derive(Debug)]
pub struct UploadedFile {
    /// 服务端生成的唯一文件名（如 `a1b2c3d4.png`）
    pub new_filename: String,
    /// 可访问 URL 路径（前端通过 VITE_APP_BASE_API + url 访问）
    pub url: String,
    /// 文件字节数
    pub size: u64,
    /// 实际扩展名（小写）
    pub ext: String,
    /// 原始文件名（前端传入）
    pub original_filename: Option<String>,
}

/// 解析上传文件根目录为绝对路径
///
/// 从 `UploadConfig.avatar_dir`（如 "uploads/avatar"）取父目录（"uploads"）作为静态资源根：
/// - 若为绝对路径，直接使用
/// - 若为相对路径，按以下顺序查找第一个存在的目录：
///   1. 进程 CWD + root（兼容 `cargo run` 从项目根启动）
///   2. 可执行文件所在目录 + root（生产部署：exe 与 uploads 同目录）
///   3. 可执行文件所在目录向上逐级查找直到找到 root（开发模式：exe 在 target/debug/，uploads 在项目根）
///   4. 兜底：创建 CWD + root 并返回（fail-soft，不阻断启动）
///
/// 修复头像 404 问题：原 `ServeDir::new("uploads")` 依赖进程 CWD，
/// 当后端从 `target/debug/axum-backend.exe` 启动且 CWD 不是 `axum-backend/` 时，
/// 相对路径无法定位到实际的 `uploads/` 目录。
pub fn resolve_upload_root(upload_config: &crate::config::UploadConfig) -> PathBuf {
    let avatar_dir = PathBuf::from(&upload_config.avatar_dir);
    let root = avatar_dir
        .parent()
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| PathBuf::from("uploads"));

    if root.is_absolute() {
        return root;
    }

    // 候选目录列表（按优先级排序）
    let mut candidates: Vec<PathBuf> = Vec::new();

    // 1. 进程 CWD + root
    if let Ok(cwd) = std::env::current_dir() {
        candidates.push(cwd.join(&root));
    }

    // 2. 可执行文件所在目录 + root
    if let Ok(exe) = std::env::current_exe()
        && let Some(exe_dir) = exe.parent()
    {
        candidates.push(exe_dir.to_path_buf().join(&root));

        // 3. 向上逐级查找（最多 5 级），适用于开发模式（exe 在 target/debug/，uploads 在项目根）
        let mut current = exe_dir.to_path_buf();
        for _ in 0..5 {
            if let Some(parent) = current.parent() {
                current = parent.to_path_buf();
                candidates.push(current.join(&root));
            } else {
                break;
            }
        }
    }

    // 返回第一个存在的候选目录
    for candidate in &candidates {
        if candidate.exists() {
            return candidate.clone();
        }
    }

    // 4. 兜底：创建 CWD + root 并返回（确保目录存在，避免保存与服务路径不一致）
    if let Some(fallback) = candidates.first() {
        std::fs::create_dir_all(fallback).ok();
        return fallback.clone();
    }
    root
}

/// 解析上传子目录为绝对路径
///
/// 与 `resolve_upload_root` 使用相同的解析逻辑，确保文件保存路径与
/// `ServeDir` 服务路径一致。
///
/// # 参数
/// - `dir`: 配置中的目录路径（如 "uploads/avatar" 或 "/data/yebot/uploads/file"）
///
/// # 返回
/// - 绝对路径：直接返回
/// - 相对路径：使用与 `resolve_upload_root` 相同的候选逻辑解析
///
/// 注：`std::env::current_dir` / `current_exe` 为进程级查询（无 async 等价物且极快），
/// 文件系统 IO（exists / create_dir_all）使用 `tokio::fs` 异步执行，避免阻塞 worker。
pub async fn resolve_upload_dir(dir: &str) -> PathBuf {
    let dir_path = PathBuf::from(dir);

    // 绝对路径直接返回
    if dir_path.is_absolute() {
        return dir_path;
    }

    // 相对路径：提取根目录，用相同候选逻辑解析
    let root = dir_path
        .parent()
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| PathBuf::from("uploads"));
    let subdir = dir_path
        .file_name()
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(""));

    let mut candidates: Vec<PathBuf> = Vec::new();

    if let Ok(cwd) = std::env::current_dir() {
        candidates.push(cwd.join(&root));
    }

    if let Ok(exe) = std::env::current_exe()
        && let Some(exe_dir) = exe.parent()
    {
        candidates.push(exe_dir.to_path_buf().join(&root));

        let mut current = exe_dir.to_path_buf();
        for _ in 0..5 {
            if let Some(parent) = current.parent() {
                current = parent.to_path_buf();
                candidates.push(current.join(&root));
            } else {
                break;
            }
        }
    }

    // 返回第一个存在的候选目录 + 子目录（异步 exists 检查，避免阻塞 worker）
    for candidate in &candidates {
        if tokio::fs::metadata(candidate).await.is_ok() {
            return candidate.join(&subdir);
        }
    }

    // 兜底：创建 CWD + root 并返回 CWD + root + subdir
    if let Some(fallback) = candidates.first() {
        tokio::fs::create_dir_all(fallback).await.ok();
        return fallback.join(&subdir);
    }
    dir_path
}

/// 将上传的字节数据异步写入文件系统
///
/// - 自动创建目标目录（若不存在）
/// - 通过 `tokio::task::spawn_blocking` 在阻塞线程池中执行文件 IO，避免阻塞异步运行时
/// - 返回写入的字节数（便于上层记录日志）
///
/// # 参数
/// - `file_path`: 目标文件完整路径（如 `/data/uploads/avatar/xxx.png`）
/// - `upload_dir`: 目标目录路径（如 `/data/uploads/avatar`），仅用于错误消息
/// - `bytes`: 文件内容
///
/// # 错误
/// - `AppError::internal("文件写入任务失败: ...")`：spawn_blocking join 失败（如 panic）
/// - `AppError::internal("写入上传文件失败: ...")`：底层 IO 错误（权限、磁盘满等）
///
/// # 使用示例
/// ```ignore
/// let file_path = upload_dir.join(&new_filename);
/// crate::common::upload::write_upload_file(
///     file_path,
///     &upload_cfg.common_dir,
///     &bytes,
/// ).await?;
/// ```
pub async fn write_upload_file(
    file_path: PathBuf,
    upload_dir: &str,
    bytes: &[u8],
) -> Result<u64, crate::common::error::AppError> {
    let file_path_clone = file_path.clone();
    let upload_dir_clone = upload_dir.to_string();
    let bytes_vec = bytes.to_vec();
    let size = bytes_vec.len() as u64;
    tokio::task::spawn_blocking(move || -> std::io::Result<()> {
        std::fs::create_dir_all(&upload_dir_clone)?;
        std::fs::write(&file_path_clone, &bytes_vec)?;
        Ok(())
    })
    .await
    .map_err(|_| {
        crate::common::error::AppError::internal(&crate::tr!("error.upload.write_task_failed"))
    })?
    .map_err(|_| {
        crate::common::error::AppError::internal(&crate::tr!("error.upload.write_failed"))
    })?;
    Ok(size)
}

/// 生成 UUID 文件名（防路径穿越，禁止使用前端原文件名）
///
/// # 参数
/// - `ext`: 文件扩展名（小写，不含点）
///
/// # 安全（P0-3）
/// 函数内部对 `ext` 做白名单净化：仅允许 1-10 位 ASCII 字母数字，
/// 拒绝 `/`、`\`、`..` 等任何路径字符与特殊符号，杜绝调用方传入恶意
/// 扩展名构成的路径穿越/覆盖。
pub fn gen_uuid_filename(ext: &str) -> Result<String, AppError> {
    let ext = ext.to_lowercase();
    if ext.is_empty() || ext.len() > 10 || !ext.chars().all(|c| c.is_ascii_alphanumeric()) {
        return Err(AppError::bad_request(&crate::tr!(
            "error.file.invalid_name"
        )));
    }
    Ok(format!("{}.{}", uuid::Uuid::new_v4(), ext))
}

/// 删除上传文件（best-effort，文件不存在视为成功）
///
/// 用于头像更新时清理旧文件、附件删除时清理本地文件等场景。
/// 使用 `spawn_blocking` 避免阻塞异步运行时。
///
/// # 安全（P0-3）
/// `allowed_root` 为已解析的受控上传根目录（如 `resolve_upload_dir(common_dir)`），
/// 函数内部通过 `canonicalize` + 路径边界校验强制 `file_path` 必须位于该根目录内，
/// 杜绝调用方疏漏导致任意文件删除。
/// 仅删除文件（不递归删除目录）。
pub async fn delete_upload_file(
    file_path: &str,
    allowed_root: &str,
) -> Result<(), crate::common::error::AppError> {
    let path = file_path.to_string();
    let root = allowed_root.to_string();
    tokio::task::spawn_blocking(move || -> std::io::Result<()> {
        let canonical_root = std::fs::canonicalize(&root).map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("上传根目录不存在: {root}"),
            )
        })?;
        // 目标不存在视为删除成功（幂等）
        let canonical_path = match std::fs::canonicalize(&path) {
            Ok(p) => p,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(e) => return Err(e),
        };
        // 路径边界校验：canonical_path 必须以 canonical_root 开头，且下一字符为分隔符或结束
        let root_str = canonical_root.to_string_lossy();
        let path_str = canonical_path.to_string_lossy();
        let sep = std::path::MAIN_SEPARATOR as u8;
        let within = path_str == root_str.as_ref()
            || (path_str.starts_with(root_str.as_ref())
                && path_str.as_bytes().get(root_str.len()) == Some(&sep));
        if !within {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "删除目标不在受控上传目录内",
            ));
        }
        std::fs::remove_file(&canonical_path)?;
        Ok(())
    })
    .await
    .map_err(|_| {
        crate::common::error::AppError::internal(&crate::tr!("error.upload.delete_task_failed"))
    })?
    .map_err(|_| {
        crate::common::error::AppError::internal(&crate::tr!("error.upload.delete_failed"))
    })?;
    Ok(())
}

/// 校验文件 magic bytes 是否匹配预期 MIME 类型
///
/// 基于文件扩展名检查前几个字节，防止伪造扩展名上传可执行文件等危险内容。
/// 不引入新 crate 依赖，仅做前缀字节匹配。
///
/// 支持的扩展名与 magic bytes：
/// - jpg/jpeg: `FF D8 FF`
/// - png: `89 50 4E 47 0D 0A 1A 0A`
/// - gif: `47 49 46 38` (GIF8)
/// - pdf: `25 50 44 46` (%PDF)
/// - doc/xls: `D0 CF 11 E0 A1 B1 1A E1`（OLE2 复合文档）
/// - docx/xlsx/pptx/zip: `50 4B 03 04` (PK..)
/// - txt: 无固定 magic；但拒绝伪装成文本的 HTML/脚本内容
///
/// # 参数
/// - `bytes`: 文件内容（至少包含 magic bytes 长度）
/// - `ext`: 文件扩展名（小写，不含点）
///
/// # 返回（P0-3 严格化）
/// - true: magic bytes 匹配，或扩展名属显式放行的纯文本类（txt）
/// - false: magic bytes 不匹配，或扩展名无对应 magic 映射（不再默认放行）
pub fn validate_magic_bytes(bytes: &[u8], ext: &str) -> bool {
    let magic: &[u8] = match ext {
        "jpg" | "jpeg" => &[0xFF, 0xD8, 0xFF],
        "png" => &[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A],
        "gif" => &[0x47, 0x49, 0x46, 0x38],
        "pdf" => &[0x25, 0x50, 0x44, 0x46],
        "doc" | "xls" => &[0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1],
        "docx" | "xlsx" | "pptx" | "zip" => &[0x50, 0x4B, 0x03, 0x04],
        // txt 无固定 magic bytes：显式放行，但需拒绝伪装成文本的标记/脚本内容
        "txt" => return !looks_like_markup_or_script(bytes),
        // 其余扩展名无 magic 映射：fail-closed 拒绝（原实现返回 true 放行，P0-3 收紧）
        _ => return false,
    };
    bytes.starts_with(magic)
}

/// 启发式检测文本内容是否伪装为 HTML/XML/脚本（P0-3 存储型 XSS 防线）
///
/// 仅对 `txt` 生效：若文本以 `<html`、`<!DOCTYPE`、`<!--`、`<script`、`<?xml`、`<svg` 等
/// 标记开头，拒绝（防止上传伪装成 txt 的网页，被静态托管后仍可被浏览器解析执行）。
fn looks_like_markup_or_script(bytes: &[u8]) -> bool {
    let head = String::from_utf8_lossy(&bytes[..bytes.len().min(256)]).to_lowercase();
    let head = head.trim_start_matches('\u{feff}').trim_start();
    head.starts_with("<html")
        || head.starts_with("<!doctype")
        || head.starts_with("<!--")
        || head.starts_with("<script")
        || head.starts_with("<?xml")
        || head.starts_with("<svg")
        || head.starts_with("<iframe")
        || head.starts_with("<object")
        || head.starts_with("<embed")
}

/// 流式读取 multipart 字段并限长（P0-3 OOM DoS 修复）
///
/// 原实现 `field.bytes()` 将整个文件读入内存后再校验大小，超大字段可直接打爆内存。
/// 本函数用 `field.chunk()` 边读边累计，超过 `max_size` 立即中止并返回错误，
/// 不将超大内容读入内存（累计缓冲上限 = max_size + 单 chunk 大小）。
///
/// # 返回
/// `(bytes, ext, original_filename)`：
/// - bytes: 已限长读取的内容
/// - ext: 从原始文件名推断的扩展名（小写，可能为 None）
/// - original_filename: 原始文件名
pub async fn read_field_limited(
    field: &mut Field<'_>,
    max_size: usize,
) -> Result<(Vec<u8>, Option<String>, Option<String>), AppError> {
    let original_filename = field.file_name().map(|s| s.to_string());
    let ext = original_filename
        .as_deref()
        .and_then(|name| std::path::Path::new(name).extension())
        .and_then(|e| e.to_str())
        .map(|e| e.to_lowercase());

    let mut bytes: Vec<u8> = Vec::new();
    let mut remaining = max_size.saturating_add(1) as u64; // 多读 1 字节用于触发超限判定
    while let Some(chunk) = field
        .chunk()
        .await
        .map_err(|e| AppError::bad_request(&crate::tr!("error.file.read_failed", e = e)))?
    {
        let chunk_len = chunk.len() as u64;
        if chunk_len > remaining {
            // 超限：丢弃本次 chunk，返回 413 语义的 400（避免整读内存）
            return Err(AppError::bad_request(&crate::tr!(
                "error.file.too_large",
                max = max_size / 1024 / 1024
            )));
        }
        remaining -= chunk_len;
        bytes.extend_from_slice(&chunk);
    }
    Ok((bytes, ext, original_filename))
}

/// 统一文件保存入口（P0-3 上传链路收敛）
///
/// 三处上传 handler（common_handler / file_handler / 头像）此前各自重复实现
/// 大小校验、扩展名白名单、magic bytes、写盘逻辑且安全水位不一。本函数统一：
/// 1. 空文件检查
/// 2. 大小检查（调用方已流式限长，此处双保险）
/// 3. 扩展名白名单校验 + 危险扩展名强制拒绝（DANGEROUS_EXTS）
/// 4. magic bytes 严格校验（图片以实际类型为准，文本类拒绝伪装标记内容）
/// 5. 生成 UUID 文件名（ext 净化）
/// 6. spawn_blocking 写盘
pub async fn save_upload_bytes(
    storage: &dyn crate::storage::StorageBackend,
    bytes: &[u8],
    declared_ext: Option<&str>,
    original_filename: Option<&str>,
    upload_cfg: &UploadConfig,
    kind: UploadKind,
) -> Result<UploadedFile, AppError> {
    if bytes.is_empty() {
        return Err(AppError::bad_request(&crate::tr!(
            "error.common_handler.file_empty"
        )));
    }
    let (allowed_exts, max_size, dir, url_prefix) = kind.config(upload_cfg);

    // 大小双保险（调用方流式限长后此处再校验一次，防配置差异）
    if bytes.len() > max_size {
        return Err(AppError::bad_request(&crate::tr!(
            "error.file.too_large",
            max = max_size / 1024 / 1024
        )));
    }

    // 扩展名白名单 + 危险类型强制拒绝
    let declared_ext = declared_ext.ok_or_else(|| {
        AppError::bad_request(&crate::tr!("error.common_handler.file_ext_unknown"))
    })?;
    let declared_ext = declared_ext.to_lowercase();
    if DANGEROUS_EXTS.contains(&declared_ext.as_str()) {
        tracing::warn!(ext = %declared_ext, "拒绝上传危险扩展名（静态托管 XSS/执行风险）");
        return Err(AppError::bad_request(&crate::tr!(
            "error.file.unsupported_type",
            ext = declared_ext
        )));
    }
    if !allowed_exts
        .iter()
        .any(|a| a.eq_ignore_ascii_case(&declared_ext))
    {
        return Err(AppError::bad_request(&crate::tr!(
            "error.file.unsupported_type",
            ext = declared_ext
        )));
    }

    // magic bytes 校验：图片类以实际识别结果为准（防伪造扩展名），其余走严格映射
    let image_exts: &[&str] = &["jpg", "jpeg", "png", "gif"];
    let ext = if image_exts.contains(&declared_ext.as_str()) {
        let detected = crate::common::image::detect_image_ext(bytes).ok_or_else(|| {
            AppError::bad_request(&crate::tr!("error.common_handler.image_format_unknown"))
        })?;
        if crate::common::image::normalize_ext(&declared_ext)
            != crate::common::image::normalize_ext(&detected)
        {
            tracing::warn!(
                declared = %declared_ext,
                detected = %detected,
                "图片扩展名与实际类型不一致，以 magic bytes 为准"
            );
        }
        detected
    } else {
        if !validate_magic_bytes(bytes, &declared_ext) {
            tracing::warn!(ext = %declared_ext, "文件内容与扩展名不匹配（magic bytes 校验失败）");
            return Err(AppError::bad_request(&crate::tr!(
                "error.file.unsupported_type",
                ext = declared_ext
            )));
        }
        declared_ext
    };

    // 生成唯一文件名（ext 已在函数内净化）
    let new_filename = gen_uuid_filename(&ext)?;

    // 保存到当前存储后端（local 写本地磁盘 / s3 上传对象），URL 由后端返回
    let url = storage.save(dir, &new_filename, url_prefix, bytes).await?;

    Ok(UploadedFile {
        new_filename,
        url,
        size: bytes.len() as u64,
        ext,
        original_filename: original_filename.map(|s| s.to_string()),
    })
}

#[cfg(test)]
mod tests {
    //! 覆盖意图：上传链路各纯函数与错误分支——`UploadKind` 配置选择、
    //! `gen_uuid_filename` 扩展名净化、`validate_magic_bytes` / `looks_like_markup_or_script`
    //! 的各类 magic 匹配、`resolve_upload_root` / `resolve_upload_dir` 的绝对路径直返、
    //! `write_upload_file` / `delete_upload_file` 的临时目录读写与路径边界校验、
    //! `read_field_limited` 的 multipart 流式限长，以及 `save_upload_bytes` 的全部分支
    //! （空文件 / 超限 / 缺扩展名 / 危险扩展名 / 白名单外 / magic 不匹配 / 图片按实际类型）。

    use super::*;
    use async_trait::async_trait;
    use std::sync::{Arc, Mutex};

    use crate::storage::StorageBackend;

    const PNG_MAGIC: &[u8] = &[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];
    const JPG_MAGIC: &[u8] = &[0xFF, 0xD8, 0xFF, 0xE0];
    const PDF_MAGIC: &[u8] = b"%PDF-1.7";
    const OLE_MAGIC: &[u8] = &[0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1];
    const ZIP_MAGIC: &[u8] = &[0x50, 0x4B, 0x03, 0x04];

    // ---------- UploadKind 配置选择 ----------

    #[test]
    fn upload_kind_selects_common_config() {
        let cfg = UploadConfig::default();
        let (exts, max, dir, prefix) = UploadKind::Common.config(&cfg);
        assert_eq!(exts, &cfg.common_allowed_exts);
        assert_eq!(max, cfg.common_max_size);
        assert_eq!(dir, &cfg.common_dir);
        assert_eq!(prefix, &cfg.common_url_prefix);
    }

    #[test]
    fn upload_kind_selects_avatar_config() {
        let cfg = UploadConfig::default();
        let (exts, max, dir, prefix) = UploadKind::Avatar.config(&cfg);
        assert_eq!(exts, &cfg.avatar_allowed_exts);
        assert_eq!(max, cfg.avatar_max_size);
        assert_eq!(dir, &cfg.avatar_dir);
        assert_eq!(prefix, &cfg.avatar_url_prefix);
    }

    // ---------- gen_uuid_filename ----------

    #[test]
    fn gen_uuid_filename_ok_and_lowercases() {
        let name = gen_uuid_filename("PNG").expect("合法扩展名应成功");
        assert!(name.ends_with(".png"), "实际: {name}");
        let uuid_part = name.trim_end_matches(".png");
        assert!(
            uuid::Uuid::parse_str(uuid_part).is_ok(),
            "应为 UUID: {name}"
        );
    }

    #[test]
    fn gen_uuid_filename_rejects_bad_ext() {
        assert!(gen_uuid_filename("").is_err()); // 空
        assert!(gen_uuid_filename("a".repeat(11).as_str()).is_err()); // 超 10 位
        assert!(gen_uuid_filename("a/b").is_err()); // 含路径分隔符
        assert!(gen_uuid_filename("..").is_err()); // 穿越
        assert!(gen_uuid_filename("a b").is_err()); // 含空格
        assert!(gen_uuid_filename("中文").is_err()); // 非 ASCII
    }

    // ---------- validate_magic_bytes / looks_like_markup_or_script ----------

    #[test]
    fn magic_bytes_match_per_extension() {
        assert!(validate_magic_bytes(JPG_MAGIC, "jpg"));
        assert!(validate_magic_bytes(JPG_MAGIC, "jpeg"));
        assert!(validate_magic_bytes(PNG_MAGIC, "png"));
        assert!(validate_magic_bytes(b"GIF89a...", "gif"));
        assert!(validate_magic_bytes(b"GIF87a...", "gif"));
        assert!(validate_magic_bytes(PDF_MAGIC, "pdf"));
        assert!(validate_magic_bytes(OLE_MAGIC, "doc"));
        assert!(validate_magic_bytes(OLE_MAGIC, "xls"));
        assert!(validate_magic_bytes(ZIP_MAGIC, "docx"));
        assert!(validate_magic_bytes(ZIP_MAGIC, "xlsx"));
        assert!(validate_magic_bytes(ZIP_MAGIC, "pptx"));
        assert!(validate_magic_bytes(ZIP_MAGIC, "zip"));
        // txt：纯文本放行
        assert!(validate_magic_bytes(b"hello plain text", "txt"));
    }

    #[test]
    fn magic_bytes_reject_mismatch_and_unknown() {
        // 内容与扩展名不匹配
        assert!(!validate_magic_bytes(b"not a jpeg", "jpg"));
        assert!(!validate_magic_bytes(PNG_MAGIC, "jpg"));
        assert!(!validate_magic_bytes(b"not pdf", "pdf"));
        // 未知扩展名 fail-closed
        assert!(!validate_magic_bytes(b"anything", "xyz"));
        assert!(!validate_magic_bytes(b"anything", ""));
        // txt 伪装成标记内容 → 拒绝
        assert!(!validate_magic_bytes(b"<html>hi</html>", "txt"));
        assert!(!validate_magic_bytes(b"<script>alert(1)</script>", "txt"));
    }

    #[test]
    fn looks_like_markup_or_script_prefixes() {
        // 各标记前缀均应判为“伪装文本”
        assert!(looks_like_markup_or_script(b"<html>"));
        assert!(looks_like_markup_or_script(b"<!DOCTYPE html>"));
        assert!(looks_like_markup_or_script(b"<!-- comment -->"));
        assert!(looks_like_markup_or_script(b"<script>"));
        assert!(looks_like_markup_or_script(b"<?xml version=\"1.0\"?>"));
        assert!(looks_like_markup_or_script(b"<svg>"));
        assert!(looks_like_markup_or_script(b"<iframe>"));
        assert!(looks_like_markup_or_script(b"<object>"));
        assert!(looks_like_markup_or_script(b"<embed>"));
        // 大小写不敏感 + 前导空白/BOM
        assert!(looks_like_markup_or_script(b"  <HTML>"));
        assert!(looks_like_markup_or_script(b"\xEF\xBB\xBF<html>"));
        // 普通文本放行
        assert!(!looks_like_markup_or_script(b"hello world"));
        assert!(!looks_like_markup_or_script(b"< not a tag"));
    }

    // ---------- resolve_upload_root / resolve_upload_dir ----------

    #[test]
    fn resolve_upload_root_absolute_path_passes_through() {
        // 绝对 avatar_dir：取父目录后 is_absolute 直接返回，不触碰文件系统
        let cfg = UploadConfig {
            avatar_dir: if cfg!(windows) {
                r"C:\yebot\uploads\avatar".to_string()
            } else {
                "/srv/yebot/uploads/avatar".to_string()
            },
            ..Default::default()
        };
        let root = resolve_upload_root(&cfg);
        assert!(root.is_absolute(), "应返回绝对路径: {root:?}");
        let expected = std::path::Path::new(&cfg.avatar_dir)
            .parent()
            .expect("有父目录");
        assert_eq!(root, expected);
    }

    #[tokio::test]
    async fn resolve_upload_dir_absolute_path_passes_through() {
        let dir = if cfg!(windows) {
            r"C:\yebot\uploads\file"
        } else {
            "/srv/yebot/uploads/file"
        };
        let resolved = resolve_upload_dir(dir).await;
        assert_eq!(resolved, std::path::PathBuf::from(dir));
    }

    // ---------- write_upload_file ----------

    #[tokio::test]
    async fn write_upload_file_writes_bytes_and_creates_dirs() {
        let root = temp_root();
        let dir = root.join("nested/deeper");
        let path = dir.join("a.txt");
        let size = write_upload_file(path.clone(), &dir.to_string_lossy(), b"hello")
            .await
            .expect("写入失败");
        assert_eq!(size, 5);
        assert_eq!(std::fs::read(&path).expect("应存在"), b"hello");
        std::fs::remove_dir_all(&root).ok();
    }

    // ---------- delete_upload_file ----------

    #[tokio::test]
    async fn delete_upload_file_deletes_and_is_idempotent() {
        let root = temp_root();
        let file = root.join("victim.txt");
        std::fs::write(&file, b"x").expect("写文件失败");
        delete_upload_file(&file.to_string_lossy(), &root.to_string_lossy())
            .await
            .expect("删除失败");
        assert!(!file.exists());
        // 不存在视为成功（幂等）
        delete_upload_file(&file.to_string_lossy(), &root.to_string_lossy())
            .await
            .expect("重复删除应幂等");
        std::fs::remove_dir_all(&root).ok();
    }

    #[tokio::test]
    async fn delete_upload_file_rejects_path_outside_root() {
        let root_a = temp_root();
        let root_b = temp_root();
        let victim = root_b.join("secret.txt");
        std::fs::write(&victim, b"x").expect("写文件失败");
        // root_a 下删除 root_b 的文件 → 越界拒绝
        let err = delete_upload_file(&victim.to_string_lossy(), &root_a.to_string_lossy())
            .await
            .expect_err("越界删除应失败");
        assert_eq!(err.code, 500); // internal（脱敏）
        assert!(victim.exists(), "越界删除不应生效");
        std::fs::remove_dir_all(&root_a).ok();
        std::fs::remove_dir_all(&root_b).ok();
    }

    #[tokio::test]
    async fn delete_upload_file_missing_root_is_error() {
        let root = temp_root().join("does_not_exist");
        let err = delete_upload_file(
            &root.join("f.txt").to_string_lossy(),
            &root.to_string_lossy(),
        )
        .await
        .expect_err("根目录不存在应报错");
        assert_eq!(err.code, 500);
    }

    // ---------- read_field_limited（multipart 流式限长） ----------

    /// 解析 multipart body 并读取第一个字段（完全异步，不嵌套 block_on）
    async fn read_first_field(
        body: &str,
        boundary: &str,
        max_size: usize,
    ) -> Result<(Vec<u8>, Option<String>, Option<String>), AppError> {
        use axum::body::Body;
        use axum::extract::FromRequest;
        use axum::extract::multipart::Multipart;
        use axum::http::Request;
        let req = Request::builder()
            .header(
                "content-type",
                format!("multipart/form-data; boundary={boundary}"),
            )
            .body(Body::from(body.to_string()))
            .expect("构造 multipart 请求失败");
        let mut mp = Multipart::from_request(req, &())
            .await
            .expect("解析 multipart 失败");
        let mut field = mp
            .next_field()
            .await
            .expect("读取字段失败")
            .expect("应存在字段");
        read_field_limited(&mut field, max_size).await
    }

    #[tokio::test]
    async fn read_field_limited_captures_bytes_ext_and_name() {
        let boundary = "XBOUND";
        let body = format!(
            "--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"report.txt\"\r\nContent-Type: text/plain\r\n\r\nhello world\r\n--{boundary}--\r\n"
        );
        let (bytes, ext, name) = read_first_field(&body, boundary, 1024)
            .await
            .expect("读取成功");
        assert_eq!(bytes, b"hello world");
        assert_eq!(ext.as_deref(), Some("txt"));
        assert_eq!(name.as_deref(), Some("report.txt"));
    }

    #[tokio::test]
    async fn read_field_limited_rejects_oversize() {
        let boundary = "XBOUND";
        let body = format!(
            "--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"big.bin\"\r\n\r\n{}\r\n--{boundary}--\r\n",
            "x".repeat(100)
        );
        let err = read_first_field(&body, boundary, 10)
            .await
            .expect_err("超限应失败");
        assert_eq!(err.code, 400);
        assert!(err.message.contains("MB"), "实际: {}", err.message);
    }

    // ---------- save_upload_bytes（mock 后端） ----------

    /// 记录保存调用（dir, key, bytes）
    type SaveCalls = Vec<(String, String, Vec<u8>)>;

    /// 记录保存调用（dir, key, bytes）的内存 mock 后端
    struct MockBackend(Arc<Mutex<SaveCalls>>);

    #[async_trait]
    impl StorageBackend for MockBackend {
        fn kind(&self) -> &'static str {
            "mock"
        }

        async fn save(
            &self,
            dir: &str,
            key: &str,
            _url_prefix: &str,
            bytes: &[u8],
        ) -> Result<String, AppError> {
            self.0
                .lock()
                .unwrap()
                .push((dir.to_string(), key.to_string(), bytes.to_vec()));
            Ok(format!("mock://{dir}/{key}"))
        }

        async fn read(&self, _dir: &str, _key: &str) -> Result<Option<Vec<u8>>, AppError> {
            Ok(None)
        }

        async fn delete(&self, _dir: &str, _key: &str) -> Result<(), AppError> {
            Ok(())
        }

        async fn list(
            &self,
            _dir: &str,
            _url_prefix: &str,
        ) -> Result<Vec<crate::storage::StorageObject>, AppError> {
            Ok(Vec::new())
        }
    }

    #[tokio::test]
    async fn save_upload_bytes_rejects_empty() {
        let backend = MockBackend(Arc::new(Mutex::new(Vec::new())));
        let cfg = UploadConfig::default();
        let err = save_upload_bytes(&backend, b"", Some("png"), None, &cfg, UploadKind::Common)
            .await
            .expect_err("空文件应失败");
        assert_eq!(err.code, 400);
    }

    #[tokio::test]
    async fn save_upload_bytes_rejects_too_large() {
        let backend = MockBackend(Arc::new(Mutex::new(Vec::new())));
        let cfg = UploadConfig::default();
        // common_max_size 默认 10MB，给 11MB 数据（不实际分配，用重复小向量）
        let big: Vec<u8> = vec![0u8; cfg.common_max_size + 1];
        let err = save_upload_bytes(&backend, &big, Some("png"), None, &cfg, UploadKind::Common)
            .await
            .expect_err("超限应失败");
        assert_eq!(err.code, 400);
        assert!(err.message.contains("MB"));
    }

    #[tokio::test]
    async fn save_upload_bytes_rejects_missing_ext() {
        let backend = MockBackend(Arc::new(Mutex::new(Vec::new())));
        let cfg = UploadConfig::default();
        let err = save_upload_bytes(&backend, b"data", None, None, &cfg, UploadKind::Common)
            .await
            .expect_err("缺扩展名应失败");
        assert_eq!(err.code, 400);
    }

    #[tokio::test]
    async fn save_upload_bytes_rejects_dangerous_ext() {
        let backend = MockBackend(Arc::new(Mutex::new(Vec::new())));
        let cfg = UploadConfig::default();
        // 即使 html 不在白名单也会被 DANGEROUS_EXTS 强制拒绝
        let err = save_upload_bytes(
            &backend,
            b"<html></html>",
            Some("html"),
            None,
            &cfg,
            UploadKind::Common,
        )
        .await
        .expect_err("危险扩展名应失败");
        assert_eq!(err.code, 400);
        assert!(err.message.contains("html"));
    }

    #[tokio::test]
    async fn save_upload_bytes_rejects_ext_not_in_whitelist() {
        let backend = MockBackend(Arc::new(Mutex::new(Vec::new())));
        let cfg = UploadConfig::default();
        let err = save_upload_bytes(
            &backend,
            b"data",
            Some("xyz"),
            None,
            &cfg,
            UploadKind::Common,
        )
        .await
        .expect_err("白名单外应失败");
        assert_eq!(err.code, 400);
    }

    #[tokio::test]
    async fn save_upload_bytes_rejects_magic_mismatch_for_non_image() {
        let backend = MockBackend(Arc::new(Mutex::new(Vec::new())));
        let cfg = UploadConfig::default();
        // 声明 pdf 但内容是纯文本 → magic 校验失败
        let err = save_upload_bytes(
            &backend,
            b"not a pdf at all",
            Some("pdf"),
            None,
            &cfg,
            UploadKind::Common,
        )
        .await
        .expect_err("magic 不匹配应失败");
        assert_eq!(err.code, 400);
    }

    #[tokio::test]
    async fn save_upload_bytes_image_uses_detected_real_type() {
        let backend = MockBackend(Arc::new(Mutex::new(Vec::new())));
        let cfg = UploadConfig::default();
        // 声明 jpg 但字节为 PNG → 以 magic 识别结果 png 为准保存
        let file = save_upload_bytes(
            &backend,
            PNG_MAGIC,
            Some("jpg"),
            Some("photo.jpg"),
            &cfg,
            UploadKind::Common,
        )
        .await
        .expect("应按实际类型保存");
        assert_eq!(file.ext, "png");
        assert!(file.new_filename.ends_with(".png"));
        assert_eq!(file.size, PNG_MAGIC.len() as u64);
        assert_eq!(file.original_filename.as_deref(), Some("photo.jpg"));
        assert_eq!(
            file.url,
            format!("mock://{}/{}", cfg.common_dir, file.new_filename)
        );
        // 后端收到 key = 生成的 UUID 文件名
        let calls = backend.0.lock().unwrap();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].0, cfg.common_dir);
        assert_eq!(calls[0].1, file.new_filename);
        assert_eq!(calls[0].2, PNG_MAGIC);
    }

    #[tokio::test]
    async fn save_upload_bytes_image_matches_declared() {
        let backend = MockBackend(Arc::new(Mutex::new(Vec::new())));
        let cfg = UploadConfig::default();
        let file = save_upload_bytes(
            &backend,
            JPG_MAGIC,
            Some("jpeg"),
            None,
            &cfg,
            UploadKind::Common,
        )
        .await
        .expect("JPEG 应成功");
        assert_eq!(file.ext, "jpg"); // jpeg 归一为 jpg
        assert!(file.new_filename.ends_with(".jpg"));
    }

    #[tokio::test]
    async fn save_upload_bytes_non_image_success() {
        let backend = MockBackend(Arc::new(Mutex::new(Vec::new())));
        let cfg = UploadConfig::default();
        let file = save_upload_bytes(
            &backend,
            b"hello world",
            Some("txt"),
            None,
            &cfg,
            UploadKind::Common,
        )
        .await
        .expect("txt 应成功");
        assert_eq!(file.ext, "txt");
        assert!(file.new_filename.ends_with(".txt"));
    }

    // ---------- 测试辅助 ----------

    fn temp_root() -> std::path::PathBuf {
        let root = std::env::temp_dir().join(format!("yebot_upload_test_{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&root).expect("创建临时目录失败");
        root
    }
}
