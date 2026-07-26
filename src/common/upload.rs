//! 文件上传通用工具
//!
//! 提供 `write_upload_file` 公共函数，消除 handler 层多处重复的
//! `spawn_blocking + create_dir_all + write` 模板代码。

use std::path::PathBuf;

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
        .map(|n| PathBuf::from(n))
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
    .map_err(|_| crate::common::error::AppError::internal(&crate::tr!("error.upload.write_task_failed")))?
    .map_err(|_| {
        crate::common::error::AppError::internal(&crate::tr!("error.upload.write_failed"))
    })?;
    Ok(size)
}

/// 生成 UUID 文件名（防路径穿越，禁止使用前端原文件名）
///
/// # 参数
/// - `ext`: 文件扩展名（小写，不含点）
pub fn gen_uuid_filename(ext: &str) -> String {
    format!("{}.{}", uuid::Uuid::new_v4(), ext)
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
/// - doc: `D0 CF 11 E0 A1 B1 1A E1`
/// - docx/xlsx/pptx/zip: `50 4B 03 04` (PK..)
/// - txt: 不校验（无 magic bytes）
///
/// # 参数
/// - `bytes`: 文件内容前若干字节（至少包含 magic bytes 长度）
/// - `ext`: 文件扩展名（小写，不含点）
///
/// # 返回
/// - true: magic bytes 匹配，或扩展名无需校验（如 txt）
/// - false: magic bytes 不匹配（疑似伪造扩展名）
pub fn validate_magic_bytes(bytes: &[u8], ext: &str) -> bool {
    let magic: &[u8] = match ext {
        "jpg" | "jpeg" => &[0xFF, 0xD8, 0xFF],
        "png" => &[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A],
        "gif" => &[0x47, 0x49, 0x46, 0x38],
        "pdf" => &[0x25, 0x50, 0x44, 0x46],
        "doc" => &[0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1],
        "docx" | "xlsx" | "pptx" | "zip" => &[0x50, 0x4B, 0x03, 0x04],
        // txt 及其他未列出扩展名：不校验 magic bytes
        _ => return true,
    };
    bytes.starts_with(magic)
}
