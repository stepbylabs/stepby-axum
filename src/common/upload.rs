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
pub fn resolve_upload_dir(dir: &str) -> PathBuf {
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

    // 返回第一个存在的候选目录 + 子目录
    for candidate in &candidates {
        if candidate.exists() {
            return candidate.join(&subdir);
        }
    }

    // 兜底：创建 CWD + root 并返回 CWD + root + subdir
    if let Some(fallback) = candidates.first() {
        std::fs::create_dir_all(fallback).ok();
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
    .map_err(|e| crate::common::error::AppError::internal(&format!("文件写入任务失败: {}", e)))?
    .map_err(|e| {
        crate::common::error::AppError::internal(&format!(
            "写入上传文件失败 (path={}, dir={}): {}",
            file_path.display(),
            upload_dir,
            e
        ))
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
