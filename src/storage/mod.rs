//! 文件存储抽象（F1）
//!
//! 通过 `StorageBackend` trait 隔离文件保存/读取/删除/列举行为，支持两种实现：
//! - [`local::LocalBackend`]：本地文件系统（默认，配合受鉴权的 `/uploads/*` 预览路由）
//! - [`s3::S3Backend`]：S3 兼容对象存储（MinIO / AWS S3 / 阿里云 OSS / 腾讯 COS）
//!
//! 切换方式：`[upload] backend = "local" | "s3"`，前端无感知（URL 由后端统一返回）。

use std::sync::Arc;

use async_trait::async_trait;

use crate::common::error::AppError;
use crate::config::UploadConfig;

mod local;
mod s3;
mod sigv4;

pub use local::LocalBackend;
/// 本地后端的路径/键校验助手：供 `initialize` 的存量上传路径回填复用，避免路径推导漂移
pub(crate) use local::{dir_path, valid_key};
pub use s3::{S3Backend, content_type_for};
pub use sigv4::{
    canonical_headers, canonical_request, hmac_sha256, payload_hash, sha256_hex, signature,
    signing_key, string_to_sign,
};

/// 按租户维度重写目录 / URL 前缀：在首个路径段之后插入 `{tenant_id}` 段。
///
/// 用于把上传文件物理隔离到 `uploads/{tid}/...`（平台租户为 `0`）：
/// - `uploads/file` + 5 → `uploads/5/file`
/// - `/uploads/file` + 5 → `/uploads/5/file`
/// - `uploads` + 5 → `uploads/5`
pub fn tenant_scoped_path(base: &str, tenant_id: i64) -> String {
    let leading = base.starts_with('/');
    let trimmed = base.trim_matches('/');
    let scoped = match trimmed.split_once('/') {
        Some((head, tail)) => format!("{head}/{tenant_id}/{tail}"),
        None if trimmed.is_empty() => tenant_id.to_string(),
        None => format!("{trimmed}/{tenant_id}"),
    };
    if leading {
        format!("/{scoped}")
    } else {
        scoped
    }
}

/// 存储对象元信息（`list` 返回）
#[derive(Debug, Clone)]
pub struct StorageObject {
    /// 文件名（不含目录前缀）
    pub name: String,
    /// 字节数
    pub size: u64,
    /// 修改时间（UNIX 秒）
    pub modified_secs: i64,
    /// 可访问 URL
    pub url: String,
}

/// 存储后端抽象（经 `async_trait` 编译为 boxed future，dyn-compatible，可存于 `Arc<dyn StorageBackend>`）
#[async_trait]
pub trait StorageBackend: Send + Sync {
    /// 后端类型标识（`local` / `s3`）
    fn kind(&self) -> &'static str;

    /// 是否提供本地静态托管（决定是否挂载受鉴权的 `/uploads/*` 预览路由）
    fn supports_static(&self) -> bool {
        false
    }

    /// 保存对象。`dir` 为配置中的目录路径（如 `uploads/file`），`tenant_id` 为归属租户
    /// （平台=0，实际落盘/对象 key 会插入该段实现隔离），`key` 为文件名，
    /// `url_prefix` 为本地访问 URL 前缀（s3 后端忽略）。返回可访问 URL。
    async fn save(
        &self,
        dir: &str,
        tenant_id: i64,
        key: &str,
        url_prefix: &str,
        bytes: &[u8],
    ) -> Result<String, AppError>;

    /// 读取对象内容（不存在返回 Ok(None)）。
    async fn read(&self, dir: &str, tenant_id: i64, key: &str) -> Result<Option<Vec<u8>>, AppError>;

    /// 删除对象（不存在视为成功，幂等）。
    async fn delete(&self, dir: &str, tenant_id: i64, key: &str) -> Result<(), AppError>;

    /// 列出指定租户目录下全部对象。
    async fn list(
        &self,
        dir: &str,
        tenant_id: i64,
        url_prefix: &str,
    ) -> Result<Vec<StorageObject>, AppError>;
}

/// 构建存储后端（依据 `UploadConfig.backend`）
///
/// - `local`：默认，本地文件系统
/// - `s3`：S3 兼容对象存储；缺少必需配置（endpoint/bucket/access_key/secret_key）时报错
/// - 其它值：报错提示支持项
pub fn new_backend(cfg: &UploadConfig) -> Result<Arc<dyn StorageBackend>, AppError> {
    match cfg.backend.as_str() {
        "local" => Ok(Arc::new(LocalBackend {})),
        "s3" => S3Backend::try_new(&cfg.s3).map(|b| Arc::new(b) as Arc<dyn StorageBackend>),
        other => Err(AppError::bad_request(&crate::tr!(
            "error.storage.unsupported_backend",
            backend = other
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tenant_scoped_path_inserts_tid_after_first_segment() {
        assert_eq!(tenant_scoped_path("uploads/file", 5), "uploads/5/file");
        assert_eq!(tenant_scoped_path("/uploads/file", 5), "/uploads/5/file");
        assert_eq!(tenant_scoped_path("uploads/avatar", 0), "uploads/0/avatar");
        assert_eq!(tenant_scoped_path("uploads", 7), "uploads/7");
        assert_eq!(tenant_scoped_path("/uploads", 7), "/uploads/7");
        assert_eq!(tenant_scoped_path("/uploads/file/", 3), "/uploads/3/file");
    }

    #[test]
    #[allow(clippy::field_reassign_with_default)]
    fn new_backend_selects_by_config() {
        let mut cfg = UploadConfig::default();

        // local（默认）：直接成功
        cfg.backend = "local".into();
        assert_eq!(new_backend(&cfg).unwrap().kind(), "local");

        // s3 但缺少必需配置 → 报错
        cfg.backend = "s3".into();
        assert!(new_backend(&cfg).is_err());

        // 未识别后端 → 报错
        cfg.backend = "ftp".into();
        assert!(new_backend(&cfg).is_err());

        // 本地后端不支持静态托管修饰为空由 kind() 判定，s3 不提供
        cfg.backend = "local".into();
        let local = new_backend(&cfg).unwrap();
        assert!(local.supports_static());
    }

    #[test]
    #[allow(clippy::field_reassign_with_default)]
    fn new_backend_s3_ok_with_full_config() {
        let mut cfg = UploadConfig::default();
        cfg.backend = "s3".into();
        cfg.s3.access_key = "ak".into();
        cfg.s3.secret_key = "sk".into();
        cfg.s3.endpoint = "http://127.0.0.1:9000".into();
        cfg.s3.bucket = "bkt".into();

        let backend = new_backend(&cfg).expect("s3 配置齐全应成功");
        assert_eq!(backend.kind(), "s3");
        assert!(!backend.supports_static()); // s3 不经 /uploads 预览路由（对象存储直出）
    }
}
