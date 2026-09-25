//! 本地文件系统存储后端（默认，F1）
//!
//! 复用既有 `common::upload` 的目录解析 / 写盘 / 删除逻辑，仅在 handler 之上
//! 增加一层统一的 `StorageBackend` 抽象，使调用方无差别使用 local/s3。

use std::path::PathBuf;

use async_trait::async_trait;

use crate::common::error::AppError;
use crate::storage::{StorageBackend, StorageObject};

/// 本地文件系统实现：配置目录（如 `uploads/file`）下按 `{tid}/dir/key` 组织文件
pub struct LocalBackend;

/// 解析带租户维度的目录绝对路径：先按既有根目录解析逻辑定位配置目录（如 `<root>/file`），
/// 再在其末段前插入 `{tenant_id}` 段（如 `<root>/5/file`），
/// 从而与 `resolve_upload_dir` 的根目录探测保持一致，并实现租户物理隔离。
pub(crate) async fn dir_path(dir: &str, tenant_id: i64) -> PathBuf {
    let base = crate::common::resolve_upload_dir(dir).await;
    match base.file_name() {
        Some(leaf) => base.with_file_name(tenant_id.to_string()).join(leaf),
        None => base.join(tenant_id.to_string()),
    }
}

/// key 安全校验（复用既有 P0-3 规则：拒绝路径分隔符与穿越）
pub(crate) fn valid_key(key: &str) -> bool {
    !key.is_empty()
        && !key.contains('/')
        && !key.contains('\\')
        && !key.contains("..")
        && !key.contains('\0')
}

#[async_trait]
impl StorageBackend for LocalBackend {
    fn kind(&self) -> &'static str {
        "local"
    }

    fn supports_static(&self) -> bool {
        true
    }

    async fn save(
        &self,
        dir: &str,
        tenant_id: i64,
        key: &str,
        url_prefix: &str,
        bytes: &[u8],
    ) -> Result<String, AppError> {
        if !valid_key(key) {
            return Err(AppError::bad_request(&crate::tr!(
                "error.file.invalid_name"
            )));
        }
        let upload_dir = dir_path(dir, tenant_id).await;
        let abs_dir = upload_dir.to_string_lossy().to_string();
        let abs_path = upload_dir.join(key);
        let bytes_vec = bytes.to_vec();
        tokio::task::spawn_blocking(move || -> std::io::Result<()> {
            std::fs::create_dir_all(&abs_dir)?;
            std::fs::write(&abs_path, &bytes_vec)?;
            Ok(())
        })
        .await
        .map_err(|_| AppError::internal(&crate::tr!("error.upload.write_task_failed")))?
        .map_err(|_| AppError::internal(&crate::tr!("error.upload.write_failed")))?;

        // URL 与落盘路径同为租户维度：`{url_prefix}/{tid}/{key}`
        let prefix = crate::storage::tenant_scoped_path(url_prefix, tenant_id);
        Ok(format!("{}/{}", prefix.trim_end_matches('/'), key))
    }

    async fn read(
        &self,
        dir: &str,
        tenant_id: i64,
        key: &str,
    ) -> Result<Option<Vec<u8>>, AppError> {
        if !valid_key(key) {
            return Err(AppError::bad_request(&crate::tr!(
                "error.file.invalid_name"
            )));
        }
        let path = dir_path(dir, tenant_id).await.join(key);
        tokio::task::spawn_blocking(move || -> std::io::Result<Option<Vec<u8>>> {
            if !path.exists() {
                return Ok(None);
            }
            std::fs::read(&path).map(Some)
        })
        .await
        .map_err(|_| AppError::internal(&crate::tr!("error.upload.file_read_task_failed")))?
        .map_err(|_| AppError::internal(&crate::tr!("error.upload.file_read_failed")))
    }

    async fn delete(&self, dir: &str, tenant_id: i64, key: &str) -> Result<(), AppError> {
        if !valid_key(key) {
            return Err(AppError::bad_request(&crate::tr!(
                "error.file.invalid_name"
            )));
        }
        let upload_dir = dir_path(dir, tenant_id).await;
        let root_str = upload_dir.to_string_lossy().to_string();
        let path_str = upload_dir.join(key).to_string_lossy().to_string();
        // 复用既有 delete_upload_file（canonicalize + 前缀边界校验，防任意删除）
        crate::common::upload::delete_upload_file(&path_str, &root_str).await
    }

    async fn list(
        &self,
        dir: &str,
        tenant_id: i64,
        url_prefix: &str,
    ) -> Result<Vec<StorageObject>, AppError> {
        let dir = dir_path(dir, tenant_id).await;
        let entries: Vec<(String, u64, i64)> =
            tokio::task::spawn_blocking(move || -> std::io::Result<Vec<(String, u64, i64)>> {
                if !dir.exists() {
                    return Ok(Vec::new());
                }
                let mut result = Vec::new();
                for entry in std::fs::read_dir(&dir)? {
                    let Ok(entry) = entry else { continue };
                    let Ok(meta) = entry.metadata() else { continue };
                    if !meta.is_file() {
                        continue;
                    }
                    let name = entry.file_name().to_string_lossy().to_string();
                    let size = meta.len();
                    let modified = meta
                        .modified()
                        .ok()
                        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                        .map(|d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
                        .unwrap_or(0);
                    result.push((name, size, modified));
                }
                Ok(result)
            })
            .await
            .map_err(|_| AppError::internal(&crate::tr!("error.file.list_task_failed")))?
            .map_err(|_| AppError::internal(&crate::tr!("error.file.list_failed")))?;

        let prefix = crate::storage::tenant_scoped_path(url_prefix, tenant_id);
        let prefix = prefix.trim_end_matches('/');
        Ok(entries
            .into_iter()
            .map(|(name, size, modified_secs)| StorageObject {
                url: format!("{prefix}/{name}"),
                name,
                size,
                modified_secs,
            })
            .collect())
    }
}

#[cfg(test)]
mod tests {
    //! 覆盖意图：本地后端的 save/read/list/delete 全流程回环、key 安全校验（穿越/分隔符/NUL
    //! 拒绝）、缺失目录 list 为空、kind/supports_static 标识，以及 `valid_key` 纯函数分支。

    use super::*;

    /// 创建一次性临时根目录（避免污染仓库 uploads/）。
    fn temp_root() -> std::path::PathBuf {
        let root =
            std::env::temp_dir().join(format!("yebot_storage_test_{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&root).expect("创建临时目录失败");
        root
    }

    #[tokio::test]
    async fn save_read_list_delete_roundtrip() {
        let root = temp_root();
        let dir = root.join("file");
        let dir_str = dir.to_string_lossy().to_string();
        let backend = LocalBackend;

        // save：返回 {url_prefix}/{tid}/{key}
        let url = backend
            .save(&dir_str, 5, "hello.txt", "/uploads/file", b"hello world")
            .await
            .expect("save 失败");
        assert_eq!(url, "/uploads/5/file/hello.txt");

        // read：回读内容一致
        let read = backend
            .read(&dir_str, 5, "hello.txt")
            .await
            .expect("read 失败");
        assert_eq!(read, Some(b"hello world".to_vec()));

        // 跨租户读取不可见（物理隔离）
        assert_eq!(
            backend.read(&dir_str, 6, "hello.txt").await.unwrap(),
            None,
            "其它租户目录不应读到本租户文件"
        );

        // list：仅返回该目录下文件，size 与文件名正确
        let list = backend
            .list(&dir_str, 5, "/uploads/file")
            .await
            .expect("list 失败");
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].name, "hello.txt");
        assert_eq!(list[0].size, 11);
        assert_eq!(list[0].url, "/uploads/5/file/hello.txt");

        // 重复 save 覆盖
        backend
            .save(&dir_str, 5, "hello.txt", "/uploads/file", b"new")
            .await
            .expect("覆盖保存失败");
        let read2 = backend
            .read(&dir_str, 5, "hello.txt")
            .await
            .expect("read 失败");
        assert_eq!(read2, Some(b"new".to_vec()));

        // delete：删除后 read 为 None，重复 delete 幂等成功
        backend
            .delete(&dir_str, 5, "hello.txt")
            .await
            .expect("delete 失败");
        assert_eq!(backend.read(&dir_str, 5, "hello.txt").await.unwrap(), None);
        backend
            .delete(&dir_str, 5, "hello.txt")
            .await
            .expect("重复删除应幂等");

        std::fs::remove_dir_all(&root).ok();
    }

    #[tokio::test]
    async fn rejects_traversal_keys() {
        let dir = std::env::temp_dir()
            .join("yebot_storage_noop")
            .to_string_lossy()
            .to_string();
        let backend = LocalBackend;
        assert!(
            backend
                .save(&dir, 0, "../evil.txt", "/uploads/file", b"x")
                .await
                .is_err()
        );
        assert!(
            backend
                .save(&dir, 0, "a\\b", "/uploads/file", b"x")
                .await
                .is_err()
        );
        assert!(backend.read(&dir, 0, "a/b").await.is_err());
        assert!(backend.delete(&dir, 0, "..").await.is_err());
        assert!(backend.read(&dir, 0, "a\0b").await.is_err());
    }

    #[tokio::test]
    async fn list_missing_dir_is_empty() {
        let root = temp_root();
        let dir_str = root.join("not_exist").to_string_lossy().to_string();
        let backend = LocalBackend;
        assert!(
            backend
                .list(&dir_str, 0, "/uploads/file")
                .await
                .unwrap()
                .is_empty()
        );
        std::fs::remove_dir_all(&root).ok();
    }

    // ---------- 补充覆盖：valid_key 纯函数 / kind / supports_static ----------

    #[test]
    fn valid_key_rejects_unsafe_keys() {
        // 合法 key
        assert!(valid_key("abc.png"));
        assert!(valid_key("a-b_c.d"));
        // 空 key
        assert!(!valid_key(""));
        // 路径分隔符 / 反斜杠
        assert!(!valid_key("a/b.png"));
        assert!(!valid_key("a\\b.png"));
        // 穿越
        assert!(!valid_key(".."));
        assert!(!valid_key("../evil.png"));
        assert!(!valid_key("a/../b.png"));
        // NUL
        assert!(!valid_key("a\0b.png"));
    }

    #[test]
    fn local_backend_kind_and_static_support() {
        let backend = LocalBackend;
        assert_eq!(backend.kind(), "local");
        assert!(backend.supports_static());
    }
}
