// stepby-axum/src/common/upload_chunk.rs
//! 分片上传/断点续传（G-10，P3 按需项——方案深审 2026-10-06 定稿）
//!
//! **架构取舍**：分片先落**服务端本地暂存区**（`__chunks/{tid}/{sid}/{idx}`），
//! complete 时服务端拼接 → 整对象校验（白名单 + magic bytes）→ `ensure_clean`
//! 扫描 → 经 `StorageBackend::save` 写最终存储。刻意**不使用 S3 multipart 直传**：
//! multipart Complete 前无法对整对象做扫描（违反"merge 后整扫"约束），且会绕过
//! `save_upload_bytes` 的统一校验链。代价是大文件需占用服务端暂存盘与内存
//! （总上限 [`UploadConfig::common_chunk_max_total_size`]，默认 64MB）——
//! 更大文件的流式校验重构另行立项。
//!
//! 三约束（深审定稿）：
//! 1. **分片不扫、merge 后整扫**——分片字节不构成完整文件，扫描无意义且会误拒；
//! 2. **会话记账经 SharedStore trait**（`get`/`set_ex`/`consume`/`del` 通用 KV 承载，
//!    JSON 会话 + TTL，禁止任何 redis 裸调用）；
//! 3. **并发硬上限**——complete 阶段 `Semaphore::try_acquire`（fail-closed 快速失败
//!    429），单机内存峰值 = 总上限 × 并发许可数。
//!
//! 断点续传语义：会话记录已收分片索引（`received`），客户端经
//! `GET /common/upload/chunk/session/{id}` 查询后仅补传缺失分片；
//! 会话 TTL（`chunk_session_ttl_secs`，默认 2h）到期自动失效，孤儿分片文件
//! 由内置定时任务 `chunk_cleanup` 按 mtime 清理。

use std::collections::BTreeSet;
use std::path::PathBuf;
use std::sync::OnceLock;

use serde::{Deserialize, Serialize};
use tokio::sync::Semaphore;

use crate::common::error::AppError;
use crate::config::UploadConfig;

/// 分片上传并发许可数（complete 拼接/校验/扫描阶段的内存保护，A2 硬上限）
pub const CHUNK_COMPLETE_PERMITS: usize = 2;

/// 进程级并发闸（complete 阶段专用；try_acquire fail-closed，不排队占连接）
pub fn complete_semaphore() -> &'static Semaphore {
    static SEM: OnceLock<Semaphore> = OnceLock::new();
    SEM.get_or_init(|| Semaphore::new(CHUNK_COMPLETE_PERMITS))
}

/// 分片会话（SharedStore JSON 载荷）
///
/// `received` 用 BTreeSet：分片乱序到达时索引天然有序，merge 按序拼接、
/// 序列化输出稳定（断点续传查询返回确定性列表）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChunkSession {
    /// 原始文件名（仅用于 complete 后回显 original_filename，不落盘）
    pub file_name: String,
    /// 扩展名（小写，init 时校验白名单后冻结——complete 按此校验，防中途换名绕过）
    pub ext: String,
    /// 分片总数
    pub total_parts: u32,
    /// 已收分片索引（0-based）
    pub received: BTreeSet<u32>,
    /// 上传者租户（分片目录隔离维度；init 冻结，complete 校验归属）
    pub tenant_id: i64,
}

impl ChunkSession {
    /// SharedStore key（租户维度隔离，防跨租户会话操作）
    pub fn store_key(tenant_id: i64, session_id: &str) -> String {
        format!("upload_session:{tenant_id}:{session_id}")
    }

    /// 反序列化校验（存储值损坏/被篡改时返回 Err 而非 panic）
    pub fn parse(raw: &str) -> Result<Self, AppError> {
        serde_json::from_str(raw)
            .map_err(|e| AppError::bad_request(&format!("分片会话数据损坏: {e}")))
    }

    /// 序列化（SharedStore 写入载荷）
    pub fn serialize(&self) -> String {
        // self 结构不含非可序列化成员，序列化不可能失败；unwrap 语义上等价于
        // "违反不变量"（Rust 专家规范：expect 信息说明被违反的不变量）
        serde_json::to_string(self).expect("ChunkSession 序列化不变量被违反：含非可序列化成员")
    }
}

/// 校验 session_id 形态（UUID，防路径穿越/键注入）
pub fn validate_session_id(session_id: &str) -> Result<(), AppError> {
    let ok = !session_id.is_empty()
        && session_id.len() == 36
        && session_id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-');
    if ok {
        Ok(())
    } else {
        Err(AppError::bad_request(&crate::tr!(
            "error.common_handler.chunk_session_invalid"
        )))
    }
}

/// 分片暂存目录：`{upload_root}/__chunks/{tid}/{sid}/`
///
/// `__chunks` 双下划线前缀与业务目录（file/avatar）隔离；租户维度二级隔离。
/// 返回 abs 路径（不存在则由调用方在写分片时 create_dir_all）。
pub fn chunk_dir(upload_root: &std::path::Path, tenant_id: i64, session_id: &str) -> PathBuf {
    upload_root
        .join("__chunks")
        .join(tenant_id.to_string())
        .join(session_id)
}

/// 分片文件名（索引零填充定宽，字典序 = 数值序，便于目录巡检与排序清理）
pub fn part_file_name(index: u32) -> String {
    format!("{index:08}.part")
}

/// init 校验：扩展名白名单 + 危险拒绝 + 总大小上限 + 分片大小与 body limit 相容
///
/// 与 [`crate::common::upload::save_upload_bytes`] 的校验口径一致（同一套
/// `DANGEROUS_EXTS` / allowed_exts）——init 早失败优于 complete 晚失败。
pub fn validate_init(
    file_name: &str,
    total_parts: u32,
    total_size: u64,
    part_size_hint: u64,
    body_limit: usize,
    cfg: &UploadConfig,
) -> Result<String, AppError> {
    use crate::common::upload::DANGEROUS_EXTS;

    let ext = file_name
        .rsplit('.')
        .next()
        .map(|e| e.to_lowercase())
        .filter(|e| !e.is_empty() && *e != file_name.to_lowercase())
        .ok_or_else(|| {
            AppError::bad_request(&crate::tr!("error.common_handler.file_ext_unknown"))
        })?;
    if DANGEROUS_EXTS.contains(&ext.as_str()) {
        tracing::warn!(ext = %ext, "分片上传拒绝危险扩展名（静态托管 XSS/执行风险）");
        return Err(AppError::bad_request(&crate::tr!(
            "error.file.unsupported_type",
            ext = ext
        )));
    }
    let allowed = cfg
        .common_allowed_exts
        .iter()
        .any(|a| a.eq_ignore_ascii_case(&ext));
    if !allowed {
        return Err(AppError::bad_request(&crate::tr!(
            "error.file.unsupported_type",
            ext = ext
        )));
    }

    let max_total = cfg.common_chunk_max_total_size as u64;
    if total_size == 0 || total_size > max_total {
        return Err(AppError::bad_request(&crate::tr!(
            "error.common_handler.chunk_total_too_large",
            max = max_total / 1024 / 1024
        )));
    }
    if total_parts == 0 || total_parts > 10_000 {
        return Err(AppError::bad_request(&crate::tr!(
            "error.common_handler.chunk_parts_invalid"
        )));
    }
    // 分片大小必须 ≤ 请求体上限（否则单个分片本身会被 body limit 拦截）
    let expected_part = total_size.div_ceil(total_parts as u64);
    if expected_part > body_limit as u64 {
        return Err(AppError::bad_request(&crate::tr!(
            "error.common_handler.chunk_part_too_large",
            limit = body_limit / 1024 / 1024
        )));
    }
    // part_size_hint 由客户端声明（辅助校验一致性），与服务端推导偏差 >1 片即拒绝
    if part_size_hint > 0
        && part_size_hint.saturating_mul(total_parts as u64)
            < total_size.saturating_sub(part_size_hint)
    {
        return Err(AppError::bad_request(&crate::tr!(
            "error.common_handler.chunk_parts_invalid"
        )));
    }
    Ok(ext)
}

/// merge 纯逻辑：按索引序读分片文件拼接为完整字节
///
/// 内存语义：总上限（默认 64MB）× 并发许可（2）为进程内存峰值上界；
/// 超上限的流式校验重构另行立项（见模块注释）。
pub async fn merge_parts(
    dir: &std::path::Path,
    session: &ChunkSession,
) -> Result<Vec<u8>, AppError> {
    if session.received.len() != session.total_parts as usize {
        return Err(AppError::bad_request(&crate::tr!(
            "error.common_handler.chunk_parts_missing",
            received = session.received.len(),
            total = session.total_parts
        )));
    }
    let mut parts: Vec<u8> = Vec::new();
    for idx in 0..session.total_parts {
        let path = dir.join(part_file_name(idx));
        let bytes = tokio::fs::read(&path).await.map_err(|_| {
            AppError::bad_request(&crate::tr!(
                "error.common_handler.chunk_part_missing",
                index = idx
            ))
        })?;
        parts.extend_from_slice(&bytes);
    }
    Ok(parts)
}

/// 删除会话的全部暂存分片（complete 成功 / abort / 测试清理共用）
pub async fn cleanup_chunk_dir(dir: &std::path::Path) {
    if let Err(e) = tokio::fs::remove_dir_all(dir).await {
        // 目录不存在（已清理）视为成功；其它错误仅日志（清理失败不阻断主流程）
        if e.kind() != std::io::ErrorKind::NotFound {
            tracing::warn!("分片暂存目录清理失败（孤儿文件将由定时任务兜底）: {e}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_cfg() -> UploadConfig {
        crate::config::UploadConfig {
            backend: "local".to_string(),
            avatar_dir: "avatar".to_string(),
            avatar_url_prefix: "/uploads/avatar".to_string(),
            avatar_allowed_exts: vec!["png".to_string()],
            avatar_max_size: 1_000_000,
            common_dir: "file".to_string(),
            common_url_prefix: "/uploads/file".to_string(),
            common_allowed_exts: vec!["png".to_string(), "zip".to_string(), "pdf".to_string()],
            common_max_size: 10 * 1024 * 1024,
            common_chunk_max_total_size: 64 * 1024 * 1024,
            chunk_session_ttl_secs: 7200,
            s3: Default::default(),
        }
    }

    #[test]
    fn test_validate_init_happy_path() {
        let cfg = base_cfg();
        let ext = validate_init(
            "photo.zip",
            4,
            10 * 1024 * 1024,
            3 * 1024 * 1024,
            10 * 1024 * 1024,
            &cfg,
        )
        .unwrap();
        assert_eq!(ext, "zip");
    }

    #[test]
    fn test_validate_init_rejects_dangerous_and_unlisted() {
        let cfg = base_cfg();
        assert!(validate_init("evil.html", 1, 100, 0, 10 * 1024 * 1024, &cfg).is_err());
        assert!(validate_init("evil.exe", 1, 100, 0, 10 * 1024 * 1024, &cfg).is_err());
        assert!(validate_init("no_ext_allowed.txt", 1, 100, 0, 10 * 1024 * 1024, &cfg).is_err());
    }

    #[test]
    fn test_validate_init_rejects_oversize_and_parts() {
        let cfg = base_cfg();
        // 总超限（> 64MB）
        assert!(validate_init("big.zip", 8, 65 * 1024 * 1024, 0, 10 * 1024 * 1024, &cfg).is_err());
        // 零分片 / 超分片数
        assert!(validate_init("a.zip", 0, 100, 0, 10 * 1024 * 1024, &cfg).is_err());
        assert!(validate_init("a.zip", 10_001, 100, 0, 10 * 1024 * 1024, &cfg).is_err());
        // 单片推导大小 > body limit（8 片 × 9MB 总 65MB 场景已被上一条拦截；
        // 此处构造总大小合法但片数过少导致单片超限）
        assert!(validate_init("a.zip", 1, 20 * 1024 * 1024, 0, 10 * 1024 * 1024, &cfg).is_err());
    }

    #[test]
    fn test_session_id_validation() {
        assert!(validate_session_id("550e8400-e29b-41d4-a716-446655440000").is_ok());
        // 路径穿越 / 键注入 / 错误长度
        assert!(validate_session_id("../../etc").is_err());
        assert!(validate_session_id("").is_err());
        assert!(validate_session_id("short").is_err());
        assert!(validate_session_id("550e8400-e29b-41d4-a716-44665544000!").is_err());
    }

    #[test]
    fn test_part_file_name_zero_padded() {
        assert_eq!(part_file_name(0), "00000000.part");
        assert_eq!(part_file_name(12345), "00012345.part");
        // 字典序 = 数值序
        assert!(part_file_name(9) < part_file_name(10));
    }

    #[test]
    fn test_session_roundtrip_and_store_key() {
        let mut s = ChunkSession {
            file_name: "a.zip".to_string(),
            ext: "zip".to_string(),
            total_parts: 3,
            received: BTreeSet::from([2, 0]),
            tenant_id: 5,
        };
        let raw = s.serialize();
        let parsed = ChunkSession::parse(&raw).unwrap();
        assert_eq!(parsed.received, BTreeSet::from([0, 2]));
        assert_eq!(parsed.tenant_id, 5);
        // 键含租户维度
        assert_eq!(ChunkSession::store_key(5, "abc"), "upload_session:5:abc");
        // 损坏数据 parse 返回 Err（不 panic）
        assert!(ChunkSession::parse("not-json").is_err());
        s.received.insert(1);
        assert_eq!(s.received.len(), 3);
    }

    #[tokio::test]
    async fn test_merge_parts_order_and_missing() {
        let tmp = std::env::temp_dir().join(format!("it_chunk_{}", uuid::Uuid::new_v4()));
        tokio::fs::create_dir_all(&tmp).await.unwrap();
        let session = ChunkSession {
            file_name: "a.bin".to_string(),
            ext: "bin".to_string(),
            total_parts: 3,
            received: BTreeSet::from([0, 1, 2]),
            tenant_id: 0,
        };
        for (idx, content) in [(0u32, b"AAA".as_slice()), (1, b"BBB"), (2, b"CC")] {
            tokio::fs::write(tmp.join(part_file_name(idx)), content)
                .await
                .unwrap();
        }
        let merged = merge_parts(&tmp, &session).await.unwrap();
        assert_eq!(merged, b"AAABBBCC");

        // 缺片：received 声称 3 片但磁盘缺 1 片 → Err
        tokio::fs::remove_file(tmp.join(part_file_name(1)))
            .await
            .unwrap();
        assert!(merge_parts(&tmp, &session).await.is_err());

        // received 数不足 → Err（快失败，不读盘）
        let partial = ChunkSession {
            received: BTreeSet::from([0]),
            ..session
        };
        assert!(merge_parts(&tmp, &partial).await.is_err());

        let _ = tokio::fs::remove_dir_all(&tmp).await;
    }

    #[tokio::test]
    async fn test_cleanup_chunk_dir_idempotent() {
        let tmp = std::env::temp_dir().join(format!("it_chunk_{}", uuid::Uuid::new_v4()));
        tokio::fs::create_dir_all(&tmp).await.unwrap();
        cleanup_chunk_dir(&tmp).await;
        // 二次清理（目录已不存在）静默成功
        cleanup_chunk_dir(&tmp).await;
    }
}
