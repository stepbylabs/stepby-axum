//! Redis 通用工具函数
//!
//! H-1：将原 `handler::monitor_cache_handler::scan_keys` 的等价能力下沉到 utils 层，
//! 供 Service 层（如 AuthService::logout）调用，避免 Service 反向依赖 Handler 层
//! （架构违规：Handler 应依赖 Service，反之不允许）。
//!
//! handler 层的原 `scan_keys` 保留不变，其他 handler 调用方（monitor_cache_handler /
//! monitor_online_handler / common_handler）无需改动。

use crate::common::error::ServiceError;

/// 使用 SCAN 游标迭代匹配键（避免 KEYS 阻塞 Redis）
///
/// 与 `handler::monitor_cache_handler::scan_keys` 行为一致，但返回 `ServiceError`
/// 以适配 Service 层错误类型。SCAN COUNT=100 在万级 key 下通常 2-3 次往返完成，
/// 不会显著阻塞 Redis 主线程。
///
/// # 参数
/// - `redis`: Redis 连接管理器（可变引用，因 SCAN 需要保持游标状态）
/// - `pattern`: Redis SCAN MATCH 模式（如 `user_sessions:1:*`）
///
/// # 错误
/// - Redis 命令失败：返回 `ServiceError::internal`（500），详情写 tracing 日志
///
/// # 用法
/// ```ignore
/// let keys = crate::utils::redis::scan_keys(redis, "user_sessions:1:*").await?;
/// ```
pub async fn scan_keys(
    redis: &mut redis::aio::ConnectionManager,
    pattern: &str,
    max_results: usize,
) -> Result<Vec<String>, ServiceError> {
    let mut keys = Vec::new();
    let mut cursor: u64 = 0;
    loop {
        let (next_cursor, batch): (u64, Vec<String>) = redis::cmd("SCAN")
            .arg(cursor)
            .arg("MATCH")
            .arg(pattern)
            .arg("COUNT")
            .arg(100)
            .query_async(redis)
            .await
            .map_err(|e| {
                tracing::error!("执行 Redis SCAN 失败: {}", e);
                ServiceError::internal(&crate::tr!("error.common.cache_failed"))
            })?;
        keys.extend(batch);
        // P2：结果上限保护（防 `*` 等 pattern 匹配海量 key 导致内存 OOM）
        if keys.len() >= max_results {
            tracing::warn!(
                "scan_keys 达到上限 {}（pattern={}），提前停止扫描",
                max_results,
                pattern
            );
            keys.truncate(max_results);
            break;
        }
        if next_cursor == 0 {
            break;
        }
        cursor = next_cursor;
    }
    Ok(keys)
}
