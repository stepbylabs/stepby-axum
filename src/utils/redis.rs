//! Redis 通用工具函数
//!
//! H-1：将原 `handler::monitor_cache_handler::scan_keys` 的等价能力下沉到 utils 层，
//! 供 Service 层（如 AuthService::logout）调用，避免 Service 反向依赖 Handler 层
//! （架构违规：Handler 应依赖 Service，反之不允许）。
//!
//! handler 层与 Service 层共用本模块：`scan_keys`（**有上限**，用于只读展示/列表，上限即
//! 响应体量与 OOM 保护）与 `scan_keys_all`（**不截断**，用于"语义要求全量"的变更型扫描，
//! 见其文档）。第九批曾出现"变更型扫描误用有上限版 ⇒ 静默漏清"的真实缺陷，改动此类调用
//! 前请先确认语义是"全部"还是"取前 N 条"。

use crate::common::error::ServiceError;

/// 以统一命令超时包裹任意 Redis 异步命令（R8-CONC-013 收口）。
///
/// 背景：`db::redis` 只对**建连**与启动期 **PING** 加了超时护栏，而历史上大量
/// 调用点直接 `redis::cmd(..).query_async(&mut conn).await`。Redis 网络抖动或
/// 慢命令时这些 await **没有上界**，会把请求（含登录、缓存监控、在线用户列表等
/// 主链路）挂死，等于把一次 Redis 抖动放大成服务不可用。
///
/// 本函数把「超时」统一转换为 `RedisError`，因此调用方**原有的 `map_err` /
/// 降级分支无需改动**即可获得超时保护（超时走的就是原来的错误路径）。
///
/// 用法：
/// ```ignore
/// let v: Option<String> = cmd_timeout(redis::cmd("GET").arg(k).query_async(&mut conn)).await?;
/// ```
pub async fn cmd_timeout<F, T>(fut: F) -> Result<T, redis::RedisError>
where
    F: std::future::Future<Output = Result<T, redis::RedisError>>,
{
    let secs = crate::db::redis::redis_cmd_timeout_secs();
    match tokio::time::timeout(std::time::Duration::from_secs(secs), fut).await {
        Ok(res) => res,
        Err(_) => Err(redis::RedisError::from((
            redis::ErrorKind::Io,
            "redis command timeout",
            format!("Redis 命令超过 {secs}s 未返回"),
        ))),
    }
}

/// 分批删除（`DEL`）时的单条命令 key 数上限（第九批）。
///
/// 动机：`scan_keys_all` 不截断 ⇒ 命中键数**无上界**，若把全部 key 塞进一条 `DEL`
/// 会长时间占用 Redis 单线程（大 key 数命令是阻塞型），逐键 `DEL` 又退化为 O(n) 往返。
/// 取 500 作折中：往返数为 `ceil(n/500)`，单命令耗时可控。
pub const DEL_BATCH_SIZE: usize = 500;

/// 使用 SCAN 游标迭代匹配键（避免 KEYS 阻塞 Redis）
///
/// ⚠️ **`max_results` 是硬上限**：达到即 `truncate` 并只打一条 `warn`（**静默截断**）。
/// 因此本函数**只适用于"取前 N 条"语义**（只读展示 / 列表 / 监控）；
/// 凡语义为"处理**全部**匹配键"的**变更型**扫描（吊销 / 清除 / 重置），
/// **必须**改用 [`scan_keys_all`]，否则会静默漏处理剩余键（第九批真实缺陷）。
///
/// 返回 `ServiceError` 以适配 Service 层错误类型。SCAN COUNT=100 在万级 key 下
/// 通常 2-3 次往返完成，不会显著阻塞 Redis 主线程。
///
/// # 参数
/// - `redis`: Redis 连接管理器（可变引用，因 SCAN 需要保持游标状态）
/// - `pattern`: Redis SCAN MATCH 模式（如 `user_sessions:1:*`）
/// - `max_results`: 结果**硬上限**（截断，见上）
///
/// # 错误
/// - Redis 命令失败：返回 `ServiceError::internal`（500），详情写 tracing 日志
///
/// # 用法
/// ```ignore
/// let keys = crate::utils::redis::scan_keys(redis, "user_sessions:1:*", 5000).await?;
/// ```
pub async fn scan_keys(
    redis: &mut redis::aio::ConnectionManager,
    pattern: &str,
    max_results: usize,
) -> Result<Vec<String>, ServiceError> {
    scan_keys_inner(redis, pattern, Some(max_results)).await
}

/// **不截断**版 SCAN：用于「必须完整」的场景。
///
/// ⚠️ 为何需要它（第九批修复的真实缺陷）：`scan_keys` 的 `max_results` 是**硬上限**，
/// 达到即 `truncate` 并只打一条 `warn` —— 属**静默截断**。用于**安全吊销**时后果严重：
/// 若某租户的 RT / 在线会话超过上限，`revoke_tenant_sessions` 会**漏清剩余凭证**，
/// 停用租户后仍可用未清除的 RT 续期身份（正是 P0-1 要堵的口子）。
/// 故吊销类调用必须走本函数「扫到游标归零」。
///
/// 约定：调用方必须给出**足够具体**的 pattern（如 `sso:rt:*` / `online:*`），
/// 禁止 `*`（那会把整库 key 收进内存）；本函数不为内存做上限保护，正确性优先。
pub async fn scan_keys_all(
    redis: &mut redis::aio::ConnectionManager,
    pattern: &str,
) -> Result<Vec<String>, ServiceError> {
    scan_keys_inner(redis, pattern, None).await
}

/// SCAN 共用实现：`max_results = None` → 扫到游标归零（不截断）
async fn scan_keys_inner(
    redis: &mut redis::aio::ConnectionManager,
    pattern: &str,
    max_results: Option<usize>,
) -> Result<Vec<String>, ServiceError> {
    let mut keys = Vec::new();
    let mut cursor: u64 = 0;
    loop {
        let (next_cursor, batch): (u64, Vec<String>) = cmd_timeout(
            redis::cmd("SCAN")
                .arg(cursor)
                .arg("MATCH")
                .arg(pattern)
                .arg("COUNT")
                .arg(100)
                .query_async(redis),
        )
        .await
        .map_err(|e| {
            tracing::error!("执行 Redis SCAN 失败: {}", e);
            ServiceError::internal(&crate::tr!("error.common.cache_failed"))
        })?;
        keys.extend(batch);
        // P2：结果上限保护（防 `*` 等 pattern 匹配海量 key 导致内存 OOM）
        // 仅对显式传入上限的调用生效；不截断路径（安全吊销）不适用本保护。
        if let Some(max) = max_results
            && keys.len() >= max
        {
            tracing::warn!(
                "scan_keys 达到上限 {}（pattern={}），提前停止扫描",
                max,
                pattern
            );
            keys.truncate(max);
            break;
        }
        if next_cursor == 0 {
            break;
        }
        cursor = next_cursor;
    }
    Ok(keys)
}
