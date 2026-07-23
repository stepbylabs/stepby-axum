// axum-backend/src/db/redis.rs

use std::time::Duration;

use redis::aio::ConnectionManager;
use crate::config::RedisConfig;

/// Redis 命令读/写超时（秒）。
///
/// R8-CONC-013：避免 Redis 网络抖动时 auth 请求无限挂起导致服务整体降级。
/// 3 秒覆盖绝大多数正常命令（GET/SET/MGET/Lua 均在 10ms 量级），
/// 超时后由调用方决定降级策略（如 fail-closed 返回 503 或 best-effort 跳过缓存查 DB）。
///
/// 实现说明：
/// `redis::Client` 与 `ConnectionManager`（异步多路复用单连接）均不直接暴露
/// `set_read_timeout` / `set_write_timeout`（这两个方法仅存在于同步 `Connection`）。
/// 异步命令超时通过 `tokio::time::timeout` 包裹 `query_async` 调用实现。
/// 此常量作为调用方包裹超时的统一参数，避免各处硬编码。
pub(crate) const REDIS_CMD_TIMEOUT_SECS: u64 = 3;

/// 初始化 Redis 连接池（ConnectionManager，自动重连）
///
/// 安全：连接失败时详情写 tracing 日志，对外返回通用文案，
/// 避免连接串（可能含密码）经 anyhow 传播到 stderr。
///
/// R8-CONC-013：命令级超时通过 `tokio::time::timeout(REDIS_CMD_TIMEOUT_SECS, ...)` 包裹
/// `query_async` 调用实现（见 auth_middleware / dict_service 等调用点）。
pub async fn init_redis(config: &RedisConfig) -> anyhow::Result<ConnectionManager> {
    let client = redis::Client::open(config.url.as_str()).map_err(|e| {
        tracing::error!("Redis 客户端创建失败: {}", e);
        anyhow::anyhow!("Redis 配置错误，请检查 REDIS_URL")
    })?;

    let mut conn = ConnectionManager::new(client).await.map_err(|e| {
        tracing::error!("Redis 连接失败: {}", e);
        anyhow::anyhow!("Redis 连接失败，请检查 REDIS_URL 配置与网络")
    })?;

    // 测试连接（用 tokio::time::timeout 包裹，R8-CONC-013：防止 PING 挂起）
    let pong: String = tokio::time::timeout(
        Duration::from_secs(REDIS_CMD_TIMEOUT_SECS),
        redis::cmd("PING").query_async(&mut conn),
    )
    .await
    .map_err(|e| {
        tracing::error!("Redis PING 超时或失败: {}", e);
        anyhow::anyhow!("Redis 连接测试失败")
    })?
    .map_err(|e| {
        tracing::error!("Redis PING 测试失败: {}", e);
        anyhow::anyhow!("Redis 连接测试失败")
    })?;
    tracing::info!(
        "Redis 连接成功 (PING -> {}, cmd_timeout={}s)",
        pong,
        REDIS_CMD_TIMEOUT_SECS
    );

    Ok(conn)
}
