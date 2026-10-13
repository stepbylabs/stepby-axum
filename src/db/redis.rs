// stepby-axum/src/db/redis.rs

use std::time::Duration;

use crate::config::RedisConfig;
use redis::aio::ConnectionManager;

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
/// 批三十八：由 `[redis] cmd_timeout_secs` 启动时注入（默认 3 = 本原值，零行为变更）。
/// 全局态理由：该超时被 6 个模块经 `cmd_timeout` 引用，签名级穿透侵入过大；
/// AtomicU64 在启动期一次性写入（无运行期写点），读侧为单次 load，无竞争语义。
pub(crate) static REDIS_CMD_TIMEOUT_SECS: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(3);

/// 启动期注入（仅 initialize 调用一次；防运行期改写导致连接池内超时不一致）。
pub(crate) fn set_redis_cmd_timeout_secs(secs: u64) {
    REDIS_CMD_TIMEOUT_SECS.store(secs, std::sync::atomic::Ordering::Relaxed);
}

/// 读当前命令超时（cmd_timeout 统一消费点）。
pub(crate) fn redis_cmd_timeout_secs() -> u64 {
    REDIS_CMD_TIMEOUT_SECS.load(std::sync::atomic::Ordering::Relaxed)
}

/// Redis 连接建立超时（秒）。
///
/// R8-CONC-013 补充：命令级超时（`REDIS_CMD_TIMEOUT_SECS`）只覆盖已建连后的
/// `query_async`；而 `ConnectionManager::new()` 在初始 TCP/TLS 握手阶段无内置超时，
/// 当 `REDIS_URL` 指向不可达地址时可能长时间挂起（曾导致 `cargo test` 在无 Redis 环境
/// 下静默卡死）。此处对连接建立本身加超时护栏，fail-closed：超时即返回错误，
/// 由调用方降级，绝不让调用线程无限阻塞。
pub(crate) const REDIS_CONN_TIMEOUT_SECS: u64 = 5;

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

    // 连接建立阶段超时护栏（R8-CONC-013 补充）：不可达地址最多等待 REDIS_CONN_TIMEOUT_SECS 秒，
    // 超时即返回错误，避免调用线程无限挂起。
    let mut conn = match tokio::time::timeout(
        Duration::from_secs(REDIS_CONN_TIMEOUT_SECS),
        ConnectionManager::new(client),
    )
    .await
    {
        Ok(Ok(c)) => c,
        Ok(Err(e)) => {
            tracing::error!("Redis 连接失败: {}", e);
            return Err(anyhow::anyhow!(
                "Redis 连接失败，请检查 REDIS_URL 配置与网络"
            ));
        }
        Err(_) => {
            tracing::error!(
                "Redis 连接建立超时（>{}s），请检查 REDIS_URL 配置与网络",
                REDIS_CONN_TIMEOUT_SECS
            );
            return Err(anyhow::anyhow!(
                "Redis 连接超时，请检查 REDIS_URL 配置与网络"
            ));
        }
    };

    // 测试连接（用 tokio::time::timeout 包裹，R8-CONC-013：防止 PING 挂起）
    let pong: String = tokio::time::timeout(
        Duration::from_secs(redis_cmd_timeout_secs()),
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
        redis_cmd_timeout_secs()
    );

    Ok(conn)
}
