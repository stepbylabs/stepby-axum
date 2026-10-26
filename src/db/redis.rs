// stepby-axum/src/db/redis.rs

use std::time::Duration;

use crate::config::RedisConfig;
use redis::aio::{ConnectionManager, ConnectionManagerConfig};

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

/// 连接管理器超时配置（与 `[redis]` 的配置同源）。
///
/// **为什么必须显式设置**：redis-rs 1.7 的 `ConnectionManagerConfig::default()` 把
/// `response_timeout` 定为 **500ms**、`connection_timeout` 定为 1s。不设置时，命令会在
/// 500ms 就被库内部判死并返回 io `timed out`，应用层 `cmd_timeout` 配的 3s（或运维调到的 5s）
/// **永远走不到**——`config.toml` 里"负载尖峰可调高减少 fail-closed 503"这句因此不成立
/// （b94 实测：全量并行测试下登录的 TOTP 状态 GET 偶发 503，日志
/// `共享态后端操作失败: timed out`，隔离单跑恒绿）。这里把两条超时对齐到应用配置：
/// 命令预算 = `cmd_timeout_secs`，建连预算 = `REDIS_CONN_TIMEOUT_SECS`。
fn connection_manager_config(
    response_timeout_secs: u64,
    connection_timeout_secs: u64,
) -> ConnectionManagerConfig {
    ConnectionManagerConfig::new()
        .set_response_timeout(Some(Duration::from_secs(response_timeout_secs)))
        .set_connection_timeout(Some(Duration::from_secs(connection_timeout_secs)))
}

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

    let manager_config =
        connection_manager_config(redis_cmd_timeout_secs(), REDIS_CONN_TIMEOUT_SECS);

    // 连接建立阶段超时护栏（R8-CONC-013 补充）：不可达地址最多等待 REDIS_CONN_TIMEOUT_SECS 秒，
    // 超时即返回错误，避免调用线程无限挂起。
    let mut conn = match tokio::time::timeout(
        Duration::from_secs(REDIS_CONN_TIMEOUT_SECS),
        ConnectionManager::new_with_config(client, manager_config),
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

#[cfg(test)]
mod tests {
    use super::*;

    /// 形状锁：连接管理器的两条超时必须取自应用配置，而不是 redis-rs 的默认值
    /// （500ms / 1s）。否则 `[redis] cmd_timeout_secs` 只能调小不能调大，
    /// 模板里"负载尖峰调高"的语义就是假的。
    #[test]
    fn connection_manager_timeouts_follow_application_config() {
        let cfg = connection_manager_config(5, 7);
        assert_eq!(cfg.response_timeout(), Some(Duration::from_secs(5)));
        assert_eq!(cfg.connection_timeout(), Some(Duration::from_secs(7)));

        // 活性正控：换了入参必须跟着变，防止有人把它写成常量。
        let other = connection_manager_config(2, 9);
        assert_eq!(other.response_timeout(), Some(Duration::from_secs(2)));
        assert_ne!(cfg.response_timeout(), other.response_timeout());
    }

    /// 默认档不得被库的 500ms 悄悄截断：至少与 `REDIS_CONN_TIMEOUT_SECS` 区分开，
    /// 并覆盖配置默认值 3s。
    #[test]
    fn default_command_budget_is_not_the_library_default() {
        let cfg = connection_manager_config(3, REDIS_CONN_TIMEOUT_SECS);
        assert_eq!(cfg.response_timeout(), Some(Duration::from_secs(3)));
        assert_ne!(cfg.response_timeout(), Some(Duration::from_millis(500)));
        assert_eq!(
            cfg.connection_timeout(),
            Some(Duration::from_secs(REDIS_CONN_TIMEOUT_SECS))
        );
    }
}
