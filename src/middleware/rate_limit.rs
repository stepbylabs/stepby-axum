// axum-backend/src/middleware/rate_limit.rs
//
// P0-59（备份方案）：全局限流中间件
//
// 实现：per-IP 令牌桶（Token Bucket）
// - 每个 IP 维护一个独立令牌桶
// - 桶容量（capacity）：突发请求上限
// - 补充速率（refill_per_second）：每秒匀速补充令牌
// - 内存态（Mutex<HashMap>），单实例有效；多实例部署请改用 Redis 实现
//
// ⚠️ 警告：本限流器为内存态（Mutex<HashMap>），仅适用单实例部署。
// 多实例部署时，业务接口限流将按实例独立计数，可能被绕过。
// 多实例场景请改用 Redis 滑动窗口实现（参考 auth_service.rs 的 RATE_LIMIT_SCRIPT）。
//
// 用法：
//   use axum::middleware::from_fn;
//   use crate::middleware::rate_limit::rate_limit_middleware;
//
//   let app = Router::new()
//       .route_layer(from_fn(rate_limit_middleware));
//
// 注意：此中间件已挂载到公开认证端点（/login、/register、/captchaImage），
// 见 router/auth_router.rs::public_auth_routes。其他敏感写操作（改密等）由业务层 Redis 限流兜底。
// 如需扩展覆盖范围，在 router/mod.rs 中通过 from_fn_with_state 挂载到目标路由分组。

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, LazyLock, Mutex};
use std::time::{Duration, Instant};

use axum::extract::{ConnectInfo, Request, State};
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};

use crate::utils::ip::extract_client_ip;
use crate::state::AppState;

/// 令牌桶配置
#[derive(Clone, Copy, Debug)]
pub struct RateLimitConfig {
    /// 桶容量（最大突发请求数）
    pub capacity: u32,
    /// 每秒补充令牌数
    pub refill_per_second: f64,
}

impl Default for RateLimitConfig {
    /// 默认：100 个突发请求，每秒补充 10 个
    fn default() -> Self {
        Self {
            capacity: 100,
            refill_per_second: 10.0,
        }
    }
}

/// 单个 IP 的令牌桶
struct TokenBucket {
    tokens: f64,
    last_refill: Instant,
}

/// 全局限流器（per-IP 令牌桶）
///
/// 使用 LazyLock 实现 once-only 初始化，所有请求共享同一实例。
pub struct RateLimiter {
    buckets: Mutex<HashMap<String, TokenBucket>>,
}

impl RateLimiter {
    fn new() -> Self {
        Self {
            buckets: Mutex::new(HashMap::new()),
        }
    }

    /// 尝试消费 1 个令牌
    ///
    /// 返回 true 表示放行，false 表示限流。
    /// 内部按时间差补充令牌（懒补充模式）。
    pub fn try_acquire(&self, key: &str, config: RateLimitConfig) -> bool {
        let now = Instant::now();
        // Mutex 中毒时恢复 Guard 而非 panic，遵循项目约定（P0-New-3）
        let mut buckets = self.buckets.lock().unwrap_or_else(|e| e.into_inner());

        // P0-5 改进：惰性清理，HashMap 大小超过阈值时，清理超过 30 分钟未访问的桶
        // 防止恶意 IP 扫描导致 HashMap 无界增长（替代之前的占位 cleanup）
        const CLEANUP_THRESHOLD: usize = 10000;
        const MAX_IDLE_SECS: u64 = 1800; // 30 分钟
        if buckets.len() > CLEANUP_THRESHOLD {
            let idle_threshold = Duration::from_secs(MAX_IDLE_SECS);
            buckets.retain(|_, bucket| now.duration_since(bucket.last_refill) <= idle_threshold);
        }

        let bucket = buckets.entry(key.to_string()).or_insert(TokenBucket {
            tokens: config.capacity as f64,
            last_refill: now,
        });

        // 按时间差补充令牌
        let elapsed = now.duration_since(bucket.last_refill);
        let refill = elapsed.as_secs_f64() * config.refill_per_second;
        bucket.tokens = (bucket.tokens + refill).min(config.capacity as f64);
        bucket.last_refill = now;

        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    /// 清理长时间未访问的桶（防止内存无界增长）（P0-5 改进）
    ///
    /// 遍历所有桶，移除 `last_refill` 超过 `max_idle_secs` 未访问的桶。
    /// 可在后台任务中定期调用，或由 `try_acquire` 的惰性清理触发。
    pub fn cleanup(&self, max_idle_secs: u64) {
        let now = Instant::now();
        let threshold = Duration::from_secs(max_idle_secs);
        // Mutex 中毒时恢复 Guard 而非 panic，遵循项目约定（P0-New-3）
        let mut buckets = self.buckets.lock().unwrap_or_else(|e| e.into_inner());
        buckets.retain(|_, bucket| now.duration_since(bucket.last_refill) <= threshold);
    }
}

/// 全局限流器单例
static RATE_LIMITER: LazyLock<RateLimiter> = LazyLock::new(RateLimiter::new);

/// 默认限流配置（可按需调整）
///
/// P0-11 后中间件改为 fail-closed，不再回退到此默认值；
/// 保留作为文档参考与其他调用方（如非 HTTP 场景 acquire）的默认参数。
#[allow(dead_code)]
const DEFAULT_CONFIG: RateLimitConfig = RateLimitConfig {
    capacity: 100,
    refill_per_second: 10.0,
};

/// 全局限流中间件
///
/// 流程：
/// 1. 从请求扩展中提取 ConnectInfo<SocketAddr>，获取客户端 IP
/// 2. 复用 auth_handler::extract_client_ip 的可信代理白名单逻辑提取真实客户端 IP
///    （trusted_proxies 为空时仅信任直连 IP，不信任 XFF，防止伪造绕过限流）
/// 3. 从数据库读取限流配置（带 Redis 缓存，5 分钟过期），失败时 fail-closed 返回 503
/// 4. 调用令牌桶 try_acquire，放行或返回 429
pub async fn rate_limit_middleware(
    State(state): State<Arc<AppState>>,
    req: Request,
    next: Next,
) -> Response {
    // 复用 utils::ip::extract_client_ip 的可信代理白名单逻辑提取真实客户端 IP
    // （trusted_proxies 为空时仅信任直连 IP，不信任 XFF，防止伪造绕过限流）
    let peer_ip = req
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ci| ci.0.ip())
        .unwrap_or_else(|| std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED));
    let ip = extract_client_ip(req.headers(), peer_ip, &state.config.server.trusted_proxies);

    // 从数据库读取限流配置（带 Redis 缓存）
    // 查询逻辑：先精确匹配 route_pattern=oper_url，未命中则使用 "*" 全局默认
    // 安全（P0-11）：fail-closed，Redis/DB 故障时返回 503 而非静默降级到 DEFAULT_CONFIG，
    // 避免限流配置丢失导致限流被绕过。
    let oper_url = req.uri().path().to_string();
    let config = match state.rate_limit_service.get_config_for_route(&oper_url).await {
        Ok(c) => c,
        Err(e) => {
            tracing::error!("限流配置查询失败（fail-closed）: {}", e);
            return (StatusCode::SERVICE_UNAVAILABLE, "服务暂时不可用").into_response();
        }
    };

    if RATE_LIMITER.try_acquire(&ip, config) {
        next.run(req).await
    } else {
        (
            StatusCode::TOO_MANY_REQUESTS,
            "请求过于频繁，请稍后再试",
        )
            .into_response()
    }
}

/// 主动消费令牌（用于非 HTTP 场景的限流，如登录接口内部调用）
///
/// 返回 true 表示放行。
#[allow(dead_code)]
pub fn acquire(ip: IpAddr, config: RateLimitConfig) -> bool {
    RATE_LIMITER.try_acquire(&ip.to_string(), config)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_token_bucket_allows_burst() {
        let limiter = RateLimiter::new();
        let config = RateLimitConfig {
            capacity: 5,
            refill_per_second: 1.0,
        };

        // 5 个突发请求应全部放行
        for _ in 0..5 {
            assert!(limiter.try_acquire("1.2.3.4", config));
        }
        // 第 6 个应被拒绝
        assert!(!limiter.try_acquire("1.2.3.4", config));
    }

    #[test]
    fn test_token_bucket_isolates_ips() {
        let limiter = RateLimiter::new();
        let config = RateLimitConfig {
            capacity: 2,
            refill_per_second: 0.0, // 不补充
        };

        // IP A 用完额度
        assert!(limiter.try_acquire("10.0.0.1", config));
        assert!(limiter.try_acquire("10.0.0.1", config));
        assert!(!limiter.try_acquire("10.0.0.1", config));

        // IP B 仍可访问
        assert!(limiter.try_acquire("10.0.0.2", config));
    }

    #[test]
    fn test_token_bucket_refills_over_time() {
        let limiter = RateLimiter::new();
        let config = RateLimitConfig {
            capacity: 1,
            refill_per_second: 1000.0, // 极快补充
        };

        assert!(limiter.try_acquire("1.1.1.1", config));
        // 立即再次请求应失败（瞬时）
        assert!(!limiter.try_acquire("1.1.1.1", config));

        // 等待少量时间后应能再次获取
        std::thread::sleep(std::time::Duration::from_millis(50));
        assert!(limiter.try_acquire("1.1.1.1", config));
    }
}
