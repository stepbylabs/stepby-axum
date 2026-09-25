// axum-backend/src/middleware/rate_limit.rs
//
// P0-59（备份方案）：全局限流中间件
//
// 实现：per-(租户, IP) 令牌桶（Token Bucket）
// - 每个「租户 + IP」组合维护一个独立令牌桶（租户彼此隔离，互不占用配额）
// - 桶容量（capacity）：突发请求上限
// - 补充速率（refill_per_second）：每秒匀速补充令牌
// - 内存态（Mutex<HashMap>），单实例有效；多实例部署请改用 Redis 实现
// - 未登录 / 无 claims 请求（登录页、公开页）回退到平台维度（tid=0），确保可用
//
// 多租户（Phase 3）说明：
// - 维度键形如 `rate_limit:{tid}:{ip}`，与既有 Redis key 命名风格（`rate_limit:config:{route}`）一致；
//   迁移到 Redis 实现时可直接沿用该 key 布局，无需再造命名。
// - tid 取自 auth 中间件注入的 `Claims.tid`（中间件链中 auth 先于 rate_limit 执行）；
//   `Claims.tid = 0` 表示平台租户维度，同时承担「无 claims 兜底」语义。
// - 配额（capacity / refill_per_second）仍来自平台级 `sys_rate_limit` 表（按请求路径匹配，
//   未命中回退 `*`），即「租户隔离计数 + 平台统一配额」。
//
// M-1 双重限流说明：本中间件与 auth_service.rs 内的 Redis 限流（RATE_LIMIT_SCRIPT）
// 同时生效，构成两层防护：
// - 本中间件（内存令牌桶）：粗粒度防护，单实例下快速拦截突发流量，无 Redis 往返开销
// - auth_service Redis 限流：精确计数（同 IP 1 分钟 ≤20 次登录尝试），多实例兼容
// 两者职责不同，不冲突：本中间件按桶容量+补充速率平滑限流，Redis 版按窗口计数硬性拦截。
// 维护者修改任一层时需注意保持另一层语义不变。
//
// M-8 多实例限制：本限流器为内存态（Mutex<HashMap>），仅支持单实例部署。
// 多实例部署时，各实例独立计数，攻击者可通过轮询不同实例绕过限流。
// 多实例场景请迁移到 Redis 实现（参考 auth_service.rs 的 RATE_LIMIT_SCRIPT Lua 脚本），
// 或在反向代理层（Nginx/Ingress）做限流。
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
use std::net::SocketAddr;
use std::sync::{Arc, LazyLock, Mutex};
use std::time::{Duration, Instant};

use axum::Json;
use axum::extract::{ConnectInfo, Request, State};
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};

use crate::state::AppState;
use crate::utils::ip::extract_client_ip;

/// 令牌桶配置
#[derive(Clone, Copy, Debug)]
pub struct RateLimitConfig {
    /// 桶容量（最大突发请求数）
    pub capacity: u32,
    /// 每秒补充令牌数
    pub refill_per_second: f64,
}

/// 构造限流维度键：`rate_limit:{tid}:{ip}`
///
/// - `tid` 为请求者租户（取自 `Claims.tid`）；无 claims 时传 `0`（平台维度兜底）
/// - 命名与既有 Redis key 风格（`rate_limit:config:{route}`）保持一致，
///   便于后续迁移到 Redis 计数实现时沿用同一 key 布局
pub fn rate_limit_bucket_key(tenant_id: i64, ip: &str) -> String {
    format!("rate_limit:{tenant_id}:{ip}")
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
        self.try_acquire_with_retry_after(key, config).0
    }

    /// 尝试消费 1 个令牌，并返回 429 时的建议 Retry-After 秒数
    ///
    /// 返回 (是否放行, Retry-After 秒数)。
    /// Retry-After 仅在限流时有意义，放行时为 0。
    pub fn try_acquire_with_retry_after(&self, key: &str, config: RateLimitConfig) -> (bool, u64) {
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
            (true, 0)
        } else {
            // 计算恢复所需秒数：还需补充 (1.0 - tokens) 个令牌
            // 时间 = 令牌数 / 补充速率
            let retry_after = if config.refill_per_second > 0.0 {
                let needed = 1.0 - bucket.tokens;
                let secs = needed / config.refill_per_second;
                // 向上取整，最少 1 秒
                (secs.ceil() as u64).max(1)
            } else {
                // 补充速率为 0 时，给一个默认值
                60
            };
            (false, retry_after)
        }
    }

    // M-3：原 cleanup() 方法已删除（dead code）。
    // 惰性清理已在 try_acquire 中实现：HashMap 大小超过 CLEANUP_THRESHOLD 时，
    // 清理超过 MAX_IDLE_SECS 未访问的桶，无需外部调用 cleanup()。
}

/// 全局限流器单例
static RATE_LIMITER: LazyLock<RateLimiter> = LazyLock::new(RateLimiter::new);

/// 全局限流中间件
///
/// 流程：
/// 1. 从请求扩展中提取 ConnectInfo<SocketAddr>，获取客户端 IP
/// 2. 复用 auth_handler::extract_client_ip 的可信代理白名单逻辑提取真实客户端 IP
///    （trusted_proxies 为空时仅信任直连 IP，不信任 XFF，防止伪造绕过限流）
/// 3. 从请求扩展中提取 `Claims.tid` 作为租户维度（无 claims → 0，平台维度兜底）
/// 4. 从数据库读取限流配置（带 Redis 缓存，5 分钟过期），失败时 fail-closed 返回 503
/// 5. 调用令牌桶 try_acquire（键为 `rate_limit:{tid}:{ip}`），放行或返回 429
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

    // 租户维度：auth 中间件（route_layer 中先于本中间件执行）已注入 Claims；
    // 公开端点（/login、/captchaImage 等）无 claims，回退到平台维度 0，保证可用
    let tenant_id = req
        .extensions()
        .get::<crate::jwt::Claims>()
        .map(|c| c.tid)
        .unwrap_or(0);
    let bucket_key = rate_limit_bucket_key(tenant_id, &ip);

    // 从数据库读取限流配置（带 Redis 缓存）
    // 查询逻辑：先精确匹配 route_pattern=oper_url，未命中则使用 "*" 全局默认
    // 安全（P0-11）：fail-closed，Redis/DB 故障时返回 503 而非静默降级到 DEFAULT_CONFIG，
    // 避免限流配置丢失导致限流被绕过。
    let oper_url = req.uri().path().to_string();
    let config = match state
        .rate_limit_service
        .get_config_for_route(&oper_url)
        .await
    {
        Ok(c) => c,
        Err(e) => {
            tracing::error!("限流配置查询失败（fail-closed）: {}", e);
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(serde_json::json!({
                    "code": 503,
                    "msg": crate::tr!("error.rate_limit.service_unavailable")
                })),
            )
                .into_response();
        }
    };

    let (allowed, retry_after) = RATE_LIMITER.try_acquire_with_retry_after(&bucket_key, config);
    if allowed {
        next.run(req).await
    } else {
        // 429 响应包含 Retry-After 头（RFC 6585 / RFC 7231），告知客户端何时可重试
        let mut resp = (
            StatusCode::TOO_MANY_REQUESTS,
            Json(serde_json::json!({
                "code": 429,
                "msg": crate::tr!("error.rate_limit.too_many_requests")
            })),
        )
            .into_response();
        let headers = resp.headers_mut();
        // Retry-After 头：以秒为单位，告知客户端需等待多久才能再次发送请求
        if let Ok(val) = axum::http::HeaderValue::from_str(&retry_after.to_string()) {
            headers.insert(axum::http::header::RETRY_AFTER, val);
        }
        resp
    }
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

    #[test]
    fn test_try_acquire_with_retry_after_reports_wait_seconds() {
        // 容量 1、慢补充（0.5/s）：用尽后下一次应被拒，并返回合理的 Retry-After
        let limiter = RateLimiter::new();
        let config = RateLimitConfig {
            capacity: 1,
            refill_per_second: 0.5,
        };
        let (allowed, retry_after) = limiter.try_acquire_with_retry_after("9.9.9.9", config);
        assert!(allowed, "首次请求应放行");
        assert_eq!(retry_after, 0);

        let (allowed2, retry_after2) = limiter.try_acquire_with_retry_after("9.9.9.9", config);
        assert!(!allowed2, "桶空后必须拒绝");
        // 还需补充 1.0 个令牌 / 0.5 每秒 = 2 秒（向上取整，至少 1 秒）
        assert_eq!(retry_after2, 2, "Retry-After 应反映恢复所需秒数");
    }

    #[test]
    fn test_try_acquire_with_retry_after_zero_refill_defaults_to_60() {
        // 补充速率为 0 时无法恢复，应给出默认 60s（而非除零 panic）
        let limiter = RateLimiter::new();
        let config = RateLimitConfig {
            capacity: 1,
            refill_per_second: 0.0,
        };
        let (allowed, _) = limiter.try_acquire_with_retry_after("8.8.8.8", config);
        assert!(allowed);
        let (denied, retry_after) = limiter.try_acquire_with_retry_after("8.8.8.8", config);
        assert!(!denied);
        assert_eq!(retry_after, 60, "补充速率为 0 时应回退到默认 60s");
    }

    // ---------- 多租户维度（Phase 3） ----------

    #[test]
    fn test_rate_limit_bucket_key_shape() {
        // 命名与既有 Redis key 风格一致：rate_limit:{tid}:{ip}
        assert_eq!(rate_limit_bucket_key(0, "1.2.3.4"), "rate_limit:0:1.2.3.4");
        assert_eq!(
            rate_limit_bucket_key(42, "10.0.0.9"),
            "rate_limit:42:10.0.0.9"
        );
    }

    #[test]
    fn test_token_bucket_isolates_tenants() {
        // 同一 IP、不同租户必须各自独立计数（租户 A 用尽不影响租户 B）
        let limiter = RateLimiter::new();
        let config = RateLimitConfig {
            capacity: 1,
            refill_per_second: 0.0,
        };
        let ip = "10.1.1.1";
        let (tid_a, tid_b) = (5, 6);

        assert!(limiter.try_acquire(&rate_limit_bucket_key(tid_a, ip), config));
        assert!(
            !limiter.try_acquire(&rate_limit_bucket_key(tid_a, ip), config),
            "同租户同 IP 第二次应被限流"
        );
        assert!(
            limiter.try_acquire(&rate_limit_bucket_key(tid_b, ip), config),
            "不同租户同 IP 应独立计数，仍可放行"
        );
        // 平台维度（无 claims 兜底，tid=0）同样独立
        assert!(limiter.try_acquire(&rate_limit_bucket_key(0, ip), config));
    }
}
