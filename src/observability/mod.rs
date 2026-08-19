// axum-backend/src/observability/mod.rs
//! 可观测性（Observability）模块
//!
//! 聚合运营可观测能力，全部为**进程内真实实现**（零新增外部依赖），
//! 通过全局静态共享，供 HTTP 中间件写入、`/monitor/*` handler 与 `/metrics` 输出读取：
//!
//! - [`slow`](slow)：慢请求（及慢 SQL）有界环形缓冲 + 聚合（/monitor/slow-sql/*）
//! - [`error_log`](error_log)：Tracing Layer 采集 ERROR 日志错误总线（/monitor/error-log/*）
//! - [`metrics`](metrics)：轻量 Prometheus 文本指标（HTTP counter + histogram）
//!
//! handler 通过 `state.observability` 或各类 `global()` 访问同一底层实例。

pub mod error_log;
pub mod metrics;
pub mod slow;

use std::sync::{Arc, OnceLock};

use axum::extract::{MatchedPath, Request};
use axum::middleware::Next;
use axum::response::Response;
use std::time::Instant;

/// 应用级可观测性句柄（聚合各子模块的全局实例）
pub struct Observability {
    pub slow: Arc<slow::SlowRequestBus>,
    pub error_log: Arc<error_log::ErrorLogBus>,
    pub metrics: Arc<metrics::MetricsRegistry>,
}

/// 全局可观测性根实例
static GLOBAL: OnceLock<Arc<Observability>> = OnceLock::new();

impl Observability {
    /// 获取全局可观测性句柄
    pub fn global() -> Arc<Self> {
        GLOBAL
            .get_or_init(|| {
                Arc::new(Observability {
                    slow: slow::SlowRequestBus::global(),
                    error_log: error_log::ErrorLogBus::global(),
                    metrics: metrics::MetricsRegistry::global(),
                })
            })
            .clone()
    }
}

/// 全局监控中间件：为每个请求
/// 1. 记录 Prometheus HTTP counter + duration histogram
/// 2. 记录超阈值（默认 300ms）的慢请求到慢请求缓冲
///
/// 作为全局 layer 注册（见 router::build_app），顺序尽量靠内以贴近真实处理耗时，
/// 同时能拿到响应状态码。
pub async fn monitoring_middleware(req: Request, next: Next) -> Response {
    let start = Instant::now();
    let method = req.method().clone();
    // 优先路由模板，避免查询参数/动态 ID 导致高基数标签
    let path = req
        .extensions()
        .get::<MatchedPath>()
        .map(|m| m.as_str().to_string())
        .unwrap_or_else(|| req.uri().path().to_string());

    let resp = next.run(req).await;

    let duration = start.elapsed();
    let status = resp.status().as_u16();
    let obs = Observability::global();

    // 指标记录（counter + histogram，秒）
    obs.metrics
        .record(method.as_str(), status, &path, duration.as_secs_f64());
    // 慢请求记录（毫秒，超阈值才入缓冲）
    obs.slow
        .record(method.as_str(), &path, status, duration.as_millis() as u64);

    resp
}
