//! 缓存监控路由注册
//!
//! 路由结构：
//! - /monitor/cache                                    — GET    获取缓存概览
//! - /monitor/cache/getNames                           — GET    获取缓存名称列表
//! - /monitor/cache/getKeys/{cacheName}                — GET    获取指定缓存的键列表
//! - /monitor/cache/getValue/{cacheName}/{cacheKey}    — GET    获取缓存值
//! - /monitor/cache/clearCacheName/{cacheName}         — DELETE 清除指定名称的缓存
//! - /monitor/cache/clearCacheKey/{cacheKey}           — DELETE 清除指定键的缓存
//!
//! 注意：clearCacheAll（FLUSHDB）端点已移除，FLUSHDB 会误清 blacklist/online/
//! login_fail 等业务键。如需批量清理请使用 clearCacheName 按白名单前缀逐类清理。

use std::sync::Arc;

use axum::Router;
use axum::routing::{delete, get};

use crate::handler::monitor_cache_handler;
use crate::state::AppState;

/// 缓存监控路由
pub fn cache_routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/monitor/cache", get(monitor_cache_handler::get_cache))
        .route(
            "/monitor/cache/getNames",
            get(monitor_cache_handler::get_names),
        )
        .route(
            "/monitor/cache/getKeys/{cacheName}",
            get(monitor_cache_handler::get_keys),
        )
        .route(
            "/monitor/cache/getValue/{cacheName}/{cacheKey}",
            get(monitor_cache_handler::get_value),
        )
        .route(
            "/monitor/cache/clearCacheName/{cacheName}",
            delete(monitor_cache_handler::clear_cache_name),
        )
        .route(
            "/monitor/cache/clearCacheKey/{cacheKey}",
            delete(monitor_cache_handler::clear_cache_key),
        )
}
