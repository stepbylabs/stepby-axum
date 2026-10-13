//! 缓存监控路由注册
//!
//! 路由结构：
//! - /monitor/cache                                    — GET    获取缓存概览
//! - /monitor/cache/getNames                           — GET    获取缓存名称列表
//! - /monitor/cache/hotKeys                            — GET    获取热 key（大内存键）提示
//! - /monitor/cache/prefixStats                        — GET    获取缓存前缀内存统计
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
use crate::middleware::platform_guard::platform_only_guard;
use crate::state::AppState;

/// 缓存监控路由
///
/// P1-1：整组 `/monitor/cache/*` 为平台专属能力，挂 [`platform_only_guard`] 请求层守卫，
/// 租户操作者（含租户管理员）一律 403（不依赖 perms，作为权限层的第二道防线）。
pub fn cache_routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/monitor/cache", get(monitor_cache_handler::get_cache))
        .route(
            "/monitor/cache/getNames",
            get(monitor_cache_handler::get_names),
        )
        .route(
            "/monitor/cache/hotKeys",
            get(monitor_cache_handler::get_hot_keys),
        )
        .route(
            "/monitor/cache/prefixStats",
            get(monitor_cache_handler::get_prefix_stats),
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
        .route_layer(axum::middleware::from_fn(platform_only_guard))
}
