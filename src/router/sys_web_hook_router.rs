//! WebHook 事件订阅模块路由注册
//!
//! 受保护路由（需 auth_middleware + permission_middleware）：
//! - /monitor/webHook/*                    回调配置管理
//! - /monitor/webHook/log/*                推送记录管理
//!
//! 注意：静态路由（list、export、test、status、log/*）需在 {id} 动态路由之前注册，
//! axum 0.8 优先匹配静态段；/monitor/webHook/{id} 与 /monitor/webHook/log/* 路径不同不冲突。

use axum::Router;
use axum::routing::{delete, get, post, put};
use std::sync::Arc;

use crate::handler::sys_web_hook_handler;
use crate::handler::sys_webhook_event_handler;
use crate::state::AppState;

/// WebHook 模块路由
pub fn web_hook_routes() -> Router<Arc<AppState>> {
    Router::new()
        // ===== 回调配置 =====
        .route("/monitor/webHook/list", get(sys_web_hook_handler::list))
        .route(
            "/monitor/webHook/export",
            post(sys_web_hook_handler::export),
        )
        .route(
            "/monitor/webHook/{id}/status",
            put(sys_web_hook_handler::change_status),
        )
        .route(
            "/monitor/webHook/{id}/test",
            post(sys_web_hook_handler::test_hook),
        )
        .route(
            "/monitor/webHook/{id}",
            get(sys_web_hook_handler::get_info).delete(sys_web_hook_handler::remove),
        )
        .route(
            "/monitor/webHook",
            post(sys_web_hook_handler::add).put(sys_web_hook_handler::edit),
        )
        // ===== 推送记录 =====
        .route(
            "/monitor/webHook/log/list",
            get(sys_web_hook_handler::log_list),
        )
        .route(
            "/monitor/webHook/log/export",
            post(sys_web_hook_handler::log_export),
        )
        .route(
            "/monitor/webHook/log/clean",
            delete(sys_web_hook_handler::log_clean),
        )
        .route(
            "/monitor/webHook/log/{ids}/retry",
            post(sys_web_hook_handler::log_retry),
        )
        .route(
            "/monitor/webHook/log/{id}",
            get(sys_web_hook_handler::log_info).delete(sys_web_hook_handler::log_remove),
        )
        // ===== 事件目录（开放域 m20261003_000002）=====
        // 静态段 /system/webhook/event/list 需在 {id} 动态路由之前注册（axum 0.8 优先匹配静态段）
        .route(
            "/system/webhook/event/list",
            get(sys_webhook_event_handler::event_list),
        )
        .route(
            "/system/webhook/{id}/test-send",
            post(sys_webhook_event_handler::test_send),
        )
}
