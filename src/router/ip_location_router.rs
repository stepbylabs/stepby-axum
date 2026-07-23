//! IP 归属地库管理路由注册
//!
//! 路由结构：
//! - /system/ipLocation/* — IP 库管理（6 个接口）
//!
//! 权限：
//! - status / config：仅需 monitor:iplocation:list
//! - PUT /config：monitor:iplocation:edit
//! - POST /update：monitor:iplocation:edit
//! - POST /reload：monitor:iplocation:edit
//! - POST /reloadXdb：monitor:iplocation:edit

use std::sync::Arc;
use axum::Router;
use axum::routing::{get, post};

use crate::handler::ip_location_handler;
use crate::state::AppState;

/// IP 库管理路由
pub fn ip_location_routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/system/ipLocation/status", get(ip_location_handler::status))
        .route(
            "/system/ipLocation/config",
            get(ip_location_handler::get_config).put(ip_location_handler::save_config),
        )
        .route("/system/ipLocation/update", post(ip_location_handler::update_now))
        .route("/system/ipLocation/reload", post(ip_location_handler::reload))
        .route("/system/ipLocation/reloadXdb", post(ip_location_handler::reload_xdb))
}
