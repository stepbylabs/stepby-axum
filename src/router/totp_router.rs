//! TOTP 多因子认证路由

use std::sync::Arc;
use axum::Router;
use axum::routing::{get, post};

use crate::handler::totp_handler;
use crate::state::AppState;

pub fn totp_routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/system/user/totp/setup", post(totp_handler::setup))
        .route("/system/user/totp/verify", post(totp_handler::verify))
        .route("/system/user/totp/status", get(totp_handler::status))
        .route("/system/user/totp/disable", post(totp_handler::disable))
}
