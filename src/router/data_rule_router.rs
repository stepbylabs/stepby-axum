// stepby-axum/src/router/data_rule_router.rs
//! DP-01 数据权限规则管理路由（system 域）

use axum::Router;
use axum::routing::{get, post};
use std::sync::Arc;

use crate::handler::data_rule_handler;
use crate::state::AppState;

pub fn data_rule_routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/system/dataRule/list", get(data_rule_handler::list))
        .route("/system/dataRule", post(data_rule_handler::save))
        .route(
            "/system/dataRule/{id}",
            axum::routing::delete(data_rule_handler::remove),
        )
}
