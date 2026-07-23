//! 文件管理路由

use std::sync::Arc;
use axum::Router;
use axum::routing::{get, post, delete};

use crate::handler::file_handler;
use crate::state::AppState;

pub fn file_routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/system/file/list", get(file_handler::list))
        .route("/system/file/upload", post(file_handler::upload))
        .route("/system/file/delete", delete(file_handler::delete))
}
