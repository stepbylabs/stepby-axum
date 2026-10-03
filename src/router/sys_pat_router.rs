// stepby-axum/src/router/sys_pat_router.rs
//! 个人访问令牌（PAT）路由注册
//!
//! - 自助：/system/user/profile/tokens*（仅需登录，恒操作本人；已加入 is_login_only_path 白名单）
//! - 管理：/monitor/pat/*（RBAC monitor:pat:list / monitor:pat:revoke）
//! - 开放 API AK/SK：/system/pat/{patId}/rotate-ak | revoke-ak（自助，敏感操作独立限流；
//!   已加入 is_login_only_path 白名单，且 /system/pat 前缀对 PAT Bearer 一律禁止）

use axum::Router;
use axum::routing::{delete, get, post};
use std::sync::Arc;

use crate::handler::sys_pat_handler;
use crate::state::AppState;

/// PAT 路由（需挂在鉴权中间件下）
pub fn pat_routes() -> Router<Arc<AppState>> {
    Router::new()
        // 自助：列表 / scope 选项 / 新建 / 吊销
        .route(
            "/system/user/profile/tokens",
            get(sys_pat_handler::list_mine).post(sys_pat_handler::create),
        )
        .route(
            "/system/user/profile/tokens/scopes",
            get(sys_pat_handler::scope_options),
        )
        .route(
            "/system/user/profile/tokens/{patId}",
            delete(sys_pat_handler::revoke_mine),
        )
        // 管理：全量列表 / 吊销
        .route("/monitor/pat/list", get(sys_pat_handler::list_all))
        .route(
            "/monitor/pat/{patId}",
            delete(sys_pat_handler::revoke_by_admin),
        )
        // 开放 API AK/SK：轮换 SK（新明文一次）/ 清空 AK/SK
        .route(
            "/system/pat/{patId}/rotate-ak",
            post(sys_pat_handler::rotate_ak),
        )
        .route(
            "/system/pat/{patId}/revoke-ak",
            post(sys_pat_handler::revoke_ak),
        )
}
