//! 单点登录 / OIDC Provider 路由注册
//!
//! 公开路由（免鉴权，挂载限流）：
//! - GET  /.well-known/openid-configuration  OIDC 发现文档
//! - GET  /sso/authorize                     授权端点（解析浏览器会话 Cookie）
//! - POST /sso/token                         令牌端点（授权码 + PKCE）
//! - GET  /sso/userinfo                      用户信息端点（Bearer access_token）
//! - GET|POST /sso/logout                    RP-initiated end-session
//!
//! 受保护路由（需 auth + permission）：
//! - POST /sso/consent                       同意页批准 / 拒绝（仅登录）
//! - GET    /system/oauth/client/list        客户端分页
//! - GET    /system/oauth/client/{id}        客户端详情
//! - POST   /system/oauth/client             新增
//! - PUT    /system/oauth/client             修改
//! - DELETE /system/oauth/client/{ids}       批量删除
//! - PUT    /system/oauth/client/{id}/status 启停

use axum::Router;
use axum::routing::{get, post, put};
use std::sync::Arc;

use crate::handler::sso_handler;
use crate::state::AppState;

/// 公开 OIDC 端点（免鉴权）
pub fn public_sso_routes(state: Arc<AppState>) -> Router<Arc<AppState>> {
    Router::new()
        .route(
            "/.well-known/openid-configuration",
            get(sso_handler::discovery),
        )
        .route("/sso/authorize", get(sso_handler::authorize))
        .route("/sso/token", post(sso_handler::token))
        .route("/sso/userinfo", get(sso_handler::userinfo))
        .route("/sso/jwks", get(sso_handler::jwks))
        .route(
            "/sso/logout",
            get(sso_handler::logout).post(sso_handler::logout),
        )
        // 限流：防止外部客户端高频探测授权/令牌端点
        .route_layer(axum::middleware::from_fn_with_state(
            state,
            crate::middleware::rate_limit::rate_limit_middleware,
        ))
}

/// 受保护路由：同意 + 客户端管理
pub fn sso_routes() -> Router<Arc<AppState>> {
    Router::new()
        // POST /sso/consent（仅登录，供同意页调用）
        .route("/sso/consent", post(sso_handler::consent))
        // ===== 客户端管理 =====
        .route("/system/oauth/client/list", get(sso_handler::client_list))
        .route(
            "/system/oauth/client/{id}",
            get(sso_handler::client_info).delete(sso_handler::client_delete),
        )
        .route(
            "/system/oauth/client/{id}/status",
            put(sso_handler::client_toggle),
        )
        .route(
            "/system/oauth/client",
            post(sso_handler::client_add).put(sso_handler::client_edit),
        )
        // ===== 自助授权管理（v4-R8：仅登录，无需管理权限）=====
        .route(
            "/system/user/profile/sso-grants",
            get(sso_handler::grant_list),
        )
        .route(
            "/system/user/profile/sso-grants/{client_id}",
            axum::routing::delete(sso_handler::grant_revoke),
        )
}
