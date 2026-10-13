//! 第三方登录 / OAuth2 / OIDC 路由注册
//!
//! 公开路由（免鉴权，挂载限流中间件）：
//! - GET /oauth2/providers                登录页启用提供商列表
//! - GET /oauth2/authorize                生成授权 URL
//! - GET /oauth2/callback                 授权回调（浏览器重定向流程）
//!
//! 受保护路由（需 auth_middleware + permission_middleware）：
//! - GET    /system/oauth/provider/list        提供商分页
//! - GET    /system/oauth/provider/{providerId} 提供商详情
//! - POST   /system/oauth/provider             新增提供商
//! - PUT    /system/oauth/provider             修改提供商
//! - DELETE /system/oauth/provider/{providerIds} 批量删除提供商
//! - PUT    /system/oauth/provider/{providerId}/status 启停提供商
//! - GET    /oauth2/my-bindings                当前账号第三方绑定列表
//! - POST   /oauth2/bind                       当前账号绑定第三方身份
//! - DELETE /oauth2/unbind                     当前账号解绑第三方身份
//!
//! 权限映射（permission_middleware）：
//! - system:oauth:provider:list/query/add/edit/remove/toggle
//! - 绑定/解绑/绑定列表：仅登录（is_login_only_path）

use axum::Router;
use axum::routing::{delete, get, post, put};
use std::sync::Arc;

use crate::handler::sys_oauth_handler;
use crate::state::AppState;

/// 公开 OAuth 路由（免鉴权）
pub fn public_oauth_routes(state: Arc<AppState>) -> Router<Arc<AppState>> {
    Router::new()
        // GET /oauth2/providers 登录页启用提供商列表
        .route("/oauth2/providers", get(sys_oauth_handler::list_providers))
        // GET /oauth2/authorize?provider_code= 生成授权 URL
        .route("/oauth2/authorize", get(sys_oauth_handler::begin_oauth))
        // GET /oauth2/callback 授权回调（code/state）→ 302 到前端 /oauth-login
        .route("/oauth2/callback", get(sys_oauth_handler::callback))
        // 限流：防止第三方客户端高频探测 /oauth2/authorize、/oauth2/callback
        .route_layer(axum::middleware::from_fn_with_state(
            state,
            crate::middleware::rate_limit::rate_limit_middleware,
        ))
}

/// 受保护 OAuth 路由（provider 管理 + 绑定管理）
pub fn oauth_routes() -> Router<Arc<AppState>> {
    Router::new()
        // ===== 提供商管理（/system/oauth/provider） =====
        // GET /system/oauth/provider/list 分页查询提供商
        .route(
            "/system/oauth/provider/list",
            get(sys_oauth_handler::provider_list),
        )
        // GET 详情 / PUT 启停 / DELETE 批量删除（三种方法共用 {providerId} 段；
        // 删除段同样按 GET 段命名，避免 axum 同位置不同参数名的路由冲突）
        .route(
            "/system/oauth/provider/{providerId}",
            get(sys_oauth_handler::provider_info).delete(sys_oauth_handler::provider_delete),
        )
        .route(
            "/system/oauth/provider/{providerId}/status",
            put(sys_oauth_handler::provider_toggle),
        )
        // POST /system/oauth/provider 新增
        .route(
            "/system/oauth/provider",
            post(sys_oauth_handler::provider_add).put(sys_oauth_handler::provider_edit),
        )
        // ===== 绑定管理（/oauth2） =====
        // GET /oauth2/my-bindings 当前账号第三方绑定列表
        .route("/oauth2/my-bindings", get(sys_oauth_handler::my_bindings))
        // POST /oauth2/bind 绑定第三方身份（handoff + 登录态）
        .route("/oauth2/bind", post(sys_oauth_handler::bind_oauth))
        // DELETE /oauth2/unbind?provider= 解绑
        .route("/oauth2/unbind", delete(sys_oauth_handler::unbind_oauth))
}
