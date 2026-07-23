// axum-backend/src/router/mod.rs

pub mod auth_router;
pub mod common_router;
pub mod ip_location_router;
pub mod monitor_cache_router;
pub mod monitor_online_router;
pub mod monitor_server_router;
pub mod public;
pub mod sys_backup_router;
pub mod sys_config_router;
pub mod sys_dept_router;
pub mod sys_dict_router;
pub mod sys_job_router;
pub mod sys_logininfor_router;
pub mod sys_menu_router;
pub mod sys_notice_router;
pub mod sys_oper_log_router;
pub mod sys_post_router;
pub mod sys_rate_limit_router;
pub mod sys_role_router;
pub mod sys_task_router;
pub mod sys_user_router;
pub mod tool_gen_router;
pub mod totp_router;
pub mod file_router;

use std::sync::Arc;
use std::time::Duration;
use axum::Router;
use axum::extract::DefaultBodyLimit;
use axum::http::{HeaderName, HeaderValue, Method, StatusCode};
use axum::middleware::from_fn_with_state;
use axum::routing::get;
use tower_http::compression::CompressionLayer;
use tower_http::cors::{AllowOrigin, CorsLayer};
use tower_http::services::ServeDir;
use tower_http::timeout::TimeoutLayer;
use tower_http::trace::TraceLayer;
use crate::config::settings::ServerConfig;
use crate::docs;
use crate::embedded_assets;
use crate::middleware::auth_middleware;
use crate::middleware::idempotency_middleware;
use crate::middleware::oper_log_middleware;
use crate::middleware::permission_middleware;
use crate::middleware::rate_limit_middleware;
use crate::middleware::request_id_middleware;
use crate::middleware::security_headers;
use crate::middleware::spa_fallback_middleware;
use crate::state::AppState;

/// 全局默认请求体大小上限（10MB，对齐 oper_log 中间件 BODY_READ_LIMIT）
const DEFAULT_BODY_LIMIT_BYTES: usize = 10 * 1024 * 1024;

/// 单个请求处理总时长上限（120s，覆盖 Slowloris 慢速攻击与长耗时业务）
const REQUEST_TIMEOUT_SECS: u64 = 120;

/// 构建完整应用路由
///
/// 路由结构：
/// - public_routes：免鉴权（/health、/captchaImage、/login）
/// - protected：需 auth_middleware + permission_middleware（/logout、/getInfo、/getRouters、/system/*）
/// - 静态资源：/uploads/*（头像等用户上传文件，免鉴权由前端 baseURL 拼接访问）
/// - 全局中间件：request_id（最外层）→ Trace → Cors → Compression（最内层）
pub fn build_app(state: Arc<AppState>) -> Router {
    // 受鉴权保护的业务路由
    let protected = Router::new()
        .merge(auth_router::protected_auth_routes())
        .merge(sys_user_router::user_routes())
        .merge(sys_role_router::role_routes())
        .merge(sys_menu_router::menu_routes())
        .merge(sys_notice_router::notice_routes())
        .merge(sys_dept_router::dept_routes())
        .merge(sys_job_router::job_routes())
        .merge(sys_dict_router::dict_routes())
        .merge(sys_config_router::config_routes())
        .merge(sys_post_router::post_routes())
        .merge(sys_rate_limit_router::rate_limit_routes())
        .merge(sys_oper_log_router::oper_log_routes())
        .merge(sys_logininfor_router::logininfor_routes())
        .merge(monitor_online_router::online_routes())
        .merge(monitor_cache_router::cache_routes())
        .merge(monitor_server_router::server_routes())
        .merge(sys_backup_router::backup_routes())
        .merge(ip_location_router::ip_location_routes())
        .merge(sys_task_router::task_routes())
        .merge(tool_gen_router::gen_routes())
        .merge(common_router::common_routes())
        .merge(totp_router::totp_routes())
        .merge(file_router::file_routes())
        // oper_log_middleware 记录写操作日志（POST/PUT/DELETE），最内层
        .route_layer(from_fn_with_state(state.clone(), oper_log_middleware))
        // permission_middleware 使用 route_layer（路由匹配后执行，可访问 MatchedPath）
        .route_layer(from_fn_with_state(state.clone(), permission_middleware))
        // idempotency_middleware 幂等性校验（R5-IDEMP-33）：基于 Idempotency-Key 头去重
        // 执行顺序：auth → rate_limit → idempotency → permission → oper_log
        // 仅对 POST/PUT/DELETE 生效，缺失 Idempotency-Key 头时放行（可选特性）
        .route_layer(from_fn_with_state(state.clone(), idempotency_middleware))
        // rate_limit_middleware 限流（P1-34）：per-IP 令牌桶，覆盖所有受保护业务接口
        // 执行顺序：auth → rate_limit → idempotency → permission → oper_log
        .route_layer(from_fn_with_state(state.clone(), rate_limit_middleware))
        // auth_middleware 使用 route_layer（仅当 path+method 完全匹配时执行）
        // 重要：若改用 .layer()，路径匹配但 method 不匹配时（如 GET /system/rateLimit），
        // 鉴权会先返回 401，导致 SPA fallback 无法触发，前端页面加载失败。
        // 使用 route_layer 确保 405/404 由路由层处理，未匹配的请求进入 SPA fallback。
        .route_layer(from_fn_with_state(state.clone(), auth_middleware))
        // spa_fallback_middleware：浏览器导航请求（Sec-Fetch-Mode: navigate）且无 token 时
        // 直接返回 SPA HTML，解决 /monitor/cache、/monitor/server 等路径与 API 完全重叠导致的
        // 浏览器访问返回 401 JSON 问题。
        // 关键：必须最后添加（最先执行/最外层），在 auth_middleware 之前拦截浏览器导航请求。
        // axum 0.8 layer 执行顺序：后添加的先执行（最外层）。
        // 安全性：仅返回 SPA HTML，不返回 API 数据；Sec-Fetch-Mode 浏览器自动设置无法伪造。
        .layer(axum::middleware::from_fn(spa_fallback_middleware));

    // CORS 配置（从配置文件读取 Origin 白名单）
    let cors = build_cors_layer(&state.config.server);

    // 前端静态资源服务模式（场景2：开发/生产双模式）
    // - 生产模式（release）：rust-embed 嵌入资源，单可执行文件部署
    // - 开发模式（debug）：从 frontend-dist/ 目录读取，前端修改后无需重编译 Rust
    // 通过 embedded_assets::is_embedded_mode() 检测（基于 cfg(debug_assertions) + 环境变量覆盖）
    let embedded_mode = embedded_assets::is_embedded_mode();

    let mut app = Router::new()
        .merge(public::public_routes(state.clone()))
        .merge(protected);

    // Swagger UI 与 OpenAPI JSON（免鉴权，供开发调试用）
    // 必须在 fallback 之前注册，否则会被 SPA fallback 吞掉
    // 生产环境可通过 server.docs_enabled = false 关闭
    if state.config.server.docs_enabled {
        app = app
            .route("/swagger-ui", get(docs::swagger_ui))
            .route("/swagger-ui/index.html", get(docs::swagger_ui))
            // Swagger UI 静态资源（本地自托管，替代 unpkg CDN）
            // 路径格式：/swagger-ui-static/swagger-ui.css, /swagger-ui-static/swagger-ui-bundle.js
            .route("/swagger-ui-static/{filename}", get(docs::swagger_assets))
            .route("/api-docs/openapi.json", get(docs::openapi_json));
    }

    // 静态资源服务：头像等用户上传文件
    // /uploads/avatar/xxx.png → <upload_root>/avatar/xxx.png
    // 必须在 SPA fallback 之前注册
    // 修复：将相对路径解析为绝对路径，基于可执行文件所在目录，避免依赖进程 CWD
    // 解析逻辑已移至 common::upload::resolve_upload_root，与 handler 层共享，确保保存与服务路径一致
    let upload_root = crate::common::resolve_upload_root(&state.config.upload);
    tracing::info!("静态资源服务目录: {}", upload_root.display());
    app = app.nest_service("/uploads", ServeDir::new(upload_root));

    // 根路径 handler：返回前端 index.html
    if embedded_mode {
        app = app.route("/", get(embedded_assets::serve_index));
    }

    // fallback handler：统一使用 serve_spa（自动根据编译模式切换读取源）
    // - 生产模式：从 rust-embed 嵌入资源读取
    // - 开发模式：从 frontend-dist/ 文件系统读取
    if embedded_mode {
        app = app.fallback(embedded_assets::serve_spa);
        // method_not_allowed_fallback：当 path 匹配但 method 不匹配时调用
        // 关键修复：浏览器 GET /system/backup（path 匹配 POST handler 但 method 不匹配）
        // 必须返回 SPA HTML 让前端路由接管，而非 405 或被 auth_middleware 拦截为 401。
        // axum 0.8 中 route_layer 在 path 匹配后即执行，method 不匹配时仍会运行中间件，
        // 因此仅靠 route_layer 无法解决 SPA fallback 问题，必须显式配置 method_not_allowed_fallback。
        app = app.method_not_allowed_fallback(embedded_assets::serve_spa);
        if cfg!(debug_assertions) {
            tracing::info!("前端开发模式已启用：从 frontend-dist/ 目录读取静态资源（ServeDir 风格）");
        } else {
            tracing::info!("前端嵌入模式已启用：单可执行文件部署（前端资源已编译进二进制）");
        }
    } else {
        app = app.fallback(|| async {
            (
                axum::http::StatusCode::NOT_FOUND,
                axum::Json(serde_json::json!({
                    "code": 404,
                    "msg": "请求的资源不存在"
                })),
            )
        });
        tracing::info!("前端分离模式：未匹配路由返回 JSON 404（开发模式）");
    }

    let app = app.with_state(state);

    // 叠加全局中间件（顺序：后添加的先执行）
    app.layer(CompressionLayer::new())
        .layer(DefaultBodyLimit::max(DEFAULT_BODY_LIMIT_BYTES))
        .layer(cors)
        .layer(TraceLayer::new_for_http())
        // Slowloris / 慢速请求防护：限制单个请求处理总时长（REQUEST_TIMEOUT_SECS），
        // 超时则中断连接，防止慢速攻击耗尽连接池（axum 0.8 Serve 不支持 http1_header_read_timeout，
        // 改用 TimeoutLayer 实现请求级超时；生产环境建议同时在 Nginx 层配置 client_header_timeout）
        .layer(TimeoutLayer::with_status_code(StatusCode::REQUEST_TIMEOUT, Duration::from_secs(REQUEST_TIMEOUT_SECS)))
        .layer(axum::middleware::from_fn(request_id_middleware))
        // 安全响应头中间件（最外层，确保所有响应都带安全头）
        .layer(axum::middleware::from_fn(security_headers))
}

/// 构建 CORS 层（从配置读取 Origin 白名单）
///
/// - allow_methods: GET/POST/PUT/DELETE/OPTIONS
/// - allow_headers: authorization/content-type/accept
/// - allow_credentials: true（支持 Cookie 传递）
/// - allow_origin: 从 config.toml 的 server.cors_origins 读取
fn build_cors_layer(server_config: &ServerConfig) -> CorsLayer {
    let origins: Vec<HeaderValue> = server_config
        .cors_origins
        .iter()
        .filter_map(|o| o.parse().ok())
        .collect();

    CorsLayer::new()
        .allow_methods([
            Method::GET,
            Method::POST,
            Method::PUT,
            Method::DELETE,
            Method::OPTIONS,
        ])
        .allow_headers([
            HeaderName::from_static("authorization"),
            HeaderName::from_static("content-type"),
            HeaderName::from_static("accept"),
        ])
        .allow_credentials(true)
        .allow_origin(AllowOrigin::list(origins))
}
