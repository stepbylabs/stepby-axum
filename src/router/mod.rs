// stepby-axum/src/router/mod.rs

pub mod ai_router;
pub mod auth_router;
pub mod common_router;
pub mod data_rule_router;
pub mod file_router;
pub mod flow_router;
pub mod ip_location_router;
pub mod monitor_cache_router;
pub mod monitor_log_router;
pub mod monitor_alert_router;
pub mod monitor_observability_router;
pub mod monitor_online_router;
pub mod monitor_server_router;
pub mod public;
pub mod scim_router;
pub mod sso_router;
pub mod sys_backup_router;
pub mod sys_config_router;
pub mod sys_dept_router;
pub mod sys_dict_router;
pub mod sys_frontend_error_router;
pub mod sys_http_debug_router;
pub mod sys_job_router;
pub mod sys_logininfor_router;
pub mod sys_menu_router;
pub mod sys_msg_router;
pub mod sys_notice_router;
pub mod sys_oauth_router;
pub mod sys_oper_log_router;
pub mod sys_pat_router;
pub mod sys_post_router;
pub mod sys_rate_limit_router;
pub mod sys_report_board_router;
pub mod sys_report_router;
pub mod sys_role_router;
pub mod sys_role_field_perm_router;
pub mod sys_scim_group_router;
pub mod sys_task_router;
pub mod sys_tenant_domain_router;
pub mod sys_tenant_nav_router;
pub mod sys_tenant_router;
pub mod sys_user_pref_router;
pub mod sys_user_router;
pub mod sys_web_hook_router;
pub mod tool_gen_router;
pub mod totp_router;
pub mod webauthn_router;

use crate::config::settings::ServerConfig;
use crate::docs;
use crate::embedded_assets;
use crate::middleware::auth_middleware;
use crate::middleware::idempotency_middleware;
use crate::middleware::locale_middleware;
use crate::middleware::oper_log_middleware;
use crate::middleware::permission_middleware;
use crate::middleware::rate_limit_middleware;
use crate::middleware::request_id_middleware;
use crate::middleware::response_cache::{ResponseCache, response_cache_middleware};
use crate::middleware::security_headers;
use crate::middleware::spa_fallback_middleware;
use crate::middleware::tenant_host_middleware;
use crate::observability::monitoring_middleware;
use crate::state::AppState;
use axum::Router;
use axum::extract::DefaultBodyLimit;
use axum::http::{HeaderName, HeaderValue, Method, StatusCode};
use axum::middleware::from_fn_with_state;
use axum::routing::get;
use std::sync::Arc;
use std::time::Duration;
use tower_http::compression::CompressionLayer;
use tower_http::cors::{AllowOrigin, CorsLayer};
use tower_http::timeout::TimeoutLayer;
use tower_http::trace::TraceLayer;

/// 全局默认请求体大小上限（10MB，对齐 oper_log 中间件 BODY_READ_LIMIT）
const DEFAULT_BODY_LIMIT_BYTES: usize = 10 * 1024 * 1024;

/// 单个请求处理总时长上限（120s，覆盖 Slowloris 慢速攻击与长耗时业务）
const REQUEST_TIMEOUT_SECS: u64 = 120;

/// 构建完整应用路由
///
/// 路由结构：
/// - public_routes：免鉴权（/health、/captchaImage、/login）
/// - protected：需 auth_middleware + permission_middleware（/logout、/getInfo、/getRouters、/system/*）
/// - 上传文件预览：`GET /uploads/{tid}/{kind}/{filename}`（受鉴权，替代此前的无鉴权静态直出）
/// - 全局中间件（由外到内执行顺序，与下方 app.layer 链一致）：
///   security_headers → locale → request_id → monitoring → Timeout → Trace → Cors
///   → DefaultBodyLimit → Compression（最内层），其后进入 api 路由的 tenant_host →
///   （protected 的 spa_fallback → auth → rate_limit → idempotency → permission → oper_log → response_cache）
pub fn build_app(state: Arc<AppState>) -> Router {
    // 受鉴权保护的业务路由
    let protected = Router::new()
        .merge(auth_router::protected_auth_routes())
        .merge(sys_user_router::user_routes())
        .merge(sys_scim_group_router::scim_group_routes())
        .merge(sys_user_pref_router::user_pref_routes())
        .merge(sys_pat_router::pat_routes())
        .merge(sys_role_router::role_routes())
        .merge(sys_role_field_perm_router::role_field_perm_routes())
        .merge(sys_menu_router::menu_routes())
        .merge(sys_msg_router::msg_routes())
        .merge(sys_oauth_router::oauth_routes())
        .merge(sso_router::sso_routes())
        .merge(sys_notice_router::notice_routes())
        .merge(sys_report_router::report_routes())
        .merge(sys_report_board_router::report_board_routes())
        .merge(sys_web_hook_router::web_hook_routes())
        .merge(sys_dept_router::dept_routes())
        .merge(sys_tenant_router::tenant_routes())
        .merge(sys_tenant_domain_router::tenant_domain_routes())
        .merge(sys_tenant_nav_router::tenant_nav_routes())
        .merge(sys_job_router::job_routes())
        .merge(sys_dict_router::dict_routes())
        .merge(sys_http_debug_router::http_debug_routes())
        .merge(sys_config_router::config_routes())
        .merge(ai_router::ai_routes())
        .merge(sys_post_router::post_routes())
        .merge(data_rule_router::data_rule_routes())
        .merge(sys_rate_limit_router::rate_limit_routes())
        .merge(sys_oper_log_router::oper_log_routes())
        .merge(sys_frontend_error_router::frontend_error_routes())
        .merge(sys_logininfor_router::logininfor_routes())
        .merge(monitor_online_router::online_routes())
        .merge(monitor_cache_router::cache_routes())
        .merge(monitor_server_router::server_routes())
        .merge(monitor_log_router::log_routes())
        .merge(monitor_observability_router::observability_routes())
        .merge(monitor_alert_router::monitor_alert_routes())
        .merge(crate::audit::router::audit_change_routes())
        .merge(sys_backup_router::backup_routes())
        .merge(ip_location_router::ip_location_routes())
        .merge(sys_task_router::task_routes())
        .merge(flow_router::flow_routes())
        .merge(tool_gen_router::gen_routes())
        .merge(common_router::common_routes())
        .merge(totp_router::totp_routes())
        .merge(webauthn_router::webauthn_routes())
        .merge(file_router::file_routes())
        // oper_log_middleware 记录写操作日志（POST/PUT/DELETE），最内层
        // response_cache_middleware（P3-6）：对白名单「幂等只读 GET」做进程内 TTL 缓存。
        // §5.34 挂载位置调整：cache 必须在 permission **内层**（route_layer 先挂载）——
        //   此前 cache 在 permission 外层，缓存命中直接返回、RBAC 从未执行（旁路：
        //   无 system:dict:query 权限的用户也能经缓存拿到 optionselect）。
        //   调整后执行序：auth → rate_limit → idempotency → permission → oper_log → cache
        //   ⇒ RBAC 恒在缓存之前执行，命中必先过权限闸门。
        // 安全理由：白名单仅含纯静态元数据接口（字典类型下拉 optionselect），缓存内容
        //   对不同登录用户完全一致，归属无用户差异，不泄露个人信息；
        //   首个请求仍走 auth+permission 校验与真实 DB 查询，续访问命中缓存直接返回。
        .route_layer(from_fn_with_state(
            ResponseCache::default(),
            response_cache_middleware,
        ))
        .route_layer(from_fn_with_state(state.clone(), oper_log_middleware))
        // permission_middleware 使用 route_layer（路由匹配后执行，可访问 MatchedPath）
        .route_layer(from_fn_with_state(state.clone(), permission_middleware))
        // idempotency_middleware 幂等性校验（R5-IDEMP-33）：基于 Idempotency-Key 头去重
        // 执行顺序：auth → rate_limit → idempotency → permission → oper_log → cache
        // 仅对 POST/PUT/DELETE 生效，缺失 Idempotency-Key 头时放行（可选特性）
        .route_layer(from_fn_with_state(state.clone(), idempotency_middleware))
        // rate_limit_middleware 限流（P1-34）：per-IP 令牌桶，覆盖所有受保护业务接口
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

    // B3：权限 fail-closed 模式告警
    // 开启 permission_deny_by_default 后，受保护路由中未登记权限映射且不在仅登录白名单的
    // 接口将返回 403。启动时明确告警，提醒运维确认 LOGIN_ONLY 白名单（permission.rs）完整，
    // 否则合法仅登录接口（下拉树、个人资料、标记已读等）会被误拦截。
    if state.config.permission_deny_by_default {
        tracing::warn!(
            "权限 fail-closed 模式已启用（permission_deny_by_default=true）：未登记权限映射且不在仅登录白名单的受保护路由将返回 403。请确认 middleware/permission.rs 的 is_login_only_path 白名单完整，否则合法仅登录接口会被拦截。"
        );
    }

    // CORS 配置（从配置文件读取 Origin 白名单）
    let cors = build_cors_layer(&state.config.server);

    // 前端静态资源服务模式（场景2：开发/生产双模式）
    // - 生产模式（release）：rust-embed 嵌入资源，单可执行文件部署
    // - 开发模式（debug）：从 frontend-dist/ 目录读取，前端修改后无需重编译 Rust
    // 通过 embedded_assets::is_embedded_mode() 检测（基于 cfg(debug_assertions) + 环境变量覆盖）
    let embedded_mode = embedded_assets::is_embedded_mode();

    // 组装 API 路由（公开 + 受保护），并设置显式 JSON 404 fallback。
    // 该 fallback 会随 Router::nest 一起嵌套到各前缀下，使未匹配的 API 路径返回
    // JSON 404（而非落入 SPA fallback 返回 HTML，避免前端把 HTML 当 JSON 解析报错）。
    let api = public::public_routes(state.clone())
        .merge(uploads_routes(state.clone()))
        // AK/SK 签名开放 API（/open/v1/*）：无 Bearer，必须与公开路由同层 merge，
        // 不得落入 protected 的 auth_middleware route_layer 覆盖范围（否则 401）。
        // 自带 ak_sign 验签中间件（X-CA-* 签名 + 防重放 + 组件 metrics）。
        .merge(crate::middleware::ak_sign::ak_protected_routes(state.clone()))
        .merge(protected)
        // tenant_host 中间件（多租户 Phase 3 域名链路）：解析请求 host / 网关注入的
        // `X-Tenant-Code` → 租户上下文，注入 HostTenant 供 auth_middleware 做一致性校验。
        // 关键：以 `Router::layer` 挂在 api 整体（在所有业务 route_layer 之外、更外层），
        // 因此对**公开路由**（登录页 / 公开页 / SSO 回调）同样生效。
        // 执行顺序（外→内）：tenant_host → spa_fallback → auth → rate_limit →
        //   idempotency → permission → oper_log → response_cache → handler。
        .layer(from_fn_with_state(state.clone(), tenant_host_middleware))
        .fallback(api_not_found);

    // 根路径挂载 API 路由，并在各前端 baseURL 前缀下重复挂载：
    // 生产构建 baseURL=/prod-api、开发 /dev-api、预发 /stage-api（见 stepby-vue/.env.*）。
    // 「后端嵌入前端」同源部署（embedded_assets）时浏览器直达后端，需命中带前缀的 API 路径。
    //
    // 为何用 Router::nest 而非 URI 改写中间件：
    // axum 0.8 中 Router::layer 的中间件在「路由匹配之后」才执行，URI 改写无法影响已完成的
    // 路径匹配（曾实现 middleware/api_prefix.rs，经验证无效已移除）。Router::nest 将前缀直接
    // 注册进路由表，并在进入子路由器前用 StripPrefix 剥离前缀，因此 handler 与中间件看到的
    // 请求路径与根路径完全一致（oper_log/rate_limit/权限匹配均不受影响）。
    let mut app = Router::new()
        .merge(api.clone())
        .nest("/prod-api", api.clone())
        .nest("/dev-api", api.clone())
        .nest("/stage-api", api.clone());

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

    // 上传文件预览：由上方 api 中的 uploads_routes 提供受鉴权路由（GET /uploads/{tid}/{kind}/{file}），
    // 不再使用无鉴权的 ServeDir 静态直出。文件物理隔离在 `uploads/{tid}/...`，
    // 由 handler 校验请求者租户与路径租户的归属关系（越权 403）。

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
            tracing::info!(
                "前端开发模式已启用：从 frontend-dist/ 目录读取静态资源（ServeDir 风格）"
            );
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
    // T-02：压缩谓词修正——xlsx/zip 等已是压缩格式，跳过二次 gzip（默认谓词仅豁免 gRPC/image/SSE/<32B）
    // 需引入 Predicate trait 才能调用 .and() 组合谓词
    use tower_http::compression::predicate::Predicate;
    let compression_predicate = tower_http::compression::predicate::SizeAbove::new(1024)
        .and(tower_http::compression::predicate::NotForContentType::GRPC)
        .and(tower_http::compression::predicate::NotForContentType::IMAGES)
        .and(tower_http::compression::predicate::NotForContentType::SSE)
        .and(
            tower_http::compression::predicate::NotForContentType::const_new(
                "application/vnd.openxmlformats",
            ),
        )
        .and(tower_http::compression::predicate::NotForContentType::const_new("application/zip"))
        .and(
            tower_http::compression::predicate::NotForContentType::const_new(
                "application/octet-stream",
            ),
        );
    app.layer(CompressionLayer::new().compress_when(compression_predicate))
        .layer(DefaultBodyLimit::max(DEFAULT_BODY_LIMIT_BYTES))
        .layer(cors)
        .layer(TraceLayer::new_for_http())
        // Slowloris / 慢速请求防护：限制单个请求处理总时长（REQUEST_TIMEOUT_SECS），
        // 超时则中断连接，防止慢速攻击耗尽连接池（axum 0.8 Serve 不支持 http1_header_read_timeout，
        // 改用 TimeoutLayer 实现请求级超时；生产环境建议同时在 Nginx 层配置 client_header_timeout）
        .layer(TimeoutLayer::with_status_code(
            StatusCode::REQUEST_TIMEOUT,
            Duration::from_secs(REQUEST_TIMEOUT_SECS),
        ))
        // 可观测性监控中间件（metrics + 慢请求）：
        // 置于 request_id 之内、Timeout 之外，既能在 request span 作用域内测量，
        // 又能覆盖到真实处理耗时（含 Timeout 以内的全部中间件 + handler）。
        // 注意：位于全局 layer，故 /health、/metrics 等公开端点同样被统计。
        .layer(axum::middleware::from_fn(monitoring_middleware))
        .layer(axum::middleware::from_fn(request_id_middleware))
        // locale 中间件（T-05）：Accept-Language → 协商 → task-local 注入（包裹全部内层，handler/AppError 均可读）
        .layer(axum::middleware::from_fn(locale_middleware))
        // 安全响应头中间件（最外层，确保所有响应都带安全头）
        .layer(axum::middleware::from_fn(security_headers))
}

/// 上传文件预览路由（`GET /uploads/{tid}/{kind}/{filename}`）
///
/// 取代此前的 `ServeDir` 无鉴权静态直出：
/// - 仅本地存储后端（`supports_static()`）挂载；S3 后端由对象存储公开 URL 直出
/// - 请求先经 cookie→Authorization 桥接（浏览器 `<img>` 无法自定义请求头，但前端 token
///   已存入 Cookie `Admin-Token`），再走 `auth_middleware` 强制鉴权
/// - 作用域严格限定本路由，避免全局 cookie 鉴权扩大 CSRF 攻击面
fn uploads_routes(state: Arc<AppState>) -> Router<Arc<AppState>> {
    if !state.storage.supports_static() {
        return Router::new();
    }
    Router::new()
        .route(
            "/uploads/{*path}",
            get(crate::handler::common_handler::serve_upload),
        )
        // 后添加先执行：cookie 桥接（补 Authorization 头）→ auth_middleware（校验）
        .route_layer(from_fn_with_state(state.clone(), auth_middleware))
        .route_layer(axum::middleware::from_fn(cookie_token_bridge))
}

/// Cookie → Authorization 请求头桥接（仅用于 `/uploads/*` 预览路由）
///
/// 前端 token 存于 Cookie `Admin-Token`（非 HttpOnly，js-cookie 写入）。
/// 浏览器在 `<img src>` 等场景无法附加自定义请求头，故此处从 Cookie 提取 token
/// 并补成 `Authorization: Bearer <token>`，使后续 `auth_middleware` 正常工作。
/// 若请求已带 Authorization 头则不覆盖（保持既有优先级）。
async fn cookie_token_bridge(
    mut req: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    if !req
        .headers()
        .contains_key(axum::http::header::AUTHORIZATION)
        && let Some(token) = extract_cookie_token(req.headers(), "Admin-Token")
        && let Ok(val) = HeaderValue::from_str(&format!("Bearer {token}"))
    {
        req.headers_mut()
            .insert(axum::http::header::AUTHORIZATION, val);
    }
    next.run(req).await
}

/// 从 Cookie 头中提取指定名称的值（简单实现，返回首个匹配项）
fn extract_cookie_token(headers: &axum::http::HeaderMap, name: &str) -> Option<String> {
    let cookies = headers.get(axum::http::header::COOKIE)?.to_str().ok()?;
    cookies.split(';').find_map(|part| {
        let (key, value) = part.trim().split_once('=')?;
        (key == name && !value.is_empty()).then(|| value.to_string())
    })
}

/// API 未匹配路径的统一 JSON 404 响应
///
/// 作为嵌套挂载的前缀路由（/prod-api、/dev-api、/stage-api）的 fallback：
/// 未匹配的 API 请求返回 JSON 错误，而非落入 SPA fallback 返回 HTML，
/// 避免前端响应拦截器把 HTML 当 JSON 解析而报错。
async fn api_not_found() -> impl axum::response::IntoResponse {
    (
        axum::http::StatusCode::NOT_FOUND,
        axum::Json(serde_json::json!({
            "code": 404,
            "msg": "请求的资源不存在"
        })),
    )
}

/// 构建 CORS 层（从配置读取 Origin 白名单）
///
/// - allow_methods: GET/POST/PUT/DELETE/OPTIONS
/// - allow_headers: authorization/content-type/accept
/// - allow_credentials: true（支持 Cookie 传递）
/// - allow_origin: 从 config.toml 的 server.cors_origins 读取
fn build_cors_layer(server_config: &ServerConfig) -> CorsLayer {
    // 过滤通配符 "*"：allow_credentials(true) 与 allow_origin: * 不兼容
    // 若运维误配置 "*"，浏览器会拒绝所有带凭据的跨域请求
    let origins: Vec<HeaderValue> = server_config
        .cors_origins
        .iter()
        .filter(|o| o.as_str() != "*")
        .filter_map(|o| o.parse().ok())
        .collect();
    if origins.is_empty() {
        tracing::warn!("CORS origins 为空或仅含通配符，CORS 将拒绝所有跨域请求");
    }

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

#[cfg(test)]
mod tests {
    use super::extract_cookie_token;
    use axum::http::{HeaderMap, HeaderValue};

    /// Cookie 提取：命中 / 缺失 / 多 cookie / 空值 / 无 Cookie 头
    #[test]
    fn extract_cookie_token_parses_admin_token() {
        let mut h = HeaderMap::new();
        h.insert(
            axum::http::header::COOKIE,
            HeaderValue::from_static("theme=dark; Admin-Token=abc.def.ghi; other=1"),
        );
        assert_eq!(
            extract_cookie_token(&h, "Admin-Token").as_deref(),
            Some("abc.def.ghi")
        );
        // 名称不匹配
        assert_eq!(extract_cookie_token(&h, "Admin-Token-Missing"), None);
        // 空值视为未提供
        let mut empty = HeaderMap::new();
        empty.insert(
            axum::http::header::COOKIE,
            HeaderValue::from_static("Admin-Token=; a=b"),
        );
        assert_eq!(extract_cookie_token(&empty, "Admin-Token"), None);
        // 无 Cookie 头
        assert_eq!(extract_cookie_token(&HeaderMap::new(), "Admin-Token"), None);
    }
}
