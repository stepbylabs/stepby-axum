// stepby-axum/src/middleware/security_headers.rs
//! 安全响应头中间件
//!
//! 为所有响应注入标准安全响应头，缓解常见 Web 安全风险（REGRESS-005：补全 HSTS / CSP / Cache-Control）：
//! - X-Content-Type-Options: nosniff — 禁止 MIME 嗅探
//! - X-Frame-Options: DENY — 禁止页面被嵌入 iframe（防点击劫持）
//! - X-XSS-Protection: 1; mode=block — 启用浏览器 XSS 过滤器
//! - Referrer-Policy: strict-origin-when-cross-origin — 限制 Referrer 泄露
//! - X-Permitted-Cross-Domain-Policies: none — 禁止 Flash/PDF 跨域策略
//! - Strict-Transport-Security — HSTS，强制 HTTPS（生产环境必选，开发环境浏览器自动忽略 HTTP）
//! - Content-Security-Policy — 限制资源加载来源（主要保护 Swagger UI 页面）
//! - Cache-Control: no-store — 禁止缓存 API 响应（防止敏感数据泄漏）
//! - Permissions-Policy — 禁用浏览器敏感能力（摄像头/麦克风/地理位置/支付）
//!
//! 挂载位置：全局最外层（在 CORS / Trace 之前），确保所有响应都带安全头。
//!
//! 特例：Swagger UI 路径（`/swagger-ui`、`/swagger-ui/index.html`）需要被前端 iframe 嵌入，
//! 资源从本地 `/swagger-ui-static/*` 加载（已自托管，无 CDN 依赖），因此对这些路径：
//! - `X-Frame-Options` 改为 `SAMEORIGIN`（允许同源 iframe 嵌入）
//! - `Content-Security-Policy` 使用严格同源策略（资源均在同源下）

use axum::http::{HeaderMap, HeaderValue, Uri};
use axum::response::Response;

/// 判断请求路径是否为 Swagger UI 相关路径（需要被前端 iframe 嵌入）
fn is_swagger_path(uri: &Uri) -> bool {
    let path = uri.path();
    path == "/swagger-ui" || path == "/swagger-ui/index.html"
}

/// 判断请求路径是否为带 hash 的静态资源（`/static/js/xxx-[hash].js`、`/static/css/xxx-[hash].css`）
/// 这类资源使用内容 hash 命名，可长期缓存以提升性能
fn is_hashed_static_asset(uri: &Uri) -> bool {
    let path = uri.path();
    if !path.starts_with("/static/") {
        return false;
    }
    // 匹配 [8位以上hash].js 或 [8位以上hash].css（vite 构建产物格式）
    // 例：/static/js/index-C4xhYXkT.js、/static/css/index-abc123.css
    if let Some(name) = path.rsplit('/').next()
        && (name.ends_with(".js")
            || name.ends_with(".css")
            || name.ends_with(".woff2")
            || name.ends_with(".woff")
            || name.ends_with(".ttf"))
    {
        // 验证文件名包含 hash 段（中划线 + 8 位以上字母数字）
        let has_hash = name
            .split('-')
            .next_back()
            .map(|s| {
                s.trim_end_matches(".js")
                    .trim_end_matches(".css")
                    .trim_end_matches(".woff2")
                    .trim_end_matches(".woff")
                    .trim_end_matches(".ttf")
                    .len()
                    >= 6
            })
            .unwrap_or(false);
        return has_hash;
    }
    false
}

/// 安全响应头中间件
///
/// 在响应返回前注入标准安全响应头。
/// 已存在的同名 header 不会被覆盖（避免与 CORS 等中间件冲突）。
pub async fn security_headers(
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> Response {
    // 在 request 被 next.run 消费前提取路径，用于判断是否为 Swagger UI 路径
    let is_swagger = is_swagger_path(request.uri());
    let is_static = is_hashed_static_asset(request.uri());

    let mut response = next.run(request).await;
    let headers = response.headers_mut();
    // 仅在响应未设置该头时插入，避免覆盖业务层或 CORS 中间件已设置的同名头
    insert_if_absent(headers, "x-content-type-options", "nosniff");

    // X-Frame-Options：
    // - Swagger UI 路径：SAMEORIGIN（允许同源 iframe 嵌入，前端"系统接口"页面需要）
    // - 其他路径：DENY（防点击劫持）
    if is_swagger {
        insert_if_absent(headers, "x-frame-options", "SAMEORIGIN");
    } else {
        insert_if_absent(headers, "x-frame-options", "DENY");
    }

    insert_if_absent(headers, "x-xss-protection", "1; mode=block");
    insert_if_absent(
        headers,
        "referrer-policy",
        "strict-origin-when-cross-origin",
    );
    insert_if_absent(headers, "x-permitted-cross-domain-policies", "none");
    // REGRESS-005：补全 HSTS / CSP / Cache-Control
    // HSTS：max-age=31536000（1年）+ includeSubDomains
    // 开发环境 HTTP 下浏览器自动忽略此头，生产环境 HTTPS 下强制加密连接
    insert_if_absent(
        headers,
        "strict-transport-security",
        "max-age=31536000; includeSubDomains",
    );
    // CSP：限制资源加载来源
    // - Swagger UI 路径：本地自托管资源，使用严格同源策略（不再依赖 unpkg CDN）
    // - 其他路径：同样严格同源策略，保护 API 响应不被注入外部资源
    if is_swagger {
        // Swagger UI HTML 从同源 /swagger-ui-static/* 加载本地资源
        insert_if_absent(
            headers,
            "content-security-policy",
            "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'",
        );
    } else {
        // CSP：非 Swagger 路径（即前端 SPA 业务页）。
        // 前端为 Vite 构建产物，脚本/样式均为带 hash 的外链资源，无需 'unsafe-inline'；
        // 收紧为仅同源，降低 XSS 注入外部资源的风险（Swagger 路径仍保留 inline 以兼容其内联脚本）。
        // - default-src 'self'：仅允许同源资源
        // - script-src 'self'：仅允许同源外链脚本（构建产物）
        // - style-src 'self' 'unsafe-inline'：保留 inline 以兼容 Element Plus 动态样式（低风险）
        // - img-src 'self' data: blob:：允许 data URI 与 blob URL 图片。
        //   blob: 必需——vue-cropper 1.1.4 在现代浏览器将工作图/预览图设为
        //   URL.createObjectURL 产物（checkOrientationImage → toBlob），缺失时
        //   头像裁剪器工作图与预览全部被拦，裁剪/上传 UI 结构性不可用
        //   （批三十七 e2e F129 实证 CSP violation）。blob URL 受同源作用域约束，
        //   无法用于加载外部资源，风险可控。
        insert_if_absent(
            headers,
            "content-security-policy",
            "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; connect-src 'self'",
        );
    }
    // Cache-Control：根据资源类型区分缓存策略
    // - 带 hash 的静态资源（/static/js/xxx-[hash].js）：长期缓存（1年 immutable），因 hash 变化即新文件
    // - API 响应、HTML、uploads：禁止缓存，防止敏感数据（token/用户信息）通过缓存泄漏
    if is_static {
        insert_if_absent(
            headers,
            "cache-control",
            "public, max-age=31536000, immutable",
        );
    } else {
        insert_if_absent(
            headers,
            "cache-control",
            "no-store, no-cache, must-revalidate, private",
        );
    }
    // Permissions-Policy：禁用浏览器敏感能力（摄像头/麦克风/地理位置/支付），
    // 防止恶意脚本或第三方嵌入内容调用这些 API（P0-7 改进）
    insert_if_absent(
        headers,
        "permissions-policy",
        "camera=(), microphone=(), geolocation=(), payment=()",
    );
    response
}

/// 仅在 header 不存在时插入，避免覆盖已有值
///
/// `name` 必须是小写 ASCII 字符串（HTTP header name 规范）。
fn insert_if_absent(headers: &mut HeaderMap<HeaderValue>, name: &'static str, value: &'static str) {
    if !headers.contains_key(name)
        && let Ok(val) = HeaderValue::from_str(value)
    {
        headers.insert(axum::http::HeaderName::from_static(name), val);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::Router;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use axum::routing::get;
    use tower::ServiceExt;

    fn test_router() -> Router {
        async fn handler() -> &'static str {
            "ok"
        }
        Router::new()
            .route("/swagger-ui", get(handler))
            .route("/swagger-ui/index.html", get(handler))
            .route("/api", get(handler))
            .layer(axum::middleware::from_fn(security_headers))
    }

    #[tokio::test]
    async fn test_swagger_path_uses_sameorigin() {
        let app = test_router();
        let res = app
            .oneshot(
                Request::builder()
                    .uri("/swagger-ui")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        assert_eq!(res.headers().get("x-frame-options").unwrap(), "SAMEORIGIN");
        // CSP 应使用严格同源策略（本地自托管资源，不再需要 unpkg.com 白名单）
        let csp = res
            .headers()
            .get("content-security-policy")
            .unwrap()
            .to_str()
            .unwrap();
        assert!(
            !csp.contains("unpkg.com"),
            "CSP should not allow unpkg.com (resources are self-hosted)"
        );
        assert!(csp.contains("'self'"), "CSP should allow self for swagger");
    }

    #[tokio::test]
    async fn test_swagger_index_path_uses_sameorigin() {
        let app = test_router();
        let res = app
            .oneshot(
                Request::builder()
                    .uri("/swagger-ui/index.html")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.headers().get("x-frame-options").unwrap(), "SAMEORIGIN");
    }

    #[tokio::test]
    async fn test_non_swagger_path_uses_deny() {
        let app = test_router();
        let res = app
            .oneshot(Request::builder().uri("/api").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(res.headers().get("x-frame-options").unwrap(), "DENY");
        // CSP 不应包含 unpkg.com
        let csp = res
            .headers()
            .get("content-security-policy")
            .unwrap()
            .to_str()
            .unwrap();
        assert!(
            !csp.contains("unpkg.com"),
            "CSP should not allow unpkg.com for non-swagger paths"
        );
    }

    #[test]
    fn test_is_swagger_path_matches() {
        let parse = |s: &str| s.parse::<Uri>().unwrap();
        assert!(is_swagger_path(&parse("/swagger-ui")));
        assert!(is_swagger_path(&parse("/swagger-ui/index.html")));
        assert!(!is_swagger_path(&parse("/api")));
        assert!(!is_swagger_path(&parse("/swagger-ui/foo"))); // 子路径不匹配
        assert!(!is_swagger_path(&parse("/api-docs/openapi.json"))); // OpenAPI JSON 不需要 iframe
    }

    // ---------- is_hashed_static_asset ----------

    #[test]
    fn test_is_hashed_static_asset_true_for_hashed_js_css_fonts() {
        let parse = |s: &str| s.parse::<Uri>().unwrap();
        assert!(is_hashed_static_asset(&parse(
            "/static/js/index-C4xhYXkT.js"
        )));
        assert!(is_hashed_static_asset(&parse(
            "/static/css/index-abc123.css"
        )));
        assert!(is_hashed_static_asset(&parse(
            "/static/ttf/codicon-ngg6Pgfi.ttf"
        )));
        assert!(is_hashed_static_asset(&parse(
            "/static/fonts/font-Dx9g7Kq2.woff2"
        )));
        assert!(is_hashed_static_asset(&parse(
            "/static/fonts/icon-wJ4Pq8zA.woff"
        )));
    }

    #[test]
    fn test_is_hashed_static_asset_false_without_hash_segment() {
        let parse = |s: &str| s.parse::<Uri>().unwrap();
        // 无 hash 段或 hash 过短 → false
        assert!(!is_hashed_static_asset(&parse("/static/js/app.js")));
        assert!(!is_hashed_static_asset(&parse("/static/js/short-ab.js"))); // hash 仅 2 位
        assert!(!is_hashed_static_asset(&parse("/static/css/index.css")));
    }

    #[test]
    fn test_is_hashed_static_asset_false_for_other_extensions_and_paths() {
        let parse = |s: &str| s.parse::<Uri>().unwrap();
        // 非 /static/ 前缀或非白名单扩展名 → false
        assert!(!is_hashed_static_asset(&parse("/api/data")));
        assert!(!is_hashed_static_asset(&parse("/static")));
        assert!(!is_hashed_static_asset(&parse("/static/")));
        assert!(!is_hashed_static_asset(&parse(
            "/static/img/logo-C4xhYXkT.png"
        )));
        assert!(!is_hashed_static_asset(&parse(
            "/static/js/index-C4xhYXkT.js.map"
        )));
    }

    // ---------- insert_if_absent ----------

    #[test]
    fn test_insert_if_absent_inserts_when_missing() {
        let mut headers = HeaderMap::new();
        insert_if_absent(&mut headers, "x-content-type-options", "nosniff");
        assert_eq!(
            headers
                .get("x-content-type-options")
                .unwrap()
                .to_str()
                .unwrap(),
            "nosniff"
        );
    }

    #[test]
    fn test_insert_if_absent_does_not_overwrite_existing() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-content-type-options",
            HeaderValue::from_static("custom-value"),
        );
        insert_if_absent(&mut headers, "x-content-type-options", "nosniff");
        assert_eq!(
            headers
                .get("x-content-type-options")
                .unwrap()
                .to_str()
                .unwrap(),
            "custom-value",
            "已存在的同名头不应被覆盖"
        );
    }

    #[test]
    fn test_insert_if_absent_multiple_headers() {
        let mut headers = HeaderMap::new();
        insert_if_absent(&mut headers, "a", "1");
        insert_if_absent(&mut headers, "b", "2");
        insert_if_absent(&mut headers, "a", "3"); // a 已存在，不应覆盖
        assert_eq!(headers.get("a").unwrap().to_str().unwrap(), "1");
        assert_eq!(headers.get("b").unwrap().to_str().unwrap(), "2");
    }

    // ---------- 中间件：静态资源缓存策略 ----------

    #[tokio::test]
    async fn test_static_asset_gets_immutable_cache_control() {
        let app = test_router();
        let res = app
            .oneshot(
                Request::builder()
                    .uri("/static/js/index-C4xhYXkT.js")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let cc = res
            .headers()
            .get("cache-control")
            .unwrap()
            .to_str()
            .unwrap();
        assert!(
            cc.contains("immutable"),
            "带 hash 静态资源应长期缓存，实际 cache-control: {cc}"
        );
    }

    #[tokio::test]
    async fn test_non_static_api_gets_no_store_cache_control() {
        let app = test_router();
        let res = app
            .oneshot(Request::builder().uri("/api").body(Body::empty()).unwrap())
            .await
            .unwrap();
        let cc = res
            .headers()
            .get("cache-control")
            .unwrap()
            .to_str()
            .unwrap();
        assert!(
            cc.contains("no-store"),
            "API 响应禁止缓存，实际 cache-control: {cc}"
        );
    }
}
