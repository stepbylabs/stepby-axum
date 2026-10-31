//! 前端静态资源服务模块（场景2：开发/生产双模式）
//!
//! ## 架构
//! - **开发模式**（`debug_assertions`）：通过 `tower-http::services::ServeDir` 读取本地
//!   `frontend-dist/` 目录，前端修改后执行 `pnpm build` 即可生效，无需重编译 Rust。
//! - **生产模式**（`not(debug_assertions)`）：通过 `rust-embed` 在编译时将
//!   `frontend-dist/` 目录嵌入到二进制中，实现单可执行文件部署。
//!
//! ## 切换逻辑
//! 使用 `#[cfg(debug_assertions)]` / `#[cfg(not(debug_assertions))]` 条件编译：
//! - `cargo run`（debug 构建）→ 自动走 ServeDir 模式
//! - `cargo build --release`（release 构建）→ 自动走 rust-embed 嵌入模式
//!
//! ## 环境变量覆盖
//! `EMBEDDED_FRONTEND` 环境变量可在运行时强制覆盖默认行为：
//! - 开发模式下设置 `EMBEDDED_FRONTEND=true` → 强制启用嵌入模式（需 frontend-dist 存在）
//! - 生产模式下设置 `EMBEDDED_FRONTEND=false` → 强制禁用嵌入模式（不推荐，仅用于调试）
//!
//! ## 构建流程
//! 1. `pnpm build`（stepby-vue 目录）→ 生成 `stepby-vue/dist/`
//! 2. 构建脚本将 `stepby-vue/dist/` 复制到 `stepby-axum/frontend-dist/`
//! 3. `cargo build --release` → rust-embed 自动嵌入 frontend-dist/
//!
//! ## 重要约束
//! - 生产模式下若 `frontend-dist` 目录不存在，编译会失败（rust-embed 强制要求目录存在）
//! - 开发模式下若 `frontend-dist` 目录不存在，ServeDir 会返回 404（不阻塞编译）
//! - 使用 `frontend-dist/`（项目内路径）而非 `../stepby-vue/dist/` 是为了兼容 cross 交叉编译

use axum::body::Body;
use axum::extract::Request;
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};

// ============================================================================
// 生产模式：rust-embed 嵌入静态资源
// ============================================================================

#[cfg(not(debug_assertions))]
use rust_embed::RustEmbed;

/// 嵌入的前端静态资源（仅生产模式编译）
///
/// `folder` 指向前端构建产物目录（相对于 Cargo.toml 所在目录）
/// 构建脚本（build-all.ps1）会先将 `stepby-vue/dist` 复制到此处，再编译后端
#[cfg(not(debug_assertions))]
#[derive(RustEmbed)]
#[folder = "frontend-dist/"]
pub struct EmbeddedAssets;

// ============================================================================
// 统一接口：serve_spa（两种模式共用，供 router fallback 与 spa_fallback_middleware 调用）
// ============================================================================

/// 统一 SPA 服务入口
///
/// 根据编译模式自动切换：生产模式读嵌入资源，开发模式读 `frontend-dist/` 文件系统。
///
/// b143：**只服务真实的静态资源与 index.html，不再为"任意未匹配路径"返回 HTML**。
/// 前端的深链兜底由调用方（router 的 `spa_or_api_not_found` 分派 / `spa_fallback`
/// 中间件）按"这是不是浏览器导航"决定；把这件事留在这里，API 消费者拿到的
/// 未知路径就会被一张 index.html 以 200 冒充成功。
pub async fn serve_spa(req: Request) -> Response {
    let path = req.uri().path().to_string();
    if let Some(resp) = try_serve_asset(&path).await {
        return resp;
    }
    let clean_path = path.trim_start_matches('/');
    if !clean_path.is_empty() && is_static_asset(clean_path) {
        return (StatusCode::NOT_FOUND, "Not Found").into_response();
    }
    serve_index().await
}

/// 命中**真实存在**的静态资源时返回其响应；未命中返回 `None`。
///
/// 未命中与"被安全策略拒绝"是两种结局：sourcemap 类被拒资源返回 `Some(404)`
/// （不能落回 index.html，否则一次猜测就能拿到 HTML 冒充的"成功"），
/// 而"文件不存在"必须交回调用方决定 SPA 还是 JSON 404。
///
/// 参数刻意取 `&str` 而不是 `&Request`：`Request<Body>` 不是 `Sync`，
/// 整个引用跨 `.await` 会让返回的 future 不是 `Send` ⇒ 无法作为 axum Handler/中间件
/// （b143 实测：编译期 `Handler<_, _>` 未实现的报错，真因是这一点）。
pub async fn try_serve_asset(path: &str) -> Option<Response> {
    let clean_path = path.trim_start_matches('/').to_string();
    if clean_path.is_empty() {
        return None;
    }
    if is_denied_public_asset(&clean_path) {
        return Some((StatusCode::NOT_FOUND, "Not Found").into_response());
    }
    #[cfg(not(debug_assertions))]
    {
        EmbeddedAssets::get(&clean_path).map(|file| build_response(&clean_path, file))
    }
    #[cfg(debug_assertions)]
    {
        let file_path = format!("frontend-dist/{}", clean_path);
        // 安全检查：防止路径穿越（如 ../../../etc/passwd）
        if !is_safe_path(&file_path) {
            return Some((StatusCode::NOT_FOUND, "Not Found").into_response());
        }
        tokio::fs::read(&file_path)
            .await
            .ok()
            .map(|content| build_fs_response(&file_path, content))
    }
}

/// 是否启用嵌入模式
///
/// - 生产模式（release）：默认 true，可通过 `EMBEDDED_FRONTEND=false` 禁用
/// - 开发模式（debug）：默认 false，可通过 `EMBEDDED_FRONTEND=true` 启用
pub fn is_embedded_mode() -> bool {
    #[cfg(not(debug_assertions))]
    {
        match std::env::var("EMBEDDED_FRONTEND") {
            Ok(v) => !matches!(v.to_lowercase().as_str(), "false" | "0" | "no"),
            Err(_) => true,
        }
    }
    #[cfg(debug_assertions)]
    {
        match std::env::var("EMBEDDED_FRONTEND") {
            Ok(v) => matches!(v.to_lowercase().as_str(), "true" | "1" | "yes"),
            Err(_) => false,
        }
    }
}

// ============================================================================
// 生产模式实现：从嵌入资源服务
// ============================================================================

/// 根路径 handler（`/`）
#[cfg(not(debug_assertions))]
pub async fn serve_index() -> Response {
    if let Some(file) = EmbeddedAssets::get("index.html") {
        return build_response("index.html", file);
    }
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        "Frontend dist not embedded. Run `pnpm build` in stepby-vue directory first.",
    )
        .into_response()
}

/// 构建响应（含 Content-Type 与缓存头）—— 生产模式
#[cfg(not(debug_assertions))]
fn build_response(path: &str, file: rust_embed::EmbeddedFile) -> Response {
    // MIME 类型推断
    // 修复：mime_guess 默认将 .ts 识别为 video/vnd.dlna.mpeg-tts（MPEG-2 Transport Stream），
    // 但前端构建产物中的 .ts 文件是 TypeScript 编译后的 JavaScript 模块（Vite 的 worker 格式），
    // 必须返回 application/javascript 才能被浏览器作为模块脚本加载。
    let guessed = mime_guess::from_path(path).first_or_octet_stream();
    let mime_str: &str =
        if path.to_lowercase().ends_with(".ts") || path.to_lowercase().ends_with(".mjs") {
            "application/javascript"
        } else {
            guessed.as_ref()
        };

    let body = Body::from(file.data.into_owned());
    let mut response = Response::builder().status(StatusCode::OK).header(
        header::CONTENT_TYPE,
        HeaderValue::from_str(mime_str)
            .unwrap_or(HeaderValue::from_static("application/octet-stream")),
    );

    // 带哈希的静态资源设置长期不可变缓存；index.html 不缓存
    if path != "index.html" && (path.starts_with("static/") || path.starts_with("assets/")) {
        response = response.header(
            header::CACHE_CONTROL,
            HeaderValue::from_static(crate::common::constants::CACHE_IMMUTABLE_SECS),
        );
    } else {
        response = response.header(
            header::CACHE_CONTROL,
            HeaderValue::from_static("no-cache, no-store, must-revalidate"),
        );
    }

    response
        .body(body)
        .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
}

// ============================================================================
// 开发模式实现：从文件系统服务（ServeDir 风格，使用 tokio::fs 异步读取）
// ============================================================================

#[cfg(debug_assertions)]
pub async fn serve_index() -> Response {
    match tokio::fs::read("frontend-dist/index.html").await {
        Ok(content) => build_fs_response("index.html", content),
        Err(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Frontend dist not found. Run `pnpm build` in stepby-vue directory first.",
        )
            .into_response(),
    }
}

/// 构建文件系统响应 —— 开发模式
#[cfg(debug_assertions)]
fn build_fs_response(path: &str, content: Vec<u8>) -> Response {
    // MIME 类型推断（与生产模式保持一致）
    let guessed = mime_guess::from_path(path).first_or_octet_stream();
    let mime_str: &str =
        if path.to_lowercase().ends_with(".ts") || path.to_lowercase().ends_with(".mjs") {
            "application/javascript"
        } else {
            guessed.as_ref()
        };

    let body = Body::from(content);
    let mut response = Response::builder().status(StatusCode::OK).header(
        header::CONTENT_TYPE,
        HeaderValue::from_str(mime_str)
            .unwrap_or(HeaderValue::from_static("application/octet-stream")),
    );

    // 开发模式：所有资源均不缓存，便于调试时及时看到修改
    let cache_control = if path != "index.html"
        && (path.starts_with("frontend-dist/static/") || path.starts_with("frontend-dist/assets/"))
    {
        "no-cache"
    } else {
        "no-cache, no-store, must-revalidate"
    };
    response = response.header(
        header::CACHE_CONTROL,
        HeaderValue::from_static(cache_control),
    );

    response
        .body(body)
        .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
}

/// 路径安全检查（防止路径穿越攻击）
///
/// 注意：此函数仅用于开发模式（#[cfg(debug_assertions)]）。
/// 生产环境使用 axum::serve_dir 或反向代理提供静态资源，不经过此函数。
#[cfg(debug_assertions)]
fn is_safe_path(path: &str) -> bool {
    use std::path::Path;
    let p = Path::new(path);
    // 检查路径组件中是否包含 .. 或绝对路径
    !p.components().any(|c| {
        matches!(
            c,
            std::path::Component::ParentDir | std::path::Component::RootDir
        )
    })
}

// ============================================================================
// 公共辅助函数（两种模式共用）
// ============================================================================

/// 判断是否为静态资源（根据扩展名）
///
/// 这些后缀的文件如果找不到，应返回 404 而非 index.html
fn is_static_asset(path: &str) -> bool {
    let lower = path.to_lowercase();
    [
        ".js", ".mjs", ".css", ".map", ".json", ".xml", ".txt", ".png", ".jpg", ".jpeg", ".gif",
        ".svg", ".ico", ".webp", ".woff", ".woff2", ".ttf", ".eot", ".otf", ".mp4", ".mp3",
        ".webm", ".pdf", ".zip",
    ]
    .iter()
    .any(|ext| lower.ends_with(ext))
}

/// 禁止对外下发的静态资源（两种服务模式共用）
///
/// sourcemap 含完整前端源码（`sourcesContent`），而本模块的服务方式是
/// **存在即下发**：只要 `frontend-dist/` 里有 `.map`，访客按入口 chunk 名加
/// `.map` 即可下载（b100 实测 `/static/js/index-*.js.map` 返回 200/20MB，
/// 与 vite 注释里"浏览器不会自动拉取 ⇒ 源码不暴露"只隔一次猜测）。
/// embedded 构建已不再产出 map（vite.config.ts 按 mode 关闭），但历史产物、
/// 手工拷贝、反代档 dist 的误拷都可能把它带进来 ⇒ 服务端必须自己拒绝，
/// 不能把安全边界放在"构建侧不会生成"上。
///
/// b101：判定必须按**文件系统实际会打开的名字**，不能按 URL 字符串后缀。
/// Windows 会去掉尾随的点与空格、把 `x.map::$DATA` 当成同名文件的默认数据流，
/// 而 HTTP 路径层这三者是完全不同的串 —— 实测改造前 `.map` 返回 404，而
/// `.map.` 与 `.map::$DATA` 都返回 200 且带出 map 正文。因此先做一次百分号解码，
/// 再按「截 NTFS 流后缀 → 去尾随点/空格 → 小写」归一后判 `.map`。
fn is_denied_public_asset(path: &str) -> bool {
    is_map_asset(path) || is_map_asset(&percent_decode(path))
}

/// 单一名字的 `.map` 判定（Windows 打开名归一：NTFS 流后缀 / 尾随点与空格 / 大小写）
fn is_map_asset(path: &str) -> bool {
    // `:` 在合法静态资源名里不出现；截断它即同时覆盖 `file.map::$DATA` 与 `file.map:zone`
    let no_stream = path.split(':').next().unwrap_or(path);
    no_stream
        .trim_end_matches(['.', ' '])
        .to_ascii_lowercase()
        .ends_with(".map")
}

/// 仅用于拒绝集合的百分号解码（结果绝不用于拼路径）
fn percent_decode(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%'
            && i + 2 < bytes.len()
            && let (Some(hi), Some(lo)) = (hex_val(bytes[i + 1]), hex_val(bytes[i + 2]))
        {
            out.push(hi * 16 + lo);
            i += 3;
            continue;
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sourcemap_is_never_public() {
        assert!(is_denied_public_asset("static/js/index-CoIDG-sZ.js.map"));
        assert!(is_denied_public_asset("STATIC/JS/INDEX-ABC.JS.MAP"));
        // 正常产物不得误伤
        assert!(!is_denied_public_asset("static/js/index-CoIDG-sZ.js"));
        assert!(!is_denied_public_asset("static/css/index-abc.css"));
        assert!(!is_denied_public_asset("index.html"));
        assert!(!is_denied_public_asset("map.png"));
        assert!(!is_denied_public_asset(""));
    }

    /// b101 实测的两种绕过：`.map.` 与 `.map::$DATA` 在改造前都返回 200 正文。
    /// 判据按文件系统打开名归一后，URL 层的写法不再有第二种结局。
    #[test]
    fn sourcemap_denial_follows_windows_open_identity() {
        for path in [
            "static/js/index-a.js.map.",
            "static/js/index-a.js.map..",
            "static/js/index-a.js.map ",
            "static/js/index-a.js.map::$DATA",
            "static/js/index-a.js.map:zone.Identifier",
            "static/js/index-a.js%2Emap",
            "static/js/index-a.js%2emap.",
            "static/js/index-a%2Ejs.map",
        ] {
            assert!(is_denied_public_asset(path), "必须拒绝：{path}");
        }
        // 不误伤：尾随点只在归一后参与判定，正常名字与"看起来像 map"的资源照常放行
        for path in [
            "static/js/index-a.js",
            "static/js/index-a.js.map.png",
            "static/js/vendor-map.js",
            "static/js/map",
            "index.html.",
        ] {
            assert!(!is_denied_public_asset(path), "不得误伤：{path}");
        }
    }

    #[test]
    fn percent_decode_is_lossless_for_valid_escapes_and_tolerates_garbage() {
        assert_eq!(percent_decode("a%2Eb%2Fc"), "a.b/c");
        assert_eq!(percent_decode("%2e%2E"), "..");
        // 坏的转义按原文保留（多解一次不应吞字符），非 ASCII 字节走 lossy 但不会伪造 `.map`
        assert_eq!(percent_decode("100%"), "100%");
        assert_eq!(percent_decode("%zz.map"), "%zz.map");
        assert!(percent_decode("%e4%b8%ad") == "中");
    }
}
