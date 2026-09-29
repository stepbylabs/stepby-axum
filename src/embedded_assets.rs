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
/// 根据编译模式自动切换：
/// - 生产模式：从嵌入资源读取
/// - 开发模式：从文件系统 `frontend-dist/` 读取
pub async fn serve_spa(req: Request) -> Response {
    #[cfg(not(debug_assertions))]
    {
        serve_embedded(req).await
    }
    #[cfg(debug_assertions)]
    {
        serve_from_fs(req).await
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

#[cfg(not(debug_assertions))]
pub async fn serve_embedded(req: Request) -> Response {
    let path = req.uri().path().to_string();
    let clean_path = path.trim_start_matches('/');

    // 优先尝试请求的路径
    if !clean_path.is_empty()
        && let Some(file) = EmbeddedAssets::get(clean_path)
    {
        return build_response(clean_path, file);
    }

    // SPA fallback：未匹配的路径返回 index.html（前端路由处理）
    if is_static_asset(clean_path) {
        return (StatusCode::NOT_FOUND, "Not Found").into_response();
    }

    if let Some(file) = EmbeddedAssets::get("index.html") {
        return build_response("index.html", file);
    }

    (
        StatusCode::INTERNAL_SERVER_ERROR,
        "Frontend dist not embedded. Run `pnpm build` in stepby-vue directory first.",
    )
        .into_response()
}

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
pub async fn serve_embedded(req: Request) -> Response {
    serve_from_fs(req).await
}

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

/// 从文件系统读取前端资源 —— 开发模式
#[cfg(debug_assertions)]
async fn serve_from_fs(req: Request) -> Response {
    let path = req.uri().path().to_string();
    let clean_path = path.trim_start_matches('/');

    // 优先尝试请求的路径
    if !clean_path.is_empty() {
        let file_path = format!("frontend-dist/{}", clean_path);
        // 安全检查：防止路径穿越（如 ../../../etc/passwd）
        if is_safe_path(&file_path)
            && let Ok(content) = tokio::fs::read(&file_path).await
        {
            return build_fs_response(&file_path, content);
        }
    }

    // SPA fallback：未匹配的路径返回 index.html
    if is_static_asset(clean_path) {
        return (StatusCode::NOT_FOUND, "Not Found").into_response();
    }

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

/// 列出嵌入的所有文件（仅用于调试）
#[cfg(debug_assertions)]
#[allow(dead_code)]
pub fn list_embedded_files() -> Vec<String> {
    // 开发模式下从文件系统列出
    let mut files = Vec::new();
    if let Ok(entries) = std::fs::read_dir("frontend-dist") {
        for entry in entries.flatten() {
            if let Ok(name) = entry.file_name().into_string() {
                files.push(name);
            }
        }
    }
    files
}
