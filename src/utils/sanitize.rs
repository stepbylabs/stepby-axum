// axum-backend/src/utils/sanitize.rs
//! HTML 危险内容净化（P0-R19-002）
//!
//! 作为前端净化的补充防线，在后端入库前移除明显危险的 HTML 标签和属性。
//! 采用双层防御策略：
//! 1. 移除完全危险的标签块（script、iframe、object、embed 等）
//! 2. 移除所有 on* 事件属性和 javascript:/vbscript: 协议
//!
//! 注意：这是基于正则的简化净化，无法覆盖所有 mutation XSS 向量。
//! 前端已使用基于 DOMParser 的白名单净化（DetailView.vue），此处为第二道防线。

use regex::Regex;
use std::sync::LazyLock;

/// script 标签块正则（连同内容一起移除）
static SCRIPT_BLOCK_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)<\s*script\b[^>]*>[\s\S]*?<\s*/\s*script\s*>")
        .expect("无效的 script 标签正则")
});

/// style 标签块正则（连同内容一起移除）
static STYLE_BLOCK_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)<\s*style\b[^>]*>[\s\S]*?<\s*/\s*style\s*>")
        .expect("无效的 style 标签正则")
});

/// 未闭合的 script/style 标签正则（无对应闭标签时移除开标签）
static SCRIPT_STYLE_OPEN_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)<\s*/?\s*(script|style)\b[^>]*/?>")
        .expect("无效的 script/style 开标签正则")
});

/// 其他危险标签正则（只移除标签，保留内容）
/// iframe、object、embed、applet、noscript、template、form、input、textarea、select、button、link、meta
static OTHER_DANGEROUS_TAG_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)<\s*/?\s*(iframe|object|embed|applet|noscript|template|form|input|textarea|select|button|link|meta)\b[^>]*/?>")
        .expect("无效的危险标签正则")
});

/// on* 事件属性正则（onclick、onerror、onload 等）
static EVENT_ATTR_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)\s+on\w+\s*=\s*("[^"]*"|'[^']*'|[^\s>]+)"#)
        .expect("无效的事件属性正则")
});

/// 危险协议正则（javascript:、vbscript:）
static DANGEROUS_PROTO_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(javascript|vbscript):"#).expect("无效的危险协议正则")
});

/// data:text/html URI 正则（可嵌入 HTML/JS）
static DATA_HTML_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)data:text/html").expect("无效的 data URI 正则")
});

/// 净化 HTML 内容
///
/// 流程：
/// 1. 移除 script/style 标签块（连同内容）
/// 2. 移除未闭合的 script/style 标签
/// 3. 移除其他危险标签（只移除标签，保留内容）
/// 4. 移除所有 on* 事件属性
/// 5. 将 javascript:/vbscript: 协议替换为安全占位符
/// 6. 将 data:text/html 替换为安全占位符
pub fn sanitize_html(html: &str) -> String {
    if html.is_empty() {
        return String::new();
    }
    let s = SCRIPT_BLOCK_RE.replace_all(html, "");
    let s = STYLE_BLOCK_RE.replace_all(&s, "");
    let s = SCRIPT_STYLE_OPEN_RE.replace_all(&s, "");
    let s = OTHER_DANGEROUS_TAG_RE.replace_all(&s, "");
    let s = EVENT_ATTR_RE.replace_all(&s, "");
    let s = DANGEROUS_PROTO_RE.replace_all(&s, "safe-disabled:");
    let s = DATA_HTML_RE.replace_all(&s, "data:text/plain");
    s.into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_removes_script_block() {
        let input = "<p>hello</p><script>alert(1)</script>";
        let result = sanitize_html(input);
        assert!(!result.contains("script"));
        assert!(!result.contains("alert"));
        assert!(result.contains("hello"));
    }

    #[test]
    fn test_removes_event_attrs() {
        let input = "<img src=x onerror=alert(1)>";
        let result = sanitize_html(input);
        assert!(!result.contains("onerror"));
        assert!(result.contains("src"));
    }

    #[test]
    fn test_removes_javascript_protocol() {
        let input = "<a href=\"javascript:alert(1)\">click</a>";
        let result = sanitize_html(input);
        assert!(!result.contains("javascript:"));
        // 验证安全内容（链接文本）被保留
        assert!(result.contains("click"), "应保留链接文本 'click'");
        // 验证 javascript: 被替换为安全占位符
        assert!(result.contains("safe-disabled:"), "javascript: 应替换为 safe-disabled:");
    }

    #[test]
    fn test_removes_iframe() {
        let input = "<iframe src=\"evil.com\"></iframe>";
        let result = sanitize_html(input);
        assert!(!result.contains("iframe"));
    }

    #[test]
    fn test_preserves_safe_content() {
        let input = "<p>安全内容 <strong>加粗</strong></p>";
        let result = sanitize_html(input);
        assert!(result.contains("安全内容"));
        assert!(result.contains("加粗"));
    }
}
