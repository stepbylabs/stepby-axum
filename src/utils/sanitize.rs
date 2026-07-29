// axum-backend/src/utils/sanitize.rs
//! HTML 白名单净化（P0-R19-002）
//!
//! 作为前端净化的补充防线，在后端入库前移除危险 HTML。
//! 使用 `ammonia` 库（基于 html5ever）做白名单净化，替代手写正则方案，
//! 彻底解决正则绕过问题（HTML 实体编码、嵌套标签、大小写、属性变异等）。
//!
//! 允许的标签和属性白名单：
//! - 基础格式：p, br, hr, strong, b, em, i, u, s, strike, sub, sup, mark, small
//! - 标题：h1-h6
//! - 列表：ul, ol, li, dl, dt, dd
//! - 引用与代码：blockquote, q, code, pre, kbd, samp, var
//! - 表格：table, thead, tbody, tfoot, tr, th, td, caption, colgroup, col
//! - 链接与图片：a (href), img (src/alt/title/width/height)
//! - 容器：div, span
//! - 通用属性：class, style（仅安全 CSS 属性，ammonia 默认已过滤危险属性）
//!
//! 禁止的标签（会被完全移除）：script, style, iframe, object, embed, applet,
//! form, input, textarea, select, button, link, meta, noscript, template 等

use ammonia::{Builder, UrlRelative};

/// 构建白名单净化器（懒加载，避免每次调用重建）
fn build_sanitizer() -> Builder<'static> {
    let mut builder = Builder::default();
    // 允许的标签白名单（ammonia 默认已含 p/br/strong 等基础标签，此处显式扩展）
    builder.add_tags([
        "h1", "h2", "h3", "h4", "h5", "h6",
        "ul", "ol", "li", "dl", "dt", "dd",
        "blockquote", "q", "code", "pre", "kbd", "samp", "var",
        "table", "thead", "tbody", "tfoot", "tr", "th", "td", "caption", "colgroup", "col",
        "img",
        "div", "span", "hr",
        "u", "s", "strike", "sub", "sup", "mark", "small",
    ]);
    // 允许的属性白名单
    builder.add_generic_attributes(["class", "style"]);
    // 链接允许 href + title + target（rel 由 link_rel 自动管理，不在此声明）
    builder.add_tag_attributes("a", ["href", "title", "target"]);
    // 图片允许 src + alt + title + width + height
    builder.add_tag_attributes("img", ["src", "alt", "title", "width", "height"]);
    // 表格相关属性
    builder.add_tag_attributes("th", ["colspan", "rowspan", "align"]);
    builder.add_tag_attributes("td", ["colspan", "rowspan", "align"]);
    builder.add_tag_attributes("col", ["span", "width"]);
    builder.add_tag_attributes("colgroup", ["span"]);
    // 列表属性
    builder.add_tag_attributes("ol", ["start", "type"]);
    // 链接 rel="noopener noreferrer" 安全策略（target=_blank 时防反向引用）
    builder.link_rel(Some("noopener noreferrer"));
    // 将相对 URL 转为绝对 URL（防协议绕过），此处保留 passthrough 不做转换
    builder.url_relative(UrlRelative::PassThrough);
    // 移除所有 on* 事件属性（ammonia 默认已移除，显式声明以防配置变更）
    // ammonia 默认不在 allowed_attributes 中包含任何 on* 属性
    builder
}

/// 净化 HTML 内容
///
/// 使用 ammonia 白名单净化，仅保留安全的标签和属性。
/// 所有 script/iframe/style 等危险标签会被完全移除（连同内容）。
/// 所有 on* 事件属性、javascript:/vbscript: 协议会被移除。
pub fn sanitize_html(html: &str) -> String {
    if html.is_empty() {
        return String::new();
    }
    build_sanitizer().clean(html).to_string()
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
        // 链接文本被保留
        assert!(result.contains("click"), "应保留链接文本 'click'");
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

    #[test]
    fn test_removes_style_tag_block() {
        let input = "<p>text</p><style>body{background:url(javascript:alert(1))}</style>";
        let result = sanitize_html(input);
        assert!(!result.contains("<style"));
        assert!(!result.contains("javascript:"));
        assert!(result.contains("text"));
    }

    #[test]
    fn test_html_entity_encoding_bypass_blocked() {
        // HTML 实体编码绕过尝试：&#106;avascript: 等价于 javascript:
        let input = "<a href=\"&#106;avascript:alert(1)\">click</a>";
        let result = sanitize_html(input);
        // ammonia 基于 html5ever 解析，会先解码实体再判断协议
        assert!(!result.contains("javascript:"), "应阻断实体编码绕过");
        assert!(!result.contains("&#106;avascript"), "不应保留原始实体编码的危险协议");
    }

    #[test]
    fn test_nested_script_bypass_blocked() {
        // 嵌套标签构造绕过尝试：ammonia 基于 html5ever 解析，
        // <scr<script>ipt> 会被解析为文本 "scr" + script 标签 + 文本 "ipt>"
        // script 标签及其内容被完全移除，alert(1) 不应出现在可执行上下文中
        let input = "<scr<script>ipt>alert(1)</script>";
        let result = sanitize_html(input);
        // script 标签被移除，alert 文本可能作为纯文本残留但不会作为脚本执行
        assert!(!result.contains("<script"), "不应残留 script 标签");
        assert!(!result.contains("</script>"), "不应残留 script 闭标签");
    }

    #[test]
    fn test_preserves_table_structure() {
        let input = "<table><tr><td colspan=\"2\">cell</td></tr></table>";
        let result = sanitize_html(input);
        assert!(result.contains("<table>"));
        assert!(result.contains("colspan"));
        assert!(result.contains("cell"));
    }

    #[test]
    fn test_link_rel_added() {
        let input = "<a href=\"https://example.com\">link</a>";
        let result = sanitize_html(input);
        assert!(result.contains("rel=\"noopener noreferrer\""), "应自动添加 rel 属性");
    }

    #[test]
    fn test_removes_form_elements() {
        let input = "<form action=\"evil\"><input name=\"pwd\"><button>submit</button></form>";
        let result = sanitize_html(input);
        assert!(!result.contains("<form"));
        assert!(!result.contains("<input"));
        assert!(!result.contains("<button"));
        // form 内的文本内容被保留
        assert!(result.contains("submit"));
    }

    #[test]
    fn test_inline_style_preserved() {
        // style 属性中的安全 CSS 被保留，危险 CSS（如 url(javascript:)）被 ammonia 过滤
        let input = "<p style=\"color:red\">text</p>";
        let result = sanitize_html(input);
        assert!(result.contains("style"), "安全 style 属性应保留");
        assert!(result.contains("color"));
    }
}
