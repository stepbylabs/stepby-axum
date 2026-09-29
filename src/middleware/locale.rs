// backend-axum/src/middleware/locale.rs
//! Locale 中间件（T-05）
//!
//! 解析 `Accept-Language` → 协商到支持的语言 → 经 task-local `LOCALE` 注入，
//! 并回写 `Content-Language` 响应头。
//!
//! 协商规则（仅支持 zh-CN / en-US）：
//! 1. 按 q-value 降序解析请求头
//! 2. 精确匹配支持集 → 命中
//! 3. 语言前缀回退（zh-* → zh-CN；en-* → en-US）
//! 4. 都不中 → 默认 zh-CN
//!
//! 与 request_id_middleware 同款 `from_fn` 风格。

use axum::extract::Request;
use axum::http::{HeaderValue, header};
use axum::middleware::Next;
use axum::response::Response;

use crate::common::i18n::{DEFAULT_LOCALE, LOCALE, SUPPORTED_LOCALES};

/// 解析 Accept-Language 头并协商出支持的语言
pub fn negotiate(accept: &str) -> String {
    // 解析并按 q-value 降序排序
    let mut entries: Vec<(String, f32)> = accept
        .split(',')
        .filter_map(|part| {
            let part = part.trim();
            if part.is_empty() {
                return None;
            }
            let (tag, q) = match part.split_once(';') {
                Some((t, rest)) => {
                    let q = rest
                        .split('=')
                        .nth(1)
                        .and_then(|v| v.trim().parse::<f32>().ok())
                        .unwrap_or(1.0);
                    (t.trim().to_lowercase(), q)
                }
                None => (part.to_lowercase(), 1.0),
            };
            Some((tag, q))
        })
        .collect();
    entries.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));

    for (tag, _q) in &entries {
        // 精确匹配
        if let Some(matched) = SUPPORTED_LOCALES.iter().find(|s| s.to_lowercase() == *tag) {
            return matched.to_string();
        }
        // 前缀回退
        if tag.starts_with("zh") {
            return "zh-CN".to_string();
        }
        if tag.starts_with("en") {
            return "en-US".to_string();
        }
    }

    DEFAULT_LOCALE.to_string()
}

/// locale 中间件：解析头 → 协商 → task-local 注入 → 回写 Content-Language
pub async fn locale_middleware(req: Request, next: Next) -> Response {
    let accept = req
        .headers()
        .get(header::ACCEPT_LANGUAGE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let locale = negotiate(accept);

    let locale_for_header = locale.clone();
    let resp = LOCALE.scope(locale, next.run(req)).await;

    let mut resp = resp;
    if let Ok(val) = HeaderValue::from_str(&locale_for_header) {
        resp.headers_mut().insert(header::CONTENT_LANGUAGE, val);
    }
    resp
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::i18n::current_locale;

    #[test]
    fn test_negotiate_exact() {
        assert_eq!(negotiate("zh-CN"), "zh-CN");
        assert_eq!(negotiate("en-US"), "en-US");
    }

    #[test]
    fn test_negotiate_prefix() {
        assert_eq!(negotiate("zh-TW"), "zh-CN");
        assert_eq!(negotiate("zh"), "zh-CN");
        assert_eq!(negotiate("en-GB"), "en-US");
        assert_eq!(negotiate("en"), "en-US");
    }

    #[test]
    fn test_negotiate_qvalue_order() {
        // en 优先级更高时应选 en
        assert_eq!(negotiate("zh-CN;q=0.8,en-US;q=0.9"), "en-US");
        assert_eq!(negotiate("en;q=0.5,zh-CN;q=0.9"), "zh-CN");
    }

    #[test]
    fn test_negotiate_empty() {
        assert_eq!(negotiate(""), "zh-CN");
    }

    #[test]
    fn test_negotiate_unsupported() {
        assert_eq!(negotiate("fr-FR"), "zh-CN");
        assert_eq!(negotiate("ja-JP,de-DE"), "zh-CN");
    }

    #[test]
    fn test_default_locale_fallback() {
        // 无 task-local 时 current_locale 回退默认
        assert_eq!(current_locale(), "zh-CN");
    }

    // ---------- 边缘用例：大小写 / 非法 q / 空白 / 特殊标记 ----------

    #[test]
    fn test_negotiate_case_insensitive() {
        // 大写语言标签经 to_lowercase 归一化后精确匹配
        assert_eq!(negotiate("ZH-CN"), "zh-CN");
        assert_eq!(negotiate("EN-US"), "en-US");
        assert_eq!(negotiate("Zh-Tw"), "zh-CN"); // zh-* 前缀回退
    }

    #[test]
    fn test_negotiate_malformed_q_defaults_to_1() {
        // q 值非数字时回退 1.0（unwrap_or(1.0) 分支）
        assert_eq!(negotiate("en-US;q=abc"), "en-US");
        assert_eq!(negotiate("zh-CN;q="), "zh-CN");
    }

    #[test]
    fn test_negotiate_q_zero_still_matched() {
        // q=0 也不跳过（实现仅按 q 降序排序，不排除 0 值条目）
        assert_eq!(negotiate("en-US;q=0"), "en-US");
    }

    #[test]
    fn test_negotiate_whitespace_tolerance() {
        // 逗号/分号周围空白应被容忍（trim 处理）
        assert_eq!(negotiate(" zh-CN , en-US "), "zh-CN");
        assert_eq!(negotiate("en-US; q=0.5"), "en-US");
        assert_eq!(negotiate("  en  ; q = 0.4 "), "en-US");
    }

    #[test]
    fn test_negotiate_wildcard_and_empty_parts() {
        // * 通配符不支持 → 默认；空分段（连续逗号）被过滤
        assert_eq!(negotiate("*"), "zh-CN");
        assert_eq!(negotiate(",,,en-US,,,"), "en-US");
        assert_eq!(negotiate("  ,  , "), "zh-CN");
    }

    #[test]
    fn test_negotiate_prefix_fallback_respects_q_order() {
        // 多个同前缀语言按 q 值选最优先者；前缀回退在精确匹配失败后生效
        assert_eq!(negotiate("zh-TW;q=0.9,zh-HK;q=0.8"), "zh-CN");
        // en 前缀回退在 zh 之后时才选中（顺序无关，q 决定优先级）
        assert_eq!(negotiate("en-GB;q=0.9,zh-CN;q=0.8"), "en-US");
    }

    #[test]
    fn test_negotiate_supported_locale_with_q_value() {
        // 精确匹配不受 q 值影响（只要排在第一位）
        assert_eq!(negotiate("en-US;q=0.7,zh-CN;q=0.6"), "en-US");
        assert_eq!(negotiate("zh-CN;q=0.6,en-US;q=0.7"), "en-US");
    }

    #[test]
    fn test_negotiate_mixed_unsupported_and_prefix() {
        // 不支持的标签跳过，前缀回退在后续标签生效
        assert_eq!(negotiate("fr-FR;q=0.9,zh;q=0.5"), "zh-CN");
        assert_eq!(negotiate("ja-JP;q=0.9,en;q=0.5"), "en-US");
    }
}
