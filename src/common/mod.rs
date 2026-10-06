// stepby-axum/src/common/mod.rs

pub mod clear_fields;
pub mod constants;
pub mod custom_scope;
pub mod data_scope;
pub mod datetime;
pub mod double_opt;
pub mod encrypted_value;
pub mod error;
pub mod excel;
pub mod extract;
pub mod features;
pub mod http_status;
pub mod i18n;
pub mod image;
pub mod page;
pub mod response;
pub mod risk_control;
pub mod sort;
pub mod ssrf;
pub mod tenant;
pub mod upload;
pub mod upload_chunk;
pub mod upload_scan;
pub mod webhook;

pub mod breaker;

#[cfg(test)]
pub mod fuzz_invariants;

pub use error::{AppError, ServiceError};
pub use extract::ValidatedJson;
pub use page::PageDomain;
pub use response::{AjaxResult, TableDataInfo, TreeSelectVo};
pub use upload::{
    delete_upload_file, gen_uuid_filename, resolve_kind_dir, resolve_upload_dir,
    resolve_upload_root, write_upload_file,
};

/// 为实现了 `Serialize` 的类型自动实现 `IntoResponse`，
/// 返回 `(StatusCode::OK, Json(self))`（P1-13）。
///
/// 消除 handler 层重复的 `impl IntoResponse` 样板代码。
///
/// # 示例
/// ```ignore
/// pub struct CaptchaResult { ... }
/// crate::impl_into_response!(CaptchaResult);
/// ```
#[macro_export]
macro_rules! impl_into_response {
    ($($t:ty),* $(,)?) => {
        $(
            impl axum::response::IntoResponse for $t {
                fn into_response(self) -> axum::response::Response {
                    (axum::http::StatusCode::OK, axum::Json(self)).into_response()
                }
            }
        )*
    };
}

/// 转义 SQL LIKE 模式中的特殊字符（%、\），防止用户输入被当作通配符
///
/// 所有 `.like(format!("%{}%", input))` 调用应使用 `like_escape(input)` 包裹 input，
/// 避免 LIKE 注入风险（用户输入 `%` 匹配全部行）。
///
/// SEC-002：转义 `%` 防止多字符通配符注入（最重要）。
/// `_` 单字符通配符不转义，原因：
/// - SeaORM `.like()` 不支持 ESCAPE 子句，而 SQLite 默认无转义字符
/// - 若转义 `\_`，SQLite 下会匹配字面 `\_` 而非 `_`，导致含下划线的搜索失效
/// - 单字符通配符安全风险远低于 `%`（仅匹配 1 个字符，不能枚举全表）
/// - 生产环境（MySQL/PostgreSQL）`_` 通配符注入仅影响搜索精度，不影响数据安全
///
/// 数据库兼容性说明：
/// - PostgreSQL / MySQL：反斜杠 `\` 是 LIKE 默认转义字符，`\%` 正确匹配字面量
/// - SQLite：默认无转义字符，`\%` 会匹配字面 `\%` 而非 `%`
///   这是 SeaORM `.like()` 不支持 ESCAPE 子句的已知限制；
///   生产环境使用 PostgreSQL/MySQL 不受影响，SQLite 仅用于本地开发
pub fn like_escape(input: &str) -> String {
    // W9（NL2SQL v4 升格项）：LIKE 模式长度上限 —— 全站单点防护。
    // 超长 LIKE 模式会让无索引的 LIKE 查询逐行回溯（CPU 消耗型 DoS；
    // MAX_PAGE_SIZE 只限制返回行数，不限制扫描行数）。正常搜索远低于此长度，
    // 截断对真实用户无感；这是除 sys_user_service 的业务级 50 字符约束之外的全站兜底。
    const MAX_LIKE_PATTERN_LEN: usize = 100;
    let input = if input.len() > MAX_LIKE_PATTERN_LEN {
        &input[..input.floor_char_boundary(MAX_LIKE_PATTERN_LEN)]
    } else {
        input
    };
    input.replace('\\', "\\\\").replace('%', "\\%")
}

#[cfg(test)]
mod like_escape_tests {
    use super::like_escape;

    #[test]
    fn escapes_percent_and_backslash() {
        assert_eq!(like_escape("a%b"), "a\\%b");
        assert_eq!(like_escape("a\\b"), "a\\\\b");
    }

    #[test]
    fn keeps_normal_search_untouched() {
        assert_eq!(like_escape("admin"), "admin");
        assert_eq!(like_escape("用户名"), "用户名");
    }

    #[test]
    fn truncates_overlong_pattern() {
        let long = "x".repeat(500);
        let escaped = like_escape(&long);
        assert_eq!(escaped.len(), 100); // 100 个 x（无转义字符，长度即上限）
    }

    #[test]
    fn truncation_respects_char_boundary() {
        // 中文字符（3 字节）跨在 100 字节边界上时不得 panic、不得切出非法 UTF-8
        let long = "汉".repeat(80); // 240 字节
        let escaped = like_escape(&long);
        assert!(escaped.len() <= 102); // ≤ 上限 + 一个多字节字符余量
        assert!(escaped.chars().all(|ch| ch == '汉'));
    }
}
