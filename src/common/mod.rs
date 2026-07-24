// axum-backend/src/common/mod.rs

pub mod constants;
pub mod datetime;
pub mod error;
pub mod excel;
pub mod extract;
pub mod i18n;
pub mod page;
pub mod response;
pub mod upload;

pub use error::{AppError, ServiceError};
pub use extract::ValidatedJson;
pub use page::PageDomain;
pub use response::{AjaxResult, TableDataInfo, TreeSelectVo};
pub use upload::{gen_uuid_filename, resolve_upload_dir, resolve_upload_root, write_upload_file};

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
    input
        .replace('\\', "\\\\")
        .replace('%', "\\%")
}
