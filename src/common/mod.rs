// stepby-axum/src/common/mod.rs

pub mod background;
// 批量操作入参归一（去重保序的唯一实现；重复 id 不得被判成"不存在"）
pub mod batch_ids;
pub mod clear_fields;
pub mod constants;
pub mod cron_compat;
pub mod custom_scope;
pub mod data_scope;
pub mod dataset_sql;
pub mod datetime;
pub mod double_opt;
// 数据外带出口（整库/全量审计/合规归档的 GET 下载导出）的审计留痕单一实现（b137）
pub mod egress_audit;
pub mod encrypted_value;
pub mod error;
pub mod excel;
pub mod extract;
pub mod features;
pub mod flow_graph;
// 请求路径已持有锁的 RAII 守卫（显式释放优先，Drop 兜底；handler future 可被丢弃）
pub mod held_lock;
pub mod http_download;
pub mod http_status;
pub mod i18n;
pub mod image;
// 出站 HTTP 客户端构造的单一事实源（系统信任库缺失时回落内嵌根证书，构造期绝不 panic）
pub mod outbound_client;
// 出站错误响应体的读取/遮蔽/截断单一通道（"读不到"不得折成空串）
pub mod outbound_error_body;
pub mod page;
// 权限键格式的单一事实源（菜单写面与种子契约测试共用）
pub mod perm_format;
// `perm:user:*` 缓存失效的唯一实现（四条触发路径同源，见该模块文档的"四份实现"立案）
pub mod perm_cache;
pub mod pwd_policy;
// 共享态读写的结局三态通道（`Err` 不得读成「未命中 / 未抢占」；计数 + 首告 + `/metrics` 同源）
//
// ⚠ 声明位置在测试专属模块**之前**：它是生产模块，必须落在默认口径的生产视图里
// （`every_site_label_is_wired_in_production_code` 与各形状锁的采集面都靠接线反查它，
// 排到刀口之后 = 整个模块对采集面消失，而报告长得和"干净"一模一样）。
pub mod store_outcome;
// 形状锁共用的生产码采集器：**只在测试构建存在**（`pub(crate)` 供各锁模块的 tests 使用）。
// 采集口径（`#[cfg(test)]` 截断、注释行处理、自豁免、体量下限）收在这一个文件里，
// 理由与六份旧实现的口径对照见该模块文档。
#[cfg(test)]
pub(crate) mod prod_scan;
// 「失败被折成正常值」的共用判据实现（三份私有谓词的最严并集，见该模块文档的立项理由）。
// **只在测试构建存在**：它不产出任何运行期行为，只被形状锁消费。
//
// ⚠ 测试专属模块的声明必须排在**第一个** `#[cfg(test)]` 聚集处（默认口径的刀口取第一个
// 逐字符等于 `#[cfg(test)]` 的行，其后的生产声明一并看不见——把这条插在 `flow_graph` 与
// `held_lock` 之间，`outbound_client` 之后的所有模块立刻从十余把形状锁的采集面消失，
// 由 `prod_scan::first_attribute_wins_limitation_is_pinned` 当场判红，本批实测踩过）。
#[cfg(test)]
pub(crate) mod fold_scan;
pub mod redact;
pub mod response;
pub mod risk_control;
// 旧会话租户归属回查的**结局类型**（读失败不得折成 tenant_id=0；列表/强退/在线数三站点共用）
pub(crate) mod session_owner;
// 重资源入口的全局并发闸门（AGENTS 工程基线 A-2「资源硬上限 + 背压」）
pub mod resource_gate;
// 软删释放唯一键的单一实现（列宽感知的 `{原名}_deleted_{id}`）
pub mod soft_delete_key;
// 软删唯一键策略登记表（仅测试期：schema 驱动双向对账 + 锚点活性）
#[cfg(test)]
pub(crate) mod soft_delete_policy;
pub mod sort;
pub mod sql_dialect;
pub mod ssrf;
pub mod tenant;
pub mod upload;
pub mod upload_chunk;
pub mod upload_scan;
// 「读-判断-写」的跨方言互斥闸（唯一实现；行锁在 SQLite 方言不生效，见模块文档）
pub mod webhook;
pub mod write_guard;

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
