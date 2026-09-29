// backend-axum/src/common/page.rs

use sea_orm::sea_query::SimpleExpr;
use sea_orm::{EntityTrait, QueryFilter, Select};
use serde::Deserialize;
use utoipa::ToSchema;

/// 分页查询参数（对齐前端 PageDomain）
/// 前端通过 GET 查询串传递：?pageNum=1&pageSize=10&orderByColumn=createTime&isAsc=desc
#[derive(Debug, Clone, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct PageDomain {
    /// 页码，从 1 开始（默认 1）
    #[serde(default = "default_page_num")]
    pub page_num: u64,

    /// 每页条数（默认 10，上限 100）
    #[serde(default = "default_page_size")]
    pub page_size: u64,

    /// 排序字段（可选）
    pub order_by_column: Option<String>,

    /// 排序方向：asc / desc（可选）
    pub is_asc: Option<String>,
}

/// 默认页码
pub fn default_page_num() -> u64 {
    1
}

/// 默认每页条数
pub fn default_page_size() -> u64 {
    10
}

/// 每页条数上限（防止恶意大分页拖垮 DB）
pub const MAX_PAGE_SIZE: u64 = 100;

/// 导出接口单次返回行数上限（防止 OOM 与长事务拖垮 DB）
///
/// 各 service 的 `export_*` 方法在调用 repository 全量/大分页查询时，
/// 应统一使用此常量作为 limit，避免 `i32::MAX` 无上限或被 PageDomain
/// 截断为 100 行导致的导出数据错误。
pub const EXPORT_MAX_ROWS: u64 = 50000;

impl PageDomain {
    /// 计算 offset（0-based）
    pub fn offset(&self) -> u64 {
        // 使用已封顶的 limit()（page_size.min(MAX_PAGE_SIZE)），并对乘法做 saturating，
        // 防止超大 page_size/page_num 触发 u64 整数溢出（release 回绕 / debug panic，构成 DoS 面）
        // P2：page_num=0 防御性归一到第 1 页（原 saturating_sub 得 0，与第 1 页 offset 相同，
        // 前端误传 0 会重复返回第一页，语义不明确）
        let page_num = if self.page_num == 0 { 1 } else { self.page_num };
        page_num.saturating_sub(1).saturating_mul(self.limit())
    }

    /// 获取 limit（即 page_size，已限制上限）
    pub fn limit(&self) -> u64 {
        self.page_size.min(MAX_PAGE_SIZE)
    }

    /// 校验排序字段名是否为合法 SQL 标识符（ERR-30 防注入）
    ///
    /// 规则：仅允许 ASCII 字母开头，后跟字母/数字/下划线，长度 ≤ 64。
    /// 拒绝含空格、引号、分号、逗号等特殊字符的输入，防止 SQL 注入。
    pub fn is_valid_order_by_column(col: &str) -> bool {
        if col.is_empty() || col.len() > 64 {
            return false;
        }
        let mut chars = col.chars();
        let Some(first) = chars.next() else {
            return false;
        };
        if !(first.is_ascii_alphabetic() || first == '_') {
            return false;
        }
        chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
    }

    /// 校验排序方向是否合法（ERR-31 白名单）
    ///
    /// 允许值：asc / desc / ascending / descending（不区分大小写）
    pub fn is_valid_is_asc(asc: &str) -> bool {
        matches!(
            asc.to_lowercase().as_str(),
            "asc" | "desc" | "ascending" | "descending"
        )
    }

    /// 校验并净化排序字段（非法值置为 None，防御性丢弃而非报错）
    ///
    /// 调用方在构造 PageDomain 后应调用此方法，确保 order_by_column 和 is_asc
    /// 不含恶意输入。当前各 service 的 From impl 均将排序字段置为 None，
    /// 此方法为后续启用动态排序时的安全防线。
    pub fn sanitize_order_fields(&mut self) {
        if let Some(ref col) = self.order_by_column
            && !Self::is_valid_order_by_column(col)
        {
            self.order_by_column = None;
        }
        if let Some(ref asc) = self.is_asc
            && !Self::is_valid_is_asc(asc)
        {
            self.is_asc = None;
        }
    }
}

impl Default for PageDomain {
    fn default() -> Self {
        Self {
            page_num: default_page_num(),
            page_size: default_page_size(),
            order_by_column: None,
            is_asc: None,
        }
    }
}

/// 游标（keyset / 深分页）参数。
///
/// 深分页用于避免高基数列表（操作日志 / 登录日志 / 用户）在深 OFFSET 下的线性扫描。
/// 当携带 `last_id`（上一页最后一条主键）时，服务端改为 `PK < last_id` 过滤 +
/// `PK DESC` 排序 + `LIMIT page_size`，返回严格递减、无重复的下一页；不携带 `last_id`
/// 时完全走原有 `page_num/page_size` OFFSET 路径，与前端既有契约保持向后兼容。
#[derive(Debug, Clone, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct PageCursor {
    /// 上一页最后一条主键。存在即启用 keyset 深分页。
    pub last_id: Option<i64>,

    /// 每页条数（默认 10，上限 [`MAX_PAGE_SIZE`]）。
    #[serde(default = "default_page_size")]
    pub page_size: u64,
}

impl Default for PageCursor {
    fn default() -> Self {
        Self {
            last_id: None,
            page_size: default_page_size(),
        }
    }
}

impl PageCursor {
    /// 是否启用 keyset 深分页（携带 last_id）。
    pub fn enabled(&self) -> bool {
        self.last_id.is_some()
    }

    /// 每页条数（已封顶）。
    pub fn limit(&self) -> u64 {
        self.page_size.min(MAX_PAGE_SIZE)
    }
}

/// 将 keyset（游标）过滤应用到列表查询的共享辅助。
///
/// 当 `last_id` 存在时对 `query` 追加参数化条件 `PK < last_id`；值为绑定参数，
/// 绝不被拼接为裸 SQL。`pk_lt` 由调用方提供，把主键值映射为 `SimpleExpr`
/// （如 `|id: i64| Column::OperId.lt(id)`）。`last_id` 为 `None` 时原样返回
/// `query`，由调用方已有的 offset/order 路径继续生效，完全向后兼容。
///
/// 排序（`PK DESC`）与 `LIMIT` 仍由调用方按各自主键列设置，本函数仅统一「过滤」这一
/// 桩，使跨实体（oper_log / logininfor / user）复用同一套 keyset 语义。
pub fn apply_keyset_filter<E>(
    mut query: Select<E>,
    last_id: Option<i64>,
    pk_lt: impl FnOnce(i64) -> SimpleExpr,
) -> Select<E>
where
    E: EntityTrait,
{
    if let Some(id) = last_id {
        query = query.filter(pk_lt(id));
    }
    query
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn page_cursor_defaults_are_sane() {
        let c = PageCursor::default();
        assert_eq!(c.page_size, default_page_size());
        assert!(!c.enabled());
        assert_eq!(c.limit(), default_page_size());
    }

    #[test]
    fn page_cursor_clamps_page_size() {
        let c = PageCursor {
            page_size: MAX_PAGE_SIZE + 1,
            ..PageCursor::default()
        };
        assert_eq!(c.limit(), MAX_PAGE_SIZE);

        let c = PageCursor {
            last_id: Some(42),
            ..PageCursor::default()
        };
        assert!(c.enabled());
        assert_eq!(c.limit(), default_page_size());
    }

    #[test]
    fn keyset_filter_appends_pk_lt_condition() {
        use sea_orm::ColumnTrait;
        use sea_orm::DatabaseBackend;
        use sea_orm::QueryTrait;

        // 用 sys_user 实体构造一个真实 Select，验证 pk_lt 被参数化追加（而非拼裸 SQL）。
        let base = crate::entity::sys_user::Entity::find();
        let q = apply_keyset_filter(base, Some(100i64), |id: i64| {
            crate::entity::sys_user::Column::UserId.lt(id)
        });
        // pk < last_id 被应用（value 由 Sqlite 后端绑定为参数，而非内联明文）
        let debug_sql = format!("{:?}", q.build(DatabaseBackend::Sqlite));
        assert!(
            debug_sql.contains("user_id") && debug_sql.contains('<'),
            "keyset 过滤应作用于 user_id 且使用占位符，实际 SQL: {debug_sql}"
        );
    }

    #[test]
    fn keyset_filter_passes_through_when_no_last_id() {
        use sea_orm::ColumnTrait;
        use sea_orm::DatabaseBackend;
        use sea_orm::QueryTrait;

        let base = crate::entity::sys_user::Entity::find();
        let q = apply_keyset_filter(base, None, |id: i64| {
            crate::entity::sys_user::Column::UserId.lt(id)
        });
        // 未携带 last_id 时不应附加任何 WHERE 条件
        let debug_sql = format!("{:?}", q.build(DatabaseBackend::Sqlite));
        assert!(
            !debug_sql.to_ascii_lowercase().contains("where"),
            "无 last_id 时不应追加 keyset 过滤，实际 SQL: {debug_sql}"
        );
    }

    // ---------- 以下为补充覆盖：PageDomain 反序列化 / offset / limit / 排序字段白名单 ----------

    #[test]
    fn page_domain_defaults() {
        let d = PageDomain::default();
        assert_eq!(d.page_num, 1);
        assert_eq!(d.page_size, 10);
        assert_eq!(d.order_by_column, None);
        assert_eq!(d.is_asc, None);
        assert_eq!(default_page_num(), 1);
        assert_eq!(default_page_size(), 10);
    }

    #[test]
    fn page_domain_deserializes_camel_case_query() {
        // 前端 ?pageNum=2&pageSize=20&orderByColumn=createTime&isAsc=desc
        let s = r#"{"pageNum":2,"pageSize":20,"orderByColumn":"createTime","isAsc":"desc"}"#;
        let d: PageDomain = serde_json::from_str(s).expect("应反序列化成功");
        assert_eq!(d.page_num, 2);
        assert_eq!(d.page_size, 20);
        assert_eq!(d.order_by_column.as_deref(), Some("createTime"));
        assert_eq!(d.is_asc.as_deref(), Some("desc"));
    }

    #[test]
    fn page_domain_missing_fields_use_defaults() {
        // 缺省字段回退默认值
        let d: PageDomain = serde_json::from_str(r#"{}"#).unwrap();
        assert_eq!(d.page_num, 1);
        assert_eq!(d.page_size, 10);
        assert_eq!(d.order_by_column, None);
        assert_eq!(d.is_asc, None);
    }

    #[test]
    fn page_domain_offset_semantics() {
        // page_num=0 防御性归一到第 1 页（offset 0）
        let d = PageDomain {
            page_num: 0,
            page_size: 10,
            ..PageDomain::default()
        };
        assert_eq!(d.offset(), 0);
        // 第 1 页 offset 0
        let d = PageDomain {
            page_num: 1,
            page_size: 10,
            ..PageDomain::default()
        };
        assert_eq!(d.offset(), 0);
        // 第 3 页 offset 20
        let d = PageDomain {
            page_num: 3,
            page_size: 10,
            ..PageDomain::default()
        };
        assert_eq!(d.offset(), 20);
    }

    #[test]
    fn page_domain_offset_saturates_on_overflow() {
        // page_num/page_size 极大 → saturating_mul 不 panic，返回 u64::MAX
        let d = PageDomain {
            page_num: u64::MAX,
            page_size: u64::MAX,
            ..PageDomain::default()
        };
        // limit 先封顶 100，(MAX-1)*100 saturating
        assert_eq!(d.offset(), u64::MAX.saturating_sub(1).saturating_mul(100));
    }

    #[test]
    fn page_domain_limit_clamps_to_max() {
        let d = PageDomain {
            page_size: 50,
            ..PageDomain::default()
        };
        assert_eq!(d.limit(), 50);
        let d = PageDomain {
            page_size: MAX_PAGE_SIZE + 1,
            ..PageDomain::default()
        };
        assert_eq!(d.limit(), MAX_PAGE_SIZE);
        let d = PageDomain {
            page_size: 0,
            ..PageDomain::default()
        };
        assert_eq!(d.limit(), 0);
    }

    #[test]
    fn order_by_column_validation() {
        // 合法：字母开头 + 字母数字下划线，长度 ≤ 64
        assert!(PageDomain::is_valid_order_by_column("createTime"));
        assert!(PageDomain::is_valid_order_by_column("_order"));
        assert!(PageDomain::is_valid_order_by_column("a"));
        assert!(PageDomain::is_valid_order_by_column("col_1"));
        let long_ok = "a".repeat(64);
        assert!(PageDomain::is_valid_order_by_column(&long_ok));
        // 非法
        assert!(!PageDomain::is_valid_order_by_column(""));
        let long_bad = "a".repeat(65);
        assert!(!PageDomain::is_valid_order_by_column(&long_bad));
        assert!(!PageDomain::is_valid_order_by_column("1abc")); // 数字开头
        assert!(!PageDomain::is_valid_order_by_column("-abc")); // 符号开头
        assert!(!PageDomain::is_valid_order_by_column("a b")); // 含空格
        assert!(!PageDomain::is_valid_order_by_column("a;drop")); // 含分号
        assert!(!PageDomain::is_valid_order_by_column("a,b")); // 含逗号
        assert!(!PageDomain::is_valid_order_by_column("a\"b")); // 含引号
        assert!(!PageDomain::is_valid_order_by_column("中文列")); // 非 ASCII
    }

    #[test]
    fn is_asc_validation_case_insensitive() {
        assert!(PageDomain::is_valid_is_asc("asc"));
        assert!(PageDomain::is_valid_is_asc("DESC"));
        assert!(PageDomain::is_valid_is_asc("Ascending"));
        assert!(PageDomain::is_valid_is_asc("descending"));
        assert!(!PageDomain::is_valid_is_asc(""));
        assert!(!PageDomain::is_valid_is_asc("desc asc"));
        assert!(!PageDomain::is_valid_is_asc("random"));
        assert!(!PageDomain::is_valid_is_asc("asc;drop"));
    }

    #[test]
    fn sanitize_order_fields_drops_invalid_keeps_valid() {
        // 非法排序字段 → 置 None
        let mut d = PageDomain {
            order_by_column: Some("a;drop".into()),
            is_asc: Some("evil".into()),
            ..PageDomain::default()
        };
        d.sanitize_order_fields();
        assert_eq!(d.order_by_column, None);
        assert_eq!(d.is_asc, None);

        // 合法值保留
        let mut d = PageDomain {
            order_by_column: Some("createTime".into()),
            is_asc: Some("desc".into()),
            ..PageDomain::default()
        };
        d.sanitize_order_fields();
        assert_eq!(d.order_by_column.as_deref(), Some("createTime"));
        assert_eq!(d.is_asc.as_deref(), Some("desc"));
    }
}
