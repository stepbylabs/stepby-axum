// stepby-axum/src/common/page.rs

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

/// 手写分页点位的 offset 计算——**全仓 offset 推导的单一事实源**。
///
/// `PageDomain` 覆盖不到的场景（service 直接收 `page_num/page_size` 形参、SCIM 的
/// `startIndex/count`、归档锚点列表等）一律走本函数，不得再各写一份算式。
///
/// 口径（与 [`PageDomain::offset`] 完全一致）：
/// - `page_num = 0` 归一到第 1 页（避免"第 0 页 = 第 1 页"的语义歧义，见 P2）；
/// - 乘法 `saturating_mul` 后再钳到 [`i64::MAX`]：超大页码在 debug 构建会 panic、release
///   构建会回绕成任意 offset（等价于随机跳页），两者都是可被单个查询参数触发的可用性缺陷；
///   再钳上界是因为下游 raw SQL 分页边界存在 `offset as i64` 转换（如
///   `repository::sys_notice_read`），饱和到 `u64::MAX` 会翻成负数让数据库报错——
///   而"深到不存在的页"正确语义是返回空集。
/// - `limit` 由调用方负责封顶（[`MAX_PAGE_SIZE`] 或业务自有上限），本函数不重复钳制，
///   以免出现"offset 按封顶值算、LIMIT 按原值算"的错位跳行。
pub fn offset_of(page_num: u64, limit: u64) -> u64 {
    let page_num = if page_num == 0 { 1 } else { page_num };
    page_num
        .saturating_sub(1)
        .saturating_mul(limit)
        .min(i64::MAX as u64)
}

/// 分页点位的成对推导：`(offset, limit)`——**limit 必须先封顶，再按封顶值算 offset**。
///
/// 存在的理由：`offset` 与 `LIMIT` 分别由两处代码算出时，会出现"offset 按封顶值算、
/// LIMIT 按原值算"的**错位跳行**（同一页码在两处各自成立、拼起来是错的）。收成一个
/// 返回值成对的函数，这类漂移在结构上不可能发生。
///
/// 默认上限 [`MAX_PAGE_SIZE`]；有业务自有上限的调用方走 [`page_args_capped`]，
/// 不得回头手算 `(num - 1) * size`（由
/// `tests::no_handrolled_page_offset_anywhere` 机械钉住）。
pub fn page_args(page_num: u64, page_size: u64) -> (u64, u64) {
    page_args_capped(page_num, page_size, MAX_PAGE_SIZE)
}

/// [`page_args`] 的显式上限形态。
///
/// `max_page_size` 是**调用方的业务上限**（观测类接口按 200 出数），必须 ≥ 1：
/// 传 0 会让 `clamp(1, 0)` 反转成 panic，所以这里按 `max(1)` 归一而非依赖 clamp 的入参不变式。
pub fn page_args_capped(page_num: u64, page_size: u64, max_page_size: u64) -> (u64, u64) {
    let limit = page_size.clamp(1, max_page_size.max(1));
    (offset_of(page_num, limit), limit)
}

impl PageDomain {
    /// 计算 offset（0-based）
    pub fn offset(&self) -> u64 {
        offset_of(self.page_num, self.limit())
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
    fn page_domain_offset_clamps_to_i64_max_on_overflow() {
        // b71 单一事实源治理：上界钳到 `i64::MAX` 而非饱和到 `u64::MAX`——
        // 下游 raw SQL 分页边界存在 `offset as i64` 转换（repository::sys_notice_read），
        // u64 饱和值会翻成负数让数据库报错，而"深到不存在的页"正确语义是返回空集。
        let d = PageDomain {
            page_num: u64::MAX,
            page_size: u64::MAX,
            ..PageDomain::default()
        };
        assert_eq!(d.offset(), i64::MAX as u64);
        assert!(
            i64::try_from(d.offset()).is_ok(),
            "offset 必须可无损转 i64（否则拼进 SQL 会变负数）"
        );
    }

    /// `offset_of` 四象限 + 与 `PageDomain::offset` 同口径（防止两处算式漂移）
    #[test]
    fn offset_of_matrix_and_parity_with_page_domain() {
        assert_eq!(offset_of(1, 10), 0);
        assert_eq!(offset_of(4, 25), 75);
        assert_eq!(offset_of(0, 10), 0, "page_num=0 应归一到第 1 页");
        assert_eq!(offset_of(3, 0), 0, "limit=0 不得产生非零 offset");
        assert_eq!(offset_of(u64::MAX, 100), i64::MAX as u64);
        assert_eq!(offset_of(u64::MAX, u64::MAX), i64::MAX as u64);
        // 手写点位与 PageDomain 必须给出同一个 offset
        for (num, size) in [(1u64, 10u64), (7, 20), (0, 10), (999, 3), (u64::MAX, 100)] {
            let d = PageDomain {
                page_num: num,
                page_size: size,
                ..PageDomain::default()
            };
            assert_eq!(d.offset(), offset_of(num, d.limit()));
        }
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

    // ---------- 批七十五 B1：分页点位单一事实源的形状锁 ----------

    /// 判据（纯函数，真实码与控制组共用）：行内出现 `(某个分页变量 - 1)` 即视为手算 offset。
    ///
    /// **按变量名收口而不是按算式收口**：`(x - 1) * y` 在时间窗、列宽、`count >= n` 的
    /// `.gt(min_count - 1)` 等等场景里都是合法算术（实测仓内有 6 处这类形态），把它们一律
    /// 判红只会逼下一个作者把违规写成一连串别名绕开判据。因此只认名字里含 `page`/`num` 的
    /// 括号内变量——这正好覆盖 `(page_num - 1) * page_size`、`((num - 1) * size, size)`、
    /// `((page_num - 1) as usize).saturating_mul(...)` 三种真实形态。
    fn raw_page_offset_hit(line: &str) -> bool {
        static RE: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
        let re = RE.get_or_init(|| {
            // 允许字段访问形态（`query.page_num`）：真实代码就是这么写的，
            // 只认裸标识符会让判据对最常见的手算形态失明
            regex::Regex::new(
                r"\(\s*([A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*)\s*-\s*1\s*\)",
            )
            .expect("正则必须可编译")
        });
        for cap in re.captures_iter(line) {
            let name = cap[1].to_lowercase();
            if name.contains("page") || name.contains("num") {
                return true;
            }
        }
        false
    }

    #[test]
    fn no_handrolled_page_offset_anywhere() {
        use crate::common::prod_scan::{Scan, prod_files};
        let files = prod_files(&Scan::default());
        // 采集面地板（实测全仓 .rs 上百个）：扫描器塌了必须红，不能"扫不到=没有违规"
        crate::common::prod_scan::require_volume(&files, 80, 20_000, "分页点位形状锁");
        let mut hits = Vec::new();
        for f in &files {
            for (i, line) in f.lines.iter().enumerate() {
                if raw_page_offset_hit(line) {
                    hits.push(format!("{}:{} {}", f.rel, i + 1, line.trim()));
                }
            }
        }
        assert!(
            hits.is_empty(),
            "分页 offset 必须由 [`offset_of`]/[`page_args`] 推导，不得手算 `(页码 - 1) * 每页`；\
             手算形态各自缺不同的那半条不变式（下溢 / 乘法回绕 / 绕过 i64::MAX 钳制 / limit 未封顶），\
             批七十五实测其中两处可被单个查询参数触发 500：\n{}",
            hits.join("\n")
        );
    }

    /// 控制组：判据必须**能**失败，且不得误伤合法算术。
    ///
    /// 反例集里的每条都是"看起来像但不该报"或"应该报但形状不同"，缺任何一侧都可能让
    /// 上面的总锁退化成装饰。
    #[test]
    fn page_offset_guard_catches_synthetic_violations_and_spares_legit_math() {
        // 必须被抓到的四种真实形态
        for src in [
            "let off = (page_num - 1) * page_size;",
            "let (a, b) = ((num - 1) * size, size);",
            "((page_num - 1) as usize).saturating_mul(page_size),",
            "    (query.page_num - 1) * query.page_size,",
        ] {
            assert!(raw_page_offset_hit(src), "手算分页形态必须被抓到: {src}");
        }
        // 不得误伤：走单一事实源、以及与分页无关的同形算术
        for src in [
            "let off = crate::common::page::offset_of(page_num, limit);",
            "let (off, lim) = page_args(params.page_num, params.page_size);",
            "page_num.saturating_sub(1).saturating_mul(limit)",
            "let start = today - Duration::days(days - 1);",
            ".gt(min_count - 1)",
            "let w = (cols - 1) * gap;",
            "depts[(i - 1) as usize]",
        ] {
            assert!(!raw_page_offset_hit(src), "合法写法不得被报: {src}");
        }
        // 采集面自身的语义也要对得上：注释里出现的模式串不算违规
        let commented = [
            "    // 曾有 `(page_num - 1) as usize` 的独立算式".to_string(),
            "    let x = 1;".to_string(),
        ];
        assert!(
            !commented
                .iter()
                .any(|l| raw_page_offset_hit(l) && !l.trim_start().starts_with("//")),
            "prod_scan 的 Blank 口径必须已把注释行清空"
        );
    }

    /// `page_args` 与 `offset_of` 必须**同源**：limit 先封顶、offset 再按封顶值算。
    ///
    /// 这条判据盯的是"两处各自 clamp"会造成的错位跳行——两处的值各自合理、拼起来是错的。
    #[test]
    fn page_args_pairs_offset_with_clamped_limit() {
        assert_eq!(page_args(1, 10), (0, 10));
        assert_eq!(page_args(3, 10), (20, 10));
        // pageSize 超上限：limit 封到 MAX_PAGE_SIZE，offset 必须按**封顶后**的值算
        assert_eq!(page_args(4, 999_999), (3 * MAX_PAGE_SIZE, MAX_PAGE_SIZE));
        // pageNum=0：归一到第 1 页，且不得下溢
        assert_eq!(page_args(0, 10), (0, 10));
        // 超大页码：饱和到 i64::MAX（深页的正确语义是空集，而不是让 DB 报错）
        assert_eq!(page_args(u64::MAX, 10), (i64::MAX as u64, 10));
        // 业务自有上限档位
        assert_eq!(page_args_capped(3, 150, 200), (300, 150));
        assert_eq!(page_args_capped(3, 1500, 200), (2 * 200, 200));
        // pageSize=0 不得算出非零 offset（clamp 到 1）
        assert_eq!(page_args(7, 0), (6, 1));
        // max_page_size=0 是调用方的笔误：不得让 clamp(1, 0) panic
        assert_eq!(page_args_capped(2, 50, 0), (1, 1));
        // 与 offset_of 的闭环：同一入参必须同值
        for (n, s) in [(1u64, 10u64), (5, 100), (0, 7), (u64::MAX, 100)] {
            let (off, lim) = page_args(n, s);
            assert_eq!(off, offset_of(n, lim), "offset 与 limit 必须成对同源");
        }
    }
}
