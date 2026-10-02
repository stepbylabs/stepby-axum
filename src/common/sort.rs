//! 动态排序统一层（方案 B）：`PageDomain` 排序参数 → sea-orm `ORDER BY`
//!
//! 背景：此前全库 20+ 处 `From<&XxxQueryDto> for PageDomain` 将排序参数硬编码为
//! `None`，前端表头 `sortable="custom"` 发出的 `orderByColumn/isAsc` 在服务层被
//! 丢弃，列表排序为"假实现"。本模块提供统一解析与应用设施，所有服务端分页列表
//! 按同一模式接入。
//!
//! 安全模型（三层防线，纵深防御）：
//! 1. [`crate::common::page::PageDomain::sanitize_order_fields`]：格式白名单
//!    （SQL 标识符字符集 + 方向枚举），非法输入防御性丢弃（不报错）；
//! 2. [`resolve_column`]：列名白名单映射——前端 prop 经 [`camel_to_snake`] 归一后
//!    必须命中该表允许排序列清单，未命中回退默认列。不透传任意列：防止按未
//!    预期列排序拖库，也避免通过排序侧信道探测隐藏列；
//! 3. 列以 sea-orm `Column` 枚举 + [`QueryOrder`] 生成参数化 `ORDER BY`，
//!    全程无字符串拼接 SQL。
//!
//! 接入模式（三步）：
//! 1. DTO 增加两个 `#[serde(default)]` 字段 `order_by_column` / `is_asc`
//!    （`rename_all = "camelCase"` 自动映射 `orderByColumn` / `isAsc`）；
//! 2. `From<&Dto> for PageDomain` 透传这两个字段，并在构造后调用
//!    [`crate::common::page::PageDomain::sanitize_order_fields`]；
//! 3. repository 分页查询签名增加 `sort: Option<SortOrder<Column>>`（`None`
//!    = 沿用原有默认排序），内部用 [`apply_order`] 应用。
//!
//! keyset（游标深分页）与动态排序互斥：携带 `last_id` 时固定 `PK DESC`
//! （keyset 语义要求单调主键序），动态排序仅在 OFFSET 分页路径生效。

use sea_orm::{EntityTrait, Order, QueryOrder, Select};

/// 解析后的单个排序规则：目标列 + 方向。
///
/// `C` 为具体实体的 `Column` 枚举（`EntityTrait::Column`）。
/// `sea_orm::Order` 非 `Copy`/`Eq`，故仅派生 `Debug/Clone/PartialEq`。
#[derive(Debug, Clone, PartialEq)]
pub struct SortOrder<C> {
    pub column: C,
    pub dir: Order,
}

impl<C> SortOrder<C> {
    /// 快捷构造（用于 service 侧把白名单解析结果传给 repository）。
    pub fn new(column: C, dir: Order) -> Self {
        Self { column, dir }
    }
}

/// camelCase / PascalCase → snake_case（前端表头 prop → 数据库列名）。
///
/// `loginTime` → `login_time`；`operTime` → `oper_time`。
/// 输入已含下划线时视为 snake_case（直传列名 / 全大写常量），整体转小写返回；
/// 连续大写缩写词仅在"前一个字符为小写/数字"的边界插下划线。
pub fn camel_to_snake(s: &str) -> String {
    if s.contains('_') {
        return s.to_ascii_lowercase();
    }
    let chars: Vec<char> = s.chars().collect();
    let mut out = String::with_capacity(s.len() + 4);
    for (i, &c) in chars.iter().enumerate() {
        if c.is_ascii_uppercase() {
            let prev_lower = i > 0 && chars[i - 1].is_ascii_lowercase();
            let digit_before = i > 0 && chars[i - 1].is_ascii_digit();
            if i > 0 && (prev_lower || digit_before) {
                out.push('_');
            }
            out.push(c.to_ascii_lowercase());
        } else {
            out.push(c);
        }
    }
    out
}

/// 解析排序方向：`asc` / `ascending` → [`Order::Asc`]，其余（含 `None`）→ [`Order::Desc`]。
///
/// 前置约定：`is_asc` 已过 [`PageDomain::is_valid_is_asc`] 白名单（asc/desc/
/// ascending/descending 不区分大小写），非法值已在 sanitize 阶段置 `None`；
/// 缺省方向按列表惯例取 `Desc`（最新在前）。
///
/// [`PageDomain::is_valid_is_asc`]: crate::common::page::PageDomain::is_valid_is_asc
pub fn parse_direction(is_asc: Option<&str>) -> Order {
    match is_asc.map(|s| s.to_ascii_lowercase()) {
        Some(ref s) if s == "asc" || s == "ascending" => Order::Asc,
        _ => Order::Desc,
    }
}

/// 白名单解析：前端排序 prop → 实体列。
///
/// - `allow`：该表允许排序的 `(数据库列名 snake_case, Column 枚举)` 清单；
/// - 前端 prop 先经 [`camel_to_snake`] 归一（同时兼容直接传 snake_case 的调用方）；
/// - 未命中返回 `None`（调用方回退默认排序，**不**透传任意列）。
pub fn resolve_column<'a, E>(prop: &str, allow: &'a [(&'a str, E::Column)]) -> Option<E::Column>
where
    E: EntityTrait,
{
    let key = camel_to_snake(prop);
    allow
        .iter()
        .find(|(name, _)| *name == key)
        .map(|(_, col)| *col)
}

/// 把动态排序应用到 sea-orm 分页查询。
///
/// - `order_by_column` / `is_asc`：来自 `PageDomain`（已 sanitize）；
/// - 命中白名单 → 按前端指定列与方向排序；
/// - `order_by_column` 为 `None` 或未命中白名单 → 使用 `default`（保持各列表
///   现有默认排序语义，如 `login_time DESC`）；
/// - 命中白名单但 `is_asc` 为 `None` → 按 [`parse_direction`] 约定取 `Desc`。
///
/// # 参数
/// - `allow`: 该表白名单，条目为 `(数据库列名 snake_case, Column 枚举)`。
pub fn apply_order<E>(
    query: Select<E>,
    order_by_column: Option<&str>,
    is_asc: Option<&str>,
    allow: &[(&str, E::Column)],
    default: (E::Column, Order),
) -> Select<E>
where
    E: EntityTrait,
{
    let (column, dir) = order_by_column
        .and_then(|prop| resolve_column::<E>(prop, allow))
        .map(|col| (col, parse_direction(is_asc)))
        .unwrap_or(default);
    query.order_by(column, dir)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entity::sys_logininfor::{Column, Entity as Logininfor};
    use sea_orm::DatabaseBackend;
    use sea_orm::QueryTrait;

    #[test]
    fn camel_to_snake_converts_and_passthrough() {
        assert_eq!(camel_to_snake("loginTime"), "login_time");
        assert_eq!(camel_to_snake("operTime"), "oper_time");
        assert_eq!(camel_to_snake("createTime"), "create_time");
        assert_eq!(camel_to_snake("userName"), "user_name");
        // PascalCase 同样处理（首个大写不插下划线）
        assert_eq!(camel_to_snake("LoginTime"), "login_time");
        // snake_case / 全大写直传：含下划线时整体转小写
        assert_eq!(camel_to_snake("login_time"), "login_time");
        assert_eq!(camel_to_snake("LOGIN_TIME"), "login_time");
        // 单词无变化
        assert_eq!(camel_to_snake("status"), "status");
        assert_eq!(camel_to_snake("STATUS"), "status");
        // 连续大写缩写词：仅小写→大写边界插下划线
        assert_eq!(camel_to_snake("operIP"), "oper_ip");
    }

    #[test]
    fn parse_direction_maps_and_defaults() {
        assert_eq!(parse_direction(Some("asc")), Order::Asc);
        assert_eq!(parse_direction(Some("ascending")), Order::Asc);
        assert_eq!(parse_direction(Some("ASC")), Order::Asc);
        assert_eq!(parse_direction(Some("desc")), Order::Desc);
        assert_eq!(parse_direction(Some("descending")), Order::Desc);
        assert_eq!(parse_direction(None), Order::Desc);
    }

    const ALLOW: &[(&str, Column)] = &[
        ("info_id", Column::InfoId),
        ("ipaddr", Column::Ipaddr),
        ("user_name", Column::UserName),
        ("status", Column::Status),
        ("login_time", Column::LoginTime),
    ];

    #[test]
    fn resolve_column_whitelist_hit_and_miss() {
        // DeriveEntityModel 生成的 Column 枚举未实现 PartialEq，
        // 用 matches! 模式匹配断言命中列
        assert!(matches!(
            resolve_column::<Logininfor>("loginTime", ALLOW),
            Some(Column::LoginTime)
        ));
        assert!(matches!(
            resolve_column::<Logininfor>("LOGIN_TIME", ALLOW),
            Some(Column::LoginTime)
        ));
        assert!(matches!(
            resolve_column::<Logininfor>("info_id", ALLOW),
            Some(Column::InfoId)
        ));
        // 未命中白名单 → None（回退默认，绝不透传任意列）
        assert!(resolve_column::<Logininfor>("tenant_id", ALLOW).is_none());
        assert!(resolve_column::<Logininfor>("passwd", ALLOW).is_none());
        assert!(resolve_column::<Logininfor>("", ALLOW).is_none());
    }

    #[test]
    fn apply_order_hit_uses_dynamic_direction() {
        // 命中白名单 + asc → ORDER BY login_time ASC
        let q = apply_order(
            Logininfor::find(),
            Some("loginTime"),
            Some("asc"),
            ALLOW,
            (Column::InfoId, Order::Desc),
        );
        let sql = format!("{:?}", q.build(DatabaseBackend::Sqlite)).to_ascii_lowercase();
        assert!(
            sql.contains("login_time") && sql.contains("asc"),
            "应按 login_time ASC 排序，实际 SQL: {sql}"
        );

        // 命中白名单 + is_asc 缺省 → Desc
        let q = apply_order(
            Logininfor::find(),
            Some("login_time"),
            None,
            ALLOW,
            (Column::InfoId, Order::Desc),
        );
        let sql = format!("{:?}", q.build(DatabaseBackend::Sqlite)).to_ascii_lowercase();
        assert!(
            sql.contains("login_time") && sql.contains("desc"),
            "is_asc 缺省应按 Desc 排序，实际 SQL: {sql}"
        );
    }

    #[test]
    fn apply_order_miss_falls_back_to_default() {
        // 未命中白名单 → 默认列（info_id DESC），不含任意注入列
        let q = apply_order(
            Logininfor::find(),
            Some("tenant_id"),
            Some("asc"),
            ALLOW,
            (Column::InfoId, Order::Desc),
        );
        let sql = format!("{:?}", q.build(DatabaseBackend::Sqlite)).to_ascii_lowercase();
        // 只检查 ORDER BY 段（SELECT 列表本来就含全部列名）
        let order_by = sql.split("order by").nth(1).unwrap_or("");
        assert!(
            order_by.contains("info_id") && order_by.contains("desc"),
            "未命中白名单应回退默认排序，实际 SQL: {sql}"
        );
        assert!(
            !order_by.contains("tenant_id"),
            "未命中列绝不应出现在 ORDER BY，实际 SQL: {sql}"
        );

        // prop 为 None → 默认列
        let q = apply_order(
            Logininfor::find(),
            None,
            None,
            ALLOW,
            (Column::LoginTime, Order::Desc),
        );
        let sql = format!("{:?}", q.build(DatabaseBackend::Sqlite)).to_ascii_lowercase();
        let order_by = sql.split("order by").nth(1).unwrap_or("");
        assert!(
            order_by.contains("login_time") && order_by.contains("desc"),
            "prop None 应回退默认排序，实际 SQL: {sql}"
        );
    }
}
