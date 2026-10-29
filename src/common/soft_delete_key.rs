// stepby-axum/src/common/soft_delete_key.rs
//! 软删释放唯一键的**唯一实现**。
//!
//! 背景：本仓多张表的唯一索引**不含 `del_flag`**（如 `uk_sys_dict_type_tenant`、
//! `uk_sys_user_name`、`uq_report_dataset_code`）——软删行仍占着键值，于是"删掉再建同名"
//! 会撞唯一约束。既有做法是删除时把键值改成 `{原名}_deleted_{主键}` 让位（REGRESS-003 起
//! 在各表各写了一遍 `format!`：改前实测 7 处调用点 —— dict / job / post / role×2 / user×2，
//! 只有 dict 一处按列宽截断；另有租户私有的 `_del_{id}` 格式），
//! 且**都没有按列宽截断**：`sys_user.user_name` 是 `varchar(30)`，21 字符以上的用户名删除后
//! 必然溢出，MySQL 严格模式（默认 `STRICT_TRANS_TABLES`）会直接 1406 报错——SQLite 不校验
//! 长度，所以本机测试恒绿而生产删除失败。
//!
//! 口径：
//! - 后缀固定 `_deleted_{id}`（与既有写法一致，改名后的行仍可读、可审计）；
//! - **总长度不超过列宽**：超出部分从原值尾部截断（不截后缀，主键必须完整可回查）；
//! - 多字节按**字符**截断而非字节（`VARCHAR(n)` 在 MySQL 计字符）；
//! - `max_len` 小于后缀长度时仍返回完整后缀（宁可超宽也不丢主键），但这类表应当在
//!   策略锁 `soft_delete_policy` 里被判红——那是列宽设计错误，不是本函数的职责。
//!
//! 反向语义（从改名值还原原名）由各表自己的恢复路径负责：本函数只保证"唯一键被释放"
//! 与"主键仍可从值里读出"。

/// `{original}_deleted_{id}`，按 `max_len` 截断原值以保证总长不超列宽。
///
/// ```
/// # use stepby_axum::common::soft_delete_key::freed_key;
/// assert_eq!(freed_key("dict_type", 7, 100), "dict_type_deleted_7");
/// // varchar(30)：21 字符的名字 + 后缀会溢出 ⇒ 原值被截到 30 - len("_deleted_9") = 20
/// let long = "a".repeat(30);
/// let freed = freed_key(&long, 9, 30);
/// assert_eq!(freed.chars().count(), 30);
/// assert!(freed.ends_with("_deleted_9"));
/// ```
pub fn freed_key(original: &str, id: i64, max_len: usize) -> String {
    let tail = format!("_deleted_{id}");
    let keep = max_len.saturating_sub(tail.chars().count());
    let base: String = original.chars().take(keep).collect();
    format!("{base}{tail}")
}

/// 改名值的后缀解析：`Some(原始值)` 仅当形如 `{original}_deleted_{id}` 且 `id` 可解析。
///
/// 供"恢复/复活"路径使用（如租户编码的 `restore_tenant_code` 同族逻辑）；解析不出来
/// 一律返回 `None` 而不是猜——猜错会把别人的键值当成本行的原名。
pub fn split_freed_key(value: &str) -> Option<(&str, i64)> {
    let (base, tail) = value.rsplit_once("_deleted_")?;
    let id: i64 = tail.parse().ok()?;
    Some((base, id))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn short_value_is_kept_verbatim() {
        assert_eq!(freed_key("dict_type", 7, 100), "dict_type_deleted_7");
    }

    #[test]
    fn long_value_is_truncated_to_column_width() {
        let long = "a".repeat(100);
        let freed = freed_key(&long, 123, 64);
        assert_eq!(freed.chars().count(), 64);
        assert!(freed.ends_with("_deleted_123"));
        // 截断发生在原值尾部，后缀完整
        assert_eq!(
            split_freed_key(&freed),
            Some(("a".repeat(64 - 12).as_str(), 123))
        );
    }

    #[test]
    fn multibyte_truncates_by_chars_not_bytes() {
        let long = "汉".repeat(40);
        let freed = freed_key(&long, 5, 30);
        assert_eq!(freed.chars().count(), 30);
        assert!(freed.ends_with("_deleted_5"));
        // 30 - len("_deleted_5"=10) = 20 个汉字
        assert!(freed.starts_with(&"汉".repeat(20)));
    }

    #[test]
    fn wide_id_still_fits() {
        let freed = freed_key("name", i64::MAX, 30);
        assert_eq!(freed.chars().count(), 30);
        assert!(freed.ends_with(&format!("_deleted_{}", i64::MAX)));
    }

    #[test]
    fn tiny_column_keeps_the_primary_key_and_overflows_loudly() {
        // 列宽小于后缀：不丢主键（宁可超宽），这类表由策略锁判红，而不是悄悄丢 id
        let freed = freed_key("abc", 42, 4);
        assert_eq!(freed, "_deleted_42");
    }

    #[test]
    fn split_round_trips_and_rejects_other_shapes() {
        assert_eq!(split_freed_key("alice_deleted_12"), Some(("alice", 12)));
        assert_eq!(split_freed_key("alice"), None);
        assert_eq!(split_freed_key("alice_deleted_x"), None);
        assert_eq!(split_freed_key("_deleted_12"), Some(("", 12)));
    }
}
