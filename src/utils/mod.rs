// stepby-axum/src/utils/mod.rs

pub mod captcha;
pub mod crypto;
pub mod dns_txt;
pub mod ip;
pub mod ip_location;
pub mod masking;
pub mod password;
pub mod redis;
pub mod retry;
pub mod sanitize;
pub mod tree;
pub mod xdb_reader;

pub use password::{encrypt_password, verify_password};
pub use sanitize::sanitize_html;

use std::str::FromStr;

/// 解析逗号分隔的字符串为指定类型的 Vec（P1-12）
///
/// 自动 trim 每个元素，跳过解析失败的元素。
/// 适用于 `split(',').filter_map(|s| s.trim().parse::<T>().ok()).collect()` 模式。
///
/// # 示例
/// ```
/// use stepby_axum::utils::parse_id_list;
/// let ids = parse_id_list::<i64>("1, 2, 3");
/// assert_eq!(ids, vec![1, 2, 3]);
/// ```
pub fn parse_id_list<T: FromStr>(s: &str) -> Vec<T> {
    s.split(',')
        .filter_map(|s| s.trim().parse::<T>().ok())
        .collect()
}
