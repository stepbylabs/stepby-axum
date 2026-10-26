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

use std::fmt;
use std::str::FromStr;

/// 单个批量入口允许的 ID 数量上限。
///
/// 上限放在解析器里而不是各处理器里：畸形/超长列表若先被解析成 Vec 再逐个查库，
/// 资源已经被消耗；解析阶段就能拒绝才是真正的背压边界。
pub const MAX_ID_LIST_LEN: usize = 1000;

/// `parse_id_list` 的失败原因（不携带原始输入，避免把用户输入反射进日志/响应）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParseIdListError {
    /// 逗号之间出现空项（含首尾逗号、连续逗号）
    EmptyItem,
    /// 某一项无法解析为目标类型
    InvalidItem,
    /// 项数超过 [`MAX_ID_LIST_LEN`]
    TooMany,
}

impl fmt::Display for ParseIdListError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyItem => write!(f, "id list contains an empty item"),
            Self::InvalidItem => write!(f, "id list contains a non-numeric item"),
            Self::TooMany => write!(f, "id list exceeds {MAX_ID_LIST_LEN} items"),
        }
    }
}

impl std::error::Error for ParseIdListError {}

/// 解析逗号分隔的 ID 列表（严格版）。
///
/// 与旧实现的关键差异：**任何一项不合法都返回错误，不再静默丢弃**。
/// 旧语义 `1,abc,2 → [1,2]` 会让删除端点"按畸形输入删掉一部分"并返回成功，
/// 调用方无从知道哪一条没有生效；批量破坏性操作的输入必须整批可判定。
///
/// - 空串/纯空白 ⇒ `Ok(vec![])`（保留"未提供"的既有语义，由各调用点自行决定是否拒绝）；
/// - 逗号之间出现空项（`1,,2`、`1,`）⇒ [`ParseIdListError::EmptyItem`]；
/// - 任一项解析失败 ⇒ [`ParseIdListError::InvalidItem`]；
/// - 超过 [`MAX_ID_LIST_LEN`] 项 ⇒ [`ParseIdListError::TooMany`]。
///
/// # 示例
/// ```
/// use stepby_axum::utils::parse_id_list;
/// let ids = parse_id_list::<i64>("1, 2, 3").expect("valid ids");
/// assert_eq!(ids, vec![1, 2, 3]);
/// assert!(parse_id_list::<i64>("1,abc").is_err());
/// ```
pub fn parse_id_list<T: FromStr>(s: &str) -> Result<Vec<T>, ParseIdListError> {
    if s.trim().is_empty() {
        return Ok(Vec::new());
    }
    let mut out = Vec::new();
    for raw in s.split(',') {
        let item = raw.trim();
        if item.is_empty() {
            return Err(ParseIdListError::EmptyItem);
        }
        let value = item
            .parse::<T>()
            .map_err(|_| ParseIdListError::InvalidItem)?;
        out.push(value);
        if out.len() > MAX_ID_LIST_LEN {
            return Err(ParseIdListError::TooMany);
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_id_list_accepts_trimmed_integers() {
        assert_eq!(parse_id_list::<i64>(" 1, 2 ,3 ").unwrap(), vec![1, 2, 3]);
        assert_eq!(parse_id_list::<i32>("7").unwrap(), vec![7]);
    }

    #[test]
    fn parse_id_list_keeps_empty_input_as_empty_vec() {
        assert_eq!(parse_id_list::<i64>("").unwrap(), Vec::<i64>::new());
        assert_eq!(parse_id_list::<i64>("   ").unwrap(), Vec::<i64>::new());
    }

    #[test]
    fn parse_id_list_rejects_partial_garbage_instead_of_dropping_it() {
        // 旧实现的真实缺陷：1,abc,2 → [1,2]，调用方以为整批都删了。
        assert_eq!(
            parse_id_list::<i64>("1,abc,2"),
            Err(ParseIdListError::InvalidItem)
        );
        assert_eq!(
            parse_id_list::<i64>("1,,2"),
            Err(ParseIdListError::EmptyItem)
        );
        assert_eq!(
            parse_id_list::<i64>("1,2,"),
            Err(ParseIdListError::EmptyItem)
        );
        assert_eq!(
            parse_id_list::<i64>("1.5"),
            Err(ParseIdListError::InvalidItem)
        );
    }

    #[test]
    fn parse_id_list_rejects_oversized_lists() {
        let at_limit = (1..=MAX_ID_LIST_LEN)
            .map(|n| n.to_string())
            .collect::<Vec<_>>()
            .join(",");
        assert_eq!(
            parse_id_list::<i64>(&at_limit).unwrap().len(),
            MAX_ID_LIST_LEN
        );
        let over_limit = format!("{at_limit},{}", MAX_ID_LIST_LEN + 1);
        assert_eq!(
            parse_id_list::<i64>(&over_limit),
            Err(ParseIdListError::TooMany)
        );
    }
}
