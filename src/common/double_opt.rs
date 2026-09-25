//! 「三态」字段反序列化助手（部分更新 / PATCH 语义）
//!
//! **为什么需要它**：serde 对 `Option<Option<T>>` 的默认行为**不是**三态——
//! JSON `null` 会被解析为**外层 `None`**，与外层 `Some(None)` 无法区分，
//! 于是"显式清空"会被静默降级为"不修改"。故写入方必须显式声明本助手：
//!
//! - 字段**缺省**（不提交）→ `None`（**不修改**；由字段上的 `#[serde(default)]` 提供）
//! - 显式 `null` → `Some(None)`（**清空**）
//! - 提交值 → `Some(Some(v))`（**设置**）
//!
//! 用法：
//! ```ignore
//! #[serde(default, deserialize_with = "double_opt::deserialize_double_opt")]
//! pub package_id: Option<Option<i64>>,
//! ```
//! 日期时间字段另见 [`crate::common::datetime::deserialize_double_opt`]（额外兼容多格式日期串）。

use serde::{Deserialize, Deserializer};

/// 三态反序列化（通用 `T`）：`null` → `Some(None)`；缺省 → `None`（需 `#[serde(default)]`）；值 → `Some(Some(v))`。
pub fn deserialize_double_opt<'de, D, T>(deserializer: D) -> Result<Option<Option<T>>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    Ok(Some(Option::<T>::deserialize(deserializer)?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;

    #[derive(Debug, Deserialize)]
    struct Dto {
        #[serde(default, deserialize_with = "deserialize_double_opt")]
        v: Option<Option<i64>>,
    }

    #[test]
    fn absent_field_means_keep() {
        let dto: Dto = serde_json::from_str("{}").expect("缺省字段应可解析");
        assert_eq!(dto.v, None, "字段缺省 = 不修改");
    }

    #[test]
    fn explicit_null_means_clear() {
        let dto: Dto = serde_json::from_str(r#"{"v":null}"#).expect("null 应可解析");
        assert_eq!(
            dto.v,
            Some(None),
            "显式 null = 清空（关键：默认 serde 行为会误判为不修改）"
        );
    }

    #[test]
    fn value_means_set() {
        let dto: Dto = serde_json::from_str(r#"{"v":7}"#).expect("值应可解析");
        assert_eq!(dto.v, Some(Some(7)), "提交值 = 设置");
    }
}
