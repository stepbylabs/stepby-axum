//! NaiveDateTime 自定义序列化模块
//!
//! 默认 chrono::NaiveDateTime 序列化为 ISO 8601 格式（T 分隔：2026-01-01T00:00:00），
//! 前端 ruoyi-vue3-ts 期望空格分隔格式（2026-01-01 00:00:00）。
//!
//! 使用方式：
//! ```ignore
//! #[serde(serialize_with = "crate::common::datetime::serialize",
//!         deserialize_with = "crate::common::datetime::deserialize")]
//! pub create_time: Option<NaiveDateTime>,
//! ```
//!
//! 反序列化兼容多种格式：
//! - `2026-01-01 00:00:00`（空格分隔，前端回传）
//! - `2026-01-01T00:00:00`（ISO 8601，默认格式）

use chrono::NaiveDateTime;
use serde::{Deserialize, Deserializer, Serializer};

const DATETIME_FORMAT: &str = "%Y-%m-%d %H:%M:%S";

/// 序列化 NaiveDateTime 为 `2026-01-01 00:00:00` 格式
pub fn serialize<S>(dt: &NaiveDateTime, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(&dt.format(DATETIME_FORMAT).to_string())
}

/// 反序列化，兼容空格分隔和 T 分隔两种格式
pub fn deserialize<'de, D>(deserializer: D) -> Result<NaiveDateTime, D::Error>
where
    D: Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    // 优先尝试空格分隔格式
    if let Ok(dt) = NaiveDateTime::parse_from_str(&s, DATETIME_FORMAT) {
        return Ok(dt);
    }
    // 回退到 ISO 8601 格式（T 分隔）
    NaiveDateTime::parse_from_str(&s, "%Y-%m-%dT%H:%M:%S").map_err(serde::de::Error::custom)
}

/// 序列化 Option<NaiveDateTime>，None 输出为 null
pub fn serialize_opt<S>(dt: &Option<NaiveDateTime>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    match dt {
        Some(t) => serialize(t, serializer),
        None => serializer.serialize_none(),
    }
}

/// 反序列化 Option<NaiveDateTime>，支持 null/空字符串/有效日期
pub fn deserialize_opt<'de, D>(deserializer: D) -> Result<Option<NaiveDateTime>, D::Error>
where
    D: Deserializer<'de>,
{
    let opt = Option::<String>::deserialize(deserializer)?;
    match opt {
        None => Ok(None),
        Some(ref s) if s.is_empty() => Ok(None),
        Some(s) => {
            if let Ok(dt) = NaiveDateTime::parse_from_str(&s, DATETIME_FORMAT) {
                return Ok(Some(dt));
            }
            NaiveDateTime::parse_from_str(&s, "%Y-%m-%dT%H:%M:%S")
                .map(Some)
                .map_err(serde::de::Error::custom)
        }
    }
}
