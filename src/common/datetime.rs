//! NaiveDateTime 自定义序列化与时区工具模块
//!
//! ## 时区契约（C4/C5 UTC 迁移）
//! 全项目持久化时间戳统一以 **UTC** 语义写入（`now_naive()`）并存储于无时区 `NaiveDateTime`
//! 列；序列化到前端时输出 **ISO 8601（`T` 分隔，如 `2026-01-01T00:00:00`）**，前端据此按 UTC 解析
//! 并展示为用户本地时间。空格分隔串仅用于"显示型本地字符串"（如文件名、会话登录时间、报告元数据），
//! 前端按本地解释，不参与存储时间戳比较。
//!
//! 使用方式：
//! ```ignore
//! #[serde(serialize_with = "crate::common::datetime::serialize",
//!         deserialize_with = "crate::common::datetime::deserialize")]
//! pub create_time: Option<NaiveDateTime>,
//! ```
//!
//! 反序列化兼容多种格式（前端回传 / 日期选择器可能给空格或 T）：
//! - `2026-01-01 00:00:00`（空格分隔，前端日期选择器）
//! - `2026-01-01T00:00:00`（ISO 8601）

use chrono::{DateTime, Local, NaiveDate, NaiveDateTime, NaiveTime, Utc};
use serde::{Deserialize, Deserializer, Serializer};

const DATETIME_FORMAT: &str = "%Y-%m-%d %H:%M:%S";
/// 序列化（输出到前端）采用 ISO 8601 `T` 分隔，前端按 UTC 解析。
const DATETIME_ISO: &str = "%Y-%m-%dT%H:%M:%S";

/// 当前 UTC 时刻的 `NaiveDateTime`（语义为 UTC，不含时区信息）。
///
/// 全项目持久化时间戳（create_time / update_time / oper_time / login_time 等）统一经此入口写入，
/// 保证时区一致、与服务器本地时区无关，避免跨时区部署下时间戳错乱。
pub fn now_naive() -> NaiveDateTime {
    Utc::now().naive_local()
}

/// 当前 UTC 日期（按"天"边界使用：清理截止、今日统计、注册周期等）。
///
/// 与 [`now_naive`] 同为 UTC 语义，确保"天"边界与 UTC 存储数据一致。
pub fn today_utc() -> NaiveDate {
    Utc::now().date_naive()
}

/// 将"用户本地日期"字符串（`%Y-%m-%d`）转换为对应的 UTC `NaiveDateTime`
/// （即该本地日 00:00 对应的 UTC 瞬间）。
///
/// 用于日期范围搜索过滤（beginTime/endTime）：前端回传的是用户本地日（如 `2026-08-05`），
/// 而库内时间戳已统一以 UTC 存储。此处把本地日起点按**服务器本地时区**解释并换算为 UTC，
/// 使过滤边界与 UTC 数据一致。
///
/// 前提假设：服务器时区 ≈ 用户时区（ruoyi 标准单区域部署假设）。若服务器以 UTC 运行，
/// 则本函数等价于直接解析为 UTC 日起点（无偏移）。
///
/// 返回 `None` 表示字符串格式非法。
pub fn parse_local_date_to_utc_naive(s: &str) -> Option<NaiveDateTime> {
    let d = NaiveDate::parse_from_str(s, "%Y-%m-%d").ok()?;
    let local_dt = d.and_time(NaiveTime::MIN);
    let dt_local: DateTime<Local> = local_dt.and_local_timezone(Local).single()?;
    Some(dt_local.with_timezone(&Utc).naive_local())
}

/// 序列化 NaiveDateTime 为 ISO 8601 `2026-01-01T00:00:00`（UTC 语义，前端按 UTC 解析）
pub fn serialize<S>(dt: &NaiveDateTime, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(&dt.format(DATETIME_ISO).to_string())
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
