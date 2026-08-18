//! NaiveDateTime 自定义序列化与时区工具模块
//!
//! ## 时区契约（C4/C5 UTC 迁移）
//! 全项目持久化时间戳统一以 **UTC** 语义写入（`now_naive()`）并存储于无时区 `NaiveDateTime`
//! 列；序列化到前端时输出 **ISO 8601（`T` 分隔，如 `2026-01-01T00:00:00`）**，前端/所有 JSON 消费者据此按 UTC 解析
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

use crate::common::error::ServiceError;

const DATETIME_FORMAT: &str = "%Y-%m-%d %H:%M:%S";
/// 序列化（输出到前端）采用 RFC3339（带 `Z`），前端按 UTC 解析。
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
/// 前提假设：服务器时区 ≈ 用户时区（标准单区域部署假设）。若服务器以 UTC 运行，
/// 则本函数等价于直接解析为 UTC 日起点（无偏移）。
///
/// 返回 `None` 表示字符串格式非法。
pub fn parse_local_date_to_utc_naive(s: &str) -> Option<NaiveDateTime> {
    let d = NaiveDate::parse_from_str(s, "%Y-%m-%d").ok()?;
    let local_dt = d.and_time(NaiveTime::MIN);
    let dt_local: DateTime<Local> = local_dt.and_local_timezone(Local).single()?;
    Some(dt_local.with_timezone(&Utc).naive_local())
}

/// 解析日期查询参数（前端回传的 `%Y-%m-%d` 本地日）为对应的 UTC `NaiveDateTime`。
///
/// 统一各 Service 的 `begin_time` / `end_time` 时间范围过滤解析入口：
/// - 复用 [`parse_local_date_to_utc_naive`] 做"本地日 → UTC 瞬间"换算，
///   使过滤边界与库内 UTC 存储时间戳一致（修复此前部分 service 用裸
///   `NaiveDateTime::parse_from_str` 导致非 UTC 时区下边界错位的问题）。
/// - 解析失败返回 `400` `error.common.time_format_invalid`。
///
/// 各 Service 的私有 `parse_time` 应统一委托本函数，消除重复样板（见 P2 收敛）。
pub fn parse_query_date(s: &str) -> Result<NaiveDateTime, ServiceError> {
    parse_local_date_to_utc_naive(s).ok_or_else(|| {
        ServiceError::bad_request(&crate::tr!("error.common.time_format_invalid", s = s))
    })
}

/// 序列化 NaiveDateTime 为 RFC3339 `2026-01-01T00:00:00Z`（UTC 语义，补 Z 使所有 JSON 消费者按 UTC 解析）
pub fn serialize<S>(dt: &NaiveDateTime, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(&format!("{}Z", dt.format(DATETIME_ISO)))
}

/// 反序列化，兼容 RFC3339（含 Z/偏移）与空格/T 分隔格式
pub fn deserialize<'de, D>(deserializer: D) -> Result<NaiveDateTime, D::Error>
where
    D: Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    // 优先 RFC3339（含 Z 或偏移），按 UTC 语义还原
    if let Ok(dt) = DateTime::parse_from_rfc3339(&s) {
        return Ok(dt.naive_utc());
    }
    // 回退到无时区格式（空格 / T 分隔），保持向后兼容
    if let Ok(dt) = NaiveDateTime::parse_from_str(&s, DATETIME_FORMAT) {
        return Ok(dt);
    }
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
            // 与 deserialize 一致：优先 RFC3339，回退空格/T 分隔
            if let Ok(dt) = DateTime::parse_from_rfc3339(&s) {
                return Ok(Some(dt.naive_utc()));
            }
            if let Ok(dt) = NaiveDateTime::parse_from_str(&s, DATETIME_FORMAT) {
                return Ok(Some(dt));
            }
            NaiveDateTime::parse_from_str(&s, "%Y-%m-%dT%H:%M:%S")
                .map(Some)
                .map_err(serde::de::Error::custom)
        }
    }
}

/// 生成 Entity 的 `ActiveModelBehavior::before_save` 实现：
/// 插入时维护 `create_time`，每次更新维护 `update_time`（统一 UTC 语义）。
///
/// 消除各 entity 中重复的 11 份时间戳样板（P2 去重）。
///
/// 用法：在 `#[async_trait::async_trait] impl ActiveModelBehavior for ActiveModel { ... }`
/// 体内调用 `crate::impl_timestamped_before_save!();` 即可。`DbErr` / `ConnectionTrait` /
/// `Set` 在调用方模块作用域内即可（entity 文件已 `use sea_orm::*` 或等价导入）。
/// 为 Entity 的 `ActiveModel` 生成完整的 `ActiveModelBehavior` 实现，
/// 在 `before_save` 中统一维护 `create_time` / `update_time`（UTC 语义）。
///
/// 消除各 entity 中重复的 11 份时间戳样板（P2 去重）。
///
/// 用法：在 entity 文件中（Relation 定义之后）直接写
/// `crate::impl_timestamped_active_model!();`
/// 宏会生成如下等价代码（整个 impl 块由宏产出，避免宏调用嵌套在
/// `#[async_trait]` impl 块内与 proc-macro 的交互问题）：
///
/// ```ignore
/// #[async_trait::async_trait]
/// impl ActiveModelBehavior for ActiveModel {
///     async fn before_save<C>(self, _db: &C, insert: bool) -> Result<Self, DbErr>
///     where C: ConnectionTrait {
///         let now = crate::common::datetime::now_naive();
///         let mut this = self;
///         if insert { this.create_time = Set(Some(now)); }
///         this.update_time = Set(Some(now));
///         Ok(this)
///     }
/// }
/// ```
///
/// 调用方需已 `use sea_orm::Set;`（entity 文件通常 `use sea_orm::entity::prelude::*`
/// 已包含 `Set`）。
#[macro_export]
macro_rules! impl_timestamped_active_model {
    () => {
        #[async_trait::async_trait]
        impl sea_orm::entity::prelude::ActiveModelBehavior for ActiveModel {
            async fn before_save<C>(
                self,
                _db: &C,
                insert: bool,
            ) -> ::core::result::Result<Self, sea_orm::entity::prelude::DbErr>
            where
                C: sea_orm::entity::prelude::ConnectionTrait,
            {
                let now = $crate::common::datetime::now_naive();
                let mut this = self;
                if insert {
                    this.create_time = Set(Some(now));
                }
                this.update_time = Set(Some(now));
                ::core::result::Result::Ok(this)
            }
        }
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_query_date_valid() {
        // 合法日期应成功解析为某个 UTC NaiveDateTime（具体值依赖服务器时区，仅验证 Ok）
        assert!(parse_query_date("2026-08-05").is_ok());
    }

    #[test]
    fn test_parse_query_date_invalid() {
        // 非法格式应返回 400 错误（与 timezone 无关，确定性断言）
        let err = parse_query_date("2026-13-40");
        assert!(err.is_err());
        let err = err.unwrap_err();
        assert_eq!(err.code, 400);
    }

    #[test]
    fn test_parse_local_date_to_utc_naive_invalid_none() {
        assert!(parse_local_date_to_utc_naive("not-a-date").is_none());
        assert!(parse_local_date_to_utc_naive("2026-02-30").is_none());
    }

    #[test]
    fn test_parse_local_date_to_utc_naive_valid_some() {
        assert!(parse_local_date_to_utc_naive("2026-08-05").is_some());
    }
}
