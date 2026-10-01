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

/// 兼容解析：优先 RFC3339（含 Z/偏移，按 UTC 语义还原），回退空格 / T 分隔格式。
///
/// 三个反序列化入口（[`deserialize`] / [`deserialize_opt`] / [`deserialize_double_opt`]）共用，
/// 避免解析逻辑三处漂移；失败时返回最后一次尝试的错误文本（由调用方包成 serde 错误）。
fn parse_flexible(s: &str) -> Result<NaiveDateTime, String> {
    if let Ok(dt) = DateTime::parse_from_rfc3339(s) {
        return Ok(dt.naive_utc());
    }
    if let Ok(dt) = NaiveDateTime::parse_from_str(s, DATETIME_FORMAT) {
        return Ok(dt);
    }
    NaiveDateTime::parse_from_str(s, "%Y-%m-%dT%H:%M:%S").map_err(|e| e.to_string())
}

/// 反序列化，兼容 RFC3339（含 Z/偏移）与空格/T 分隔格式
pub fn deserialize<'de, D>(deserializer: D) -> Result<NaiveDateTime, D::Error>
where
    D: Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    parse_flexible(&s).map_err(serde::de::Error::custom)
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
        Some(s) => parse_flexible(&s)
            .map(Some)
            .map_err(serde::de::Error::custom),
    }
}

/// 反序列化「三态」`Option<Option<NaiveDateTime>>`（部分更新语义）：
/// - 字段缺省 → `None`（由 `#[serde(default)]` 提供，表示**不修改**）；
/// - 显式 `null` / 空字符串 → `Some(None)`（表示**清空**，如"到期时间置空 = 永不过期"）；
/// - 有效日期字符串 → `Some(Some(dt))`（表示**设置为该值**）。
pub fn deserialize_double_opt<'de, D>(
    deserializer: D,
) -> Result<Option<Option<NaiveDateTime>>, D::Error>
where
    D: Deserializer<'de>,
{
    let opt = Option::<String>::deserialize(deserializer)?;
    match opt {
        Some(s) if !s.is_empty() => parse_flexible(&s)
            .map(|dt| Some(Some(dt)))
            .map_err(serde::de::Error::custom),
        // null / 空字符串 → 显式清空
        _ => Ok(Some(None)),
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

    // ---------- 以下为补充覆盖：now/today、序列化、反序列化全分支 ----------

    fn dt(y: i32, mo: u32, d: u32, h: u32, mi: u32, s: u32) -> NaiveDateTime {
        NaiveDateTime::new(
            NaiveDate::from_ymd_opt(y, mo, d).expect("合法日期"),
            NaiveTime::from_hms_opt(h, mi, s).expect("合法时间"),
        )
    }

    #[test]
    fn now_naive_is_close_to_utc_now() {
        // now_naive 语义为 UTC：与 Utc::now().naive_local() 相差应 < 5 秒
        let before = Utc::now().naive_local();
        let now = now_naive();
        let after = Utc::now().naive_local();
        assert!(now >= before && now <= after, "now_naive 应落在查询区间内");
    }

    #[test]
    fn today_utc_matches_utc_date() {
        let expected = Utc::now().date_naive();
        assert_eq!(today_utc(), expected);
    }

    #[test]
    fn serialize_outputs_rfc3339_with_z() {
        let dt = dt(2026, 1, 2, 3, 4, 5);
        // 直接调用 serialize（经 serde_json::Serializer）
        let out = serde_json::to_string(&SerializeProbe(dt)).expect("序列化失败");
        assert_eq!(out, r#""2026-01-02T03:04:05Z""#);
    }

    /// 包装类型：复用 datetime::serialize 走完整 serde_json 路径
    #[derive(serde::Serialize)]
    struct SerializeProbe(#[serde(serialize_with = "serialize")] NaiveDateTime);

    #[test]
    fn deserialize_accepts_various_formats() {
        use serde_json::Value;
        let cases = [
            r#""2026-01-02T03:04:05Z""#,
            r#""2026-01-02T03:04:05+00:00""#,
            r#""2026-01-02 03:04:05""#,
            r#""2026-01-02T03:04:05""#,
        ];
        for c in cases {
            let v: Value = serde_json::from_str(c).unwrap();
            let deser: NaiveDateTime = deserialize(&v).expect("应解析成功");
            assert_eq!(deser, dt(2026, 1, 2, 3, 4, 5), "输入: {c}");
        }
    }

    #[test]
    fn deserialize_applies_utc_offset() {
        use serde_json::Value;
        // +08:00 → naive_utc 为 2026-01-02 03:04:05（本地 11:04:05 前移 8 小时）
        let v: Value = serde_json::from_str(r#""2026-01-02T11:04:05+08:00""#).unwrap();
        let deser: NaiveDateTime = deserialize(&v).expect("带偏移应解析成功");
        assert_eq!(deser, dt(2026, 1, 2, 3, 4, 5));
    }

    #[test]
    fn deserialize_rejects_invalid() {
        use serde_json::Value;
        let v: Value = serde_json::from_str(r#""not-a-date""#).unwrap();
        assert!(deserialize(&v).is_err());
    }

    #[test]
    fn serialize_opt_none_is_null_and_some_serializes() {
        #[derive(serde::Serialize)]
        struct OptProbe(#[serde(serialize_with = "serialize_opt")] Option<NaiveDateTime>);
        let none = serde_json::to_string(&OptProbe(None)).unwrap();
        assert_eq!(none, r#"null"#);
        let some = serde_json::to_string(&OptProbe(Some(dt(2026, 1, 2, 3, 4, 5)))).unwrap();
        assert_eq!(some, r#""2026-01-02T03:04:05Z""#);
    }

    #[test]
    fn deserialize_opt_handles_null_empty_and_valid() {
        use serde_json::Value;
        // null → None
        let v: Value = serde_json::json!(null);
        assert_eq!(deserialize_opt(&v).unwrap(), None);
        // 空串 → None
        let v: Value = serde_json::json!("");
        assert_eq!(deserialize_opt(&v).unwrap(), None);
        // RFC3339 → Some
        let v: Value = serde_json::json!("2026-01-02T03:04:05Z");
        assert_eq!(deserialize_opt(&v).unwrap(), Some(dt(2026, 1, 2, 3, 4, 5)));
        // 空格分隔 → Some
        let v: Value = serde_json::json!("2026-01-02 03:04:05");
        assert_eq!(deserialize_opt(&v).unwrap(), Some(dt(2026, 1, 2, 3, 4, 5)));
        // T 分隔 → Some
        let v: Value = serde_json::json!("2026-01-02T03:04:05");
        assert_eq!(deserialize_opt(&v).unwrap(), Some(dt(2026, 1, 2, 3, 4, 5)));
        // 非法 → Err
        let v: Value = serde_json::json!("garbage");
        assert!(deserialize_opt(&v).is_err());
    }

    #[test]
    fn deserialize_opt_applies_utc_offset() {
        use serde_json::Value;
        let v: Value = serde_json::json!("2026-01-02T11:04:05+08:00");
        assert_eq!(deserialize_opt(&v).unwrap(), Some(dt(2026, 1, 2, 3, 4, 5)));
    }

    #[test]
    fn deserialize_double_opt_tri_state_semantics() {
        #[derive(serde::Deserialize)]
        struct Dto {
            #[serde(default, deserialize_with = "deserialize_double_opt")]
            expire_time: Option<Option<NaiveDateTime>>,
        }
        // 字段缺省 → None（不修改）
        let d: Dto = serde_json::from_str("{}").unwrap();
        assert_eq!(d.expire_time, None);
        // 显式 null → Some(None)（清空 = 永不过期）
        let d: Dto = serde_json::from_str(r#"{"expire_time":null}"#).unwrap();
        assert_eq!(d.expire_time, Some(None));
        // 空串 → Some(None)（兼容前端清空后传空串）
        let d: Dto = serde_json::from_str(r#"{"expire_time":""}"#).unwrap();
        assert_eq!(d.expire_time, Some(None));
        // 有效日期串（空格分隔 / RFC3339）→ Some(Some(dt))
        let d: Dto = serde_json::from_str(r#"{"expire_time":"2026-01-02 03:04:05"}"#).unwrap();
        assert_eq!(d.expire_time, Some(Some(dt(2026, 1, 2, 3, 4, 5))));
        let d: Dto =
            serde_json::from_str(r#"{"expire_time":"2026-01-02T11:04:05+08:00"}"#).unwrap();
        assert_eq!(d.expire_time, Some(Some(dt(2026, 1, 2, 3, 4, 5))));
        // 非法串 → 解析失败（不静默降级为清空）
        assert!(serde_json::from_str::<Dto>(r#"{"expire_time":"garbage"}"#).is_err());
    }
}
