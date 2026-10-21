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

/// 种子/兜底**拼 SQL 字面量**时的当前时间表达式（批七十四 B1 归口）。
///
/// 定义在 `migration::seed_now_expr`（本函数只是再导出，使 app 侧与迁移侧共用
/// **同一个函数对象**，杜绝"两份判据"）：三方言统一返回带引号的 **UTC** 字面量。
/// 改造前 `src/initialize/` 有 5 份同构 helper（`flow_now` 等）、`migration` 有 40 份
/// `now_expr` 副本，且一律用 `chrono::Local::now()` ⇒ **种子行带本机挂钟、运行行带 UTC**，
/// 同一库两种口径并存；`seed_diff` 里长期被记成 "informational" 的
/// `sys_user.login_date` 8 小时差异即是其症状（不是运行态演进，是口径分裂）。
///
/// 与 [`now_naive`] 的分工：本函数产 SQL 片段（给种子 INSERT 用），`now_naive()` 产
/// `NaiveDateTime`（给 sea-orm `Set(...)` 用）——两者同为 UTC 语义，是同一口径的两种形态。
pub use migration::seed_now_expr;

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

/// 序列化 `Option<NaiveDateTime>`，None 输出为 null
pub fn serialize_opt<S>(dt: &Option<NaiveDateTime>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    match dt {
        Some(t) => serialize(t, serializer),
        None => serializer.serialize_none(),
    }
}

/// 反序列化 `Option<NaiveDateTime>`，支持 null/空字符串/有效日期
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
    /// 落库时间列的真实写入形态（ActiveModel 赋值 或 INSERT/UPDATE 文本含时间列）。
    /// 单独成函数：控制组要能脱离文件系统**直接**验证判据本身。
    fn db_time_write_re() -> regex::Regex {
        regex::Regex::new(
        r"(?s)(_time|_date)\s*:\s*Set\(|(INSERT INTO|UPDATE\s+\w+\s+SET)[\s\S]{0,400}?(create_time|update_time|oper_time|login_time)",
    )
    .expect("落库时间列正则编译失败")
    }

    /// 函数起始（含 `pub` / `pub(crate)` / `async` 变体），用于把源码切成函数窗口。
    /// **窗口止于下一个函数**（同 b72 spawn 扫描器口径）：否则隔壁合法用法会洗白违规项。
    fn fn_start_re() -> regex::Regex {
        regex::Regex::new(r"(?m)^\s{0,4}(?:pub(?:\([^)]*\))?\s+)?(?:async\s+)?fn\s+([A-Za-z0-9_]+)")
            .expect("函数起始正则编译失败")
    }
    // ==================== 批七十四 B1：落库时间口径的单一事实源锁 ====================

    /// 去注释：剥掉行首 `//` / `///` / `//!` 与块注释内容（简化为行级判断）。
    /// **为什么必须先剥**：本批修法在源码里留下了大量"原为 `chrono::Local::now()`"的
    /// 说明文字，不剥注释的锁会把自己的文档报成违规（假红 ⇒ 人们很快会把锁放宽，
    /// 那才是真正的失效）。
    fn strip_comments(text: &str) -> String {
        crate::common::prod_scan::normalize(
            text,
            &crate::common::prod_scan::Scan {
                strip_test_code: false,
                comments: crate::common::prod_scan::Comments::DropBlocks,
                ..Default::default()
            },
        )
        .join("\n")
    }

    /// 采集改走共享扫描器（批七十五 B9）；语义与本锁原实现一致（递归、跳过 `target`、排序）。
    fn collect_rs(dir: &std::path::Path) -> Vec<std::path::PathBuf> {
        crate::common::prod_scan::walk_rs(dir)
    }

    /// 种子/兜底**写库路径**禁止出现本机挂钟；三方言统一由 `seed_now_expr` 产 UTC 字面量。
    ///
    /// 改造前的规模（本轮实测，非估算）：`migration/src/migrations/*.rs` 里
    /// **40 份**同构 `now_expr`（36 个 `fn now_expr` + 4 处 `up()` 内联 `match backend`），
    /// `src/initialize/` 里 **8 处**内联 + `flow_now` 一份，全部写 `chrono::Local::now()`；
    /// 另 `data_rule_service.rs:181` 用 `Local::now().naive_local()` 写 `create_time`。
    /// ⇒ 同一库内"种子行=本机挂钟 / 运行行=UTC"两种口径并存，`seed_diff` 里
    /// `sys_user.login_date` 的 8 小时差异长期被误记为 informational。
    ///
    /// **本轮（存量库逐条前推迁移时）补的第二半**：只禁 `Local::now()` 的判据漏掉了
    /// "分支里自产 `NOW()` / `CURRENT_TIMESTAMP`"这一族（6 个迁移、共 7 处，
    /// `m20261004_000002/3`、`m20261006_000001`(×2)/`000002`、`m20261008_000001`）。
    /// MySQL/PG 的 `NOW()` 取的是**会话时区**挂钟，与 `seed_now_expr` 的 UTC 字面量不同源
    /// ⇒ 台账 §3.5 说的"换库即换口径"这条漂移当时并没被消掉，因为源码里根本没有
    /// `Local::now()` 这个串。DDL 里的 `DEFAULT CURRENT_TIMESTAMP`（不带引号、不作分支值）
    /// 不在本判据内：那是"默认值兜底"的方言差异，台账已如实登记，写路径恒显式赋值。
    #[test]
    fn seed_paths_never_use_local_clock() {
        /// 自建方言时间来源：匹配分支里产出的 `NOW()` / `CURRENT_TIMESTAMP` 字面量。
        /// 抽成函数是为了让**真扫描与控制组走同一条判据**（本仓反复自曝的"锁与自己的
        /// 对照组不同源"缺陷，这里不留第二个机会）。
        fn dialect_time_source(line: &str) -> bool {
            line.contains("=> \"NOW()\"") || line.contains("=> \"CURRENT_TIMESTAMP\"")
        }

        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let dirs = [root.join("migration/src"), root.join("src/initialize")];
        let mut hits: Vec<String> = Vec::new();
        let mut dhits: Vec<String> = Vec::new();
        let mut scanned = 0usize;
        for dir in dirs {
            let files = collect_rs(&dir);
            assert!(
                !files.is_empty(),
                "{} 下没读到 .rs ⇒ 本锁没有跑，不是通过",
                dir.display()
            );
            for f in files {
                scanned += 1;
                let text = strip_comments(&std::fs::read_to_string(&f).unwrap_or_default());
                for (i, line) in text.lines().enumerate() {
                    if line.contains("Local::now()") {
                        hits.push(format!("{}:{} {}", f.display(), i + 1, line.trim()));
                    }
                    if dialect_time_source(line) {
                        dhits.push(format!("{}:{} {}", f.display(), i + 1, line.trim()));
                    }
                }
            }
        }
        // 控制组：扫描面必须真的看见过内容（文件数下标取本轮实测）
        assert!(
            scanned >= 60,
            "只扫了 {scanned} 个文件 ⇒ 目录定位失效，本锁即将空转（不是通过）"
        );
        // 控制组（双向）：新判据必须抓到合成违规，且不得把唯一事实源的委托形态抓成违规
        let synth = "let now = match backend {\n    MySql => \"NOW()\",\n    _ => \"CURRENT_TIMESTAMP\",\n};";
        assert_eq!(
            synth.lines().filter(|l| dialect_time_source(l)).count(),
            2,
            "方言时间判据抓不到合成违规 ⇒ 那个 0 是虚零"
        );
        let delegated = "let now = crate::seed_now_expr();";
        assert_eq!(
            delegated.lines().filter(|l| dialect_time_source(l)).count(),
            0,
            "委托形态被误判 ⇒ 唯一事实源自己会报红，判据写坏了"
        );
        assert!(
            dhits.is_empty(),
            "种子路径自建方言时间来源（NOW()/CURRENT_TIMESTAMP 取会话时区挂钟），换库即换口径：
{}",
            dhits.join(
                "
"
            )
        );
        assert!(
            hits.is_empty(),
            "种子/兜底写库路径仍使用本机挂钟，落库时间口径将随服务器时区漂移：
{}",
            hits.join(
                "
"
            )
        );

        // 唯一来源必须是 UTC：口径写错时全仓一起错，故单独钉一行。
        // **不用花括号配平切函数体**——`format!("'{}'", …)` 里的 `{}` 会把切分点提前，
        // 取到半截函数体（本轮首跑即因此报"未取 UTC"）；改用"止于下一个函数"的窗口，
        // 与 b72 spawn 扫描器、b74 顺序锁同一口径。
        let mig_lib = strip_comments(
            &std::fs::read_to_string(root.join("migration/src/lib.rs")).unwrap_or_default(),
        );
        let sig_at = mig_lib
            .find("pub fn seed_now_expr() -> String")
            .expect("seed_now_expr 不存在 ⇒ 单一事实源已被删除或改名，本锁失去约束对象");
        let after = &mig_lib[sig_at..];
        let body_end = ["\npub fn ", "\nfn ", "\nimpl ", "\npub use "]
            .iter()
            .filter_map(|n| after[1..].find(n).map(|p| p + 1))
            .min()
            .unwrap_or(after.len());
        let body = &after[..body_end];
        assert!(
            body.contains("Utc::now()"),
            "seed_now_expr 未取 UTC（函数体窗口：{body}）⇒ 换库/换时区即换口径"
        );
        assert!(
            !body.contains("Local::now()") && !body.contains("NOW()"),
            "seed_now_expr 仍含本机挂钟或方言 NOW() 分支（函数体窗口：{body}）"
        );

        // 合成违规必须被抓（证明上面那条不是恒真断言）
        let synth = "let now = chrono::Local::now().format(\"%Y-%m-%d %H:%M:%S\");
";
        assert!(
            strip_comments(synth)
                .lines()
                .any(|l| l.contains("Local::now()")),
            "合成违规未被抓到 ⇒ 判据失效（本锁是虚锁）"
        );
        // 而注释里的同款文本不得被抓（防止把文档报成违规）
        assert!(
            !strip_comments("// let now = chrono::Local::now();").contains("Local::now()"),
            "注释未被剥除 ⇒ 本锁会因自己的说明文字假红，很快被人放宽"
        );
    }

    /// **裸 SQL 里的时间来源**（b83 补的第三族）：DML 文本内直接写 `CURRENT_TIMESTAMP` /
    /// `NOW()` 一律禁止。SQLite 落 **UTC**，MySQL/PG 落**会话时区**——
    /// `deploy/docker-compose.db.yml` 给 PG 容器设 `TZ: Asia/Shanghai`，本机实测同一条语句
    /// 差 8 小时（`CURRENT_TIMESTAMP` = 18:05+08，而 UTC 侧 10:05）。
    ///
    /// 与 `seed_paths_never_use_local_clock` 的分工（两把都要，缺一不可）：那把吃的是
    /// `match` 分支自产方言时间的形态（`=> "NOW()"`），**看不见拼在 SQL 字面量里的**这一族。
    /// b83 实测该族有 7 处在册外长期存在：`ai/config_service.rs:174`、`ai/service.rs:372`、
    /// `upload_config_service.rs`（两处 write_key + 一处 persist）、`initialize/menu.rs` 两处，
    /// 全部已改为显式绑定 `now_naive()`。
    ///
    /// **不在本判据内**：DDL 的 `DEFAULT CURRENT_TIMESTAMP`（仅当 INSERT 省略该列才生效）。
    /// 这类列里唯一真实存在的是 `sys_notice_read.read_time`，由
    /// `notice_read_inserts_always_set_read_time` 单独证明生产写路径恒显式赋值——
    /// "默认值不会被用到"必须是判据，不能是注释里的断言。
    #[test]
    fn naked_sql_time_source_banned_across_production_code() {
        fn sql_time_literal(line: &str) -> bool {
            let is_dml = ["INSERT ", "UPDATE ", "DELETE ", "SELECT "]
                .iter()
                .any(|k| line.contains(k));
            let has_db_clock = line.contains("CURRENT_TIMESTAMP") || line.contains("NOW()");
            // DDL 默认值走另一条锁（见模块注释），这里必须放过，否则判据会因为
            // 迁移里的建表语句假红——而"假红的锁"很快就被放宽成没有锁。
            is_dml && has_db_clock && !line.contains("DEFAULT CURRENT_TIMESTAMP")
        }

        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let mut hits: Vec<String> = Vec::new();
        let mut scanned = 0usize;
        for dir in [root.join("src"), root.join("migration/src")] {
            for f in collect_rs(&dir) {
                let rel = f
                    .strip_prefix(root)
                    .unwrap_or(f.as_path())
                    .to_string_lossy()
                    .replace('\\', "/");
                // 本文件是判据自己的家：控制组字面量必然含被禁形态（同 prod_scan 的 SCANNER_SELF）
                if rel.ends_with("src/common/datetime.rs")
                    || rel.contains("integration_tests")
                    || rel.ends_with("/tests.rs")
                {
                    continue;
                }
                scanned += 1;
                let raw = std::fs::read_to_string(f).unwrap_or_default();
                // 采集走共享管道，且**注释置空但保留行号**（`Comments::Blank`）：
                // 用 DropBlocks 会让上报行号与真实文件错位（本轮首跑实测偏移 33 行），
                // 而"照着行号去改"是这把锁唯一的用法。
                let lines = crate::common::prod_scan::normalize(
                    &raw,
                    &crate::common::prod_scan::Scan {
                        strip_test_code: true,
                        comments: crate::common::prod_scan::Comments::Blank,
                        ..Default::default()
                    },
                );
                for (i, line) in lines
                    .iter()
                    .enumerate()
                    .filter(|(_, l)| sql_time_literal(l))
                {
                    hits.push(format!("{}:{} {}", rel, i + 1, line.trim()));
                }
            }
        }
        // 采集面探针：扫不到文件必须响亮失败，"没跑"不得读成"干净"
        assert!(
            scanned >= 400,
            "只扫了 {scanned} 个生产文件 ⇒ 采集面定位失效，本锁即将空转（不是通过）"
        );

        // 双向：合成违规必须被抓
        assert!(
            sql_time_literal(
                "                \"UPDATE sys_config SET config_value = ?, update_time = CURRENT_TIMESTAMP WHERE config_key = ?\","
            ),
            "拼在 SQL 字面量里的 CURRENT_TIMESTAMP 未被抓到 ⇒ 本锁是虚锁"
        );
        assert!(
            sql_time_literal("let sql = \"INSERT INTO t (a, create_time) VALUES (?, NOW())\";"),
            "MySQL 方言 NOW() 同族形态未被抓到 ⇒ 判据只覆盖了半个族"
        );
        // 双向：三类合法形态不得误报
        assert!(
            !sql_time_literal("read_time  DATETIME DEFAULT CURRENT_TIMESTAMP,"),
            "DDL 默认值被误判 ⇒ 该列属另一条锁的口径"
        );
        assert!(
            !sql_time_literal(
                "crate::common::sql_dialect::stmt(backend, \"UPDATE t SET update_time = ?\", [v.into()])"
            ),
            "已改绑参数的正确形态被误判 ⇒ 判据会把修法本身报成违规"
        );
        assert!(
            !sql_time_literal("// 历史上这里曾写 CURRENT_TIMESTAMP，现已收敛"),
            "注释被 strip_comments 剥除后仍含被禁形态 ⇒ 剥注环节失效"
        );

        assert!(
            hits.is_empty(),
            "生产裸 SQL 把时间来源交给数据库会话时区（换库即换口径，见本测试注释）：
{}",
            hits.join(
                "
"
            )
        );
    }

    /// `sys_notice_read.read_time` 的 DDL 带 `DEFAULT CURRENT_TIMESTAMP`（三档都建了）。
    /// 该默认值只在"INSERT 省略 read_time"时生效，而 PG/MySQL 下它取**会话时区**——
    /// 所以"生产写路径恒显式赋值"必须由代码逐点证明，不能停在注释里的断言。
    #[test]
    fn notice_read_inserts_always_set_read_time() {
        /// 取一段 `ActiveModel { … }` 文本，判断它是否显式赋了 read_time。
        /// 抽成函数是为了让**真扫描与对照组走同一条判据**（本仓反复自曝的"锁与对照组
        /// 不同源"缺陷形态，这里不留第二个机会）。
        fn model_sets_read_time(body: &str) -> bool {
            body.contains("read_time: Set(")
        }

        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let repo = root.join("src/repository/sys_notice_read.rs");
        let raw = std::fs::read_to_string(&repo).expect("sys_notice_read 仓储文件必须存在");
        let prod = match raw.find("#[cfg(test)]") {
            Some(i) => &raw[..i],
            None => raw.as_str(),
        };
        // 逐个写模型取窗口（止于下一个 `};`），逐点判"有没有赋 read_time"
        let mut models: Vec<String> = Vec::new();
        let mut from = 0usize;
        while let Some(rel_at) = prod[from..].find("ActiveModel {") {
            let start = from + rel_at;
            let end = prod[start..]
                .find("};")
                .map(|p| start + p + 2)
                .unwrap_or(prod.len());
            models.push(prod[start..end].to_string());
            from = end;
        }
        assert!(
            !models.is_empty(),
            "sys_notice_read 里一个写模型都没找到 ⇒ 本锁失去约束对象（不是通过）"
        );
        let missing: Vec<&str> = models
            .iter()
            .filter(|m| !model_sets_read_time(m))
            .map(|m| m.as_str())
            .collect();
        assert!(
            missing.is_empty(),
            "有 {} 个 sys_notice_read 写模型省略了 read_time ⇒ 该列将落到 DDL 默认值 \
             CURRENT_TIMESTAMP（PG/MySQL 取会话时区，与全仓 UTC 口径分裂）：
{}",
            missing.len(),
            missing.join(
                "
"
            )
        );
        // 双向：合成缺失形态必须被同一条判据抓到
        assert!(
            !model_sets_read_time("ActiveModel { notice_id: Set(1), user_id: Set(2), }"),
            "合成缺失形态未被抓到 ⇒ 上面的通过是恒真断言"
        );
        assert!(
            model_sets_read_time("ActiveModel { read_time: Set(Some(now)), }"),
            "合规形态被判缺 ⇒ 判据方向写反"
        );
    }

    /// **充分判据**：任何"函数体内既取本机挂钟、又写持久化时间列"的形态必须显式在册。
    ///
    /// 为什么还要这一把（`seed_paths_never_use_local_clock` 之外）：
    /// `db_state_audit.py` 的"未来时间"检查只在**本机比 UTC 快**的时区（dev 机 UTC+8）
    /// 暴露口径分裂；部署到 UTC-5 时同一缺陷写成"过去 5 小时"，该检查看不见
    /// ⇒ **静态锁才是充分判据**，运行时检查只是补充（登记于此，防下批误以为"没 WARN=没问题"）。
    ///
    /// 判据只认**真实落库形态**（`*_time/*_date: Set(…)` 或 INSERT/UPDATE 文本里的时间列），
    /// 不用宽泛的"出现 login_time 字样"——后者会把在线会话显示串（与
    /// `monitor_online_handler.rs` 的 `and_local_timezone(Local)` 成对还原）误报成缺陷。
    #[test]
    fn local_clock_never_feeds_persisted_time_columns() {
        // EXEMPT：函数内确有本机挂钟，但该值**不进时间列**（逐条带理由）
        const EXEMPT: &[(&str, &str, &str)] = &[
            (
                "src/service/sys_backup_service.rs",
                "create_backup",
                "`Local::now()` 仅用于备份**文件名**时间戳（人类可读、随运维所在时区）；\
                 同函数 :322/:332 的 create_time/update_time 已显式取 `now_naive()`（UTC）",
            ),
            (
                "src/service/sys_backup_service.rs",
                "export_tenant_package",
                "同上：`Local::now()` 仅拼导出包文件名；导出载荷里的 exportedAt 与\
                 落库 create_time 均取 `now_naive()`（UTC）",
            ),
        ];

        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let files = collect_rs(&root.join("src"));
        let db_write = db_time_write_re();
        let fn_start = fn_start_re();
        let mut hits: Vec<String> = Vec::new();
        let mut scanned = 0usize;
        for f in &files {
            let rel = f
                .strip_prefix(root)
                .unwrap_or(f.as_path())
                .to_string_lossy()
                .replace('\\', "/");
            // 测试面不约束（用例里造"未来/过去"时间是刻意的）
            if rel.contains("integration_tests") || rel.ends_with("/tests.rs") {
                continue;
            }
            scanned += 1;
            let raw = std::fs::read_to_string(f).unwrap_or_default();
            // 只约束**生产代码路径**：截掉 `#[cfg(test)]` 之后的内容。
            // 不这么做的话，本锁自己的控制组字面量（同一函数里既有 `Local::now()` 又有
            // `create_time: Set(`）会命中它自己 —— 首轮实测正是如此（锁抓到自己是好信号，
            // 但判据范围必须与"生产落库路径"这一命题一致）。
            let without_tests = match raw.find("#[cfg(test)]") {
                Some(i) => raw[..i].to_string(),
                None => raw.clone(),
            };
            let text = strip_comments(&without_tests);
            let starts: Vec<(usize, String)> = fn_start
                .find_iter(&text)
                .map(|m| {
                    let name = fn_start
                        .captures(m.as_str())
                        .and_then(|c| c.get(1))
                        .map(|x| x.as_str().to_string())
                        .unwrap_or_default();
                    (m.start(), name)
                })
                .collect();
            for (i, (pos, name)) in starts.iter().enumerate() {
                let end = starts.get(i + 1).map(|(p, _)| *p).unwrap_or(text.len());
                let body = &text[*pos..end];
                if body.contains("Local::now()") && db_write.is_match(body) {
                    if EXEMPT
                        .iter()
                        .any(|(ef, en, _)| *ef == rel.as_str() && *en == name.as_str())
                    {
                        continue;
                    }
                    hits.push(format!("{rel} :: fn {name}"));
                }
            }
        }
        assert!(
            scanned >= 200,
            "只扫了 {scanned} 个 src 文件 ⇒ 扫描面失效（不是通过）"
        );
        assert!(
            hits.is_empty(),
            "以下函数把**本机挂钟**与**持久化时间列**写在同一处，落库口径将随服务器时区漂移\
             （UTC- 时区下 db_state_audit 的未来时间检查看不见）：\n{}\n\
             修法：改 `common::datetime::now_naive()`；若该挂钟确实只用于文件名/显示，\
             在 EXEMPT 表逐条带理由登记。",
            hits.join("\n")
        );

        // 控制组一：合成违规必须被抓（证明判据不是恒真）
        let synth = "async fn fake(db: &X) {
    let now = chrono::Local::now().naive_local();
    let am = ActiveModel { create_time: Set(Some(now)) };
}
";
        assert!(
            synth.contains("Local::now()") && db_write.is_match(synth),
            "合成违规未被判为落库+挂钟同处 ⇒ 判据失效，本锁是虚锁"
        );
        // 控制组二：合法用法**不得**被误报（显示串、文件名与 DB 时间分写的形态）
        let ok_display = "fn show() -> String {
    chrono::Local::now().format(\"%H:%M\").to_string()
}
";
        assert!(
            !db_write.is_match(ok_display),
            "纯显示函数被误判 ⇒ 会逼人放宽判据"
        );
    }

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
