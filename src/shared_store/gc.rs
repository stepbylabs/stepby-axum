//! local 档过期行 GC（批八十五 项 C 收口：`[cache].gc_interval_secs` 从此才有读点）。
//!
//! ## 立案（取证在先）
//! `config.toml.example` 第 61 行写着 `gc_interval_secs = 600   # local 档过期行 GC 周期（秒）`，
//! `CacheConfig` 也有字段与默认值函数，而**全仓没有任何一处读它**——即"配置面承诺了一个
//! 不存在的机制"。后果不是风格问题：local 档把 S2 短期态放在 `sys_shared_kv`（TTL 落
//! `expire_at` 列），读路径有 `is_expired` 过滤所以**正确性**没事，但过期行**没有任何删除
//! 路径**，随验证码/在线会话/幂等槽/SSO 码票的写入量无限累积（单文件部署恰恰最没人
//! 定期清库）。`sys_token_revocation` 那一族已由每日 04:30 的内置任务清理，本地这两张表
//! 是本模块补的那一块。
//!
//! ## 为什么是独立循环而不是调度器 cron
//! 旋钮的粒度是**秒**（`gc_interval_secs`），cron 表达不了任意秒数周期；且固定时刻的 cron
//! 有"错过即整日不补"的结构缺口（AGENTS B.6 / b73 保留期清理那条）。间隔循环天然自愈：
//! `tokio::time::interval` 的首个 tick **立即**触发 ⇒ 停机很久后重启会马上清一次，
//! `MissedTickBehavior::Delay` 保证慢轮次不会补发一串连环 GC。
//!
//! ## 与 B.6 后台任务范式的关系
//! `common::background` 的文档边界写明"**长驻循环不套** `run_tracked`"——这里遵循的是同一句话
//! 的另一半：**循环本身**长驻（不套外层超时，套了就等于砍掉合法长任务），但**每一轮工作单元**
//! 都经 `run_tracked` ⇒ 超时 + panic 隔离 + 失败留痕 + `bg:sharedStoreGc` 指标齐备。
//! 因此 `fail_closed_guard::background_spawn_tasks_are_guarded_or_explicitly_exempted`
//! 按"经 helper"判定通过，不需要进 EXEMPT 表。
//!
//! ## 档位边界
//! 只在 **local 档**启动（见 `initialize`/`main` 的调用点）：redis 档的键由 TTL 自过期，
//! 而这两张表在 redis 档根本不被写（S1 权威层 `sys_token_revocation` 另有清理任务）。
//! 配置取**启动只读**（AGENTS C.7）：热改后闸门仍是首次建闸值，行为分裂比不改更糟。

use std::sync::Arc;
use std::time::Duration;

use sea_orm::{ConnectionTrait, DatabaseConnection, DbErr, Statement};
use tokio::task::JoinHandle;

use crate::common::background;
use crate::observability::metrics::MetricsRegistry;

/// 每轮预算：与 [`background::LIGHT_DB_BUDGET`] 同源（两条带索引的 DELETE，不是重活）。
pub const GC_BUDGET: Duration = background::LIGHT_DB_BUDGET;

/// 周期下限：低于此值 GC 自己就成了负载（每轮两次全表索引扫描 + 一次 fsync）。
pub const GC_MIN_INTERVAL_SECS: u64 = 30;

/// 周期上限：一天。再大就与"每日内置任务"没有区别，不如直接用调度器。
pub const GC_MAX_INTERVAL_SECS: u64 = 86_400;

/// 指标标签（`bg:<label>` 结局族）
pub const GC_LABEL: &str = "sharedStoreGc";

/// 一轮 GC 的删除计数（进日志与审计，便于"清不动"与"没东西可清"区分开）
#[derive(Debug, Default, Clone, Copy)]
pub struct SharedGcSummary {
    pub kv_deleted: u64,
    pub lock_deleted: u64,
}

impl SharedGcSummary {
    pub fn total(&self) -> u64 {
        self.kv_deleted + self.lock_deleted
    }
}

/// 一轮 GC 的两条 DELETE 语句（**纯函数**，为的是让"边界方向"这一件事可判）。
///
/// 抽出来的原因不是复用：`<=` 写成 `<` 时，行落在恰好等于 `now` 的那一秒上会被读路径
/// 判过期、却被 GC 判未过期 ⇒ 永久留下一行"读说没了、库里还在"的僵尸，而这种偏移在真实
/// 时钟上几乎造不出夹具（执行体内部的 `now` 不可控）。于是判据落到两侧：本函数被
/// `gc_sql_predicates_match_reader_side`（本模块 `#[cfg(test)]` 用例）钉住**语句文本**，
/// `local_store::is_expired` 的
/// 同一边界由它自己的用例钉住——两侧对齐才叫"同源"，单靠集成测试的远端边界判不出来。
pub fn gc_delete_statements(now_epoch: i64) -> (String, String) {
    (
        format!(
            "DELETE FROM sys_shared_kv WHERE expire_at IS NOT NULL AND expire_at <= {now_epoch}"
        ),
        format!("DELETE FROM sys_shared_lock WHERE expire_at <= {now_epoch}"),
    )
}

/// 删除 `sys_shared_kv` / `sys_shared_lock` 中**已过期**的行。
///
/// 三条口径都是设计而非巧合（逐条由 `integration_tests::shared_store_gc` 与
/// [`gc_delete_statements`] 的单测钉住）：
/// 1. `expire_at IS NOT NULL`：永不过期的键族（密码版本号、用户会话集合这类由业务显式
///    删除的键）**必须**保留——把它们删掉等于把"改密后旧 token 立即失效"这类安全不变量洗掉。
/// 2. `expire_at <= now`：与读路径 [`super::local_store::is_expired`] **同一判据**，
///    GC 不得比读路径更激进（否则"读还说没过期、行已经没了"= 静默丢数据）。
/// 3. 时间戳取服务端 i64 整数并直接拼接（无注入面），与既有的
///    [`super::cleanup_expired_token_revocations`] 同形态；三方言 `DELETE` 语法一致。
pub async fn cleanup_expired_shared_rows(
    db: &DatabaseConnection,
) -> Result<SharedGcSummary, DbErr> {
    let now_epoch = chrono::Utc::now().timestamp();
    let backend = db.get_database_backend();
    let (kv_sql, lock_sql) = gc_delete_statements(now_epoch);
    let kv = db
        .execute_raw(Statement::from_string(backend, kv_sql))
        .await?;
    let lock = db
        .execute_raw(Statement::from_string(backend, lock_sql))
        .await?;
    Ok(SharedGcSummary {
        kv_deleted: kv.rows_affected(),
        lock_deleted: lock.rows_affected(),
    })
}

/// 配置的 `gc_interval_secs` → 实际周期。`None` = 不启动 GC。
///
/// `0` 是**显式关闭**（运维自带 cron 清库的逃生舱），不是"取默认值"——把 0 当"没配"
/// 会静默变成 30 秒一轮，那是把用户明确的意图读成相反的意思。其余取值一律夹到
/// [`GC_MIN_INTERVAL_SECS`]..=[`GC_MAX_INTERVAL_SECS`]，被夹时打 WARN（fail-safe：
/// 回落可用值 + 响亮提示，与 `[health].probe_timeout` 的 clamp 同口径）。
pub fn resolve_gc_interval(configured: u64) -> Option<u64> {
    if configured == 0 {
        return None;
    }
    let clamped = configured.clamp(GC_MIN_INTERVAL_SECS, GC_MAX_INTERVAL_SECS);
    if clamped != configured {
        tracing::warn!(
            configured,
            applied = clamped,
            allowed = ?[GC_MIN_INTERVAL_SECS, GC_MAX_INTERVAL_SECS],
            "[cache].gc_interval_secs 超出可用区间，已夹到边界（0 才是显式关闭）"
        );
    }
    Some(clamped)
}

/// 启动 local 档过期行 GC 循环（返回句柄仅供测试/优雅关闭；生产侧可 drop）。
///
/// 调用方负责**只在 local 档**调用（见模块文档"档位边界"）。
pub fn spawn_shared_store_gc(
    db: DatabaseConnection,
    configured_secs: u64,
    metrics: Option<Arc<MetricsRegistry>>,
) -> Option<JoinHandle<()>> {
    let Some(secs) = resolve_gc_interval(configured_secs) else {
        tracing::info!(
            "[cache].gc_interval_secs = 0 ⇒ 不启动 local 档过期行 GC（显式关闭；\
             sys_shared_kv 过期行只增不删，请自行安排清库）"
        );
        return None;
    };
    tracing::info!("local 档共享态过期行 GC 已启动：每 {secs}s 一轮（首轮立即执行）");
    Some(tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(secs));
        // 慢轮次（大库 DELETE 撞上 fsync 尖峰）不得补发一串连环 GC
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tick.tick().await;
            let db = db.clone();
            let m = metrics.clone();
            // 每轮经 run_tracked：超时 + panic 隔离 + 失败留痕 + bg:sharedStoreGc（AGENTS B.6）。
            // 循环本身不套外层超时——长驻循环"超时"= 砍断合法长任务（语义倒置）。
            background::run_tracked(GC_LABEL, GC_BUDGET, m, async move {
                match cleanup_expired_shared_rows(&db).await {
                    Ok(s) if s.total() > 0 => tracing::info!(
                        kv_deleted = s.kv_deleted,
                        lock_deleted = s.lock_deleted,
                        "共享态 GC: 清理 local 档过期行"
                    ),
                    Ok(_) => tracing::debug!("共享态 GC: 本轮无过期行"),
                    Err(e) => tracing::warn!("共享态 GC 失败（下一轮重试，不影响业务读写）: {e}"),
                }
            })
            .await;
        }
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// ① `0` 必须读成"显式关闭"，而不是"回落默认值"。
    #[test]
    fn zero_means_disabled_not_default() {
        assert_eq!(resolve_gc_interval(0), None, "0 是逃生舱，不得被当成没配");
    }

    /// ② 区间内的值原样通过（**默认值必须落在区间内**，否则默认态就被静默改写）。
    #[test]
    fn in_range_values_pass_through() {
        assert_eq!(resolve_gc_interval(600), Some(600));
        assert_eq!(
            resolve_gc_interval(GC_MIN_INTERVAL_SECS),
            Some(GC_MIN_INTERVAL_SECS)
        );
        assert_eq!(
            resolve_gc_interval(GC_MAX_INTERVAL_SECS),
            Some(GC_MAX_INTERVAL_SECS)
        );
        let d = crate::config::settings::CacheConfig::default().gc_interval_secs;
        assert_eq!(
            resolve_gc_interval(d),
            Some(d),
            "默认周期 {d} 被 clamp 了 = 默认行为与文档不一致"
        );
    }

    /// ③ 区间外的值必须夹到边界（对照 ①：夹与关是两种语义，不得混为一谈）。
    #[test]
    fn out_of_range_values_are_clamped_not_disabled() {
        assert_eq!(resolve_gc_interval(1), Some(GC_MIN_INTERVAL_SECS));
        assert_eq!(resolve_gc_interval(u64::MAX), Some(GC_MAX_INTERVAL_SECS));
    }

    /// ④ 反脆弱（真受约束）：`Some(_)` 的分支不是恒成立——把 0 的处理摘掉就会在这里红，
    ///    而把 clamp 摘掉则 ③ 红。三条用例彼此不可互相顶替。
    #[test]
    fn the_three_branches_are_distinct() {
        assert_eq!(resolve_gc_interval(0), None);
        assert_eq!(resolve_gc_interval(29), Some(GC_MIN_INTERVAL_SECS));
        assert_ne!(resolve_gc_interval(30), resolve_gc_interval(0));
    }

    /// ⑤ GC 的过期判据必须与读路径 `is_expired` **同一边界方向**（文本级钉死）。
    ///
    /// 为什么在单测里判语句文本、而不是在集成测试里造一行"恰好等于 now"：执行体内部的
    /// `now` 由 `chrono::Utc::now()` 现取，测试写不出与它逐秒相等的 `expire_at`；
    /// 把 `<=` 写成 `<` 时集成测试的两条边界用例（±3600 与 now-1）**都不会红**，
    /// 于是偏移只能靠语句文本这一侧的锁看见。读路径那一侧由
    /// `local_store::tests::test_is_expired` 钉，两侧合起来才是"同源"。
    #[test]
    fn gc_sql_predicates_match_reader_side() {
        use crate::shared_store::local_store::is_expired;

        // `is_expired` 用**真实时钟**（这是它的语义），所以参考时刻只能取当前秒；
        // 断言方向都取"跨过一秒也不会翻转"的那一侧：`== now` 恒判过期（时钟只往前走），
        // 而 +3600 在单测时长内不会到期。
        let now = chrono::Utc::now().timestamp();
        let n = now.to_string();
        let (kv, lock) = gc_delete_statements(now);
        assert_eq!(
            kv,
            format!("DELETE FROM sys_shared_kv WHERE expire_at IS NOT NULL AND expire_at <= {n}"),
            "kv 侧判据文本变了 = 与读路径的边界关系需要重新对账（不得只改这里）"
        );
        assert_eq!(
            lock,
            format!("DELETE FROM sys_shared_lock WHERE expire_at <= {n}"),
            "lock 侧判据文本同上"
        );
        // 读路径在同一时刻的结论：等于 now 即过期（与 `<=` 同向）
        assert!(
            is_expired(Some(now)),
            "读路径必须把 == now 判为过期，否则应与 GC 同改"
        );
        assert!(is_expired(Some(now - 1)));
        assert!(!is_expired(Some(now + 3600)), "未来一刻两侧都不得判过期");
        assert!(!is_expired(None), "永不过期在两侧都必须是\"不删\"");
    }

    /// ⑥ 反脆弱：语句必须由 `now_epoch` **实参**拼出（写死常量的实现能让 ⑤ 的第一条
    ///    断言在某个特定输入下侥幸通过）。
    #[test]
    fn statements_carry_the_supplied_epoch() {
        let (a, _) = gc_delete_statements(1);
        let (b, _) = gc_delete_statements(2);
        assert!(
            a.contains("<= 1") && b.contains("<= 2") && a != b,
            "实得 {a} / {b}"
        );
    }
}
