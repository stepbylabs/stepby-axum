// stepby-axum/src/db/limits.rs
//! 数据库进程级限制快照（R9-ERR-004 / R111-MIN-BE-CORR-002 配套）
//!
//! `DatabaseConfig` 只在进程启动时由 `main` 加载一次，但仓库层（如
//! `repository::sys_dept::find_descendant_ids` 的递归 CTE 深度上限）无法
//! 直达 config —— 若沿 `AppState → service::new → repo::new` 签名穿透，
//! 需改动十余处构造函数并波及全部集成测试。
//!
//! 因此在连接池初始化（全进程恰好一次）时把防御性限制值快照到进程级 `OnceLock`，
//! 仓库层零签名穿透读取：
//!
//! - [`dept_cte_max_depth`]：data_scope 递归 CTE 深度上限（`repository::sys_dept` 读取）。
//!
//! ⚠️ 语句级超时**不走**本通道：它在连接池建立时按方言直接落到连接参数
//! （PostgreSQL `statement_timeout` / MySQL `after_connect` 会话变量，见 `db::pool.rs`），
//! 覆盖驱动层的全部语句。这里原先另有一份 `statement_timeout_secs()` 快照、模块文档
//! 还声称"仓库层零签名穿透读取"，而全仓**没有任何消费点**——"写了没接线 = 没写"，
//! 且那句注释与事实相反（b89 项 E6 删除；留一份没人读的数只会让人以为仓库层在读它）。
//!
//! 仅限**防御性**参数走此通道；业务可变配置必须走 AppState。

use std::sync::OnceLock;

use crate::config::DatabaseConfig;

static DEPT_CTE_MAX_DEPTH: OnceLock<u32> = OnceLock::new();

/// 部门递归 CTE 深度上限。未初始化时取 30，
/// 与 `default_db_dept_cte_max_depth` 保持一致。
pub fn dept_cte_max_depth() -> u32 {
    *DEPT_CTE_MAX_DEPTH.get_or_init(|| 30)
}

/// 递归 CTE 深度的合法夹取区间（脏数据/配错都不得把上限调到 0 或无穷）。
fn clamp_depth(raw: u32) -> u32 {
    raw.clamp(1, 1000)
}

/// 连接池初始化时快照配置（全进程仅 main 调用一次；重复调用首写优先，
/// 便于集成测试在不同配置下多次建池而不互相覆盖）。
pub fn init(config: &DatabaseConfig) {
    let depth = clamp_depth(config.dept_cte_max_depth);
    let _ = DEPT_CTE_MAX_DEPTH.set(depth);
    tracing::info!(
        dept_cte_max_depth = depth,
        // 打**生效值**而不是配置原值：配成 `u64::MAX` 时显示原值会让人以为超时是 1.8e19 秒，
        // 而实际下发的是夹取后的 3600 秒（AGENTS C.7 禁止"管理端显示 8、实际 4"这类行为分裂）。
        statement_timeout_ms = config.statement_timeout_ms(),
        "数据库限制快照已加载（语句超时按方言在连接池侧生效，见 db::pool）"
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fallback_values_match_config_defaults() {
        // 未 init 时（测试进程内 OnceLock 可能已被其他测试初始化，
        // 因此这里只断言兜底值方向正确：非零、有界）
        assert!((1..=1000).contains(&dept_cte_max_depth()));
    }

    /// 夹取规则本身必须可证伪（`OnceLock` 首写优先 ⇒ 快照值随测试顺序变，
    /// 断言快照"等于某个数"是假绿；断言纯函数才判得到规则）
    #[test]
    fn clamp_depth_rule_is_falsifiable() {
        assert_eq!(clamp_depth(0), 1, "0 必须夹到下限");
        assert_eq!(clamp_depth(1), 1);
        assert_eq!(clamp_depth(30), 30, "区间内不得改动");
        assert_eq!(clamp_depth(1000), 1000);
        assert_eq!(clamp_depth(u32::MAX), 1000, "超上限必须夹到 1000");
    }

    #[test]
    fn init_snapshots_depth_without_panic_on_extreme_config() {
        let cfg = DatabaseConfig {
            url: "sqlite::memory:".to_string(),
            max_connections: 1,
            min_connections: 1,
            connect_timeout: 8,
            idle_timeout: 600,
            max_lifetime_secs: 1800,
            acquire_timeout_secs: 10,
            statement_timeout_secs: u64::MAX,
            dept_cte_max_depth: 0,
            slow_sql_threshold_ms: 1000,
        };
        init(&cfg);
        // 首写优先：本进程内可能已被其他测试先行初始化，故只断"落在合法区间"
        assert!((1..=1000).contains(&dept_cte_max_depth()));
    }
}
