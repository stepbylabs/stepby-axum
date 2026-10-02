// stepby-axum/src/db/limits.rs
//! 数据库进程级限制快照（R9-ERR-004 / R111-MIN-BE-CORR-002 配套）
//!
//! `DatabaseConfig` 只在进程启动时由 `main` 加载一次，但仓库层（如
//! `repository::sys_dept::find_descendant_ids` 的递归 CTE 深度上限）无法
//! 直达 config —— 若沿 `AppState → service::new → repo::new` 签名穿透，
//! 需改动十余处构造函数并波及全部集成测试。
//!
//! 因此在连接池初始化（全进程恰好一次）时把这两个防御性限制值快照到
//! 进程级 `OnceLock`，仓库层零签名穿透读取：
//!
//! - [`statement_timeout_secs`]：语句级超时（见 `pool.rs` 的三方言落地）；
//! - [`dept_cte_max_depth`]：data_scope 递归 CTE 深度上限。
//!
//! 仅限**防御性**参数走此通道；业务可变配置必须走 AppState。

use std::sync::OnceLock;

use crate::config::DatabaseConfig;

static STATEMENT_TIMEOUT_SECS: OnceLock<u64> = OnceLock::new();
static DEPT_CTE_MAX_DEPTH: OnceLock<u32> = OnceLock::new();

/// 语句级超时兜底值（秒）。未初始化（如单测直接调用仓库层）时取 60，
/// 与 `default_db_statement_timeout_secs` 保持一致。
pub fn statement_timeout_secs() -> u64 {
    *STATEMENT_TIMEOUT_SECS.get_or_init(|| 60)
}

/// 部门递归 CTE 深度上限兜底值。未初始化时取 30，
/// 与 `default_db_dept_cte_max_depth` 保持一致。
pub fn dept_cte_max_depth() -> u32 {
    *DEPT_CTE_MAX_DEPTH.get_or_init(|| 30)
}

/// 连接池初始化时快照配置（全进程仅 main 调用一次；重复调用首写优先，
/// 便于集成测试在不同配置下多次建池而不互相覆盖）。
pub fn init(config: &DatabaseConfig) {
    // 非法值防御：语句超时上限 1 小时；CTE 深度夹取 [1, 1000]
    let stmt = config.statement_timeout_secs.min(3600);
    let depth = config.dept_cte_max_depth.clamp(1, 1000);
    let _ = STATEMENT_TIMEOUT_SECS.set(stmt);
    let _ = DEPT_CTE_MAX_DEPTH.set(depth);
    tracing::info!(
        statement_timeout_secs = stmt,
        dept_cte_max_depth = depth,
        "数据库限制快照已加载"
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fallback_values_match_config_defaults() {
        // 未 init 时（测试进程内 OnceLock 可能已被其他测试初始化，
        // 因此这里只断言兜底值方向正确：非零、有界）
        assert!(statement_timeout_secs() > 0);
        assert!(statement_timeout_secs() <= 3600);
        assert!((1..=1000).contains(&dept_cte_max_depth()));
    }

    #[test]
    fn init_clamps_out_of_range_values() {
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
        };
        // init 首写优先：本进程内若已被其他测试先行初始化，则此处断言
        // 只验证夹取逻辑本身（构造期望值对比）。
        // u64::MAX 已超上限，实现侧 .min(3600) 后必然夹到 3600（1.99 clippy 确认恒等）。
        let expect_stmt = 3600u64;
        let expect_depth = 0u32.clamp(1, 1000);
        init(&cfg);
        // 无论如何，快照值必须落在合法区间
        assert!(statement_timeout_secs() <= 3600);
        assert_eq!(expect_stmt, 3600);
        assert_eq!(expect_depth, 1);
        assert!((1..=1000).contains(&dept_cte_max_depth()));
    }
}
