// stepby-axum/src/integration_tests/live_db_smoke.rs
//! 活库方言 smoke（批七十七新增，默认 `#[ignore]`）
//!
//! ## 为什么必须有这一环
//! 本仓 1544 条测试全部跑在 SQLite 上（测试环用 `Migrator::up` 建临时库），
//! **MySQL 与 PostgreSQL 的方言差异从来没被执行过**。批七十七连出的两类根因正是
//! 这个盲区的产物：
//! - R-12：`CREATE INDEX IF NOT EXISTS` 在 MySQL 8.0 是 `ERROR 1064`（MariaDB 专属子句），
//!   `ensure_flow_graph_doc_table` 无条件执行它，而启动链 `?` 上抛 ⇒ MySQL 存量库每次
//!   启动都在这里硬失败；同族还有 6 处「MySQL 整段跳过、注释写交由 migration 补齐」，
//!   而架构约定是存量库不跑 `Migrator::up` ⇒ 索引/唯一约束在 MySQL 上永远缺失。
//! - R-11：吞错误文案式幂等在 PG 上是结构性错误（事务内首错即 aborted，后续语句全废）。
//!
//! 静态锁（`ddl_dialect_discipline`）只能防「同类写法回潮」，防不了「写法没变但方言
//! 行为不同」。方言行为只有对真库跑一次才知道——这就是本文件的存在理由。接入本环后，
//! 它当场照出 4 处真缺陷：MySQL 1064、MySQL 1305（隐式提交抹掉 SAVEPOINT）、
//! PG「SAVEPOINT can only be used in transaction blocks」、以及
//! `ON sys_pat(token_hash)` 不带空格导致解析器放弃探测。
//!
//! ## 只有一个测试函数，而且必须是只有一个
//! 本环的两段（兜底幂等 / 回滚重放）都**直接 ALTER 同一个 schema**。cargo 默认并行跑
//! 测试时，两个函数会互相拆台（实测：并行必挂、串行全绿）。所以它们合并成一条生命周期
//! 用例，而不是靠"请记得加 --test-threads=1"这种口头约定。
//!
//! ## 跑法（本地/CI 皆可，需要一个可写的空库）
//! ```text
//! # MySQL（本机 drill 容器 stepby-mysql，先 CREATE DATABASE stepby_smoke）
//! STEPBY_SMOKE_DATABASE_URL='mysql://root:<pw>@127.0.0.1:3306/stepby_smoke' \
//!   cargo test -j 4 --lib live_db_smoke -- --ignored --nocapture
//! # PostgreSQL（throwaway 容器，见 stepby-vue/tests/e2e/RUN-RECIPE.md）
//! STEPBY_SMOKE_DATABASE_URL='postgres://stepby:<pw>@127.0.0.1:5432/stepby_smoke' \
//!   cargo test -j 4 --lib live_db_smoke -- --ignored --nocapture
//! ```
//! 未设环境变量时测试直接 panic（不是静默跳过）——「没跑」不能冒充「通过」；
//! `#[ignore]` 只保证默认 `cargo test` 不因缺库而变红。

use migration::{Migrator, MigratorTrait};
use sea_orm::{ConnectionTrait, Database, DatabaseBackend, DatabaseConnection, Statement};

/// 兜底段声明并必须真实存在的索引：(索引名, 表名)。
/// 只断言「函数返回 Ok」会放过「静默跳过」，所以逐个回查数据字典。
const EXPECTED_INDEXES: [(&str, &str); 19] = [
    ("uk_flow_task_biz", "sys_flow_task"),
    ("idx_flow_task_assignee", "sys_flow_task"),
    ("idx_flow_task_due", "sys_flow_task"),
    ("idx_flow_log_biz", "sys_flow_log"),
    ("idx_flow_log_operator", "sys_flow_log"),
    ("idx_flow_doc_applicant", "flow_demo_doc"),
    ("uq_flow_def_code_ver", "flow_definition"),
    ("idx_flow_graph_doc_tenant", "flow_graph_doc"),
    ("uk_sys_pat_token_hash", "sys_pat"),
    ("idx_sys_pat_user_id", "sys_pat"),
    (
        "uk_sys_user_credential_credential_id",
        "sys_user_credential",
    ),
    ("idx_sys_user_credential_user_id", "sys_user_credential"),
    ("uk_user_dept", "sys_user_dept"),
    ("idx_user_dept_dept", "sys_user_dept"),
    ("uk_scim_group_external_id", "sys_scim_group"),
    ("uk_scim_group_binding", "sys_scim_group_binding"),
    ("uq_sso_consent_user_client", "sys_oauth_consent"),
    ("uq_report_dataset_code", "report_dataset"),
    ("uq_report_dashboard_code", "report_dashboard"),
];

macro_rules! step {
    ($label:expr, $call:expr) => {{
        $call
            .await
            .unwrap_or_else(|e| panic!("[smoke] {} 失败: {e}", $label))
    }};
}

/// 兜底段全链（11 个函数，与启动链里带索引/建表 DDL 的段落一一对应）。
/// 显式逐个调用而不用闭包数组：不同函数返回 `anyhow::Error` / `DbErr` 两种错误类型，
/// 且失败时报出的名字必须就是那个函数。
async fn run_fallback_rounds(db: &DatabaseConnection, label: &str) {
    step!(
        "ensure_shared_store_tables",
        crate::initialize::ensure_shared_store_tables(db)
    );
    step!(
        "ensure_flow_definition_table",
        crate::initialize::ensure_flow_definition_table(db)
    );
    step!(
        "ensure_flow_indexes",
        crate::initialize::ensure_flow_indexes(db)
    );
    step!(
        "ensure_flow_graph_doc_table",
        crate::initialize::ensure_flow_graph_doc_table(db)
    );
    step!(
        "ensure_sys_pat_table",
        crate::initialize::ensure_sys_pat_table(db)
    );
    step!(
        "ensure_sys_user_credential_table",
        crate::initialize::ensure_sys_user_credential_table(db)
    );
    step!(
        "ensure_user_dept_table",
        crate::initialize::ensure_user_dept_table(db)
    );
    step!(
        "ensure_scim_group_tables",
        crate::initialize::ensure_scim_group_tables(db)
    );
    step!(
        "ensure_sso_consent_unique",
        crate::initialize::ensure_sso_consent_unique(db)
    );
    step!(
        "ensure_report_tables",
        crate::initialize::ensure_report_tables(db)
    );
    step!(
        "ensure_perf_indexes",
        crate::initialize::ensure_perf_indexes(db)
    );
    println!("[smoke] {label}：11 个兜底段函数全部返回 Ok");
}

/// 三方言索引存在性探测（表名/索引名都是本文件常量，不来自外部输入）
async fn index_present(db: &DatabaseConnection, table: &str, index: &str) -> bool {
    let backend = db.get_database_backend();
    let sql = match backend {
        DatabaseBackend::Sqlite => format!(
            "SELECT 1 FROM sqlite_master WHERE type='index' AND name='{index}' AND tbl_name='{table}' LIMIT 1"
        ),
        DatabaseBackend::Postgres => format!(
            "SELECT 1 FROM pg_indexes WHERE schemaname = current_schema() AND tablename='{table}' AND indexname='{index}' LIMIT 1"
        ),
        DatabaseBackend::MySql => format!(
            "SELECT 1 FROM information_schema.statistics WHERE table_schema = DATABASE() AND table_name='{table}' AND index_name='{index}' LIMIT 1"
        ),
        _ => unreachable!("unknown backend"),
    };
    !db.query_all_raw(Statement::from_string(backend, sql))
        .await
        .unwrap_or_else(|e| panic!("[smoke] 探测索引 {index} 失败: {e}"))
        .is_empty()
}

async fn missing_indexes(db: &DatabaseConnection) -> Vec<String> {
    let mut missing = Vec::new();
    for (index, table) in EXPECTED_INDEXES {
        if !index_present(db, table, index).await {
            missing.push(format!("{index}@{table}"));
        }
    }
    missing
}

async fn applied_count(db: &DatabaseConnection) -> usize {
    Migrator::get_applied_migrations(db)
        .await
        .expect("[smoke] 读取已应用迁移失败")
        .len()
}

async fn connect_smoke_db() -> DatabaseConnection {
    let url = std::env::var("STEPBY_SMOKE_DATABASE_URL")
        .ok()
        .filter(|s| !s.is_empty())
        .expect(
            "[smoke] 未设置 STEPBY_SMOKE_DATABASE_URL：活库方言 smoke 必须指向真实 \
             MySQL/PostgreSQL 库（跑法见本文件头部）。缺库时不得静默通过。",
        );
    Database::connect(&url)
        .await
        .unwrap_or_else(|e| panic!("[smoke] 连接失败: {e}"))
}

/// 完整生命周期：迁移前滚 → 兜底两轮（幂等 + 索引真实存在 + 种子不写重）→
/// 全量回滚 → 重放 → 兜底再来两轮。一条用例、一个 schema，不存在并行自扰。
#[tokio::test]
#[ignore = "需要真实 MySQL/PostgreSQL 活库（STEPBY_SMOKE_DATABASE_URL）"]
async fn live_dialect_migration_and_fallback_lifecycle() {
    let db = connect_smoke_db().await;
    println!("[smoke] backend = {:?}", db.get_database_backend());

    // ---- 1. 前滚（对应"迁移库"形态的存量库）----
    Migrator::up(&db, None)
        .await
        .expect("[smoke] Migrator::up 前置建库失败");
    let up_count = applied_count(&db).await;
    // 期望值从注册表派生，**不写死数字**（b83 实测：本机 PG 上跑本环时硬失败在
    // "应为 121、实际 122"——b82 加了 `m20261021_000001_notice_read_user_index` 之后
    // 没人再跑过本环，常量就悄悄过期了。写死数字的判据每加一条迁移就红一次，
    // 而它红了以后人人都会改成"新数字"，等于没有判据）。
    let registered = <Migrator as MigratorTrait>::migrations().len();
    assert_eq!(
        up_count, registered,
        "[smoke] 前滚后已应用迁移数应等于注册表条数（注册表 {registered} 条，库内 {up_count} 条）\
         ⇒ 有迁移在该方言上没落库，或注册表与 _seaql_migrations 漂移"
    );
    assert!(
        registered >= 100,
        "[smoke] 注册表只有 {registered} 条 ⇒ 采集面塌了，这个相等断言即将空转"
    );

    // ---- 2. 兜底段：每次启动都重复执行，必须幂等且真的把索引补齐 ----
    run_fallback_rounds(&db, "第 1 轮").await;
    let missing_1 = missing_indexes(&db).await;
    assert!(
        missing_1.is_empty(),
        "[smoke] 第 1 轮后索引缺失（正是 R-12 的『MySQL 整段跳过』形态）: {missing_1:?}"
    );
    run_fallback_rounds(&db, "第 2 轮").await;
    let missing_2 = missing_indexes(&db).await;
    assert!(
        missing_2.is_empty(),
        "[smoke] 第 2 轮后索引反而缺失: {missing_2:?}"
    );

    let backend = db.get_database_backend();
    let seed_rows = db
        .query_all_raw(Statement::from_string(
            backend,
            "SELECT * FROM flow_definition WHERE flow_code = 'demo_v2'".to_string(),
        ))
        .await
        .expect("[smoke] flow_definition 种子计数失败");
    assert_eq!(
        seed_rows.len(),
        1,
        "[smoke] 两轮兜底后 demo_v2 流程定义应恰好 1 行，实际 {} 行（种子幂等守卫失效）",
        seed_rows.len()
    );

    // ---- 3. 全量回滚（R-10 通道的真方言验证）----
    Migrator::down(&db, None)
        .await
        .expect("[smoke] 全量回滚失败：某条 down() 在该方言上不可用");

    // ---- 4. 重放（R-11 的案发现场：吞错误文案的旧实现在这里让 PG 整笔事务 aborted）----
    Migrator::up(&db, None)
        .await
        .expect("[smoke] 回滚后重放失败（R-11 统一执行器未生效）");
    let replay_count = applied_count(&db).await;
    assert_eq!(
        up_count, replay_count,
        "[smoke] 回滚重放后已应用迁移数不一致（{up_count} → {replay_count}）"
    );

    // ---- 5. 重放后的库再走一遍兜底：真实"存量库被回滚过又前滚"的形态 ----
    run_fallback_rounds(&db, "重放后第 1 轮").await;
    run_fallback_rounds(&db, "重放后第 2 轮").await;
    let missing_3 = missing_indexes(&db).await;
    assert!(
        missing_3.is_empty(),
        "[smoke] 回滚重放后兜底段没能补齐索引: {missing_3:?}"
    );

    // ---- 6. 占位符方言探针（b83：PG 不吃 `?`，而 sea-orm 不翻译）----
    //  正控：经 `common::sql_dialect::stmt` 的语句在三档都能真实执行（修法的端到端证据）。
    //  对照：**只有 PG 档**要求未转换的 `?` 必须失败。缺了这条对照，"三档都成功"
    //       什么都没证明——它可能只是因为连的根本不是 PG（本机实测：
    //       `PREPARE … = ?` ⇒ syntax error，`PREPARE … = $1` ⇒ 成功）。
    {
        let bind = || vec![sea_orm::Value::String(Some("sys.ai.enabled".to_string()))];
        let translated = crate::common::sql_dialect::stmt(
            backend,
            "SELECT COUNT(*) FROM sys_config WHERE config_key = ?",
            bind(),
        );
        let rows = db.query_all_raw(translated).await.unwrap_or_else(|e| {
            panic!("[smoke] 经 sql_dialect::stmt 的查询在 {backend:?} 上失败：{e}")
        });
        assert_eq!(
            rows.len(),
            1,
            "[smoke] COUNT 查询应恰好返回 1 行，实际 {}",
            rows.len()
        );

        if matches!(backend, DatabaseBackend::Postgres) {
            let raw = Statement::from_sql_and_values(
                backend,
                "SELECT COUNT(*) FROM sys_config WHERE config_key = ?",
                bind(),
            );
            let err = db.query_all_raw(raw).await.expect_err(
                "[smoke] PG 上未转换的 `?` 竟然执行成功 ⇒ 本批定性的前提被推翻\
                     （sea-orm 或 PG 行为变了），`common::sql_dialect` 与 \
                     `scripts/pg_placeholder_scan.py` 的判据必须重新定性",
            );
            let text = err.to_string();
            assert!(
                text.contains('?') || text.to_lowercase().contains("syntax"),
                "[smoke] PG 的 `?` 失败文案与预期形态不符，实际：{text}"
            );
            println!("[smoke] 占位符探针：PG 档 `?` 如期失败（对照成立），sql_dialect 档成功");
        } else {
            println!("[smoke] 占位符探针：{backend:?} 档 `?` 原生可用，正控通过");
        }
    }

    println!(
        "[smoke] 通过：{up_count} 条迁移 up→down→up 收敛，{} 个索引在 4 轮兜底后都存在，种子恰好 1 行",
        EXPECTED_INDEXES.len()
    );
}
