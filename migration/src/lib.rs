// stepby-axum/migration/src/lib.rs
//! migration 子 crate 库入口
//!
//! Migrator 实现 MigratorTrait，聚合全部迁移（按里程碑时间序；条数以
//! `migrations/mod.rs` 与本文件 Vec 为准，二者一致性由
//! `src/integration_tests/migration_registry.rs` 机械锁定——本行**不写死条数**，
//! 因为写死的数字已经烂过一次：注释停留在 86 时实际是 119）。
//! 2026-09-30 目录重组：迁移文件移入 migrations/ 子目录集中维护，
//! MigrationTrait::name() 未变，seaql_migrations 记录与存量库完全兼容（零影响）。
//! 本文件另承载跨迁移共享的 DDL/seed 工具（IndexDdlExt / adapt_placeholders / now_expr 等），
//! 各迁移文件通过 `use crate::*` 引用。
//!
//! 新增迁移流程：
//! 1. 在 migrations/ 下新建 `m<yyyymmdd>_<seq>_<slug>.rs`（impl MigrationTrait）；
//! 2. 在 migrations/mod.rs 登记（pub mod）；
//! 3. 在本文件 Migrator Vec 末尾追加 `Box::new(<mod名>::Migration)`；
//! 4. 跑 `cargo test migration_registry`——漏登记直接判红（历史上
//!    `m20260806_000001_add_log_time_indexes` 就因漏登记导致索引从未生效）。
use sea_orm_migration::prelude::*;

pub mod migrations;
pub use migrations::*;
/// re-export：AppInitializer 等生产代码调用 Migrator::up 所需的 trait（避免主 crate 引入 sea-orm-migration 依赖）
pub use sea_orm_migration::MigratorTrait;

#[derive(DeriveMigrationName)]
pub struct Migrator;

// 修复预先存在的问题：m20260806_000001_add_log_time_indexes 已创建但漏注册，索引从未生效

use sea_orm_migration::sea_orm::{DatabaseBackend, Statement, Value};
use std::borrow::Cow;

/// 将 SQL 中的 PostgreSQL 风格 `$N` 占位符按目标方言转换：
/// Postgres 原样返回；MySQL/SQLite 将 `$N`（连续数字）替换为 `?`。
///
/// 背景：`Statement::from_sql_and_values` **不会**自动改写占位符——
/// MySQL 驱动只识别 `?`（`$1` 会被当作列名，报 1054 Unknown column '$1'）；
/// SQLite 的 `$1` 是合法命名参数恰好可用，但统一转换消除方言差异。
/// 迁移 SQL 统一按 PG 风格书写占位符，经本函数适配后交给 from_sql_and_values。
/// 单引号字符串字面量内的 `$` 不转换。
pub fn adapt_placeholders(backend: DatabaseBackend, sql: &str) -> Cow<'_, str> {
    if backend == DatabaseBackend::Postgres || !sql.contains('$') {
        return Cow::Borrowed(sql);
    }
    let mut out = String::with_capacity(sql.len());
    let mut in_string = false;
    let mut chars = sql.char_indices().peekable();
    while let Some((_, c)) = chars.next() {
        match c {
            '\'' => {
                in_string = !in_string;
                out.push('\'');
            }
            '$' if !in_string && chars.peek().is_some_and(|&(_, nc)| nc.is_ascii_digit()) => {
                out.push('?');
                while chars.peek().is_some_and(|&(_, nc)| nc.is_ascii_digit()) {
                    chars.next();
                }
            }
            _ => out.push(c),
        }
    }
    Cow::Owned(out)
}

/// MySQL 方言兼容扩展：索引 DDL 幂等执行器。
///
/// `CREATE [UNIQUE] INDEX IF NOT EXISTS` 是 SQLite / PostgreSQL / MariaDB 支持的语法，
/// MySQL 8.0 不支持（MariaDB 专属扩展）。因此迁移中的索引 DDL 统一去掉
/// `IF NOT EXISTS`，改由本 trait 做**跨方言幂等**执行。
///
/// ## 为什么不能"先执行、再按错误文案吞掉"（批七十七 R-11 根因）
///
/// 旧实现是 `execute_unprepared(sql)` 之后判断错误串里有没有
/// `Duplicate key name` / `42P07` / `already exists`，有就当成功。三库实测证明这套
/// 只在 MySQL 上成立：**PostgreSQL 的事务里任何一条语句失败，整笔事务就进入 aborted
/// 状态**，之后每条语句都只能拿到 `current transaction is aborted`，而 sea-orm 是
/// **一条迁移一个事务**。于是"吞掉首错"实际把这条迁移剩下的所有语句一起废掉，
/// 报出来的还是与首错无关的二级错——回滚后重放正是在这里断的
/// （`m20260925_000003` 的 `uk_sys_tenant_migration_map_old`：它的表按 §29.7 故意不随
/// down 删除，索引因此残留，重放时首错即"索引已存在"）。
///
/// 现在的两条真判据：
/// 1. **先探测再执行**（sqlite `sqlite_master` / pg `pg_indexes` / mysql
///    `information_schema.statistics`），已存在就直接跳过，压根不发会失败的语句；
/// 2. 确实要发时用 `SAVEPOINT` 把它隔开，失败就 `ROLLBACK TO SAVEPOINT`，
///    事务保持可用（PG 上唯一正确的"容忍单条语句失败"做法），错误仍原样上抛，
///    由调用方决定是否只告警不阻断。
///
/// 仅用于索引类 DDL（表/数据类 DDL 不适用）。
#[async_trait::async_trait]
pub trait IndexDdlExt {
    /// 幂等执行索引类 DDL；索引已存在则跳过，其余错误原样上抛（不吞文案）。
    async fn execute_index_ddl_ic(&self, sql: &str) -> Result<(), DbErr>;
}

/// 本执行器单条语句用的 SAVEPOINT 名（同一连接内顺序执行，不会重入）。
const IDX_SAVEPOINT: &str = "stepby_idx_ddl_sp";

/// 从 `CREATE [UNIQUE] INDEX [IF NOT EXISTS] <name> ON <table> (...)` 里取出
/// `(索引名, 表名)`；形态不符返回 `None`（调用方此时直接执行原语句，不自作主张）。
///
/// 表名取最后一段：`db`.`sys_user` / `sys_user` 都归一成 `sys_user`，
/// 因为 MySQL 的探测按 `table_schema = DATABASE()` 限定，前缀反而会查不到。
pub fn parse_index_ddl(sql: &str) -> Option<(String, String)> {
    let parts: Vec<&str> = sql.split_whitespace().collect();
    let up: Vec<String> = parts.iter().map(|t| t.to_ascii_uppercase()).collect();
    let create_at = up.iter().position(|t| t == "CREATE")?;
    let index_at = up
        .iter()
        .skip(create_at + 1)
        .position(|t| t == "INDEX")
        .map(|p| p + create_at + 1)?;
    let mut name_at = index_at + 1;
    if name_at + 2 < up.len()
        && up[name_at] == "IF"
        && up[name_at + 1] == "NOT"
        && up[name_at + 2] == "EXISTS"
    {
        name_at += 3;
    }
    let name = clean_ident(parts.get(name_at)?)?;
    let on_at = up
        .iter()
        .skip(name_at + 1)
        .position(|t| t == "ON")
        .map(|p| p + name_at + 1)?;
    // 库前缀与引号由 clean_ident 归一（先分段后剥引号）；不带空格的 `tbl(col)`
    // 写法由 table_ident 取 `(` 之前的部分
    let table = table_ident(parts.get(on_at + 1)?)?;
    Some((name, table))
}

/// 表名令牌 → 标识符。`ON sys_pat(token_hash)` 这种列清单不带空格的写法在兜底段里
/// 是真实形态（活库 smoke 实测：解析不出来就退化成"直接执行"，MySQL 撞 1061），
/// 所以先按 `(` 截断再走 `clean_ident`。
fn table_ident(tok: &str) -> Option<String> {
    clean_ident(tok.split('(').next()?)
}

/// 剥出干净的标识符：先按 `.` 取最后一段（`db`.`tbl` 要归一成 `tbl`，
/// MySQL 侧探测按 `table_schema = DATABASE()` 限定，带库前缀反而查不到），
/// 再剥两侧的引号族（反引号 / 双引号 / 单引号）与尾随逗号。
///
/// 顺序很重要：先 trim 再 split 会把 "`stepby`.`sys_role`" 变成 "`sys_role"
/// （两端反引号被整体 trim 掉后，中间的反引号留在了段首）——本函数的测试里抓到了它。
fn clean_ident(tok: &str) -> Option<String> {
    let s = tok.trim().trim_end_matches(',');
    let last = s.rsplit('.').next().unwrap_or(s);
    let s2 = last.trim_matches(|c| c == '`' || c == '"' || c == '\'');
    if s2.is_empty() || s2.contains('(') || s2.contains('.') {
        None
    } else {
        Some(s2.to_string())
    }
}

#[async_trait::async_trait]
impl IndexDdlExt for SchemaManagerConnection<'_> {
    async fn execute_index_ddl_ic(&self, sql: &str) -> Result<(), DbErr> {
        // 迁移侧：sea-orm 一条迁移一个事务，必须用 SAVEPOINT 隔离（见 ensure_index_ddl_in_tx）
        ensure_index_ddl_in_tx(self, sql).await
    }
}

/// 索引 DDL 的**唯一**幂等实现（批七十七 R-11）：先按方言探测存在性，已存在就跳过。
///
/// 泛型到 `ConnectionTrait` 是为了两个入口共用一份探测代码：
/// - 迁移侧：`SchemaManagerConnection`（经 `IndexDdlExt`，走 `ensure_index_ddl_in_tx`）；
/// - 启动兜底侧：`DatabaseConnection`（`initialize::menu|flow|oauth_sso|schema|scim|tenant`
///   此前各自内联一份"执行后按错误文案吞掉"的副本——同构四份，且每一份都可能被 PG
///   事务语义反噬）。
///
/// **本函数用于自动提交上下文**（兜底段每条语句自成事务，失败不污染后续语句），
/// 因此不发 SAVEPOINT：PG 在事务块外执行 `SAVEPOINT` 会直接报
/// `SAVEPOINT can only be used in transaction blocks`（批七十七活库 smoke 实测）。
/// 需要事务隔离的调用方请用 [`ensure_index_ddl_in_tx`]。
pub async fn ensure_index_ddl<C>(conn: &C, sql: &str) -> Result<(), DbErr>
where
    C: ConnectionTrait,
{
    ensure_index_ddl_impl(conn, sql, false).await
}

/// 事务内形态（迁移路径）：探测 → SAVEPOINT 隔离 → 失败回滚到保存点、错误原样上抛。
pub async fn ensure_index_ddl_in_tx<C>(conn: &C, sql: &str) -> Result<(), DbErr>
where
    C: ConnectionTrait,
{
    ensure_index_ddl_impl(conn, sql, true).await
}

async fn ensure_index_ddl_impl<C>(conn: &C, sql: &str, in_tx: bool) -> Result<(), DbErr>
where
    C: ConnectionTrait,
{
    let backend = conn.get_database_backend();
    let Some((index, table)) = parse_index_ddl(sql) else {
        // 形态不认识：不猜，直接执行，让真实错误暴露出来
        // （判据 D 静态盯着兜底段的写法必须可解析，见 integration_tests/ddl_dialect_discipline）
        return conn.execute_unprepared(sql).await.map(|_| ());
    };
    if index_exists(conn, backend, &table, &index).await? {
        return Ok(());
    }
    if backend == DatabaseBackend::MySql || !in_tx {
        // MySQL 的 DDL 自带隐式提交，而隐式提交会**抹掉会话里所有 SAVEPOINT**：
        // `SAVEPOINT` → `CREATE INDEX` → `RELEASE SAVEPOINT` 三连在 MySQL 8.0.46 上以
        // `ERROR 1305 SAVEPOINT stepby_idx_ddl_sp does not exist` 失败（活库 smoke 实测
        // ——此前"SAVEPOINT 对 MySQL 无害"的注释是未验证的推断）。
        // 非事务上下文（兜底段）同理：既没有需要保住的事务，SAVEPOINT 还会直接被 PG 拒。
        return conn.execute_unprepared(sql).await.map(|_| ());
    }
    // PG / SQLite 且确在事务内：这一条失败会污染事务（PG 首错即 aborted），
    // 用 SAVEPOINT 把它隔开，失败回滚到保存点后原样上抛，事务仍然可用
    conn.execute_unprepared(&format!("SAVEPOINT {IDX_SAVEPOINT}"))
        .await?;
    match conn.execute_unprepared(sql).await {
        Ok(_) => conn
            .execute_unprepared(&format!("RELEASE SAVEPOINT {IDX_SAVEPOINT}"))
            .await
            .map(|_| ()),
        Err(e) => {
            let _ = conn
                .execute_unprepared(&format!("ROLLBACK TO SAVEPOINT {IDX_SAVEPOINT}"))
                .await;
            let _ = conn
                .execute_unprepared(&format!("RELEASE SAVEPOINT {IDX_SAVEPOINT}"))
                .await;
            Err(e)
        }
    }
}

/// 三方言索引存在性探测（索引名走绑定参数；MySQL 侧表名是迁移内常量标识符，
/// 与同仓 `ensure_column` 的探测口径一致地内联）。
///
/// 判据用 `SELECT 1 … LIMIT 1` + 结果集是否为空，不取 `COUNT(*)`：数值列的解码类型在
/// 方言间不一致（MySQL 的 `COUNT` 是无符号宽度），一旦取不到值就 `unwrap_or(0)` 静默
/// 退化成「索引不存在」。
///
/// 本批真正被活库 smoke 照出来的静默退化在另一侧：解析器不认 `ON sys_pat(token_hash)`
/// （列清单不带空格）→ 探测整段被跳过 → 真 MySQL 8.0 上重复建索引撞 1061。两处一并收口，
/// 并由 `integration_tests/ddl_dialect_discipline.rs` 判据 D 静态盯着解析面。
async fn index_exists<C>(
    conn: &C,
    backend: DatabaseBackend,
    table: &str,
    index: &str,
) -> Result<bool, DbErr>
where
    C: ConnectionTrait,
{
    // 每支自己拼到最终 SQL（含本方言的占位符形态），不再借 `adapt_placeholders`：
    // 「哪支用 $1、哪支用 ?」在源码里一目了然，dialect_audit 也不需要为此留豁免。
    // 三库的标识符**一律走绑定参数**（R-14 收口）：MySQL 支此前把表名 `format!` 内联，
    // 取值恒为源码内常量、当下没有注入面，但"恒为常量"是靠纪律而非类型维持的——
    // 一旦有人把用户可控字符串传进来，这里就是一处 SQL 拼接。绑定参数没有这个前提。
    // SQLite/PG 的索引名在库/模式内唯一，无需表名谓词；MySQL 的 information_schema
    // 跨库聚合，必须带 `table_schema = DATABASE()` + `table_name`。
    let (sql, values) = match backend {
        DatabaseBackend::Sqlite => (
            "SELECT 1 FROM sqlite_master WHERE type = 'index' AND name = $1 LIMIT 1".to_string(),
            vec![Value::String(Some(index.to_string()))],
        ),
        DatabaseBackend::Postgres => (
            "SELECT 1 FROM pg_indexes WHERE schemaname = current_schema() AND indexname = $1 LIMIT 1"
                .to_string(),
            vec![Value::String(Some(index.to_string()))],
        ),
        DatabaseBackend::MySql => (
            "SELECT 1 FROM information_schema.statistics \
             WHERE table_schema = DATABASE() AND table_name = ? AND index_name = ? LIMIT 1"
                .to_string(),
            vec![
                Value::String(Some(table.to_string())),
                Value::String(Some(index.to_string())),
            ],
        ),
        _ => unreachable!("unknown backend"),
    };
    let stmt = Statement::from_sql_and_values(backend, sql, values);
    Ok(!conn.query_all_raw(stmt).await?.is_empty())
}

/// 数据库迁移管理器

#[async_trait::async_trait]
impl MigratorTrait for Migrator {
    fn migrations() -> Vec<Box<dyn MigrationTrait>> {
        vec![
            Box::new(m20250711_000001_init::Migration),
            Box::new(m20250716_000001_gen_and_notice_read::Migration),
            Box::new(m20260717_000001_add_indexes::Migration),
            Box::new(m20260718_000001_add_more_indexes::Migration),
            Box::new(m20260719_000001_adjust_field_length::Migration),
            Box::new(m20260720_000001_hide_druid_menu::Migration),
            Box::new(m20260721_000001_sys_backup_log::Migration),
            Box::new(m20260721_000002_sys_task::Migration),
            Box::new(m20260721_000003_add_new_menus::Migration),
            Box::new(m20260722_000001_add_dict_label_en::Migration),
            Box::new(m20260722_000002_oper_log_before::Migration),
            Box::new(m20260722_000003_sys_rate_limit::Migration),
            Box::new(m20260723_000001_add_backup_restore_perm::Migration),
            Box::new(m20260724_000001_ip_location_menus::Migration),
            Box::new(m20260725_000001_add_mylogin_about_menus::Migration),
            Box::new(m20260725_000002_add_menu_i18n_key::Migration),
            Box::new(m20260726_000001_add_notice_center_session_menus::Migration),
            Box::new(m20260727_000001_add_workbench_shortcuts_help_menus::Migration),
            Box::new(m20260728_000001_add_changelog_menu::Migration),
            Box::new(m20260729_000001_fix_menu_icons_and_dashboard::Migration),
            Box::new(m20260730_000001_remove_duplicate_health_file_menus::Migration),
            Box::new(m20260731_000001_fix_menu_order_and_icons::Migration),
            Box::new(m20260801_000001_remove_druid_menu::Migration),
            Box::new(m20260801_000002_register_dashboard_menu::Migration),
            Box::new(m20260801_000003_fix_missing_menu_i18n_key::Migration),
            Box::new(m20260802_000001_merge_server_to_health::Migration),
            Box::new(m20260802_000002_merge_cache_list_to_cache::Migration),
            Box::new(m20260802_000003_merge_session_login_menus::Migration),
            Box::new(m20260802_000004_add_missing_button_perms::Migration),
            Box::new(m20260803_000001_restrict_backup_write_perms::Migration),
            Box::new(m20260804_000001_fix_ip_location_menu_parent::Migration),
            Box::new(m20260805_000001_fix_backup_task_ratelimit_menu_parent::Migration),
            Box::new(m20260806_000001_add_log_time_indexes::Migration),
            Box::new(m20260806_000002_add_task_operator_id::Migration),
            Box::new(m20260818_000001_add_log_monitor_menu::Migration),
            Box::new(m20260818_000002_msg_module::Migration),
            Box::new(m20260818_000003_audit_alarm_config::Migration),
            Box::new(m20260819_000001_oauth_module::Migration),
            Box::new(m20260819_000002_http_debugger_menu::Migration),
            Box::new(m20260819_000003_report_module::Migration),
            Box::new(m20260819_000004_user_pref_module::Migration),
            Box::new(m20260819_000005_add_role_custom_sql::Migration),
            Box::new(m20260819_000006_observability_menu::Migration),
            Box::new(m20260820_000001_demo_seed::Migration),
            Box::new(m20260820_000002_web_hook_module::Migration),
            Box::new(m20260821_000001_frontend_error_module::Migration),
            Box::new(m20260822_000001_oper_log_diff::Migration),
            Box::new(m20260823_000001_sys_pat::Migration),
            Box::new(m20260922_000001_sso_module::Migration),
            Box::new(m20260923_000001_sso_v4_hardening::Migration),
            Box::new(m20260923_000002_flow_module::Migration),
            Box::new(m20260924_000001_sso_rate_limit_tiers::Migration),
            Box::new(m20260924_000002_sso_consent_unique::Migration),
            Box::new(m20260924_000003_sso_rs256::Migration),
            Box::new(m20260924_000004_sso_subject_type::Migration),
            Box::new(m20260924_000005_user_tenant_id::Migration),
            Box::new(m20260924_000006_scim_external_id::Migration),
            Box::new(m20260924_000007_sector_identifier::Migration),
            Box::new(m20260924_000008_scim_groups::Migration),
            Box::new(m20260924_000009_user_dept::Migration),
            Box::new(m20260924_000010_common_role_readonly::Migration),
            Box::new(m20260925_000001_multitenant_phase2::Migration),
            Box::new(m20260925_000002_tenant_module::Migration),
            Box::new(m20260925_000003_tenant_phase3::Migration),
            Box::new(m20260925_000004_tenant_saas_governance::Migration),
            Box::new(m20260925_000005_tenant_unique_scope::Migration),
            Box::new(m20260926_000001_role_is_system::Migration),
            Box::new(m20260926_000002_platform_only_menu_regrant::Migration),
            Box::new(m20260926_000003_logininfor_user_id::Migration),
            Box::new(m20260926_000004_oauth_client_key_id::Migration),
            Box::new(m20260926_000005_platform_only_prefix_governance::Migration),
            Box::new(m20260926_000006_platform_only_prefix_full::Migration),
            Box::new(m20260926_000007_platform_only_ratelimit::Migration),
            Box::new(m20260926_000008_flow_log_operator_index::Migration),
            Box::new(m20260926_000009_gen_column_rust_naming::Migration),
            Box::new(m20260926_000010_tenant_package_features::Migration),
            Box::new(m20260926_000011_tenant_domain_self_service_menu::Migration),
            Box::new(m20260926_000012_backup_permission_granularity::Migration),
            Box::new(m20260926_000013_platform_only_tenant_menu::Migration),
            Box::new(m20260926_000014_tenant_nav_menu::Migration),
            Box::new(m20260927_000001_oauth_client_prev_secret::Migration),
            Box::new(m20260927_000002_sys_user_credential::Migration),
            Box::new(m20260928_000001_sys_dept_ancestors_width::Migration),
            Box::new(m20260928_000002_frontend_error_device_type::Migration),
            Box::new(m20260928_000003_dedupe_dashboard_menu::Migration),
            Box::new(m20260928_000004_optimize_menu_structure::Migration),
            Box::new(m20261001_000001_shared_store::Migration),
            Box::new(m20261002_000001_perf_indexes::Migration),
            Box::new(m20261003_000001_audit_change::Migration),
            Box::new(m20261003_000002_webhook_event::Migration),
            Box::new(m20261003_000003_alert_rule::Migration),
            Box::new(m20261003_000004_webhook_unify::Migration),
            Box::new(m20261003_000005_role_field_perm::Migration),
            Box::new(m20261003_000006_report_board::Migration),
            Box::new(m20261004_000001_alert_rule_index::Migration),
            Box::new(m20261004_000002_webhook_event_edit::Migration),
            Box::new(m20261004_000003_force_pwd_change::Migration),
            Box::new(m20261006_000001_ai_config_and_history::Migration),
            Box::new(m20261006_000002_data_rule::Migration),
            Box::new(m20261006_000003_ai_token_usage::Migration),
            Box::new(m20261007_000001_job_log_duration::Migration),
            Box::new(m20261007_000002_upload_config_menu::Migration),
            Box::new(m20261007_000003_flow_definition::Migration),
            Box::new(m20261007_000004_report_dataset::Migration),
            Box::new(m20261007_000005_flow_report_menus::Migration),
            Box::new(m20261007_000006_flow_task_action::Migration),
            Box::new(m20261007_000007_sms_cloud_columns::Migration),
            Box::new(m20261007_000008_report_menus_visible::Migration),
            Box::new(m20261007_000009_flow_designer_menu_visible::Migration),
            Box::new(m20261007_000010_flow_report_role_menus::Migration),
            Box::new(m20261007_000011_config_seed_and_menu_hygiene::Migration),
            Box::new(m20261007_000012_flow_graph_doc::Migration),
            Box::new(m20261007_000013_flow_task_actions_json::Migration),
            Box::new(m20261008_000001_log_archive_anchor::Migration),
            Box::new(m20261010_000001_fix_ai_history_menu_parent::Migration),
            Box::new(m20261012_000001_config_governance_and_archive_menus::Migration),
            Box::new(m20261013_000001_normalize_menu_del_flag::Migration),
            Box::new(m20261017_000001_common_role_grant_erosion::Migration),
            Box::new(m20261017_000002_platform_only_alert::Migration),
            Box::new(m20261018_000001_flow_action_dict::Migration),
            Box::new(m20261019_000001_flow_action_dict_drop_reserved::Migration),
            Box::new(m20261021_000001_notice_read_user_index::Migration),
        ]
    }
}

/// 种子/迁移写库的**唯一**时间表达式（批七十四 B1 归口）。
///
/// ## 为什么三方言统一返回 UTC 字面量
///
/// 改造前本逻辑在 `migration/src/migrations/*.rs` 里有 **36 份**逐字同构的副本
/// （`grep -rln "fn now_expr" | wc -l` = 36），外加 `src/initialize/` 里 5 份同构 helper
/// （`flow_now` 等）——同一逻辑的两批副本，改一处必然漏其余。每份都写成
/// "SQLite 用 `chrono::Local::now()` 预计算串 / MySQL+PG 用 `NOW()`"，于是同时存在两处漂移：
///
/// 1. **口径漂移**：运行期写入口径是 `common::datetime::now_naive()` =
///    `Utc::now().naive_local()`（全仓 202 处），而种子用**本机挂钟**（dev 机 UTC+8）
///    ⇒ 同一库内两种时间并存。实测：`sys_data_rule` 6 行 `create_time` 晚于 UTC now
///    整 8 小时；`seed_diff` 里 `sys_user.login_date: seed='2026-10-18 02:38:59' →
///    live='2026-10-17 18:37:19'` 长期被记成 "informational"，**它不是运行态演进，是口径分裂**。
/// 2. **方言漂移**：MySQL/PG 的 `NOW()` 取**会话时区**挂钟，与 SQLite 分支的字符串不同源
///    ⇒ 换库即换口径。
///
/// 带引号的日期时间字面量在 SQLite / MySQL / PostgreSQL **三方言均合法**，无需分支；
/// 统一取 UTC 后两条漂移同时消失，且"一份判据"使形状锁可以只扫一个函数。
///
/// 展示与调度侧使用 `Local` 是**合法**的（本地日界统计、HTTP `Last-Modified` 头、
/// 备份文件名、在线会话显示串等），本函数只约束**落库时间**；由
/// `initialize::tests::seed_time_writes_use_single_utc_source` 钉住"落库路径禁 `Local::now()`"。
pub fn seed_now_expr() -> String {
    format!("'{}'", chrono::Utc::now().format("%Y-%m-%d %H:%M:%S"))
}

#[cfg(test)]
mod tests {
    use super::parse_index_ddl;

    #[test]
    fn parse_index_ddl_取到三方言调用点的索引与表() {
        let cases = [
            (
                "CREATE UNIQUE INDEX uk_sys_tenant_migration_map_old ON sys_tenant_migration_map (old_tid)",
                "uk_sys_tenant_migration_map_old",
                "sys_tenant_migration_map",
            ),
            (
                "CREATE INDEX idx_sys_tenant_menu_tid ON sys_tenant_menu (tenant_id)",
                "idx_sys_tenant_menu_tid",
                "sys_tenant_menu",
            ),
            (
                // 小写形态（历史调用点里存在）
                "create index idx_a on sys_user (user_name)",
                "idx_a",
                "sys_user",
            ),
            (
                // 反引号 + 库前缀（MySQL 探测按 DATABASE() 限定，表名必须剥前缀）
                "CREATE UNIQUE INDEX `uk_b` ON `stepby`.`sys_role` (`role_key`)",
                "uk_b",
                "sys_role",
            ),
            (
                // 调用方自己写了 IF NOT EXISTS 也要能解析
                "CREATE UNIQUE INDEX IF NOT EXISTS uk_c ON sys_config (config_key)",
                "uk_c",
                "sys_config",
            ),
            (
                // 多行缩进书写
                "CREATE UNIQUE INDEX uk_d ON sys_dict_type (\n    tenant_id, dict_type\n)",
                "uk_d",
                "sys_dict_type",
            ),
            (
                // 列清单不带空格（sys_pat(token_hash)）：兜底段的真实写法。
                // 曾经解析不出来 → 退化成"不探测直接执行" → MySQL 存量库撞 1061
                "CREATE UNIQUE INDEX uk_sys_pat_token_hash ON sys_pat(token_hash)",
                "uk_sys_pat_token_hash",
                "sys_pat",
            ),
            (
                "CREATE INDEX idx_sys_user_credential_user_id ON sys_user_credential(user_id)",
                "idx_sys_user_credential_user_id",
                "sys_user_credential",
            ),
            (
                // 反引号 + 不带空格
                "CREATE UNIQUE INDEX `uk_e` ON `sys_oauth_consent`(user_id, client_id)",
                "uk_e",
                "sys_oauth_consent",
            ),
        ];
        for (sql, want_idx, want_tbl) in cases {
            let got = parse_index_ddl(sql)
                .unwrap_or_else(|| panic!("解析失败：{sql}（幂等探测将退化成不探测）"));
            assert_eq!(got.0, want_idx, "索引名解析错：{sql}");
            assert_eq!(got.1, want_tbl, "表名解析错：{sql}");
        }
    }

    #[test]
    fn parse_index_ddl_形态不符必须返回_none_而不是猜() {
        // 非索引 DDL：不得被当成索引语句去探测
        assert!(
            parse_index_ddl("ALTER TABLE sys_user ADD COLUMN scim_external_id VARCHAR(64)")
                .is_none()
        );
        assert!(
            parse_index_ddl("CREATE TABLE IF NOT EXISTS sys_tenant (tenant_id BIGINT)").is_none()
        );
        assert!(parse_index_ddl("DROP INDEX uk_x ON sys_role").is_none());
        assert!(parse_index_ddl("").is_none());
        // ON 缺位（少写 ON 的畸形语句）不得把列名当表名
        assert!(parse_index_ddl("CREATE INDEX idx_e (a, b)").is_none());
    }

    #[test]
    fn parse_index_ddl_不被列清单里的相似词骗走() {
        // 列名里带 on/index 关键字时，第一个 ON 才是真正的表分隔符
        let (i, t) =
            parse_index_ddl("CREATE INDEX idx_f ON sys_logininfor (login_time, user_id)").unwrap();
        assert_eq!((i.as_str(), t.as_str()), ("idx_f", "sys_logininfor"));
        // 列名恰好叫 on（PG 允许带引号）时，`(ON)` 整 token 不等于 ON，不会被误判
        let (i2, t2) = parse_index_ddl("CREATE INDEX idx_g ON sys_menu (meta, (ON))").unwrap();
        assert_eq!((i2.as_str(), t2.as_str()), ("idx_g", "sys_menu"));
    }
}
