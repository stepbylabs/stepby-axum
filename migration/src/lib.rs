// stepby-axum/migration/src/lib.rs
//! migration 子 crate 库入口
//!
//! Migrator 实现 MigratorTrait，聚合全部迁移（86 个，按里程碑时间序）。
//! 2026-09-30 目录重组：迁移文件移入 migrations/ 子目录集中维护，
//! MigrationTrait::name() 未变，seaql_migrations 记录与存量库完全兼容（零影响）。
//! 本文件另承载跨迁移共享的 DDL/seed 工具（IndexDdlExt / adapt_placeholders / now_expr 等），
//! 各迁移文件通过 `use crate::*` 引用。
//!
//! 新增迁移流程：
//! 1. 在 migrations/ 下新建 m<yyyymmdd>_<seq>_<slug>.rs（impl MigrationTrait）；
//! 2. 在 migrations/mod.rs 登记（pub mod）；
//! 3. 在本文件 Migrator Vec 末尾追加 Box::new(<mod名>::Migration)。
use sea_orm_migration::prelude::*;

pub mod migrations;
pub use migrations::*;
/// re-export：AppInitializer 等生产代码调用 Migrator::up 所需的 trait（避免主 crate 引入 sea-orm-migration 依赖）
pub use sea_orm_migration::MigratorTrait;

#[derive(DeriveMigrationName)]
pub struct Migrator;

// 修复预先存在的问题：m20260806_000001_add_log_time_indexes 已创建但漏注册，索引从未生效

use sea_orm_migration::sea_orm::DatabaseBackend;
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
/// `IF NOT EXISTS`，改由本 trait 执行并容错"索引已存在"类错误，保证跨方言幂等：
/// - MySQL   1061: `Duplicate key name 'xxx'`
/// - PostgreSQL 42P07: `relation "xxx" already exists`
/// - SQLite: `index xxx already exists`
///
/// 仅用于索引类 DDL（表/数据类 DDL 不适用，避免误吞 `Table already exists` 等错误）。
#[async_trait::async_trait]
pub trait IndexDdlExt {
    /// 执行索引类 DDL；若错误为"索引已存在"则视为成功，其余错误原样上抛。
    async fn execute_index_ddl_ic(&self, sql: &str) -> Result<(), DbErr>;
}

#[async_trait::async_trait]
impl IndexDdlExt for SchemaManagerConnection<'_> {
    async fn execute_index_ddl_ic(&self, sql: &str) -> Result<(), DbErr> {
        match self.execute_unprepared(sql).await {
            Ok(_) => Ok(()),
            Err(e) => {
                let msg = e.to_string();
                if msg.contains("Duplicate key name")
                    || msg.contains("42P07")
                    || msg.contains("already exists")
                {
                    Ok(())
                } else {
                    Err(e)
                }
            }
        }
    }
}

/// 数据库迁移管理器

#[async_trait::async_trait]
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
        ]
    }
}
