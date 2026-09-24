// axum-backend/migration/src/lib.rs
//! migration 子 crate 库入口
//! Migrator 实现 MigratorTrait，聚合全部迁移

pub use m20250711_000001_init::Migration as M20250711Init;
pub use m20250716_000001_gen_and_notice_read::Migration as M20250716GenAndNoticeRead;
pub use m20260717_000001_add_indexes::Migration as M20260717AddIndexes;
pub use m20260718_000001_add_more_indexes::Migration as M20260718AddMoreIndexes;
pub use m20260719_000001_adjust_field_length::Migration as M20260719AdjustFieldLength;
pub use m20260720_000001_hide_druid_menu::Migration as M20260720HideDruidMenu;
pub use m20260721_000001_sys_backup_log::Migration as M20260721SysBackupLog;
pub use m20260721_000002_sys_task::Migration as M20260721SysTask;
pub use m20260721_000003_add_new_menus::Migration as M20260721AddNewMenus;
pub use m20260722_000001_add_dict_label_en::Migration as M20260722AddDictLabelEn;
pub use m20260722_000002_oper_log_before::Migration as M20260722OperLogBefore;
pub use m20260722_000003_sys_rate_limit::Migration as M20260722SysRateLimit;
pub use m20260723_000001_add_backup_restore_perm::Migration as M20260723AddBackupRestorePerm;
pub use m20260724_000001_ip_location_menus::Migration as M20260724IpLocationMenus;
pub use m20260725_000001_add_mylogin_about_menus::Migration as M20260725AddMyloginAboutMenus;
pub use m20260725_000002_add_menu_i18n_key::Migration as M20260725AddMenuI18nKey;
pub use m20260726_000001_add_notice_center_session_menus::Migration as M20260726AddNoticeCenterSessionMenus;
pub use m20260727_000001_add_workbench_shortcuts_help_menus::Migration as M20260727AddWorkbenchShortcutsHelpMenus;
pub use m20260728_000001_add_changelog_menu::Migration as M20260728AddChangelogMenu;
pub use m20260729_000001_fix_menu_icons_and_dashboard::Migration as M20260729FixMenuIconsAndDashboard;
pub use m20260730_000001_remove_duplicate_health_file_menus::Migration as M20260730RemoveDuplicateHealthFileMenus;
pub use m20260731_000001_fix_menu_order_and_icons::Migration as M20260731FixMenuOrderAndIcons;
pub use m20260801_000001_remove_druid_menu::Migration as M20260801RemoveDruidMenu;
pub use m20260801_000002_register_dashboard_menu::Migration as M20260801RegisterDashboardMenu;
pub use m20260801_000003_fix_missing_menu_i18n_key::Migration as M20260801FixMissingMenuI18nKey;
pub use m20260802_000001_merge_server_to_health::Migration as M20260802MergeServerToHealth;
pub use m20260802_000002_merge_cache_list_to_cache::Migration as M20260802MergeCacheListToCache;
pub use m20260802_000003_merge_session_login_menus::Migration as M20260802MergeSessionLoginMenus;
pub use m20260802_000004_add_missing_button_perms::Migration as M20260802AddMissingButtonPerms;
pub use m20260803_000001_restrict_backup_write_perms::Migration as M20260803RestrictBackupWritePerms;
pub use m20260804_000001_fix_ip_location_menu_parent::Migration as M20260804FixIpLocationMenuParent;
pub use m20260805_000001_fix_backup_task_ratelimit_menu_parent::Migration as M20260805FixBackupTaskRatelimitMenuParent;
// 修复预先存在的问题：m20260806_000001_add_log_time_indexes 已创建但漏注册，索引从未生效
pub use m20260806_000001_add_log_time_indexes::Migration as M20260806AddLogTimeIndexes;
pub use m20260806_000002_add_task_operator_id::Migration as M20260806AddTaskOperatorId;
pub use m20260818_000001_add_log_monitor_menu::Migration as M20260818AddLogMonitorMenu;
pub use m20260818_000002_msg_module::Migration as M20260818MsgModule;
pub use m20260818_000003_audit_alarm_config::Migration as M20260818AuditAlarmConfig;
pub use m20260819_000001_oauth_module::Migration as M20260819OauthModule;
pub use m20260819_000002_http_debugger_menu::Migration as M20260819HttpDebuggerMenu;
pub use m20260819_000003_report_module::Migration as M20260819ReportModule;
pub use m20260819_000004_user_pref_module::Migration as M20260819UserPrefModule;
pub use m20260819_000005_add_role_custom_sql::Migration as M20260819AddRoleCustomSql;
pub use m20260819_000006_observability_menu::Migration as M20260819ObservabilityMenu;
pub use m20260820_000001_demo_seed::Migration as M20260820DemoSeed;
pub use m20260820_000002_web_hook_module::Migration as M20260820WebHookModule;
pub use m20260821_000001_frontend_error_module::Migration as M20260821FrontendErrorModule;
pub use m20260822_000001_oper_log_diff::Migration as M20260822OperLogDiff;
pub use m20260823_000001_sys_pat::Migration as M20260823SysPat;
pub use m20260922_000001_sso_module::Migration as M20260922SsoModule;
pub use m20260923_000001_sso_v4_hardening::Migration as M20260923SsoV4Hardening;
pub use m20260923_000002_flow_module::Migration as M20260923FlowModule;
pub use m20260924_000001_sso_rate_limit_tiers::Migration as M20260924SsoRateLimitTiers;
pub use m20260924_000002_sso_consent_unique::Migration as M20260924SsoConsentUnique;
pub use m20260924_000003_sso_rs256::Migration as M20260924SsoRs256;
pub use m20260924_000004_sso_subject_type::Migration as M20260924SsoSubjectType;
pub use m20260924_000005_user_tenant_id::Migration as M20260924UserTenantId;
pub use m20260924_000006_scim_external_id::Migration as M20260924ScimExternalId;
pub use m20260924_000007_sector_identifier::Migration as M20260924SectorIdentifier;
pub use m20260924_000008_scim_groups::Migration as M20260924ScimGroups;
pub use m20260924_000009_user_dept::Migration as M20260924UserDept;

mod m20250711_000001_init;
mod m20250716_000001_gen_and_notice_read;
mod m20260717_000001_add_indexes;
mod m20260718_000001_add_more_indexes;
mod m20260719_000001_adjust_field_length;
mod m20260720_000001_hide_druid_menu;
mod m20260721_000001_sys_backup_log;
mod m20260721_000002_sys_task;
mod m20260721_000003_add_new_menus;
mod m20260722_000001_add_dict_label_en;
mod m20260722_000002_oper_log_before;
mod m20260722_000003_sys_rate_limit;
mod m20260723_000001_add_backup_restore_perm;
mod m20260724_000001_ip_location_menus;
mod m20260725_000001_add_mylogin_about_menus;
mod m20260725_000002_add_menu_i18n_key;
mod m20260726_000001_add_notice_center_session_menus;
mod m20260727_000001_add_workbench_shortcuts_help_menus;
mod m20260728_000001_add_changelog_menu;
mod m20260729_000001_fix_menu_icons_and_dashboard;
mod m20260730_000001_remove_duplicate_health_file_menus;
mod m20260731_000001_fix_menu_order_and_icons;
mod m20260801_000001_remove_druid_menu;
mod m20260801_000002_register_dashboard_menu;
mod m20260801_000003_fix_missing_menu_i18n_key;
mod m20260802_000001_merge_server_to_health;
mod m20260802_000002_merge_cache_list_to_cache;
mod m20260802_000003_merge_session_login_menus;
mod m20260802_000004_add_missing_button_perms;
mod m20260803_000001_restrict_backup_write_perms;
mod m20260804_000001_fix_ip_location_menu_parent;
mod m20260805_000001_fix_backup_task_ratelimit_menu_parent;
mod m20260806_000001_add_log_time_indexes;
mod m20260806_000002_add_task_operator_id;
mod m20260818_000001_add_log_monitor_menu;
mod m20260818_000002_msg_module;
mod m20260818_000003_audit_alarm_config;
mod m20260819_000001_oauth_module;
mod m20260819_000002_http_debugger_menu;
mod m20260819_000003_report_module;
mod m20260819_000004_user_pref_module;
mod m20260819_000005_add_role_custom_sql;
mod m20260819_000006_observability_menu;
mod m20260820_000001_demo_seed;
mod m20260820_000002_web_hook_module;
mod m20260821_000001_frontend_error_module;
mod m20260822_000001_oper_log_diff;
mod m20260823_000001_sys_pat;
mod m20260922_000001_sso_module;
mod m20260923_000001_sso_v4_hardening;
mod m20260923_000002_flow_module;
mod m20260924_000001_sso_rate_limit_tiers;
mod m20260924_000002_sso_consent_unique;
mod m20260924_000003_sso_rs256;
mod m20260924_000004_sso_subject_type;
mod m20260924_000005_user_tenant_id;
mod m20260924_000006_scim_external_id;
mod m20260924_000007_sector_identifier;
mod m20260924_000008_scim_groups;
mod m20260924_000009_user_dept;

use sea_orm_migration::prelude::*;
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
pub struct Migrator;

#[async_trait::async_trait]
impl MigratorTrait for Migrator {
    fn migrations() -> Vec<Box<dyn MigrationTrait>> {
        vec![
            Box::new(M20250711Init),
            Box::new(M20250716GenAndNoticeRead),
            Box::new(M20260717AddIndexes),
            Box::new(M20260718AddMoreIndexes),
            Box::new(M20260719AdjustFieldLength),
            Box::new(M20260720HideDruidMenu),
            Box::new(M20260721SysBackupLog),
            Box::new(M20260721SysTask),
            Box::new(M20260721AddNewMenus),
            Box::new(M20260722AddDictLabelEn),
            Box::new(M20260722OperLogBefore),
            Box::new(M20260722SysRateLimit),
            Box::new(M20260723AddBackupRestorePerm),
            Box::new(M20260724IpLocationMenus),
            Box::new(M20260725AddMyloginAboutMenus),
            Box::new(M20260725AddMenuI18nKey),
            Box::new(M20260726AddNoticeCenterSessionMenus),
            Box::new(M20260727AddWorkbenchShortcutsHelpMenus),
            Box::new(M20260728AddChangelogMenu),
            Box::new(M20260729FixMenuIconsAndDashboard),
            Box::new(M20260730RemoveDuplicateHealthFileMenus),
            Box::new(M20260731FixMenuOrderAndIcons),
            Box::new(M20260801RemoveDruidMenu),
            Box::new(M20260801RegisterDashboardMenu),
            Box::new(M20260801FixMissingMenuI18nKey),
            Box::new(M20260802MergeServerToHealth),
            Box::new(M20260802MergeCacheListToCache),
            Box::new(M20260802MergeSessionLoginMenus),
            Box::new(M20260802AddMissingButtonPerms),
            Box::new(M20260803RestrictBackupWritePerms),
            Box::new(M20260804FixIpLocationMenuParent),
            Box::new(M20260805FixBackupTaskRatelimitMenuParent),
            Box::new(M20260806AddLogTimeIndexes),
            Box::new(M20260806AddTaskOperatorId),
            Box::new(M20260818AddLogMonitorMenu),
            Box::new(M20260818MsgModule),
            Box::new(M20260818AuditAlarmConfig),
            Box::new(M20260819OauthModule),
            Box::new(M20260819HttpDebuggerMenu),
            Box::new(M20260819ReportModule),
            Box::new(M20260819UserPrefModule),
            Box::new(M20260819AddRoleCustomSql),
            Box::new(M20260819ObservabilityMenu),
            Box::new(M20260820DemoSeed),
            Box::new(M20260820WebHookModule),
            Box::new(M20260821FrontendErrorModule),
            Box::new(M20260822OperLogDiff),
            Box::new(M20260823SysPat),
            Box::new(M20260922SsoModule),
            Box::new(M20260923SsoV4Hardening),
            Box::new(M20260923FlowModule),
            Box::new(M20260924SsoRateLimitTiers),
            Box::new(M20260924SsoConsentUnique),
            Box::new(M20260924SsoRs256),
            Box::new(M20260924SsoSubjectType),
            Box::new(M20260924UserTenantId),
            Box::new(M20260924ScimExternalId),
            Box::new(M20260924SectorIdentifier),
            Box::new(M20260924ScimGroups),
            Box::new(M20260924UserDept),
        ]
    }
}
