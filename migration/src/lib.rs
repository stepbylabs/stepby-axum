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

use sea_orm_migration::prelude::*;

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
        ]
    }
}
