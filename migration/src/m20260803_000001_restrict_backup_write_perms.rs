//! 收紧 common 角色(role_id=2) 备份写权限
//!
//! 背景：
//!   - m20260729_000001_fix_menu_icons_and_dashboard 已移除 common 角色的
//!     system:backup:remove(1202) 和 system:backup:edit(1211, 恢复备份) 权限
//!   - 但 system:backup:add(1201, 创建备份) 仍处于不确定状态：
//!     m20260721_000003 声明插入 (2, 1201)，但 m20260729 的注释说"保留新增类权限"，
//!     实际 DB 中 (2, 1201) 缺失（历史原因不可考，可能由早期数据迁移或手动操作导致）
//!   - 测试脚本 testFeature31 期望 ry 调用 POST /system/backup 返回 403
//!
//! 决策：
//!   备份创建（add）与恢复（edit）、删除（remove）同属敏感写操作，
//!   普通角色不应具备任何备份写权限，仅保留 list/query/download 只读权限。
//!   这与 m20260729 的"高危操作收紧"方向一致，避免普通角色创建大量备份占用磁盘。
//!
//! 操作：
//!   幂等删除 sys_role_menu 中 (role_id=2, menu_id IN (1201, 1202, 1211))
//!   - 1201: system:backup:add（创建备份）
//!   - 1202: system:backup:remove（删除备份，m20260729 已删，此处理论兜底）
//!   - 1211: system:backup:edit（恢复备份，m20260729 已删，此处理论兜底）
//!
//! 注意：超管(role_id=1)通过 *:*:* 通配符不受影响。

use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // 幂等删除：若行不存在，DELETE 不会报错
        manager
            .get_connection()
            .execute_unprepared(
                "DELETE FROM sys_role_menu WHERE role_id = 2 AND menu_id IN (1201, 1202, 1211)",
            )
            .await?;
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // 回滚：恢复 common 角色的备份写权限（仅用于开发/测试环境回滚）
        // 使用 INSERT OR IGNORE 幂等插入（SQLite）；MySQL/PostgreSQL 由 sea-orm 自动适配
        let backend = manager.get_connection().get_database_backend();
        use sea_orm_migration::sea_orm::Statement;
        for menu_id in [1201i64, 1202, 1211] {
            let sql = match backend {
                sea_orm_migration::sea_orm::DatabaseBackend::Postgres => {
                    format!("INSERT INTO sys_role_menu (role_id, menu_id) VALUES (2, {}) ON CONFLICT DO NOTHING", menu_id)
                }
                sea_orm_migration::sea_orm::DatabaseBackend::Sqlite => {
                    format!("INSERT OR IGNORE INTO sys_role_menu (role_id, menu_id) VALUES (2, {})", menu_id)
                }
                _ => {
                    format!("INSERT IGNORE INTO sys_role_menu (role_id, menu_id) VALUES (2, {})", menu_id)
                }
            };
            manager
                .get_connection()
                .execute(Statement::from_sql_and_values(backend, &sql, []))
                .await?;
        }
        Ok(())
    }
}
