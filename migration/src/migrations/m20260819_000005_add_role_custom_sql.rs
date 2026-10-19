// stepby-axum/migration/src/migrations/m20260819_000005_add_role_custom_sql.rs
//! 数据权限加深：为 sys_role 增加 `custom_sql` 列（自定义部门 SQL 过滤片段）
//!
//! 背景：data_scope = "2"（自定义数据权限）原本仅支持「勾选部门」（sys_role_dept）。
//! 本迁移新增可空的 `custom_sql` 文本列，允许在自定义模式下额外附加一条简单的
//! 白名单列条件，扩展数据权限到按字段过滤（如 status、dept_id、sex 等）。
//!
//! 安全性：
//! - 该列只存储原始片段字符串，运行时由 src/common/custom_scope 的解析器白名单校验，
//!   参数化重建为 SeaORM 查询，绝不拼接为裸 SQL。
//! - 仅管理员通过角色编辑接口可写入本列。
//!
//! 兼容性：SQLite / PostgreSQL / MySQL 均支持 `ALTER TABLE ... ADD COLUMN ... TEXT`（可空），
//! 无需按后端分支。

use sea_orm_migration::prelude::*;

pub struct Migration;

impl MigrationName for Migration {
    fn name(&self) -> &str {
        "m20260819_000005_add_role_custom_sql"
    }
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .get_connection()
            .execute_unprepared("ALTER TABLE sys_role ADD COLUMN custom_sql TEXT")
            .await?;
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .get_connection()
            .execute_unprepared("ALTER TABLE sys_role DROP COLUMN custom_sql")
            .await?;
        Ok(())
    }
}
