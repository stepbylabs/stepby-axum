// axum-backend/migration/src/m20260924_000009_user_dept.rs
//! 多部门任职（最小侵入版）——福哥拍板方案一组成。
//!
//! 设计决策（§23 §4 更优解，拍板前审查定稿）：
//!   - **主部门沿用 sys_user.dept_id 字段**（语义 = 主部门），data_scope
//!     （本部门/及以下，repository `scope_dept_ids` 注入过滤的就是
//!     sys_user.dept_id）**零改动**——"本部门"口径恒为主部门，语义零歧义。
//!   - **兼职部门进本表**（只存兼职，不存主部门）——避免 is_primary 双写
//!     漂移：主部门唯一事实源 = sys_user.dept_id，本表唯一事实源 = 兼职集合。
//!     "全部归属" = dept_id ∪ 本表。
//!   - source 列：'admin'（人工配置）| 'scim:{group_id}'（Phase B 组→兼职
//!     部门同步写入）——两个事实源分离，与 sys_user_role.source 同构。
//!   - 存量迁移：**无需**——存量用户本表为空即"无兼职"，dept_id 已在主列。
//!   - 部门删除联动：服务层删除兼职记录（主部门归属沿用既有逻辑）。
//!
//! 跨 sqlite/postgres/mysql 兼容，DCL 参考 m20260922_000001_sso_module。

use sea_orm_migration::prelude::*;
use crate::IndexDdlExt;

pub struct Migration;

/// 判断当前数据库是否为 SQLite
fn is_sqlite(manager: &SchemaManager<'_>) -> bool {
    matches!(
        manager.get_connection().get_database_backend(),
        sea_orm_migration::sea_orm::DatabaseBackend::Sqlite
    )
}

/// 判断当前数据库是否为 PostgreSQL
fn is_postgres(manager: &SchemaManager<'_>) -> bool {
    matches!(
        manager.get_connection().get_database_backend(),
        sea_orm_migration::sea_orm::DatabaseBackend::Postgres
    )
}

impl MigrationName for Migration {
    fn name(&self) -> &str {
        "m20260924_000009_user_dept"
    }
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let (id_pk, dt_type) = if is_sqlite(manager) {
            ("INTEGER PRIMARY KEY AUTOINCREMENT", "DATETIME")
        } else if is_postgres(manager) {
            ("BIGSERIAL PRIMARY KEY", "TIMESTAMP")
        } else {
            ("BIGINT PRIMARY KEY AUTO_INCREMENT", "DATETIME")
        };
        let bigint_type = if is_postgres(manager) {
            "BIGINT NOT NULL"
        } else {
            "INTEGER NOT NULL"
        };

        manager
            .get_connection()
            .execute_unprepared(&format!(
                r#"CREATE TABLE IF NOT EXISTS sys_user_dept (
            id          {id_pk},
            user_id     {bigint_type},
            dept_id     {bigint_type},
            source      VARCHAR(64) NOT NULL DEFAULT 'admin',
            create_time {dt_type}
        )"#
            ))
            .await?;
        manager
            .get_connection()
            .execute_index_ddl_ic(
                "CREATE UNIQUE INDEX uk_user_dept ON sys_user_dept (user_id, dept_id)",
            )
            .await?;
        manager
            .get_connection()
            .execute_index_ddl_ic(
                "CREATE INDEX idx_user_dept_dept ON sys_user_dept (dept_id)",
            )
            .await?;
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let conn = manager.get_connection();
        conn.execute_unprepared("DELETE FROM sys_user_dept WHERE source <> 'admin'")
            .await?;
        conn.execute_unprepared("DROP TABLE IF EXISTS sys_user_dept")
            .await?;
        Ok(())
    }
}
