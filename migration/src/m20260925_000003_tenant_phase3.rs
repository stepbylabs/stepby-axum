// axum-backend/migration/src/m20260925_000003_tenant_phase3.rs
//! 多租户 Phase 3：独立租户表族（文档 §27 / §29.7 P1 落地）。
//!
//! 决策（福哥拍板，§29 专项核查后修订）：
//!   1. **租户独立 id 空间**：`sys_tenant.tenant_id` 不再复用 `sys_dept.dept_id`；
//!      `sys_tenant.dept_id` 仅是该租户组织树的挂载根部门，二者无相等关系；
//!   2. `tenant_id = 0` 保留为**平台租户**（跨租户运营），不落 sys_tenant 行；
//!   3. 本迁移只建表建索引（**DDL**）；存量库的 `旧 tid → 新 tenant_id` remap
//!      由 AppInitializer `ensure_tenant_phase3` 完成（存量库启动不跑 Migrator::up，
//!      与 Phase 2 同型：两处清单必须双写，R4 是回归门禁）；
//!   4. `sys_tenant_menu`（L3 租户自建导航）本阶段只建表，功能属 P3 可选
//!      （见 §29.4：只能引用 L1 既有 component、perms 必须 ∈ 静态映射表）。
//!
//! 幂等：`CREATE TABLE IF NOT EXISTS` + `execute_index_ddl_ic`（三方言）。
//! 跨 sqlite/postgres/mysql。

use crate::IndexDdlExt;
use sea_orm_migration::prelude::*;

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
        "m20260925_000003_tenant_phase3"
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
        let conn = manager.get_connection();

        // ---- 1. sys_tenant（租户主表）----
        conn.execute_unprepared(&format!(
            r#"CREATE TABLE IF NOT EXISTS sys_tenant (
            tenant_id     {id_pk},
            tenant_code   VARCHAR(64) NOT NULL,
            tenant_name   VARCHAR(64) NOT NULL,
            dept_id       BIGINT NULL,
            package_id    BIGINT NULL,
            contact_name  VARCHAR(64) NULL,
            contact_phone VARCHAR(20) NULL,
            contact_email VARCHAR(64) NULL,
            domain        VARCHAR(255) NULL,
            expire_time   {dt_type} NULL,
            account_count INT NOT NULL DEFAULT 0,
            status        VARCHAR(1) NOT NULL DEFAULT '0',
            del_flag      VARCHAR(1) NOT NULL DEFAULT '0',
            create_by     VARCHAR(64) NULL,
            create_time   {dt_type} NULL,
            update_by     VARCHAR(64) NULL,
            update_time   {dt_type} NULL,
            remark        VARCHAR(500) NULL
        )"#
        ))
        .await?;
        conn.execute_index_ddl_ic(
            "CREATE UNIQUE INDEX uk_sys_tenant_code ON sys_tenant (tenant_code)",
        )
        .await?;
        conn.execute_index_ddl_ic("CREATE INDEX idx_sys_tenant_dept ON sys_tenant (dept_id)")
            .await?;

        // ---- 2. sys_tenant_package（套餐 = 功能白名单上限）----
        conn.execute_unprepared(&format!(
            r#"CREATE TABLE IF NOT EXISTS sys_tenant_package (
            package_id            {id_pk},
            package_name          VARCHAR(64) NOT NULL,
            menu_ids              TEXT NULL,
            default_account_count INT NOT NULL DEFAULT 0,
            status                VARCHAR(1) NOT NULL DEFAULT '0',
            del_flag              VARCHAR(1) NOT NULL DEFAULT '0',
            create_by             VARCHAR(64) NULL,
            create_time           {dt_type} NULL,
            update_by             VARCHAR(64) NULL,
            update_time           {dt_type} NULL,
            remark                VARCHAR(500) NULL
        )"#
        ))
        .await?;
        conn.execute_index_ddl_ic(
            "CREATE UNIQUE INDEX uk_sys_tenant_package_name ON sys_tenant_package (package_name)",
        )
        .await?;

        // ---- 3. sys_tenant_domain（域名绑定；domain 全局唯一）----
        conn.execute_unprepared(&format!(
            r#"CREATE TABLE IF NOT EXISTS sys_tenant_domain (
            domain_id     {id_pk},
            tenant_id     BIGINT NOT NULL DEFAULT 0,
            domain        VARCHAR(255) NOT NULL,
            domain_type   VARCHAR(16) NOT NULL DEFAULT '1',
            is_primary    VARCHAR(1) NOT NULL DEFAULT '1',
            verify_status VARCHAR(1) NOT NULL DEFAULT '0',
            verify_token  VARCHAR(64) NULL,
            verified_at   {dt_type} NULL,
            status        VARCHAR(1) NOT NULL DEFAULT '0',
            del_flag      VARCHAR(1) NOT NULL DEFAULT '0',
            create_by     VARCHAR(64) NULL,
            create_time   {dt_type} NULL,
            update_by     VARCHAR(64) NULL,
            update_time   {dt_type} NULL,
            remark        VARCHAR(500) NULL
        )"#
        ))
        .await?;
        conn.execute_index_ddl_ic(
            "CREATE UNIQUE INDEX uk_sys_tenant_domain_domain ON sys_tenant_domain (domain)",
        )
        .await?;
        conn.execute_index_ddl_ic(
            "CREATE INDEX idx_sys_tenant_domain_tid ON sys_tenant_domain (tenant_id)",
        )
        .await?;

        // ---- 4. sys_tenant_menu（L3 租户自建导航；段位 5000+）----
        conn.execute_unprepared(&format!(
            r#"CREATE TABLE IF NOT EXISTS sys_tenant_menu (
            l3_id       BIGINT NOT NULL PRIMARY KEY,
            tenant_id   BIGINT NOT NULL DEFAULT 0,
            ref_menu_id BIGINT NOT NULL DEFAULT 0,
            parent_id   BIGINT NOT NULL DEFAULT 0,
            order_num   INT NOT NULL DEFAULT 0,
            visible     VARCHAR(1) NOT NULL DEFAULT '0',
            status      VARCHAR(1) NOT NULL DEFAULT '0',
            del_flag    VARCHAR(1) NOT NULL DEFAULT '0',
            create_by   VARCHAR(64) NULL,
            create_time {dt_type} NULL,
            update_by   VARCHAR(64) NULL,
            update_time {dt_type} NULL
        )"#
        ))
        .await?;
        conn.execute_index_ddl_ic(
            "CREATE UNIQUE INDEX uk_sys_tenant_menu ON sys_tenant_menu (tenant_id, ref_menu_id)",
        )
        .await?;
        conn.execute_index_ddl_ic(
            "CREATE INDEX idx_sys_tenant_menu_tid ON sys_tenant_menu (tenant_id)",
        )
        .await?;

        // ---- 5. sys_tenant_migration_map（tid remap 映射表，唯一不可逆点的回滚依赖）----
        conn.execute_unprepared(&format!(
            r#"CREATE TABLE IF NOT EXISTS sys_tenant_migration_map (
            map_id        {id_pk},
            old_tid       BIGINT NOT NULL,
            new_tenant_id BIGINT NOT NULL,
            create_time   {dt_type} NULL,
            remark        VARCHAR(500) NULL
        )"#
        ))
        .await?;
        conn.execute_index_ddl_ic(
            "CREATE UNIQUE INDEX uk_sys_tenant_migration_map_old ON sys_tenant_migration_map (old_tid)",
        )
        .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // 映射表含反向回滚信息，不随 down 删除（禁止清理，§29.7）
        let conn = manager.get_connection();
        for table in [
            "sys_tenant_menu",
            "sys_tenant_domain",
            "sys_tenant_package",
            "sys_tenant",
        ] {
            conn.execute_unprepared(&format!("DROP TABLE IF EXISTS {table}"))
                .await?;
        }
        Ok(())
    }
}
