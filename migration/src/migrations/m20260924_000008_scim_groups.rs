// stepby-axum/migration/src/m20260924_000008_scim_groups.rs
//! v5-D12 Group：SCIM Group 资源落地（组→角色集合 / 组→部门 双映射）。
//!
//! 拍板方案（福哥 2026-09-24，方案一全做）：
//!   - A（组→角色集合映射）：组绑定一组角色，成员变更自动联动 sys_user_role
//!     授权增删（带 source='scim:{group_id}' 来源标记，与管理员手授 'admin'
//!     互不干扰——消除回写抖动）。
//!   - B（组→兼职部门同步）：组级 mapping_type='dept' 的组绑定一个部门，
//!     成员同步写 sys_user_dept 兼职记录（主部门永远人工管理，见 000009）。
//!   - C（独立用户组）已被"组→角色集合"变体取代，不实现。
//!
//! 表设计（跨 sqlite/postgres/mysql 兼容，DCL 参考 m20260922_000001_sso_module）：
//!
//! sys_scim_group：组实体（IdP 推送 / SCIM API 管理；管理端不可建组——
//! 组权威在 IdP，管理端仅可改映射类型与绑定、删组）。
//!   - external_id：IdP 侧标识（唯一索引；NULL 允许多行——非 IdP 场景）
//!   - mapping_type：'role'（默认）| 'dept'；变更时必须先清空绑定（服务层强制）
//!   - tenant_id：多租户前向兼容预留（E3 约定：新表一律预留）
//!
//! sys_scim_group_binding：组绑定目标（target_id 语义由组 mapping_type 决定：
//! role→sys_role.role_id / dept→sys_dept.dept_id）。
//!
//! sys_scim_group_member：组成员（复合 PK (group_id, user_id)；user_id 关联
//! sys_user，成员展示从 SCIM Users 语义取 user_id 字符串）。
//!
//! sys_user_role 加 source 列：'admin'（默认，存量行自动归入）| 'scim:{group_id}'。
//! 管理员编辑用户只 diff 'admin' 行；SCIM 联动只动本组 source 行——两个事实源分离，
//! 回写抖动消除。
//!
//! 菜单元数据（前置约定：单点登录目录 menu_id=145）：
//!   - C 页面「SCIM 用户组」(menu_id=148, path=scimGroup, component=system/scimGroup/index,
//!     perms=system:scimgroup:list)——段位登记：页面增量 148；按钮 3620-3622
//!   - F 按钮：3620 组编辑(system:scimgroup:edit) / 3621 组删除(system:scimgroup:remove)
//!     / 3622 组详情查询(system:scimgroup:query)
//!   - role_menu 关联 role_id=2
//!
//! 幂等：全部走 execute_idempotent_insert（INSERT OR IGNORE / ON CONFLICT DO NOTHING）。

use crate::IndexDdlExt;
use sea_orm_migration::prelude::*;

pub struct Migration;

/// 判断当前数据库是否为 SQLite
fn is_sqlite(manager: &SchemaManager<'_>) -> bool {
    let backend = manager.get_connection().get_database_backend();
    matches!(backend, sea_orm_migration::sea_orm::DatabaseBackend::Sqlite)
}

/// 判断当前数据库是否为 PostgreSQL
fn is_postgres(manager: &SchemaManager<'_>) -> bool {
    matches!(
        manager.get_connection().get_database_backend(),
        sea_orm_migration::sea_orm::DatabaseBackend::Postgres
    )
}

/// 当前时间表达式（跨数据库兼容）
fn now_expr(manager: &SchemaManager<'_>) -> String {
    if is_sqlite(manager) {
        let now = chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
        format!("'{}'", now)
    } else {
        "NOW()".to_string()
    }
}

/// 幂等 INSERT
async fn execute_idempotent_insert(manager: &SchemaManager<'_>, body: &str) -> Result<(), DbErr> {
    let sql = if is_sqlite(manager) {
        format!("INSERT OR IGNORE INTO {}", body)
    } else if is_postgres(manager) {
        format!("INSERT INTO {} ON CONFLICT DO NOTHING", body)
    } else {
        format!("INSERT IGNORE INTO {}", body)
    };
    manager.get_connection().execute_unprepared(&sql).await?;
    Ok(())
}

impl MigrationName for Migration {
    fn name(&self) -> &str {
        "m20260924_000008_scim_groups"
    }
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // ==================== 1. 建表 ====================
        let (id_pk, dt_type) = if is_sqlite(manager) {
            ("INTEGER PRIMARY KEY AUTOINCREMENT", "DATETIME")
        } else if is_postgres(manager) {
            ("BIGSERIAL PRIMARY KEY", "TIMESTAMP")
        } else {
            ("BIGINT PRIMARY KEY AUTO_INCREMENT", "DATETIME")
        };
        let (tenant_type, bigint_type) = if is_postgres(manager) {
            ("BIGINT NOT NULL DEFAULT 0", "BIGINT NOT NULL")
        } else {
            ("INTEGER NOT NULL DEFAULT 0", "INTEGER NOT NULL")
        };

        // 1.1 sys_scim_group 组实体
        manager
            .get_connection()
            .execute_unprepared(&format!(
                r#"CREATE TABLE IF NOT EXISTS sys_scim_group (
            group_id     {id_pk},
            display_name VARCHAR(255) NOT NULL,
            external_id  VARCHAR(255),
            mapping_type VARCHAR(16) NOT NULL DEFAULT 'role',
            del_flag     VARCHAR(1) NOT NULL DEFAULT '0',
            tenant_id    {tenant_type},
            create_by    VARCHAR(64) DEFAULT '',
            create_time  {dt_type},
            update_time  {dt_type}
        )"#
            ))
            .await?;
        // external_id 唯一（NULL 不受唯一约束——mysql/pg/sqlite 三方言同语义）
        manager
            .get_connection()
            .execute_index_ddl_ic(
                "CREATE UNIQUE INDEX uk_scim_group_external_id ON sys_scim_group (external_id)",
            )
            .await?;

        // 1.2 sys_scim_group_binding 组绑定目标
        manager
            .get_connection()
            .execute_unprepared(&format!(
                r#"CREATE TABLE IF NOT EXISTS sys_scim_group_binding (
            id          {id_pk},
            group_id    {bigint_type},
            target_id   {bigint_type},
            create_time {dt_type}
        )"#
            ))
            .await?;
        manager
            .get_connection()
            .execute_index_ddl_ic(
                "CREATE UNIQUE INDEX uk_scim_group_binding ON sys_scim_group_binding (group_id, target_id)",
            )
            .await?;

        // 1.3 sys_scim_group_member 组成员（复合 PK）
        manager
            .get_connection()
            .execute_unprepared(&format!(
                r#"CREATE TABLE IF NOT EXISTS sys_scim_group_member (
            group_id    {bigint_type},
            user_id     {bigint_type},
            create_time {dt_type},
            PRIMARY KEY (group_id, user_id)
        )"#
            ))
            .await?;

        // 1.4 sys_user_role 加来源标记列（存量行自动 'admin'）
        manager
            .get_connection()
            .execute_unprepared(
                "ALTER TABLE sys_user_role ADD COLUMN source VARCHAR(64) NOT NULL DEFAULT 'admin'",
            )
            .await?;

        // ==================== 2. 菜单元数据 ====================
        let now = now_expr(manager);
        let menu_cols = "sys_menu (menu_id, menu_name, parent_id, order_num, path, component, query, route_name, is_frame, is_cache, menu_type, visible, status, perms, icon, create_by, create_time, remark, del_flag)";

        // 2.1 C 页面「SCIM 用户组」（挂单点登录目录 145）
        let page_sql = format!(
            "{menu_cols} VALUES \
            (148, 'SCIM 用户组', 145, 3, 'scimGroup', 'system/scimGroup/index', '', '', '1', '0', 'C', '0', '0', 'system:scimgroup:list', 'peoples', 'admin', {now}, 'SCIM Group 组→角色/部门映射管理', '0')"
        );
        execute_idempotent_insert(manager, &page_sql).await?;
        execute_idempotent_insert(manager, "sys_role_menu (role_id, menu_id) VALUES (2, 148)")
            .await?;

        // 2.2 F 按钮权限（关联页面 148）
        let btn_rows: &[(i64, &str, &str)] = &[
            (3620, "组绑定编辑", "system:scimgroup:edit"),
            (3621, "组删除", "system:scimgroup:remove"),
            (3622, "组详情查询", "system:scimgroup:query"),
        ];
        for (menu_id, name, perms) in btn_rows {
            let sql = format!(
                "{menu_cols} VALUES \
                ({menu_id}, '{name}', 148, 1, '', '', '', '', '1', '0', 'F', '0', '0', '{perms}', '#', 'admin', {now}, '', '0')"
            );
            execute_idempotent_insert(manager, &sql).await?;
            execute_idempotent_insert(
                manager,
                &format!("sys_role_menu (role_id, menu_id) VALUES (2, {menu_id})"),
            )
            .await?;
        }

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let conn = manager.get_connection();
        for menu_id in [148, 3620, 3621, 3622] {
            conn.execute_unprepared(&format!(
                "DELETE FROM sys_role_menu WHERE menu_id = {menu_id}"
            ))
            .await?;
            conn.execute_unprepared(&format!("DELETE FROM sys_menu WHERE menu_id = {menu_id}"))
                .await?;
        }
        // source 列回落：删除 SCIM 来源授权行后去列（保 admin 数据不丢）
        conn.execute_unprepared("DELETE FROM sys_user_role WHERE source <> 'admin'")
            .await?;
        conn.execute_unprepared("ALTER TABLE sys_user_role DROP COLUMN source")
            .await?;
        conn.execute_unprepared("DROP TABLE IF EXISTS sys_scim_group_member")
            .await?;
        conn.execute_unprepared("DROP TABLE IF EXISTS sys_scim_group_binding")
            .await?;
        conn.execute_unprepared("DROP TABLE IF EXISTS sys_scim_group")
            .await?;
        Ok(())
    }
}
