// stepby-axum/src/initialize/scim.rs

use sea_orm::{ConnectionTrait, DatabaseBackend, DatabaseConnection, DbErr, Statement};

// ==================== SCIM Group + 多部门任职存量库兜底 ====================
// 与迁移 m20260924_000008_scim_groups / m20260924_000009_user_dept 等价：
// SCIM Group 三表 + sys_user_dept 兼职表 + sys_user_role.source 列 + 菜单 148/3620-3622。
// DDL 与种子 SQL 与迁移保持同步（双写惯例，参照 ensure_flow_module）；
// 全部幂等，每次启动重复执行不产生重复行。

/// 幂等确保 `sys_user_role` 含 `source` 列（授权来源两事实源分离）。
///
/// 实体带 source 字段后，存量库缺列会使所有 sys_user_role SELECT 失败——
/// 登录后权限加载、角色管理、SCIM 联动全站 500，优先级最高的兜底项。
/// 与迁移 m20260924_000008 §1.4 逐字对齐（存量行自动 'admin'）。
pub(crate) async fn ensure_user_role_source_column(db: &DatabaseConnection) -> Result<(), DbErr> {
    let exists = sso_table_exists(db, "sys_user_role")
        .await
        .map_err(|e| DbErr::Custom(format!("sys_user_role 存在性检查失败: {}", e)))?;
    if !exists {
        tracing::info!("sys_user_role 表尚未创建，跳过 source 列检查（由 migration 负责建表）");
        return Ok(());
    }
    let has_source = sso_has_column(db, "sys_user_role", "source")
        .await
        .map_err(|e| DbErr::Custom(format!("sys_user_role.source 列检查失败: {}", e)))?;
    if has_source {
        return Ok(());
    }
    db.execute_raw(Statement::from_string(
        db.get_database_backend(),
        "ALTER TABLE sys_user_role ADD COLUMN source VARCHAR(64) NOT NULL DEFAULT 'admin'"
            .to_string(),
    ))
    .await?;
    tracing::info!("sys_user_role.source 列已补建（SCIM Group 存量库兜底）");
    Ok(())
}

/// 幂等确保 `sys_user_dept` 兼职中间表存在（多部门任职，DDL 与迁移 m20260924_000009 逐字对齐）。
///
/// CREATE TABLE IF NOT EXISTS 三方言幂等；索引 SQLite/PG 支持 IF NOT EXISTS，
/// MySQL 跳过交由 migration 补齐（与 ensure_sys_pat_table 同策略）。
pub(crate) async fn ensure_user_dept_table(db: &DatabaseConnection) -> Result<(), DbErr> {
    let backend = db.get_database_backend();
    let (id_pk, bigint_type, dt_type) = match backend {
        DatabaseBackend::Sqlite => (
            "INTEGER PRIMARY KEY AUTOINCREMENT",
            "INTEGER NOT NULL",
            "DATETIME",
        ),
        DatabaseBackend::Postgres => ("BIGSERIAL PRIMARY KEY", "BIGINT NOT NULL", "TIMESTAMP"),
        _ => (
            "BIGINT PRIMARY KEY AUTO_INCREMENT",
            "INTEGER NOT NULL",
            "DATETIME",
        ),
    };
    flow_exec(
        db,
        format!(
            "CREATE TABLE IF NOT EXISTS sys_user_dept (\n\
             \x20 id          {id_pk},\n\
             \x20 user_id     {bigint_type},\n\
             \x20 dept_id     {bigint_type},\n\
             \x20 source      VARCHAR(64) NOT NULL DEFAULT 'admin',\n\
             \x20 create_time {dt_type}\n\
             )"
        ),
    )
    .await?;
    if !matches!(backend, DatabaseBackend::MySql) {
        for ddl in [
            "CREATE UNIQUE INDEX IF NOT EXISTS uk_user_dept ON sys_user_dept (user_id, dept_id)",
            "CREATE INDEX IF NOT EXISTS idx_user_dept_dept ON sys_user_dept (dept_id)",
        ] {
            if let Err(e) = flow_exec(db, ddl).await {
                tracing::debug!("sys_user_dept 索引创建跳过（可能已存在）: {}", e);
            }
        }
    }
    Ok(())
}

/// 幂等确保 SCIM Group 三表存在（DDL 与迁移 m20260924_000008 §1.1-1.3 逐字对齐）
pub(crate) async fn ensure_scim_group_tables(db: &DatabaseConnection) -> Result<(), DbErr> {
    let backend = db.get_database_backend();
    let (id_pk, dt_type) = match backend {
        DatabaseBackend::Sqlite => ("INTEGER PRIMARY KEY AUTOINCREMENT", "DATETIME"),
        DatabaseBackend::Postgres => ("BIGSERIAL PRIMARY KEY", "TIMESTAMP"),
        _ => ("BIGINT PRIMARY KEY AUTO_INCREMENT", "DATETIME"),
    };
    let (tenant_type, bigint_type) = if backend == DatabaseBackend::Postgres {
        ("BIGINT NOT NULL DEFAULT 0", "BIGINT NOT NULL")
    } else {
        ("INTEGER NOT NULL DEFAULT 0", "INTEGER NOT NULL")
    };

    // 1.1 sys_scim_group 组实体（管理端不可建组——组权威在 IdP）
    flow_exec(
        db,
        format!(
            "CREATE TABLE IF NOT EXISTS sys_scim_group (\n\
             \x20 group_id     {id_pk},\n\
             \x20 display_name VARCHAR(255) NOT NULL,\n\
             \x20 external_id  VARCHAR(255),\n\
             \x20 mapping_type VARCHAR(16) NOT NULL DEFAULT 'role',\n\
             \x20 del_flag     VARCHAR(1) NOT NULL DEFAULT '0',\n\
             \x20 tenant_id    {tenant_type},\n\
             \x20 create_by    VARCHAR(64) DEFAULT '',\n\
             \x20 create_time  {dt_type},\n\
             \x20 update_time  {dt_type}\n\
             )"
        ),
    )
    .await?;

    // 1.2 sys_scim_group_binding 组绑定目标（target_id 语义由组 mapping_type 决定）
    flow_exec(
        db,
        format!(
            "CREATE TABLE IF NOT EXISTS sys_scim_group_binding (\n\
             \x20 id          {id_pk},\n\
             \x20 group_id    {bigint_type},\n\
             \x20 target_id   {bigint_type},\n\
             \x20 create_time {dt_type}\n\
             )"
        ),
    )
    .await?;

    // 1.3 sys_scim_group_member 组成员（复合 PK (group_id, user_id)）
    flow_exec(
        db,
        format!(
            "CREATE TABLE IF NOT EXISTS sys_scim_group_member (\n\
             \x20 group_id    {bigint_type},\n\
             \x20 user_id     {bigint_type},\n\
             \x20 create_time {dt_type},\n\
             \x20 PRIMARY KEY (group_id, user_id)\n\
             )"
        ),
    )
    .await?;

    // 索引：SQLite/PG 支持 IF NOT EXISTS；MySQL 跳过交由 migration（照 ensure_flow_indexes）
    if !matches!(backend, DatabaseBackend::MySql) {
        for ddl in [
            "CREATE UNIQUE INDEX IF NOT EXISTS uk_scim_group_external_id ON sys_scim_group (external_id)",
            "CREATE UNIQUE INDEX IF NOT EXISTS uk_scim_group_binding ON sys_scim_group_binding (group_id, target_id)",
        ] {
            if let Err(e) = flow_exec(db, ddl).await {
                tracing::debug!("SCIM Group 索引创建跳过（可能已存在）: {}", e);
            }
        }
    }
    Ok(())
}

/// 幂等补种 SCIM 组管理菜单（页 148 挂 145 SSO 目录 + 按钮 3620-3622 + role_menu(2)；
/// 与迁移 m20260924_000008 §2 逐字对齐，flow_insert 幂等——menu_id 主键防重）
pub(crate) async fn ensure_scim_group_menu(db: &DatabaseConnection) -> Result<(), DbErr> {
    // sys_menu 表存在性保护：全新空库未建系统表时跳过种子（交由 migration 负责初始种子）
    let sys_menu_exists = sso_table_exists(db, "sys_menu")
        .await
        .map_err(|e| DbErr::Custom(format!("SCIM 组菜单种子表存在性检查失败: {}", e)))?;
    if !sys_menu_exists {
        tracing::info!("SCIM 组菜单种子跳过（sys_menu 不存在，空库交由 migration 负责初始种子）");
        return Ok(());
    }
    let now = flow_now(db);
    let menu_cols = "sys_menu (menu_id, menu_name, parent_id, order_num, path, component, query, route_name, is_frame, is_cache, menu_type, visible, status, perms, icon, create_by, create_time, remark, del_flag)";

    // 2.1 C 页面「SCIM 用户组」
    flow_insert(
        db,
        &format!(
            "{menu_cols} VALUES \
             (148, 'SCIM 用户组', 145, 3, 'scimGroup', 'system/scimGroup/index', '', '', '1', '0', 'C', '0', '0', 'system:scimgroup:list', 'peoples', 'admin', {now}, 'SCIM Group 组→角色/部门映射管理', '0')"
        ),
    )
    .await?;
    // 2.2 F 按钮权限
    let btn_rows: &[(&i64, &str, &str)] = &[
        (&3620, "组绑定编辑", "system:scimgroup:edit"),
        (&3621, "组删除", "system:scimgroup:remove"),
        (&3622, "组详情查询", "system:scimgroup:query"),
    ];
    for (menu_id, name, perms) in btn_rows {
        flow_insert(
            db,
            &format!(
                "{menu_cols} VALUES \
                 ({menu_id}, '{name}', 148, 1, '', '', '', '', '1', '0', 'F', '0', '0', '{perms}', '#', 'admin', {now}, '', '0')"
            ),
        )
        .await?;
    }
    // common 授权（菜单行写入**之后**统一补，SELECT 侧才看得见本轮新行）：
    // b73 轮 15 起走 governance 策略体——148 页面与 3622 `:query` 放行，
    // 3620/3621（改/删 SCIM 组→角色映射，等同间接给他人提权）不再默认授予 common。
    flow_insert(
        db,
        &governance::common_role_grant_select_body(&[148, 3620, 3621, 3622]),
    )
    .await?;
    Ok(())
}

/// 幂等确保 SCIM Group 模块与多部门任职完整就绪（列 + 表 + 索引 + 菜单；存量库向后兼容）
pub(crate) async fn ensure_scim_group_module(db: &DatabaseConnection) -> anyhow::Result<()> {
    ensure_user_role_source_column(db)
        .await
        .map_err(|e| anyhow::anyhow!("sys_user_role.source 列兜底失败: {}", e))?;
    ensure_user_dept_table(db)
        .await
        .map_err(|e| anyhow::anyhow!("sys_user_dept 建表失败: {}", e))?;
    ensure_scim_group_tables(db)
        .await
        .map_err(|e| anyhow::anyhow!("SCIM Group 三表建表失败: {}", e))?;
    ensure_scim_group_menu(db)
        .await
        .map_err(|e| anyhow::anyhow!("SCIM 组菜单种子补齐失败: {}", e))?;
    tracing::info!("SCIM Group 模块与多部门任职表已就绪（幂等确保完成）");
    Ok(())
}

use super::*;
