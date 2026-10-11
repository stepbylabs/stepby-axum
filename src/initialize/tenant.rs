// stepby-axum/src/initialize/tenant.rs

use crate::shared_store::SharedStore;
use sea_orm::{
    ConnectionTrait, DatabaseBackend, DatabaseConnection, Statement, TransactionTrait, Value,
};
use std::collections::HashMap;
use std::sync::Arc;

/// 多租户 Phase 2 存量库兜底（与迁移 m20260925_000001/000002 等价，全幂等）：
/// 1) 27 张业务表补 tenant_id 列（BIGINT NOT NULL DEFAULT 0，存量归平台租户 0）
/// 2) tid 索引（3 张大表用 (tenant_id, 时间列) 组合索引，其余单列）
/// 3) 菜单 3700-3704 租户管理段 + role_menu（3700/3701 → role_id=2 只读）
pub(crate) async fn ensure_multitenant_module(db: &DatabaseConnection) -> anyhow::Result<()> {
    let backend = db.get_database_backend();

    // ---- 1. 幂等补列 ----
    const TABLES: &[&str] = &[
        "sys_dept",
        "sys_role",
        "sys_post",
        "sys_config",
        "sys_dict_type",
        "sys_dict_data",
        "sys_notice",
        "sys_notice_read",
        "sys_pat",
        "sys_user_pref",
        "sys_oauth_consent",
        "sys_oauth_provider",
        "sys_oauth_user",
        "sys_msg_channel",
        "sys_msg_template",
        "sys_msg_send_log",
        "sys_web_hook",
        "sys_web_hook_log",
        "sys_report",
        "sys_report_sub",
        "sys_job",
        "sys_job_log",
        "sys_task",
        "sys_backup_log",
        "sys_oper_log",
        "sys_logininfor",
        "sys_frontend_error",
    ];
    let mut added = 0usize;
    for table in TABLES {
        if sso_table_exists(db, table).await? && !sso_has_column(db, table, "tenant_id").await? {
            db.execute_raw(Statement::from_string(
                backend,
                format!("ALTER TABLE {table} ADD COLUMN tenant_id BIGINT NOT NULL DEFAULT 0"),
            ))
            .await?;
            added += 1;
        }
    }
    if added > 0 {
        tracing::info!("多租户 tenant_id 列已补建 {added} 张表（存量库兜底）");
    }

    // ---- 2. 幂等建索引（三方言全覆盖：MySQL 经 information_schema 查存后建，不再跳过）----
    {
        let mut idx_defs: Vec<(String, String, String)> = Vec::new();
        // 大表组合索引（时间列名各异：oper_time/login_time/create_time）
        for (t, c) in [
            ("sys_oper_log", "oper_time"),
            ("sys_logininfor", "login_time"),
            ("sys_msg_send_log", "create_time"),
        ] {
            idx_defs.push((
                t.to_string(),
                format!("idx_{t}_tid_time"),
                format!("tenant_id, {c}"),
            ));
        }
        for t in TABLES {
            if !matches!(*t, "sys_oper_log" | "sys_logininfor" | "sys_msg_send_log") {
                idx_defs.push((
                    t.to_string(),
                    format!("idx_{t}_tid"),
                    "tenant_id".to_string(),
                ));
            }
        }
        for (table, index_name, columns) in &idx_defs {
            if let Err(e) = ensure_tenant_index(db, table, index_name, columns, false).await {
                tracing::debug!("租户索引 {index_name} 创建跳过: {}", e);
            }
        }
    }

    // ---- 3. 菜单 3700-3704 段幂等登记 + role_menu（对齐 m20260925_000002）----
    let insert_prefix = match backend {
        DatabaseBackend::Sqlite => "INSERT OR IGNORE INTO ",
        DatabaseBackend::Postgres => "INSERT INTO ",
        DatabaseBackend::MySql => "INSERT IGNORE INTO ",
        _ => unreachable!("unknown backend"),
    };
    let insert_suffix = if backend == DatabaseBackend::Postgres {
        " ON CONFLICT DO NOTHING"
    } else {
        ""
    };
    let now_expr = match backend {
        DatabaseBackend::Sqlite => {
            format!("'{}'", chrono::Local::now().format("%Y-%m-%d %H:%M:%S"))
        }
        _ => "NOW()".to_string(),
    };
    let menu_cols = "sys_menu (menu_id, menu_name, parent_id, order_num, path, component, query, route_name, is_frame, is_cache, menu_type, visible, status, perms, icon, create_by, create_time, remark, del_flag, i18n_key)";
    let body_rows = [
        format!(
            "{menu_cols} VALUES (3700, '租户管理', 1, 8, 'tenant', 'system/tenant/index', '', '', '1', '0', 'C', '0', '0', 'system:tenant:list', 'peoples', 'admin', {now_expr}, '多租户管理（dept 树根=租户）', '0', 'menu.tenant')"
        ),
        "sys_role_menu (role_id, menu_id) VALUES (2, 3700)".to_string(),
        format!(
            "{menu_cols} VALUES (3701, '租户查询', 3700, 1, '', '', '', '', '1', '0', 'F', '0', '0', 'system:tenant:query', '#', 'admin', {now_expr}, '', '0', NULL)"
        ),
        "sys_role_menu (role_id, menu_id) VALUES (2, 3701)".to_string(),
        format!(
            "{menu_cols} VALUES (3702, '租户新增', 3700, 1, '', '', '', '', '1', '0', 'F', '0', '0', 'system:tenant:add', '#', 'admin', {now_expr}, '', '0', NULL)"
        ),
        format!(
            "{menu_cols} VALUES (3703, '租户修改', 3700, 1, '', '', '', '', '1', '0', 'F', '0', '0', 'system:tenant:edit', '#', 'admin', {now_expr}, '', '0', NULL)"
        ),
        format!(
            "{menu_cols} VALUES (3704, '租户删除', 3700, 4, '', '', '', '', '1', '0', 'F', '0', '0', 'system:tenant:remove', '#', 'admin', {now_expr}, '', '0', NULL)"
        ),
        // ---- 域名绑定（多租户 Phase 3 域名链路，menu_id 段位 3800-3804，父 3700）----
        // 授予约定与 3700/3701 一致：运维查看（list）与验证（verify）授予平台普通角色（role_id=2），
        // 新增/修改/删除仅平台操作者（operator_tid=0）可用，故不授予普通角色。
        format!(
            "{menu_cols} VALUES (3800, '域名查询', 3700, 5, '', '', '', '', '1', '0', 'F', '0', '0', 'system:tenant:domain:list', '#', 'admin', {now_expr}, '', '0', NULL)"
        ),
        "sys_role_menu (role_id, menu_id) VALUES (2, 3800)".to_string(),
        format!(
            "{menu_cols} VALUES (3801, '域名新增', 3700, 6, '', '', '', '', '1', '0', 'F', '0', '0', 'system:tenant:domain:add', '#', 'admin', {now_expr}, '', '0', NULL)"
        ),
        format!(
            "{menu_cols} VALUES (3802, '域名验证', 3700, 7, '', '', '', '', '1', '0', 'F', '0', '0', 'system:tenant:domain:verify', '#', 'admin', {now_expr}, '', '0', NULL)"
        ),
        "sys_role_menu (role_id, menu_id) VALUES (2, 3802)".to_string(),
        format!(
            "{menu_cols} VALUES (3803, '域名修改', 3700, 8, '', '', '', '', '1', '0', 'F', '0', '0', 'system:tenant:domain:edit', '#', 'admin', {now_expr}, '', '0', NULL)"
        ),
        format!(
            "{menu_cols} VALUES (3804, '域名删除', 3700, 9, '', '', '', '', '1', '0', 'F', '0', '0', 'system:tenant:domain:remove', '#', 'admin', {now_expr}, '', '0', NULL)"
        ),
    ];
    for body in body_rows {
        db.execute_raw(Statement::from_string(
            backend,
            format!("{insert_prefix}{body}{insert_suffix}"),
        ))
        .await?;
    }

    tracing::info!("多租户 Phase 2 模块已就绪（幂等确保完成）");
    Ok(())
}

/// 承载租户归属的表清单（Phase 3 remap 改写范围；同时被
/// `service::sys_backup_service::export_tenant_package` 复用为「租户数据包」导出范围）：
/// = Phase 2 `ensure_multitenant_module::TABLES` 的 27 张 + `sys_user`（列由
/// m20260924_000005 / `ensure_user_tenant_id_column` 补）+ 后加却带 tenant_id
/// 的 5 张（oauth_client / flow_task / flow_log / scim_group / flow_demo_doc）。
/// **两处清单须同步维护**（R4 门禁解析的是 ensure_multitenant_module 内的字面量，
/// 故此处必须独立成表；实际改写前逐个探测列存在性，缺列则跳过）。
pub(crate) const TENANT_CARRYING_TABLES: &[&str] = &[
    "sys_dept",
    "sys_user",
    "sys_role",
    "sys_post",
    "sys_config",
    "sys_dict_type",
    "sys_dict_data",
    "sys_notice",
    "sys_notice_read",
    "sys_pat",
    "sys_user_pref",
    "sys_oauth_consent",
    "sys_oauth_provider",
    "sys_oauth_user",
    "sys_msg_channel",
    "sys_msg_template",
    "sys_msg_send_log",
    "sys_web_hook",
    "sys_web_hook_log",
    "sys_report",
    "sys_report_sub",
    "sys_job",
    "sys_job_log",
    "sys_task",
    "sys_backup_log",
    "sys_oper_log",
    "sys_logininfor",
    "sys_frontend_error",
    "sys_oauth_client",
    "sys_flow_task",
    "sys_flow_log",
    "sys_scim_group",
    "flow_demo_doc",
];

/// 多租户 Phase 3 存量库兜底（与迁移 m20260925_000003_tenant_phase3 等价，全幂等）：
///
/// 1) 幂等建 5 张租户表族（sys_tenant / sys_tenant_package / sys_tenant_domain /
///    sys_tenant_menu / sys_tenant_migration_map）+ 索引（三方言）；
/// 2) 默认套餐「标准版」种子（`menu_ids = NULL` = 不限制功能白名单）；
/// 3) **tid remap（唯一不可逆点，§29.7）**：旧模型"dept 树根 = 租户"（租户 tid 复用
///    根部门 dept_id）一次性换源为 `sys_tenant.tenant_id` 独立 id 空间：
///    - 扫 `sys_dept` 中 `parent_id = 0`、未删除、且非平台根（100）的根部门；
///    - 每根部门建一行 `sys_tenant`（`tenant_code = t{root_dept_id}` 确定性唯一、
///      `dept_id` = 该根部门）并**同事务**写 `sys_tenant_migration_map`
///      （`old_tid → new_tenant_id`，回滚唯一依赖，禁止清理）；
///    - 按映射把承载表的 `tenant_id` 由旧 tid 改写为新 tenant_id；
///    - 用 BFS 求租户子树，顺带修复子树内 `tenant_id = 0` 的后代部门与用户
///      （Phase 2 兜底把存量行统一归 0 导致的串号 bug）。
///
/// 一次性语义（幂等关键）：仅当 `sys_tenant` 与映射表**均为空**时执行 remap——
/// 首次启动换源后再次启动即跳过；此后新建租户由服务层落表（其根部门不会再被换源）。
pub(crate) async fn ensure_tenant_phase3(db: &DatabaseConnection) -> anyhow::Result<()> {
    let backend = db.get_database_backend();
    let (id_pk, dt) = match backend {
        DatabaseBackend::Sqlite => ("INTEGER PRIMARY KEY AUTOINCREMENT", "DATETIME"),
        DatabaseBackend::Postgres => ("BIGSERIAL PRIMARY KEY", "TIMESTAMP"),
        _ => ("BIGINT PRIMARY KEY AUTO_INCREMENT", "DATETIME"),
    };
    let ph = |i: usize| -> String {
        if backend == DatabaseBackend::Postgres {
            format!("${i}")
        } else {
            "?".to_string()
        }
    };
    let now_expr = match backend {
        DatabaseBackend::Sqlite => {
            format!("'{}'", chrono::Local::now().format("%Y-%m-%d %H:%M:%S"))
        }
        _ => "NOW()".to_string(),
    };

    // ---- 1. 幂等建表（与迁移 m20260925_000003 DDL 逐列一致）----
    db.execute_raw(Statement::from_string(
        backend,
        format!(
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
            expire_time   {dt} NULL,
            account_count INT NOT NULL DEFAULT 0,
            status        VARCHAR(1) NOT NULL DEFAULT '0',
            del_flag      VARCHAR(1) NOT NULL DEFAULT '0',
            create_by     VARCHAR(64) NULL,
            create_time   {dt} NULL,
            update_by     VARCHAR(64) NULL,
            update_time   {dt} NULL,
            remark        VARCHAR(500) NULL
        )"#
        ),
    ))
    .await?;
    db.execute_raw(Statement::from_string(
        backend,
        format!(
            r#"CREATE TABLE IF NOT EXISTS sys_tenant_package (
            package_id            {id_pk},
            package_name          VARCHAR(64) NOT NULL,
            menu_ids              TEXT NULL,
            default_account_count INT NOT NULL DEFAULT 0,
            status                VARCHAR(1) NOT NULL DEFAULT '0',
            del_flag              VARCHAR(1) NOT NULL DEFAULT '0',
            create_by             VARCHAR(64) NULL,
            create_time           {dt} NULL,
            update_by             VARCHAR(64) NULL,
            update_time           {dt} NULL,
            remark                VARCHAR(500) NULL
        )"#
        ),
    ))
    .await?;
    db.execute_raw(Statement::from_string(
        backend,
        format!(
            r#"CREATE TABLE IF NOT EXISTS sys_tenant_domain (
            domain_id     {id_pk},
            tenant_id     BIGINT NOT NULL DEFAULT 0,
            domain        VARCHAR(255) NOT NULL,
            domain_type   VARCHAR(16) NOT NULL DEFAULT '1',
            is_primary    VARCHAR(1) NOT NULL DEFAULT '1',
            verify_status VARCHAR(1) NOT NULL DEFAULT '0',
            verify_token  VARCHAR(64) NULL,
            verified_at   {dt} NULL,
            status        VARCHAR(1) NOT NULL DEFAULT '0',
            del_flag      VARCHAR(1) NOT NULL DEFAULT '0',
            create_by     VARCHAR(64) NULL,
            create_time   {dt} NULL,
            update_by     VARCHAR(64) NULL,
            update_time   {dt} NULL,
            remark        VARCHAR(500) NULL
        )"#
        ),
    ))
    .await?;
    db.execute_raw(Statement::from_string(
        backend,
        format!(
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
            create_time {dt} NULL,
            update_by   VARCHAR(64) NULL,
            update_time {dt} NULL
        )"#
        ),
    ))
    .await?;
    db.execute_raw(Statement::from_string(
        backend,
        format!(
            r#"CREATE TABLE IF NOT EXISTS sys_tenant_migration_map (
            map_id        {id_pk},
            old_tid       BIGINT NOT NULL,
            new_tenant_id BIGINT NOT NULL,
            create_time   {dt} NULL,
            remark        VARCHAR(500) NULL
        )"#
        ),
    ))
    .await?;

    // 索引：失败只告警不阻断启动（与 Phase 2 兜底同策略；缺失仅影响性能与
    // 唯一约束强度，可在服务起来后由 migration 补齐）
    for (table, index, cols, unique) in [
        ("sys_tenant", "uk_sys_tenant_code", "tenant_code", true),
        ("sys_tenant", "idx_sys_tenant_dept", "dept_id", false),
        (
            "sys_tenant_package",
            "uk_sys_tenant_package_name",
            "package_name",
            true,
        ),
        (
            "sys_tenant_domain",
            "uk_sys_tenant_domain_domain",
            "domain",
            true,
        ),
        (
            "sys_tenant_domain",
            "idx_sys_tenant_domain_tid",
            "tenant_id",
            false,
        ),
        (
            "sys_tenant_menu",
            "uk_sys_tenant_menu",
            "tenant_id, ref_menu_id",
            true,
        ),
        (
            "sys_tenant_menu",
            "idx_sys_tenant_menu_tid",
            "tenant_id",
            false,
        ),
        (
            "sys_tenant_migration_map",
            "uk_sys_tenant_migration_map_old",
            "old_tid",
            true,
        ),
    ] {
        if let Err(e) = ensure_tenant_index(db, table, index, cols, unique).await {
            tracing::warn!("Phase 3 索引 {index} 创建失败（不阻断启动，请人工核查）: {e}");
        }
    }

    // ---- 1b. 存量库幂等补列：sys_tenant_domain 域名链路列（domain_type / verified_at）----
    // 域名链路（§27.7）：`domain_type` 决定验证策略（'0' 子域名平台分配免验证 / '1' 自定义需 DNS TXT），
    // `verified_at` 记录 TXT 验证通过时间。`CREATE TABLE IF NOT EXISTS` 对存量表不生效，故此处补列。
    if sso_table_exists(db, "sys_tenant_domain").await? {
        for (column, column_def) in [
            (
                "domain_type",
                "VARCHAR(16) NOT NULL DEFAULT '1'".to_string(),
            ),
            ("verified_at", format!("{dt} NULL")),
        ] {
            if sso_has_column(db, "sys_tenant_domain", column).await? {
                continue;
            }
            db.execute_raw(Statement::from_string(
                backend,
                format!("ALTER TABLE sys_tenant_domain ADD COLUMN {column} {column_def}"),
            ))
            .await?;
            tracing::info!("域名链路列 sys_tenant_domain.{column} 已补建（存量库兜底）");
        }
    }

    // ---- 2. 默认套餐种子（menu_ids = NULL = 不限制）----
    if tenant_scalar_count(db, "sys_tenant_package").await? == 0 {
        db.execute_raw(Statement::from_string(
            backend,
            format!(
                "INSERT INTO sys_tenant_package (package_name, menu_ids, default_account_count, status, del_flag, create_by, create_time, remark) \
                 VALUES ('标准版', NULL, 0, '0', '0', 'system', {now_expr}, 'Phase3 默认套餐：menu_ids 为空即不限制功能白名单')"
            ),
        ))
        .await?;
        tracing::info!("已种入默认租户套餐「标准版」（不限制功能白名单）");
    }

    // ---- 3. tid remap（唯一不可逆点）----
    let tenants = tenant_scalar_count(db, "sys_tenant").await?;
    let mapped = tenant_scalar_count(db, "sys_tenant_migration_map").await?;
    if tenants > 0 || mapped > 0 {
        tracing::debug!(
            "Phase 3 换源已完成（sys_tenant={tenants} 行 / 映射={mapped} 行），跳过一次性 remap"
        );
        return Ok(());
    }
    if !sso_table_exists(db, "sys_dept").await? {
        return Ok(());
    }
    let roots = db
        .query_all_raw(Statement::from_string(
            backend,
            "SELECT dept_id, dept_name, status FROM sys_dept \
             WHERE parent_id = 0 AND del_flag = '0' AND dept_id <> 100 ORDER BY dept_id",
        ))
        .await?;
    if roots.is_empty() {
        tracing::info!(
            "Phase 3 换源：无旧模型租户根部门（parent_id=0 且 dept_id<>100），无需 remap"
        );
        return Ok(());
    }

    // 部门父子关系（BFS 求子树；不依赖 ancestors 字段，兼容 NULL/脏数据）
    let dept_rows = db
        .query_all_raw(Statement::from_string(
            backend,
            "SELECT dept_id, parent_id FROM sys_dept",
        ))
        .await?;
    let mut children: HashMap<i64, Vec<i64>> = HashMap::new();
    for row in &dept_rows {
        let Ok(id) = row.try_get::<i64>("", "dept_id") else {
            continue;
        };
        if let Ok(Some(pid)) = row.try_get::<Option<i64>>("", "parent_id") {
            children.entry(pid).or_default().push(id);
        }
    }
    // 改写范围：逐个探测列存在性（极旧库后加表可能还没有 tenant_id 列）
    let mut remap_tables: Vec<&str> = Vec::new();
    for t in TENANT_CARRYING_TABLES {
        if sso_table_exists(db, t).await? && sso_has_column(db, t, "tenant_id").await? {
            remap_tables.push(t);
        }
    }
    let default_pkg: Option<i64> = db
        .query_one_raw(Statement::from_string(
            backend,
            "SELECT package_id FROM sys_tenant_package WHERE package_name = '标准版' AND del_flag = '0' \
             ORDER BY package_id LIMIT 1"
                .to_string(),
        ))
        .await?
        .and_then(|r| r.try_get::<i64>("", "package_id").ok());

    let txn = db.begin().await?;
    let mut migrated = 0usize;
    for root in &roots {
        let Ok(root_dept_id) = root.try_get::<i64>("", "dept_id") else {
            continue;
        };
        let dept_name = root
            .try_get::<Option<String>>("", "dept_name")
            .ok()
            .flatten()
            .filter(|s| !s.trim().is_empty())
            .unwrap_or_else(|| format!("租户{root_dept_id}"));
        let status = root
            .try_get::<Option<String>>("", "status")
            .ok()
            .flatten()
            .unwrap_or_else(|| "0".to_string());
        let code = format!("t{root_dept_id}");
        let pkg_id: Value = match default_pkg {
            Some(v) => v.into(),
            None => Value::BigInt(None),
        };
        txn.execute_raw(Statement::from_sql_and_values(
            backend,
            format!(
                "INSERT INTO sys_tenant (tenant_code, tenant_name, dept_id, package_id, account_count, status, del_flag, create_by, create_time, remark) \
                 VALUES ({}, {}, {}, {}, 0, {}, '0', 'system', {now_expr}, {})",
                ph(1),
                ph(2),
                ph(3),
                ph(4),
                ph(5),
                ph(6)
            ),
            [
                code.clone().into(),
                dept_name.clone().into(),
                root_dept_id.into(),
                pkg_id,
                status.into(),
                "Phase3 存量换源：旧模型租户根部门（dept 树根）→ 独立 tenant_id 空间".into(),
            ],
        ))
        .await?;
        let new_tid = txn
            .query_one_raw(Statement::from_sql_and_values(
                backend,
                format!(
                    "SELECT tenant_id FROM sys_tenant WHERE tenant_code = {}",
                    ph(1)
                ),
                [code.clone().into()],
            ))
            .await?
            .and_then(|r| r.try_get::<i64>("", "tenant_id").ok())
            .filter(|v| *v > 0)
            .ok_or_else(|| {
                anyhow::anyhow!("Phase 3 换源失败：tenant_code={code} 插入后回读 tenant_id 为空")
            })?;
        // 映射表与业务改写同事务写入（回滚唯一依赖，禁止清理）
        txn.execute_raw(Statement::from_sql_and_values(
            backend,
            format!(
                "INSERT INTO sys_tenant_migration_map (old_tid, new_tenant_id, create_time, remark) \
                 VALUES ({}, {}, {now_expr}, {})",
                ph(1),
                ph(2),
                ph(3)
            ),
            [
                root_dept_id.into(),
                new_tid.into(),
                "Phase3 remap：旧 tid（租户根 dept_id）→ 新 tenant_id（回滚=反向 UPDATE）".into(),
            ],
        ))
        .await?;

        // 子树 BFS（含软删部门）：顺带修复子树内 tenant_id = 0 的后代部门
        let mut subtree = vec![root_dept_id];
        let mut cursor = 0usize;
        while cursor < subtree.len() {
            let cur = subtree[cursor];
            cursor += 1;
            if let Some(kids) = children.get(&cur) {
                for k in kids {
                    if !subtree.contains(k) {
                        subtree.push(*k);
                    }
                }
            }
        }
        for chunk in subtree.chunks(200) {
            let list = chunk
                .iter()
                .map(|v| v.to_string())
                .collect::<Vec<_>>()
                .join(", ");
            txn.execute_raw(Statement::from_string(
                backend,
                format!("UPDATE sys_dept SET tenant_id = {new_tid} WHERE dept_id IN ({list})"),
            ))
            .await?;
            // 子树内用户：tenant_id 仍为旧 tid，或 0（Phase 2 统一归平台）→ 新 tenant_id
            txn.execute_raw(Statement::from_string(
                backend,
                format!(
                    "UPDATE sys_user SET tenant_id = {new_tid} \
                     WHERE tenant_id = {root_dept_id} OR (tenant_id = 0 AND dept_id IN ({list}))"
                ),
            ))
            .await?;
        }
        // 其余承载表（含 sys_dept / sys_user 的子树外遗留行）：旧 tid → 新 tenant_id
        for table in &remap_tables {
            txn.execute_raw(Statement::from_string(
                backend,
                format!(
                    "UPDATE {table} SET tenant_id = {new_tid} WHERE tenant_id = {root_dept_id}"
                ),
            ))
            .await?;
        }
        migrated += 1;
        tracing::info!(
            "Phase 3 换源：租户根部门 {root_dept_id}（{dept_name}）→ tenant_id={new_tid}（映射已持久化，回滚依赖）"
        );
    }
    txn.commit().await?;
    tracing::info!(
        "多租户 Phase 3 换源完成：共迁移 {migrated} 个存量租户；sys_tenant_migration_map 为回滚唯一依赖，禁止清理"
    );
    Ok(())
}

/// 多租户 Phase 3.5f 存量库兜底（与迁移 m20260925_000004_tenant_saas_governance
/// 等价，全幂等；列定义须与迁移逐列一致）：
///
/// 1) `sys_config` 增治理列 `scope` / `tenant_editable` / `visible_to_tenant`；
/// 2) `sys_oper_log` 增 `target_tenant_id`（审计目标租户列，只建列不写数据）；
/// 3) **唯一域租户化 4 项**：先幂等删旧单列唯一索引，再建 `(tenant_id, <列>)`
///    复合唯一索引；**建索引失败只告警不阻断启动**（存量数据可能存在同租户重复 key）；
/// 4) config 治理元数据 seed（幂等 UPDATE，只改治理列，不动 config_value）。
///
/// 缺此兜底时：sys_config 实体 SELECT 带治理列 → 参数配置全站 500；
/// 旧单列唯一索引仍生效 → 租户无法自建同 key 覆盖行。
pub(crate) async fn ensure_tenant_saas_governance(db: &DatabaseConnection) -> anyhow::Result<()> {
    let backend = db.get_database_backend();

    // ---- 1. 幂等补列（列名/类型/默认值须与迁移 m20260925_000004 逐列一致）----
    for (table, column, column_def) in [
        (
            "sys_config",
            "scope",
            "VARCHAR(32) NOT NULL DEFAULT 'platform_only'",
        ),
        (
            "sys_config",
            "tenant_editable",
            "VARCHAR(1) NOT NULL DEFAULT '0'",
        ),
        (
            "sys_config",
            "visible_to_tenant",
            "VARCHAR(1) NOT NULL DEFAULT '0'",
        ),
        ("sys_oper_log", "target_tenant_id", "BIGINT NULL"),
    ] {
        if !sso_table_exists(db, table).await? || sso_has_column(db, table, column).await? {
            continue;
        }
        db.execute_raw(Statement::from_string(
            backend,
            format!("ALTER TABLE {table} ADD COLUMN {column} {column_def}"),
        ))
        .await?;
        tracing::info!("多租户 SaaS 治理列 {table}.{column} 已补建（存量库兜底）");
    }

    // ---- 2. 唯一域租户化 4 项（先删旧单列唯一，再建复合唯一）----
    for (table, old_index, new_index, columns) in [
        (
            "sys_role",
            "uk_sys_role_key",
            "uk_sys_role_tenant_key",
            "tenant_id, role_key",
        ),
        (
            "sys_user",
            "idx_sys_user_scim_external_id",
            "uk_sys_user_tenant_scim",
            "tenant_id, scim_external_id",
        ),
        (
            "sys_config",
            "uk_sys_config_key",
            "uk_sys_config_tenant_key",
            "tenant_id, config_key",
        ),
        (
            "sys_dict_type",
            "uk_sys_dict_type",
            "uk_sys_dict_type_tenant",
            "tenant_id, dict_type",
        ),
    ] {
        if !sso_table_exists(db, table).await? {
            continue;
        }
        drop_tenant_index(db, table, old_index).await?;
        if let Err(e) = ensure_tenant_index(db, table, new_index, columns, true).await {
            tracing::warn!(
                "Phase 3.5f 唯一索引 {new_index} 创建失败（存量数据可能存在同租户重复 key，不阻断启动，请人工核查）: {e}"
            );
        }
    }

    // ---- 3. config 治理元数据 seed（幂等 UPDATE，只改治理列）----
    if sso_table_exists(db, "sys_config").await? {
        // 按覆盖策略分组做幂等 UPDATE：每组的 (scope, tenant_editable, visible_to_tenant)
        // 三元组由共享注册表的 `Coverage` 单一事实源给出 ⇒ **新增治理域无需改本函数**
        // （此前是两个硬编码 SQL 分支，新增一档就要再来一个分支）。
        // 只改治理列，**绝不动 `config_value`**：平台运维已调过的值不被启动流程覆盖。
        for coverage in [
            governance::Coverage::Locked,
            governance::Coverage::Free,
            governance::Coverage::Ceiling,
            governance::Coverage::Private,
        ] {
            let keys: Vec<String> = governance::keys_with_coverage(coverage)
                .map(|k| format!("'{k}'"))
                .collect();
            if keys.is_empty() {
                continue;
            }
            db.execute_raw(Statement::from_string(
                backend,
                format!(
                    "UPDATE sys_config SET scope = '{}', tenant_editable = '{}', \
                     visible_to_tenant = '{}' WHERE config_key IN ({})",
                    coverage.scope(),
                    coverage.tenant_editable(),
                    coverage.visible_to_tenant(),
                    keys.join(", ")
                ),
            ))
            .await?;
        }
    }

    tracing::info!("多租户 Phase 3 SaaS 治理模块已就绪（幂等确保完成）");
    Ok(())
}

/// 治理参数项**缺行补齐**（批次十四，注册表驱动）：按 `governance::CONFIG_DEFAULTS`
/// 三元组 INSERT OR IGNORE 全部 `CONFIGS` 键，治理列（scope/tenant_editable/
/// visible_to_tenant）由 `Coverage` 单一事实源生成。
///
/// 为何必须有本兜底：`ensure_tenant_saas_governance` 的 seed 段**只 UPDATE 既有行、
/// 不 INSERT 新行**，而 G-11 的 8 个 `sys.upload.*` 键从未在任何迁移 seed ⇒ 存量库
/// 无行，且 `UploadConfigService` 写入是**纯 UPDATE** ⇒ 0 行更新不报错 = OSS 管理
/// 页保存静默失效（接口 200 实际未落库，重启回落 config.toml——集成测试用迁移齐全
/// 的隔离库故从未暴露）。
///
/// 幂等：行在零影响（INSERT OR IGNORE）；**只补缺行，绝不动既有 config_value**——
/// 平台运维已调过的值不被覆盖；治理列交给上方 3.5f 的收敛 UPDATE（本函数补的行
/// 在同一次启动内即被收敛到注册表声明的姿态）。
pub(crate) async fn ensure_governance_config_rows(db: &DatabaseConnection) -> anyhow::Result<()> {
    if !sso_table_exists(db, "sys_config").await? {
        return Ok(());
    }
    let now = flow_now(db);
    for (key, name, value) in governance::CONFIG_DEFAULTS {
        // Coverage → 治理列三元组（与 3.5f 收敛 UPDATE 同源，单一事实源）
        let coverage = governance::item(key)
            .map(|i| i.coverage)
            .unwrap_or(governance::Coverage::Locked);
        flow_insert(
            db,
            &format!(
                "sys_config (config_name, config_key, config_value, config_type, create_by, \
                 create_time, remark, scope, tenant_editable, visible_to_tenant) VALUES \
                 ('{}', '{}', '{}', 'Y', 'admin', {}, \
                 '治理注册表缺行补齐（批次十四）', '{}', '{}', '{}')",
                name,
                key,
                value,
                now,
                coverage.scope(),
                coverage.tenant_editable(),
                coverage.visible_to_tenant(),
            ),
        )
        .await?;
    }
    tracing::info!(
        "治理参数项缺行补齐完成（扫描 {} 项，INSERT OR IGNORE 幂等——批次十四）",
        governance::CONFIG_DEFAULTS.len()
    );
    Ok(())
}

/// 3.5g 多租户 Phase 3.5g 存量库兜底：与迁移 `m20260925_000005_tenant_unique_scope`
/// 等价（**双写关系，修改时必须两处同步**——启动不跑 `Migrator::up`）。
///
/// 剩余唯一域租户化 2 项（先删旧单列唯一，再建含 tenant_id 的复合唯一）：
/// - `sys_flow_task`：业务键唯一（biz_type/biz_id/...）改为租户内唯一；
/// - `sys_scim_group`：`external_id`（IdP 标识）改为租户内唯一。
///
/// 缺此兜底时：不同租户使用相同业务键 / externalId 会互相顶撞（第二个租户写入失败）。
pub(crate) async fn ensure_tenant_unique_scope(db: &DatabaseConnection) -> anyhow::Result<()> {
    for (table, old_index, new_index, columns) in [
        (
            "sys_flow_task",
            "uk_flow_task_biz",
            "uk_flow_task_tenant_biz",
            "tenant_id, biz_type, biz_id, round_no, node_seq, assignee_id",
        ),
        (
            "sys_scim_group",
            "uk_scim_group_external_id",
            "uk_scim_group_tenant_external",
            "tenant_id, external_id",
        ),
    ] {
        if !sso_table_exists(db, table).await? {
            continue;
        }
        drop_tenant_index(db, table, old_index).await?;
        if let Err(e) = ensure_tenant_index(db, table, new_index, columns, true).await {
            tracing::warn!(
                "Phase 3.5g 唯一索引 {new_index} 创建失败（存量数据可能存在同租户重复键，不阻断启动，请人工核查）: {e}"
            );
        }
    }
    tracing::info!("多租户 Phase 3.5g 唯一域租户化模块已就绪（幂等确保完成）");
    Ok(())
}

/// Phase 3.5h 租户角色菜单治理回填（存量库兜底，幂等）：**一剔一补**。
///
/// ① **剔除**平台专属菜单：除能力位已解锁者外，全部平台专属前缀
///    （`system:tenant:domain:*` / `tool:gen:*` / `monitor:cache:*` …）整体为平台专属
///    （服务层对租户一律 403），存量租户管理员角色因继承平台普通角色而持有
///    `domain:list` / `domain:verify` → "菜单可见但请求一律 403"的假入口，
///    此处从非平台租户角色中移除该前缀菜单授权（幂等，重复执行为 0 行）。
///
///    **能力位感知（2026-09-26 批次 1c，批次 2 升级为 perms 粒度）**：剔除条件 =
///    命中 `PLATFORM_ONLY_PERM_PREFIXES` **且** 不在
///    `common::features::unlocked_capability_perms` 内。否则平台开启
///    `tenant.domain_self_service` 并授出域名菜单后，**每次重启都会把授权收回**，
///    能力位形同虚设。默认（全关）下解锁清单为空 ⇒ 剔除清单 = 全量 ⇒ 与改造前逐条等价。
///
///    必须 **perms 粒度**而非前缀粒度：`system:backup:` 是部分解锁前缀
///    （只读 3 条 + 导出 1 条可下放，创建/恢复/删除仍平台专属），按前缀粒度会把这些
///    危险菜单一并"免剔 + 回填"给 role 2，重造假入口（见 `unlocked_capability_perms` 文档）。
///
///    ①' **回填**（与①严格对称）：把**解锁清单内**的 perms 对应菜单重新授予
///    **平台普通角色（role_id=2）**——role 2 是"新建租户默认管理员角色"的
///    菜单模板（见 `sys_tenant_service::tenant_role_menu_ids`），缺它则能力位开启后
///    新建租户仍拿不到租户自助页面。**只回填 role 2**，不回填存量租户角色
///    （那等于静默给存量租户扩权；存量租户的授权由管理员按需授予）。
///
/// ② **补齐**租户自助能力按钮：租户默认管理员角色的菜单 = 平台普通角色菜单 ∩ 套餐白名单，
///    而平台普通角色只有 config/dict 的 list/query，缺 add/edit/remove 按钮 perms →
///    存量租户自建字典类型 / 覆盖 `platform_default` 键 / 自建 `tenant_private` 键的
///    写入链路一律 403（链路断裂）。新建租户已由 `SysTenantService::add` 并入
///    [`TENANT_SELF_SERVICE_PERMS`]，存量租户在此回填：
///    - **最小补齐**：仅补缺失授权，不回收①以外的任何已有授权；
///    - 候选角色 = 非平台租户（`tenant_id <> 0`）、未删除、且已持有 dict/config
///      **列表**菜单的"管理型角色"（只读角色不会因此获得写权限）；
///    - 受套餐白名单约束（`menu_ids` 为空 = 不限制；非空则仅补白名单内菜单）。
///
/// 无迁移孪生：纯数据治理修复（依赖 sys_menu 实时 perms 集合与租户角色现状），非 schema 变更。
pub(crate) async fn ensure_tenant_role_menu_governance(
    db: &DatabaseConnection,
) -> anyhow::Result<()> {
    let self_service_perms = crate::service::sys_tenant_service::TENANT_SELF_SERVICE_PERMS;
    // 台账 F-4/F-5（原则 B）：平台专属能力 perms 前缀统一清单。
    // 剔除 = 命中前缀 **且** 不在解锁清单内；回填 = 在解锁清单内（二者的唯一事实源，
    // 见 `common::features::unlocked_capability_perms` 的文档）。
    let platform_features = crate::common::features::platform_features();
    let unlocked_perms = crate::common::features::unlocked_capability_perms(platform_features);
    let platform_only_prefixes = crate::common::tenant::PLATFORM_ONLY_PERM_PREFIXES;
    const LIST_PERMS: [&str; 2] = ["system:config:list", "system:dict:list"];

    if !sso_table_exists(db, "sys_role_menu").await?
        || !sso_table_exists(db, "sys_role").await?
        || !sso_table_exists(db, "sys_menu").await?
    {
        return Ok(());
    }
    let backend = db.get_database_backend();
    let ph = |i: usize| -> String {
        if backend == DatabaseBackend::Postgres {
            format!("${i}")
        } else {
            "?".to_string()
        }
    };

    // ---- ① 剔除平台专属菜单（域名管理 / 代码生成 / 缓存监控 / 备份 / …）----
    // 目标角色：平台普通角色（role_id=2，只读白名单曾保底授予）+ 存量租户自建角色
    // （tenant_id <> 0，初始化时复制了平台普通角色菜单 ⇒ 残留假入口）。
    // 集中生成 LIKE 子句（**含 `perms LIKE` 列名**）：见 `common::tenant::perms_like_clause`
    // 的文档——原实现只拼裸占位符（`? OR ? …`），使本段 SQL 恒为假、DELETE 影响 0 行，
    // 导致**存量库的平台专属菜单治理从未生效**（2026-09-26 实测 role2 仍持 13 个，含 3800/3802）。
    //
    // 能力位感知（perms 粒度）：命中前缀 **且** 不在解锁清单内才剔除；
    // 解锁清单为空（默认全关）时 `NOT IN` 子句省略 ⇒ 与改造前逐条等价。
    {
        let like_clause = crate::common::tenant::perms_like_clause(platform_only_prefixes, ph);
        let mut like_values: Vec<Value> = platform_only_prefixes
            .iter()
            .map(|p| format!("{p}%").into())
            .collect();
        // 占位符编号**续接** LIKE 子句：Postgres 用 `$n`（需绝对序号），其余方言是 `?`
        // （`ph` 忽略入参，位置由 values 顺序决定）。
        let like_len = like_values.len();
        let not_in_clause =
            crate::common::features::perms_not_in_clause(&unlocked_perms, |i| ph(like_len + i))
                .map(|c| format!(" AND {c}"))
                .unwrap_or_default();
        like_values.extend(unlocked_perms.iter().map(|p| (*p).into()));
        let removed = db
            .execute_raw(Statement::from_sql_and_values(
                backend,
                format!(
                    "DELETE FROM sys_role_menu WHERE menu_id IN (\
                       SELECT menu_id FROM sys_menu WHERE ({like_clause}){not_in_clause}) \
                     AND (role_id = 2 OR role_id IN (\
                       SELECT role_id FROM sys_role WHERE tenant_id <> 0 AND del_flag = '0'))"
                ),
                like_values,
            ))
            .await?;
        if removed.rows_affected() > 0 {
            tracing::info!(
                removed = removed.rows_affected(),
                prefixes = platform_only_prefixes.len(),
                unlocked_perms = unlocked_perms.len(),
                "Phase 3.5h 已剔除平台专属菜单授权（剔除条件已按能力位 perms 粒度收窄）"
            );
        }
    }

    // ---- ①' 回填：解锁清单内的 perms → 重新授予平台普通角色（role_id=2）----
    // 与①严格对称：①剔的是"平台专属且未被能力位解锁"的面，①'补的是"已被能力位解锁"的面。
    // 只补 role 2（新建租户默认管理员角色的菜单模板），不回填存量租户角色。
    // 幂等：SQLite/MySQL 用 `INSERT OR IGNORE` / `INSERT IGNORE`，Postgres 用
    // `ON CONFLICT DO NOTHING`，配合 `sys_role_menu` 的 (role_id, menu_id) 主键，
    // 重复执行 0 行。
    if !unlocked_perms.is_empty() {
        let ph_list = (1..=unlocked_perms.len())
            .map(ph)
            .collect::<Vec<_>>()
            .join(", ");
        let insert_prefix = match backend {
            DatabaseBackend::Sqlite => "INSERT OR IGNORE INTO ",
            DatabaseBackend::Postgres => "INSERT INTO ",
            DatabaseBackend::MySql => "INSERT IGNORE INTO ",
            _ => unreachable!("unknown backend"),
        };
        let conflict_suffix = if backend == DatabaseBackend::Postgres {
            " ON CONFLICT DO NOTHING"
        } else {
            ""
        };
        let granted = db
            .execute_raw(Statement::from_sql_and_values(
                backend,
                format!(
                    "{insert_prefix}sys_role_menu (role_id, menu_id) \
                     SELECT 2, menu_id FROM sys_menu \
                     WHERE del_flag = '0' AND perms IN ({ph_list})\
                     {conflict_suffix}"
                ),
                unlocked_perms
                    .iter()
                    .map(|p| (*p).into())
                    .collect::<Vec<Value>>(),
            ))
            .await?;
        tracing::info!(
            granted = granted.rows_affected(),
            perms = %unlocked_perms.join(","),
            "Phase 3.5h 已按能力位回填平台普通角色的已解锁菜单授权（perms 粒度）"
        );
    }

    // 1) 目标 perms → menu_id（仅启用、未删除；缺菜单的 perms 跳过，不阻断启动）
    let wanted: Vec<&str> = self_service_perms
        .iter()
        .chain(LIST_PERMS.iter())
        .copied()
        .collect();
    let placeholders = (1..=wanted.len()).map(ph).collect::<Vec<_>>().join(", ");
    let menu_rows = db
        .query_all_raw(Statement::from_sql_and_values(
            backend,
            format!(
                "SELECT menu_id, perms FROM sys_menu WHERE status = '0' AND del_flag = '0' AND perms IN ({placeholders})"
            ),
            wanted.iter().map(|p| (*p).into()).collect::<Vec<Value>>(),
        ))
        .await?;
    let mut perm_menu: std::collections::HashMap<String, i64> = std::collections::HashMap::new();
    for row in &menu_rows {
        let menu_id = row.try_get::<i64>("", "menu_id").ok();
        let perms = row.try_get::<Option<String>>("", "perms").ok().flatten();
        if let (Some(menu_id), Some(perms)) = (menu_id, perms) {
            perm_menu.entry(perms).or_insert(menu_id);
        }
    }
    let mut targets: Vec<i64> = self_service_perms
        .iter()
        .filter_map(|p| perm_menu.get(*p).copied())
        .collect();
    targets.sort_unstable();
    targets.dedup();
    if targets.is_empty() {
        tracing::info!("Phase 3.5h 自助能力菜单不存在，跳过权限回填");
        return Ok(());
    }
    let list_menu_ids: Vec<i64> = LIST_PERMS
        .iter()
        .filter_map(|p| perm_menu.get(*p).copied())
        .collect();
    if list_menu_ids.is_empty() {
        tracing::info!("Phase 3.5h 未找到 dict/config 列表菜单，跳过权限回填");
        return Ok(());
    }

    // 2) 候选角色：非平台、未删除、已持有列表菜单
    let list_ph = (1..=list_menu_ids.len())
        .map(ph)
        .collect::<Vec<_>>()
        .join(", ");
    let role_rows = db
        .query_all_raw(Statement::from_sql_and_values(
            backend,
            format!(
                "SELECT DISTINCT rm.role_id AS role_id, r.tenant_id AS tenant_id \
                 FROM sys_role_menu rm \
                 JOIN sys_role r ON r.role_id = rm.role_id \
                 WHERE r.tenant_id <> 0 AND r.del_flag = '0' AND rm.menu_id IN ({list_ph})"
            ),
            list_menu_ids
                .iter()
                .map(|id| (*id).into())
                .collect::<Vec<Value>>(),
        ))
        .await?;
    if role_rows.is_empty() {
        // 无候选角色（无租户角色 / 无持有 config·dict 列表菜单的管理型角色）：
        // 属正常幂等路径（新租户建租时已并入自助 perms，无需回填），
        // 但仍打日志，避免"回填是否执行过"不可观测。
        tracing::info!("Phase 3.5h 无待回填的租户管理型角色（候选为空，跳过自助权限补齐）");
        return Ok(());
    }

    // 3) 套餐白名单（None = 不限制）
    let pkg_rows = db
        .query_all_raw(Statement::from_string(
            backend,
            "SELECT t.tenant_id AS tenant_id, p.menu_ids AS menu_ids \
             FROM sys_tenant t LEFT JOIN sys_tenant_package p ON p.package_id = t.package_id"
                .to_string(),
        ))
        .await?;
    let mut whitelist: std::collections::HashMap<i64, Option<std::collections::HashSet<i64>>> =
        std::collections::HashMap::new();
    for row in &pkg_rows {
        let Some(tid) = row.try_get::<i64>("", "tenant_id").ok() else {
            continue;
        };
        let raw = row.try_get::<Option<String>>("", "menu_ids").ok().flatten();
        // 复用服务层解析口径（空/NULL = 不限制），避免两处语义漂移
        let parsed = crate::service::sys_tenant_service::parse_menu_ids(&raw)
            .map(|ids| ids.into_iter().collect::<std::collections::HashSet<i64>>());
        whitelist.insert(tid, parsed);
    }

    // 4) 现有授权 → 差集插入
    let mut candidates: Vec<(i64, i64)> = Vec::new();
    for row in &role_rows {
        let role_id = row.try_get::<i64>("", "role_id").ok();
        let tenant_id = row.try_get::<i64>("", "tenant_id").ok();
        if let (Some(role_id), Some(tenant_id)) = (role_id, tenant_id) {
            candidates.push((role_id, tenant_id));
        }
    }
    let role_ph = (1..=candidates.len())
        .map(ph)
        .collect::<Vec<_>>()
        .join(", ");
    let granted_rows = db
        .query_all_raw(Statement::from_sql_and_values(
            backend,
            format!("SELECT role_id, menu_id FROM sys_role_menu WHERE role_id IN ({role_ph})"),
            candidates
                .iter()
                .map(|(rid, _)| (*rid).into())
                .collect::<Vec<Value>>(),
        ))
        .await?;
    let mut granted: std::collections::HashMap<i64, std::collections::HashSet<i64>> =
        std::collections::HashMap::new();
    for row in &granted_rows {
        let role_id = row.try_get::<i64>("", "role_id").ok();
        let menu_id = row.try_get::<i64>("", "menu_id").ok();
        if let (Some(role_id), Some(menu_id)) = (role_id, menu_id) {
            granted.entry(role_id).or_default().insert(menu_id);
        }
    }

    let mut inserted = 0u64;
    for (role_id, tenant_id) in candidates {
        let allowed = match whitelist.get(&tenant_id) {
            Some(Some(set)) => targets
                .iter()
                .copied()
                .filter(|id| set.contains(id))
                .collect::<Vec<i64>>(),
            // 无套餐限制（或租户行缺失）：全量补齐
            _ => targets.clone(),
        };
        for menu_id in allowed {
            if granted.get(&role_id).is_some_and(|s| s.contains(&menu_id)) {
                continue;
            }
            db.execute_raw(Statement::from_sql_and_values(
                backend,
                format!(
                    "INSERT INTO sys_role_menu (role_id, menu_id) VALUES ({}, {})",
                    ph(1),
                    ph(2)
                ),
                [role_id.into(), menu_id.into()],
            ))
            .await?;
            inserted += 1;
        }
    }
    tracing::info!(
        inserted,
        roles = granted.len(),
        "多租户 Phase 3.5h 租户角色菜单治理完成（幂等：剔除平台专属菜单 + 补齐自助按钮授权）"
    );
    Ok(())
}

/// 存量上传路径回填（3.5i，幂等）：把租户文件隔离**之前**写入的扁平引用改为租户维度。
///
/// 隔离前：文件落在 `uploads/{kind}/{key}`，DB 存 `/uploads/{kind}/{key}`；
/// 隔离后：文件落在 `uploads/{tid}/{kind}/{key}`，URL 为 `/{prefix}/{tid}/{key}`，
/// 且 `GET /uploads/*` 严格按三段解析（`{tid}/{kind}/{key}`）——旧引用段数不足会被判
/// 路径非法 → **400**（表现为全站头像破图、附件预览失败）。
///
/// 处置（逐行、幂等）：
/// - 第二段已是数字（`/uploads/{tid}/...`）→ 跳过；
/// - 目标文件已就位 → 只改写 DB 引用；
/// - 遗留文件存在而目标缺失 → 迁移文件（同盘 rename，跨盘回退 copy+delete）后改写 DB；
/// - 两侧文件都不存在 → 打 `warn` 跳过该行（改写引用只会把 400 变成 404，无收益）。
///
/// 仅 `local` 后端执行：`s3` 后端不存在扁平历史布局（对象键自隔离上线即为租户维度）。
/// 扫描列：`sys_user.avatar`（全库扫描确认唯一存在活引用的列为该列）。
pub(crate) async fn ensure_legacy_upload_paths(
    db: &DatabaseConnection,
    upload_cfg: &crate::config::UploadConfig,
) -> anyhow::Result<()> {
    if upload_cfg.backend != "local" {
        return Ok(());
    }
    if !sso_table_exists(db, "sys_user").await? || !sso_has_column(db, "sys_user", "avatar").await?
    {
        return Ok(());
    }
    let backend = db.get_database_backend();
    let ph = |i: usize| -> String {
        if backend == DatabaseBackend::Postgres {
            format!("${i}")
        } else {
            "?".to_string()
        }
    };
    let rows = db
        .query_all_raw(Statement::from_string(
            backend,
            "SELECT user_id, tenant_id, avatar FROM sys_user WHERE avatar LIKE '/uploads/%'"
                .to_string(),
        ))
        .await?;

    let (mut migrated, mut moved, mut skipped) = (0u64, 0u64, 0u64);
    for row in &rows {
        let Some(user_id) = row.try_get::<i64>("", "user_id").ok() else {
            continue;
        };
        let tenant_id = row.try_get::<i64>("", "tenant_id").ok().unwrap_or(0);
        let Some(avatar) = row.try_get::<Option<String>>("", "avatar").ok().flatten() else {
            continue;
        };
        let segs: Vec<&str> = avatar.trim_matches('/').split('/').collect();
        // 仅处理扁平旧式引用；其余形态（已是租户维度 / 外部 URL / 段数异常）不动
        if segs.len() != 3 || segs[0] != "uploads" || segs[1].parse::<i64>().is_ok() {
            continue;
        }
        let (kind, key) = (segs[1], segs[2]);
        let Some(dir) = crate::common::upload::resolve_kind_dir(upload_cfg, kind) else {
            tracing::warn!(user_id, avatar = %avatar, "存量上传路径回填：未知文件类别，跳过");
            skipped += 1;
            continue;
        };
        let url_prefix = if kind == "avatar" {
            upload_cfg.avatar_url_prefix.as_str()
        } else {
            upload_cfg.common_url_prefix.as_str()
        };
        if !crate::storage::valid_key(key) {
            tracing::warn!(user_id, avatar = %avatar, "存量上传路径回填：文件名非法，跳过");
            skipped += 1;
            continue;
        }

        let legacy_path = crate::common::upload::resolve_upload_dir(&dir)
            .await
            .join(key);
        let target_dir = crate::storage::dir_path(&dir, tenant_id).await;
        let target_path = target_dir.join(key);
        let (lp, td, tp) = (
            legacy_path.to_string_lossy().to_string(),
            target_dir.to_string_lossy().to_string(),
            target_path.to_string_lossy().to_string(),
        );
        let outcome = tokio::task::spawn_blocking(move || -> std::io::Result<bool> {
            let (legacy, target) = (std::path::Path::new(&lp), std::path::Path::new(&tp));
            if target.exists() {
                return Ok(false); // 文件已就位，无需搬动
            }
            if !legacy.exists() {
                return Ok(false);
            }
            std::fs::create_dir_all(&td)?;
            if std::fs::rename(legacy, target).is_err() {
                std::fs::copy(legacy, target)?;
                std::fs::remove_file(legacy)?;
            }
            Ok(true)
        })
        .await
        .map_err(|e| anyhow::anyhow!("存量上传路径回填任务失败: {e}"))?;

        match outcome {
            Ok(did_move) => {
                if !did_move && !target_path.exists() {
                    tracing::warn!(
                        user_id,
                        avatar = %avatar,
                        "存量上传路径回填：遗留文件与目标文件均不存在，保留原引用待人工处置"
                    );
                    skipped += 1;
                    continue;
                }
                if did_move {
                    moved += 1;
                }
                let new_url = format!(
                    "{}/{}",
                    crate::storage::tenant_scoped_path(url_prefix, tenant_id).trim_end_matches('/'),
                    key
                );
                db.execute_raw(Statement::from_sql_and_values(
                    backend,
                    format!(
                        "UPDATE sys_user SET avatar = {} WHERE user_id = {}",
                        ph(1),
                        ph(2)
                    ),
                    [new_url.into(), user_id.into()],
                ))
                .await?;
                migrated += 1;
            }
            Err(e) => {
                tracing::warn!(user_id, avatar = %avatar, error = %e, "存量上传路径回填：文件迁移失败，跳过该行");
                skipped += 1;
            }
        }
    }

    tracing::info!(
        migrated,
        moved,
        skipped,
        scanned = rows.len(),
        "存量上传路径回填完成（幂等：扁平 uploads/kind/key → prefix/tid/key，缺 tid 段的历史引用已租户化）"
    );
    Ok(())
}

/// 方言感知的幂等删索引：SQLite/PostgreSQL 用 `DROP INDEX IF EXISTS`；
/// MySQL 无该从句，先查 information_schema.statistics 判存在再 `DROP INDEX ... ON table`。
pub(crate) async fn drop_tenant_index(
    db: &DatabaseConnection,
    table: &str,
    index_name: &str,
) -> anyhow::Result<()> {
    let backend = db.get_database_backend();
    match backend {
        DatabaseBackend::MySql => {
            let exists = db
                .query_all_raw(Statement::from_string(
                    backend,
                    format!(
                        "SELECT 1 FROM information_schema.statistics WHERE table_schema=DATABASE() AND table_name='{table}' AND index_name='{index_name}' LIMIT 1"
                    ),
                ))
                .await?;
            if !exists.is_empty() {
                db.execute_raw(Statement::from_string(
                    backend,
                    format!("DROP INDEX {index_name} ON {table}"),
                ))
                .await?;
            }
            Ok(())
        }
        _ => {
            db.execute_raw(Statement::from_string(
                backend,
                format!("DROP INDEX IF EXISTS {index_name}"),
            ))
            .await?;
            Ok(())
        }
    }
}

/// 标量计数（三方言；表不存在时返回 0，供幂等探测用）
pub(crate) async fn tenant_scalar_count(
    db: &DatabaseConnection,
    table: &str,
) -> anyhow::Result<i64> {
    if !sso_table_exists(db, table).await? {
        return Ok(0);
    }
    let backend = db.get_database_backend();
    let row = db
        .query_one_raw(Statement::from_string(
            backend,
            format!("SELECT COUNT(*) AS c FROM {table}"),
        ))
        .await?;
    Ok(row
        .and_then(|r| r.try_get::<i64>("", "c").ok())
        .unwrap_or(0))
}

/// 方言感知的幂等索引创建：SQLite/PostgreSQL 直接 `CREATE INDEX IF NOT EXISTS`；
/// MySQL 不支持该子句，先查 information_schema.statistics 判存在，缺失才建
/// （补齐此前"MySQL 跳过、依赖 migration 补齐"的方言缺口——存量库不跑 migration）。
/// `unique = true` 时建 `CREATE UNIQUE INDEX`。
pub(crate) async fn ensure_tenant_index(
    db: &DatabaseConnection,
    table: &str,
    index_name: &str,
    columns: &str,
    unique: bool,
) -> anyhow::Result<()> {
    let backend = db.get_database_backend();
    let kind = if unique { "UNIQUE " } else { "" };
    match backend {
        DatabaseBackend::MySql => {
            let exists = db
                .query_all_raw(Statement::from_string(
                    backend,
                    format!(
                        "SELECT 1 FROM information_schema.statistics WHERE table_schema=DATABASE() AND table_name='{table}' AND index_name='{index_name}' LIMIT 1"
                    ),
                ))
                .await?;
            if !exists.is_empty() {
                return Ok(());
            }
            db.execute_raw(Statement::from_string(
                backend,
                format!("CREATE {kind}INDEX {index_name} ON {table} ({columns})"),
            ))
            .await?;
            Ok(())
        }
        _ => {
            db.execute_raw(Statement::from_string(
                backend,
                format!("CREATE {kind}INDEX IF NOT EXISTS {index_name} ON {table} ({columns})"),
            ))
            .await?;
            Ok(())
        }
    }
}

/// v4 §13-F1：历史 JWT 型 SSO 访问令牌一次性转写吊销（幂等 + 精准识别）。
///
/// 背景：P0-A 修复前 SSO access_token 是平台 JWT（可横扫全站业务 API），仅靠
/// auth 中间件的「`sso:at:{hash}` 绑定命中 → 拒绝」过渡阻断止血。但绑定 TTL（1h 量级）
/// 短于历史 JWT 本体 TTL（最长 24h）——绑定过期后历史 JWT 失去唯一标识，剩余窗口内
/// 仍可通行业务路由，**止血动作自毁止血范围**。
///
/// 定案（转写而非清除）：把存量 `sso:at:*` 绑定转写为
/// `blacklist:{hash}`（TTL = max(剩余TTL, 24h)）并删除原绑定 → 历史 JWT 立即全量吊销。
///
/// **精准识别（v5 核查修正）**：绑定 value 含 `access_token_hash` 字段即 A 形态
/// （不透明 AT）活跃绑定，**跳过不转写**——仅转写无该字段的历史 JWT 型绑定。
/// 消除两类误杀：① P0-A 已部署实例（6a60528）升级到本版时，存量绑定是不透明 AT；
/// ② Redis 清空导致标记丢失后重跑。
///
/// 幂等：`sso:v4_legacy_at_migrated` SETNX 标记；已标记即跳过。
/// Redis 故障时跳过转写并告警（下次启动重试）。
/// §5.17 启动期能力位授权收敛（幂等；**任何失败都不阻断启动**）。
///
/// ## 背景（为何需要启动期兜底）
///
/// 授权回收（`converge_tenant_role_menus_conn`）此前只在**套餐变更**时触发；平台层
/// `[features]` on→off（改配置重启）后，租户的"曾经可授予"授权行残留——有效能力集
/// （平台天花板 ∩ 套餐）已把该能力钳为 off，但 `sys_role_menu` 行还在 ⇒
/// "菜单可见但请求 403"的假入口数据层残留。
///
/// ## 语义
///
/// - 遍历**全部绑定套餐**的未删除租户，逐个按其套餐跑收敛核心（幂等：无收敛面零删除）；
/// - 单租户失败 WARN continue（数据清理任务，非启动必需；下次启动自然重试）；
/// - 总删除 > 0 ⇒ best-effort 失效全部 `perm:user:*` 权限缓存（授权集合已变化）；
/// - **WARN 级汇总日志**：授权行被删属不可自动回滚操作（重开能力位后需重新授权），
///   运维必须能看到本次启动删了什么。
///
/// 测试策略：核心收敛语义（回收 + 幂等）由 `integration_tests::capability_features`
/// 直驱 `converge_tenant_role_menus_conn` 覆盖；本函数为**薄编排**（查询 + 循环 +
/// 缓存失效），且全表遍历在并行共享库测试下有跨用例污染风险，故不直测。
pub(crate) async fn converge_tenant_grants_on_startup(
    db: &DatabaseConnection,
    store: &Arc<dyn SharedStore>,
) {
    use crate::entity::{sys_tenant, sys_tenant_package};
    use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};
    use std::collections::HashMap;

    // 套餐小表全量载入内存（pkg_id → Model），避免逐租户回查
    let packages: Vec<sys_tenant_package::Model> = match sys_tenant_package::Entity::find()
        .filter(sys_tenant_package::Column::DelFlag.eq("0"))
        .all(db)
        .await
    {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!("启动期授权收敛：查询套餐表失败（跳过，下次启动重试）: {e}");
            return;
        }
    };
    if packages.is_empty() {
        return;
    }
    let pkg_map: HashMap<i64, sys_tenant_package::Model> =
        packages.into_iter().map(|p| (p.package_id, p)).collect();

    let tenants: Vec<sys_tenant::Model> = match sys_tenant::Entity::find()
        .filter(sys_tenant::Column::DelFlag.eq("0"))
        .filter(sys_tenant::Column::PackageId.is_not_null())
        .all(db)
        .await
    {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!("启动期授权收敛：查询租户表失败（跳过，下次启动重试）: {e}");
            return;
        }
    };
    if tenants.is_empty() {
        tracing::info!("启动期授权收敛：无绑定套餐的租户，跳过");
        return;
    }

    let mut total_removed: u64 = 0;
    let mut failed: usize = 0;
    for t in &tenants {
        let Some(pkg_id) = t.package_id else { continue };
        let Some(pkg) = pkg_map.get(&pkg_id) else {
            tracing::warn!(
                tenant_id = t.tenant_id,
                package_id = pkg_id,
                "启动期授权收敛：租户绑定的套餐不存在/已删除，跳过该租户"
            );
            continue;
        };
        match crate::service::sys_tenant_service::converge_tenant_role_menus_conn(
            db,
            t.tenant_id,
            pkg,
        )
        .await
        {
            Ok(removed) => total_removed += removed,
            Err(e) => {
                failed += 1;
                tracing::warn!(
                    tenant_id = t.tenant_id,
                    error = %e,
                    "启动期授权收敛失败（跳过该租户，不阻断启动）"
                );
            }
        }
    }

    if total_removed > 0 {
        // 授权集合已变化 ⇒ perm cache 必须失效（best-effort，对齐 menu_service 同名语义）
        let pattern = format!("{}*", crate::common::constants::PERM_CACHE_PREFIX);
        if let Ok(keys) = store.scan(&pattern, None).await
            && !keys.is_empty()
            && let Err(e) = store.del(&keys).await
        {
            tracing::warn!(count = keys.len(), error = %e, "启动期 perm cache 失效失败，授权变更可能不即时生效（残留至 TTL）")
        }
        tracing::warn!(
            tenants = tenants.len(),
            removed = total_removed,
            failed,
            "启动期授权收敛：回收了平台层能力位/套餐收敛面之外的角色菜单授权。\
             授权行删除不可自动回滚——重开能力位/扩白名单后需重新授权"
        );
    } else {
        tracing::info!(
            tenants = tenants.len(),
            failed,
            "启动期授权收敛：无残留不可授予授权（幂等零删除）"
        );
    }
}

use super::*;
