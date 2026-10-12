// stepby-axum/src/initialize/menu.rs

use sea_orm::{ConnectionTrait, DatabaseBackend, DatabaseConnection, Statement};

/// 幂等确保 AI 助手菜单就绪（NL2SQL v4.1，menu_id 4100 顶级 C 菜单，perms `ai:chat`）。
///
/// 不授予 role 2：AI 能力由管理员按需在角色管理里勾选 `ai:chat`（三层开关的角色层）；
/// 超管 `*:*:*` 天然可用。能力位 `ai.copilot` + `[ai].enabled` 双门控在 handler 校验。
pub(crate) async fn ensure_ai_menu(db: &DatabaseConnection) -> anyhow::Result<()> {
    let backend = db.get_database_backend();
    let insert_prefix = match backend {
        DatabaseBackend::Sqlite => "INSERT OR IGNORE INTO ",
        DatabaseBackend::Postgres => "INSERT INTO ",
        DatabaseBackend::MySql => "INSERT IGNORE INTO ",
        _ => "INSERT INTO ",
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
    db.execute_raw(
        Statement::from_string(
            backend,
            format!(
                "{insert_prefix}{menu_cols} VALUES (4100, 'AI助手', 0, 9, 'ai', 'ai/panel/index', '', '', '1', '0', 'C', '0', '0', 'ai:chat', 'chart', 'admin', {now_expr}, 'AI 数据查询助手（NL2SQL，受白名单与租户隔离约束）', '0', 'menu.ai'){insert_suffix}"
            ),
        ),
    )
    .await?;
    // 兜底修正：init.rs 基线 seed 先占位 menu_id=4100（无 i18n_key），INSERT OR IGNORE 跳过后
    // 增强列不会写入——UPDATE 幂等补齐（新库/存量库均安全，见 UX 真机核查的新旧库 diff 实证）
    db.execute_raw(Statement::from_string(
        backend,
        "UPDATE sys_menu SET i18n_key = 'menu.ai' WHERE menu_id = 4100 AND (i18n_key IS NULL OR i18n_key = '')".to_string(),
    ))
    .await?;
    Ok(())
}

/// 菜单信息架构优化兜底（与迁移 m20260928_000004_optimize_menu_structure 等价，全幂等）：
/// ① 新目录 3950「租户服务」并收编自助页 3900/3627（原游离顶层）；
/// ② 三个目录内 order 重排（消除 order=8/10/11 多处重复导致的显示顺序不稳定）；
/// ③ icon 语义修正（peoples/connection/documentation 等多处复用改贴切图标）。
/// 全部为幂等 UPDATE/INSERT，重复执行无副作用。
/// 菜单-only 迁移兜底（与迁移 m20260818_000001_add_log_monitor_menu /
/// m20260819_000002_http_debugger_menu / m20260819_000006_observability_menu 等价，全幂等）：
/// 补建 实时日志(135) / HTTP 调试器(3410) / 运行监控(3550) / 清空按钮(3551) 四行菜单。
///
/// 为何必须有本兜底：这四个菜单的迁移**只建菜单行**（页面后端零专属表依赖），
/// 此前无 ensure 孪生 ⇒ 极老存量库（m20260818 之前）四个功能页面假功能
/// （schema 等价性总锁实测发现）。3.5d-6 的菜单结构优化兜底只 UPDATE 既有行，
/// 故本兜底必须**先于** `ensure_menu_structure_optimize` 执行，让 order/icon 收敛到终态。
/// 幂等：menu_id 已存在则 INSERT OR IGNORE 跳过。
/// ⚠️ 不补 `sys_role_menu` 授权：这些 perms 前缀（monitor:log / tool:httpDebug /
/// monitor:slowSql）属平台专属（`PLATFORM_ONLY_PERM_PREFIXES`），m20260926_000005/000006
/// 已把 role_id=2 的授权回收，补授权会与迁移终态漂移。
pub(crate) async fn ensure_menu_only_migration_menus(
    db: &DatabaseConnection,
) -> anyhow::Result<()> {
    if !sso_table_exists(db, "sys_menu").await? {
        return Ok(());
    }
    let backend = db.get_database_backend();
    let insert_prefix = match backend {
        DatabaseBackend::Sqlite => "INSERT OR IGNORE INTO ",
        DatabaseBackend::Postgres => "INSERT INTO ",
        DatabaseBackend::MySql => "INSERT IGNORE INTO ",
        _ => "INSERT INTO ",
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
    let menu_cols = "sys_menu (menu_id, menu_name, parent_id, order_num, path, component, query, route_name, is_frame, is_cache, menu_type, visible, status, perms, icon, create_by, create_time, remark, del_flag)";
    for body in [
        format!(
            "{menu_cols} VALUES (135, '实时日志', 2, 9, 'logtail', 'monitor/logtail/index', '', '', '1', '0', 'C', '0', '0', 'monitor:log:list', 'log', 'admin', {now_expr}, '在线查看应用实时日志（自动刷新，支持级别/关键字过滤）', '0')"
        ),
        format!(
            "{menu_cols} VALUES (3410, 'HTTP 调试器', 3, 9, 'http-debugger', 'tool/http-debugger/index', '', '', '1', '0', 'C', '0', '0', 'tool:httpDebug:list', 'send', 'admin', {now_expr}, '在线 HTTP 转发调试（服务端代理 + SSRF 防护）', '0')"
        ),
        format!(
            "{menu_cols} VALUES (3550, '运行监控', 2, 10, 'observability', 'monitor/observability/index', '', '', '1', '0', 'C', '0', '0', 'monitor:slowSql:list', 'monitor', 'admin', {now_expr}, '可观测性：慢请求 / 错误聚合 / Redis 指标', '0')"
        ),
        format!(
            "{menu_cols} VALUES (3551, '清空', 3550, 1, '', '', '', '', '1', '0', 'F', '0', '0', 'monitor:slowSql:list', 'delete', 'admin', {now_expr}, '清空慢请求 / 错误日志缓冲', '0')"
        ),
    ] {
        db.execute_raw(Statement::from_string(
            backend,
            format!("{insert_prefix}{body}{insert_suffix}"),
        ))
        .await?;
    }
    Ok(())
}

pub(crate) async fn ensure_menu_structure_optimize(db: &DatabaseConnection) -> anyhow::Result<()> {
    let backend = db.get_database_backend();

    // ---- ① 3950 目录（幂等插入）----
    let exists: Option<i64> = match db
        .query_one_raw(Statement::from_string(
            backend,
            "SELECT menu_id FROM sys_menu WHERE menu_id = 3950".to_string(),
        ))
        .await
    {
        Ok(row) => row.and_then(|r| r.try_get_by_index::<i64>(0).ok()),
        Err(_) => None,
    };
    if exists.is_none() {
        let prefix = match backend {
            DatabaseBackend::Sqlite => "INSERT OR IGNORE INTO",
            DatabaseBackend::MySql => "INSERT IGNORE INTO",
            DatabaseBackend::Postgres => "INSERT INTO",
            _ => unreachable!("unknown backend"),
        };
        let now = match backend {
            DatabaseBackend::Sqlite => "'2026-09-28 00:00:00'".to_string(),
            _ => "NOW()".to_string(),
        };
        db.execute_raw(Statement::from_string(
            backend,
            format!(
                "{} sys_menu (menu_id, menu_name, parent_id, order_num, path, component, query, route_name, is_frame, is_cache, menu_type, visible, status, perms, icon, create_by, create_time, remark, del_flag, i18n_key) VALUES (3950, '租户服务', 0, 5, 'tenant-space', NULL, '', '', '1', '0', 'M', '0', '0', '', 'shopping', 'admin', {}, '租户自助功能聚合（我的域名 / 导航设置）', '0', 'menu.tenantSpace')",
                prefix, now
            ),
        ))
        .await?;
        let rm_prefix = match backend {
            DatabaseBackend::Postgres => {
                "INSERT INTO sys_role_menu (role_id, menu_id) VALUES (2, 3950) ON CONFLICT DO NOTHING"
            }
            DatabaseBackend::Sqlite => {
                "INSERT OR IGNORE INTO sys_role_menu (role_id, menu_id) VALUES (2, 3950)"
            }
            DatabaseBackend::MySql => {
                "INSERT IGNORE INTO sys_role_menu (role_id, menu_id) VALUES (2, 3950)"
            }
            _ => unreachable!("unknown backend"),
        };
        db.execute_raw(Statement::from_string(backend, rm_prefix.to_string()))
            .await?;
    }

    // ---- ② 自助页收编 + order 重排 + icon 修正（幂等 UPDATE 清单）----
    let updates: &[&str] = &[
        "UPDATE sys_menu SET menu_name = '域名管理' WHERE menu_id = 3900",
        "UPDATE sys_menu SET menu_name = '我的导航' WHERE menu_id = 3627",
        "UPDATE sys_menu SET parent_id = 3950 WHERE menu_id = 3900",
        "UPDATE sys_menu SET parent_id = 3950 WHERE menu_id = 3627",
        "UPDATE sys_menu SET parent_id = 3 WHERE menu_id = 3560",
        "UPDATE sys_menu SET order_num = 1 WHERE menu_id = 3900",
        "UPDATE sys_menu SET order_num = 2 WHERE menu_id = 3627",
        // 顶层：工作台 0 / 数据看板 1 / 系统管理 2 / 系统监控 3 / 系统工具 4 / 租户服务 5 / 官网 6
        "UPDATE sys_menu SET order_num = 0 WHERE menu_id = 127",
        "UPDATE sys_menu SET order_num = 1 WHERE menu_id = 132",
        "UPDATE sys_menu SET order_num = 2 WHERE menu_id = 1",
        "UPDATE sys_menu SET order_num = 3 WHERE menu_id = 2",
        "UPDATE sys_menu SET order_num = 4 WHERE menu_id = 3",
        "UPDATE sys_menu SET order_num = 5 WHERE menu_id = 3950",
        "UPDATE sys_menu SET order_num = 6 WHERE menu_id = 4",
        // 系统管理(1)
        "UPDATE sys_menu SET order_num = 1 WHERE menu_id = 100",
        "UPDATE sys_menu SET order_num = 2 WHERE menu_id = 101",
        "UPDATE sys_menu SET order_num = 3 WHERE menu_id = 102",
        "UPDATE sys_menu SET order_num = 4 WHERE menu_id = 103",
        "UPDATE sys_menu SET order_num = 5 WHERE menu_id = 104",
        "UPDATE sys_menu SET order_num = 6 WHERE menu_id = 105",
        "UPDATE sys_menu SET order_num = 7 WHERE menu_id = 106",
        "UPDATE sys_menu SET order_num = 8 WHERE menu_id = 107",
        "UPDATE sys_menu SET order_num = 9 WHERE menu_id = 3700",
        "UPDATE sys_menu SET order_num = 10 WHERE menu_id = 108",
        "UPDATE sys_menu SET order_num = 11 WHERE menu_id = 125",
        "UPDATE sys_menu SET order_num = 12 WHERE menu_id = 134",
        "UPDATE sys_menu SET order_num = 13 WHERE menu_id = 140",
        "UPDATE sys_menu SET order_num = 14 WHERE menu_id = 151",
        "UPDATE sys_menu SET order_num = 15 WHERE menu_id = 3600",
        "UPDATE sys_menu SET order_num = 16 WHERE menu_id = 145",
        "UPDATE sys_menu SET order_num = 17 WHERE menu_id = 157",
        // 系统监控(2)
        "UPDATE sys_menu SET order_num = 1 WHERE menu_id = 109",
        "UPDATE sys_menu SET order_num = 2 WHERE menu_id = 110",
        "UPDATE sys_menu SET order_num = 3 WHERE menu_id = 119",
        "UPDATE sys_menu SET order_num = 4 WHERE menu_id = 113",
        "UPDATE sys_menu SET order_num = 5 WHERE menu_id = 135",
        "UPDATE sys_menu SET order_num = 6 WHERE menu_id = 118",
        "UPDATE sys_menu SET order_num = 7 WHERE menu_id = 3550",
        "UPDATE sys_menu SET order_num = 8 WHERE menu_id = 133",
        "UPDATE sys_menu SET order_num = 9 WHERE menu_id = 121",
        "UPDATE sys_menu SET order_num = 10 WHERE menu_id = 122",
        "UPDATE sys_menu SET order_num = 11 WHERE menu_id = 120",
        "UPDATE sys_menu SET order_num = 12 WHERE menu_id = 160",
        "UPDATE sys_menu SET order_num = 13 WHERE menu_id = 501",
        // 系统工具(3)
        "UPDATE sys_menu SET order_num = 1 WHERE menu_id = 115",
        "UPDATE sys_menu SET order_num = 2 WHERE menu_id = 116",
        "UPDATE sys_menu SET order_num = 3 WHERE menu_id = 117",
        "UPDATE sys_menu SET order_num = 4 WHERE menu_id = 3410",
        "UPDATE sys_menu SET order_num = 5 WHERE menu_id = 3560",
        "UPDATE sys_menu SET order_num = 6 WHERE menu_id = 124",
        "UPDATE sys_menu SET order_num = 7 WHERE menu_id = 128",
        "UPDATE sys_menu SET order_num = 8 WHERE menu_id = 129",
        "UPDATE sys_menu SET order_num = 9 WHERE menu_id = 131",
        // icon 语义修正（第二批，语义直觉优先——同语义页面允许复用同图标）：
        "UPDATE sys_menu SET icon = 'message' WHERE menu_id = 107",
        "UPDATE sys_menu SET icon = 'email' WHERE menu_id = 140",
        "UPDATE sys_menu SET icon = 'log' WHERE menu_id = 135",
        "UPDATE sys_menu SET icon = 'druid' WHERE menu_id = 133",
        "UPDATE sys_menu SET icon = 'icon' WHERE menu_id = 124",
        "UPDATE sys_menu SET icon = 'switch' WHERE menu_id = 146",
        "UPDATE sys_menu SET icon = 'nested' WHERE menu_id = 3700",
        "UPDATE sys_menu SET icon = 'peoples' WHERE menu_id = 3950",
        "UPDATE sys_menu SET icon = 'clipboard' WHERE menu_id = 3560",
        "UPDATE sys_menu SET icon = 'drag' WHERE menu_id = 3627",
    ];
    for sql in updates {
        db.execute_raw(Statement::from_string(backend, sql.to_string()))
            .await?;
    }
    tracing::info!("菜单信息架构优化已应用（order 重排 / 自助页收编 3950 / icon 语义修正）");
    Ok(())
}

/// 数据看板菜单去重兜底（与迁移 m20260928_000003_dedupe_dashboard_menu 等价，全幂等）：
/// 删除「系统管理」下与顶级 132 重复的 dashboard 菜单（m20260801_000002 查重条件
/// 带 parent_id=1 漏判顶级 132 所致的重复注册）。重复执行为 no-op。
pub(crate) async fn ensure_dashboard_menu_dedupe(db: &DatabaseConnection) -> anyhow::Result<()> {
    let backend = db.get_database_backend();
    let dedup_rows = db
        .execute_raw(Statement::from_string(
            backend,
            "DELETE FROM sys_role_menu WHERE menu_id IN (
                SELECT menu_id FROM sys_menu
                WHERE path = 'dashboard' AND parent_id = 1 AND component = 'dashboard/index'
            )",
        ))
        .await?;
    let deleted = db
        .execute_raw(Statement::from_string(
            backend,
            "DELETE FROM sys_menu WHERE path = 'dashboard' AND parent_id = 1 AND component = 'dashboard/index'",
        ))
        .await?;
    let rows = deleted.rows_affected() + dedup_rows.rows_affected();
    if rows > 0 {
        tracing::info!("数据看板重复菜单已清理 {} 行（存量库兜底）", rows);
    }
    Ok(())
}

/// 租户自助域名页面菜单（批次 1c；与迁移
/// `m20260926_000011_tenant_domain_self_service_menu` **双写一致**，R4 为回归门禁）。
///
/// 新增 `menu-id-registry.md` §「新增大模块 3900 起」段位的一组自包含菜单：
/// - C 页面 3900「我的域名」（顶层菜单，`system/tenant/domain/index`，perms 复用
///   `system:tenant:domain:list`）；
/// - F 按钮 3901 新增 / 3902 验证 / 3903 修改 / 3904 删除。
///
/// **不授予任何角色**：能力位 `tenant.domain_self_service` 默认 `off`，
/// 授予与回收由 [`ensure_tenant_role_menu_governance`] 的 ①/①' 按能力位动态处理
/// （开启 ⇒ 回填给平台普通角色 role 2 作新建租户模板；关闭 ⇒ 收回）。
pub(crate) async fn ensure_domain_self_service_menu(db: &DatabaseConnection) -> anyhow::Result<()> {
    let backend = db.get_database_backend();
    if !sso_table_exists(db, "sys_menu").await? {
        return Ok(());
    }
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
            "{menu_cols} VALUES (3900, '我的域名', 0, 90, 'my-domain', 'system/tenant/domain/index', '', '', '1', '0', 'C', '0', '0', 'system:tenant:domain:list', 'link', 'admin', {now_expr}, '租户自助域名管理（需能力位 tenant.domain_self_service）', '0', 'menu.myDomain')"
        ),
        format!(
            "{menu_cols} VALUES (3901, '域名新增', 3900, 1, '', '', '', '', '1', '0', 'F', '0', '0', 'system:tenant:domain:add', '#', 'admin', {now_expr}, '', '0', NULL)"
        ),
        format!(
            "{menu_cols} VALUES (3902, '域名验证', 3900, 2, '', '', '', '', '1', '0', 'F', '0', '0', 'system:tenant:domain:verify', '#', 'admin', {now_expr}, '', '0', NULL)"
        ),
        format!(
            "{menu_cols} VALUES (3903, '域名修改', 3900, 3, '', '', '', '', '1', '0', 'F', '0', '0', 'system:tenant:domain:edit', '#', 'admin', {now_expr}, '', '0', NULL)"
        ),
        format!(
            "{menu_cols} VALUES (3904, '域名删除', 3900, 4, '', '', '', '', '1', '0', 'F', '0', '0', 'system:tenant:domain:remove', '#', 'admin', {now_expr}, '', '0', NULL)"
        ),
    ];
    for body in body_rows {
        db.execute_raw(Statement::from_string(
            backend,
            format!("{insert_prefix}{body}{insert_suffix}"),
        ))
        .await?;
    }
    tracing::info!("租户自助域名页面菜单已就绪（3900-3904，幂等确保完成）");
    Ok(())
}

/// 备份权限粒度化菜单（批次 2；与迁移
/// `m20260926_000012_backup_permission_granularity` **双写一致**，R4 为回归门禁）。
///
/// 新增两个 F 按钮（`menu-id-registry.md`「新增 C/F 页面按钮（小模块）3625 起」），
/// 挂在既有备份页 118 之下：
/// - 3625 `system:backup:download`（整库文件下载，原与 `query` 混用）
/// - 3626 `system:backup:export`（数据包导出：平台代导出 + 租户自助导出）
///
/// **不授予任何角色**：与 3900-3904 同理，授予/回收由
/// [`ensure_tenant_role_menu_governance`] 按能力位 **perms 粒度**动态处理。
pub(crate) async fn ensure_backup_permission_menus(db: &DatabaseConnection) -> anyhow::Result<()> {
    let backend = db.get_database_backend();
    if !sso_table_exists(db, "sys_menu").await? {
        return Ok(());
    }
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
            "{menu_cols} VALUES (3625, '备份下载', 118, 5, '', '', '', '', '1', '0', 'F', '0', '0', 'system:backup:download', '#', 'admin', {now_expr}, '整库备份文件下载（批次 2 从 query 独立）', '0', NULL)"
        ),
        format!(
            "{menu_cols} VALUES (3626, '数据包导出', 118, 6, '', '', '', '', '1', '0', 'F', '0', '0', 'system:backup:export', '#', 'admin', {now_expr}, '租户数据包导出（平台代导出 + 租户自助导出）', '0', NULL)"
        ),
    ];
    for body in body_rows {
        db.execute_raw(Statement::from_string(
            backend,
            format!("{insert_prefix}{body}{insert_suffix}"),
        ))
        .await?;
    }
    tracing::info!("备份权限粒度化菜单已就绪（3625-3626，幂等确保完成）");
    Ok(())
}

/// 租户自建导航 L3 页面菜单（批次 3；与迁移
/// `m20260926_000014_tenant_nav_menu` **双写一致**，R4 为回归门禁）。
///
/// 新增 `menu-id-registry.md` §「新增 C/F 页面按钮（小模块）3627 起」的一组菜单：
/// - C 页面 3627「导航设置」（顶层菜单，`system/tenant/nav/index`，
///   perms `system:tenantMenu:list`）；
/// - F 按钮 3628 新增 / 3629 修改 / 3630 删除。
///
/// **不授予任何角色**：能力位 `nav.l3` 默认 `off`，授予与回收由
/// [`ensure_tenant_role_menu_governance`] 的 ①/①' 按能力位 **perms 粒度 + 档位阈值**
/// 动态处理（`view_only` ⇒ 仅回填 3627；`full` ⇒ 追加回填 3628-3630）。
pub(crate) async fn ensure_tenant_nav_menu(db: &DatabaseConnection) -> anyhow::Result<()> {
    let backend = db.get_database_backend();
    if !sso_table_exists(db, "sys_menu").await? {
        return Ok(());
    }
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
            "{menu_cols} VALUES (3627, '导航设置', 0, 91, 'my-nav', 'system/tenant/nav/index', '', '', '1', '0', 'C', '0', '0', 'system:tenantMenu:list', 'tree-table', 'admin', {now_expr}, '租户自建导航 L3 配置（需能力位 nav.l3）', '0', 'menu.myNav')"
        ),
        format!(
            "{menu_cols} VALUES (3628, '导航新增', 3627, 1, '', '', '', '', '1', '0', 'F', '0', '0', 'system:tenantMenu:add', '#', 'admin', {now_expr}, '', '0', NULL)"
        ),
        format!(
            "{menu_cols} VALUES (3629, '导航修改', 3627, 2, '', '', '', '', '1', '0', 'F', '0', '0', 'system:tenantMenu:edit', '#', 'admin', {now_expr}, '', '0', NULL)"
        ),
        format!(
            "{menu_cols} VALUES (3630, '导航删除', 3627, 3, '', '', '', '', '1', '0', 'F', '0', '0', 'system:tenantMenu:remove', '#', 'admin', {now_expr}, '', '0', NULL)"
        ),
    ];
    for body in body_rows {
        db.execute_raw(Statement::from_string(
            backend,
            format!("{insert_prefix}{body}{insert_suffix}"),
        ))
        .await?;
    }
    tracing::info!("租户自建导航页面菜单已就绪（3627-3630，幂等确保完成）");
    Ok(())
}

/// 幂等确保 PAT 管理菜单存在（Tier-S #3）
///
/// 背景同 `ensure_sys_pat_table`：存量库启动不跑 Migrator::up，m20260823_000001_sys_pat
/// 迁移登记的 sys_menu（页 3560 + 按钮 3561）不会落到已有库。此处以等价的检查-后-插入补齐，
/// 使管理员页 /monitor/pat 在存量库上同样可经"系统监控"菜单进入并被 E2E 覆盖。
/// 超管用户可见全部菜单（不依赖 sys_role_menu），role_id=2 的授权仅为与普通角色对齐。
pub(crate) async fn ensure_sys_pat_menu(db: &DatabaseConnection) -> anyhow::Result<()> {
    let backend = db.get_database_backend();
    // sys_menu 表存在性保护：空库未建表时跳过，交由 migration 负责初始种子
    let exists_sql = match backend {
        DatabaseBackend::Sqlite => {
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='sys_menu'".to_string()
        }
        DatabaseBackend::Postgres => {
            "SELECT 1 FROM information_schema.tables WHERE table_name='sys_menu' AND table_schema=current_schema() LIMIT 1".to_string()
        }
        DatabaseBackend::MySql => {
            "SELECT 1 FROM information_schema.tables WHERE table_name='sys_menu' AND table_schema=DATABASE() LIMIT 1".to_string()
        }
        _ => unreachable!("unknown backend"),
    };
    if !db
        .query_all_raw(Statement::from_string(backend, exists_sql))
        .await?
        .is_empty()
    {
        let ts = crate::common::datetime::now_naive()
            .format("%Y-%m-%d %H:%M:%S")
            .to_string();

        // 页菜单 3560
        if count_scalar(
            db,
            "SELECT COUNT(*) AS c FROM sys_menu WHERE menu_id=3560".to_string(),
        )
        .await?
            == 0
        {
            db.execute_raw(Statement::from_string(
                backend,
                format!(
                    "INSERT INTO sys_menu (menu_id, menu_name, parent_id, order_num, path, component, query, route_name, is_frame, is_cache, menu_type, visible, status, perms, icon, create_by, create_time, remark, del_flag, i18n_key) \
                     VALUES (3560, 'API 令牌', 2, 11, 'pat', 'monitor/pat/index', '', '', '1', '0', 'C', '0', '0', 'monitor:pat:list', 'key', 'admin', '{ts}', '个人访问令牌统一管理', '0', 'menu.pat')"
                ),
            ))
            .await?;
            tracing::info!("已登记 PAT 管理页菜单 (menu_id=3560)");
        }

        // 按钮 3561
        if count_scalar(
            db,
            "SELECT COUNT(*) AS c FROM sys_menu WHERE menu_id=3561".to_string(),
        )
        .await?
            == 0
        {
            db.execute_raw(Statement::from_string(
                backend,
                format!(
                    "INSERT INTO sys_menu (menu_id, menu_name, parent_id, order_num, path, component, query, route_name, is_frame, is_cache, menu_type, visible, status, perms, icon, create_by, create_time, remark, del_flag, i18n_key) \
                     VALUES (3561, '吊销', 3560, 1, '', '', '', '', '1', '0', 'F', '0', '0', 'monitor:pat:revoke', 'delete', 'admin', '{ts}', '吊销指定用户的访问令牌', '0', '')"
                ),
            ))
            .await?;
            tracing::info!("已登记 PAT 吊销按钮 (menu_id=3561)");
        }

        // role_id=2（普通角色）授权，与迁移对齐；超管无需授权即可见全部菜单
        for mid in [3560i64, 3561] {
            if count_scalar(
                db,
                format!(
                    "SELECT COUNT(*) AS c FROM sys_role_menu WHERE role_id=2 AND menu_id={mid}"
                ),
            )
            .await?
                == 0
            {
                db.execute_raw(Statement::from_string(
                    backend,
                    format!("INSERT INTO sys_role_menu (role_id, menu_id) VALUES (2, {mid})"),
                ))
                .await?;
            }
        }
    }
    Ok(())
}

/// G-11（存量库兜底，等价迁移 `m20261007_000002`）：OSS 存储配置管理页菜单
/// （menu_id 4103，platform-only，perms `system:uploadConfig:edit`）。
///
/// 菜单缺失不产生 500（仅 getRouters 少一个入口），但为"权限齐备、入口可见"
/// 的完整性兜底（避免"超管有 perms 却无菜单入口"）；幂等：menu_id 已存在跳过。
pub(crate) async fn ensure_upload_config_menu(db: &DatabaseConnection) -> anyhow::Result<()> {
    if !sso_table_exists(db, "sys_menu").await? {
        return Ok(());
    }
    let backend = db.get_database_backend();
    let occupied = db
        .query_all_raw(Statement::from_string(
            backend,
            "SELECT component, path AS comp_path FROM sys_menu WHERE menu_id = 4103".to_string(),
        ))
        .await?;
    if !occupied.is_empty() {
        // G-14 批次五加固：4103 已存在时**校验内容**而非盲目跳过——
        // 若被非目标菜单占位（如历史 e2e 孤儿残留），OR IGNORE 会静默失效
        // 且无任何日志（实测缺陷：孤儿 test-menu-* 占位导致 OSS 菜单从未落库，
        // uploadConfig 页面入口丢失）。此处显性化冲突，交由人工/测试侧清理重建。
        let existing = occupied
            .first()
            .and_then(|r| r.try_get::<String>("", "component").ok());
        if existing.as_deref() == Some("system/uploadConfig/index") {
            return Ok(());
        }
        tracing::warn!(
            "menu_id=4103 已被其他菜单占用（component={:?}）——OSS 存储配置菜单补建跳过；\
             请清理占位菜单后重启，或将 G-11 菜单迁移至其他 menu_id",
            existing
        );
        return Ok(());
    }
    let now = flow_now(db);
    flow_insert(
        db,
        &format!(
            "sys_menu (menu_id, menu_name, parent_id, order_num, path, component, query, route_name, is_frame, is_cache, menu_type, visible, status, perms, icon, create_by, create_time, remark, del_flag) VALUES              (4103, 'OSS 存储配置', 1, 15, 'uploadConfig', 'system/uploadConfig/index', '', '', '1', '0', 'C', '0', '0', 'system:uploadConfig:edit', 'upload', 'admin', {now}, 'OSS 凭据动态化管理（平台专属；仅 backend=s3 档生效）', '0')"
        ),
    )
    .await?;
    tracing::info!("OSS 存储配置菜单已补建（menu_id=4103，G-11 存量库兜底）");
    Ok(())
}

/// 台账（G-01 M1，存量库兜底，等价迁移 `m20261007_000004`）：
/// report_dataset / report_dashboard 两表。
///
/// 为何必须有本兜底：embedded/存量库按架构约定**不跑 `Migrator::up`**，而
/// `report_dataset_service` 已读写两表 ⇒ 缺此兜底则数据集 CRUD/试跑/大屏存取全链 500。
/// 幂等：表存在即跳过；唯一索引容错"已存在"。
pub(crate) async fn ensure_report_tables(db: &DatabaseConnection) -> anyhow::Result<()> {
    if sso_table_exists(db, "report_dataset").await?
        && sso_table_exists(db, "report_dashboard").await?
    {
        return Ok(());
    }
    let backend = db.get_database_backend();
    let (pk, text_type) = match backend {
        DatabaseBackend::Sqlite => ("INTEGER PRIMARY KEY AUTOINCREMENT", "TEXT"),
        DatabaseBackend::Postgres => ("BIGSERIAL PRIMARY KEY", "TEXT"),
        _ => ("BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY", "LONGTEXT"),
    };
    let dataset_sql = format!(
        "CREATE TABLE IF NOT EXISTS report_dataset (\
         dataset_id {pk},\
         tenant_id BIGINT NOT NULL DEFAULT 0,\
         dataset_code VARCHAR(64) NOT NULL,\
         dataset_name VARCHAR(128) NOT NULL,\
         sql_template {text_type} NOT NULL,\
         params_schema {text_type},\
         columns_meta {text_type},\
         status CHAR(1) NOT NULL DEFAULT '0',\
         remark VARCHAR(500),\
         create_by VARCHAR(64),\
         create_time DATETIME,\
         update_by VARCHAR(64),\
         update_time DATETIME,\
         del_flag CHAR(1) DEFAULT '0')"
    );
    db.execute_raw(Statement::from_string(backend, dataset_sql))
        .await?;
    let dashboard_sql = format!(
        "CREATE TABLE IF NOT EXISTS report_dashboard (\
         dashboard_id {pk},\
         tenant_id BIGINT NOT NULL DEFAULT 0,\
         dashboard_code VARCHAR(64) NOT NULL,\
         dashboard_name VARCHAR(128) NOT NULL,\
         layout_json {text_type} NOT NULL,\
         schema_version INT NOT NULL DEFAULT 1,\
         status CHAR(1) NOT NULL DEFAULT '0',\
         remark VARCHAR(500),\
         create_by VARCHAR(64),\
         create_time DATETIME,\
         update_by VARCHAR(64),\
         update_time DATETIME,\
         del_flag CHAR(1) DEFAULT '0')"
    );
    db.execute_raw(Statement::from_string(backend, dashboard_sql))
        .await?;
    // 唯一索引：MySQL 不支持 IF NOT EXISTS，容错"已存在"
    for (idx_name, table, cols) in [
        (
            "uq_report_dataset_code",
            "report_dataset",
            "(tenant_id, dataset_code)",
        ),
        (
            "uq_report_dashboard_code",
            "report_dashboard",
            "(tenant_id, dashboard_code)",
        ),
    ] {
        let idx_sql = match backend {
            DatabaseBackend::MySql => {
                format!("CREATE UNIQUE INDEX {idx_name} ON {table} {cols}")
            }
            _ => format!("CREATE UNIQUE INDEX IF NOT EXISTS {idx_name} ON {table} {cols}"),
        };
        if let Err(e) = db
            .execute_raw(Statement::from_string(backend, idx_sql))
            .await
        {
            let msg = e.to_string();
            if !(msg.contains("Duplicate key name")
                || msg.contains("42P07")
                || msg.contains("already exists"))
            {
                return Err(e.into());
            }
        }
    }
    tracing::info!("report_dataset / report_dashboard 表已补建（G-01 存量库兜底）");
    Ok(())
}

/// 台账（G-01/G-02 M1，存量库兜底，等价迁移 `m20261007_000005`）：
/// 流程定义与报表数据集/大屏的菜单权限承载（menu_id 4140-4148）。
///
/// 契约测试 `menu_perm_contract` 要求后端 PERM_ROUTE_TABLE 每个权限键 ⊆ sys_menu.perms，
/// 存量库缺菜单行则普通角色永远无法被授予这些能力。页面菜单 `visible='1'`（隐藏，
/// M2 前端上线时翻转可见性）。幂等 + E6 加固：menu_id 已存在时**校验 perms 内容**，
/// 被其他菜单占位则显性 warn（不盲目跳过、不覆盖）。
pub(crate) async fn ensure_flow_report_menus(db: &DatabaseConnection) -> anyhow::Result<()> {
    if !sso_table_exists(db, "sys_menu").await? {
        return Ok(());
    }
    /// 菜单 seed 行（与迁移 m20261007_000005 的 MENUS 同构）
    struct MenuSeedRow {
        menu_id: i64,
        menu_name: &'static str,
        parent_id: i64,
        order_num: i64,
        menu_type: &'static str,
        path: &'static str,
        component: &'static str,
        perms: &'static str,
        icon: &'static str,
    }
    const MENUS: &[MenuSeedRow] = &[
        MenuSeedRow {
            menu_id: 4140,
            menu_name: "流程定义",
            parent_id: 1,
            order_num: 16,
            menu_type: "C",
            path: "flowDefinition",
            component: "flow/designer/index",
            perms: "flow:definition:list",
            icon: "form",
        },
        MenuSeedRow {
            menu_id: 4141,
            menu_name: "流程定义查询",
            parent_id: 4140,
            order_num: 1,
            menu_type: "F",
            path: "",
            component: "",
            perms: "flow:definition:query",
            icon: "#",
        },
        MenuSeedRow {
            menu_id: 4142,
            menu_name: "流程定义新增",
            parent_id: 4140,
            order_num: 2,
            menu_type: "F",
            path: "",
            component: "",
            perms: "flow:definition:add",
            icon: "#",
        },
        MenuSeedRow {
            menu_id: 4143,
            menu_name: "流程定义编辑",
            parent_id: 4140,
            order_num: 3,
            menu_type: "F",
            path: "",
            component: "",
            perms: "flow:definition:edit",
            icon: "#",
        },
        MenuSeedRow {
            menu_id: 4144,
            menu_name: "流程定义发布",
            parent_id: 4140,
            order_num: 4,
            menu_type: "F",
            path: "",
            component: "",
            perms: "flow:definition:publish",
            icon: "#",
        },
        MenuSeedRow {
            menu_id: 4145,
            menu_name: "流程定义删除",
            parent_id: 4140,
            order_num: 5,
            menu_type: "F",
            path: "",
            component: "",
            perms: "flow:definition:remove",
            icon: "#",
        },
        MenuSeedRow {
            menu_id: 4146,
            menu_name: "报表数据集",
            parent_id: 1,
            order_num: 17,
            menu_type: "C",
            path: "reportDataset",
            component: "report/dataset/index",
            perms: "report:dataset:list",
            icon: "chart",
        },
        MenuSeedRow {
            menu_id: 4147,
            menu_name: "数据集编辑",
            parent_id: 4146,
            order_num: 1,
            menu_type: "F",
            path: "",
            component: "",
            perms: "report:dataset:edit",
            icon: "#",
        },
        MenuSeedRow {
            menu_id: 4148,
            menu_name: "大屏管理",
            parent_id: 1,
            order_num: 18,
            menu_type: "C",
            path: "reportDashboard",
            component: "report/view/index",
            perms: "report:dashboard:view",
            icon: "dashboard",
        },
    ];
    let backend = db.get_database_backend();
    for m in MENUS {
        let occupied = db
            .query_all_raw(Statement::from_string(
                backend,
                format!("SELECT perms FROM sys_menu WHERE menu_id = {}", m.menu_id),
            ))
            .await?;
        if let Some(row) = occupied.first() {
            let existing = row.try_get::<String>("", "perms").ok();
            if existing.as_deref() == Some(m.perms) {
                continue;
            }
            // 自动修正（批次十三，用户拍板）：menu_id 被占且 perms 不符 = 占位垃圾行
            //（实证：存量库 4148 被历史 e2e 菜单测试孤儿占用 ⇒ 迁移 INSERT OR IGNORE
            // 静默失效，大屏管理菜单从未落库，垃圾行还入了菜单树）。内容字段整行
            // 对齐 seed；visible 保持现值（页面行随后由翻转兜底收敛到显示态）。
            // e2e 垃圾行零引用（无 role_menu/子菜单），整行 UPDATE 安全。
            db.execute_raw(Statement::from_string(
                backend,
                format!(
                    "UPDATE sys_menu SET menu_name = '{}', parent_id = {}, order_num = {}, \
                     path = '{}', component = '{}', menu_type = '{}', perms = '{}', \
                     icon = '{}', del_flag = '0' WHERE menu_id = {}",
                    m.menu_name,
                    m.parent_id,
                    m.order_num,
                    m.path,
                    m.component,
                    m.menu_type,
                    m.perms,
                    m.icon,
                    m.menu_id
                ),
            ))
            .await?;
            tracing::warn!(
                "menu_id={} 原被占位菜单占用（perms={existing:?}），已自动修正为 G-01/G-02 \
                 菜单（预期 perms={}）——批次十三自动修正",
                m.menu_id,
                m.perms,
            );
            continue;
        }
        let now = flow_now(db);
        flow_insert(
            db,
            &format!(
                "sys_menu (menu_id, menu_name, parent_id, order_num, path, component, query, \
                 route_name, is_frame, is_cache, menu_type, visible, status, perms, icon, \
                 create_by, create_time, remark, del_flag) VALUES \
                 ({}, '{}', {}, {}, '{}', '{}', '', '', \
                 '1', '0', '{}', '1', '0', '{}', '{}', 'admin', {}, \
                 'G-01/G-02 菜单权限承载（存量库兜底）', '0')",
                m.menu_id,
                m.menu_name,
                m.parent_id,
                m.order_num,
                m.path,
                m.component,
                m.menu_type,
                m.perms,
                m.icon,
                now
            ),
        )
        .await?;
    }
    // role_menu 补授（批次十三，用户拍板：平台普通角色 role 2 全量授权 4140-4148）。
    // 对齐菜单 148/3950 惯例（新业务菜单默认授予 role 2）；超管经 isAdmin 特判无需授权行。
    // 幂等：INSERT OR IGNORE（方言感知由 flow_insert 承担）；写权限仍受三层守卫
    // （菜单 perms 契约 + report.designer/flow.designer 能力位 + 租户过滤）。
    if sso_table_exists(db, "sys_role_menu").await? {
        for m in MENUS {
            // 幂等由 flow_insert 方言前后缀承担（SQLite OR IGNORE / PG ON CONFLICT）
            flow_insert(
                db,
                &format!("sys_role_menu (role_id, menu_id) VALUES (2, {})", m.menu_id),
            )
            .await?;
        }
        tracing::info!("role 2 已补授 G-01/G-02 菜单 4140-4148（批次十三）");
    }
    tracing::info!("流程/报表菜单已补建（4140-4148，G-01/G-02 存量库兜底）");
    Ok(())
}

/// 台账（G-01 M2，存量库兜底，等价迁移 `m20261007_000008`）：
/// 报表前端三页上线，翻转菜单 4146（报表数据集）/4148（大屏管理）可见性。
/// **仅翻这两行**——4140-4145（G-02 流程定义）属 M3 前端，继续隐藏。
/// 幂等：仅当 visible='1' 时置 '0'，可重复执行；表/行不存在零影响。
pub(crate) async fn ensure_report_menus_visible(db: &DatabaseConnection) -> anyhow::Result<()> {
    if !sso_table_exists(db, "sys_menu").await? {
        return Ok(());
    }
    db.execute_raw(Statement::from_string(
        db.get_database_backend(),
        "UPDATE sys_menu SET visible = '0' WHERE menu_id IN (4146, 4148) AND visible = '1'"
            .to_string(),
    ))
    .await?;
    Ok(())
}

/// 台账（G-02 M3，存量库兜底，等价迁移 m20261007_000009）：
/// 流程定义设计器上线，翻转菜单 4140（流程定义页面）可见性。
/// 4141-4145 为 F（按钮）行，visible 无导航语义，不翻。幂等：仅当 visible='1' 置 '0'。
pub(crate) async fn ensure_flow_designer_menu_visible(
    db: &DatabaseConnection,
) -> anyhow::Result<()> {
    if !sso_table_exists(db, "sys_menu").await? {
        return Ok(());
    }
    db.execute_raw(Statement::from_string(
        db.get_database_backend(),
        "UPDATE sys_menu SET visible = '0' WHERE menu_id = 4140 AND visible = '1'".to_string(),
    ))
    .await?;
    Ok(())
}

/// 台账（批次三十一，存量库兜底，等价迁移 m20261010_000001）：
/// 「AI 问数历史」(4116) 原挂在菜单 120「审计大屏」之下，而 120 自身是
/// menu_type='C' 且带 component 的页面菜单——C 型菜单带 children 时，
/// 前端注册嵌套路由需父组件以 `<router-view>` 承接，而 audit-dashboard/index.vue
/// 无 router-view ⇒ 子页面永不渲染，访问 /monitor/audit-dashboard/aiHistory
/// 实际显示审计大屏（静默失效，不报错不 404）。修复：4116 改挂「系统监控」(2)
/// 平级，与同域其它 14 项页面菜单结构一致。幂等：仅当仍挂在 120 下时修正。
pub(crate) async fn ensure_ai_history_menu_parent(db: &DatabaseConnection) -> anyhow::Result<()> {
    if !sso_table_exists(db, "sys_menu").await? {
        return Ok(());
    }
    db.execute_raw(Statement::from_string(
        db.get_database_backend(),
        "UPDATE sys_menu SET parent_id = 2, path = 'aiHistory' WHERE menu_id = 4116 AND parent_id = 120"
            .to_string(),
    ))
    .await?;
    Ok(())
}

/// 「审计归档下载」(4180) 与「链完整性校验」(4181) 按钮菜单兜底（批五十六）
///
/// 批次十九（链感知保留）的两个 F 型功能按钮 2026-10-08 以菜单管理页手工创建、
/// 未登记种子——种子漂移审计实证全新部署缺失两个功能入口。迁移
/// m20261012_000001 补种；本兜底为存量库幂等镜像（仅当 menu_id 缺失时插入，
/// 对齐 ensure_ai_history_menu_parent 先例）。role_menu 授权为部署决策不随种子。
pub(crate) async fn ensure_archive_menus(db: &DatabaseConnection) -> anyhow::Result<()> {
    if !sso_table_exists(db, "sys_menu").await? {
        return Ok(());
    }
    db.execute_raw(Statement::from_string(
        db.get_database_backend(),
        "INSERT OR IGNORE INTO sys_menu \
         (menu_id, menu_name, parent_id, order_num, path, component, query, route_name, \
          is_frame, is_cache, menu_type, visible, status, perms, icon, create_by, create_time, \
          remark, del_flag) \
         VALUES \
         (4180, '审计归档下载', 500, 4, '#', '', '', '', '1', '0', 'F', '0', '0', \
          'monitor:operlogArchive:download', '#', 'admin', CURRENT_TIMESTAMP, \
          '链感知保留：归档对象下载（平台专属，monitor:operlogArchive: 前缀）', '0'), \
         (4181, '链完整性校验', 500, 5, '#', '', '', '', '1', '0', 'F', '0', '0', \
          'monitor:operlogArchive:verify', '#', 'admin', CURRENT_TIMESTAMP, \
          '批次十九收尾：verify-chain 收紧平台专属（原复用 monitor:operlog:query，租户可见即泄漏全平台链统计）', '0')"
            .to_string(),
    ))
    .await?;
    Ok(())
}

/// 皮肤/主题键治理修正兜底（批五十六，等价迁移 m20261012_000001 的存量库交付路径）
///
/// 背景：**存量库启动跳过 Migrator::up**（initialize/mod.rs:45 实证）——迁移只服务
/// 全新库，存量库的一切数据修正必须走兜底。skinName/sideTheme 的 init 迁移未指定
/// 治理列（列默认 fail-closed platform_only），与功能 72「租户覆盖 platform_default 键」
/// 的产品语义冲突（全新库该测试必失败）。
///
/// 守卫：仅当三列恰为 legacy 缺省三元组（platform_only/0/0）时翻转为
/// platform_default/1/1——迁移已应用的库与管理员后续治理变更零影响；
/// 管理员若刻意回设完整 legacy 三元组会被再翻转（产品语义归 skin 可覆盖，留档）。
pub(crate) async fn ensure_skin_governance(db: &DatabaseConnection) -> anyhow::Result<()> {
    if !sso_table_exists(db, "sys_config").await? {
        return Ok(());
    }
    db.execute_raw(Statement::from_string(
        db.get_database_backend(),
        "UPDATE sys_config SET scope = 'platform_default', tenant_editable = '1', \
         visible_to_tenant = '1' \
         WHERE config_key IN ('sys.index.skinName', 'sys.index.sideTheme') AND tenant_id = 0 \
         AND scope = 'platform_only' AND tenant_editable = '0' AND visible_to_tenant = '0'"
            .to_string(),
    ))
    .await?;
    Ok(())
}

use super::*;
