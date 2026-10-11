// stepby-axum/src/initialize/schema.rs

use sea_orm::{ConnectionTrait, DatabaseBackend, DatabaseConnection, Statement};

/// 零配置/本地路径引导：`database.url` 为 `sqlite://` 时，解析出库文件父目录并幂等自建。
///
/// 统一覆盖两类场景：① from_env_only 的零配置默认（`sqlite://./data/stepby.db?mode=rwc`）；
/// ② 有 config.toml 但 SQLite 路径父目录尚未创建的存量/新部署。查询串（`?` 起）截除后取
/// parent；非 sqlite 前缀 / 无 parent / 建目录失败一律静默跳过（后续真实 IO 会报确切错误）。
pub(crate) fn ensure_sqlite_parent_dir(url: &str) {
    let Some(path) = url.strip_prefix("sqlite://") else {
        return;
    };
    let file_part = path.split('?').next().unwrap_or(path);
    let Some(parent) = std::path::Path::new(file_part).parent() else {
        return;
    };
    if let Err(e) = std::fs::create_dir_all(parent) {
        tracing::debug!("SQLite 父目录 {parent:?} 创建失败（不阻断，交由 init 报真实错误）: {e}");
    }
}

/// 共享态存储三表兜底（存量库不跑 Migrator::up，等价迁移 `m20261001_000001_shared_store`）。
///
/// 列定义与迁移**完全一致**（两处必须同步维护）：
/// - `sys_shared_kv`：S2 一次性/短期态（键值 + 可空过期时间戳 UTC 秒）；
/// - `sys_shared_lock`：调度锁（单语句 CAS）；
/// - `sys_token_revocation`：S1 吊销权威层（blacklist + 历史 SSO AT 阻断，source 区分）。
///
/// `CREATE TABLE IF NOT EXISTS` 三方言均合法；索引经 `ensure_tenant_index` 方言兜底
/// （MySQL 不支持 `IF NOT EXISTS` 子句，information_schema 判存在后建——与迁移
/// IndexDdlExt 容错思路一致）。全部幂等，重复执行无副作用。
pub(crate) async fn ensure_shared_store_tables(db: &DatabaseConnection) -> anyhow::Result<()> {
    let backend = db.get_database_backend();
    // 主键为 VARCHAR：SQLite/MySQL 直接 PRIMARY KEY；PG VARCHAR PK 通用，无需自增列
    for ddl in [
        "CREATE TABLE IF NOT EXISTS sys_shared_kv (
            kv_key VARCHAR(255) NOT NULL PRIMARY KEY,
            kv_value TEXT NOT NULL,
            expire_at BIGINT NULL
        )",
        "CREATE TABLE IF NOT EXISTS sys_shared_lock (
            lock_key VARCHAR(255) NOT NULL PRIMARY KEY,
            lock_token VARCHAR(64) NOT NULL,
            expire_at BIGINT NOT NULL
        )",
        "CREATE TABLE IF NOT EXISTS sys_token_revocation (
            token_hash VARCHAR(128) NOT NULL PRIMARY KEY,
            expire_at BIGINT NOT NULL,
            source VARCHAR(32) NOT NULL DEFAULT 'logout'
        )",
    ] {
        db.execute_raw(Statement::from_string(backend, ddl.to_string()))
            .await?;
    }
    // 过期行 GC 扫描索引（与迁移同名；MySQL 方言差异由 ensure_tenant_index 收口）
    ensure_tenant_index(
        db,
        "sys_shared_kv",
        "idx_sys_shared_kv_expire_at",
        "expire_at",
        false,
    )
    .await?;
    ensure_tenant_index(
        db,
        "sys_token_revocation",
        "idx_sys_token_revocation_expire_at",
        "expire_at",
        false,
    )
    .await?;
    tracing::info!(
        "共享态存储三表已就绪（sys_shared_kv / sys_shared_lock / sys_token_revocation）"
    );

    // ===== AI 助手（AI-01/AI-02，§5.39）：ai_chat_history 表 + sys.ai.* 配置种子兜底 =====
    // 与 m20261006_000001 迁移同源（pub fn 单一事实源）；存量库启动不跑 Migrator 时由本段兜底。
    migration::migrations::m20261006_000001_ai_config_and_history::init_ai_config_and_history(db)
        .await?;
    tracing::info!(
        "AI 助手：ai_chat_history 表与 sys.ai.* 配置种子已就绪（幂等，管理页可改热生效）"
    );
    Ok(())
}

/// 幂等确保 `sys_user` 含 `password_version` 列（S1 密码版本号权威层；与
/// `ensure_user_tenant_id_column` 同范式：表存在检查 + 列存在检查 + ALTER 补列）。
/// `ALTER TABLE sys_user ADD COLUMN ... BIGINT NOT NULL DEFAULT 0` 三方言语法通用。
/// 缺此兜底时：存量库实体 SELECT 带 password_version ⇒ 登录/改密链路 500。
pub(crate) async fn ensure_user_password_version_column(
    db: &DatabaseConnection,
) -> anyhow::Result<()> {
    if !sso_table_exists(db, "sys_user").await? {
        return Ok(());
    }
    if sso_has_column(db, "sys_user", "password_version").await? {
        return Ok(());
    }
    db.execute_raw(Statement::from_string(
        db.get_database_backend(),
        "ALTER TABLE sys_user ADD COLUMN password_version BIGINT NOT NULL DEFAULT 0".to_string(),
    ))
    .await?;
    tracing::info!("sys_user.password_version 列已补建（存量库兜底）");
    Ok(())
}

/// B4 强制首登改密兜底（等价迁移 `m20261004_000003_force_pwd_change`，幂等）：
/// 1. `sys_user.must_change_pwd CHAR(1) DEFAULT '0'`——列不存在时补建，**仅本次建列时**
///    回填 admin 标记（存量库重跑不误标已改密用户）；
/// 2. `sys_config` 强改开关种子 `sys.user.forceFirstLoginChangePwd='false'`
///    （幂等 INSERT，不 UPDATE——尊重管理员已改值）。
pub(crate) async fn ensure_user_must_change_pwd_column(
    db: &DatabaseConnection,
) -> anyhow::Result<()> {
    if !sso_table_exists(db, "sys_user").await? {
        return Ok(());
    }
    let newly_added = !sso_has_column(db, "sys_user", "must_change_pwd").await?;
    if newly_added {
        db.execute_raw(Statement::from_string(
            db.get_database_backend(),
            "ALTER TABLE sys_user ADD COLUMN must_change_pwd CHAR(1) DEFAULT '0'".to_string(),
        ))
        .await?;
        db.execute_raw(Statement::from_string(
            db.get_database_backend(),
            "UPDATE sys_user SET must_change_pwd = '1' WHERE user_id = 1 AND must_change_pwd = '0'"
                .to_string(),
        ))
        .await?;
        tracing::info!("sys_user.must_change_pwd 列已补建并标记 admin（B4 存量库兜底）");
    }
    if sso_table_exists(db, "sys_config").await? {
        let now = flow_now(db);
        flow_insert(
            db,
            &format!(
                "sys_config (config_id, config_name, config_key, config_value, config_type, create_by, create_time, remark) VALUES \
                (9010, '用户首登强制改密开关', 'sys.user.forceFirstLoginChangePwd', 'false', 'Y', 'admin', {now}, '开启后初始密码/过期密码用户登录时被强制引导改密')"
            ),
        )
        .await?;
    }
    Ok(())
}

/// v5-N2 Phase 2（第一步）：幂等确保 `sys_user` 含 `tenant_id` 列（登录 JWT 的 tid
/// 数据源）。与 `ensure_user_country_code_column` 同源方案：表不存在跳过；列不存在
/// 则 `ALTER TABLE sys_user ADD COLUMN tenant_id BIGINT NOT NULL DEFAULT 0`。
pub(crate) async fn ensure_user_tenant_id_column(db: &DatabaseConnection) -> anyhow::Result<()> {
    if !sso_table_exists(db, "sys_user").await? {
        return Ok(());
    }
    if sso_has_column(db, "sys_user", "tenant_id").await? {
        tracing::info!("sys_user.tenant_id 列已存在，无需 ALTER");
        return Ok(());
    }
    db.execute_raw(Statement::from_string(
        db.get_database_backend(),
        "ALTER TABLE sys_user ADD COLUMN tenant_id BIGINT NOT NULL DEFAULT 0".to_string(),
    ))
    .await?;
    tracing::info!("sys_user.tenant_id 列已补建（v5-N2 Phase 2 存量库兜底）");
    Ok(())
}

/// 幂等确保 `sys_user` 表含 `country_code` 列（方案 D，G18：手机号多地区化向后兼容）
///
/// 实体新增 `country_code` 字段后，存量 SQLite / Postgres / MySQL 数据库若无该列，
/// 查询会因缺列报错。启动初始化时按当前数据库方言检测列是否存在：
/// - 表不存在则跳过（由 migration 负责建表，下次启动再补列）
/// - 列不存在则执行 `ALTER TABLE sys_user ADD COLUMN country_code VARCHAR(8)`
pub(crate) async fn ensure_user_country_code_column(db: &DatabaseConnection) -> anyhow::Result<()> {
    let backend = db.get_database_backend();

    // 1) 表是否存在（避免对尚未建表的空库误执行 ALTER）
    let table_exists = match backend {
        DatabaseBackend::Sqlite => {
            let rows = db
                .query_all_raw(Statement::from_string(
                    backend,
                    "SELECT name FROM sqlite_master WHERE type='table' AND name='sys_user'",
                ))
                .await?;
            !rows.is_empty()
        }
        DatabaseBackend::Postgres => {
            let rows = db
                .query_all_raw(Statement::from_string(
                    backend,
                    "SELECT 1 FROM information_schema.tables WHERE table_name='sys_user' AND table_schema=current_schema()",
                ))
                .await?;
            !rows.is_empty()
        }
        DatabaseBackend::MySql => {
            let rows = db
                .query_all_raw(Statement::from_string(
                    backend,
                    "SELECT 1 FROM information_schema.tables WHERE table_name='sys_user' AND table_schema=DATABASE()",
                ))
                .await?;
            !rows.is_empty()
        }
        _ => unreachable!("unknown backend"),
    };

    if !table_exists {
        tracing::info!("sys_user 表尚未创建，跳过 country_code 列检查（由 migration 负责建表）");
        return Ok(());
    }

    // 2) 列是否存在
    let has_column = match backend {
        DatabaseBackend::Sqlite => {
            let rows = db
                .query_all_raw(Statement::from_string(
                    backend,
                    "PRAGMA table_info(sys_user)",
                ))
                .await?;
            rows.iter().any(|row| {
                row.try_get::<String>("", "name")
                    .map(|n| n.eq_ignore_ascii_case("country_code"))
                    .unwrap_or(false)
            })
        }
        DatabaseBackend::Postgres => {
            let rows = db
                .query_all_raw(Statement::from_string(
                    backend,
                    "SELECT 1 FROM information_schema.columns WHERE table_name='sys_user' AND column_name='country_code' AND table_schema=current_schema() LIMIT 1",
                ))
                .await?;
            !rows.is_empty()
        }
        DatabaseBackend::MySql => {
            let rows = db
                .query_all_raw(Statement::from_string(
                    backend,
                    "SELECT 1 FROM information_schema.columns WHERE table_name='sys_user' AND column_name='country_code' AND table_schema=DATABASE() LIMIT 1",
                ))
                .await?;
            !rows.is_empty()
        }
        _ => unreachable!("unknown backend"),
    };

    if !has_column {
        tracing::info!("sys_user 缺少 country_code 列，执行幂等 ALTER 添加");
        db.execute_raw(Statement::from_string(
            backend,
            "ALTER TABLE sys_user ADD COLUMN country_code VARCHAR(8)",
        ))
        .await?;
    } else {
        tracing::info!("sys_user.country_code 列已存在，无需 ALTER");
    }

    Ok(())
}

/// 幂等确保 `sys_task` 表含 `operator_id` 列（P0-2：taskProgress 定向推送目标 user_id）
///
/// 与 G18 `ensure_user_country_code_column` 同源方案：实体新增 `operator_id` 字段后，
/// 存量库若无该列，`/system/task/list` 等查询会因缺列报 500。启动初始化时按当前数据库方言
/// 检测列是否存在并幂等补列。m20260806_000002_add_task_operator_id 迁移负责全新库建表时带该列；
/// 此处兜底存量库（AppInitializer 启动不跑 Migrator::up，避免对已有种子数据重跑 seed 导致主键冲突）。
pub(crate) async fn ensure_task_operator_id_column(db: &DatabaseConnection) -> anyhow::Result<()> {
    let backend = db.get_database_backend();

    // 1) 表是否存在（避免对尚未建表的空库误执行 ALTER）
    let table_exists = match backend {
        DatabaseBackend::Sqlite => {
            let rows = db
                .query_all_raw(Statement::from_string(
                    backend,
                    "SELECT name FROM sqlite_master WHERE type='table' AND name='sys_task'",
                ))
                .await?;
            !rows.is_empty()
        }
        DatabaseBackend::Postgres => {
            let rows = db
                .query_all_raw(Statement::from_string(
                    backend,
                    "SELECT 1 FROM information_schema.tables WHERE table_name='sys_task' AND table_schema=current_schema()",
                ))
                .await?;
            !rows.is_empty()
        }
        DatabaseBackend::MySql => {
            let rows = db
                .query_all_raw(Statement::from_string(
                    backend,
                    "SELECT 1 FROM information_schema.tables WHERE table_name='sys_task' AND table_schema=DATABASE()",
                ))
                .await?;
            !rows.is_empty()
        }
        _ => unreachable!("unknown backend"),
    };

    if !table_exists {
        tracing::info!("sys_task 表尚未创建，跳过 operator_id 列检查（由 migration 负责建表）");
        return Ok(());
    }

    // 2) 列是否存在
    let has_column = match backend {
        DatabaseBackend::Sqlite => {
            let rows = db
                .query_all_raw(Statement::from_string(
                    backend,
                    "PRAGMA table_info(sys_task)",
                ))
                .await?;
            rows.iter().any(|row| {
                row.try_get::<String>("", "name")
                    .map(|n| n.eq_ignore_ascii_case("operator_id"))
                    .unwrap_or(false)
            })
        }
        DatabaseBackend::Postgres => {
            let rows = db
                .query_all_raw(Statement::from_string(
                    backend,
                    "SELECT 1 FROM information_schema.columns WHERE table_name='sys_task' AND column_name='operator_id' AND table_schema=current_schema() LIMIT 1",
                ))
                .await?;
            !rows.is_empty()
        }
        DatabaseBackend::MySql => {
            let rows = db
                .query_all_raw(Statement::from_string(
                    backend,
                    "SELECT 1 FROM information_schema.columns WHERE table_name='sys_task' AND column_name='operator_id' AND table_schema=DATABASE() LIMIT 1",
                ))
                .await?;
            !rows.is_empty()
        }
        _ => unreachable!("unknown backend"),
    };

    if !has_column {
        tracing::info!("sys_task 缺少 operator_id 列，执行幂等 ALTER 添加");
        db.execute_raw(Statement::from_string(
            backend,
            "ALTER TABLE sys_task ADD COLUMN operator_id BIGINT",
        ))
        .await?;
    } else {
        tracing::info!("sys_task.operator_id 列已存在，无需 ALTER");
    }

    Ok(())
}

/// 幂等确保 `sys_oper_log` 表含 `oper_diff` 列（Tier-S #2：字段级审计 diff）
///
/// 与 `ensure_task_operator_id_column` 同源方案：实体新增 `oper_diff` 字段后，存量库若无该列，
/// 操作日志的查询（SeaORM 显式列名 SELECT）与写入都会因缺列报错。m20260822_000001_oper_log_diff
/// 迁移负责全新库建表时带该列；此处兜底存量库（AppInitializer 启动不跑 Migrator::up）。
/// `ALTER TABLE ... ADD COLUMN oper_diff TEXT` 语法在 SQLite/MySQL/PostgreSQL 三方言下均合法。
pub(crate) async fn ensure_oper_log_diff_column(db: &DatabaseConnection) -> anyhow::Result<()> {
    let backend = db.get_database_backend();

    // 1) 表是否存在（避免对尚未建表的空库误执行 ALTER）
    let table_exists = match backend {
        DatabaseBackend::Sqlite => {
            let rows = db
                .query_all_raw(Statement::from_string(
                    backend,
                    "SELECT name FROM sqlite_master WHERE type='table' AND name='sys_oper_log'",
                ))
                .await?;
            !rows.is_empty()
        }
        DatabaseBackend::Postgres => {
            let rows = db
                .query_all_raw(Statement::from_string(
                    backend,
                    "SELECT 1 FROM information_schema.tables WHERE table_name='sys_oper_log' AND table_schema=current_schema()",
                ))
                .await?;
            !rows.is_empty()
        }
        DatabaseBackend::MySql => {
            let rows = db
                .query_all_raw(Statement::from_string(
                    backend,
                    "SELECT 1 FROM information_schema.tables WHERE table_name='sys_oper_log' AND table_schema=DATABASE()",
                ))
                .await?;
            !rows.is_empty()
        }
        _ => unreachable!("unknown backend"),
    };

    if !table_exists {
        tracing::info!("sys_oper_log 表尚未创建，跳过 oper_diff 列检查（由 migration 负责建表）");
        return Ok(());
    }

    // 2) 列是否存在
    let has_column = match backend {
        DatabaseBackend::Sqlite => {
            let rows = db
                .query_all_raw(Statement::from_string(
                    backend,
                    "PRAGMA table_info(sys_oper_log)",
                ))
                .await?;
            rows.iter().any(|row| {
                row.try_get::<String>("", "name")
                    .map(|n| n.eq_ignore_ascii_case("oper_diff"))
                    .unwrap_or(false)
            })
        }
        DatabaseBackend::Postgres => {
            let rows = db
                .query_all_raw(Statement::from_string(
                    backend,
                    "SELECT 1 FROM information_schema.columns WHERE table_name='sys_oper_log' AND column_name='oper_diff' AND table_schema=current_schema() LIMIT 1",
                ))
                .await?;
            !rows.is_empty()
        }
        DatabaseBackend::MySql => {
            let rows = db
                .query_all_raw(Statement::from_string(
                    backend,
                    "SELECT 1 FROM information_schema.columns WHERE table_name='sys_oper_log' AND column_name='oper_diff' AND table_schema=DATABASE() LIMIT 1",
                ))
                .await?;
            !rows.is_empty()
        }
        _ => unreachable!("unknown backend"),
    };

    if !has_column {
        tracing::info!("sys_oper_log 缺少 oper_diff 列，执行幂等 ALTER 添加");
        db.execute_raw(Statement::from_string(
            backend,
            "ALTER TABLE sys_oper_log ADD COLUMN oper_diff TEXT",
        ))
        .await?;
    } else {
        tracing::info!("sys_oper_log.oper_diff 列已存在，无需 ALTER");
    }

    Ok(())
}

/// 幂等确保 DP-01 数据权限规则两表存在（§5.53，等价迁移 `m20261006_000002`）
///
/// 为何必须有本兜底：embedded/存量库按架构约定**不跑 `Migrator::up`**，而规则引擎
/// 管理端（/system/dataRule）与求值入口已接线——缺此兜底则存量库访问规则页/带规则
/// 查询全链路 `no such table: sys_data_rule`（500）。
///
/// 幂等：`CREATE TABLE IF NOT EXISTS` 三方言合法；菜单走 INSERT OR IGNORE/等价子句。
pub(crate) async fn ensure_data_rule_tables(db: &DatabaseConnection) -> anyhow::Result<()> {
    let backend = db.get_database_backend();
    let pk = match backend {
        DatabaseBackend::Sqlite => "rule_id INTEGER PRIMARY KEY AUTOINCREMENT",
        DatabaseBackend::MySql => "rule_id BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY",
        DatabaseBackend::Postgres => "rule_id BIGSERIAL PRIMARY KEY",
        _ => unreachable!("unknown backend"),
    };
    let create_rule = format!(
        "CREATE TABLE IF NOT EXISTS sys_data_rule (
            {pk},
            rule_name VARCHAR(64) NOT NULL,
            table_name VARCHAR(64) NOT NULL,
            field_name VARCHAR(64) NOT NULL,
            op VARCHAR(8) NOT NULL,
            value_type VARCHAR(24) NOT NULL,
            rule_value VARCHAR(255) NULL,
            status VARCHAR(1) NOT NULL DEFAULT '0',
            del_flag VARCHAR(1) NOT NULL DEFAULT '0',
            tenant_id BIGINT NOT NULL DEFAULT 0,
            create_by VARCHAR(64) NULL,
            create_time {ts} NULL,
            update_by VARCHAR(64) NULL,
            update_time {ts} NULL,
            remark VARCHAR(255) NULL
        )",
        ts = "DATETIME"
    );
    db.execute_raw(Statement::from_string(backend, create_rule))
        .await?;
    db.execute_raw(Statement::from_string(
        backend,
        "CREATE TABLE IF NOT EXISTS sys_role_data_rule (
            role_id BIGINT NOT NULL,
            rule_id BIGINT NOT NULL,
            PRIMARY KEY (role_id, rule_id)
        )"
        .to_string(),
    ))
    .await?;

    // 菜单幂等种子（与迁移 m20261006_000002 等价口径）
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
    let menu_rows = format!(
        "(4117, '数据权限规则', 1, 15, 'dataRule', 'system/dataRule/index', '', '', '1', '0', 'C', '0', '0', 'system:dataRule:list', 'rule', 'admin', {now_expr}, 'DP-01 结构化数据权限规则', '0'), \
         (4118, '规则新增', 4117, 1, '#', '', '', '', '1', '0', 'F', '0', '0', 'system:dataRule:add', '#', 'admin', {now_expr}, '', '0'), \
         (4119, '规则编辑', 4117, 2, '#', '', '', '', '1', '0', 'F', '0', '0', 'system:dataRule:edit', '#', 'admin', {now_expr}, '', '0'), \
         (4122, '规则删除', 4117, 3, '#', '', '', '', '1', '0', 'F', '0', '0', 'system:dataRule:remove', '#', 'admin', {now_expr}, '', '0')"
    );
    db.execute_raw(Statement::from_string(
        backend,
        format!("{insert_prefix}{menu_cols} VALUES {menu_rows}{insert_suffix}"),
    ))
    .await?;
    // §5.57 token 观测列兜底（等价迁移 m20261006_000003）：存量库 ai_chat_history
    // 幂等补三列（SQLite 无 IF NOT EXISTS——按错误忽略，列已存在属正常情况）
    for col in ["prompt_tokens", "completion_tokens", "total_tokens"] {
        let ddl = format!("ALTER TABLE ai_chat_history ADD COLUMN {col} BIGINT NULL");
        if let Err(e) = db.execute_raw(Statement::from_string(backend, ddl)).await {
            tracing::debug!("ai_chat_history.{col} 列补建跳过（可能已存在）: {}", e);
        }
    }
    tracing::info!("data_rule 表/菜单已就绪（幂等确保完成）");
    Ok(())
}

/// 幂等确保 `sys_pat` 表存在（Tier-S #3：个人访问令牌）
///
/// `CREATE TABLE IF NOT EXISTS` 在 SQLite/PostgreSQL/MySQL 三方言下均合法且幂等。
/// 索引创建：SQLite/PostgreSQL 支持 `CREATE INDEX IF NOT EXISTS`，直接执行；MySQL 不支持该子句，
/// 交由 migration（seaorm `if_not_exists`）在支持 MySQL 的部署中补齐，此处对 MySQL 跳过。
/// 主键 `pat_id` 用 VARCHAR 由应用生成 uuid，规避自增列跨方言差异。
pub(crate) async fn ensure_sys_pat_table(db: &DatabaseConnection) -> anyhow::Result<()> {
    let backend = db.get_database_backend();
    let dt = match backend {
        DatabaseBackend::Postgres => "TIMESTAMP",
        _ => "DATETIME",
    };
    let create_sql = format!(
        "CREATE TABLE IF NOT EXISTS sys_pat (
            pat_id       VARCHAR(64) NOT NULL PRIMARY KEY,
            user_id      BIGINT NOT NULL,
            name         VARCHAR(100) NOT NULL,
            token_hash   VARCHAR(64) NOT NULL,
            token_prefix VARCHAR(24) NOT NULL,
            scopes       TEXT NOT NULL,
            status       VARCHAR(1) NOT NULL DEFAULT '0',
            expires_at   {dt} NULL,
            last_used_at {dt} NULL,
            create_by    VARCHAR(64) DEFAULT '',
            create_time  {dt} NULL,
            update_time  {dt} NULL
        )"
    );
    db.execute_raw(Statement::from_string(backend, create_sql))
        .await?;

    if !matches!(backend, DatabaseBackend::MySql) {
        // token_hash 唯一索引 + user_id 普通索引（SQLite/PostgreSQL 支持 IF NOT EXISTS）
        for ddl in [
            "CREATE UNIQUE INDEX IF NOT EXISTS uk_sys_pat_token_hash ON sys_pat(token_hash)",
            "CREATE INDEX IF NOT EXISTS idx_sys_pat_user_id ON sys_pat(user_id)",
        ] {
            // 并发/已存在时忽略失败（表与索引已由 migration 建好属正常情况）
            if let Err(e) = db
                .execute_raw(Statement::from_string(backend, ddl.to_string()))
                .await
            {
                tracing::debug!("sys_pat 索引创建跳过（可能已存在）: {}", e);
            }
        }
    }

    tracing::info!("sys_pat 表已就绪（幂等确保完成）");
    Ok(())
}

/// 台账（能力位 `auth.webauthn`，存量库兜底，等价迁移 `m20260927_000002`）：
/// WebAuthn / Passkey 凭据表 `sys_user_credential`。
///
/// 为何必须有本兜底：embedded/存量库按架构约定**不跑 `Migrator::up`**，而实体已声明该表
/// ⇒ 缺此兜底则凭据查询/写入全链报 `no such table: sys_user_credential`（500），
/// 能力位开启后自助绑定与 passkey 登录不可用（假功能）。
///
/// 幂等：`CREATE TABLE IF NOT EXISTS` 三方言均合法；主键按方言声明自增（SQLite
/// `INTEGER PRIMARY KEY AUTOINCREMENT` / MySQL `BIGINT AUTO_INCREMENT` / PG `BIGSERIAL`）。
/// 索引：SQLite/PG 支持 `CREATE INDEX IF NOT EXISTS`，MySQL 不支持该子句，交由 migration 补齐。
pub(crate) async fn ensure_sys_user_credential_table(
    db: &DatabaseConnection,
) -> anyhow::Result<()> {
    let backend = db.get_database_backend();
    let pk = match backend {
        DatabaseBackend::Sqlite => "cred_id INTEGER PRIMARY KEY AUTOINCREMENT",
        DatabaseBackend::MySql => "cred_id BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY",
        DatabaseBackend::Postgres => "cred_id BIGSERIAL PRIMARY KEY",
        _ => unreachable!("unknown backend"),
    };
    let dt = match backend {
        DatabaseBackend::Postgres => "TIMESTAMP",
        _ => "DATETIME",
    };
    let create_sql = format!(
        "CREATE TABLE IF NOT EXISTS sys_user_credential (
            {pk},
            user_id        BIGINT NOT NULL,
            tenant_id      BIGINT NOT NULL DEFAULT 0,
            credential_id  VARCHAR(512) NOT NULL,
            public_key     TEXT NOT NULL,
            name           VARCHAR(255) NOT NULL,
            sign_count     BIGINT NOT NULL DEFAULT 0,
            last_used_at   {dt} NULL,
            create_time    {dt} NULL,
            del_flag       VARCHAR(1) NOT NULL DEFAULT '0'
        )"
    );
    db.execute_raw(Statement::from_string(backend, create_sql))
        .await?;

    if !matches!(backend, DatabaseBackend::MySql) {
        for ddl in [
            "CREATE UNIQUE INDEX IF NOT EXISTS uk_sys_user_credential_credential_id ON sys_user_credential(credential_id)",
            "CREATE INDEX IF NOT EXISTS idx_sys_user_credential_user_id ON sys_user_credential(user_id)",
        ] {
            // 并发/已存在时忽略失败（表与索引已由 migration 建好属正常情况）
            if let Err(e) = db
                .execute_raw(Statement::from_string(backend, ddl.to_string()))
                .await
            {
                tracing::debug!("sys_user_credential 索引创建跳过（可能已存在）: {}", e);
            }
        }
    }

    tracing::info!("sys_user_credential 表已就绪（幂等确保完成）");
    Ok(())
}

/// 前端错误日志 device_type 列兜底（FCP-011，与迁移
/// m20260928_000002_frontend_error_device_type 等价，全幂等）：
/// `sys_frontend_error` 存量库补 `device_type VARCHAR(16) NULL`。
/// 缺此兜底时（优先级最高的一项）：实体 SELECT 带 device_type ⇒
/// /monitor/frontendError 列表/上报全站 500。
pub(crate) async fn ensure_frontend_error_device_type(
    db: &DatabaseConnection,
) -> anyhow::Result<()> {
    let backend = db.get_database_backend();
    if sso_table_exists(db, "sys_frontend_error").await?
        && !sso_has_column(db, "sys_frontend_error", "device_type").await?
    {
        db.execute_raw(Statement::from_string(
            backend,
            "ALTER TABLE sys_frontend_error ADD COLUMN device_type VARCHAR(16) NULL",
        ))
        .await?;
        tracing::info!("sys_frontend_error.device_type 列已补建（存量库兜底，FCP-011）");
    }
    Ok(())
}

/// E2-a 性能索引兜底（等价迁移 `m20261002_000001_perf_indexes` + `m20261004_000001_alert_rule_index`，幂等）：
/// - `idx_flow_doc_tenant ON flow_demo_doc (tenant_id)`
/// - `idx_web_hook_log_status ON sys_web_hook_log (status)`
/// - `idx_web_hook_log_event_type ON sys_web_hook_log (event_type)`
/// - `idx_alert_rule_enabled ON sys_alert_rule (enabled)`
///
/// 为何必须有本兜底：embedded/存量库按架构约定**不跑 `Migrator::up`**，缺索引仅影响
/// 查询性能（列表分页/过滤全表扫描），故创建失败只告警不阻断（与 Phase 3 索引兜底
/// 同策略）。表不存在时（如对应模块建表迁移未应用过的极老存量库）跳过对应索引。
/// 方言：经 `ensure_tenant_index` 收敛——SQLite/PG 直接 `CREATE INDEX IF NOT EXISTS`，
/// MySQL 先查 information_schema 判存在，缺失才建。
pub(crate) async fn ensure_perf_indexes(db: &DatabaseConnection) -> anyhow::Result<()> {
    let targets: &[(&str, &str, &str)] = &[
        ("flow_demo_doc", "idx_flow_doc_tenant", "tenant_id"),
        ("sys_web_hook_log", "idx_web_hook_log_status", "status"),
        (
            "sys_web_hook_log",
            "idx_web_hook_log_event_type",
            "event_type",
        ),
        ("sys_alert_rule", "idx_alert_rule_enabled", "enabled"),
    ];
    for (table, index, cols) in targets {
        if !sso_table_exists(db, table).await? {
            tracing::debug!("性能索引 {index} 跳过（表 {table} 不存在）");
            continue;
        }
        if let Err(e) = ensure_tenant_index(db, table, index, cols, false).await {
            tracing::warn!("性能索引 {index} 创建失败（不阻断启动，请人工核查）: {e}");
        }
    }
    tracing::info!("性能索引兜底完成（flow_demo_doc / sys_web_hook_log / sys_alert_rule，幂等）");
    Ok(())
}

/// 台账 P0-2（存量库兜底，等价迁移 m20260926_000001）：`sys_role.is_system` 列 +
/// 平台 admin 角色标记。
///
/// 超管判定已改为 `is_system && tenant_id == 0`（`entity/sys_role.rs`），实体 SELECT
/// 会带 `is_system` 列 ⇒ 存量库缺列时角色/菜单/权限接口全站 500。
/// 回填为**不变量**（每次启动收敛）：平台租户（tid=0）的 `admin` 角色必须为系统角色。
pub(crate) async fn ensure_role_is_system_column(db: &DatabaseConnection) -> anyhow::Result<()> {
    if !sso_table_exists(db, "sys_role").await? {
        return Ok(());
    }
    let backend = db.get_database_backend();
    // boolean 字面量按方言书写：PG 不接受 0/1 作为 boolean 默认值
    let (false_lit, true_lit) = if backend == DatabaseBackend::Postgres {
        ("FALSE", "TRUE")
    } else {
        ("0", "1")
    };
    if !sso_has_column(db, "sys_role", "is_system").await? {
        db.execute_raw(Statement::from_string(
            backend,
            format!(
                "ALTER TABLE sys_role ADD COLUMN is_system BOOLEAN NOT NULL DEFAULT {false_lit}"
            ),
        ))
        .await?;
        tracing::info!("sys_role.is_system 列已补建（台账 P0-2 存量库兜底）");
    }
    let updated = db
        .execute_raw(Statement::from_string(
            backend,
            format!(
                "UPDATE sys_role SET is_system = {true_lit} \
                 WHERE tenant_id = 0 AND role_key = 'admin' AND del_flag = '0'"
            ),
        ))
        .await?;
    if updated.rows_affected() > 0 {
        tracing::info!(
            rows = updated.rows_affected(),
            "平台 admin 角色已标记为系统角色（is_system=1）"
        );
    }
    Ok(())
}

/// 台账 F-8（存量库兜底，等价迁移 m20260926_000003）：`sys_logininfor.user_id` 列 +
/// 索引 + 按 user_name 精确回填（未匹配置 0；user_name 全局唯一 ⇒ 回填无歧义）。
///
/// 列定义 `BIGINT NOT NULL DEFAULT 0`：0 为"无对应用户"的唯一缺省表示（与 `tenant_id` 同款）。
/// 回填仅在**列刚补建**时执行一次（迁移库已回填；避免每次启动全表扫描）。
pub(crate) async fn ensure_logininfor_user_id_column(
    db: &DatabaseConnection,
) -> anyhow::Result<()> {
    if !sso_table_exists(db, "sys_logininfor").await? {
        return Ok(());
    }
    let backend = db.get_database_backend();
    if sso_has_column(db, "sys_logininfor", "user_id").await? {
        return Ok(());
    }
    db.execute_raw(Statement::from_string(
        backend,
        "ALTER TABLE sys_logininfor ADD COLUMN user_id BIGINT NOT NULL DEFAULT 0".to_string(),
    ))
    .await?;
    if let Err(e) = db
        .execute_raw(Statement::from_string(
            backend,
            "CREATE INDEX idx_sys_logininfor_user ON sys_logininfor (user_id)".to_string(),
        ))
        .await
    {
        // 索引已存在（MySQL 1061 / PG 42P07 / SQLite already exists）不影响后续
        tracing::warn!("sys_logininfor user_id 索引创建跳过: {}", e);
    }
    let updated = db
        .execute_raw(Statement::from_string(
            backend,
            "UPDATE sys_logininfor SET user_id = COALESCE(\
               (SELECT MIN(u.user_id) FROM sys_user u WHERE u.user_name = sys_logininfor.user_name)\
               , 0) WHERE user_name IS NOT NULL"
                .to_string(),
        ))
        .await?;
    tracing::info!(
        rows = updated.rows_affected(),
        "sys_logininfor.user_id 列已补建并完成存量回填（台账 F-8 存量库兜底）"
    );
    Ok(())
}

/// G-09（存量库兜底，等价迁移 `m20261007_000001`）：`sys_job_log.duration_ms`
/// 独立耗时列——定时任务运行统计报表的聚合基础。
///
/// 为何必须有本兜底：embedded/存量库按架构约定**不跑 `Migrator::up`**，而实体已声明该列
/// ⇒ 缺此兜底则调度日志写入/查询全链报 `no such column: duration_ms`（500）。
/// 幂等：列已存在或表不存在时安全返回；存量行留 `NULL` = 无耗时数据，报表聚合跳过。
pub(crate) async fn ensure_job_log_duration_column(db: &DatabaseConnection) -> anyhow::Result<()> {
    if !sso_table_exists(db, "sys_job_log").await? {
        return Ok(());
    }
    if sso_has_column(db, "sys_job_log", "duration_ms").await? {
        return Ok(());
    }
    db.execute_raw(Statement::from_string(
        db.get_database_backend(),
        "ALTER TABLE sys_job_log ADD COLUMN duration_ms BIGINT NULL".to_string(),
    ))
    .await?;
    tracing::info!("sys_job_log.duration_ms 列已补建（G-09 存量库兜底）");
    Ok(())
}

/// G-16（平台默认消息模板 seed，幂等；UNIQUE(template_code) 冲突即忽略）
///
/// - `notice_email`：通知公告邮件正文骨架（channel_code='email' 仅表达用途；
///   公告邮件有自带的用户枚举/偏好过滤/批量投递链路，不经过 send() 的渠道查找）。
///   变量 {{title}}/{{content}}/{{footer}} 均由调用方 html_escape 后注入。
/// - `report_push`：报表订阅站内信模板（site 渠道，经 SysMsgService::send 统一
///   投递内核——尊重用户消息偏好/免打扰 + 失败进重试链）。
///
/// 表不存在（极旧存量库）时跳过；与代码侧"模板缺失回落内置默认"双保险。
pub(crate) async fn ensure_msg_template_seeds(db: &DatabaseConnection) -> anyhow::Result<()> {
    if !sso_table_exists(db, "sys_msg_template").await? {
        return Ok(());
    }
    let now = flow_now(db);
    // 公告邮件正文骨架（与 sys_notice_service 内置回落内容保持一致）
    let notice_email_content = "<div style=\"font-family: Arial, sans-serif; line-height: 1.6; max-width: 800px; margin: 0 auto; padding: 20px;\">\
<h2 style=\"color: #409EFF; border-bottom: 2px solid #409EFF; padding-bottom: 10px;\">{{title}}</h2>\
<div style=\"margin: 20px 0;\">{{content}}</div>\
<hr style=\"border: none; border-top: 1px solid #ddd; margin: 20px 0;\"/>\
<p style=\"color: #999; font-size: 12px;\">{{footer}}</p>\
</div>";
    let seeds: &[(&str, &str, &str, &str, &str, &str)] = &[
        (
            "通知公告邮件",
            "notice_email",
            "email",
            "{{title}}",
            notice_email_content,
            "G-16 公告邮件正文骨架（变量已由后端转义）",
        ),
        (
            "报表订阅推送",
            "report_push",
            "site",
            "报表推送：{{report_name}}",
            "{{content}}",
            "G-16 报表订阅站内信模板（site 渠道统一投递）",
        ),
    ];
    for (name, code, channel, subject, content, remark) in seeds {
        flow_insert(
            db,
            &format!(
                "sys_msg_template (template_name, template_code, channel_code, template_subject, template_content, status, remark, create_by, create_time, del_flag) VALUES \
                 ('{name}', '{code}', '{channel}', '{subject}', '{content}', '0', '{remark}', 'admin', {now}, '0')"
            ),
        )
        .await?;
    }
    tracing::info!("平台默认消息模板 seed 完成（notice_email / report_push，G-16）");
    Ok(())
}

/// 台账（G-07 扩展，存量库兜底，等价迁移 `m20261007_000007`）：
/// `sys_msg_template.sms_template_code`（云厂商短信模板 code）与
/// `sys_msg_send_log.sms_params`（原始渲染参数 JSON 快照，重试还原用）。
///
/// 为何必须有本兜底：embedded/存量库按架构约定**不跑 `Migrator::up`**，而实体已带
/// 新字段 ⇒ 缺此兜底则模板/发送日志读写全链 500。幂等：has_column 守卫逐列判定。
pub(crate) async fn ensure_sms_cloud_columns(db: &DatabaseConnection) -> anyhow::Result<()> {
    let adds: [(&str, &str, &str); 2] = [
        ("sys_msg_template", "sms_template_code", "VARCHAR(64) NULL"),
        ("sys_msg_send_log", "sms_params", "TEXT NULL"),
    ];
    for (table, col, ddl) in adds {
        if !sso_table_exists(db, table).await? {
            continue;
        }
        if sso_has_column(db, table, col).await? {
            continue;
        }
        db.execute_raw(Statement::from_string(
            db.get_database_backend(),
            format!("ALTER TABLE {table} ADD COLUMN {col} {ddl}"),
        ))
        .await?;
        tracing::info!("{table}.{col} 已补列（G-07 扩展存量库兜底）");
    }
    Ok(())
}

/// 台账（第八批，存量库兜底，等价迁移 `m20260926_000009`）：代码生成列元数据的
/// **Java 遗留命名 → Rust 命名** —— `gen_table_column.java_type/java_field`
/// → `rust_type/rust_field`。
///
/// 为何必须有本兜底：embedded/存量库按架构约定**不跑 `Migrator::up`**，而实体已改用新列名
/// ⇒ 缺此兜底则 gen 列表/详情/预览/导入全链报 `no such column: rust_type`（500）。
/// 幂等：仅当**旧列存在且新列不存在**时执行 `RENAME COLUMN`；表不存在时安全返回。
pub(crate) async fn ensure_gen_column_rust_naming(db: &DatabaseConnection) -> anyhow::Result<()> {
    if !sso_table_exists(db, "gen_table_column").await? {
        return Ok(());
    }
    let backend = db.get_database_backend();
    for (old, new) in [("java_type", "rust_type"), ("java_field", "rust_field")] {
        if !sso_has_column(db, "gen_table_column", old).await?
            || sso_has_column(db, "gen_table_column", new).await?
        {
            continue;
        }
        db.execute_raw(Statement::from_string(
            backend,
            format!("ALTER TABLE gen_table_column RENAME COLUMN {old} TO {new}"),
        ))
        .await?;
        tracing::info!("gen_table_column.{old} 已重命名为 {new}（台账第八批 Java 遗留命名收口）");
    }
    Ok(())
}

/// 台账（能力位批次 0，存量库兜底，等价迁移 `m20260926_000010`）：
/// `sys_tenant_package.features` 列（租户套餐能力位 JSON）。
///
/// 为何必须有本兜底：embedded/存量库按架构约定**不跑 `Migrator::up`**，而实体已带
/// `features` 字段 ⇒ 缺此兜底则套餐列表/详情/新建/编辑全链报 `no such column: features`（500）。
/// 列可空（NULL = 全默认 = **全部关闭**），**不回填任何值**（关闭态即安全态）。
pub(crate) async fn ensure_tenant_package_features(db: &DatabaseConnection) -> anyhow::Result<()> {
    if !sso_table_exists(db, "sys_tenant_package").await? {
        return Ok(());
    }
    if sso_has_column(db, "sys_tenant_package", "features").await? {
        return Ok(());
    }
    db.execute_raw(Statement::from_string(
        db.get_database_backend(),
        "ALTER TABLE sys_tenant_package ADD COLUMN features TEXT NULL".to_string(),
    ))
    .await?;
    tracing::info!("sys_tenant_package.features 列已补建（能力位批次 0 存量库兜底）");
    Ok(())
}

use super::*;
