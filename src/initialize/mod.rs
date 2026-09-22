// axum-backend/src/initialize/mod.rs

use crate::config::Settings;
use crate::db;
use crate::logger;
use crate::scheduler::JobScheduler;
use crate::service::IpLocationService;
use crate::state::AppState;
use crate::utils::ip_location::IpLocator;
use sea_orm::{ConnectionTrait, DatabaseBackend, DatabaseConnection, Statement};
use std::sync::Arc;

/// 初始化编排模块
pub struct AppInitializer;

impl AppInitializer {
    /// 执行完整初始化流程，返回 AppState
    pub async fn run(config_path: &str) -> anyhow::Result<Arc<AppState>> {
        // 1. 加载配置（含 .env 环境变量覆盖）
        let settings = Arc::new(Settings::from_file(config_path)?);

        // 2. 初始化日志
        logger::init_logger(&settings.log);

        tracing::info!("=== axum-backend 初始化中 ===");

        // 3. 初始化数据库
        let db = db::init_database(&settings.database, settings.log.sql_logging).await?;

        // 3.1 G18：幂等确保 sys_user 含 country_code 列（存量库向后兼容，加列后才不会因实体新字段查询报错）
        ensure_user_country_code_column(&db)
            .await
            .map_err(|e| anyhow::anyhow!("初始化 sys_user.country_code 列失败: {}", e))?;

        // 3.2 P0-2：幂等确保 sys_task 含 operator_id 列（存量库向后兼容）
        // 背景：m20260806_000002_add_task_operator_id 迁移负责全新库建表时带该列，
        // 但 AppInitializer 启动不跑 Migrator::up（避免对已有种子数据的存量库重跑 seed 导致主键冲突），
        // 故存量库需在此幂等补列，否则 /system/task/list 会因缺列报 500。
        ensure_task_operator_id_column(&db)
            .await
            .map_err(|e| anyhow::anyhow!("初始化 sys_task.operator_id 列失败: {}", e))?;

        // 3.3 Tier-S #2：幂等确保 sys_oper_log 含 oper_diff 列（存量库向后兼容）
        // 背景：m20260822_000001_oper_log_diff 迁移负责全新库建表时带该列，但 AppInitializer
        // 启动不跑 Migrator::up，故存量库需在此幂等补列，否则操作日志查询/写入会因缺列报错。
        ensure_oper_log_diff_column(&db)
            .await
            .map_err(|e| anyhow::anyhow!("初始化 sys_oper_log.oper_diff 列失败: {}", e))?;

        // 3.4 Tier-S #3：幂等确保 sys_pat 表存在（存量库向后兼容）
        // 背景：m20260823_000001_sys_pat 迁移负责全新库建表，但 AppInitializer 启动不跑
        // Migrator::up（避免对已有种子数据的存量库重跑 seed 导致主键冲突），故存量库需在此
        // 幂等建表，否则 PAT 鉴权查库与令牌管理接口会因缺表报错。
        ensure_sys_pat_table(&db)
            .await
            .map_err(|e| anyhow::anyhow!("初始化 sys_pat 表失败: {}", e))?;

        // 3.5 Tier-S #3：幂等确保 PAT 管理菜单存在（存量库启动不跑 Migrator::up，
        // 与迁移 m20260823_000001_sys_pat 等价地登记 sys_menu，使 /monitor/pat 页面可进入）。
        ensure_sys_pat_menu(&db)
            .await
            .map_err(|e| anyhow::anyhow!("初始化 sys_pat 管理菜单失败: {}", e))?;

        // 4. 初始化 Redis
        let redis = db::init_redis(&settings.redis).await?;

        // 5. 提前创建 IP 归属地查询器和 IP 库管理 Service
        // 原因：scheduler 需要在闭包内调用 IpLocationService::update_now，
        // 而 IpLocator 又需要被 AppState 共享，故提前创建后同时注入 scheduler 和 AppState
        // 双库模式：若 xdb_enabled=true 且 xdb 文件存在，加载 xdb（国内 IP 优先查 xdb）
        let ip_locator = Arc::new(IpLocator::new_with_xdb(
            &settings.ip_location.mmdb_path,
            &settings.ip_location.xdb_path,
            settings.ip_location.xdb_enabled,
        ));
        let ip_location_service =
            IpLocationService::new(db.clone(), settings.clone(), ip_locator.clone());

        // 6. 创建调度器并加载任务（注入 ip_location_service 以支持 mmdb_auto_update 内置任务）
        tracing::info!("=== 初始化定时任务调度器 ===");
        let job_scheduler = Arc::new(
            JobScheduler::new(
                db.clone(),
                redis.clone(),
                ip_location_service.clone(),
                settings.clone(),
            )
            .await?,
        );
        // 创建临时 Service 用于 load_from_db（需要 Repository）
        let temp_job_service =
            crate::service::SysJobService::new(db.clone(), job_scheduler.clone());
        if let Err(e) = job_scheduler
            .load_from_db(temp_job_service.job_repo())
            .await
        {
            tracing::warn!("定时任务加载失败（不阻断启动）: {}", e);
        }

        // 7. 构建文件存储后端（F1：local / s3，按 upload.backend 切换）
        let storage: Arc<dyn crate::storage::StorageBackend> =
            crate::storage::new_backend(&settings.upload)
                .map_err(|e| anyhow::anyhow!("存储后端初始化失败: {}", e.message))?;
        tracing::info!("存储后端已启用: {}", storage.kind());

        // 8. 构建 AppState（传入 scheduler + ip_locator + ip_location_service + storage）
        let state = Arc::new(AppState::new(
            db,
            redis,
            settings,
            job_scheduler,
            ip_locator,
            ip_location_service,
            storage,
        ));

        tracing::info!("=== axum-backend 初始化完成 ===");
        Ok(state)
    }
}

/// 幂等确保 `sys_user` 表含 `country_code` 列（方案 D，G18：手机号多地区化向后兼容）
///
/// 实体新增 `country_code` 字段后，存量 SQLite / Postgres / MySQL 数据库若无该列，
/// 查询会因缺列报错。启动初始化时按当前数据库方言检测列是否存在：
/// - 表不存在则跳过（由 migration 负责建表，下次启动再补列）
/// - 列不存在则执行 `ALTER TABLE sys_user ADD COLUMN country_code VARCHAR(8)`
async fn ensure_user_country_code_column(db: &DatabaseConnection) -> anyhow::Result<()> {
    let backend = db.get_database_backend();

    // 1) 表是否存在（避免对尚未建表的空库误执行 ALTER）
    let table_exists = match backend {
        DatabaseBackend::Sqlite => {
            let rows = db
                .query_all(Statement::from_string(
                    backend,
                    "SELECT name FROM sqlite_master WHERE type='table' AND name='sys_user'",
                ))
                .await?;
            !rows.is_empty()
        }
        DatabaseBackend::Postgres => {
            let rows = db
                .query_all(Statement::from_string(
                    backend,
                    "SELECT 1 FROM information_schema.tables WHERE table_name='sys_user' AND table_schema=current_schema()",
                ))
                .await?;
            !rows.is_empty()
        }
        DatabaseBackend::MySql => {
            let rows = db
                .query_all(Statement::from_string(
                    backend,
                    "SELECT 1 FROM information_schema.tables WHERE table_name='sys_user' AND table_schema=DATABASE()",
                ))
                .await?;
            !rows.is_empty()
        }
    };

    if !table_exists {
        tracing::info!("sys_user 表尚未创建，跳过 country_code 列检查（由 migration 负责建表）");
        return Ok(());
    }

    // 2) 列是否存在
    let has_column = match backend {
        DatabaseBackend::Sqlite => {
            let rows = db
                .query_all(Statement::from_string(
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
                .query_all(Statement::from_string(
                    backend,
                    "SELECT 1 FROM information_schema.columns WHERE table_name='sys_user' AND column_name='country_code' AND table_schema=current_schema() LIMIT 1",
                ))
                .await?;
            !rows.is_empty()
        }
        DatabaseBackend::MySql => {
            let rows = db
                .query_all(Statement::from_string(
                    backend,
                    "SELECT 1 FROM information_schema.columns WHERE table_name='sys_user' AND column_name='country_code' AND table_schema=DATABASE() LIMIT 1",
                ))
                .await?;
            !rows.is_empty()
        }
    };

    if !has_column {
        tracing::info!("sys_user 缺少 country_code 列，执行幂等 ALTER 添加");
        db.execute(Statement::from_string(
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
async fn ensure_task_operator_id_column(db: &DatabaseConnection) -> anyhow::Result<()> {
    let backend = db.get_database_backend();

    // 1) 表是否存在（避免对尚未建表的空库误执行 ALTER）
    let table_exists = match backend {
        DatabaseBackend::Sqlite => {
            let rows = db
                .query_all(Statement::from_string(
                    backend,
                    "SELECT name FROM sqlite_master WHERE type='table' AND name='sys_task'",
                ))
                .await?;
            !rows.is_empty()
        }
        DatabaseBackend::Postgres => {
            let rows = db
                .query_all(Statement::from_string(
                    backend,
                    "SELECT 1 FROM information_schema.tables WHERE table_name='sys_task' AND table_schema=current_schema()",
                ))
                .await?;
            !rows.is_empty()
        }
        DatabaseBackend::MySql => {
            let rows = db
                .query_all(Statement::from_string(
                    backend,
                    "SELECT 1 FROM information_schema.tables WHERE table_name='sys_task' AND table_schema=DATABASE()",
                ))
                .await?;
            !rows.is_empty()
        }
    };

    if !table_exists {
        tracing::info!("sys_task 表尚未创建，跳过 operator_id 列检查（由 migration 负责建表）");
        return Ok(());
    }

    // 2) 列是否存在
    let has_column = match backend {
        DatabaseBackend::Sqlite => {
            let rows = db
                .query_all(Statement::from_string(
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
                .query_all(Statement::from_string(
                    backend,
                    "SELECT 1 FROM information_schema.columns WHERE table_name='sys_task' AND column_name='operator_id' AND table_schema=current_schema() LIMIT 1",
                ))
                .await?;
            !rows.is_empty()
        }
        DatabaseBackend::MySql => {
            let rows = db
                .query_all(Statement::from_string(
                    backend,
                    "SELECT 1 FROM information_schema.columns WHERE table_name='sys_task' AND column_name='operator_id' AND table_schema=DATABASE() LIMIT 1",
                ))
                .await?;
            !rows.is_empty()
        }
    };

    if !has_column {
        tracing::info!("sys_task 缺少 operator_id 列，执行幂等 ALTER 添加");
        db.execute(Statement::from_string(
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
async fn ensure_oper_log_diff_column(db: &DatabaseConnection) -> anyhow::Result<()> {
    let backend = db.get_database_backend();

    // 1) 表是否存在（避免对尚未建表的空库误执行 ALTER）
    let table_exists = match backend {
        DatabaseBackend::Sqlite => {
            let rows = db
                .query_all(Statement::from_string(
                    backend,
                    "SELECT name FROM sqlite_master WHERE type='table' AND name='sys_oper_log'",
                ))
                .await?;
            !rows.is_empty()
        }
        DatabaseBackend::Postgres => {
            let rows = db
                .query_all(Statement::from_string(
                    backend,
                    "SELECT 1 FROM information_schema.tables WHERE table_name='sys_oper_log' AND table_schema=current_schema()",
                ))
                .await?;
            !rows.is_empty()
        }
        DatabaseBackend::MySql => {
            let rows = db
                .query_all(Statement::from_string(
                    backend,
                    "SELECT 1 FROM information_schema.tables WHERE table_name='sys_oper_log' AND table_schema=DATABASE()",
                ))
                .await?;
            !rows.is_empty()
        }
    };

    if !table_exists {
        tracing::info!("sys_oper_log 表尚未创建，跳过 oper_diff 列检查（由 migration 负责建表）");
        return Ok(());
    }

    // 2) 列是否存在
    let has_column = match backend {
        DatabaseBackend::Sqlite => {
            let rows = db
                .query_all(Statement::from_string(
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
                .query_all(Statement::from_string(
                    backend,
                    "SELECT 1 FROM information_schema.columns WHERE table_name='sys_oper_log' AND column_name='oper_diff' AND table_schema=current_schema() LIMIT 1",
                ))
                .await?;
            !rows.is_empty()
        }
        DatabaseBackend::MySql => {
            let rows = db
                .query_all(Statement::from_string(
                    backend,
                    "SELECT 1 FROM information_schema.columns WHERE table_name='sys_oper_log' AND column_name='oper_diff' AND table_schema=DATABASE() LIMIT 1",
                ))
                .await?;
            !rows.is_empty()
        }
    };

    if !has_column {
        tracing::info!("sys_oper_log 缺少 oper_diff 列，执行幂等 ALTER 添加");
        db.execute(Statement::from_string(
            backend,
            "ALTER TABLE sys_oper_log ADD COLUMN oper_diff TEXT",
        ))
        .await?;
    } else {
        tracing::info!("sys_oper_log.oper_diff 列已存在，无需 ALTER");
    }

    Ok(())
}

/// 幂等确保 `sys_pat` 表存在（Tier-S #3：个人访问令牌）
///
/// `CREATE TABLE IF NOT EXISTS` 在 SQLite/PostgreSQL/MySQL 三方言下均合法且幂等。
/// 索引创建：SQLite/PostgreSQL 支持 `CREATE INDEX IF NOT EXISTS`，直接执行；MySQL 不支持该子句，
/// 交由 migration（seaorm `if_not_exists`）在支持 MySQL 的部署中补齐，此处对 MySQL 跳过。
/// 主键 `pat_id` 用 VARCHAR 由应用生成 uuid，规避自增列跨方言差异。
async fn ensure_sys_pat_table(db: &DatabaseConnection) -> anyhow::Result<()> {
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
    db.execute(Statement::from_string(backend, create_sql))
        .await?;

    if !matches!(backend, DatabaseBackend::MySql) {
        // token_hash 唯一索引 + user_id 普通索引（SQLite/PostgreSQL 支持 IF NOT EXISTS）
        for ddl in [
            "CREATE UNIQUE INDEX IF NOT EXISTS uk_sys_pat_token_hash ON sys_pat(token_hash)",
            "CREATE INDEX IF NOT EXISTS idx_sys_pat_user_id ON sys_pat(user_id)",
        ] {
            // 并发/已存在时忽略失败（表与索引已由 migration 建好属正常情况）
            if let Err(e) = db
                .execute(Statement::from_string(backend, ddl.to_string()))
                .await
            {
                tracing::debug!("sys_pat 索引创建跳过（可能已存在）: {}", e);
            }
        }
    }

    tracing::info!("sys_pat 表已就绪（幂等确保完成）");
    Ok(())
}

/// 读取一条 `SELECT COUNT(*) AS c ...` 的结果（跨方言返回 i64）。
async fn count_scalar(db: &DatabaseConnection, sql: String) -> anyhow::Result<i64> {
    let backend = db.get_database_backend();
    let row = db.query_one(Statement::from_string(backend, sql)).await?;
    match row {
        Some(r) => Ok(r.try_get::<i64>("", "c").unwrap_or(0)),
        None => Ok(0),
    }
}

/// 幂等确保 PAT 管理菜单存在（Tier-S #3）
///
/// 背景同 `ensure_sys_pat_table`：存量库启动不跑 Migrator::up，m20260823_000001_sys_pat
/// 迁移登记的 sys_menu（页 3560 + 按钮 3561）不会落到已有库。此处以等价的检查-后-插入补齐，
/// 使管理员页 /monitor/pat 在存量库上同样可经"系统监控"菜单进入并被 E2E 覆盖。
/// 超管用户可见全部菜单（不依赖 sys_role_menu），role_id=2 的授权仅为与普通角色对齐。
async fn ensure_sys_pat_menu(db: &DatabaseConnection) -> anyhow::Result<()> {
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
    };
    if !db
        .query_all(Statement::from_string(backend, exists_sql))
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
            db.execute(Statement::from_string(
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
            db.execute(Statement::from_string(
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
                db.execute(Statement::from_string(
                    backend,
                    format!("INSERT INTO sys_role_menu (role_id, menu_id) VALUES (2, {mid})"),
                ))
                .await?;
            }
        }
    }
    Ok(())
}
