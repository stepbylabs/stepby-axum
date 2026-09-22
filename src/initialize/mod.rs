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
