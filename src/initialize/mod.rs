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

        // 3.6 v4 加固：幂等确保 SSO 表新列（update_by/del_flag/consented_at/client_name_snapshot）
        // 与存量数据回填（同意时刻/客户端名快照/grant_types 修正/明文 id_token_secret 加密）。
        // 与迁移 m20260923_000001_sso_v4_hardening 等价（启动不跑 Migrator::up 的存量库兜底）。
        ensure_sso_v4_columns(&db)
            .await
            .map_err(|e| anyhow::anyhow!("初始化 SSO v4 列失败: {}", e))?;

        // 3.7 v4 §1.3：SSO 启动自检（issuer https、client_id 与平台 JWT 命名空间碰撞告警）。
        // 仅告警不阻断（存量部署允许先启动后整改），新客户端已由 add_client 硬校验拦截。
        sso_startup_self_check(&db, &settings).await;

        // 4. 初始化 Redis
        let redis = db::init_redis(&settings.redis).await?;

        // 4.1 v4 §13-F1：历史 JWT 型 SSO 访问令牌一次性转写吊销（幂等，详见函数注释）
        revoke_legacy_sso_at_tokens(&mut redis.clone()).await;

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

/// 幂等检查表是否存在（三方言）
async fn sso_table_exists(db: &DatabaseConnection, table: &str) -> anyhow::Result<bool> {
    let backend = db.get_database_backend();
    let sql = match backend {
        DatabaseBackend::Sqlite => {
            format!("SELECT 1 FROM sqlite_master WHERE type='table' AND name='{table}'")
        }
        DatabaseBackend::Postgres => format!(
            "SELECT 1 FROM information_schema.tables WHERE table_name='{table}' AND table_schema=current_schema() LIMIT 1"
        ),
        DatabaseBackend::MySql => format!(
            "SELECT 1 FROM information_schema.tables WHERE table_name='{table}' AND table_schema=DATABASE() LIMIT 1"
        ),
    };
    Ok(!db
        .query_all(Statement::from_string(backend, sql))
        .await?
        .is_empty())
}

/// 幂等检查列是否存在（三方言）
async fn sso_has_column(
    db: &DatabaseConnection,
    table: &str,
    column: &str,
) -> anyhow::Result<bool> {
    let backend = db.get_database_backend();
    let rows = match backend {
        DatabaseBackend::Sqlite => {
            db.query_all(Statement::from_string(
                backend,
                format!("PRAGMA table_info({table})"),
            ))
            .await?
        }
        _ => {
            let schema = if backend == DatabaseBackend::Postgres {
                "table_schema=current_schema()"
            } else {
                "table_schema=DATABASE()"
            };
            db.query_all(Statement::from_string(
                backend,
                format!("SELECT 1 FROM information_schema.columns WHERE table_name='{table}' AND column_name='{column}' AND {schema} LIMIT 1"),
            ))
            .await?
        }
    };
    if backend == DatabaseBackend::Sqlite {
        Ok(rows.iter().any(|row| {
            row.try_get::<String>("", "name")
                .map(|n| n.eq_ignore_ascii_case(column))
                .unwrap_or(false)
        }))
    } else {
        Ok(!rows.is_empty())
    }
}

/// v4 加固：幂等确保 SSO 表新列与存量数据回填（等价 m20260923_000001_sso_v4_hardening）
///
/// - sys_oauth_client：+ update_by / + del_flag（客户端软删，v2-K7/P1-5）
/// - sys_oauth_consent：auth_time → consented_at 更名（v4-R4 语义修正）、
///   + client_name_snapshot（v4-R6 名称快照）、+ del_flag（撤销=软删，v2-I7）
/// - 存量回填：consented_at ← create_time；client_name_snapshot ← 当前客户端名；
///   grant_types 去除未实现的 refresh_token（v4 §1.2）
/// - 存量明文 id_token_secret 以 CONFIG_ENC_KEY 加密（v3-P1'-4，读到一条加密一条）
async fn ensure_sso_v4_columns(db: &DatabaseConnection) -> anyhow::Result<()> {
    if !sso_table_exists(db, "sys_oauth_client").await?
        || !sso_table_exists(db, "sys_oauth_consent").await?
    {
        tracing::info!("SSO 表尚未创建，跳过 v4 列检查（由 migration 负责建表）");
        return Ok(());
    }

    // ---- sys_oauth_client ----
    if !sso_has_column(db, "sys_oauth_client", "update_by").await? {
        db.execute(Statement::from_string(
            db.get_database_backend(),
            "ALTER TABLE sys_oauth_client ADD COLUMN update_by VARCHAR(64) DEFAULT ''",
        ))
        .await?;
    }
    if !sso_has_column(db, "sys_oauth_client", "del_flag").await? {
        db.execute(Statement::from_string(
            db.get_database_backend(),
            "ALTER TABLE sys_oauth_client ADD COLUMN del_flag VARCHAR(1) NOT NULL DEFAULT '0'",
        ))
        .await?;
    }

    // ---- sys_oauth_consent：auth_time → consented_at ----
    let has_consented_at = sso_has_column(db, "sys_oauth_consent", "consented_at").await?;
    let has_auth_time = sso_has_column(db, "sys_oauth_consent", "auth_time").await?;
    if !has_consented_at && has_auth_time {
        db.execute(Statement::from_string(
            db.get_database_backend(),
            "ALTER TABLE sys_oauth_consent RENAME COLUMN auth_time TO consented_at",
        ))
        .await?;
        tracing::info!("sys_oauth_consent.auth_time 已更名为 consented_at（v4-R4）");
    } else if !has_consented_at && !has_auth_time {
        // 极旧结构缺列：直接补（无可迁移数据）
        db.execute(Statement::from_string(
            db.get_database_backend(),
            "ALTER TABLE sys_oauth_consent ADD COLUMN consented_at DATETIME",
        ))
        .await?;
    }
    if !sso_has_column(db, "sys_oauth_consent", "client_name_snapshot").await? {
        db.execute(Statement::from_string(
            db.get_database_backend(),
            "ALTER TABLE sys_oauth_consent ADD COLUMN client_name_snapshot VARCHAR(128) NOT NULL DEFAULT ''",
        ))
        .await?;
    }
    if !sso_has_column(db, "sys_oauth_consent", "del_flag").await? {
        db.execute(Statement::from_string(
            db.get_database_backend(),
            "ALTER TABLE sys_oauth_consent ADD COLUMN del_flag VARCHAR(1) NOT NULL DEFAULT '0'",
        ))
        .await?;
    }

    // ---- 存量回填 ----
    db.execute(Statement::from_string(
        db.get_database_backend(),
        "UPDATE sys_oauth_consent SET consented_at = create_time WHERE consented_at IS NULL",
    ))
    .await?;
    db.execute(Statement::from_string(
        db.get_database_backend(),
        "UPDATE sys_oauth_consent SET client_name_snapshot = COALESCE(\
            (SELECT c.client_name FROM sys_oauth_client c WHERE c.client_id = sys_oauth_consent.client_id), '') \
         WHERE client_name_snapshot = ''",
    ))
    .await?;
    db.execute(Statement::from_string(
        db.get_database_backend(),
        "UPDATE sys_oauth_client SET grant_types = '[\"authorization_code\"]' \
         WHERE grant_types LIKE '%refresh_token%'",
    ))
    .await?;

    // ---- 存量明文 id_token_secret 加密（fail-open：主密钥未配置时跳过，留待配置后回填）----
    let backend = db.get_database_backend();
    let rows = db
        .query_all(Statement::from_string(
            backend,
            "SELECT sso_client_id, id_token_secret FROM sys_oauth_client \
             WHERE id_token_secret NOT LIKE 'enc:%' AND id_token_secret != ''",
        ))
        .await?;
    if rows.is_empty() {
        return Ok(());
    }
    let enc_key = std::env::var("CONFIG_ENC_KEY").unwrap_or_default();
    if enc_key.is_empty() {
        tracing::warn!(
            "检测到 {} 条明文 id_token_secret，但 CONFIG_ENC_KEY 未配置，跳过加密（fail-open，与配置层策略一致）",
            rows.len()
        );
        return Ok(());
    }
    let mut encrypted = 0usize;
    let (ph_enc, ph_pk) = if backend == DatabaseBackend::Postgres {
        ("$1", "$2")
    } else {
        ("?", "?")
    };
    for row in rows {
        let Ok(pk) = row.try_get::<i64>("", "sso_client_id") else {
            continue;
        };
        let Ok(plain) = row.try_get::<String>("", "id_token_secret") else {
            continue;
        };
        match crate::utils::crypto::encrypt_config_value(&plain, &enc_key) {
            Ok(enc) => {
                db.execute(Statement::from_sql_and_values(
                    backend,
                    format!(
                        "UPDATE sys_oauth_client SET id_token_secret = {ph_enc} WHERE sso_client_id = {ph_pk}"
                    ),
                    [enc.into(), pk.into()],
                ))
                .await?;
                encrypted += 1;
            }
            Err(e) => tracing::error!("id_token_secret 回填加密失败 sso_client_id={pk}: {e}"),
        }
    }
    if encrypted > 0 {
        tracing::info!("已加密存量明文 id_token_secret {encrypted} 条（v3-P1'-4）");
    }
    Ok(())
}

/// v4 §1.3 / §10：SSO 启动自检（仅告警，不阻断启动）
///
/// 1. SSO 启用时 issuer 必须为 https（本机回环豁免，validate_secrets 已硬校验，此处兜底告警）；
/// 2. 存量 client_id 与平台 JWT 命名空间（audience/issuer）碰撞 → 告警（新客户端已被
///    add_client 保留字校验拦截，存量只提示管理员整改）。
async fn sso_startup_self_check(db: &DatabaseConnection, settings: &Settings) {
    if !settings.sso.enabled {
        return;
    }
    if !sso_table_exists(db, "sys_oauth_client")
        .await
        .unwrap_or(false)
    {
        return;
    }
    let issuer = settings.sso.issuer.trim();
    if issuer.is_empty() {
        tracing::warn!("SSO 启动自检：issuer 未配置（SSO_ISSUER），发现文档将回退请求 base_url");
    }
    let audience = settings.jwt.audience.trim();
    let jwt_issuer = settings.jwt.issuer.trim();
    let backend = db.get_database_backend();
    for reserved in [audience, jwt_issuer] {
        if reserved.is_empty() {
            continue;
        }
        let sql =
            format!("SELECT COUNT(*) AS c FROM sys_oauth_client WHERE client_id = '{reserved}'");
        if let Ok(Some(row)) = db.query_one(Statement::from_string(backend, sql)).await {
            let count = row.try_get::<i64>("", "c").unwrap_or(0);
            if count > 0 {
                tracing::warn!(
                    "SSO 启动自检：存在与平台 JWT 命名空间撞名的 client_id='{reserved}'，请尽快整改（v4 §1.3）"
                );
            }
        }
    }
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

/// v4 §13-F1：历史 JWT 型 SSO 访问令牌一次性转写吊销（幂等）。
///
/// 背景：P0-A 修复前 SSO access_token 是平台 JWT（可横扫全站业务 API），仅靠
/// auth 中间件的「`sso:at:{hash}` 绑定命中 → 拒绝」过渡阻断止血。但绑定 TTL（1h 量级）
/// 短于历史 JWT 本体 TTL（最长 24h）——绑定过期后历史 JWT 失去唯一标识，剩余窗口内
/// 仍可通行业务路由，**止血动作自毁止血范围**。
///
/// 定案（转写而非清除）：首次启动时把存量 `sso:at:*` 绑定转写为
/// `blacklist:{hash}`（TTL = max(剩余TTL, 24h)）并删除原绑定 → 历史 JWT 立即全量吊销。
/// 此刻 A 形态（不透明 AT）尚未签发过任何绑定，SCAN 命中的必为历史 JWT 型，无误伤。
///
/// 幂等：`sso:v4_legacy_at_migrated` SETNX 标记；已标记即跳过。
/// 注意：标记随 Redis 清空丢失时会重跑转写——误伤的仅是活跃不透明 AT（持有方重新
/// 走授权即可，TTL ≤ 1h），可接受；Redis 故障时跳过转写并告警（下次启动重试）。
pub(crate) async fn revoke_legacy_sso_at_tokens(redis: &mut redis::aio::ConnectionManager) {
    const LEGACY_MARKER: &str = "sso:v4_legacy_at_migrated";
    const LEGACY_AT_PREFIX: &str = "sso:at:";
    /// 历史 JWT 型 SSO AT 的最大剩余寿命 = 平台 JWT TTL 上限（expire_hours ≤ 24h）
    const LEGACY_TTL_FLOOR_SECS: i64 = 86_400;

    let marker: Result<Option<String>, _> = redis::cmd("SET")
        .arg(LEGACY_MARKER)
        .arg("1")
        .arg("NX")
        .query_async(redis)
        .await;
    match marker {
        Err(e) => {
            tracing::warn!("v4-F1 存量转写跳过（Redis 不可达，下次启动重试）: {e}");
            return;
        }
        Ok(None) => return, // 已标记：转写已完成
        Ok(Some(_)) => {}
    }

    let mut cursor = String::from("0");
    let mut migrated = 0usize;
    loop {
        let scan: Result<(String, Vec<String>), _> = redis::cmd("SCAN")
            .arg(&cursor)
            .arg("MATCH")
            .arg(format!("{LEGACY_AT_PREFIX}*"))
            .arg("COUNT")
            .arg(500)
            .query_async(redis)
            .await;
        let (next, keys) = match scan {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!("v4-F1 存量转写 SCAN 失败（已置标记，可用 DEL {LEGACY_MARKER} 重跑）: {e}");
                return;
            }
        };
        for key in &keys {
            let Some(hash) = key.strip_prefix(LEGACY_AT_PREFIX) else {
                continue;
            };
            if hash.is_empty() {
                continue;
            }
            let ttl: i64 = redis::cmd("TTL")
                .arg(key)
                .query_async(redis)
                .await
                .unwrap_or(-2);
            if ttl <= 0 {
                // 已过期/不存在：直接清理
                let _: Result<i64, _> = redis::cmd("DEL").arg(key).query_async(redis).await;
                continue;
            }
            let blacklist_key = format!("blacklist:{hash}");
            let effective_ttl = ttl.max(LEGACY_TTL_FLOOR_SECS);
            let set: Result<Option<()>, _> = redis::cmd("SETEX")
                .arg(&blacklist_key)
                .arg(effective_ttl)
                .arg("1")
                .query_async(redis)
                .await;
            if set.is_ok() {
                // 绑定转写成功后删除原 key：userinfo（只认绑定）与业务路由（认 blacklist）
                // 双路径同时立即 401
                let _: Result<i64, _> = redis::cmd("DEL").arg(key).query_async(redis).await;
                migrated += 1;
            }
        }
        cursor = next;
        if cursor == "0" {
            break;
        }
    }
    if migrated > 0 {
        tracing::info!("v4-F1 已转写吊销历史 JWT 型 SSO 访问令牌 {migrated} 条（blacklist，TTL≥24h）");
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
