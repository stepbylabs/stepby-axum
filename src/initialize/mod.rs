// axum-backend/src/initialize/mod.rs

use crate::config::Settings;
use crate::db;
use crate::logger;
use crate::scheduler::JobScheduler;
use crate::service::IpLocationService;
use crate::state::AppState;
use crate::utils::ip_location::IpLocator;
use sea_orm::{ConnectionTrait, DatabaseBackend, DatabaseConnection, DbErr, Statement};
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

        // 3.1.1 v5-N2 Phase 2：幂等确保 sys_user 含 tenant_id 列（登录 JWT tid 数据源；
        // 存量库启动不跑 Migrator::up，m20260924_000005 由 migration 负责全新库）
        ensure_user_tenant_id_column(&db)
            .await
            .map_err(|e| anyhow::anyhow!("初始化 sys_user.tenant_id 列失败: {}", e))?;

        // 3.1.3 v5-D12：幂等确保 sys_user 含 scim_external_id 列（SCIM 用户目录同步；
        // m20260924_000006 由 migration 负责全新库）
        if !sso_has_column(&db, "sys_user", "scim_external_id").await? {
            db.execute(Statement::from_string(
                db.get_database_backend(),
                "ALTER TABLE sys_user ADD COLUMN scim_external_id VARCHAR(255)".to_string(),
            ))
            .await?;
            tracing::info!("sys_user.scim_external_id 列已补建（存量库兜底）");
        }

        // 3.1.4 v5-D5：幂等确保 sys_oauth_client 含 sector_identifier_uri 列
        //（pairwise sector 聚合；m20260924_000007 由 migration 负责全新库）
        if !sso_has_column(&db, "sys_oauth_client", "sector_identifier_uri").await? {
            db.execute(Statement::from_string(
                db.get_database_backend(),
                "ALTER TABLE sys_oauth_client ADD COLUMN sector_identifier_uri VARCHAR(255)"
                    .to_string(),
            ))
            .await?;
            tracing::info!("sys_oauth_client.sector_identifier_uri 列已补建（存量库兜底）");
        }

        // 3.1.2 真实运行验证发现的存量库漂移：sys_dept 缺 leader_user_id 列导致
        //        登录链路 dept 查询 500（oper_log 部门名/在线列表）。幂等补列兜底。
        if sso_table_exists(&db, "sys_dept").await?
            && !sso_has_column(&db, "sys_dept", "leader_user_id").await?
        {
            db.execute(Statement::from_string(
                db.get_database_backend(),
                "ALTER TABLE sys_dept ADD COLUMN leader_user_id BIGINT".to_string(),
            ))
            .await?;
            tracing::info!("sys_dept.leader_user_id 列已补建（存量库兜底）");
        }

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
            .map_err(|e| anyhow::anyhow!("初始化 PAT 管理菜单失败: {}", e))?;

        // 3.5b 审批工作流模块（flow_module）存量库兜底：
        // 与迁移 m20260923_000002_flow_module 等价（启动不跑 Migrator::up）——
        // 三表 + 索引 + 菜单 3600 段 + 字典 70 段 + site 渠道与 flow_* 模板种子，全部幂等。
        // 缺此兜底时，存量库直接启动服务后审批 API 全部 500（表不存在）。
        ensure_flow_module(&db)
            .await
            .map_err(|e| anyhow::anyhow!("初始化审批工作流模块失败: {}", e))?;

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

        // 4.2 v5-S1：SSO/OIDC 公开端点限流分档（存量库兜底，幂等；与迁移
        //     m20260924_000001_sso_rate_limit_tiers 等价——启动不跑 Migrator::up）
        ensure_sso_rate_limit_tiers(&db)
            .await
            .map_err(|e| anyhow::anyhow!("初始化 SSO 限流分档失败: {}", e))?;

        // 4.3 v5-E6：运行期敏感凭据存量明文回填（幂等；CONFIG_ENC_KEY 未配置时跳过，
        //     与 id_token_secret 迁移期 fail-open 策略一致）
        ensure_runtime_secrets_encrypted(&db, &settings.config_enc_key).await;

        // 4.4 v5-E1：consent 组合唯一索引（存量库兜底：清软删行/去重/建索引，
        //     与迁移 m20260924_000002_sso_consent_unique 等价）
        ensure_sso_consent_unique(&db)
            .await
            .map_err(|e| anyhow::anyhow!("初始化 SSO consent 唯一索引失败: {}", e))?;

        // 4.5 v5-D2：为存量 RS256 客户端补生成 RSA 私钥（rsa_private_key IS NULL 的行，
        //     PKCS#8 PEM 信封加密落库；CONFIG_ENC_KEY 未配置时明文，迁移期策略）
        ensure_sso_rs256_keys(&db, &settings.config_enc_key)
            .await
            .map_err(|e| anyhow::anyhow!("初始化 SSO RSA 密钥失败: {}", e))?;

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

/// v5-N2 Phase 2（第一步）：幂等确保 `sys_user` 含 `tenant_id` 列（登录 JWT 的 tid
/// 数据源）。与 `ensure_user_country_code_column` 同源方案：表不存在跳过；列不存在
/// 则 `ALTER TABLE sys_user ADD COLUMN tenant_id BIGINT NOT NULL DEFAULT 0`。
async fn ensure_user_tenant_id_column(db: &DatabaseConnection) -> anyhow::Result<()> {
    if !sso_table_exists(db, "sys_user").await? {
        return Ok(());
    }
    if sso_has_column(db, "sys_user", "tenant_id").await? {
        tracing::info!("sys_user.tenant_id 列已存在，无需 ALTER");
        return Ok(());
    }
    db.execute(Statement::from_string(
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

// ==================== 审批工作流模块（flow_module）存量库兜底 ====================
// 与迁移 m20260923_000002_flow_module 等价：三表 + 索引 + 菜单/字典/渠道/模板种子。
// DDL 与种子 SQL 必须与迁移保持同步（双写惯例，参照 ensure_sys_pat_table）；
// 所有种子依赖主键/唯一键（menu_id/dict_code/channel_code/template_code UNIQUE）幂等，
// 每次启动重复执行不产生重复行。

/// 幂等执行一条 SQL（flow 双写内部用；错误向上传播由调用方统一 anyhow 包装）
async fn flow_exec(db: &DatabaseConnection, sql: impl Into<String>) -> Result<(), DbErr> {
    db.execute(Statement::from_string(
        db.get_database_backend(),
        sql.into(),
    ))
    .await
    .map(|_| ())
}

/// 三方言幂等 INSERT 前缀（对齐迁移 execute_idempotent_insert）
fn flow_insert_prefix(backend: DatabaseBackend) -> &'static str {
    match backend {
        DatabaseBackend::Sqlite => "INSERT OR IGNORE INTO ",
        DatabaseBackend::Postgres => "INSERT INTO ",
        _ => "INSERT IGNORE INTO ",
    }
}

/// 三方言幂等 INSERT 后缀（仅 PostgreSQL 需要 ON CONFLICT）
fn flow_insert_suffix(backend: DatabaseBackend) -> &'static str {
    if backend == DatabaseBackend::Postgres {
        " ON CONFLICT DO NOTHING"
    } else {
        ""
    }
}

/// 幂等 INSERT（body 为 "表名 (列...) VALUES (...)" 形式，与迁移 execute_idempotent_insert 同构）
async fn flow_insert(db: &DatabaseConnection, body: &str) -> Result<(), DbErr> {
    let backend = db.get_database_backend();
    let sql = format!(
        "{}{}{}",
        flow_insert_prefix(backend),
        body,
        flow_insert_suffix(backend)
    );
    flow_exec(db, sql).await
}

/// flow 种子用当前时间表达式（与迁移 now_expr 同构）
fn flow_now(db: &DatabaseConnection) -> String {
    if db.get_database_backend() == DatabaseBackend::Sqlite {
        format!("'{}'", chrono::Local::now().format("%Y-%m-%d %H:%M:%S"))
    } else {
        "NOW()".to_string()
    }
}

/// 幂等确保审批工作流三张表存在（三方言 DDL 与迁移逐字对齐）
async fn ensure_flow_tables(db: &DatabaseConnection) -> Result<(), DbErr> {
    let backend = db.get_database_backend();
    let (id_task, id_log, id_doc) = match backend {
        DatabaseBackend::Sqlite => (
            "INTEGER PRIMARY KEY AUTOINCREMENT",
            "INTEGER PRIMARY KEY AUTOINCREMENT",
            "INTEGER PRIMARY KEY AUTOINCREMENT",
        ),
        DatabaseBackend::Postgres => (
            "BIGSERIAL PRIMARY KEY",
            "BIGSERIAL PRIMARY KEY",
            "BIGSERIAL PRIMARY KEY",
        ),
        _ => (
            "BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY",
            "BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY",
            "BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY",
        ),
    };
    let ts = match backend {
        DatabaseBackend::Postgres => "TIMESTAMP",
        _ => "DATETIME",
    };

    flow_exec(
        db,
        format!(
            "CREATE TABLE IF NOT EXISTS sys_flow_task (\n\
             \x20 task_id        {id_task},\n\
             \x20 biz_type       VARCHAR(64) NOT NULL,\n\
             \x20 biz_id         BIGINT NOT NULL,\n\
             \x20 round_no       INTEGER NOT NULL DEFAULT 1,\n\
             \x20 node_seq       INTEGER NOT NULL,\n\
             \x20 node_name      VARCHAR(64),\n\
             \x20 assignee_id    BIGINT NOT NULL,\n\
             \x20 task_type      VARCHAR(16) NOT NULL DEFAULT 'single',\n\
             \x20 status         VARCHAR(16) NOT NULL DEFAULT 'pending',\n\
             \x20 title          VARCHAR(200),\n\
             \x20 applicant_id   BIGINT NOT NULL,\n\
             \x20 applicant_name VARCHAR(64),\n\
             \x20 comment        VARCHAR(500),\n\
             \x20 acted_at       {ts},\n\
             \x20 due_at         {ts},\n\
             \x20 last_reminded_at {ts},\n\
             \x20 tenant_id      BIGINT NOT NULL DEFAULT 0,\n\
             \x20 create_by      VARCHAR(64),\n\
             \x20 create_time    {ts},\n\
             \x20 update_by      VARCHAR(64),\n\
             \x20 update_time    {ts}\n\
             )"
        ),
    )
    .await?;

    flow_exec(
        db,
        format!(
            "CREATE TABLE IF NOT EXISTS sys_flow_log (\n\
             \x20 log_id       {id_log},\n\
             \x20 biz_type     VARCHAR(64) NOT NULL,\n\
             \x20 biz_id       BIGINT NOT NULL,\n\
             \x20 round_no     INTEGER NOT NULL DEFAULT 1,\n\
             \x20 node_seq     INTEGER,\n\
             \x20 action       VARCHAR(24) NOT NULL,\n\
             \x20 from_status  VARCHAR(16),\n\
             \x20 to_status    VARCHAR(16),\n\
             \x20 operator_id  BIGINT,\n\
             \x20 to_user_id   BIGINT,\n\
             \x20 comment      VARCHAR(500),\n\
             \x20 acted_at     {ts},\n\
             \x20 tenant_id    BIGINT NOT NULL DEFAULT 0,\n\
             \x20 create_by    VARCHAR(64),\n\
             \x20 create_time  {ts},\n\
             \x20 update_by    VARCHAR(64),\n\
             \x20 update_time  {ts}\n\
             )"
        ),
    )
    .await?;

    flow_exec(
        db,
        format!(
            "CREATE TABLE IF NOT EXISTS flow_demo_doc (\n\
             \x20 doc_id           {id_doc},\n\
             \x20 title            VARCHAR(200) NOT NULL,\n\
             \x20 applicant_id     BIGINT NOT NULL,\n\
             \x20 applicant_name   VARCHAR(64),\n\
             \x20 dept_id          BIGINT,\n\
             \x20 leave_type       VARCHAR(16) NOT NULL DEFAULT 'annual',\n\
             \x20 days             INTEGER NOT NULL DEFAULT 1,\n\
             \x20 reason           VARCHAR(500),\n\
             \x20 flow_mode        VARCHAR(16) NOT NULL DEFAULT 'single',\n\
             \x20 status           VARCHAR(16) NOT NULL DEFAULT 'draft',\n\
             \x20 current_round    INTEGER NOT NULL DEFAULT 0,\n\
             \x20 current_node_seq INTEGER,\n\
             \x20 submitted_at     {ts},\n\
             \x20 finished_at      {ts},\n\
             \x20 tenant_id        BIGINT NOT NULL DEFAULT 0,\n\
             \x20 create_by        VARCHAR(64),\n\
             \x20 create_time      {ts},\n\
             \x20 update_by        VARCHAR(64),\n\
             \x20 update_time      {ts}\n\
             )"
        ),
    )
    .await
}

/// 幂等建 flow 索引（SQLite/PostgreSQL 支持 IF NOT EXISTS；MySQL 跳过交由迁移补齐，参照 ensure_sys_pat_table）
async fn ensure_flow_indexes(db: &DatabaseConnection) -> Result<(), DbErr> {
    let backend = db.get_database_backend();
    if backend == DatabaseBackend::MySql {
        tracing::debug!("flow 索引创建跳过（MySQL 无 IF NOT EXISTS，交由 migration）");
        return Ok(());
    }
    let indexes = [
        "CREATE UNIQUE INDEX IF NOT EXISTS uk_flow_task_biz ON sys_flow_task (biz_type, biz_id, round_no, node_seq, assignee_id)",
        "CREATE INDEX IF NOT EXISTS idx_flow_task_assignee ON sys_flow_task (assignee_id, status)",
        "CREATE INDEX IF NOT EXISTS idx_flow_task_due ON sys_flow_task (status, due_at)",
        "CREATE INDEX IF NOT EXISTS idx_flow_log_biz ON sys_flow_log (biz_type, biz_id, round_no)",
        "CREATE INDEX IF NOT EXISTS idx_flow_doc_applicant ON flow_demo_doc (applicant_id, status)",
    ];
    for stmt in indexes {
        // 容错：个别存量库索引名冲突等异常不阻断启动（与 sys_pat 索引兜底同策略）
        if let Err(e) = flow_exec(db, stmt).await {
            tracing::debug!("flow 索引创建跳过（可能已存在）: {}", e);
        }
    }
    Ok(())
}

/// 幂等补种 flow 菜单（3600 段）/字典（70 段）/site 渠道/flow_* 模板
async fn ensure_flow_seeds(db: &DatabaseConnection) -> Result<(), DbErr> {
    // sys_menu 表存在性保护：全新空库未建系统表时跳过种子（交由 migration 初始种子负责），
    // 与 ensure_sys_pat_menu 同范式——否则空库启动会因种子 INSERT 失败而阻断（影响面回归修复）
    let sys_menu_exists = sso_table_exists(db, "sys_menu")
        .await
        .map_err(|e| DbErr::Custom(format!("flow 种子表存在性检查失败: {}", e)))?;
    if !sys_menu_exists {
        tracing::info!("flow 种子跳过（sys_menu 不存在，空库交由 migration 负责初始种子）");
        return Ok(());
    }
    let now = flow_now(db);

    // 菜单 3600/3601/3611 + role 2 授权（与迁移 4.1-4.3 同构；remark 亦对齐迁移）
    // 类型标注省略（11 元元组触发 clippy type_complexity，交给编译器推断）
    let menus = &[
        (
            3600,
            "审批中心",
            1,
            95,
            "flow",
            "ParentView",
            "M",
            "",
            "example",
            "审批工作流",
            "route.flow",
        ),
        (
            3601,
            "审批中心",
            3600,
            1,
            "todo",
            "system/flow/index",
            "C",
            "system:flow:list",
            "checkbox",
            "审批待办/我发起/全部单据",
            "route.flowTodo",
        ),
        (
            3611,
            "全部单据查询",
            3601,
            1,
            "",
            "",
            "F",
            "system:flow:list",
            "#",
            "",
            "",
        ),
    ];
    for (menu_id, name, parent, order, path, component, mtype, perms, icon, remark, i18n_key) in
        menus
    {
        // F 按钮（3611）无 i18n_key 列值，与其余 C/M 分支拼列
        if *mtype == "F" {
            flow_insert(
                db,
                &format!(
                    "sys_menu (menu_id, menu_name, parent_id, order_num, path, component, query, route_name, is_frame, is_cache, menu_type, visible, status, perms, icon, create_by, create_time, remark, del_flag) VALUES \
                     ({menu_id}, '{name}', {parent}, {order}, '{path}', '{component}', '', '', '1', '0', '{mtype}', '0', '0', '{perms}', '{icon}', 'admin', {now}, '{remark}', '0')"
                ),
            )
            .await?;
        } else {
            flow_insert(
                db,
                &format!(
                    "sys_menu (menu_id, menu_name, parent_id, order_num, path, component, query, route_name, is_frame, is_cache, menu_type, visible, status, perms, icon, create_by, create_time, remark, del_flag, i18n_key) VALUES \
                     ({menu_id}, '{name}', {parent}, {order}, '{path}', '{component}', '', '', '1', '0', '{mtype}', '0', '0', '{perms}', '{icon}', 'admin', {now}, '{remark}', '0', '{i18n_key}')"
                ),
            )
            .await?;
        }
        flow_insert(
            db,
            &format!("sys_role_menu (role_id, menu_id) VALUES (2, {menu_id})"),
        )
        .await?;
    }

    // 字典 70/71/72 段（与迁移 4.4-4.6 同构）
    let dict_types: &[(i64, &str, &str, &str)] = &[
        (70, "审批状态", "sys_flow_task_status", "审批任务与单据状态"),
        (71, "审批动作", "sys_flow_action", "审批流水动作"),
        (
            72,
            "请假类型",
            "sys_flow_leave_type",
            "示例审批单据-请假类型",
        ),
    ];
    for (dict_id, name, dtype, remark) in dict_types {
        flow_insert(
            db,
            &format!(
                "sys_dict_type (dict_id, dict_name, dict_type, status, create_by, create_time, remark, del_flag) VALUES \
                 ({dict_id}, '{name}', '{dtype}', '0', 'admin', {now}, '{remark}', '0')"
            ),
        )
        .await?;
    }
    let status_rows: &[(i64, &str, &str, &str, &str)] = &[
        (700, "待审批", "pending", "warning", "To Approve"),
        (701, "已通过", "approved", "success", "Approved"),
        (702, "已驳回", "rejected", "danger", "Rejected"),
        (703, "已取消", "cancelled", "info", "Cancelled"),
        (704, "已转办", "transferred", "info", "Transferred"),
        (705, "已撤回", "withdrawn", "info", "Withdrawn"),
        (706, "草稿", "draft", "info", "Draft"),
    ];
    for (code, label, value, css, label_en) in status_rows {
        flow_insert(
            db,
            &format!(
                "sys_dict_data (dict_code, dict_sort, dict_label, dict_value, dict_type, css_class, list_class, is_default, status, create_by, create_time, remark, del_flag, dict_label_en) VALUES \
                 ({code}, {code}, '{label}', '{value}', 'sys_flow_task_status', '', '{css}', 'N', '0', 'admin', {now}, '', '0', '{label_en}')"
            ),
        )
        .await?;
    }
    let action_rows: &[(i64, &str, &str, &str)] = &[
        (710, "提交", "submit", "To Submit"),
        (711, "同意", "approve", "Approve"),
        (712, "驳回", "reject", "Reject"),
        (713, "撤回", "withdraw", "Withdraw"),
        (714, "转办", "transfer", "Transfer"),
        (715, "超时提醒", "timeout_remind", "Timeout Remind"),
        (716, "自动通过", "auto_approve", "Auto Approve"),
    ];
    for (code, label, value, label_en) in action_rows {
        flow_insert(
            db,
            &format!(
                "sys_dict_data (dict_code, dict_sort, dict_label, dict_value, dict_type, css_class, list_class, is_default, status, create_by, create_time, remark, del_flag, dict_label_en) VALUES \
                 ({code}, {code}, '{label}', '{value}', 'sys_flow_action', '', 'info', 'N', '0', 'admin', {now}, '', '0', '{label_en}')"
            ),
        )
        .await?;
    }
    let leave_rows: &[(i64, &str, &str, &str)] = &[
        (720, "年假", "annual", "Annual Leave"),
        (721, "病假", "sick", "Sick Leave"),
        (722, "事假", "personal", "Personal Leave"),
    ];
    for (code, label, value, label_en) in leave_rows {
        flow_insert(
            db,
            &format!(
                "sys_dict_data (dict_code, dict_sort, dict_label, dict_value, dict_type, css_class, list_class, is_default, status, create_by, create_time, remark, del_flag, dict_label_en) VALUES \
                 ({code}, {code}, '{label}', '{value}', 'sys_flow_leave_type', '', 'primary', 'N', '0', 'admin', {now}, '', '0', '{label_en}')"
            ),
        )
        .await?;
    }

    // site 渠道 + flow_* 模板（与迁移 4.7/4.8 同构；channel_code/template_code UNIQUE 幂等）
    flow_insert(
        db,
        &format!(
            "sys_msg_channel (channel_name, channel_code, channel_type, config_json, status, remark, create_by, create_time, del_flag) VALUES \
             ('站内信', 'site', 'site', NULL, '0', '审批/系统站内提醒', 'admin', {now}, '0')"
        ),
    )
    .await?;
    let templates: &[(&str, &str, &str, &str)] = &[
        (
            "审批待办提醒",
            "flow_todo",
            "您有新的审批待办",
            "单据「{{{{title}}}}」等待您审批，请及时处理。",
        ),
        (
            "审批超时提醒",
            "flow_timeout",
            "审批待办已超时",
            "单据「{{{{title}}}}」已超过办理时限，请尽快处理。",
        ),
        (
            "审批驳回通知",
            "flow_reject",
            "您的单据已被驳回",
            "您提交的单据「{{{{title}}}}」已被驳回，请查看审批意见。",
        ),
    ];
    for (name, code, subject, content) in templates {
        flow_insert(
            db,
            &format!(
                "sys_msg_template (template_name, template_code, channel_code, template_subject, template_content, status, remark, create_by, create_time, del_flag) VALUES \
                 ('{name}', '{code}', 'site', '{subject}', '{content}', '0', '审批站内提醒', 'admin', {now}, '0')"
            ),
        )
        .await?;
    }
    Ok(())
}

/// 幂等确保审批工作流模块完整就绪（表 + 索引 + 种子；存量库向后兼容，与迁移等价）
async fn ensure_flow_module(db: &DatabaseConnection) -> anyhow::Result<()> {
    ensure_flow_tables(db)
        .await
        .map_err(|e| anyhow::anyhow!("flow 建表失败: {}", e))?;
    ensure_flow_indexes(db)
        .await
        .map_err(|e| anyhow::anyhow!("flow 索引创建失败: {}", e))?;
    // 存量库 leader_user_id 已由 AppInitializer 3.1.2 统一兜底（sys_dept 漂移修复），此处无需重复
    ensure_flow_seeds(db)
        .await
        .map_err(|e| anyhow::anyhow!("flow 种子补齐失败: {}", e))?;
    tracing::info!("审批工作流模块已就绪（幂等确保完成）");
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

/// v5-D2：为存量 RS256 客户端补生成 RSA-2048 私钥（幂等：仅处理 rsa_private_key 为
/// NULL 且 id_token_alg='RS256' 的行）。PKCS#8 PEM 按 CONFIG_ENC_KEY 信封加密落库
/// （key 未配置时明文，迁移期策略与 v5-E6 一致）；CONFIG_ENC_KEY 未配置时整体跳过。
async fn ensure_sso_rs256_keys(db: &DatabaseConnection, enc_key: &str) -> anyhow::Result<()> {
    if !sso_table_exists(db, "sys_oauth_client").await? {
        return Ok(());
    }
    // v5-D2/D5：存量库启动不跑 Migrator::up——先幂等补列（id_token_alg/rsa_private_key/
    // subject_type），否则下方查询因缺列直接失败（真实运行验证发现的启动阻断）
    if !sso_has_column(db, "sys_oauth_client", "id_token_alg").await? {
        db.execute(Statement::from_string(
            db.get_database_backend(),
            "ALTER TABLE sys_oauth_client ADD COLUMN id_token_alg VARCHAR(8) NOT NULL DEFAULT 'RS256'"
                .to_string(),
        ))
        .await?;
        tracing::info!("sys_oauth_client.id_token_alg 列已补建（v5-D2 存量库兜底）");
    }
    if !sso_has_column(db, "sys_oauth_client", "rsa_private_key").await? {
        db.execute(Statement::from_string(
            db.get_database_backend(),
            "ALTER TABLE sys_oauth_client ADD COLUMN rsa_private_key TEXT".to_string(),
        ))
        .await?;
        tracing::info!("sys_oauth_client.rsa_private_key 列已补建（v5-D2 存量库兜底）");
    }
    if !sso_has_column(db, "sys_oauth_client", "subject_type").await? {
        db.execute(Statement::from_string(
            db.get_database_backend(),
            "ALTER TABLE sys_oauth_client ADD COLUMN subject_type VARCHAR(8) NOT NULL DEFAULT 'public'"
                .to_string(),
        ))
        .await?;
        tracing::info!("sys_oauth_client.subject_type 列已补建（v5-D5 存量库兜底）");
    }
    if enc_key.is_empty() {
        tracing::warn!("CONFIG_ENC_KEY 未配置：跳过 RS256 密钥生成（v5-D2，下次启动重试）");
        return Ok(());
    }
    let backend = db.get_database_backend();
    let select_sql = "SELECT sso_client_id AS pk, client_id AS cid FROM sys_oauth_client \
                      WHERE rsa_private_key IS NULL AND id_token_alg = 'RS256'";
    let rows = db
        .query_all(Statement::from_string(backend, select_sql))
        .await?;
    for row in rows {
        let pk = row.try_get::<i64>("", "pk").unwrap_or(0);
        let cid = row.try_get::<String>("", "cid").unwrap_or_default();
        // v5-D2 修正：keygen 在专用大栈线程执行（tokio 栈上 stack overflow 硬崩，
        // 与 sso_service::generate_rsa_private_pem 同款防护）
        let pem = match tokio::task::spawn_blocking(|| {
            crate::service::sso_service::generate_rsa_private_pem()
        })
        .await
        {
            Ok(Ok(p)) => p,
            Ok(Err(e)) => {
                tracing::error!("v5-D2 RSA 生成失败 client_id={cid}: {}", e);
                continue;
            }
            Err(e) => {
                tracing::error!("v5-D2 RSA keygen 任务失败 client_id={cid}: {}", e);
                continue;
            }
        };
        let sealed = match crate::utils::crypto::seal_sensitive_value(&pem, enc_key) {
            Ok(s) => s,
            Err(e) => {
                tracing::error!("v5-D2 RSA 私钥加密失败 client_id={cid}: {}", e);
                continue;
            }
        };
        let update_sql = format!(
            "UPDATE sys_oauth_client SET rsa_private_key = '{}' WHERE sso_client_id = {pk}",
            sealed.replace('\'', "''")
        );
        db.execute(Statement::from_string(backend, update_sql))
            .await?;
        tracing::info!("v5-D2 已为存量客户端生成 RS256 密钥 client_id={cid}");
    }
    Ok(())
}

/// v5-E1：consent 组合唯一索引兜底（幂等）——清软删行、同 (user_id, client_id)
/// 去重（保留最早）、建唯一索引 uq_sso_consent_user_client。与迁移
/// m20260924_000002_sso_consent_unique 等价；索引已存在时 CREATE IF NOT EXISTS 跳过。
async fn ensure_sso_consent_unique(db: &DatabaseConnection) -> anyhow::Result<()> {
    if !sso_table_exists(db, "sys_oauth_consent").await? {
        return Ok(());
    }
    let backend = db.get_database_backend();
    let stmts = [
        "DELETE FROM sys_oauth_consent WHERE del_flag = '2'",
        "DELETE FROM sys_oauth_consent WHERE consent_id NOT IN (\
         SELECT MIN(consent_id) FROM sys_oauth_consent GROUP BY user_id, client_id)",
        "CREATE UNIQUE INDEX IF NOT EXISTS uq_sso_consent_user_client \
         ON sys_oauth_consent (user_id, client_id)",
    ];
    for sql in stmts {
        db.execute(Statement::from_string(backend, sql)).await?;
    }
    Ok(())
}

/// v5-E6：运行期敏感凭据存量明文回填（幂等）。
///
/// 范围（四组明文落库的敏感列，与 id_token_secret 同标准信封加密）：
/// - `sys_oauth_provider.client_secret`（第三方 OAuth 客户端密钥）
/// - `sys_oauth_user.access_token` / `refresh_token`（第三方用户令牌）
/// - `sys_msg_channel.config_json`（渠道配置，含 SMTP 凭据）
/// - `sys_web_hook.secret`（回调 HMAC 签名密钥）
///
/// 规则：CONFIG_ENC_KEY 未配置 → 跳过（fail-open，下次启动重试）；
/// 值已带 `enc2:`/`enc:` 前缀 → 跳过（已加密）；空值 → 跳过；
/// 其余 → `seal_sensitive_value` 加密 UPDATE（逐行，幂等：回填后即带前缀）。
async fn ensure_runtime_secrets_encrypted(db: &DatabaseConnection, enc_key: &str) {
    if enc_key.is_empty() {
        tracing::warn!("CONFIG_ENC_KEY 未配置：跳过运行期敏感凭据存量明文回填（v5-E6）");
        return;
    }
    // (表, 主键列, 敏感列)
    const TARGETS: &[(&str, &str, &str)] = &[
        ("sys_oauth_provider", "provider_id", "client_secret"),
        ("sys_oauth_user", "oauth_id", "access_token"),
        ("sys_oauth_user", "oauth_id", "refresh_token"),
        ("sys_msg_channel", "channel_id", "config_json"),
        ("sys_web_hook", "id", "secret"),
    ];
    let backend = db.get_database_backend();
    let mut sealed_total = 0usize;
    for (table, pk, col) in TARGETS {
        let select_sql = format!(
            "SELECT {pk} AS pk, {col} AS val FROM {table} WHERE {col} IS NOT NULL AND {col} != ''"
        );
        let rows = match db
            .query_all(Statement::from_string(backend, select_sql))
            .await
        {
            Ok(r) => r,
            Err(e) => {
                // 表可能不存在（极旧存量库），warn 并继续下一目标
                tracing::warn!("v5-E6 回填读取 {table}.{col} 失败（跳过）: {}", e);
                continue;
            }
        };
        for row in rows {
            let pk_val = match row.try_get::<i64>("", "pk") {
                Ok(v) => v,
                Err(_) => continue,
            };
            let val = match row.try_get::<String>("", "val") {
                Ok(v) => v,
                Err(_) => continue,
            };
            // 已加密（带前缀）或空值跳过
            if val.starts_with("enc2:") || val.starts_with("enc:") {
                continue;
            }
            let sealed = match crate::utils::crypto::seal_sensitive_value(&val, enc_key) {
                Ok(s) => s,
                Err(e) => {
                    tracing::error!("v5-E6 回填加密失败 {table}.{col} pk={pk_val}: {}", e);
                    continue;
                }
            };
            let update_sql = format!(
                "UPDATE {table} SET {col} = '{}' WHERE {pk} = {pk_val}",
                sealed.replace('\'', "''")
            );
            if let Err(e) = db
                .execute(Statement::from_string(backend, update_sql))
                .await
            {
                tracing::error!("v5-E6 回填更新失败 {table}.{col} pk={pk_val}: {}", e);
                continue;
            }
            sealed_total += 1;
        }
    }
    if sealed_total > 0 {
        tracing::info!("v5-E6 已加密回填运行期敏感凭据 {sealed_total} 条（v5-E6）");
    }
}

/// v5-S1：SSO/OIDC 公开端点限流分档（存量库兜底，幂等）。
///
/// 与迁移 m20260924_000001_sso_rate_limit_tiers 等价：rate_limit 中间件先按
/// route_pattern 精确匹配、未命中回退 '*'；此处为不跑 Migrator::up 的存量库
/// 以「查存在 → 缺则 INSERT」补齐五条分档（应用层判存，跨 SQLite/PG/MySQL 稳定）。
/// 已有同 pattern 行（运维自调）不覆盖。生效时机：下次启动或 Redis 配置缓存过期。
async fn ensure_sso_rate_limit_tiers(db: &DatabaseConnection) -> anyhow::Result<()> {
    if !sso_table_exists(db, "sys_rate_limit").await? {
        return Ok(()); // 极旧存量库无限流表（理论不可达，防御性跳过）
    }
    const TIERS: &[(&str, u32, f64, &str)] = &[
        (
            "/sso/token",
            30,
            0.5,
            "SSO 令牌兑换（机器对机器，严档防暴力试 secret）",
        ),
        (
            "/sso/authorize",
            60,
            1.0,
            "SSO 授权端点（浏览器导航，中档）",
        ),
        ("/sso/logout", 30, 0.5, "SSO 登出（低频严档）"),
        (
            "/sso/userinfo",
            120,
            2.0,
            "SSO 用户信息（RP 高频会话校验，宽档）",
        ),
        (
            "/.well-known/openid-configuration",
            60,
            1.0,
            "OIDC 发现文档（RP 启动期拉取，中档）",
        ),
    ];
    let backend = db.get_database_backend();
    for (pattern, capacity, refill, description) in TIERS {
        let count_sql =
            format!("SELECT COUNT(*) AS c FROM sys_rate_limit WHERE route_pattern = '{pattern}'");
        let exists = match db
            .query_one(Statement::from_string(backend, count_sql))
            .await?
        {
            Some(row) => row.try_get::<i64>("", "c").unwrap_or(0) > 0,
            None => false,
        };
        if exists {
            continue;
        }
        let now = chrono::Local::now().format("%Y-%m-%d %H:%M:%S");
        let insert_sql = format!(
            "INSERT INTO sys_rate_limit (route_pattern, capacity, refill_per_second, enabled, description, create_by, create_time, update_by, update_time) \
             VALUES ('{pattern}', {capacity}, {refill}, TRUE, '{description}', 'admin', '{now}', 'admin', '{now}')"
        );
        db.execute(Statement::from_string(backend, insert_sql))
            .await?;
        tracing::info!("已插入 SSO 限流分档 route_pattern={pattern}");
    }
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
    let mut skipped = 0usize;
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
                tracing::warn!(
                    "v4-F1 存量转写 SCAN 失败（已置标记，可用 DEL {LEGACY_MARKER} 重跑）: {e}"
                );
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
            // v5 核查：A 形态活跃绑定（value 含 access_token_hash）不转写，防误杀
            let is_legacy: Option<bool> = redis::cmd("GET")
                .arg(key)
                .query_async::<Option<String>>(redis)
                .await
                .ok()
                .flatten()
                .and_then(|v| serde_json::from_str::<serde_json::Value>(&v).ok())
                .map(|json| !json.get("access_token_hash").is_some());
            match is_legacy {
                Some(false) => {
                    skipped += 1;
                    continue;
                }
                None => {
                    // 读取/解析失败（key 已过期或 value 异常）→ 按过期清理处理
                }
                _ => {}
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
        tracing::info!(
            "v4-F1 已转写吊销历史 JWT 型 SSO 访问令牌 {migrated} 条（blacklist，TTL≥24h）"
        );
    }
    if skipped > 0 {
        tracing::info!("v4-F1 跳过 A 形态活跃绑定 {skipped} 条（含 access_token_hash，不转写）");
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

#[cfg(test)]
mod flow_backfill_tests {
    use super::*;
    use sea_orm::Database;

    /// 依赖表最小 DDL（种子写入目标：sys_menu/sys_role_menu/sys_dict_type/sys_dict_data/
    /// sys_msg_channel/sys_msg_template；列结构对齐各自迁移，仅保留种子涉及列 + 唯一键）
    const MIN_SEED_TABLES: &[&str] = &[
        "CREATE TABLE sys_menu (menu_id INTEGER PRIMARY KEY, menu_name VARCHAR(64), parent_id INTEGER, order_num INTEGER, path VARCHAR(64), component VARCHAR(64), query VARCHAR(64), route_name VARCHAR(64), is_frame VARCHAR(2), is_cache VARCHAR(2), menu_type VARCHAR(2), visible VARCHAR(2), status VARCHAR(2), perms VARCHAR(64), icon VARCHAR(64), create_by VARCHAR(64), create_time DATETIME, remark VARCHAR(500), del_flag VARCHAR(1), i18n_key VARCHAR(64))",
        "CREATE TABLE sys_role_menu (role_id BIGINT, menu_id BIGINT, PRIMARY KEY (role_id, menu_id))",
        "CREATE TABLE sys_dict_type (dict_id INTEGER PRIMARY KEY, dict_name VARCHAR(64), dict_type VARCHAR(64) UNIQUE, status VARCHAR(2), create_by VARCHAR(64), create_time DATETIME, remark VARCHAR(500), del_flag VARCHAR(1))",
        "CREATE TABLE sys_dict_data (dict_code INTEGER PRIMARY KEY, dict_sort INTEGER, dict_label VARCHAR(64), dict_value VARCHAR(64), dict_type VARCHAR(64), css_class VARCHAR(64), list_class VARCHAR(64), is_default VARCHAR(2), status VARCHAR(2), create_by VARCHAR(64), create_time DATETIME, remark VARCHAR(500), del_flag VARCHAR(1), dict_label_en VARCHAR(64))",
        "CREATE TABLE sys_msg_channel (channel_id INTEGER PRIMARY KEY AUTOINCREMENT, channel_name VARCHAR(64), channel_code VARCHAR(64) UNIQUE, channel_type VARCHAR(32), config_json TEXT, status VARCHAR(2), remark VARCHAR(500), create_by VARCHAR(64), create_time DATETIME, del_flag VARCHAR(1))",
        "CREATE TABLE sys_msg_template (template_id INTEGER PRIMARY KEY AUTOINCREMENT, template_name VARCHAR(64), template_code VARCHAR(64) UNIQUE, channel_code VARCHAR(64), template_subject VARCHAR(200), template_content TEXT, status VARCHAR(2), remark VARCHAR(500), create_by VARCHAR(64), create_time DATETIME, del_flag VARCHAR(1))",
    ];

    /// 场景 1：全新空库（连 sys_menu 都没有）→ 三表兜底建出、种子安全跳过、不阻断启动
    #[tokio::test]
    async fn flow_backfill_on_empty_db_creates_tables_and_skips_seeds() {
        let db = Database::connect("sqlite::memory:").await.unwrap();
        ensure_flow_module(&db).await.unwrap();
        let tables = db
            .query_all(Statement::from_string(
                DatabaseBackend::Sqlite,
                "SELECT name FROM sqlite_master WHERE type='table' AND name IN ('sys_flow_task','sys_flow_log','flow_demo_doc')".to_string(),
            ))
            .await
            .unwrap();
        assert_eq!(tables.len(), 3, "空库应兜底建出三张 flow 表");
    }

    /// 场景 2：存量库（有 sys_menu 等系统表）→ 种子落库 + 重复调用幂等（不报错、不重复行）
    #[tokio::test]
    async fn flow_backfill_is_idempotent_on_existing_db() {
        let db = Database::connect("sqlite::memory:").await.unwrap();
        for ddl in MIN_SEED_TABLES {
            db.execute(Statement::from_string(
                DatabaseBackend::Sqlite,
                ddl.to_string(),
            ))
            .await
            .unwrap();
        }
        // 首次调用：种子落库
        ensure_flow_module(&db).await.unwrap();
        // 重复调用（模拟每次启动）：幂等不报错
        ensure_flow_module(&db).await.unwrap();

        let count_menu: u64 = db
            .query_one(Statement::from_string(
                DatabaseBackend::Sqlite,
                "SELECT COUNT(*) AS c FROM sys_menu WHERE menu_id = 3600".to_string(),
            ))
            .await
            .unwrap()
            .unwrap()
            .try_get::<i64>("", "c")
            .unwrap() as u64;
        assert_eq!(count_menu, 1, "menu 3600 应恰一条（幂等防重）");

        let count_tpl: u64 = db
            .query_one(Statement::from_string(
                DatabaseBackend::Sqlite,
                "SELECT COUNT(*) AS c FROM sys_msg_template WHERE template_code IN ('flow_todo','flow_timeout','flow_reject')".to_string(),
            ))
            .await
            .unwrap()
            .unwrap()
            .try_get::<i64>("", "c")
            .unwrap() as u64;
        assert_eq!(count_tpl, 3, "三条 flow 模板应恰各一条（UNIQUE 幂等）");

        let count_dict: u64 = db
            .query_one(Statement::from_string(
                DatabaseBackend::Sqlite,
                "SELECT COUNT(*) AS c FROM sys_dict_data WHERE dict_type = 'sys_flow_task_status'"
                    .to_string(),
            ))
            .await
            .unwrap()
            .unwrap()
            .try_get::<i64>("", "c")
            .unwrap() as u64;
        assert_eq!(count_dict, 7, "审批状态字典应恰 7 条");
    }
}
