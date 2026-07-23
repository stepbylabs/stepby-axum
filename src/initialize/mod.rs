// axum-backend/src/initialize/mod.rs

use std::sync::Arc;
use crate::config::Settings;
use crate::db;
use crate::logger;
use crate::scheduler::JobScheduler;
use crate::service::IpLocationService;
use crate::state::AppState;
use crate::utils::ip_location::IpLocator;

/// 初始化编排模块（对齐 ref-soybean-admin 的 server/initialize）
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
        let ip_location_service = IpLocationService::new(
            db.clone(),
            settings.clone(),
            ip_locator.clone(),
        );

        // 6. 创建调度器并加载任务（注入 ip_location_service 以支持 mmdb_auto_update 内置任务）
        tracing::info!("=== 初始化定时任务调度器 ===");
        let job_scheduler = Arc::new(
            JobScheduler::new(db.clone(), redis.clone(), ip_location_service.clone()).await?,
        );
        // 创建临时 Service 用于 load_from_db（需要 Repository）
        let temp_job_service = crate::service::SysJobService::new(
            db.clone(),
            job_scheduler.clone(),
        );
        if let Err(e) = job_scheduler.load_from_db(temp_job_service.job_repo()).await {
            tracing::warn!("定时任务加载失败（不阻断启动）: {}", e);
        }

        // 7. 构建 AppState（传入 scheduler + ip_locator + ip_location_service）
        let state = Arc::new(AppState::new(
            db,
            redis,
            settings,
            job_scheduler,
            ip_locator,
            ip_location_service,
        ));

        tracing::info!("=== axum-backend 初始化完成 ===");
        Ok(state)
    }
}
