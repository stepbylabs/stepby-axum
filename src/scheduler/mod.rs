// axum-backend/src/scheduler/mod.rs
//! 定时任务调度内核
//!
//! 设计要点：
//! - 基于 `tokio-cron-scheduler` 独立实现，不复用任何参考项目的调度器
//! - 调度内核与 Web 层完全解耦，仅依赖 `sea-orm` + `tokio` + `tokio-cron-scheduler` + `tracing`
//! - 通过 `Arc<JobScheduler>` 注入 AppState，不使用全局 Lazy
//! - 任务执行异常捕获写日志，不影响调度器和其他任务
//! - 并发控制：`concurrent='1'` 时检查 executing_jobs 跳过重叠执行
//! - 超时控制：60 秒超时被 tokio::time::timeout 杀死

pub mod registry;

use std::collections::HashMap;
use std::panic::AssertUnwindSafe;
use std::sync::Arc;
use std::time::Duration;

use futures::FutureExt;
use redis::aio::ConnectionManager;
use sea_orm::{DatabaseConnection, Set};
use tokio::sync::RwLock;
use tokio_cron_scheduler::{Job, JobScheduler as TokioScheduler};

/// 任务执行超时时间（秒）
/// REGRESS-008：锁 TTL 必须大于此值，否则锁过期后其他实例可重复执行
const TASK_TIMEOUT_SECS: u64 = 60;
/// 分布式锁 TTL（秒），等于 TASK_TIMEOUT_SECS × 1.5，留 50% 余量
///
/// R8-CONC-007：锁 TTL 与任务超时联动，确保任务在超时窗口内锁不会自然过期。
/// 即便任务接近超时，renew_lock 续期任务也会在执行过半时延长 TTL，
/// 避免长任务执行中锁过期被其他实例重复获取。
const LOCK_TTL_SECS: u64 = TASK_TIMEOUT_SECS * 3 / 2;
/// 锁续期间隔（秒），取 TASK_TIMEOUT_SECS / 2，确保任务执行过半时触发续期
const LOCK_RENEW_INTERVAL_SECS: u64 = TASK_TIMEOUT_SECS / 2;

use crate::entity::sys_job::Model as SysJobModel;
use crate::entity::sys_job_log;
use crate::repository::sys_job::SysJobRepository;
use crate::repository::sys_job_log::SysJobLogRepository;

// ==================== 错误类型 ====================

/// 调度内核错误类型（不依赖 Web 框架）
#[derive(Debug)]
pub enum SchedulerError {
    /// cron 表达式解析失败
    InvalidCron(String),
    /// 调度器内部错误（add/remove/start 失败）
    SchedulerInternal(String),
}

impl std::fmt::Display for SchedulerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SchedulerError::InvalidCron(msg) => write!(f, "cron 表达式非法: {}", msg),
            SchedulerError::SchedulerInternal(msg) => write!(f, "调度器内部错误: {}", msg),
        }
    }
}

impl std::error::Error for SchedulerError {}

/// SchedulerError → ServiceError 转换（Service 层 ? 自动使用）
impl From<SchedulerError> for crate::common::error::ServiceError {
    fn from(err: SchedulerError) -> Self {
        match err {
            SchedulerError::InvalidCron(msg) => {
                crate::common::error::ServiceError::bad_request(&format!("cron 表达式非法: {}", msg))
            }
            SchedulerError::SchedulerInternal(msg) => {
                tracing::error!("调度器内部错误: {}", msg);
                crate::common::error::ServiceError::internal("调度器操作失败，请联系管理员")
            }
        }
    }
}

// ==================== 调度内核封装 ====================

/// 调度内核封装（不依赖 Web 框架）
///
/// 持有：
/// - `TokioScheduler`：tokio-cron-scheduler 实例
/// - `DatabaseConnection`：用于任务执行时写日志（Clone 廉价，内部 Arc 共享连接池）
/// - `running_jobs`：job_id → scheduler 内部 job guid 映射（用于精确移除）
/// - `executing_jobs`：正在执行中的任务标记（用于并发控制）
pub struct JobScheduler {
    scheduler: Arc<TokioScheduler>,
    db: DatabaseConnection,
    /// Redis 连接管理器，用于分布式锁（多实例部署时防止任务重复执行）
    redis: ConnectionManager,
    /// 运行中任务的 UUID 映射（job_id -> scheduler 内部 job guid）
    running_jobs: RwLock<HashMap<i64, uuid::Uuid>>,
    /// 正在执行中的任务标记（job_id -> true）
    /// 用于 concurrent='1' 时禁止并发执行
    /// 使用 std::sync::Mutex 以支持 ExecutingFlagGuard 的同步 Drop
    /// （锁持有时间极短，不跨 await，符合异步上下文使用约束）
    executing_jobs: Arc<std::sync::Mutex<HashMap<i64, bool>>>,
}

impl JobScheduler {
    /// 创建并启动调度器
    ///
    /// 内部流程：
    /// 1. 创建 TokioScheduler 并 start()
    /// 2. 注册内置任务函数到 registry
    pub async fn new(
        db: DatabaseConnection,
        redis: ConnectionManager,
        ip_location_service: crate::service::IpLocationService,
    ) -> Result<Self, SchedulerError> {
        let scheduler = TokioScheduler::new()
            .await
            .map_err(|e| SchedulerError::SchedulerInternal(format!("创建调度器失败: {}", e)))?;

        scheduler
            .start()
            .await
            .map_err(|e| SchedulerError::SchedulerInternal(format!("启动调度器失败: {}", e)))?;

        // 注册内置任务函数（含日志保留期清理任务）
        register_builtin_tasks(db.clone());

        // 注册并调度内置 cron 任务（日志保留期清理，每日凌晨 3:00 执行；登录异常检测，每 5 分钟执行；IP 库自动更新，按 cron 配置）
        if let Err(e) = Self::register_builtin_scheduled_jobs(
            &scheduler,
            db.clone(),
            redis.clone(),
            ip_location_service,
        )
        .await
        {
            tracing::warn!("内置定时任务调度注册失败（不阻断启动）: {}", e);
        }

        Ok(Self {
            scheduler: Arc::new(scheduler),
            db,
            redis,
            running_jobs: RwLock::new(HashMap::new()),
            executing_jobs: Arc::new(std::sync::Mutex::new(HashMap::new())),
        })
    }

    /// 注册并调度内置 cron 任务（直接添加到 TokioScheduler，不依赖 sys_job 表）
    ///
    /// 目前注册的内置调度任务：
    /// - `cleanup_expired_logs`：每日凌晨 3:00 清理 90 天前的日志（P0-R81-019，cron: "0 0 3 * * *"）
    /// - `login_anomaly_detector`：每 5 分钟扫描最近 5 分钟失败登录，按 IP 分组阈值告警
    /// - `mmdb_auto_update`：按 `config.ip_location.auto_update_cron` 定时更新 mmdb 文件（默认每周二 04:00）
    async fn register_builtin_scheduled_jobs(
        scheduler: &TokioScheduler,
        db: DatabaseConnection,
        redis: ConnectionManager,
        ip_location_service: crate::service::IpLocationService,
    ) -> Result<(), SchedulerError> {
        // 先 clone 出登录异常检测任务所需的 db/redis，避免被 cleanup_job 闭包 move 后无法使用
        let anomaly_db = db.clone();
        let anomaly_redis = redis.clone();

        // 日志保留期清理任务：每日凌晨 3:00 执行（cron: "0 0 3 * * *"）
        // 删除 90 天前的操作日志和登录日志，避免日志表无限增长导致生产崩溃
        // FIX-Cron: tokio-cron-scheduler 0.15.1 强制要求 6 字段（含秒）cron 表达式，
        // 5 字段的 "0 3 * * *" 会触发 ParseSchedule 错误，改为 "0 0 3 * * *"（秒=0 分=0 时=3）
        let cleanup_job = Job::new_async("0 0 3 * * *", move |_uuid, _l| {
            let db = db.clone();
            Box::pin(async move {
                tracing::info!("内置任务 cleanup_expired_logs 开始执行：清理 90 天前的日志");

                // 清理操作日志
                let oper_log_service =
                    crate::service::sys_oper_log_service::SysOperLogService::new(db.clone());
                let logininfor_service =
                    crate::service::sys_logininfor_service::SysLogininforService::new(db.clone());

                const RETENTION_DAYS: i64 = 90;

                match oper_log_service.cleanup_old_logs(RETENTION_DAYS).await {
                    Ok(affected) => {
                        tracing::info!(
                            "cleanup_expired_logs: 清理操作日志 {} 条（保留 {} 天）",
                            affected, RETENTION_DAYS
                        );
                    }
                    Err(e) => {
                        tracing::error!(
                            "cleanup_expired_logs: 清理操作日志失败: {}",
                            e
                        );
                    }
                }

                match logininfor_service.cleanup_old_logs(RETENTION_DAYS).await {
                    Ok(affected) => {
                        tracing::info!(
                            "cleanup_expired_logs: 清理登录日志 {} 条（保留 {} 天）",
                            affected, RETENTION_DAYS
                        );
                    }
                    Err(e) => {
                        tracing::error!(
                            "cleanup_expired_logs: 清理登录日志失败: {}",
                            e
                        );
                    }
                }
            })
        })
        .map_err(|e| SchedulerError::SchedulerInternal(format!("创建日志清理任务失败: {}", e)))?;

        scheduler
            .add(cleanup_job)
            .await
            .map_err(|e| SchedulerError::SchedulerInternal(format!("添加日志清理任务失败: {}", e)))?;

        tracing::info!("内置定时任务注册成功: cleanup_expired_logs (cron: '0 0 3 * * *', 保留 90 天)");

        // 登录异常检测任务：每 5 分钟执行（cron: "0 */5 * * * *"）
        // 扫描最近 5 分钟 sys_logininfor 失败记录，按 IP 分组，count>=5 视为撞库攻击
        // 为每个异常 IP 创建 sys_notice 通知，同一 IP 30 分钟内不重复告警（Redis SETNX 去重）
        let anomaly_job = Job::new_async("0 */5 * * * *", move |_uuid, _l| {
            let db = anomaly_db.clone();
            let mut redis = anomaly_redis.clone();
            Box::pin(async move {
                tracing::debug!("内置任务 login_anomaly_detector 开始执行：扫描最近 5 分钟登录失败记录");

                let logininfor_service =
                    crate::service::sys_logininfor_service::SysLogininforService::new(db.clone());
                let notice_service =
                    crate::service::sys_notice_service::SysNoticeService::new(db.clone());

                // 查询最近 5 分钟的失败登录，按 IP 分组，count >= 5 视为异常
                const WINDOW_MINUTES: i64 = 5;
                const FAIL_THRESHOLD: i64 = 5;
                const DEDUP_TTL_SECS: u64 = 30 * 60; // 30 分钟

                let since = chrono::Local::now().naive_local()
                    - chrono::Duration::minutes(WINDOW_MINUTES);

                let anomaly_ips = match logininfor_service
                    .find_failed_group_by_ip(since, FAIL_THRESHOLD)
                    .await
                {
                    Ok(rows) => rows,
                    Err(e) => {
                        tracing::error!("login_anomaly_detector: 查询失败登录分组失败: {}", e);
                        return;
                    }
                };

                if anomaly_ips.is_empty() {
                    tracing::debug!("login_anomaly_detector: 最近 {} 分钟无异常 IP", WINDOW_MINUTES);
                    return;
                }

                for (ip, count) in anomaly_ips {
                    let dedup_key = format!("login_anomaly:{}", ip);
                    // SETNX 去重：30 分钟内同一 IP 不重复创建告警
                    let acquired: Option<String> = redis::cmd("SET")
                        .arg(&dedup_key)
                        .arg("1")
                        .arg("NX")
                        .arg("EX")
                        .arg(DEDUP_TTL_SECS)
                        .query_async(&mut redis)
                        .await
                        .unwrap_or(None);

                    if acquired.is_none() {
                        tracing::debug!(
                            "login_anomaly_detector: IP {} 在 {} 分钟内已告警，跳过",
                            ip,
                            DEDUP_TTL_SECS / 60
                        );
                        continue;
                    }

                    let dto = crate::service::sys_notice_service::NoticeAddDto {
                        notice_title: format!("登录异常告警 - IP {}", ip),
                        notice_type: "1".to_string(),
                        notice_content: Some(format!(
                            "最近 {} 分钟内 IP {} 失败登录 {} 次，疑似撞库攻击，请及时关注。",
                            WINDOW_MINUTES, ip, count
                        )),
                        status: Some("0".to_string()),
                        remark: Some(format!("auto-detected;ip={};count={}", ip, count)),
                        notify_email: false,
                    };

                    match notice_service.add_notice(dto, "system/scheduler", None).await {
                        Ok(_) => {
                            tracing::warn!(
                                "login_anomaly_detector: 已为 IP {} 创建告警通知（失败 {} 次）",
                                ip,
                                count
                            );
                        }
                        Err(e) => {
                            tracing::error!(
                                "login_anomaly_detector: 为 IP {} 创建告警失败: {}",
                                ip,
                                e
                            );
                        }
                    }
                }
            })
        })
        .map_err(|e| SchedulerError::SchedulerInternal(format!("创建登录异常检测任务失败: {}", e)))?;

        scheduler.add(anomaly_job).await.map_err(|e| {
            SchedulerError::SchedulerInternal(format!("添加登录异常检测任务失败: {}", e))
        })?;

        tracing::info!(
            "内置定时任务注册成功: login_anomaly_detector (cron: '0 */5 * * * *', 阈值 5 次/5 分钟)"
        );

        // IP 库自动更新任务：按 config.ip_location.auto_update_cron 定时更新 mmdb 文件
        // 默认 cron: "0 0 4 * * 2"（每周二凌晨 4:00）
        // 设计要点：
        // - 读取 sys_config 表的 auto_update_enabled 开关（双开关：cron 非空 + sys_config 开关）
        // - 使用 Redis 分布式锁防止多实例并发下载（锁 key: lock:scheduler:mmdb_auto_update）
        // - 锁 TTL 30 分钟（mmdb 下载约 60-100MB，耗时 1-5 分钟，留充足余量）
        // - 调用 IpLocationService::update_now(None) 执行下载+校验+热加载
        // - 失败不阻断调度器和其他任务
        let mmdb_cron = ip_location_service.auto_update_cron().to_string();
        let mmdb_redis = redis.clone();
        let mmdb_service = ip_location_service.clone();

        if mmdb_cron.trim().is_empty() {
            tracing::info!(
                "内置定时任务 mmdb_auto_update 未注册：config.ip_location.auto_update_cron 为空（禁用自动更新）"
            );
        } else {
            // 验证 cron 表达式有效性（提前 fail-fast，避免运行时才发现错误）
            match Job::new_async(mmdb_cron.as_str(), move |_uuid, _l| {
                let mut redis = mmdb_redis.clone();
                let service = mmdb_service.clone();
                Box::pin(async move {
                    tracing::info!("内置任务 mmdb_auto_update 触发：检查并更新 IP 库");

                    // 双开关检查：sys_config 表的 auto_update_enabled
                    let cfg = match service.read_config().await {
                        Ok(c) => c,
                        Err(e) => {
                            tracing::error!("mmdb_auto_update: 读取配置失败: {}", e);
                            return;
                        }
                    };
                    if !cfg.auto_update_enabled {
                        tracing::debug!("mmdb_auto_update: auto_update_enabled=false，跳过本次执行");
                        return;
                    }

                    // Redis 分布式锁（fail-closed：Redis 故障时跳过执行，避免多实例并发下载）
                    const MMDB_LOCK_KEY: &str = "lock:scheduler:mmdb_auto_update";
                    const MMDB_LOCK_TTL_SECS: u64 = 30 * 60; // 30 分钟
                    let lock_value = uuid::Uuid::new_v4().to_string();

                    let lock_result: Option<String> = redis::cmd("SET")
                        .arg(MMDB_LOCK_KEY)
                        .arg(&lock_value)
                        .arg("NX")
                        .arg("EX")
                        .arg(MMDB_LOCK_TTL_SECS)
                        .query_async(&mut redis)
                        .await
                        .unwrap_or(None);

                    if lock_result.is_none() {
                        tracing::info!("mmdb_auto_update: 其他实例正在执行 IP 库更新，跳过本次调度");
                        return;
                    }

                    // 执行更新（下载 + 校验 + 热加载）
                    match service.update_now(None).await {
                        Ok(result) => {
                            tracing::info!(
                                "mmdb_auto_update: IP 库更新成功 - source={}, size={}B, elapsed={:.2}s, sha256={}",
                                result.source,
                                result.new_size,
                                result.elapsed_seconds,
                                &result.new_sha256[..16]
                            );
                        }
                        Err(e) => {
                            tracing::error!("mmdb_auto_update: IP 库更新失败: {}", e);
                        }
                    }

                    // 释放锁（CAS：仅当 lock_value 匹配时删除，避免误删其他实例的锁）
                    // Lua 脚本保证 GET + DEL 原子性
                    let lua_script = r#"
                        if redis.call('GET', KEYS[1]) == ARGV[1] then
                            return redis.call('DEL', KEYS[1])
                        else
                            return 0
                        end
                    "#;
                    let _: redis::RedisResult<i64> = redis::cmd("EVAL")
                        .arg(lua_script)
                        .arg(1)
                        .arg(MMDB_LOCK_KEY)
                        .arg(&lock_value)
                        .query_async(&mut redis)
                        .await;
                })
            }) {
                Ok(mmdb_job) => {
                    scheduler.add(mmdb_job).await.map_err(|e| {
                        SchedulerError::SchedulerInternal(format!(
                            "添加 IP 库自动更新任务失败: {}",
                            e
                        ))
                    })?;
                    tracing::info!(
                        "内置定时任务注册成功: mmdb_auto_update (cron: '{}', 默认源由 sys_config 决定, Redis 分布式锁已启用)",
                        mmdb_cron
                    );
                }
                Err(e) => {
                    tracing::warn!(
                        "内置定时任务 mmdb_auto_update 注册失败（cron 表达式无效: '{}'）: {}",
                        mmdb_cron,
                        e
                    );
                }
            }
        }

        Ok(())
    }

    /// 从数据库加载所有 status='0' AND del_flag='0' 的任务并注册
    ///
    /// - 单个任务加载失败不阻断其他任务
    /// - misfire_policy='1'/'2' 的任务补执行一次
    pub async fn load_from_db(
        &self,
        job_repo: &SysJobRepository,
    ) -> Result<(), SchedulerError> {
        let jobs = job_repo
            .find_by_status("0")
            .await
            .map_err(|e| SchedulerError::SchedulerInternal(format!("加载任务失败: {}", e)))?;

        for job in jobs {
            match self.add_job(&job).await {
                Ok(_) => {
                    tracing::info!(
                        "任务加载成功: job_id={}, job_name={}",
                        job.job_id,
                        job.job_name
                    );

                    // misfire_policy='1' 或 '2' 的任务补执行一次
                    let misfire = job.misfire_policy.as_deref().unwrap_or("3");
                    if misfire == "1" || misfire == "2" {
                        tracing::info!(
                            "任务 job_id={} misfire_policy={}，启动时补执行一次",
                            job.job_id,
                            misfire
                        );
                        self.run_once(&job).await?;
                    }
                }
                Err(e) => {
                    tracing::warn!(
                        "任务加载失败: job_id={}, job_name={}, error={}",
                        job.job_id,
                        job.job_name,
                        e
                    );
                }
            }
        }

        Ok(())
    }

    /// 添加任务到调度器
    ///
    /// - 解析 cron 表达式（非法返回 InvalidCron）
    /// - 创建 Job（闭包内调用 execute 逻辑）
    /// - 注册到调度器
    /// - 记录 uuid 到 running_jobs
    pub async fn add_job(&self, job: &SysJobModel) -> Result<uuid::Uuid, SchedulerError> {
        let cron_str = job.cron_expression.as_deref().unwrap_or("");
        if cron_str.is_empty() {
            return Err(SchedulerError::InvalidCron("cron 表达式为空".to_string()));
        }

        // 校验 cron 合法性
        validate_cron(cron_str)?;

        let job_id = job.job_id;
        let job_clone = job.clone();
        let db = self.db.clone();
        let redis = self.redis.clone();
        let executing_jobs = self.executing_jobs.clone();

        // 创建调度任务
        let sched_job = Job::new_async(cron_str, move |_uuid, _l| {
            let job = job_clone.clone();
            let db = db.clone();
            let mut redis = redis.clone();
            let executing_jobs = executing_jobs.clone();

            Box::pin(async move {
                // catch_unwind 捕获 async fn 内部的 panic，防止 panic 影响调度器运行时
                // 注意：std::panic::catch_unwind 无法捕获 async fn poll 时的 panic，
                // 必须使用 futures::FutureExt::catch_unwind 对 Future 本身进行捕获
                let result = AssertUnwindSafe(execute_with_logging(&db, &mut redis, &executing_jobs, &job))
                    .catch_unwind()
                    .await;

                if let Err(panic_err) = result {
                    tracing::error!(
                        "定时任务执行 panic: job_id={}, job_name={}, panic={:?}",
                        job.job_id,
                        job.job_name,
                        panic_err
                    );
                }
            })
        })
        .map_err(|e| SchedulerError::InvalidCron(format!("cron 解析失败: {}", e)))?;

        let guid = sched_job.guid();

        self.scheduler
            .add(sched_job)
            .await
            .map_err(|e| SchedulerError::SchedulerInternal(format!("添加任务失败: {}", e)))?;

        // 记录 uuid 到 running_jobs
        {
            let mut running = self.running_jobs.write().await;
            running.insert(job_id, guid);
        }

        tracing::info!("任务注册成功: job_id={}, guid={}", job_id, guid);
        Ok(guid)
    }

    /// 从调度器移除任务（幂等：不存在时静默成功）
    pub async fn remove_job(&self, job_id: i64) -> Result<(), SchedulerError> {
        let guid = {
            let mut running = self.running_jobs.write().await;
            running.remove(&job_id)
        };

        if let Some(guid) = guid {
            self.scheduler
                .remove(&guid)
                .await
                .map_err(|e| SchedulerError::SchedulerInternal(format!("移除任务失败: {}", e)))?;
            tracing::info!("任务移除成功: job_id={}, guid={}", job_id, guid);
        } else {
            tracing::warn!("任务移除跳过：调度器中不存在 job_id={}", job_id);
        }

        Ok(())
    }

    /// 更新任务（先移除再添加）
    pub async fn update_job(&self, job: &SysJobModel) -> Result<(), SchedulerError> {
        self.remove_job(job.job_id).await?;
        self.add_job(job).await?;
        Ok(())
    }

    /// 手动执行一次（不注册调度，直接 spawn）
    ///
    /// 使用 AssertUnwindSafe + catch_unwind 捕获任务函数 panic，
    /// 确保 panic 被记录日志且不影响调度器运行时
    pub async fn run_once(&self, job: &SysJobModel) -> Result<(), SchedulerError> {
        let db = self.db.clone();
        let mut redis = self.redis.clone();
        let executing_jobs = self.executing_jobs.clone();
        let job_clone = job.clone();

        tokio::spawn(async move {
            // catch_unwind 捕获 async fn 内部的 panic，防止 panic 跨 spawn 边界传播
            // 注意：std::panic::catch_unwind 无法捕获 async fn poll 时的 panic，
            // 必须使用 futures::FutureExt::catch_unwind 对 Future 本身进行捕获
            let result = AssertUnwindSafe(execute_with_logging(&db, &mut redis, &executing_jobs, &job_clone))
                .catch_unwind()
                .await;

            if let Err(panic_err) = result {
                tracing::error!(
                    "任务执行 panic: job_id={}, job_name={}, panic={:?}",
                    job_clone.job_id,
                    job_clone.job_name,
                    panic_err
                );
                // ExecutingFlagGuard 的 Drop 已在 unwind 过程中清除标记
            }
        });

        Ok(())
    }

    /// 关闭调度器，停止所有定时任务（P0-R81-020）
    ///
    /// 用于优雅关闭流程：在 main.rs 的 shutdown 流程中调用。
    /// 内部通过克隆 TokioScheduler 获得 `&mut self` 访问权（tokio-cron-scheduler 的
    /// shutdown 方法签名为 `&mut self`，但其内部状态均为 Arc 共享，克隆后调用 shutdown
    /// 会影响原始实例的调度循环）。
    ///
    /// 建议调用方使用 `tokio::time::timeout` 包装以防关闭流程卡死：
    /// ```ignore
    /// let _ = tokio::time::timeout(Duration::from_secs(10), scheduler.shutdown()).await;
    /// ```
    pub async fn shutdown(&self) -> Result<(), SchedulerError> {
        tracing::info!("正在关闭调度器...");
        // 克隆 TokioScheduler（共享内部 Arc 状态）以获取 owned 实例，
        // 从而可以调用需要 `&mut self` 的 shutdown 方法。
        // 由于内部 scheduler 字段为 Arc<RwLock<Scheduler>>，克隆后调用 shutdown
        // 仍会影响原始实例的调度循环。
        let mut sched = (*self.scheduler).clone();
        sched
            .shutdown()
            .await
            .map_err(|e| SchedulerError::SchedulerInternal(format!("调度器关闭失败: {}", e)))?;
        tracing::info!("调度器已关闭");
        Ok(())
    }
}

// ==================== 内部函数 ====================

/// 校验 cron 表达式合法性
///
/// 使用 `croner::Cron::from_str` 解析（与 tokio-cron-scheduler 内部使用的 cron 解析库一致，
/// 避免同时引入 cron 和 croner 两个功能重复的 crate）
///
/// FIX-Cron: tokio-cron-scheduler 0.15.1 的 `Job::new_async` 内部使用
/// `CronParser::builder().seconds(Seconds::Required)` 强制要求 6 字段（含秒）cron 表达式，
/// 而默认的 `Cron::from_str` 接受 5 字段格式。为保持校验与实际调度行为一致，
/// 这里也使用 `Seconds::Required` 构建解析器，提前拒绝 5 字段表达式。
fn validate_cron(cron_str: &str) -> Result<(), SchedulerError> {
    use croner::parser::CronParser;
    let cron = CronParser::builder()
        .seconds(croner::parser::Seconds::Required)
        .dom_and_dow(true)
        .build()
        .parse(cron_str)
        .map_err(|e| SchedulerError::InvalidCron(format!("{}", e)))?;
    // 触发一次 next_occurrence 计算以尽早暴露无效模式（如 2月30日）
    use chrono::Utc;
    cron.find_next_occurrence(&Utc::now(), false)
        .map_err(|e| SchedulerError::InvalidCron(format!("无法计算下次执行时间: {}", e)))?;
    Ok(())
}

/// 执行中标记守卫
///
/// RAII 模式：创建时标记执行中，Drop 时清除标记。
/// 确保即使任务函数 panic，标记也会被清除，避免 concurrent='1' 任务永久禁用。
///
/// 注意：由于 `tokio::sync::RwLock` 的 write() 是 async，不能在同步 Drop 中调用，
/// 因此本 guard 采用 `std::sync::Mutex<HashMap>` 存储标记的独立 map。
/// 调度闭包内不跨 await 持有此锁，符合 std::sync::Mutex 在异步上下文的使用约束。
struct ExecutingFlagGuard {
    flags: Arc<std::sync::Mutex<HashMap<i64, bool>>>,
    job_id: i64,
    /// 是否需要清除（若并发跳过则不需要清除）
    armed: bool,
}

impl ExecutingFlagGuard {
    /// 原子化 check-and-set 获取执行权（防止 TOCTOU 竞态）
    ///
    /// 在同一锁内完成「检查是否已在执行」与「标记执行中」两步操作，
    /// 避免 check-then-set 分离导致的并发重复执行（P0-6/P0-30）。
    ///
    /// 参数：
    /// - `enforce_concurrent`: 是否强制并发禁止（concurrent='1' 时为 true）
    ///
    /// 返回：
    /// - `Some(guard)`: 获取执行权成功（已标记 executing_jobs[job_id]=true）
    /// - `None`: 已有任务在执行中（仅 enforce_concurrent=true 时返回）
    fn try_acquire(
        flags: Arc<std::sync::Mutex<HashMap<i64, bool>>>,
        job_id: i64,
        enforce_concurrent: bool,
    ) -> Option<Self> {
        {
            let mut map = flags.lock().unwrap_or_else(|e| e.into_inner());
            if enforce_concurrent && map.get(&job_id).copied().unwrap_or(false) {
                return None;
            }
            map.insert(job_id, true);
        }
        Some(Self {
            flags,
            job_id,
            armed: true,
        })
    }

    /// 释放前清除标记（正常路径可显式调用，避免等待 Drop）
    fn disarm(&mut self) {
        if self.armed {
            let mut map = self.flags.lock().unwrap_or_else(|e| e.into_inner());
            map.remove(&self.job_id);
            self.armed = false;
        }
    }
}

impl Drop for ExecutingFlagGuard {
    fn drop(&mut self) {
        if self.armed {
            let mut map = self.flags.lock().unwrap_or_else(|e| e.into_inner());
            map.remove(&self.job_id);
        }
    }
}

/// 释放分布式锁（CAS：仅当锁 value 匹配时才删除，避免误删他人的锁）（P0-6/30 改进）
///
/// 使用 Lua 脚本保证 GET + DEL 的原子性，避免以下竞态：
/// 1. 客户端 A 持有锁（value=A），因 GC 暂停或任务超时导致锁过期
/// 2. 客户端 B 获取锁（value=B）
/// 3. 客户端 A 恢复后执行 DEL，误删了 B 的锁，导致 B 的任务重复执行
///
/// CAS 校验（fencing token）确保只有 value 匹配时才删除。
async fn release_lock(redis: &mut ConnectionManager, lock_key: &str, lock_value: &str) {
    // Lua 脚本：KEYS[1]=lock_key, ARGV[1]=expected lock_value
    let del_script = r#"
if redis.call("GET", KEYS[1]) == ARGV[1] then
    return redis.call("DEL", KEYS[1])
else
    return 0
end
"#;
    let _: redis::Value = redis::Script::new(del_script)
        .key(lock_key)
        .arg(lock_value)
        .invoke_async(redis)
        .await
        .unwrap_or(redis::Value::Nil);
}

/// 续期分布式锁（CAS：仅当锁 value 匹配时才延长 TTL）（R8-CONC-007）
///
/// 使用 Lua 脚本保证 GET + EXPIRE 的原子性，避免以下竞态：
/// 1. 客户端 A 持有锁（value=A），但因 GC 暂停或网络延迟导致锁过期
/// 2. 客户端 B 获取锁（value=B）
/// 3. 客户端 A 恢复后调用 EXPIRE，错误地延长了 B 的锁，导致 B 的任务被误判仍持锁
///
/// CAS 校验（fencing token）确保只有 value 匹配时才续期。
/// 返回 true 表示续期成功，false 表示锁已被其他实例持有（应中止当前任务）。
async fn renew_lock(
    redis: &mut ConnectionManager,
    lock_key: &str,
    lock_value: &str,
    ttl_secs: u64,
) -> bool {
    // Lua 脚本：KEYS[1]=lock_key, ARGV[1]=expected lock_value, ARGV[2]=new TTL
    let renew_script = r#"
if redis.call("GET", KEYS[1]) == ARGV[1] then
    return redis.call("EXPIRE", KEYS[1], ARGV[2])
else
    return 0
end
"#;
    let result: i64 = redis::Script::new(renew_script)
        .key(lock_key)
        .arg(lock_value)
        .arg(ttl_secs)
        .invoke_async(redis)
        .await
        .unwrap_or(0);
    result == 1
}

/// 执行任务并写日志（统一执行逻辑，供定时触发和手动执行复用）
///
/// 分布式锁：通过 Redis SETNX 实现，多实例部署时防止任务重复执行（P0-58）
/// 并发控制：concurrent='1' 时通过原子 check-and-set 跳过重叠执行（P0-6/P0-30）
/// 超时控制：60 秒
/// 异常隔离：使用 ExecutingFlagGuard 确保即使 panic 标记也被清除
async fn execute_with_logging(
    db: &DatabaseConnection,
    redis: &mut ConnectionManager,
    executing_jobs: &Arc<std::sync::Mutex<HashMap<i64, bool>>>,
    job: &SysJobModel,
) {
    // 分布式锁：Redis SETNX，TTL 90 秒（REGRESS-008：原 30s < 任务 60s 超时，锁过期后可重复执行）
    // 多实例部署时，其他实例获取锁失败则跳过本次执行
    // P0-6/30 改进：锁 value 使用随机 UUID 作为 fencing token，
    // 释放时通过 Lua CAS 脚本校验，避免误删其他实例持有的锁
    let lock_key = format!("lock:scheduler:{}", job.job_id);
    let lock_value = uuid::Uuid::new_v4().to_string();
    let lock_result: Result<Option<String>, _> = redis::cmd("SET")
        .arg(&lock_key)
        .arg(&lock_value)
        .arg("NX")
        .arg("EX")
        .arg(LOCK_TTL_SECS)
        .query_async(redis)
        .await;

    // Redis 故障 fail-closed 策略（P0-R81-012）：
    // - Redis 不可用时直接跳过本次执行，避免多实例部署下的任务重复执行
    // - 之前采用降级模式（视为获取锁成功继续执行），多实例部署会导致任务重复执行
    // - 现在 fail-closed：Redis 错误时 tracing::error! 记录并 return，跳过执行
    // - 单实例部署下若有 Redis 依赖则需尽快恢复，否则任务不执行
    //
    // M-6 Major 告警提升：Redis 持续故障会导致所有定时任务停止执行，需运维介入。
    // 原先使用 warn 级别，告警系统通常不监控 warn；改为 error 级别确保告警触发。
    let lock_acquired = match lock_result {
        Ok(v) => v,
        Err(e) => {
            tracing::error!(
                "Redis 连接失败，跳过本次任务执行以避免多实例重复 (job_id={}, job_name={}, error={})。\
                 注意：Redis 持续故障会导致所有定时任务停止执行，需运维介入恢复 Redis 服务",
                job.job_id,
                job.job_name,
                e
            );
            return;
        }
    };

    if lock_acquired.is_none() {
        tracing::debug!(
            "任务 {} 被其他实例持有分布式锁，跳过本次执行",
            job.job_name
        );
        return;
    }

    let concurrent = job.concurrent.as_deref().unwrap_or("1");
    let enforce_concurrent = concurrent == "1";

    // 原子化 check-and-set 获取执行权（防止 TOCTOU 竞态导致重复执行）
    let mut guard = match ExecutingFlagGuard::try_acquire(
        executing_jobs.clone(),
        job.job_id,
        enforce_concurrent,
    ) {
        Some(g) => g,
        None => {
            tracing::debug!(
                "任务 {} 禁止并发，跳过本次执行",
                job.job_name
            );
            // 释放分布式锁（本实例并发跳过，允许其他实例或其他周期执行）
            // P0-6/30 改进：使用 CAS 释放，避免误删其他实例持有的锁
            release_lock(redis, &lock_key, &lock_value).await;
            return;
        }
    };

    let start = std::time::Instant::now();

    // R8-CONC-007: 启动锁续期任务，任务执行过半时调用 Lua 脚本续期
    //
    // 续期间隔取 LOCK_RENEW_INTERVAL_SECS（= TASK_TIMEOUT_SECS / 2），确保任务执行过半时触发续期。
    // 续期使用 CAS Lua 脚本（renew_lock），仅当锁 value 仍为本实例的 fencing token 时才延长 TTL，
    // 避免误续期其他实例持有的锁。
    //
    // 续期任务在独立 tokio::spawn 中运行，与主任务并发：
    // - 主任务完成（成功/失败/超时）后，调用 abort() 取消续期任务
    // - 续期失败（锁丢失）时仅 warn 告警，不中止主任务（无法安全回滚已开始的执行）
    //   锁丢失意味着另一实例可能已开始执行相同任务，需运维介入排查
    let renew_handle = {
        let redis_clone = redis.clone();
        let lock_key_clone = lock_key.clone();
        let lock_value_clone = lock_value.clone();
        let job_name_clone = job.job_name.clone();
        let job_id = job.job_id;
        tokio::spawn(async move {
            // 首次 sleep 一个完整间隔，避免刚获取锁就立即续期
            tokio::time::sleep(Duration::from_secs(LOCK_RENEW_INTERVAL_SECS)).await;
            loop {
                let mut conn = redis_clone.clone();
                let renewed = renew_lock(
                    &mut conn,
                    &lock_key_clone,
                    &lock_value_clone,
                    LOCK_TTL_SECS,
                )
                .await;
                if renewed {
                    tracing::trace!(
                        "任务 {} 的分布式锁续期成功 (job_id={})",
                        job_name_clone,
                        job_id
                    );
                    // 继续下一轮续期
                    tokio::time::sleep(Duration::from_secs(LOCK_RENEW_INTERVAL_SECS)).await;
                } else {
                    tracing::warn!(
                        "任务 {} 的分布式锁续期失败，锁可能已被其他实例获取 (job_id={})。\
                         另一实例可能正在重复执行此任务，需运维介入排查",
                        job_name_clone,
                        job_id
                    );
                    // 锁已丢失，停止续期（继续重试也只会失败）
                    break;
                }
            }
        })
    };

    // 执行任务（捕获 panic，避免 panic 跨 spawn 边界传播）
    let (status, message, exception_info) = match execute_inner(&job.invoke_target).await {
        Ok(msg) => ("0", msg, String::new()),
        Err(e) => ("1", format!("任务执行失败: {}", e), e.to_string()),
    };

    // 主任务完成（成功/失败/超时），取消续期任务
    renew_handle.abort();

    let elapsed = start.elapsed().as_millis();

    // 正常路径显式释放标记
    guard.disarm();

    // 释放分布式锁
    // P0-6/30 改进：使用 CAS 释放，避免误删其他实例持有的锁
    release_lock(redis, &lock_key, &lock_value).await;

    // 写日志（失败不影响主流程）
    let log_repo = SysJobLogRepository::new(db.clone());
    let log_am = sys_job_log::ActiveModel {
        job_name: Set(job.job_name.clone()),
        job_group: Set(job.job_group.clone()),
        invoke_target: Set(job.invoke_target.clone()),
        job_message: Set(Some(format!("{} (耗时 {}ms)", message, elapsed))),
        status: Set(Some(status.to_string())),
        exception_info: if exception_info.is_empty() {
            Set(None)
        } else {
            Set(Some(exception_info))
        },
        create_time: Set(Some(chrono::Local::now().naive_local())),
        ..Default::default()
    };
    if let Err(e) = log_repo.insert(log_am).await {
        tracing::error!("写入任务日志失败 job_id={}: {}", job.job_id, e);
    }
}

/// 执行任务内部函数
///
/// - 从 registry 查表获取任务函数
/// - 超时控制：TASK_TIMEOUT_SECS 秒
///
/// R5-TYPE-19：错误类型改为 `Box<dyn Error + Send + Sync>`，支持类型化错误传播。
async fn execute_inner(
    invoke_target: &str,
) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    let func = registry::get_task(invoke_target)
        .ok_or_else(|| format!("未找到调用目标: {}", invoke_target))?;

    // REGRESS-008：使用常量 TASK_TIMEOUT_SECS，与 LOCK_TTL_SECS 保持联动
    tokio::time::timeout(Duration::from_secs(TASK_TIMEOUT_SECS), func())
        .await
        .map_err(|_| format!("任务执行超时（>{}s）", TASK_TIMEOUT_SECS))?
}

/// 注册内置任务函数
///
/// 对齐 ref-salvo-admin 初始数据，invoke_target 完整字符串作为 key。
/// 同时注册日志保留期清理任务 cleanup_expired_logs（P0-R81-019）。
///
/// 注意：cleanup_expired_logs 任务函数本身只执行清理逻辑，
/// 调度时间由 `register_builtin_scheduled_jobs` 中的 cron "0 0 3 * * *" 控制。
/// 此处注册函数仅用于通过 invoke_target 调用（如手动执行测试）。
fn register_builtin_tasks(db: DatabaseConnection) {
    // ryTask.ryNoParams — 无参数示例任务
    // 演示调度器最简调用形式：无参数、返回成功消息
    registry::register_task(
        "ryTask.ryNoParams",
        Arc::new(|| {
            Box::pin(async {
                tracing::info!("ryTask.ryNoParams 示例任务触发（无参数）");
                Ok("ryNoParams 示例任务执行成功（无业务逻辑，仅演示调度器调用）".to_string())
            })
        }),
    );

    // ryTask.ryParams('ry') — 带参数示例任务
    // 演示带字符串参数的任务调用形式
    registry::register_task(
        "ryTask.ryParams('ry')",
        Arc::new(|| {
            Box::pin(async {
                tracing::info!("ryTask.ryParams('ry') 示例任务触发（带字符串参数）");
                Ok("ryParams 示例任务执行成功，参数: ry（无业务逻辑，仅演示参数传递）".to_string())
            })
        }),
    );

    // ryTask.ryMultipleParams('ry', true, 2000L, 316.5F, 100) — 多参数示例任务
    // 演示多类型参数（字符串/布尔/长整型/浮点/整型）的任务调用形式
    registry::register_task(
        "ryTask.ryMultipleParams('ry', true, 2000L, 316.5F, 100)",
        Arc::new(|| {
            Box::pin(async {
                tracing::info!("ryTask.ryMultipleParams 示例任务触发（多类型参数）");
                Ok("ryMultipleParams 示例任务执行成功（无业务逻辑，仅演示多参数传递）".to_string())
            })
        }),
    );

    // cleanup_expired_logs — 日志保留期清理任务（P0-R81-019）
    // 删除 90 天前的操作日志和登录日志，避免日志表无限增长导致生产崩溃
    // 调度时间：每日凌晨 3:00（由 register_builtin_scheduled_jobs 中 cron "0 0 3 * * *" 控制）
    let cleanup_db = db.clone();
    registry::register_task(
        "cleanup_expired_logs",
        Arc::new(move || {
            let db = cleanup_db.clone();
            Box::pin(async move {
                tracing::info!("任务 cleanup_expired_logs 调用：清理 90 天前的日志");

                let oper_log_service =
                    crate::service::sys_oper_log_service::SysOperLogService::new(db.clone());
                let logininfor_service =
                    crate::service::sys_logininfor_service::SysLogininforService::new(db.clone());

                const RETENTION_DAYS: i64 = 90;
                let mut messages = Vec::new();

                match oper_log_service.cleanup_old_logs(RETENTION_DAYS).await {
                    Ok(affected) => {
                        let msg = format!("清理操作日志 {} 条", affected);
                        tracing::info!("{}", msg);
                        messages.push(msg);
                    }
                    Err(e) => {
                        let msg = format!("清理操作日志失败: {}", e);
                        tracing::error!("{}", msg);
                        return Err(msg.into());
                    }
                }

                match logininfor_service.cleanup_old_logs(RETENTION_DAYS).await {
                    Ok(affected) => {
                        let msg = format!("清理登录日志 {} 条", affected);
                        tracing::info!("{}", msg);
                        messages.push(msg);
                    }
                    Err(e) => {
                        let msg = format!("清理登录日志失败: {}", e);
                        tracing::error!("{}", msg);
                        return Err(msg.into());
                    }
                }

                Ok(messages.join("; "))
            })
        }),
    );

    tracing::info!(
        "内置任务注册完成: {:?}",
        registry::list_registered_tasks()
    );
}
