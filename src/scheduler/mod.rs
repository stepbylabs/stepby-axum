// axum-backend/src/scheduler/mod.rs
//! 定时任务调度内核
//!
//! 设计要点：
//! - 基于 `tokio-cron-scheduler` 独立实现，不依赖外部框架的调度器
//! - 调度内核与 Web 层完全解耦，仅依赖 `sea-orm` + `tokio` + `tokio-cron-scheduler` + `tracing`
//! - 通过 `Arc<JobScheduler>` 注入 AppState，不使用全局 Lazy
//! - 任务执行异常捕获写日志，不影响调度器和其他任务
//! - 并发控制：`concurrent='1'` 时检查 executing_jobs 跳过重叠执行
//! - 超时控制：60 秒超时被 tokio::time::timeout 杀死

pub mod cluster;
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
/// 消息发送失败单批次重试上限（防止单次重试耗时过长）
const MESSAGE_RETRY_BATCH: u64 = 100;

use crate::config::Settings;
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
            SchedulerError::InvalidCron(msg) => write!(f, "invalid cron expression: {}", msg),
            SchedulerError::SchedulerInternal(msg) => {
                write!(f, "scheduler internal error: {}", msg)
            }
        }
    }
}

impl std::error::Error for SchedulerError {}

/// SchedulerError → ServiceError 转换（Service 层 ? 自动使用）
impl From<SchedulerError> for crate::common::error::ServiceError {
    fn from(err: SchedulerError) -> Self {
        match err {
            SchedulerError::InvalidCron(_msg) => crate::common::error::ServiceError::bad_request(
                &crate::tr!("error.job.cron_invalid"),
            ),
            SchedulerError::SchedulerInternal(msg) => {
                tracing::error!("调度器内部错误: {}", msg);
                crate::common::error::ServiceError::internal(&crate::tr!(
                    "error.scheduler.operation_failed"
                ))
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
        config: Arc<Settings>,
    ) -> Result<Self, SchedulerError> {
        let scheduler = TokioScheduler::new().await.map_err(|e| {
            SchedulerError::SchedulerInternal(format!("Failed to create scheduler: {}", e))
        })?;

        scheduler.start().await.map_err(|e| {
            SchedulerError::SchedulerInternal(format!("Failed to start scheduler: {}", e))
        })?;

        // 注册内置任务函数（含日志保留期清理任务）
        register_builtin_tasks(db.clone());

        // 注册并调度内置 cron 任务（日志保留期清理，每日凌晨 3:00 执行；登录异常检测，每 5 分钟执行；IP 库自动更新，按 cron 配置）
        if let Err(e) = Self::register_builtin_scheduled_jobs(
            &scheduler,
            db.clone(),
            redis.clone(),
            ip_location_service,
            config,
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
    /// - `cleanup_expired_logs`：每日凌晨 3:00 清理 retention_days（默认 90）天前的日志（M2，cron: "0 0 3 * * *"）
    /// - `login_anomaly_detector`：每 5 分钟扫描最近 5 分钟失败登录，按 IP 分组阈值告警
    /// - `mmdb_auto_update`：按 `config.ip_location.auto_update_cron` 定时更新 mmdb 文件（默认每周二 04:00）
    async fn register_builtin_scheduled_jobs(
        scheduler: &TokioScheduler,
        db: DatabaseConnection,
        redis: ConnectionManager,
        ip_location_service: crate::service::IpLocationService,
        config: Arc<Settings>,
    ) -> Result<(), SchedulerError> {
        // 先 clone 出登录异常检测任务所需的 db/redis，避免被 cleanup_job 闭包 move 后无法使用
        let anomaly_db = db.clone();
        let anomaly_redis = redis.clone();
        // 审批超时扫描（flow_timeout_scan）所需：同样必须在 cleanup_job move db 之前克隆
        let flow_scan_db = db.clone();
        let flow_scan_redis = redis.clone();
        // 消息重试任务也需在 cleanup_job move 前 clone（db 非 Copy）
        let msg_retry_db = db.clone();
        let msg_retry_config = config.clone();
        // 报表订阅推送任务同样需在 cleanup_job / msg_retry_job move 前 clone
        // （db / config 均非 Copy，闭包 move 后原变量不可再使用）
        let report_db = db.clone();
        let report_config = config.clone();

        // 集群模式（`[scheduler].cluster_mode`，项目准则③：开关取「模式」而非裸 bool）。
        // `auto`（缺省）= 沿用各任务自身历史开关 ⇒ **对存量部署零行为变更**；
        // 非法取值回落 `auto` 并告警（fail-safe，不会意外开/关锁）。
        let cluster_mode =
            crate::scheduler::cluster::ClusterMode::parse_or_auto(&config.scheduler.cluster_mode);
        if crate::scheduler::cluster::ClusterMode::parse(&config.scheduler.cluster_mode).is_none() {
            tracing::warn!(
                value = %config.scheduler.cluster_mode,
                "scheduler.cluster_mode 取值非法（允许 auto|single|leader|all），已回落 auto（= 沿用各任务历史开关）"
            );
        }
        // flow 的锁 TTL 优先用它自己的配置（须大于单轮扫描最坏耗时），否则用 [scheduler] 兜底
        let flow_round_lock_ttl = if config.flow.scan_lock_ttl_secs > 0 {
            config.flow.scan_lock_ttl_secs
        } else {
            config.scheduler.lock_ttl_secs
        };
        let flow_round_lock_needed =
            cluster_mode.requires_round_lock(config.flow.scan_lock_enabled);
        // mmdb 改造前**始终**加锁 ⇒ legacy_enabled 传 true，保证 auto 下保持现状
        let mmdb_round_lock_needed = cluster_mode.requires_round_lock(true);
        tracing::info!(
            cluster_mode = cluster_mode.as_str(),
            replicas = config.scheduler.replicas,
            flow_round_lock = flow_round_lock_needed,
            mmdb_round_lock = mmdb_round_lock_needed,
            "调度器集群模式已解析（内置任务整轮互斥锁；sys_job 逐任务防重入锁不受本开关影响）"
        );
        // WF-2 加固（批次 4）：**显式声明多副本**却仍用 `auto` ⇒ 告警。
        // 为什么用"显式声明"而不是探针：副本数无法在进程内可靠探测（探针不可靠已被历史结论否掉），
        // 所以要求部署方在 `[scheduler].replicas` 里如实声明；声明了却忘了选模式才告警。
        if config.scheduler.replicas > 1
            && cluster_mode == crate::scheduler::cluster::ClusterMode::Auto
        {
            tracing::warn!(
                replicas = config.scheduler.replicas,
                "[scheduler].replicas > 1 但 cluster_mode = auto：内置任务（flow 超时扫描 / mmdb 更新）\
                 是否加锁取决于各任务的历史开关。多副本部署请显式置 cluster_mode = \"leader\"\
                 （仅持锁实例执行整轮），否则会出现多实例并发扫描同一批任务"
            );
        }

        // 日志保留期清理任务：每日凌晨 3:00 执行（cron: "0 0 3 * * *"）
        // 删除 (当前时间 - sys_log.retention_days) 天前的操作日志和登录日志，
        // 避免日志表无限增长导致生产崩溃（M2，保留天数可配置，默认 90）
        // FIX-Cron: tokio-cron-scheduler 0.15.1 强制要求 6 字段（含秒）cron 表达式，
        // 5 字段的 "0 3 * * *" 会触发 ParseSchedule 错误，改为 "0 0 3 * * *"（秒=0 分=0 时=3）
        let cleanup_config = config.clone();
        let cleanup_job = Job::new_async("0 0 3 * * *", move |_uuid, _l| {
            let db = db.clone();
            let config = cleanup_config.clone();
            Box::pin(async move {
                tracing::info!("内置任务 cleanup_expired_logs 开始执行：清理过期日志");

                // 清理操作日志
                let oper_log_service =
                    crate::service::sys_oper_log_service::SysOperLogService::new(db.clone());
                let logininfor_service =
                    crate::service::sys_logininfor_service::SysLogininforService::new(db.clone());

                let retention_days = config.sys_log.retention_days;

                match oper_log_service.cleanup_old_logs(retention_days).await {
                    Ok(affected) => {
                        tracing::info!(
                            "cleanup_expired_logs: 清理操作日志 {} 条（保留 {} 天）",
                            affected,
                            retention_days
                        );
                    }
                    Err(e) => {
                        tracing::error!("cleanup_expired_logs: 清理操作日志失败: {}", e);
                    }
                }

                match logininfor_service.cleanup_old_logs(retention_days).await {
                    Ok(affected) => {
                        tracing::info!(
                            "cleanup_expired_logs: 清理登录日志 {} 条（保留 {} 天）",
                            affected,
                            retention_days
                        );
                    }
                    Err(e) => {
                        tracing::error!("cleanup_expired_logs: 清理登录日志失败: {}", e);
                    }
                }
            })
        })
        .map_err(|e| {
            SchedulerError::SchedulerInternal(format!("Failed to create log cleanup task: {}", e))
        })?;

        scheduler.add(cleanup_job).await.map_err(|e| {
            SchedulerError::SchedulerInternal(format!("Failed to add log cleanup task: {}", e))
        })?;

        tracing::info!(
            "内置定时任务注册成功: cleanup_expired_logs (cron: '0 0 3 * * *', 保留 {} 天)",
            config.sys_log.retention_days
        );

        // 登录异常检测任务：每 5 分钟执行（cron: "0 */5 * * * *"）
        // 扫描最近 5 分钟 sys_logininfor 失败记录，按 IP 分组，count>=5 视为撞库攻击
        // 为每个异常 IP 创建 sys_notice 通知，同一 IP 30 分钟内不重复告警（Redis SETNX 去重）
        let anomaly_job = Job::new_async("0 */5 * * * *", move |_uuid, _l| {
            let db = anomaly_db.clone();
            let mut redis = anomaly_redis.clone();
            Box::pin(async move {
                tracing::debug!(
                    "内置任务 login_anomaly_detector 开始执行：扫描最近 5 分钟登录失败记录"
                );

                let logininfor_service =
                    crate::service::sys_logininfor_service::SysLogininforService::new(db.clone());
                let notice_service =
                    crate::service::sys_notice_service::SysNoticeService::new(db.clone());

                // 查询最近 5 分钟的失败登录，按 IP 分组，count >= 5 视为异常
                const WINDOW_MINUTES: i64 = crate::common::constants::LOGIN_ANOMALY_WINDOW_MINS;
                const FAIL_THRESHOLD: i64 = crate::common::constants::CREDENTIAL_STUFFING_THRESHOLD;
                const DEDUP_TTL_SECS: u64 =
                    (crate::common::constants::CREDENTIAL_STUFFING_DEDUP_MINS as u64) * 60; // 30 分钟

                let since = crate::common::datetime::now_naive()
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
                    tracing::debug!(
                        "login_anomaly_detector: 最近 {} 分钟无异常 IP",
                        WINDOW_MINUTES
                    );
                    return;
                }

                for (ip, count) in anomaly_ips {
                    let dedup_key = format!("login_anomaly:{}", ip);
                    // SETNX 去重：30 分钟内同一 IP 不重复创建告警
                    // P3 修复: 区分 Redis 错误与 key 已存在，Redis 故障时仍创建告警（宁可重复也不漏报）
                    let acquired = match redis::cmd("SET")
                        .arg(&dedup_key)
                        .arg("1")
                        .arg("NX")
                        .arg("EX")
                        .arg(DEDUP_TTL_SECS)
                        .query_async::<Option<String>>(&mut redis)
                        .await
                    {
                        Ok(Some(_)) => true, // 成功获取去重锁
                        Ok(None) => false,   // key 已存在，跳过
                        Err(e) => {
                            tracing::warn!(
                                "login_anomaly_detector: Redis 去重查询失败，仍创建告警: {}",
                                e
                            );
                            true // Redis 故障时仍创建告警（fail-open for alerting）
                        }
                    };

                    if !acquired {
                        tracing::debug!(
                            "login_anomaly_detector: IP {} 在 {} 分钟内已告警，跳过",
                            ip,
                            DEDUP_TTL_SECS / 60
                        );
                        continue;
                    }

                    let dto = crate::service::sys_notice_service::NoticeAddDto {
                        notice_title: crate::tr!("notice.login_anomaly.title", ip = ip),
                        notice_type: "1".to_string(),
                        notice_content: Some(crate::tr!(
                            "notice.login_anomaly.content",
                            minutes = WINDOW_MINUTES,
                            ip = ip,
                            count = count
                        )),
                        status: Some("0".to_string()),
                        remark: Some(format!("auto-detected;ip={};count={}", ip, count)),
                        notify_email: false,
                    };

                    match notice_service
                        // 系统级（定时任务）无操作者租户上下文 → 平台租户 0
                        .add_notice(dto, "system/scheduler", 0, None)
                        .await
                    {
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
        .map_err(|e| {
            SchedulerError::SchedulerInternal(format!(
                "Failed to create login anomaly detection task: {}",
                e
            ))
        })?;

        scheduler.add(anomaly_job).await.map_err(|e| {
            SchedulerError::SchedulerInternal(format!(
                "Failed to add login anomaly detection task: {}",
                e
            ))
        })?;

        tracing::info!(
            "内置定时任务注册成功: login_anomaly_detector (cron: '0 */5 * * * *', 阈值 5 次/5 分钟)"
        );

        // 消息发送失败重试任务：每分钟重试一批待重试消息（status='2' 且 retry_count<max_retry_count）
        // cron: "0 */1 * * * *"（秒=0，分钟=每 1 分钟）
        // 通过 SysMsgService::retry_pending 兜底投递失败的消息；重试耗尽置为失败由 service 内部处理。
        // 失败不阻断调度器和其他任务。
        let msg_retry_job = Job::new_async("0 */1 * * * *", move |_uuid, _l| {
            let db = msg_retry_db.clone();
            let config = msg_retry_config.clone();
            Box::pin(async move {
                tracing::debug!("内置任务 msg_send_retry 开始执行：重试待重试消息批次");

                let msg_service = crate::service::sys_msg_service::SysMsgService::new(db, config);

                match msg_service.retry_pending(MESSAGE_RETRY_BATCH, 0).await {
                    Ok(n) => {
                        if n > 0 {
                            tracing::info!("msg_send_retry: 本次重试完成 {} 条待重试消息", n);
                        }
                    }
                    Err(e) => {
                        tracing::error!("msg_send_retry: 重试待重试消息失败: {}", e);
                    }
                }
            })
        })
        .map_err(|e| {
            SchedulerError::SchedulerInternal(format!(
                "Failed to create message send retry task: {}",
                e
            ))
        })?;

        scheduler.add(msg_retry_job).await.map_err(|e| {
            SchedulerError::SchedulerInternal(format!(
                "Failed to add message send retry task: {}",
                e
            ))
        })?;

        tracing::info!(
            "内置定时任务注册成功: msg_send_retry (cron: '0 */1 * * * *', 单批次上限 {} 条)",
            MESSAGE_RETRY_BATCH
        );

        // 报表订阅推送任务：每分钟扫描一次到期的启用订阅（cron: "0 */1 * * * *"）并推送。
        // 通过 SysReportService::run_due_subscriptions 按各订阅自身的 cron 到期待执行，
        // 邮件经 MailerService、站内信写入 sys_msg_send_log，均复用既有投递语义。
        // 失败仅日志告警，不阻断调度器和其他任务。
        let report_sub_job = Job::new_async("0 */1 * * * *", move |_uuid, _l| {
            let db = report_db.clone();
            let config = report_config.clone();
            Box::pin(async move {
                tracing::debug!("内置任务 report_sub_due 开始执行：扫描到期的报表订阅");

                let report_service =
                    crate::service::sys_report_service::SysReportService::new(db, config);

                match report_service.run_due_subscriptions().await {
                    Ok(n) => {
                        if n > 0 {
                            tracing::info!("report_sub_due: 本次共推送 {} 个到期的报表订阅", n);
                        }
                    }
                    Err(e) => {
                        tracing::error!("report_sub_due: 扫描推送报表订阅失败: {}", e);
                    }
                }
            })
        })
        .map_err(|e| {
            SchedulerError::SchedulerInternal(format!(
                "Failed to create report subscription push task: {}",
                e
            ))
        })?;

        scheduler.add(report_sub_job).await.map_err(|e| {
            SchedulerError::SchedulerInternal(format!(
                "Failed to add report subscription push task: {}",
                e
            ))
        })?;

        tracing::info!(
            "内置定时任务注册成功: report_sub_due (cron: '0 */1 * * * *', 按订阅自身 cron 到期推送)"
        );

        // ==================== 审批超时扫描（m20260923_000002 flow_module；V5 §1.2 路径②）====================
        // - cron 来自 config.flow.timeout_scan_cron（6 字段含秒；**为空 = 禁用**，与 mmdb_auto_update 同款约定）
        // - config.flow.enabled 为第二开关（运行配置级）
        // - 提醒去重：Redis SETNX + TTL（login_anomaly_detector 范式，Redis 故障宁可重复不漏报）
        // - 用户可见性：待办列表 + 站内审计（service 内完成；WS 为加速器，见 V7-E2 取舍说明）
        // - db/config 非 Copy：clone 进闭包（与上方 cleanup/anomaly/msg_retry/report 闭包一致）
        if !config.flow.enabled || config.flow.timeout_scan_cron.trim().is_empty() {
            tracing::info!(
                "内置任务 flow_timeout_scan 未注册：config.flow.enabled={} 或 timeout_scan_cron 为空",
                config.flow.enabled
            );
        } else {
            let flow_scan_config = config.clone();
            let flow_cron = config.flow.timeout_scan_cron.clone();
            // 提前 fail-fast 校验 cron（mmdb_auto_update 范式）
            let flow_job = Job::new_async(flow_cron.as_str(), move |_uuid, _l| {
                let db = flow_scan_db.clone();
                let config = flow_scan_config.clone();
                let mut redis = flow_scan_redis.clone();
                Box::pin(async move {
                    // S-1 / 批次 1a：整轮互斥锁统一由 `[scheduler].cluster_mode` 驱动
                    // （`single`/`all` 不加锁；`leader` 一律加锁；`auto` 沿用
                    // `[flow].scan_lock_enabled`）。释放走 Lua CAS（`ClusterLock::release`），
                    // 避免误删其他实例持有的锁。
                    let Some(round_lock) = crate::scheduler::cluster::ClusterLock::acquire(
                        &mut redis,
                        "lock:scheduler:flow_timeout_scan",
                        flow_round_lock_needed,
                        flow_round_lock_ttl,
                        "flow_timeout_scan",
                    )
                    .await
                    else {
                        return;
                    };
                    let msg_service = crate::service::sys_msg_service::SysMsgService::new(
                        db.clone(),
                        config.clone(),
                    );
                    let flow_service = crate::service::sys_flow_service::SysFlowService::new(
                        db.clone(),
                        config.clone(),
                        msg_service,
                    );
                    match flow_service
                        .scan_timeouts_with_redis(&mut redis, config.flow.scan_batch_limit)
                        .await
                    {
                        Ok(outcome) => {
                            if outcome.reminded > 0 || outcome.escalated > 0 {
                                tracing::info!(
                                    "flow_timeout_scan: 本轮超时提醒 {} 条 / 升级提醒 {} 条（去重跳过 {} 条）",
                                    outcome.reminded,
                                    outcome.escalated,
                                    outcome.skipped
                                );
                            }
                            // W-9：一致性巡检并入本 Job 尾部（漂移仅告警，明细见 service 日志）
                            if outcome.drift > 0 {
                                tracing::warn!(
                                    "flow_timeout_scan: 一致性巡检发现 {} 条漂移（单据 status 与 task 聚合不一致）",
                                    outcome.drift
                                );
                            }
                        }
                        Err(e) => {
                            tracing::error!("flow_timeout_scan 执行失败: {}", e.message);
                        }
                    }
                    // S-1 / 批次 1a：释放整轮互斥锁（CAS，仅本实例持有才删除）
                    round_lock.release(&mut redis).await;
                })
            })
            .map_err(|e| {
                SchedulerError::SchedulerInternal(format!(
                    "Failed to create flow timeout scan task: {e}"
                ))
            })?;
            scheduler.add(flow_job).await.map_err(|e| {
                SchedulerError::SchedulerInternal(format!(
                    "Failed to add flow timeout scan task: {e}"
                ))
            })?;
            tracing::info!(
                "内置定时任务注册成功: flow_timeout_scan (cron: '{}', 单批上限 {} 条, SLA {}h, 升级阈值 {}h, 整轮互斥锁: {})",
                config.flow.timeout_scan_cron,
                config.flow.scan_batch_limit,
                config.flow.timeout_hours,
                config.flow.escalate_after_hours,
                if flow_round_lock_needed {
                    format!("启用（TTL {}s）", flow_round_lock_ttl)
                } else {
                    format!("未启用（cluster_mode={}）", cluster_mode.as_str())
                }
            );
        }

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
                        tracing::debug!(
                            "mmdb_auto_update: auto_update_enabled=false，跳过本次执行"
                        );
                        return;
                    }

                    // Redis 整轮互斥锁（批次 1a：统一由 `[scheduler].cluster_mode` 驱动；
                    // `auto` 下 legacy_enabled=true ⇒ 与改造前"始终加锁"一致）。
                    // fail-closed：Redis 故障时跳过执行，避免多实例并发下载。
                    const MMDB_LOCK_KEY: &str = "lock:scheduler:mmdb_auto_update";
                    const MMDB_LOCK_TTL_SECS: u64 = crate::common::constants::MMDB_LOCK_TTL_SECS; // 30 分钟
                    let Some(mmdb_lock) = crate::scheduler::cluster::ClusterLock::acquire(
                        &mut redis,
                        MMDB_LOCK_KEY,
                        mmdb_round_lock_needed,
                        MMDB_LOCK_TTL_SECS,
                        "mmdb_auto_update",
                    )
                    .await
                    else {
                        return;
                    };

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

                    // 释放锁（CAS：仅当 fencing token 匹配时删除，避免误删其他实例的锁）
                    mmdb_lock.release(&mut redis).await;
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
                        "内置定时任务注册成功: mmdb_auto_update (cron: '{}', 默认源由 sys_config 决定, 整轮互斥锁: {})",
                        mmdb_cron,
                        if mmdb_round_lock_needed {
                            "已启用".to_string()
                        } else {
                            format!("未启用（cluster_mode={}）", cluster_mode.as_str())
                        }
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
    ///
    /// 多租户：调度器为平台级组件，需覆盖**所有租户**的启用任务，故 tenant_scope 传 None；
    /// 每个 job 自身的 tenant_id 在写 job_log / 任务进度时用于归属。
    pub async fn load_from_db(&self, job_repo: &SysJobRepository) -> Result<(), SchedulerError> {
        let jobs = job_repo.find_by_status("0", None).await.map_err(|e| {
            SchedulerError::SchedulerInternal(format!("Failed to load jobs: {}", e))
        })?;

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
                let result =
                    AssertUnwindSafe(execute_with_logging(&db, &mut redis, &executing_jobs, &job))
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
        .map_err(|e| SchedulerError::InvalidCron(format!("Cron expression parse error: {}", e)))?;

        let guid = sched_job.guid();

        self.scheduler
            .add(sched_job)
            .await
            .map_err(|e| SchedulerError::SchedulerInternal(format!("Failed to add job: {}", e)))?;

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
            self.scheduler.remove(&guid).await.map_err(|e| {
                SchedulerError::SchedulerInternal(format!("Failed to remove job: {}", e))
            })?;
            tracing::info!("任务移除成功: job_id={}, guid={}", job_id, guid);
        } else {
            tracing::warn!("任务移除跳过：调度器中不存在 job_id={}", job_id);
        }

        Ok(())
    }

    /// 更新任务（P1 修复：先添加新任务成功后再移除旧任务，避免 add 失败时任务静默丢失）
    ///
    /// 原实现先 remove_job 再 add_job：若新 cron 表达式非法导致 add 失败，
    /// 任务已从调度器移除且 running_jobs 已删，任务**静默丢失**（用户感知为"任务莫名不再执行"）。
    /// 现改为先 add（成功后才动旧任务），失败时旧任务保持原样。
    pub async fn update_job(&self, job: &SysJobModel) -> Result<(), SchedulerError> {
        // 记录旧任务 guid（add_job 会用新 guid 覆盖 running_jobs[job_id]，需提前取出）
        let old_guid = {
            let running = self.running_jobs.read().await;
            running.get(&job.job_id).copied()
        };

        // 先添加新任务：失败则旧任务原样保留（不丢失）
        self.add_job(job).await?;

        // 再移除旧任务（guid 不同才需要 remove；remove 失败仅告警——新任务已注册，功能可用，
        // 重复注册由调度器幂等/手动触发兜底，风险低于任务丢失）
        if let Some(old_guid) = old_guid
            && self.running_jobs.read().await.get(&job.job_id).copied() != Some(old_guid)
            && let Err(e) = self.scheduler.remove(&old_guid).await
        {
            tracing::warn!(
                "更新任务后移除旧调度失败 job_id={}, guid={}: {}（新任务已注册，可接受）",
                job.job_id,
                old_guid,
                e
            );
        }

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
            let result = AssertUnwindSafe(execute_with_logging(
                &db,
                &mut redis,
                &executing_jobs,
                &job_clone,
            ))
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
        sched.shutdown().await.map_err(|e| {
            SchedulerError::SchedulerInternal(format!("Failed to shutdown scheduler: {}", e))
        })?;
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
    cron.find_next_occurrence(&Utc::now(), false).map_err(|e| {
        SchedulerError::InvalidCron(format!("Failed to calculate next execution time: {}", e))
    })?;
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

/// 主任务生命周期 RAII 守卫（P0-5 分布式锁泄漏修复）
///
/// 背景：任务函数 panic 时（execute_inner 未捕获前），`renew_handle.abort()` 与
/// `release_lock()` 均不会执行 → 续期任务继续每 30s 用 Lua 无限续锁，分布式锁被本实例
/// 永久持有，该 job 此后永远不会再执行（直到进程重启）。
///
/// 本守卫保证无论正常返回、业务失败还是 panic/unwind（Drop），续期任务都会被 abort，
/// 分布式锁都会被释放（Drop 中 spawn 异步执行 CAS 释放，避免误删其他实例的锁）。
struct JobLockGuard {
    /// 续期任务句柄（Drop 中 abort，防止无限续锁）
    renew_handle: Option<tokio::task::JoinHandle<()>>,
    redis: ConnectionManager,
    lock_key: String,
    lock_value: String,
    /// 是否已释放（防重复 abort/release）
    armed: bool,
}

impl JobLockGuard {
    fn new(
        renew_handle: tokio::task::JoinHandle<()>,
        redis: ConnectionManager,
        lock_key: String,
        lock_value: String,
    ) -> Self {
        Self {
            renew_handle: Some(renew_handle),
            redis,
            lock_key,
            lock_value,
            armed: true,
        }
    }

    /// 正常路径收尾：abort 续期任务 + 等待 CAS 释放锁（保持与旧逻辑一致的显式释放）
    async fn finish(&mut self) {
        if let Some(h) = self.renew_handle.take() {
            h.abort();
        }
        if self.armed {
            self.armed = false;
            let mut conn = self.redis.clone();
            release_lock(&mut conn, &self.lock_key, &self.lock_value).await;
        }
    }

    /// 同步 abort 续期任务（Drop 兜底用；release 因 async 走 spawn）
    fn abort_and_spawn_release(&mut self) {
        if let Some(h) = self.renew_handle.take() {
            h.abort();
        }
        if self.armed {
            self.armed = false;
            let mut conn = self.redis.clone();
            let k = self.lock_key.clone();
            let v = self.lock_value.clone();
            tokio::spawn(async move {
                release_lock(&mut conn, &k, &v).await;
            });
        }
    }
}

impl Drop for JobLockGuard {
    fn drop(&mut self) {
        // panic/unwind 路径兜底：abort 续期 + 异步释放锁，杜绝锁永久持有
        self.abort_and_spawn_release();
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
        tracing::debug!("任务 {} 被其他实例持有分布式锁，跳过本次执行", job.job_name);
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
            tracing::debug!("任务 {} 禁止并发，跳过本次执行", job.job_name);
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
                // catch_unwind 捕获单次续期迭代内的 panic，避免 panic 终止续期任务
                // 导致分布式锁无人续期而过期（参考 add_job/run_once 的 catch_unwind 写法）。
                // 注意：catch_unwind 放在 loop 体内每次迭代捕获，而非包裹整个 loop，
                // 这样 panic 后可主动 break 停止续期，避免吞掉 panic 继续空转。
                let result = AssertUnwindSafe(async {
                    let mut conn = redis_clone.clone();
                    renew_lock(&mut conn, &lock_key_clone, &lock_value_clone, LOCK_TTL_SECS).await
                })
                .catch_unwind()
                .await;

                match result {
                    Ok(true) => {
                        tracing::trace!(
                            "任务 {} 的分布式锁续期成功 (job_id={})",
                            job_name_clone,
                            job_id
                        );
                        // 继续下一轮续期
                        tokio::time::sleep(Duration::from_secs(LOCK_RENEW_INTERVAL_SECS)).await;
                    }
                    Ok(false) => {
                        tracing::warn!(
                            "任务 {} 的分布式锁续期失败，锁可能已被其他实例获取 (job_id={})。\
                             另一实例可能正在重复执行此任务，需运维介入排查",
                            job_name_clone,
                            job_id
                        );
                        // 锁已丢失，停止续期（继续重试也只会失败）
                        break;
                    }
                    Err(panic_err) => {
                        tracing::error!(
                            "分布式锁续期任务 panic: job_id={}, job_name={}, panic={:?}",
                            job_id,
                            job_name_clone,
                            panic_err
                        );
                        // panic 后无法确定锁状态，停止续期
                        break;
                    }
                }
            }
        })
    };

    // P0-5：RAII 守卫接管续期任务句柄与锁释放——任何退出路径（含 panic/Drop）都会
    // abort 续期任务并释放分布式锁，杜绝"任务 panic → 续期任务无限续锁 → job 永久禁用"。
    let mut lock_guard = JobLockGuard::new(
        renew_handle,
        redis.clone(),
        lock_key.clone(),
        lock_value.clone(),
    );

    // 执行任务（捕获 panic，避免 panic 跨 spawn 边界传播）
    // P0-5 加固：catch_unwind 包裹，任务函数 panic 转为业务失败而非中断主流程，
    // 确保后续 finish()（abort 续期 + 释放锁）一定执行。
    let (status, message, exception_info) =
        match AssertUnwindSafe(execute_inner(&job.invoke_target))
            .catch_unwind()
            .await
        {
            Ok(Ok(msg)) => ("0", msg, String::new()),
            Ok(Err(e)) => {
                // B11：业务执行失败需在 tracing 日志层可见。DB 层 sys_job_log 已记录失败，
                // 但此前缺 tracing::error!，导致日志/告警系统（通常只监控 error 级）无法感知业务失败。
                tracing::error!(
                    "任务执行业务失败: job_id={}, job_name={}, error={:?}",
                    job.job_id,
                    job.job_name,
                    e
                );
                ("1", format!("Job execution failed: {}", e), e.to_string())
            }
            Err(panic_err) => {
                // 任务函数 panic：记录并视为失败（P0-5：不让 panic 中断主流程导致锁泄漏）
                tracing::error!(
                    "任务函数 panic: job_id={}, job_name={}, panic={:?}",
                    job.job_id,
                    job.job_name,
                    panic_err
                );
                (
                    "1",
                    format!("Job execution panicked: {:?}", panic_err),
                    format!("{:?}", panic_err),
                )
            }
        };

    let elapsed = start.elapsed().as_millis();

    // 正常路径显式释放标记
    guard.disarm();

    // 正常路径收尾：abort 续期任务 + CAS 释放分布式锁（panic 路径由 lock_guard 的 Drop 兜底）
    lock_guard.finish().await;

    // 写日志（失败不影响主流程）
    // 多租户：调度器无登录操作者上下文，日志归属**按 job 行自身 tenant_id** 落库
    // （平台级系统任务 tid=0），避免租户任务日志落到平台维度导致租户侧不可见。
    let log_repo = SysJobLogRepository::new(db.clone());
    let log_am = sys_job_log::ActiveModel {
        tenant_id: Set(job.tenant_id),
        job_name: Set(job.job_name.clone()),
        job_group: Set(job.job_group.clone()),
        invoke_target: Set(job.invoke_target.clone()),
        job_message: Set(Some(format!("{} (elapsed {}ms)", message, elapsed))),
        status: Set(Some(status.to_string())),
        exception_info: if exception_info.is_empty() {
            Set(None)
        } else {
            Set(Some(exception_info))
        },
        create_time: Set(Some(crate::common::datetime::now_naive())),
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
    let func = registry::get_task(invoke_target).ok_or_else(|| {
        crate::tr!(
            "msg.scheduler.invoke_target_not_found",
            target = invoke_target
        )
    })?;

    // REGRESS-008：使用常量 TASK_TIMEOUT_SECS，与 LOCK_TTL_SECS 保持联动
    tokio::time::timeout(Duration::from_secs(TASK_TIMEOUT_SECS), func())
        .await
        .map_err(|_| crate::tr!("msg.scheduler.job_timeout", secs = TASK_TIMEOUT_SECS))?
}

/// 注册内置任务函数
///
/// 对齐内置初始数据，invoke_target 完整字符串作为 key。
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
                Ok(crate::tr!("msg.scheduler.ryNoParams_success"))
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

                const RETENTION_DAYS: i64 = crate::common::constants::LOG_RETENTION_DAYS;
                let mut messages = Vec::new();

                match oper_log_service.cleanup_old_logs(RETENTION_DAYS).await {
                    Ok(affected) => {
                        let msg = format!("Cleaned {} oper_log records", affected);
                        tracing::info!("{}", msg);
                        messages.push(msg);
                    }
                    Err(e) => {
                        let msg = format!("Failed to clean oper_log: {}", e);
                        tracing::error!("{}", msg);
                        return Err(msg.into());
                    }
                }

                match logininfor_service.cleanup_old_logs(RETENTION_DAYS).await {
                    Ok(affected) => {
                        let msg = format!("Cleaned {} logininfor records", affected);
                        tracing::info!("{}", msg);
                        messages.push(msg);
                    }
                    Err(e) => {
                        let msg = format!("Failed to clean logininfor: {}", e);
                        tracing::error!("{}", msg);
                        return Err(msg.into());
                    }
                }

                Ok(messages.join("; "))
            })
        }),
    );

    tracing::info!("内置任务注册完成: {:?}", registry::list_registered_tasks());
}

// ==================== 单元测试 ====================
//
// 覆盖意图：
// - validate_cron / SchedulerError / ExecutingFlagGuard / JobLockGuard / register_builtin_tasks /
//   execute_inner 均为纯逻辑，不依赖外部 DB/Redis，逐分支覆盖。
// - 涉及分布式锁 / 任务日志写入的 execute_with_logging 与 JobScheduler 生命周期测试，
//   通过容错连接本地 Redis（127.0.0.1:6379/15）实现：Redis 不可用时直接 return 跳过，
//   避免 CI 无 Redis 时挂掉。测试统一使用 Redis DB 15，job_id 使用高位段（1001+ / 9000+），
//   与集成测试使用的真实 job_id 1~3 及种子数据不冲突。
#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::error::ServiceError;
    use crate::config::Settings;
    use crate::entity::sys_job::ActiveModel as SysJobActiveModel;
    use crate::repository::sys_job::SysJobRepository;
    use crate::repository::sys_job_log::SysJobLogRepository;
    use crate::service::IpLocationService;
    use crate::utils::ip_location::IpLocator;
    use sea_orm::NotSet;

    /// 构造一个测试用 sys_job Model（concurrent='1'、misfire_policy='3'）
    fn job(id: i64, name: &str, cron: &str, invoke: &str) -> SysJobModel {
        SysJobModel {
            tenant_id: 0,
            job_id: id,
            job_name: name.to_string(),
            job_group: "DEFAULT".to_string(),
            invoke_target: invoke.to_string(),
            cron_expression: Some(cron.to_string()),
            misfire_policy: Some("3".to_string()),
            concurrent: Some("1".to_string()),
            status: Some("0".to_string()),
            create_by: None,
            create_time: None,
            update_by: None,
            update_time: None,
            remark: None,
            del_flag: Some("0".to_string()),
        }
    }

    /// 容错连接本地 Redis（DB 15）：不可用返回 None（测试直接跳过）
    async fn try_redis() -> Option<ConnectionManager> {
        let client = redis::Client::open("redis://127.0.0.1:6379/15").ok()?;
        match tokio::time::timeout(
            Duration::from_secs(2),
            redis::aio::ConnectionManager::new(client),
        )
        .await
        {
            Ok(Ok(c)) => Some(c),
            _ => None,
        }
    }

    /// 加载配置（先注入合法 JWT 密钥，规避 validate_secrets 拒绝占位密钥）
    fn load_settings() -> Settings {
        unsafe {
            std::env::set_var(
                "JWT_SECRET",
                "a-very-long-jwt-secret-key-for-testing-32+chars",
            );
        }
        let dir = std::env::var("CARGO_MANIFEST_DIR").unwrap_or_else(|_| ".".to_string());
        let path = format!("{}/config/config.toml", dir);
        Settings::from_file(&path).expect("加载 config/config.toml 失败（请确认文件存在）")
    }

    /// 构建完整 JobScheduler（容错 Redis；Redis 不可用返回 None）
    async fn build_scheduler() -> Option<Arc<JobScheduler>> {
        let redis = try_redis().await?;
        let db = crate::repository::test_support::migrated_db()
            .await
            .unwrap();
        let settings = Arc::new(load_settings());
        let ip_locator = Arc::new(IpLocator::new_with_xdb(
            &settings.ip_location.mmdb_path,
            &settings.ip_location.xdb_path,
            settings.ip_location.xdb_enabled,
        ));
        let ip_location_service =
            IpLocationService::new(db.clone(), settings.clone(), ip_locator.clone());
        let scheduler = Arc::new(
            JobScheduler::new(db.clone(), redis, ip_location_service, settings)
                .await
                .unwrap(),
        );
        Some(scheduler)
    }

    // ---------- validate_cron ----------

    #[test]
    fn test_validate_cron_valid_6_field() {
        assert!(validate_cron("0 0 3 * * *").is_ok());
        assert!(validate_cron("0 */5 * * * *").is_ok());
        assert!(validate_cron("0 0 4 * * 2").is_ok());
    }

    #[test]
    fn test_validate_cron_rejects_garbage() {
        assert!(matches!(
            validate_cron(""),
            Err(SchedulerError::InvalidCron(_))
        ));
        assert!(matches!(
            validate_cron("not-a-cron"),
            Err(SchedulerError::InvalidCron(_))
        ));
    }

    #[test]
    fn test_validate_cron_rejects_5_field() {
        // tokio-cron-scheduler 0.15 强制要求 6 字段（含秒），5 字段应被提前拒绝
        assert!(matches!(
            validate_cron("0 3 * * *"),
            Err(SchedulerError::InvalidCron(_))
        ));
    }

    // ---------- SchedulerError ----------

    #[test]
    fn test_scheduler_error_display() {
        assert_eq!(
            SchedulerError::InvalidCron("bad".to_string()).to_string(),
            "invalid cron expression: bad"
        );
        assert_eq!(
            SchedulerError::SchedulerInternal("oops".to_string()).to_string(),
            "scheduler internal error: oops"
        );
    }

    #[test]
    fn test_scheduler_error_into_service_error() {
        let e: ServiceError = SchedulerError::InvalidCron("bad".to_string()).into();
        assert_eq!(e.code, 400);
        let e: ServiceError = SchedulerError::SchedulerInternal("oops".to_string()).into();
        assert_eq!(e.code, 500);
    }

    // ---------- ExecutingFlagGuard ----------

    #[test]
    fn test_executing_flag_guard_acquire_and_drop() {
        let flags = Arc::new(std::sync::Mutex::new(HashMap::new()));
        {
            let guard = ExecutingFlagGuard::try_acquire(flags.clone(), 1, true).unwrap();
            assert_eq!(flags.lock().unwrap().get(&1), Some(&true));
            // 并发禁止时再次获取返回 None
            assert!(ExecutingFlagGuard::try_acquire(flags.clone(), 1, true).is_none());
            drop(guard);
        }
        // Drop 应清除标记
        assert!(!flags.lock().unwrap().contains_key(&1));
    }

    #[test]
    fn test_executing_flag_guard_enforce_false_allows_reentry() {
        let flags = Arc::new(std::sync::Mutex::new(HashMap::new()));
        let _g1 = ExecutingFlagGuard::try_acquire(flags.clone(), 7, true).unwrap();
        // concurrent != '1' 时允许覆盖执行（enforce_concurrent=false）
        assert!(ExecutingFlagGuard::try_acquire(flags.clone(), 7, false).is_some());
    }

    #[test]
    fn test_executing_flag_guard_disarm_is_idempotent() {
        let flags = Arc::new(std::sync::Mutex::new(HashMap::new()));
        let mut guard = ExecutingFlagGuard::try_acquire(flags.clone(), 5, true).unwrap();
        guard.disarm();
        assert!(!flags.lock().unwrap().contains_key(&5));
        // 二次 disarm / drop 不应 panic 或重复清除
        guard.disarm();
        drop(guard);
        assert!(!flags.lock().unwrap().contains_key(&5));
    }

    // ---------- register_builtin_tasks ----------

    #[tokio::test]
    async fn test_register_builtin_tasks_registers_expected_targets() {
        let db = crate::repository::test_support::migrated_db()
            .await
            .unwrap();
        register_builtin_tasks(db);
        let targets = registry::list_registered_tasks();
        for expected in [
            "ryTask.ryNoParams",
            "ryTask.ryParams('ry')",
            "ryTask.ryMultipleParams('ry', true, 2000L, 316.5F, 100)",
            "cleanup_expired_logs",
        ] {
            assert!(
                targets.iter().any(|t| t == expected),
                "内置任务未注册: {expected}"
            );
        }
    }

    // ---------- execute_inner ----------

    #[tokio::test]
    async fn test_execute_inner_unknown_target_errors() {
        let err = execute_inner("unitTest.no.such.task").await.unwrap_err();
        assert!(!err.to_string().is_empty());
    }

    #[tokio::test]
    async fn test_execute_inner_registered_task_returns_ok() {
        let target = "unitTest.scheduler.quick";
        registry::register_task(
            target,
            Arc::new(|| Box::pin(async { Ok("done-ok".to_string()) })),
        );
        let msg = execute_inner(target).await.unwrap();
        assert_eq!(msg, "done-ok");
    }

    // ---------- JobLockGuard（容错 Redis） ----------

    #[tokio::test]
    async fn test_job_lock_guard_finish_releases_lock() {
        let Some(mut redis) = try_redis().await else {
            return;
        };
        let key = "lock:scheduler:unit-lockguard-finish";
        let value = "token-abc";
        // 普通 SET 预置锁（覆盖历史残留，保证前置条件确定）
        let _: () = redis::cmd("SET")
            .arg(key)
            .arg(value)
            .arg("EX")
            .arg(60)
            .query_async(&mut redis)
            .await
            .unwrap();
        let handle = tokio::spawn(async {
            tokio::time::sleep(Duration::from_secs(3600)).await;
        });
        let mut guard =
            JobLockGuard::new(handle, redis.clone(), key.to_string(), value.to_string());
        guard.finish().await;
        drop(guard);
        let v: Option<String> = redis::cmd("GET")
            .arg(key)
            .query_async(&mut redis)
            .await
            .unwrap();
        assert!(v.is_none(), "finish() 应通过 CAS 释放锁");
    }

    #[tokio::test]
    async fn test_job_lock_guard_drop_releases_lock_async() {
        let Some(mut redis) = try_redis().await else {
            return;
        };
        let key = "lock:scheduler:unit-lockguard-drop";
        let value = "token-def";
        let _: () = redis::cmd("SET")
            .arg(key)
            .arg(value)
            .arg("EX")
            .arg(60)
            .query_async(&mut redis)
            .await
            .unwrap();
        let handle = tokio::spawn(async {
            tokio::time::sleep(Duration::from_secs(3600)).await;
        });
        let guard = JobLockGuard::new(handle, redis.clone(), key.to_string(), value.to_string());
        drop(guard); // Drop 兜底：abort 续期 + spawn 异步释放锁
        tokio::time::sleep(Duration::from_millis(150)).await;
        let v: Option<String> = redis::cmd("GET")
            .arg(key)
            .query_async(&mut redis)
            .await
            .unwrap();
        assert!(v.is_none(), "Drop 应触发异步释放锁");
    }

    // ---------- execute_with_logging（容错 Redis + 临时 SQLite） ----------

    #[tokio::test]
    async fn test_execute_with_logging_success_writes_log() {
        let Some(mut redis) = try_redis().await else {
            return;
        };
        let db = crate::repository::test_support::migrated_db()
            .await
            .unwrap();
        let executing_jobs = Arc::new(std::sync::Mutex::new(HashMap::new()));
        let target = "unitTest.scheduler.success";
        registry::register_task(
            target,
            Arc::new(|| Box::pin(async { Ok("all-good".to_string()) })),
        );
        // 清理历史残留锁，避免跨测试运行遗留的锁导致本次跳过
        let _: () = redis::cmd("DEL")
            .arg("lock:scheduler:9001")
            .query_async(&mut redis)
            .await
            .unwrap();
        let job = job(9001, "unit-success", "0 0 3 * * *", target);
        execute_with_logging(&db, &mut redis, &executing_jobs, &job).await;
        let log_repo = SysJobLogRepository::new(db.clone());
        let logs = log_repo
            .find_by_job_name("unit-success", None)
            .await
            .unwrap();
        assert_eq!(logs.len(), 1);
        assert_eq!(logs[0].status.as_deref(), Some("0"));
        assert!(
            logs[0].job_message.as_deref().unwrap().contains("all-good"),
            "job_message 应包含任务返回消息"
        );
        assert!(
            !executing_jobs.lock().unwrap().contains_key(&9001),
            "执行标记应被清除"
        );
    }

    #[tokio::test]
    async fn test_execute_with_logging_business_failure_writes_error_log() {
        let Some(mut redis) = try_redis().await else {
            return;
        };
        let db = crate::repository::test_support::migrated_db()
            .await
            .unwrap();
        let executing_jobs = Arc::new(std::sync::Mutex::new(HashMap::new()));
        let target = "unitTest.scheduler.fail";
        registry::register_task(
            target,
            Arc::new(|| {
                Box::pin(async {
                    Err::<String, Box<dyn std::error::Error + Send + Sync>>("boom".into())
                })
            }),
        );
        let _: () = redis::cmd("DEL")
            .arg("lock:scheduler:9002")
            .query_async(&mut redis)
            .await
            .unwrap();
        let job = job(9002, "unit-fail", "0 0 3 * * *", target);
        execute_with_logging(&db, &mut redis, &executing_jobs, &job).await;
        let log_repo = SysJobLogRepository::new(db.clone());
        let logs = log_repo.find_by_job_name("unit-fail", None).await.unwrap();
        assert_eq!(logs.len(), 1);
        assert_eq!(logs[0].status.as_deref(), Some("1"));
        assert!(logs[0].exception_info.as_deref().unwrap().contains("boom"));
    }

    #[tokio::test]
    async fn test_execute_with_logging_panic_writes_error_log() {
        let Some(mut redis) = try_redis().await else {
            return;
        };
        let db = crate::repository::test_support::migrated_db()
            .await
            .unwrap();
        let executing_jobs = Arc::new(std::sync::Mutex::new(HashMap::new()));
        let target = "unitTest.scheduler.panic";
        let f: registry::TaskFn = Arc::new(|| {
            Box::pin(async {
                panic!("intentional test panic in scheduler unit test");
            })
        });
        registry::register_task(target, f);
        let _: () = redis::cmd("DEL")
            .arg("lock:scheduler:9003")
            .query_async(&mut redis)
            .await
            .unwrap();
        let job = job(9003, "unit-panic", "0 0 3 * * *", target);
        execute_with_logging(&db, &mut redis, &executing_jobs, &job).await;
        let log_repo = SysJobLogRepository::new(db.clone());
        let logs = log_repo.find_by_job_name("unit-panic", None).await.unwrap();
        assert_eq!(logs.len(), 1);
        assert_eq!(logs[0].status.as_deref(), Some("1"));
    }

    #[tokio::test]
    async fn test_execute_with_logging_skips_when_lock_held() {
        let Some(mut redis) = try_redis().await else {
            return;
        };
        let db = crate::repository::test_support::migrated_db()
            .await
            .unwrap();
        let executing_jobs = Arc::new(std::sync::Mutex::new(HashMap::new()));
        // 预置其他实例持有的锁 → execute_with_logging 的 SETNX 应失败并跳过执行
        let lock_key = format!("lock:scheduler:{}", 9004);
        let _: Option<String> = redis::cmd("SET")
            .arg(&lock_key)
            .arg("foreign-token")
            .arg("NX")
            .arg("EX")
            .arg(90)
            .query_async(&mut redis)
            .await
            .unwrap();
        let job = job(
            9004,
            "unit-skiplock",
            "0 0 3 * * *",
            "unitTest.scheduler.never",
        );
        execute_with_logging(&db, &mut redis, &executing_jobs, &job).await;
        let log_repo = SysJobLogRepository::new(db.clone());
        let logs = log_repo
            .find_by_job_name("unit-skiplock", None)
            .await
            .unwrap();
        assert!(logs.is_empty(), "锁被占用时应跳过执行，不写日志");
    }

    #[tokio::test]
    async fn test_execute_with_logging_skips_concurrent_overlap() {
        let Some(mut redis) = try_redis().await else {
            return;
        };
        let db = crate::repository::test_support::migrated_db()
            .await
            .unwrap();
        let executing_jobs = Arc::new(std::sync::Mutex::new(HashMap::new()));
        let job_id = 9005i64;
        // 清理历史残留锁，保证本次能获取锁以走到并发检查分支
        let _: () = redis::cmd("DEL")
            .arg(format!("lock:scheduler:{}", job_id))
            .query_async(&mut redis)
            .await
            .unwrap();
        executing_jobs.lock().unwrap().insert(job_id, true); // 模拟已有任务在执行
        let job = job(
            job_id,
            "unit-skipconcurrent",
            "0 0 3 * * *",
            "unitTest.scheduler.never",
        );
        execute_with_logging(&db, &mut redis, &executing_jobs, &job).await;
        let log_repo = SysJobLogRepository::new(db.clone());
        let logs = log_repo
            .find_by_job_name("unit-skipconcurrent", None)
            .await
            .unwrap();
        assert!(logs.is_empty(), "并发禁止时应跳过执行，不写日志");
        // 并发跳过会释放已获取的分布式锁
        let lock_key = format!("lock:scheduler:{}", job_id);
        let v: Option<String> = redis::cmd("GET")
            .arg(&lock_key)
            .query_async(&mut redis)
            .await
            .unwrap();
        assert!(v.is_none(), "并发跳过时应释放已获取的分布式锁");
    }

    // ---------- JobScheduler 生命周期（容错 Redis） ----------

    #[tokio::test]
    async fn test_scheduler_add_and_remove_job() {
        let Some(scheduler) = build_scheduler().await else {
            return;
        };
        let j = job(1001, "unit-add", "0 0 3 * * *", "unitTest.scheduler.add");
        let guid = scheduler.add_job(&j).await.unwrap();
        assert_eq!(
            scheduler.running_jobs.read().await.get(&1001).copied(),
            Some(guid)
        );
        scheduler.remove_job(1001).await.unwrap();
        assert!(scheduler.running_jobs.read().await.get(&1001).is_none());
    }

    #[tokio::test]
    async fn test_scheduler_add_invalid_cron_errors() {
        let Some(scheduler) = build_scheduler().await else {
            return;
        };
        // 空 cron
        let j = job(1002, "unit-badcron-empty", "", "unitTest.scheduler.add");
        assert!(matches!(
            scheduler.add_job(&j).await,
            Err(SchedulerError::InvalidCron(_))
        ));
        // 非法 cron 语法
        let j = job(
            1003,
            "unit-badcron-syntax",
            "not-a-cron",
            "unitTest.scheduler.add",
        );
        assert!(matches!(
            scheduler.add_job(&j).await,
            Err(SchedulerError::InvalidCron(_))
        ));
    }

    #[tokio::test]
    async fn test_scheduler_remove_nonexistent_is_ok() {
        let Some(scheduler) = build_scheduler().await else {
            return;
        };
        // 移除不存在的任务应幂等成功（仅告警）
        assert!(scheduler.remove_job(999999).await.is_ok());
    }

    #[tokio::test]
    async fn test_scheduler_update_job_replaces_guid() {
        let Some(scheduler) = build_scheduler().await else {
            return;
        };
        let j = job(1004, "unit-update", "0 0 3 * * *", "unitTest.scheduler.add");
        let g1 = scheduler.add_job(&j).await.unwrap();
        let j2 = job(1004, "unit-update", "0 0 4 * * *", "unitTest.scheduler.add");
        scheduler.update_job(&j2).await.unwrap();
        let g2 = scheduler.running_jobs.read().await.get(&1004).copied();
        assert!(g2.is_some());
        assert_ne!(g1, g2.unwrap(), "更新后应使用新 guid");
    }

    #[tokio::test]
    async fn test_scheduler_run_once_executes_and_logs() {
        let Some(scheduler) = build_scheduler().await else {
            return;
        };
        let db = scheduler.db.clone();
        let target = "unitTest.scheduler.once";
        registry::register_task(
            target,
            Arc::new(|| Box::pin(async { Ok("once-done".to_string()) })),
        );
        // 清理历史残留锁，避免 run_once 内部获取锁失败跳过执行
        let mut redis = scheduler.redis.clone();
        let _: () = redis::cmd("DEL")
            .arg("lock:scheduler:1005")
            .query_async(&mut redis)
            .await
            .unwrap();
        let j = job(1005, "unit-once", "0 0 3 * * *", target);
        scheduler.run_once(&j).await.unwrap();
        // run_once 内部 spawn 执行，等待其完成并写入日志
        tokio::time::sleep(Duration::from_millis(600)).await;
        let log_repo = SysJobLogRepository::new(db.clone());
        let logs = log_repo.find_by_job_name("unit-once", None).await.unwrap();
        assert_eq!(logs.len(), 1);
    }

    #[tokio::test]
    async fn test_scheduler_load_from_db_registers_jobs() {
        let Some(scheduler) = build_scheduler().await else {
            return;
        };
        let db = scheduler.db.clone();
        let target = "unitTest.scheduler.load";
        registry::register_task(
            target,
            Arc::new(|| Box::pin(async { Ok("load-done".to_string()) })),
        );
        let am = SysJobActiveModel {
            tenant_id: Set(0),
            job_name: Set("unit-load".to_string()),
            job_group: Set("DEFAULT".to_string()),
            invoke_target: Set(target.to_string()),
            cron_expression: Set(Some("0 0 3 * * *".to_string())),
            misfire_policy: Set(Some("3".to_string())),
            concurrent: Set(Some("1".to_string())),
            status: Set(Some("0".to_string())),
            create_by: Set(None),
            create_time: Set(None),
            update_by: Set(None),
            update_time: Set(None),
            remark: Set(None),
            del_flag: Set(Some("0".to_string())),
            job_id: NotSet,
        };
        let repo = SysJobRepository::new(db.clone());
        repo.insert(am).await.unwrap();
        scheduler.load_from_db(&repo).await.unwrap();
        assert!(
            scheduler
                .running_jobs
                .read()
                .await
                .values()
                .next()
                .is_some(),
            "load_from_db 应注册数据库中的启用任务"
        );
    }

    #[tokio::test]
    async fn test_scheduler_shutdown_ok() {
        let Some(scheduler) = build_scheduler().await else {
            return;
        };
        assert!(scheduler.shutdown().await.is_ok());
    }
}
