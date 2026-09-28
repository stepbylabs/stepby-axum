// axum-backend/src/handler/health.rs

use crate::common::{AjaxResult, AppError};
use crate::state::AppState;
use axum::extract::State;
use serde::Serialize;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use utoipa::ToSchema;

/// 健康检查缓存 TTL（R6-PERF-23：避免高频探针打爆 DB/Redis）
const HEALTH_CACHE_TTL: Duration = Duration::from_secs(5);

/// 健康检查结果缓存（OnceLock 懒初始化，进程级共享）
///
/// 存储 `(写入时刻, HealthStatus)`，读取时若 `elapsed < TTL` 则直接返回缓存，
/// 否则重新探测并更新。多请求并发时可能出现一次 TTL 到期后并发触发多次探测，
/// 但锁粒度极小，且 5 秒 TTL 下并发触发概率低，权衡后采用此简单实现。
static HEALTH_CACHE: std::sync::OnceLock<RwLock<Option<(Instant, HealthStatus)>>> =
    std::sync::OnceLock::new();

/// 获取健康检查缓存的全局 RwLock 引用
fn health_cache() -> &'static RwLock<Option<(Instant, HealthStatus)>> {
    HEALTH_CACHE.get_or_init(|| RwLock::new(None))
}

/// 健康检查响应体
#[derive(Serialize, Clone, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct HealthStatus {
    pub status: String,
    pub version: String,
    /// 数据库连通性："UP" / "DOWN"
    pub db: String,
    /// Redis 连通性："UP" / "DOWN"
    pub redis: String,
}

/// GET /health
/// 健康检查接口（免鉴权）
/// 真实探测 DB 与 Redis 连通性，避免"伪健康"（P0-New-5）
///
/// R6-PERF-23：增加 5 秒 TTL 缓存，防止 K8s/Consul 高频探针（每秒 N 次）
/// 直接打爆 DB ping 和 Redis PING。缓存过期前所有请求直接返回上次结果，
/// 牺牲最多 5 秒状态延迟换取后端依赖保护。
#[utoipa::path(
    get,
    path = "/health",
    responses(
        (status = 200, description = "健康检查结果（DB/Redis 连通性）", body = AjaxResult<HealthStatus>),
    ),
    security(()),
    tag = "monitor-health"
)]
pub async fn health(
    State(state): State<Arc<AppState>>,
) -> Result<AjaxResult<HealthStatus>, AppError> {
    // 先查缓存：未过期则直接返回
    {
        let cache = health_cache().read().await;
        if let Some((ts, status)) = cache.as_ref()
            && ts.elapsed() < HEALTH_CACHE_TTL
        {
            return Ok(AjaxResult::success(status.clone()));
        }
    }

    // 缓存过期或不存在，执行真实健康检查
    // 探测数据库连通性（ping 失败不 panic，记录 DOWN）
    let db_status = match state.db.ping().await {
        Ok(_) => "UP".to_string(),
        Err(e) => {
            tracing::error!(error = ?e, "健康检查：数据库 ping 失败");
            "DOWN".to_string()
        }
    };

    // 探测 Redis 连通性
    let redis_status = {
        let mut conn = state.redis.clone();
        match crate::utils::redis::cmd_timeout(redis::cmd("PING").query_async::<String>(&mut conn))
            .await
        {
            Ok(_) => "UP".to_string(),
            Err(e) => {
                tracing::error!(error = ?e, "健康检查：Redis ping 失败");
                "DOWN".to_string()
            }
        }
    };

    // 任一依赖 DOWN 则整体 DEGRADED（仍返回 200 便于探针观察细节，
    // 生产环境如需 503 可根据 status 字段判断）
    let overall = if db_status == "UP" && redis_status == "UP" {
        "UP"
    } else {
        "DEGRADED"
    };

    let status = HealthStatus {
        status: overall.to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        db: db_status,
        redis: redis_status,
    };

    // 更新缓存（即使写入失败也不影响本次响应）
    {
        let mut cache = health_cache().write().await;
        *cache = Some((Instant::now(), status.clone()));
    }

    Ok(AjaxResult::success(status))
}

// ==================== Prometheus 指标端点 ====================

/// 进程启动时间（OnceLock 懒初始化，首次调用 /metrics 时记录）
static START_TIME: std::sync::OnceLock<Instant> = std::sync::OnceLock::new();

/// GET /metrics
///
/// Prometheus 文本格式指标端点（免鉴权），供监控系统采集。
/// 暴露指标：
/// - yebot_uptime_seconds：进程运行时长
/// - yebot_process_resident_memory_bytes / yebot_process_virtual_memory_bytes：进程内存
/// - yebot_db_backend：数据库后端类型（sqlite/mysql/postgres，info 标签）
/// - yebot_db_connected：数据库连通性（1=已连接 0=未连接）
///
/// 无 Grafana/Prometheus 时仍可 `curl http://localhost:8080/metrics` 查看文本格式指标。
///
/// 注：sea-orm 1.1 未公开底层 sqlx Pool 的 size()/num_idle() API，
/// 故连接池容量统计暂不可用。未来 sea-orm 暴露 pool 访问接口后可扩展。
#[utoipa::path(
    get,
    path = "/metrics",
    responses(
        (status = 200, description = "Prometheus 文本格式指标", content_type = "text/plain"),
        (status = 401, description = "已配置 metrics_token 且 Authorization 校验失败"),
    ),
    security(()),
    tag = "monitor-health"
)]
pub async fn metrics(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
) -> Result<String, AppError> {
    // 可选指标鉴权（向后兼容）：
    // 仅当配置 monitor.metrics_token（或环境变量 MONITOR_METRICS_TOKEN）非空时才要求
    // `Authorization: Bearer <token>`；未配置时保持匿名可访问（便于本地 curl / Prometheus 无配置拉取）。
    // 生产环境建议配置该 token，或在反向代理层限制 /metrics 来源 IP。
    let expected_token = &state.config.monitor.metrics_token;
    if !expected_token.is_empty() {
        let ok = headers
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .map(|v| v == format!("Bearer {}", expected_token))
            .unwrap_or(false);
        if !ok {
            return Err(AppError::unauthorized("metrics token required"));
        }
    }

    let start = START_TIME.get_or_init(Instant::now);
    let uptime = start.elapsed().as_secs();
    let (rss, vms) = process_memory();
    let db_backend_name = db_backend_name(&state.db);
    let db_connected = db_is_connected(&state.db).await;

    let mut s = String::new();
    // uptime
    s.push_str("# HELP yebot_uptime_seconds 进程运行时长（秒）\n");
    s.push_str("# TYPE yebot_uptime_seconds gauge\n");
    s.push_str(&format!("yebot_uptime_seconds {}\n", uptime));
    // 进程内存
    s.push_str("# HELP yebot_process_resident_memory_bytes 进程常驻内存（字节）\n");
    s.push_str("# TYPE yebot_process_resident_memory_bytes gauge\n");
    s.push_str(&format!("yebot_process_resident_memory_bytes {}\n", rss));
    s.push_str("# HELP yebot_process_virtual_memory_bytes 进程虚拟内存（字节）\n");
    s.push_str("# TYPE yebot_process_virtual_memory_bytes gauge\n");
    s.push_str(&format!("yebot_process_virtual_memory_bytes {}\n", vms));
    // 进程信息
    s.push_str("# HELP yebot_process_info 进程信息（version=后端版本）\n");
    s.push_str("# TYPE yebot_process_info gauge\n");
    s.push_str(&format!(
        "yebot_process_info{{version=\"{}\"}} 1\n",
        env!("CARGO_PKG_VERSION")
    ));
    // DB 后端类型指标
    s.push_str("# HELP yebot_db_backend 数据库后端类型（sqlite/mysql/postgres）\n");
    s.push_str("# TYPE yebot_db_backend gauge\n");
    s.push_str(&format!(
        "yebot_db_backend{{backend=\"{}\"}} 1\n",
        db_backend_name
    ));
    // DB 连通性指标
    s.push_str("# HELP yebot_db_connected 数据库连通性（1=已连接 0=未连接）\n");
    s.push_str("# TYPE yebot_db_connected gauge\n");
    s.push_str(&format!(
        "yebot_db_connected{{backend=\"{}\"}} {}\n",
        db_backend_name,
        if db_connected { 1 } else { 0 }
    ));

    // 业务 HTTP 指标（request counter + duration histogram，由 monitoring_middleware 写入）
    s.push_str(&state.observability.metrics.render_prometheus());

    // Redis 运行指标（INFO 精简为 gauge，best-effort：失败则不输出该组指标）
    s.push_str(&collect_redis_prometheus(&state).await);

    Ok(s)
}

/// Redis 运行指标 → Prometheus gauge（best-effort，失败返回空串不影响整体输出）
async fn collect_redis_prometheus(state: &Arc<AppState>) -> String {
    let mut conn = state.redis.clone();
    let info_text: String =
        match crate::utils::redis::cmd_timeout(redis::cmd("INFO").query_async(&mut conn)).await {
            Ok(t) => t,
            Err(e) => {
                tracing::warn!(error = %e, "/metrics 采集 Redis INFO 失败，跳过 Redis 指标");
                return String::new();
            }
        };
    let mut map = std::collections::HashMap::new();
    for line in info_text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some((k, v)) = line.split_once(':') {
            map.insert(k.trim().to_string(), v.trim().to_string());
        }
    }
    let num = |k: &str| map.get(k).and_then(|v| v.parse::<f64>().ok());

    let mut s = String::new();
    // 仅在取值成功时输出对应 gauge，保证单行格式正确。
    if let Some(v) = num("uptime_in_seconds") {
        s.push_str(&format!("yebot_redis_uptime_seconds {}\n", format_gauge(v)));
    }
    if let Some(v) = num("connected_clients") {
        s.push_str(&format!("yebot_redis_connected_clients {}\n", v));
    }
    if let Some(v) = num("used_memory") {
        s.push_str(&format!("yebot_redis_used_memory_bytes {}\n", v));
    }
    if let Some(v) = num("used_memory_peak") {
        s.push_str(&format!("yebot_redis_used_memory_peak_bytes {}\n", v));
    }
    if let Some(v) = num("keyspace_hits") {
        s.push_str(&format!("yebot_redis_keyspace_hits {}\n", v));
    }
    if let Some(v) = num("keyspace_misses") {
        s.push_str(&format!("yebot_redis_keyspace_misses {}\n", v));
    }
    if let Some(v) = num("total_commands_processed") {
        s.push_str(&format!("yebot_redis_commands_processed {}\n", v));
    }
    if let Some(v) = num("total_net_input_bytes") {
        s.push_str(&format!("yebot_redis_net_input_bytes {}\n", v));
    }
    if let Some(v) = num("total_net_output_bytes") {
        s.push_str(&format!("yebot_redis_net_output_bytes {}\n", v));
    }
    s
}

/// 格式化 gauge 数值（整数打印不带小数点）
fn format_gauge(v: f64) -> String {
    if v.fract() == 0.0 {
        format!("{}", v as i64)
    } else {
        format!("{v}")
    }
}

/// 获取数据库后端类型名称
fn db_backend_name(db: &sea_orm::DatabaseConnection) -> &'static str {
    use sea_orm::{ConnectionTrait, DatabaseBackend};
    match db.get_database_backend() {
        DatabaseBackend::Sqlite => "sqlite",
        DatabaseBackend::MySql => "mysql",
        DatabaseBackend::Postgres => "postgres",
    }
}

/// 探测数据库连通性（通过 ping）
async fn db_is_connected(db: &sea_orm::DatabaseConnection) -> bool {
    db.ping().await.is_ok()
}

/// 采集当前进程的常驻内存与虚拟内存（字节）
///
/// 仅刷新当前进程而非 System::new_all()，避免遍历系统所有进程的开销
fn process_memory() -> (u64, u64) {
    use sysinfo::{ProcessesToUpdate, System};
    let mut sys = System::new();
    let pid = sysinfo::get_current_pid().unwrap_or(sysinfo::Pid::from(0usize));
    sys.refresh_processes(ProcessesToUpdate::Some(&[pid]), true);
    if let Some(proc) = sys.process(pid) {
        (proc.memory(), proc.virtual_memory())
    } else {
        (0, 0)
    }
}
