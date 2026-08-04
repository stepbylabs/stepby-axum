// axum-backend/src/handler/health.rs

use std::sync::Arc;
use std::time::{Duration, Instant};
use axum::extract::State;
use serde::Serialize;
use tokio::sync::RwLock;
use crate::common::{AjaxResult, AppError};
use crate::state::AppState;

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
#[derive(Serialize, Clone)]
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
pub async fn health(State(state): State<Arc<AppState>>) -> Result<AjaxResult<HealthStatus>, AppError> {
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
        match redis::cmd("PING").query_async::<String>(&mut conn).await {
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
pub async fn metrics(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
) -> Result<String, AppError> {
    // 可选指标鉴权（向后兼容）：
    // 仅当设置环境变量 YEBOT_METRICS_TOKEN 时才要求 `Authorization: Bearer <token>`；
    // 未设置时保持原有匿名可访问行为（便于本地 curl / Prometheus 无配置拉取）。
    // 生产环境建议设置该变量，或在反向代理层限制 /metrics 来源 IP。
    if let Ok(expected) = std::env::var("YEBOT_METRICS_TOKEN") {
        if !expected.is_empty() {
            let ok = headers
                .get(axum::http::header::AUTHORIZATION)
                .and_then(|v| v.to_str().ok())
                .map(|v| v == format!("Bearer {}", expected))
                .unwrap_or(false);
            if !ok {
                return Err(AppError::unauthorized("metrics token required"));
            }
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
    s.push_str(&format!(
        "yebot_process_resident_memory_bytes {}\n",
        rss
    ));
    s.push_str("# HELP yebot_process_virtual_memory_bytes 进程虚拟内存（字节）\n");
    s.push_str("# TYPE yebot_process_virtual_memory_bytes gauge\n");
    s.push_str(&format!(
        "yebot_process_virtual_memory_bytes {}\n",
        vms
    ));
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
        db_backend_name, if db_connected { 1 } else { 0 }
    ));

    Ok(s)
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
