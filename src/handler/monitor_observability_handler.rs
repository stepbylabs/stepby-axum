//! 可观测性监控 Handler（慢请求 / 错误聚合 / Redis 指标）
//!
//! 接口路径（供「运行监控」面板消费）：
//! - GET    /monitor/slow-sql/list     慢请求列表（分页）
//! - GET    /monitor/slow-sql/stats    慢请求聚合统计（count/avg/max/top）
//! - DELETE /monitor/slow-sql/clear    清空慢请求缓冲
//! - GET    /monitor/error-log/list    错误日志列表（按 module/level 过滤 + 分页）
//! - GET    /monitor/error-log/stats   错误聚合统计（by-module / by-level）
//! - DELETE /monitor/error-log/clear   清空错误缓冲
//! - GET    /monitor/redis/stats       Redis 运行指标（INFO 精简版，供 Prometheus/面板）
//!
//! 数据全部读取进程内可观测性全局实例（`state.observability`），
//! 由监控中间件（observability::monitoring_middleware）与日志层（ErrorCaptureLayer）写入。

use std::sync::Arc;

use axum::extract::{Query, State};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::common::{AjaxResult, AppError, TableDataInfo};
use crate::observability::error_log::ErrorEntry;
use crate::observability::slow::SlowRequestRecord;
use crate::state::AppState;

// ==================== 通用分页 ====================

fn default_page_num() -> u64 {
    1
}
fn default_page_size() -> u64 {
    10
}

// ==================== 慢请求（慢 SQL 面板）====================

/// 慢请求列表查询参数
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SlowQueryDto {
    #[serde(default = "default_page_num")]
    pub page_num: u64,
    #[serde(default = "default_page_size")]
    pub page_size: u64,
}

/// GET /monitor/slow-sql/list
/// 慢请求列表（分页，最新在前）。超过配置阈值（monitor.slow_request_ms）的请求进入缓冲。
#[utoipa::path(
    get,
    path = "/monitor/slow-sql/list",
    responses(
        (status = 200, description = "查询成功", body = TableDataInfo<SlowRequestRecord>),
    ),
    tag = "monitor-observability"
)]
pub async fn slow_sql_list(
    State(state): State<Arc<AppState>>,
    Query(dto): Query<SlowQueryDto>,
) -> Result<TableDataInfo<SlowRequestRecord>, AppError> {
    let all = state.observability.slow.list();
    let (offset, limit) = page_slice(dto.page_num, dto.page_size);
    let total = all.len();
    let rows = all.into_iter().skip(offset).take(limit).collect();
    Ok(TableDataInfo::new(total as u64, rows))
}

/// GET /monitor/slow-sql/stats
/// 慢请求聚合统计（count/avg/max/over1s/top_paths），供面板指标卡与 Top 表。
#[utoipa::path(
    get,
    path = "/monitor/slow-sql/stats",
    responses(
        (status = 200, description = "查询成功", body = AjaxResult<crate::observability::slow::SlowStats>),
    ),
    tag = "monitor-observability"
)]
pub async fn slow_sql_stats(
    State(state): State<Arc<AppState>>,
) -> Result<AjaxResult<crate::observability::slow::SlowStats>, AppError> {
    Ok(AjaxResult::success(state.observability.slow.stats()))
}

/// DELETE /monitor/slow-sql/clear
/// 清空慢请求缓冲，返回清空条数。
#[utoipa::path(
    delete,
    path = "/monitor/slow-sql/clear",
    responses(
        (status = 200, description = "清空成功", body = AjaxResult<serde_json::Value>),
    ),
    tag = "monitor-observability"
)]
pub async fn slow_sql_clear(
    State(state): State<Arc<AppState>>,
) -> Result<AjaxResult<serde_json::Value>, AppError> {
    let cleared = state.observability.slow.clear();
    Ok(AjaxResult::success(
        serde_json::json!({ "cleared": cleared }),
    ))
}

// ==================== 错误聚合 ====================

/// 错误日志查询参数（按 module 模糊 / level 精确过滤 + 分页）
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ErrorLogQueryDto {
    pub module: Option<String>,
    pub level: Option<String>,
    #[serde(default = "default_page_num")]
    pub page_num: u64,
    #[serde(default = "default_page_size")]
    pub page_size: u64,
}

/// GET /monitor/error-log/list
/// 错误日志列表（按 module / level 过滤 + 分页，最新在前）。
#[utoipa::path(
    get,
    path = "/monitor/error-log/list",
    responses(
        (status = 200, description = "查询成功", body = TableDataInfo<ErrorEntry>),
    ),
    tag = "monitor-observability"
)]
pub async fn error_log_list(
    State(state): State<Arc<AppState>>,
    Query(dto): Query<ErrorLogQueryDto>,
) -> Result<TableDataInfo<ErrorEntry>, AppError> {
    let (offset, limit) = page_slice(dto.page_num, dto.page_size);
    let (total, list) = state.observability.error_log.list(
        dto.module.as_deref(),
        dto.level.as_deref(),
        offset,
        limit,
    );
    // 一次取全量后业务层分页，避免重复重复查库；此处错误总线已内部分页，直接返回
    Ok(TableDataInfo::new(total as u64, list))
}

/// GET /monitor/error-log/stats
/// 错误聚合统计（按 target 模块 / 级别分桶）。
#[utoipa::path(
    get,
    path = "/monitor/error-log/stats",
    responses(
        (status = 200, description = "查询成功", body = AjaxResult<crate::observability::error_log::ErrorStats>),
    ),
    tag = "monitor-observability"
)]
pub async fn error_log_stats(
    State(state): State<Arc<AppState>>,
) -> Result<AjaxResult<crate::observability::error_log::ErrorStats>, AppError> {
    Ok(AjaxResult::success(state.observability.error_log.stats()))
}

/// DELETE /monitor/error-log/clear
/// 清空错误缓冲，返回清空条数。
#[utoipa::path(
    delete,
    path = "/monitor/error-log/clear",
    responses(
        (status = 200, description = "清空成功", body = AjaxResult<serde_json::Value>),
    ),
    tag = "monitor-observability"
)]
pub async fn error_log_clear(
    State(state): State<Arc<AppState>>,
) -> Result<AjaxResult<serde_json::Value>, AppError> {
    let cleared = state.observability.error_log.clear();
    Ok(AjaxResult::success(
        serde_json::json!({ "cleared": cleared }),
    ))
}

// ==================== Redis 运行指标 ====================

/// Redis 运行指标（从 INFO 精简提取，供面板与 Prometheus 共享）
#[derive(Debug, Clone, Serialize, ToSchema, Default)]
#[serde(rename_all = "camelCase")]
pub struct RedisStats {
    /// 进程运行秒数（uptime_in_seconds）
    pub uptime_seconds: String,
    /// 已连接客户端数（connected_clients）
    pub connected_clients: String,
    /// 已使用内存字节（used_memory）
    pub used_memory_bytes: String,
    /// 峰值内存字节（used_memory_peak）
    pub used_memory_peak_bytes: String,
    /// 命中键数（keyspace_hits）
    pub keyspace_hits: String,
    /// 未命中键数（keyspace_misses）
    pub keyspace_misses: String,
    /// 累计处理命令数（total_commands_processed）
    pub total_commands_processed: String,
    /// 累计网络输入字节（total_net_input_bytes）
    pub total_net_input_bytes: String,
    /// 累计网络输出字节（total_net_output_bytes）
    pub total_net_output_bytes: String,
    /// 当前数据库键数量（db0:keys=N）
    pub db_size: String,
}

/// GET /monitor/redis/stats
/// Redis 运行指标（真实执行 INFO 命令解析，脱敏——不含配置/密码段）。
#[utoipa::path(
    get,
    path = "/monitor/redis/stats",
    responses(
        (status = 200, description = "查询成功", body = AjaxResult<RedisStats>),
        (status = 500, description = "Redis INFO 执行失败"),
    ),
    tag = "monitor-observability"
)]
pub async fn redis_stats(
    State(state): State<Arc<AppState>>,
) -> Result<AjaxResult<RedisStats>, AppError> {
    let mut conn = state.redis.clone();
    let info_text: String = redis::cmd("INFO")
        .query_async(&mut conn)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Redis INFO 查询失败");
            AppError::internal(&crate::tr!("error.cache.info_fetch_failed"))
        })?;
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
    let get = |k: &str| map.get(k).cloned().unwrap_or_default();
    // db0:keys=N 提取（至少覆盖 Redis 默认单库）
    let db_size = map
        .iter()
        .find(|(k, _)| k.starts_with("db") && k.contains(":"))
        .and_then(|(_, v)| v.split(',').next().map(|s| s.trim().replace("keys=", "")))
        .unwrap_or_default();

    Ok(AjaxResult::success(RedisStats {
        uptime_seconds: get("uptime_in_seconds"),
        connected_clients: get("connected_clients"),
        used_memory_bytes: get("used_memory"),
        used_memory_peak_bytes: get("used_memory_peak"),
        keyspace_hits: get("keyspace_hits"),
        keyspace_misses: get("keyspace_misses"),
        total_commands_processed: get("total_commands_processed"),
        total_net_input_bytes: get("total_net_input_bytes"),
        total_net_output_bytes: get("total_net_output_bytes"),
        db_size,
    }))
}

// ==================== 工具函数 ====================

/// 由 page_num/page_size 计算 skip/take（page_num 从 1 起，最小为 1）
fn page_slice(page_num: u64, page_size: u64) -> (usize, usize) {
    let page_num = page_num.max(1);
    let page_size = page_size.clamp(1, 200) as usize;
    (
        ((page_num - 1) as usize).saturating_mul(page_size),
        page_size,
    )
}
