//! 缓存监控 Handler（Axum 原生实现）
//!
//! 接口路径对齐前端调用规范：
//! - GET    /monitor/cache                                    获取 Redis 缓存概览
//! - GET    /monitor/cache/getNames                           获取缓存键名列表
//! - GET    /monitor/cache/hotKeys                            获取热 key（大内存键）提示
//! - GET    /monitor/cache/prefixStats                        获取缓存前缀内存统计
//! - GET    /monitor/cache/getKeys/{cacheName}                获取指定缓存的键列表
//! - GET    /monitor/cache/getValue/{cacheName}/{cacheKey}    获取缓存值
//! - DELETE /monitor/cache/clearCacheName/{cacheName}         清除指定名称的缓存
//! - DELETE /monitor/cache/clearCacheKey/{cacheKey}           清除指定键的缓存
//! - DELETE /monitor/cache/clearCacheAll                      清除所有缓存（已禁用）
//!
//! 直接操作 Redis，使用 redis::cmd 执行原生命令。

use std::collections::HashMap;
use std::sync::Arc;

use axum::extract::{Path, State};
use serde::Serialize;
use utoipa::ToSchema;

use crate::common::{AjaxResult, AppError};
use crate::state::AppState;
use crate::utils::redis::{scan_keys, scan_keys_all};

// ==================== 缓存前缀白名单 ====================

/// 允许查询/清理的缓存前缀白名单
const ALLOWED_CACHE_PREFIXES: &[&str] = &[
    "dict:",
    "sys_config:",
    "captcha:",
    "login_fail:",
    "login_ip:",
    "blacklist:",
    "online:",
    // v3 §5.1：仅暴露不透明 AT 绑定（运维可见/可清理）；
    // 不加 sso:code:——授权码 TTL 仅 60s 且含 PKCE challenge，无运维价值且有泄漏面
    "sso:at:",
    "sso:user_at:",
];

/// `sso:at:` 绑定 value（AccessBinding JSON）中的个人信息字段——
/// 缓存监控页展示时一律脱敏（v4 F4-1：username/email/nick_name 全脱敏，
/// 保留 client_id/user_id/scope/iat 供排障）
const SSO_BINDING_SENSITIVE_FIELDS: &[&str] = &["username", "email", "nick_name"];

/// `online:` 会话 value（OnlineSession JSON）中的个人信息字段——
/// v5-S3：与 sso:at: 同标准脱敏（username/ip），其余字段供排障
const ONLINE_SESSION_SENSITIVE_FIELDS: &[&str] = &["username", "ip"];

/// 对 `sso:at:` / `online:` 类缓存值做个人信息脱敏：JSON 中命中敏感字段替换为固定掩码；
/// 非 JSON / 无敏感字段时原样返回
fn mask_sso_binding_value(value: &str, fields: &[&str]) -> String {
    let Ok(mut json) = serde_json::from_str::<serde_json::Value>(value) else {
        return value.to_string();
    };
    if let Some(obj) = json.as_object_mut() {
        let mut masked = false;
        for field in fields {
            if obj.contains_key(*field) {
                obj.insert(field.to_string(), serde_json::json!("***"));
                masked = true;
            }
        }
        if !masked {
            return value.to_string();
        }
    }
    serde_json::to_string(&json).unwrap_or_else(|_| value.to_string())
}

/// 校验缓存前缀是否在白名单内，防止通配符滥用或误删关键键
fn validate_cache_prefix(prefix: &str) -> Result<(), AppError> {
    // 拒绝包含通配符的输入
    if prefix.contains('*') || prefix.contains('?') || prefix.contains('[') {
        return Err(AppError::bad_request(&crate::tr!(
            "error.cache.name_wildcard_forbidden"
        )));
    }
    // 检查白名单
    if !ALLOWED_CACHE_PREFIXES.iter().any(|p| prefix.starts_with(p)) {
        return Err(AppError::bad_request(&crate::tr!(
            "error.cache.prefix_not_allowed",
            prefix = prefix,
            allowed = ALLOWED_CACHE_PREFIXES.join(", ")
        )));
    }
    Ok(())
}

// ==================== 响应结构体 ====================

/// Redis 缓存概览（对齐前端 cache 对象结构）
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct CacheOverview {
    /// Redis INFO 解析后的键值对
    pub info: HashMap<String, String>,
    /// 当前数据库键数量
    pub db_size: i64,
    /// 命令统计（用于前端饼图）
    pub command_stats: Vec<CommandStat>,
}

/// 命令统计项（对齐前端 echarts 饼图数据 { name, value }）
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct CommandStat {
    pub name: String,
    pub value: String,
}

/// 缓存条目（对齐前端 SysCache）
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct SysCache {
    /// 缓存名称（前缀）
    pub cache_name: String,
    /// 缓存键名
    pub cache_key: String,
    /// 缓存内容
    pub cache_value: String,
    /// 备注
    pub remark: String,
}

/// 热 key 项（大内存键提示）
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct HotKey {
    /// 键名
    pub key: String,
    /// 键类型（string/list/hash/set/zset 等，经 TYPE 命令标注）
    pub key_type: String,
    /// 内存占用（字节），来自 MEMORY USAGE 真实数值
    pub memory_bytes: i64,
}

/// 缓存前缀内存统计项
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct CachePrefixStat {
    /// 缓存前缀（冒号前含冒号）
    pub cache_name: String,
    /// 键数量
    pub key_count: usize,
    /// 内存占用（字节），逐键 MEMORY USAGE 累加
    pub memory_bytes: i64,
}

// ==================== Handler 实现 ====================

/// GET /monitor/cache
/// 获取 Redis 缓存概览信息（info + dbSize + commandStats）
#[utoipa::path(
    get,
    path = "/monitor/cache",
    responses(
        (status = 200, description = "查询成功", body = AjaxResult<CacheOverview>),
        (status = 500, description = "服务器错误"),
    ),
    tag = "monitor-cache"
)]
pub async fn get_cache(
    State(state): State<Arc<AppState>>,
) -> Result<AjaxResult<CacheOverview>, AppError> {
    let mut redis = state.redis.clone();

    // 1. 获取 Redis INFO 全量信息
    let info_text: String = redis::cmd("INFO")
        .query_async(&mut redis)
        .await
        .map_err(|e| {
            tracing::error!("执行 Redis INFO 失败: {}", e);
            AppError::internal(&crate::tr!("error.cache.info_fetch_failed"))
        })?;
    let info = parse_redis_info(&info_text);

    // 2. 获取当前数据库键数量
    let db_size: i64 = redis::cmd("DBSIZE")
        .query_async(&mut redis)
        .await
        .map_err(|e| {
            tracing::error!("执行 Redis DBSIZE 失败: {}", e);
            AppError::internal(&crate::tr!("error.cache.key_count_failed"))
        })?;

    // 3. 获取命令统计
    let cmd_text: String = redis::cmd("INFO")
        .arg("commandstats")
        .query_async(&mut redis)
        .await
        .unwrap_or_else(|e| {
            tracing::warn!("Redis INFO commandstats 查询失败: {}", e);
            String::new()
        });
    let command_stats = parse_command_stats(&cmd_text);

    Ok(AjaxResult::success(CacheOverview {
        info,
        db_size,
        command_stats,
    }))
}

/// GET /monitor/cache/getNames
/// 获取缓存键名列表（按前缀分组）
#[utoipa::path(
    get,
    path = "/monitor/cache/getNames",
    responses(
        (status = 200, description = "查询成功", body = AjaxResult<Vec<SysCache>>),
        (status = 500, description = "服务器错误"),
    ),
    tag = "monitor-cache"
)]
pub async fn get_names(
    State(state): State<Arc<AppState>>,
) -> Result<AjaxResult<Vec<SysCache>>, AppError> {
    let mut redis = state.redis.clone();

    // 获取全部键，按前缀（冒号前的部分）分组
    let keys: Vec<String> = scan_keys(&mut redis, "*", 5000).await?;

    // 按前缀分组统计
    let mut groups: HashMap<String, usize> = HashMap::new();
    for key in &keys {
        let prefix = if let Some(idx) = key.find(':') {
            &key[..=idx] // 包含冒号
        } else {
            key.as_str()
        };
        *groups.entry(prefix.to_string()).or_insert(0) += 1;
    }

    let list: Vec<SysCache> = groups
        .into_iter()
        .map(|(name, count)| SysCache {
            cache_name: name,
            cache_key: String::new(),
            cache_value: String::new(),
            remark: crate::tr!("error.cache.key_count_remark", count = count).to_string(),
        })
        .collect();

    Ok(AjaxResult::success(list))
}

/// GET /monitor/cache/hotKeys
/// 获取热 key（大内存键）提示，按内存占用降序取 top N（最多 20）
#[utoipa::path(
    get,
    path = "/monitor/cache/hotKeys",
    responses(
        (status = 200, description = "查询成功", body = AjaxResult<Vec<HotKey>>),
        (status = 500, description = "服务器错误"),
    ),
    tag = "monitor-cache"
)]
pub async fn get_hot_keys(
    State(state): State<Arc<AppState>>,
) -> Result<AjaxResult<Vec<HotKey>>, AppError> {
    let mut redis = state.redis.clone();

    let keys: Vec<String> = scan_keys(&mut redis, "*", 5000).await?;
    let stats = compute_key_memory(&mut redis, &keys).await?;

    // 过滤掉已过期/空内存（None）的键，按内存字节降序排序，取 top 20
    let mut ranked: Vec<(String, i64)> = stats
        .into_iter()
        .filter_map(|(key, mem)| mem.map(|m| (key, m)))
        .collect();
    ranked.sort_by_key(|(_, m)| std::cmp::Reverse(*m));
    ranked.truncate(20);

    let mut list = Vec::with_capacity(ranked.len());
    for (key, memory_bytes) in ranked {
        // 非 string 键用 TYPE 标注类型（MEMORY USAGE 对任意类型键均返回字节数）
        let key_type: String = redis::cmd("TYPE")
            .arg(&key)
            .query_async(&mut redis)
            .await
            .unwrap_or_else(|e| {
                tracing::warn!("Redis TYPE 查询失败: {}", e);
                "unknown".to_string()
            });
        list.push(HotKey {
            key,
            key_type,
            memory_bytes,
        });
    }

    Ok(AjaxResult::success(list))
}

/// GET /monitor/cache/prefixStats
/// 获取缓存前缀内存统计（按前缀分组，逐键 MEMORY USAGE 累加）
#[utoipa::path(
    get,
    path = "/monitor/cache/prefixStats",
    responses(
        (status = 200, description = "查询成功", body = AjaxResult<Vec<CachePrefixStat>>),
        (status = 500, description = "服务器错误"),
    ),
    tag = "monitor-cache"
)]
pub async fn get_prefix_stats(
    State(state): State<Arc<AppState>>,
) -> Result<AjaxResult<Vec<CachePrefixStat>>, AppError> {
    let mut redis = state.redis.clone();

    let keys: Vec<String> = scan_keys(&mut redis, "*", 5000).await?;
    let stats = compute_key_memory(&mut redis, &keys).await?;

    // 按前缀分组累加内存/计数
    let mut groups: HashMap<String, (usize, i64)> = HashMap::new();
    for (key, mem) in stats {
        let prefix = key_prefix(&key);
        let entry = groups.entry(prefix).or_insert((0, 0));
        entry.0 += 1;
        if let Some(m) = mem {
            entry.1 += m;
        }
    }

    let mut list: Vec<CachePrefixStat> = groups
        .into_iter()
        .map(|(cache_name, (key_count, memory_bytes))| CachePrefixStat {
            cache_name,
            key_count,
            memory_bytes,
        })
        .collect();
    // 按内存占用降序，供前端展示各前缀内存占比
    list.sort_by_key(|a| std::cmp::Reverse(a.memory_bytes));

    Ok(AjaxResult::success(list))
}

/// GET /monitor/cache/getKeys/{cacheName}
/// 获取指定缓存前缀的键列表
#[utoipa::path(
    get,
    path = "/monitor/cache/getKeys/{cacheName}",
    params(
        ("cacheName" = String, Path, description = "缓存名称（前缀）")
    ),
    responses(
        (status = 200, description = "查询成功", body = AjaxResult<Vec<String>>),
        (status = 500, description = "服务器错误"),
    ),
    tag = "monitor-cache"
)]
pub async fn get_keys(
    State(state): State<Arc<AppState>>,
    Path(cache_name): Path<String>,
) -> Result<AjaxResult<Vec<String>>, AppError> {
    // 校验缓存前缀白名单
    validate_cache_prefix(&cache_name)?;
    let mut redis = state.redis.clone();
    let pattern = format!("{}*", cache_name);

    let keys: Vec<String> = scan_keys(&mut redis, &pattern, 5000).await?;

    Ok(AjaxResult::success(keys))
}

/// GET /monitor/cache/getValue/{cacheName}/{cacheKey}
/// 获取指定键的缓存值
#[utoipa::path(
    get,
    path = "/monitor/cache/getValue/{cacheName}/{cacheKey}",
    params(
        ("cacheName" = String, Path, description = "缓存名称（前缀）"),
        ("cacheKey" = String, Path, description = "缓存键名")
    ),
    responses(
        (status = 200, description = "查询成功", body = AjaxResult<SysCache>),
        (status = 500, description = "服务器错误"),
    ),
    tag = "monitor-cache"
)]
pub async fn get_value(
    State(state): State<Arc<AppState>>,
    Path((cache_name, cache_key)): Path<(String, String)>,
) -> Result<AjaxResult<SysCache>, AppError> {
    // 校验缓存前缀白名单
    validate_cache_prefix(&cache_name)?;
    // 去除两端空白，防止绕过前缀校验
    let cache_key = cache_key.trim().to_string();
    // 校验 cache_key 必须以 cache_name 开头，防止 IDOR
    // （如 cache_name="dict:" 时传 cache_key="blacklist:xxx" 读取任意键）
    if !cache_key.starts_with(&cache_name) {
        return Err(AppError::bad_request(&crate::tr!(
            "error.cache.key_prefix_required",
            name = cache_name
        )));
    }
    let mut redis = state.redis.clone();

    // 查询键的类型，非 string 类型不支持预览
    let key_type: String = redis::cmd("TYPE")
        .arg(&cache_key)
        .query_async(&mut redis)
        .await
        .unwrap_or_else(|e| {
            tracing::warn!("Redis TYPE 查询失败: {}", e);
            "unknown".to_string()
        });

    let cache_value = if key_type == "string" {
        let raw = redis::cmd("GET")
            .arg(&cache_key)
            .query_async::<Option<String>>(&mut redis)
            .await
            .map_err(|e| {
                tracing::error!("Redis GET 查询失败: {}", e);
                AppError::internal(&crate::tr!("error.cache.value_query_failed"))
            })?
            .unwrap_or_default();
        // SSO 绑定（username/email/nick_name，v4 F4-1）与在线会话（username/ip，v5-S3）
        // 展示前按前缀选字段集脱敏
        if cache_key.starts_with("sso:") {
            mask_sso_binding_value(&raw, SSO_BINDING_SENSITIVE_FIELDS)
        } else if cache_key.starts_with("online:") {
            mask_sso_binding_value(&raw, ONLINE_SESSION_SENSITIVE_FIELDS)
        } else {
            raw
        }
    } else {
        crate::tr!("error.cache.type_not_previewable", r#type = key_type).to_string()
    };

    Ok(AjaxResult::success(SysCache {
        cache_name,
        cache_key,
        cache_value,
        remark: String::new(),
    }))
}

/// DELETE /monitor/cache/clearCacheName/{cacheName}
/// 清除指定名称（前缀）的所有缓存
#[utoipa::path(
    delete,
    path = "/monitor/cache/clearCacheName/{cacheName}",
    params(
        ("cacheName" = String, Path, description = "缓存名称（前缀）")
    ),
    responses(
        (status = 200, description = "清除成功", body = AjaxResult<serde_json::Value>),
        (status = 500, description = "服务器错误"),
    ),
    tag = "monitor-cache"
)]
pub async fn clear_cache_name(
    State(state): State<Arc<AppState>>,
    Path(cache_name): Path<String>,
) -> Result<AjaxResult<()>, AppError> {
    // 校验缓存前缀白名单
    validate_cache_prefix(&cache_name)?;
    let mut redis = state.redis.clone();
    let pattern = format!("{}*", cache_name);

    // 查询匹配的键
    // 第九批：改用 **不截断** 扫描。本接口语义是"清除**该前缀下全部**缓存"，
    // 原 `scan_keys(.., 5000)` 超限即静默截断 ⇒ 只清了前 5000 个却报"已清除 N 个"，
    // 让运维误判缓存已清空。pattern 来自白名单前缀校验（非裸 `*`），无 OOM 风险。
    let keys: Vec<String> = scan_keys_all(&mut redis, &pattern).await?;

    if keys.is_empty() {
        return Ok(AjaxResult::success_msg(&crate::tr!("msg.cache.no_match")));
    }

    // 批量删除
    let count = delete_keys(&mut redis, &keys).await?;
    Ok(AjaxResult::success_msg(&crate::tr!(
        "msg.cache.cleared",
        count = count
    )))
}

/// DELETE /monitor/cache/clearCacheKey/{cacheKey}
/// 清除指定键的缓存
#[utoipa::path(
    delete,
    path = "/monitor/cache/clearCacheKey/{cacheKey}",
    params(
        ("cacheKey" = String, Path, description = "缓存键名")
    ),
    responses(
        (status = 200, description = "清除成功", body = AjaxResult<serde_json::Value>),
        (status = 500, description = "服务器错误"),
    ),
    tag = "monitor-cache"
)]
pub async fn clear_cache_key(
    State(state): State<Arc<AppState>>,
    Path(cache_key): Path<String>,
) -> Result<AjaxResult<()>, AppError> {
    // 校验缓存键前缀白名单，防止误删关键键
    validate_cache_prefix(&cache_key)?;
    let mut redis = state.redis.clone();

    let deleted: i64 = redis::cmd("DEL")
        .arg(&cache_key)
        .query_async(&mut redis)
        .await
        .map_err(|e| {
            tracing::error!("执行 Redis DEL {} 失败: {}", cache_key, e);
            AppError::internal(&crate::tr!("error.cache.key_clear_failed"))
        })?;

    if deleted == 0 {
        return Ok(AjaxResult::success_msg(&crate::tr!(
            "msg.cache.key_not_found"
        )));
    }
    Ok(AjaxResult::success_msg(&crate::tr!("msg.success.clear")))
}

/// DELETE /monitor/cache/clearCacheAll
/// 清除所有缓存（已禁用 FLUSHDB，防止误清 blacklist/online/login_fail 等业务键）
///
/// 安全说明：FLUSHDB 会清空整个 Redis 数据库，包括 blacklist、online_tokens、
/// login_fail、captcha 等业务关键键，导致已注销 token 失效、在线用户管理失效、
/// 登录限流失效等严重问题。此端点已改为返回 403 禁止访问。
/// 如需批量清理，请使用 clearCacheName 按白名单前缀逐类清理。
#[utoipa::path(
    delete,
    path = "/monitor/cache/clearCacheAll",
    responses(
        (status = 403, description = "该端点已禁用，FLUSHDB 会误清业务键"),
    ),
    tag = "monitor-cache"
)]
pub async fn clear_cache_all(
    State(_state): State<Arc<AppState>>,
) -> Result<AjaxResult<()>, AppError> {
    Err(AppError::new(
        403,
        crate::tr!("error.cache.flushdb_disabled"),
    ))
}

// ==================== 辅助函数 ====================

// scan_keys 统一使用 crate::utils::redis::scan_keys（P2：带 max_results 上限，
// 防 `*` 等 pattern 匹配海量 key 导致 OOM）；原模块内本地实现已移除。

/// 解析 Redis INFO 输出为键值对 Map
///
/// INFO 输出格式：每行 `key:value`，以 `#` 开头为分组注释，空行跳过。
fn parse_redis_info(text: &str) -> HashMap<String, String> {
    let mut map = HashMap::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some((k, v)) = line.split_once(':') {
            let k = k.trim();
            // 跳过空键（如 `:value` 行），避免无意义的占位键
            if !k.is_empty() {
                map.insert(k.to_string(), v.trim().to_string());
            }
        }
    }
    map
}

/// 解析 Redis INFO commandstats 输出为命令统计列表
///
/// 输出格式：`cmdstat_<命令>:calls=N,usec=...`，提取命令名和调用次数。
fn parse_command_stats(text: &str) -> Vec<CommandStat> {
    let mut stats = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        // 格式：cmdstat_get:calls=100,usec=500,...
        if let Some((key, rest)) = line.split_once(':')
            && let Some(name) = key.strip_prefix("cmdstat_")
        {
            // 从 calls=N 中提取 N
            let calls = rest
                .split(',')
                .next()
                .and_then(|s| s.strip_prefix("calls="))
                .unwrap_or("0");
            stats.push(CommandStat {
                name: name.to_string(),
                value: calls.to_string(),
            });
        }
    }
    stats
}

/// 提取键前缀（冒号前含冒号；无冒号则整键）
///
/// 与 get_names 分组逻辑一致的独立封装，供 prefixStats 使用。
fn key_prefix(key: &str) -> String {
    if let Some(idx) = key.find(':') {
        key[..=idx].to_string()
    } else {
        key.to_string()
    }
}

/// 批量查询各键内存占用（MEMORY USAGE，字节），key 不存在时返回 None
///
/// 使用 pipeline 批量下发，减少 N 次 RTT。空列表直接返回空结果（避免空 pipeline 报错）。
/// 单个键内存超限/删除等导致 MEMORY USAGE 返回空视为 None，不阻断整体统计。
async fn compute_key_memory(
    redis: &mut redis::aio::ConnectionManager,
    keys: &[String],
) -> Result<Vec<(String, Option<i64>)>, AppError> {
    if keys.is_empty() {
        return Ok(Vec::new());
    }
    let mut pipe = redis::pipe();
    for k in keys {
        pipe.cmd("MEMORY").arg("USAGE").arg(k);
    }
    let vals: Vec<Option<i64>> = pipe.query_async(redis).await.map_err(|e| {
        tracing::error!("执行 Redis MEMORY USAGE 批量查询失败: {}", e);
        AppError::internal(&crate::tr!("error.cache.memory_usage_failed"))
    })?;
    Ok(keys.iter().cloned().zip(vals).collect())
}

/// 批量删除 Redis 键，返回删除数量
async fn delete_keys(
    redis: &mut redis::aio::ConnectionManager,
    keys: &[String],
) -> Result<i64, AppError> {
    if keys.is_empty() {
        return Ok(0);
    }
    // 第九批：分批下发（`scan_keys_all` 不截断 ⇒ 键数无上界；单条超长 DEL 会长时间
    // 占用 Redis 单线程）。语义不变：返回各批实际删除数之和。
    let mut deleted = 0i64;
    for chunk in keys.chunks(crate::utils::redis::DEL_BATCH_SIZE) {
        let mut cmd = redis::cmd("DEL");
        for k in chunk {
            cmd.arg(k);
        }
        let n: i64 = cmd.query_async(redis).await.map_err(|e| {
            tracing::error!("执行 Redis DEL 批量删除失败: {}", e);
            AppError::internal(&crate::tr!("error.cache.key_batch_delete_failed"))
        })?;
        deleted += n.max(0);
    }
    Ok(deleted)
}

// ==================== 单元测试 ====================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_redis_info_parses_key_value_lines() {
        let text = "# Server\r\nredis_version:7.2.0\n\nuptime_in_seconds:123\n";
        let map = parse_redis_info(text);
        assert_eq!(map.get("redis_version").map(String::as_str), Some("7.2.0"));
        assert_eq!(
            map.get("uptime_in_seconds").map(String::as_str),
            Some("123")
        );
        // 分组注释与空行不进入结果
        assert!(!map.contains_key("# Server"));
    }

    #[test]
    fn parse_redis_info_skips_malformed_lines() {
        let text = "no-colon-line\nfoo:bar\n:empty-key\n";
        let map = parse_redis_info(text);
        assert_eq!(map.len(), 1);
        assert_eq!(map.get("foo").map(String::as_str), Some("bar"));
    }

    #[test]
    fn parse_command_stats_extracts_calls() {
        let text = "# Commandstats\r\ncmdstat_get:calls=1000,usec=20000,usec_per_call=20.00\r\ncmdstat_set:calls=500\r\n";
        let stats = parse_command_stats(text);
        assert_eq!(stats.len(), 2);
        assert_eq!(stats[0].name, "get");
        assert_eq!(stats[0].value, "1000");
        assert_eq!(stats[1].name, "set");
        assert_eq!(stats[1].value, "500");
    }

    #[test]
    fn parse_command_stats_ignores_non_cmdstat_lines() {
        let text = "# Server\nredis_version:7.2.0\ncmdstat_get:calls=42\n";
        let stats = parse_command_stats(text);
        assert_eq!(stats.len(), 1);
        assert_eq!(stats[0].name, "get");
        assert_eq!(stats[0].value, "42");
    }

    #[test]
    fn key_prefix_keeps_colon_and_falls_back_to_whole_key() {
        assert_eq!(key_prefix("dict:user:1"), "dict:");
        assert_eq!(key_prefix("login_fail:admin"), "login_fail:");
        assert_eq!(key_prefix("no-namespace-key"), "no-namespace-key");
    }

    #[test]
    fn validate_cache_prefix_allows_whitelisted_prefix() {
        assert!(validate_cache_prefix("dict:user").is_ok());
        assert!(validate_cache_prefix("sys_config:site_name").is_ok());
        assert!(validate_cache_prefix("online:").is_ok());
    }

    #[test]
    fn validate_cache_prefix_rejects_wildcards() {
        assert!(validate_cache_prefix("dict:*").is_err());
        assert!(validate_cache_prefix("dict:user?").is_err());
        assert!(validate_cache_prefix("dict:[abc]").is_err());
    }

    #[test]
    fn validate_cache_prefix_rejects_non_whitelisted_prefix() {
        // 非白名单前缀，防误删关键业务键
        assert!(validate_cache_prefix("session:").is_err());
        assert!(validate_cache_prefix("user:token:1").is_err());
        // 空串既不在白名单前缀内，也会被拒
        assert!(validate_cache_prefix("").is_err());
    }

    #[test]
    fn sso_at_prefix_is_whitelisted() {
        assert!(validate_cache_prefix("sso:at:abc123").is_ok());
        assert!(validate_cache_prefix("sso:user_at:1").is_ok());
        // sso:code: 刻意不入白名单（TTL 短且含 PKCE challenge）
        assert!(validate_cache_prefix("sso:code:xyz").is_err());
        assert!(validate_cache_prefix("sso:sess:1").is_err());
    }

    #[test]
    fn mask_sso_binding_value_masks_pii_fields() {
        let binding = r#"{"client_id":"app_x","user_id":1,"username":"admin","email":"a@b.c","nick_name":"管理员","scope":["openid"],"iat":1700000000}"#;
        let masked = mask_sso_binding_value(binding, SSO_BINDING_SENSITIVE_FIELDS);
        let v: serde_json::Value = serde_json::from_str(&masked).unwrap();
        assert_eq!(v["username"], "***");
        assert_eq!(v["email"], "***");
        assert_eq!(v["nick_name"], "***");
        // 排障字段保留
        assert_eq!(v["client_id"], "app_x");
        assert_eq!(v["user_id"], 1);
        assert_eq!(v["scope"][0], "openid");
    }

    #[test]
    fn mask_online_session_value_masks_username_and_ip() {
        // v5-S3：online: 会话 username/ip 脱敏，其余排障字段保留
        let session = r#"{"user_id":2,"username":"tester","ip":"203.0.113.9","browser":"Chrome","os":"Win","jti":"sso-at-app_x","dept_name":"","exp":1790000000,"source":"sso"}"#;
        let masked = mask_sso_binding_value(session, ONLINE_SESSION_SENSITIVE_FIELDS);
        let v: serde_json::Value = serde_json::from_str(&masked).unwrap();
        assert_eq!(v["username"], "***");
        assert_eq!(v["ip"], "***");
        assert_eq!(v["user_id"], 2);
        assert_eq!(v["jti"], "sso-at-app_x");
        assert_eq!(v["source"], "sso");
    }

    #[test]
    fn mask_sso_binding_value_passthrough_non_binding() {
        // 非 JSON 原样返回
        assert_eq!(
            mask_sso_binding_value("plain", SSO_BINDING_SENSITIVE_FIELDS),
            "plain"
        );
        // JSON 但无敏感字段原样返回
        assert_eq!(
            mask_sso_binding_value(
                r#"{"client_id":"a","scope":[]}"#,
                SSO_BINDING_SENSITIVE_FIELDS
            ),
            r#"{"client_id":"a","scope":[]}"#
        );
    }
}
