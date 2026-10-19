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
//! 经 SharedStore trait 操作共享态存储（redis 档 = 现状 Redis 命令；local 档 = SQL 承载）。

use std::collections::HashMap;
use std::sync::Arc;

use axum::extract::{Path, State};
use serde::Serialize;
use utoipa::ToSchema;

use crate::common::{AjaxResult, AppError};
use crate::state::AppState;
use crate::utils::redis::DEL_BATCH_SIZE;

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
/// 获取共享态缓存概览信息（info + dbSize + commandStats）
///
/// 展示层档位适配：`info_summary` redis 档返回 INFO 原文（解析口径不变）；
/// local 档返回计数文本（`mode=local kv_entries=N ...`）→ info 只含计数项、
/// db_size 取条目数。commandstats 段 trait 未暴露（redis 档专属），返回空列表。
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
    // 1. 读取共享态存储运行摘要
    let info_text = state.store.info_summary().await.map_err(|e| {
        tracing::error!("读取共享态存储 info_summary 失败: {}", e);
        AppError::internal(&crate::tr!("error.cache.info_fetch_failed"))
    })?;
    let info = parse_redis_info(&info_text);

    // 2. 获取当前数据库键数量
    //    redis 档：从 INFO 的 `dbN:keys=N` 段提取（与 DBSIZE 等价，单库部署口径一致）；
    //    parse_redis_info 已按首个 `:` 切分，键名为 `dbN`（不含冒号），故只按前缀匹配；
    //    local 档：取 kv_entries 条目计数
    let db_size: i64 = if state.store.kind() == "redis" {
        info.iter()
            .find(|(k, _)| k.starts_with("db") && k[2..].chars().all(|c| c.is_ascii_digit()))
            .and_then(|(_, v)| v.split(',').next())
            .and_then(|s| s.trim().strip_prefix("keys="))
            .and_then(|s| s.parse::<i64>().ok())
            .unwrap_or(0)
    } else {
        info.get("kv_entries")
            .and_then(|v| v.parse::<i64>().ok())
            .unwrap_or(0)
    };

    // 3. 命令统计：trait 未暴露 commandstats（redis 档原 INFO commandstats 段为
    //    Redis 专属观测，local 档无对应概念）→ 返回空列表，前端饼图按空态兼容
    let command_stats: Vec<CommandStat> = Vec::new();

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
    // 获取全部键（截断版，上限保持 5000），按前缀（冒号前的部分）分组
    let keys: Vec<String> = state
        .store
        .scan("*", Some(5000))
        .await
        .map_err(map_scan_error)?;

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

    // 仅保留白名单前缀组：getKeys/清理接口按 ALLOWED_CACHE_PREFIXES 校验（防通配符滥用），
    // getNames 若不过滤会列出点击后必 400 的"死行"（前端行点击仅拿到拦截器统一报错，
    // 行本身不可操作=假入口）。口径与 get_keys/清理接口的 validate_cache_prefix 单点收敛。
    groups.retain(|name, _| ALLOWED_CACHE_PREFIXES.iter().any(|p| name.starts_with(p)));

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
///
/// 展示层档位适配：共享态存储统一为 string KV（redis 档项目内仅 GET/SETEX，
/// local 档 sys_shared_kv 单值列），原 `MEMORY USAGE`/`TYPE` 命令不可经 trait 获得——
/// 改以**值字节长度**真实计量（非 mock），key_type 恒为 "string"。
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
    let keys: Vec<String> = state
        .store
        .scan("*", Some(5000))
        .await
        .map_err(map_scan_error)?;
    let stats = collect_value_sizes(&state, &keys).await?;

    // 过滤掉不存在/空值（None）的键，按占用字节降序排序，取 top 20
    let mut ranked: Vec<(String, i64)> = stats
        .into_iter()
        .filter_map(|(key, mem)| mem.map(|m| (key, m)))
        .collect();
    ranked.sort_by_key(|(_, m)| std::cmp::Reverse(*m));
    ranked.truncate(20);

    let list = ranked
        .into_iter()
        .map(|(key, memory_bytes)| HotKey {
            key,
            // 共享态存储全部为 string 类型键（见函数头适配说明）
            key_type: "string".to_string(),
            memory_bytes,
        })
        .collect();

    Ok(AjaxResult::success(list))
}

/// GET /monitor/cache/prefixStats
/// 获取缓存前缀内存统计（按前缀分组，逐键值字节长度累加——适配说明见 get_hot_keys）
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
    let keys: Vec<String> = state
        .store
        .scan("*", Some(5000))
        .await
        .map_err(map_scan_error)?;
    let stats = collect_value_sizes(&state, &keys).await?;

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
    // 解码只做一次，且由框架做：`Path<String>` 已把 `%3A` 还原成 `:`（与 get_value /
    // clear_cache_name 同一口径）。这里再解一次会让"双重编码的手误"（`%253A`）被洗成
    // 合法前缀 ⇒ 管理员以为在查 `sys_config%3A`，实际清的是 `sys_config:`，静默打偏。
    // 校验缓存前缀白名单
    validate_cache_prefix(&cache_name)?;
    let pattern = format!("{}*", cache_name);

    let keys: Vec<String> = state
        .store
        .scan(&pattern, Some(5000))
        .await
        .map_err(map_scan_error)?;

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

    // 读取缓存值（共享态存储统一为 string KV，原 TYPE 预检分支随之收敛：
    // 键不存在 → 空值，与原 GET nil → unwrap_or_default 等价）
    let raw = state
        .store
        .get(&cache_key)
        .await
        .map_err(|e| {
            tracing::error!("读取缓存值失败: {}", e);
            AppError::internal(&crate::tr!("error.cache.value_query_failed"))
        })?
        .unwrap_or_default();
    // SSO 绑定（username/email/nick_name，v4 F4-1）与在线会话（username/ip，v5-S3）
    // 展示前按前缀选字段集脱敏
    let cache_value = if cache_key.starts_with("sso:") {
        mask_sso_binding_value(&raw, SSO_BINDING_SENSITIVE_FIELDS)
    } else if cache_key.starts_with("online:") {
        mask_sso_binding_value(&raw, ONLINE_SESSION_SENSITIVE_FIELDS)
    } else {
        raw
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
    let pattern = format!("{}*", cache_name);

    // 查询匹配的键
    // 第九批：改用 **不截断** 扫描。本接口语义是"清除**该前缀下全部**缓存"，
    // 原 `scan_keys(.., 5000)` 超限即静默截断 ⇒ 只清了前 5000 个却报"已清除 N 个"，
    // 让运维误判缓存已清空。pattern 来自白名单前缀校验（非裸 `*`），无 OOM 风险。
    let keys: Vec<String> = state
        .store
        .scan(&pattern, None)
        .await
        .map_err(map_scan_error)?;

    if keys.is_empty() {
        return Ok(AjaxResult::success_msg(&crate::tr!("msg.cache.no_match")));
    }

    // 批量删除
    let count = delete_keys(&state, &keys).await?;
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

    let deleted = state
        .store
        .del(std::slice::from_ref(&cache_key))
        .await
        .map_err(|e| {
            tracing::error!("删除缓存键 {} 失败: {}", cache_key, e);
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

// 键扫描统一走 `store.scan(pattern, Some(n))` 截断版 / `store.scan(pattern, None)` 全量版
// （P2：上限保护防 `*` 等 pattern 匹配海量 key 导致 OOM；语义对齐原 utils::redis::scan_keys）。

/// SCAN 类错误统一映射：详情写日志，对外口径与原 utils 层 `error.common.cache_failed` 一致
fn map_scan_error(e: crate::shared_store::StoreError) -> AppError {
    tracing::error!("共享态存储键扫描失败: {}", e);
    AppError::internal(&crate::tr!("error.common.cache_failed"))
}

/// 解析 Redis INFO 输出为键值对 Map
///
/// INFO 输出格式：每行 `key:value`，以 `#` 开头为分组注释，空行跳过；
/// 无 `:` 的行回退按 `key=value` 解析——兼容 local 档 info_summary 计数文本
/// （`mode=local kv_entries=N ...`，非 INFO 格式），调用方无需按档位分叉解析。
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
        } else if line.contains('=') {
            // local 档计数文本（`mode=local kv_entries=N ...`，空格分隔的 key=value
            // 令牌）兼容解析：逐令牌拆分后插入，调用方无需按档位分叉解析
            for token in line.split_whitespace() {
                if let Some((k, v)) = token.split_once('=') {
                    let k = k.trim();
                    if !k.is_empty() {
                        map.insert(k.to_string(), v.trim().to_string());
                    }
                }
            }
        }
    }
    map
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

/// 批量读取各键值字节长度（string KV 的占用提示，适配说明见 get_hot_keys），
/// 键不存在时返回 None。单次 `get_many` 批量读（原 MEMORY USAGE pipeline 语义对齐）。
async fn collect_value_sizes(
    state: &Arc<AppState>,
    keys: &[String],
) -> Result<Vec<(String, Option<i64>)>, AppError> {
    if keys.is_empty() {
        return Ok(Vec::new());
    }
    let vals: Vec<Option<String>> = state.store.get_many(keys).await.map_err(|e| {
        tracing::error!("批量读取缓存值失败: {}", e);
        AppError::internal(&crate::tr!("error.cache.memory_usage_failed"))
    })?;
    Ok(keys
        .iter()
        .cloned()
        .zip(vals)
        .map(|(k, v)| (k, v.map(|s| s.len() as i64)))
        .collect())
}

/// 批量删除键，返回删除数量（分批下发，保持原 DEL_BATCH_SIZE 批次语义）
async fn delete_keys(state: &Arc<AppState>, keys: &[String]) -> Result<i64, AppError> {
    if keys.is_empty() {
        return Ok(0);
    }
    // 第九批：分批下发（`scan(pattern, None)` 不截断 ⇒ 键数无上界；单条超长 DEL 会长时间
    // 占用 Redis 单线程）。语义不变：返回各批实际删除数之和。
    let mut deleted: u64 = 0;
    for chunk in keys.chunks(DEL_BATCH_SIZE) {
        let n = state.store.del(chunk).await.map_err(|e| {
            tracing::error!("批量删除缓存键失败: {}", e);
            AppError::internal(&crate::tr!("error.cache.key_batch_delete_failed"))
        })?;
        deleted += n;
    }
    Ok(deleted as i64)
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
    fn parse_redis_info_parses_local_summary_counts() {
        // local 档 info_summary 计数文本（`key=value` 形态）兼容解析
        let text = "mode=local kv_entries=42 shared_locks=1 revocations=7\n";
        let map = parse_redis_info(text);
        assert_eq!(map.get("mode").map(String::as_str), Some("local"));
        assert_eq!(map.get("kv_entries").map(String::as_str), Some("42"));
        assert_eq!(map.get("revocations").map(String::as_str), Some("7"));
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
    fn get_names_retains_only_whitelisted_prefix_groups() {
        // 模拟 get_names 分组结果：白名单组 + 非白名单组（如 rate_limit:/pwd_ver:）
        let mut groups: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
        for (name, count) in [
            ("dict:", 3),
            ("sys_config:", 2),
            ("rate_limit:", 5),
            ("pwd_ver:", 1),
            ("sso:at:", 4),
        ] {
            groups.insert(name.to_string(), count);
        }
        groups.retain(|name, _| ALLOWED_CACHE_PREFIXES.iter().any(|p| name.starts_with(p)));
        assert!(groups.contains_key("dict:"));
        assert!(groups.contains_key("sys_config:"));
        assert!(groups.contains_key("sso:at:"));
        assert!(!groups.contains_key("rate_limit:"));
        assert!(!groups.contains_key("pwd_ver:"));
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
