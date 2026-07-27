//! 在线用户监控 Handler（Axum 原生实现）
//!
//! 接口路径对齐 ruoyi-vue3-ts 前端：
//! - GET    /monitor/online/list            分页查询在线用户
//! - DELETE /monitor/online/{tokenHash}     强退用户
//!
//! P1-19 方案 B 实现说明：
//! 在线用户列表通过 Redis SCAN `online:*` + MGET 解析 `OnlineSession` JSON 获取，
//! 不再查 sys_logininfor 表（消除 30 分钟硬窗口 Bug）。
//! 登录时 `auth_service::finalize_login` 写入 `online:{token_hash}` → JSON（TTL = JWT 有效期）。
//! 登出时 `auth_service::logout` DEL `online:{token_hash}`（修复登出后仍显示在线的 Bug）。
//! 强退时用 Lua 脚本原子化 SETEX blacklist + DEL online（落实 memory 第 68 行约束）。
//!
//! 降级策略：Redis SCAN/MGET 失败时降级查 sys_logininfor 表（记 warn 日志）。
//! fail-closed：force_logout 的 Redis 操作失败返回 503。

use std::sync::Arc;

use axum::extract::{Path, Query, State};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};

use crate::common::constants::{SECS_PER_HOUR, SUPER_ADMIN_USER_ID};
use crate::common::{AjaxResult, AppError, TableDataInfo};
use crate::handler::monitor_cache_handler::scan_keys;
use crate::state::AppState;
use crate::utils::crypto::OnlineSession;

// ==================== 常量 ====================

/// 强退 Lua 脚本：原子化 SETEX 黑名单 + DEL online（落实 memory 第 68 行约束）
///
/// KEYS[1] = `blacklist:{token_hash}`
/// KEYS[2] = `online:{token_hash}`
/// ARGV[1] = 黑名单 TTL（秒，保守上界 = jwt_config.expire_hours * SECS_PER_HOUR）
///
/// 使用 Lua 保证原子性，避免 SETEX 与 DEL 分离导致：
/// - 强退后 online key 仍存在（用户出现在在线列表）
/// - 黑名单写入失败但 online 已删除（用户无法被再次强退）
const FORCE_LOGOUT_SCRIPT: &str = r#"
redis.call("SETEX", KEYS[1], ARGV[1], "1")
redis.call("DEL", KEYS[2])
return 1
"#;

// ==================== DTO / Vo ====================

/// 在线用户查询参数（对齐前端 OnlineQueryParams）
#[derive(Debug, Clone, Deserialize, IntoParams)]
#[serde(rename_all = "camelCase")]
pub struct OnlineQueryDto {
    /// 登录 IP 地址（模糊查询）
    pub ipaddr: Option<String>,
    /// 用户名称（模糊查询）
    #[serde(alias = "userName")]
    pub user_name: Option<String>,
}

/// 在线用户信息（对齐前端 SysUserOnline）
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct SysUserOnline {
    /// 会话编号（P1-19：使用 token_hash 作为标识，前端字段名不变）
    pub token_id: String,
    /// 部门名称（降级路径无 user_id，保持空字符串）
    pub dept_name: String,
    /// 用户名称
    pub user_name: String,
    /// 登录 IP
    pub ipaddr: String,
    /// 登录地址
    pub login_location: String,
    /// 浏览器类型
    pub browser: String,
    /// 操作系统
    pub os: String,
    /// 登录时间（时间戳，毫秒）
    pub login_time: i64,
}

// ==================== Handler 实现 ====================

/// GET /monitor/online/list
/// 分页查询在线用户
///
/// P1-19 方案 B：通过 Redis SCAN `online:*` + MGET 解析 `OnlineSession` JSON 获取在线列表，
/// 不再查 sys_logininfor 表（消除 30 分钟硬窗口 Bug，列表与 JWT 有效期完全对齐）。
///
/// 降级策略：Redis SCAN/MGET 失败时降级调用 `get_online_users` 查 sys_logininfor 表，记 warn 日志。
///
/// 客户端分页：total 为当前真实在线总数，后端不做服务端切片，返回全部在线用户由前端分页展示。
#[utoipa::path(
    get,
    path = "/monitor/online/list",
    params(OnlineQueryDto),
    responses(
        (status = 200, description = "查询成功", body = TableDataInfo<SysUserOnline>),
        (status = 500, description = "服务器错误"),
    ),
    tag = "monitor-online"
)]
pub async fn list(
    State(state): State<Arc<AppState>>,
    Query(query): Query<OnlineQueryDto>,
) -> Result<TableDataInfo<SysUserOnline>, AppError> {
    let mut redis = state.redis.clone();

    // 1. SCAN online:* 获取所有在线会话 key（复用 monitor_cache_handler::scan_keys）
    let keys = match scan_keys(&mut redis, "online:*").await {
        Ok(k) => k,
        Err(e) => {
            tracing::warn!("Redis SCAN online:* 失败，降级到 sys_logininfor 查询: {}", e);
            return fallback_to_logininfor(&state, &query).await;
        }
    };

    if keys.is_empty() {
        return Ok(TableDataInfo::new(0, Vec::new()));
    }

    // 2. MGET 批量获取所有 online JSON（单次 pipeline，遵循 memory 第 57 行约束）
    let values: Vec<Option<String>> = match redis::cmd("MGET")
        .arg(&keys)
        .query_async(&mut redis)
        .await
    {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!("Redis MGET online 失败，降级到 sys_logininfor 查询: {}", e);
            return fallback_to_logininfor(&state, &query).await;
        }
    };

    // 3. 解析 JSON 为 OnlineSession，构建 SysUserOnline 列表
    let mut online_list: Vec<SysUserOnline> = Vec::new();
    for (key, value) in keys.iter().zip(values.iter()) {
        let Some(json) = value else {
            continue;
        };
        let session: OnlineSession = match serde_json::from_str(json) {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!("解析 online key {} 的 JSON 失败（跳过）: {}", key, e);
                continue;
            }
        };

        // 应用过滤条件（ipaddr / user_name 模糊匹配）
        if let Some(ref ip_filter) = query.ipaddr
            && !session.ip.contains(ip_filter.as_str())
        {
            continue;
        }
        if let Some(ref name_filter) = query.user_name
            && !session.username.contains(name_filter.as_str())
        {
            continue;
        }

        // 从 key 提取 token_hash: "online:{token_hash}" → token_hash
        let token_hash = key.strip_prefix("online:").unwrap_or(key);

        // loginLocation: 复用 ip_locator 查询（mmdb 不存在时返回空字符串）
        let login_location = state.ip_locator.locate(&session.ip);

        // login_time: 解析 "%Y-%m-%d %H:%M:%S"（本地时区） → timestamp_millis
        // 注意：session.login_time 由 chrono::Local::now() 生成（北京时间），
        // 必须用 and_local_timezone(Local) 解析，否则 and_utc() 会让时间戳偏移 +8 小时
        let login_time_millis =
            chrono::NaiveDateTime::parse_from_str(&session.login_time, "%Y-%m-%d %H:%M:%S")
                .map(|dt| {
                    dt.and_local_timezone(chrono::Local)
                        .single()
                        .map(|t| t.timestamp_millis())
                        .unwrap_or_default()
                })
                .unwrap_or_default();

        online_list.push(SysUserOnline {
            token_id: token_hash.to_string(),
            dept_name: session.dept_name,
            user_name: session.username,
            ipaddr: session.ip,
            login_location,
            browser: session.browser,
            os: session.os,
            login_time: login_time_millis,
        });
    }

    // M-4：按 login_time 倒序排序，确保最新登录的用户排在前面（与 ify-admin 前端期望一致）
    online_list.sort_by_key(|item| std::cmp::Reverse(item.login_time));

    // C-03：在线用户为动态数据（非持久化），采用客户端分页模式
    let total = online_list.len() as u64;
    Ok(TableDataInfo::new(total, online_list))
}

/// 降级查询：Redis 故障时查 sys_logininfor 表最近 30 分钟登录记录
///
/// 调用 `get_online_users`（已标记 deprecated），仅作为 Redis 故障的 fallback。
/// 返回的 token_id 为 info_id（降级模式下前端 forceLogout 会因 online key 不存在返回 404，
/// 属于可接受的降级行为）。
#[allow(deprecated)]
async fn fallback_to_logininfor(
    state: &AppState,
    query: &OnlineQueryDto,
) -> Result<TableDataInfo<SysUserOnline>, AppError> {
    let rows = state
        .logininfor_service
        .get_online_users(query.ipaddr.as_deref(), query.user_name.as_deref())
        .await?;

    let online_list: Vec<SysUserOnline> = rows
        .iter()
        .map(|r| SysUserOnline {
            token_id: r.info_id.to_string(),
            dept_name: String::new(),
            user_name: r.user_name.clone().unwrap_or_default(),
            ipaddr: r.ipaddr.clone().unwrap_or_default(),
            login_location: r.login_location.clone().unwrap_or_default(),
            browser: r.browser.clone().unwrap_or_default(),
            os: r.os.clone().unwrap_or_default(),
            login_time: r
                .login_time
                .map(|dt| {
                    // sys_logininfor.login_time 由 chrono::Local::now().naive_local() 写入（北京时间），
                    // 必须用 and_local_timezone(Local) 解析，否则 and_utc() 会让时间戳偏移 +8 小时
                    dt.and_local_timezone(chrono::Local)
                        .single()
                        .map(|t| t.timestamp_millis())
                        .unwrap_or_default()
                })
                .unwrap_or_default(),
        })
        .collect();

    let total = online_list.len() as u64;
    Ok(TableDataInfo::new(total, online_list))
}

/// DELETE /monitor/online/{tokenHash}
/// 强退用户
///
/// P1-19 方案 B：路径参数从 `{tokenId}`（info_id）改为 `{tokenHash}`（token 的 SHA-256 哈希）。
///
/// 流程：
/// 1. GET `online:{token_hash}` → JSON → OnlineSession（确认会话存在 + 获取 user_id 用于超管保护）
/// 2. 超管保护：user_id == SUPER_ADMIN_USER_ID 返回 403
/// 3. Lua 原子化 SETEX `blacklist:{token_hash}` + DEL `online:{token_hash}`
/// 4. fail-closed：Redis 故障返回 503
///
/// Lua 脚本 TTL 说明：
/// ARGV[1] = `jwt_config.expire_hours * SECS_PER_HOUR`（保守上界）。
/// OnlineSession 不存储 JWT exp，故使用 JWT 最大有效期作为黑名单 TTL。
/// 这保证黑名单 TTL ≥ token 实际剩余有效期（token 最多还有 expire_hours 过期），
/// 过度保守的黑名单条目会在 expire_hours 后自动过期，内存开销可接受。
#[utoipa::path(
    delete,
    path = "/monitor/online/{tokenHash}",
    params(
        ("tokenHash" = String, Path, description = "会话编号（token 的 SHA-256 哈希）")
    ),
    responses(
        (status = 200, description = "强退成功", body = AjaxResult<serde_json::Value>),
        (status = 403, description = "不允许强退超级管理员"),
        (status = 404, description = "会话不存在或已过期"),
        (status = 503, description = "认证服务暂时不可用"),
    ),
    tag = "monitor-online"
)]
pub async fn force_logout(
    State(state): State<Arc<AppState>>,
    Path(token_hash): Path<String>,
) -> Result<AjaxResult<()>, AppError> {
    let online_key = format!("online:{}", token_hash);
    let blacklist_key = format!("blacklist:{}", token_hash);
    let mut redis = state.redis.clone();

    // 1. GET online:{token_hash} → JSON → OnlineSession（确认会话存在 + 获取 user_id）
    let session_json: Option<String> = redis::cmd("GET")
        .arg(&online_key)
        .query_async(&mut redis)
        .await
        .map_err(|e| {
            tracing::error!("Redis 查询在线会话失败（fail-closed）: {}", e);
            AppError::new(503, crate::tr!("error.auth.auth_unavailable"))
        })?;

    let session_json = match session_json {
        Some(s) => s,
        None => return Err(AppError::not_found(&crate::tr!("error.monitor.session_not_found"))),
    };

    let session: OnlineSession = serde_json::from_str(&session_json).map_err(|e| {
        tracing::error!("解析 OnlineSession JSON 失败: {}", e);
        AppError::internal(&crate::tr!("error.monitor.session_invalid"))
    })?;

    // 2. 超管保护（P0-R81-006）：禁止强退超级管理员
    if session.user_id == SUPER_ADMIN_USER_ID {
        return Err(AppError::new(403, crate::tr!("error.monitor.admin_force_logout_forbidden")));
    }

    // 3. Lua 原子化 SETEX blacklist + DEL online（落实 memory 第 68 行约束）
    //    KEYS[1] = blacklist:{token_hash}, KEYS[2] = online:{token_hash}
    //    ARGV[1] = jwt_config.expire_hours * SECS_PER_HOUR（保守上界，黑名单 TTL ≥ token 剩余有效期）
    //    TODO(H-2): 精确 TTL 需 OnlineSession 存储 exp 字段（记录 token 实际过期时间），
    //    当前用 JWT 最大有效期作为保守上界，黑名单条目会在 expire_hours 后自动过期。
    //    精确化改动需同步修改 OnlineSession 结构、登录中间件写入逻辑与 force_logout 读取逻辑，
    //    改动较大，暂保留现状。
    let blacklist_ttl = state
        .config
        .jwt
        .expire_hours
        .saturating_mul(SECS_PER_HOUR)
        .max(1);
    let _: i64 = redis::Script::new(FORCE_LOGOUT_SCRIPT)
        .key(&blacklist_key)
        .key(&online_key)
        .arg(blacklist_ttl)
        .invoke_async(&mut redis)
        .await
        .map_err(|e| {
            tracing::error!("Lua 强退脚本执行失败（fail-closed）: {}", e);
            AppError::new(503, crate::tr!("error.auth.auth_unavailable"))
        })?;

    // 广播 forceLogout 事件，通知被强退用户的客户端跳转登录页
    // 失败不阻断主流程（强退已成功，仅 WS 推送失败）
    crate::handler::ws_handler::broadcast(
        &state,
        "forceLogout",
        serde_json::json!({
            "tokenHash": token_hash,
            "userId": session.user_id,
            "userName": session.username
        }),
    );

    Ok(AjaxResult::success_msg(&crate::tr!("msg.success.force_logout")))
}
