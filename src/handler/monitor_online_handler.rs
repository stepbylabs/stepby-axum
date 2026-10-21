//! 在线用户监控 Handler（Axum 原生实现）
//!
//! 接口路径对齐前端调用规范：
//! - GET    /monitor/online/list            分页查询在线用户
//! - DELETE /monitor/online/{tokenHash}     强退用户
//! - POST   /monitor/online/batchLogout     批量强退（复用单个强退吊销逻辑，有界并发）
//!
//! P1-19 方案 B 实现说明：
//! 在线用户列表通过共享态存储 SCAN `online:*` + 批量读解析 `OnlineSession` JSON 获取，
//! 不再查 sys_logininfor 表（消除 30 分钟硬窗口 Bug）。
//! 登录时 `auth_service::finalize_login` 写入 `online:{token_hash}` → JSON（TTL = JWT 有效期）。
//! 登出时 `auth_service::logout` 删除 `online:{token_hash}`（修复登出后仍显示在线的 Bug）。
//! 强退时经 `store.revoke_session` 原子化 blacklist 登记 + online / sso:at 删除
//! （redis 档 = 原三键 Lua，已封入 shared_store::RedisStore；local 档 = 单事务）。
//!
//! 降级策略：SCAN/批量读失败时降级查 sys_logininfor 表（记 warn 日志）。
//! fail-closed：force_logout 的共享态存储操作失败返回 503。

use std::sync::Arc;

use axum::Json;
use axum::extract::{Path, Query, State};
use futures::StreamExt;
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};

use crate::common::constants::{MAX_BATCH_DELETE_SIZE, SECS_PER_HOUR, SUPER_ADMIN_USER_ID};
use crate::common::{AjaxResult, AppError, TableDataInfo};
use crate::middleware::auth::Operator;
use crate::state::AppState;
use crate::utils::crypto::OnlineSession;

// ==================== 常量 ====================

// 强退三键原子操作（原 FORCE_LOGOUT_SCRIPT：SETEX blacklist + DEL online + DEL sso:at）
// 已收敛为 `SharedStore::revoke_session(token_hash, ttl)`，实现封入 shared_store 双档
// （redis 档 Lua 原样保留于 RedisStore；local 档为单事务）。本 handler 不再感知实现细节。

/// 批量强退的并发上限（单次请求内并行吊销的 token 数）
const BATCH_LOGOUT_CONCURRENCY: usize = 8;

// ==================== DTO / Vo ====================

/// 在线用户查询参数（对齐前端 OnlineQueParams）
#[derive(Debug, Clone, Deserialize, IntoParams)]
#[serde(rename_all = "camelCase")]
pub struct OnlineQueryDto {
    /// 登录 IP 地址（模糊查询）
    pub ipaddr: Option<String>,
    /// 用户名称（模糊查询）
    #[serde(alias = "userName")]
    pub user_name: Option<String>,
    /// 租户筛选（仅平台操作者有效；租户操作者恒为本租户，见 §27.13.2 分层视图）
    #[serde(alias = "tenantId")]
    pub tenant_id: Option<i64>,
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
    /// 所属租户 ID（0 = 平台租户；§27.13.2 分层视图：平台分组/筛选依据）
    pub tenant_id: i64,
    /// 所属租户名称（平台租户为 "平台"；租户行缺失时为空串，前端按 tenantId 展示）
    pub tenant_name: String,
}

// ==================== Handler 实现 ====================

/// GET /monitor/online/list
/// 分页查询在线用户
///
/// P1-19 方案 B：通过共享态存储 SCAN `online:*` + 批量读解析 `OnlineSession` JSON 获取在线列表，
/// 不再查 sys_logininfor 表（消除 30 分钟硬窗口 Bug，列表与 JWT 有效期完全对齐）。
///
/// 降级策略：SCAN/批量读失败时降级调用 `get_online_users` 查 sys_logininfor 表，记 warn 日志。
///
/// 客户端分页：total 为当前真实在线总数，后端不做服务端切片，返回全部在线用户由前端分页展示。
///
/// §27.13.2 分层视图（Phase 3）：
/// - 平台操作者（tid=0）：全量在线会话，可按 `tenantId` 筛选分组；
/// - 租户操作者（tid≠0）：**仅本租户**会话（含旧 JSON 会话按 user_id 回查兜底归属）。
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
    operator: Operator,
    Query(query): Query<OnlineQueryDto>,
) -> Result<TableDataInfo<SysUserOnline>, AppError> {
    list_sessions(&state, operator.tenant_id(), &query, None).await
}

/// 自助入口（`/monitor/my-session/*`）的**属主约束**。
///
/// 旧实现把 `query.user_name` 改写成操作人用户名后复用管理员列表的 `contains` 模糊匹配，
/// 于是"用户名是他人前缀"的账号在「我的登录设备」里能看到**他人**会话（含实时 tokenId、
/// 内网 IP、浏览器、登录时刻）——tokenId 虽不足以冒用，但把别人的活跃会话暴露给同租户
/// 乃至平台外的低权账号，属归属判定散落的必然漂移。
///
/// 判据按 `user_id` 精确匹配；降级路径（sys_logininfor 不带 user_id 列）按用户名**精确**
/// 匹配。**两条路径必须共用本约束**——只修主路径等于给降级分支留了同一个洞（同 AGENTS
/// 铁律 1"读侧与写侧共用同一谓词"）。
#[derive(Debug, Clone)]
struct SessionOwner {
    user_id: i64,
    user_name: String,
}

/// 会话列表实现体（`/monitor/online/list` 与 `/monitor/my-session/list` 共用）。
///
/// `owner = Some(_)` 时只保留本人会话；`None` 时为管理员视图（可按 userName 模糊搜索）。
async fn list_sessions(
    state: &Arc<AppState>,
    operator_tid: i64,
    query: &OnlineQueryDto,
    owner: Option<SessionOwner>,
) -> Result<TableDataInfo<SysUserOnline>, AppError> {
    // 1. SCAN online:* 获取所有在线会话 key（截断版，上限保持 5000）
    let keys = match state.store.scan("online:*", Some(5000)).await {
        Ok(k) => k,
        Err(e) => {
            tracing::warn!(
                "共享态存储 SCAN online:* 失败，降级到 sys_logininfor 查询: {}",
                e
            );
            return fallback_to_logininfor(state, query, operator_tid, owner.as_ref()).await;
        }
    };

    if keys.is_empty() {
        return Ok(TableDataInfo::new(0, Vec::new()));
    }

    // 2. 批量读取所有 online JSON（原 MGET 单次往返语义 → store.get_many）
    let values: Vec<Option<String>> = match state.store.get_many(&keys).await {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!(
                "共享态存储批量读取 online 失败，降级到 sys_logininfor 查询: {}",
                e
            );
            return fallback_to_logininfor(state, query, operator_tid, owner.as_ref()).await;
        }
    };

    // 3. 解析 JSON 为 OnlineSession（先全量收集，便于批量兜底回填租户归属）
    let mut sessions: Vec<(String, OnlineSession)> = Vec::new();
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
        // 从 key 提取 token_hash: "online:{token_hash}" → token_hash
        let token_hash = key.strip_prefix("online:").unwrap_or(key).to_string();
        sessions.push((token_hash, session));
    }

    // 3.1 旧会话兜底：v2.13 前的 online JSON 无 tenant_id（serde default=0），
    //     按 user_id 回查 sys_user.tenant_id——否则租户管理员既看不到也踢不掉本租户旧会话
    let legacy_user_ids: Vec<i64> = sessions
        .iter()
        .filter(|(_, s)| s.tenant_id == 0 && s.user_id > 0)
        .map(|(_, s)| s.user_id)
        .collect();
    let legacy_tenant_map = if legacy_user_ids.is_empty() {
        std::collections::HashMap::new()
    } else {
        state
            .user_service
            .tenant_ids_by_user_ids(&legacy_user_ids)
            .await
            .unwrap_or_else(|e| {
                tracing::warn!("在线会话租户兜底回填失败（按平台会话处理）: {}", e);
                std::collections::HashMap::new()
            })
    };

    // 3.2 租户过滤 + 构建列表
    let mut online_list: Vec<SysUserOnline> = Vec::new();
    for (token_hash, session) in sessions {
        // 自助入口：先按属主收敛（user_id 相等；解析不出 user_id 的令牌一律不放行，
        // fail-closed——宁可让自己看不到自己，也不能让前缀同名互相可见）
        if let Some(o) = owner.as_ref()
            && (o.user_id <= 0 || session.user_id != o.user_id)
        {
            continue;
        }
        // 会话租户归属：新会话取 JSON 字段；旧会话按 user_id 兜底
        let session_tid = if session.tenant_id != 0 {
            session.tenant_id
        } else {
            legacy_tenant_map
                .get(&session.user_id)
                .copied()
                .unwrap_or(0)
        };
        // 租户操作者：仅本租户（无法定位租户的旧会话视为平台会话，不展示）
        if operator_tid != 0 && session_tid != operator_tid {
            continue;
        }
        // 平台操作者：可按租户筛选
        if let Some(filter_tid) = query.tenant_id
            && session_tid != filter_tid
        {
            continue;
        }
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

        // loginLocation: 复用 ip_locator 查询（mmdb 不存在时返回空字符串）
        let login_location = state.ip_locator.locate(&session.ip);

        online_list.push(SysUserOnline {
            token_id: token_hash,
            dept_name: session.dept_name,
            user_name: session.username,
            ipaddr: session.ip,
            login_location,
            browser: session.browser,
            os: session.os,
            login_time: login_time_millis,
            tenant_id: session_tid,
            tenant_name: if session_tid == 0 {
                crate::tr!("common.platform_tenant")
            } else {
                String::new()
            },
        });
    }

    // 3.3 租户名填充（缺失租户行留空，前端按 tenantId 展示）
    fill_tenant_names(state, &mut online_list).await;

    // M-4：按 login_time 倒序排序，确保最新登录的用户排在前面（与 ify-admin 前端期望一致）
    online_list.sort_by_key(|item| std::cmp::Reverse(item.login_time));

    // C-03：在线用户为动态数据（非持久化），采用客户端分页模式
    let total = online_list.len() as u64;
    Ok(TableDataInfo::new(total, online_list))
}

/// 填充在线用户的 `tenantName`（平台租户由调用方置为 "平台"，此处只处理 tid≠0）
async fn fill_tenant_names(state: &AppState, list: &mut [SysUserOnline]) {
    let mut ids: Vec<i64> = Vec::new();
    for item in list.iter() {
        if item.tenant_id != 0 && !ids.contains(&item.tenant_id) {
            ids.push(item.tenant_id);
        }
    }
    if ids.is_empty() {
        return;
    }
    match state.tenant_service.tenant_name_map(&ids).await {
        Ok(map) => {
            for item in list.iter_mut() {
                if item.tenant_id != 0 {
                    item.tenant_name = map.get(&item.tenant_id).cloned().unwrap_or_default();
                }
            }
        }
        Err(e) => tracing::warn!("在线用户租户名查询失败（tenantName 留空）: {}", e),
    }
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
    operator_tid: i64,
    owner: Option<&SessionOwner>,
) -> Result<TableDataInfo<SysUserOnline>, AppError> {
    let rows = state
        .logininfor_service
        .get_online_users(
            query.ipaddr.as_deref(),
            query.user_name.as_deref(),
            crate::common::tenant::tenant_scope(operator_tid),
        )
        .await?;

    // 租户归属：登录记录已带 tenant_id；此处按用户名回查 sys_user 以统一口径（与主路径一致的展示用分组）
    let names: Vec<String> = rows.iter().filter_map(|r| r.user_name.clone()).collect();
    let tenant_of_name = state
        .user_service
        .tenant_ids_by_user_names(&names)
        .await
        .unwrap_or_else(|e| {
            tracing::warn!("降级路径租户归属回查失败（按平台会话处理）: {}", e);
            std::collections::HashMap::new()
        });

    let mut online_list: Vec<SysUserOnline> = Vec::new();
    for r in rows.iter() {
        // 降级路径无 user_id 列，用**精确**用户名等值（登录记录已按 operator 租户范围取），
        // 与主路径的 user_id 判定同语义：不得退回 `contains`，否则属主约束在这条分支失效
        if let Some(o) = owner
            && r.user_name.as_deref() != Some(o.user_name.as_str())
        {
            continue;
        }
        let tid = r
            .user_name
            .as_ref()
            .and_then(|n| tenant_of_name.get(n))
            .copied()
            .unwrap_or(0);
        // 分层视图：租户操作者仅本租户；平台操作者可按 tenantId 筛选
        if operator_tid != 0 && tid != operator_tid {
            continue;
        }
        if let Some(filter_tid) = query.tenant_id
            && tid != filter_tid
        {
            continue;
        }
        online_list.push(SysUserOnline {
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
                    // sys_logininfor.login_time 由 crate::common::datetime::now_naive() 写入（北京时间），
                    // 必须用 and_local_timezone(Local) 解析，否则 and_utc() 会让时间戳偏移 +8 小时
                    dt.and_local_timezone(chrono::Local)
                        .single()
                        .map(|t| t.timestamp_millis())
                        .unwrap_or_default()
                })
                .unwrap_or_default(),
            tenant_id: tid,
            tenant_name: if tid == 0 {
                crate::tr!("common.platform_tenant")
            } else {
                String::new()
            },
        });
    }
    fill_tenant_names(state, &mut online_list).await;

    let total = online_list.len() as u64;
    Ok(TableDataInfo::new(total, online_list))
}

/// DELETE /monitor/online/{tokenHash}
/// 强退用户
///
/// P1-19 方案 B：路径参数从 `{tokenId}`（info_id）改为 `{tokenHash}`（token 的 SHA-256 哈希）。
///
/// 流程：
/// 1. 读 `online:{token_hash}` → JSON → OnlineSession（确认会话存在 + 获取 user_id 用于超管保护）
/// 2. 租户越权防护（§27.13.2 分层视图）：租户操作者只能强退本租户会话，跨租户返回 403
/// 3. 超管保护：user_id == SUPER_ADMIN_USER_ID 返回 403
/// 4. `store.revoke_session` 原子化 blacklist 登记 + 删除 online / sso:at（原三键 Lua 语义）
/// 5. fail-closed：共享态存储故障返回 503
///
/// blacklist TTL 说明（M-3 精确化）：
/// TTL = `max(session.exp - now, 1)`（精确剩余有效期，秒）。
/// OnlineSession.exp 由登录流程从 JWT claims.exp 写入（UTC 秒）。
/// 旧 JSON（v2.13 前，exp 默认 0）回退到 `jwt_config.expire_hours * SECS_PER_HOUR` 保守上界。
/// 黑名单条目与 token 同时过期，避免旧方案中"登录 1 小时被强退 → 黑名单仍留 24 小时"的内存浪费。
#[utoipa::path(
    delete,
    path = "/monitor/online/{tokenHash}",
    params(
        ("tokenHash" = String, Path, description = "会话编号（token 的 SHA-256 哈希）")
    ),
    responses(
        (status = 200, description = "强退成功", body = AjaxResult<serde_json::Value>),
        (status = 403, description = "不允许强退超级管理员 / 跨租户越权"),
        (status = 404, description = "会话不存在或已过期"),
        (status = 503, description = "认证服务暂时不可用"),
    ),
    tag = "monitor-online"
)]
pub async fn force_logout(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    Path(token_hash): Path<String>,
) -> Result<AjaxResult<()>, AppError> {
    let (user_id, username) = revoke_one_session(state.as_ref(), &operator, &token_hash).await?;

    // 定向推送 forceLogout 事件，仅通知被强退用户的客户端跳转登录页
    // P0-2 越权广播修复：原实现走全局广播，所有在线客户端（含无权限用户）都会收到
    // 他人被强退及其 tokenHash/userId/userName，造成跨用户会话/身份信息泄漏。
    // 现改为按用户定向投递，仅目标用户的连接收到；失败不阻断主流程（强退已成功，仅 WS 推送失败）。
    state.broadcast_to_user(
        user_id,
        "forceLogout",
        serde_json::json!({
            "tokenHash": token_hash,
            "userId": user_id,
            "userName": username
        }),
    );

    Ok(AjaxResult::success_msg(&crate::tr!(
        "msg.success.force_logout"
    )))
}

/// 单个会话强退核心流程（force_logout / batch_logout 共用）
///
/// 流程（与原 force_logout 一致）：
/// 1. 读 `online:{token_hash}` → JSON → OnlineSession（确认会话存在 + 获取 user_id 用于超管保护）
/// 2. 租户越权防护（§27.13.2）：租户操作者只能强退本租户会话，跨租户返回 403
/// 3. 超管保护：user_id == SUPER_ADMIN_USER_ID 返回 403
/// 4. `store.revoke_session` 原子化 blacklist 登记 + 删除 online / sso:at
/// 5. fail-closed：共享态存储故障返回 503
///
/// blacklist TTL 说明（M-3 精确化）：TTL = `max(session.exp - now, 1)`（精确剩余有效期，秒）；
/// 旧 JSON（v2.13 前，exp 默认 0）回退到 `jwt_config.expire_hours * SECS_PER_HOUR` 保守上界。
async fn revoke_one_session(
    state: &AppState,
    operator: &Operator,
    token_hash: &str,
) -> Result<(i64, String), AppError> {
    let online_key = format!("online:{}", token_hash);

    // 1. 读 online:{token_hash} → JSON → OnlineSession（确认会话存在 + 获取 user_id）
    let session_json = state.store.get(&online_key).await.map_err(|e| {
        tracing::error!("共享态存储查询在线会话失败（fail-closed）: {}", e);
        AppError::new(503, crate::tr!("error.auth.auth_unavailable"))
    })?;

    let session_json = match session_json {
        Some(s) => s,
        None => {
            return Err(AppError::not_found(&crate::tr!(
                "error.monitor.session_not_found"
            )));
        }
    };

    let session: OnlineSession = serde_json::from_str(&session_json).map_err(|e| {
        tracing::error!("解析 OnlineSession JSON 失败: {}", e);
        AppError::internal(&crate::tr!("error.monitor.session_invalid"))
    })?;

    // 2. 租户越权防护（§27.13.2 分层视图）：租户操作者只能强退本租户会话。
    //    旧 JSON（v2.13 前无 tenant_id，默认 0）按 user_id 回查 sys_user.tenant_id 兜底；
    //    回查失败/用户已删除时按平台会话处理（0）→ 与 tenants 隔离口径一致地拒绝。
    let operator_tid = operator.tenant_id();
    if operator_tid != 0 {
        let session_tid = if session.tenant_id != 0 {
            session.tenant_id
        } else {
            state
                .user_service
                .tenant_ids_by_user_ids(&[session.user_id])
                .await
                .ok()
                .and_then(|m| m.get(&session.user_id).copied())
                .unwrap_or(0)
        };
        if session_tid != operator_tid {
            tracing::warn!(
                "跨租户强退拦截：operator_tid={} session_tid={} user_id={}",
                operator_tid,
                session_tid,
                session.user_id
            );
            return Err(AppError::new(403, crate::tr!("error.common.forbidden")));
        }
    }

    // 3. 超管保护（P0-R81-006）：禁止强退超级管理员
    if session.user_id == SUPER_ADMIN_USER_ID {
        return Err(AppError::new(
            403,
            crate::tr!("error.monitor.admin_force_logout_forbidden"),
        ));
    }

    // 4. 原子强退：blacklist 登记 + DEL online + DEL sso:at（v4-F2 联动 → store.revoke_session）
    //    M-3：精确 TTL 计算（使用 OnlineSession.exp 实际剩余有效期）
    let now_secs = chrono::Utc::now().timestamp();
    let precise_ttl = session.exp.checked_sub(now_secs).unwrap_or(0).max(0);
    let fallback_ttl = state
        .config
        .jwt
        .expire_hours
        .saturating_mul(SECS_PER_HOUR)
        .max(1);
    // exp == 0 表示旧 JSON（无 exp 字段），用 fallback；否则用精确值（至少 1 秒保证写入）
    let blacklist_ttl = if session.exp > 0 {
        precise_ttl.max(1)
    } else {
        fallback_ttl
    };
    state
        .store
        .revoke_session(token_hash, blacklist_ttl as u64)
        .await
        .map_err(|e| {
            tracing::error!("revoke_session 强退执行失败（fail-closed）: {}", e);
            AppError::new(503, crate::tr!("error.auth.auth_unavailable"))
        })?;

    Ok((session.user_id, session.username))
}

/// POST /monitor/online/batchLogout
/// 批量强退（前端多选批量操作入口）
///
/// 复用单个强退的吊销逻辑（`revoke_one_session`），以有界并发（BATCH_LOGOUT_CONCURRENCY）
/// 循环执行；每个 token 的成功/失败独立记录，部分失败不阻断其余目标。
/// 入参上限与批量删除惯例一致（MAX_BATCH_DELETE_SIZE）。
#[utoipa::path(
    post,
    path = "/monitor/online/batchLogout",
    request_body = BatchLogoutDto,
    responses(
        (status = 200, description = "批量强退完成（含逐项结果）", body = AjaxResult<serde_json::Value>),
        (status = 400, description = "token 列表为空或超出批量上限"),
    ),
    tag = "monitor-online"
)]
pub async fn batch_logout(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    Json(dto): Json<BatchLogoutDto>,
) -> Result<AjaxResult<serde_json::Value>, AppError> {
    // 去空 + 去重，保留首次出现顺序
    let mut seen = std::collections::HashSet::new();
    let hashes: Vec<String> = dto
        .token_hashes
        .into_iter()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty() && seen.insert(s.clone()))
        .collect();

    if hashes.is_empty() {
        return Err(AppError::bad_request(&crate::tr!(
            "error.monitor.batch_logout_empty"
        )));
    }
    if hashes.len() > MAX_BATCH_DELETE_SIZE {
        return Err(AppError::bad_request(&crate::tr!(
            "error.common.batch_size_exceeded",
            max = MAX_BATCH_DELETE_SIZE
        )));
    }

    // 有界并发吊销：单项失败（404/403/503）记录为逐项结果，不中断整体
    let results: Vec<BatchLogoutItem> = futures::stream::iter(hashes)
        .map(|hash| {
            let state = state.clone();
            let operator = operator.clone();
            async move {
                match revoke_one_session(state.as_ref(), &operator, &hash).await {
                    Ok((user_id, username)) => {
                        // 与单个强退一致：定向推送 forceLogout 事件（失败不阻断主流程）
                        state.broadcast_to_user(
                            user_id,
                            "forceLogout",
                            serde_json::json!({
                                "tokenHash": hash,
                                "userId": user_id,
                                "userName": username
                            }),
                        );
                        BatchLogoutItem {
                            token_hash: hash,
                            code: 200,
                            msg: crate::tr!("msg.success.force_logout"),
                        }
                    }
                    Err(e) => BatchLogoutItem {
                        token_hash: hash,
                        code: e.code,
                        msg: e.message,
                    },
                }
            }
        })
        .buffer_unordered(BATCH_LOGOUT_CONCURRENCY)
        .collect::<Vec<_>>()
        .await;

    let success_count = results.iter().filter(|r| r.code == 200).count();
    let failed: Vec<&BatchLogoutItem> = results.iter().filter(|r| r.code != 200).collect();

    Ok(AjaxResult::success(serde_json::json!({
        "successCount": success_count,
        "failed": failed,
    })))
}

/// POST /monitor/online/batchLogout 入参
#[derive(Debug, Clone, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct BatchLogoutDto {
    /// 会话编号（token 的 SHA-256 哈希）列表
    pub token_hashes: Vec<String>,
}

/// 批量强退逐项结果
#[derive(Debug, Clone, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct BatchLogoutItem {
    /// 会话编号（token 的 SHA-256 哈希）
    pub token_hash: String,
    /// 单项结果码（200 = 成功，其余与单个强退错误码一致）
    pub code: i32,
    /// 单项结果消息
    pub msg: String,
}

/// GET /monitor/my-session/list（v5-N5：普通用户自助「会话管理」）
///
/// 背景：前端 MySessionPanel（菜单 126）此前复用管理员接口 `GET /monitor/online/list`，
/// 该接口要求 `monitor:online:list` 权限，普通用户必 403（功能不可用）；而菜单
/// `monitor:session:list` 在后端权限映射中不存在。
///
/// 本端点：仅登录（is_login_only_path），**强制**只返回本人会话，
/// 前端传入的 userName 一律忽略——判定见 `SessionOwner`（按 user_id 精确，非模糊同名）。
#[utoipa::path(
    get,
    path = "/monitor/my-session/list",
    params(OnlineQueryDto),
    responses(
        (status = 200, description = "查询成功", body = TableDataInfo<SysUserOnline>),
        (status = 500, description = "服务器错误"),
    ),
    tag = "monitor-online"
)]
pub async fn my_session_list(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    Query(mut query): Query<OnlineQueryDto>,
) -> Result<TableDataInfo<SysUserOnline>, AppError> {
    // 入参 userName 不参与筛选：属主约束由 SessionOwner 给出（旧写法把它塞进 contains
    // 模糊匹配，前缀同名账号互相可见）
    // 入参 userName 不参与筛选：属主约束由 SessionOwner 给出（旧写法把它塞进 contains
    // 模糊匹配，前缀同名账号互相可见——b82 变异证伪实测：还原旧写法后 `it_adm` 的自助列表
    // 里出现 `["it_admx"]`，新用例当场红在 leaked 断言）
    query.user_name = None;
    let owner = SessionOwner {
        user_id: operator.user_id().parse::<i64>().unwrap_or(0),
        user_name: operator.username().to_string(),
    };
    list_sessions(&state, operator.tenant_id(), &query, Some(owner)).await
}

/// DELETE /monitor/my-session/{tokenHash}（v5-N5：自助注销本人会话）
///
/// 与管理员 force_logout 的区别：**属主校验**——目标会话的 user_id 必须等于当前
/// 登录用户，否则 403（防止借自助入口踢他人会话的横向越权）。注销自身当前会话
/// 允许（前端 isCurrentSession 已排除；后端不做二次限制，自助语义下踢自己可接受）。
#[utoipa::path(
    delete,
    path = "/monitor/my-session/{tokenHash}",
    params(
        ("tokenHash" = String, Path, description = "会话编号（token 的 SHA-256 哈希）")
    ),
    responses(
        (status = 200, description = "注销成功", body = AjaxResult<serde_json::Value>),
        (status = 403, description = "只能注销本人的会话"),
        (status = 404, description = "会话不存在或已过期"),
        (status = 503, description = "认证服务暂时不可用"),
    ),
    tag = "monitor-online"
)]
pub async fn my_session_logout(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    Path(token_hash): Path<String>,
) -> Result<AjaxResult<()>, AppError> {
    let user_id: i64 = operator
        .user_id()
        .parse()
        .map_err(|_| AppError::internal(&crate::tr!("error.user.operator_id_parse_failed")))?;
    let online_key = format!("online:{}", token_hash);

    // 1. 读会话 → 确认存在 + 属主校验（v5-N5：横向越权防线）
    let session_json = state.store.get(&online_key).await.map_err(|e| {
        tracing::error!("共享态存储查询在线会话失败（fail-closed）: {}", e);
        AppError::new(503, crate::tr!("error.auth.auth_unavailable"))
    })?;
    let session: OnlineSession = match session_json {
        Some(s) => serde_json::from_str(&s).map_err(|e| {
            tracing::error!("解析 OnlineSession JSON 失败: {}", e);
            AppError::internal(&crate::tr!("error.monitor.session_invalid"))
        })?,
        None => {
            return Err(AppError::not_found(&crate::tr!(
                "error.monitor.session_not_found"
            )));
        }
    };
    if session.user_id != user_id {
        return Err(AppError::new(
            403,
            crate::tr!("error.monitor.session_not_owned"),
        ));
    }

    // 2. 与 force_logout 同款原子吊销（blacklist + online + sso:at，经 store.revoke_session）
    let now_secs = chrono::Utc::now().timestamp();
    let precise_ttl = session.exp.saturating_sub(now_secs).max(0);
    let fallback_ttl = state
        .config
        .jwt
        .expire_hours
        .saturating_mul(SECS_PER_HOUR)
        .max(1);
    let blacklist_ttl = if session.exp > 0 {
        precise_ttl.max(1)
    } else {
        fallback_ttl
    };
    state
        .store
        .revoke_session(&token_hash, blacklist_ttl as u64)
        .await
        .map_err(|e| {
            tracing::error!("revoke_session 自助注销执行失败（fail-closed）: {}", e);
            AppError::new(503, crate::tr!("error.auth.auth_unavailable"))
        })?;

    // 3. 定向推送（本人其它端跳登录页）
    state.broadcast_to_user(
        user_id,
        "forceLogout",
        serde_json::json!({
            "tokenHash": token_hash,
            "userId": user_id,
            "userName": session.username
        }),
    );

    Ok(AjaxResult::success_msg(&crate::tr!(
        "msg.success.force_logout"
    )))
}
