//! 工作台/仪表盘聚合统计服务（B-2：handler 层 ORM 下沉）
//!
//! 原 `common_handler.rs::dashboard_stats` / `user_stats` 直接在 handler 内写
//! sea-orm 查询（`sys_user::Entity::find()...`），违反分层（handler 只做参数解析
//! 与响应封装，数据访问归 service/repository）。此处把聚合逻辑下沉为服务，
//! handler 仅负责把服务结果包成 `AjaxResult`。
//!
//! 口径严格保持与原实现一致（并发 join!、租户过滤、软删语义、趋势聚合窗口），
//! 仅搬迁代码位置，不改变行为。

use std::sync::Arc;

use sea_orm::{ColumnTrait, EntityTrait, PaginatorTrait, QueryFilter, QueryOrder, QuerySelect};
use serde::Serialize;
use utoipa::ToSchema;

use crate::entity::{sys_oper_log, sys_role, sys_user};
use crate::state::AppState;

/// 工作台统计响应
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct DashboardStatsVo {
    /// 今日异常登录 IP 数
    pub today_anomaly_ips: i64,
    /// 用户总数
    pub total_users: i64,
    /// 角色总数
    pub total_roles: i64,
    /// 启用角色数
    pub active_roles: i64,
    /// 今日登录次数
    pub today_logins: i64,
    /// 今日登录失败次数
    pub login_fail: i64,
    /// 在线用户数
    pub online_count: i64,
    /// 最近操作日志
    pub recent_oper_logs: Vec<RecentOperLog>,
}

/// 最近操作日志项
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct RecentOperLog {
    /// 操作模块标题
    pub title: String,
    /// 操作人
    pub oper_name: String,
    /// 状态（0 成功 / 1 失败）
    pub status: String,
    /// 耗时（毫秒）
    pub cost_time: i64,
}

/// 用户统计响应
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct UserStatsVo {
    /// 用户总数
    pub total_users: i64,
    /// 最近 7 天新增用户数
    pub new_users_this_week: i64,
    /// 启用状态（status='0'）的用户数
    pub active_users: i64,
    /// 停用状态（status='1'）的用户数
    pub disabled_users: i64,
    /// 最近 30 天按天聚合的新增用户数
    pub create_trend: Vec<UserCreateTrendItem>,
}

/// 用户创建趋势单项
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct UserCreateTrendItem {
    /// 日期（YYYY-MM-DD）
    pub date: String,
    /// 当天新增用户数
    pub count: i64,
}

/// 工作台聚合统计服务（无状态，直接借 AppState 取 db / 子服务）
pub struct DashboardService;

impl DashboardService {
    /// 工作台统计：用户/角色/登录/操作日志并发聚合
    ///
    /// `tenant_scope`：None = 平台操作者（不过滤），Some(tid) = 仅本租户。
    pub async fn dashboard_stats(
        state: &Arc<AppState>,
        tenant_scope: Option<i64>,
    ) -> DashboardStatsVo {
        use sys_oper_log::Column as OperCol;
        use sys_role::Column as RoleCol;
        use sys_user::Column as UserCol;

        let db = &state.db;

        // 并发聚合查询：用户/角色/登录日志/操作日志（各查询互不依赖，用 tokio::join! 并发执行）
        let (total_users, total_roles, active_roles, today_login, recent_logs, today_anomaly_ips) = tokio::join!(
            // 用户总数（del_flag != '2'，即未被逻辑删除）
            async {
                let mut query = sys_user::Entity::find().filter(UserCol::DelFlag.ne("2"));
                if let Some(tid) = tenant_scope {
                    query = query.filter(UserCol::TenantId.eq(tid));
                }
                query
                    .count(db)
                    .await
                    .map(|c| i64::try_from(c).unwrap_or(i64::MAX))
                    .unwrap_or(0)
            },
            // 角色总数（del_flag != '2'）
            async {
                let mut query = sys_role::Entity::find().filter(RoleCol::DelFlag.ne("2"));
                if let Some(tid) = tenant_scope {
                    query = query.filter(RoleCol::TenantId.eq(tid));
                }
                query
                    .count(db)
                    .await
                    .map(|c| i64::try_from(c).unwrap_or(i64::MAX))
                    .unwrap_or(0)
            },
            // 启用角色数（status='0' 且 del_flag != '2'）
            async {
                let mut query = sys_role::Entity::find()
                    .filter(RoleCol::Status.eq("0"))
                    .filter(RoleCol::DelFlag.ne("2"));
                if let Some(tid) = tenant_scope {
                    query = query.filter(RoleCol::TenantId.eq(tid));
                }
                query
                    .count(db)
                    .await
                    .map(|c| i64::try_from(c).unwrap_or(i64::MAX))
                    .unwrap_or(0)
            },
            // 今日登录统计：复用 logininfor_service.daily_stats(1)
            async {
                state
                    .logininfor_service
                    .daily_stats(1, tenant_scope)
                    .await
                    .ok()
                    .and_then(|v| v.into_iter().next())
                    .map(|s| (s.success, s.fail))
                    .unwrap_or((0, 0))
            },
            // 最近 5 条操作日志（按 oper_time 降序）
            async {
                let mut query = sys_oper_log::Entity::find();
                if let Some(tid) = tenant_scope {
                    query = query.filter(OperCol::TenantId.eq(tid));
                }
                query
                    .order_by_desc(OperCol::OperTime)
                    .limit(5)
                    .all(db)
                    .await
                    .unwrap_or_default()
            },
            // 今日异常登录 IP 数（已有方法）
            async {
                state
                    .logininfor_service
                    .count_today_failed_ips(tenant_scope)
                    .await
                    .unwrap_or(0)
            }
        );

        // 在线用户数：Redis SCAN online:*（与 monitor_online_handler 口径一致，租户仅本租户）
        let online_count = count_online_sessions(state, tenant_scope).await;

        let recent_oper_logs = recent_logs
            .into_iter()
            .map(|m| RecentOperLog {
                title: m.title.unwrap_or_default(),
                oper_name: m.oper_name.unwrap_or_default(),
                status: m.status.unwrap_or_else(|| "0".to_string()),
                cost_time: m.cost_time.unwrap_or(0),
            })
            .collect();

        DashboardStatsVo {
            today_anomaly_ips,
            total_users,
            total_roles,
            active_roles,
            today_logins: today_login.0 + today_login.1,
            login_fail: today_login.1,
            online_count,
            recent_oper_logs,
        }
    }

    /// 用户统计：总数 / 周新增 / 启用 / 停用 + 近 30 天创建趋势
    pub async fn user_stats(state: &Arc<AppState>, tenant_scope: Option<i64>) -> UserStatsVo {
        use chrono::Duration;
        use sys_user::Column as UserCol;

        let db = &state.db;
        let now = crate::common::datetime::today_utc();
        let week_ago = now - Duration::days(7);
        let month_ago = now - Duration::days(29); // 最近 30 天（含今天）

        let week_begin = week_ago.and_time(chrono::NaiveTime::MIN);
        let month_begin = month_ago.and_time(chrono::NaiveTime::MIN);

        // 并发执行：总数 / 周新增 / 启用数 / 停用数 / 月内创建用户列表（用于趋势聚合）
        let (total_users, new_users_this_week, active_users, disabled_users, recent_users) = tokio::join!(
            async {
                let mut query = sys_user::Entity::find().filter(UserCol::DelFlag.ne("2"));
                if let Some(tid) = tenant_scope {
                    query = query.filter(UserCol::TenantId.eq(tid));
                }
                query
                    .count(db)
                    .await
                    .map(|c| i64::try_from(c).unwrap_or(i64::MAX))
                    .unwrap_or(0)
            },
            async {
                let mut query = sys_user::Entity::find()
                    .filter(UserCol::DelFlag.ne("2"))
                    .filter(UserCol::CreateTime.gte(week_begin));
                if let Some(tid) = tenant_scope {
                    query = query.filter(UserCol::TenantId.eq(tid));
                }
                query
                    .count(db)
                    .await
                    .map(|c| i64::try_from(c).unwrap_or(i64::MAX))
                    .unwrap_or(0)
            },
            async {
                let mut query = sys_user::Entity::find()
                    .filter(UserCol::DelFlag.ne("2"))
                    .filter(UserCol::Status.eq("0"));
                if let Some(tid) = tenant_scope {
                    query = query.filter(UserCol::TenantId.eq(tid));
                }
                query
                    .count(db)
                    .await
                    .map(|c| i64::try_from(c).unwrap_or(i64::MAX))
                    .unwrap_or(0)
            },
            async {
                let mut query = sys_user::Entity::find()
                    .filter(UserCol::DelFlag.ne("2"))
                    .filter(UserCol::Status.eq("1"));
                if let Some(tid) = tenant_scope {
                    query = query.filter(UserCol::TenantId.eq(tid));
                }
                query
                    .count(db)
                    .await
                    .map(|c| i64::try_from(c).unwrap_or(i64::MAX))
                    .unwrap_or(0)
            },
            async {
                let mut query = sys_user::Entity::find()
                    .filter(UserCol::DelFlag.ne("2"))
                    .filter(UserCol::CreateTime.gte(month_begin));
                if let Some(tid) = tenant_scope {
                    query = query.filter(UserCol::TenantId.eq(tid));
                }
                query
                    .order_by_asc(UserCol::CreateTime)
                    .all(db)
                    .await
                    .unwrap_or_default()
            }
        );

        // 按天聚合最近 30 天的用户创建数
        let mut create_trend: Vec<UserCreateTrendItem> = Vec::new();
        let mut trend_map: std::collections::HashMap<String, i64> =
            std::collections::HashMap::new();
        for u in &recent_users {
            if let Some(ct) = u.create_time {
                let date_str = ct.format("%Y-%m-%d").to_string();
                *trend_map.entry(date_str).or_insert(0) += 1;
            }
        }
        for i in 0..30i64 {
            let date = month_ago + Duration::days(i);
            let date_str = date.format("%Y-%m-%d").to_string();
            let count = trend_map.get(&date_str).copied().unwrap_or(0);
            create_trend.push(UserCreateTrendItem {
                date: date_str,
                count,
            });
        }

        UserStatsVo {
            total_users,
            new_users_this_week,
            active_users,
            disabled_users,
            create_trend,
        }
    }
}

/// 统计在线会话数（§27.13.2 分层视图口径，与 `monitor_online_handler::list` 一致）
///
/// - `tenant_scope = None`（平台操作者）：key 数量即在线数，无需解析 JSON；
/// - `tenant_scope = Some(tid)`：解析 `OnlineSession` 仅计本租户；v2.13 前的旧 JSON
///   无 `tenant_id`（serde default=0）时按 `user_id` 回查 `sys_user.tenant_id` 兜底归属
///   （无法定位租户的旧会话视为平台会话，不计入租户）。
///
/// Redis 故障时返回 0（不阻塞 dashboard）。
async fn count_online_sessions(state: &Arc<AppState>, tenant_scope: Option<i64>) -> i64 {
    use crate::utils::crypto::OnlineSession;

    let store = state.store.clone();
    // 截断版扫描（保持原 scan_keys 上限 5000 与截断语义——仅读展示，S3 允许截断）
    let keys = match store.scan("online:*", Some(5000)).await {
        Ok(k) => k,
        Err(e) => {
            tracing::warn!("Redis SCAN online:* 失败，dashboard 在线数降级为 0: {}", e);
            return 0;
        }
    };
    if keys.is_empty() {
        return 0;
    }
    let Some(operator_tid) = tenant_scope else {
        return keys.len() as i64;
    };

    let values: Vec<Option<String>> = match store.get_many(&keys).await {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!("Redis MGET online 失败，dashboard 在线数降级为 0: {}", e);
            return 0;
        }
    };

    let sessions: Vec<OnlineSession> = values
        .iter()
        .flatten()
        .filter_map(|json| match serde_json::from_str::<OnlineSession>(json) {
            Ok(s) => Some(s),
            Err(e) => {
                tracing::warn!("解析 online JSON 失败（跳过）: {}", e);
                None
            }
        })
        .collect();

    // 旧会话兜底：按 user_id 回查 sys_user.tenant_id（否则租户看不到本租户旧会话的在线数）
    let legacy_user_ids: Vec<i64> = sessions
        .iter()
        .filter(|s| s.tenant_id == 0 && s.user_id > 0)
        .map(|s| s.user_id)
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

    sessions
        .iter()
        .filter(|s| {
            let session_tid = if s.tenant_id != 0 {
                s.tenant_id
            } else {
                legacy_tenant_map.get(&s.user_id).copied().unwrap_or(0)
            };
            session_tid == operator_tid
        })
        .count() as i64
}
