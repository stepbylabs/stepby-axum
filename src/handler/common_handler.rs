//! 通用模块 Handler（Axum 原生实现）
//!
//! 接口路径对齐前端调用规范：
//! - POST /common/upload             通用文件上传（multipart/form-data，字段名 file）
//! - GET  /common/download           通用文件下载（按服务器文件名）
//! - GET  /common/download/resource  通用资源下载（按相对资源路径）
//!
//! 安全要点：
//! - 上传：扩展名白名单 + 文件大小限制；图片类型额外做 magic bytes 校验
//! - 文件名重命名为 `{uuid}.{ext}`，禁止使用前端原文件名（防路径穿越）
//! - 落盘路径带上传者租户维度：`uploads/{tid}/...`（平台 = 0），实现租户物理隔离
//! - 下载：fileName / resource 严格路径穿越校验（拒绝 `..`、`/`、`\`）
//! - download_resource：解析 `uploads/{tid}/{kind}/{key}` 并校验文件归属租户，越权 403
//! - serve_upload（GET /uploads/*）：受鉴权预览路由，同样校验文件归属租户

use std::sync::Arc;

use axum::extract::{Multipart, Path, Query, State};
use axum::http::{HeaderMap, HeaderName, HeaderValue};
use axum::response::{IntoResponse, Response};
use chrono::Duration;
use sea_orm::{ColumnTrait, EntityTrait, PaginatorTrait, QueryFilter, QueryOrder, QuerySelect};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};

use crate::common::{AjaxResult, AppError};
use crate::entity::{sys_oper_log, sys_role, sys_user};
use crate::middleware::Operator;
use crate::state::AppState;
use crate::utils::crypto::OnlineSession;
use crate::utils::redis::scan_keys;

// ==================== DTO ====================

/// 通用文件下载请求参数
#[derive(Debug, Deserialize, IntoParams)]
#[serde(rename_all = "camelCase")]
pub struct DownloadParams {
    /// 服务器端文件名（不含路径，UUID 命名）
    pub file_name: String,
    /// 是否下载后删除原文件
    #[serde(default)]
    pub delete: bool,
}

/// 通用资源下载请求参数
#[derive(Debug, Deserialize, IntoParams)]
#[serde(rename_all = "camelCase")]
pub struct DownloadResourceParams {
    /// 资源相对路径（必须以 uploads/ 开头）
    pub resource: String,
}

// ==================== 响应类型 ====================

/// 通用上传响应（对齐前端 UploadFileResult extends AjaxResult）
///
/// 字段挂在响应根对象上：url / fileName / newFileName / originalFilename。
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct CommonUploadResult {
    pub code: i32,
    pub msg: String,
    /// 完整 URL 地址（如 "/uploads/file/xxx.pdf"）
    pub url: String,
    /// 文件名（包含路径，前端用作访问 URL）
    pub file_name: String,
    /// 文件名（不含路径）
    pub new_file_name: String,
    /// 原始文件名（前端传入）
    pub original_filename: String,
}

crate::impl_into_response!(CommonUploadResult);

// ==================== Handler ====================

/// GET /dashboard/stats
/// 仪表盘聚合统计接口
///
/// 返回首页仪表盘统计卡片所需的全部聚合指标（U5 优化：从 6 路并发请求合并为单次调用）。
/// 字段含义：
/// - todayAnomalyIps：今日登录失败的不重复 IP 数
/// - totalUsers：用户总数（del_flag != '2'）
/// - totalRoles：角色总数（del_flag != '2'）
/// - activeRoles：启用状态（status='0'）的角色数
/// - todayLogins：今日登录总次数（成功 + 失败）
/// - loginFail：今日登录失败次数
/// - onlineCount：当前在线用户数（Redis online:* key 计数）
/// - recentOperLogs：最近 5 条操作日志
///
/// §27.13.2 分层视图（Phase 3）：`monitor:dashboard:list` 为所有登录用户可用
/// （看板是默认首页），故本接口**必须**按操作者租户过滤——租户操作者（tid≠0）只统计
/// 本租户的用户/角色/登录日志/操作日志/在线会话；平台操作者（tid=0）全量。
#[utoipa::path(
    get,
    path = "/dashboard/stats",
    responses(
        (status = 200, description = "查询成功", body = AjaxResult<DashboardStatsVo>),
        (status = 500, description = "服务器错误"),
    ),
    tag = "dashboard"
)]
pub async fn dashboard_stats(
    State(state): State<Arc<AppState>>,
    operator: Operator,
) -> Result<AjaxResult<DashboardStatsVo>, AppError> {
    use sys_oper_log::Column as OperCol;
    use sys_role::Column as RoleCol;
    use sys_user::Column as UserCol;

    let db = &state.db;
    // 租户维度：None = 平台操作者（不过滤），Some(tid) = 仅本租户
    let tenant_scope = crate::common::tenant::tenant_scope(operator.tenant_id());

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
        // 今日登录统计：复用 logininfor_service.daily_stats(1)，返回 [LoginDailyStat { date, success, fail }]
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
    let online_count = count_online_sessions(&state, tenant_scope).await;

    let recent_oper_logs = recent_logs
        .into_iter()
        .map(|m| RecentOperLog {
            title: m.title.unwrap_or_default(),
            oper_name: m.oper_name.unwrap_or_default(),
            status: m.status.unwrap_or_else(|| "0".to_string()),
            cost_time: m.cost_time.unwrap_or(0),
        })
        .collect();

    Ok(AjaxResult::success(DashboardStatsVo {
        today_anomaly_ips,
        total_users,
        total_roles,
        active_roles,
        today_logins: today_login.0 + today_login.1,
        login_fail: today_login.1,
        online_count,
        recent_oper_logs,
    }))
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
    let mut redis = state.redis.clone();
    let keys = match scan_keys(&mut redis, "online:*", 5000).await {
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

    let values: Vec<Option<String>> = match crate::utils::redis::cmd_timeout(
        redis::cmd("MGET").arg(&keys).query_async(&mut redis),
    )
    .await
    {
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

/// 仪表盘聚合统计响应
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct DashboardStatsVo {
    /// 今日异常登录 IP 数（登录失败的不重复 IP 数）
    pub today_anomaly_ips: i64,
    /// 用户总数（del_flag != '2'）
    pub total_users: i64,
    /// 角色总数（del_flag != '2'）
    pub total_roles: i64,
    /// 启用角色数（status='0'）
    pub active_roles: i64,
    /// 今日登录总次数（成功 + 失败）
    pub today_logins: i64,
    /// 今日登录失败次数
    pub login_fail: i64,
    /// 当前在线用户数（Redis online:* key 计数）
    pub online_count: i64,
    /// 最近 5 条操作日志
    pub recent_oper_logs: Vec<RecentOperLog>,
}

/// 最近操作日志（仪表盘卡片用，仅返回展示所需字段）
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct RecentOperLog {
    /// 操作模块标题
    pub title: String,
    /// 操作人员名称
    pub oper_name: String,
    /// 操作状态（'0' 成功，'1' 失败）
    pub status: String,
    /// 耗时（毫秒）
    pub cost_time: i64,
}

/// GET /dashboard/user-stats
/// 用户统计接口（U14 优化：替代前端 /system/user/list?pageSize=100 的低效拉取）
///
/// 返回用户分布与创建趋势，供首页"用户创建趋势"图表与统计卡片使用。
/// 字段含义：
/// - totalUsers：用户总数
/// - newUsersThisWeek：最近 7 天新增用户数
/// - activeUsers：启用状态（status='0'）的用户数
/// - disabledUsers：停用状态（status='1'）的用户数
/// - createTrend：最近 30 天按天聚合的新增用户数 [{date, count}]
///
/// §27.13.2 分层视图：与 `dashboard_stats` 同口径——租户操作者仅统计本租户用户，
/// 平台操作者全量（`monitor:dashboard:list` 对所有登录用户可用）。
#[utoipa::path(
    get,
    path = "/dashboard/user-stats",
    responses(
        (status = 200, description = "查询成功", body = AjaxResult<UserStatsVo>),
        (status = 500, description = "服务器错误"),
    ),
    tag = "dashboard"
)]
pub async fn user_stats(
    State(state): State<Arc<AppState>>,
    operator: Operator,
) -> Result<AjaxResult<UserStatsVo>, AppError> {
    use sys_user::Column as UserCol;

    let db = &state.db;
    let now = crate::common::datetime::today_utc();
    let week_ago = now - Duration::days(7);
    let month_ago = now - Duration::days(29); // 最近 30 天（含今天）

    let week_begin = week_ago.and_time(chrono::NaiveTime::MIN);
    let month_begin = month_ago.and_time(chrono::NaiveTime::MIN);

    // 租户维度：None = 平台操作者（不过滤），Some(tid) = 仅本租户
    let tenant_scope = crate::common::tenant::tenant_scope(operator.tenant_id());

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
    let mut trend_map: std::collections::HashMap<String, i64> = std::collections::HashMap::new();
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

    Ok(AjaxResult::success(UserStatsVo {
        total_users,
        new_users_this_week,
        active_users,
        disabled_users,
        create_trend,
    }))
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

/// POST /common/upload
/// 通用文件上传（multipart/form-data，字段名 file）
///
/// 安全策略：
/// - 扩展名白名单（从 UploadConfig.common_allowed_exts 读取）
/// - 文件大小限制（UploadConfig.common_max_size，默认 10MB）
/// - 图片类型额外做 magic bytes 校验（防伪造扩展名）
/// - 文件名重命名为 `{uuid}.{ext}`，禁用前端原文件名（防路径穿越）
#[utoipa::path(
    post,
    path = "/common/upload",
    responses(
        (status = 200, description = "上传成功", body = CommonUploadResult),
        (status = 400, description = "参数错误或文件不合法"),
    ),
    tag = "common"
)]
pub async fn upload(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    mut multipart: Multipart,
) -> Result<CommonUploadResult, AppError> {
    let upload_cfg = &state.config.upload;

    // 从 multipart 中提取 file 字段（前端约定字段名为 file）
    // P0-3 OOM 修复：流式限长读取（chunk 边读边限长），不再 field.bytes() 整读内存
    let mut file_bytes: Option<Vec<u8>> = None;
    let mut original_filename: Option<String> = None;
    let mut file_ext: Option<String> = None;
    while let Some(mut field) = multipart.next_field().await.map_err(|e| {
        AppError::bad_request(&crate::tr!("error.file.multipart_parse_failed", e = e))
    })? {
        if field.name() == Some("file") {
            let (bytes, ext, original) =
                crate::common::upload::read_field_limited(&mut field, upload_cfg.common_max_size)
                    .await?;
            file_ext = ext;
            original_filename = original;
            file_bytes = Some(bytes);
        }
    }

    // 上传扫描集成点（`[upload_scan]`，默认 off ⇒ **零出站**、逐字节等价于改造前）
    if let Some(bytes) = file_bytes.as_deref() {
        crate::common::upload_scan::ensure_clean(
            &state.config.upload_scan,
            original_filename.as_deref().unwrap_or_default(),
            bytes,
        )
        .await?;
    }

    // P0-3：统一校验 + 保存（扩展名白名单、危险类型拒绝、magic bytes、UUID 文件名、写盘）
    let saved = crate::common::upload::save_upload_bytes(
        state.storage.as_ref(),
        file_bytes.as_deref().ok_or_else(|| {
            AppError::bad_request(&crate::tr!("error.common_handler.field_not_found_file"))
        })?,
        file_ext.as_deref(),
        original_filename.as_deref(),
        upload_cfg,
        operator.tenant_id(),
        crate::common::upload::UploadKind::Common,
    )
    .await?;

    Ok(CommonUploadResult {
        code: 200,
        msg: crate::tr!("error.common_handler.upload_success").to_string(),
        url: saved.url.clone(),
        file_name: saved.url,
        new_file_name: saved.new_filename,
        original_filename: saved.original_filename.unwrap_or_default(),
    })
}

/// GET /common/download
/// 通用文件下载（按服务器文件名）
///
/// 安全要点：
/// - fileName 不能包含 `/`、`\\`、`..`（防路径穿越）
/// - 文件不存在返回 JSON 错误
/// - delete=true 时下载后删除原文件
/// - 仅在请求者自身租户目录（`uploads/{tid}/file/`）内查找，跨租户自然 404
/// - 响应头 `download-filename`：URL 编码的文件名，前端据此确定保存名
#[utoipa::path(
    get,
    path = "/common/download",
    params(DownloadParams),
    responses(
        (status = 200, description = "文件二进制流", content_type = "application/octet-stream"),
        (status = 404, description = "文件不存在"),
    ),
    tag = "common"
)]
pub async fn download(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    Query(params): Query<DownloadParams>,
) -> Result<Response, AppError> {
    // 路径穿越校验：fileName 不能包含路径分隔符或 ..
    let file_name = params.file_name.trim();
    if file_name.is_empty()
        || file_name.contains('/')
        || file_name.contains('\\')
        || file_name.contains("..")
        || file_name.contains('\0')
    {
        return Err(AppError::bad_request(&crate::tr!(
            "error.common_handler.filename_invalid"
        )));
    }

    let upload_cfg = &state.config.upload;
    // 统一走存储后端读取（local 读盘 / s3 下载对象），文件不存在由后端返回 None；
    // 读取目录带请求者租户维度，无法读取其它租户文件
    let tenant_id = operator.tenant_id();
    let bytes = state
        .storage
        .read(&upload_cfg.common_dir, tenant_id, file_name)
        .await?
        .ok_or_else(|| AppError::not_found(&crate::tr!("error.common_handler.file_not_found")))?;

    // delete=true 时下载后删除原文件（后端删除幂等：不存在视为成功）
    if params.delete {
        state
            .storage
            .delete(&upload_cfg.common_dir, tenant_id, file_name)
            .await?;
    }

    Ok(build_download_response(&bytes, file_name))
}

/// GET /common/download/resource
/// 通用资源下载（按相对资源路径）
///
/// 安全要点（更严格）：
/// - resource 必须形如 `uploads/{tid}/{kind}/{key}`（kind 为配置目录末段：file / avatar）
/// - 禁止 `..`、`\\`
/// - 校验 `{tid}` 与请求者租户的归属关系，越权返回 403
/// - 按「配置目录 + 文件名」拆分后交存储后端二次路径穿越校验（本地基于目录解析 + key 拼接，
///   等价于原 canonicalize 的 upload_root 边界约束）
#[utoipa::path(
    get,
    path = "/common/download/resource",
    params(DownloadResourceParams),
    responses(
        (status = 200, description = "文件二进制流", content_type = "application/octet-stream"),
        (status = 403, description = "无权访问该租户资源"),
        (status = 404, description = "资源不存在"),
    ),
    tag = "common"
)]
pub async fn download_resource(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    Query(params): Query<DownloadResourceParams>,
) -> Result<Response, AppError> {
    let resource = params.resource.trim();

    // 基础校验：必须以 uploads/ 开头，禁止 .. 与 \；路径安全在存储后端内再次校验
    if resource.is_empty()
        || !resource.starts_with("uploads/")
        || resource.contains("..")
        || resource.contains('\\')
        || resource.contains('\0')
    {
        return Err(AppError::bad_request(&crate::tr!(
            "error.common_handler.resource_path_invalid"
        )));
    }

    let (dir, tenant_id, key) = parse_tenant_resource(&state, resource)?;
    // 租户归属校验：平台租户（0）可读任意租户资源，非平台租户仅可读自身资源
    if !crate::common::tenant::tenant_allowed(operator.tenant_id(), tenant_id) {
        tracing::warn!(
            operator_tid = operator.tenant_id(),
            resource_tid = tenant_id,
            resource = %resource,
            "资源下载越权访问被拒绝"
        );
        return Err(AppError::forbidden(&crate::tr!("error.common.forbidden")));
    }

    let bytes = state
        .storage
        .read(&dir, tenant_id, &key)
        .await?
        .ok_or_else(|| {
            AppError::not_found(&crate::tr!("error.common_handler.resource_not_found"))
        })?;

    Ok(build_download_response(&bytes, &key))
}

/// GET /uploads/{*path}
/// 受鉴权文件预览（替代此前的无鉴权 `ServeDir` 静态直出）
///
/// 路径形如 `{tid}/{kind}/{key}`（如 `5/avatar/a1b2.png`）：
/// - 校验 `{tid}` 与请求者租户的归属关系，越权返回 403
/// - `{kind}` 必须是配置目录末段（file / avatar）之一，防止路径段被用于拼接旁路目录
/// - 按扩展名设置 Content-Type 以便浏览器内联预览
#[utoipa::path(
    get,
    path = "/uploads/{path}",
    params(("path" = String, Path, description = "租户维度相对路径 {tid}/{kind}/{filename}")),
    responses(
        (status = 200, description = "文件二进制流"),
        (status = 403, description = "无权访问该租户文件"),
        (status = 404, description = "文件不存在"),
    ),
    tag = "common"
)]
pub async fn serve_upload(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    Path(path): Path<String>,
) -> Result<Response, AppError> {
    let segments: Vec<&str> = path.trim_matches('/').split('/').collect();
    if segments.len() != 3 {
        return Err(AppError::bad_request(&crate::tr!(
            "error.common_handler.resource_path_invalid"
        )));
    }
    let (tid_seg, kind, key) = (segments[0], segments[1], segments[2]);
    let tenant_id: i64 = tid_seg.parse().map_err(|_| {
        AppError::bad_request(&crate::tr!("error.common_handler.resource_path_invalid"))
    })?;
    let dir =
        crate::common::upload::resolve_kind_dir(&state.config.upload, kind).ok_or_else(|| {
            AppError::bad_request(&crate::tr!("error.common_handler.resource_path_invalid"))
        })?;

    if !crate::common::tenant::tenant_allowed(operator.tenant_id(), tenant_id) {
        tracing::warn!(
            operator_tid = operator.tenant_id(),
            resource_tid = tenant_id,
            path = %path,
            "文件预览越权访问被拒绝"
        );
        return Err(AppError::forbidden(&crate::tr!("error.common.forbidden")));
    }

    let bytes = state
        .storage
        .read(&dir, tenant_id, key)
        .await?
        .ok_or_else(|| {
            AppError::not_found(&crate::tr!("error.common_handler.resource_not_found"))
        })?;

    let content_type = crate::storage::content_type_for(key).unwrap_or("application/octet-stream");
    let mut headers = HeaderMap::new();
    if let Ok(val) = HeaderValue::from_str(content_type) {
        headers.insert(axum::http::header::CONTENT_TYPE, val);
    }
    if let Ok(val) = HeaderValue::from_str(&bytes.len().to_string()) {
        headers.insert(axum::http::header::CONTENT_LENGTH, val);
    }
    // 禁缓存：响应依赖请求者身份，避免中间层缓存导致跨租户泄漏
    headers.insert(
        axum::http::header::CACHE_CONTROL,
        HeaderValue::from_static("private, no-store"),
    );

    Ok((axum::http::StatusCode::OK, headers, bytes).into_response())
}

// ==================== 辅助函数 ====================

/// 解析租户维度资源路径 `uploads/{tid}/{kind}/{key}` → (配置目录, 租户 id, 文件名)
fn parse_tenant_resource(
    state: &AppState,
    resource: &str,
) -> Result<(String, i64, String), AppError> {
    let invalid =
        || AppError::bad_request(&crate::tr!("error.common_handler.resource_path_invalid"));
    let segments: Vec<&str> = resource.trim_matches('/').split('/').collect();
    if segments.len() != 4 || segments[0] != "uploads" {
        return Err(invalid());
    }
    let tenant_id: i64 = segments[1].parse().map_err(|_| invalid())?;
    let dir = crate::common::upload::resolve_kind_dir(&state.config.upload, segments[2])
        .ok_or_else(invalid)?;
    if segments[3].is_empty() {
        return Err(invalid());
    }
    Ok((dir, tenant_id, segments[3].to_string()))
}

/// 构造文件下载响应（Content-Type: application/octet-stream，带 download-filename 头）
fn build_download_response(bytes: &[u8], file_name: &str) -> Response {
    let mut headers = HeaderMap::new();
    headers.insert(
        axum::http::header::CONTENT_TYPE,
        HeaderValue::from_static("application/octet-stream"),
    );
    if let Ok(val) = HeaderValue::from_str(&bytes.len().to_string()) {
        headers.insert(axum::http::header::CONTENT_LENGTH, val);
    }
    // download-filename 头：URL 编码（前端通过 decodeURIComponent 解码获取保存名）
    let encoded = url_encode(file_name);
    if let Ok(val) = HeaderValue::from_str(&encoded) {
        headers.insert(HeaderName::from_static("download-filename"), val);
    }

    (axum::http::StatusCode::OK, headers, bytes.to_vec()).into_response()
}

/// URL 编码（百分号编码），用于 download-filename 响应头
///
/// 简化实现：保留 ASCII 字母数字和少数安全字符，其他全部百分号编码。
/// 对齐前端 `decodeURIComponent(res.headers['download-filename'])` 解码逻辑。
fn url_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len() * 3);
    for byte in s.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
            out.push(byte as char);
        } else {
            out.push_str(&format!("%{:02X}", byte));
        }
    }
    out
}

// detect_image_ext / normalize_ext 已抽到 crate::common::image（C13），此处不再重复定义。
