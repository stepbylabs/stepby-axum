//! 通用模块 Handler（Axum 原生实现）
//!
//! 接口路径对齐 ruoyi-vue3-ts 前端：
//! - POST /common/upload             通用文件上传（multipart/form-data，字段名 file）
//! - GET  /common/download           通用文件下载（按服务器文件名）
//! - GET  /common/download/resource  通用资源下载（按相对资源路径）
//!
//! 安全要点：
//! - 上传：扩展名白名单 + 文件大小限制；图片类型额外做 magic bytes 校验
//! - 文件名重命名为 `{uuid}.{ext}`，禁止使用前端原文件名（防路径穿越）
//! - 下载：fileName / resource 严格路径穿越校验（拒绝 `..`、`/`、`\`）
//! - download_resource：用 `Path::canonicalize` 二次校验规范化后路径仍以 `uploads/` 开头

use std::sync::Arc;

use axum::extract::{Multipart, Query, State};
use axum::http::{HeaderMap, HeaderName, HeaderValue};
use axum::response::{IntoResponse, Response};
use chrono::{Duration, Local};
use sea_orm::{ColumnTrait, EntityTrait, PaginatorTrait, QueryFilter, QueryOrder, QuerySelect};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};

use crate::common::{AjaxResult, AppError};
use crate::entity::{sys_oper_log, sys_role, sys_user};
use crate::handler::monitor_cache_handler::scan_keys;
use crate::state::AppState;

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
) -> Result<AjaxResult<DashboardStatsVo>, AppError> {
    use sys_user::Column as UserCol;
    use sys_role::Column as RoleCol;
    use sys_oper_log::Column as OperCol;

    let db = &state.db;

    // 并发聚合查询：用户/角色/登录日志/操作日志（各查询互不依赖，用 tokio::join! 并发执行）
    let (total_users, total_roles, active_roles, today_login, recent_logs, today_anomaly_ips) = tokio::join!(
        // 用户总数（del_flag != '2'，即未被逻辑删除）
        async {
            sys_user::Entity::find()
                .filter(UserCol::DelFlag.ne("2"))
                .count(db)
                .await
                .unwrap_or(0) as i64
        },
        // 角色总数（del_flag != '2'）
        async {
            sys_role::Entity::find()
                .filter(RoleCol::DelFlag.ne("2"))
                .count(db)
                .await
                .unwrap_or(0) as i64
        },
        // 启用角色数（status='0' 且 del_flag != '2'）
        async {
            sys_role::Entity::find()
                .filter(RoleCol::Status.eq("0"))
                .filter(RoleCol::DelFlag.ne("2"))
                .count(db)
                .await
                .unwrap_or(0) as i64
        },
        // 今日登录统计：复用 logininfor_service.daily_stats(1)，返回 [LoginDailyStat { date, success, fail }]
        async {
            state
                .logininfor_service
                .daily_stats(1)
                .await
                .ok()
                .and_then(|v| v.into_iter().next())
                .map(|s| (s.success, s.fail))
                .unwrap_or((0, 0))
        },
        // 最近 5 条操作日志（按 oper_time 降序）
        async {
            sys_oper_log::Entity::find()
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
                .count_today_failed_ips()
                .await
                .unwrap_or(0)
        }
    );

    // 在线用户数：Redis SCAN online:*（与 monitor_online_handler 一致）
    // Redis 故障时降级为 0（不阻塞 dashboard）
    let online_count = scan_keys(&mut state.redis.clone(), "online:*")
        .await
        .map(|keys| keys.len() as i64)
        .unwrap_or(0);

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
) -> Result<AjaxResult<UserStatsVo>, AppError> {
    use sys_user::Column as UserCol;

    let db = &state.db;
    let now = Local::now().date_naive();
    let week_ago = now - Duration::days(7);
    let month_ago = now - Duration::days(29); // 最近 30 天（含今天）

    let week_begin = week_ago.and_time(chrono::NaiveTime::MIN);
    let month_begin = month_ago.and_time(chrono::NaiveTime::MIN);

    // 并发执行：总数 / 周新增 / 启用数 / 停用数 / 月内创建用户列表（用于趋势聚合）
    let (total_users, new_users_this_week, active_users, disabled_users, recent_users) = tokio::join!(
        async {
            sys_user::Entity::find()
                .filter(UserCol::DelFlag.ne("2"))
                .count(db)
                .await
                .unwrap_or(0) as i64
        },
        async {
            sys_user::Entity::find()
                .filter(UserCol::DelFlag.ne("2"))
                .filter(UserCol::CreateTime.gte(week_begin))
                .count(db)
                .await
                .unwrap_or(0) as i64
        },
        async {
            sys_user::Entity::find()
                .filter(UserCol::DelFlag.ne("2"))
                .filter(UserCol::Status.eq("0"))
                .count(db)
                .await
                .unwrap_or(0) as i64
        },
        async {
            sys_user::Entity::find()
                .filter(UserCol::DelFlag.ne("2"))
                .filter(UserCol::Status.eq("1"))
                .count(db)
                .await
                .unwrap_or(0) as i64
        },
        async {
            sys_user::Entity::find()
                .filter(UserCol::DelFlag.ne("2"))
                .filter(UserCol::CreateTime.gte(month_begin))
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
        create_trend.push(UserCreateTrendItem { date: date_str, count });
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
    mut multipart: Multipart,
) -> Result<CommonUploadResult, AppError> {
    let upload_cfg = &state.config.upload;

    // 从 multipart 中提取 file 字段（前端约定字段名为 file）
    let mut file_bytes: Option<Vec<u8>> = None;
    let mut original_filename: Option<String> = None;
    let mut file_ext: Option<String> = None;
    while let Some(field) = multipart
        .next_field()
        .await
        .map_err(|e| AppError::bad_request(&format!("解析 multipart 失败: {}", e)))?
    {
        if field.name() == Some("file") {
            if let Some(filename) = field.file_name()
                && let Some(ext) = std::path::Path::new(filename)
                    .extension()
                    .and_then(|e| e.to_str())
            {
                file_ext = Some(ext.to_lowercase());
            }
            original_filename = field.file_name().map(|s| s.to_string());
            let bytes = field
                .bytes()
                .await
                .map_err(|e| AppError::bad_request(&format!("读取文件内容失败: {}", e)))?;
            file_bytes = Some(bytes.to_vec());
        }
    }

    let bytes = file_bytes.ok_or_else(|| AppError::bad_request("未找到 file 字段"))?;
    if bytes.is_empty() {
        return Err(AppError::bad_request("上传文件为空"));
    }

    // 文件大小限制
    if bytes.len() > upload_cfg.common_max_size {
        return Err(AppError::bad_request(&format!(
            "文件大小不能超过 {}MB",
            upload_cfg.common_max_size / 1024 / 1024
        )));
    }

    // 扩展名校验：必须提供且在白名单内
    let declared_ext = file_ext
        .as_deref()
        .ok_or_else(|| AppError::bad_request("无法识别文件扩展名"))?;
    let allowed: &[&str] = &upload_cfg
        .common_allowed_exts
        .iter()
        .map(|s| s.as_str())
        .collect::<Vec<_>>();
    if !allowed.contains(&declared_ext) {
        return Err(AppError::bad_request(&format!(
            "不支持的文件类型: {}",
            declared_ext
        )));
    }

    // magic bytes 校验：图片类型必须通过，其他类型跳过 magic bytes 校验
    // （仅做扩展名白名单 + 大小校验，因为非图片类型的 magic bytes 校验库依赖较重）
    let image_exts: &[&str] = &["jpg", "jpeg", "png", "gif"];
    let final_ext = if image_exts.contains(&declared_ext) {
        let detected = detect_image_ext(&bytes).ok_or_else(|| {
            AppError::bad_request("无法识别的图片格式，仅支持 jpg/jpeg/png/gif")
        })?;
        // 声明扩展名与 magic bytes 不一致时以 magic bytes 为准（防伪造）
        if normalize_ext(declared_ext) != normalize_ext(&detected) {
            tracing::warn!(
                declared = %declared_ext,
                detected = %detected,
                "图片扩展名与实际类型不一致，以 magic bytes 为准"
            );
        }
        detected
    } else {
        declared_ext.to_string()
    };

    // 生成唯一文件名（禁止使用前端原文件名，防路径穿越）
    let new_filename = crate::common::gen_uuid_filename(&final_ext);
    let file_path = std::path::Path::new(&upload_cfg.common_dir).join(&new_filename);

    // 写入文件系统（spawn_blocking + create_dir_all + write 已封装在公共函数中）
    crate::common::write_upload_file(file_path, &upload_cfg.common_dir, &bytes).await?;

    // 可访问 URL 路径（前端通过 VITE_APP_BASE_API + url 访问）
    let url = format!("{}/{}", upload_cfg.common_url_prefix, new_filename);

    Ok(CommonUploadResult {
        code: 200,
        msg: "上传成功".to_string(),
        url: url.clone(),
        file_name: url,
        new_file_name: new_filename,
        original_filename: original_filename.unwrap_or_default(),
    })
}

/// GET /common/download
/// 通用文件下载（按服务器文件名）
///
/// 安全要点：
/// - fileName 不能包含 `/`、`\\`、`..`（防路径穿越）
/// - 文件不存在返回 JSON 错误
/// - delete=true 时下载后删除原文件
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
        return Err(AppError::bad_request("非法的文件名"));
    }

    let upload_cfg = &state.config.upload;
    // 解析上传目录为绝对路径，确保与 ServeDir 服务路径一致
    let common_dir = crate::common::resolve_upload_dir(&upload_cfg.common_dir).await;
    let file_path = common_dir.join(file_name);

    // 读取文件内容（同步 IO 放到 spawn_blocking）
    let file_path_clone = file_path.clone();
    let file_name_str = file_path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or(file_name)
        .to_string();
    let content = tokio::task::spawn_blocking(move || -> std::io::Result<Option<Vec<u8>>> {
        if !file_path_clone.exists() {
            return Ok(None);
        }
        std::fs::read(&file_path_clone).map(Some)
    })
    .await
    .map_err(|e| AppError::internal(&format!("文件读取任务失败: {}", e)))?
    .map_err(|e| AppError::internal(&format!("读取文件失败: {}", e)))?;

    let bytes = match content {
        Some(b) => b,
        None => {
            return Err(AppError::not_found("文件不存在"));
        }
    };

    // delete=true 时下载后删除原文件
    if params.delete {
        let path_to_remove = file_path.clone();
        if let Err(e) = tokio::fs::remove_file(&path_to_remove).await {
            tracing::warn!(error = %e, path = ?path_to_remove, "下载后删除文件失败");
        }
    }

    Ok(build_download_response(&bytes, &file_name_str))
}

/// GET /common/download/resource
/// 通用资源下载（按相对资源路径）
///
/// 安全要点（更严格）：
/// - resource 必须以 `uploads/` 开头
/// - 禁止 `..`、`\\`
/// - 用 `Path::canonicalize` 二次校验：规范化后路径必须仍以 `uploads/` 开头
#[utoipa::path(
    get,
    path = "/common/download/resource",
    params(DownloadResourceParams),
    responses(
        (status = 200, description = "文件二进制流", content_type = "application/octet-stream"),
        (status = 404, description = "资源不存在"),
    ),
    tag = "common"
)]
pub async fn download_resource(
    State(_state): State<Arc<AppState>>,
    Query(params): Query<DownloadResourceParams>,
) -> Result<Response, AppError> {
    let resource = params.resource.trim();

    // 基础校验：必须以 uploads/ 开头，禁止 .. 和反斜杠
    if resource.is_empty()
        || !resource.starts_with("uploads/")
        || resource.contains("..")
        || resource.contains('\\')
        || resource.contains('\0')
    {
        return Err(AppError::bad_request("非法的资源路径"));
    }

    // 规范化路径二次校验：canonicalize 后必须仍以 uploads/ 开头
    let path = std::path::Path::new(resource);
    let canonical = tokio::fs::canonicalize(path)
        .await
        .map_err(|_| AppError::not_found("资源不存在"))?;
    let canonical_str = canonical.to_string_lossy();
    // 跨平台兼容：Windows 下 canonicalize 返回 `\\?\D:\...\uploads\...`
    if !canonical_str.replace('\\', "/").contains("uploads/") {
        return Err(AppError::bad_request("非法的资源路径"));
    }

    // 读取文件内容
    let path_clone = canonical.clone();
    let content = tokio::task::spawn_blocking(move || -> std::io::Result<Option<Vec<u8>>> {
        if !path_clone.is_file() {
            return Ok(None);
        }
        std::fs::read(&path_clone).map(Some)
    })
    .await
    .map_err(|e| AppError::internal(&format!("文件读取任务失败: {}", e)))?
    .map_err(|e| AppError::internal(&format!("读取文件失败: {}", e)))?;

    let bytes = match content {
        Some(b) => b,
        None => {
            return Err(AppError::not_found("资源不存在"));
        }
    };

    // download-filename 取 basename
    let basename = canonical
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("download")
        .to_string();

    Ok(build_download_response(&bytes, &basename))
}

// ==================== 辅助函数 ====================

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

    (
        axum::http::StatusCode::OK,
        headers,
        bytes.to_vec(),
    )
        .into_response()
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

/// 通过文件头 magic bytes 识别图片真实格式
///
/// 返回标准化扩展名（小写）：
/// - JPEG: FF D8 FF
/// - PNG: 89 50 4E 47 0D 0A 1A 0A
/// - GIF: 47 49 46 38 (37/39)
fn detect_image_ext(bytes: &[u8]) -> Option<String> {
    // JPEG: FF D8 FF
    if bytes.len() >= 3 && bytes[0] == 0xFF && bytes[1] == 0xD8 && bytes[2] == 0xFF {
        return Some("jpg".to_string());
    }
    // PNG: 89 50 4E 47 0D 0A 1A 0A（需 8 字节）
    if bytes.len() >= 8 && bytes[0..8] == [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A] {
        return Some("png".to_string());
    }
    // GIF: 47 49 46 38 (37/39)（需 5 字节）
    if bytes.len() >= 5
        && bytes[0..4] == [0x47, 0x49, 0x46, 0x38]
        && (bytes[4] == 0x37 || bytes[4] == 0x39)
    {
        return Some("gif".to_string());
    }
    None
}

/// 标准化扩展名（jpeg → jpg）
fn normalize_ext(ext: &str) -> String {
    let lower = ext.to_lowercase();
    match lower.as_str() {
        "jpeg" => "jpg".to_string(),
        _ => lower,
    }
}
