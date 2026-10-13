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
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};

use crate::common::{AjaxResult, AppError};
use crate::middleware::Operator;
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
    // B-2：聚合逻辑已下沉至 DashboardService（handler 只做参数解析与响应封装）
    // 租户维度：None = 平台操作者（不过滤），Some(tid) = 仅本租户
    let tenant_scope = crate::common::tenant::tenant_scope(operator.tenant_id());
    let stats =
        crate::service::dashboard_service::DashboardService::dashboard_stats(&state, tenant_scope)
            .await;
    Ok(AjaxResult::success(stats))
}

// B-2：仪表盘/用户统计 VO 已下沉至 DashboardService，此处 re-export 供 utoipa 路径引用。
pub use crate::service::dashboard_service::{
    DashboardStatsVo, RecentOperLog, UserCreateTrendItem, UserStatsVo,
};

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
    // B-2：统计逻辑已下沉至 DashboardService（handler 只做参数解析与响应封装）
    // 租户维度：None = 平台操作者（不过滤），Some(tid) = 仅本租户
    let tenant_scope = crate::common::tenant::tenant_scope(operator.tenant_id());
    let stats =
        crate::service::dashboard_service::DashboardService::user_stats(&state, tenant_scope).await;
    Ok(AjaxResult::success(stats))
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
        // G-11：运行时解析存储后端（s3 档 + sys.upload.s3.* 覆盖生效时用运行时后端）
        state.resolve_storage().await?.as_ref(),
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
        .resolve_storage()
        .await?
        .read(&upload_cfg.common_dir, tenant_id, file_name)
        .await?
        .ok_or_else(|| AppError::not_found(&crate::tr!("error.common_handler.file_not_found")))?;

    // delete=true 时下载后删除原文件（后端删除幂等：不存在视为成功）
    if params.delete {
        state
            .resolve_storage()
            .await?
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
        .resolve_storage()
        .await?
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

    // 批次十八影响面修复：档位判定从启动期路由装配移到请求期——运行档为非静态
    // 后端（s3，文件由对象存储公开 URL 直出）时，/uploads/* 请求回落出厂本地后端
    // 读存量文件（读幂等，无"写新配置删旧对象"撕裂风险；s3-only 部署回落仍为 s3
    // → 404，与原先不挂载路由行为等价）
    let backend = state.resolve_storage().await?;
    let backend = if backend.supports_static() {
        backend
    } else {
        state.storage.clone()
    };
    let bytes = backend.read(&dir, tenant_id, key).await?.ok_or_else(|| {
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
