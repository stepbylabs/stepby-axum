//! 个人访问令牌（PAT）Handler（Axum 原生实现）
//!
//! 自助接口（仅需登录，恒操作当前用户本人，加入 is_login_only_path 白名单）：
//! - GET    /system/user/profile/tokens            我的令牌列表
//! - GET    /system/user/profile/tokens/scopes     我可授予的 scope 选项
//! - POST   /system/user/profile/tokens            新建令牌（返回一次性明文）
//! - DELETE /system/user/profile/tokens/{patId}    吊销我的令牌
//!
//! 管理接口（RBAC monitor:pat:list / monitor:pat:revoke）：
//! - GET    /monitor/pat/list                      全量令牌列表
//! - DELETE /monitor/pat/{patId}                   吊销任意令牌
//!
//! 开放 API AK/SK 域（自助，仅本人 PAT；敏感操作独立限流）：
//! - POST   /system/pat/{patId}/rotate-ak          轮换 SK（新明文仅此一次返回）
//! - POST   /system/pat/{patId}/revoke-ak          清空 AK/SK

use std::sync::Arc;

use axum::Json;
use axum::extract::{Path, Query, State};

use crate::common::{AjaxResult, AppError, TableDataInfo};
use crate::middleware::Operator;
use crate::service::sys_pat_service::{
    CreatePatDto, CreatePatResult, PatVo, RotateAkResult,
};
use crate::state::AppState;

/// 解析 Operator.user_id（JWT sub）为 i64
fn parse_user_id(sub: &str) -> Result<i64, AppError> {
    sub.parse::<i64>()
        .map_err(|_| AppError::unauthorized(&crate::tr!("error.auth.login_info_missing")))
}

/// 分页查询参数
#[derive(Debug, serde::Deserialize, utoipa::IntoParams)]
#[serde(rename_all = "camelCase")]
pub struct PatPageQuery {
    #[serde(default = "default_page_num")]
    pub page_num: u64,
    #[serde(default = "default_page_size")]
    pub page_size: u64,
}

/// 管理列表查询参数（可选按属主过滤）
#[derive(Debug, serde::Deserialize, utoipa::IntoParams)]
#[serde(rename_all = "camelCase")]
pub struct PatAdminQuery {
    #[serde(default = "default_page_num")]
    pub page_num: u64,
    #[serde(default = "default_page_size")]
    pub page_size: u64,
    #[serde(default)]
    pub user_id: Option<i64>,
}

fn default_page_num() -> u64 {
    1
}
fn default_page_size() -> u64 {
    10
}

/// GET /system/user/profile/tokens
#[utoipa::path(
    get,
    path = "/system/user/profile/tokens",
    params(PatPageQuery),
    responses(
        (status = 200, description = "查询成功", body = TableDataInfo<PatVo>),
    ),
    tag = "pat"
)]
pub async fn list_mine(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    Query(q): Query<PatPageQuery>,
) -> Result<TableDataInfo<PatVo>, AppError> {
    let user_id = parse_user_id(operator.user_id())?;
    let (rows, total) = state
        .pat_service
        .list_mine(user_id, q.page_num, q.page_size)
        .await?;
    Ok(TableDataInfo::new(total, rows))
}

/// GET /system/user/profile/tokens/scopes
#[utoipa::path(
    get,
    path = "/system/user/profile/tokens/scopes",
    responses(
        (status = 200, description = "查询成功", body = AjaxResult<Vec<String>>),
    ),
    tag = "pat"
)]
pub async fn scope_options(
    State(state): State<Arc<AppState>>,
    operator: Operator,
) -> Result<AjaxResult<Vec<String>>, AppError> {
    let user_id = parse_user_id(operator.user_id())?;
    let opts = state.pat_service.scope_options(user_id).await?;
    Ok(AjaxResult::success(opts))
}

/// POST /system/user/profile/tokens
#[utoipa::path(
    post,
    path = "/system/user/profile/tokens",
    request_body = CreatePatDto,
    responses(
        (status = 200, description = "创建成功（token 明文仅此一次返回）", body = AjaxResult<CreatePatResult>),
        (status = 400, description = "参数非法"),
    ),
    tag = "pat"
)]
pub async fn create(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    Json(dto): Json<CreatePatDto>,
) -> Result<AjaxResult<CreatePatResult>, AppError> {
    let user_id = parse_user_id(operator.user_id())?;
    let result = state
        .pat_service
        .create(
            user_id,
            operator.tenant_id(),
            operator.username(),
            dto,
            &state.config.pat,
            // SK 信封加密主密钥（与 oauth client_secret 同机制）
            &state.config.config_enc_key,
        )
        .await?;
    Ok(AjaxResult::success(result))
}

/// DELETE /system/user/profile/tokens/{patId}
#[utoipa::path(
    delete,
    path = "/system/user/profile/tokens/{patId}",
    params(("patId" = String, Path, description = "令牌 ID")),
    responses(
        (status = 200, description = "吊销成功", body = AjaxResult<serde_json::Value>),
        (status = 404, description = "令牌不存在"),
    ),
    tag = "pat"
)]
pub async fn revoke_mine(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    Path(pat_id): Path<String>,
) -> Result<AjaxResult<()>, AppError> {
    let user_id = parse_user_id(operator.user_id())?;
    state.pat_service.revoke_mine(&pat_id, user_id).await?;
    Ok(AjaxResult::success_msg(&crate::tr!("msg.success.delete")))
}

/// GET /monitor/pat/list
#[utoipa::path(
    get,
    path = "/monitor/pat/list",
    params(PatAdminQuery),
    responses(
        (status = 200, description = "查询成功", body = TableDataInfo<PatVo>),
    ),
    tag = "pat"
)]
pub async fn list_all(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    Query(q): Query<PatAdminQuery>,
) -> Result<TableDataInfo<PatVo>, AppError> {
    // 多租户：租户操作者仅见本租户令牌；平台操作者全量（tenant_id=0 → None）
    let tenant_scope = crate::common::tenant::tenant_scope(operator.tenant_id());
    let (rows, total) = state
        .pat_service
        .list_all(q.user_id, q.page_num, q.page_size, tenant_scope)
        .await?;
    Ok(TableDataInfo::new(total, rows))
}

/// DELETE /monitor/pat/{patId}
#[utoipa::path(
    delete,
    path = "/monitor/pat/{patId}",
    params(("patId" = String, Path, description = "令牌 ID")),
    responses(
        (status = 200, description = "吊销成功", body = AjaxResult<serde_json::Value>),
        (status = 404, description = "令牌不存在"),
    ),
    tag = "pat"
)]
pub async fn revoke_by_admin(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    Path(pat_id): Path<String>,
) -> Result<AjaxResult<()>, AppError> {
    // 多租户：租户操作者仅能吊销本租户令牌；平台（tenant_id=0）不限
    state
        .pat_service
        .revoke_by_admin(&pat_id, operator.tenant_id())
        .await?;
    Ok(AjaxResult::success_msg(&crate::tr!("msg.success.delete")))
}

// ══ 开放 API AK/SK 域（自助：仅本人 PAT）══

/// AK 敏感操作独立限流桶：每用户每小时最多 10 次（rotate/revoke 各自独立计数）
///
/// 键：`rate_limit:pat_ak:{user_id}:{op}`，走 SharedStore `incr_with_ttl`
/// （INCR + 首次 EXPIRE 原子语义，与登录失败计数/TOTP 失败计数同范式，
/// 禁止裸 Redis 调用）。存储故障 fail-closed 返回 503。
async fn enforce_ak_sensitive_limit(
    state: &AppState,
    user_id: i64,
    op: &str,
) -> Result<(), AppError> {
    const LIMIT: i64 = 10;
    const WINDOW_SECS: u64 = 3600;
    let key = format!("rate_limit:pat_ak:{}:{}", user_id, op);
    let count = state
        .store
        .incr_with_ttl(&key, WINDOW_SECS)
        .await
        .map_err(|e| {
            tracing::error!("AK 敏感操作限流计数失败（fail-closed）: {}", e);
            AppError::new(503, crate::tr!("error.ak.store_unavailable"))
        })?;
    if count > LIMIT {
        return Err(AppError::new(429, crate::tr!("error.ak.rate_limited")));
    }
    Ok(())
}

/// POST /system/pat/{patId}/rotate-ak：轮换开放 API SK（新明文仅此一次返回）
///
/// - 未开通 AK 的 PAT → 404 语义错误；
/// - 敏感操作独立限流（每用户 10 次/小时）。
#[utoipa::path(
    post,
    path = "/system/pat/{patId}/rotate-ak",
    params(("patId" = String, Path, description = "令牌 ID")),
    responses(
        (status = 200, description = "轮换成功（新 SK 明文仅此一次返回）", body = AjaxResult<RotateAkResult>),
        (status = 404, description = "令牌不存在或未开通 AK"),
        (status = 429, description = "操作过于频繁"),
    ),
    tag = "pat"
)]
pub async fn rotate_ak(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    Path(pat_id): Path<String>,
) -> Result<AjaxResult<RotateAkResult>, AppError> {
    let user_id = parse_user_id(operator.user_id())?;
    enforce_ak_sensitive_limit(&state, user_id, "rotate").await?;
    let result = state
        .pat_service
        .rotate_ak(&pat_id, user_id, &state.config.config_enc_key)
        .await?;
    Ok(AjaxResult::success(result))
}

/// POST /system/pat/{patId}/revoke-ak：吊销开放 API AK/SK（清空两列，幂等）
///
/// 敏感操作独立限流（每用户 10 次/小时，与轮换分桶）。
#[utoipa::path(
    post,
    path = "/system/pat/{patId}/revoke-ak",
    params(("patId" = String, Path, description = "令牌 ID")),
    responses(
        (status = 200, description = "吊销成功"),
        (status = 404, description = "令牌不存在"),
        (status = 429, description = "操作过于频繁"),
    ),
    tag = "pat"
)]
pub async fn revoke_ak(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    Path(pat_id): Path<String>,
) -> Result<AjaxResult<()>, AppError> {
    let user_id = parse_user_id(operator.user_id())?;
    enforce_ak_sensitive_limit(&state, user_id, "revoke").await?;
    state.pat_service.revoke_ak(&pat_id, user_id).await?;
    Ok(AjaxResult::success_msg(&crate::tr!("msg.success.delete")))
}
