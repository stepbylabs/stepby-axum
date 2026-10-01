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

use std::sync::Arc;

use axum::Json;
use axum::extract::{Path, Query, State};

use crate::common::{AjaxResult, AppError, TableDataInfo};
use crate::middleware::Operator;
use crate::service::sys_pat_service::{CreatePatDto, CreatePatResult, PatVo};
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
