//! 报表看板 Handler（Axum 原生实现，配置化只读报表 v1）
//!
//! 接口路径（受保护，权限 tool:reportBoard:list / tool:reportBoard:save）：
//! - GET    /tool/report-board/list              本人看板清单
//! - POST   /tool/report-board                   创建看板（save 权限）
//! - GET    /tool/report-board/{boardId}         看板详情（仅本人，404 语义）
//! - PUT    /tool/report-board/{boardId}         更新看板（save 权限，仅本人）
//! - DELETE /tool/report-board/{boardId}         删除看板（save 权限，仅本人）
//! - GET    /tool/report-board/sources           可用数据源清单（白名单）
//! - GET    /tool/report-board/data/{sourceKey}  数据源数据（range=7d|30d）
//!
//! 安全要点：
//! - 配置强类型校验 + 数据源白名单（杜绝任意 URL/SQL 注入面）
//! - v1 仅本人可读写：所有查询按 operator user_id 过滤，他人/不存在统一 404

use std::sync::Arc;

use axum::Json;
use axum::extract::{Path, Query, State};
use serde::Deserialize;

use crate::common::{AjaxResult, AppError};
use crate::middleware::Operator;
use crate::service::sys_report_board_service::{
    BoardCreateDto, BoardUpdateDto, BoardVo, SourceDataVo, SourceMetaVo,
};
use crate::state::AppState;

/// 数据端点查询参数（range=7d|30d）
#[derive(Debug, Deserialize, utoipa::IntoParams)]
#[serde(rename_all = "camelCase")]
pub struct SourceDataParams {
    /// 时间范围（7d / 30d；时点类数据源忽略该参数）
    #[serde(default = "default_range")]
    pub range: String,
}

fn default_range() -> String {
    "7d".to_string()
}

/// 解析 Operator 携带的 user_id（JWT sub，字符串）为 i64
fn parse_user_id(sub: &str) -> Result<i64, AppError> {
    sub.parse::<i64>()
        .map_err(|_| AppError::unauthorized(&crate::tr!("error.auth.login_info_missing")))
}

/// GET /tool/report-board/list — 本人看板清单
#[utoipa::path(
    get,
    path = "/tool/report-board/list",
    responses(
        (status = 200, description = "本人看板清单", body = AjaxResult<Vec<BoardVo>>),
        (status = 401, description = "未授权"),
    ),
    tag = "tool-report-board"
)]
pub async fn board_list(
    State(state): State<Arc<AppState>>,
    operator: Operator,
) -> Result<AjaxResult<Vec<BoardVo>>, AppError> {
    let user_id = parse_user_id(operator.user_id())?;
    let vos = state.report_board_service.list(user_id).await?;
    Ok(AjaxResult::success(vos))
}

/// POST /tool/report-board — 创建看板
#[utoipa::path(
    post,
    path = "/tool/report-board",
    request_body = BoardCreateDto,
    responses(
        (status = 200, description = "创建后的看板", body = AjaxResult<BoardVo>),
        (status = 400, description = "参数错误（名称/启用状态/配置不合法或同名）"),
        (status = 401, description = "未授权"),
    ),
    tag = "tool-report-board"
)]
pub async fn board_add(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    Json(dto): Json<BoardCreateDto>,
) -> Result<AjaxResult<BoardVo>, AppError> {
    let user_id = parse_user_id(operator.user_id())?;
    let vo = state
        .report_board_service
        .create(user_id, operator.tenant_id(), dto)
        .await?;
    Ok(AjaxResult::success(vo))
}

/// GET /tool/report-board/{boardId} — 看板详情（仅本人）
#[utoipa::path(
    get,
    path = "/tool/report-board/{boardId}",
    params(("boardId" = i64, Path, description = "看板 ID")),
    responses(
        (status = 200, description = "看板详情", body = AjaxResult<BoardVo>),
        (status = 404, description = "看板不存在或非本人"),
        (status = 401, description = "未授权"),
    ),
    tag = "tool-report-board"
)]
pub async fn board_info(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    Path(board_id): Path<i64>,
) -> Result<AjaxResult<BoardVo>, AppError> {
    let user_id = parse_user_id(operator.user_id())?;
    let vo = state.report_board_service.get(board_id, user_id).await?;
    Ok(AjaxResult::success(vo))
}

/// PUT /tool/report-board/{boardId} — 更新看板（部分更新；config 提供时全量覆盖）
#[utoipa::path(
    put,
    path = "/tool/report-board/{boardId}",
    params(("boardId" = i64, Path, description = "看板 ID")),
    request_body = BoardUpdateDto,
    responses(
        (status = 200, description = "更新后的看板", body = AjaxResult<BoardVo>),
        (status = 400, description = "参数错误（名称/启用状态/配置不合法或同名）"),
        (status = 404, description = "看板不存在或非本人"),
        (status = 401, description = "未授权"),
    ),
    tag = "tool-report-board"
)]
pub async fn board_edit(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    Path(board_id): Path<i64>,
    Json(dto): Json<BoardUpdateDto>,
) -> Result<AjaxResult<BoardVo>, AppError> {
    let user_id = parse_user_id(operator.user_id())?;
    let vo = state
        .report_board_service
        .update(board_id, user_id, dto)
        .await?;
    Ok(AjaxResult::success(vo))
}

/// DELETE /tool/report-board/{boardId} — 删除看板（仅本人）
#[utoipa::path(
    delete,
    path = "/tool/report-board/{boardId}",
    params(("boardId" = i64, Path, description = "看板 ID")),
    responses(
        (status = 200, description = "删除成功"),
        (status = 404, description = "看板不存在或非本人"),
        (status = 401, description = "未授权"),
    ),
    tag = "tool-report-board"
)]
pub async fn board_remove(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    Path(board_id): Path<i64>,
) -> Result<AjaxResult<()>, AppError> {
    let user_id = parse_user_id(operator.user_id())?;
    state.report_board_service.delete(board_id, user_id).await?;
    Ok(AjaxResult::success_msg(&crate::tr!("msg.success.default")))
}

/// GET /tool/report-board/sources — 可用数据源清单（白名单）
#[utoipa::path(
    get,
    path = "/tool/report-board/sources",
    responses(
        (status = 200, description = "数据源清单", body = AjaxResult<Vec<SourceMetaVo>>),
        (status = 401, description = "未授权"),
    ),
    tag = "tool-report-board"
)]
pub async fn source_list(
    State(state): State<Arc<AppState>>,
) -> Result<AjaxResult<Vec<SourceMetaVo>>, AppError> {
    Ok(AjaxResult::success(
        state.report_board_service.available_sources(),
    ))
}

/// GET /tool/report-board/data/{sourceKey}?range=7d|30d — 数据源数据
#[utoipa::path(
    get,
    path = "/tool/report-board/data/{sourceKey}",
    params(
        ("sourceKey" = String, Path, description = "数据源标识（白名单内）"),
        ("range" = String, Query, description = "时间范围 7d/30d"),
    ),
    responses(
        (status = 200, description = "数据源数据", body = AjaxResult<SourceDataVo>),
        (status = 400, description = "白名单外数据源或 range 不合法"),
        (status = 401, description = "未授权"),
    ),
    tag = "tool-report-board"
)]
pub async fn source_data(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    Path(source_key): Path<String>,
    Query(params): Query<SourceDataParams>,
) -> Result<AjaxResult<SourceDataVo>, AppError> {
    let days = crate::service::sys_report_board_service::parse_range_days(&params.range)?;
    let vo = state
        .report_board_service
        .resolve_source(&source_key, days, operator.tenant_id())
        .await?;
    Ok(AjaxResult::success(vo))
}
