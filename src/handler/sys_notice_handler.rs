//! 通知公告模块 Handler（Axum 原生实现）
//!
//! 接口路径对齐 ruoyi-vue3-ts 前端：
//! - GET    /system/notice/list            分页查询通知公告
//! - GET    /system/notice/listTop         首页顶部公告列表（带未读数）
//! - GET    /system/notice/{noticeId}      查询通知公告详情
//! - POST   /system/notice                 新增通知公告
//! - POST   /system/notice/markRead        标记公告已读
//! - POST   /system/notice/markReadAll     批量标记公告已读
//! - GET    /system/notice/readUsers/list  查询公告已读用户列表
//! - PUT    /system/notice                 修改通知公告
//! - DELETE /system/notice/{noticeIds}     批量删除通知公告

use std::sync::Arc;
use axum::extract::{Path, Query, State};
use serde::Serialize;

use crate::common::constants::MAX_BATCH_DELETE_SIZE;
use crate::common::ValidatedJson;
use crate::common::{AjaxResult, AppError, TableDataInfo};
use crate::entity::sys_notice::Model as SysNoticeModel;
use crate::middleware::Operator;
use crate::repository::sys_notice_read::NoticeReadUserVo;
use crate::service::sys_notice_service::{
    NoticeAddDto, NoticeEditDto, NoticeQueryDto, NoticeReadUserQueryDto,
};
use crate::state::AppState;
use crate::utils::parse_id_list;

/// GET /system/notice/list
/// 分页查询通知公告
#[utoipa::path(
    get,
    path = "/system/notice/list",
    params(NoticeQueryDto),
    responses(
        (status = 200, description = "查询成功", body = TableDataInfo<SysNoticeModel>),
        (status = 500, description = "服务器错误"),
    ),
    tag = "system-notice"
)]
pub async fn list(
    State(state): State<Arc<AppState>>,
    Query(query): Query<NoticeQueryDto>,
) -> Result<TableDataInfo<SysNoticeModel>, AppError> {
    let (rows, total) = state.notice_service.get_notice_page(query).await?;
    Ok(TableDataInfo::new(total, rows))
}

/// GET /system/notice/{noticeId}
/// 查询通知公告详情
#[utoipa::path(
    get,
    path = "/system/notice/{noticeId}",
    params(
        ("noticeId" = i64, Path, description = "通知公告 ID")
    ),
    responses(
        (status = 200, description = "查询成功", body = AjaxResult<SysNoticeModel>),
        (status = 404, description = "通知公告不存在"),
    ),
    tag = "system-notice"
)]
pub async fn get_info(
    State(state): State<Arc<AppState>>,
    Path(notice_id): Path<i64>,
) -> Result<AjaxResult<SysNoticeModel>, AppError> {
    let model = state.notice_service.get_notice_by_id(notice_id).await?;
    Ok(AjaxResult::success(model))
}

/// POST /system/notice
/// 新增通知公告
#[utoipa::path(
    post,
    path = "/system/notice",
    request_body = NoticeAddDto,
    responses(
        (status = 200, description = "新增成功", body = AjaxResult<serde_json::Value>),
        (status = 400, description = "参数错误"),
    ),
    tag = "system-notice"
)]
pub async fn add(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    ValidatedJson(dto): ValidatedJson<NoticeAddDto>,
) -> Result<AjaxResult<()>, AppError> {
    state
        .notice_service
        .add_notice(dto, operator.username(), Some(&state))
        .await?;
    Ok(AjaxResult::success_msg(&crate::tr!("msg.success.add")))
}

/// PUT /system/notice
/// 修改通知公告
#[utoipa::path(
    put,
    path = "/system/notice",
    request_body = NoticeEditDto,
    responses(
        (status = 200, description = "修改成功", body = AjaxResult<serde_json::Value>),
        (status = 400, description = "参数错误"),
        (status = 404, description = "通知公告不存在"),
    ),
    tag = "system-notice"
)]
pub async fn edit(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    ValidatedJson(dto): ValidatedJson<NoticeEditDto>,
) -> Result<AjaxResult<()>, AppError> {
    state
        .notice_service
        .edit_notice(dto, operator.username())
        .await?;
    Ok(AjaxResult::success_msg(&crate::tr!("msg.success.edit")))
}

/// DELETE /system/notice/{noticeIds}
/// 批量删除通知公告（noticeIds 为逗号分隔的 ID 字符串，物理删除）
#[utoipa::path(
    delete,
    path = "/system/notice/{noticeIds}",
    params(
        ("noticeIds" = String, Path, description = "通知公告 ID 列表（逗号分隔）")
    ),
    responses(
        (status = 200, description = "删除成功", body = AjaxResult<serde_json::Value>),
        (status = 400, description = "通知公告 ID 不合法"),
    ),
    tag = "system-notice"
)]
pub async fn remove(
    State(state): State<Arc<AppState>>,
    Path(notice_ids): Path<String>,
) -> Result<AjaxResult<()>, AppError> {
    let ids: Vec<i64> = parse_id_list::<i64>(&notice_ids);

    if ids.is_empty() {
        return Err(AppError::bad_request(&crate::tr!("error.notice.id_invalid")));
    }

    if ids.len() > MAX_BATCH_DELETE_SIZE {
        return Err(AppError::bad_request(&crate::tr!(
            "error.common.batch_size_exceeded",
            max = MAX_BATCH_DELETE_SIZE
        )));
    }

    state.notice_service.delete_notice(ids).await?;
    Ok(AjaxResult::success_msg(&crate::tr!("msg.success.delete")))
}

/// 顶部公告响应 VO
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NoticeTopVo {
    #[serde(flatten)]
    pub base: AjaxResult<Vec<SysNoticeModel>>,
    pub unread_count: u64,
}

crate::impl_into_response!(NoticeTopVo);

/// GET /system/notice/listTop
/// 首页顶部公告列表（通知铃铛用，带未读数）
pub async fn list_top(
    State(state): State<Arc<AppState>>,
    operator: Operator,
) -> Result<NoticeTopVo, AppError> {
    let rows = state.notice_service.get_notice_top().await?;
    let user_id: i64 = parse_operator_id(&operator)?;
    let unread_count = state
        .notice_service
        .count_unread(user_id)
        .await
        .unwrap_or(0);
    Ok(NoticeTopVo {
        base: AjaxResult::success(rows),
        unread_count,
    })
}

/// POST /system/notice/markRead
/// 标记公告已读
pub async fn mark_read(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    Query(params): Query<NoticeMarkReadParams>,
) -> Result<AjaxResult<()>, AppError> {
    let user_id: i64 = parse_operator_id(&operator)?;
    state
        .notice_service
        .mark_read(params.notice_id, user_id)
        .await?;
    Ok(AjaxResult::success_msg(&crate::tr!("msg.success.default")))
}

/// POST /system/notice/markReadAll
/// 批量标记公告已读
pub async fn mark_read_all(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    Query(params): Query<NoticeMarkReadAllParams>,
) -> Result<AjaxResult<()>, AppError> {
    let user_id: i64 = parse_operator_id(&operator)?;
    state
        .notice_service
        .mark_read_all(&params.ids, user_id)
        .await?;
    Ok(AjaxResult::success_msg(&crate::tr!("msg.success.default")))
}

/// POST /system/notice/markAllUnreadRead
/// 标记当前用户所有未读公告为已读（"全部已读"功能，跨页生效）
///
/// 与 markReadAll 的区别：markReadAll 需要前端传入具体 notice IDs，
/// 前端分页时只能拿到当前页的 ID；本接口服务端查询所有未读并标记，确保跨页未读也被清除。
pub async fn mark_all_unread_read(
    State(state): State<Arc<AppState>>,
    operator: Operator,
) -> Result<AjaxResult<u64>, AppError> {
    let user_id: i64 = parse_operator_id(&operator)?;
    let count = state
        .notice_service
        .mark_all_unread_read(user_id)
        .await?;
    Ok(AjaxResult::success(count))
}

/// 标记已读请求参数
#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NoticeMarkReadParams {
    pub notice_id: i64,
}

/// 批量标记已读请求参数
#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NoticeMarkReadAllParams {
    pub ids: String,
}

/// GET /system/notice/readUsers/list
/// 查询公告已读用户列表
pub async fn list_read_users(
    State(state): State<Arc<AppState>>,
    Query(query): Query<NoticeReadUserQueryDto>,
) -> Result<TableDataInfo<NoticeReadUserVo>, AppError> {
    let (rows, total) = state
        .notice_service
        .get_read_users_page(query)
        .await?;
    Ok(TableDataInfo::new(total, rows))
}

/// 从 Operator 解析 user_id（fail-closed）
///
/// P1 修复：解析失败返回错误而非静默回退 0，
/// 避免 user_id 解析异常时以 0 身份误标记/查询他人已读记录。
fn parse_operator_id(operator: &Operator) -> Result<i64, AppError> {
    operator
        .user_id()
        .parse::<i64>()
        .map_err(|_| AppError::internal(&crate::tr!("error.auth.user_id_parse_failed")))
}
