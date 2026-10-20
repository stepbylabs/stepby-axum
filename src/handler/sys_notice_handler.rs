//! 通知公告模块 Handler（Axum 原生实现）
//!
//! 接口路径对齐前端调用规范：
//! - GET    /system/notice/list            分页查询通知公告
//! - GET    /system/notice/listTop         首页顶部公告列表（带未读数）
//! - GET    /system/notice/{noticeId}      查询通知公告详情
//! - POST   /system/notice                 新增通知公告
//! - POST   /system/notice/markRead        标记公告已读
//! - POST   /system/notice/markReadAll     批量标记公告已读
//! - GET    /system/notice/readUsers/list  查询公告已读用户列表
//! - PUT    /system/notice                 修改通知公告
//! - DELETE /system/notice/{noticeIds}     批量删除通知公告

use axum::extract::{Path, Query, State};
use serde::Serialize;
use std::sync::Arc;
use utoipa::{IntoParams, ToSchema};

use crate::common::ValidatedJson;
use crate::common::constants::MAX_BATCH_DELETE_SIZE;
use crate::common::{AjaxResult, AppError, TableDataInfo};
use crate::entity::sys_notice::Model as SysNoticeModel;
use crate::middleware::Operator;
use crate::repository::sys_notice_read::NoticeReadUserVo;
use crate::service::sys_notice_service::{
    NoticeAddDto, NoticeEditDto, NoticeQueryDto, NoticeReadUserQueryDto, NoticeRowVo,
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
        (status = 200, description = "查询成功", body = TableDataInfo<NoticeRowVo>),
        (status = 500, description = "服务器错误"),
    ),
    tag = "system-notice"
)]
pub async fn list(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    Query(query): Query<NoticeQueryDto>,
) -> Result<TableDataInfo<NoticeRowVo>, AppError> {
    let user_id: i64 = parse_operator_id(&operator)?;
    let (rows, total) = state
        .notice_service
        .get_notice_page_with_read(query, operator.tenant_id(), user_id)
        .await?;
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
    operator: Operator,
    Path(notice_id): Path<i64>,
) -> Result<AjaxResult<SysNoticeModel>, AppError> {
    let model = state
        .notice_service
        .get_notice_by_id(notice_id, operator.tenant_id())
        .await?;
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
    // 提前取出公告标题（dto 将被 add_notice 按值消费）
    let notice_title = dto.notice_title.clone();
    state
        .notice_service
        .add_notice(dto, operator.username(), operator.tenant_id(), Some(&state))
        .await?;
    // Webhook 事件目录（开放域）：新增事务已提交，派发 notice.published
    // P0 跨租户修复：tenant_id 取操作者租户，事件仅投递给同租户回调
    crate::service::sys_web_hook_service::emit_event(
        &state,
        "notice.published",
        serde_json::json!({
            "noticeTitle": notice_title,
            "tenantId": operator.tenant_id(),
            "operator": operator.username(),
        }),
        operator.tenant_id(),
    )
    .await;
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
        .edit_notice(dto, operator.username(), operator.tenant_id())
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
    operator: Operator,
    Path(notice_ids): Path<String>,
) -> Result<AjaxResult<()>, AppError> {
    let ids: Vec<i64> = parse_id_list::<i64>(&notice_ids);

    if ids.is_empty() {
        return Err(AppError::bad_request(&crate::tr!(
            "error.notice.id_invalid"
        )));
    }

    if ids.len() > MAX_BATCH_DELETE_SIZE {
        return Err(AppError::bad_request(&crate::tr!(
            "error.common.batch_size_exceeded",
            max = MAX_BATCH_DELETE_SIZE
        )));
    }

    state
        .notice_service
        .delete_notice(ids, operator.username(), operator.tenant_id())
        .await?;
    Ok(AjaxResult::success_msg(&crate::tr!("msg.success.delete")))
}

/// 顶部公告响应 VO
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct NoticeTopVo {
    #[serde(flatten)]
    pub base: AjaxResult<Vec<NoticeRowVo>>,
    /// 未读数（可见面 = `status='0'` 且未读，与 `list?isRead=0&status=0` 的 total 同源）
    pub unread_count: u64,
    /// 可见公告总数（`status='0'`，不分页、不按已读/类型筛选）
    ///
    /// b80 新增：通知中心顶部三张卡片要同时显示"全部 / 未读 / 已读"，而列表的 `total`
    /// 会随筛选变化（'未读' 档下它就是未读数）——拿它减 unreadCount 会得到"已读 0"。
    /// 计数随本请求一起下发（同一次往返、同一谓词），比让前端再发一次计数请求更省，
    /// 也比让前端自己减更不易漂移。
    pub total_count: u64,
}

crate::impl_into_response!(NoticeTopVo);

/// GET /system/notice/listTop
/// 首页顶部公告列表（通知铃铛用，带未读数与可见总数）
#[utoipa::path(
    get,
    path = "/system/notice/listTop",
    responses(
        (status = 200, description = "顶部公告列表 + 当前用户未读数 + 可见总数", body = NoticeTopVo),
        (status = 500, description = "服务器错误"),
    ),
    tag = "system-notice"
)]
pub async fn list_top(
    State(state): State<Arc<AppState>>,
    operator: Operator,
) -> Result<NoticeTopVo, AppError> {
    let user_id: i64 = parse_operator_id(&operator)?;
    let rows = state
        .notice_service
        .get_notice_top_with_read(operator.tenant_id(), user_id)
        .await?;
    // 计数失败**不得**回落成 0：未读数为 0 会被渲染成"全部已读"的安全态并把
    // "全部已读"按钮禁用——查询出错与真的没有未读，对用户是两个相反的结论。
    let unread_count = state
        .notice_service
        .count_unread(user_id, operator.tenant_id())
        .await?;
    let total_count = state
        .notice_service
        .count_visible(operator.tenant_id())
        .await?;
    Ok(NoticeTopVo {
        base: AjaxResult::success(rows),
        unread_count,
        total_count,
    })
}

/// POST /system/notice/markRead
/// 标记公告已读
#[utoipa::path(
    post,
    path = "/system/notice/markRead",
    params(NoticeMarkReadParams),
    responses(
        (status = 200, description = "标记成功", body = AjaxResult<serde_json::Value>),
        (status = 400, description = "参数错误"),
    ),
    tag = "system-notice"
)]
pub async fn mark_read(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    Query(params): Query<NoticeMarkReadParams>,
) -> Result<AjaxResult<()>, AppError> {
    let user_id: i64 = parse_operator_id(&operator)?;
    state
        .notice_service
        .mark_read(params.notice_id, user_id, operator.tenant_id())
        .await?;
    Ok(AjaxResult::success_msg(&crate::tr!("msg.success.default")))
}

/// POST /system/notice/markReadAll
/// 批量标记公告已读
#[utoipa::path(
    post,
    path = "/system/notice/markReadAll",
    params(NoticeMarkReadAllParams),
    responses(
        (status = 200, description = "批量标记成功", body = AjaxResult<serde_json::Value>),
        (status = 400, description = "参数错误或 ID 列表超上限"),
    ),
    tag = "system-notice"
)]
pub async fn mark_read_all(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    Query(params): Query<NoticeMarkReadAllParams>,
) -> Result<AjaxResult<()>, AppError> {
    let user_id: i64 = parse_operator_id(&operator)?;
    // P1 修复：ids 条数上限（防恶意构造超长 ID 列表引发大查询）
    if !params.ids.trim().is_empty()
        && parse_id_list::<i64>(&params.ids).len() > MAX_BATCH_DELETE_SIZE
    {
        return Err(AppError::bad_request(&crate::tr!(
            "error.common.batch_size_exceeded",
            max = MAX_BATCH_DELETE_SIZE
        )));
    }
    state
        .notice_service
        .mark_read_all(&params.ids, user_id, operator.tenant_id())
        .await?;
    Ok(AjaxResult::success_msg(&crate::tr!("msg.success.default")))
}

/// POST /system/notice/markAllUnreadRead
/// 标记当前用户所有未读公告为已读（"全部已读"功能，跨页生效）
///
/// 与 markReadAll 的区别：markReadAll 需要前端传入具体 notice IDs，
/// 前端分页时只能拿到当前页的 ID；本接口服务端查询所有未读并标记，确保跨页未读也被清除。
#[utoipa::path(
    post,
    path = "/system/notice/markAllUnreadRead",
    responses(
        (status = 200, description = "已标记的未读数量", body = AjaxResult<u64>),
    ),
    tag = "system-notice"
)]
pub async fn mark_all_unread_read(
    State(state): State<Arc<AppState>>,
    operator: Operator,
) -> Result<AjaxResult<u64>, AppError> {
    let user_id: i64 = parse_operator_id(&operator)?;
    let count = state
        .notice_service
        .mark_all_unread_read(user_id, operator.tenant_id())
        .await?;
    Ok(AjaxResult::success(count))
}

/// 标记已读请求参数
#[derive(Debug, serde::Deserialize, IntoParams)]
#[serde(rename_all = "camelCase")]
pub struct NoticeMarkReadParams {
    pub notice_id: i64,
}

/// 批量标记已读请求参数
#[derive(Debug, serde::Deserialize, IntoParams)]
#[serde(rename_all = "camelCase")]
pub struct NoticeMarkReadAllParams {
    pub ids: String,
}

/// GET /system/notice/readUsers/list
/// 查询公告已读用户列表
#[utoipa::path(
    get,
    path = "/system/notice/readUsers/list",
    params(NoticeReadUserQueryDto),
    responses(
        (status = 200, description = "公告已读用户分页列表", body = TableDataInfo<NoticeReadUserVo>),
        (status = 500, description = "服务器错误"),
    ),
    tag = "system-notice"
)]
pub async fn list_read_users(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    Query(query): Query<NoticeReadUserQueryDto>,
) -> Result<TableDataInfo<NoticeReadUserVo>, AppError> {
    // M1 脱敏影响面补齐：phonenumber 按三口径掩码（operator_user_id 参与本人行判定）
    let operator_user_id = operator.user_id().parse::<i64>().ok();
    let (rows, total) = state
        .notice_service
        .get_read_users_page(query, operator_user_id, operator.tenant_id())
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
