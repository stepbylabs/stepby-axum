//! 消息渠道与模板管理模块 Handler（Axum 原生实现）
//!
//! 接口路径对齐前端调用规范（前缀 /system/msg）：
//! - GET    /system/msg/channel/list             分页查询消息渠道
//! - GET    /system/msg/channel/{channelId}      查询渠道详情
//! - POST   /system/msg/channel                  新增消息渠道
//! - PUT    /system/msg/channel                  修改消息渠道
//! - DELETE /system/msg/channel/{channelIds}     批量删除消息渠道
//! - POST   /system/msg/channel/test/{channelId} 渠道连通性测试
//! - GET    /system/msg/template/list            分页查询消息模板
//! - GET    /system/msg/template/{templateId}    查询模板详情
//! - POST   /system/msg/template                 新增消息模板
//! - PUT    /system/msg/template                 修改消息模板
//! - DELETE /system/msg/template/{templateIds}   批量删除消息模板
//! - GET    /system/msg/log/list                 分页查询发送记录
//! - DELETE /system/msg/log/{logIds}             批量删除发送记录
//! - DELETE /system/msg/log/clean                清空发送记录
//! - POST   /system/msg/send                     直接发送（按模板 + 渠道 + 参数）
//! - POST   /system/msg/log/retry/{logIds}       重试指定发送记录
//! - POST   /system/msg/log/retryPending/{batch} 触发待重试批次批量重试
//! - POST   /system/msg/log/markPending/{logIds} 将发送记录标记为待重试

use axum::extract::{Path, Query, State};
use std::sync::Arc;

use crate::common::ValidatedJson;
use crate::common::constants::MAX_BATCH_DELETE_SIZE;
use crate::common::{AjaxResult, AppError, TableDataInfo};
use crate::entity::sys_msg_send_log::Model as SysMsgSendLogModel;
use crate::entity::sys_msg_template::Model as SysMsgTemplateModel;
use crate::middleware::Operator;
use crate::service::sys_msg_service::{
    ChannelAddDto, ChannelEditDto, ChannelQueryDto, ChannelVo, SendDto, SendLogQueryDto,
    TemplateAddDto, TemplateEditDto, TemplateQueryDto,
};
use crate::state::AppState;

// ==================== 消息渠道 ====================

/// GET /system/msg/channel/list
/// 分页查询消息渠道
#[utoipa::path(
    get,
    path = "/system/msg/channel/list",
    params(ChannelQueryDto),
    responses(
        (status = 200, description = "查询成功", body = TableDataInfo<ChannelVo>),
        (status = 500, description = "服务器错误"),
    ),
    tag = "system-msg"
)]
pub async fn channel_list(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    Query(query): Query<ChannelQueryDto>,
) -> Result<TableDataInfo<ChannelVo>, AppError> {
    let (rows, total) = state
        .msg_service
        .get_channel_page(query, operator.tenant_id())
        .await?;
    Ok(TableDataInfo::new(total, rows))
}

/// GET /system/msg/channel/{channelId}
/// 查询渠道详情
#[utoipa::path(
    get,
    path = "/system/msg/channel/{channelId}",
    params(("channelId" = i64, Path, description = "渠道 ID")),
    responses(
        (status = 200, description = "查询成功", body = AjaxResult<ChannelVo>),
        (status = 404, description = "渠道不存在"),
    ),
    tag = "system-msg"
)]
pub async fn channel_info(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    Path(channel_id): Path<i64>,
) -> Result<AjaxResult<ChannelVo>, AppError> {
    let model = state
        .msg_service
        .get_channel_by_id(channel_id, operator.tenant_id())
        .await?;
    Ok(AjaxResult::success(model))
}

/// POST /system/msg/channel
/// 新增消息渠道
#[utoipa::path(
    post,
    path = "/system/msg/channel",
    request_body = ChannelAddDto,
    responses(
        (status = 200, description = "新增成功", body = AjaxResult<ChannelVo>),
        (status = 400, description = "参数错误"),
    ),
    tag = "system-msg"
)]
pub async fn channel_add(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    ValidatedJson(dto): ValidatedJson<ChannelAddDto>,
) -> Result<AjaxResult<ChannelVo>, AppError> {
    let model = state
        .msg_service
        .add_channel(dto, operator.username(), operator.tenant_id())
        .await?;
    Ok(AjaxResult::success(model))
}

/// PUT /system/msg/channel
/// 修改消息渠道
#[utoipa::path(
    put,
    path = "/system/msg/channel",
    request_body = ChannelEditDto,
    responses(
        (status = 200, description = "修改成功", body = AjaxResult<ChannelVo>),
        (status = 400, description = "参数错误"),
        (status = 404, description = "渠道不存在"),
    ),
    tag = "system-msg"
)]
pub async fn channel_edit(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    ValidatedJson(dto): ValidatedJson<ChannelEditDto>,
) -> Result<AjaxResult<ChannelVo>, AppError> {
    let model = state
        .msg_service
        .edit_channel(dto, operator.username(), operator.tenant_id())
        .await?;
    Ok(AjaxResult::success(model))
}

/// DELETE /system/msg/channel/{channelIds}
/// 批量删除消息渠道
#[utoipa::path(
    delete,
    path = "/system/msg/channel/{channelIds}",
    params(("channelIds" = String, Path, description = "渠道 ID 列表（逗号分隔）")),
    responses(
        (status = 200, description = "删除成功"),
        (status = 400, description = "参数错误"),
    ),
    tag = "system-msg"
)]
pub async fn channel_remove(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    Path(ids): Path<String>,
) -> Result<AjaxResult<()>, AppError> {
    let ids = crate::service::SysMsgService::parse_ids(&ids);
    if ids.is_empty() {
        return Err(AppError::bad_request(&crate::tr!(
            "error.msg.channel_id_invalid"
        )));
    }
    if ids.len() > MAX_BATCH_DELETE_SIZE {
        return Err(AppError::bad_request(&crate::tr!(
            "error.common.batch_size_exceeded",
            max = MAX_BATCH_DELETE_SIZE
        )));
    }
    state
        .msg_service
        .delete_channel(ids, operator.tenant_id())
        .await?;
    Ok(AjaxResult::success_msg(&crate::tr!("msg.success.delete")))
}

/// POST /system/msg/channel/test/{channelId}
/// 渠道连通性测试
#[utoipa::path(
    post,
    path = "/system/msg/channel/test/{channelId}",
    params(("channelId" = i64, Path, description = "渠道 ID")),
    responses(
        (status = 200, description = "测试成功"),
        (status = 400, description = "测试失败"),
    ),
    tag = "system-msg"
)]
pub async fn channel_test(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    Path(channel_id): Path<i64>,
) -> Result<AjaxResult<()>, AppError> {
    state
        .msg_service
        .test_channel(channel_id, operator.tenant_id())
        .await?;
    Ok(AjaxResult::success_msg(&crate::tr!("msg.success.test")))
}

// ==================== 消息模板 ====================

/// GET /system/msg/template/list
/// 分页查询消息模板
#[utoipa::path(
    get,
    path = "/system/msg/template/list",
    params(TemplateQueryDto),
    responses(
        (status = 200, description = "查询成功", body = TableDataInfo<SysMsgTemplateModel>),
        (status = 500, description = "服务器错误"),
    ),
    tag = "system-msg"
)]
pub async fn template_list(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    Query(query): Query<TemplateQueryDto>,
) -> Result<TableDataInfo<SysMsgTemplateModel>, AppError> {
    let (rows, total) = state
        .msg_service
        .get_template_page(query, operator.tenant_id())
        .await?;
    Ok(TableDataInfo::new(total, rows))
}

/// GET /system/msg/template/{templateId}
/// 查询模板详情
#[utoipa::path(
    get,
    path = "/system/msg/template/{templateId}",
    params(("templateId" = i64, Path, description = "模板 ID")),
    responses(
        (status = 200, description = "查询成功", body = AjaxResult<SysMsgTemplateModel>),
        (status = 404, description = "模板不存在"),
    ),
    tag = "system-msg"
)]
pub async fn template_info(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    Path(template_id): Path<i64>,
) -> Result<AjaxResult<SysMsgTemplateModel>, AppError> {
    let model = state
        .msg_service
        .get_template_by_id(template_id, operator.tenant_id())
        .await?;
    Ok(AjaxResult::success(model))
}

/// POST /system/msg/template
/// 新增消息模板
#[utoipa::path(
    post,
    path = "/system/msg/template",
    request_body = TemplateAddDto,
    responses(
        (status = 200, description = "新增成功", body = AjaxResult<SysMsgTemplateModel>),
        (status = 400, description = "参数错误"),
    ),
    tag = "system-msg"
)]
pub async fn template_add(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    ValidatedJson(dto): ValidatedJson<TemplateAddDto>,
) -> Result<AjaxResult<SysMsgTemplateModel>, AppError> {
    let model = state
        .msg_service
        .add_template(dto, operator.username(), operator.tenant_id())
        .await?;
    Ok(AjaxResult::success(model))
}

/// PUT /system/msg/template
/// 修改消息模板
#[utoipa::path(
    put,
    path = "/system/msg/template",
    request_body = TemplateEditDto,
    responses(
        (status = 200, description = "修改成功", body = AjaxResult<SysMsgTemplateModel>),
        (status = 400, description = "参数错误"),
        (status = 404, description = "模板不存在"),
    ),
    tag = "system-msg"
)]
pub async fn template_edit(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    ValidatedJson(dto): ValidatedJson<TemplateEditDto>,
) -> Result<AjaxResult<SysMsgTemplateModel>, AppError> {
    let model = state
        .msg_service
        .edit_template(dto, operator.username(), operator.tenant_id())
        .await?;
    Ok(AjaxResult::success(model))
}

/// DELETE /system/msg/template/{templateIds}
/// 批量删除消息模板
#[utoipa::path(
    delete,
    path = "/system/msg/template/{templateIds}",
    params(("templateIds" = String, Path, description = "模板 ID 列表（逗号分隔）")),
    responses(
        (status = 200, description = "删除成功"),
        (status = 400, description = "参数错误"),
    ),
    tag = "system-msg"
)]
pub async fn template_remove(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    Path(ids): Path<String>,
) -> Result<AjaxResult<()>, AppError> {
    let ids = crate::service::SysMsgService::parse_ids(&ids);
    if ids.is_empty() {
        return Err(AppError::bad_request(&crate::tr!(
            "error.msg.template_id_invalid"
        )));
    }
    if ids.len() > MAX_BATCH_DELETE_SIZE {
        return Err(AppError::bad_request(&crate::tr!(
            "error.common.batch_size_exceeded",
            max = MAX_BATCH_DELETE_SIZE
        )));
    }
    state
        .msg_service
        .delete_template(ids, operator.tenant_id())
        .await?;
    Ok(AjaxResult::success_msg(&crate::tr!("msg.success.delete")))
}

// ==================== 发送记录 ====================

/// GET /system/msg/log/list
/// 分页查询发送记录
#[utoipa::path(
    get,
    path = "/system/msg/log/list",
    params(SendLogQueryDto),
    responses(
        (status = 200, description = "查询成功", body = TableDataInfo<SysMsgSendLogModel>),
        (status = 500, description = "服务器错误"),
    ),
    tag = "system-msg"
)]
pub async fn send_log_list(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    Query(query): Query<SendLogQueryDto>,
) -> Result<TableDataInfo<SysMsgSendLogModel>, AppError> {
    let (rows, total) = state
        .msg_service
        .get_send_log_page(query, operator.tenant_id())
        .await?;
    Ok(TableDataInfo::new(total, rows))
}

/// DELETE /system/msg/log/{logIds}
/// 批量删除发送记录
#[utoipa::path(
    delete,
    path = "/system/msg/log/{logIds}",
    params(("logIds" = String, Path, description = "发送记录 ID 列表（逗号分隔）")),
    responses(
        (status = 200, description = "删除成功"),
        (status = 400, description = "参数错误"),
    ),
    tag = "system-msg"
)]
pub async fn send_log_remove(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    Path(ids): Path<String>,
) -> Result<AjaxResult<()>, AppError> {
    let ids = crate::service::SysMsgService::parse_ids(&ids);
    if ids.is_empty() {
        return Err(AppError::bad_request(&crate::tr!(
            "error.msg.log_id_invalid"
        )));
    }
    if ids.len() > MAX_BATCH_DELETE_SIZE {
        return Err(AppError::bad_request(&crate::tr!(
            "error.common.batch_size_exceeded",
            max = MAX_BATCH_DELETE_SIZE
        )));
    }
    state
        .msg_service
        .delete_send_logs(ids, operator.tenant_id())
        .await?;
    Ok(AjaxResult::success_msg(&crate::tr!("msg.success.delete")))
}

/// DELETE /system/msg/log/clean
/// 清空发送记录
#[utoipa::path(
    delete,
    path = "/system/msg/log/clean",
    responses(
        (status = 200, description = "清空成功", body = AjaxResult<u64>),
    ),
    tag = "system-msg"
)]
pub async fn send_log_clean(
    State(state): State<Arc<AppState>>,
    operator: Operator,
) -> Result<AjaxResult<u64>, AppError> {
    let count = state
        .msg_service
        .clean_send_logs(None, operator.tenant_id())
        .await?;
    Ok(AjaxResult::success(count))
}

/// POST /system/msg/send
/// 直接发送（按模板 + 渠道 + 参数落地）
#[utoipa::path(
    post,
    path = "/system/msg/send",
    request_body = SendDto,
    responses(
        (status = 200, description = "发送成功", body = AjaxResult<SysMsgSendLogModel>),
        (status = 400, description = "参数错误或模板/渠道不可用"),
    ),
    tag = "system-msg"
)]
pub async fn send(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    ValidatedJson(dto): ValidatedJson<SendDto>,
) -> Result<AjaxResult<SysMsgSendLogModel>, AppError> {
    let model = state
        .msg_service
        .send(dto, operator.username(), operator.tenant_id())
        .await?;
    // 投递成功 status='0'；否则 status='2'（待重试）由定时任务/手动重试兜底
    Ok(AjaxResult::success(model))
}

/// POST /system/msg/log/retry/{logIds}
/// 重试指定发送记录
#[utoipa::path(
    post,
    path = "/system/msg/log/retry/{logIds}",
    params(("logIds" = String, Path, description = "发送记录 ID 列表（逗号分隔）")),
    responses(
        (status = 200, description = "重试成功", body = AjaxResult<u64>),
    ),
    tag = "system-msg"
)]
pub async fn retry_logs(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    Path(ids): Path<String>,
) -> Result<AjaxResult<u64>, AppError> {
    let ids = crate::service::SysMsgService::parse_ids(&ids);
    if ids.is_empty() {
        return Err(AppError::bad_request(&crate::tr!(
            "error.msg.log_id_invalid"
        )));
    }
    if ids.len() > MAX_BATCH_DELETE_SIZE {
        return Err(AppError::bad_request(&crate::tr!(
            "error.common.batch_size_exceeded",
            max = MAX_BATCH_DELETE_SIZE
        )));
    }
    let count = state
        .msg_service
        .retry_logs(ids, operator.tenant_id())
        .await?;
    Ok(AjaxResult::success(count))
}

/// POST /system/msg/log/retryPending/{batch}
/// 触发待重试批次批量重试（供后台手动触发，返回本次实际重试条数）
#[utoipa::path(
    post,
    path = "/system/msg/log/retryPending/{batch}",
    params(("batch" = u64, Path, description = "单批最大重试条数")),
    responses(
        (status = 200, description = "重试完成", body = AjaxResult<u64>),
    ),
    tag = "system-msg"
)]
pub async fn retry_pending(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    Path(batch): Path<u64>,
) -> Result<AjaxResult<u64>, AppError> {
    let count = state
        .msg_service
        .retry_pending(batch, operator.tenant_id())
        .await?;
    Ok(AjaxResult::success(count))
}

/// POST /system/msg/log/markPending/{logIds}
/// 将指定发送记录标记为待重试（前端「标记重试」按钮）
#[utoipa::path(
    post,
    path = "/system/msg/log/markPending/{logIds}",
    params(("logIds" = String, Path, description = "发送记录 ID 列表（逗号分隔）")),
    responses(
        (status = 200, description = "标记成功", body = AjaxResult<u64>),
    ),
    tag = "system-msg"
)]
pub async fn mark_pending_retry(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    Path(ids): Path<String>,
) -> Result<AjaxResult<u64>, AppError> {
    let ids = crate::service::SysMsgService::parse_ids(&ids);
    if ids.is_empty() {
        return Err(AppError::bad_request(&crate::tr!(
            "error.msg.log_id_invalid"
        )));
    }
    let count = state
        .msg_service
        .mark_pending_retry(&ids, operator.tenant_id())
        .await?;
    Ok(AjaxResult::success(count))
}
