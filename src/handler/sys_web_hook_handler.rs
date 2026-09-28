//! WebHook 事件订阅 Handler（Axum 原生实现）
//!
//! 接口路径对齐前端：
//! - GET    /monitor/webHook/list               分页查询回调配置
//! - GET    /monitor/webHook/{id}               查询回调详情
//! - POST   /monitor/webHook                    新增回调
//! - PUT    /monitor/webHook                    修改回调
//! - PUT    /monitor/webHook/{id}/status        回调启停
//! - POST   /monitor/webHook/{id}/test          手动测试推送
//! - POST   /monitor/webHook/export             导出回调配置
//! - GET    /monitor/webHook/log/list           分页查询推送记录
//! - GET    /monitor/webHook/log/{id}           查询推送记录详情
//! - DELETE /monitor/webHook/log/{ids}          删除推送记录
//! - DELETE /monitor/webHook/log/clean          清空推送记录
//! - POST   /monitor/webHook/log/{ids}/retry    失败记录重试
//! - POST   /monitor/webHook/log/export         导出推送记录

use axum::extract::{Form, Path, Query, State};
use axum::response::Response;
use std::sync::Arc;

use crate::common::ValidatedJson;
use crate::common::constants::MAX_BATCH_DELETE_SIZE;
use crate::common::excel::{CellValue, ExcelColumn, export_to_excel};
use crate::common::{AjaxResult, AppError, TableDataInfo};
use crate::entity::sys_web_hook_log::Model as SysWebHookLogModel;
use crate::middleware::Operator;
use crate::service::sys_web_hook_service::{
    WebHookAddDto, WebHookEditDto, WebHookLogQueryDto, WebHookQueryDto, WebHookTestDto, WebHookVo,
};
use crate::state::AppState;
use crate::utils::parse_id_list;

/// GET /monitor/webHook/list —— 分页查询回调配置
///
/// 出参为脱敏 VO（[`WebHookVo`]）：**不含**签名密钥 `secret`，仅以 `hasSecret` 标注。
#[utoipa::path(
    get,
    path = "/monitor/webHook/list",
    params(WebHookQueryDto),
    responses(
        (status = 200, description = "查询成功", body = TableDataInfo<WebHookVo>),
        (status = 500, description = "服务器错误"),
    ),
    tag = "monitor-webhook"
)]
pub async fn list(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    Query(query): Query<WebHookQueryDto>,
) -> Result<TableDataInfo<WebHookVo>, AppError> {
    let (rows, total) = state
        .web_hook_service
        .list(query, operator.tenant_id())
        .await?;
    Ok(TableDataInfo::new(total, rows))
}

/// GET /monitor/webHook/{id} —— 查询回调详情
///
/// 出参为脱敏 VO（[`WebHookVo`]）：**不含**签名密钥 `secret`，仅以 `hasSecret` 标注。
#[utoipa::path(
    get,
    path = "/monitor/webHook/{id}",
    params(("id" = i64, Path, description = "回调 ID")),
    responses(
        (status = 200, description = "查询成功", body = AjaxResult<WebHookVo>),
        (status = 404, description = "回调不存在"),
    ),
    tag = "monitor-webhook"
)]
pub async fn get_info(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    Path(id): Path<i64>,
) -> Result<AjaxResult<WebHookVo>, AppError> {
    let vo = state
        .web_hook_service
        .detail(id, operator.tenant_id())
        .await?;
    Ok(AjaxResult::success(vo))
}

/// POST /monitor/webHook —— 新增回调配置
#[utoipa::path(
    post,
    path = "/monitor/webHook",
    request_body = WebHookAddDto,
    responses(
        (status = 200, description = "新增成功", body = AjaxResult<serde_json::Value>),
        (status = 400, description = "参数错误或目标 URL 被 SSRF 拦截"),
    ),
    tag = "monitor-webhook"
)]
pub async fn add(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    ValidatedJson(dto): ValidatedJson<WebHookAddDto>,
) -> Result<AjaxResult<()>, AppError> {
    state
        .web_hook_service
        .add(dto, operator.username(), operator.tenant_id())
        .await?;
    Ok(AjaxResult::success_msg(&crate::tr!("msg.success.add")))
}

/// PUT /monitor/webHook —— 修改回调配置
#[utoipa::path(
    put,
    path = "/monitor/webHook",
    request_body = WebHookEditDto,
    responses(
        (status = 200, description = "修改成功", body = AjaxResult<serde_json::Value>),
        (status = 400, description = "参数错误或目标 URL 被 SSRF 拦截"),
        (status = 404, description = "回调不存在"),
    ),
    tag = "monitor-webhook"
)]
pub async fn edit(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    ValidatedJson(dto): ValidatedJson<WebHookEditDto>,
) -> Result<AjaxResult<()>, AppError> {
    state
        .web_hook_service
        .edit(dto, operator.username(), operator.tenant_id())
        .await?;
    Ok(AjaxResult::success_msg(&crate::tr!("msg.success.edit")))
}

/// PUT /monitor/webHook/{id}/status —— 回调启停
#[utoipa::path(
    put,
    path = "/monitor/webHook/{id}/status",
    params(("id" = i64, Path, description = "回调 ID")),
    request_body = serde_json::Value,
    responses(
        (status = 200, description = "操作成功", body = AjaxResult<serde_json::Value>),
        (status = 400, description = "参数错误"),
    ),
    tag = "monitor-webhook"
)]
pub async fn change_status(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    Path(id): Path<i64>,
    axum::Json(body): axum::Json<serde_json::Value>,
) -> Result<AjaxResult<()>, AppError> {
    let status = body
        .get("status")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AppError::bad_request(&crate::tr!("error.common.invalid_param")))?;
    state
        .web_hook_service
        .change_status(id, status, operator.tenant_id())
        .await?;
    Ok(AjaxResult::success_msg(&crate::tr!(
        "msg.success.operation"
    )))
}

/// POST /monitor/webHook/{id}/test —— 手动测试推送
#[utoipa::path(
    post,
    path = "/monitor/webHook/{id}/test",
    params(("id" = i64, Path, description = "回调 ID")),
    request_body = WebHookTestDto,
    responses(
        (status = 200, description = "投递结果", body = AjaxResult<crate::service::sys_web_hook_service::DeliveryResult>),
    ),
    tag = "monitor-webhook"
)]
pub async fn test_hook(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    Path(id): Path<i64>,
    ValidatedJson(dto): ValidatedJson<WebHookTestDto>,
) -> Result<AjaxResult<crate::service::sys_web_hook_service::DeliveryResult>, AppError> {
    let result = state
        .web_hook_service
        .test_hook(id, dto, operator.tenant_id())
        .await?;
    Ok(AjaxResult::success(result))
}

/// POST /monitor/webHook/export —— 导出回调配置
#[utoipa::path(
    post,
    path = "/monitor/webHook/export",
    params(WebHookQueryDto),
    responses(
        (status = 200, description = "导出成功", content_type = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"),
        (status = 500, description = "服务器错误"),
    ),
    tag = "monitor-webhook"
)]
pub async fn export(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    Form(query): Form<WebHookQueryDto>,
) -> Result<Response, AppError> {
    let rows = state
        .web_hook_service
        .list(
            WebHookQueryDto {
                page_num: 1,
                page_size: crate::common::page::EXPORT_MAX_ROWS,
                hook_name: query.hook_name,
                event_types: query.event_types,
                status: Some(query.status.unwrap_or_default()),
            },
            operator.tenant_id(),
        )
        .await?
        .0;

    let columns = [
        ExcelColumn {
            key: "id",
            header: ("ID", "ID"),
            getter: |r: &WebHookVo| CellValue::Number(r.id as f64),
        },
        ExcelColumn {
            key: "hookName",
            header: ("回调名称", "Hook Name"),
            getter: |r: &WebHookVo| CellValue::Text(r.hook_name.clone().into()),
        },
        ExcelColumn {
            key: "eventTypes",
            header: ("事件类型", "Event Types"),
            getter: |r: &WebHookVo| CellValue::Text(r.event_types.clone().into()),
        },
        ExcelColumn {
            key: "targetUrl",
            header: ("目标 URL", "Target URL"),
            getter: |r: &WebHookVo| CellValue::Text(r.target_url.clone().into()),
        },
        ExcelColumn {
            key: "status",
            header: ("状态", "Status"),
            getter: |r: &WebHookVo| {
                CellValue::Text(
                    (if r.status == "0" {
                        crate::tr!("common.enabled")
                    } else {
                        crate::tr!("common.disabled")
                    })
                    .into(),
                )
            },
        },
        ExcelColumn {
            key: "createTime",
            header: ("创建时间", "Create Time"),
            getter: |r: &WebHookVo| CellValue::from_opt_datetime(r.create_time),
        },
    ];
    export_to_excel(
        &crate::tr!("excel.sheet.web_hook"),
        "web_hook",
        &columns,
        &rows,
    )
    .await
}

// ==================== 推送记录 ====================

/// DELETE /monitor/webHook/{ids} —— 批量删除回调配置
#[utoipa::path(
    delete,
    path = "/monitor/webHook/{ids}",
    params(("ids" = String, Path, description = "回调 ID 列表（逗号分隔）")),
    responses(
        (status = 200, description = "删除成功", body = AjaxResult<serde_json::Value>),
        (status = 400, description = "参数 ID 不合法"),
    ),
    tag = "monitor-webhook"
)]
pub async fn remove(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    Path(ids): Path<String>,
) -> Result<AjaxResult<()>, AppError> {
    let ids: Vec<i64> = parse_id_list::<i64>(&ids);
    if ids.is_empty() {
        return Err(AppError::bad_request(&crate::tr!(
            "error.web_hook.id_invalid"
        )));
    }
    if ids.len() > MAX_BATCH_DELETE_SIZE {
        return Err(AppError::bad_request(&crate::tr!(
            "error.common.batch_size_exceeded",
            max = MAX_BATCH_DELETE_SIZE
        )));
    }
    state
        .web_hook_service
        .remove(ids, operator.tenant_id())
        .await?;
    Ok(AjaxResult::success_msg(&crate::tr!("msg.success.delete")))
}

/// GET /monitor/webHook/log/list —— 分页查询推送记录
#[utoipa::path(
    get,
    path = "/monitor/webHook/log/list",
    params(WebHookLogQueryDto),
    responses(
        (status = 200, description = "查询成功", body = TableDataInfo<SysWebHookLogModel>),
        (status = 500, description = "服务器错误"),
    ),
    tag = "monitor-webhook"
)]
pub async fn log_list(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    Query(query): Query<WebHookLogQueryDto>,
) -> Result<TableDataInfo<SysWebHookLogModel>, AppError> {
    let (rows, total) = state
        .web_hook_service
        .list_logs(query, operator.tenant_id())
        .await?;
    Ok(TableDataInfo::new(total, rows))
}

/// GET /monitor/webHook/log/{id} —— 查询推送记录详情
#[utoipa::path(
    get,
    path = "/monitor/webHook/log/{id}",
    params(("id" = i64, Path, description = "记录 ID")),
    responses(
        (status = 200, description = "查询成功", body = AjaxResult<SysWebHookLogModel>),
        (status = 404, description = "记录不存在"),
    ),
    tag = "monitor-webhook"
)]
pub async fn log_info(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    Path(id): Path<i64>,
) -> Result<AjaxResult<SysWebHookLogModel>, AppError> {
    let model = state
        .web_hook_service
        .get_log_by_id(id, operator.tenant_id())
        .await?;
    Ok(AjaxResult::success(model))
}

/// DELETE /monitor/webHook/log/{ids} —— 删除推送记录
#[utoipa::path(
    delete,
    path = "/monitor/webHook/log/{ids}",
    params(("ids" = String, Path, description = "记录 ID 列表（逗号分隔）")),
    responses(
        (status = 200, description = "删除成功", body = AjaxResult<serde_json::Value>),
        (status = 400, description = "参数 ID 不合法"),
    ),
    tag = "monitor-webhook"
)]
pub async fn log_remove(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    Path(ids): Path<String>,
) -> Result<AjaxResult<()>, AppError> {
    let ids: Vec<i64> = parse_id_list::<i64>(&ids);
    if ids.is_empty() {
        return Err(AppError::bad_request(&crate::tr!(
            "error.web_hook.id_invalid"
        )));
    }
    if ids.len() > MAX_BATCH_DELETE_SIZE {
        return Err(AppError::bad_request(&crate::tr!(
            "error.common.batch_size_exceeded",
            max = MAX_BATCH_DELETE_SIZE
        )));
    }
    state
        .web_hook_service
        .remove_logs(ids, operator.tenant_id())
        .await?;
    Ok(AjaxResult::success_msg(&crate::tr!("msg.success.delete")))
}

/// DELETE /monitor/webHook/log/clean —— 清空推送记录
#[utoipa::path(
    delete,
    path = "/monitor/webHook/log/clean",
    responses(
        (status = 200, description = "清空成功", body = AjaxResult<serde_json::Value>),
    ),
    tag = "monitor-webhook"
)]
pub async fn log_clean(
    State(state): State<Arc<AppState>>,
    operator: Operator,
) -> Result<AjaxResult<serde_json::Value>, AppError> {
    let (expired, cleaned) = state
        .web_hook_service
        .clean_logs(operator.tenant_id())
        .await?;
    Ok(AjaxResult::success(serde_json::json!({
        "expired": expired,
        "cleaned": cleaned
    })))
}

/// POST /monitor/webHook/log/{ids}/retry —— 失败记录重试
#[utoipa::path(
    post,
    path = "/monitor/webHook/log/{ids}/retry",
    params(("ids" = String, Path, description = "记录 ID 列表（逗号分隔）")),
    responses(
        (status = 200, description = "重试完成", body = AjaxResult<serde_json::Value>),
        (status = 400, description = "参数 ID 不合法"),
    ),
    tag = "monitor-webhook"
)]
pub async fn log_retry(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    Path(ids): Path<String>,
) -> Result<AjaxResult<serde_json::Value>, AppError> {
    let ids: Vec<i64> = parse_id_list::<i64>(&ids);
    if ids.is_empty() {
        return Err(AppError::bad_request(&crate::tr!(
            "error.web_hook.id_invalid"
        )));
    }
    if ids.len() > MAX_BATCH_DELETE_SIZE {
        return Err(AppError::bad_request(&crate::tr!(
            "error.common.batch_size_exceeded",
            max = MAX_BATCH_DELETE_SIZE
        )));
    }
    let count = state
        .web_hook_service
        .retry_logs(ids, operator.tenant_id())
        .await?;
    Ok(AjaxResult::success(serde_json::json!({ "count": count })))
}

/// POST /monitor/webHook/log/export —— 导出推送记录
#[utoipa::path(
    post,
    path = "/monitor/webHook/log/export",
    params(WebHookLogQueryDto),
    responses(
        (status = 200, description = "导出成功", content_type = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"),
        (status = 500, description = "服务器错误"),
    ),
    tag = "monitor-webhook"
)]
pub async fn log_export(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    Form(query): Form<WebHookLogQueryDto>,
) -> Result<Response, AppError> {
    let rows = state
        .web_hook_service
        .list_logs(
            WebHookLogQueryDto {
                page_num: 1,
                page_size: crate::common::page::EXPORT_MAX_ROWS,
                hook_id: query.hook_id,
                event_type: query.event_type,
                status: Some(query.status.unwrap_or_default()),
            },
            operator.tenant_id(),
        )
        .await?
        .0;

    let columns = [
        ExcelColumn {
            key: "id",
            header: ("ID", "ID"),
            getter: |r: &SysWebHookLogModel| CellValue::Number(r.id as f64),
        },
        ExcelColumn {
            key: "hookName",
            header: ("回调名称", "Hook Name"),
            getter: |r: &SysWebHookLogModel| {
                CellValue::Text(r.hook_name.clone().unwrap_or_default().into())
            },
        },
        ExcelColumn {
            key: "eventType",
            header: ("事件类型", "Event Type"),
            getter: |r: &SysWebHookLogModel| CellValue::Text(r.event_type.clone().into()),
        },
        ExcelColumn {
            key: "targetUrl",
            header: ("目标 URL", "Target URL"),
            getter: |r: &SysWebHookLogModel| CellValue::Text(r.target_url.clone().into()),
        },
        ExcelColumn {
            key: "status",
            header: ("状态", "Status"),
            getter: |r: &SysWebHookLogModel| {
                CellValue::Text(
                    (if r.status == "0" {
                        crate::tr!("common.status.success")
                    } else {
                        crate::tr!("common.status.failed")
                    })
                    .into(),
                )
            },
        },
        ExcelColumn {
            key: "costMs",
            header: ("耗时(ms)", "Cost (ms)"),
            getter: |r: &SysWebHookLogModel| CellValue::Number(f64::from(r.cost_ms)),
        },
        ExcelColumn {
            key: "createTime",
            header: ("创建时间", "Create Time"),
            getter: |r: &SysWebHookLogModel| CellValue::from_opt_datetime(r.create_time),
        },
    ];
    export_to_excel(
        &crate::tr!("excel.sheet.web_hook_log"),
        "web_hook_log",
        &columns,
        &rows,
    )
    .await
}
