// stepby-axum/src/handler/monitor_alert_handler.rs
//! 告警规则 Handler（Axum 原生实现）
//!
//! 接口路径对齐前端（系统监控 / 告警规则菜单，component = monitor/alert/index）：
//! - GET    /monitor/alert/list              分页查询告警规则（动态排序白名单）
//! - GET    /monitor/alert/{id}              查询告警规则详情
//! - POST   /monitor/alert                   新增告警规则
//! - PUT    /monitor/alert                   修改告警规则
//! - PUT    /monitor/alert/changeEnabled     启用/停用切换
//! - DELETE /monitor/alert/{ids}             批量删除告警规则（ids 为逗号分隔）
//! - POST   /monitor/alert/{id}/evaluate     手动评估一次（返回 {metricValue, fired, reason}）
//!
//! 权限（PERM_ROUTE_TABLE 同步登记，见 middleware/permission.rs）：
//! list → monitor:alert:list / {id} GET → monitor:alert:query /
//! add → monitor:alert:add / edit + changeEnabled → monitor:alert:edit /
//! remove → monitor:alert:remove（evaluate 归入 edit：评估即触发通知，属运营操作）

use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::response::Response;

use crate::common::ValidatedJson;
use crate::common::constants::MAX_BATCH_DELETE_SIZE;
use crate::common::excel::{CellValue, ExcelColumn, export_to_excel};
use crate::common::{AjaxResult, AppError, TableDataInfo};
use crate::entity::sys_alert_rule::Model as AlertRuleModel;
use crate::middleware::Operator;
use crate::service::sys_alert_service::{
    AlertEvaluateResult, AlertRuleAddDto, AlertRuleEditDto, AlertRuleEnabledDto,
    AlertRuleQueryDto,
};
use crate::state::AppState;
use crate::utils::parse_id_list;

/// GET /monitor/alert/list
/// 分页查询告警规则（name 模糊 / metric 精确 / enabled 精确 + 动态排序白名单）
#[utoipa::path(
    get,
    path = "/monitor/alert/list",
    params(AlertRuleQueryDto),
    responses(
        (status = 200, description = "查询成功", body = TableDataInfo<AlertRuleModel>),
        (status = 500, description = "服务器错误"),
    ),
    tag = "monitor-alert"
)]
pub async fn list(
    State(state): State<Arc<AppState>>,
    Query(query): Query<AlertRuleQueryDto>,
) -> Result<TableDataInfo<AlertRuleModel>, AppError> {
    let (rows, total) = state.alert_service.list(query).await?;
    Ok(TableDataInfo::new(total, rows))
}

/// GET /monitor/alert/{id}
/// 查询告警规则详情
#[utoipa::path(
    get,
    path = "/monitor/alert/{id}",
    params(
        ("id" = i64, Path, description = "告警规则 ID")
    ),
    responses(
        (status = 200, description = "查询成功", body = AjaxResult<AlertRuleModel>),
        (status = 404, description = "告警规则不存在"),
    ),
    tag = "monitor-alert"
)]
pub async fn get_info(
    State(state): State<Arc<AppState>>,
    Path(id): Path<i64>,
) -> Result<AjaxResult<AlertRuleModel>, AppError> {
    let model = state.alert_service.get_by_id(id).await?;
    Ok(AjaxResult::success(model))
}

/// POST /monitor/alert
/// 新增告警规则（metric / comparator 白名单校验在 service 层）
#[utoipa::path(
    post,
    path = "/monitor/alert",
    request_body = AlertRuleAddDto,
    responses(
        (status = 200, description = "新增成功", body = AjaxResult<AlertRuleModel>),
        (status = 400, description = "参数错误（指标/比较器不在白名单）"),
    ),
    tag = "monitor-alert"
)]
pub async fn add(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    ValidatedJson(dto): ValidatedJson<AlertRuleAddDto>,
) -> Result<AjaxResult<AlertRuleModel>, AppError> {
    let model = state.alert_service.add(dto, operator.username()).await?;
    Ok(AjaxResult::success(model))
}

/// PUT /monitor/alert
/// 修改告警规则（metric / comparator 白名单校验在 service 层）
#[utoipa::path(
    put,
    path = "/monitor/alert",
    request_body = AlertRuleEditDto,
    responses(
        (status = 200, description = "修改成功", body = AjaxResult<AlertRuleModel>),
        (status = 400, description = "参数错误"),
        (status = 404, description = "告警规则不存在"),
    ),
    tag = "monitor-alert"
)]
pub async fn edit(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    ValidatedJson(dto): ValidatedJson<AlertRuleEditDto>,
) -> Result<AjaxResult<AlertRuleModel>, AppError> {
    let model = state.alert_service.edit(dto, operator.username()).await?;
    Ok(AjaxResult::success(model))
}

/// PUT /monitor/alert/changeEnabled
/// 启用/停用切换
#[utoipa::path(
    put,
    path = "/monitor/alert/changeEnabled",
    request_body = AlertRuleEnabledDto,
    responses(
        (status = 200, description = "切换成功", body = AjaxResult<serde_json::Value>),
        (status = 400, description = "enabled 取值非法"),
        (status = 404, description = "告警规则不存在"),
    ),
    tag = "monitor-alert"
)]
pub async fn change_enabled(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    ValidatedJson(dto): ValidatedJson<AlertRuleEnabledDto>,
) -> Result<AjaxResult<()>, AppError> {
    state
        .alert_service
        .change_enabled(dto, operator.username())
        .await?;
    Ok(AjaxResult::success_msg(&crate::tr!("msg.success.edit")))
}

/// DELETE /monitor/alert/{ids}
/// 批量删除告警规则（ids 为逗号分隔的 ID 字符串）
#[utoipa::path(
    delete,
    path = "/monitor/alert/{ids}",
    params(
        ("ids" = String, Path, description = "告警规则 ID 列表（逗号分隔）")
    ),
    responses(
        (status = 200, description = "删除成功", body = AjaxResult<serde_json::Value>),
        (status = 400, description = "参数 ID 不合法"),
    ),
    tag = "monitor-alert"
)]
pub async fn remove(
    State(state): State<Arc<AppState>>,
    Path(ids): Path<String>,
) -> Result<AjaxResult<()>, AppError> {
    let ids: Vec<i64> = parse_id_list::<i64>(&ids);

    if ids.is_empty() {
        return Err(AppError::bad_request(&crate::tr!(
            "error.common.id_invalid"
        )));
    }
    if ids.len() > MAX_BATCH_DELETE_SIZE {
        return Err(AppError::bad_request(&crate::tr!(
            "error.common.batch_size_exceeded",
            max = MAX_BATCH_DELETE_SIZE
        )));
    }

    state.alert_service.remove(ids).await?;
    Ok(AjaxResult::success_msg(&crate::tr!("msg.success.delete")))
}

/// POST /monitor/alert/{id}/evaluate
/// 手动评估一次：立即采集指标并按规则判定，返回 {metricValue, fired, reason}
///
/// 与定时评估共用同一触发权抢占路径（claim_fire）：并发到达时只发送一次通知。
#[utoipa::path(
    post,
    path = "/monitor/alert/{id}/evaluate",
    params(
        ("id" = i64, Path, description = "告警规则 ID")
    ),
    responses(
        (status = 200, description = "评估完成", body = AjaxResult<AlertEvaluateResult>),
        (status = 400, description = "指标采集失败"),
        (status = 404, description = "告警规则不存在"),
    ),
    tag = "monitor-alert"
)]
pub async fn evaluate(
    State(state): State<Arc<AppState>>,
    Path(id): Path<i64>,
) -> Result<AjaxResult<AlertEvaluateResult>, AppError> {
    let result = state.alert_service.evaluate_one(id).await?;
    Ok(AjaxResult::success(result))
}

/// POST /monitor/alert/export
/// 导出告警规则列表为 Excel（前端 download() 发送表单编码，使用 Form 提取器）
#[utoipa::path(
    post,
    path = "/monitor/alert/export",
    params(AlertRuleQueryDto),
    responses(
        (status = 200, description = "导出成功", content_type = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"),
        (status = 500, description = "服务器错误"),
    ),
    tag = "monitor-alert"
)]
pub async fn export(
    State(state): State<Arc<AppState>>,
    axum::extract::Form(query): axum::extract::Form<AlertRuleQueryDto>,
) -> Result<Response, AppError> {
    // 导出走全量口径（EXPORT_MAX_ROWS 上限），不再复用 list 分页逻辑
    let rows = state.alert_service.export_rules(query).await?;

    let columns = [
        ExcelColumn {
            key: "id",
            header: ("ID", "ID"),
            getter: |r: &AlertRuleModel| CellValue::Number(r.id as f64),
        },
        ExcelColumn {
            key: "name",
            header: ("规则名称", "Rule Name"),
            getter: |r: &AlertRuleModel| CellValue::Text(r.name.clone().into()),
        },
        ExcelColumn {
            key: "metric",
            header: ("监控指标", "Metric"),
            getter: |r: &AlertRuleModel| CellValue::Text(r.metric.clone().into()),
        },
        ExcelColumn {
            key: "comparator",
            header: ("比较器", "Comparator"),
            getter: |r: &AlertRuleModel| CellValue::Text(r.comparator.clone().into()),
        },
        ExcelColumn {
            key: "threshold",
            header: ("阈值", "Threshold"),
            getter: |r: &AlertRuleModel| CellValue::Number(r.threshold),
        },
        ExcelColumn {
            key: "silentMinutes",
            header: ("静默期(分钟)", "Silence (min)"),
            getter: |r: &AlertRuleModel| CellValue::Number(f64::from(r.silent_minutes)),
        },
        ExcelColumn {
            key: "enabled",
            header: ("是否启用", "Enabled"),
            getter: |r: &AlertRuleModel| {
                CellValue::Text(
                    if r.enabled.as_deref() == Some("1") {
                        crate::tr!("common.yes")
                    } else {
                        crate::tr!("common.no")
                    }
                    .into(),
                )
            },
        },
        ExcelColumn {
            key: "lastFiredAt",
            header: ("最近触发时间", "Last Fired At"),
            getter: |r: &AlertRuleModel| CellValue::from_opt_datetime(r.last_fired_at),
        },
        ExcelColumn {
            key: "createdAt",
            header: ("创建时间", "Create Time"),
            getter: |r: &AlertRuleModel| CellValue::from_opt_datetime(r.created_at),
        },
    ];

    export_to_excel(
        &crate::tr!("excel.sheet.alert_rule"),
        "alert_rule",
        &columns,
        &rows,
    )
    .await
}
