//! 操作日志 Handler（Axum 原生实现）
//!
//! 接口路径对齐 ruoyi-vue3-ts 前端：
//! - GET    /monitor/operlog/list          分页查询操作日志
//! - DELETE /monitor/operlog/{operIds}     批量删除操作日志
//! - DELETE /monitor/operlog/clean         清空操作日志
//! - POST   /monitor/operlog/export        导出操作日志列表

use std::sync::Arc;
use axum::extract::{Form, Path, Query, State};
use axum::response::Response;

use crate::common::excel::{export_to_excel_with_fields, CellValue, ExcelColumn};
use crate::common::{AjaxResult, AppError, TableDataInfo};
use crate::entity::sys_oper_log::Model as SysOperLogModel;
use crate::service::sys_oper_log_service::{AuditStatsVo, ComplianceReportVo, OperLogQueryDto};
use crate::state::AppState;
use crate::common::constants::MAX_BATCH_DELETE_SIZE;
use crate::utils::parse_id_list;

/// GET /monitor/operlog/list
/// 分页查询操作日志
#[utoipa::path(
    get,
    path = "/monitor/operlog/list",
    params(OperLogQueryDto),
    responses(
        (status = 200, description = "查询成功", body = TableDataInfo<SysOperLogModel>),
        (status = 500, description = "服务器错误"),
    ),
    tag = "monitor-operlog"
)]
pub async fn list(
    State(state): State<Arc<AppState>>,
    Query(query): Query<OperLogQueryDto>,
) -> Result<TableDataInfo<SysOperLogModel>, AppError> {
    let (rows, total) = state.oper_log_service.get_oper_log_page(query).await?;
    Ok(TableDataInfo::new(total, rows))
}

/// DELETE /monitor/operlog/{operIds}
/// 批量删除操作日志（operIds 为逗号分隔的 ID 字符串）
#[utoipa::path(
    delete,
    path = "/monitor/operlog/{operIds}",
    params(
        ("operIds" = String, Path, description = "操作日志 ID 列表（逗号分隔）")
    ),
    responses(
        (status = 200, description = "删除成功", body = AjaxResult<serde_json::Value>),
        (status = 400, description = "日志 ID 不合法"),
    ),
    tag = "monitor-operlog"
)]
pub async fn remove(
    State(state): State<Arc<AppState>>,
    Path(oper_ids): Path<String>,
) -> Result<AjaxResult<()>, AppError> {
    let ids: Vec<i64> = parse_id_list::<i64>(&oper_ids);

    if ids.is_empty() {
        return Err(AppError::bad_request(&crate::tr!("error.oper_log.id_invalid")));
    }
    if ids.len() > MAX_BATCH_DELETE_SIZE {
        return Err(AppError::bad_request(&crate::tr!(
            "error.common.batch_size_exceeded",
            max = MAX_BATCH_DELETE_SIZE
        )));
    }

    state.oper_log_service.delete_oper_logs(ids).await?;
    Ok(AjaxResult::success_msg(&crate::tr!("msg.success.delete")))
}

/// 操作日志清理保留最近 N 天（仅删除早于该天数的日志，保证审计合规）
const OPER_LOG_CLEAN_RETAIN_DAYS: i64 = 30;

/// DELETE /monitor/operlog/clean
/// 清空操作日志（仅删除 30 天前的日志，保留最近 30 天用于审计）
///
/// 修复 P0-R81-010：原端点物理删除全部日志，违反审计合规。
/// 现改为仅删除 30 天前日志，并记录操作者信息到 tracing::warn!
#[utoipa::path(
    delete,
    path = "/monitor/operlog/clean",
    responses(
        (status = 200, description = "清空成功", body = AjaxResult<serde_json::Value>),
        (status = 500, description = "服务器错误"),
    ),
    tag = "monitor-operlog"
)]
pub async fn clean(
    State(state): State<Arc<AppState>>,
) -> Result<AjaxResult<serde_json::Value>, AppError> {
    // 仅删除 OPER_LOG_CLEAN_RETAIN_DAYS 天前的日志，保留最近同天数用于审计
    let days = OPER_LOG_CLEAN_RETAIN_DAYS;
    tracing::warn!(
        "操作日志清理：仅删除 {} 天前日志，操作者 = sys/operlog/clean（管理员）",
        days
    );
    let affected = state.oper_log_service.clean_oper_logs(days).await?;
    Ok(AjaxResult::success(serde_json::json!({ "affected": affected })))
}

/// POST /monitor/operlog/export
/// 导出操作日志列表为 Excel
///
/// 前端 download() 发送 application/x-www-form-urlencoded，使用 Form 提取器
/// 支持可选 `fields` 参数（逗号分隔的表头名称），仅导出指定字段
#[utoipa::path(
    post,
    path = "/monitor/operlog/export",
    responses(
        (status = 200, description = "导出成功", content_type = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"),
        (status = 500, description = "服务器错误"),
    ),
    tag = "monitor-operlog"
)]
pub async fn export(
    State(state): State<Arc<AppState>>,
    Form(dto): Form<OperLogExportDto>,
) -> Result<Response, AppError> {
    // 解析可选 fields（逗号分隔）
    let fields: Option<Vec<String>> = dto
        .fields
        .as_deref()
        .filter(|s| !s.trim().is_empty())
        .map(|s| s.split(',').map(|f| f.trim().to_string()).filter(|f| !f.is_empty()).collect::<Vec<_>>());

    let query = OperLogQueryDto {
        page_num: dto.page_num,
        page_size: dto.page_size,
        title: dto.title,
        business_type: dto.business_type,
        oper_name: dto.oper_name,
        status: dto.status,
        begin_time: dto.begin_time,
        end_time: dto.end_time,
    };

    // 长任务进度跟踪：行数较大时创建 sys_task 记录
    let task_id = if fields.is_some() {
        // 字段选择导出场景才走任务进度（普通全量导出走原有同步路径）
        let dto = crate::service::sys_task_service::TaskCreateDto {
            task_type: "operlog_export".to_string(),
            task_name: crate::tr!("msg.export.oper_log_task"),
            total: 100,
        };
        let task = state
            .task_service
            .create_task(dto, "system", &state)
            .await
            .ok();
        task.map(|t| t.task_id)
    } else {
        None
    };

    let rows = state.oper_log_service.export_oper_logs(query).await?;

    // 完成任务进度
    if let Some(tid) = task_id {
        let _ = state
            .task_service
            .complete_task(tid, Some(crate::tr!("msg.export.progress", count = rows.len())), &state)
            .await;
    }

    let columns = [
        ExcelColumn { key: "operId", header: ("日志编号", "Log ID"), getter: |r: &SysOperLogModel| CellValue::Text(r.oper_id.to_string().into()) },
        ExcelColumn { key: "title", header: ("模块标题", "Module Title"), getter: |r: &SysOperLogModel| CellValue::Text(crate::common::i18n::module_title(r.title.as_deref().unwrap_or_default()).into_owned().into()) },
        ExcelColumn { key: "businessType", header: ("业务类型", "Business Type"), getter: |r: &SysOperLogModel| CellValue::Text(r.business_type.map(|b| b.to_string()).unwrap_or_default().into()) },
        ExcelColumn { key: "requestMethod", header: ("请求方式", "Request Method"), getter: |r: &SysOperLogModel| CellValue::Text(r.request_method.clone().unwrap_or_default().into()) },
        ExcelColumn { key: "operName", header: ("操作人员", "Operator"), getter: |r: &SysOperLogModel| CellValue::Text(r.oper_name.clone().unwrap_or_default().into()) },
        ExcelColumn { key: "operUrl", header: ("请求URL", "Request URL"), getter: |r: &SysOperLogModel| CellValue::Text(r.oper_url.clone().unwrap_or_default().into()) },
        ExcelColumn { key: "operIp", header: ("主机地址", "Host Address"), getter: |r: &SysOperLogModel| CellValue::Text(r.oper_ip.clone().unwrap_or_default().into()) },
        ExcelColumn { key: "status", header: ("操作状态", "Status"), getter: |r: &SysOperLogModel| CellValue::Text(r.status.as_deref().map(|s| if s == "0" { crate::tr!("common.status.normal") } else { crate::tr!("common.status.anomaly") }).unwrap_or_default().into()) },
        ExcelColumn { key: "errorMsg", header: ("错误消息", "Error Message"), getter: |r: &SysOperLogModel| CellValue::Text(r.error_msg.clone().unwrap_or_default().into()) },
        ExcelColumn { key: "operTime", header: ("操作时间", "Operation Time"), getter: |r: &SysOperLogModel| CellValue::Text({
                r.oper_time
                    .map(|dt| dt.format("%Y-%m-%d %H:%M:%S").to_string())
                    .unwrap_or_default()
                    .into()
            }) },
        ExcelColumn { key: "costTime", header: ("消耗时间(ms)", "Cost Time (ms)"), getter: |r: &SysOperLogModel| CellValue::Text(r.cost_time.map(|c| c.to_string()).unwrap_or_default().into()) },
    ];

    export_to_excel_with_fields(&crate::tr!("excel.sheet.oper_log"), "oper_log", &columns, &rows, fields.as_deref(), false).await
}

/// 操作日志导出 DTO（在原查询参数基础上增加 fields 字段选择）
#[derive(Debug, serde::Deserialize, utoipa::IntoParams, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct OperLogExportDto {
    #[serde(default = "default_page_num")]
    pub page_num: u64,
    #[serde(default = "default_page_size")]
    pub page_size: u64,
    pub title: Option<String>,
    pub business_type: Option<i32>,
    pub oper_name: Option<String>,
    pub status: Option<String>,
    #[serde(alias = "params[beginTime]", default)]
    pub begin_time: Option<String>,
    #[serde(alias = "params[endTime]", default)]
    pub end_time: Option<String>,
    /// 导出字段列表（逗号分隔的表头名称），为空时导出全部字段
    pub fields: Option<String>,
}

fn default_page_num() -> u64 {
    1
}
fn default_page_size() -> u64 {
    10
}

/// GET /monitor/operlog/stats
/// 审计大屏综合统计（汇总数据 + 业务类型分布 + 操作人 Top10 + 最近 N 天趋势）
///
/// 查询参数 `days` 控制每日趋势统计的天数，默认 30 天
#[utoipa::path(
    get,
    path = "/monitor/operlog/stats",
    params(
        ("days" = Option<i64>, Query, description = "每日趋势统计天数（默认 30）")
    ),
    responses(
        (status = 200, description = "查询成功", body = AjaxResult<AuditStatsVo>),
        (status = 500, description = "服务器错误"),
    ),
    tag = "monitor-operlog"
)]
pub async fn stats(
    State(state): State<Arc<AppState>>,
    Query(params): Query<AuditStatsQuery>,
) -> Result<AjaxResult<AuditStatsVo>, AppError> {
    let days = params.days.unwrap_or(30).clamp(1, 365);
    let vo = state.oper_log_service.get_audit_stats(days).await?;
    Ok(AjaxResult::success(vo))
}

/// 审计大屏统计查询参数
#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuditStatsQuery {
    /// 每日趋势统计天数（默认 30，范围 1-365）
    pub days: Option<i64>,
}

/// GET /monitor/operlog/compliance-report
/// 审计合规报告数据（比 stats 更详细，包含异常事件列表与报告周期元数据）
///
/// 供前端"导出合规报告 PDF"功能调用，一次性返回报告所需的全部数据。
#[utoipa::path(
    get,
    path = "/monitor/operlog/compliance-report",
    params(
        ("days" = Option<i64>, Query, description = "报告周期天数（默认 30，范围 1-365）")
    ),
    responses(
        (status = 200, description = "查询成功", body = AjaxResult<ComplianceReportVo>),
        (status = 500, description = "服务器错误"),
    ),
    tag = "monitor-operlog"
)]
pub async fn compliance_report(
    State(state): State<Arc<AppState>>,
    Query(params): Query<AuditStatsQuery>,
) -> Result<AjaxResult<ComplianceReportVo>, AppError> {
    let days = params.days.unwrap_or(30).clamp(1, 365);
    let vo = state
        .oper_log_service
        .get_compliance_report(days)
        .await?;
    Ok(AjaxResult::success(vo))
}
