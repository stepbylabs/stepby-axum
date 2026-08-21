//! 操作日志 Handler（Axum 原生实现）
//!
//! 接口路径对齐前端调用规范：
//! - GET    /monitor/operlog/list          分页查询操作日志
//! - DELETE /monitor/operlog/{operIds}     批量删除操作日志
//! - DELETE /monitor/operlog/clean         清空操作日志
//! - POST   /monitor/operlog/export        导出操作日志列表

use axum::extract::{Form, Path, Query, State};
use axum::response::Response;
use std::sync::Arc;

use crate::common::constants::MAX_BATCH_DELETE_SIZE;
use crate::common::excel::{CellValue, ExcelColumn, export_to_excel_with_fields};
use crate::common::{AjaxResult, AppError, TableDataInfo};
use crate::entity::sys_oper_log::Model as SysOperLogModel;
use crate::middleware::Operator;
use crate::service::sys_oper_log_service::{
    AlarmStatusVo, AuditStatsVo, ComplianceReportVo, OperLogQueryDto, OperLogTypeStatsVo,
};
use crate::state::AppState;
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
        return Err(AppError::bad_request(&crate::tr!(
            "error.oper_log.id_invalid"
        )));
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
    Ok(AjaxResult::success(
        serde_json::json!({ "affected": affected }),
    ))
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
    // P0-2：提取操作人，用于 taskProgress 定向推送（此前 operator 写死 "system" 且广播全局）
    operator: Operator,
    Form(dto): Form<OperLogExportDto>,
) -> Result<Response, AppError> {
    // 解析可选 fields（逗号分隔）
    let fields: Option<Vec<String>> =
        dto.fields
            .as_deref()
            .filter(|s| !s.trim().is_empty())
            .map(|s| {
                s.split(',')
                    .map(|f| f.trim().to_string())
                    .filter(|f| !f.is_empty())
                    .collect::<Vec<_>>()
            });

    let query = OperLogQueryDto {
        page_num: dto.page_num,
        // P1 修复：导出 page_size 上限 clamp（防超大值一次性查询海量行到内存）
        page_size: dto.page_size.clamp(1, crate::common::page::EXPORT_MAX_ROWS),
        title: dto.title,
        business_type: dto.business_type,
        oper_name: dto.oper_name,
        status: dto.status,
        begin_time: dto.begin_time,
        end_time: dto.end_time,
        last_id: None,
    };

    // 长任务进度跟踪：行数较大时创建 sys_task 记录（P0-2：记录操作人 user_id 用于定向推送）
    let operator_id = operator.user_id().parse::<i64>().ok();
    let task_id = if fields.is_some() {
        // 字段选择导出场景才走任务进度（普通全量导出走原有同步路径）
        let dto = crate::service::sys_task_service::TaskCreateDto {
            task_type: "operlog_export".to_string(),
            task_name: crate::tr!("msg.export.oper_log_task"),
            total: 100,
            operator_id,
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
            .complete_task(
                tid,
                Some(crate::tr!("msg.export.progress", count = rows.len())),
                &state,
            )
            .await;
    }

    let columns = [
        ExcelColumn {
            key: "operId",
            header: ("日志编号", "Log ID"),
            getter: |r: &SysOperLogModel| CellValue::Number(r.oper_id as f64),
        },
        ExcelColumn {
            key: "title",
            header: ("模块标题", "Module Title"),
            getter: |r: &SysOperLogModel| {
                CellValue::Text(
                    crate::common::i18n::module_title(r.title.as_deref().unwrap_or_default())
                        .into_owned()
                        .into(),
                )
            },
        },
        ExcelColumn {
            key: "businessType",
            header: ("业务类型", "Business Type"),
            getter: |r: &SysOperLogModel| {
                CellValue::Text(
                    r.business_type
                        .map(|b| b.to_string())
                        .unwrap_or_default()
                        .into(),
                )
            },
        },
        ExcelColumn {
            key: "requestMethod",
            header: ("请求方式", "Request Method"),
            getter: |r: &SysOperLogModel| {
                CellValue::Text(r.request_method.clone().unwrap_or_default().into())
            },
        },
        ExcelColumn {
            key: "operName",
            header: ("操作人员", "Operator"),
            getter: |r: &SysOperLogModel| {
                CellValue::Text(r.oper_name.clone().unwrap_or_default().into())
            },
        },
        ExcelColumn {
            key: "operUrl",
            header: ("请求URL", "Request URL"),
            getter: |r: &SysOperLogModel| {
                CellValue::Text(r.oper_url.clone().unwrap_or_default().into())
            },
        },
        ExcelColumn {
            key: "operIp",
            header: ("主机地址", "Host Address"),
            getter: |r: &SysOperLogModel| {
                CellValue::Text(r.oper_ip.clone().unwrap_or_default().into())
            },
        },
        ExcelColumn {
            key: "status",
            header: ("操作状态", "Status"),
            getter: |r: &SysOperLogModel| {
                CellValue::Text(
                    r.status
                        .as_deref()
                        .map(|s| {
                            if s == "0" {
                                crate::tr!("common.status.normal")
                            } else {
                                crate::tr!("common.status.anomaly")
                            }
                        })
                        .unwrap_or_default()
                        .into(),
                )
            },
        },
        ExcelColumn {
            key: "errorMsg",
            header: ("错误消息", "Error Message"),
            getter: |r: &SysOperLogModel| {
                CellValue::Text(r.error_msg.clone().unwrap_or_default().into())
            },
        },
        ExcelColumn {
            key: "operTime",
            header: ("操作时间", "Operation Time"),
            getter: |r: &SysOperLogModel| CellValue::from_opt_datetime(r.oper_time),
        },
        ExcelColumn {
            key: "costTime",
            header: ("消耗时间(ms)", "Cost Time (ms)"),
            getter: |r: &SysOperLogModel| {
                CellValue::Number(r.cost_time.map(|c| c as f64).unwrap_or(0.0))
            },
        },
    ];

    export_to_excel_with_fields(
        &crate::tr!("excel.sheet.oper_log"),
        "oper_log",
        &columns,
        &rows,
        fields.as_deref(),
        false,
    )
    .await
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

/// GET /monitor/operlog/stats-by-type
/// 操作日志业务类型分布（仪表盘饼图专用聚合接口，G5）
///
/// 替代前端拉取 pageSize=1000 全量明细后在客户端分组的低效做法，
/// 改为后端 GROUP BY business_type 一次性返回 insert/update/delete/other 四桶计数。
#[utoipa::path(
    get,
    path = "/monitor/operlog/stats-by-type",
    responses(
        (status = 200, description = "查询成功", body = AjaxResult<OperLogTypeStatsVo>),
        (status = 500, description = "服务器错误"),
    ),
    tag = "monitor-operlog"
)]
pub async fn stats_by_type(
    State(state): State<Arc<AppState>>,
) -> Result<AjaxResult<OperLogTypeStatsVo>, AppError> {
    let vo = state.oper_log_service.oper_log_type_stats().await?;
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
    let vo = state.oper_log_service.get_compliance_report(days).await?;
    Ok(AjaxResult::success(vo))
}

/// 异常操作告警查询参数
///
/// 阈值优先级：显式参数 > 系统配置(sys_config) > 内置默认值。
/// 系统配置键：
/// - sys.audit.alarm.window_minutes      窗口分钟数（默认 5）
/// - sys.audit.alarm.fail_threshold      同一对象失败次数阈值（默认 5）
/// - sys.audit.alarm.fail_rate_threshold 失败率百分比阈值（默认 30）
#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AlarmStatusQuery {
    /// 时间窗口（分钟，1-1440）
    pub window_minutes: Option<i64>,
    /// 失败次数阈值
    pub fail_threshold: Option<i64>,
    /// 失败率（百分比）阈值
    pub fail_rate_threshold: Option<i64>,
}

/// GET /monitor/operlog/alarm-status
/// 异常操作告警状态检测（失败率 + 操作人/模块失败 Burst）
#[utoipa::path(
    get,
    path = "/monitor/operlog/alarm-status",
    responses(
        (status = 200, description = "查询成功", body = AjaxResult<AlarmStatusVo>),
        (status = 500, description = "服务器错误"),
    ),
    tag = "monitor-operlog"
)]
pub async fn alarm_status(
    State(state): State<Arc<AppState>>,
    Query(params): Query<AlarmStatusQuery>,
) -> Result<AjaxResult<AlarmStatusVo>, AppError> {
    // 读系统配置（带默认值），返回失效时回退默认
    let window_minutes = match params.window_minutes {
        Some(v) => v.clamp(1, 1440),
        None => {
            let v = state
                .config_service
                .get_config_value_by_key_cached("sys.audit.alarm.window_minutes")
                .await
                .ok()
                .flatten()
                .and_then(|s| s.trim().parse::<i64>().ok());
            v.unwrap_or(5).clamp(1, 1440)
        }
    };
    let fail_threshold = match params.fail_threshold {
        Some(v) => v.max(1),
        None => {
            let v = state
                .config_service
                .get_config_value_by_key_cached("sys.audit.alarm.fail_threshold")
                .await
                .ok()
                .flatten()
                .and_then(|s| s.trim().parse::<i64>().ok());
            v.unwrap_or(5).max(1)
        }
    };
    let fail_rate_threshold = match params.fail_rate_threshold {
        Some(v) => v.clamp(0, 100),
        None => {
            let v = state
                .config_service
                .get_config_value_by_key_cached("sys.audit.alarm.fail_rate_threshold")
                .await
                .ok()
                .flatten()
                .and_then(|s| s.trim().parse::<i64>().ok());
            v.unwrap_or(30).clamp(0, 100)
        }
    };

    let vo = state
        .oper_log_service
        .get_alarm_status(window_minutes, fail_threshold, fail_rate_threshold)
        .await?;
    Ok(AjaxResult::success(vo))
}
