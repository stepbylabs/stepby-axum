//! 登录日志 Handler（Axum 原生实现）
//!
//! 接口路径对齐前端调用规范：
//! - GET    /monitor/logininfor/list            分页查询登录日志
//! - DELETE /monitor/logininfor/{infoIds}       批量删除登录日志
//! - GET    /monitor/logininfor/unlock/{userName} 解锁用户（清除登录失败日志）
//! - DELETE /monitor/logininfor/clean           清空登录日志
//! - POST   /monitor/logininfor/export          导出登录日志列表

use axum::extract::{Form, Path, Query, State};
use axum::response::Response;
use std::sync::Arc;

use crate::common::constants::{MAX_BATCH_DELETE_SIZE, SUPER_ADMIN_USER_ID};
use crate::common::excel::{CellValue, ExcelColumn, export_to_excel};
use crate::common::{AjaxResult, AppError, TableDataInfo};
use crate::entity::sys_logininfor::Model as SysLogininforModel;
use crate::middleware::Operator;
use crate::service::sys_logininfor_service::{LoginDailyStat, LogininforQueryDto};
use crate::state::AppState;
use crate::utils::parse_id_list;

/// GET /monitor/logininfor/list
/// 分页查询登录日志
#[utoipa::path(
    get,
    path = "/monitor/logininfor/list",
    params(LogininforQueryDto),
    responses(
        (status = 200, description = "查询成功", body = TableDataInfo<SysLogininforModel>),
        (status = 500, description = "服务器错误"),
    ),
    tag = "monitor-logininfor"
)]
pub async fn list(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    Query(query): Query<LogininforQueryDto>,
) -> Result<TableDataInfo<SysLogininforModel>, AppError> {
    let (rows, total) = state
        .logininfor_service
        .get_logininfor_page(
            query,
            crate::common::tenant::tenant_scope(operator.tenant_id()),
        )
        .await?;
    Ok(TableDataInfo::new(total, rows))
}

/// DELETE /monitor/logininfor/{infoIds}
/// 批量删除登录日志（infoIds 为逗号分隔的 ID 字符串）
#[utoipa::path(
    delete,
    path = "/monitor/logininfor/{infoIds}",
    params(
        ("infoIds" = String, Path, description = "登录日志 ID 列表（逗号分隔）")
    ),
    responses(
        (status = 200, description = "删除成功", body = AjaxResult<serde_json::Value>),
        (status = 400, description = "日志 ID 不合法"),
    ),
    tag = "monitor-logininfor"
)]
pub async fn remove(
    State(state): State<Arc<AppState>>,
    Path(info_ids): Path<String>,
) -> Result<AjaxResult<()>, AppError> {
    let ids: Vec<i64> = parse_id_list::<i64>(&info_ids);

    if ids.is_empty() {
        return Err(AppError::bad_request(&crate::tr!(
            "error.login_log.id_invalid"
        )));
    }
    if ids.len() > MAX_BATCH_DELETE_SIZE {
        return Err(AppError::bad_request(&crate::tr!(
            "error.common.batch_size_exceeded",
            max = MAX_BATCH_DELETE_SIZE
        )));
    }

    state.logininfor_service.delete_logininfors(ids).await?;
    Ok(AjaxResult::success_msg(&crate::tr!("msg.success.delete")))
}

/// POST /monitor/logininfor/unlock/{userName}
/// 解锁用户（删除该用户的登录失败日志）
#[utoipa::path(
    post,
    path = "/monitor/logininfor/unlock/{userName}",
    params(
        ("userName" = String, Path, description = "用户名")
    ),
    responses(
        (status = 200, description = "解锁成功", body = AjaxResult<serde_json::Value>),
        (status = 404, description = "用户不存在"),
    ),
    tag = "monitor-logininfor"
)]
pub async fn unlock(
    State(state): State<Arc<AppState>>,
    Path(user_name): Path<String>,
) -> Result<AjaxResult<()>, AppError> {
    // 超管保护（P0-R81-006）：禁止解锁超级管理员账号（M-2 + M-3 Major：使用常量替代硬编码）
    // 防止通过解锁接口重置超管的登录失败计数
    if let Ok(Some(user)) = state.user_service.get_user_by_username(&user_name).await
        && user.user_id == SUPER_ADMIN_USER_ID
    {
        return Err(AppError::new(
            403,
            crate::tr!("error.login_log.admin_unlock_forbidden"),
        ));
    }

    state.logininfor_service.unlock_user(&user_name).await?;
    // 同步重置 Redis 中的登录失败计数，否则用户仍会被锁定（auth_service 使用 login_fail:{username}）
    let fail_key = format!("login_fail:{}", user_name);
    let mut redis = state.redis.clone();
    let del_result: Result<(), _> = redis::cmd("DEL")
        .arg(&fail_key)
        .query_async(&mut redis)
        .await;
    if let Err(e) = del_result {
        tracing::warn!("重置 Redis 登录失败计数失败 (user={}): {}", user_name, e);
    }
    Ok(AjaxResult::success_msg(&crate::tr!("msg.success.unlock")))
}

/// 登录日志清理查询参数（兼容前端 addDateRange 嵌套格式 params[beginTime]/params[endTime]）
#[derive(Debug, serde::Deserialize, utoipa::IntoParams)]
#[serde(rename_all = "camelCase")]
pub struct LogininforCleanQuery {
    /// 清理时间范围起点（`%Y-%m-%d`），与 endTime 同时提供时执行按时间范围清理
    #[serde(alias = "params[beginTime]", default)]
    pub begin_time: Option<String>,
    /// 清理时间范围终点（`%Y-%m-%d`），与 beginTime 同时提供时执行按时间范围清理
    #[serde(alias = "params[endTime]", default)]
    pub end_time: Option<String>,
}

/// DELETE /monitor/logininfor/clean
/// 清空登录日志（可选按时间范围清理）
///
/// - 不传时间参数：清空全部登录日志（物理删除）。
/// - 传入 `params[beginTime]`/`params[endTime]`（`%Y-%m-%d`）：仅清理 [begin, end] 区间的日志。
#[utoipa::path(
    delete,
    path = "/monitor/logininfor/clean",
    params(LogininforCleanQuery),
    responses(
        (status = 200, description = "清空成功", body = AjaxResult<serde_json::Value>),
        (status = 500, description = "服务器错误"),
    ),
    tag = "monitor-logininfor"
)]
pub async fn clean(
    State(state): State<Arc<AppState>>,
    Query(query): Query<LogininforCleanQuery>,
) -> Result<AjaxResult<serde_json::Value>, AppError> {
    // 传入时间范围时执行按时间清理，否则清空全部
    let affected = if query.begin_time.is_some() || query.end_time.is_some() {
        tracing::warn!(
            "登录日志清理（按时间范围）：begin={:?} end={:?}，操作者 = sys/logininfor/clean（管理员）",
            query.begin_time,
            query.end_time
        );
        state
            .logininfor_service
            .clean_logininfors_by_range(query.begin_time.clone(), query.end_time.clone())
            .await?
    } else {
        state.logininfor_service.clean_logininfors().await?;
        0 // 全量清空不返回具体数量，兼容既有契约
    };
    Ok(AjaxResult::success(
        serde_json::json!({ "affected": affected }),
    ))
}

/// POST /monitor/logininfor/export
/// 导出登录日志列表为 Excel
///
/// 前端 download() 发送 application/x-www-form-urlencoded，使用 Form 提取器
#[utoipa::path(
    post,
    path = "/monitor/logininfor/export",
    params(LogininforQueryDto),
    responses(
        (status = 200, description = "导出成功", content_type = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"),
        (status = 500, description = "服务器错误"),
    ),
    tag = "monitor-logininfor"
)]
pub async fn export(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    Form(query): Form<LogininforQueryDto>,
) -> Result<Response, AppError> {
    let rows = state
        .logininfor_service
        .export_logininfors(
            query,
            crate::common::tenant::tenant_scope(operator.tenant_id()),
        )
        .await?;

    let columns = [
        ExcelColumn {
            key: "operId",
            header: ("日志编号", "Log ID"),
            getter: |r: &SysLogininforModel| CellValue::Number(r.info_id as f64),
        },
        ExcelColumn {
            key: "userName",
            header: ("用户名称", "Username"),
            getter: |r: &SysLogininforModel| {
                CellValue::Text(r.user_name.clone().unwrap_or_default().into())
            },
        },
        ExcelColumn {
            key: "ipaddr",
            header: ("IP地址", "IP Address"),
            getter: |r: &SysLogininforModel| {
                CellValue::Text(r.ipaddr.clone().unwrap_or_default().into())
            },
        },
        ExcelColumn {
            key: "loginLocation",
            header: ("登录地点", "Login Location"),
            getter: |r: &SysLogininforModel| {
                CellValue::Text(r.login_location.clone().unwrap_or_default().into())
            },
        },
        ExcelColumn {
            key: "browser",
            header: ("浏览器", "Browser"),
            getter: |r: &SysLogininforModel| {
                CellValue::Text(r.browser.clone().unwrap_or_default().into())
            },
        },
        ExcelColumn {
            key: "os",
            header: ("操作系统", "OS"),
            getter: |r: &SysLogininforModel| {
                CellValue::Text(r.os.clone().unwrap_or_default().into())
            },
        },
        ExcelColumn {
            key: "status",
            header: ("状态", "Status"),
            getter: |r: &SysLogininforModel| {
                CellValue::Text({
                    r.status
                        .as_deref()
                        .map(|s| {
                            if s == "0" {
                                crate::tr!("common.status.success")
                            } else {
                                crate::tr!("common.status.failed")
                            }
                        })
                        .unwrap_or_default()
                        .into()
                })
            },
        },
        ExcelColumn {
            key: "msg",
            header: ("操作信息", "Message"),
            getter: |r: &SysLogininforModel| {
                CellValue::Text(r.msg.clone().unwrap_or_default().into())
            },
        },
        ExcelColumn {
            key: "loginTime",
            header: ("登录时间", "Login Time"),
            getter: |r: &SysLogininforModel| CellValue::from_opt_datetime(r.login_time),
        },
    ];

    export_to_excel(
        &crate::tr!("excel.sheet.logininfor"),
        "logininfor",
        &columns,
        &rows,
    )
    .await
}

/// GET /monitor/logininfor/stats?days=7
/// 登录统计：最近 N 天每天成功/失败次数（首页仪表盘用）
///
/// days 参数范围 1-90，默认 7 天
#[utoipa::path(
    get,
    path = "/monitor/logininfor/stats",
    params(
        ("days" = Option<i64>, Query, description = "统计天数（1-90，默认 7）")
    ),
    responses(
        (status = 200, description = "查询成功", body = AjaxResult<Vec<LoginDailyStat>>),
        (status = 500, description = "服务器错误"),
    ),
    tag = "monitor-logininfor"
)]
pub async fn stats(
    State(state): State<Arc<AppState>>,
    Query(params): Query<StatsQuery>,
) -> Result<AjaxResult<Vec<LoginDailyStat>>, AppError> {
    let days = params.days.unwrap_or(7).clamp(1, 90);
    let data = state.logininfor_service.daily_stats(days).await?;
    Ok(AjaxResult::success(data))
}

/// 统计查询参数
#[derive(Debug, Clone, serde::Deserialize, utoipa::IntoParams)]
pub struct StatsQuery {
    pub days: Option<i64>,
}
