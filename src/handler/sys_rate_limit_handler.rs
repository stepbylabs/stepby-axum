//! API 限流配置 Handler（Axum 原生实现）
//!
//! 接口路径对齐前端：
//! - GET    /system/rateLimit/list         分页查询限流配置
//! - GET    /system/rateLimit/{id}         查询限流配置详情
//! - POST   /system/rateLimit              新增限流配置
//! - PUT    /system/rateLimit              修改限流配置
//! - DELETE /system/rateLimit/{ids}        批量删除限流配置（ids 为逗号分隔）
//! - POST   /system/rateLimit/export       导出限流配置

use axum::extract::{Form, Path, Query, State};
use axum::response::Response;
use std::sync::Arc;

use crate::common::ValidatedJson;
use crate::common::constants::MAX_BATCH_DELETE_SIZE;
use crate::common::excel::{CellValue, ExcelColumn, export_to_excel};
use crate::common::{AjaxResult, AppError, TableDataInfo};
use crate::entity::sys_rate_limit::Model as SysRateLimitModel;
use crate::middleware::Operator;
use crate::service::sys_rate_limit_service::{
    RateLimitAddDto, RateLimitEditDto, RateLimitQueryDto,
};
use crate::state::AppState;
use crate::utils::parse_id_list;

/// GET /system/rateLimit/list
/// 分页查询限流配置
#[utoipa::path(
    get,
    path = "/system/rateLimit/list",
    params(RateLimitQueryDto),
    responses(
        (status = 200, description = "查询成功", body = TableDataInfo<SysRateLimitModel>),
        (status = 500, description = "服务器错误"),
    ),
    tag = "system-rate-limit"
)]
pub async fn list(
    State(state): State<Arc<AppState>>,
    Query(query): Query<RateLimitQueryDto>,
) -> Result<TableDataInfo<SysRateLimitModel>, AppError> {
    let (rows, total) = state.rate_limit_service.list(query).await?;
    Ok(TableDataInfo::new(total, rows))
}

/// GET /system/rateLimit/{id}
/// 查询限流配置详情
#[utoipa::path(
    get,
    path = "/system/rateLimit/{id}",
    params(
        ("id" = i64, Path, description = "限流配置 ID")
    ),
    responses(
        (status = 200, description = "查询成功", body = AjaxResult<SysRateLimitModel>),
        (status = 404, description = "限流配置不存在"),
    ),
    tag = "system-rate-limit"
)]
pub async fn get_info(
    State(state): State<Arc<AppState>>,
    Path(id): Path<i64>,
) -> Result<AjaxResult<SysRateLimitModel>, AppError> {
    let model = state.rate_limit_service.get_by_id(id).await?;
    Ok(AjaxResult::success(model))
}

/// POST /system/rateLimit
/// 新增限流配置
#[utoipa::path(
    post,
    path = "/system/rateLimit",
    request_body = RateLimitAddDto,
    responses(
        (status = 200, description = "新增成功", body = AjaxResult<serde_json::Value>),
        (status = 400, description = "参数错误或路由前缀重复"),
    ),
    tag = "system-rate-limit"
)]
pub async fn add(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    ValidatedJson(dto): ValidatedJson<RateLimitAddDto>,
) -> Result<AjaxResult<()>, AppError> {
    state
        .rate_limit_service
        .add(dto, operator.username())
        .await?;
    Ok(AjaxResult::success_msg(&crate::tr!("msg.success.add")))
}

/// PUT /system/rateLimit
/// 修改限流配置
#[utoipa::path(
    put,
    path = "/system/rateLimit",
    request_body = RateLimitEditDto,
    responses(
        (status = 200, description = "修改成功", body = AjaxResult<serde_json::Value>),
        (status = 400, description = "参数错误"),
        (status = 404, description = "限流配置不存在"),
    ),
    tag = "system-rate-limit"
)]
pub async fn edit(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    ValidatedJson(dto): ValidatedJson<RateLimitEditDto>,
) -> Result<AjaxResult<()>, AppError> {
    state
        .rate_limit_service
        .edit(dto, operator.username())
        .await?;
    Ok(AjaxResult::success_msg(&crate::tr!("msg.success.edit")))
}

/// DELETE /system/rateLimit/{ids}
/// 批量删除限流配置（ids 为逗号分隔的 ID 字符串）
#[utoipa::path(
    delete,
    path = "/system/rateLimit/{ids}",
    params(
        ("ids" = String, Path, description = "限流配置 ID 列表（逗号分隔）")
    ),
    responses(
        (status = 200, description = "删除成功", body = AjaxResult<serde_json::Value>),
        (status = 400, description = "参数 ID 不合法"),
    ),
    tag = "system-rate-limit"
)]
pub async fn remove(
    State(state): State<Arc<AppState>>,
    Path(ids): Path<String>,
) -> Result<AjaxResult<()>, AppError> {
    let ids: Vec<i64> = parse_id_list::<i64>(&ids);

    if ids.is_empty() {
        return Err(AppError::bad_request(&crate::tr!(
            "error.rate_limit.id_invalid"
        )));
    }
    if ids.len() > MAX_BATCH_DELETE_SIZE {
        return Err(AppError::bad_request(&crate::tr!(
            "error.common.batch_size_exceeded",
            max = MAX_BATCH_DELETE_SIZE
        )));
    }

    state.rate_limit_service.remove(ids).await?;
    Ok(AjaxResult::success_msg(&crate::tr!("msg.success.delete")))
}

/// POST /system/rateLimit/export
/// 导出限流配置列表为 Excel
///
/// 前端 download() 发送 application/x-www-form-urlencoded，使用 Form 提取器
#[utoipa::path(
    post,
    path = "/system/rateLimit/export",
    params(RateLimitQueryDto),
    responses(
        (status = 200, description = "导出成功", content_type = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"),
        (status = 500, description = "服务器错误"),
    ),
    tag = "system-rate-limit"
)]
pub async fn export(
    State(state): State<Arc<AppState>>,
    Form(query): Form<RateLimitQueryDto>,
) -> Result<Response, AppError> {
    let rows = state.rate_limit_service.export(query).await?;

    let columns = [
        ExcelColumn {
            key: "id",
            header: ("ID", "ID"),
            getter: |r: &SysRateLimitModel| CellValue::Number(r.id as f64),
        },
        ExcelColumn {
            key: "routePrefix",
            header: ("路由前缀", "Route Prefix"),
            getter: |r: &SysRateLimitModel| CellValue::Text(r.route_pattern.clone().into()),
        },
        ExcelColumn {
            key: "bucketCapacity",
            header: ("桶容量", "Bucket Capacity"),
            getter: |r: &SysRateLimitModel| CellValue::Number(f64::from(r.capacity)),
        },
        ExcelColumn {
            key: "refillRate",
            header: ("补充速率(每秒)", "Refill Rate (per sec)"),
            getter: |r: &SysRateLimitModel| CellValue::Number(r.refill_per_second),
        },
        ExcelColumn {
            key: "enabled",
            header: ("是否启用", "Enabled"),
            getter: |r: &SysRateLimitModel| {
                CellValue::Text(
                    if r.enabled {
                        crate::tr!("common.yes")
                    } else {
                        crate::tr!("common.no")
                    }
                    .into(),
                )
            },
        },
        ExcelColumn {
            key: "description",
            header: ("描述", "Description"),
            getter: |r: &SysRateLimitModel| {
                CellValue::Text(r.description.clone().unwrap_or_default().into())
            },
        },
        ExcelColumn {
            key: "createTime",
            header: ("创建时间", "Create Time"),
            getter: |r: &SysRateLimitModel| CellValue::from_opt_datetime(r.create_time),
        },
    ];

    export_to_excel(
        &crate::tr!("excel.sheet.rate_limit"),
        "rate_limit",
        &columns,
        &rows,
    )
    .await
}
