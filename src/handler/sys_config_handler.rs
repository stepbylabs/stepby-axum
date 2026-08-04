//! 参数配置 Handler（Axum 原生实现）
//!
//! 接口路径对齐 ruoyi-vue3-ts 前端：
//! - GET    /system/config/list                 分页查询参数配置
//! - GET    /system/config/configKey/{configKey} 按 key 查询参数值（需 system:config:query 权限，P0-R81-003）
//! - GET    /system/config/{configId}           查询参数配置详情
//! - POST   /system/config                      新增参数配置
//! - PUT    /system/config                      修改参数配置
//! - DELETE /system/config/{configIds}          批量删除参数配置
//! - DELETE /system/config/refreshCache         刷新缓存
//! - POST   /system/config/export               导出参数配置

use std::sync::Arc;
use axum::extract::{Form, Path, Query, State};
use axum::response::Response;

use crate::common::excel::{export_to_excel, CellValue, ExcelColumn};
use crate::common::ValidatedJson;
use crate::common::{AjaxResult, AppError, TableDataInfo};
use crate::entity::sys_config::Model as SysConfigModel;
use crate::middleware::Operator;
use crate::service::sys_config_service::{
    ConfigAddDto, ConfigEditDto, ConfigQueryDto,
};
use crate::state::AppState;
use crate::common::constants::MAX_BATCH_DELETE_SIZE;
use crate::utils::parse_id_list;

/// GET /system/config/list
/// 分页查询参数配置
#[utoipa::path(
    get,
    path = "/system/config/list",
    params(ConfigQueryDto),
    responses(
        (status = 200, description = "查询成功", body = TableDataInfo<SysConfigModel>),
        (status = 500, description = "服务器错误"),
    ),
    tag = "system-config"
)]
pub async fn list(
    State(state): State<Arc<AppState>>,
    Query(query): Query<ConfigQueryDto>,
) -> Result<TableDataInfo<SysConfigModel>, AppError> {
    let (rows, total) = state.config_service.get_config_page(query).await?;
    Ok(TableDataInfo::new(total, rows))
}

/// GET /system/config/configKey/{configKey}
/// 按 config_key 查询参数值（需 system:config:query 权限，由 permission_middleware 强制校验，P0-R81-003）
#[utoipa::path(
    get,
    path = "/system/config/configKey/{configKey}",
    params(
        ("configKey" = String, Path, description = "参数键名")
    ),
    responses(
        (status = 200, description = "查询成功", body = AjaxResult<String>),
        (status = 404, description = "参数不存在"),
    ),
    tag = "system-config"
)]
pub async fn get_config_by_key(
    State(state): State<Arc<AppState>>,
    Path(config_key): Path<String>,
) -> Result<AjaxResult<String>, AppError> {
    let value = state.config_service.get_config_by_key(&config_key).await?;
    Ok(AjaxResult::success(value))
}

/// GET /system/config/{configId}
/// 查询参数配置详情
#[utoipa::path(
    get,
    path = "/system/config/{configId}",
    params(
        ("configId" = i64, Path, description = "参数 ID")
    ),
    responses(
        (status = 200, description = "查询成功", body = AjaxResult<SysConfigModel>),
        (status = 404, description = "参数不存在"),
    ),
    tag = "system-config"
)]
pub async fn get_info(
    State(state): State<Arc<AppState>>,
    Path(config_id): Path<i64>,
) -> Result<AjaxResult<SysConfigModel>, AppError> {
    let model = state.config_service.get_config_by_id(config_id).await?;
    Ok(AjaxResult::success(model))
}

/// POST /system/config
/// 新增参数配置
#[utoipa::path(
    post,
    path = "/system/config",
    request_body = ConfigAddDto,
    responses(
        (status = 200, description = "新增成功", body = AjaxResult<serde_json::Value>),
        (status = 400, description = "参数错误或参数键名重复"),
    ),
    tag = "system-config"
)]
pub async fn add(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    ValidatedJson(dto): ValidatedJson<ConfigAddDto>,
) -> Result<AjaxResult<()>, AppError> {
    state.config_service.add_config(dto, operator.username()).await?;
    Ok(AjaxResult::success_msg(&crate::tr!("msg.success.add")))
}

/// PUT /system/config
/// 修改参数配置
#[utoipa::path(
    put,
    path = "/system/config",
    request_body = ConfigEditDto,
    responses(
        (status = 200, description = "修改成功", body = AjaxResult<serde_json::Value>),
        (status = 400, description = "参数错误"),
        (status = 404, description = "参数不存在"),
    ),
    tag = "system-config"
)]
pub async fn edit(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    ValidatedJson(dto): ValidatedJson<ConfigEditDto>,
) -> Result<AjaxResult<()>, AppError> {
    state.config_service.edit_config(dto, operator.username()).await?;
    Ok(AjaxResult::success_msg(&crate::tr!("msg.success.edit")))
}

/// DELETE /system/config/{configIds}
/// 批量删除参数配置（configIds 为逗号分隔的 ID 字符串）
#[utoipa::path(
    delete,
    path = "/system/config/{configIds}",
    params(
        ("configIds" = String, Path, description = "参数 ID 列表（逗号分隔）")
    ),
    responses(
        (status = 200, description = "删除成功", body = AjaxResult<serde_json::Value>),
        (status = 400, description = "参数 ID 不合法"),
    ),
    tag = "system-config"
)]
pub async fn remove(
    State(state): State<Arc<AppState>>,
    Path(config_ids): Path<String>,
) -> Result<AjaxResult<()>, AppError> {
    let ids: Vec<i64> = parse_id_list::<i64>(&config_ids);

    if ids.is_empty() {
        return Err(AppError::bad_request(&crate::tr!("error.config.id_invalid")));
    }
    if ids.len() > MAX_BATCH_DELETE_SIZE {
        return Err(AppError::bad_request(&crate::tr!(
            "error.common.batch_size_exceeded",
            max = MAX_BATCH_DELETE_SIZE
        )));
    }

    state.config_service.delete_configs(ids).await?;
    Ok(AjaxResult::success_msg(&crate::tr!("msg.success.delete")))
}

/// DELETE /system/config/refreshCache
/// 刷新参数缓存
///
/// 当前后端参数查询直接走 DB，无 Redis 缓存层，此接口直接返回成功。
#[utoipa::path(
    delete,
    path = "/system/config/refreshCache",
    responses(
        (status = 200, description = "刷新成功", body = AjaxResult<serde_json::Value>),
        (status = 500, description = "服务器错误"),
    ),
    tag = "system-config"
)]
pub async fn refresh_cache(
    State(state): State<Arc<AppState>>,
) -> Result<AjaxResult<()>, AppError> {
    state.config_service.refresh_cache().await?;
    Ok(AjaxResult::success_msg(&crate::tr!("msg.success.refresh")))
}

/// POST /system/config/export
/// 导出参数配置列表为 Excel
///
/// 前端 download() 发送 application/x-www-form-urlencoded，使用 Form 提取器
#[utoipa::path(
    post,
    path = "/system/config/export",
    params(ConfigQueryDto),
    responses(
        (status = 200, description = "导出成功", content_type = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"),
        (status = 500, description = "服务器错误"),
    ),
    tag = "system-config"
)]
pub async fn export(
    State(state): State<Arc<AppState>>,
    Form(query): Form<ConfigQueryDto>,
) -> Result<Response, AppError> {
    let rows = state.config_service.export_configs(query).await?;

    let columns = [
        ExcelColumn { key: "configId", header: ("参数主键", "Config ID"), getter: |r: &SysConfigModel| CellValue::Text(r.config_id.to_string().into()) },
        ExcelColumn { key: "configName", header: ("参数名称", "Config Name"), getter: |r: &SysConfigModel| CellValue::Text(r.config_name.clone().unwrap_or_default().into()) },
        ExcelColumn { key: "configKey", header: ("参数键名", "Config Key"), getter: |r: &SysConfigModel| CellValue::Text(r.config_key.clone().into()) },
        ExcelColumn { key: "configValue", header: ("参数键值", "Config Value"), getter: |r: &SysConfigModel| CellValue::Text(r.config_value.clone().unwrap_or_default().into()) },
        ExcelColumn { key: "isBuiltIn", header: ("系统内置", "Built-in"), getter: |r: &SysConfigModel| CellValue::Text(match r.config_type.as_deref() {
                Some("Y") => crate::tr!("common.yes"),
                Some("N") => crate::tr!("common.no"),
                _ => String::new(),
            }.into()) },
        ExcelColumn { key: "remark", header: ("备注", "Remark"), getter: |r: &SysConfigModel| CellValue::Text(r.remark.clone().unwrap_or_default().into()) },
        ExcelColumn { key: "createTime", header: ("创建时间", "Create Time"), getter: |r: &SysConfigModel| CellValue::Text({
                r.create_time
                    .map(|dt| dt.format("%Y-%m-%d %H:%M:%S").to_string())
                    .unwrap_or_default()
                    .into()
            }) },
    ];

    export_to_excel(&crate::tr!("excel.sheet.config"), "config", &columns, &rows).await
}
