//! 参数配置 Handler（Axum 原生实现）
//!
//! 接口路径对齐前端调用规范：
//! - GET    /system/config/list                 分页查询参数配置
//! - GET    /system/config/configKey/{configKey} 按 key 查询参数值（需 system:config:query 权限，P0-R81-003）
//! - GET    /system/config/{configId}           查询参数配置详情
//! - POST   /system/config                      新增参数配置
//! - PUT    /system/config                      修改参数配置
//! - DELETE /system/config/{configIds}          批量删除参数配置
//! - DELETE /system/config/refreshCache         刷新缓存
//! - POST   /system/config/export               导出参数配置

use axum::extract::{Form, Path, Query, State};
use axum::response::Response;
use std::sync::Arc;

use crate::common::ValidatedJson;
use crate::common::constants::MAX_BATCH_DELETE_SIZE;
use crate::common::excel::{CellValue, ExcelColumn, export_to_excel};
use crate::common::{AjaxResult, AppError, TableDataInfo};
use crate::entity::sys_config::Model as SysConfigModel;
use crate::middleware::Operator;
use crate::service::sys_config_service::{ConfigAddDto, ConfigEditDto, ConfigQueryDto};
use crate::state::AppState;
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
    operator: Operator,
    Query(query): Query<ConfigQueryDto>,
) -> Result<TableDataInfo<SysConfigModel>, AppError> {
    // 治理视图（§27.8）：平台操作者(0) 全量；租户仅返回「本租户行 + 平台 visible_to_tenant='1' 行」
    let (rows, total) = state
        .config_service
        .get_config_page(query, Some(operator.tenant_id()))
        .await?;
    Ok(TableDataInfo::new(total, rows))
}

/// GET /system/config/governance-locked
/// 平台锁定（Coverage::Locked）参数键清单（E-04 参数治理 UI 辅助数据）
///
/// 前端编辑对话框据此禁用锁定键的治理控件（后端 resolve_governance 恒强制
/// platform_only/'0'/'0' 兜底）。治理视图=平台专属：租户的列表行恒为
/// tenant_private，无锁定语义，故仅平台操作者可取（tenant_id=0 双保险）。
#[utoipa::path(
    get,
    path = "/system/config/governance-locked",
    responses(
        (status = 200, description = "查询成功", body = AjaxResult<Vec<String>>),
        (status = 403, description = "非平台操作者"),
    ),
    tag = "system-config"
)]
pub async fn governance_locked_keys(
    State(state): State<Arc<AppState>>,
    operator: Operator,
) -> Result<AjaxResult<Vec<String>>, AppError> {
    if operator.tenant_id() != 0 {
        return Err(AppError::from(
            crate::common::error::ServiceError::forbidden(&crate::tr!(
                "error.config.governance_platform_only"
            )),
        ));
    }
    let _ = state; // AppState 一致性签名；清单为编译期常量
    Ok(AjaxResult::success(
        crate::service::sys_config_service::platform_locked_keys()
            .map(|s| s.to_string())
            .collect(),
    ))
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
    operator: Operator,
    Path(config_key): Path<String>,
) -> Result<AjaxResult<String>, AppError> {
    // 治理视图（§27.8）：租户读取平台不可见行（含 platform_only）时脱敏为 ***
    let value = state
        .config_service
        .get_config_by_key(&config_key, Some(operator.tenant_id()))
        .await?;
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
    operator: Operator,
    Path(config_id): Path<i64>,
) -> Result<AjaxResult<SysConfigModel>, AppError> {
    // 治理视图（§27.8）：租户仅可见本租户行或平台 visible_to_tenant='1' 行，否则 403
    let model = state
        .config_service
        .get_config_by_id(config_id, Some(operator.tenant_id()))
        .await?;
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
    state
        .config_service
        .add_config(dto, operator.username(), operator.tenant_id())
        .await?;
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
    state
        .config_service
        .edit_config(dto, operator.username(), operator.tenant_id())
        .await?;
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
    operator: Operator,
    Path(config_ids): Path<String>,
) -> Result<AjaxResult<()>, AppError> {
    let ids: Vec<i64> = parse_id_list::<i64>(&config_ids)?;

    if ids.is_empty() {
        return Err(AppError::bad_request(&crate::tr!(
            "error.config.id_invalid"
        )));
    }
    if ids.len() > MAX_BATCH_DELETE_SIZE {
        return Err(AppError::bad_request(&crate::tr!(
            "error.common.batch_size_exceeded",
            max = MAX_BATCH_DELETE_SIZE
        )));
    }

    state
        .config_service
        .delete_configs(ids, operator.username(), operator.tenant_id())
        .await?;
    Ok(AjaxResult::success_msg(&crate::tr!("msg.success.delete")))
}

/// DELETE /system/config/refreshCache
/// 刷新参数缓存
///
/// 生效参数走**两层共享缓存**（平台默认层 `config:def:{key}` + 租户覆盖层
/// `config:{tid}:{key}`，TTL 300s，见 `SysConfigService::get_config_value_by_key_cached`），
/// 本接口扫描并删除全部 `config:*` 键，令其它节点/进程的下一次读取回落查库。
///
/// **不是 no-op**（旧文档写"直接走 DB、无缓存层"与实现相反）：scan/del 失败一律 5xx ——
/// 这是显式用户动作，不能把"一个键都没删掉"答复成"刷新成功"。
#[utoipa::path(
    delete,
    path = "/system/config/refreshCache",
    responses(
        (status = 200, description = "刷新成功", body = AjaxResult<serde_json::Value>),
        (status = 429, description = "缓存维护入口繁忙"),
        (status = 500, description = "扫描或删除缓存键失败"),
    ),
    tag = "system-config"
)]
pub async fn refresh_cache(State(state): State<Arc<AppState>>) -> Result<AjaxResult<()>, AppError> {
    let _gate = crate::common::resource_gate::try_enter(
        crate::common::resource_gate::HeavyEntry::CacheMaintenance,
    )?;
    let deleted = state.config_service.refresh_cache().await?;
    tracing::debug!(deleted, "参数缓存已刷新（显式请求）");
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
    operator: Operator,
    Form(query): Form<ConfigQueryDto>,
) -> Result<Response, AppError> {
    // 治理视图（§27.8）：平台操作者全量导出；租户导出生效视图（绝不导出 platform_only）
    let rows = state
        .config_service
        .export_configs(query, Some(operator.tenant_id()))
        .await?;

    let columns = [
        ExcelColumn {
            key: "configId",
            header: ("参数主键", "Config ID"),
            getter: |r: &SysConfigModel| CellValue::Number(r.config_id as f64),
        },
        ExcelColumn {
            key: "configName",
            header: ("参数名称", "Config Name"),
            getter: |r: &SysConfigModel| {
                CellValue::Text(r.config_name.clone().unwrap_or_default().into())
            },
        },
        ExcelColumn {
            key: "configKey",
            header: ("参数键名", "Config Key"),
            getter: |r: &SysConfigModel| CellValue::Text(r.config_key.clone().into()),
        },
        ExcelColumn {
            key: "configValue",
            header: ("参数键值", "Config Value"),
            getter: |r: &SysConfigModel| {
                CellValue::Text(r.config_value.clone().unwrap_or_default().into())
            },
        },
        ExcelColumn {
            key: "isBuiltIn",
            header: ("系统内置", "Built-in"),
            getter: |r: &SysConfigModel| {
                CellValue::Text(
                    match r.config_type.as_deref() {
                        Some("Y") => crate::tr!("common.yes"),
                        Some("N") => crate::tr!("common.no"),
                        _ => String::new(),
                    }
                    .into(),
                )
            },
        },
        ExcelColumn {
            key: "remark",
            header: ("备注", "Remark"),
            getter: |r: &SysConfigModel| {
                CellValue::Text(r.remark.clone().unwrap_or_default().into())
            },
        },
        ExcelColumn {
            key: "createTime",
            header: ("创建时间", "Create Time"),
            getter: |r: &SysConfigModel| CellValue::from_opt_datetime(r.create_time),
        },
    ];

    export_to_excel(&crate::tr!("excel.sheet.config"), "config", &columns, &rows).await
}
