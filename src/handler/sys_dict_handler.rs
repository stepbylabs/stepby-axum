//! 字典模块 Handler（Axum 原生实现）
//!
//! 接口路径对齐前端调用规范：
//! - GET    /system/dict/type/list            分页查询字典类型
//! - GET    /system/dict/type/optionselect    查询全部字典类型（下拉用）
//! - GET    /system/dict/type/{dictId}        查询字典类型详情
//! - POST   /system/dict/type                 新增字典类型
//! - PUT    /system/dict/type                 修改字典类型
//! - DELETE /system/dict/type/{dictIds}       批量删除字典类型
//! - GET    /system/dict/data/list            分页查询字典数据
//! - GET    /system/dict/data/type/{dictType} 按字典类型查询字典数据列表
//! - GET    /system/dict/data/{dictCode}      查询字典数据详情
//! - POST   /system/dict/data                 新增字典数据
//! - PUT    /system/dict/data                 修改字典数据
//! - DELETE /system/dict/data/{dictCodes}     批量删除字典数据

use axum::extract::{Form, Path, Query, State};
use axum::response::Response;
use std::sync::Arc;

use crate::common::ValidatedJson;
use crate::common::constants::MAX_BATCH_DELETE_SIZE;
use crate::common::{
    AjaxResult, AppError, TableDataInfo,
    excel::{CellValue, ExcelColumn, export_to_excel},
};
use crate::entity::sys_dict_data::Model as SysDictDataModel;
use crate::entity::sys_dict_type::Model as SysDictTypeModel;
use crate::middleware::Operator;
use crate::service::sys_dict_service::{
    DictDataAddDto, DictDataEditDto, DictDataQueryDto, DictTypeAddDto, DictTypeEditDto,
    DictTypeQueryDto,
};
use crate::state::AppState;
use crate::utils::parse_id_list;

// ==================== 字典类型 Handler ====================

/// GET /system/dict/type/list
/// 分页查询字典类型
#[utoipa::path(
    get,
    path = "/system/dict/type/list",
    params(DictTypeQueryDto),
    responses(
        (status = 200, description = "查询成功", body = TableDataInfo<SysDictTypeModel>),
        (status = 500, description = "服务器错误"),
    ),
    tag = "system-dict"
)]
pub async fn dict_type_list(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    Query(query): Query<DictTypeQueryDto>,
) -> Result<TableDataInfo<SysDictTypeModel>, AppError> {
    // 多租户（§27.8）：平台操作者(0) 全量；租户仅返回「本租户自建类型 + 平台类型」
    let (rows, total) = state
        .dict_service
        .get_dict_type_page(query, Some(operator.tenant_id()))
        .await?;
    Ok(TableDataInfo::new(total, rows))
}

/// GET /system/dict/type/optionselect
/// 查询全部字典类型（前端下拉选择用）
#[utoipa::path(
    get,
    path = "/system/dict/type/optionselect",
    responses(
        (status = 200, description = "查询成功", body = AjaxResult<Vec<SysDictTypeModel>>),
        (status = 500, description = "服务器错误"),
    ),
    tag = "system-dict"
)]
pub async fn dict_type_optionselect(
    State(state): State<Arc<AppState>>,
    operator: Operator,
) -> Result<AjaxResult<Vec<SysDictTypeModel>>, AppError> {
    // 多租户（§27.8）：内容随租户域变化（本租户自建类型 + 平台类型），不可被跨租户共享缓存
    let rows = state
        .dict_service
        .get_all_dict_types(Some(operator.tenant_id()))
        .await?;
    Ok(AjaxResult::success(rows))
}

/// DELETE /system/dict/type/refreshCache
/// 刷新字典缓存
///
/// 删除 Redis 中所有 dict:* 的键，下次查询时自动从 DB 重新加载。
/// 前端收到成功后自行 cleanDict()，下次使用时重新从后端拉取。
#[utoipa::path(
    delete,
    path = "/system/dict/type/refreshCache",
    responses(
        (status = 200, description = "刷新成功", body = AjaxResult<serde_json::Value>),
        (status = 500, description = "服务器错误"),
    ),
    tag = "system-dict"
)]
pub async fn dict_type_refresh_cache(
    State(state): State<Arc<AppState>>,
) -> Result<AjaxResult<()>, AppError> {
    state.dict_service.refresh_all_dict_cache().await?;
    Ok(AjaxResult::success_msg(&crate::tr!("msg.success.refresh")))
}

/// POST /system/dict/type/export
/// 导出字典类型列表为 Excel
///
/// 前端 download() 发送 application/x-www-form-urlencoded，使用 Form 提取器
#[utoipa::path(
    post,
    path = "/system/dict/type/export",
    params(DictTypeQueryDto),
    responses(
        (status = 200, description = "导出成功", content_type = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"),
        (status = 500, description = "服务器错误"),
    ),
    tag = "system-dict"
)]
pub async fn dict_type_export(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    Form(query): Form<DictTypeQueryDto>,
) -> Result<Response, AppError> {
    // 多租户（§27.8）：平台操作者全量导出；租户导出生效视图
    let rows = state
        .dict_service
        .export_dict_types(query, Some(operator.tenant_id()))
        .await?;

    let columns = [
        ExcelColumn {
            key: "dictId",
            header: ("字典主键", "Dict ID"),
            getter: |r: &SysDictTypeModel| CellValue::Number(r.dict_id as f64),
        },
        ExcelColumn {
            key: "dictName",
            header: ("字典名称", "Dict Name"),
            getter: |r: &SysDictTypeModel| {
                CellValue::Text(r.dict_name.clone().unwrap_or_default().into())
            },
        },
        ExcelColumn {
            key: "dictType",
            header: ("字典类型", "Dict Type"),
            getter: |r: &SysDictTypeModel| {
                CellValue::Text(r.dict_type.clone().unwrap_or_default().into())
            },
        },
        ExcelColumn {
            key: "status",
            header: ("状态", "Status"),
            getter: |r: &SysDictTypeModel| {
                CellValue::Text(
                    if r.status.as_deref() == Some("0") {
                        crate::tr!("common.status.normal")
                    } else {
                        crate::tr!("common.status.disabled")
                    }
                    .into(),
                )
            },
        },
        ExcelColumn {
            key: "createTime",
            header: ("创建时间", "Create Time"),
            getter: |r: &SysDictTypeModel| CellValue::from_opt_datetime(r.create_time),
        },
        ExcelColumn {
            key: "remark",
            header: ("备注", "Remark"),
            getter: |r: &SysDictTypeModel| {
                CellValue::Text(r.remark.clone().unwrap_or_default().into())
            },
        },
    ];

    export_to_excel(
        &crate::tr!("excel.sheet.dict_type"),
        "dict_type",
        &columns,
        &rows,
    )
    .await
}

/// GET /system/dict/type/{dictId}
/// 查询字典类型详情
#[utoipa::path(
    get,
    path = "/system/dict/type/{dictId}",
    params(
        ("dictId" = i64, Path, description = "字典类型 ID")
    ),
    responses(
        (status = 200, description = "查询成功", body = AjaxResult<SysDictTypeModel>),
        (status = 404, description = "字典类型不存在"),
    ),
    tag = "system-dict"
)]
pub async fn dict_type_get_info(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    Path(dict_id): Path<i64>,
) -> Result<AjaxResult<SysDictTypeModel>, AppError> {
    // 多租户（§27.8）：租户仅可见平台类型或本租户自建类型，否则 403
    let model = state
        .dict_service
        .get_dict_type_by_id(dict_id, Some(operator.tenant_id()))
        .await?;
    Ok(AjaxResult::success(model))
}

/// POST /system/dict/type
/// 新增字典类型
#[utoipa::path(
    post,
    path = "/system/dict/type",
    request_body = DictTypeAddDto,
    responses(
        (status = 200, description = "新增成功", body = AjaxResult<serde_json::Value>),
        (status = 400, description = "参数错误或字典类型重复"),
    ),
    tag = "system-dict"
)]
pub async fn dict_type_add(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    ValidatedJson(dto): ValidatedJson<DictTypeAddDto>,
) -> Result<AjaxResult<()>, AppError> {
    state
        .dict_service
        .add_dict_type(dto, operator.username(), operator.tenant_id())
        .await?;
    Ok(AjaxResult::success_msg(&crate::tr!("msg.success.add")))
}

/// PUT /system/dict/type
/// 修改字典类型
#[utoipa::path(
    put,
    path = "/system/dict/type",
    request_body = DictTypeEditDto,
    responses(
        (status = 200, description = "修改成功", body = AjaxResult<serde_json::Value>),
        (status = 400, description = "参数错误"),
        (status = 404, description = "字典类型不存在"),
    ),
    tag = "system-dict"
)]
pub async fn dict_type_edit(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    ValidatedJson(dto): ValidatedJson<DictTypeEditDto>,
) -> Result<AjaxResult<()>, AppError> {
    state
        .dict_service
        .edit_dict_type(dto, operator.username(), operator.tenant_id())
        .await?;
    Ok(AjaxResult::success_msg(&crate::tr!("msg.success.edit")))
}

/// DELETE /system/dict/type/{dictIds}
/// 批量删除字典类型（dictIds 为逗号分隔的 ID 字符串）
#[utoipa::path(
    delete,
    path = "/system/dict/type/{dictIds}",
    params(
        ("dictIds" = String, Path, description = "字典类型 ID 列表（逗号分隔）")
    ),
    responses(
        (status = 200, description = "删除成功", body = AjaxResult<serde_json::Value>),
        (status = 400, description = "字典 ID 不合法"),
    ),
    tag = "system-dict"
)]
pub async fn dict_type_remove(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    Path(dict_ids): Path<String>,
) -> Result<AjaxResult<()>, AppError> {
    let ids: Vec<i64> = parse_id_list::<i64>(&dict_ids)?;

    if ids.is_empty() {
        return Err(AppError::bad_request(&crate::tr!("error.dict.id_invalid")));
    }

    if ids.len() > MAX_BATCH_DELETE_SIZE {
        return Err(AppError::bad_request(&crate::tr!(
            "error.common.batch_size_exceeded",
            max = MAX_BATCH_DELETE_SIZE
        )));
    }

    state
        .dict_service
        .delete_dict_types(ids, operator.username(), operator.tenant_id())
        .await?;
    Ok(AjaxResult::success_msg(&crate::tr!("msg.success.delete")))
}

// ==================== 字典数据 Handler ====================

/// GET /system/dict/data/list
/// 分页查询字典数据
#[utoipa::path(
    get,
    path = "/system/dict/data/list",
    params(DictDataQueryDto),
    responses(
        (status = 200, description = "查询成功", body = TableDataInfo<SysDictDataModel>),
        (status = 500, description = "服务器错误"),
    ),
    tag = "system-dict"
)]
pub async fn dict_data_list(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    Query(query): Query<DictDataQueryDto>,
) -> Result<TableDataInfo<SysDictDataModel>, AppError> {
    // 多租户（§27.8）：平台操作者(0) 全量；租户仅返回「平台类型数据 + 本租户自建类型数据」
    let (rows, total) = state
        .dict_service
        .get_dict_data_page(query, Some(operator.tenant_id()))
        .await?;
    Ok(TableDataInfo::new(total, rows))
}

/// GET /system/dict/data/type/{dictType}
/// 按字典类型查询字典数据列表（前端下拉组件用）
#[utoipa::path(
    get,
    path = "/system/dict/data/type/{dictType}",
    params(
        ("dictType" = String, Path, description = "字典类型")
    ),
    responses(
        (status = 200, description = "查询成功", body = AjaxResult<Vec<SysDictDataModel>>),
        (status = 500, description = "服务器错误"),
    ),
    tag = "system-dict"
)]
pub async fn dict_data_by_type(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    Path(dict_type): Path<String>,
) -> Result<AjaxResult<Vec<SysDictDataModel>>, AppError> {
    // 多租户（§27.8）：本租户自建类型数据优先，否则回落平台类型数据
    let rows = state
        .dict_service
        .get_dict_data_by_type(&dict_type, Some(operator.tenant_id()))
        .await?;
    Ok(AjaxResult::success(rows))
}

/// GET /system/dict/data/{dictCode}
/// 查询字典数据详情
#[utoipa::path(
    get,
    path = "/system/dict/data/{dictCode}",
    params(
        ("dictCode" = i64, Path, description = "字典数据 ID")
    ),
    responses(
        (status = 200, description = "查询成功", body = AjaxResult<SysDictDataModel>),
        (status = 404, description = "字典数据不存在"),
    ),
    tag = "system-dict"
)]
pub async fn dict_data_get_info(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    Path(dict_code): Path<i64>,
) -> Result<AjaxResult<SysDictDataModel>, AppError> {
    // 多租户（§27.8）：租户仅可见平台数据或本租户自建数据，否则 403
    let model = state
        .dict_service
        .get_dict_data_by_id(dict_code, Some(operator.tenant_id()))
        .await?;
    Ok(AjaxResult::success(model))
}

/// POST /system/dict/data
/// 新增字典数据
#[utoipa::path(
    post,
    path = "/system/dict/data",
    request_body = DictDataAddDto,
    responses(
        (status = 200, description = "新增成功", body = AjaxResult<serde_json::Value>),
        (status = 400, description = "参数错误"),
    ),
    tag = "system-dict"
)]
pub async fn dict_data_add(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    ValidatedJson(dto): ValidatedJson<DictDataAddDto>,
) -> Result<AjaxResult<()>, AppError> {
    state
        .dict_service
        .add_dict_data(dto, operator.username(), operator.tenant_id())
        .await?;
    Ok(AjaxResult::success_msg(&crate::tr!("msg.success.add")))
}

/// PUT /system/dict/data
/// 修改字典数据
#[utoipa::path(
    put,
    path = "/system/dict/data",
    request_body = DictDataEditDto,
    responses(
        (status = 200, description = "修改成功", body = AjaxResult<serde_json::Value>),
        (status = 400, description = "参数错误"),
        (status = 404, description = "字典数据不存在"),
    ),
    tag = "system-dict"
)]
pub async fn dict_data_edit(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    ValidatedJson(dto): ValidatedJson<DictDataEditDto>,
) -> Result<AjaxResult<()>, AppError> {
    state
        .dict_service
        .edit_dict_data(dto, operator.username(), operator.tenant_id())
        .await?;
    Ok(AjaxResult::success_msg(&crate::tr!("msg.success.edit")))
}

/// DELETE /system/dict/data/{dictCodes}
/// 批量删除字典数据（dictCodes 为逗号分隔的 ID 字符串）
#[utoipa::path(
    delete,
    path = "/system/dict/data/{dictCodes}",
    params(
        ("dictCodes" = String, Path, description = "字典数据 ID 列表（逗号分隔）")
    ),
    responses(
        (status = 200, description = "删除成功", body = AjaxResult<serde_json::Value>),
        (status = 400, description = "字典数据 ID 不合法"),
    ),
    tag = "system-dict"
)]
pub async fn dict_data_remove(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    Path(dict_codes): Path<String>,
) -> Result<AjaxResult<()>, AppError> {
    let ids: Vec<i64> = parse_id_list::<i64>(&dict_codes)?;

    if ids.is_empty() {
        return Err(AppError::bad_request(&crate::tr!(
            "error.dict.data_id_invalid"
        )));
    }

    if ids.len() > MAX_BATCH_DELETE_SIZE {
        return Err(AppError::bad_request(&crate::tr!(
            "error.common.batch_size_exceeded",
            max = MAX_BATCH_DELETE_SIZE
        )));
    }

    state
        .dict_service
        .delete_dict_data(ids, operator.username(), operator.tenant_id())
        .await?;
    Ok(AjaxResult::success_msg(&crate::tr!("msg.success.delete")))
}

/// POST /system/dict/data/export
/// 导出字典数据列表
#[utoipa::path(
    post,
    path = "/system/dict/data/export",
    params(DictDataQueryDto),
    responses(
        (status = 200, description = "字典数据 xlsx", content_type = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"),
        (status = 500, description = "服务器错误"),
    ),
    tag = "system-dict"
)]
pub async fn dict_data_export(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    Form(query): Form<DictDataQueryDto>,
) -> Result<Response, AppError> {
    // 多租户（§27.8）：平台操作者全量导出；租户导出生效视图
    let rows = state
        .dict_service
        .export_dict_data(query, Some(operator.tenant_id()))
        .await?;

    let columns = [
        ExcelColumn {
            key: "dictCode",
            header: ("字典编码", "Dict Code"),
            getter: |r: &SysDictDataModel| CellValue::Number(r.dict_code as f64),
        },
        ExcelColumn {
            key: "dictLabel",
            header: ("字典标签", "Dict Label"),
            getter: |r: &SysDictDataModel| {
                CellValue::Text(r.dict_label.clone().unwrap_or_default().into())
            },
        },
        ExcelColumn {
            key: "dictValue",
            header: ("字典键值", "Dict Value"),
            getter: |r: &SysDictDataModel| {
                CellValue::Text(r.dict_value.clone().unwrap_or_default().into())
            },
        },
        ExcelColumn {
            key: "dictSort",
            header: ("字典排序", "Sort"),
            getter: |r: &SysDictDataModel| CellValue::Number(f64::from(r.dict_sort.unwrap_or(0))),
        },
        ExcelColumn {
            key: "status",
            header: ("状态", "Status"),
            getter: |r: &SysDictDataModel| {
                CellValue::Text(
                    if r.status.as_deref() == Some("0") {
                        crate::tr!("common.status.normal")
                    } else {
                        crate::tr!("common.status.disabled")
                    }
                    .into(),
                )
            },
        },
        ExcelColumn {
            key: "remark",
            header: ("备注", "Remark"),
            getter: |r: &SysDictDataModel| {
                CellValue::Text(r.remark.clone().unwrap_or_default().into())
            },
        },
        ExcelColumn {
            key: "createTime",
            header: ("创建时间", "Create Time"),
            getter: |r: &SysDictDataModel| CellValue::from_opt_datetime(r.create_time),
        },
    ];

    export_to_excel(
        &crate::tr!("excel.sheet.dict_data"),
        "dict_data",
        &columns,
        &rows,
    )
    .await
}
