//! 代码生成模块 Handler（Axum 原生实现）
//!
//! 接口路径对齐前端调用规范：
//! - GET    /tool/gen/list            分页查询代码生成业务表
//! - GET    /tool/gen/db/list         查询数据库表列表（导入用）
//! - GET    /tool/gen/{tableId}       查询代码生成业务表详情
//! - POST   /tool/gen/importTable     导入表
//! - POST   /tool/gen/createTable     创建表
//! - PUT    /tool/gen                 修改代码生成配置
//! - DELETE /tool/gen/{tableIds}      批量删除代码生成业务表
//! - GET    /tool/gen/preview/{tableId}  预览生成代码
//! - GET    /tool/gen/genCode/{tableName} 生成代码（ZIP 下载）
//! - GET    /tool/gen/synchDb/{tableName}  同步数据库

use std::sync::Arc;

use axum::Json;
use axum::extract::{Path, Query, State};
use axum::response::{IntoResponse, Response};
use serde::Serialize;

use crate::common::{AjaxResult, AppError, TableDataInfo};
use crate::middleware::Operator;
use crate::repository::gen_table::DbTableInfo;
use crate::service::gen_table_service::{
    CreateTableDto, CreateTableResultVo, DbTableQueryDto, GenTableEditDto, GenTableInfoVo,
    GenTableQueryDto, PreviewCodeVo,
};
use crate::state::AppState;
use crate::utils::parse_id_list;

/// GET /tool/gen/list
/// 分页查询代码生成业务表
pub async fn list(
    State(state): State<Arc<AppState>>,
    Query(query): Query<GenTableQueryDto>,
) -> Result<TableDataInfo<crate::entity::gen_table::Model>, AppError> {
    let (rows, total) = state.gen_table_service.get_page(query).await?;
    Ok(TableDataInfo::new(total, rows))
}

/// GET /tool/gen/db/list
/// 查询数据库表列表（导入表用，排除已导入的表）
pub async fn db_list(
    State(state): State<Arc<AppState>>,
    Query(query): Query<DbTableQueryDto>,
) -> Result<TableDataInfo<DbTableInfo>, AppError> {
    let (rows, total) = state.gen_table_service.get_db_table_page(query).await?;
    Ok(TableDataInfo::new(total, rows))
}

/// GET /tool/gen/{tableId}
/// 查询代码生成业务表详情（包含列信息和所有表列表）
pub async fn get_table(
    State(state): State<Arc<AppState>>,
    Path(table_id): Path<i64>,
) -> Result<AjaxResult<GenTableInfoVo>, AppError> {
    let info = state.gen_table_service.get_info(table_id).await?;
    Ok(AjaxResult::success(info))
}

/// POST /tool/gen/importTable
/// 导入表（从数据库元数据导入）
pub async fn import_table(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    Query(params): Query<ImportTableParams>,
) -> Result<AjaxResult<()>, AppError> {
    let table_names: Vec<&str> = params
        .tables
        .split(',')
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .collect();
    if table_names.is_empty() {
        return Err(AppError::bad_request(&crate::tr!(
            "error.gen.table_select_required"
        )));
    }
    // P1 修复：与同文件 gen_code/synch_db 一致，逐个白名单校验表名（防 CRLF/引号/路径穿越注入）
    for table_name in &table_names {
        validate_table_name(table_name)?;
    }
    for table_name in table_names {
        state
            .gen_table_service
            .import_table(table_name, operator.username())
            .await?;
    }
    Ok(AjaxResult::success_msg(&crate::tr!("msg.success.import")))
}

/// 导入表请求参数
#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ImportTableParams {
    /// 要导入的表名列表（逗号分隔）
    pub tables: String,
}

/// POST /tool/gen/createTable
/// 创建表（结构化建表，方案 A：消除 SQL 注入）
///
/// 通过结构化字段描述表结构，后端用 sea-query 声明式构造 DDL，
/// 自动适配 PostgreSQL/MySQL/SQLite 方言。
///
/// 安全说明：
/// - 不接收原始 SQL，完全消除 SQL 注入风险
/// - 表名/列名通过白名单正则校验
/// - 类型枚举固定，无法传入任意类型
pub async fn create_table(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    Json(dto): Json<CreateTableDto>,
) -> Result<AjaxResult<CreateTableResultVo>, AppError> {
    crate::common::i18n::validate(&dto)?;
    let result = state
        .gen_table_service
        .create_table_structured(dto, operator.username())
        .await?;
    Ok(AjaxResult::success(result))
}

/// PUT /tool/gen
/// 修改代码生成配置
pub async fn update_table(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    Json(dto): Json<GenTableEditDto>,
) -> Result<AjaxResult<()>, AppError> {
    state
        .gen_table_service
        .update_table(dto, operator.username())
        .await?;
    Ok(AjaxResult::success_msg(&crate::tr!("msg.success.edit")))
}

/// DELETE /tool/gen/{tableIds}
/// 批量删除代码生成业务表
pub async fn delete_table(
    State(state): State<Arc<AppState>>,
    Path(table_ids): Path<String>,
) -> Result<AjaxResult<()>, AppError> {
    let ids: Vec<i64> = parse_id_list::<i64>(&table_ids);
    if ids.is_empty() {
        return Err(AppError::bad_request(&crate::tr!(
            "error.gen.table_id_invalid"
        )));
    }
    // P1 修复：批量删除上限（与其他删除端点一致，防批量删除风暴）
    if ids.len() > crate::common::constants::MAX_BATCH_DELETE_SIZE {
        return Err(AppError::bad_request(&crate::tr!(
            "error.common.batch_size_exceeded",
            max = crate::common::constants::MAX_BATCH_DELETE_SIZE
        )));
    }
    state.gen_table_service.delete_tables(ids).await?;
    Ok(AjaxResult::success_msg(&crate::tr!("msg.success.delete")))
}

/// 预览代码响应包装
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PreviewResponse {
    pub code: i32,
    pub msg: String,
    pub data: PreviewCodeVo,
}

crate::impl_into_response!(PreviewResponse);

/// GET /tool/gen/preview/{tableId}
/// 预览生成代码
pub async fn preview(
    State(state): State<Arc<AppState>>,
    Path(table_id): Path<i64>,
) -> Result<PreviewResponse, AppError> {
    let data = state.gen_table_service.preview(table_id).await?;
    Ok(PreviewResponse {
        code: 200,
        msg: crate::tr!("msg.success.default"),
        data,
    })
}

/// 校验表名仅含字母、数字、下划线，长度 1-64（SEC-004：防 CRLF / 引号 / 路径穿越注入）
fn validate_table_name(table_name: &str) -> Result<(), AppError> {
    if table_name.is_empty()
        || table_name.len() > 64
        || !table_name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_')
    {
        return Err(AppError::bad_request(&crate::tr!(
            "error.gen.table_name_invalid"
        )));
    }
    Ok(())
}

/// GET /tool/gen/genCode/{tableName}
/// 生成代码（返回 ZIP 文件下载）
pub async fn gen_code(
    State(state): State<Arc<AppState>>,
    Path(table_name): Path<String>,
) -> Result<Response, AppError> {
    // SEC-004：白名单校验表名，防 CRLF / 引号 / 路径穿越
    validate_table_name(&table_name)?;

    let zip_bytes = state.gen_table_service.gen_code(&table_name).await?;

    // 返回 ZIP 文件响应
    let mut headers = axum::http::HeaderMap::new();
    let filename = format!("{}.zip", table_name);
    let content_disposition = format!("attachment; filename=\"{}\"", filename);
    if let Ok(val) = axum::http::HeaderValue::from_str(&content_disposition) {
        headers.insert(axum::http::header::CONTENT_DISPOSITION, val);
    }
    headers.insert(
        axum::http::header::CONTENT_TYPE,
        axum::http::HeaderValue::from_static("application/zip"),
    );
    if let Ok(val) = axum::http::HeaderValue::from_str(&zip_bytes.len().to_string()) {
        headers.insert(axum::http::header::CONTENT_LENGTH, val);
    }

    Ok((axum::http::StatusCode::OK, headers, zip_bytes).into_response())
}

/// POST /tool/gen/synchDb/{tableName}
/// 同步数据库（从数据库更新表字段信息）
#[utoipa::path(
    post,
    path = "/tool/gen/synchDb/{tableName}",
    params(
        ("tableName" = String, Path, description = "表名")
    ),
    responses(
        (status = 200, description = "同步成功", body = AjaxResult<serde_json::Value>),
    ),
    tag = "tool-gen"
)]
pub async fn synch_db(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    Path(table_name): Path<String>,
) -> Result<AjaxResult<()>, AppError> {
    // SEC-004：白名单校验表名
    validate_table_name(&table_name)?;

    state
        .gen_table_service
        .synch_db(&table_name, operator.username())
        .await?;
    Ok(AjaxResult::success_msg(&crate::tr!("msg.success.sync")))
}

/// 批量生成代码请求参数
#[derive(Debug, serde::Deserialize, utoipa::IntoParams)]
pub struct BatchGenCodeParams {
    /// 要生成的表名列表（逗号分隔）
    pub tables: String,
}

/// GET /tool/gen/batchGenCode
/// 批量生成代码（多表打包成一个 ZIP 下载）
///
/// 安全要点：
/// - 校验每张表名（白名单：字母/数字/下划线，长度 1-64）
/// - 单次最多 20 张表（防内存爆炸）
/// - 复用 gen_code 的 ZIP 打包逻辑，多表渲染结果写入同一 ZIP
/// - 文件名加表名子目录前缀避免冲突（如 `sys_user/entity.rs`、`sys_role/entity.rs`）
#[utoipa::path(
    get,
    path = "/tool/gen/batchGenCode",
    params(BatchGenCodeParams),
    responses(
        (status = 200, description = "批量生成代码 ZIP", content_type = "application/zip"),
        (status = 400, description = "参数错误"),
    ),
    tag = "tool-gen"
)]
pub async fn batch_gen_code(
    State(state): State<Arc<AppState>>,
    Query(params): Query<BatchGenCodeParams>,
) -> Result<Response, AppError> {
    // 解析 tables 参数（逗号分隔）
    let table_names: Vec<String> = params
        .tables
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();

    if table_names.is_empty() {
        return Err(AppError::bad_request(&crate::tr!(
            "error.gen.table_select_for_gen_required"
        )));
    }

    // 限制单次最多 20 张表（防内存爆炸）
    const MAX_BATCH_TABLES: usize = 20;
    if table_names.len() > MAX_BATCH_TABLES {
        return Err(AppError::bad_request(&crate::tr!(
            "error.gen.batch_tables_exceeded",
            max = MAX_BATCH_TABLES
        )));
    }

    // SEC-004：白名单校验每张表名
    for name in &table_names {
        validate_table_name(name)?;
    }

    let zip_bytes = state.gen_table_service.batch_gen_code(&table_names).await?;

    // 返回 ZIP 文件响应
    let mut headers = axum::http::HeaderMap::new();
    let content_disposition = "attachment; filename=\"batch.zip\"";
    if let Ok(val) = axum::http::HeaderValue::from_str(content_disposition) {
        headers.insert(axum::http::header::CONTENT_DISPOSITION, val);
    }
    headers.insert(
        axum::http::header::CONTENT_TYPE,
        axum::http::HeaderValue::from_static("application/zip"),
    );
    if let Ok(val) = axum::http::HeaderValue::from_str(&zip_bytes.len().to_string()) {
        headers.insert(axum::http::header::CONTENT_LENGTH, val);
    }

    Ok((axum::http::StatusCode::OK, headers, zip_bytes).into_response())
}
