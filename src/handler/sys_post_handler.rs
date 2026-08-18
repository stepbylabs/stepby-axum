//! 岗位模块 Handler（Axum 原生实现）
//!
//! 接口路径对齐前端调用规范：
//! - GET    /system/post/list            分页查询岗位
//! - GET    /system/post/optionselect    查询全部岗位（下拉用）
//! - GET    /system/post/{postId}        查询岗位详情
//! - POST   /system/post                 新增岗位
//! - PUT    /system/post                 修改岗位
//! - DELETE /system/post/{postIds}       批量删除岗位
//! - POST   /system/post/export          导出岗位列表

use axum::extract::{Form, Path, Query, State};
use axum::response::Response;
use std::sync::Arc;

use crate::common::ValidatedJson;
use crate::common::constants::MAX_BATCH_DELETE_SIZE;
use crate::common::excel::{CellValue, ExcelColumn, export_to_excel};
use crate::common::{AjaxResult, AppError, TableDataInfo};
use crate::entity::sys_post::Model as SysPostModel;
use crate::middleware::Operator;
use crate::service::sys_post_service::{PostAddDto, PostEditDto, PostQueryDto};
use crate::state::AppState;
use crate::utils::parse_id_list;

/// GET /system/post/list
/// 分页查询岗位
#[utoipa::path(
    get,
    path = "/system/post/list",
    params(PostQueryDto),
    responses(
        (status = 200, description = "查询成功", body = TableDataInfo<SysPostModel>),
        (status = 500, description = "服务器错误"),
    ),
    tag = "system-post"
)]
pub async fn list(
    State(state): State<Arc<AppState>>,
    Query(query): Query<PostQueryDto>,
) -> Result<TableDataInfo<SysPostModel>, AppError> {
    let (rows, total) = state.post_service.get_post_page(query).await?;
    Ok(TableDataInfo::new(total, rows))
}

/// GET /system/post/optionselect
/// 查询全部岗位（前端下拉选择用）
#[utoipa::path(
    get,
    path = "/system/post/optionselect",
    responses(
        (status = 200, description = "查询成功", body = AjaxResult<Vec<SysPostModel>>),
        (status = 500, description = "服务器错误"),
    ),
    tag = "system-post"
)]
pub async fn optionselect(
    State(state): State<Arc<AppState>>,
) -> Result<AjaxResult<Vec<SysPostModel>>, AppError> {
    let rows = state.post_service.get_post_options().await?;
    Ok(AjaxResult::success(rows))
}

/// GET /system/post/{postId}
/// 查询岗位详情
#[utoipa::path(
    get,
    path = "/system/post/{postId}",
    params(
        ("postId" = i64, Path, description = "岗位 ID")
    ),
    responses(
        (status = 200, description = "查询成功", body = AjaxResult<SysPostModel>),
        (status = 404, description = "岗位不存在"),
    ),
    tag = "system-post"
)]
pub async fn get_info(
    State(state): State<Arc<AppState>>,
    Path(post_id): Path<i64>,
) -> Result<AjaxResult<SysPostModel>, AppError> {
    let model = state.post_service.get_post_by_id(post_id).await?;
    Ok(AjaxResult::success(model))
}

/// POST /system/post
/// 新增岗位
#[utoipa::path(
    post,
    path = "/system/post",
    request_body = PostAddDto,
    responses(
        (status = 200, description = "新增成功", body = AjaxResult<serde_json::Value>),
        (status = 400, description = "参数错误或岗位名称/编码重复"),
    ),
    tag = "system-post"
)]
pub async fn add(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    ValidatedJson(dto): ValidatedJson<PostAddDto>,
) -> Result<AjaxResult<()>, AppError> {
    state
        .post_service
        .add_post(dto, operator.username())
        .await?;
    Ok(AjaxResult::success_msg(&crate::tr!("msg.success.add")))
}

/// PUT /system/post
/// 修改岗位
#[utoipa::path(
    put,
    path = "/system/post",
    request_body = PostEditDto,
    responses(
        (status = 200, description = "修改成功", body = AjaxResult<serde_json::Value>),
        (status = 400, description = "参数错误"),
        (status = 404, description = "岗位不存在"),
    ),
    tag = "system-post"
)]
pub async fn edit(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    ValidatedJson(dto): ValidatedJson<PostEditDto>,
) -> Result<AjaxResult<()>, AppError> {
    state
        .post_service
        .edit_post(dto, operator.username())
        .await?;
    Ok(AjaxResult::success_msg(&crate::tr!("msg.success.edit")))
}

/// DELETE /system/post/{postIds}
/// 批量删除岗位（postIds 为逗号分隔的 ID 字符串）
#[utoipa::path(
    delete,
    path = "/system/post/{postIds}",
    params(
        ("postIds" = String, Path, description = "岗位 ID 列表（逗号分隔）")
    ),
    responses(
        (status = 200, description = "删除成功", body = AjaxResult<serde_json::Value>),
        (status = 400, description = "岗位 ID 不合法"),
    ),
    tag = "system-post"
)]
pub async fn remove(
    State(state): State<Arc<AppState>>,
    Path(post_ids): Path<String>,
) -> Result<AjaxResult<()>, AppError> {
    let ids: Vec<i64> = parse_id_list::<i64>(&post_ids);

    if ids.is_empty() {
        return Err(AppError::bad_request(&crate::tr!("error.post.id_invalid")));
    }

    if ids.len() > MAX_BATCH_DELETE_SIZE {
        return Err(AppError::bad_request(&crate::tr!(
            "error.common.batch_size_exceeded",
            max = MAX_BATCH_DELETE_SIZE
        )));
    }

    state.post_service.delete_posts(ids).await?;
    Ok(AjaxResult::success_msg(&crate::tr!("msg.success.delete")))
}

/// POST /system/post/export
/// 导出岗位列表为 Excel
///
/// 前端 download() 发送 application/x-www-form-urlencoded，使用 Form 提取器
#[utoipa::path(
    post,
    path = "/system/post/export",
    params(PostQueryDto),
    responses(
        (status = 200, description = "导出成功", content_type = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"),
        (status = 500, description = "服务器错误"),
    ),
    tag = "system-post"
)]
pub async fn export(
    State(state): State<Arc<AppState>>,
    Form(query): Form<PostQueryDto>,
) -> Result<Response, AppError> {
    let rows = state.post_service.export_posts(query).await?;

    let columns = [
        ExcelColumn {
            key: "postId",
            header: ("岗位编号", "Post ID"),
            getter: |r: &SysPostModel| CellValue::Text(r.post_id.to_string().into()),
        },
        ExcelColumn {
            key: "postCode",
            header: ("岗位编码", "Post Code"),
            getter: |r: &SysPostModel| CellValue::Text(r.post_code.clone().into()),
        },
        ExcelColumn {
            key: "postName",
            header: ("岗位名称", "Post Name"),
            getter: |r: &SysPostModel| CellValue::Text(r.post_name.clone().into()),
        },
        ExcelColumn {
            key: "postSort",
            header: ("岗位排序", "Sort"),
            getter: |r: &SysPostModel| CellValue::Text(r.post_sort.to_string().into()),
        },
        ExcelColumn {
            key: "status",
            header: ("状态", "Status"),
            getter: |r: &SysPostModel| {
                CellValue::Text(
                    r.status
                        .as_deref()
                        .map(|s| {
                            if s == "0" {
                                crate::tr!("common.status.normal")
                            } else {
                                crate::tr!("common.status.disabled")
                            }
                        })
                        .unwrap_or_default()
                        .into(),
                )
            },
        },
        ExcelColumn {
            key: "createTime",
            header: ("创建时间", "Create Time"),
            getter: |r: &SysPostModel| {
                CellValue::Text({
                    r.create_time
                        .map(|dt| dt.format("%Y-%m-%d %H:%M:%S").to_string())
                        .unwrap_or_default()
                        .into()
                })
            },
        },
        ExcelColumn {
            key: "remark",
            header: ("备注", "Remark"),
            getter: |r: &SysPostModel| CellValue::Text(r.remark.clone().unwrap_or_default().into()),
        },
    ];

    export_to_excel(&crate::tr!("excel.sheet.post"), "post", &columns, &rows).await
}
