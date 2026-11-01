// stepby-axum/src/handler/sys_role_field_perm_handler.rs
//! 字段级权限 M2 Handler（角色字段权限矩阵）
//!
//! 接口路径对齐前端（角色管理页按钮「字段权限」，菜单 4120/4121）：
//! - GET /system/role/field-perm/{roleId}?tableKey=sys_user  查询矩阵（全白名单字段 + hidden 态）
//! - PUT /system/role/field-perm/{roleId}?tableKey=sys_user  保存矩阵（全量覆盖式）
//!
//! 权限（PERM_ROUTE_TABLE 同步登记，见 middleware/permission.rs）：
//! GET → system:role:fieldPerm（菜单 4120）/ PUT → system:role:fieldPermSave（菜单 4121）。
//!
//! 开关语义（fail-safe，见服务层三层判定链）：
//! 第一层平台开关（sys.fieldPerm.enabled）或第二层套餐能力位（role.field_perm）
//! 任一未开启 ⇒ 读写接口一律 403 + error.fieldperm.disabled（前端入口由接口数据驱动隐藏）。

use std::sync::Arc;

use axum::extract::{Path, Query, State};
use serde::Deserialize;
use utoipa::IntoParams;

use crate::common::{AjaxResult, AppError};
use crate::middleware::Operator;
use crate::service::sys_role_field_perm_service::{FieldPermItem, FieldPermSaveDto};
use crate::state::AppState;

/// 矩阵接口的查询参数（tableKey 指定业务表，白名单校验在服务层）
#[derive(Debug, Deserialize, IntoParams)]
#[serde(rename_all = "camelCase")]
pub struct FieldPermQuery {
    /// 业务表标识（白名单见 FIELD_PERM_TABLES，首期仅 sys_user）
    pub table_key: String,
}

/// GET /system/role/field-perm/{roleId}
/// 查询角色字段权限矩阵：返回**全白名单字段** + hidden 态（前端据此渲染开关列表）
#[utoipa::path(
    get,
    path = "/system/role/field-perm/{roleId}",
    params(
        ("roleId" = i64, Path, description = "角色 ID"),
        FieldPermQuery,
    ),
    responses(
        (status = 200, description = "矩阵查询成功", body = AjaxResult<Vec<FieldPermItem>>),
        (status = 400, description = "tableKey 不在白名单"),
        (status = 403, description = "字段级权限开关未开启（平台开关/套餐能力位）"),
    ),
    tag = "system-role-field-perm"
)]
pub async fn get_matrix(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    Path(role_id): Path<i64>,
    Query(query): Query<FieldPermQuery>,
) -> Result<AjaxResult<Vec<FieldPermItem>>, AppError> {
    let items = state
        .field_perm_service
        .get_matrix(role_id, operator.tenant_id(), &query.table_key)
        .await?;
    Ok(AjaxResult::success(items))
}

/// PUT /system/role/field-perm/{roleId}
/// 全量覆盖式保存角色字段权限矩阵（hiddenFields 即最终态；白名单外字段拒绝）
#[utoipa::path(
    put,
    path = "/system/role/field-perm/{roleId}",
    params(
        ("roleId" = i64, Path, description = "角色 ID"),
        FieldPermQuery,
    ),
    request_body = FieldPermSaveDto,
    responses(
        (status = 200, description = "保存成功"),
        (status = 400, description = "tableKey / fieldKey 不在白名单"),
        (status = 403, description = "字段级权限开关未开启（平台开关/套餐能力位）"),
    ),
    tag = "system-role-field-perm"
)]
pub async fn save_matrix(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    Path(role_id): Path<i64>,
    Query(query): Query<FieldPermQuery>,
    crate::common::ValidatedJson(dto): crate::common::ValidatedJson<FieldPermSaveDto>,
) -> Result<AjaxResult<()>, AppError> {
    state
        .field_perm_service
        .save_matrix(role_id, operator.tenant_id(), &query.table_key, dto)
        .await?;
    Ok(AjaxResult::success_msg(&crate::tr!("msg.success.default")))
}

/// GET /system/user/field-hidden
/// 当前操作者生效的隐藏字段集（列表动态隐藏列用；仅需登录，fail-safe 语义见服务层）：
/// - 开关未开启/白名单外/管理员/无上下文 → 空数组（关闭态零行为变化）
/// - 开启态 → 操作者全部角色的 hidden 字段并集
#[utoipa::path(
    get,
    path = "/system/user/field-hidden",
    params(FieldPermQuery),
    responses(
        (status = 200, description = "隐藏字段集（空数组 = 无隐藏，关闭态恒空）", body = AjaxResult<Vec<String>>),
        (status = 400, description = "tableKey 不在白名单"),
    ),
    tag = "system-role-field-perm"
)]
pub async fn get_field_hidden(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    Query(query): Query<FieldPermQuery>,
) -> Result<AjaxResult<Vec<String>>, AppError> {
    // 白名单外 → 400（与矩阵接口同口径，前端只对白名单表调用）
    if crate::service::sys_role_field_perm_service::field_perm_whitelist(&query.table_key).is_none()
    {
        return Err(AppError::new(
            400,
            crate::tr!("error.fieldperm.table_not_allowed"),
        ));
    }
    let hidden: Vec<String> = state
        .field_perm_service
        .hidden_fields(
            Some(operator.user_id_i64()?),
            operator.tenant_id(),
            &query.table_key,
        )
        .await?
        .into_iter()
        .collect();
    let mut hidden = hidden;
    hidden.sort();
    Ok(AjaxResult::success(hidden))
}
