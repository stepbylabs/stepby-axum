// stepby-axum/src/router/sys_role_field_perm_router.rs
//! 角色字段权限矩阵模块路由注册（字段级权限 M2）
//!
//! 路由结构：
//! - /system/role/field-perm/{roleId}  GET（矩阵查询，system:role:fieldPerm）
//!   /system/role/field-perm/{roleId}  PUT（矩阵保存，system:role:fieldPermSave）
//!   （tableKey 为 query 参数 ?tableKey=sys_user，不参与路由匹配）
//!
//! 注意：`/system/role/field-perm/{roleId}` 为两段路径，与 `/system/role/{id}`
//! （一段动态）在 axum 0.8 路由表中不冲突；开关未开启时接口返回 403
//! （错误信息 error.fieldperm.disabled），路由本身始终注册——能力是否存在
//! 由服务层开关链判定，路由层不做隐藏（与 WebAuthn 的 404 策略不同：
//! 本能力关闭态要求"矩阵接口返回明确配置关闭提示"而非端点不存在）。

use axum::Router;
use axum::routing::get;
use std::sync::Arc;

use crate::handler::sys_role_field_perm_handler;
use crate::state::AppState;

/// 角色字段权限矩阵路由（需挂在鉴权中间件下）
pub fn role_field_perm_routes() -> Router<Arc<AppState>> {
    Router::new()
        .route(
            "/system/role/field-perm/{roleId}",
            get(sys_role_field_perm_handler::get_matrix)
                .put(sys_role_field_perm_handler::save_matrix),
        )
        // 当前操作者生效的隐藏字段集（列表动态隐藏列用；仅登录，无矩阵 RBAC——
        // 所有用户都需能拿到自己的隐藏集，fail-safe 语义见 handler/服务层）
        .route(
            "/system/user/field-hidden",
            get(sys_role_field_perm_handler::get_field_hidden),
        )
}
