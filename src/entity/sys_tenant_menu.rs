//! sys_tenant_menu 实体定义（L3 租户自建导航，多租户 Phase 3）
//!
//! 硬边界（文档 §29.4 结论，必须遵守）：
//! - L3 **只能引用**（`ref_menu_id`）平台 L1 既有菜单，复用其 `component`/`path`；
//!   前端路由由 `import.meta.glob('./../../views/**/*.vue')` 编译期解析，租户
//!   无法新增 `.vue` 页面；
//! - L3 **不能自定义权限码**：后端 `middleware/permission.rs` 是静态
//!   `(METHOD, PATH) → perm` 映射表，`perms` 必须 ∈ `all_required_perm_keys()`；
//! - `ref_menu_id ⊆ 套餐白名单`（加载时 JOIN 过滤）。
//!
//! 本表行只表达"租户自己的导航结构（排序/显隐/分组）"，不复制平台菜单的权限语义。

use chrono::NaiveDateTime;
use sea_orm::Set;
use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};
use ts_rs::TS;
use utoipa::ToSchema;

use crate::common::datetime;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize, TS, ToSchema)]
#[sea_orm(table_name = "sys_tenant_menu")]
#[serde(rename_all = "camelCase")]
#[ts(
    export,
    rename = "SysTenantMenu",
    export_to = "SysTenantMenu.ts",
    rename_all = "camelCase"
)]
#[schema(as = SysTenantMenu)]
pub struct Model {
    /// L3 节点 ID（独立段位：登记为 5000+，见 docs/optimization/menu-id-registry.md）
    #[sea_orm(primary_key, auto_increment = false)]
    pub l3_id: i64,
    /// 归属租户（sys_tenant.tenant_id）
    pub tenant_id: i64,
    /// 引用的平台 L1 菜单（sys_menu.menu_id）——组件/路径/权限码均取自它
    pub ref_menu_id: i64,
    /// L3 内部父节点（0 = 顶层；仅允许指向本租户其它 L3 行）
    pub parent_id: i64,
    pub order_num: Option<i32>,
    /// '0' 显示 / '1' 隐藏
    pub visible: Option<String>,
    /// '0' 正常 / '1' 停用
    pub status: Option<String>,
    pub del_flag: Option<String>,
    pub create_by: Option<String>,
    #[serde(
        serialize_with = "datetime::serialize_opt",
        deserialize_with = "datetime::deserialize_opt"
    )]
    #[ts(as = "Option<String>")]
    pub create_time: Option<NaiveDateTime>,
    pub update_by: Option<String>,
    #[serde(
        serialize_with = "datetime::serialize_opt",
        deserialize_with = "datetime::deserialize_opt"
    )]
    #[ts(as = "Option<String>")]
    pub update_time: Option<NaiveDateTime>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

crate::impl_timestamped_active_model!();