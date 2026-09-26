// axum-backend/src/service/sys_tenant_nav_service.rs
//! 租户自建导航 L3 服务（批次 3 / MT-1，文档 §29.4）
//!
//! ## 三层导航模型中的位置
//!
//! - **L1 平台菜单**（`sys_menu`）：组件、路径、`perms` 的唯一来源；
//! - **L2 套餐白名单**（`sys_tenant_package.menu_ids`）：该租户能用哪些 L1 菜单；
//! - **L3 租户自建导航**（`sys_tenant_menu`，本服务）：租户在 **L2 之内**调整
//!   「父级 / 排序 / 显隐」。**不新增节点、不新增 component/perms** ⇒ 天然不扩权。
//!
//! ## 硬边界（`entity/sys_tenant_menu.rs` 注释与 §29.4 结论）
//!
//! 1. `ref_menu_id` 必须指向**已存在**的 L1 菜单，且 `menu_type ∈ {M, C}`（按钮 F 不可作为
//!    导航节点）、`status='0'`（停用菜单不可被引用）；
//! 2. `ref_menu_id` 必须落在该租户的 L2 套餐白名单内（白名单为 `None` = 不限制）；
//! 3. 引用菜单的 `perms` 不得属**平台专属能力前缀**（否则等于借 L3 把平台面暴露给租户）；
//! 4. 同一租户不得重复挂载同一 `ref_menu_id`；
//! 5. `parent_id` 只能是 0（顶层）或**本租户**另一 L3 行；禁止自父 / 成环 / 超过
//!    [`L3_MAX_DEPTH`]；
//! 6. 删除前必须无子节点（`count_children == 0`）。
//!
//! ## 能力位门控（`nav.l3 = off | view_only | full`）
//!
//! [`NavScope`] 是**所有接口的唯一准入判据**：
//! - `off`（默认）：租户操作者一律 **403**（关闭态即现状）；
//! - `view_only`：仅可 `list` / `options`；
//! - `full`：可读写。
//!
//! 平台操作者（`tid == 0`）恒可读写全部租户（不受能力位影响，与域名链路同口径）。
//! 加载期重组由 `service::auth_service::apply_l3_overrides` 承担（纯函数，同一语义）。

use std::collections::{HashMap, HashSet};

use chrono::NaiveDateTime;
use sea_orm::{DatabaseConnection, IntoActiveModel, Set};
use serde::{Deserialize, Serialize};
use ts_rs::TS;
use utoipa::ToSchema;

use crate::common::datetime::{self, now_naive};
use crate::common::error::ServiceError;
use crate::common::tenant::is_platform_only_perm;
use crate::entity::sys_menu::Model as SysMenuModel;
use crate::entity::sys_tenant_menu::ActiveModel as L3ActiveModel;
use crate::entity::sys_tenant_menu::Model as L3Model;
use crate::repository::sys_menu::SysMenuRepository;
use crate::repository::sys_tenant_menu::SysTenantMenuRepository;
use crate::service::auth_service::{L3_MAX_DEPTH, prune_menu_tree_by_whitelist};
use crate::service::sys_menu_service::SysMenuService;
use crate::service::sys_tenant_service::SysTenantService;

/// L3 租户自建导航能力位键（注册表见 `common::features::KNOWN_FEATURES`）
pub const FEATURE_NAV_L3: &str = "nav.l3";

/// L3 允许引用的菜单类型（目录 M / 页面 C；按钮 F 不是导航节点）
const NAV_MENU_TYPES: [&str; 2] = ["M", "C"];

/// 停用态字面量（`sys_menu.status` / `sys_tenant_menu.status`）
const STATUS_DISABLED: &str = "1";

/// L3 导航管理的**操作者数据范围**（由能力位解析得出，是所有接口的唯一准入判据）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NavScope {
    /// 平台操作者：可见/可写全部租户的导航配置
    Platform,
    /// 租户操作者 + `view_only`：仅可读本租户
    TenantViewOnly(i64),
    /// 租户操作者 + `full`：可读写本租户
    TenantFull(i64),
}

impl NavScope {
    /// 是否允许写操作（新增 / 修改 / 删除）
    pub fn allows_write(self) -> bool {
        matches!(self, NavScope::Platform | NavScope::TenantFull(_))
    }

    /// 租户操作者视角的 tid（平台返回 `None`）
    pub fn tenant(self) -> Option<i64> {
        match self {
            NavScope::Platform => None,
            NavScope::TenantViewOnly(tid) | NavScope::TenantFull(tid) => Some(tid),
        }
    }
}

/// 由能力集解析操作者范围（纯函数，便于单测；唯一准入判据的判定体）。
///
/// - `operator_tid == 0` ⇒ 平台（不受能力位影响）；
/// - 否则按 `nav.l3` 的有效模式分档：`view_only` / `full` / 其余（含 `off`、非法值）一律 403。
///
/// 传入的是**已收窄**的有效能力集（平台天花板 ∩ 套餐），故平台层未开启时租户侧恒为 `off`。
fn nav_scope_from_features(
    operator_tid: i64,
    features: &crate::common::features::FeatureSet,
) -> Result<NavScope, ServiceError> {
    if operator_tid == 0 {
        return Ok(NavScope::Platform);
    }
    match features.mode(FEATURE_NAV_L3) {
        "view_only" => Ok(NavScope::TenantViewOnly(operator_tid)),
        "full" => Ok(NavScope::TenantFull(operator_tid)),
        _ => Err(ServiceError::forbidden(&crate::tr!(
            "error.tenant.nav_l3_disabled"
        ))),
    }
}

/// 跨租户越权（导航归属与操作者租户不一致）——显式 403，**禁止静默降级**
fn cross_tenant_denied() -> ServiceError {
    ServiceError::forbidden(&crate::tr!("error.tenant.nav_cross_tenant"))
}

/// 列表实际过滤值（纯函数）：
/// - 平台：按请求值（`None` = 全量）；
/// - 租户范围：**显式传入他租户 id 一律 403**（不静默降级为"忽略参数"）。
fn effective_list_filter(
    scope: NavScope,
    requested: Option<i64>,
) -> Result<Option<i64>, ServiceError> {
    match scope {
        NavScope::Platform => Ok(requested),
        NavScope::TenantViewOnly(tid) | NavScope::TenantFull(tid) => {
            if let Some(r) = requested
                && r != tid
            {
                return Err(cross_tenant_denied());
            }
            Ok(Some(tid))
        }
    }
}

/// 写操作的归属租户（纯函数）：平台必须显式指定；租户只能作用于自身。
fn effective_write_tenant(scope: NavScope, requested: Option<i64>) -> Result<i64, ServiceError> {
    match scope {
        NavScope::Platform => requested.ok_or_else(|| {
            ServiceError::bad_request(&crate::tr!("error.tenant.nav_tenant_required"))
        }),
        NavScope::TenantViewOnly(tid) | NavScope::TenantFull(tid) => {
            if let Some(r) = requested
                && r != tid
            {
                return Err(cross_tenant_denied());
            }
            Ok(tid)
        }
    }
}

// ==================== DTO / Vo ====================

/// L3 导航行视图（含引用菜单的展示信息，供页面表格直接渲染）
#[derive(Debug, Clone, Serialize, TS, ToSchema)]
#[serde(rename_all = "camelCase")]
#[ts(export, rename = "SysTenantMenuVo", rename_all = "camelCase")]
#[schema(as = SysTenantMenuVo)]
pub struct SysTenantMenuVo {
    pub l3_id: i64,
    pub tenant_id: i64,
    pub ref_menu_id: i64,
    /// 0 = 顶层；其余为本租户其它 L3 行的 `l3_id`
    pub parent_id: i64,
    pub order_num: Option<i32>,
    /// '0' 显示 / '1' 隐藏
    pub visible: Option<String>,
    /// '0' 正常 / '1' 停用
    pub status: Option<String>,
    pub create_by: Option<String>,
    #[serde(
        skip_serializing_if = "Option::is_none",
        serialize_with = "datetime::serialize_opt",
        deserialize_with = "datetime::deserialize_opt"
    )]
    pub create_time: Option<NaiveDateTime>,
    pub update_by: Option<String>,
    #[serde(
        skip_serializing_if = "Option::is_none",
        serialize_with = "datetime::serialize_opt",
        deserialize_with = "datetime::deserialize_opt"
    )]
    pub update_time: Option<NaiveDateTime>,
    /// 引用菜单名（菜单被删除时为空串）
    pub ref_menu_name: String,
    /// 引用菜单类型：'M' 目录 / 'C' 页面
    pub ref_menu_type: String,
    pub ref_menu_path: Option<String>,
    pub ref_menu_perms: Option<String>,
    pub ref_menu_icon: Option<String>,
}

/// 可选菜单项（前端「添加导航」选择器）
#[derive(Debug, Clone, Serialize, TS, ToSchema)]
#[serde(rename_all = "camelCase")]
#[ts(export, rename = "TenantNavMenuOptionVo", rename_all = "camelCase")]
#[schema(as = TenantNavMenuOptionVo)]
pub struct TenantNavMenuOptionVo {
    pub menu_id: i64,
    pub menu_name: String,
    /// 'M' 目录 / 'C' 页面
    pub menu_type: String,
    pub parent_id: i64,
    pub perms: Option<String>,
    pub icon: Option<String>,
    /// 是否已被本租户挂载（前端据此禁用重复添加）
    pub selected: bool,
}

/// 新增 L3 导航行 DTO
#[derive(Debug, Clone, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
#[schema(as = TenantNavAddDto)]
pub struct TenantNavAddDto {
    /// 归属租户（平台操作者必填；租户操作者可省略，填入他租户一律 403）
    #[serde(default)]
    pub tenant_id: Option<i64>,
    /// 引用的平台 L1 菜单 ID（组件/路径/权限码取自它）
    pub ref_menu_id: i64,
    /// 0 = 顶层（缺省）；其余为本租户其它 L3 行的 `l3_id`
    #[serde(default)]
    pub parent_id: Option<i64>,
    #[serde(default)]
    pub order_num: Option<i32>,
    /// '0' 显示（缺省）/ '1' 隐藏
    #[serde(default)]
    pub visible: Option<String>,
}

/// 修改 L3 导航行 DTO（缺省字段表示"不修改"）
#[derive(Debug, Clone, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
#[schema(as = TenantNavEditDto)]
pub struct TenantNavEditDto {
    pub l3_id: i64,
    #[serde(default)]
    pub parent_id: Option<i64>,
    #[serde(default)]
    pub order_num: Option<i32>,
    #[serde(default)]
    pub visible: Option<String>,
    /// '0' 正常 / '1' 停用（停用后该行整体忽略，节点回退平台默认位置）
    #[serde(default)]
    pub status: Option<String>,
}

/// L3 列表 / 可选菜单查询参数
#[derive(Debug, Clone, Deserialize, ToSchema, utoipa::IntoParams)]
#[serde(rename_all = "camelCase")]
#[into_params(parameter_in = Query)]
#[schema(as = TenantNavQueryDto)]
pub struct TenantNavQueryDto {
    /// 归属租户过滤（平台操作者可选；租户操作者传他租户一律 403）
    #[serde(default)]
    pub tenant_id: Option<i64>,
}

// ==================== Service ====================

/// 租户自建导航 L3 服务
#[derive(Clone)]
pub struct SysTenantNavService {
    db: DatabaseConnection,
    nav_repo: SysTenantMenuRepository,
    menu_repo: SysMenuRepository,
    menu_service: SysMenuService,
    tenant_service: SysTenantService,
}

impl SysTenantNavService {
    pub fn new(
        db: DatabaseConnection,
        menu_service: SysMenuService,
        tenant_service: SysTenantService,
    ) -> Self {
        Self {
            nav_repo: SysTenantMenuRepository::new(db.clone()),
            menu_repo: SysMenuRepository::new(db.clone()),
            menu_service,
            tenant_service,
            db,
        }
    }

    fn db(&self) -> &DatabaseConnection {
        &self.db
    }

    /// 解析操作者范围（**唯一准入判据**，见 [`NavScope`]）
    async fn resolve_scope(&self, operator_tid: i64) -> Result<NavScope, ServiceError> {
        if operator_tid == 0 {
            return Ok(NavScope::Platform);
        }
        let features =
            crate::service::sys_tenant_service::tenant_features_conn(self.db(), operator_tid)
                .await?;
        nav_scope_from_features(operator_tid, &features)
    }

    /// 写操作前解析（含 `view_only` 拒绝）
    async fn resolve_write_scope(&self, operator_tid: i64) -> Result<NavScope, ServiceError> {
        let scope = self.resolve_scope(operator_tid).await?;
        if !scope.allows_write() {
            return Err(ServiceError::forbidden(&crate::tr!(
                "error.tenant.nav_l3_readonly"
            )));
        }
        Ok(scope)
    }

    // ---------- 查询 ----------

    /// L3 导航行列表（范围见 [`NavScope`]）
    pub async fn list(
        &self,
        requested_tid: Option<i64>,
        operator_tid: i64,
    ) -> Result<Vec<SysTenantMenuVo>, ServiceError> {
        let scope = self.resolve_scope(operator_tid).await?;
        let filter = effective_list_filter(scope, requested_tid)?;
        let rows = self.nav_repo.list(filter).await?;
        let ref_ids: Vec<i64> = rows.iter().map(|r| r.ref_menu_id).collect();
        let menus: HashMap<i64, SysMenuModel> = self
            .menu_repo
            .find_by_ids(&ref_ids)
            .await?
            .into_iter()
            .map(|m| (m.menu_id, m))
            .collect();
        Ok(rows
            .into_iter()
            .map(|r| to_vo(&r, menus.get(&r.ref_menu_id)))
            .collect())
    }

    /// 可选菜单池（M/C 类型展平，带 `selected` 标记）
    ///
    /// 口径（与加载期重组同源，避免"页面可选但登录后看不到"的漂移）：
    /// - **租户操作者**：其自身角色授权菜单树 ∩ 套餐白名单（`get_menu_tree_by_user_id` + prune）；
    /// - **平台操作者**：目标租户的「平台普通角色菜单 ∪ 租户自助按钮」∩ 可授予（带该租户能力位）
    ///   ∩ 套餐白名单（无自身角色可借，故用租户管理型菜单模板）。
    pub async fn options(
        &self,
        requested_tid: Option<i64>,
        user_id: i64,
        operator_tid: i64,
    ) -> Result<Vec<TenantNavMenuOptionVo>, ServiceError> {
        let scope = self.resolve_scope(operator_tid).await?;
        let target_tid = match scope.tenant() {
            Some(tid) => {
                if let Some(r) = requested_tid
                    && r != tid
                {
                    return Err(cross_tenant_denied());
                }
                tid
            }
            None => requested_tid.ok_or_else(|| {
                ServiceError::bad_request(&crate::tr!("error.tenant.nav_tenant_required"))
            })?,
        };

        let candidates: Vec<SysMenuModel> = match scope.tenant() {
            Some(_) => {
                let tree = self.menu_service.get_menu_tree_by_user_id(user_id).await?;
                let tree = match self
                    .tenant_service
                    .package_menu_whitelist(target_tid)
                    .await?
                {
                    Some(whitelist) => prune_menu_tree_by_whitelist(tree, &whitelist),
                    None => tree,
                };
                flatten_ms(tree)
            }
            None => {
                let features =
                    crate::service::sys_tenant_service::tenant_features_conn(self.db(), target_tid)
                        .await?;
                let whitelist = self
                    .tenant_service
                    .package_menu_whitelist(target_tid)
                    .await?;
                let ids = crate::service::sys_tenant_service::tenant_role_menu_ids(
                    self.db(),
                    whitelist.as_ref(),
                    &features,
                    true,
                )
                .await?;
                self.menu_repo.find_by_ids(&ids).await?
            }
        };

        let selected: HashSet<i64> = self
            .nav_repo
            .list(Some(target_tid))
            .await?
            .into_iter()
            .map(|r| r.ref_menu_id)
            .collect();

        let mut out: Vec<TenantNavMenuOptionVo> = candidates
            .into_iter()
            .filter(|m| {
                let mt = m.menu_type.as_deref().unwrap_or("C");
                NAV_MENU_TYPES.contains(&mt)
                    && m.status.as_deref().unwrap_or("0") != STATUS_DISABLED
                    && !m
                        .perms
                        .as_deref()
                        .is_some_and(|p| !p.is_empty() && is_platform_only_perm(p))
            })
            .map(|m| TenantNavMenuOptionVo {
                selected: selected.contains(&m.menu_id),
                menu_id: m.menu_id,
                menu_name: m.menu_name,
                menu_type: m.menu_type.unwrap_or_else(|| "C".to_string()),
                parent_id: m.parent_id.unwrap_or(0),
                perms: m.perms,
                icon: m.icon,
            })
            .collect();
        out.sort_by_key(|o| (o.parent_id, o.menu_id));
        Ok(out)
    }

    // ---------- 写操作 ----------

    /// 新增 L3 导航行
    pub async fn add(
        &self,
        dto: TenantNavAddDto,
        operator: &str,
        operator_tid: i64,
    ) -> Result<SysTenantMenuVo, ServiceError> {
        let scope = self.resolve_write_scope(operator_tid).await?;
        let target_tid = effective_write_tenant(scope, dto.tenant_id)?;

        // 1) 引用菜单必须存在、类型合法、启用、且 perms 非平台专属
        let ref_menu = self.load_ref_menu(dto.ref_menu_id).await?;
        // 2) 引用菜单必须在该租户的 L2 套餐白名单内
        self.ensure_ref_in_package(target_tid, dto.ref_menu_id)
            .await?;
        // 3) 同一租户不得重复挂载
        if self
            .nav_repo
            .exists_ref(target_tid, dto.ref_menu_id, None)
            .await?
        {
            return Err(ServiceError::bad_request(&crate::tr!(
                "error.tenant.nav_ref_duplicate"
            )));
        }
        // 4) 父级校验（0 / 本租户 L3 行；非停用；深度受限）
        let parent_id = dto.parent_id.unwrap_or(0);
        if parent_id != 0 {
            self.ensure_parent_valid(target_tid, parent_id, None)
                .await?;
        }

        let l3_id = self.nav_repo.next_l3_id().await?;
        let model = L3ActiveModel {
            l3_id: Set(l3_id),
            tenant_id: Set(target_tid),
            ref_menu_id: Set(dto.ref_menu_id),
            parent_id: Set(parent_id),
            order_num: Set(order_num_payload(dto.order_num)),
            visible: Set(Some(visible_payload(dto.visible.as_deref().unwrap_or("0")))),
            status: Set(Some("0".to_string())),
            del_flag: Set(Some("0".to_string())),
            create_by: Set(Some(operator.to_string())),
            create_time: Set(Some(now_naive())),
            update_by: Set(None),
            update_time: Set(None),
        };
        let saved = self.nav_repo.insert(model).await?;
        Ok(to_vo(&saved, Some(&ref_menu)))
    }

    /// 修改 L3 导航行（缺省字段不变；`parent_id = 0` 表示提升为顶层）
    pub async fn edit(
        &self,
        dto: TenantNavEditDto,
        operator: &str,
        operator_tid: i64,
    ) -> Result<SysTenantMenuVo, ServiceError> {
        let scope = self.resolve_write_scope(operator_tid).await?;
        let row = self.load_scoped_row(scope, dto.l3_id).await?;

        if let Some(parent_id) = dto.parent_id
            && parent_id != 0
        {
            self.ensure_parent_valid(row.tenant_id, parent_id, Some(dto.l3_id))
                .await?;
        }
        if let Some(status) = dto.status.as_deref()
            && status != "0"
            && status != STATUS_DISABLED
        {
            return Err(ServiceError::bad_request(&crate::tr!(
                "error.tenant.nav_status_invalid"
            )));
        }

        let mut active: L3ActiveModel = row.clone().into_active_model();
        if let Some(parent_id) = dto.parent_id {
            active.parent_id = Set(parent_id);
        }
        if let Some(order_num) = dto.order_num {
            active.order_num = Set(Some(order_num));
        }
        if let Some(visible) = dto.visible {
            active.visible = Set(Some(visible_payload(&visible)));
        }
        if let Some(status) = dto.status {
            active.status = Set(Some(status));
        }
        active.update_by = Set(Some(operator.to_string()));
        active.update_time = Set(Some(now_naive()));
        let saved = self.nav_repo.update(active).await?;

        let ref_menu = self.menu_repo.find_by_id(saved.ref_menu_id).await?;
        Ok(to_vo(&saved, ref_menu.as_ref()))
    }

    /// 删除 L3 导航行（软删；有子节点时拒绝）
    pub async fn remove(
        &self,
        l3_id: i64,
        operator: &str,
        operator_tid: i64,
    ) -> Result<i64, ServiceError> {
        let scope = self.resolve_write_scope(operator_tid).await?;
        let row = self.load_scoped_row(scope, l3_id).await?;
        if self
            .nav_repo
            .count_children(row.tenant_id, row.l3_id)
            .await?
            > 0
        {
            return Err(ServiceError::bad_request(&crate::tr!(
                "error.tenant.nav_has_children"
            )));
        }
        self.nav_repo.soft_delete(row.l3_id, operator).await?;
        Ok(row.tenant_id)
    }

    // ---------- 内部校验 ----------

    /// 载入并校验引用菜单（存在 / 类型 M·C / 启用 / perms 非平台专属）
    async fn load_ref_menu(&self, ref_menu_id: i64) -> Result<SysMenuModel, ServiceError> {
        let menu = self
            .menu_repo
            .find_by_id(ref_menu_id)
            .await?
            .ok_or_else(|| {
                ServiceError::bad_request(&crate::tr!("error.tenant.nav_ref_menu_invalid"))
            })?;
        let menu_type = menu.menu_type.as_deref().unwrap_or("");
        if !NAV_MENU_TYPES.contains(&menu_type) {
            return Err(ServiceError::bad_request(&crate::tr!(
                "error.tenant.nav_ref_menu_invalid"
            )));
        }
        if menu.status.as_deref().unwrap_or("0") == STATUS_DISABLED {
            return Err(ServiceError::bad_request(&crate::tr!(
                "error.tenant.nav_ref_menu_invalid"
            )));
        }
        if menu
            .perms
            .as_deref()
            .is_some_and(|p| !p.is_empty() && is_platform_only_perm(p))
        {
            return Err(ServiceError::bad_request(&crate::tr!(
                "error.tenant.nav_ref_platform_only"
            )));
        }
        Ok(menu)
    }

    /// 引用菜单必须落在该租户的 L2 套餐白名单内（`None` = 不限制）
    async fn ensure_ref_in_package(
        &self,
        tenant_id: i64,
        ref_menu_id: i64,
    ) -> Result<(), ServiceError> {
        let Some(whitelist) = self
            .tenant_service
            .package_menu_whitelist(tenant_id)
            .await?
        else {
            return Ok(());
        };
        if !whitelist.contains(&ref_menu_id) {
            return Err(ServiceError::forbidden(&crate::tr!(
                "error.tenant.nav_ref_outside_package"
            )));
        }
        Ok(())
    }

    /// 父级校验：0 由调用方早退；否则必须是**同租户**未删除、未停用的 L3 行，
    /// 且与 `exclude_l3_id`（被修改的行自身）之间不成环、深度不超过 [`L3_MAX_DEPTH`]。
    async fn ensure_parent_valid(
        &self,
        tenant_id: i64,
        parent_l3_id: i64,
        exclude_l3_id: Option<i64>,
    ) -> Result<(), ServiceError> {
        if Some(parent_l3_id) == exclude_l3_id {
            return Err(ServiceError::bad_request(&crate::tr!(
                "error.tenant.nav_parent_invalid"
            )));
        }
        let parent = self
            .nav_repo
            .find_by_id(parent_l3_id)
            .await?
            .filter(|r| r.tenant_id == tenant_id)
            .ok_or_else(|| {
                ServiceError::bad_request(&crate::tr!("error.tenant.nav_parent_invalid"))
            })?;
        if parent.status.as_deref().unwrap_or("0") == STATUS_DISABLED {
            return Err(ServiceError::bad_request(&crate::tr!(
                "error.tenant.nav_parent_invalid"
            )));
        }
        // 沿 parent 链上溯：命中被修改行 ⇒ 成环；超过深度上限 ⇒ 拒绝
        let by_id: HashMap<i64, i64> = self
            .nav_repo
            .list(Some(tenant_id))
            .await?
            .into_iter()
            .map(|r| (r.l3_id, r.parent_id))
            .collect();
        let mut cur = parent_l3_id;
        let mut seen: HashSet<i64> = HashSet::new();
        seen.insert(cur);
        for _ in 0..L3_MAX_DEPTH {
            let next = by_id.get(&cur).copied().unwrap_or(0);
            if next == 0 {
                return Ok(());
            }
            if Some(next) == exclude_l3_id || !seen.insert(next) {
                return Err(ServiceError::bad_request(&crate::tr!(
                    "error.tenant.nav_parent_invalid"
                )));
            }
            cur = next;
        }
        Err(ServiceError::bad_request(&crate::tr!(
            "error.tenant.nav_parent_invalid"
        )))
    }

    /// 按范围载入 L3 行（租户范围下归属不符一律 403；不存在 404）
    async fn load_scoped_row(&self, scope: NavScope, l3_id: i64) -> Result<L3Model, ServiceError> {
        let row =
            self.nav_repo.find_by_id(l3_id).await?.ok_or_else(|| {
                ServiceError::not_found(&crate::tr!("error.tenant.nav_not_found"))
            })?;
        if let Some(tid) = scope.tenant()
            && row.tenant_id != tid
        {
            return Err(cross_tenant_denied());
        }
        Ok(row)
    }
}

/// 归一化 `visible` 载荷（仅 '1' 视为隐藏，其余一律 '0'）
fn visible_payload(visible: &str) -> String {
    if visible == "1" {
        "1".to_string()
    } else {
        "0".to_string()
    }
}

/// 新增时的 `order_num` 落库载荷（DTO 缺省 ⇒ 0）。
///
/// 列 `sys_tenant_menu.order_num` 是 `INT NOT NULL DEFAULT 0`，而 sea-orm 的
/// `Set(None)` 会在 INSERT 里**显式写入 NULL**、不触发列默认值 ⇒ 直接
/// `NOT NULL constraint failed`（2026-09-26 活体联调实测：不带 `orderNum` 的
/// `POST /system/tenant/menu` 返回 500）。故缺省必须在此补 0，
/// 与 `sys_tenant_service` 建租户根部门时的 `Set(dto_order.or(Some(0)))` 同口径。
fn order_num_payload(order_num: Option<i32>) -> Option<i32> {
    order_num.or(Some(0))
}

/// 展平菜单树为 M/C 节点列表（丢弃 `children`，保留节点自身字段）
fn flatten_ms(menus: Vec<SysMenuModel>) -> Vec<SysMenuModel> {
    let mut out = Vec::new();
    let mut stack: Vec<SysMenuModel> = menus;
    stack.reverse();
    while let Some(mut node) = stack.pop() {
        let kids = node.children.take().unwrap_or_default();
        out.push(node);
        for kid in kids.into_iter().rev() {
            stack.push(kid);
        }
    }
    out
}

/// L3 行 → Vo（引用菜单信息缺失时用空值占位，不阻断列表渲染）
fn to_vo(row: &L3Model, ref_menu: Option<&SysMenuModel>) -> SysTenantMenuVo {
    SysTenantMenuVo {
        l3_id: row.l3_id,
        tenant_id: row.tenant_id,
        ref_menu_id: row.ref_menu_id,
        parent_id: row.parent_id,
        order_num: row.order_num,
        visible: row.visible.clone(),
        status: row.status.clone(),
        create_by: row.create_by.clone(),
        create_time: row.create_time,
        update_by: row.update_by.clone(),
        update_time: row.update_time,
        ref_menu_name: ref_menu.map(|m| m.menu_name.clone()).unwrap_or_default(),
        ref_menu_type: ref_menu
            .and_then(|m| m.menu_type.clone())
            .unwrap_or_default(),
        ref_menu_path: ref_menu.and_then(|m| m.path.clone()),
        ref_menu_perms: ref_menu.and_then(|m| m.perms.clone()),
        ref_menu_icon: ref_menu.and_then(|m| m.icon.clone()),
    }
}

/// 供 router 挂载的类型自检（避免 unused import 告警）
#[allow(dead_code)]
fn _type_assert(_s: &SysTenantNavService, _m: &SysMenuModel, _r: &L3Model) {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::features::FeatureSet;

    #[test]
    fn test_nav_scope_platform_ignores_feature() {
        // 平台操作者不受能力位影响（恒可读写）
        let off = FeatureSet::default();
        let scope = nav_scope_from_features(0, &off).unwrap();
        assert_eq!(scope, NavScope::Platform);
        assert!(scope.allows_write());
    }

    #[test]
    fn test_nav_scope_tenant_modes() {
        let off = FeatureSet::default();
        assert!(
            nav_scope_from_features(7, &off).is_err(),
            "关闭态租户操作者必须 403（关闭态即现状）"
        );

        let view_only = FeatureSet::from_json(Some(r#"{"nav.l3":"view_only"}"#));
        let scope = nav_scope_from_features(7, &view_only).unwrap();
        assert_eq!(scope, NavScope::TenantViewOnly(7));
        assert!(!scope.allows_write(), "view_only 不得写");
        assert_eq!(scope.tenant(), Some(7));

        let full = FeatureSet::from_json(Some(r#"{"nav.l3":"full"}"#));
        let scope = nav_scope_from_features(7, &full).unwrap();
        assert_eq!(scope, NavScope::TenantFull(7));
        assert!(scope.allows_write());
    }

    #[test]
    fn test_effective_list_filter_rejects_cross_tenant() {
        assert_eq!(
            effective_list_filter(NavScope::Platform, None).unwrap(),
            None
        );
        assert_eq!(
            effective_list_filter(NavScope::Platform, Some(9)).unwrap(),
            Some(9)
        );
        assert_eq!(
            effective_list_filter(NavScope::TenantViewOnly(7), None).unwrap(),
            Some(7)
        );
        assert_eq!(
            effective_list_filter(NavScope::TenantFull(7), Some(7)).unwrap(),
            Some(7)
        );
        assert!(
            effective_list_filter(NavScope::TenantViewOnly(7), Some(9)).is_err(),
            "显式越权必须 403（禁止静默降级为空列表）"
        );
    }

    #[test]
    fn test_effective_write_tenant() {
        assert!(effective_write_tenant(NavScope::Platform, None).is_err());
        assert_eq!(
            effective_write_tenant(NavScope::Platform, Some(9)).unwrap(),
            9
        );
        assert_eq!(
            effective_write_tenant(NavScope::TenantFull(7), None).unwrap(),
            7
        );
        assert!(effective_write_tenant(NavScope::TenantFull(7), Some(9)).is_err());
    }

    #[test]
    fn test_visible_payload_normalizes() {
        assert_eq!(visible_payload("1"), "1");
        assert_eq!(visible_payload("0"), "0");
        assert_eq!(visible_payload("bogus"), "0", "非法值一律归一为显示");
    }

    #[test]
    fn test_order_num_payload_defaults_to_zero() {
        // 列 `order_num` 为 NOT NULL；`Set(None)` 会显式写 NULL 而非走列默认值 ⇒ 500。
        // 本断言锁定"缺省必须补 0"：若改回 `Set(dto.order_num)` 语义（返回 None），即变红。
        assert_eq!(
            order_num_payload(None),
            Some(0),
            "orderNum 缺省必须落 0，否则 INSERT 触发 NOT NULL constraint failed"
        );
        assert_eq!(order_num_payload(Some(5)), Some(5), "显式值原样保留");
    }
}
