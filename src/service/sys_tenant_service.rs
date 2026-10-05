// stepby-axum/src/service/sys_tenant_service.rs
//! 租户管理服务（多租户 Phase 3：**以 `sys_tenant` 为唯一事实源**）
//!
//! 决策（§27.1 / §29.7，2026-09-25 专项核查后修订，**推翻 Phase 2「dept 树根=租户」**）：
//! - `sys_tenant.tenant_id` 是**独立 id 空间**（不复用 `sys_dept.dept_id`）；
//!   `sys_tenant.dept_id` 仅是该租户组织树的挂载根部门，二者无相等关系；
//! - `tenant_id = 0` 保留为**平台租户**（跨租户运营，不落 `sys_tenant` 行）；
//! - 租户生命周期（状态/到期/配额）以本表列为准；组织树信息（负责人/电话/排序）
//!   仍落在根部门行，读写时与租户行同步（保持部门页与租户页一致）。
//!
//! 租户初始化（新建租户同事务，§27.4）：
//! 租户行 → 默认角色（菜单 = 套餐白名单 ∩ 平台"普通角色"菜单集）→ 根部门 →
//! 管理员用户 `{tenant_code}_admin`（随机初始密码，仅在创建响应中返回一次）。
//!
//! 会话吊销（§27.4）：租户停用/删除/到期不依赖 JWT 声明，而是
//! ① `tenant:state:{tid}` / `tenant:exp:{tid}` 运行时键（鉴权中间件逐请求校验，
//!   见 `common::tenant` 的三态求值）→ 存量 JWT 立即失效；
//! ② 定向扫描 `online:*` 踢掉该租户全部在线会话（黑名单 + 清 online/sso 绑定）。

use std::collections::{HashMap, HashSet};

use chrono::NaiveDateTime;
use futures::future::FutureExt;
use std::sync::Arc;
use sea_orm::sea_query::Expr;
use sea_orm::*;
use serde::{Deserialize, Serialize};
use ts_rs::TS;
use utoipa::ToSchema;

use crate::common::datetime::{self, now_naive};
use crate::common::double_opt;
use crate::common::error::ServiceError;
use crate::common::features::FeatureSet;
use crate::common::tenant::{
    TENANT_EXPIRE_GRACE_DAYS, TENANT_STATE_ACTIVE, TENANT_STATE_DISABLED, TENANT_STATE_GRACE,
    tenant_expire_key, tenant_state_key,
};
use crate::entity::sys_dept::{self, Column as DeptColumn, Entity as SysDept};
use crate::entity::sys_menu::{Column as MenuColumn, Entity as SysMenu};
use crate::entity::sys_pat::{Column as PatColumn, Entity as SysPat};
use crate::entity::sys_role::{
    ActiveModel as SysRoleActiveModel, Column as RoleColumn, Entity as SysRole,
};
use crate::entity::sys_role_menu::{
    ActiveModel as SysRoleMenuActiveModel, Column as RoleMenuColumn, Entity as SysRoleMenu,
};
use crate::entity::sys_tenant::{
    ActiveModel as TenantActiveModel, Column as TenantColumn, Entity as SysTenant,
    Model as SysTenantModel,
};
use crate::entity::sys_tenant_domain::{
    ActiveModel as TenantDomainActiveModel, Column as TenantDomainColumn, Entity as SysTenantDomain,
};
use crate::entity::sys_tenant_menu::{
    ActiveModel as TenantMenuActiveModel, Column as TenantMenuColumn, Entity as SysTenantMenu,
};
use crate::entity::sys_tenant_package::{
    ActiveModel as PkgActiveModel, Column as PkgColumn, Entity as SysTenantPackage,
};
use crate::entity::sys_user::{
    ActiveModel as SysUserActiveModel, Column as UserColumn, Entity as SysUser,
};
use crate::entity::sys_user_role::ActiveModel as SysUserRoleActiveModel;
use crate::repository::sys_dept::SysDeptRepository;
use crate::repository::sys_role::SysRoleRepository;
use crate::repository::sys_role_menu::SysRoleMenuRepository;
use crate::repository::sys_tenant::SysTenantRepository;
use crate::repository::sys_user::SysUserRepository;
use crate::repository::sys_user_role::SysUserRoleRepository;
use crate::service::sso_service::RefreshBinding;
use crate::shared_store::SharedStore;

/// 平台组织种子部门 ID（m20250711 init 种子"Stepby科技"）：
/// 其下用户与部门 `tenant_id = 0`（平台租户），**仅为组织种子、不再承担租户身份**
/// （§27.1 决策 5：`dept_id = 100` 降级，删除 `ensure_not_platform_root` 一类特判）。
pub const PLATFORM_ROOT_DEPT_ID: i64 = 100;

/// 平台"普通角色"角色 ID（init 种子）：新建租户默认管理员角色的菜单上限来源
const COMMON_ROLE_ID: i64 = 2;

/// 租户初始化时随默认管理员角色一并授予的"租户自助能力"按钮权限（§27.8 / §29）：
/// 平台普通角色（`COMMON_ROLE_ID`）只有 config/dict 的 list/query，缺 add/edit/remove
/// 按钮 perms，租户侧将无法自建字典类型、无法覆盖 `platform_default` 键或自建
/// `tenant_private` 键（链路断裂）。此处按 perms 精确补齐（仍受套餐白名单收敛），
/// 不整包放开其他平台按钮；治理边界由 `sys_config_service` 的服务层校验保证。
///
/// `pub(crate)`：`initialize::ensure_tenant_role_menu_governance` 存量回填复用同一清单。
pub(crate) const TENANT_SELF_SERVICE_PERMS: &[&str] = &[
    "system:config:add",
    "system:config:edit",
    "system:config:remove",
    "system:dict:add",
    "system:dict:edit",
    "system:dict:remove",
];

// 不下放给租户管理员角色的**平台专属 perms 前缀**清单统一收敛在
// [`crate::common::tenant::PLATFORM_ONLY_PERM_PREFIXES`]（台账 §3.1 原则 B）：
// 域名管理（`system:tenant:domain:`）、代码生成（`tool:gen:`）、缓存监控（`monitor:cache:`）
// 均经服务层守卫对租户一律 403，若随平台普通角色继承给租户管理员，会造成
// "菜单可见但请求一律 403"的假入口；租户初始化与存量回填均按该清单剔除菜单。

/// 踢线黑名单兜底 TTL（会话 JSON 无 exp 字段时的保守上界，24h）
const FALLBACK_BLACKLIST_TTL_SECS: i64 = 24 * 3600;

// ---------------------------------------------------------------- 租户角色菜单工具函数
//
// 下列三个函数是**模块级自由函数**（`&impl ConnectionTrait`），供"无 `SysTenantService`
// 实例"的路径复用（如 `sys_oauth_service` 的 OAuth 自动建号），目的是让
// **"平台普通角色菜单 ∩ 可授予 ∩ 套餐白名单"** 这一口径只有**一处实现**：
// 租户初始化（`add`，含自助按钮）与租户普通角色（OAuth 自动建号，不含自助按钮）共用，
// 避免"复制路径 / 授权路径"两处口径漂移。

/// 套餐白名单（`None` = 不限制 / 平台租户 / 租户不存在）。
///
/// 与 `SysTenantService::package_menu_whitelist` 同源（后者为本函数的薄包装）。
pub(crate) async fn package_menu_whitelist_conn(
    conn: &impl ConnectionTrait,
    tenant_id: i64,
) -> Result<Option<HashSet<i64>>, DbErr> {
    if tenant_id == 0 {
        return Ok(None);
    }
    let Some(tenant) = SysTenant::find()
        .filter(TenantColumn::TenantId.eq(tenant_id))
        .filter(TenantColumn::DelFlag.eq("0"))
        .one(conn)
        .await?
    else {
        return Ok(None);
    };
    let Some(package_id) = tenant.package_id else {
        return Ok(None);
    };
    let Some(package) = SysTenantPackage::find()
        .filter(PkgColumn::PackageId.eq(package_id))
        .filter(PkgColumn::DelFlag.eq("0"))
        .one(conn)
        .await?
    else {
        return Ok(None);
    };
    Ok(parse_menu_ids(&package.menu_ids).map(|v| v.into_iter().collect()))
}

/// 套餐行 → **租户请求的能力位**（套餐 `features` JSON 净化后的覆盖集）。
///
/// 注意：这只是"这个租户想开什么"；**平台层是天花板**，最终有效值由
/// [`effective_features_from_package`] / [`tenant_features_conn`] 取较保守者合成。
pub(crate) fn package_feature_overrides(
    package: Option<&crate::entity::sys_tenant_package::Model>,
) -> FeatureSet {
    FeatureSet::from_json(package.and_then(|p| p.features.as_deref()))
}

/// 有效能力集（**平台天花板 ∩ 套餐请求**）——由套餐行直接合成。
///
/// 供"租户尚未落库 / 尚未绑定套餐行"的初始化路径使用（无需回查租户行）。
/// 平台层未开启的能力位，无论套餐写什么，结果恒为 `off`（见 `FeatureSet::narrowed_by`）。
pub(crate) fn effective_features_from_package(
    package: Option<&crate::entity::sys_tenant_package::Model>,
) -> FeatureSet {
    crate::common::features::platform_features().narrowed_by(&package_feature_overrides(package))
}

/// 租户**有效能力集**（按 `tenant_id` 回查套餐行）。
///
/// - `tenant_id == 0`（平台租户）→ 仅平台层；
/// - 租户不存在 / 未绑定套餐 / 套餐已软删 → 仅平台层（未配置 = 跟随平台默认）；
/// - 套餐 `features` 为空 / 非法 JSON → 仅平台层（**fail-closed**）。
pub(crate) async fn tenant_features_conn(
    conn: &impl ConnectionTrait,
    tenant_id: i64,
) -> Result<FeatureSet, DbErr> {
    if tenant_id == 0 {
        return Ok(crate::common::features::platform_features().clone());
    }
    let Some(tenant) = SysTenant::find()
        .filter(TenantColumn::TenantId.eq(tenant_id))
        .filter(TenantColumn::DelFlag.eq("0"))
        .one(conn)
        .await?
    else {
        return Ok(crate::common::features::platform_features().clone());
    };
    let Some(package_id) = tenant.package_id else {
        return Ok(crate::common::features::platform_features().clone());
    };
    let package = SysTenantPackage::find()
        .filter(PkgColumn::PackageId.eq(package_id))
        .filter(PkgColumn::DelFlag.eq("0"))
        .one(conn)
        .await?;
    Ok(effective_features_from_package(package.as_ref()))
}

/// 租户角色的**菜单上限** = （平台普通角色菜单 ∪ 租户自助按钮）∩ **可授予** ∩ 套餐白名单。
///
/// - `include_self_service = true`：租户管理员角色用（`config`/`dict` 的 add/edit/remove
///   自助按钮需要，否则租户无法自建字典/覆盖 config）；
/// - `include_self_service = false`：租户**普通角色**用（OAuth 自动建号默认角色；
///   普通用户不应获得 config/dict 写权限）。
///
/// "可授予"判定与角色授权门禁同源，且**带能力位**（`is_grantable_perm_with_features`）：
/// 平台专属能力（域名管理等）仅在租户套餐对应能力位非 `off` 时才可随复制进入角色菜单，
/// 否则复制即造出"菜单可见但请求 403"的假入口。
pub(crate) async fn tenant_role_menu_ids(
    conn: &impl ConnectionTrait,
    whitelist: Option<&HashSet<i64>>,
    features: &FeatureSet,
    include_self_service: bool,
) -> Result<Vec<i64>, DbErr> {
    let mut base_menu_ids: Vec<i64> = SysRoleMenu::find()
        .filter(RoleMenuColumn::RoleId.eq(COMMON_ROLE_ID))
        .all(conn)
        .await?
        .into_iter()
        .map(|rm| rm.menu_id)
        .collect();
    if include_self_service {
        let self_service_menu_ids: Vec<i64> = SysMenu::find()
            .select_only()
            .column(MenuColumn::MenuId)
            .filter(MenuColumn::Perms.is_in(TENANT_SELF_SERVICE_PERMS.iter().copied()))
            .filter(MenuColumn::Status.eq("0"))
            .filter(MenuColumn::DelFlag.eq("0"))
            .into_tuple::<i64>()
            .all(conn)
            .await?;
        base_menu_ids.extend(self_service_menu_ids);
    }
    // 剔除**不可授予**菜单（平台专属前缀 ∪ tier2 未接过滤表，能力位未开启时平台专属项仍在
    // 此列）——租户侧不出现假入口，也不带入"先授菜单后补过滤"的跨租户读窗口。
    let menu_perms: Vec<(i64, Option<String>)> = SysMenu::find()
        .select_only()
        .column(MenuColumn::MenuId)
        .column(MenuColumn::Perms)
        .filter(MenuColumn::DelFlag.eq("0"))
        .into_tuple::<(i64, Option<String>)>()
        .all(conn)
        .await?;
    let excluded_menu_ids: HashSet<i64> = menu_perms
        .into_iter()
        .filter(|(_, perms)| {
            perms.as_deref().is_some_and(|p| {
                !p.is_empty()
                    && !crate::common::features::is_grantable_perm_with_features(p, features)
            })
        })
        .map(|(id, _)| id)
        .collect();
    base_menu_ids.retain(|id| !excluded_menu_ids.contains(id));
    base_menu_ids.sort_unstable();
    base_menu_ids.dedup();
    Ok(match whitelist {
        Some(white) => base_menu_ids
            .into_iter()
            .filter(|id| white.contains(id))
            .collect(),
        None => base_menu_ids,
    })
}

/// 按 `(tenant_id, role_key)` 查询启用中的角色 id（租户普通角色定位用）。
async fn find_role_id_by_key(
    conn: &impl ConnectionTrait,
    tenant_id: i64,
    role_key: &str,
) -> Result<Option<i64>, DbErr> {
    Ok(SysRole::find()
        .filter(RoleColumn::TenantId.eq(tenant_id))
        .filter(RoleColumn::RoleKey.eq(role_key))
        .filter(RoleColumn::DelFlag.eq("0"))
        .one(conn)
        .await?
        .map(|r| r.role_id))
}

/// **OAuth 自动建号的默认角色**解析（GAP-C 根治，第十一批）。
///
/// 背景：原实现无条件绑定 `DEFAULT_ROLE_ID`(=2)——那是**平台**普通角色（`tenant_id = 0`）；
/// 当供应商属租户 T（`provider_tid != 0`）时，就形成"租户用户 → 平台角色"的**跨租户引用**
/// （第十批 MT-2 复核发现并登记；见 `docs/optimization/all-topics-open-items-2026-09-26.md`
/// 与 `scripts/tenant-audit-allow.json` 的 notes-R9）。改绑租户**管理员**角色则是**过度授权**，
/// 故正确解法是：让租户拥有**自己的**普通角色。
///
/// 语义：
/// - `tenant_id == 0` → 平台普通角色 `COMMON_ROLE_ID`（行为不变）；
/// - `tenant_id != 0` → 该租户的普通角色（`role_key = "{tenant_code}_common"`）；
///   不存在则**幂等创建**（角色字段以平台普通角色为语义母版；菜单 =
///   `tenant_role_menu_ids(.., include_self_service = false)`）；并发由唯一索引
///   `uk_sys_role_tenant_key` 兜底——插入冲突时**回读**已存在行；
/// - 租户不存在或创建失败 → `Ok(None)`：调用方**不绑定角色**（**fail-closed**：
///   宁可账号无角色，也绝不复用平台角色，从而不产生跨租户角色引用）。
pub(crate) async fn resolve_default_role_for_tenant(
    db: &DatabaseConnection,
    tenant_id: i64,
) -> Result<Option<i64>, ServiceError> {
    if tenant_id == 0 {
        return Ok(Some(COMMON_ROLE_ID));
    }
    let Some(tenant) = SysTenant::find()
        .filter(TenantColumn::TenantId.eq(tenant_id))
        .filter(TenantColumn::DelFlag.eq("0"))
        .one(db)
        .await?
    else {
        tracing::warn!(
            tenant_id,
            "OAuth 自动建号：租户不存在，跳过默认角色绑定（fail-closed）"
        );
        return Ok(None);
    };
    let role_key = format!("{}_common", tenant.tenant_code);
    if let Some(role_id) = find_role_id_by_key(db, tenant_id, &role_key).await? {
        return Ok(Some(role_id));
    }

    // 语义母版：平台普通角色（data_scope / 严格校验开关 / 排序位与其对齐）
    let template = SysRole::find()
        .filter(RoleColumn::RoleId.eq(COMMON_ROLE_ID))
        .one(db)
        .await?;
    let whitelist = package_menu_whitelist_conn(db, tenant_id).await?;
    // 有效能力集（平台天花板 ∩ 套餐）；复制菜单时按它决定平台专属 perms 是否可进角色
    let features = tenant_features_conn(db, tenant_id).await?;
    let role_sort = template.as_ref().map(|r| r.role_sort).unwrap_or(2);
    let data_scope = template
        .as_ref()
        .and_then(|r| r.data_scope.clone())
        .or_else(|| Some("2".to_string()));
    let menu_check_strictly = template.as_ref().and_then(|r| r.menu_check_strictly);
    let dept_check_strictly = template.as_ref().and_then(|r| r.dept_check_strictly);
    let role_name = format!("{}-普通角色", tenant.tenant_name);
    let now = now_naive();

    let role_repo = SysRoleRepository::new(db.clone());
    let role_menu_repo = SysRoleMenuRepository::new(db.clone());
    let created = db
        .transaction::<_, i64, DbErr>(|txn| {
            let role_repo = role_repo.clone();
            let role_menu_repo = role_menu_repo.clone();
            let role_key = role_key.clone();
            let role_name = role_name.clone();
            let data_scope = data_scope.clone();
            let whitelist = whitelist.clone();
            let features = features.clone();
            Box::pin(async move {
                let menu_ids = tenant_role_menu_ids(txn, whitelist.as_ref(), &features, false).await?;
                let am = SysRoleActiveModel {
                    role_id: NotSet,
                    tenant_id: Set(tenant_id),
                    role_name: Set(role_name),
                    role_key: Set(role_key),
                    role_sort: Set(role_sort),
                    data_scope: Set(data_scope),
                    custom_sql: Set(None),
                    menu_check_strictly: Set(menu_check_strictly),
                    dept_check_strictly: Set(dept_check_strictly),
                    status: Set("0".to_string()),
                    // 非系统角色：不享超管短路（与租户管理员角色一致）
                    is_system: Set(false),
                    del_flag: Set(Some("0".to_string())),
                    create_by: Set(Some("oauth:auto-register".to_string())),
                    create_time: Set(Some(now)),
                    update_by: Set(Some("oauth:auto-register".to_string())),
                    update_time: Set(Some(now)),
                    remark: Set(Some(
                        "OAuth 自动建号默认角色（租户普通角色；菜单 = 平台普通角色菜单 ∩ 可授予 ∩ 套餐白名单）"
                            .to_string(),
                    )),
                };
                let role = role_repo.base().insert_conn(txn, am).await?;
                if !menu_ids.is_empty() {
                    let rows: Vec<SysRoleMenuActiveModel> = menu_ids
                        .into_iter()
                        .map(|menu_id| SysRoleMenuActiveModel {
                            role_id: Set(role.role_id),
                            menu_id: Set(menu_id),
                        })
                        .collect();
                    role_menu_repo.insert_many_conn(txn, rows).await?;
                }
                Ok(role.role_id)
            })
        })
        .await;

    match created {
        Ok(role_id) => {
            tracing::info!(
                tenant_id,
                role_id,
                role_key = %role_key,
                "OAuth 自动建号：已创建租户普通角色（跨租户角色引用已消除）"
            );
            Ok(Some(role_id))
        }
        Err(e) => {
            // 并发：另一请求已创建同名角色 ⇒ 回读（唯一索引 uk_sys_role_tenant_key 兜底）
            if let Some(role_id) = find_role_id_by_key(db, tenant_id, &role_key).await? {
                return Ok(Some(role_id));
            }
            tracing::warn!(
                tenant_id,
                error = %e,
                "OAuth 自动建号：创建租户普通角色失败，跳过绑定（fail-closed，不使用平台角色兜底）"
            );
            Ok(None)
        }
    }
}

/// 运行时键 TTL（覆盖 JWT 有效期上界，续期靠每次登录重写）
const TENANT_RUNTIME_KEY_TTL_SECS: i64 = 30 * 24 * 3600;

/// tenant_code → tid 缓存 TTL（域名链路 host 头 `X-Tenant-Code` 解析，秒）
const CODE_CACHE_TTL_SECS: i64 = 300;

/// `tenant:code:{code}` 键名（租户短码 → tid）
fn code_cache_key(tenant_code: &str) -> String {
    format!("tenant:code:{}", tenant_code)
}

/// 配额校验业务标记（`DbErr::Custom`，见 `ensure_account_quota_txn`）：
/// 租户不可用（不存在/已删除）
const QUOTA_MARKER_DISABLED: &str = "tenant_quota_disabled";
/// 配额校验业务标记：已达上限（后接 `account_count` 数值）
const QUOTA_MARKER_PREFIX: &str = "tenant_quota_exceeded:";

/// 租户账号配额可用性（事务内锁定租户行后的判定结果）
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TenantQuotaAvailability {
    /// 租户行缺失或已删除（不可写入）
    Unavailable,
    /// 不限量（tenant_id = 0 平台租户，或 `account_count <= 0`）
    Unlimited,
    /// 限量：`limit` 为总上限，`remaining` 为剩余可新增数
    Limited { limit: u64, remaining: u64 },
}

// ==================== DTO / Vo ====================

/// 租户视图（租户行 + 根部门展示字段 + 用户统计）
#[derive(Debug, Clone, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
#[schema(as = TenantVo)]
pub struct TenantVo {
    /// 租户 ID（独立 id 空间；接口主键）
    pub tenant_id: i64,
    /// 租户短码（域名/展示/管理员用户名前缀）
    pub tenant_code: String,
    pub tenant_name: String,
    /// 组织树挂载根部门（可能为空：平台侧尚未建组织时）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dept_id: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub package_id: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub package_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub contact_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub contact_phone: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub contact_email: Option<String>,
    /// 主域名（冗余自 sys_tenant_domain，域名链路落地后由绑定接口维护）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>,
    /// 到期时间（NULL = 永不过期；过期宽限期见 `TENANT_EXPIRE_GRACE_DAYS`）
    #[serde(
        skip_serializing_if = "Option::is_none",
        serialize_with = "datetime::serialize_opt",
        deserialize_with = "datetime::deserialize_opt"
    )]
    pub expire_time: Option<NaiveDateTime>,
    /// 账号数上限（0 = 不限）
    pub account_count: i32,
    /// '0' 正常 / '1' 停用
    pub status: Option<String>,
    /// '0' 存在 / '2' 已删除
    pub del_flag: Option<String>,
    /// 租户内用户数（sys_user.tenant_id = tenant_id 且未删除）
    pub user_count: u64,
    /// 根部门负责人（组织树展示字段，与部门页同步）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub leader: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub phone: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub order_num: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remark: Option<String>,
    #[serde(
        skip_serializing_if = "Option::is_none",
        serialize_with = "datetime::serialize_opt",
        deserialize_with = "datetime::deserialize_opt"
    )]
    pub create_time: Option<NaiveDateTime>,
    /// 租户管理员用户名（仅新建租户响应返回）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub admin_user_name: Option<String>,
    /// 租户管理员初始密码（**仅新建租户响应返回一次**，服务端只存哈希）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub admin_init_password: Option<String>,
}

/// 套餐下拉项（租户表单选择套餐白名单用；仅平台可见）
#[derive(Debug, Clone, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
#[schema(as = TenantPackageOptionVo)]
pub struct TenantPackageOptionVo {
    pub package_id: i64,
    pub package_name: String,
    /// 套餐默认账号数（NULL / 0 = 不限）
    pub default_account_count: i32,
}

/// 能力位注册项（管理面渲染用：能力位键 + 该套餐当前模式 + 注册表默认/允许模式）
///
/// 前端**不硬编码**能力位清单——一律由本 VO 渲染，保证与后端注册表单一事实源。
#[derive(Debug, Clone, Serialize, TS, ToSchema)]
#[serde(rename_all = "camelCase")]
#[ts(
    export,
    rename = "PackageFeatureItemVo",
    export_to = "PackageFeatureItemVo.ts",
    rename_all = "camelCase"
)]
#[schema(as = PackageFeatureItemVo)]
pub struct PackageFeatureItemVo {
    /// 能力位键（`common::features::KNOWN_FEATURES` 注册表）
    pub key: String,
    /// 该套餐当前**请求**的模式（未显式配置时 = `defaultMode`）
    pub mode: String,
    /// 注册表默认模式（恒为 `off`，即"关闭态即安全态"）
    pub default_mode: String,
    /// 允许的模式集合（首项恒为 `off`）
    pub modes: Vec<String>,
}

/// 套餐能力位配置视图（管理面；仅平台管理员）
#[derive(Debug, Clone, Serialize, TS, ToSchema)]
#[serde(rename_all = "camelCase")]
#[ts(
    export,
    rename = "PackageFeaturesVo",
    export_to = "PackageFeaturesVo.ts",
    rename_all = "camelCase"
)]
#[schema(as = PackageFeaturesVo)]
pub struct PackageFeaturesVo {
    pub package_id: i64,
    pub package_name: String,
    /// 该套餐**显式覆盖**的能力位（key → mode）；未出现的键 = 跟随注册表默认（`off`）
    pub overrides: std::collections::BTreeMap<String, String>,
    /// 全量注册表 + 该套餐的当前模式
    pub items: Vec<PackageFeatureItemVo>,
    /// 平台层（`config.toml [features]`）已开启的能力位——**天花板**：
    /// 未出现在此列表的能力位，套餐无法开启（开启即"假入口"，会被服务层拒绝）
    pub platform_enabled: Vec<String>,
}

/// 套餐能力位更新入参（仅平台管理员）
#[derive(Debug, Clone, Deserialize, TS, ToSchema)]
#[serde(rename_all = "camelCase")]
#[ts(
    export,
    rename = "PackageFeaturesUpdateDto",
    export_to = "PackageFeaturesUpdateDto.ts",
    rename_all = "camelCase"
)]
#[schema(as = PackageFeaturesUpdateDto)]
pub struct PackageFeaturesUpdateDto {
    pub package_id: i64,
    /// 显式覆盖（key → mode）；传空对象 = 全部回落默认（全关闭）。
    ///
    /// 未登记键 / 非法模式 / 平台未开启项一律 **400 拒绝**（不静默净化），
    /// 避免管理面出现"以为开了其实没开"的错觉。
    #[serde(default)]
    pub features: HashMap<String, String>,
}

/// 租户查询入参
#[derive(Debug, Clone, Deserialize, ToSchema, utoipa::IntoParams)]
#[serde(rename_all = "camelCase")]
#[into_params(parameter_in = Query)]
pub struct TenantQueryDto {
    /// 租户名称（模糊）
    #[serde(default)]
    pub tenant_name: Option<String>,
    /// 租户短码（精确）
    #[serde(default)]
    pub tenant_code: Option<String>,
    /// 生命周期过滤：'0' 在册（默认）/ '2' 回收站 / 其他值原样过滤
    #[serde(default)]
    pub del_flag: Option<String>,
}

/// 租户新增入参（仅平台管理员）
#[derive(Debug, Clone, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct TenantAddDto {
    pub tenant_name: String,
    /// 租户短码（可选；缺省按 `t{uuid前8位}` 生成，全局唯一）
    #[serde(default)]
    pub tenant_code: Option<String>,
    #[serde(default)]
    pub package_id: Option<i64>,
    #[serde(default)]
    pub contact_name: Option<String>,
    #[serde(default)]
    pub contact_phone: Option<String>,
    #[serde(default)]
    pub contact_email: Option<String>,
    /// 到期时间（可空 = 永不过期）
    #[serde(
        default,
        serialize_with = "datetime::serialize_opt",
        deserialize_with = "datetime::deserialize_opt"
    )]
    pub expire_time: Option<NaiveDateTime>,
    /// 账号数上限（0 = 不限；缺省取套餐 default_account_count）
    #[serde(default)]
    pub account_count: Option<i32>,
    /// '0' 正常 / '1' 停用
    #[serde(default)]
    pub status: Option<String>,
    #[serde(default)]
    pub order_num: Option<i32>,
    /// 根部门负责人
    #[serde(default)]
    pub leader: Option<String>,
    #[serde(default)]
    pub phone: Option<String>,
    #[serde(default)]
    pub email: Option<String>,
    #[serde(default)]
    pub remark: Option<String>,
}

/// 租户修改入参（平台可改全部字段；租户仅可改名称/联系人/备注）
///
/// **平台分配项三态语义**（`package_id` / `account_count` / `expire_time`）：
/// - 字段缺省（不提交）→ **不修改**（避免"仅改名"的调用顺手清空套餐/配额/到期，属隐式数据丢失）；
/// - 显式 `null` → `package_id` 置空（不分配套餐）/ `account_count` 归零（0 = 不限）/
///   `expire_time` 置空（永不过期）；
/// - 提交值 → 设置为该值（`account_count` 负值按 0 处理；该列 NOT NULL，**绝不写入 NULL**）。
///
/// 说明：`account_count` 的显式 `null` 映射为 0 而非 NULL，是"清空配额 = 不限"的语义落地，
/// 与 `sys_tenant.account_count` 的 NOT NULL 约束一致。
#[derive(Debug, Clone, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct TenantEditDto {
    pub tenant_id: i64,
    pub tenant_name: String,
    #[serde(default, deserialize_with = "double_opt::deserialize_double_opt")]
    pub package_id: Option<Option<i64>>,
    #[serde(default)]
    pub contact_name: Option<String>,
    #[serde(default)]
    pub contact_phone: Option<String>,
    #[serde(default)]
    pub contact_email: Option<String>,
    #[serde(default, deserialize_with = "datetime::deserialize_double_opt")]
    pub expire_time: Option<Option<NaiveDateTime>>,
    #[serde(default, deserialize_with = "double_opt::deserialize_double_opt")]
    pub account_count: Option<Option<i32>>,
    #[serde(default)]
    pub order_num: Option<i32>,
    #[serde(default)]
    pub leader: Option<String>,
    #[serde(default)]
    pub phone: Option<String>,
    #[serde(default)]
    pub email: Option<String>,
    #[serde(default)]
    pub remark: Option<String>,
    /// 显式清空声明（批次 4）：列出的字段写 NULL；缺省 = 保持现值（见 `common::clear_fields`）
    #[serde(default)]
    pub clear_fields: Option<Vec<String>>,
}

/// 「显式清空」契约（批次 4）：联系人/负责人字段在"未传 = 保持现值"语义下无法清空。
///
/// 白名单**逐条枚举**：`contactName`/`contactPhone`/`contactEmail` 落 `sys_tenant` 行，
/// `leader`/`phone`/`email` 落该租户**根部门**行（`sys_tenant.dept_id` 指向的组织树挂载根）。
/// `remark` 不列入（其更新语义本就是"未传即写 NULL"）。
impl crate::common::clear_fields::ClearFieldsDto for TenantEditDto {
    const CLEARABLE_FIELDS: &'static [&'static str] = &[
        "contactName",
        "contactPhone",
        "contactEmail",
        "leader",
        "phone",
        "email",
    ];

    fn clear_fields(&self) -> Option<&[String]> {
        self.clear_fields.as_deref()
    }

    fn field_value_is_present(&self, field: &str) -> bool {
        let value = match field {
            "contactName" => self.contact_name.as_deref(),
            "contactPhone" => self.contact_phone.as_deref(),
            "contactEmail" => self.contact_email.as_deref(),
            "leader" => self.leader.as_deref(),
            "phone" => self.phone.as_deref(),
            "email" => self.email.as_deref(),
            _ => None,
        };
        crate::common::clear_fields::value_is_present(value)
    }
}

/// 租户启停入参
#[derive(Debug, Clone, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct TenantStatusDto {
    pub tenant_id: i64,
    /// '0' 正常 / '1' 停用（停用立即吊销该租户全部会话）
    pub status: String,
}

/// 登录态三态判定结果（到期三态：正常 / 宽限期只读 / 停用或超期）
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TenantLoginState {
    /// 正常（未到期或永不过期）
    Active,
    /// 宽限期只读（已过期但在宽限期内：允许读与续费，拒绝写）
    Grace,
}

impl TenantLoginState {
    pub fn runtime_state_value(self) -> &'static str {
        match self {
            TenantLoginState::Active => TENANT_STATE_ACTIVE,
            TenantLoginState::Grace => TENANT_STATE_GRACE,
        }
    }
}

/// 新建租户事务产物
struct TenantInitOutcome {
    tenant_id: i64,
    dept_id: i64,
    admin_user_name: String,
}

// ==================== 服务 ====================

/// 租户管理服务
#[derive(Clone)]
pub struct SysTenantService {
    db: DatabaseConnection,
    /// 共享态存储（Redis / local 双档；运行时键、code 缓存、踢线吊销统一走此抽象）
    store: Arc<dyn SharedStore>,
    tenant_repo: SysTenantRepository,
    dept_repo: SysDeptRepository,
    user_repo: SysUserRepository,
    role_repo: SysRoleRepository,
    role_menu_repo: SysRoleMenuRepository,
    user_role_repo: SysUserRoleRepository,
}

impl SysTenantService {
    pub fn new(db: DatabaseConnection, store: Arc<dyn SharedStore>) -> Self {
        Self {
            tenant_repo: SysTenantRepository::new(db.clone()),
            dept_repo: SysDeptRepository::new(db.clone()),
            user_repo: SysUserRepository::new(db.clone()),
            role_repo: SysRoleRepository::new(db.clone()),
            role_menu_repo: SysRoleMenuRepository::new(db.clone()),
            user_role_repo: SysUserRoleRepository::new(db.clone()),
            db,
            store,
        }
    }

    // ---------- 归属/权限 ----------

    /// 租户归属校验：平台操作者（tid=0）放行；否则仅本租户
    fn ensure_tenant_access(operator_tid: i64, tenant_id: i64) -> Result<(), ServiceError> {
        if crate::common::tenant::tenant_allowed(operator_tid, tenant_id) {
            Ok(())
        } else {
            Err(ServiceError::forbidden(&crate::tr!(
                "error.common.forbidden"
            )))
        }
    }

    /// 平台专属操作校验（新建/启停/删除/恢复仅平台管理员）
    fn ensure_platform_operator(operator_tid: i64) -> Result<(), ServiceError> {
        if operator_tid == 0 {
            Ok(())
        } else {
            Err(ServiceError::forbidden(&crate::tr!(
                "error.tenant.platform_only"
            )))
        }
    }

    // ---------- 查询 ----------

    /// 租户列表（租户表为事实源；tenant_scope=Some(tid) 时仅返回本租户，
    /// 防止只读权限跨租户窥探租户名录）
    pub async fn list(
        &self,
        q: TenantQueryDto,
        tenant_scope_tid: Option<i64>,
    ) -> Result<Vec<TenantVo>, ServiceError> {
        let del_flag = q.del_flag.as_deref().unwrap_or("0");
        let mut query = SysTenant::find().filter(TenantColumn::DelFlag.eq(del_flag));
        if let Some(tid) = tenant_scope_tid {
            query = query.filter(TenantColumn::TenantId.eq(tid));
        }
        if let Some(name) = q.tenant_name.as_deref().filter(|s| !s.is_empty()) {
            query = query.filter(
                TenantColumn::TenantName.like(format!("%{}%", crate::common::like_escape(name))),
            );
        }
        if let Some(code) = q.tenant_code.as_deref().filter(|s| !s.is_empty()) {
            query = query.filter(TenantColumn::TenantCode.eq(code));
        }
        let tenants = query
            .order_by_asc(TenantColumn::TenantId)
            .all(self.db())
            .await?;
        self.build_vos(tenants).await
    }

    /// 套餐下拉（仅平台：套餐是平台侧功能白名单上限，租户无权枚举平台套餐名录）
    pub async fn package_options(
        &self,
        operator_tid: i64,
    ) -> Result<Vec<TenantPackageOptionVo>, ServiceError> {
        Self::ensure_platform_operator(operator_tid)?;
        let rows = SysTenantPackage::find()
            .filter(PkgColumn::DelFlag.eq("0"))
            .filter(PkgColumn::Status.eq("0"))
            .order_by_asc(PkgColumn::PackageId)
            .all(self.db())
            .await?;
        Ok(rows
            .into_iter()
            .map(|p| TenantPackageOptionVo {
                package_id: p.package_id,
                package_name: p.package_name,
                default_account_count: p.default_account_count.unwrap_or(0),
            })
            .collect())
    }

    /// 读取租户**有效能力集**（平台天花板 ∩ 套餐 `features`）。
    ///
    /// 供"按能力位决定是否启用某功能"的加载期路径复用（如批次 3 的 `get_routers` L3 重组）：
    /// 关闭态必须完全等价于改造前行为，故调用方需先取能力集再决定是否叠加。
    pub async fn tenant_features(
        &self,
        tenant_id: i64,
    ) -> Result<crate::common::features::FeatureSet, ServiceError> {
        Ok(tenant_features_conn(self.db(), tenant_id).await?)
    }

    /// 读取套餐能力位配置（仅平台管理员）。
    ///
    /// 返回**全量注册表**（而非仅已配置项），使前端无需硬编码能力位清单；
    /// 同时返回平台层已开启项（天花板），前端可据此禁用"平台未开"的开关。
    pub async fn package_features(
        &self,
        package_id: i64,
        operator_tid: i64,
    ) -> Result<PackageFeaturesVo, ServiceError> {
        Self::ensure_platform_operator(operator_tid)?;
        let package = self.load_package(package_id).await?;
        Ok(Self::build_package_features_vo(&package))
    }

    /// 设置套餐能力位（仅平台管理员）。
    ///
    /// 三道校验（任一不过即 400，**不静默净化**——管理面配置必须"所见即所得"）：
    /// ① key 已在 `KNOWN_FEATURES` 登记；② mode 在该能力位的允许集合内；
    /// ③ 非 `off` 的项必须在平台层 `[features]` 已开启（否则形成"租户开了但平台没开"的假入口）。
    ///
    /// 写入后**立即收敛**该套餐下所有租户的角色菜单授权：关闭能力位必须同步回收原先随能力位
    /// 下放的平台专属菜单（否则残留授权形成"菜单可见但请求 403"）。套餐是跨租户共享的，
    /// 故收敛按"绑定该套餐的全部租户"逐个执行。
    pub async fn set_package_features(
        &self,
        dto: PackageFeaturesUpdateDto,
        operator: &str,
        operator_tid: i64,
    ) -> Result<PackageFeaturesVo, ServiceError> {
        use crate::common::features::{FEATURE_OFF, FeatureSet, is_valid_mode, platform_features};
        Self::ensure_platform_operator(operator_tid)?;
        let package = self.load_package(dto.package_id).await?;

        for (key, mode) in &dto.features {
            if !is_valid_mode(key, mode) {
                return Err(ServiceError::bad_request(&crate::tr!(
                    "error.tenant.feature_invalid",
                    key = key,
                    mode = mode
                )));
            }
            if mode != FEATURE_OFF && !platform_features().is_on(key) {
                return Err(ServiceError::bad_request(&crate::tr!(
                    "error.tenant.feature_platform_disabled",
                    key = key
                )));
            }
        }

        let platform = platform_features();
        // 与平台层**同一模式**的显式项是无信息量的（平台是天花板，"未配置 = 跟随平台"
        // 与"显式写成与平台相同"行为完全一致），剔除后保持最小显式集、便于 diff 审计。
        // 注意：与平台**不同**的项一律保留（含显式 `off`——它是租户主动收窄，必须落库）。
        let set = FeatureSet::sanitized(
            dto.features
                .iter()
                .filter(|(k, v)| platform.mode(k) != v.as_str())
                .map(|(k, v)| (k.clone(), v.clone())),
        );
        // 全默认（全关闭）时落 NULL：与存量行语义一致（`NULL` / `{}` 均 = 全默认）
        let mut am: PkgActiveModel = package.into();
        am.features = Set(if set.is_default() {
            None
        } else {
            Some(set.to_json())
        });
        am.update_by = Set(Some(operator.to_string()));
        am.update_time = Set(Some(now_naive()));
        SysTenantPackage::update(am).exec(self.db()).await?;

        let updated = self.load_package(dto.package_id).await?;
        let tenant_ids: Vec<i64> = SysTenant::find()
            .select_only()
            .column(TenantColumn::TenantId)
            .filter(TenantColumn::PackageId.eq(dto.package_id))
            .filter(TenantColumn::DelFlag.eq("0"))
            .into_tuple::<i64>()
            .all(self.db())
            .await?;
        for tid in tenant_ids {
            self.converge_tenant_role_menus(tid, &updated).await?;
        }

        Ok(Self::build_package_features_vo(&updated))
    }

    /// 组装套餐能力位视图（注册表 + 当前模式 + 平台天花板）
    fn build_package_features_vo(
        package: &crate::entity::sys_tenant_package::Model,
    ) -> PackageFeaturesVo {
        use crate::common::features::{KNOWN_FEATURES, platform_features};
        let overrides = package_feature_overrides(Some(package));
        let platform = platform_features();
        PackageFeaturesVo {
            package_id: package.package_id,
            package_name: package.package_name.clone(),
            overrides: overrides.overrides().clone(),
            items: KNOWN_FEATURES
                .iter()
                .map(|def| PackageFeatureItemVo {
                    key: def.key.to_string(),
                    mode: overrides.mode(def.key).to_string(),
                    default_mode: def.default_mode.to_string(),
                    modes: def.modes.iter().map(|m| (*m).to_string()).collect(),
                })
                .collect(),
            platform_enabled: KNOWN_FEATURES
                .iter()
                .filter(|def| platform.is_on(def.key))
                .map(|def| def.key.to_string())
                .collect(),
        }
    }

    /// 加载套餐行（未找到 / 已软删 → 404）
    async fn load_package(
        &self,
        package_id: i64,
    ) -> Result<crate::entity::sys_tenant_package::Model, ServiceError> {
        SysTenantPackage::find()
            .filter(PkgColumn::PackageId.eq(package_id))
            .filter(PkgColumn::DelFlag.eq("0"))
            .one(self.db())
            .await?
            .ok_or_else(|| ServiceError::not_found(&crate::tr!("error.tenant.not_found")))
    }

    /// 租户详情（operator_tid≠0 时仅允许查本租户）
    pub async fn get_info(
        &self,
        tenant_id: i64,
        operator_tid: i64,
    ) -> Result<TenantVo, ServiceError> {
        Self::ensure_tenant_access(operator_tid, tenant_id)?;
        let tenant = self.load_tenant(tenant_id).await?;
        let mut vos = self.build_vos(vec![tenant]).await?;
        vos.pop()
            .ok_or_else(|| ServiceError::not_found(&crate::tr!("error.tenant.not_found")))
    }
    /// 把租户行批量组装为 Vo（根部门展示字段 + 套餐名 + 用户数，批量查询避免 N+1）
    async fn build_vos(&self, tenants: Vec<SysTenantModel>) -> Result<Vec<TenantVo>, ServiceError> {
        if tenants.is_empty() {
            return Ok(Vec::new());
        }
        // 根部门批量
        let dept_ids: Vec<i64> = tenants.iter().filter_map(|t| t.dept_id).collect();
        let dept_map: HashMap<i64, sys_dept::Model> = if dept_ids.is_empty() {
            HashMap::new()
        } else {
            SysDept::find()
                .filter(DeptColumn::DeptId.is_in(dept_ids))
                .all(self.db())
                .await?
                .into_iter()
                .map(|d| (d.dept_id, d))
                .collect()
        };
        // 套餐名批量
        let pkg_ids: Vec<i64> = tenants.iter().filter_map(|t| t.package_id).collect();
        let pkg_map: HashMap<i64, String> = if pkg_ids.is_empty() {
            HashMap::new()
        } else {
            SysTenantPackage::find()
                .filter(PkgColumn::PackageId.is_in(pkg_ids))
                .all(self.db())
                .await?
                .into_iter()
                .map(|p| (p.package_id, p.package_name))
                .collect()
        };
        // 用户数批量（一次 GROUP BY，避免逐租户 count）
        let tid_list: Vec<i64> = tenants.iter().map(|t| t.tenant_id).collect();
        let counts = self.count_users_grouped(&tid_list).await?;

        Ok(tenants
            .into_iter()
            .map(|t| {
                let dept = t.dept_id.and_then(|id| dept_map.get(&id));
                TenantVo {
                    tenant_id: t.tenant_id,
                    tenant_code: t.tenant_code.clone(),
                    tenant_name: t.tenant_name.clone(),
                    dept_id: t.dept_id,
                    package_id: t.package_id,
                    package_name: t.package_id.and_then(|id| pkg_map.get(&id).cloned()),
                    contact_name: t.contact_name.clone(),
                    contact_phone: t.contact_phone.clone(),
                    contact_email: t.contact_email.clone(),
                    domain: t.domain.clone(),
                    expire_time: t.expire_time,
                    account_count: t.account_count.unwrap_or(0),
                    status: t.status.clone(),
                    del_flag: t.del_flag.clone(),
                    user_count: counts.get(&t.tenant_id).copied().unwrap_or(0),
                    leader: dept.and_then(|d| d.leader.clone()),
                    phone: dept.and_then(|d| d.phone.clone()),
                    email: dept.and_then(|d| d.email.clone()),
                    order_num: dept.and_then(|d| d.order_num),
                    remark: t.remark.clone(),
                    create_time: t.create_time,
                    admin_user_name: None,
                    admin_init_password: None,
                }
            })
            .collect())
    }

    /// 租户用户数分组统计（口径：含停用用户、不含软删、含管理员，§27.4）
    async fn count_users_grouped(
        &self,
        tenant_ids: &[i64],
    ) -> Result<HashMap<i64, u64>, ServiceError> {
        use sea_orm::FromQueryResult;

        #[derive(Debug, FromQueryResult)]
        struct CountRow {
            tenant_id: i64,
            cnt: i64,
        }

        let rows = SysUser::find()
            .select_only()
            .column(UserColumn::TenantId)
            .column_as(
                sea_orm::sea_query::Expr::col(UserColumn::UserId).count(),
                "cnt",
            )
            .filter(UserColumn::TenantId.is_in(tenant_ids.to_vec()))
            .filter(UserColumn::DelFlag.eq("0"))
            .group_by(UserColumn::TenantId)
            .into_model::<CountRow>()
            .all(self.db())
            .await?;
        Ok(rows
            .into_iter()
            .map(|r| (r.tenant_id, r.cnt.max(0) as u64))
            .collect())
    }

    // ---------- 新建（含租户初始化） ----------

    /// 新建租户（仅平台管理员）。同事务完成：
    /// 租户行 → 根部门（parent_id=0 / ancestors='0' / tenant_id=新 tid）→
    /// 默认角色（菜单 = 套餐白名单 ∩ 平台普通角色菜单）→ 管理员用户 `{tenant_code}_admin`
    pub async fn add(
        &self,
        dto: TenantAddDto,
        operator: &str,
        operator_tid: i64,
    ) -> Result<TenantVo, ServiceError> {
        Self::ensure_platform_operator(operator_tid)?;
        let name = dto.tenant_name.trim();
        if name.is_empty() {
            return Err(ServiceError::bad_request(&crate::tr!(
                "error.tenant.name_required"
            )));
        }
        if self.tenant_repo.find_active_by_name(name).await?.is_some() {
            return Err(ServiceError::bad_request(&crate::tr!(
                "error.tenant.name_duplicate"
            )));
        }

        // 租户短码：显式给定则校验格式与占用；缺省按 uuid 前 8 位生成（全局唯一）
        let tenant_code = match dto
            .tenant_code
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            Some(code) => {
                let code = code.to_ascii_lowercase();
                validate_tenant_code(&code)?;
                if self.tenant_repo.find_by_code_any(&code).await?.is_some() {
                    return Err(ServiceError::bad_request(&crate::tr!(
                        "error.tenant.code_duplicate"
                    )));
                }
                code
            }
            None => {
                let mut candidate = String::new();
                for _ in 0..5 {
                    let c = format!("t{}", &uuid::Uuid::new_v4().simple().to_string()[..8]);
                    if self.tenant_repo.find_by_code_any(&c).await?.is_none() {
                        candidate = c;
                        break;
                    }
                }
                if candidate.is_empty() {
                    return Err(ServiceError::bad_request(&crate::tr!(
                        "error.tenant.code_duplicate"
                    )));
                }
                candidate
            }
        };

        // 套餐：显式指定必须存在且启用；缺省取平台第一个启用套餐
        let package = self.resolve_package_for_new(dto.package_id).await?;
        let account_count = dto
            .account_count
            .or_else(|| package.as_ref().and_then(|p| p.default_account_count))
            .unwrap_or(0)
            .max(0);
        let package_whitelist = package.as_ref().and_then(|p| parse_menu_ids(&p.menu_ids));
        // 有效能力集（平台天花板 ∩ 套餐请求）：决定平台专属 perms 是否可随复制进入
        // 租户角色菜单（关闭态 = 现状 = 一律剔除，杜绝"菜单可见但请求 403"的假入口）。
        let tenant_features = effective_features_from_package(package.as_ref());

        // 管理员用户名全局唯一（决策 4：user_name 保持全局唯一）
        let admin_user_name = format!("{tenant_code}_admin");
        let dup_user = SysUser::find()
            .filter(UserColumn::UserName.eq(admin_user_name.as_str()))
            .one(self.db())
            .await?;
        if dup_user.is_some() {
            return Err(ServiceError::bad_request(&crate::tr!(
                "error.tenant.admin_user_conflict",
                user_name = admin_user_name
            )));
        }

        let status = dto.status.clone().unwrap_or_else(|| "0".to_string());
        if status != "0" && status != "1" {
            return Err(ServiceError::bad_request(&crate::tr!(
                "error.tenant.status_invalid",
                value = status
            )));
        }
        let init_password = generate_init_password();
        let password_hash =
            crate::utils::password::encrypt_password(&init_password).map_err(|e| {
                tracing::error!(error = %e, "租户管理员初始密码哈希失败");
                ServiceError::internal(&crate::tr!("error.tenant.admin_init_failed"))
            })?;

        let status_for_txn = status.clone();
        let now = now_naive();
        let tenant_repo = self.tenant_repo.clone();
        let dept_repo = self.dept_repo.clone();
        let role_menu_repo = self.role_menu_repo.clone();
        let user_role_repo = self.user_role_repo.clone();
        let role_repo = self.role_repo.clone();
        let user_repo = self.user_repo.clone();
        let db = self.db.clone();
        let name_owned = name.to_string();
        let code_owned = tenant_code.clone();
        let admin_name_owned = admin_user_name.clone();
        let operator_owned = operator.to_string();
        let dto_leader = dto.leader.clone();
        let dto_phone = dto.phone.clone();
        let dto_email = dto.email.clone();
        let dto_order = dto.order_num;
        let dto_remark = dto.remark.clone();
        let dto_contact_name = dto.contact_name.clone();
        let dto_contact_phone = dto.contact_phone.clone();
        let dto_contact_email = dto.contact_email.clone();
        let dto_expire = dto.expire_time;

        let outcome = db
            .transaction::<_, TenantInitOutcome, sea_orm::DbErr>(move |txn| {
                async move {
                    // 1. 租户行（dept_id 待回填）
                    let tenant_am = TenantActiveModel {
                        tenant_id: sea_orm::NotSet,
                        tenant_code: Set(code_owned.clone()),
                        tenant_name: Set(name_owned.clone()),
                        dept_id: Set(None),
                        package_id: Set(package.as_ref().map(|p| p.package_id)),
                        contact_name: Set(dto_contact_name.clone()),
                        contact_phone: Set(dto_contact_phone.clone()),
                        contact_email: Set(dto_contact_email.clone()),
                        domain: Set(None),
                        expire_time: Set(dto_expire),
                        account_count: Set(Some(account_count)),
                        status: Set(Some(status_for_txn.clone())),
                        del_flag: Set(Some("0".to_string())),
                        create_by: Set(Some(operator_owned.clone())),
                        create_time: Set(Some(now)),
                        update_by: Set(Some(operator_owned.clone())),
                        update_time: Set(Some(now)),
                        remark: Set(dto_remark.clone()),
                    };
                    let tenant = tenant_repo.base().insert_conn(txn, tenant_am).await?;

                    // 2. 根部门（租户组织树挂载根；tenant_id = 新租户 id）
                    let dept_am = sys_dept::ActiveModel {
                        dept_id: sea_orm::NotSet,
                        parent_id: Set(Some(0)),
                        ancestors: Set(Some("0".to_string())),
                        dept_name: Set(name_owned.clone()),
                        order_num: Set(dto_order.or(Some(0))),
                        leader: Set(dto_leader.clone()),
                        phone: Set(dto_phone.clone()),
                        email: Set(dto_email.clone()),
                        status: Set(Some("0".to_string())),
                        del_flag: Set(Some("0".to_string())),
                        create_by: Set(Some(operator_owned.clone())),
                        create_time: Set(Some(now)),
                        update_by: Set(Some(operator_owned.clone())),
                        update_time: Set(Some(now)),
                        tenant_id: Set(tenant.tenant_id),
                        leader_user_id: Set(None),
                    };
                    let dept = dept_repo.base().insert_conn(txn, dept_am).await?;

                    // 3. 回填租户行 dept_id
                    let mut tenant_am: TenantActiveModel = tenant.clone().into();
                    tenant_am.dept_id = Set(Some(dept.dept_id));
                    tenant_repo.base().update_conn(txn, tenant_am).await?;
                    // 审计合规域：INSERT 变更留痕（同事务提交/回滚；after 取回填 dept_id 后的终态行）
                    let mut tenant_final: SysTenantModel = tenant.clone();
                    tenant_final.dept_id = Some(dept.dept_id);
                    crate::service::sys_audit_change_service::audit_insert(
                        txn,
                        "sys_tenant",
                        &tenant_final.tenant_id.to_string(),
                        &tenant_final,
                        None, // add 签名仅携带操作人用户名，ID 由回查补齐
                        Some(operator_owned.as_str()),
                    )
                    .await?;

                    // 4. 默认角色（菜单 = (平台普通角色菜单 ∪ 租户自助按钮) ∩ 可授予 ∩ 套餐白名单）
                    //    与 OAuth 自动建号的"租户普通角色"共用同一实现
                    //    （`tenant_role_menu_ids`，差异仅在是否含自助按钮）⇒ 口径单点、不漂移。
                    let role_menu_ids = {
                        let whitelist: Option<HashSet<i64>> = package_whitelist
                            .as_ref()
                            .map(|names| names.iter().copied().collect());
                        tenant_role_menu_ids(txn, whitelist.as_ref(), &tenant_features, true).await?
                    };
                    let role_am = SysRoleActiveModel {
                        role_id: sea_orm::NotSet,
                        tenant_id: Set(tenant.tenant_id),
                        role_name: Set(format!("{name_owned}-管理员")),
                        role_key: Set(format!("{code_owned}_admin")),
                        role_sort: Set(1),
                        data_scope: Set(Some("1".to_string())),
                        custom_sql: Set(None),
                        menu_check_strictly: Set(Some(true)),
                        dept_check_strictly: Set(Some(true)),
                        status: Set("0".to_string()),
                        // 台账 P0-2：租户默认管理员角色非系统角色（不享超管短路）
                        is_system: Set(false),
                        del_flag: Set(Some("0".to_string())),
                        create_by: Set(Some(operator_owned.clone())),
                        create_time: Set(Some(now)),
                        update_by: Set(Some(operator_owned.clone())),
                        update_time: Set(Some(now)),
                        remark: Set(Some(
                            "租户初始化自动创建（菜单 = 套餐白名单 ∩ （平台普通角色菜单 ∪ 租户自助按钮））"
                                .to_string(),
                        )),
                    };
                    let role = role_repo.base().insert_conn(txn, role_am).await?;
                    if !role_menu_ids.is_empty() {
                        let rows: Vec<SysRoleMenuActiveModel> = role_menu_ids
                            .into_iter()
                            .map(|menu_id| SysRoleMenuActiveModel {
                                role_id: Set(role.role_id),
                                menu_id: Set(menu_id),
                            })
                            .collect();
                        role_menu_repo.insert_many_conn(txn, rows).await?;
                    }

                    // 5. 管理员用户
                    let user_am = SysUserActiveModel {
                        user_id: sea_orm::NotSet,
                        dept_id: Set(Some(dept.dept_id)),
                        user_name: Set(admin_name_owned.clone()),
                        nick_name: Set(format!("{name_owned}管理员")),
                        user_type: Set(Some("0".to_string())),
                        email: Set(dto_email.clone()),
                        phonenumber: Set(dto_phone.clone()),
                        country_code: Set(Some("86".to_string())),
                        sex: Set(Some("2".to_string())),
                        avatar: Set(None),
                        password: Set(Some(password_hash.clone())),
                        status: Set(Some("0".to_string())),
                        del_flag: Set(Some("0".to_string())),
                        // B4：租户管理员由创建流程分发密码（非系统初始密码），不标待改
                        must_change_pwd: Set(Some("0".to_string())),
                        login_ip: Set(None),
                        login_date: Set(None),
                        create_by: Set(Some(operator_owned.clone())),
                        create_time: Set(Some(now)),
                        update_by: Set(Some(operator_owned.clone())),
                        update_time: Set(Some(now)),
                        remark: Set(Some("租户管理员（租户初始化自动创建）".to_string())),
                        tenant_id: Set(tenant.tenant_id),
                        scim_external_id: Set(None),
                    };
                    let user = user_repo.base().insert_conn(txn, user_am).await?;
                    let ur_am = SysUserRoleActiveModel {
                        user_id: Set(user.user_id),
                        role_id: Set(role.role_id),
                        source: Set("admin".to_owned()),
                    };
                    user_role_repo.insert_many_conn(txn, vec![ur_am]).await?;

                    Ok(TenantInitOutcome {
                        tenant_id: tenant.tenant_id,
                        dept_id: dept.dept_id,
                        admin_user_name: admin_name_owned.clone(),
                    })
                }
                .boxed()
            })
            .await?;

        // 运行时键（新建即写入，登录/鉴权链路逐请求判定）
        self.sync_runtime_keys(outcome.tenant_id, Some(status.as_str()), dto.expire_time)
            .await;

        let tenant = self.load_tenant(outcome.tenant_id).await?;
        let mut vo = self
            .build_vos(vec![tenant])
            .await?
            .pop()
            .ok_or_else(|| ServiceError::not_found(&crate::tr!("error.tenant.not_found")))?;
        vo.admin_user_name = Some(outcome.admin_user_name);
        vo.admin_init_password = Some(init_password);
        tracing::info!(
            tenant_id = outcome.tenant_id,
            dept_id = outcome.dept_id,
            tenant_code = %tenant_code,
            "租户初始化完成（租户行 + 根部门 + 默认角色 + 管理员用户）"
        );
        Ok(vo)
    }

    /// 解析新建租户所用套餐（显式指定须存在且启用；缺省取平台第一个启用套餐）
    async fn resolve_package_for_new(
        &self,
        package_id: Option<i64>,
    ) -> Result<Option<crate::entity::sys_tenant_package::Model>, ServiceError> {
        let pkg = match package_id {
            Some(id) => SysTenantPackage::find()
                .filter(PkgColumn::PackageId.eq(id))
                .filter(PkgColumn::DelFlag.eq("0"))
                .one(self.db())
                .await?
                .filter(|p| p.status.as_deref() != Some("1")),
            None => {
                SysTenantPackage::find()
                    .filter(PkgColumn::DelFlag.eq("0"))
                    .filter(PkgColumn::Status.eq("0"))
                    .order_by_asc(PkgColumn::PackageId)
                    .one(self.db())
                    .await?
            }
        };
        if package_id.is_some() && pkg.is_none() {
            return Err(ServiceError::bad_request(&crate::tr!(
                "error.tenant.package_not_found"
            )));
        }
        Ok(pkg)
    }

    // ---------- 修改 ----------

    /// 修改租户：平台可改全部字段；租户操作者仅可改名称/联系人/备注
    /// （套餐/到期/配额属平台分配项，租户改这些字段直接 403）
    pub async fn edit(
        &self,
        dto: TenantEditDto,
        operator: &str,
        operator_tid: i64,
    ) -> Result<TenantVo, ServiceError> {
        Self::ensure_tenant_access(operator_tid, dto.tenant_id)?;
        // 显式清空声明（批次 4）：白名单校验 + 与提交值冲突检测（400），缺省为空集
        let clears = crate::common::clear_fields::resolve(&dto)?;
        let tenant = self.load_tenant(dto.tenant_id).await?;
        let name = dto.tenant_name.trim();
        if name.is_empty() {
            return Err(ServiceError::bad_request(&crate::tr!(
                "error.tenant.name_required"
            )));
        }
        // 同名查重（排除自身）
        if let Some(dup) = self.tenant_repo.find_active_by_name(name).await?
            && dup.tenant_id != dto.tenant_id
        {
            return Err(ServiceError::bad_request(&crate::tr!(
                "error.tenant.name_duplicate"
            )));
        }

        // 平台分配项三态：None = 不修改；Some(None) = 清空；Some(Some(v)) = 设置
        let next_package: Option<Option<i64>> = dto.package_id;
        let next_expire: Option<Option<NaiveDateTime>> = dto.expire_time;
        let next_account: Option<Option<i32>> = dto.account_count.map(|v| v.map(|x| x.max(0)));

        let tenant_self = operator_tid != 0;
        if tenant_self {
            let package_changed = matches!(next_package, Some(v) if v != tenant.package_id);
            let account_changed =
                matches!(next_account, Some(v) if v != tenant.account_count.map(|x| x.max(0)));
            let expire_changed = matches!(next_expire, Some(v) if v != tenant.expire_time);
            if package_changed || account_changed || expire_changed {
                return Err(ServiceError::forbidden(&crate::tr!(
                    "error.tenant.platform_only"
                )));
            }
        }

        // 平台分配套餐变更：新套餐须存在且启用（显式清空套餐 = 不分配，不触发菜单收敛）
        let changed_package_id = match (next_package, tenant.package_id) {
            (Some(Some(pid)), current) if Some(pid) != current => Some(pid),
            _ => None,
        };
        let new_package = match changed_package_id {
            Some(pid) => self.resolve_package_for_new(Some(pid)).await?,
            None => None,
        };

        let now = now_naive();
        let mut am: TenantActiveModel = tenant.clone().into();
        am.tenant_name = Set(name.to_string());
        if !tenant_self {
            if let Some(pid) = next_package {
                am.package_id = Set(pid);
            }
            if let Some(v) = next_account {
                // 显式 null → 0（配额"不限"）；该列 NOT NULL，绝不写入 NULL
                am.account_count = Set(Some(v.unwrap_or(0)));
            }
            if let Some(v) = next_expire {
                am.expire_time = Set(v);
            }
        }
        // 部分更新语义（2026-09-26 缺陷修复）：联系信息未传时保持现值，而非置 NULL。
        // 批次 4 补"显式清空"：`clearFields` 声明的字段才写 NULL（否则这条路被永久堵死）。
        use crate::common::clear_fields::is_cleared;
        am.contact_name = Set(if is_cleared(&clears, "contactName") {
            None
        } else {
            dto.contact_name
                .clone()
                .or_else(|| tenant.contact_name.clone())
        });
        am.contact_phone = Set(if is_cleared(&clears, "contactPhone") {
            None
        } else {
            dto.contact_phone
                .clone()
                .or_else(|| tenant.contact_phone.clone())
        });
        am.contact_email = Set(if is_cleared(&clears, "contactEmail") {
            None
        } else {
            dto.contact_email
                .clone()
                .or_else(|| tenant.contact_email.clone())
        });
        am.remark = Set(dto.remark.clone());
        am.update_by = Set(Some(operator.to_string()));
        am.update_time = Set(Some(now));
        // 审计合规域：变更前快照（tenant 此前为 clone().into()，本行仍持有完整改前行）
        let before_snapshot = serde_json::to_value(&tenant).unwrap_or(serde_json::Value::Null);
        // 事务：租户行更新 + 审计留痕 + 根部门同步原子化
        // （根部门同步原在事务外独立写，存在"租户行已提交、根部门同步失败"的
        //   不一致窗口——本轮一并修复并接入审计留痕）
        let tenant_repo = self.tenant_repo.clone();
        let dept_repo = self.dept_repo.clone();
        let operator_owned = operator.to_string();
        // 根部门同步预计算（事务外只读：查部门 + before 快照 + ActiveModel 组装；
        // dept 不存在或租户未挂载根部门时为 None，跳过同步）
        let dept_sync: Option<(serde_json::Value, sys_dept::ActiveModel)> = match tenant.dept_id {
            Some(dept_id) => {
                let dept = self.dept_repo.base().find_by_id(dept_id).await?;
                dept.map(|dept| {
                    let before = serde_json::to_value(&dept).unwrap_or(serde_json::Value::Null);
                    let (existing_leader, existing_phone, existing_email) =
                        (dept.leader.clone(), dept.phone.clone(), dept.email.clone());
                    let mut dam: sys_dept::ActiveModel = dept.into();
                    dam.dept_name = Set(name.to_string());
                    // 同口径：未传保持现值；显式 `clearFields: ["leader"/"phone"/"email"]` 才写 NULL
                    dam.leader = Set(if is_cleared(&clears, "leader") {
                        None
                    } else {
                        dto.leader.clone().or(existing_leader)
                    });
                    dam.phone = Set(if is_cleared(&clears, "phone") {
                        None
                    } else {
                        dto.phone.clone().or(existing_phone)
                    });
                    dam.email = Set(if is_cleared(&clears, "email") {
                        None
                    } else {
                        dto.email.clone().or(existing_email)
                    });
                    if let Some(order) = dto.order_num {
                        dam.order_num = Set(Some(order));
                    }
                    dam.update_by = Set(Some(operator.to_string()));
                    dam.update_time = Set(Some(now));
                    (before, dam)
                })
            }
            None => None,
        };

        self.db()
            .transaction::<_, (), sea_orm::DbErr>(|txn| {
                let tenant_repo = tenant_repo.clone();
                let dept_repo = dept_repo.clone();
                let am = am;
                let before_snapshot = before_snapshot.clone();
                let operator = operator_owned.clone();
                let dept_sync = dept_sync;
                Box::pin(async move {
                    let model = tenant_repo.base().update_conn(txn, am).await?;
                    // 审计合规域：UPDATE 变更留痕（同事务提交/回滚）
                    crate::service::sys_audit_change_service::audit_update(
                        txn,
                        "sys_tenant",
                        &model.tenant_id.to_string(),
                        &before_snapshot,
                        &model,
                        None, // edit 签名仅携带操作人用户名，ID 由回查补齐
                        Some(operator.as_str()),
                    )
                    .await?;
                    // 根部门同步（与租户行同提交/回滚）+ sys_dept 审计留痕
                    if let Some((dept_before, dam)) = dept_sync {
                        let updated_dept = dept_repo.base().update_conn(txn, dam).await?;
                        crate::service::sys_audit_change_service::audit_update(
                            txn,
                            "sys_dept",
                            &updated_dept.dept_id.to_string(),
                            &dept_before,
                            &updated_dept,
                            None,
                            Some(operator.as_str()),
                        )
                        .await?;
                    }
                    Ok(())
                })
            })
            .await?;

        // 套餐收敛：改小套餐后必须收敛该租户角色授权，否则残留越权菜单（§27.6 生效点③）
        // （审计口径：converge 为套餐变更从属动作，sys_tenant UPDATE 留痕已含
        //   packageId 变更，授权明细不再重复留痕）
        if let Some(pkg) = new_package {
            self.converge_tenant_role_menus(dto.tenant_id, &pkg).await?;
        }

        // 运行时键：到期时间变化立即影响已登录会话（宽限/超期判定）
        // 三态语义：未提交 → 保持现值；提交（含显式清空）→ 用提交后的生效值
        // （租户自助路径不可能提交到期时间，其 403 防护见上）
        let effective_expire = next_expire.unwrap_or(tenant.expire_time);
        self.sync_runtime_keys(dto.tenant_id, tenant.status.as_deref(), effective_expire)
            .await;

        let tenant = self.load_tenant(dto.tenant_id).await?;
        self.build_vos(vec![tenant])
            .await?
            .pop()
            .ok_or_else(|| ServiceError::not_found(&crate::tr!("error.tenant.not_found")))
    }

    /// 套餐变更收敛：删除该租户所有角色中「不在套餐白名单内」或「已不可授予」的菜单授权。
    ///
    /// 两个触发面：
    /// - **白名单改小**（`menu_ids`）：裁剪超出套餐的菜单（`menu_ids` 为空 = 不限制，不裁剪）；
    /// - **能力位关闭**（`features`，如关掉 `tenant.domain_self_service`）：回收原先随能力位
    ///   下放的平台专属菜单。**此面与 `menu_ids` 无关**——即使套餐不限制菜单也必须收敛，
    ///   否则残留授权形成"菜单可见但请求 403"的假入口。
    ///
    /// `pub(crate)`：集成测试直接驱动本收敛面（`capability_features` 模块）。
    /// 收敛核心见 [`converge_tenant_role_menus_conn`]（单一事实源，启动期兜底共用）；
    /// 本方法在其上追加**权限缓存失效**（授权行被删 ⇒ `perm:user:*` 缓存必须在
    /// TTL 之前失效，否则最多 5 分钟窗口内用户仍持旧 perms）。
    pub(crate) async fn converge_tenant_role_menus(
        &self,
        tenant_id: i64,
        package: &crate::entity::sys_tenant_package::Model,
    ) -> Result<(), ServiceError> {
        let removed = converge_tenant_role_menus_conn(self.db(), tenant_id, package)
            .await
            .map_err(ServiceError::from)?;
        if removed > 0 {
            self.invalidate_all_perm_cache().await;
        }
        Ok(())
    }

    /// 失效所有用户权限缓存（best-effort，对齐 `sys_menu_service` 同名语义：
    /// SCAN 遍历 `perm:user:*` 批量删除，避免 KEYS 阻塞；失败仅记日志）。
    ///
    /// 触发面：本服务收敛删除了 `sys_role_menu` 行（角色授权集合变化 ⇒ perms 下发变化）。
    async fn invalidate_all_perm_cache(&self) {
        let pattern = format!("{}*", crate::common::constants::PERM_CACHE_PREFIX);
        let Ok(keys) = self.store.scan(&pattern, None).await else {
            tracing::warn!("权限缓存失效：SCAN {} 失败（best-effort 忽略）", pattern);
            return;
        };
        if keys.is_empty() {
            return;
        }
        let _ = self.store.del(&keys).await;
    }

    // ---------- 启停 / 删除 / 恢复 ----------

    /// 启停租户（仅平台管理员）。停用副作用（真实生效，非仅改状态）：
    /// ① 运行时键置停用 → 存量 JWT 下次请求即被鉴权中间件拒绝；
    /// ② 定向踢线该租户全部在线会话（黑名单 + 清 online/sso 绑定）。
    pub async fn change_status(
        &self,
        dto: TenantStatusDto,
        operator: &str,
        operator_tid: i64,
    ) -> Result<(), ServiceError> {
        Self::ensure_platform_operator(operator_tid)?;
        if dto.status != "0" && dto.status != "1" {
            return Err(ServiceError::bad_request(&crate::tr!(
                "error.tenant.status_invalid",
                value = dto.status
            )));
        }
        let tenant = self.load_tenant(dto.tenant_id).await?;
        let now = now_naive();
        let mut am: TenantActiveModel = tenant.clone().into();
        am.status = Set(Some(dto.status.clone()));
        am.update_by = Set(Some(operator.to_string()));
        am.update_time = Set(Some(now));
        self.tenant_repo.base().update(am).await?;

        self.sync_runtime_keys(dto.tenant_id, Some(dto.status.as_str()), tenant.expire_time)
            .await;
        if dto.status == "1" {
            let kicked = self.revoke_tenant_sessions(dto.tenant_id).await;
            tracing::warn!(
                tenant_id = dto.tenant_id,
                kicked,
                "租户已停用：运行时键置停用并吊销该租户全部在线会话"
            );
        }
        Ok(())
    }

    /// 删除租户（软删，回收站语义；仅平台管理员）：
    /// ① 租户内仍有未删除用户 → 拒绝；
    /// ② 租户行 del_flag='2' 且 `tenant_code` 追加 `_del_{id}` 让位（唯一键不占坑）；
    /// ③ 该租户全部部门软删（避免组织树残留孤立树）；
    /// ④ 该租户全部角色软删（避免角色残留被平台误分配，`restore` 对称恢复）；
    /// ⑤ 会话吊销（同停用）。
    pub async fn remove(
        &self,
        tenant_id: i64,
        operator: &str,
        operator_tid: i64,
    ) -> Result<(), ServiceError> {
        Self::ensure_platform_operator(operator_tid)?;
        let tenant = self.load_tenant(tenant_id).await?;
        let user_count = self.count_users_for_tenant(tenant_id).await?;
        if user_count > 0 {
            return Err(ServiceError::bad_request(&crate::tr!(
                "error.tenant.has_users",
                count = user_count
            )));
        }
        if tenant.dept_id == Some(PLATFORM_ROOT_DEPT_ID) {
            // 平台组织种子不得作为租户被删除（dept 100 降级后仍有此保护，防误操作）
            return Err(ServiceError::bad_request(&crate::tr!(
                "error.tenant.platform_protected"
            )));
        }
        let now = now_naive();
        let mut am: TenantActiveModel = tenant.clone().into();
        am.del_flag = Set(Some("2".to_string()));
        am.tenant_code = Set(truncate_code_with_suffix(
            &tenant.tenant_code,
            "_del_",
            tenant.tenant_id,
        ));
        am.status = Set(Some("1".to_string()));
        am.update_by = Set(Some(operator.to_string()));
        am.update_time = Set(Some(now));

        // 单事务包络（与 delete_user 原子事务模式一致）：租户行 + 部门树 + 角色 +
        // 域名 + 租户自建菜单，任一失败整体回滚，避免部分级联的部分成功状态。
        // 返回角色软删行数仅用于日志。
        // 审计合规域：变更前快照（tenant 此后仍被引用，快照独立持有改前行状态）
        let before_snapshot = serde_json::to_value(&tenant).unwrap_or(serde_json::Value::Null);
        let tenant_repo = self.tenant_repo.clone();
        let tid = tenant_id;
        let operator_name = operator.to_string();
        let roles = self
            .db()
            .transaction::<_, sea_orm::UpdateResult, sea_orm::DbErr>(|txn| {
                async move {
                    // ① 租户行软删（回收站语义）
                    tenant_repo.base().update_conn(txn, am).await?;
                    // 审计合规域：DELETE 变更留痕（同事务提交/回滚）
                    crate::service::sys_audit_change_service::audit_delete(
                        txn,
                        "sys_tenant",
                        &tid.to_string(),
                        &before_snapshot,
                        None, // remove 签名仅携带操作人用户名，ID 由回查补齐
                        Some(operator_name.as_str()),
                    )
                    .await?;

                    // ② 组织树软删（按租户维度，不依赖 dept 树结构）
                    let dam: sys_dept::ActiveModel = sys_dept::ActiveModel {
                        del_flag: Set(Some("2".to_string())),
                        update_by: Set(Some(operator_name.clone())),
                        update_time: Set(Some(now)),
                        ..Default::default()
                    };
                    SysDept::update_many()
                        .set(dam)
                        .filter(DeptColumn::TenantId.eq(tid))
                        .exec(txn)
                        .await?;

                    // ③ 角色软删（del_flag='2' 与租户/部门软删语义一致）：
                    //    避免已删租户的角色残留在平台角色列表（可被误分配、破坏数据卫生）
                    let ram: SysRoleActiveModel = SysRoleActiveModel {
                        del_flag: Set(Some("2".to_string())),
                        update_by: Set(Some(operator_name.clone())),
                        update_time: Set(Some(now)),
                        ..Default::default()
                    };
                    let roles = SysRole::update_many()
                        .set(ram)
                        .filter(RoleColumn::TenantId.eq(tid))
                        .filter(RoleColumn::DelFlag.eq("0"))
                        .exec(txn)
                        .await?;

                    // ④ E1-c：域名级联软删。域名解析链路 `find_active_by_domain`
                    //    （repository/sys_tenant_domain.rs）按
                    //    `del_flag='0' AND status='0' AND verify_status='1'` 过滤，
                    //    软删行天然被排除——即使并发窗口内残留也不会被解析命中。
                    let dam2: TenantDomainActiveModel = TenantDomainActiveModel {
                            del_flag: Set(Some("2".to_string())),
                            update_by: Set(Some(operator_name.clone())),
                            update_time: Set(Some(now)),
                            ..Default::default()
                        };
                    SysTenantDomain::update_many()
                        .set(dam2)
                        .filter(TenantDomainColumn::TenantId.eq(tid))
                        .filter(TenantDomainColumn::DelFlag.eq("0"))
                        .exec(txn)
                        .await?;

                    // ⑤ E1-c：租户自建导航菜单级联软删（restore 对称恢复）
                    let mam: TenantMenuActiveModel = TenantMenuActiveModel {
                        del_flag: Set(Some("2".to_string())),
                        update_by: Set(Some(operator_name)),
                        update_time: Set(Some(now)),
                        ..Default::default()
                    };
                    SysTenantMenu::update_many()
                        .set(mam)
                        .filter(TenantMenuColumn::TenantId.eq(tid))
                        .filter(TenantMenuColumn::DelFlag.eq("0"))
                        .exec(txn)
                        .await?;
                    Ok(roles)
                }
                .boxed()
            })
            .await?;

        // 域名链路：旧短码让位（tenant_code 已改），失效 tenant:code 缓存（Redis，事务外）
        self.invalidate_code_cache(&tenant.tenant_code).await;

        self.sync_runtime_keys(tenant_id, Some("1"), tenant.expire_time)
            .await;
        let kicked = self.revoke_tenant_sessions(tenant_id).await;
        tracing::warn!(
            tenant_id,
            kicked,
            roles = roles.rows_affected,
            "租户已删除（回收站）：唯一键让位、组织树/角色/域名/自建菜单软删（单事务）、会话吊销"
        );
        Ok(())
    }

    /// 恢复租户（回收站 → 在册；仅平台管理员）：
    /// ① 唯一键冲突检测与改名（tenant_code 让位后仍可能被新租户占用 → 追加 `_r{id}`）；
    /// ② 恢复为**停用态**（status='1'），由平台显式启用，避免静默恢复访问；
    /// ③ 该租户名下软删部门一并恢复；
    /// ④ 该租户名下软删角色一并恢复（与 `remove` 对称）。
    pub async fn restore(
        &self,
        tenant_id: i64,
        operator: &str,
        operator_tid: i64,
    ) -> Result<TenantVo, ServiceError> {
        Self::ensure_platform_operator(operator_tid)?;
        let tenant = self
            .tenant_repo
            .find_by_id_any(tenant_id)
            .await?
            .ok_or_else(|| ServiceError::not_found(&crate::tr!("error.tenant.not_found")))?;
        if tenant.del_flag.as_deref() != Some("2") {
            return Err(ServiceError::bad_request(&crate::tr!(
                "error.tenant.not_deleted"
            )));
        }
        let restored_code = restore_tenant_code(&tenant.tenant_code, tenant_id);
        let final_code = match self.tenant_repo.find_by_code_any(&restored_code).await? {
            Some(other) if other.tenant_id != tenant_id => {
                truncate_code_with_suffix(&restored_code, "_r_", tenant_id)
            }
            _ => restored_code.clone(),
        };
        let now = now_naive();
        let mut am: TenantActiveModel = tenant.clone().into();
        am.tenant_code = Set(final_code.clone());
        am.del_flag = Set(Some("0".to_string()));
        am.status = Set(Some("1".to_string()));
        am.update_by = Set(Some(operator.to_string()));
        am.update_time = Set(Some(now));
        // §5.35（S-A-1）：五步恢复操作（租户行/组织树/角色/域名/自建菜单）包进
        // 同一事务——此前非事务，部分失败会留"租户已恢复但其余仍软删"的半恢复态
        // 且无整体回滚。缓存失效与运行时键同步在事务提交后执行（失败回滚不污染缓存）。
        let operator_name = operator.to_string();
        let tenant_repo = self.tenant_repo.clone();
        let tenant_row = self
            .db()
            .transaction::<_, u64, sea_orm::DbErr>(|txn| {
                Box::pin(async move {
                    tenant_repo.base().update_conn(txn, am).await?;

                    let dam: sys_dept::ActiveModel = sys_dept::ActiveModel {
                        del_flag: Set(Some("0".to_string())),
                        update_by: Set(Some(operator_name.clone())),
                        update_time: Set(Some(now)),
                        ..Default::default()
                    };
                    SysDept::update_many()
                        .set(dam)
                        .filter(DeptColumn::TenantId.eq(tenant_id))
                        .filter(sys_dept::Column::DelFlag.eq("2"))
                        .exec(txn)
                        .await?;

                    // 角色恢复（与 remove 的软删对称；仅恢复 del_flag='2' 的行，避免影响租户内其他状态）
                    let ram: SysRoleActiveModel = SysRoleActiveModel {
                        del_flag: Set(Some("0".to_string())),
                        update_by: Set(Some(operator_name.clone())),
                        update_time: Set(Some(now)),
                        ..Default::default()
                    };
                    let roles = SysRole::update_many()
                        .set(ram)
                        .filter(RoleColumn::TenantId.eq(tenant_id))
                        .filter(RoleColumn::DelFlag.eq("2"))
                        .exec(txn)
                        .await?;

                    // E1-c 对称恢复：域名与租户自建菜单随租户恢复（仅恢复 remove 级联软删的行，
                    // del_flag='2' → '0'；手工删除的域名/菜单已被让位/清理，不受影响）
                    let dam2: TenantDomainActiveModel = TenantDomainActiveModel {
                        del_flag: Set(Some("0".to_string())),
                        update_by: Set(Some(operator_name.clone())),
                        update_time: Set(Some(now)),
                        ..Default::default()
                    };
                    SysTenantDomain::update_many()
                        .set(dam2)
                        .filter(TenantDomainColumn::TenantId.eq(tenant_id))
                        .filter(TenantDomainColumn::DelFlag.eq("2"))
                        .exec(txn)
                        .await?;
                    let mam: TenantMenuActiveModel = TenantMenuActiveModel {
                        del_flag: Set(Some("0".to_string())),
                        update_by: Set(Some(operator_name.clone())),
                        update_time: Set(Some(now)),
                        ..Default::default()
                    };
                    SysTenantMenu::update_many()
                        .set(mam)
                        .filter(TenantMenuColumn::TenantId.eq(tenant_id))
                        .filter(TenantMenuColumn::DelFlag.eq("2"))
                        .exec(txn)
                        .await?;

                    Ok(roles.rows_affected)
                })
            })
            .await
            .map_err(|e| ServiceError::internal(&format!("租户恢复事务失败: {e}")))?;

        // 域名链路：短码变化，失效 tenant:code 缓存（旧码 / 恢复码 / 最终码）
        self.invalidate_code_cache(&tenant.tenant_code).await;
        self.invalidate_code_cache(&restored_code).await;
        self.invalidate_code_cache(&final_code).await;

        tracing::info!(
            tenant_id,
            roles = tenant_row,
            "租户已恢复（回收站 → 在册，停用态，单事务）：组织树/角色/域名/自建菜单一并恢复"
        );

        self.sync_runtime_keys(tenant_id, Some("1"), tenant.expire_time)
            .await;
        let tenant = self.load_tenant(tenant_id).await?;
        self.build_vos(vec![tenant])
            .await?
            .pop()
            .ok_or_else(|| ServiceError::not_found(&crate::tr!("error.tenant.not_found")))
    }

    // ---------- 登录/会话链路（供 auth_service 与鉴权中间件复用） ----------

    /// 登录闸门：租户行不存在/已删除/停用 → 403；到期三态 →
    /// 正常 / 宽限期只读（`TenantLoginState::Grace`）/ 超期拒绝。
    /// 同时把运行时键（state/exp）重置为最新，保证已登录会话的中间件判定与登录一致。
    pub async fn resolve_login_state(
        &self,
        tenant_id: i64,
    ) -> Result<TenantLoginState, ServiceError> {
        if tenant_id == 0 {
            return Ok(TenantLoginState::Active);
        }
        let tenant = self
            .tenant_repo
            .find_active_by_id(tenant_id)
            .await?
            .ok_or_else(|| ServiceError::forbidden(&crate::tr!("error.tenant.disabled")))?;
        if tenant.status.as_deref() == Some("1") {
            self.sync_runtime_keys(tenant_id, Some("1"), tenant.expire_time)
                .await;
            return Err(ServiceError::forbidden(&crate::tr!(
                "error.tenant.disabled"
            )));
        }
        let state = match tenant.expire_time {
            None => TenantLoginState::Active,
            Some(exp) => {
                let now = now_naive();
                if now >= exp + chrono::Duration::days(TENANT_EXPIRE_GRACE_DAYS) {
                    self.sync_runtime_keys(tenant_id, Some("0"), tenant.expire_time)
                        .await;
                    return Err(ServiceError::forbidden(&crate::tr!("error.tenant.expired")));
                } else if now >= exp {
                    TenantLoginState::Grace
                } else {
                    TenantLoginState::Active
                }
            }
        };
        self.sync_runtime_keys(tenant_id, Some("0"), tenant.expire_time)
            .await;
        Ok(state)
    }

    /// 写入租户运行时键（鉴权中间件逐请求读取）：
    /// - `tenant:state:{tid}`：'0' 正常 / '1' 宽限只读 / '2' 停用；
    /// - `tenant:exp:{tid}`：到期 UTC 时间戳（0 = 永不过期）。
    async fn sync_runtime_keys(
        &self,
        tenant_id: i64,
        status: Option<&str>,
        expire_time: Option<NaiveDateTime>,
    ) {
        if tenant_id == 0 {
            return;
        }
        let state = if status == Some("1") {
            TENANT_STATE_DISABLED
        } else {
            match expire_time {
                Some(exp) => {
                    let now = now_naive();
                    if now >= exp + chrono::Duration::days(TENANT_EXPIRE_GRACE_DAYS) {
                        TENANT_STATE_DISABLED
                    } else if now >= exp {
                        TENANT_STATE_GRACE
                    } else {
                        TENANT_STATE_ACTIVE
                    }
                }
                None => TENANT_STATE_ACTIVE,
            }
        };
        let expire_epoch = expire_time.map(|dt| dt.and_utc().timestamp()).unwrap_or(0);
        let ttl = TENANT_RUNTIME_KEY_TTL_SECS.max(0) as u64;
        // 原实现为一条 pipe 双 SETEX（tenant:state / tenant:exp）→ 拆为两次 SharedStore 写入，
        // 值与 TTL 逐字节等价：state 取 TENANT_STATE_* 常量（'0' 正常 / '1' 宽限 / '2' 停用）；
        // expire 为 NULL → 写 "0"（永不过期），非 NULL → UTC 秒时间戳
        // 类型注解：async block 内 `?` 产出 StoreError，编译器无法推断 Ok(()) 的整体类型（E0282）
        let result: Result<(), crate::shared_store::StoreError> = async {
            self.store
                .set_ex(&tenant_state_key(tenant_id), state, ttl)
                .await?;
            self.store
                .set_ex(&tenant_expire_key(tenant_id), &expire_epoch.to_string(), ttl)
                .await?;
            Ok(())
        }
        .await;
        if let Err(e) = result {
            // 键写入失败不阻断业务（DB 仍为事实源，登录闸门每次查库；此处仅影响已登录会话的即时性）
            tracing::warn!(tenant_id, error = %e, "租户运行时键写入失败（Redis 异常）");
        }
    }

    /// 启动期**全量重建**租户运行时投影键（R1-redis 档兜底，R8-STARTUP-REBUILD）。
    ///
    /// 背景：redis 档下 `tenant:state:{tid}` / `tenant:exp:{tid}` 投影键的既有语义是
    /// 「键缺失 = Active，事实源 = 库表」（`common/tenant.rs::eval_tenant_runtime_state`），
    /// 但 Redis 清空 / 过期驱逐 / 重启后，**已停用租户的存量令牌会在「键重建前」复活**
    /// （窗口截止于该租户下次登录闸门重写或管理员变更）。本函数在启动时从 `sys_tenant`
    /// 表全量重建投影键，**消除该窗口**（local 档直接查库求值，天然不受影响，无需调用）。
    ///
    /// 逐租户复用 [`Self::sync_runtime_keys`]（状态/宽限/到期映射单点），幂等可重入；
    /// 单键写入失败仅 warn 不中断（与 sync 既有口径一致），返回处理的租户数。
    pub async fn rebuild_all_runtime_keys(&self) -> u64 {
        use sea_orm::{ConnectionTrait, Statement};
        let backend = self.db().get_database_backend();
        let sql = "SELECT tenant_id, status, expire_time FROM sys_tenant WHERE tenant_id != 0";
        let rows = match self
            .db()
            .query_all(Statement::from_string(backend, sql.to_string()))
            .await
        {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!(error = %e, "租户运行时键重建：读取 sys_tenant 失败（下次启动重试）");
                return 0;
            }
        };
        let mut rebuilt = 0u64;
        for row in rows {
            let tid: i64 = match row.try_get::<i64>("", "tenant_id") {
                Ok(v) => v,
                Err(_) => continue,
            };
            let status: Option<String> = row.try_get::<Option<String>>("", "status").ok().flatten();
            let expire_time: Option<chrono::NaiveDateTime> = row
                .try_get::<Option<chrono::NaiveDateTime>>("", "expire_time")
                .ok()
                .flatten();
            // 写入失败在 sync_runtime_keys 内部 warn（键失败不阻断业务，DB 为事实源）
            self.sync_runtime_keys(tid, status.as_deref(), expire_time)
                .await;
            rebuilt += 1;
        }
        if rebuilt > 0 {
            tracing::info!(rebuilt, "租户运行时投影键已全量重建（R1 启动兜底）");
        }
        rebuilt
    }

    /// 吊销某租户全部在线会话（停用/删除/到期链路）：
    /// 扫描 `online:*` → 解析 `OnlineSession.tenant_id`（旧会话无该字段时按 user_id 回查
    /// `sys_user.tenant_id`）→ 原子 Lua「黑名单 + 清 online + 清 SSO AT 绑定」。
    /// 返回被吊销的会话数；Redis 异常返回 0（运行时键仍会拦截后续请求，不静默放行）。
    ///
    /// P0-1-a：同口径追加吊销该租户全部 SSO refresh_token（`sso:rt:*`）——停用后存量 RT
    /// 若不清理，可在 token_refresh 处续期身份（RT 绑定为权威结构 `RefreshBinding`）。
    /// P0-1-b（F-7）：即时吊销该租户全部 PAT（`sys_pat.status` '0'→'1'）。
    /// 以上两步为 best-effort：Redis/DB 异常一律 warn，不 panic、不阻断其它吊销。
    pub async fn revoke_tenant_sessions(&self, tenant_id: i64) -> u64 {
        if tenant_id == 0 {
            return 0;
        }
        // ① 在线会话扫描：失败仅告警（不得阻断后续 PAT=DB 与 RT 吊销；空结果亦不早退）
        // 第九批：改用 **不截断** 扫描 —— 原 `scan_keys(.., 5000)` 会在超限时静默截断，
        // 导致部分在线会话**未被踢线**（安全吊销必须完整）。
        // SharedStore 迁移：`scan(pattern, None)` 即全量版（扫到尾），与原 `scan_keys_all` 等价。
        let keys = match self.store.scan("online:*", None).await {
            Ok(k) => k,
            Err(e) => {
                tracing::warn!(tenant_id, error = %e, "租户踢线：SCAN online:* 失败");
                Vec::new()
            }
        };
        let values: Vec<Option<String>> = if keys.is_empty() {
            Vec::new()
        } else {
            match self.store.get_many(&keys).await {
                Ok(v) => v,
                Err(e) => {
                    tracing::warn!(tenant_id, error = %e, "租户踢线：MGET online 失败");
                    Vec::new()
                }
            }
        };
        // 解析会话；旧会话（无 tenant_id）先收集 user_id 以便批量回查
        let mut sessions = Vec::new();
        let mut legacy_user_ids = Vec::new();
        for (key, value) in keys.iter().zip(values.iter()) {
            let Some(json) = value else { continue };
            let Ok(session) = serde_json::from_str::<crate::utils::crypto::OnlineSession>(json)
            else {
                continue;
            };
            let token_hash = key.strip_prefix("online:").unwrap_or(key).to_string();
            if session.tenant_id == 0 && tenant_id != 0 {
                legacy_user_ids.push(session.user_id);
            }
            sessions.push((token_hash, session));
        }
        // ② SSO 刷新令牌（sso:rt:*）：以权威结构 RefreshBinding 解析
        //   - tid == tenant_id → 直接命中；
        //   - tid == 0（旧绑定）→ 同 online 口径按 user_id 回查归属后判定
        //
        // 第九批：改用 **不截断** 扫描。原 `scan_keys(.., 5000)` 超限即静默截断 ⇒
        // 租户 RT 超过 5000 条时**漏清剩余 RT**，停用后仍可用其续期身份（P0-1 的目标口子）。
        // 关于 D6「索引化」的偏离登记：本处**不引入** `tenant:sso_rt:{tid}` 索引 ——
        // 变更前签发的 RT 不在索引内，吊销仍须保留本扫描兜底（RT TTL 窗口内），
        // 故索引只增"签发/吊销/轮换三处写入点 + TTL 索引键"的一致性负担而无净收益；
        // 正确性由「不截断扫描 + 权威结构按 tid 过滤」保证（详见台账 §5.1-D6 状态行）。
        let rt_keys = match self.store.scan("sso:rt:*", None).await {
            Ok(k) => k,
            Err(e) => {
                tracing::warn!(tenant_id, error = %e, "租户踢线：SCAN sso:rt:* 失败");
                Vec::new()
            }
        };
        let rt_values: Vec<Option<String>> = if rt_keys.is_empty() {
            Vec::new()
        } else {
            match self.store.get_many(&rt_keys).await {
                Ok(v) => v,
                Err(e) => {
                    tracing::warn!(tenant_id, error = %e, "租户踢线：MGET sso:rt 失败");
                    Vec::new()
                }
            }
        };
        let mut rt_entries = Vec::new();
        for (key, value) in rt_keys.iter().zip(rt_values.iter()) {
            let Some(json) = value else { continue };
            let Ok(binding) = serde_json::from_str::<RefreshBinding>(json) else {
                continue;
            };
            let rt_hash = key.strip_prefix("sso:rt:").unwrap_or(key).to_string();
            if binding.tid == 0 {
                legacy_user_ids.push(binding.user_id);
            }
            rt_entries.push((rt_hash, binding));
        }
        // ③ 一次批量回查同时覆盖 online 与 RT 的 legacy user_id 集合
        let mut legacy_tids: HashMap<i64, i64> = HashMap::new();
        if !legacy_user_ids.is_empty() {
            legacy_user_ids.sort_unstable();
            legacy_user_ids.dedup();
            let rows = SysUser::find()
                .filter(UserColumn::UserId.is_in(legacy_user_ids))
                .all(self.db())
                .await
                .unwrap_or_default();
            for u in rows {
                legacy_tids.insert(u.user_id, u.tenant_id);
            }
        }
        let now_secs = chrono::Utc::now().timestamp();
        let mut revoked = 0u64;
        for (token_hash, session) in sessions {
            let session_tid = if session.tenant_id != 0 {
                session.tenant_id
            } else {
                legacy_tids.get(&session.user_id).copied().unwrap_or(0)
            };
            if session_tid != tenant_id {
                continue;
            }
            let ttl = if session.exp > 0 {
                session.exp.saturating_sub(now_secs).max(1)
            } else {
                FALLBACK_BLACKLIST_TTL_SECS
            };
            // SharedStore 迁移：原逐 token 三键 Lua（blacklist SETEX + online DEL + sso:at DEL，
            // 原 REVOKE_SESSION_SCRIPT）→ `revoke_session`，三键同生共死的原子语义封进实现
            match self.store.revoke_session(&token_hash, ttl as u64).await {
                Ok(_) => revoked += 1,
                Err(e) => {
                    tracing::warn!(tenant_id, token_hash = %token_hash, error = %e, "租户踢线：Lua 执行失败")
                }
            }
        }

        // ④（P0-1-a）吊销该租户全部 SSO refresh_token（无需维护索引键，扫描即自愈）
        //   原实现：命中集合按 `DEL_BATCH_SIZE`(500) 分批 DEL（减少不截断扫描后的往返次数）
        //   → SharedStore 迁移后一次传整批即可（`del` 实现内部自行处理分批/单语句批量删除），
        //   外层不再保留 chunks 循环。
        let mut rt_hashes: Vec<String> = Vec::new();
        for (rt_hash, binding) in rt_entries {
            let rt_tid = if binding.tid != 0 {
                binding.tid
            } else {
                legacy_tids.get(&binding.user_id).copied().unwrap_or(0)
            };
            if rt_tid == tenant_id {
                rt_hashes.push(rt_hash);
            }
        }
        let rt_del_keys: Vec<String> = rt_hashes
            .iter()
            .map(|h| format!("sso:rt:{h}"))
            .collect();
        let mut rt_revoked = 0u64;
        if !rt_del_keys.is_empty() {
            match self.store.del(&rt_del_keys).await {
                Ok(n) => rt_revoked = n,
                Err(e) => {
                    tracing::warn!(tenant_id, batch = rt_del_keys.len(), error = %e, "租户踢线：批量 DEL sso:rt 失败")
                }
            }
        }
        if rt_revoked > 0 {
            tracing::info!(tenant_id, rt_revoked, "租户踢线：SSO refresh_token 已吊销");
        }

        // ⑤（P0-1-b / F-7）即时吊销该租户全部 PAT：status '0' → '1'
        match SysPat::update_many()
            .col_expr(PatColumn::Status, Expr::value("1"))
            .filter(PatColumn::TenantId.eq(tenant_id))
            .filter(PatColumn::Status.eq("0"))
            .exec(self.db())
            .await
        {
            Ok(res) => {
                if res.rows_affected > 0 {
                    tracing::info!(
                        tenant_id,
                        pat_revoked = res.rows_affected,
                        "租户踢线：PAT 已吊销"
                    );
                }
            }
            Err(e) => {
                tracing::warn!(tenant_id, error = %e, "租户踢线：PAT 吊销失败（DB 异常）")
            }
        }
        revoked
    }

    /// 账号配额预检（口径：含停用用户、不含软删、含管理员，§27.4）：
    /// `sys_tenant.account_count <= 0` 表示不限；超额返回 400。
    ///
    /// 注意：本方法为**事务外预检**（无锁），仅用于"提前失败"体验；
    /// 真正防并发超额的是事务内的 [`Self::ensure_account_quota_txn`]，
    /// 所有插入 `sys_user` 的写路径必须调用后者。
    pub async fn check_account_quota(&self, tenant_id: i64) -> Result<(), ServiceError> {
        if tenant_id == 0 {
            return Ok(());
        }
        let Some(tenant) = self.tenant_repo.find_active_by_id(tenant_id).await? else {
            return Err(ServiceError::forbidden(&crate::tr!(
                "error.tenant.disabled"
            )));
        };
        let limit = tenant.account_count.unwrap_or(0);
        if limit <= 0 {
            return Ok(());
        }
        let current = self.count_users_for_tenant(tenant_id).await? as i64;
        if current >= limit as i64 {
            return Err(ServiceError::bad_request(&crate::tr!(
                "error.tenant.account_quota_exceeded",
                max = limit
            )));
        }
        Ok(())
    }

    /// 账号配额校验（**事务内权威版本**，§27.1 决策 10 / §27.4）：
    /// 先在写事务内对租户行取 `FOR UPDATE` 行锁（SQLite 不支持行锁，按 sea-query
    /// 语义静默忽略——SQLite 写事务本身串行，效果等价），再统计租户内用户数，
    /// 从而杜绝并发创建用户导致的超额。
    ///
    /// 返回 `DbErr::Custom` 业务标记（调用方用 [`Self::quota_violation_to_service_error`]
    /// 映射为带状态的 ServiceError，避免与真实 DB 错误混淆）：
    /// - `QUOTA_MARKER_DISABLED`：租户不存在/已删除；
    /// - `QUOTA_MARKER_PREFIX + max`：已达 `account_count` 上限。
    pub async fn ensure_account_quota_txn<C: ConnectionTrait>(
        &self,
        txn: &C,
        tenant_id: i64,
    ) -> Result<(), DbErr> {
        Self::ensure_account_quota_conn(txn, tenant_id).await
    }

    /// 账号配额校验的**无状态实现**（不依赖服务实例，供 SCIM 等仅持有连接的调用方复用，
    /// 与实例方法共用同一实现，杜绝两套口径漂移）。语义同 [`Self::ensure_account_quota_txn`]。
    pub async fn ensure_account_quota_conn<C: ConnectionTrait>(
        txn: &C,
        tenant_id: i64,
    ) -> Result<(), DbErr> {
        match Self::lock_and_available_quota_conn(txn, tenant_id).await? {
            TenantQuotaAvailability::Unavailable => {
                Err(DbErr::Custom(QUOTA_MARKER_DISABLED.to_string()))
            }
            TenantQuotaAvailability::Unlimited => Ok(()),
            TenantQuotaAvailability::Limited { remaining, limit } => {
                if remaining == 0 {
                    Err(DbErr::Custom(format!("{}{}", QUOTA_MARKER_PREFIX, limit)))
                } else {
                    Ok(())
                }
            }
        }
    }

    /// 事务内锁定租户行并返回**剩余可新增账号数**（批量导入按行截断的依据）。
    ///
    /// 与 [`Self::ensure_account_quota_txn`] 共用同一把锁与同一计数口径（含停用用户、
    /// 不含软删、含管理员）：批量场景先锁一次，再按 `remaining` 逐行放行，
    /// 避免逐行加锁且保证同事务内新插入行被后续计数可见。
    pub async fn lock_and_available_quota_txn<C: ConnectionTrait>(
        &self,
        txn: &C,
        tenant_id: i64,
    ) -> Result<TenantQuotaAvailability, DbErr> {
        Self::lock_and_available_quota_conn(txn, tenant_id).await
    }

    /// [`Self::lock_and_available_quota_txn`] 的无状态实现（供仅有连接的调用方复用）
    pub async fn lock_and_available_quota_conn<C: ConnectionTrait>(
        txn: &C,
        tenant_id: i64,
    ) -> Result<TenantQuotaAvailability, DbErr> {
        // 平台租户（0）不落 sys_tenant 行，无配额语义
        if tenant_id == 0 {
            return Ok(TenantQuotaAvailability::Unlimited);
        }
        let tenant = SysTenant::find()
            .filter(TenantColumn::TenantId.eq(tenant_id))
            .filter(TenantColumn::DelFlag.eq("0"))
            .lock_exclusive()
            .one(txn)
            .await?;
        let Some(tenant) = tenant else {
            return Ok(TenantQuotaAvailability::Unavailable);
        };
        let limit = tenant.account_count.unwrap_or(0);
        if limit <= 0 {
            return Ok(TenantQuotaAvailability::Unlimited);
        }
        let current = SysUser::find()
            .filter(UserColumn::TenantId.eq(tenant_id))
            .filter(UserColumn::DelFlag.eq("0"))
            .count(txn)
            .await?;
        Ok(TenantQuotaAvailability::Limited {
            limit: limit as u64,
            remaining: (limit as u64).saturating_sub(current),
        })
    }

    /// 把 [`Self::ensure_account_quota_txn`] 抛出的业务标记映射为 ServiceError；
    /// 非业务标记（真实 DB 错误）返回 `None`，由调用方走通用错误转换。
    pub fn quota_violation_to_service_error(err: &DbErr) -> Option<ServiceError> {
        let DbErr::Custom(msg) = err else {
            return None;
        };
        if msg == QUOTA_MARKER_DISABLED {
            return Some(ServiceError::forbidden(&crate::tr!(
                "error.tenant.disabled"
            )));
        }
        if let Some(max) = msg.strip_prefix(QUOTA_MARKER_PREFIX) {
            return Some(ServiceError::bad_request(&crate::tr!(
                "error.tenant.account_quota_exceeded",
                max = max
            )));
        }
        None
    }

    /// 租户套餐白名单（`None` = 不限制）。菜单三层模型的 L2（§27.6），
    /// 供角色授权校验 / 菜单树求交 / L3 引用过滤复用。
    pub async fn package_menu_whitelist(
        &self,
        tenant_id: i64,
    ) -> Result<Option<HashSet<i64>>, ServiceError> {
        Ok(package_menu_whitelist_conn(self.db(), tenant_id).await?)
    }

    /// 校验菜单集合是否 ⊆ 套餐白名单（角色授权前置校验，§27.6 生效点①）
    pub async fn ensure_menus_in_package(
        &self,
        tenant_id: i64,
        menu_ids: &[i64],
    ) -> Result<(), ServiceError> {
        // 原则 B 前置门禁：平台专属能力（域名管理/代码生成/缓存监控）不进租户可授集合。
        // 必须置于套餐白名单早退（None=不限制）之前，避免"无套餐 ⇒ 全放开"绕过。
        if tenant_id != 0 {
            self.ensure_menus_not_platform_only(menu_ids).await?;
        }
        let Some(whitelist) = self.package_menu_whitelist(tenant_id).await? else {
            return Ok(());
        };
        if let Some(outside) = menu_ids.iter().find(|id| !whitelist.contains(id)) {
            return Err(ServiceError::forbidden(&crate::tr!(
                "error.tenant.menu_outside_package",
                menu_id = outside
            )));
        }
        Ok(())
    }

    /// 原则 B 门禁：菜单集合不得包含平台专属能力（域名管理/代码生成/缓存监控）——
    /// 租户角色授权（`add_role`/`edit_role`）的唯一入口校验，防止绕过菜单授予面
    /// 直接构造请求把平台能力授给租户管理员。
    async fn ensure_menus_not_platform_only(&self, menu_ids: &[i64]) -> Result<(), ServiceError> {
        if menu_ids.is_empty() {
            return Ok(());
        }
        let rows = SysMenu::find()
            .select_only()
            .column(MenuColumn::MenuId)
            .column(MenuColumn::Perms)
            .filter(MenuColumn::MenuId.is_in(menu_ids.to_vec()))
            .into_tuple::<(i64, Option<String>)>()
            .all(self.db())
            .await?;
        if let Some((menu_id, _)) = rows.into_iter().find(|(_, perms)| {
            perms
                .as_deref()
                .is_some_and(crate::common::tenant::is_platform_only_perm)
        }) {
            return Err(ServiceError::forbidden(&crate::tr!(
                "error.tenant.menu_platform_only",
                menu_id = menu_id
            )));
        }
        Ok(())
    }

    /// 租户 ID → 租户名（在线用户分层视图 / 审计展示；缺失/已删除 ID 不返回）
    pub async fn tenant_name_map(
        &self,
        tenant_ids: &[i64],
    ) -> Result<HashMap<i64, String>, ServiceError> {
        let rows = self.tenant_repo.find_name_map(tenant_ids).await?;
        Ok(rows.into_iter().collect())
    }

    // ---------- 域名链路：tenant_code → tid 解析（中间件复用） ----------

    /// tenant_code → tid（host 头 `X-Tenant-Code` 解析；cache-aside `tenant:code:{code}` TTL 300s）
    ///
    /// 仅返回**未删除**租户；**不按 status 过滤**——停用租户仍需保留 host 租户上下文，
    /// 由登录闸门（`resolve_login_state`）给出明确停用提示（fail-safe，避免静默降级为平台上下文）。
    /// Redis 异常降级为回源 DB，不阻断请求。
    pub async fn resolve_tenant_id_by_code(
        &self,
        tenant_code: &str,
    ) -> Result<Option<i64>, ServiceError> {
        let code = tenant_code.trim();
        if code.is_empty() {
            return Ok(None);
        }
        let key = code_cache_key(code);
        if let Some(raw) = self.redis_get(&key).await
            && let Ok(tid) = raw.parse::<i64>()
        {
            return Ok(Some(tid));
        }
        match self.tenant_repo.find_active_by_code(code).await? {
            Some(m) => {
                self.redis_setex(&key, CODE_CACHE_TTL_SECS, &m.tenant_id.to_string())
                    .await;
                Ok(Some(m.tenant_id))
            }
            None => Ok(None),
        }
    }

    /// 失效 tenant_code 缓存（remove/restore 改码后调用；旧码/新码均需失效）
    pub async fn invalidate_code_cache(&self, tenant_code: &str) {
        let code = tenant_code.trim();
        if code.is_empty() {
            return;
        }
        self.redis_del(&code_cache_key(code)).await;
    }

    // SharedStore 迁移：以下三个助手保留原函数名与调用点（`redis_get`/`redis_setex`/`redis_del`），
    // 内部由裸 Redis 命令（GET/SETEX/DEL + cmd_timeout 包裹）改为 store 薄封装——
    // 超时保护与异常降级语义由 SharedStore 实现内部承载，调用方口径不变（best-effort）。
    async fn redis_get(&self, key: &str) -> Option<String> {
        match self.store.get(key).await {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(key, error = %e, "租户 code 缓存读取失败（降级回源 DB）");
                None
            }
        }
    }

    async fn redis_setex(&self, key: &str, ttl: i64, value: &str) {
        // 与原实现一致：写失败静默忽略（cache-aside 回填，best-effort）
        let _ = self.store.set_ex(key, value, ttl.max(0) as u64).await;
    }

    async fn redis_del(&self, key: &str) {
        // 与原实现一致：删失败静默忽略（缓存失效，best-effort）
        let _ = self.store.del(&[key.to_string()]).await;
    }

    // ---------- 内部工具 ----------

    fn db(&self) -> &DatabaseConnection {
        &self.db
    }

    /// 载入在册租户（不存在/已删除 → 404）
    async fn load_tenant(&self, tenant_id: i64) -> Result<SysTenantModel, ServiceError> {
        self.tenant_repo
            .find_active_by_id(tenant_id)
            .await?
            .ok_or_else(|| ServiceError::not_found(&crate::tr!("error.tenant.not_found")))
    }

    /// 租户内用户计数（含停用、不含软删）
    async fn count_users_for_tenant(&self, tenant_id: i64) -> Result<u64, ServiceError> {
        let count = SysUser::find()
            .filter(UserColumn::TenantId.eq(tenant_id))
            .filter(UserColumn::DelFlag.eq("0"))
            .count(self.db())
            .await?;
        Ok(count)
    }
}

/// 租户短码格式校验：2-32 位小写字母/数字/下划线/连字符，且以字母或数字开头
fn validate_tenant_code(code: &str) -> Result<(), ServiceError> {
    let ok_len = (2..=32).contains(&code.len());
    let first_ok = code
        .chars()
        .next()
        .map(|c| c.is_ascii_alphanumeric())
        .unwrap_or(false);
    let chars_ok = code
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '-');
    if ok_len && first_ok && chars_ok {
        Ok(())
    } else {
        Err(ServiceError::bad_request(&crate::tr!(
            "error.tenant.code_invalid"
        )))
    }
}

/// 解析套餐菜单白名单（逗号分隔；空 / NULL = 不限制 → None）
///
/// `pub(crate)`：`initialize::ensure_tenant_self_service_perm_backfill` 回填时复用，
/// 保证"套餐白名单语义"单一事实源（避免两处解析口径漂移）。
pub(crate) fn parse_menu_ids(raw: &Option<String>) -> Option<Vec<i64>> {
    let s = raw.as_deref()?.trim();
    if s.is_empty() {
        return None;
    }
    let ids: Vec<i64> = s
        .split(',')
        .filter_map(|t| t.trim().parse::<i64>().ok())
        .collect();
    if ids.is_empty() { None } else { Some(ids) }
}

/// 唯一键让位：`{code}{suffix}{id}`，并截断到列上限 64（保留后缀与 id 的可读性）
fn truncate_code_with_suffix(code: &str, suffix: &str, id: i64) -> String {
    let tail = format!("{suffix}{id}");
    let max_base = 64usize.saturating_sub(tail.len());
    let base: String = code.chars().take(max_base).collect();
    format!("{base}{tail}")
}

/// 恢复 tenant_code：剥掉 `_del_{id}` / `_r_{id}` 让位后缀
fn restore_tenant_code(code: &str, tenant_id: i64) -> String {
    for suffix in ["_del_", "_r_"] {
        let tail = format!("{suffix}{tenant_id}");
        if let Some(stripped) = code.strip_suffix(&tail) {
            return stripped.to_string();
        }
    }
    code.to_string()
}

/// 生成租户管理员初始密码（12 位、四类字符，满足强度要求；仅返回一次明文）
fn generate_init_password() -> String {
    const UPPER: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZ";
    const LOWER: &[u8] = b"abcdefghijkmnopqrstuvwxyz";
    const DIGIT: &[u8] = b"23456789";
    const SYM: &[u8] = b"!@#$%^&*";
    let uuid = uuid::Uuid::new_v4();
    let bytes = uuid.as_bytes();
    let mut out = String::with_capacity(12);
    for i in 0..3 {
        out.push(UPPER[bytes[i] as usize % UPPER.len()] as char);
        out.push(LOWER[bytes[3 + i] as usize % LOWER.len()] as char);
        out.push(DIGIT[bytes[6 + i] as usize % DIGIT.len()] as char);
        out.push(SYM[bytes[9 + i] as usize % SYM.len()] as char);
    }
    out
}

/// **套餐授权收敛核心**（自由函数，单一事实源；方案 §5.17）。
///
/// 删除该租户所有角色中「不在套餐白名单内」或「已不可授予」的菜单授权，
/// 返回删除行数。两个收敛面（白名单改小 / 能力位关闭）语义详见
/// [`SysTenantService::converge_tenant_role_menus`]。
///
/// 两个调用方：
/// - [`SysTenantService::converge_tenant_role_menus`]（套餐变更 / 套餐能力位变更路径，
///   追加 perm cache 失效）；
/// - `initialize::converge_tenant_grants_on_startup`（**启动期兜底**：平台层
///   `[features]` on→off 改配置重启后，存量授权无回收触发点——收敛只在套餐变更时跑，
///   此处补全；幂等：无收敛面时零删除）。
///
/// 返回 `DbErr`（不映射 ServiceError）：启动兜底调用方按 anyhow 处理并 WARN continue。
pub(crate) async fn converge_tenant_role_menus_conn(
    db: &DatabaseConnection,
    tenant_id: i64,
    package: &crate::entity::sys_tenant_package::Model,
) -> Result<u64, DbErr> {
    let whitelist = parse_menu_ids(&package.menu_ids);
    // 不可授予菜单（平台专属前缀 ∪ tier2 未接过滤表，**带能力位判定**）——与角色授权
    // 门禁同源，套餐变更时一并移除，不把"收敛"只做成白名单裁剪。
    let features = effective_features_from_package(Some(package));
    let menu_perms: Vec<(i64, Option<String>)> = SysMenu::find()
        .select_only()
        .column(MenuColumn::MenuId)
        .column(MenuColumn::Perms)
        .filter(MenuColumn::DelFlag.eq("0"))
        .into_tuple::<(i64, Option<String>)>()
        .all(db)
        .await?;
    let ungradable_ids: Vec<i64> = menu_perms
        .into_iter()
        .filter(|(_, perms)| {
            perms.as_deref().is_some_and(|p| {
                !p.is_empty()
                    && !crate::common::features::is_grantable_perm_with_features(p, &features)
            })
        })
        .map(|(id, _)| id)
        .collect();
    // 两个收敛面都为空 ⇒ 无需删任何东西（也避免空 `Condition::any()` 的语义歧义）
    if whitelist.is_none() && ungradable_ids.is_empty() {
        return Ok(0);
    }
    let role_ids: Vec<i64> = SysRole::find()
        .select_only()
        .column(RoleColumn::RoleId)
        .filter(RoleColumn::TenantId.eq(tenant_id))
        .filter(RoleColumn::DelFlag.eq("0"))
        .into_tuple::<i64>()
        .all(db)
        .await?;
    if role_ids.is_empty() {
        return Ok(0);
    }
    let mut predicate =
        sea_orm::Condition::any().add(RoleMenuColumn::MenuId.is_in(ungradable_ids.clone()));
    if let Some(ref wl) = whitelist {
        predicate = predicate.add(RoleMenuColumn::MenuId.is_not_in(wl.clone()));
    }
    let deleted = SysRoleMenu::delete_many()
        .filter(RoleMenuColumn::RoleId.is_in(role_ids.clone()))
        .filter(predicate)
        .exec(db)
        .await?;
    tracing::info!(
        tenant_id,
        roles = role_ids.len(),
        removed = deleted.rows_affected,
        whitelist_trimmed = whitelist.is_some(),
        ungrantable = ungradable_ids.len(),
        "套餐授权收敛：已移除超出套餐白名单 / 已不可授予的角色菜单授权"
    );
    Ok(deleted.rows_affected)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_platform_root_constant() {
        // 平台组织种子固定 100（init 种子）；租户身份已与其解耦
        assert_eq!(PLATFORM_ROOT_DEPT_ID, 100);
    }

    #[test]
    fn test_parse_menu_ids() {
        assert_eq!(parse_menu_ids(&None), None, "NULL = 不限制");
        assert_eq!(
            parse_menu_ids(&Some("   ".to_string())),
            None,
            "空串 = 不限制"
        );
        assert_eq!(
            parse_menu_ids(&Some("1,2, 3".to_string())),
            Some(vec![1, 2, 3])
        );
        assert_eq!(
            parse_menu_ids(&Some("abc".to_string())),
            None,
            "无有效 id = 不限制"
        );
    }

    #[test]
    fn test_validate_tenant_code() {
        assert!(validate_tenant_code("t100").is_ok());
        assert!(validate_tenant_code("acme_01").is_ok());
        assert!(validate_tenant_code("A1").is_err(), "大写非法");
        assert!(validate_tenant_code("x").is_err(), "过短");
        assert!(validate_tenant_code("_abc").is_err(), "首字符须字母数字");
        assert!(validate_tenant_code("中文").is_err());
    }

    #[test]
    fn test_code_suffix_roundtrip() {
        let code = truncate_code_with_suffix("acme", "_del_", 42);
        assert_eq!(code, "acme_del_42");
        assert_eq!(restore_tenant_code(&code, 42), "acme");
        let code2 = truncate_code_with_suffix("acme_del_42", "_r_", 42);
        assert_eq!(restore_tenant_code(&code2, 42), "acme_del_42");
        // 超长短码截断到 64 列上限
        let long = "a".repeat(80);
        let truncated = truncate_code_with_suffix(&long, "_del_", 7);
        assert!(truncated.len() <= 64);
    }

    #[test]
    fn test_generate_init_password_strength() {
        let pwd = generate_init_password();
        assert_eq!(pwd.chars().count(), 12);
        assert!(
            crate::utils::password::password_strength_score(&pwd) >= 3,
            "初始密码须满足强度要求"
        );
    }

    /// 治理一致性防线（2026-09-26）：租户自助能力清单**必须**全部可授予。
    ///
    /// 背景：`initialize::ensure_tenant_role_menu_governance` 的"差集回填"是**第 4 条**写
    /// `sys_role_menu` 的路径，它按本清单直接 INSERT（不调用 `ensure_menu_filter_coverage`）。
    /// 当前清单仅 `system:config|dict:add/edit/remove`（过滤矩阵中均为 `Covered`）⇒ 不可利用；
    /// 但若将来往清单里加平台专属（`PLATFORM_ONLY_PERM_PREFIXES`）或 tier2 的 perms，就会
    /// **无门禁地**把菜单授给租户角色。故用本断言把该风险**前移到测试期**（清单变更即失败），
    /// 比在启动链路做运行时过滤更早暴露、且零运行时开销。
    #[test]
    fn tenant_self_service_perms_all_grantable() {
        for p in TENANT_SELF_SERVICE_PERMS {
            assert!(
                crate::common::tenant::is_grantable_perm(p),
                "租户自助能力清单不得含不可授予的 perms（平台专属前缀 / tier2 表）：`{p}`"
            );
        }
    }
}
