// axum-backend/src/service/sys_tenant_service.rs
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
use redis::aio::ConnectionManager;
use sea_orm::*;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::common::datetime::{self, now_naive};
use crate::common::double_opt;
use crate::common::error::ServiceError;
use crate::common::tenant::{
    TENANT_EXPIRE_GRACE_DAYS, TENANT_STATE_ACTIVE, TENANT_STATE_DISABLED, TENANT_STATE_GRACE,
    tenant_expire_key, tenant_state_key,
};
use crate::entity::sys_dept::{self, Column as DeptColumn, Entity as SysDept};
use crate::entity::sys_menu::{Column as MenuColumn, Entity as SysMenu};
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
use crate::entity::sys_tenant_package::{Column as PkgColumn, Entity as SysTenantPackage};
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

/// 平台组织种子部门 ID（m20250711 init 种子"若依科技"）：
/// 其下用户与部门 `tenant_id = 0`（平台租户），**仅为组织种子、不再承担租户身份**
/// （§27.1 决策 5：`dept_id = 100` 降级，删除 `ensure_not_platform_root` 一类特判）。
pub const PLATFORM_ROOT_DEPT_ID: i64 = 100;

/// 平台"普通角色"角色 ID（RuoYi 系种子）：新建租户默认管理员角色的菜单上限来源
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

/// 不下放给租户管理员角色的**平台专属 perms 前缀**：
/// 域名管理接口组（`system:tenant:domain:*`）整体为平台专属（服务层对租户一律 403，
/// 见 [`crate::service::sys_tenant_domain_service`]），若随平台普通角色继承给租户管理员，
/// 会造成"菜单可见但请求一律 403"的假入口，故在租户角色菜单集合中显式剔除。
///
/// `pub(crate)`：`initialize::ensure_tenant_role_menu_governance` 存量回填复用同一前缀。
pub(crate) const TENANT_ROLE_EXCLUDED_PERM_PREFIX: &str = "system:tenant:domain:";

/// 踢线黑名单兜底 TTL（会话 JSON 无 exp 字段时的保守上界，24h）
const FALLBACK_BLACKLIST_TTL_SECS: i64 = 24 * 3600;

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
    redis: ConnectionManager,
    tenant_repo: SysTenantRepository,
    dept_repo: SysDeptRepository,
    user_repo: SysUserRepository,
    role_repo: SysRoleRepository,
    role_menu_repo: SysRoleMenuRepository,
    user_role_repo: SysUserRoleRepository,
}

impl SysTenantService {
    pub fn new(db: DatabaseConnection, redis: ConnectionManager) -> Self {
        Self {
            tenant_repo: SysTenantRepository::new(db.clone()),
            dept_repo: SysDeptRepository::new(db.clone()),
            user_repo: SysUserRepository::new(db.clone()),
            role_repo: SysRoleRepository::new(db.clone()),
            role_menu_repo: SysRoleMenuRepository::new(db.clone()),
            user_role_repo: SysUserRoleRepository::new(db.clone()),
            db,
            redis,
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
    async fn build_vos(
        &self,
        tenants: Vec<SysTenantModel>,
    ) -> Result<Vec<TenantVo>, ServiceError> {
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
            .column_as(sea_orm::sea_query::Expr::col(UserColumn::UserId).count(), "cnt")
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
                    let c = format!(
                        "t{}",
                        &uuid::Uuid::new_v4().simple().to_string()[..8]
                    );
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
        let package_whitelist = package
            .as_ref()
            .and_then(|p| parse_menu_ids(&p.menu_ids));

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

                    // 4. 默认角色（菜单 = (平台普通角色菜单 ∪ 租户自助按钮 perms) ∩ 套餐白名单）
                    let mut base_menu_ids: Vec<i64> = SysRoleMenu::find()
                        .filter(RoleMenuColumn::RoleId.eq(COMMON_ROLE_ID))
                        .all(txn)
                        .await?
                        .into_iter()
                        .map(|rm| rm.menu_id)
                        .collect();
                    // 自助能力按钮（config/dict 的 add/edit/remove）：按 perms 解析菜单 id 补齐，
                    // 保证"租户自建字典类型 / 租户 config 覆盖与自建键"链路权限完整
                    let self_service_menu_ids: Vec<i64> = SysMenu::find()
                        .select_only()
                        .column(MenuColumn::MenuId)
                        .filter(MenuColumn::Perms.is_in(TENANT_SELF_SERVICE_PERMS.iter().copied()))
                        .filter(MenuColumn::Status.eq("0"))
                        .filter(MenuColumn::DelFlag.eq("0"))
                        .into_tuple::<i64>()
                        .all(txn)
                        .await?;
                    base_menu_ids.extend(self_service_menu_ids);
                    // 剔除平台专属菜单（域名管理：`system:tenant:domain:*`）——租户侧不出现假入口
                    let excluded_menu_ids: Vec<i64> = SysMenu::find()
                        .select_only()
                        .column(MenuColumn::MenuId)
                        .filter(MenuColumn::Perms.like(format!(
                            "{TENANT_ROLE_EXCLUDED_PERM_PREFIX}%"
                        )))
                        .into_tuple::<i64>()
                        .all(txn)
                        .await?;
                    base_menu_ids.retain(|id| !excluded_menu_ids.contains(id));
                    base_menu_ids.sort_unstable();
                    base_menu_ids.dedup();
                    let role_menu_ids: Vec<i64> = match &package_whitelist {
                        Some(white) => base_menu_ids
                            .iter()
                            .copied()
                            .filter(|id| white.contains(id))
                            .collect(),
                        None => base_menu_ids,
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
            None => SysTenantPackage::find()
                .filter(PkgColumn::DelFlag.eq("0"))
                .filter(PkgColumn::Status.eq("0"))
                .order_by_asc(PkgColumn::PackageId)
                .one(self.db())
                .await?,
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
        am.contact_name = Set(dto.contact_name.clone());
        am.contact_phone = Set(dto.contact_phone.clone());
        am.contact_email = Set(dto.contact_email.clone());
        am.remark = Set(dto.remark.clone());
        am.update_by = Set(Some(operator.to_string()));
        am.update_time = Set(Some(now));
        self.tenant_repo.base().update(am).await?;

        // 组织树同步（根部门展示字段与租户行一致）
        if let Some(dept_id) = tenant.dept_id
            && let Some(dept) = self.dept_repo.base().find_by_id(dept_id).await?
        {
            let mut dam: sys_dept::ActiveModel = dept.into();
            dam.dept_name = Set(name.to_string());
            dam.leader = Set(dto.leader.clone());
            dam.phone = Set(dto.phone.clone());
            dam.email = Set(dto.email.clone());
            if let Some(order) = dto.order_num {
                dam.order_num = Set(Some(order));
            }
            dam.update_by = Set(Some(operator.to_string()));
            dam.update_time = Set(Some(now));
            self.dept_repo.base().update(dam).await?;
        }

        // 套餐收敛：改小套餐后必须收敛该租户角色授权，否则残留越权菜单（§27.6 生效点③）
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

    /// 套餐变更收敛：删除该租户所有角色中「不在新套餐白名单内」的菜单授权
    /// （套餐 menu_ids 为空 = 不限制，则无需收敛）
    async fn converge_tenant_role_menus(
        &self,
        tenant_id: i64,
        package: &crate::entity::sys_tenant_package::Model,
    ) -> Result<(), ServiceError> {
        let Some(whitelist) = parse_menu_ids(&package.menu_ids) else {
            return Ok(());
        };
        let role_ids: Vec<i64> = SysRole::find()
            .select_only()
            .column(RoleColumn::RoleId)
            .filter(RoleColumn::TenantId.eq(tenant_id))
            .filter(RoleColumn::DelFlag.eq("0"))
            .into_tuple::<i64>()
            .all(self.db())
            .await?;
        if role_ids.is_empty() {
            return Ok(());
        }
        let deleted = SysRoleMenu::delete_many()
            .filter(RoleMenuColumn::RoleId.is_in(role_ids.clone()))
            .filter(RoleMenuColumn::MenuId.is_not_in(whitelist.to_vec()))
            .exec(self.db())
            .await?;
        tracing::info!(
            tenant_id,
            roles = role_ids.len(),
            removed = deleted.rows_affected,
            "套餐变更收敛：已移除超出套餐白名单的角色菜单授权"
        );
        Ok(())
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

        self.sync_runtime_keys(
            dto.tenant_id,
            Some(dto.status.as_str()),
            tenant.expire_time,
        )
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
        self.tenant_repo.base().update(am).await?;

        // 域名链路：旧短码让位（tenant_code 已改），失效 tenant:code 缓存
        self.invalidate_code_cache(&tenant.tenant_code).await;

        // 组织树软删（按租户维度，不依赖 dept 树结构）
        let dam: sys_dept::ActiveModel = sys_dept::ActiveModel {
            del_flag: Set(Some("2".to_string())),
            update_by: Set(Some(operator.to_string())),
            update_time: Set(Some(now)),
            ..Default::default()
        };
        SysDept::update_many()
            .set(dam)
            .filter(DeptColumn::TenantId.eq(tenant_id))
            .exec(self.db())
            .await?;

        // 角色软删（按租户维度，del_flag='2' 与租户/部门软删语义一致）：
        // 避免已删租户的角色残留在平台角色列表（可被误分配、破坏数据卫生）
        let ram: SysRoleActiveModel = SysRoleActiveModel {
            del_flag: Set(Some("2".to_string())),
            update_by: Set(Some(operator.to_string())),
            update_time: Set(Some(now)),
            ..Default::default()
        };
        let roles = SysRole::update_many()
            .set(ram)
            .filter(RoleColumn::TenantId.eq(tenant_id))
            .filter(RoleColumn::DelFlag.eq("0"))
            .exec(self.db())
            .await?;

        self.sync_runtime_keys(tenant_id, Some("1"), tenant.expire_time)
            .await;
        let kicked = self.revoke_tenant_sessions(tenant_id).await;
        tracing::warn!(
            tenant_id,
            kicked,
            roles = roles.rows_affected,
            "租户已删除（回收站）：唯一键让位、组织树软删、角色软删、会话吊销"
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
        self.tenant_repo.base().update(am).await?;

        // 域名链路：短码变化，失效 tenant:code 缓存（旧码 / 恢复码 / 最终码）
        self.invalidate_code_cache(&tenant.tenant_code).await;
        self.invalidate_code_cache(&restored_code).await;
        self.invalidate_code_cache(&final_code).await;

        let dam: sys_dept::ActiveModel = sys_dept::ActiveModel {
            del_flag: Set(Some("0".to_string())),
            update_by: Set(Some(operator.to_string())),
            update_time: Set(Some(now)),
            ..Default::default()
        };
        SysDept::update_many()
            .set(dam)
            .filter(DeptColumn::TenantId.eq(tenant_id))
            .exec(self.db())
            .await?;

        // 角色恢复（与 remove 的软删对称；仅恢复 del_flag='2' 的行，避免影响租户内其他状态）
        let ram: SysRoleActiveModel = SysRoleActiveModel {
            del_flag: Set(Some("0".to_string())),
            update_by: Set(Some(operator.to_string())),
            update_time: Set(Some(now)),
            ..Default::default()
        };
        let roles = SysRole::update_many()
            .set(ram)
            .filter(RoleColumn::TenantId.eq(tenant_id))
            .filter(RoleColumn::DelFlag.eq("2"))
            .exec(self.db())
            .await?;
        tracing::info!(
            tenant_id,
            roles = roles.rows_affected,
            "租户已恢复（回收站 → 在册，停用态）：组织树与角色一并恢复"
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
    pub async fn resolve_login_state(&self, tenant_id: i64) -> Result<TenantLoginState, ServiceError> {
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
            return Err(ServiceError::forbidden(&crate::tr!("error.tenant.disabled")));
        }
        let state = match tenant.expire_time {
            None => TenantLoginState::Active,
            Some(exp) => {
                let now = now_naive();
                if now >= exp + chrono::Duration::days(TENANT_EXPIRE_GRACE_DAYS) {
                    self.sync_runtime_keys(tenant_id, Some("0"), tenant.expire_time)
                        .await;
                    return Err(ServiceError::forbidden(&crate::tr!(
                        "error.tenant.expired"
                    )));
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
        let expire_epoch = expire_time
            .map(|dt| dt.and_utc().timestamp())
            .unwrap_or(0);
        let mut redis = self.redis.clone();
        let result: Result<(), redis::RedisError> = redis::pipe()
            .cmd("SETEX")
            .arg(tenant_state_key(tenant_id))
            .arg(TENANT_RUNTIME_KEY_TTL_SECS)
            .arg(state)
            .cmd("SETEX")
            .arg(tenant_expire_key(tenant_id))
            .arg(TENANT_RUNTIME_KEY_TTL_SECS)
            .arg(expire_epoch)
            .query_async(&mut redis)
            .await
            .map(|_: Vec<String>| ());
        if let Err(e) = result {
            // 键写入失败不阻断业务（DB 仍为事实源，登录闸门每次查库；此处仅影响已登录会话的即时性）
            tracing::warn!(tenant_id, error = %e, "租户运行时键写入失败（Redis 异常）");
        }
    }

    /// 吊销某租户全部在线会话（停用/删除/到期链路）：
    /// 扫描 `online:*` → 解析 `OnlineSession.tenant_id`（旧会话无该字段时按 user_id 回查
    /// `sys_user.tenant_id`）→ 原子 Lua「黑名单 + 清 online + 清 SSO AT 绑定」。
    /// 返回被吊销的会话数；Redis 异常返回 0（运行时键仍会拦截后续请求，不静默放行）。
    pub async fn revoke_tenant_sessions(&self, tenant_id: i64) -> u64 {
        if tenant_id == 0 {
            return 0;
        }
        let mut redis = self.redis.clone();
        let keys = match crate::utils::redis::scan_keys(&mut redis, "online:*", 5000).await {
            Ok(k) => k,
            Err(e) => {
                tracing::warn!(tenant_id, error = %e, "租户踢线：SCAN online:* 失败");
                return 0;
            }
        };
        if keys.is_empty() {
            return 0;
        }
        let values: Vec<Option<String>> =
            match redis::cmd("MGET").arg(&keys).query_async(&mut redis).await {
                Ok(v) => v,
                Err(e) => {
                    tracing::warn!(tenant_id, error = %e, "租户踢线：MGET online 失败");
                    return 0;
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
        let mut legacy_tids: HashMap<i64, i64> = HashMap::new();
        if !legacy_user_ids.is_empty() {
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
            let r: Result<i64, redis::RedisError> = redis::Script::new(REVOKE_SESSION_SCRIPT)
                .key(format!("blacklist:{token_hash}"))
                .key(format!("online:{token_hash}"))
                .key(format!("sso:at:{token_hash}"))
                .arg(ttl)
                .invoke_async(&mut redis)
                .await;
            match r {
                Ok(_) => revoked += 1,
                Err(e) => {
                    tracing::warn!(tenant_id, token_hash = %token_hash, error = %e, "租户踢线：Lua 执行失败")
                }
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
            return Err(ServiceError::forbidden(&crate::tr!("error.tenant.disabled")));
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
            return Some(ServiceError::forbidden(&crate::tr!("error.tenant.disabled")));
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
        if tenant_id == 0 {
            return Ok(None);
        }
        let Some(tenant) = self.tenant_repo.find_active_by_id(tenant_id).await? else {
            return Ok(None);
        };
        let Some(package_id) = tenant.package_id else {
            return Ok(None);
        };
        let Some(package) = SysTenantPackage::find()
            .filter(PkgColumn::PackageId.eq(package_id))
            .filter(PkgColumn::DelFlag.eq("0"))
            .one(self.db())
            .await?
        else {
            return Ok(None);
        };
        Ok(parse_menu_ids(&package.menu_ids).map(|v| v.into_iter().collect()))
    }

    /// 校验菜单集合是否 ⊆ 套餐白名单（角色授权前置校验，§27.6 生效点①）
    pub async fn ensure_menus_in_package(
        &self,
        tenant_id: i64,
        menu_ids: &[i64],
    ) -> Result<(), ServiceError> {
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

    async fn redis_get(&self, key: &str) -> Option<String> {
        let mut redis = self.redis.clone();
        match tokio::time::timeout(
            std::time::Duration::from_secs(crate::db::redis::REDIS_CMD_TIMEOUT_SECS),
            redis::cmd("GET").arg(key).query_async::<Option<String>>(&mut redis),
        )
        .await
        {
            Ok(Ok(v)) => v,
            Ok(Err(e)) => {
                tracing::warn!(key, error = %e, "租户 code 缓存读取失败（降级回源 DB）");
                None
            }
            Err(_) => {
                tracing::warn!(key, "租户 code 缓存读取超时（降级回源 DB）");
                None
            }
        }
    }

    async fn redis_setex(&self, key: &str, ttl: i64, value: &str) {
        let mut redis = self.redis.clone();
        let _ = tokio::time::timeout(
            std::time::Duration::from_secs(crate::db::redis::REDIS_CMD_TIMEOUT_SECS),
            redis::cmd("SETEX")
                .arg(key)
                .arg(ttl)
                .arg(value)
                .query_async::<()>(&mut redis),
        )
        .await;
    }

    async fn redis_del(&self, key: &str) {
        let mut redis = self.redis.clone();
        let _ = tokio::time::timeout(
            std::time::Duration::from_secs(crate::db::redis::REDIS_CMD_TIMEOUT_SECS),
            redis::cmd("DEL").arg(key).query_async::<()>(&mut redis),
        )
        .await;
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

/// 会话吊销 Lua（与 monitor_online_handler 的强退脚本同型：原子化黑名单 + 清 online + 清 SSO AT）
const REVOKE_SESSION_SCRIPT: &str = r#"
redis.call("SETEX", KEYS[1], ARGV[1], "1")
redis.call("DEL", KEYS[2])
redis.call("DEL", KEYS[3])
return 1
"#;

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_platform_root_constant() {
        // 平台组织种子固定 100（RuoYi init 种子）；租户身份已与其解耦
        assert_eq!(PLATFORM_ROOT_DEPT_ID, 100);
    }

    #[test]
    fn test_parse_menu_ids() {
        assert_eq!(parse_menu_ids(&None), None, "NULL = 不限制");
        assert_eq!(parse_menu_ids(&Some("   ".to_string())), None, "空串 = 不限制");
        assert_eq!(
            parse_menu_ids(&Some("1,2, 3".to_string())),
            Some(vec![1, 2, 3])
        );
        assert_eq!(parse_menu_ids(&Some("abc".to_string())), None, "无有效 id = 不限制");
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
        assert!(crate::utils::password::password_strength_score(&pwd) >= 3, "初始密码须满足强度要求");
    }
}