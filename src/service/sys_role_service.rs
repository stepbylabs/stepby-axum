//! 角色模块 Service 层
//!
//! 职责：
//! - 角色 CRUD、角色菜单绑定、数据权限配置、级联删除校验
//! - 不依赖任何 Web 框架类型（axum / tower / tower-http）
//! - 多表操作使用 SeaORM 事务保证一致性
//! - 参数校验使用 garde crate（经 common::i18n::validate 统一入口）
//! - 数据访问通过 Repository 层委托

use futures::future::FutureExt;
use garde::Validate;
use sea_orm::{DatabaseConnection, Set, TransactionTrait};
use serde::Deserialize;
use std::sync::Arc;
use ts_rs::TS;
use utoipa::{IntoParams, ToSchema};

use crate::common::TreeSelectVo;
use crate::common::constants::{SUPER_ADMIN_ROLE_ID, SUPER_ADMIN_USER_ID};
use crate::common::error::ServiceError;
use crate::common::page::{PageDomain, default_page_num, default_page_size};
use crate::common::sort::{self, SortOrder};
use crate::entity::sys_role::{ActiveModel as SysRoleActiveModel, Column as RoleColumn, Model as SysRoleModel};
use crate::entity::sys_role_dept::ActiveModel as SysRoleDeptActiveModel;
use crate::entity::sys_role_menu::ActiveModel as SysRoleMenuActiveModel;
use crate::entity::sys_user::Column as UserColumn;
use crate::entity::sys_user::Model as SysUserModel;
use crate::entity::sys_user_role::ActiveModel as SysUserRoleActiveModel;
use crate::repository::sys_dept::SysDeptRepository;
use crate::repository::sys_menu::SysMenuRepository;
use crate::repository::sys_role::SysRoleRepository;
use crate::repository::sys_role_dept::SysRoleDeptRepository;
use crate::repository::sys_role_menu::SysRoleMenuRepository;
use crate::repository::sys_user::SysUserRepository;
use crate::repository::sys_user_role::SysUserRoleRepository;
use crate::shared_store::SharedStore;
use crate::utils::parse_id_list;

// 部门树组装函数抽取至 service/mod.rs，避免与 sys_user_service 重复
use super::build_dept_tree_select;

// ==================== DTO 定义 ====================

/// 新增角色 DTO
#[derive(Debug, Deserialize, Validate, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct RoleAddDto {
    #[garde(length(min = 2, max = 30))]
    pub role_name: String,
    #[garde(length(min = 2, max = 100))]
    pub role_key: String,
    #[garde(range(min = 0, max = 999))]
    pub role_sort: i32,
    #[garde(skip)]
    pub data_scope: Option<String>,
    #[garde(skip)]
    pub menu_check_strictly: Option<bool>,
    #[garde(skip)]
    pub dept_check_strictly: Option<bool>,
    #[garde(length(min = 1, max = 1))]
    pub status: String,
    /// 菜单 ID 列表（None 不绑定，Some(vec![]) 清空）
    #[garde(skip)]
    pub menu_ids: Option<Vec<i64>>,
    #[garde(length(max = 500))]
    pub remark: Option<String>,
}

/// 修改角色 DTO
#[derive(Debug, Deserialize, Validate, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct RoleEditDto {
    #[garde(skip)]
    pub role_id: i64,
    #[garde(length(min = 2, max = 30))]
    pub role_name: Option<String>,
    #[garde(length(min = 2, max = 100))]
    pub role_key: Option<String>,
    #[garde(range(min = 0, max = 999))]
    pub role_sort: Option<i32>,
    #[garde(skip)]
    pub data_scope: Option<String>,
    #[garde(skip)]
    pub menu_check_strictly: Option<bool>,
    #[garde(skip)]
    pub dept_check_strictly: Option<bool>,
    #[garde(skip)]
    pub status: Option<String>,
    /// None 不修改菜单绑定，Some(vec![]) 清空
    #[garde(skip)]
    pub menu_ids: Option<Vec<i64>>,
    #[garde(length(max = 500))]
    pub remark: Option<String>,
}

/// 角色分页查询 DTO
#[derive(Debug, Clone, Deserialize, IntoParams, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct RoleQueryDto {
    #[serde(default = "default_page_num")]
    pub page_num: u64,
    #[serde(default = "default_page_size")]
    pub page_size: u64,
    /// 排序字段（前端表头 prop，camelCase/snake_case 均可；经列白名单映射后生效，
    /// 未命中白名单回退默认排序，绝不透传任意列）
    #[serde(default)]
    pub order_by_column: Option<String>,
    /// 排序方向 asc / ascending / desc / descending（缺省 desc）
    #[serde(default)]
    pub is_asc: Option<String>,
    pub role_name: Option<String>,
    pub role_key: Option<String>,
    pub status: Option<String>,
}

impl From<&RoleQueryDto> for PageDomain {
    fn from(dto: &RoleQueryDto) -> Self {
        // 动态排序透传：先 sanitize（格式白名单），列级白名单在 service 查询时解析
        let mut page = PageDomain {
            page_num: dto.page_num,
            page_size: dto.page_size,
            order_by_column: dto.order_by_column.clone(),
            is_asc: dto.is_asc.clone(),
        };
        page.sanitize_order_fields();
        page
    }
}

/// 角色视图对象（含已绑定菜单 ID 列表）
#[derive(Debug, Clone, serde::Serialize, TS, ToSchema)]
#[serde(rename_all = "camelCase")]
#[ts(export, rename_all = "camelCase")]
pub struct RoleVo {
    #[serde(flatten)]
    #[ts(flatten)]
    pub role: SysRoleModel,
    pub menu_ids: Vec<i64>,
}

/// 数据权限修改 DTO
#[derive(Debug, Deserialize, Validate, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct DataScopeDto {
    #[garde(skip)]
    pub role_id: i64,
    /// 数据范围（1全部 2自定义 3本部门 4本部门及以下 5仅本人）
    #[garde(length(min = 1, max = 1))]
    pub data_scope: String,
    /// 自定义数据权限时勾选的部门 ID 列表（data_scope=2 时使用）
    #[serde(default)]
    #[garde(skip)]
    pub dept_ids: Vec<i64>,
    #[garde(skip)]
    pub dept_check_strictly: Option<bool>,
}

/// 角色已授权用户分页查询 DTO
#[derive(Debug, Clone, Deserialize, IntoParams)]
#[serde(rename_all = "camelCase")]
pub struct AuthUserQueryDto {
    #[serde(default = "default_page_num")]
    pub page_num: u64,
    #[serde(default = "default_page_size")]
    pub page_size: u64,
    /// 排序字段（前端表头 prop，camelCase/snake_case 均可；经列白名单映射后生效，
    /// 未命中白名单回退默认排序，绝不透传任意列）
    #[serde(default)]
    pub order_by_column: Option<String>,
    /// 排序方向 asc / ascending / desc / descending（缺省 desc）
    #[serde(default)]
    pub is_asc: Option<String>,
    pub role_id: i64,
    pub user_name: Option<String>,
    pub phonenumber: Option<String>,
}

impl From<&AuthUserQueryDto> for PageDomain {
    fn from(dto: &AuthUserQueryDto) -> Self {
        // 动态排序透传：先 sanitize（格式白名单），列级白名单在 service 查询时解析
        let mut page = PageDomain {
            page_num: dto.page_num,
            page_size: dto.page_size,
            order_by_column: dto.order_by_column.clone(),
            is_asc: dto.is_asc.clone(),
        };
        page.sanitize_order_fields();
        page
    }
}

/// 取消用户授权 DTO（单条）
#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct CancelAuthUserDto {
    pub user_id: i64,
    pub role_id: i64,
}

/// 批量授权用户查询参数（通过 URL query 传递）
#[derive(Debug, Deserialize, IntoParams)]
#[serde(rename_all = "camelCase")]
pub struct AuthUserSelectDto {
    pub role_id: i64,
    /// 逗号分隔的用户 ID 字符串（对齐前端 params: data）
    pub user_ids: String,
}

/// 角色部门树视图对象（对齐前端 RoleDeptTreeResult）
#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RoleDeptTreeVo {
    pub checked_keys: Vec<i64>,
    pub depts: Vec<TreeSelectVo>,
}

// ==================== Service 实现 ====================

/// 角色列表允许排序的列白名单（数据库列名 snake_case；前端 prop 经 camel_to_snake 归一后匹配）。
///
/// 覆盖角色业务展示列；`custom_sql`、`tenant_id`、`del_flag` 等内部列不开放动态排序。
const SORTABLE_COLUMNS: &[(&str, RoleColumn)] = &[
    ("role_id", RoleColumn::RoleId),
    ("role_name", RoleColumn::RoleName),
    ("role_key", RoleColumn::RoleKey),
    ("role_sort", RoleColumn::RoleSort),
    ("status", RoleColumn::Status),
    ("create_time", RoleColumn::CreateTime),
];

/// 角色已授权/未授权用户列表允许排序的列白名单（查询目标为 sys_user 表）。
///
/// `password`（凭据哈希）、`login_ip`（审计）、`tenant_id` 等内部/敏感列不开放动态排序。
const AUTH_USER_SORTABLE_COLUMNS: &[(&str, UserColumn)] = &[
    ("user_id", UserColumn::UserId),
    ("user_name", UserColumn::UserName),
    ("nick_name", UserColumn::NickName),
    ("phonenumber", UserColumn::Phonenumber),
    ("status", UserColumn::Status),
    ("create_time", UserColumn::CreateTime),
];

/// 权限缓存 key 前缀（与 sys_menu_service 保持一致）
const PERM_CACHE_PREFIX: &str = "perm:user:";

/// 角色模块 Service
///
/// 数据访问通过 Repository 层委托：
/// - role_repo: sys_role 表 CRUD
/// - role_menu_repo: sys_role_menu 关联表 CRUD
/// - role_dept_repo: sys_role_dept 关联表 CRUD（数据权限）
/// - user_role_repo: sys_user_role 关联表 CRUD（级联清理 + 授权用户管理）
/// - dept_repo: sys_dept 表查询（部门树）
/// - store: 共享态存储（SharedStore），用于权限缓存失效
/// - 事务通过 role_repo.base().db() 获取连接
#[derive(Clone)]
pub struct SysRoleService {
    role_repo: SysRoleRepository,
    role_menu_repo: SysRoleMenuRepository,
    role_dept_repo: SysRoleDeptRepository,
    user_role_repo: SysUserRoleRepository,
    user_repo: SysUserRepository,
    dept_repo: SysDeptRepository,
    /// 菜单表只读访问（§27.13.4 授予前门禁：按 menu_id 取 perms 做覆盖校验）
    menu_repo: SysMenuRepository,
    /// 租户套餐服务（§27.6 生效点①：角色授权 `menu_ids ⊆ 套餐白名单` 校验）
    tenant_service: crate::service::SysTenantService,
    /// 共享态存储（权限缓存失效）
    store: Arc<dyn SharedStore>,
}

impl SysRoleService {
    pub fn new(db: DatabaseConnection, store: Arc<dyn SharedStore>) -> Self {
        Self {
            role_repo: SysRoleRepository::new(db.clone()),
            role_menu_repo: SysRoleMenuRepository::new(db.clone()),
            role_dept_repo: SysRoleDeptRepository::new(db.clone()),
            user_role_repo: SysUserRoleRepository::new(db.clone()),
            user_repo: SysUserRepository::new(db.clone()),
            dept_repo: SysDeptRepository::new(db.clone()),
            menu_repo: SysMenuRepository::new(db.clone()),
            tenant_service: crate::service::SysTenantService::new(db, store.clone()),
            store,
        }
    }

    /// 获取数据库连接引用（用于事务）
    fn db(&self) -> &DatabaseConnection {
        self.role_repo.base().db()
    }

    /// §27.13.4 授予前门禁：待授予租户角色的菜单 perms 必须"可授予"。
    ///
    /// 不可授予的情况（见 `common::features::is_grantable_perm_with_features`）：
    /// ① 平台专属能力前缀（`is_platform_only_perm`，如 `system:backup:*` / `monitor:log:*`）
    ///    ——**除非**租户有效能力位（平台天花板 ∩ 套餐）已显式解锁该项；
    /// ② 命中 tier2 的 perms（表带 tenant_id 但集合读路径未接过滤）。
    ///
    /// `effective_tid == 0`（平台角色授权）不受限；目录 / 无 perms 的菜单天然通过。
    async fn ensure_menus_filter_coverage(
        &self,
        menu_ids: &[i64],
        effective_tid: i64,
    ) -> Result<(), ServiceError> {
        if effective_tid == 0 || menu_ids.is_empty() {
            return Ok(());
        }
        // 有效能力位：三层开关的中间层（平台 `[features]` 为天花板 ∩ 租户套餐
        // `sys_tenant_package.features`）。全 `off` 时与本门禁原语义逐条等价。
        let features =
            crate::service::sys_tenant_service::tenant_features_conn(self.db(), effective_tid)
                .await?;
        let rows = self.menu_repo.find_perms_by_ids(menu_ids).await?;
        let perms_list: Vec<&str> = rows
            .iter()
            .filter_map(|(_, perms)| perms.as_deref())
            .filter(|p| !p.is_empty())
            .collect();
        if let Err(offender) = crate::common::features::ensure_menu_filter_coverage_with_features(
            perms_list, &features,
        ) {
            tracing::warn!(
                tenant_id = effective_tid,
                perms = %offender,
                "拒绝向租户角色授予不可授予菜单（平台专属未解锁 / tier2 未过滤，§27.13.4）"
            );
            return Err(ServiceError::forbidden(&crate::tr!(
                "error.tenant.menu_filter_uncovered",
                perms = offender
            )));
        }
        Ok(())
    }

    // ==================== 权限缓存失效 ====================

    /// 失效指定用户的权限缓存（best-effort，失败仅记日志不阻断业务）
    pub async fn invalidate_perm_cache(&self, user_id: i64) {
        let key = format!("{}{}", PERM_CACHE_PREFIX, user_id);
        if let Err(e) = self.store.del(std::slice::from_ref(&key)).await {
            tracing::warn!("失效权限缓存 {} 失败: {}", key, e);
        }
    }

    /// 失效所有用户权限缓存（角色变更时，best-effort）
    ///
    /// 使用 SCAN 遍历所有 perm:user:* 键并批量删除，避免 KEYS 命令阻塞 Redis。
    pub async fn invalidate_all_perm_cache(&self) {
        let pattern = format!("{}*", PERM_CACHE_PREFIX);
        // 全量扫描（原 cursor 循环至游标归零的语义）；失败即中止（best-effort，与原 Err(_) => break 一致）
        let Ok(keys) = self.store.scan(&pattern, None).await else {
            return;
        };
        if keys.is_empty() {
            return;
        }
        // 批量删除（原 pipeline 语义——非事务允许部分成功；结果忽略，best-effort）
        let _ = self.store.del(&keys).await;
    }

    /// 分页查询角色（仅未删除）
    ///
    /// 数据权限（P0-R81-004 / REGRESS-004）：当传入 operator_user_id 时，按 operator 角色的 data_scope 过滤：
    /// - data_scope=1（全部）：不过滤
    /// - data_scope=5（仅本人）：仅返回 operator 已绑定的角色（role_id IN operator.role_ids）
    /// - data_scope=2/3/4（自定义/本部门/本部门及以下）：角色无 dept_id 概念，
    ///   安全失败策略：降级为"仅本人"，避免普通管理员看到所有角色
    ///
    /// 取 operator 所有角色中 data_scope 值最小者（最宽松）生效。
    /// 超管（user_id==1）短路：直接返回全部。
    pub async fn get_role_page(
        &self,
        query: RoleQueryDto,
        operator_user_id: Option<i64>,
        tenant_scope: Option<i64>,
    ) -> Result<(Vec<SysRoleModel>, u64), ServiceError> {
        let page = PageDomain::from(&query);
        let offset = page.offset();
        let limit = page.limit();
        // 动态排序：白名单命中才生效，未命中/缺省由 repository 回退默认排序
        let sort = page.order_by_column.as_deref().and_then(|prop| {
            sort::resolve_column::<crate::entity::sys_role::Entity>(prop, SORTABLE_COLUMNS).map(
                |col| SortOrder::new(col, sort::parse_direction(page.is_asc.as_deref())),
            )
        });

        // 数据权限过滤参数（P0-6 统一入口）
        let mut scope_role_ids: Option<Vec<i64>> = None;

        if let Some(op_uid) = operator_user_id {
            scope_role_ids = self.resolve_scope_role_ids(op_uid).await?;
        }

        let scope_ref = scope_role_ids.as_deref();
        // 通过 Repository 多条件分页查询（含 data_scope 过滤）
        let (rows, total) = self
            .role_repo
            .find_page_with_data_scope(
                offset,
                limit,
                query.role_name.as_deref(),
                query.role_key.as_deref(),
                query.status.as_deref(),
                scope_ref,
                None,
                None,
                tenant_scope,
                sort,
            )
            .await?;
        Ok((rows, total))
    }

    /// 导出角色列表（受 EXPORT_MAX_ROWS 限制，避免无上限查询导致 OOM）
    pub async fn export_roles(
        &self,
        query: RoleQueryDto,
        operator_user_id: Option<i64>,
        tenant_scope: Option<i64>,
    ) -> Result<Vec<SysRoleModel>, ServiceError> {
        // P0-2 修复：导出接口需应用与 list 相同的数据权限过滤，防止越权导出（P0-6 统一入口）
        let scope_role_ids: Option<Vec<i64>> = match operator_user_id {
            Some(uid) => self.resolve_scope_role_ids(uid).await?,
            None => None,
        };

        // 导出与页面列表同序：动态排序白名单解析口径一致
        let page = PageDomain::from(&query);
        let sort = page.order_by_column.as_deref().and_then(|prop| {
            sort::resolve_column::<crate::entity::sys_role::Entity>(prop, SORTABLE_COLUMNS).map(
                |col| SortOrder::new(col, sort::parse_direction(page.is_asc.as_deref())),
            )
        });

        // 导出使用大分页，获取全部符合条件的记录（上限 EXPORT_MAX_ROWS + 数据权限过滤）
        let (rows, _) = self
            .role_repo
            .find_page_with_data_scope(
                0,
                crate::common::page::EXPORT_MAX_ROWS,
                query.role_name.as_deref(),
                query.role_key.as_deref(),
                query.status.as_deref(),
                scope_role_ids.as_deref(),
                None,
                None,
                tenant_scope,
                sort,
            )
            .await?;
        Ok(rows)
    }

    /// 计算操作人的数据范围角色 ID 集合（P0-6 统一入口）
    ///
    /// 供 get_role_page / export_roles / get_role_by_id 等所有角色查询端点复用，
    /// 杜绝"list 有过滤、旁路端点裸奔"的 data_scope 不一致越权。
    ///
    /// - 超管（user_id==1）或 data_scope=1（全部）：返回 `None`（不过滤）
    /// - 其他（角色无 dept_id，data_scope 2/3/4/5 降级为"仅本人"）：返回 `Some(ids)`，
    ///   即 operator 已绑定的角色 ID 集合（可能为空）
    async fn resolve_scope_role_ids(
        &self,
        operator_user_id: i64,
    ) -> Result<Option<Vec<i64>>, ServiceError> {
        // 超管短路
        if operator_user_id == SUPER_ADMIN_USER_ID {
            return Ok(None);
        }
        let op_roles = self.role_repo.find_by_user_id(operator_user_id).await?;
        let min_scope = crate::common::data_scope::min_data_scope(&op_roles);
        let ids: Vec<i64> = op_roles.iter().map(|r| r.role_id).collect();
        match min_scope {
            Some(1) => Ok(None), // 全部数据：不追加过滤
            _ => Ok(Some(ids)),  // 2/3/4/5/未知/缺失：安全失败，仅本人角色
        }
    }

    /// 查询角色详情（含 menu_ids）
    ///
    /// P0-6：`operator_user_id` 传入时校验角色在数据范围内（不在则 404，避免暴露存在性）。
    pub async fn get_role_by_id(
        &self,
        role_id: i64,
        operator_user_id: Option<i64>,
    ) -> Result<RoleVo, ServiceError> {
        let role = self
            .role_repo
            .base()
            .find_by_id(role_id)
            .await?
            .ok_or_else(|| ServiceError::not_found(&crate::tr!("error.role.not_found")))?;
        if role.del_flag.as_deref() == Some("2") {
            return Err(ServiceError::not_found(&crate::tr!("error.role.not_found")));
        }

        // P0-6 数据范围校验
        if let Some(uid) = operator_user_id {
            let scope_ids = self.resolve_scope_role_ids(uid).await?;
            if let Some(ref ids) = scope_ids
                && !ids.contains(&role_id)
            {
                return Err(ServiceError::not_found(&crate::tr!("error.role.not_found")));
            }
        }

        let menu_ids = self.get_menu_ids_by_role_id(role_id).await?;
        Ok(RoleVo { role, menu_ids })
    }

    /// 新增角色（事务：插入角色 + 批量插入菜单关联）
    pub async fn add_role(
        &self,
        dto: RoleAddDto,
        operator: &str,
        operator_tid: i64,
    ) -> Result<SysRoleModel, ServiceError> {
        crate::common::i18n::validate(&dto)?;

        // role_key 查重（**租户内唯一**，与唯一索引 uk_sys_role_tenant_key 语义对齐，台账 P0-3）：
        // 查重范围 = 角色归属租户（新角色归属操作者租户，见下方 am.tenant_id），
        // 而非全局——否则不同租户无法使用同名 role_key。
        let exists = self
            .role_repo
            .find_by_role_key_in_tenant(&dto.role_key, operator_tid)
            .await?;
        if exists.is_some() {
            return Err(ServiceError::bad_request(&crate::tr!(
                "error.role.perm_key_exists"
            )));
        }

        // §27.6 生效点①：授权菜单必须 ⊆ 租户套餐白名单（无套餐/平台租户 → 不限制）
        if let Some(ids) = dto.menu_ids.as_deref()
            && !ids.is_empty()
        {
            self.tenant_service
                .ensure_menus_in_package(operator_tid, ids)
                .await?;
            // §27.13.4 授予前门禁：不可授予 perms（平台专属 / tier2 未过滤）不得下放租户角色
            self.ensure_menus_filter_coverage(ids, operator_tid).await?;
        }

        let role_repo = self.role_repo.clone();
        let role_menu_repo = self.role_menu_repo.clone();
        let result = self
            .db()
            .transaction::<_, SysRoleModel, sea_orm::DbErr>(|txn| {
                let now = crate::common::datetime::now_naive();
                let mut am = SysRoleActiveModel {
                    ..Default::default()
                };
                // 多租户 Phase 2：角色归属操作者租户（平台管理员=0）
                am.tenant_id = Set(operator_tid);
                am.role_name = Set(dto.role_name.clone());
                am.role_key = Set(dto.role_key.clone());
                am.role_sort = Set(dto.role_sort);
                // 新增角色 data_scope 默认 "1"（全部数据权限）
                am.data_scope = Set(dto.data_scope.clone().or_else(|| Some("1".to_string())));
                am.menu_check_strictly = Set(dto.menu_check_strictly);
                am.dept_check_strictly = Set(dto.dept_check_strictly);
                am.status = Set(dto.status.clone());
                am.del_flag = Set(Some("0".to_string()));
                am.create_by = Set(Some(operator.to_string()));
                am.create_time = Set(Some(now));
                am.update_by = Set(Some(operator.to_string()));
                am.update_time = Set(Some(now));
                am.remark = Set(dto.remark.clone());

                // 审计留痕块为 boxed()（需 'static），operator 为 &str 引用生命周期不足，
                // 克隆为 owned String 移入 async move 块
                let operator_owned = operator.to_string();
                let menu_ids = dto.menu_ids.clone();
                async move {
                    // 1. 插入 sys_role（通过 Repository）
                    let new_role = role_repo.base().insert_conn(txn, am).await?;

                    // 1.5 审计合规域：INSERT 变更留痕（同事务提交/回滚，失败令业务一并回滚）
                    let after =
                        serde_json::to_value(&new_role).unwrap_or(serde_json::Value::Null);
                    let audit_operator =
                        crate::service::sys_audit_change_service::resolve_operator(
                            txn,
                            None, // add_role 签名仅携带操作人用户名，ID 由回查补齐
                            Some(operator_owned.as_str()),
                        )
                        .await;
                    crate::service::sys_audit_change_service::record_change(
                        txn,
                        "sys_role",
                        &new_role.role_id.to_string(),
                        crate::service::sys_audit_change_service::ACTION_INSERT,
                        None,
                        Some(after),
                        audit_operator,
                    )
                    .await?;

                    // 2. 若 menu_ids 非空，批量插入 sys_role_menu（通过 Repository）
                    if let Some(ids) = menu_ids
                        && !ids.is_empty()
                    {
                        let models: Vec<SysRoleMenuActiveModel> = ids
                            .into_iter()
                            .map(|mid| SysRoleMenuActiveModel {
                                role_id: Set(new_role.role_id),
                                menu_id: Set(mid),
                            })
                            .collect();
                        role_menu_repo.insert_many_conn(txn, models).await?;
                    }
                    Ok(new_role)
                }
                .boxed()
            })
            .await?;

        Ok(result)
    }

    /// 修改角色（事务：更新角色 + 重分配菜单）
    pub async fn edit_role(
        &self,
        dto: RoleEditDto,
        operator: &str,
        operator_tid: i64,
    ) -> Result<SysRoleModel, ServiceError> {
        crate::common::i18n::validate(&dto)?;

        // 查询角色是否存在
        let existing = self
            .role_repo
            .base()
            .find_by_id(dto.role_id)
            .await?
            .ok_or_else(|| ServiceError::not_found(&crate::tr!("error.role.not_found")))?;
        if existing.del_flag.as_deref() == Some("2") {
            return Err(ServiceError::not_found(&crate::tr!("error.role.not_found")));
        }
        // 多租户越权防护：只能修改本租户角色（平台操作者放行）
        if !crate::common::tenant::tenant_allowed(operator_tid, existing.tenant_id) {
            return Err(ServiceError::forbidden(&crate::tr!(
                "error.common.forbidden"
            )));
        }

        // 超管保护：SUPER_ADMIN_ROLE_ID 不允许修改 role_key
        if dto.role_id == SUPER_ADMIN_ROLE_ID
            && let Some(ref new_key) = dto.role_key
            && *new_key != existing.role_key
        {
            return Err(ServiceError::bad_request(&crate::tr!(
                "error.role.admin_perm_key_forbidden"
            )));
        }

        // role_key 查重：若 role_key 变更，校验新 role_key 是否已被**同租户内**其他角色占用
        // （与唯一索引 uk_sys_role_tenant_key 语义对齐，台账 P0-3；平台操作者代管租户角色时
        // 按**角色归属租户**校验）
        if let Some(ref new_key) = dto.role_key
            && *new_key != existing.role_key
        {
            let dup = self
                .role_repo
                .find_by_role_key_in_tenant(new_key, existing.tenant_id)
                .await?;
            if let Some(d) = &dup
                && d.role_id != dto.role_id
            {
                return Err(ServiceError::bad_request(&crate::tr!(
                    "error.role.perm_key_exists"
                )));
            }
        }

        // §27.6 生效点①：授权菜单必须 ⊆ 角色所属租户的套餐白名单。
        // 平台操作者（tid=0）代管租户角色时，按**角色归属租户**校验（受影响的正是它）。
        if let Some(ids) = dto.menu_ids.as_deref()
            && !ids.is_empty()
        {
            let effective_tid = if operator_tid == 0 {
                existing.tenant_id
            } else {
                operator_tid
            };
            self.tenant_service
                .ensure_menus_in_package(effective_tid, ids)
                .await?;
            // §27.13.4 授予前门禁：不可授予 perms（平台专属 / tier2 未过滤）不得下放租户角色
            self.ensure_menus_filter_coverage(ids, effective_tid)
                .await?;
        }

        // 审计合规域：变更前快照（必须在 existing 被 move 进事务闭包之前计算）
        let before_snapshot =
            serde_json::to_value(&existing).unwrap_or(serde_json::Value::Null);
        let role_repo = self.role_repo.clone();
        let role_menu_repo = self.role_menu_repo.clone();
        let result = self
            .db()
            .transaction::<_, SysRoleModel, sea_orm::DbErr>(|txn| {
                let now = crate::common::datetime::now_naive();
                let mut am: SysRoleActiveModel = existing.into();
                if let Some(ref name) = dto.role_name {
                    am.role_name = Set(name.clone());
                }
                if let Some(ref key) = dto.role_key {
                    am.role_key = Set(key.clone());
                }
                if let Some(sort) = dto.role_sort {
                    am.role_sort = Set(sort);
                }
                if let Some(ref scope) = dto.data_scope {
                    am.data_scope = Set(Some(scope.clone()));
                }
                if let Some(strict) = dto.menu_check_strictly {
                    am.menu_check_strictly = Set(Some(strict));
                }
                if let Some(strict) = dto.dept_check_strictly {
                    am.dept_check_strictly = Set(Some(strict));
                }
                if let Some(ref status) = dto.status {
                    am.status = Set(status.clone());
                }
                if let Some(ref remark) = dto.remark {
                    am.remark = Set(Some(remark.clone()));
                }
                am.update_by = Set(Some(operator.to_string()));
                am.update_time = Set(Some(now));

                // 审计留痕块为 boxed()（需 'static），operator 为 &str 引用生命周期不足，
                // 克隆为 owned String 移入 async move 块
                let operator_owned = operator.to_string();
                let menu_ids = dto.menu_ids.clone();
                let role_id = dto.role_id;
                async move {
                    // 1. 更新 sys_role（通过 Repository）
                    let updated = role_repo.base().update_conn(txn, am).await?;

                    // 2. 若 menu_ids 为 Some（非 None），重分配菜单（通过 Repository）
                    if let Some(ids) = menu_ids {
                        // 先删除旧关联
                        role_menu_repo.delete_by_role_id_conn(txn, role_id).await?;
                        // 若非空，再插入新关联
                        if !ids.is_empty() {
                            let models: Vec<SysRoleMenuActiveModel> = ids
                                .into_iter()
                                .map(|mid| SysRoleMenuActiveModel {
                                    role_id: Set(role_id),
                                    menu_id: Set(mid),
                                })
                                .collect();
                            role_menu_repo.insert_many_conn(txn, models).await?;
                        }
                    }

                    // 3. 审计合规域：UPDATE 变更留痕（同事务提交/回滚，失败令业务一并回滚）
                    let after =
                        serde_json::to_value(&updated).unwrap_or(serde_json::Value::Null);
                    let audit_operator =
                        crate::service::sys_audit_change_service::resolve_operator(
                            txn,
                            None, // edit_role 签名仅携带操作人用户名，ID 由回查补齐
                            Some(operator_owned.as_str()),
                        )
                        .await;
                    crate::service::sys_audit_change_service::record_change(
                        txn,
                        "sys_role",
                        &updated.role_id.to_string(),
                        crate::service::sys_audit_change_service::ACTION_UPDATE,
                        Some(before_snapshot),
                        Some(after),
                        audit_operator,
                    )
                    .await?;
                    Ok(updated)
                }
                .boxed()
            })
            .await?;
        // 角色变更影响绑定该角色的用户权限，全量失效权限缓存
        self.invalidate_all_perm_cache().await;

        Ok(result)
    }

    /// 删除角色（事务：级联清理 + 软删除）
    ///
    /// M-1 Major TOCTOU 修复：用户关联检查移入事务内，避免事务外预检查后
    /// 被其他事务插入新关联（TOCTOU）导致数据不一致。
    pub async fn delete_role(&self, role_id: i64, operator_tid: i64) -> Result<(), ServiceError> {
        // 超管保护
        if role_id == SUPER_ADMIN_ROLE_ID {
            return Err(ServiceError::bad_request(&crate::tr!(
                "error.role.admin_delete_forbidden"
            )));
        }

        let existing = self
            .role_repo
            .base()
            .find_by_id(role_id)
            .await?
            .ok_or_else(|| ServiceError::not_found(&crate::tr!("error.role.not_found")))?;
        if existing.del_flag.as_deref() == Some("2") {
            return Err(ServiceError::not_found(&crate::tr!("error.role.not_found")));
        }
        // 多租户越权防护：只能删除本租户角色（平台操作者放行）
        if !crate::common::tenant::tenant_allowed(operator_tid, existing.tenant_id) {
            return Err(ServiceError::forbidden(&crate::tr!(
                "error.common.forbidden"
            )));
        }

        // 释放唯一字段值，避免软删除后唯一索引冲突（uk_sys_role_key）
        // 软删除记录仍占用 role_key 唯一索引，导致无法重新创建同 key 角色
        let deleted_role_key = format!("{}_deleted_{}", existing.role_key, role_id);

        // 审计合规域：变更前快照（必须在 existing 被 move 进事务闭包之前计算）
        let before_snapshot =
            serde_json::to_value(&existing).unwrap_or(serde_json::Value::Null);
        let role_repo = self.role_repo.clone();
        let role_menu_repo = self.role_menu_repo.clone();
        let user_role_repo = self.user_role_repo.clone();
        // M-1 Major TOCTOU 修复：将 count_by_role_id 检查移入事务内，
        // 使用 _conn 变体在事务上下文中重新检查，确保检查与删除原子执行。
        // 使用 DbErr::Custom 携带业务消息，事务返回后映射回 ServiceError::bad_request。
        let txn_result = self
            .db()
            .transaction::<_, (), sea_orm::DbErr>(|txn| {
                async move {
                    // 0. TOCTOU 防护：事务内重新检查用户关联（原检查在事务外，存在竞态）
                    let user_count = user_role_repo.count_by_role_id_conn(txn, role_id).await?;
                    if user_count > 0 {
                        return Err(sea_orm::DbErr::Custom(crate::tr!(
                            "error.role.assigned_to_user",
                            id = role_id
                        )));
                    }

                    // 1. 软删除 sys_role（通过 Repository）
                    let mut am: SysRoleActiveModel = existing.into();
                    am.del_flag = Set(Some("2".to_string()));
                    am.role_key = Set(deleted_role_key);
                    role_repo.base().update_conn(txn, am).await?;

                    // 1.5 审计合规域：DELETE 变更留痕（同事务提交/回滚，失败令业务一并回滚；
                    //     delete_role 签名无操作人信息，操作人两列留空（列可空））
                    let audit_operator =
                        crate::service::sys_audit_change_service::resolve_operator(txn, None, None)
                            .await;
                    crate::service::sys_audit_change_service::record_change(
                        txn,
                        "sys_role",
                        &role_id.to_string(),
                        crate::service::sys_audit_change_service::ACTION_DELETE,
                        Some(before_snapshot),
                        None,
                        audit_operator,
                    )
                    .await?;

                    // 2. 物理删除 sys_role_menu 关联（通过 Repository）
                    role_menu_repo.delete_by_role_id_conn(txn, role_id).await?;

                    // 3. 物理删除 sys_user_role 关联（冗余保护，正常应已被上面校验拦截）
                    user_role_repo.delete_by_role_id_conn(txn, role_id).await?;
                    Ok(())
                }
                .boxed()
            })
            .await;

        match txn_result {
            Ok(()) => {
                // 角色删除影响绑定该角色的用户权限，全量失效权限缓存
                self.invalidate_all_perm_cache().await;
                Ok(())
            }
            // TOCTOU 检查的业务错误：映射为 400 bad_request
            Err(sea_orm::TransactionError::Transaction(sea_orm::DbErr::Custom(msg))) => {
                Err(ServiceError::bad_request(&msg))
            }
            // 其他数据库/事务错误：走通用转换
            Err(e) => Err(ServiceError::from(e)),
        }
    }

    /// 批量删除角色（原子事务，R8-API-008）
    ///
    /// 所有角色删除操作包装在单个事务中，保证原子性：
    /// - 任一角色校验失败（超管保护/已分配用户/不存在）→ 整个事务回滚
    /// - 任一 DB 操作失败 → 整个事务回滚
    ///
    /// 对比 handler 层 for 循环调用 delete_role：
    /// - 旧方案：第 2 个角色删除失败时第 1 个已删，第 3 个未删，数据状态不一致
    /// - 新方案：全部成功才提交，部分失败回滚到操作前状态
    pub async fn delete_roles(
        &self,
        role_ids: Vec<i64>,
        operator_tid: i64,
    ) -> Result<(), ServiceError> {
        // 预校验：超管保护（事务外快速失败）
        if role_ids.contains(&SUPER_ADMIN_ROLE_ID) {
            return Err(ServiceError::bad_request(&crate::tr!(
                "error.role.admin_delete_forbidden"
            )));
        }

        // 单个 ID 直接走 delete_role（保持原有事务行为）
        if role_ids.len() == 1 {
            return self.delete_role(role_ids[0], operator_tid).await;
        }

        // 多租户越权防护（批量）：任一所选角色跨越操作者租户即整体拒绝（平台操作者放行）
        let targets = self.role_repo.find_by_ids(&role_ids).await?;
        if targets
            .iter()
            .any(|r| !crate::common::tenant::tenant_allowed(operator_tid, r.tenant_id))
        {
            return Err(ServiceError::forbidden(&crate::tr!(
                "error.common.forbidden"
            )));
        }

        // 批量删除：单个事务包装所有操作
        let role_repo = self.role_repo.clone();
        let role_menu_repo = self.role_menu_repo.clone();
        let user_role_repo = self.user_role_repo.clone();
        let db = self.db().clone();

        let txn_result = db
            .transaction::<_, (), sea_orm::DbErr>(|txn| {
                async move {
                    for role_id in role_ids {
                        // 1. 查询角色存在性（事务内，防止 TOCTOU）
                        let existing = role_repo
                            .base()
                            .find_by_id_conn(txn, role_id)
                            .await?
                            .ok_or_else(|| {
                                sea_orm::DbErr::Custom(crate::tr!(
                                    "error.role.not_found_by_id",
                                    id = role_id
                                ))
                            })?;
                        if existing.del_flag.as_deref() == Some("2") {
                            return Err(sea_orm::DbErr::Custom(crate::tr!(
                                "error.role.not_found_by_id",
                                id = role_id
                            )));
                        }

                        // 2. TOCTOU 防护：事务内重新检查用户关联
                        let user_count = user_role_repo.count_by_role_id_conn(txn, role_id).await?;
                        if user_count > 0 {
                            return Err(sea_orm::DbErr::Custom(crate::tr!(
                                "error.role.assigned_to_user",
                                id = role_id
                            )));
                        }

                        // 3. 释放唯一字段值（避免软删除后唯一索引冲突）
                        let deleted_role_key = format!("{}_deleted_{}", existing.role_key, role_id);

                        // 4. 软删除 sys_role
                        let mut am: SysRoleActiveModel = existing.into();
                        am.del_flag = Set(Some("2".to_string()));
                        am.role_key = Set(deleted_role_key);
                        role_repo.base().update_conn(txn, am).await?;

                        // 5. 物理删除 sys_role_menu 关联
                        role_menu_repo.delete_by_role_id_conn(txn, role_id).await?;

                        // 6. 物理删除 sys_user_role 关联（冗余保护）
                        user_role_repo.delete_by_role_id_conn(txn, role_id).await?;
                    }
                    Ok(())
                }
                .boxed()
            })
            .await;

        match txn_result {
            Ok(()) => {
                // 角色批量删除影响绑定这些角色的用户权限，全量失效权限缓存
                self.invalidate_all_perm_cache().await;
                Ok(())
            }
            Err(sea_orm::TransactionError::Transaction(sea_orm::DbErr::Custom(msg))) => {
                Err(ServiceError::bad_request(&msg))
            }
            Err(e) => Err(ServiceError::from(e)),
        }
    }

    /// 启停角色
    pub async fn update_role_status(
        &self,
        role_id: i64,
        status: &str,
        operator: &str,
        operator_tid: i64,
    ) -> Result<(), ServiceError> {
        // 超管保护：SUPER_ADMIN_ROLE_ID 不允许停用
        if role_id == SUPER_ADMIN_ROLE_ID && status == "1" {
            return Err(ServiceError::bad_request(&crate::tr!(
                "error.role.admin_disable_forbidden"
            )));
        }

        let existing = self
            .role_repo
            .base()
            .find_by_id(role_id)
            .await?
            .ok_or_else(|| ServiceError::not_found(&crate::tr!("error.role.not_found")))?;
        if existing.del_flag.as_deref() == Some("2") {
            return Err(ServiceError::not_found(&crate::tr!("error.role.not_found")));
        }
        // 多租户越权防护：只能启停本租户角色（平台操作者放行）
        if !crate::common::tenant::tenant_allowed(operator_tid, existing.tenant_id) {
            return Err(ServiceError::forbidden(&crate::tr!(
                "error.common.forbidden"
            )));
        }

        let now = crate::common::datetime::now_naive();
        let mut am: SysRoleActiveModel = existing.into();
        am.status = Set(status.to_string());
        am.update_by = Set(Some(operator.to_string()));
        am.update_time = Set(Some(now));
        self.role_repo.update(am).await?;
        // 角色状态变更影响绑定该角色的用户权限，全量失效权限缓存
        self.invalidate_all_perm_cache().await;

        Ok(())
    }

    /// 分配角色菜单（事务：先清空再插入，全量覆盖）
    pub async fn assign_role_menus(
        &self,
        role_id: i64,
        menu_ids: Vec<i64>,
        operator_tid: i64,
    ) -> Result<(), ServiceError> {
        let existing = self
            .role_repo
            .base()
            .find_by_id(role_id)
            .await?
            .ok_or_else(|| ServiceError::not_found(&crate::tr!("error.role.not_found")))?;
        if existing.del_flag.as_deref() == Some("2") {
            return Err(ServiceError::not_found(&crate::tr!("error.role.not_found")));
        }
        // 多租户越权防护：只能为所属租户范围内的角色授权菜单（平台操作者放行）
        if !crate::common::tenant::tenant_allowed(operator_tid, existing.tenant_id) {
            return Err(ServiceError::forbidden(&crate::tr!(
                "error.common.forbidden"
            )));
        }
        // §27.6 生效点①：授权菜单必须 ⊆ 角色所属租户的套餐白名单
        if !menu_ids.is_empty() {
            let effective_tid = if operator_tid == 0 {
                existing.tenant_id
            } else {
                operator_tid
            };
            self.tenant_service
                .ensure_menus_in_package(effective_tid, &menu_ids)
                .await?;
            // §27.13.4 授予前门禁：不可授予 perms（平台专属 / tier2 未过滤）不得下放租户角色
            self.ensure_menus_filter_coverage(&menu_ids, effective_tid)
                .await?;
        }

        let role_menu_repo = self.role_menu_repo.clone();
        self.db()
            .transaction::<_, (), sea_orm::DbErr>(|txn| {
                let menu_ids = menu_ids.clone();
                async move {
                    // 先删除旧关联（通过 Repository）
                    role_menu_repo.delete_by_role_id_conn(txn, role_id).await?;
                    // 若非空，再插入新关联（通过 Repository）
                    if !menu_ids.is_empty() {
                        let models: Vec<SysRoleMenuActiveModel> = menu_ids
                            .into_iter()
                            .map(|mid| SysRoleMenuActiveModel {
                                role_id: Set(role_id),
                                menu_id: Set(mid),
                            })
                            .collect();
                        role_menu_repo.insert_many_conn(txn, models).await?;
                    }
                    Ok(())
                }
                .boxed()
            })
            .await?;
        // 角色菜单分配变更影响绑定该角色的用户权限，全量失效权限缓存
        self.invalidate_all_perm_cache().await;

        Ok(())
    }

    /// 查询用户角色列表（登录后获取角色列表注入 JWT）
    pub async fn get_roles_by_user_id(
        &self,
        user_id: i64,
    ) -> Result<Vec<SysRoleModel>, ServiceError> {
        let roles = self.role_repo.find_by_user_id(user_id).await?;
        Ok(roles)
    }

    /// 查询用户角色 key 列表（权限校验用）
    pub async fn get_role_keys_by_user_id(
        &self,
        user_id: i64,
    ) -> Result<Vec<String>, ServiceError> {
        let roles = self.get_roles_by_user_id(user_id).await?;
        let keys: Vec<String> = roles.into_iter().map(|r| r.role_key).collect();
        Ok(keys)
    }

    // ==================== 数据权限 ====================

    /// 修改角色数据权限（事务：更新 data_scope + 重分配 sys_role_dept）
    ///
    /// - data_scope = "2"（自定义）：保存 dept_ids 到 sys_role_dept
    /// - data_scope != "2"：清空 sys_role_dept
    /// - 超管角色（role_id=1）禁止修改数据权限
    pub async fn update_data_scope(
        &self,
        dto: DataScopeDto,
        operator: &str,
        operator_tid: i64,
    ) -> Result<(), ServiceError> {
        crate::common::i18n::validate(&dto)?;

        // 超管保护
        if dto.role_id == SUPER_ADMIN_ROLE_ID {
            return Err(ServiceError::bad_request(&crate::tr!(
                "error.role.admin_data_scope_forbidden"
            )));
        }

        let existing = self
            .role_repo
            .base()
            .find_by_id(dto.role_id)
            .await?
            .ok_or_else(|| ServiceError::not_found(&crate::tr!("error.role.not_found")))?;
        if existing.del_flag.as_deref() == Some("2") {
            return Err(ServiceError::not_found(&crate::tr!("error.role.not_found")));
        }
        // 多租户越权防护：只能修改本租户角色的数据权限（平台操作者放行）
        if !crate::common::tenant::tenant_allowed(operator_tid, existing.tenant_id) {
            return Err(ServiceError::forbidden(&crate::tr!(
                "error.common.forbidden"
            )));
        }

        let now = crate::common::datetime::now_naive();
        let data_scope = dto.data_scope.clone();
        let dept_ids = dto.dept_ids.clone();
        let role_id = dto.role_id;
        let dept_check_strictly = dto.dept_check_strictly;
        let operator = operator.to_string();

        let role_repo = self.role_repo.clone();
        let role_dept_repo = self.role_dept_repo.clone();
        self.db()
            .transaction::<_, (), sea_orm::DbErr>(|txn| {
                let operator = operator.clone();
                let data_scope = data_scope.clone();
                let dept_ids = dept_ids.clone();
                async move {
                    // 1. 更新 sys_role 的 data_scope 和 dept_check_strictly（通过 Repository）
                    let mut am: SysRoleActiveModel = existing.into();
                    am.data_scope = Set(Some(data_scope.clone()));
                    if let Some(strict) = dept_check_strictly {
                        am.dept_check_strictly = Set(Some(strict));
                    }
                    am.update_by = Set(Some(operator));
                    am.update_time = Set(Some(now));
                    role_repo.base().update_conn(txn, am).await?;

                    // 2. 先删除旧的 sys_role_dept 关联（通过 Repository）
                    role_dept_repo.delete_by_role_id_conn(txn, role_id).await?;

                    // 3. 若 data_scope == "2" 且 dept_ids 非空，插入新关联（通过 Repository）
                    if data_scope == "2" && !dept_ids.is_empty() {
                        let models: Vec<SysRoleDeptActiveModel> = dept_ids
                            .into_iter()
                            .map(|did| SysRoleDeptActiveModel {
                                role_id: Set(role_id),
                                dept_id: Set(did),
                            })
                            .collect();
                        role_dept_repo.insert_many_conn(txn, models).await?;
                    }
                    Ok(())
                }
                .boxed()
            })
            .await?;
        // R12：data_scope 变更影响绑定该角色的用户的数据权限，需失效权限缓存
        self.invalidate_all_perm_cache().await;

        Ok(())
    }

    // ==================== 角色授权用户管理 ====================

    /// 查询角色已授权用户列表（分页 + 可选 userName/phonenumber 过滤）
    ///
    /// SQL 语义：SELECT * FROM sys_user WHERE del_flag='0' AND user_id IN
    ///          (SELECT user_id FROM sys_user_role WHERE role_id=?)
    ///
    /// `tenant_scope`：租户操作者 → `Some(tid)` 仅本租户用户；平台 → `None` 全量。
    pub async fn get_allocated_users(
        &self,
        query: AuthUserQueryDto,
        operator_user_id: Option<i64>,
        tenant_scope: Option<i64>,
    ) -> Result<(Vec<SysUserModel>, u64), ServiceError> {
        let page = PageDomain::from(&query);
        let offset = page.offset();
        let limit = page.limit();
        // 动态排序：白名单命中才生效，未命中/缺省由 repository 回退默认排序（查询目标为 sys_user）
        let sort = page.order_by_column.as_deref().and_then(|prop| {
            sort::resolve_column::<crate::entity::sys_user::Entity>(prop, AUTH_USER_SORTABLE_COLUMNS)
                .map(|col| SortOrder::new(col, sort::parse_direction(page.is_asc.as_deref())))
        });

        // P0-6：操作人数据范围（与 user list 一致），防止枚举全部用户
        let (scope_dept_ids, scope_user_id) =
            self.resolve_user_data_scope(operator_user_id).await?;

        // 先查角色关联的 user_id 列表（通过 Repository）
        let user_ids: Vec<i64> = self
            .user_role_repo
            .find_by_role_id(query.role_id)
            .await?
            .into_iter()
            .map(|ur| ur.user_id)
            .collect();

        if user_ids.is_empty() {
            return Ok((vec![], 0));
        }

        // 通过 Repository 分页查询 user_id 集合内的用户（P0-6：含数据范围过滤）
        let (rows, total) = self
            .user_repo
            .find_page_in_ids(
                offset,
                limit,
                user_ids,
                query.user_name.as_deref(),
                query.phonenumber.as_deref(),
                scope_dept_ids.as_deref(),
                scope_user_id,
                tenant_scope,
                sort,
            )
            .await?;
        Ok((rows, total))
    }

    /// 查询角色未授权用户列表（分页 + 可选 userName/phonenumber 过滤）
    ///
    /// SQL 语义：SELECT * FROM sys_user WHERE del_flag='0' AND user_id NOT IN
    ///          (SELECT user_id FROM sys_user_role WHERE role_id=?)
    ///
    /// `tenant_scope`：租户操作者 → `Some(tid)` 仅本租户用户；平台 → `None` 全量。
    pub async fn get_unallocated_users(
        &self,
        query: AuthUserQueryDto,
        operator_user_id: Option<i64>,
        tenant_scope: Option<i64>,
    ) -> Result<(Vec<SysUserModel>, u64), ServiceError> {
        let page = PageDomain::from(&query);
        let offset = page.offset();
        let limit = page.limit();
        // 动态排序：白名单命中才生效，未命中/缺省由 repository 回退默认排序（查询目标为 sys_user）
        let sort = page.order_by_column.as_deref().and_then(|prop| {
            sort::resolve_column::<crate::entity::sys_user::Entity>(prop, AUTH_USER_SORTABLE_COLUMNS)
                .map(|col| SortOrder::new(col, sort::parse_direction(page.is_asc.as_deref())))
        });

        // P0-6：操作人数据范围（与 user list 一致），防止枚举全部用户
        let (scope_dept_ids, scope_user_id) =
            self.resolve_user_data_scope(operator_user_id).await?;

        // 先查角色已关联的 user_id 列表（通过 Repository）
        let allocated_ids: Vec<i64> = self
            .user_role_repo
            .find_by_role_id(query.role_id)
            .await?
            .into_iter()
            .map(|ur| ur.user_id)
            .collect();

        // 通过 Repository 分页查询不在 user_id 集合内的用户（P0-6：含数据范围过滤）
        let (rows, total) = self
            .user_repo
            .find_page_not_in_ids(
                offset,
                limit,
                allocated_ids,
                query.user_name.as_deref(),
                query.phonenumber.as_deref(),
                scope_dept_ids.as_deref(),
                scope_user_id,
                tenant_scope,
                sort,
            )
            .await?;
        Ok((rows, total))
    }

    /// 计算操作人的用户数据范围（P0-6，与 sys_user_service::resolve_data_scope 语义一致）
    ///
    /// 返回 `(scope_dept_ids, scope_user_id)`：None = 不过滤；仅本人 = scope_user_id。
    /// - 超管（user_id==1）短路，返回 (None, None)（全部数据）
    /// - data_scope=1 全部；2 自定义部门；3 本部门；4 本部门及以下；5 仅本人
    /// - 无角色 / data_scope 缺失 / 未知值：安全失败，限定为本人
    async fn resolve_user_data_scope(
        &self,
        op_uid: Option<i64>,
    ) -> Result<(Option<Vec<i64>>, Option<i64>), ServiceError> {
        let mut scope_dept_ids: Option<Vec<i64>> = None;
        let mut scope_user_id: Option<i64> = None;

        if let Some(op_uid) = op_uid {
            // 超管短路
            if op_uid != SUPER_ADMIN_USER_ID {
                let op_roles = self.role_repo.find_by_user_id(op_uid).await?;
                let min_scope = crate::common::data_scope::min_data_scope(&op_roles);

                if let Some(scope) = min_scope {
                    match scope {
                        1 => {}
                        2 => {
                            let role_ids: Vec<i64> = op_roles
                                .iter()
                                .filter(|r| r.data_scope.as_deref() == Some("2"))
                                .map(|r| r.role_id)
                                .collect();
                            let rids = self.role_dept_repo.find_by_role_ids(&role_ids).await?;
                            scope_dept_ids = Some(rids.into_iter().map(|rd| rd.dept_id).collect());
                        }
                        3 => {
                            let op_user = self.user_repo.base().find_by_id(op_uid).await?;
                            scope_dept_ids = Some(
                                op_user
                                    .and_then(|u| u.dept_id)
                                    .map(|d| vec![d])
                                    .unwrap_or_default(),
                            );
                        }
                        4 => {
                            let op_user = self.user_repo.base().find_by_id(op_uid).await?;
                            let op_dept_id = op_user.and_then(|u| u.dept_id).unwrap_or(0);
                            scope_dept_ids =
                                Some(self.dept_repo.find_descendant_ids(op_dept_id).await?);
                        }
                        5 => {
                            scope_user_id = Some(op_uid);
                        }
                        _ => {
                            // 未知 data_scope 值，安全失败：限定为本人
                            scope_user_id = Some(op_uid);
                        }
                    }
                } else {
                    // operator 无角色或 data_scope 缺失：安全失败，仅本人
                    scope_user_id = Some(op_uid);
                }
            }
        }

        Ok((scope_dept_ids, scope_user_id))
    }

    /// 取消单个用户授权（删除 sys_user_role 中 user_id+role_id 记录）
    ///
    /// 安全校验（P0-C2）：
    /// - 超管角色保护：禁止操作 SUPER_ADMIN_ROLE_ID 的授权
    /// - 超管用户保护：禁止取消 SUPER_ADMIN_USER_ID 的超管角色绑定
    /// - 垂直越权校验：operator 不得对高于自身角色的用户执行取消授权
    pub async fn cancel_auth_user(
        &self,
        dto: CancelAuthUserDto,
        operator_user_id: i64,
    ) -> Result<(), ServiceError> {
        // 超管角色保护：禁止操作超管角色的授权绑定
        if dto.role_id == SUPER_ADMIN_ROLE_ID {
            return Err(ServiceError::bad_request(&crate::tr!(
                "error.user.admin_role_forbidden"
            )));
        }

        // 垂直越权校验：operator 不得对持有更高优先级角色的用户执行取消授权
        self.check_vertical_auth_by_user_id(operator_user_id, dto.user_id)
            .await?;

        self.user_role_repo
            .delete_by_user_and_role(dto.user_id, dto.role_id)
            .await?;
        // 用户角色绑定变更，失效该用户的权限缓存
        self.invalidate_perm_cache(dto.user_id).await;
        Ok(())
    }

    /// 批量取消用户授权（取消多个用户对某角色的授权）
    ///
    /// 前端通过 URL query 传递 roleId + userIds（逗号分隔）
    ///
    /// 安全校验（P0-C3）：
    /// - 超管角色保护：禁止操作 SUPER_ADMIN_ROLE_ID 的授权
    /// - 垂直越权校验：operator 不得对高于自身角色的用户执行取消授权
    pub async fn cancel_all_auth_users(
        &self,
        dto: AuthUserSelectDto,
        operator_user_id: i64,
    ) -> Result<(), ServiceError> {
        // 超管角色保护
        if dto.role_id == SUPER_ADMIN_ROLE_ID {
            return Err(ServiceError::bad_request(&crate::tr!(
                "error.user.admin_role_forbidden"
            )));
        }

        let user_ids: Vec<i64> = parse_id_list::<i64>(&dto.user_ids);
        if user_ids.is_empty() {
            return Err(ServiceError::bad_request(&crate::tr!(
                "error.role.user_id_empty"
            )));
        }

        // 垂直越权校验：批量检查每个目标用户
        for target_user_id in &user_ids {
            self.check_vertical_auth_by_user_id(operator_user_id, *target_user_id)
                .await?;
        }

        self.user_role_repo
            .delete_by_role_and_users(dto.role_id, user_ids)
            .await?;
        // 批量用户角色绑定变更，全量失效权限缓存
        self.invalidate_all_perm_cache().await;
        Ok(())
    }

    /// 批量授权用户选择（为多个用户分配指定角色）
    ///
    /// 前端通过 URL query 传递 roleId + userIds（逗号分隔）
    ///
    /// 安全校验（P0-C1）：
    /// - 超管角色保护：禁止将 SUPER_ADMIN_ROLE_ID 分配给任何用户
    /// - 垂直越权校验：operator 不得对高于自身角色的用户执行授权
    pub async fn select_all_auth_users(
        &self,
        dto: AuthUserSelectDto,
        operator_user_id: i64,
    ) -> Result<(), ServiceError> {
        // 超管角色保护：禁止分配超管角色
        if dto.role_id == SUPER_ADMIN_ROLE_ID {
            return Err(ServiceError::bad_request(&crate::tr!(
                "error.user.admin_role_forbidden"
            )));
        }

        let user_ids: Vec<i64> = parse_id_list::<i64>(&dto.user_ids);
        if user_ids.is_empty() {
            return Err(ServiceError::bad_request(&crate::tr!(
                "error.role.user_id_empty"
            )));
        }

        // 垂直越权校验：批量检查每个目标用户
        for target_user_id in &user_ids {
            self.check_vertical_auth_by_user_id(operator_user_id, *target_user_id)
                .await?;
        }

        // 先查已存在的关联，避免重复插入（通过 Repository）
        let existing: Vec<i64> = self
            .user_role_repo
            .find_by_role_and_users(dto.role_id, user_ids.clone())
            .await?
            .into_iter()
            .map(|ur| ur.user_id)
            .collect();

        let to_insert: Vec<i64> = user_ids
            .iter()
            .filter(|uid| !existing.contains(uid))
            .copied()
            .collect();

        if to_insert.is_empty() {
            return Ok(());
        }

        let models: Vec<SysUserRoleActiveModel> = to_insert
            .iter()
            .map(|&uid| SysUserRoleActiveModel {
                user_id: Set(uid),
                role_id: Set(dto.role_id),
                source: Set("admin".to_owned()),
            })
            .collect();
        self.user_role_repo.insert_many(models).await?;
        // 批量用户角色绑定变更，全量失效权限缓存
        self.invalidate_all_perm_cache().await;
        Ok(())
    }

    /// 垂直越权校验：基于目标用户当前绑定的角色
    ///
    /// 复用 SysUserService.check_vertical_auth_by_user_id 的语义：
    /// - 超管（user_id==1）豁免
    /// - 其他 operator：取目标用户角色中最小 role_sort，若小于 operator 最小 role_sort 则拒绝
    async fn check_vertical_auth_by_user_id(
        &self,
        operator_user_id: i64,
        target_user_id: i64,
    ) -> Result<(), ServiceError> {
        if operator_user_id == SUPER_ADMIN_USER_ID {
            return Ok(());
        }
        let op_roles = self.role_repo.find_by_user_id(operator_user_id).await?;
        let op_min_sort = op_roles.iter().map(|r| r.role_sort).min();

        let target_roles = self.role_repo.find_by_user_id(target_user_id).await?;
        let target_min_sort = target_roles.iter().map(|r| r.role_sort).min();

        if let (Some(target_min), Some(op_min)) = (target_min_sort, op_min_sort)
            && target_min < op_min
        {
            return Err(ServiceError::new(
                403,
                crate::tr!("error.user.higher_role_forbidden"),
            ));
        }
        Ok(())
    }

    // ==================== 部门树 ====================

    /// 查询角色部门树（含已勾选部门 ID）
    ///
    /// 返回 RoleDeptTreeVo:
    /// - checked_keys: 该角色已勾选的部门 ID 列表（来自 sys_role_dept）
    /// - depts: 本租户全部部门的树形结构（TreeSelect 格式）
    ///
    /// 多租户加固：先做角色归属校验（不存在/已删除 → 404；跨租户 → 403），
    /// 再按操作者租户过滤部门树，避免传入任意 role_id 越权读取他租户部门/勾选结果。
    pub async fn get_dept_tree(
        &self,
        role_id: i64,
        operator_tid: i64,
    ) -> Result<RoleDeptTreeVo, ServiceError> {
        // 1. 加载角色并做归属校验（与 delete_role 一致的既有范式）
        let existing = self
            .role_repo
            .base()
            .find_by_id(role_id)
            .await?
            .ok_or_else(|| ServiceError::not_found(&crate::tr!("error.role.not_found")))?;
        if existing.del_flag.as_deref() == Some("2") {
            return Err(ServiceError::not_found(&crate::tr!("error.role.not_found")));
        }
        // 多租户越权防护：只能查看本租户角色（平台操作者放行）
        if !crate::common::tenant::tenant_allowed(operator_tid, existing.tenant_id) {
            return Err(ServiceError::forbidden(&crate::tr!(
                "error.common.forbidden"
            )));
        }

        // 2. 查询本租户未删除部门（平台操作者 tenant_scope=None 不过滤）
        let depts = self
            .dept_repo
            .find_active_all(crate::common::tenant::tenant_scope(operator_tid))
            .await?;

        // 3. 查询该角色已勾选的部门 ID
        let checked_keys: Vec<i64> = self
            .role_dept_repo
            .find_by_role_id(role_id)
            .await?
            .into_iter()
            .map(|rd| rd.dept_id)
            .collect();

        // 4. 组装部门树（TreeSelect 格式）
        let tree = build_dept_tree_select(&depts, 0);

        Ok(RoleDeptTreeVo {
            checked_keys,
            depts: tree,
        })
    }

    // ==================== 内部辅助方法 ====================

    /// 查询角色已绑定的菜单 ID 列表
    async fn get_menu_ids_by_role_id(&self, role_id: i64) -> Result<Vec<i64>, ServiceError> {
        let role_menus = self.role_menu_repo.find_by_role_id(role_id).await?;
        let menu_ids: Vec<i64> = role_menus.into_iter().map(|rm| rm.menu_id).collect();
        Ok(menu_ids)
    }
}
