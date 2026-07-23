//! 角色模块 Service 层
//!
//! 职责：
//! - 角色 CRUD、角色菜单绑定、数据权限配置、级联删除校验
//! - 不依赖任何 Web 框架类型（axum / tower / tower-http）
//! - 多表操作使用 SeaORM 事务保证一致性
//! - 参数校验使用 validator crate
//! - 数据访问通过 Repository 层委托

use futures::future::FutureExt;
use sea_orm::{DatabaseConnection, Set, TransactionTrait};
use serde::Deserialize;
use ts_rs::TS;
use utoipa::{IntoParams, ToSchema};
use validator::Validate;

use crate::common::constants::{SUPER_ADMIN_ROLE_ID, SUPER_ADMIN_USER_ID};
use crate::common::error::ServiceError;
use crate::common::page::{default_page_num, default_page_size, PageDomain};
use crate::common::TreeSelectVo;
use crate::entity::sys_role::{
    ActiveModel as SysRoleActiveModel, Model as SysRoleModel,
};
use crate::entity::sys_role_dept::ActiveModel as SysRoleDeptActiveModel;
use crate::entity::sys_role_menu::ActiveModel as SysRoleMenuActiveModel;
use crate::entity::sys_user::Model as SysUserModel;
use crate::entity::sys_user_role::ActiveModel as SysUserRoleActiveModel;
use crate::repository::sys_dept::SysDeptRepository;
use crate::repository::sys_role::SysRoleRepository;
use crate::repository::sys_role_dept::SysRoleDeptRepository;
use crate::repository::sys_role_menu::SysRoleMenuRepository;
use crate::repository::sys_user::SysUserRepository;
use crate::repository::sys_user_role::SysUserRoleRepository;
use crate::utils::parse_id_list;

// 部门树组装函数抽取至 service/mod.rs，避免与 sys_user_service 重复
use super::build_dept_tree_select;

// ==================== DTO 定义 ====================

/// 新增角色 DTO
#[derive(Debug, Deserialize, Validate, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct RoleAddDto {
    #[validate(length(min = 2, max = 30, message = "角色名称长度必须在2-30之间"))]
    pub role_name: String,
    #[validate(length(min = 2, max = 100, message = "角色权限字符串长度必须在2-100之间"))]
    pub role_key: String,
    #[validate(range(min = 0, max = 999, message = "显示顺序必须在0-999之间"))]
    pub role_sort: i32,
    pub data_scope: Option<String>,
    pub menu_check_strictly: Option<bool>,
    pub dept_check_strictly: Option<bool>,
    #[validate(length(min = 1, max = 1, message = "状态值不合法"))]
    pub status: String,
    /// 菜单 ID 列表（None 不绑定，Some(vec![]) 清空）
    pub menu_ids: Option<Vec<i64>>,
    #[validate(length(max = 500, message = "备注长度不能超过500"))]
    pub remark: Option<String>,
}

/// 修改角色 DTO
#[derive(Debug, Deserialize, Validate, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct RoleEditDto {
    pub role_id: i64,
    #[validate(length(min = 2, max = 30, message = "角色名称长度必须在2-30之间"))]
    pub role_name: Option<String>,
    #[validate(length(min = 2, max = 100, message = "角色权限字符串长度必须在2-100之间"))]
    pub role_key: Option<String>,
    #[validate(range(min = 0, max = 999, message = "显示顺序必须在0-999之间"))]
    pub role_sort: Option<i32>,
    pub data_scope: Option<String>,
    pub menu_check_strictly: Option<bool>,
    pub dept_check_strictly: Option<bool>,
    pub status: Option<String>,
    /// None 不修改菜单绑定，Some(vec![]) 清空
    pub menu_ids: Option<Vec<i64>>,
    #[validate(length(max = 500, message = "备注长度不能超过500"))]
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
    pub role_name: Option<String>,
    pub role_key: Option<String>,
    pub status: Option<String>,
}

impl From<&RoleQueryDto> for PageDomain {
    fn from(dto: &RoleQueryDto) -> Self {
        PageDomain {
            page_num: dto.page_num,
            page_size: dto.page_size,
            order_by_column: None,
            is_asc: None,
        }
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
    pub role_id: i64,
    /// 数据范围（1全部 2自定义 3本部门 4本部门及以下 5仅本人）
    #[validate(length(min = 1, max = 1, message = "数据范围值不合法"))]
    pub data_scope: String,
    /// 自定义数据权限时勾选的部门 ID 列表（data_scope=2 时使用）
    #[serde(default)]
    pub dept_ids: Vec<i64>,
    pub dept_check_strictly: Option<bool>,
}

/// 角色已授权用户分页查询 DTO
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthUserQueryDto {
    #[serde(default = "default_page_num")]
    pub page_num: u64,
    #[serde(default = "default_page_size")]
    pub page_size: u64,
    pub role_id: i64,
    pub user_name: Option<String>,
    pub phonenumber: Option<String>,
}

impl From<&AuthUserQueryDto> for PageDomain {
    fn from(dto: &AuthUserQueryDto) -> Self {
        PageDomain {
            page_num: dto.page_num,
            page_size: dto.page_size,
            order_by_column: None,
            is_asc: None,
        }
    }
}

/// 取消用户授权 DTO（单条）
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CancelAuthUserDto {
    pub user_id: i64,
    pub role_id: i64,
}

/// 批量授权用户查询参数（通过 URL query 传递）
#[derive(Debug, Deserialize)]
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

/// 角色模块 Service
///
/// 数据访问通过 Repository 层委托：
/// - role_repo: sys_role 表 CRUD
/// - role_menu_repo: sys_role_menu 关联表 CRUD
/// - role_dept_repo: sys_role_dept 关联表 CRUD（数据权限）
/// - user_role_repo: sys_user_role 关联表 CRUD（级联清理 + 授权用户管理）
/// - dept_repo: sys_dept 表查询（部门树）
/// - 事务通过 role_repo.base().db() 获取连接
#[derive(Clone)]
pub struct SysRoleService {
    role_repo: SysRoleRepository,
    role_menu_repo: SysRoleMenuRepository,
    role_dept_repo: SysRoleDeptRepository,
    user_role_repo: SysUserRoleRepository,
    user_repo: SysUserRepository,
    dept_repo: SysDeptRepository,
}

impl SysRoleService {
    pub fn new(db: DatabaseConnection) -> Self {
        Self {
            role_repo: SysRoleRepository::new(db.clone()),
            role_menu_repo: SysRoleMenuRepository::new(db.clone()),
            role_dept_repo: SysRoleDeptRepository::new(db.clone()),
            user_role_repo: SysUserRoleRepository::new(db.clone()),
            user_repo: SysUserRepository::new(db.clone()),
            dept_repo: SysDeptRepository::new(db),
        }
    }

    /// 获取数据库连接引用（用于事务）
    fn db(&self) -> &DatabaseConnection {
        self.role_repo.base().db()
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
    ) -> Result<(Vec<SysRoleModel>, u64), ServiceError> {
        let page = PageDomain::from(&query);
        let offset = page.offset();
        let limit = page.limit();

        // 数据权限过滤参数
        let mut scope_role_ids: Option<Vec<i64>> = None;

        if let Some(op_uid) = operator_user_id {
            // 超管短路（REGRESS-011：使用常量 SUPER_ADMIN_USER_ID 替代硬编码 1）
            if op_uid != SUPER_ADMIN_USER_ID {
                let op_roles = self.role_repo.find_by_user_id(op_uid).await?;
                let min_scope = op_roles
                    .iter()
                    .filter_map(|r| r.data_scope.as_deref())
                    .filter_map(|s| s.parse::<i32>().ok())
                    .min();

                if let Some(scope) = min_scope {
                    match scope {
                        1 => {
                            // 全部数据：不追加过滤
                        }
                        2..=4 => {
                            // REGRESS-004：角色无 dept_id，data_scope 2/3/4 降级为"仅本人"
                            // 安全失败：普通管理员只能看到自己绑定的角色，避免越权查看所有角色
                            let ids: Vec<i64> = op_roles.iter().map(|r| r.role_id).collect();
                            scope_role_ids = Some(ids);
                        }
                        5 => {
                            // 仅本人：仅返回 operator 已绑定的角色
                            let ids: Vec<i64> = op_roles.iter().map(|r| r.role_id).collect();
                            scope_role_ids = Some(ids);
                        }
                        _ => {
                            // 未知 data_scope：安全失败，仅本人角色
                            let ids: Vec<i64> = op_roles.iter().map(|r| r.role_id).collect();
                            scope_role_ids = Some(ids);
                        }
                    }
                } else {
                    // operator 无角色或 data_scope 缺失：安全失败，仅本人角色（可能为空）
                    let ids: Vec<i64> = op_roles.iter().map(|r| r.role_id).collect();
                    scope_role_ids = Some(ids);
                }
            }
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
            )
            .await?;
        Ok((rows, total))
    }

    /// 导出角色列表（受 EXPORT_MAX_ROWS 限制，避免无上限查询导致 OOM）
    pub async fn export_roles(&self, query: RoleQueryDto) -> Result<Vec<SysRoleModel>, ServiceError> {
        // 导出使用大分页，获取全部符合条件的记录（上限 EXPORT_MAX_ROWS）
        let (rows, _) = self
            .role_repo
            .find_page_filtered(
                0,
                crate::common::page::EXPORT_MAX_ROWS,
                query.role_name.as_deref(),
                query.role_key.as_deref(),
                query.status.as_deref(),
                None,
                None,
            )
            .await?;
        Ok(rows)
    }

    /// 查询角色详情（含 menu_ids）
    pub async fn get_role_by_id(&self, role_id: i64) -> Result<RoleVo, ServiceError> {
        let role = self.role_repo.base().find_by_id(role_id).await?
            .ok_or_else(|| ServiceError::not_found("角色不存在"))?;
        if role.del_flag.as_deref() == Some("2") {
            return Err(ServiceError::not_found("角色不存在"));
        }

        let menu_ids = self.get_menu_ids_by_role_id(role_id).await?;
        Ok(RoleVo { role, menu_ids })
    }

    /// 查询所有未删除角色（用于用户编辑页角色下拉选择）
    pub async fn get_all_roles(&self) -> Result<Vec<SysRoleModel>, ServiceError> {
        let roles = self.role_repo.find_active_all().await?;
        Ok(roles)
    }

    /// 新增角色（事务：插入角色 + 批量插入菜单关联）
    pub async fn add_role(
        &self,
        dto: RoleAddDto,
        operator: &str,
    ) -> Result<SysRoleModel, ServiceError> {
        dto.validate()?;

        // role_key 查重
        let exists = self.role_repo.find_by_role_key(&dto.role_key).await?;
        if exists.is_some() {
            return Err(ServiceError::bad_request("角色权限字符不能重复"));
        }

        let role_repo = self.role_repo.clone();
        let role_menu_repo = self.role_menu_repo.clone();
        let result = self
            .db()
            .transaction::<_, SysRoleModel, sea_orm::DbErr>(|txn| {
                let now = chrono::Local::now().naive_local();
                let mut am = SysRoleActiveModel {
                    ..Default::default()
                };
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

                let menu_ids = dto.menu_ids.clone();
                async move {
                    // 1. 插入 sys_role（通过 Repository）
                    let new_role = role_repo.base().insert_conn(txn, am).await?;

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
    ) -> Result<SysRoleModel, ServiceError> {
        dto.validate()?;

        // 查询角色是否存在
        let existing = self.role_repo.base().find_by_id(dto.role_id).await?
            .ok_or_else(|| ServiceError::not_found("角色不存在"))?;
        if existing.del_flag.as_deref() == Some("2") {
            return Err(ServiceError::not_found("角色不存在"));
        }

        // 超管保护：SUPER_ADMIN_ROLE_ID 不允许修改 role_key
        if dto.role_id == SUPER_ADMIN_ROLE_ID
            && let Some(ref new_key) = dto.role_key
            && *new_key != existing.role_key
        {
            return Err(ServiceError::bad_request("不允许修改超级管理员角色的权限字符"));
        }

        // role_key 查重：若 role_key 变更，校验新 role_key 是否已被其他角色占用（通过 Repository）
        if let Some(ref new_key) = dto.role_key
            && *new_key != existing.role_key
        {
            let dup = self.role_repo.find_by_role_key(new_key).await?;
            if let Some(d) = &dup
                && d.role_id != dto.role_id
            {
                return Err(ServiceError::bad_request("角色权限字符不能重复"));
            }
        }

        let role_repo = self.role_repo.clone();
        let role_menu_repo = self.role_menu_repo.clone();
        let result = self
            .db()
            .transaction::<_, SysRoleModel, sea_orm::DbErr>(|txn| {
                let now = chrono::Local::now().naive_local();
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
                    Ok(updated)
                }
                .boxed()
            })
            .await?;

        Ok(result)
    }

    /// 删除角色（事务：级联清理 + 软删除）
    ///
    /// M-1 Major TOCTOU 修复：用户关联检查移入事务内，避免事务外预检查后
    /// 被其他事务插入新关联（TOCTOU）导致数据不一致。
    pub async fn delete_role(&self, role_id: i64) -> Result<(), ServiceError> {
        // 超管保护
        if role_id == SUPER_ADMIN_ROLE_ID {
            return Err(ServiceError::bad_request("不允许删除超级管理员角色"));
        }

        let existing = self.role_repo.base().find_by_id(role_id).await?
            .ok_or_else(|| ServiceError::not_found("角色不存在"))?;
        if existing.del_flag.as_deref() == Some("2") {
            return Err(ServiceError::not_found("角色不存在"));
        }

        // 释放唯一字段值，避免软删除后唯一索引冲突（uk_sys_role_key）
        // 软删除记录仍占用 role_key 唯一索引，导致无法重新创建同 key 角色
        let deleted_role_key = format!("{}_deleted_{}", existing.role_key, role_id);

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
                    let user_count = user_role_repo
                        .count_by_role_id_conn(txn, role_id)
                        .await?;
                    if user_count > 0 {
                        return Err(sea_orm::DbErr::Custom(
                            "该角色已分配给用户，不允许删除".to_string(),
                        ));
                    }

                    // 1. 软删除 sys_role（通过 Repository）
                    let mut am: SysRoleActiveModel = existing.into();
                    am.del_flag = Set(Some("2".to_string()));
                    am.role_key = Set(deleted_role_key);
                    role_repo.base().update_conn(txn, am).await?;

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
            Ok(()) => Ok(()),
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
    pub async fn delete_roles(&self, role_ids: Vec<i64>) -> Result<(), ServiceError> {
        // 预校验：超管保护（事务外快速失败）
        if role_ids.contains(&SUPER_ADMIN_ROLE_ID) {
            return Err(ServiceError::bad_request("不允许删除超级管理员角色"));
        }

        // 单个 ID 直接走 delete_role（保持原有事务行为）
        if role_ids.len() == 1 {
            return self.delete_role(role_ids[0]).await;
        }

        // 批量删除：单个事务包装所有操作
        let role_repo = self.role_repo.clone();
        let role_menu_repo = self.role_menu_repo.clone();
        let user_role_repo = self.user_role_repo.clone();
        let db = self.db().clone();

        let txn_result = db.transaction::<_, (), sea_orm::DbErr>(|txn| {
                async move {
                    for role_id in role_ids {
                        // 1. 查询角色存在性（事务内，防止 TOCTOU）
                        let existing = role_repo.base().find_by_id_conn(txn, role_id).await?
                            .ok_or_else(|| sea_orm::DbErr::Custom(format!("角色 {} 不存在", role_id)))?;
                        if existing.del_flag.as_deref() == Some("2") {
                            return Err(sea_orm::DbErr::Custom(format!("角色 {} 不存在", role_id)));
                        }

                        // 2. TOCTOU 防护：事务内重新检查用户关联
                        let user_count = user_role_repo.count_by_role_id_conn(txn, role_id).await?;
                        if user_count > 0 {
                            return Err(sea_orm::DbErr::Custom(
                                format!("角色 {} 已分配给用户，不允许删除", role_id),
                            ));
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
            Ok(()) => Ok(()),
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
    ) -> Result<(), ServiceError> {
        // 超管保护：SUPER_ADMIN_ROLE_ID 不允许停用
        if role_id == SUPER_ADMIN_ROLE_ID && status == "1" {
            return Err(ServiceError::bad_request("不允许停用超级管理员角色"));
        }

        let existing = self.role_repo.base().find_by_id(role_id).await?
            .ok_or_else(|| ServiceError::not_found("角色不存在"))?;
        if existing.del_flag.as_deref() == Some("2") {
            return Err(ServiceError::not_found("角色不存在"));
        }

        let now = chrono::Local::now().naive_local();
        let mut am: SysRoleActiveModel = existing.into();
        am.status = Set(status.to_string());
        am.update_by = Set(Some(operator.to_string()));
        am.update_time = Set(Some(now));
        self.role_repo.update(am).await?;

        Ok(())
    }

    /// 分配角色菜单（事务：先清空再插入，全量覆盖）
    pub async fn assign_role_menus(
        &self,
        role_id: i64,
        menu_ids: Vec<i64>,
    ) -> Result<(), ServiceError> {
        let existing = self.role_repo.base().find_by_id(role_id).await?
            .ok_or_else(|| ServiceError::not_found("角色不存在"))?;
        if existing.del_flag.as_deref() == Some("2") {
            return Err(ServiceError::not_found("角色不存在"));
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

        Ok(())
    }

    /// 查询用户角色列表（登录后获取角色列表注入 JWT）
    pub async fn get_roles_by_user_id(&self, user_id: i64) -> Result<Vec<SysRoleModel>, ServiceError> {
        let roles = self.role_repo.find_by_user_id(user_id).await?;
        Ok(roles)
    }

    /// 查询用户角色 key 列表（权限校验用）
    pub async fn get_role_keys_by_user_id(&self, user_id: i64) -> Result<Vec<String>, ServiceError> {
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
    ) -> Result<(), ServiceError> {
        dto.validate()?;

        // 超管保护
        if dto.role_id == SUPER_ADMIN_ROLE_ID {
            return Err(ServiceError::bad_request("不允许修改超级管理员角色的数据权限"));
        }

        let existing = self.role_repo.base().find_by_id(dto.role_id).await?
            .ok_or_else(|| ServiceError::not_found("角色不存在"))?;
        if existing.del_flag.as_deref() == Some("2") {
            return Err(ServiceError::not_found("角色不存在"));
        }

        let now = chrono::Local::now().naive_local();
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

        Ok(())
    }

    // ==================== 角色授权用户管理 ====================

    /// 查询角色已授权用户列表（分页 + 可选 userName/phonenumber 过滤）
    ///
    /// SQL 语义：SELECT * FROM sys_user WHERE del_flag='0' AND user_id IN
    ///          (SELECT user_id FROM sys_user_role WHERE role_id=?)
    pub async fn get_allocated_users(
        &self,
        query: AuthUserQueryDto,
    ) -> Result<(Vec<SysUserModel>, u64), ServiceError> {
        let page = PageDomain::from(&query);
        let offset = page.offset();
        let limit = page.limit();

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

        // 通过 Repository 分页查询 user_id 集合内的用户
        let (rows, total) = self
            .user_repo
            .find_page_in_ids(
                offset,
                limit,
                user_ids,
                query.user_name.as_deref(),
                query.phonenumber.as_deref(),
            )
            .await?;
        Ok((rows, total))
    }

    /// 查询角色未授权用户列表（分页 + 可选 userName/phonenumber 过滤）
    ///
    /// SQL 语义：SELECT * FROM sys_user WHERE del_flag='0' AND user_id NOT IN
    ///          (SELECT user_id FROM sys_user_role WHERE role_id=?)
    pub async fn get_unallocated_users(
        &self,
        query: AuthUserQueryDto,
    ) -> Result<(Vec<SysUserModel>, u64), ServiceError> {
        let page = PageDomain::from(&query);
        let offset = page.offset();
        let limit = page.limit();

        // 先查角色已关联的 user_id 列表（通过 Repository）
        let allocated_ids: Vec<i64> = self
            .user_role_repo
            .find_by_role_id(query.role_id)
            .await?
            .into_iter()
            .map(|ur| ur.user_id)
            .collect();

        // 通过 Repository 分页查询不在 user_id 集合内的用户
        let (rows, total) = self
            .user_repo
            .find_page_not_in_ids(
                offset,
                limit,
                allocated_ids,
                query.user_name.as_deref(),
                query.phonenumber.as_deref(),
            )
            .await?;
        Ok((rows, total))
    }

    /// 取消单个用户授权（删除 sys_user_role 中 user_id+role_id 记录）
    pub async fn cancel_auth_user(
        &self,
        dto: CancelAuthUserDto,
    ) -> Result<(), ServiceError> {
        self.user_role_repo
            .delete_by_user_and_role(dto.user_id, dto.role_id)
            .await?;
        Ok(())
    }

    /// 批量取消用户授权（取消多个用户对某角色的授权）
    ///
    /// 前端通过 URL query 传递 roleId + userIds（逗号分隔）
    pub async fn cancel_all_auth_users(
        &self,
        dto: AuthUserSelectDto,
    ) -> Result<(), ServiceError> {
        let user_ids: Vec<i64> = parse_id_list::<i64>(&dto.user_ids);
        if user_ids.is_empty() {
            return Err(ServiceError::bad_request("用户 ID 不能为空"));
        }

        self.user_role_repo
            .delete_by_role_and_users(dto.role_id, user_ids)
            .await?;
        Ok(())
    }

    /// 批量授权用户选择（为多个用户分配指定角色）
    ///
    /// 前端通过 URL query 传递 roleId + userIds（逗号分隔）
    pub async fn select_all_auth_users(
        &self,
        dto: AuthUserSelectDto,
    ) -> Result<(), ServiceError> {
        let user_ids: Vec<i64> = parse_id_list::<i64>(&dto.user_ids);
        if user_ids.is_empty() {
            return Err(ServiceError::bad_request("用户 ID 不能为空"));
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
            })
            .collect();
        self.user_role_repo.insert_many(models).await?;
        Ok(())
    }

    // ==================== 部门树 ====================

    /// 查询角色部门树（含已勾选部门 ID）
    ///
    /// 返回 RoleDeptTreeVo:
    /// - checked_keys: 该角色已勾选的部门 ID 列表（来自 sys_role_dept）
    /// - depts: 全部部门的树形结构（TreeSelect 格式）
    pub async fn get_dept_tree(&self, role_id: i64) -> Result<RoleDeptTreeVo, ServiceError> {
        // 1. 查询全部未删除部门
        let depts = self.dept_repo.find_active_all().await?;

        // 2. 查询该角色已勾选的部门 ID
        let checked_keys: Vec<i64> = self
            .role_dept_repo
            .find_by_role_id(role_id)
            .await?
            .into_iter()
            .map(|rd| rd.dept_id)
            .collect();

        // 3. 组装部门树（TreeSelect 格式）
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
