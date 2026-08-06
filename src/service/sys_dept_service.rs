//! 部门模块 Service 层
//!
//! 职责：
//! - 部门 CRUD、ancestors 祖先链维护、树形结构组装
//! - 不依赖任何 Web 框架类型（axum / tower / tower-http）
//! - 多表操作使用 SeaORM 事务保证一致性
//! - 参数校验使用 garde crate（经 common::i18n::validate 统一入口）
//! - 数据访问通过 Repository 层委托

use futures::future::FutureExt;
use sea_orm::{
    ColumnTrait, ConnectionTrait, DatabaseBackend, DatabaseConnection, EntityTrait,
    QueryFilter, Set, Statement, TransactionTrait,
};
use serde::Deserialize;
use utoipa::{IntoParams, ToSchema};
use garde::Validate;

use crate::common::error::ServiceError;
use crate::common::constants::SUPER_ADMIN_USER_ID;
use crate::common::{like_escape, TreeSelectVo};
use crate::entity::sys_dept::{
    ActiveModel as SysDeptActiveModel, Column as DeptColumn, Entity as SysDept, Model as SysDeptModel,
};
use crate::entity::sys_role_dept::{
    Column as RoleDeptColumn, Entity as SysRoleDept,
};
use crate::entity::sys_user::{Column as UserColumn, Entity as SysUser};
use crate::repository::sys_dept::SysDeptRepository;
use crate::repository::sys_role::SysRoleRepository;
use crate::repository::sys_role_dept::SysRoleDeptRepository;
use crate::repository::sys_user::SysUserRepository;
use crate::utils::parse_id_list;

// 部门树组装函数抽取至 service/mod.rs，复用 sys_role_service 的实现
use super::build_dept_tree_select;

// ==================== DTO 定义 ====================

/// 部门列表查询 DTO
#[derive(Debug, Clone, Deserialize, Default, IntoParams)]
#[serde(rename_all = "camelCase")]
pub struct DeptQueryDto {
    pub dept_name: Option<String>,
    pub status: Option<String>,
}

/// 新增部门 DTO
#[derive(Debug, Deserialize, Validate, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct DeptAddDto {
    #[garde(range(min = 0))]
    pub parent_id: Option<i64>,
    #[garde(length(min = 2, max = 30))]
    pub dept_name: String,
    #[garde(range(min = 0, max = 999))]
    pub order_num: Option<i32>,
    #[garde(length(min = 1, max = 20))]
    pub leader: Option<String>,
    #[garde(length(min = 1, max = 11))]
    pub phone: Option<String>,
    #[garde(length(max = 50))]
    #[garde(email)]
    pub email: Option<String>,
    #[garde(length(min = 1, max = 1))]
    pub status: Option<String>,
}

/// 修改部门 DTO（同 Add + dept_id，字段均可选以支持部分更新）
#[derive(Debug, Deserialize, Validate, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct DeptEditDto {
    #[garde(skip)]
    pub dept_id: i64,
    #[garde(range(min = 0))]
    pub parent_id: Option<i64>,
    #[garde(length(min = 2, max = 30))]
    pub dept_name: Option<String>,
    #[garde(range(min = 0, max = 999))]
    pub order_num: Option<i32>,
    #[garde(length(min = 1, max = 20))]
    pub leader: Option<String>,
    #[garde(length(min = 1, max = 11))]
    pub phone: Option<String>,
    #[garde(length(max = 50))]
    #[garde(email)]
    pub email: Option<String>,
    #[garde(length(min = 1, max = 1))]
    pub status: Option<String>,
}

/// 部门排序 DTO（对齐前端 DeptSortParams：deptIds/orderNums 逗号分隔字符串）
#[derive(Debug, Deserialize, Validate, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct DeptSortDto {
    #[garde(length(min = 1))]
    pub dept_ids: String,
    #[garde(length(min = 1))]
    pub order_nums: String,
}

// ==================== Service 实现 ====================

/// 部门模块 Service
///
/// 数据访问通过 Repository 层委托：
/// - dept_repo: sys_dept 表 CRUD + 按状态/名称查询
/// - role_dept_repo: sys_role_dept 关联表（删除校验 + data_scope=2 自定义数据权限）
/// - role_repo: sys_role 表查询（data_scope 读取）
/// - user_repo: sys_user 表查询（operator.dept_id 读取）
/// - 事务通过 dept_repo.base().db() 获取连接
#[derive(Clone)]
pub struct SysDeptService {
    dept_repo: SysDeptRepository,
    role_dept_repo: SysRoleDeptRepository,
    role_repo: SysRoleRepository,
    user_repo: SysUserRepository,
}

impl SysDeptService {
    pub fn new(db: DatabaseConnection) -> Self {
        Self {
            dept_repo: SysDeptRepository::new(db.clone()),
            role_dept_repo: SysRoleDeptRepository::new(db.clone()),
            role_repo: SysRoleRepository::new(db.clone()),
            user_repo: SysUserRepository::new(db),
        }
    }

    /// 获取数据库连接引用（用于事务和复杂查询）
    fn db(&self) -> &DatabaseConnection {
        self.dept_repo.base().db()
    }

    /// 部门列表（扁平，可加 dept_name/status 过滤）
    ///
    /// 用途：部门管理表格展示（前端自行组装树）
    ///
    /// 数据权限（P0-R81-004）：当传入 operator_user_id 时，按 operator 角色的 data_scope 过滤：
    /// - data_scope=1（全部）：不过滤
    /// - data_scope=2（自定义）：filter by sys_role_dept 中角色绑定的 dept_ids
    /// - data_scope=3（本部门）：filter by operator.dept_id
    /// - data_scope=4（本部门及以下）：filter by operator.dept_id 及其所有后代部门（ancestors 含 operator.dept_id）
    /// - data_scope=5（仅本人）：部门无 user_id 概念，等同 data_scope=3（限定为 operator.dept_id）
    ///
    /// 取 operator 所有角色中 data_scope 值最小者（最宽松）生效。
    /// 超管（user_id==1）短路：直接返回全部。
    pub async fn list_depts(
        &self,
        query: DeptQueryDto,
        operator_user_id: Option<i64>,
    ) -> Result<Vec<SysDeptModel>, ServiceError> {
        let mut select = SysDept::find().filter(DeptColumn::DelFlag.eq("0"));
        if let Some(ref name) = query.dept_name {
            select = select.filter(DeptColumn::DeptName.like(format!("%{}%", like_escape(name))));
        }
        if let Some(ref status) = query.status {
            select = select.filter(DeptColumn::Status.eq(status));
        }

        // 数据权限过滤（P0-R81-004 / P0-6 统一入口）
        if let Some(op_uid) = operator_user_id {
            let scope_dept_ids = self.resolve_scope_dept_ids(op_uid).await?;
            match scope_dept_ids {
                Some(ids) if ids.is_empty() => {
                    // 空集合：无可见部门，返回空结果（用永假条件）
                    select = select.filter(DeptColumn::DeptId.eq(-1_i64));
                }
                Some(ids) => {
                    select = select.filter(DeptColumn::DeptId.is_in(ids));
                }
                None => {}
            }
        }

        let list = self.dept_repo.base().find_many(select).await?;
        Ok(list)
    }

    /// 计算操作人的数据范围部门 ID 集合（P0-6 统一入口）
    ///
    /// 供 list / list_exclude / treeselect / get_info 等所有部门查询端点复用，
    /// 杜绝"list 有过滤、旁路端点裸奔"的 data_scope 不一致越权。
    ///
    /// - 超管（user_id==1）或 data_scope=1（全部）：返回 `None`（不过滤）
    /// - 其他：返回 `Some(ids)`，ids 为空表示无可见部门
    async fn resolve_scope_dept_ids(
        &self,
        operator_user_id: i64,
    ) -> Result<Option<Vec<i64>>, ServiceError> {
        // 超管短路
        if operator_user_id == SUPER_ADMIN_USER_ID {
            return Ok(None);
        }

        let op_roles = self.role_repo.find_by_user_id(operator_user_id).await?;
        let min_scope = crate::common::data_scope::min_data_scope(&op_roles);

        let scope_dept_ids: Option<Vec<i64>> = if let Some(scope) = min_scope {
            match scope {
                1 => None, // 全部数据：不追加过滤
                2 => {
                    // 自定义：聚合 operator 所有角色的 sys_role_dept 部门
                    let role_ids: Vec<i64> = op_roles
                        .iter()
                        .filter(|r| r.data_scope.as_deref() == Some("2"))
                        .map(|r| r.role_id)
                        .collect();
                    let rids = self.role_dept_repo.find_by_role_ids(&role_ids).await?;
                    Some(rids.into_iter().map(|rd| rd.dept_id).collect())
                }
                3 | 5 => {
                    // 本部门 / 仅本人：部门无 user_id 概念，两者均限定为 operator.dept_id
                    Some(self.read_op_dept(operator_user_id).await?)
                }
                4 => {
                    // 本部门及以下：operator.dept_id + 所有后代部门
                    let op_user = self.user_repo.base().find_by_id(operator_user_id).await?;
                    let op_dept_id = op_user.and_then(|u| u.dept_id).unwrap_or(0);
                    Some(self.dept_repo.find_descendant_ids(op_dept_id).await?)
                }
                _ => {
                    // 未知 data_scope 值，安全失败：限定为 operator.dept_id
                    Some(self.read_op_dept(operator_user_id).await?)
                }
            }
        } else {
            // operator 无角色或 data_scope 缺失：安全失败，限定为 operator.dept_id
            Some(self.read_op_dept(operator_user_id).await?)
        };
        Ok(scope_dept_ids)
    }

    /// 读取操作人所属部门 ID（None → 空集合，安全失败）
    async fn read_op_dept(&self, operator_user_id: i64) -> Result<Vec<i64>, ServiceError> {
        self.user_repo
            .base()
            .find_by_id(operator_user_id)
            .await
            .map(|u| u.and_then(|u| u.dept_id).map(|d| vec![d]).unwrap_or_default())
            .map_err(ServiceError::from)
    }

    /// 保存部门排序（批量更新 order_num）
    ///
    /// 前端传入逗号分隔的 dept_ids 和 order_nums，事务内逐条更新。
    pub async fn update_dept_sort(
        &self,
        dto: DeptSortDto,
        operator: &str,
    ) -> Result<(), ServiceError> {
        crate::common::i18n::validate(&dto)?;

        // 解析逗号分隔的 dept_ids 和 order_nums
        let dept_ids: Vec<i64> = parse_id_list::<i64>(&dto.dept_ids);
        let order_nums: Vec<i32> = parse_id_list::<i32>(&dto.order_nums);

        if dept_ids.is_empty() || order_nums.is_empty() {
            return Err(ServiceError::bad_request(&crate::tr!("error.dept.ids_empty")));
        }
        if dept_ids.len() != order_nums.len() {
            return Err(ServiceError::bad_request(
                &crate::tr!("error.dept.ids_count_mismatch"),
            ));
        }

        let now = crate::common::datetime::now_naive();
        let operator = operator.to_string();
        let dept_repo = self.dept_repo.clone();
        self.db()
            .transaction::<_, (), sea_orm::DbErr>(|txn| {
                let dept_ids = dept_ids.clone();
                let order_nums = order_nums.clone();
                let operator = operator.clone();
                async move {
                    for (dept_id, order_num) in dept_ids.iter().zip(order_nums.iter()) {
                        // 直接 UPDATE order_num：未匹配到记录时 affected_rows=0，
                        // 等价于原 find_by_id 后 continue 的 silent skip 行为，
                        // 同时避免"先查完整实体再保存全行"的两轮 DB 往返。
                        dept_repo
                            .update_sort_conn(txn, *dept_id, *order_num, &operator, now)
                            .await?;
                    }
                    Ok(())
                }
                .boxed()
            })
            .await?;

        Ok(())
    }

    /// 排除指定节点及其子部门的部门列表（修改部门时选择父部门用）
    ///
    /// 排除 dept_id 本身 + 其所有后代（ancestors 中包含 dept_id 的部门）。
    /// P0-6：`operator_user_id` 传入时先应用 data_scope 过滤（超管/全部数据不限制），
    /// 防止低权限管理员通过本端点枚举全部部门结构（此前与 list 的数据范围不一致）。
    pub async fn list_exclude(
        &self,
        dept_id: i64,
        operator_user_id: Option<i64>,
    ) -> Result<Vec<SysDeptModel>, ServiceError> {
        // 数据范围过滤后的可见部门
        let visible_ids: Option<Vec<i64>> = match operator_user_id {
            Some(uid) => self.resolve_scope_dept_ids(uid).await?,
            None => None, // 无操作人上下文（如内部调用）：不过滤，保持原行为
        };
        let all = self.dept_repo.find_active_all().await?;
        // 收集要排除的 ID：dept_id 本身 + 后代部门
        let result: Vec<SysDeptModel> = all
            .into_iter()
            .filter(|d| {
                // data_scope 限制：不在可见集合内的部门直接过滤（visible_ids 为 None 表示全部可见）
                if let Some(ref ids) = visible_ids
                    && !ids.contains(&d.dept_id)
                {
                    return false;
                }
                if d.dept_id == dept_id {
                    return false;
                }
                // 后代判定：ancestors 中包含 dept_id
                d.ancestors
                    .as_ref()
                    .map(|a| ancestor_contains(a, dept_id))
                    .unwrap_or(false)
            })
            .collect();
        Ok(result)
    }

    /// 部门详情
    ///
    /// P0-6：`operator_user_id` 传入时校验部门是否在数据范围内，不在则视为不存在
    /// （返回 404 而非 403，避免暴露部门存在性）。
    pub async fn get_dept_by_id(
        &self,
        dept_id: i64,
        operator_user_id: Option<i64>,
    ) -> Result<SysDeptModel, ServiceError> {
        let dept = self
            .dept_repo
            .base()
            .find_by_id(dept_id)
            .await?
            .ok_or_else(|| ServiceError::not_found(&crate::tr!("error.dept.not_found")))?;
        if dept.del_flag.as_deref() == Some("2") {
            return Err(ServiceError::not_found(&crate::tr!("error.dept.not_found")));
        }
        // 数据范围校验（P0-6）
        if let Some(uid) = operator_user_id
            && uid != SUPER_ADMIN_USER_ID
        {
            let scope_ids = self.resolve_scope_dept_ids(uid).await?;
            if let Some(ref ids) = scope_ids
                && !ids.contains(&dept_id)
            {
                return Err(ServiceError::not_found(&crate::tr!("error.dept.not_found")));
            }
        }
        Ok(dept)
    }

    /// 新增部门（校验父部门存在，自动计算 ancestors）
    ///
    /// ancestors 计算：
    /// - parent_id = 0 → ancestors = "0"
    /// - parent_id != 0 → ancestors = "{parent.ancestors},{parent_id}"
    pub async fn add_dept(
        &self,
        dto: DeptAddDto,
        operator: &str,
    ) -> Result<SysDeptModel, ServiceError> {
        crate::common::i18n::validate(&dto)?;

        let parent_id = dto.parent_id.unwrap_or(0);
        // 计算祖先链
        let ancestors = if parent_id == 0 {
            "0".to_string()
        } else {
            let parent = self
                .dept_repo
                .base()
                .find_by_id(parent_id)
                .await?
                .ok_or_else(|| ServiceError::bad_request(&crate::tr!("error.dept.parent_not_found")))?;
            if parent.del_flag.as_deref() == Some("2") {
                return Err(ServiceError::bad_request(&crate::tr!("error.dept.parent_deleted")));
            }
            format!(
                "{},{}",
                parent.ancestors.as_deref().unwrap_or("0"),
                parent_id
            )
        };

        let now = crate::common::datetime::now_naive();
        let mut am = SysDeptActiveModel {
            ..Default::default()
        };
        am.parent_id = Set(Some(parent_id));
        am.ancestors = Set(Some(ancestors));
        am.dept_name = Set(dto.dept_name.clone());
        am.order_num = Set(dto.order_num);
        am.leader = Set(dto.leader.clone());
        am.phone = Set(dto.phone.clone());
        am.email = Set(dto.email.clone());
        am.status = Set(dto.status.clone().or_else(|| Some("0".to_string())));
        am.create_by = Set(Some(operator.to_string()));
        am.create_time = Set(Some(now));
        am.update_by = Set(Some(operator.to_string()));
        am.update_time = Set(Some(now));
        am.del_flag = Set(Some("0".to_string()));

        let new_dept = self.dept_repo.insert(am).await?;
        Ok(new_dept)
    }

    /// 修改部门（校验父部门存在 + 防环，父部门变更时递归更新子部门 ancestors）
    ///
    /// 使用事务保证部门自身更新与子部门 ancestors 更新的原子性。
    pub async fn edit_dept(
        &self,
        dto: DeptEditDto,
        operator: &str,
    ) -> Result<SysDeptModel, ServiceError> {
        crate::common::i18n::validate(&dto)?;

        // 查询现有部门
        let existing = self
            .dept_repo
            .base()
            .find_by_id(dto.dept_id)
            .await?
            .ok_or_else(|| ServiceError::not_found(&crate::tr!("error.dept.not_found")))?;
        if existing.del_flag.as_deref() == Some("2") {
            return Err(ServiceError::not_found(&crate::tr!("error.dept.not_found")));
        }

        // parent_id 校验
        let parent_id = dto.parent_id.unwrap_or(existing.parent_id.unwrap_or(0));
        if parent_id == dto.dept_id {
            return Err(ServiceError::bad_request(&crate::tr!("error.dept.parent_self_forbidden")));
        }

        // 计算新祖先链 + 校验父部门存在 + 防环
        let new_ancestors = if parent_id == 0 {
            "0".to_string()
        } else {
            let parent = self
                .dept_repo
                .base()
                .find_by_id(parent_id)
                .await?
                .ok_or_else(|| ServiceError::bad_request(&crate::tr!("error.dept.parent_not_found")))?;
            if parent.del_flag.as_deref() == Some("2") {
                return Err(ServiceError::bad_request(&crate::tr!("error.dept.parent_deleted")));
            }
            // 防环校验：新 parent_id 不能是当前部门的后代节点
            if self.is_descendant(dto.dept_id, parent_id).await? {
                return Err(ServiceError::bad_request(
                    &crate::tr!("error.dept.parent_self_forbidden"),
                ));
            }
            format!(
                "{},{}",
                parent.ancestors.as_deref().unwrap_or("0"),
                parent_id
            )
        };

        let old_ancestors = existing.ancestors.clone().unwrap_or_else(|| "0".to_string());
        let ancestors_changed = new_ancestors != old_ancestors;

        let now = crate::common::datetime::now_naive();
        let dept_id = dto.dept_id;
        let dept_repo = self.dept_repo.clone();

        // 提取 DTO 字段为独立变量（避免在闭包中借用 dto）
        let dept_name = dto.dept_name.clone();
        let order_num = dto.order_num;
        let leader = dto.leader.clone();
        let phone = dto.phone.clone();
        let email = dto.email.clone();
        let status = dto.status.clone();
        let operator_owned = operator.to_string();

        // 事务：更新部门自身 + 父部门变更时递归更新子部门 ancestors
        let updated = self
            .db()
            .transaction::<_, SysDeptModel, sea_orm::DbErr>(|txn| {
                // 克隆闭包捕获值（支持事务重试语义）
                let dept_repo = dept_repo.clone();
                let old_ancestors = old_ancestors.clone();
                let new_ancestors = new_ancestors.clone();
                let dept_name = dept_name.clone();
                let leader = leader.clone();
                let phone = phone.clone();
                let email = email.clone();
                let status = status.clone();
                let operator_owned = operator_owned.clone();
                let existing_clone = existing.clone();
                async move {
                    let mut am: SysDeptActiveModel = existing_clone.into();
                    am.parent_id = Set(Some(parent_id));
                    am.ancestors = Set(Some(new_ancestors.clone()));
                    if let Some(ref name) = dept_name {
                        am.dept_name = Set(name.clone());
                    }
                    if let Some(order) = order_num {
                        am.order_num = Set(Some(order));
                    }
                    if let Some(ref l) = leader {
                        am.leader = Set(Some(l.clone()));
                    }
                    if let Some(ref p) = phone {
                        am.phone = Set(Some(p.clone()));
                    }
                    if let Some(ref e) = email {
                        am.email = Set(Some(e.clone()));
                    }
                    if let Some(ref s) = status {
                        am.status = Set(Some(s.clone()));
                    }
                    am.update_by = Set(Some(operator_owned.clone()));
                    am.update_time = Set(Some(now));

                    let updated = dept_repo.base().update_conn(txn, am).await?;

                    // 父部门变更：递归更新子部门 ancestors
                    if ancestors_changed {
                        update_children_ancestors_conn(
                            txn,
                            &dept_repo,
                            dept_id,
                            &old_ancestors,
                            &new_ancestors,
                        )
                        .await?;
                    }
                    Ok(updated)
                }
                .boxed()
            })
            .await?;
        Ok(updated)
    }

    /// 删除部门（事务：TOCTOU 防护 + 级联校验 + 软删除）
    ///
    /// P0-H4 TOCTOU 修复：所有校验和软删除放入单个事务，避免事务外预检查后
    /// 被其他事务插入新关联（如新用户绑定此部门）导致数据不一致。
    ///
    /// 删除前置校验（事务内）：
    /// 1. 无子部门（del_flag = '0' 的直接子部门）
    /// 2. 无角色关联（sys_role_dept 中无关联记录）
    /// 3. 无用户关联（sys_user.dept_id 指向此部门的未删除用户）
    pub async fn delete_dept(&self, dept_id: i64) -> Result<(), ServiceError> {
        let existing = self
            .dept_repo
            .base()
            .find_by_id(dept_id)
            .await?
            .ok_or_else(|| ServiceError::not_found(&crate::tr!("error.dept.not_found")))?;
        if existing.del_flag.as_deref() == Some("2") {
            return Err(ServiceError::not_found(&crate::tr!("error.dept.not_found")));
        }

        let dept_repo = self.dept_repo.clone();
        let user_repo = self.user_repo.clone();
        // P0-H4 TOCTOU 修复：将所有校验和软删除放入事务内
        let txn_result = self
            .db()
            .transaction::<_, (), sea_orm::DbErr>(|txn| {
                let dept_repo = dept_repo.clone();
                let user_repo = user_repo.clone();
                async move {
                    // 1. 事务内重新检查子部门
                    let child_select = SysDept::find()
                        .filter(DeptColumn::ParentId.eq(dept_id))
                        .filter(DeptColumn::DelFlag.eq("0"));
                    let child_count = dept_repo.base().find_many_conn(txn, child_select).await?.len() as u64;
                    if child_count > 0 {
                        return Err(sea_orm::DbErr::Custom(
                            crate::tr!("error.dept.has_children"),
                        ));
                    }

                    // 2. 事务内重新检查角色关联
                    let role_count = SysRoleDept::find()
                        .filter(RoleDeptColumn::DeptId.eq(dept_id))
                        .all(txn)
                        .await?
                        .len() as u64;
                    if role_count > 0 {
                        return Err(sea_orm::DbErr::Custom(
                            crate::tr!("error.dept.assigned_to_role"),
                        ));
                    }

                    // 3. 事务内重新检查用户关联
                    let user_select = SysUser::find()
                        .filter(UserColumn::DeptId.eq(dept_id))
                        .filter(UserColumn::DelFlag.eq("0"));
                    let user_count = user_repo.base().find_many_conn(txn, user_select).await?.len() as u64;
                    if user_count > 0 {
                        return Err(sea_orm::DbErr::Custom(
                            crate::tr!("error.dept.has_users"),
                        ));
                    }

                    // 4. 软删除（del_flag = '2'）
                    let mut am: SysDeptActiveModel = existing.into();
                    am.del_flag = Set(Some("2".to_string()));
                    dept_repo.base().update_conn(txn, am).await?;

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

    /// 部门下拉树（TreeSelect 格式，对齐前端 treeselect 接口）
    ///
    /// 返回 `{ id, label, disabled, children }` 结构，用于下拉选择场景。
    /// disabled = status != "0"（停用状态禁用选择）。
    /// P0-6：`operator_user_id` 传入时先应用 data_scope 过滤，防止旁路枚举全部部门。
    pub async fn build_dept_tree_select(
        &self,
        operator_user_id: Option<i64>,
    ) -> Result<Vec<TreeSelectVo>, ServiceError> {
        let list = match operator_user_id {
            Some(uid) => {
                // 复用 list_depts 的数据范围过滤（空 query）
                self.list_depts(DeptQueryDto::default(), Some(uid)).await?
            }
            None => self.dept_repo.find_active_all().await?,
        };
        let tree = build_dept_tree_select(&list, 0);
        Ok(tree)
    }

    /// 根据 user_id 查询用户所属部门名称（操作日志中间件用）
    ///
    /// 流程：sys_user.dept_id → sys_dept.dept_name
    /// 用户或部门不存在时返回空字符串（不阻断日志写入）
    pub async fn get_dept_name_by_user_id(
        &self,
        user_id: i64,
    ) -> Result<String, ServiceError> {
        use crate::entity::sys_user::Entity as SysUser;

        // 1. 查询用户的 dept_id
        let user = SysUser::find_by_id(user_id)
            .one(self.db())
            .await
            .map_err(ServiceError::from)?;
        let Some(user) = user else {
            return Ok(String::new());
        };
        let Some(dept_id) = user.dept_id else {
            return Ok(String::new());
        };

        // 2. 查询部门名称
        let dept = self.dept_repo.base().find_by_id(dept_id).await?;
        match dept {
            Some(d) if d.del_flag.as_deref() != Some("2") => {
                Ok(d.dept_name)
            }
            _ => Ok(String::new()),
        }
    }

    // ==================== 内部辅助方法 ====================

    /// 防环校验：判断 candidate_parent_id 是否是 dept_id 的后代节点
    ///
    /// N+1 优化：利用 sys_dept.ancestors 字段（CSV 格式 "0,100,101"），
    /// 一次查询 candidate_parent_id 的记录，检查其 ancestors 是否包含 dept_id。
    /// 若包含，则 candidate_parent_id 是 dept_id 的后代，形成环。
    /// 复杂度从 O(N) 次 DB 查询降为 O(1)。
    async fn is_descendant(
        &self,
        dept_id: i64,
        candidate_parent_id: i64,
    ) -> Result<bool, ServiceError> {
        if candidate_parent_id == 0 {
            return Ok(false);
        }
        if candidate_parent_id == dept_id {
            return Ok(true);
        }
        // O(1) 查询：读取 candidate_parent_id 的 ancestors 字段
        let dept = self
            .dept_repo
            .base()
            .find_by_id(candidate_parent_id)
            .await?
            .ok_or_else(|| {
                ServiceError::not_found(&crate::tr!(
                    "error.dept.id_not_found",
                    id = candidate_parent_id
                ))
            })?;
        // ancestors 字段包含 candidate_parent_id 的所有祖先 ID
        // 若 dept_id 在其中，说明 candidate_parent_id 是 dept_id 的后代
        if let Some(ref ancestors) = dept.ancestors
            && ancestor_contains(ancestors, dept_id)
        {
            return Ok(true);
        }
        // ancestors 不包含 dept_id，或者 ancestors 为空（根节点）
        Ok(false)
    }
}

// ==================== 模块级辅助函数 ====================

/// 判断 ancestors 字符串中是否包含指定的部门 ID
///
/// ancestors 格式: "0,100,101"
fn ancestor_contains(ancestors: &str, id: i64) -> bool {
    ancestors
        .split(',')
        .filter_map(|s| s.trim().parse::<i64>().ok())
        .any(|x| x == id)
}

/// 递归更新子部门 ancestors（父部门变更时调用，事务上下文）
///
/// 找出所有 ancestors 中包含 dept_id 的后代部门，
/// 将其 ancestors 中的 old_ancestors 前缀替换为 new_ancestors。
///
/// DB-25：使用单条 SQL 批量更新后代部门的 ancestors，消除 N+1 查询。
///
/// 原实现先 SELECT 后循环 UPDATE（N 个后代 = N+1 次 DB 交互），
/// 现改为单条 UPDATE ... REPLACE() 完成，性能从 O(N) 降为 O(1)。
///
/// 多数据库兼容：
/// - MySQL：使用 CONCAT 拼接前后逗号 + REPLACE 函数
/// - PostgreSQL / SQLite：使用 `||` 字符串连接符 + REPLACE 函数
///
/// 通过在 ancestors 前后加逗号后 LIKE `%,dept_id,%`，确保精确匹配 ID
/// （避免 "1" 误匹配 "100"、"11" 等）。
async fn update_children_ancestors_conn<C: ConnectionTrait>(
    conn: &C,
    _dept_repo: &SysDeptRepository,
    dept_id: i64,
    old_ancestors: &str,
    new_ancestors: &str,
) -> Result<(), sea_orm::DbErr> {
    let backend = conn.get_database_backend();
    let pattern = format!("%,{},%", dept_id);
    // 单条 UPDATE + REPLACE 批量替换 ancestors 中的 old → new
    let sql = match backend {
        DatabaseBackend::MySql => r#"UPDATE sys_dept
            SET ancestors = REPLACE(ancestors, ?, ?)
            WHERE del_flag = '0' AND dept_id <> ? AND CONCAT(',', ancestors, ',') LIKE ?"#,
        _ => r#"UPDATE sys_dept
            SET ancestors = REPLACE(ancestors, $1, $2)
            WHERE del_flag = '0' AND dept_id <> $3 AND (',' || ancestors || ',') LIKE $4"#,
    };
    let stmt = Statement::from_sql_and_values(
        backend,
        sql,
        [old_ancestors.into(), new_ancestors.into(), dept_id.into(), pattern.into()],
    );
    conn.execute(stmt).await?;
    Ok(())
}
