//! 部门模块 Service 层
//!
//! 职责：
//! - 部门 CRUD、ancestors 祖先链维护、树形结构组装
//! - 不依赖任何 Web 框架类型（axum / tower / tower-http）
//! - 多表操作使用 SeaORM 事务保证一致性
//! - 参数校验使用 validator crate
//! - 数据访问通过 Repository 层委托

use futures::future::FutureExt;
use sea_orm::{
    ColumnTrait, ConnectionTrait, DatabaseBackend, DatabaseConnection, EntityTrait, FromQueryResult,
    QueryFilter, Set, Statement, TransactionTrait,
};
use serde::Deserialize;
use utoipa::{IntoParams, ToSchema};
use validator::Validate;

use crate::common::error::ServiceError;
use crate::common::constants::SUPER_ADMIN_USER_ID;
use crate::common::{like_escape, TreeSelectVo};
use crate::entity::sys_dept::{
    ActiveModel as SysDeptActiveModel, Column as DeptColumn, Entity as SysDept, Model as SysDeptModel,
};
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
    #[validate(range(min = 0, message = "父部门 ID 不能为负数"))]
    pub parent_id: Option<i64>,
    #[validate(length(min = 2, max = 30, message = "部门名称长度必须在2-30之间"))]
    pub dept_name: String,
    #[validate(range(min = 0, max = 999, message = "显示顺序必须在0-999之间"))]
    pub order_num: Option<i32>,
    #[validate(length(min = 1, max = 20, message = "负责人长度必须在1-20之间"))]
    pub leader: Option<String>,
    #[validate(length(min = 1, max = 11, message = "联系电话长度必须在1-11之间"))]
    pub phone: Option<String>,
    #[validate(length(max = 50, message = "邮箱长度不能超过50"))]
    #[validate(email(message = "邮箱格式不正确"))]
    pub email: Option<String>,
    #[validate(length(min = 1, max = 1, message = "状态值不合法"))]
    pub status: Option<String>,
}

/// 修改部门 DTO（同 Add + dept_id，字段均可选以支持部分更新）
#[derive(Debug, Deserialize, Validate, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct DeptEditDto {
    pub dept_id: i64,
    #[validate(range(min = 0, message = "父部门 ID 不能为负数"))]
    pub parent_id: Option<i64>,
    #[validate(length(min = 2, max = 30, message = "部门名称长度必须在2-30之间"))]
    pub dept_name: Option<String>,
    #[validate(range(min = 0, max = 999, message = "显示顺序必须在0-999之间"))]
    pub order_num: Option<i32>,
    #[validate(length(min = 1, max = 20, message = "负责人长度必须在1-20之间"))]
    pub leader: Option<String>,
    #[validate(length(min = 1, max = 11, message = "联系电话长度必须在1-11之间"))]
    pub phone: Option<String>,
    #[validate(length(max = 50, message = "邮箱长度不能超过50"))]
    #[validate(email(message = "邮箱格式不正确"))]
    pub email: Option<String>,
    #[validate(length(min = 1, max = 1, message = "状态值不合法"))]
    pub status: Option<String>,
}

/// 部门排序 DTO（对齐前端 DeptSortParams：deptIds/orderNums 逗号分隔字符串）
#[derive(Debug, Deserialize, Validate, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct DeptSortDto {
    #[validate(length(min = 1, message = "deptIds 不能为空"))]
    pub dept_ids: String,
    #[validate(length(min = 1, message = "orderNums 不能为空"))]
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

        // 数据权限过滤（P0-R81-004）
        if let Some(op_uid) = operator_user_id {
            // 超管短路
            if op_uid != SUPER_ADMIN_USER_ID {
                let op_roles = self.role_repo.find_by_user_id(op_uid).await?;
                let min_scope = op_roles
                    .iter()
                    .filter_map(|r| r.data_scope.as_deref())
                    .filter_map(|s| s.parse::<i32>().ok())
                    .min();

                let scope_dept_ids: Option<Vec<i64>> = if let Some(scope) = min_scope {
                    match scope {
                        1 => None, // 全部数据：不追加过滤
                        2 => {
                            // 自定义：聚合 operator 所有角色的 sys_role_dept 部门
                            // P0-R81-004 暂缓项：N+1 改批量查询，单次 SQL 完成
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
                            let op_user = self.user_repo.base().find_by_id(op_uid).await?;
                            op_user
                                .and_then(|u| u.dept_id)
                                .map(|d| vec![d])
                                .or_else(|| Some(vec![]))
                        }
                        4 => {
                            // 本部门及以下：operator.dept_id + 所有后代部门
                            // P0-R81-004 暂缓项：递归 CTE 替代全表扫描 + 内存过滤 ancestors CSV
                            let op_user = self.user_repo.base().find_by_id(op_uid).await?;
                            let op_dept_id = op_user.and_then(|u| u.dept_id).unwrap_or(0);
                            Some(self.dept_repo.find_descendant_ids(op_dept_id).await?)
                        }
                        _ => {
                            // 未知 data_scope 值，安全失败：限定为 operator.dept_id
                            let op_user = self.user_repo.base().find_by_id(op_uid).await?;
                            op_user
                                .and_then(|u| u.dept_id)
                                .map(|d| vec![d])
                                .or_else(|| Some(vec![]))
                        }
                    }
                } else {
                    // operator 无角色或 data_scope 缺失：安全失败，限定为 operator.dept_id
                    let op_user = self.user_repo.base().find_by_id(op_uid).await?;
                    op_user
                        .and_then(|u| u.dept_id)
                        .map(|d| vec![d])
                        .or_else(|| Some(vec![]))
                };

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
        }

        let list = self.dept_repo.base().find_many(select).await?;
        Ok(list)
    }

    /// 保存部门排序（批量更新 order_num）
    ///
    /// 前端传入逗号分隔的 dept_ids 和 order_nums，事务内逐条更新。
    pub async fn update_dept_sort(
        &self,
        dto: DeptSortDto,
        operator: &str,
    ) -> Result<(), ServiceError> {
        dto.validate()?;

        // 解析逗号分隔的 dept_ids 和 order_nums
        let dept_ids: Vec<i64> = parse_id_list::<i64>(&dto.dept_ids);
        let order_nums: Vec<i32> = parse_id_list::<i32>(&dto.order_nums);

        if dept_ids.is_empty() || order_nums.is_empty() {
            return Err(ServiceError::bad_request("deptIds/orderNums 解析后为空"));
        }
        if dept_ids.len() != order_nums.len() {
            return Err(ServiceError::bad_request(
                "deptIds 与 orderNums 数量不一致",
            ));
        }

        let now = chrono::Local::now().naive_local();
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
    /// 排除 dept_id 本身 + 其所有后代（ancestors 中包含 dept_id 的部门）
    pub async fn list_exclude(&self, dept_id: i64) -> Result<Vec<SysDeptModel>, ServiceError> {
        let all = self.dept_repo.find_active_all().await?;
        // 收集要排除的 ID：dept_id 本身 + 后代部门
        let result: Vec<SysDeptModel> = all
            .into_iter()
            .filter(|d| {
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
    pub async fn get_dept_by_id(&self, dept_id: i64) -> Result<SysDeptModel, ServiceError> {
        let dept = self
            .dept_repo
            .base()
            .find_by_id(dept_id)
            .await?
            .ok_or_else(|| ServiceError::not_found("部门不存在"))?;
        if dept.del_flag.as_deref() == Some("2") {
            return Err(ServiceError::not_found("部门不存在"));
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
        dto.validate()?;

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
                .ok_or_else(|| ServiceError::bad_request("父部门不存在"))?;
            if parent.del_flag.as_deref() == Some("2") {
                return Err(ServiceError::bad_request("父部门已删除"));
            }
            format!(
                "{},{}",
                parent.ancestors.as_deref().unwrap_or("0"),
                parent_id
            )
        };

        let now = chrono::Local::now().naive_local();
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
        dto.validate()?;

        // 查询现有部门
        let existing = self
            .dept_repo
            .base()
            .find_by_id(dto.dept_id)
            .await?
            .ok_or_else(|| ServiceError::not_found("部门不存在"))?;
        if existing.del_flag.as_deref() == Some("2") {
            return Err(ServiceError::not_found("部门不存在"));
        }

        // parent_id 校验
        let parent_id = dto.parent_id.unwrap_or(existing.parent_id.unwrap_or(0));
        if parent_id == dto.dept_id {
            return Err(ServiceError::bad_request("上级部门不能选择自己"));
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
                .ok_or_else(|| ServiceError::bad_request("父部门不存在"))?;
            if parent.del_flag.as_deref() == Some("2") {
                return Err(ServiceError::bad_request("父部门已删除"));
            }
            // 防环校验：新 parent_id 不能是当前部门的后代节点
            if self.is_descendant(dto.dept_id, parent_id).await? {
                return Err(ServiceError::bad_request(
                    "上级部门不能选择自己的子部门，否则会形成环路",
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

        let now = chrono::Local::now().naive_local();
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

    /// 删除部门（校验子部门 + 角色关联，软删除）
    ///
    /// 删除前置校验：
    /// 1. 无子部门（del_flag = '0' 的直接子部门）
    /// 2. 无角色关联（sys_role_dept 中无关联记录）
    pub async fn delete_dept(&self, dept_id: i64) -> Result<(), ServiceError> {
        let existing = self
            .dept_repo
            .base()
            .find_by_id(dept_id)
            .await?
            .ok_or_else(|| ServiceError::not_found("部门不存在"))?;
        if existing.del_flag.as_deref() == Some("2") {
            return Err(ServiceError::not_found("部门不存在"));
        }

        // 子部门校验
        let child_select = SysDept::find()
            .filter(DeptColumn::ParentId.eq(dept_id))
            .filter(DeptColumn::DelFlag.eq("0"));
        let child_count = self.dept_repo.base().find_many(child_select).await?.len() as u64;
        if child_count > 0 {
            return Err(ServiceError::bad_request("存在子部门，不允许删除"));
        }

        // 角色关联校验
        let role_count = self.role_dept_repo.find_by_dept_id(dept_id).await?.len() as u64;
        if role_count > 0 {
            return Err(ServiceError::bad_request("部门已分配给角色，不允许删除"));
        }

        // 软删除（del_flag = '2'）
        self.dept_repo.soft_delete(dept_id).await?;
        Ok(())
    }

    /// 部门下拉树（TreeSelect 格式，对齐前端 treeselect 接口）
    ///
    /// 返回 `{ id, label, disabled, children }` 结构，用于下拉选择场景。
    /// disabled = status != "0"（停用状态禁用选择）。
    pub async fn build_dept_tree_select(&self) -> Result<Vec<TreeSelectVo>, ServiceError> {
        let list = self.dept_repo.find_active_all().await?;
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
    /// 算法：从 candidate_parent_id 向上遍历祖先链，
    /// 若在祖先链中遇到 dept_id，说明 candidate_parent_id 是 dept_id 的后代，形成环。
    async fn is_descendant(
        &self,
        dept_id: i64,
        candidate_parent_id: i64,
    ) -> Result<bool, ServiceError> {
        let mut current = candidate_parent_id;
        // 防御性上限：部门层级通常不超过 10 层，这里给 100 层兜底
        for _ in 0..100 {
            if current == 0 {
                return Ok(false);
            }
            if current == dept_id {
                return Ok(true);
            }
            // 查询 current 的 parent_id
            let dept = self
                .dept_repo
                .base()
                .find_by_id(current)
                .await?
                .ok_or_else(|| {
                    ServiceError::not_found(&format!("部门 ID={} 不存在", current))
                })?;
            let next = dept.parent_id.unwrap_or(0);
            if next == current {
                // 异常数据自环，退出避免死循环
                return Ok(false);
            }
            current = next;
        }
        // 超过 100 层仍未回到根，视为异常
        // 状态码：400 Bad Request（客户端提交了循环引用的 parentId）
        Err(ServiceError::bad_request("部门层级过深，防环校验失败"))
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
/// DB-25：原实现加载全表后内存过滤 ancestors CSV，改为 SQL 层 LIKE 过滤，
/// 仅查询实际需要更新的后代部门，减少数据传输和内存开销。
///
/// 多数据库兼容：
/// - MySQL：使用 CONCAT 拼接前后逗号（MySQL 默认 `||` 是逻辑 OR）
/// - PostgreSQL / SQLite：使用 `||` 字符串连接符（标准 SQL）
///
/// 通过在 ancestors 前后加逗号后 LIKE `%,dept_id,%`，确保精确匹配 ID
/// （避免 "1" 误匹配 "100"、"11" 等）。
async fn update_children_ancestors_conn<C: ConnectionTrait>(
    conn: &C,
    dept_repo: &SysDeptRepository,
    dept_id: i64,
    old_ancestors: &str,
    new_ancestors: &str,
) -> Result<(), sea_orm::DbErr> {
    let backend = conn.get_database_backend();
    let pattern = format!("%,{},%", dept_id);
    // 占位符差异：MySQL 使用 `?`，PostgreSQL/SQLite 使用 `$N`
    let sql = match backend {
        DatabaseBackend::MySql => r#"SELECT * FROM sys_dept
            WHERE del_flag = '0' AND dept_id <> ? AND CONCAT(',', ancestors, ',') LIKE ?"#,
        _ => r#"SELECT * FROM sys_dept
            WHERE del_flag = '0' AND dept_id <> $1 AND (',' || ancestors || ',') LIKE $2"#,
    };
    let stmt = Statement::from_sql_and_values(
        backend,
        sql,
        [dept_id.into(), pattern.into()],
    );
    let descendants = SysDeptModel::find_by_statement(stmt).all(conn).await?;

    for child in descendants {
        let Some(ref child_ancestors) = child.ancestors else {
            continue;
        };
        // 替换 old_ancestors 前缀为 new_ancestors
        let new_child_ancestors = child_ancestors.replace(old_ancestors, new_ancestors);
        if new_child_ancestors == *child_ancestors {
            continue;
        }
        let mut am: SysDeptActiveModel = child.into();
        am.ancestors = Set(Some(new_child_ancestors));
        dept_repo.base().update_conn(conn, am).await?;
    }
    Ok(())
}
