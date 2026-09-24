// axum-backend/src/service/sys_tenant_service.rs
//! 租户管理服务（多租户 Phase 2 立项实施，2026-09-25 福哥拍板"现在立项"）
//!
//! 数据模型（立项定案第 2 条）：**dept 树根 = 租户**——不建独立 sys_tenant 表，
//! 租户 = `sys_dept` 中 `parent_id = 0` 的顶层部门（平台根 `PLATFORM_ROOT_DEPT_ID`
//! 除外）。租户的用户通过 `sys_user.tenant_id`（= 根部门 dept_id，平台用户恒 0）
//! 归属，由用户管理链路联动写入（sys_user_service `resolve_user_tenant`）。
//!
//! 平台租户 tid=0：跨租户运营语义（common/tenant.rs 过滤语义：tid=0 不过滤）。

use chrono::NaiveDateTime;
use sea_orm::*;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::common::like_escape;
use crate::common::ServiceError;
use crate::entity::sys_dept::{self, Column as DeptColumn, Entity as SysDept};
use crate::repository::sys_dept::SysDeptRepository;
use crate::repository::sys_user::SysUserRepository;

/// 平台根部门 ID（m20250711 init 种子"若依科技"，RuoYi 系约定；其下用户 tid=0）
pub const PLATFORM_ROOT_DEPT_ID: i64 = 100;

/// 租户视图（根部门 + 用户统计）
#[derive(Debug, Clone, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
#[schema(as = TenantVo)]
pub struct TenantVo {
    pub dept_id: i64,
    pub tenant_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub leader: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub phone: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub order_num: Option<i32>,
    /// 租户内用户数（sys_user.tenant_id = 根 dept_id 且未删除）
    pub user_count: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub create_time: Option<NaiveDateTime>,
}

/// 租户查询入参（名称模糊）
#[derive(Debug, Clone, Deserialize, ToSchema, utoipa::IntoParams)]
#[serde(rename_all = "camelCase")]
#[into_params(parameter_in = Query)]
pub struct TenantQueryDto {
    #[serde(default)]
    pub tenant_name: Option<String>,
}

/// 租户新增入参
#[derive(Debug, Clone, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct TenantAddDto {
    pub tenant_name: String,
    #[serde(default)]
    pub leader: Option<String>,
    #[serde(default)]
    pub phone: Option<String>,
    #[serde(default)]
    pub email: Option<String>,
    #[serde(default)]
    pub order_num: Option<i32>,
    /// '0' 正常 / '1' 停用
    #[serde(default)]
    pub status: Option<String>,
}

/// 租户修改入参
#[derive(Debug, Clone, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct TenantEditDto {
    pub dept_id: i64,
    pub tenant_name: String,
    #[serde(default)]
    pub leader: Option<String>,
    #[serde(default)]
    pub phone: Option<String>,
    #[serde(default)]
    pub email: Option<String>,
    #[serde(default)]
    pub order_num: Option<i32>,
}

/// 租户启停入参
#[derive(Debug, Clone, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct TenantStatusDto {
    pub dept_id: i64,
    /// '0' 正常 / '1' 停用（停用后该租户用户无法登录）
    pub status: String,
}

/// 租户管理服务
#[derive(Clone)]
pub struct SysTenantService {
    dept_repo: SysDeptRepository,
    user_repo: SysUserRepository,
}

impl SysTenantService {
    pub fn new(db: DatabaseConnection) -> Self {
        Self {
            dept_repo: SysDeptRepository::new(db.clone()),
            user_repo: SysUserRepository::new(db),
        }
    }

    /// 租户是否为平台根（平台根不允许通过租户接口修改/停用/删除）
    fn ensure_not_platform_root(dept_id: i64) -> Result<(), ServiceError> {
        if dept_id == PLATFORM_ROOT_DEPT_ID {
            return Err(ServiceError::bad_request(&crate::tr!(
                "error.tenant.platform_protected"
            )));
        }
        Ok(())
    }

    /// 租户归属校验：平台操作者（tid=0）放行任意租户；租户操作者仅能
    /// 访问/操作本租户（dept_id == tid）。用于租户接口的越权防护。
    fn ensure_tenant_access(operator_tid: i64, dept_id: i64) -> Result<(), ServiceError> {
        if crate::common::tenant::tenant_allowed(operator_tid, dept_id) {
            Ok(())
        } else {
            Err(ServiceError::forbidden(&crate::tr!(
                "error.common.forbidden"
            )))
        }
    }

    /// 租户列表（parent_id=0 的顶层部门，排除平台根；tenant_name 模糊过滤）
    ///
    /// 多租户：tenant_scope 为 Some(tid)（租户操作者）时仅返回本租户根，
    /// 防止 common 只读权限（菜单 3700）跨租户窥探租户名录。
    pub async fn list(
        &self,
        q: TenantQueryDto,
        tenant_scope: Option<i64>,
    ) -> Result<Vec<TenantVo>, ServiceError> {
        let mut query = SysDept::find()
            .filter(DeptColumn::ParentId.eq(0))
            .filter(DeptColumn::DelFlag.eq("0"))
            .filter(DeptColumn::DeptId.ne(PLATFORM_ROOT_DEPT_ID));
        if let Some(tid) = tenant_scope {
            query = query.filter(DeptColumn::DeptId.eq(tid));
        }
        if let Some(name) = q.tenant_name.as_deref().filter(|s| !s.is_empty()) {
            query = query.filter(DeptColumn::DeptName.like(format!("%{}%", like_escape(name))));
        }
        let roots = query
            .order_by_asc(DeptColumn::OrderNum)
            .order_by_asc(DeptColumn::DeptId)
            .all(self.dept_repo.base().db())
            .await?;
        let mut vos = Vec::with_capacity(roots.len());
        for root in roots {
            let user_count = self.count_tenant_users(root.dept_id).await?;
            vos.push(TenantVo {
                dept_id: root.dept_id,
                tenant_name: root.dept_name,
                leader: root.leader,
                phone: root.phone,
                email: root.email,
                status: root.status,
                order_num: root.order_num,
                user_count,
                create_time: root.create_time,
            });
        }
        Ok(vos)
    }

    /// 租户详情（operator_tid≠0 时仅允许查本租户）
    pub async fn get_info(&self, dept_id: i64, operator_tid: i64) -> Result<TenantVo, ServiceError> {
        Self::ensure_not_platform_root(dept_id)?;
        Self::ensure_tenant_access(operator_tid, dept_id)?;
        let root = self
            .load_tenant_root(dept_id)
            .await?
            .ok_or_else(|| ServiceError::not_found(&crate::tr!("error.tenant.not_found")))?;
        let user_count = self.count_tenant_users(root.dept_id).await?;
        Ok(TenantVo {
            dept_id: root.dept_id,
            tenant_name: root.dept_name,
            leader: root.leader,
            phone: root.phone,
            email: root.email,
            status: root.status,
            order_num: root.order_num,
            user_count,
            create_time: root.create_time,
        })
    }

    /// 新建租户：创建根部门（parent_id=0 / ancestors='0' / tenant_id=自身 dept_id）
    pub async fn add(
        &self,
        dto: TenantAddDto,
        operator: &str,
    ) -> Result<TenantVo, ServiceError> {
        let name = dto.tenant_name.trim();
        if name.is_empty() {
            return Err(ServiceError::bad_request(&crate::tr!(
                "error.tenant.name_required"
            )));
        }
        // 同名查重（顶层租户内唯一）
        let dup = SysDept::find()
            .filter(DeptColumn::ParentId.eq(0))
            .filter(DeptColumn::DelFlag.eq("0"))
            .filter(DeptColumn::DeptName.eq(name))
            .one(self.dept_repo.base().db())
            .await?;
        if dup.is_some() {
            return Err(ServiceError::bad_request(&crate::tr!(
                "error.tenant.name_duplicate"
            )));
        }

        let now = crate::common::datetime::now_naive();
        let am = sys_dept::ActiveModel {
            parent_id: Set(Some(0)),
            ancestors: Set(Some("0".to_string())),
            dept_name: Set(name.to_string()),
            order_num: Set(dto.order_num.or(Some(0))),
            leader: Set(dto.leader.clone()),
            phone: Set(dto.phone.clone()),
            email: Set(dto.email.clone()),
            status: Set(dto.status.clone().or_else(|| Some("0".to_string()))),
            del_flag: Set(Some("0".to_string())),
            create_by: Set(Some(operator.to_string())),
            create_time: Set(Some(now)),
            update_by: Set(Some(operator.to_string())),
            update_time: Set(Some(now)),
            // tenant_id：插入后回填自身 dept_id（根部门归属自身租户）
            tenant_id: NotSet,
            leader_user_id: Set(None),
            dept_id: NotSet,
        };
        let root = self.dept_repo.base().insert(am).await?;
        // 回填 tenant_id = 自身 dept_id
        let mut am: sys_dept::ActiveModel = root.clone().into();
        am.tenant_id = Set(root.dept_id);
        let root = self.dept_repo.base().update(am).await?;
        Ok(TenantVo {
            dept_id: root.dept_id,
            tenant_name: root.dept_name,
            leader: root.leader,
            phone: root.phone,
            email: root.email,
            status: root.status,
            order_num: root.order_num,
            user_count: 0,
            create_time: root.create_time,
        })
    }

    /// 修改租户信息（根部门字段；operator_tid≠0 时仅允许改本租户）
    pub async fn edit(
        &self,
        dto: TenantEditDto,
        operator: &str,
        operator_tid: i64,
    ) -> Result<TenantVo, ServiceError> {
        Self::ensure_not_platform_root(dto.dept_id)?;
        Self::ensure_tenant_access(operator_tid, dto.dept_id)?;
        let root = self
            .load_tenant_root(dto.dept_id)
            .await?
            .ok_or_else(|| ServiceError::not_found(&crate::tr!("error.tenant.not_found")))?;

        let name = dto.tenant_name.trim();
        if name.is_empty() {
            return Err(ServiceError::bad_request(&crate::tr!(
                "error.tenant.name_required"
            )));
        }
        // 同名查重（排除自身）
        let dup = SysDept::find()
            .filter(DeptColumn::ParentId.eq(0))
            .filter(DeptColumn::DelFlag.eq("0"))
            .filter(DeptColumn::DeptName.eq(name))
            .filter(DeptColumn::DeptId.ne(dto.dept_id))
            .one(self.dept_repo.base().db())
            .await?;
        if dup.is_some() {
            return Err(ServiceError::bad_request(&crate::tr!(
                "error.tenant.name_duplicate"
            )));
        }

        let now = crate::common::datetime::now_naive();
        let mut am: sys_dept::ActiveModel = root.into();
        am.dept_name = Set(name.to_string());
        am.leader = Set(dto.leader.clone());
        am.phone = Set(dto.phone.clone());
        am.email = Set(dto.email.clone());
        if let Some(order) = dto.order_num {
            am.order_num = Set(Some(order));
        }
        am.update_by = Set(Some(operator.to_string()));
        am.update_time = Set(Some(now));
        let root = self.dept_repo.base().update(am).await?;
        let user_count = self.count_tenant_users(root.dept_id).await?;
        Ok(TenantVo {
            dept_id: root.dept_id,
            tenant_name: root.dept_name,
            leader: root.leader,
            phone: root.phone,
            email: root.email,
            status: root.status,
            order_num: root.order_num,
            user_count,
            create_time: root.create_time,
        })
    }

    /// 启停租户（停用后该租户用户登录被拒绝，见 auth_service 登录链路校验；
    /// operator_tid≠0 时仅允许操作本租户）
    pub async fn change_status(
        &self,
        dto: TenantStatusDto,
        operator: &str,
        operator_tid: i64,
    ) -> Result<(), ServiceError> {
        Self::ensure_not_platform_root(dto.dept_id)?;
        Self::ensure_tenant_access(operator_tid, dto.dept_id)?;
        if dto.status != "0" && dto.status != "1" {
            return Err(ServiceError::bad_request(&crate::tr!(
                "error.tenant.status_invalid"
            )));
        }
        let root = self
            .load_tenant_root(dto.dept_id)
            .await?
            .ok_or_else(|| ServiceError::not_found(&crate::tr!("error.tenant.not_found")))?;
        let now = crate::common::datetime::now_naive();
        let mut am: sys_dept::ActiveModel = root.into();
        am.status = Set(Some(dto.status));
        am.update_by = Set(Some(operator.to_string()));
        am.update_time = Set(Some(now));
        self.dept_repo.base().update(am).await?;
        Ok(())
    }

    /// 删除租户（软删根部门及其子树；租户内仍有用户时拒绝；
    /// operator_tid≠0 时仅允许删本租户）
    pub async fn remove(
        &self,
        dept_id: i64,
        operator: &str,
        operator_tid: i64,
    ) -> Result<(), ServiceError> {
        Self::ensure_not_platform_root(dept_id)?;
        Self::ensure_tenant_access(operator_tid, dept_id)?;
        let root = self
            .load_tenant_root(dept_id)
            .await?
            .ok_or_else(|| ServiceError::not_found(&crate::tr!("error.tenant.not_found")))?;
        let user_count = self.count_tenant_users(root.dept_id).await?;
        if user_count > 0 {
            return Err(ServiceError::bad_request(&crate::tr!(
                "error.tenant.has_users",
                count = user_count
            )));
        }
        // 软删整棵租户子树（根 + 后代）
        let descendant_ids = self
            .dept_repo
            .find_descendant_ids(root.dept_id)
            .await?;
        let now = crate::common::datetime::now_naive();
        for id in descendant_ids {
            let Some(d) = self.dept_repo.base().find_by_id(id).await? else {
                continue;
            };
            let mut am: sys_dept::ActiveModel = d.into();
            am.del_flag = Set(Some("2".to_string()));
            am.update_by = Set(Some(operator.to_string()));
            am.update_time = Set(Some(now));
            self.dept_repo.base().update(am).await?;
        }
        Ok(())
    }

    /// 登录链路校验：租户用户（tid≠0）的根部门被停用 → 拒绝登录
    pub async fn ensure_tenant_active(&self, tenant_id: i64) -> Result<(), ServiceError> {
        if tenant_id == 0 {
            return Ok(());
        }
        let root = self
            .load_tenant_root(tenant_id)
            .await?
            .ok_or_else(|| ServiceError::forbidden(&crate::tr!("error.tenant.disabled")))?;
        if root.status.as_deref() == Some("1") {
            return Err(ServiceError::forbidden(&crate::tr!("error.tenant.disabled")));
        }
        Ok(())
    }

    /// 加载租户根部门（parent_id=0 且未删除；防止把普通部门当租户操作）
    async fn load_tenant_root(&self, dept_id: i64) -> Result<Option<sys_dept::Model>, DbErr> {
        SysDept::find()
            .filter(DeptColumn::DeptId.eq(dept_id))
            .filter(DeptColumn::ParentId.eq(0))
            .filter(DeptColumn::DelFlag.eq("0"))
            .one(self.dept_repo.base().db())
            .await
    }

    /// 租户内用户计数（tenant_id = 根 dept_id，未删除）
    async fn count_tenant_users(&self, root_dept_id: i64) -> Result<u64, ServiceError> {
        let db = self.user_repo.base().db();
        let count = crate::entity::sys_user::Entity::find()
            .filter(crate::entity::sys_user::Column::TenantId.eq(root_dept_id))
            .filter(crate::entity::sys_user::Column::DelFlag.eq("0"))
            .count(db)
            .await?;
        Ok(count)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_platform_root_constant() {
        // 平台根固定 100（RuoYi init 种子），租户接口不得操作
        assert_eq!(PLATFORM_ROOT_DEPT_ID, 100);
    }
}
