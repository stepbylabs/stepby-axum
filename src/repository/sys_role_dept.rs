// axum-backend/src/repository/sys_role_dept.rs
//! sys_role_dept 数据访问层（角色部门关联表，复合主键，用于自定义数据权限）
//!
//! 扩展关联特有查询：
//! - 按角色 ID 查询关联部门
//! - 按部门 ID 查询关联角色
//! - 按角色 ID 删除关联

use sea_orm::*;

use crate::entity::sys_role_dept::{ActiveModel, Column, Entity as SysRoleDept, Model};
use crate::repository::base::BaseRepository;

/// 角色部门关联 Repository
#[derive(Clone)]
pub struct SysRoleDeptRepository {
    base: BaseRepository<SysRoleDept>,
}

impl SysRoleDeptRepository {
    pub fn new(db: DatabaseConnection) -> Self {
        Self {
            base: BaseRepository::new(db),
        }
    }

    pub fn base(&self) -> &BaseRepository<SysRoleDept> {
        &self.base
    }

    /// 按角色 ID 查询所有部门关联
    pub async fn find_by_role_id(&self, role_id: i64) -> Result<Vec<Model>, DbErr> {
        SysRoleDept::find()
            .filter(Column::RoleId.eq(role_id))
            .all(self.base.db())
            .await
    }

    /// 批量按多个角色 ID 查询部门关联（P0-R81-004 暂缓项）
    ///
    /// 用于 data_scope scope=2 消除 N+1：一次查询所有角色对应的 role_dept 关联，
    /// 而非循环每个角色单独查询。
    pub async fn find_by_role_ids(&self, role_ids: &[i64]) -> Result<Vec<Model>, DbErr> {
        if role_ids.is_empty() {
            return Ok(vec![]);
        }
        SysRoleDept::find()
            .filter(Column::RoleId.is_in(role_ids.to_vec()))
            .all(self.base.db())
            .await
    }

    /// 按部门 ID 查询所有角色关联
    pub async fn find_by_dept_id(&self, dept_id: i64) -> Result<Vec<Model>, DbErr> {
        SysRoleDept::find()
            .filter(Column::DeptId.eq(dept_id))
            .all(self.base.db())
            .await
    }

    /// 删除某角色的所有部门关联
    pub async fn delete_by_role_id(&self, role_id: i64) -> Result<DeleteResult, DbErr> {
        SysRoleDept::delete_many()
            .filter(Column::RoleId.eq(role_id))
            .exec(self.base.db())
            .await
    }

    /// 删除某部门的所有角色关联
    pub async fn delete_by_dept_id(&self, dept_id: i64) -> Result<DeleteResult, DbErr> {
        SysRoleDept::delete_many()
            .filter(Column::DeptId.eq(dept_id))
            .exec(self.base.db())
            .await
    }

    /// 插入关联
    pub async fn insert(&self, model: ActiveModel) -> Result<Model, DbErr> {
        self.base.insert(model).await
    }

    // ==================== 事务上下文方法（_conn 系列） ====================

    /// 删除某角色的所有部门关联（使用指定连接，用于事务内调用）
    pub async fn delete_by_role_id_conn<C: ConnectionTrait>(
        &self,
        conn: &C,
        role_id: i64,
    ) -> Result<DeleteResult, DbErr> {
        SysRoleDept::delete_many()
            .filter(Column::RoleId.eq(role_id))
            .exec(conn)
            .await
    }

    /// 批量插入关联（使用指定连接，用于事务内调用）
    pub async fn insert_many_conn<C: ConnectionTrait>(
        &self,
        conn: &C,
        models: Vec<ActiveModel>,
    ) -> Result<InsertResult<ActiveModel>, DbErr> {
        SysRoleDept::insert_many(models).exec(conn).await
    }
}
