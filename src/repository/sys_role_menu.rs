// axum-backend/src/repository/sys_role_menu.rs
//! sys_role_menu 数据访问层（角色菜单关联表，复合主键）
//!
//! 继承 BaseRepository 通用 CRUD，扩展关联特有查询：
//! - 按角色 ID 查询关联菜单
//! - 按菜单 ID 查询关联角色
//! - 按角色 ID / 菜单 ID 删除关联

use sea_orm::*;

use crate::entity::sys_role_menu::{ActiveModel, Column, Entity as SysRoleMenu, Model};
use crate::repository::base::BaseRepository;

/// 角色菜单关联 Repository
#[derive(Clone)]
pub struct SysRoleMenuRepository {
    base: BaseRepository<SysRoleMenu>,
}

impl SysRoleMenuRepository {
    pub fn new(db: DatabaseConnection) -> Self {
        Self {
            base: BaseRepository::new(db),
        }
    }

    pub fn base(&self) -> &BaseRepository<SysRoleMenu> {
        &self.base
    }

    /// 按角色 ID 查询所有菜单关联
    pub async fn find_by_role_id(&self, role_id: i64) -> Result<Vec<Model>, DbErr> {
        SysRoleMenu::find()
            .filter(Column::RoleId.eq(role_id))
            .all(self.base.db())
            .await
    }

    /// 按菜单 ID 查询所有角色关联
    pub async fn find_by_menu_id(&self, menu_id: i64) -> Result<Vec<Model>, DbErr> {
        SysRoleMenu::find()
            .filter(Column::MenuId.eq(menu_id))
            .all(self.base.db())
            .await
    }

    /// 删除某角色的所有菜单关联（角色重分配菜单时调用）
    pub async fn delete_by_role_id(&self, role_id: i64) -> Result<DeleteResult, DbErr> {
        SysRoleMenu::delete_many()
            .filter(Column::RoleId.eq(role_id))
            .exec(self.base.db())
            .await
    }

    /// 删除某菜单的所有角色关联（菜单删除时调用）
    pub async fn delete_by_menu_id(&self, menu_id: i64) -> Result<DeleteResult, DbErr> {
        SysRoleMenu::delete_many()
            .filter(Column::MenuId.eq(menu_id))
            .exec(self.base.db())
            .await
    }

    /// 插入关联
    pub async fn insert(&self, model: ActiveModel) -> Result<Model, DbErr> {
        self.base.insert(model).await
    }

    /// 统计某菜单关联的角色数（菜单删除校验用）
    pub async fn count_by_menu_id(&self, menu_id: i64) -> Result<u64, DbErr> {
        SysRoleMenu::find()
            .filter(Column::MenuId.eq(menu_id))
            .count(self.base.db())
            .await
    }

    // ==================== 事务上下文方法（_conn 系列） ====================

    /// 删除某角色的所有菜单关联（使用指定连接，用于事务内调用）
    pub async fn delete_by_role_id_conn<C: ConnectionTrait>(
        &self,
        conn: &C,
        role_id: i64,
    ) -> Result<DeleteResult, DbErr> {
        SysRoleMenu::delete_many()
            .filter(Column::RoleId.eq(role_id))
            .exec(conn)
            .await
    }

    /// 删除某菜单的所有角色关联（使用指定连接，用于事务内调用）
    pub async fn delete_by_menu_id_conn<C: ConnectionTrait>(
        &self,
        conn: &C,
        menu_id: i64,
    ) -> Result<DeleteResult, DbErr> {
        SysRoleMenu::delete_many()
            .filter(Column::MenuId.eq(menu_id))
            .exec(conn)
            .await
    }

    /// 批量插入关联（使用指定连接，用于事务内调用）
    pub async fn insert_many_conn<C: ConnectionTrait>(
        &self,
        conn: &C,
        models: Vec<ActiveModel>,
    ) -> Result<InsertResult<ActiveModel>, DbErr> {
        SysRoleMenu::insert_many(models).exec(conn).await
    }
}
