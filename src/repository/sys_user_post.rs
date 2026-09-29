// backend-axum/src/repository/sys_user_post.rs
//! sys_user_post 数据访问层（用户岗位关联表，复合主键）
//!
//! 扩展关联特有查询：
//! - 按用户 ID 查询关联岗位
//! - 按岗位 ID 查询关联用户
//! - 按用户 ID / 岗位 ID 删除关联

use sea_orm::*;

use crate::entity::sys_user_post::{ActiveModel, Column, Entity as SysUserPost, Model};
use crate::repository::base::BaseRepository;

/// 用户岗位关联 Repository
#[derive(Clone)]
pub struct SysUserPostRepository {
    base: BaseRepository<SysUserPost>,
}

impl SysUserPostRepository {
    pub fn new(db: DatabaseConnection) -> Self {
        Self {
            base: BaseRepository::new(db),
        }
    }

    pub fn base(&self) -> &BaseRepository<SysUserPost> {
        &self.base
    }

    /// 按用户 ID 查询所有岗位关联
    pub async fn find_by_user_id(&self, user_id: i64) -> Result<Vec<Model>, DbErr> {
        SysUserPost::find()
            .filter(Column::UserId.eq(user_id))
            .all(self.base.db())
            .await
    }

    /// 按岗位 ID 查询所有用户关联
    pub async fn find_by_post_id(&self, post_id: i64) -> Result<Vec<Model>, DbErr> {
        SysUserPost::find()
            .filter(Column::PostId.eq(post_id))
            .all(self.base.db())
            .await
    }

    /// 按岗位 ID 查询所有用户关联（使用指定连接，用于事务内调用）
    pub async fn find_by_post_id_conn<C: ConnectionTrait>(
        &self,
        conn: &C,
        post_id: i64,
    ) -> Result<Vec<Model>, DbErr> {
        SysUserPost::find()
            .filter(Column::PostId.eq(post_id))
            .all(conn)
            .await
    }

    /// 删除某用户的所有岗位关联
    pub async fn delete_by_user_id(&self, user_id: i64) -> Result<DeleteResult, DbErr> {
        SysUserPost::delete_many()
            .filter(Column::UserId.eq(user_id))
            .exec(self.base.db())
            .await
    }

    /// 删除某岗位的所有用户关联
    pub async fn delete_by_post_id(&self, post_id: i64) -> Result<DeleteResult, DbErr> {
        SysUserPost::delete_many()
            .filter(Column::PostId.eq(post_id))
            .exec(self.base.db())
            .await
    }

    /// 插入关联
    pub async fn insert(&self, model: ActiveModel) -> Result<Model, DbErr> {
        self.base.insert(model).await
    }

    // ==================== 事务上下文方法（_conn 系列） ====================

    /// 删除某用户的所有岗位关联（使用指定连接，用于事务内调用）
    pub async fn delete_by_user_id_conn<C: ConnectionTrait>(
        &self,
        conn: &C,
        user_id: i64,
    ) -> Result<DeleteResult, DbErr> {
        SysUserPost::delete_many()
            .filter(Column::UserId.eq(user_id))
            .exec(conn)
            .await
    }

    /// 批量插入关联（使用指定连接，用于事务内调用）
    pub async fn insert_many_conn<C: ConnectionTrait>(
        &self,
        conn: &C,
        models: Vec<ActiveModel>,
    ) -> Result<InsertResult<ActiveModel>, DbErr> {
        SysUserPost::insert_many(models).exec(conn).await
    }
}
