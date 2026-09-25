// axum-backend/src/repository/sys_post.rs
//! sys_post 数据访问层
//!
//! 继承 BaseRepository 通用 CRUD，扩展岗位特有查询：
//! - 软删除过滤（del_flag = '0'）
//! - 按状态查询
//! - 按岗位编码查询（查重）

use sea_orm::sea_query::Expr;
use sea_orm::*;

use crate::common::like_escape;
use crate::entity::sys_post::{ActiveModel, Column, Entity as SysPost, Model};
use crate::repository::base::BaseRepository;

/// 岗位 Repository
#[derive(Clone)]
pub struct SysPostRepository {
    base: BaseRepository<SysPost>,
}

impl SysPostRepository {
    pub fn new(db: DatabaseConnection) -> Self {
        Self {
            base: BaseRepository::new(db),
        }
    }

    pub fn base(&self) -> &BaseRepository<SysPost> {
        &self.base
    }

    /// 查询未删除岗位（del_flag = '0'）。
    ///
    /// 多租户：`tenant_scope = Some(tid)` → 仅本租户岗位（`tenant_id = tid`）；
    /// `None`（平台操作者）→ 全量不过滤。
    pub async fn find_active_all(&self, tenant_scope: Option<i64>) -> Result<Vec<Model>, DbErr> {
        let mut query = SysPost::find().filter(Column::DelFlag.eq("0"));
        if let Some(tid) = tenant_scope {
            query = query.filter(Column::TenantId.eq(tid));
        }
        query.all(self.base.db()).await
    }

    /// 按岗位编码查询（查重用）
    pub async fn find_by_post_code(&self, post_code: &str) -> Result<Option<Model>, DbErr> {
        SysPost::find()
            .filter(Column::PostCode.eq(post_code))
            .filter(Column::DelFlag.eq("0"))
            .one(self.base.db())
            .await
    }

    /// 按 post_id 列表查询未删除岗位（用于获取岗位名称拼接 postGroup）
    pub async fn find_by_ids(&self, post_ids: Vec<i64>) -> Result<Vec<Model>, DbErr> {
        if post_ids.is_empty() {
            return Ok(vec![]);
        }
        SysPost::find()
            .filter(Column::PostId.is_in(post_ids))
            .filter(Column::DelFlag.eq("0"))
            .all(self.base.db())
            .await
    }

    /// 软删除岗位
    pub async fn soft_delete(&self, post_id: i64) -> Result<UpdateResult, DbErr> {
        SysPost::update_many()
            .col_expr(Column::DelFlag, Expr::value("2"))
            .filter(Column::PostId.eq(post_id))
            .exec(self.base.db())
            .await
    }

    /// 软删除岗位（使用指定连接，用于事务内调用）
    pub async fn soft_delete_conn<C: ConnectionTrait>(
        &self,
        conn: &C,
        post_id: i64,
    ) -> Result<UpdateResult, DbErr> {
        SysPost::update_many()
            .col_expr(Column::DelFlag, Expr::value("2"))
            .filter(Column::PostId.eq(post_id))
            .exec(conn)
            .await
    }

    /// 软删除岗位并重命名 post_code（REGRESS-003：释放唯一索引 uk_sys_post_code）
    ///
    /// 软删除记录仍占用 post_code 唯一索引，导致无法重新创建同 post_code。
    /// 在同一 UPDATE 中将 post_code 改为 `{original}_deleted_{post_id}`，避免冲突。
    pub async fn soft_delete_with_rename_conn<C: ConnectionTrait>(
        &self,
        conn: &C,
        post_id: i64,
        new_post_code: String,
    ) -> Result<UpdateResult, DbErr> {
        SysPost::update_many()
            .col_expr(Column::DelFlag, Expr::value("2"))
            .col_expr(Column::PostCode, Expr::value(new_post_code))
            .filter(Column::PostId.eq(post_id))
            .exec(conn)
            .await
    }

    /// 按 post_id 查询未删除岗位
    pub async fn find_active_by_id(&self, post_id: i64) -> Result<Option<Model>, DbErr> {
        SysPost::find()
            .filter(Column::PostId.eq(post_id))
            .filter(Column::DelFlag.eq("0"))
            .one(self.base.db())
            .await
    }

    /// 按 post_id 查询未删除岗位（使用指定连接，用于事务内调用）
    pub async fn find_active_by_id_conn<C: ConnectionTrait>(
        &self,
        conn: &C,
        post_id: i64,
    ) -> Result<Option<Model>, DbErr> {
        SysPost::find()
            .filter(Column::PostId.eq(post_id))
            .filter(Column::DelFlag.eq("0"))
            .one(conn)
            .await
    }

    /// 多条件分页查询（post_code 模糊，post_name 模糊，status 精确）
    pub async fn find_page_filtered(
        &self,
        offset: u64,
        limit: u64,
        post_code: Option<&str>,
        post_name: Option<&str>,
        status: Option<&str>,
        tenant_scope: Option<i64>,
    ) -> Result<(Vec<Model>, u64), DbErr> {
        let mut query = SysPost::find().filter(Column::DelFlag.eq("0"));
        // 多租户 Phase 2：租户用户仅见本租户岗位；平台 0 不过滤
        if let Some(t) = tenant_scope {
            query = query.filter(Column::TenantId.eq(t));
        }
        if let Some(code) = post_code {
            query = query.filter(Column::PostCode.like(format!("%{}%", like_escape(code))));
        }
        if let Some(name) = post_name {
            query = query.filter(Column::PostName.like(format!("%{}%", like_escape(name))));
        }
        if let Some(st) = status {
            query = query.filter(Column::Status.eq(st));
        }
        // P1：稳定排序，防翻页重复/漏行
        query = query.order_by_asc(Column::PostId);

        let total = query.clone().count(self.base.db()).await?;
        let rows = query
            .offset(offset)
            .limit(limit)
            .all(self.base.db())
            .await?;
        Ok((rows, total))
    }

    /// 插入岗位
    pub async fn insert(&self, model: ActiveModel) -> Result<Model, DbErr> {
        self.base.insert(model).await
    }

    /// 更新岗位
    pub async fn update(&self, model: ActiveModel) -> Result<Model, DbErr> {
        self.base.update(model).await
    }
}
