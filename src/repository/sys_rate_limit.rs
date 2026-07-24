// axum-backend/src/repository/sys_rate_limit.rs
//! sys_rate_limit 数据访问层（API 限流配置表，物理删除）
//!
//! 继承 BaseRepository 通用 CRUD，扩展限流配置特有查询：
//! - 按 route_pattern 精确查询（唯一约束）
//! - 查询所有启用的配置（中间件加载用）
//! - 多条件分页查询（route_pattern 模糊 + enabled 精确）

use sea_orm::*;

use crate::common::like_escape;
use crate::entity::sys_rate_limit::{ActiveModel, Column, Entity as SysRateLimit, Model};
use crate::repository::base::BaseRepository;

/// API 限流配置 Repository
#[derive(Clone)]
pub struct SysRateLimitRepository {
    base: BaseRepository<SysRateLimit>,
}

impl SysRateLimitRepository {
    pub fn new(db: DatabaseConnection) -> Self {
        Self {
            base: BaseRepository::new(db),
        }
    }

    pub fn base(&self) -> &BaseRepository<SysRateLimit> {
        &self.base
    }

    /// 查询所有限流配置（按 id 升序）
    pub async fn find_all(&self) -> Result<Vec<Model>, DbErr> {
        SysRateLimit::find()
            .order_by_asc(Column::Id)
            .all(self.base.db())
            .await
    }

    /// 按 id 查询单条限流配置
    pub async fn find_by_id(&self, id: i64) -> Result<Option<Model>, DbErr> {
        SysRateLimit::find_by_id(id).one(self.base.db()).await
    }

    /// 按 id 列表批量查询限流配置（单次查询替代 N 次 find_by_id）
    pub async fn find_by_ids(&self, ids: Vec<i64>) -> Result<Vec<Model>, DbErr> {
        if ids.is_empty() {
            return Ok(Vec::new());
        }
        SysRateLimit::find()
            .filter(Column::Id.is_in(ids))
            .all(self.base.db())
            .await
    }

    /// 按 route_pattern 精确查询（唯一约束，用于查重和中间件按路由取配置）
    pub async fn find_by_route_pattern(
        &self,
        route_pattern: &str,
    ) -> Result<Option<Model>, DbErr> {
        SysRateLimit::find()
            .filter(Column::RoutePattern.eq(route_pattern))
            .one(self.base.db())
            .await
    }

    /// 查询所有启用的限流配置（中间件加载用）
    pub async fn find_enabled(&self) -> Result<Vec<Model>, DbErr> {
        SysRateLimit::find()
            .filter(Column::Enabled.eq(true))
            .order_by_asc(Column::Id)
            .all(self.base.db())
            .await
    }

    /// 多条件分页查询（route_pattern 模糊 + enabled 精确）
    pub async fn find_page_filtered(
        &self,
        offset: u64,
        limit: u64,
        route_pattern: Option<&str>,
        enabled: Option<bool>,
    ) -> Result<(Vec<Model>, u64), DbErr> {
        let query = Self::build_filter_query(route_pattern, enabled);

        let total = query.clone().count(self.base.db()).await?;
        let rows = query
            .order_by_desc(Column::Id)
            .offset(offset)
            .limit(limit)
            .all(self.base.db())
            .await?;
        Ok((rows, total))
    }

    /// 多条件全量查询（导出用，不分页但受 EXPORT_MAX_ROWS 限制防 OOM）
    pub async fn find_all_filtered(
        &self,
        route_pattern: Option<&str>,
        enabled: Option<bool>,
    ) -> Result<Vec<Model>, DbErr> {
        let query = Self::build_filter_query(route_pattern, enabled);
        query
            .order_by_desc(Column::Id)
            .limit(crate::common::page::EXPORT_MAX_ROWS)
            .all(self.base.db())
            .await
    }

    /// 构建多条件查询（分页与全量查询共用）
    fn build_filter_query(
        route_pattern: Option<&str>,
        enabled: Option<bool>,
    ) -> Select<SysRateLimit> {
        let mut query = SysRateLimit::find();
        if let Some(rp) = route_pattern {
            query = query.filter(Column::RoutePattern.like(format!("%{}%", like_escape(rp))));
        }
        if let Some(en) = enabled {
            query = query.filter(Column::Enabled.eq(en));
        }
        query
    }

    /// 批量删除限流配置（物理删除）
    pub async fn delete_by_ids(&self, ids: Vec<i64>) -> Result<DeleteResult, DbErr> {
        SysRateLimit::delete_many()
            .filter(Column::Id.is_in(ids))
            .exec(self.base.db())
            .await
    }

    /// 插入限流配置
    pub async fn insert(&self, model: ActiveModel) -> Result<Model, DbErr> {
        self.base.insert(model).await
    }

    /// 更新限流配置
    pub async fn update(&self, model: ActiveModel) -> Result<Model, DbErr> {
        self.base.update(model).await
    }
}
