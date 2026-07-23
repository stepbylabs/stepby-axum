// axum-backend/src/repository/sys_config.rs
//! sys_config 数据访问层（参数配置表，物理删除）
//!
//! 继承 BaseRepository 通用 CRUD，扩展参数配置特有查询：
//! - 按 config_key 查询（唯一约束）
//! - 多条件分页查询（config_name/config_key 模糊 + config_type 精确 + 时间范围）
//! - 多条件全量查询（导出用，不分页，但受 EXPORT_MAX_ROWS 限制）

use chrono::NaiveDateTime;
use sea_orm::*;

use crate::common::like_escape;
use crate::common::page::EXPORT_MAX_ROWS;
use crate::entity::sys_config::{ActiveModel, Column, Entity as SysConfig, Model};
use crate::repository::base::BaseRepository;

/// 参数配置 Repository
#[derive(Clone)]
pub struct SysConfigRepository {
    base: BaseRepository<SysConfig>,
}

impl SysConfigRepository {
    pub fn new(db: DatabaseConnection) -> Self {
        Self {
            base: BaseRepository::new(db),
        }
    }

    pub fn base(&self) -> &BaseRepository<SysConfig> {
        &self.base
    }

    /// 按 config_id 查询单条参数配置
    pub async fn find_by_id(&self, config_id: i64) -> Result<Option<Model>, DbErr> {
        SysConfig::find_by_id(config_id)
            .one(self.base.db())
            .await
    }

    /// 按 config_key 查询（唯一约束，用于查重和按 key 取值）
    pub async fn find_by_config_key(&self, config_key: &str) -> Result<Option<Model>, DbErr> {
        SysConfig::find()
            .filter(Column::ConfigKey.eq(config_key))
            .one(self.base.db())
            .await
    }

    /// 多条件分页查询（config_name 模糊，config_key 模糊，config_type 精确，时间范围）
    #[allow(clippy::too_many_arguments)]
    pub async fn find_page_filtered(
        &self,
        offset: u64,
        limit: u64,
        config_name: Option<&str>,
        config_key: Option<&str>,
        config_type: Option<&str>,
        begin_time: Option<NaiveDateTime>,
        end_time: Option<NaiveDateTime>,
    ) -> Result<(Vec<Model>, u64), DbErr> {
        let query = Self::build_filter_query(config_name, config_key, config_type, begin_time, end_time);

        let total = query.clone().count(self.base.db()).await?;
        let rows = query
            .offset(offset)
            .limit(limit)
            .all(self.base.db())
            .await?;
        Ok((rows, total))
    }

    /// 多条件全量查询（导出用，不分页但受 EXPORT_MAX_ROWS 限制防 OOM）
    #[allow(clippy::too_many_arguments)]
    pub async fn find_all_filtered(
        &self,
        config_name: Option<&str>,
        config_key: Option<&str>,
        config_type: Option<&str>,
        begin_time: Option<NaiveDateTime>,
        end_time: Option<NaiveDateTime>,
    ) -> Result<Vec<Model>, DbErr> {
        let query = Self::build_filter_query(config_name, config_key, config_type, begin_time, end_time);
        query
            .limit(EXPORT_MAX_ROWS)
            .all(self.base.db())
            .await
    }

    /// 构建多条件查询（分页与全量查询共用）
    fn build_filter_query(
        config_name: Option<&str>,
        config_key: Option<&str>,
        config_type: Option<&str>,
        begin_time: Option<NaiveDateTime>,
        end_time: Option<NaiveDateTime>,
    ) -> Select<SysConfig> {
        let mut query = SysConfig::find();
        if let Some(name) = config_name {
            query = query.filter(Column::ConfigName.like(format!("%{}%", like_escape(name))));
        }
        if let Some(key) = config_key {
            query = query.filter(Column::ConfigKey.like(format!("%{}%", like_escape(key))));
        }
        if let Some(ct) = config_type {
            query = query.filter(Column::ConfigType.eq(ct));
        }
        if let Some(begin) = begin_time {
            query = query.filter(Column::CreateTime.gte(begin));
        }
        if let Some(end) = end_time {
            query = query.filter(Column::CreateTime.lte(end));
        }
        query
    }

    /// 批量删除参数配置（物理删除）
    pub async fn delete_by_ids(&self, config_ids: Vec<i64>) -> Result<DeleteResult, DbErr> {
        SysConfig::delete_many()
            .filter(Column::ConfigId.is_in(config_ids))
            .exec(self.base.db())
            .await
    }

    /// 插入参数配置
    pub async fn insert(&self, model: ActiveModel) -> Result<Model, DbErr> {
        self.base.insert(model).await
    }

    /// 更新参数配置
    pub async fn update(&self, model: ActiveModel) -> Result<Model, DbErr> {
        self.base.update(model).await
    }
}
