// axum-backend/src/repository/sys_backup_log.rs
//! sys_backup_log 数据访问层（数据备份日志表）
//!
//! 继承 BaseRepository 通用 CRUD，扩展备份日志特有查询：
//! - 多条件分页查询（backup_type / status / 时间范围）
//! - 按 ID 查询
//! - 批量删除

use chrono::NaiveDateTime;
use sea_orm::*;

use crate::entity::sys_backup_log::{ActiveModel, Column, Entity as SysBackupLog, Model};
use crate::repository::base::BaseRepository;

/// 数据备份日志 Repository
#[derive(Clone)]
pub struct SysBackupLogRepository {
    base: BaseRepository<SysBackupLog>,
}

impl SysBackupLogRepository {
    pub fn new(db: DatabaseConnection) -> Self {
        Self {
            base: BaseRepository::new(db),
        }
    }

    pub fn base(&self) -> &BaseRepository<SysBackupLog> {
        &self.base
    }

    /// 多条件分页查询
    ///
    /// 支持 backup_type 精确、status 精确、时间范围筛选，按 create_time 倒序
    #[allow(clippy::too_many_arguments)]
    pub async fn find_page_filtered(
        &self,
        offset: u64,
        limit: u64,
        backup_type: Option<&str>,
        status: Option<&str>,
        begin_time: Option<NaiveDateTime>,
        end_time: Option<NaiveDateTime>,
    ) -> Result<(Vec<Model>, u64), DbErr> {
        let mut query = SysBackupLog::find();
        if let Some(bt) = backup_type {
            query = query.filter(Column::BackupType.eq(bt));
        }
        if let Some(st) = status {
            query = query.filter(Column::Status.eq(st));
        }
        if let Some(begin) = begin_time {
            query = query.filter(Column::CreateTime.gte(begin));
        }
        if let Some(end) = end_time {
            query = query.filter(Column::CreateTime.lte(end));
        }

        let total = query.clone().count(self.base.db()).await?;
        let rows = query
            .order_by_desc(Column::CreateTime)
            .offset(offset)
            .limit(limit)
            .all(self.base.db())
            .await?;
        Ok((rows, total))
    }

    /// 按 ID 查询
    pub async fn find_by_id(&self, backup_id: i64) -> Result<Option<Model>, DbErr> {
        SysBackupLog::find_by_id(backup_id)
            .one(self.base.db())
            .await
    }

    /// 插入一条记录
    pub async fn insert(&self, model: ActiveModel) -> Result<Model, DbErr> {
        self.base.insert(model).await
    }

    /// 更新一条记录
    pub async fn update(&self, model: ActiveModel) -> Result<Model, DbErr> {
        model.update(self.base.db()).await
    }

    /// 批量删除（物理删除）
    pub async fn delete_by_ids(&self, ids: Vec<i64>) -> Result<DeleteResult, DbErr> {
        SysBackupLog::delete_many()
            .filter(Column::BackupId.is_in(ids))
            .exec(self.base.db())
            .await
    }
}
