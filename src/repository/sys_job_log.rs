// axum-backend/src/repository/sys_job_log.rs
//! sys_job_log 数据访问层（定时任务调度日志表，物理删除）
//!
//! 继承 BaseRepository 通用 CRUD，扩展任务日志特有查询：
//! - 按任务名称查询
//! - 按状态查询（0=成功 1=失败）

use sea_orm::*;

use chrono::NaiveDateTime;
use crate::common::like_escape;
use crate::entity::sys_job_log::{ActiveModel, Column, Entity as SysJobLog, Model};
use crate::repository::base::BaseRepository;

/// 定时任务日志 Repository
pub struct SysJobLogRepository {
    base: BaseRepository<SysJobLog>,
}

impl SysJobLogRepository {
    pub fn new(db: DatabaseConnection) -> Self {
        Self {
            base: BaseRepository::new(db),
        }
    }

    pub fn base(&self) -> &BaseRepository<SysJobLog> {
        &self.base
    }

    /// 按任务名称查询日志
    pub async fn find_by_job_name(&self, job_name: &str) -> Result<Vec<Model>, DbErr> {
        SysJobLog::find()
            .filter(Column::JobName.eq(job_name))
            .all(self.base.db())
            .await
    }

    /// 按状态查询（0=成功 1=失败）
    pub async fn find_by_status(&self, status: &str) -> Result<Vec<Model>, DbErr> {
        SysJobLog::find()
            .filter(Column::Status.eq(status))
            .all(self.base.db())
            .await
    }

    /// 分页查询任务日志（按创建时间倒序）
    pub async fn find_page_desc(
        &self,
        offset: u64,
        limit: u64,
    ) -> Result<(Vec<Model>, u64), DbErr> {
        let total = SysJobLog::find().count(self.base.db()).await?;
        let rows = SysJobLog::find()
            .order_by_desc(Column::CreateTime)
            .offset(offset)
            .limit(limit)
            .all(self.base.db())
            .await?;
        Ok((rows, total))
    }

    /// 多条件分页查询（job_name 模糊，job_group/status 精确，时间范围，按 create_time 倒序）
    #[allow(clippy::too_many_arguments)]
    pub async fn find_page_filtered(
        &self,
        offset: u64,
        limit: u64,
        job_name: Option<&str>,
        job_group: Option<&str>,
        status: Option<&str>,
        begin_time: Option<NaiveDateTime>,
        end_time: Option<NaiveDateTime>,
    ) -> Result<(Vec<Model>, u64), DbErr> {
        let mut query = SysJobLog::find();
        if let Some(name) = job_name {
            query = query.filter(Column::JobName.like(format!("%{}%", like_escape(name))));
        }
        if let Some(group) = job_group {
            query = query.filter(Column::JobGroup.eq(group));
        }
        if let Some(st) = status {
            query = query.filter(Column::Status.eq(st));
        }
        // P1：时间解析上移 service（parse_query_date 统一"本地日→UTC"换算），
        // repository 只收 NaiveDateTime，避免时区边界错位与 DbErr::Custom 中文泄漏
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

    /// 批量物理删除
    pub async fn delete_by_ids(&self, ids: Vec<i64>) -> Result<DeleteResult, DbErr> {
        SysJobLog::delete_many()
            .filter(Column::JobLogId.is_in(ids))
            .exec(self.base.db())
            .await
    }

    /// 插入任务日志
    pub async fn insert(&self, model: ActiveModel) -> Result<Model, DbErr> {
        self.base.insert(model).await
    }

    /// 清空任务日志（物理删除全部）
    pub async fn clean_all(&self) -> Result<DeleteResult, DbErr> {
        SysJobLog::delete_many()
            .exec(self.base.db())
            .await
    }
}
