// stepby-axum/src/repository/sys_job_log.rs
//! sys_job_log 数据访问层（定时任务调度日志表，物理删除）
//!
//! 继承 BaseRepository 通用 CRUD，扩展任务日志特有查询：
//! - 按任务名称查询
//! - 按状态查询（0=成功 1=失败）

use sea_orm::*;

use crate::common::like_escape;
use crate::common::sort::SortOrder;
use crate::entity::sys_job_log::{ActiveModel, Column, Entity as SysJobLog, Model};
use crate::repository::base::BaseRepository;
use chrono::NaiveDateTime;

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
    ///
    /// 多租户 Phase 2：tenant_scope=Some(tid) 仅返回本租户日志；None（平台 0）不过滤。
    pub async fn find_by_job_name(
        &self,
        job_name: &str,
        tenant_scope: Option<i64>,
    ) -> Result<Vec<Model>, DbErr> {
        let mut query = SysJobLog::find().filter(Column::JobName.eq(job_name));
        if let Some(t) = tenant_scope {
            query = query.filter(Column::TenantId.eq(t));
        }
        query.all(self.base.db()).await
    }

    /// 按状态查询（0=成功 1=失败）
    ///
    /// 多租户 Phase 2：tenant_scope=Some(tid) 仅返回本租户日志；None（平台 0）不过滤。
    pub async fn find_by_status(
        &self,
        status: &str,
        tenant_scope: Option<i64>,
    ) -> Result<Vec<Model>, DbErr> {
        let mut query = SysJobLog::find().filter(Column::Status.eq(status));
        if let Some(t) = tenant_scope {
            query = query.filter(Column::TenantId.eq(t));
        }
        query.all(self.base.db()).await
    }

    /// 分页查询任务日志（按创建时间倒序）
    ///
    /// 多租户 Phase 2：tenant_scope=Some(tid) 仅返回本租户日志；None（平台 0）不过滤。
    pub async fn find_page_desc(
        &self,
        offset: u64,
        limit: u64,
        tenant_scope: Option<i64>,
    ) -> Result<(Vec<Model>, u64), DbErr> {
        let mut query = SysJobLog::find();
        if let Some(t) = tenant_scope {
            query = query.filter(Column::TenantId.eq(t));
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

    /// 多条件分页查询（job_name 模糊，job_group/status 精确，时间范围，按 create_time 倒序）
    ///
    /// 多租户 Phase 2：tenant_scope=Some(tid) 仅返回本租户日志；None（平台 0）不过滤。
    ///
    /// `sort`：动态排序（方案 B，白名单已在 service 层解析为 `SortOrder`）；
    /// `None` 时回退默认 `create_time DESC`。
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
        tenant_scope: Option<i64>,
        sort: Option<SortOrder<Column>>,
    ) -> Result<(Vec<Model>, u64), DbErr> {
        let mut query = SysJobLog::find();
        if let Some(t) = tenant_scope {
            query = query.filter(Column::TenantId.eq(t));
        }
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
        // 动态排序（白名单已解析）或默认 create_time 倒序
        let rows = match sort {
            Some(s) => query.order_by(s.column, s.dir),
            None => query.order_by_desc(Column::CreateTime),
        }
        .offset(offset)
        .limit(limit)
        .all(self.base.db())
        .await?;
        Ok((rows, total))
    }

    /// 按 ID 列表查询（多租户归属校验用）
    pub async fn find_by_ids(&self, ids: &[i64]) -> Result<Vec<Model>, DbErr> {
        if ids.is_empty() {
            return Ok(Vec::new());
        }
        SysJobLog::find()
            .filter(Column::JobLogId.is_in(ids.to_vec()))
            .all(self.base.db())
            .await
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

    /// 清空任务日志（物理删除；tenant_scope=None 时清空全部，Some(tid) 仅清本租户）
    pub async fn clean_all(&self, tenant_scope: Option<i64>) -> Result<DeleteResult, DbErr> {
        let mut query = SysJobLog::delete_many();
        if let Some(tid) = tenant_scope {
            query = query.filter(Column::TenantId.eq(tid));
        }
        query.exec(self.base.db()).await
    }

    /// G-09 运行报表：窗口内调度日志行（应用层聚合的数据源）
    ///
    /// 只取报表聚合所需列的完整 Model（ORM Select 语义），窗口过滤在 DB 侧完成
    /// （`create_time >= begin`），聚合在应用层按 UTC 日期分桶——刻意不做 SQL
    /// `GROUP BY date(...)`：三方言日期函数分叉（SQLite `date()` / MySQL `DATE()` /
    /// PostgreSQL `date_trunc`），应用层聚合零方言差异且单测友好；窗口由调用方
    /// 限制（days ≤ 30），行数有上界保护（`max_rows` 截断，防失控表拖垮报表接口）。
    ///
    /// 多租户：tenant_scope=Some(tid) 仅本租户；None（平台 0）不过滤。
    pub async fn find_window_for_stats(
        &self,
        begin: NaiveDateTime,
        max_rows: u64,
        tenant_scope: Option<i64>,
    ) -> Result<Vec<Model>, DbErr> {
        let mut query = SysJobLog::find().filter(Column::CreateTime.gte(begin));
        if let Some(t) = tenant_scope {
            query = query.filter(Column::TenantId.eq(t));
        }
        query
            .order_by_asc(Column::CreateTime)
            .limit(max_rows)
            .all(self.base.db())
            .await
    }
}
