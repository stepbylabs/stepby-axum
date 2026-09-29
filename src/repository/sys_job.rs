// backend-axum/src/repository/sys_job.rs
//! sys_job 数据访问层（定时任务调度表）
//!
//! 继承 BaseRepository 通用 CRUD，扩展定时任务特有查询：
//! - 按任务名称查询
//! - 软删除过滤（del_flag = '0'）
//! - 软删除操作（del_flag = '2'）

use sea_orm::sea_query::Expr;
use sea_orm::*;

use crate::common::like_escape;
use crate::entity::sys_job::{ActiveModel, Column, Entity as SysJob, Model};
use crate::repository::base::BaseRepository;

/// 定时任务 Repository
#[derive(Clone)]
pub struct SysJobRepository {
    base: BaseRepository<SysJob>,
}

impl SysJobRepository {
    pub fn new(db: DatabaseConnection) -> Self {
        Self {
            base: BaseRepository::new(db),
        }
    }

    pub fn base(&self) -> &BaseRepository<SysJob> {
        &self.base
    }

    /// 查询所有未删除定时任务（del_flag = '0'）
    ///
    /// 多租户 Phase 2：tenant_scope=Some(tid) 仅返回本租户任务；None（平台 0）不过滤。
    pub async fn find_active_all(&self, tenant_scope: Option<i64>) -> Result<Vec<Model>, DbErr> {
        let mut query = SysJob::find().filter(Column::DelFlag.eq("0"));
        if let Some(t) = tenant_scope {
            query = query.filter(Column::TenantId.eq(t));
        }
        query.all(self.base.db()).await
    }

    /// 分页查询未删除定时任务
    ///
    /// 多租户 Phase 2：tenant_scope=Some(tid) 仅返回本租户任务；None（平台 0）不过滤。
    pub async fn find_active_page(
        &self,
        offset: u64,
        limit: u64,
        tenant_scope: Option<i64>,
    ) -> Result<(Vec<Model>, u64), DbErr> {
        let mut query = SysJob::find().filter(Column::DelFlag.eq("0"));
        if let Some(t) = tenant_scope {
            query = query.filter(Column::TenantId.eq(t));
        }
        let total = query.clone().count(self.base.db()).await?;
        let rows = query
            .offset(offset)
            .limit(limit)
            .all(self.base.db())
            .await?;
        Ok((rows, total))
    }

    /// 按任务名称查询（任务名 + 任务组唯一）
    ///
    /// 注意：唯一索引 `uk_sys_job_name_group(job_name, job_group)` 当前为**全局**唯一
    /// （per-tenant 化属 R5，待决策），故查重不接租户过滤，避免"预检通过、INSERT 撞唯一索引"
    /// 把友好的 400 提示变成 500。
    pub async fn find_by_name_and_group(
        &self,
        job_name: &str,
        job_group: &str,
    ) -> Result<Option<Model>, DbErr> {
        SysJob::find()
            .filter(Column::JobName.eq(job_name))
            .filter(Column::JobGroup.eq(job_group))
            .filter(Column::DelFlag.eq("0"))
            .one(self.base.db())
            .await
    }

    /// 按状态查询未删除任务（del_flag = '0'）
    /// 用于启动时加载 status='0' 的任务
    ///
    /// 多租户：调度器启动加载需覆盖所有租户（tenant_scope=None），
    /// 租户侧入口传 Some(tid) 时仅返回本租户任务。
    pub async fn find_by_status(
        &self,
        status: &str,
        tenant_scope: Option<i64>,
    ) -> Result<Vec<Model>, DbErr> {
        let mut query = SysJob::find()
            .filter(Column::DelFlag.eq("0"))
            .filter(Column::Status.eq(status));
        if let Some(t) = tenant_scope {
            query = query.filter(Column::TenantId.eq(t));
        }
        query.all(self.base.db()).await
    }

    /// 按 ID 查询未删除任务（del_flag = '0'）
    ///
    /// 多租户：tenant_scope=Some(tid) 时跨租户任务视为不存在（详情 404）；
    /// 需要"先取再判越权返回 403"的写路径传 None。
    pub async fn find_active_by_id(
        &self,
        job_id: i64,
        tenant_scope: Option<i64>,
    ) -> Result<Option<Model>, DbErr> {
        let mut query = SysJob::find()
            .filter(Column::JobId.eq(job_id))
            .filter(Column::DelFlag.eq("0"));
        if let Some(t) = tenant_scope {
            query = query.filter(Column::TenantId.eq(t));
        }
        query.one(self.base.db()).await
    }

    /// 按 ID 查询未删除任务（使用指定连接，用于事务内调用）
    pub async fn find_active_by_id_conn<C: ConnectionTrait>(
        &self,
        conn: &C,
        job_id: i64,
    ) -> Result<Option<Model>, DbErr> {
        SysJob::find()
            .filter(Column::JobId.eq(job_id))
            .filter(Column::DelFlag.eq("0"))
            .one(conn)
            .await
    }

    /// 多条件分页查询（job_name 模糊匹配，job_group/status 精确匹配，按 job_id 升序）
    ///
    /// 多租户 Phase 2：tenant_scope=Some(tid) 仅返回本租户任务；None（平台 0）不过滤。
    pub async fn find_page_filtered(
        &self,
        offset: u64,
        limit: u64,
        job_name: Option<&str>,
        job_group: Option<&str>,
        status: Option<&str>,
        tenant_scope: Option<i64>,
    ) -> Result<(Vec<Model>, u64), DbErr> {
        let mut query = SysJob::find().filter(Column::DelFlag.eq("0"));
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

        let total = query.clone().count(self.base.db()).await?;
        let rows = query
            .order_by_asc(Column::JobId)
            .offset(offset)
            .limit(limit)
            .all(self.base.db())
            .await?;
        Ok((rows, total))
    }

    /// 软删除定时任务
    pub async fn soft_delete(&self, job_id: i64) -> Result<UpdateResult, DbErr> {
        SysJob::update_many()
            .col_expr(Column::DelFlag, Expr::value("2"))
            .filter(Column::JobId.eq(job_id))
            .exec(self.base.db())
            .await
    }

    /// 软删除定时任务（使用指定连接，用于事务内调用）
    pub async fn soft_delete_conn<C: ConnectionTrait>(
        &self,
        conn: &C,
        job_id: i64,
    ) -> Result<UpdateResult, DbErr> {
        SysJob::update_many()
            .col_expr(Column::DelFlag, Expr::value("2"))
            .filter(Column::JobId.eq(job_id))
            .exec(conn)
            .await
    }

    /// 软删除定时任务并重命名 job_name（REGRESS-003：释放唯一索引 uk_sys_job_name_group）
    ///
    /// 软删除记录仍占用 (job_name, job_group) 唯一索引，导致无法重新创建同 job_name。
    /// 在同一 UPDATE 中将 job_name 改为 `{original}_deleted_{job_id}`，避免冲突。
    pub async fn soft_delete_with_rename_conn<C: ConnectionTrait>(
        &self,
        conn: &C,
        job_id: i64,
        new_job_name: String,
    ) -> Result<UpdateResult, DbErr> {
        SysJob::update_many()
            .col_expr(Column::DelFlag, Expr::value("2"))
            .col_expr(Column::JobName, Expr::value(new_job_name))
            .filter(Column::JobId.eq(job_id))
            .exec(conn)
            .await
    }

    /// 插入定时任务
    pub async fn insert(&self, model: ActiveModel) -> Result<Model, DbErr> {
        self.base.insert(model).await
    }

    /// 更新定时任务
    pub async fn update(&self, model: ActiveModel) -> Result<Model, DbErr> {
        self.base.update(model).await
    }
}
