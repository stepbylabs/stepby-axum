// axum-backend/src/repository/sys_flow_task.rs
//! sys_flow_task 数据访问层（审批待办）
//!
//! 继承 BaseRepository 通用 CRUD，扩展：
//! - 待办列表（assignee + status，跨 biz_type 聚合）
//! - 条件更新（`WHERE status='pending'`，并发安全 + 幂等，V4-E1/E3）
//! - 节点聚合判定（会签/或签）
//! - 超时扫描（pending + due_at 过期）

use chrono::NaiveDateTime;
use sea_orm::*;
use sea_query::Expr;

use crate::entity::sys_flow_task::{ActiveModel, Column, Entity as SysFlowTask, Model};
use crate::repository::base::BaseRepository;

/// 审批待办 Repository
#[derive(Clone)]
pub struct SysFlowTaskRepository {
    base: BaseRepository<SysFlowTask>,
}

impl SysFlowTaskRepository {
    pub fn new(db: DatabaseConnection) -> Self {
        Self {
            base: BaseRepository::new(db),
        }
    }

    pub fn base(&self) -> &BaseRepository<SysFlowTask> {
        &self.base
    }

    /// 我的待办（assignee + status 过滤；跨 biz_type 聚合，title 已冗余）
    pub async fn find_todo_page(
        &self,
        assignee_id: i64,
        offset: u64,
        limit: u64,
    ) -> Result<(Vec<Model>, u64), DbErr> {
        let query = SysFlowTask::find()
            .filter(Column::AssigneeId.eq(assignee_id))
            .filter(Column::Status.eq("pending"));
        let total = query.clone().count(self.base.db()).await?;
        let rows = query
            .order_by_desc(Column::CreateTime)
            .offset(offset)
            .limit(limit)
            .all(self.base.db())
            .await?;
        Ok((rows, total))
    }

    /// 当前用户待办数量（红点）
    pub async fn count_pending(&self, assignee_id: i64) -> Result<u64, DbErr> {
        SysFlowTask::find()
            .filter(Column::AssigneeId.eq(assignee_id))
            .filter(Column::Status.eq("pending"))
            .count(self.base.db())
            .await
    }

    /// 某单据某轮的全部任务行（会签/或签聚合判定 + 时间线）
    pub async fn find_by_biz_round(
        &self,
        biz_type: &str,
        biz_id: i64,
        round_no: i32,
    ) -> Result<Vec<Model>, DbErr> {
        SysFlowTask::find()
            .filter(Column::BizType.eq(biz_type))
            .filter(Column::BizId.eq(biz_id))
            .filter(Column::RoundNo.eq(round_no))
            .order_by_asc(Column::NodeSeq)
            .all(self.base.db())
            .await
    }

    /// 按 ID 查询
    pub async fn find_by_id(&self, task_id: i64) -> Result<Option<Model>, DbErr> {
        SysFlowTask::find_by_id(task_id).one(self.base.db()).await
    }

    /// 某单据当前轮的任一 pending 任务（发起人撤回入口：docId → taskId）
    pub async fn find_first_pending_by_biz(
        &self,
        biz_type: &str,
        biz_id: i64,
    ) -> Result<Option<Model>, DbErr> {
        SysFlowTask::find()
            .filter(Column::BizType.eq(biz_type))
            .filter(Column::BizId.eq(biz_id))
            .filter(Column::Status.eq("pending"))
            .order_by_asc(Column::TaskId)
            .one(self.base.db())
            .await
    }

    /// 条件更新（并发安全 + 幂等）：仅当行仍为 pending 时生效，返回影响行数
    pub async fn update_status_if_pending(
        &self,
        task_id: i64,
        new_status: &str,
        comment: Option<&str>,
    ) -> Result<u64, DbErr> {
        let mut upd = SysFlowTask::update_many()
            .col_expr(Column::Status, Expr::value(new_status))
            .col_expr(Column::ActedAt, Expr::current_timestamp().into());
        if let Some(c) = comment {
            upd = upd.col_expr(Column::Comment, Expr::value(c));
        }
        let res = upd
            .filter(Column::TaskId.eq(task_id))
            .filter(Column::Status.eq("pending"))
            .exec(self.base.db())
            .await?;
        Ok(res.rows_affected)
    }

    /// 转办：pending 行改 assignee（同轮同节点新审批人已存在时由唯一索引兜底）
    pub async fn transfer_if_pending(
        &self,
        task_id: i64,
        new_assignee_id: i64,
    ) -> Result<u64, DbErr> {
        let res = SysFlowTask::update_many()
            .col_expr(Column::AssigneeId, Expr::value(new_assignee_id))
            .col_expr(Column::Status, Expr::value("pending"))
            .filter(Column::TaskId.eq(task_id))
            .filter(Column::Status.eq("pending"))
            .exec(self.base.db())
            .await?;
        Ok(res.rows_affected)
    }

    /// 批量取消同单据的 pending 行（撤回 / 驳回终止；V4-E4 task 行状态机）
    pub async fn cancel_pending_by_biz(
        &self,
        biz_type: &str,
        biz_id: i64,
        round_no: i32,
    ) -> Result<u64, DbErr> {
        let res = SysFlowTask::update_many()
            .col_expr(Column::Status, Expr::value("cancelled"))
            .col_expr(Column::ActedAt, Expr::current_timestamp().into())
            .filter(Column::BizType.eq(biz_type))
            .filter(Column::BizId.eq(biz_id))
            .filter(Column::RoundNo.eq(round_no))
            .filter(Column::Status.eq("pending"))
            .exec(self.base.db())
            .await?;
        Ok(res.rows_affected)
    }

    /// 超时扫描候选：pending 且 due_at 已过（分页限量，V2-P1-6）
    pub async fn find_timeout_candidates(
        &self,
        now: NaiveDateTime,
        limit: u64,
    ) -> Result<Vec<Model>, DbErr> {
        SysFlowTask::find()
            .filter(Column::Status.eq("pending"))
            .filter(Column::DueAt.is_not_null())
            .filter(Column::DueAt.lt(now))
            .order_by_asc(Column::DueAt)
            .limit(limit)
            .all(self.base.db())
            .await
    }

    /// 更新最近提醒时间
    pub async fn touch_reminded(&self, task_id: i64, now: NaiveDateTime) -> Result<(), DbErr> {
        let am = ActiveModel {
            task_id: Set(task_id),
            last_reminded_at: Set(Some(now)),
            ..Default::default()
        };
        self.base.update(am).await?;
        Ok(())
    }
}
