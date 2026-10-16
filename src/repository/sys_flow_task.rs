// stepby-axum/src/repository/sys_flow_task.rs
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

    /// 某审批人的全部 pending 待办（离岗自动转办入口，W-4；不分页，量级受待办规模约束）
    pub async fn find_pending_by_assignee(&self, assignee_id: i64) -> Result<Vec<Model>, DbErr> {
        SysFlowTask::find()
            .filter(Column::AssigneeId.eq(assignee_id))
            .filter(Column::Status.eq("pending"))
            .order_by_asc(Column::TaskId)
            .all(self.base.db())
            .await
    }

    /// 某单据某轮的全部任务行（会签/或签聚合判定 + 时间线）
    ///
    /// **纵深防御（W-2 建议②）**：`(biz_type, biz_id, round_no)` 在
    /// `uk_flow_task_tenant_biz (tenant_id, biz_type, biz_id, …)` 下**不跨租户唯一**，
    /// 若不带租户收敛，聚合判定可能把他租户同号行的 `approved` 计入本租户节点
    /// ⇒ **误判节点已完成**（正确性缺陷，非仅可见面）。调用方传**被推进 task 的
    /// `tenant_id`**（`Some(tid)`）：同轮的 task 行由引擎写入同一租户，故为精确匹配。
    pub async fn find_by_biz_round(
        &self,
        biz_type: &str,
        biz_id: i64,
        round_no: i32,
        tenant_scope: Option<i64>,
    ) -> Result<Vec<Model>, DbErr> {
        let mut query = SysFlowTask::find()
            .filter(Column::BizType.eq(biz_type))
            .filter(Column::BizId.eq(biz_id))
            .filter(Column::RoundNo.eq(round_no));
        if let Some(t) = tenant_scope {
            query = query.filter(Column::TenantId.eq(t));
        }
        query
            .order_by_asc(Column::NodeSeq)
            .all(self.base.db())
            .await
    }

    /// 按 ID 查询
    pub async fn find_by_id(&self, task_id: i64) -> Result<Option<Model>, DbErr> {
        SysFlowTask::find_by_id(task_id).one(self.base.db()).await
    }

    /// 某单据当前轮的任一 pending 任务（发起人撤回入口：docId → taskId）
    ///
    /// 多租户：`tenant_scope = Some(tid)` → 仅本租户任务；`None`（平台）→ 全量。
    pub async fn find_first_pending_by_biz(
        &self,
        biz_type: &str,
        biz_id: i64,
        tenant_scope: Option<i64>,
    ) -> Result<Option<Model>, DbErr> {
        let mut query = SysFlowTask::find()
            .filter(Column::BizType.eq(biz_type))
            .filter(Column::BizId.eq(biz_id))
            .filter(Column::Status.eq("pending"));
        if let Some(t) = tenant_scope {
            query = query.filter(Column::TenantId.eq(t));
        }
        query.order_by_asc(Column::TaskId).one(self.base.db()).await
    }

    /// 批版存在性探测：给定业务类型下，**哪些** `biz_id` 至少还有一条 pending 待办。
    ///
    /// b71 N+1 治理：一致性巡检 A 原先对每个 pending 单据单独
    /// [`Self::find_first_pending_by_biz`]（limit 个单据 = limit 次往返）。语义等价：
    /// 同一 `biz_id` 命中即入集，不要求"首条"（原实现只判存在性，取首条仅为省行）。
    pub async fn find_pending_biz_ids(
        &self,
        biz_type: &str,
        biz_ids: &[i64],
    ) -> Result<std::collections::HashSet<i64>, DbErr> {
        if biz_ids.is_empty() {
            return Ok(std::collections::HashSet::new());
        }
        Ok(SysFlowTask::find()
            .filter(Column::BizType.eq(biz_type))
            .filter(Column::BizId.is_in(biz_ids))
            .filter(Column::Status.eq("pending"))
            .select_only()
            .column(Column::BizId)
            .into_tuple::<i64>()
            .all(self.base.db())
            .await?
            .into_iter()
            .collect())
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
            .col_expr(Column::ActedAt, Expr::current_timestamp());
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
            // 换持有人即重置提醒状态：首次提醒语义针对**当前持有人**，
            // 不重置会让转办后的新持有人永远收不到首次提醒（W-7）。
            .col_expr(
                Column::LastRemindedAt,
                Expr::value(Option::<NaiveDateTime>::None),
            )
            .filter(Column::TaskId.eq(task_id))
            .filter(Column::Status.eq("pending"))
            .exec(self.base.db())
            .await?;
        Ok(res.rows_affected)
    }

    /// 同轮同节点是否已存在指定审批人的任务行（加签防重，W-3）
    pub async fn exists_node_assignee(
        &self,
        biz_type: &str,
        biz_id: i64,
        round_no: i32,
        node_seq: i32,
        assignee_id: i64,
    ) -> Result<bool, DbErr> {
        Ok(SysFlowTask::find()
            .filter(Column::BizType.eq(biz_type))
            .filter(Column::BizId.eq(biz_id))
            .filter(Column::RoundNo.eq(round_no))
            .filter(Column::NodeSeq.eq(node_seq))
            .filter(Column::AssigneeId.eq(assignee_id))
            .count(self.base.db())
            .await?
            > 0)
    }

    /// 将同轮同节点的全部 pending 行升级为会签（加签语义：节点由单审转会签，须全部通过）
    pub async fn mark_node_countersign(
        &self,
        biz_type: &str,
        biz_id: i64,
        round_no: i32,
        node_seq: i32,
    ) -> Result<u64, DbErr> {
        let res = SysFlowTask::update_many()
            .col_expr(Column::TaskType, Expr::value("countersign"))
            .filter(Column::BizType.eq(biz_type))
            .filter(Column::BizId.eq(biz_id))
            .filter(Column::RoundNo.eq(round_no))
            .filter(Column::NodeSeq.eq(node_seq))
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
            .col_expr(Column::ActedAt, Expr::current_timestamp())
            .filter(Column::BizType.eq(biz_type))
            .filter(Column::BizId.eq(biz_id))
            .filter(Column::RoundNo.eq(round_no))
            .filter(Column::Status.eq("pending"))
            .exec(self.base.db())
            .await?;
        Ok(res.rows_affected)
    }

    /// 取消同轮同节点的 pending 行（G-02 M2：or_sign 任一通过 / weighted 达标后，
    /// 兄弟待办随节点完成收敛）。当前行已 approved（非 pending），条件更新天然排除自身。
    pub async fn cancel_pending_by_node(
        &self,
        biz_type: &str,
        biz_id: i64,
        round_no: i32,
        node_seq: i32,
        tenant_scope: Option<i64>,
    ) -> Result<u64, DbErr> {
        let mut upd = SysFlowTask::update_many()
            .col_expr(Column::Status, Expr::value("cancelled"))
            .col_expr(Column::ActedAt, Expr::current_timestamp())
            .filter(Column::BizType.eq(biz_type))
            .filter(Column::BizId.eq(biz_id))
            .filter(Column::RoundNo.eq(round_no))
            .filter(Column::NodeSeq.eq(node_seq))
            .filter(Column::Status.eq("pending"));
        if let Some(t) = tenant_scope {
            upd = upd.filter(Column::TenantId.eq(t));
        }
        let res = upd.exec(self.base.db()).await?;
        Ok(res.rows_affected)
    }

    /// 委派（G-02 M2）：pending 行换受托人并记录转出人（`delegate_from`），
    /// 语义与转办同型——处理后回不到转出人；换持有人重置首次提醒（对齐 W-7）。
    pub async fn delegate_if_pending(
        &self,
        task_id: i64,
        new_assignee_id: i64,
        delegate_from: i64,
    ) -> Result<u64, DbErr> {
        let res = SysFlowTask::update_many()
            .col_expr(Column::AssigneeId, Expr::value(new_assignee_id))
            .col_expr(Column::DelegateFrom, Expr::value(delegate_from))
            .col_expr(
                Column::LastRemindedAt,
                Expr::value(Option::<NaiveDateTime>::None),
            )
            .filter(Column::TaskId.eq(task_id))
            .filter(Column::Status.eq("pending"))
            .exec(self.base.db())
            .await?;
        Ok(res.rows_affected)
    }

    /// 减签·未投票：pending 行置 cancelled（G-02 M2，节点判定已兼容 cancelled 行）
    pub async fn cancel_row_if_pending(&self, task_id: i64) -> Result<u64, DbErr> {
        let res = SysFlowTask::update_many()
            .col_expr(Column::Status, Expr::value("cancelled"))
            .col_expr(Column::ActedAt, Expr::current_timestamp())
            .filter(Column::TaskId.eq(task_id))
            .filter(Column::Status.eq("pending"))
            .exec(self.base.db())
            .await?;
        Ok(res.rows_affected)
    }

    /// 减签·已投票：approved 行置 discarded（投票事实保留在流水，行不再参与聚合——
    /// countersign 判定"无 pending 且有 approved"天然排除 discarded，G-02 M2）
    pub async fn discard_row_if_approved(&self, task_id: i64) -> Result<u64, DbErr> {
        let res = SysFlowTask::update_many()
            .col_expr(Column::Status, Expr::value("discarded"))
            .filter(Column::TaskId.eq(task_id))
            .filter(Column::Status.eq("approved"))
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

    /// 全部 pending 任务（一致性巡检用，W-9；限量避免大库全扫）
    pub async fn find_pending_page(&self, offset: u64, limit: u64) -> Result<Vec<Model>, DbErr> {
        SysFlowTask::find()
            .filter(Column::Status.eq("pending"))
            .order_by_asc(Column::TaskId)
            .offset(offset)
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

    /// 按 `(biz_type, biz_id)` 批量取单据标题（`title` 为开轮时的冗余快照）
    ///
    /// 「已办」视图对**非内置示例**业务类型无单据表可联查（W-19：引擎不感知单据表结构），
    /// 故回退到 task 行快照，避免已办列表中标题恒为空。
    ///
    /// **必须带租户收敛**：唯一索引为 `uk_flow_task_tenant_biz (tenant_id, biz_type, biz_id, …)`，
    /// 即 `(biz_type, biz_id)` **不跨租户唯一**——若按 biz_id 无租户查询，
    /// 同一 `(biz_type, biz_id)` 在他租户存在时会取到他租户的标题（跨租户泄漏）。
    /// 调用方传**该流水行自身的 `tenant_id`**（`Some(tid)`），与 task 行开轮时写入的租户一致。
    pub async fn find_titles_by_biz(
        &self,
        biz_type: &str,
        biz_ids: Vec<i64>,
        tenant_scope: Option<i64>,
    ) -> Result<std::collections::HashMap<i64, String>, DbErr> {
        if biz_ids.is_empty() {
            return Ok(std::collections::HashMap::new());
        }
        let mut query = SysFlowTask::find()
            .filter(Column::BizType.eq(biz_type))
            .filter(Column::BizId.is_in(biz_ids));
        if let Some(tid) = tenant_scope {
            query = query.filter(Column::TenantId.eq(tid));
        }
        Ok(query
            .all(self.base.db())
            .await?
            .into_iter()
            .filter_map(|m| m.title.map(|t| (m.biz_id, t)))
            .collect())
    }
}
