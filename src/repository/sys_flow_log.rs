// axum-backend/src/repository/sys_flow_log.rs
//! sys_flow_log 数据访问层（审批流水：语义级动作时间线）
//!
//! 本表为审批凭证，永不纳入日志保留期清理（cleanup_expired_logs 只清 oper_log/logininfor）。

use sea_orm::*;

use crate::entity::sys_flow_log::{ActiveModel, Column, Entity as SysFlowLog, Model};
use crate::repository::base::BaseRepository;

/// 审批流水 Repository
#[derive(Clone)]
pub struct SysFlowLogRepository {
    base: BaseRepository<SysFlowLog>,
}

impl SysFlowLogRepository {
    pub fn new(db: DatabaseConnection) -> Self {
        Self {
            base: BaseRepository::new(db),
        }
    }

    pub fn base(&self) -> &BaseRepository<SysFlowLog> {
        &self.base
    }

    /// 时间线：某单据全部轮次的动作流（按轮次+时间正序）
    ///
    /// 多租户：`tenant_scope = Some(tid)` → 仅本租户流水；`None`（平台）→ 全量。
    pub async fn find_timeline(
        &self,
        biz_type: &str,
        biz_id: i64,
        tenant_scope: Option<i64>,
    ) -> Result<Vec<Model>, DbErr> {
        let mut query = SysFlowLog::find()
            .filter(Column::BizType.eq(biz_type))
            .filter(Column::BizId.eq(biz_id));
        if let Some(t) = tenant_scope {
            query = query.filter(Column::TenantId.eq(t));
        }
        query
            .order_by_asc(Column::RoundNo)
            .order_by_asc(Column::LogId)
            .all(self.base.db())
            .await
    }

    /// 「已办」分页：我作为**审批人**处理过的流水（W-8）
    ///
    /// 口径：`operator_id = 我` 且 `action ∈ {approve, reject}`（即裁决类动作）；
    /// 提交/撤回/重提交/转办/加签属"发起侧或流转动作"，不计入"我审批过的"。
    /// 索引 `idx_flow_log_operator (operator_id, acted_at)`（W-12）完全覆盖本查询。
    pub async fn find_done_page(
        &self,
        operator_id: i64,
        offset: u64,
        limit: u64,
    ) -> Result<(Vec<Model>, u64), DbErr> {
        let query = SysFlowLog::find()
            .filter(Column::OperatorId.eq(operator_id))
            .filter(Column::Action.is_in(vec!["approve", "reject"]));
        let total = query.clone().count(self.base.db()).await?;
        let rows = query
            .order_by_desc(Column::ActedAt)
            .order_by_desc(Column::LogId)
            .offset(offset)
            .limit(limit)
            .all(self.base.db())
            .await?;
        Ok((rows, total))
    }

    /// 追加一条流水
    pub async fn insert(&self, model: ActiveModel) -> Result<Model, DbErr> {
        self.base.insert(model).await
    }
}
