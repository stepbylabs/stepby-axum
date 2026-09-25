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

    /// 追加一条流水
    pub async fn insert(&self, model: ActiveModel) -> Result<Model, DbErr> {
        self.base.insert(model).await
    }
}
