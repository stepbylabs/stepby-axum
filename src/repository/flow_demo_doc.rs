// axum-backend/src/repository/flow_demo_doc.rs
//! flow_demo_doc 数据访问层（示例业务单据：请假申请）

use sea_orm::*;

use crate::entity::flow_demo_doc::{ActiveModel, Column, Entity as FlowDemoDoc, Model};
use crate::repository::base::BaseRepository;

/// 示例单据 Repository
#[derive(Clone)]
pub struct FlowDemoDocRepository {
    base: BaseRepository<FlowDemoDoc>,
}

impl FlowDemoDocRepository {
    pub fn new(db: DatabaseConnection) -> Self {
        Self {
            base: BaseRepository::new(db),
        }
    }

    pub fn base(&self) -> &BaseRepository<FlowDemoDoc> {
        &self.base
    }

    /// 我发起的（applicant + 全部状态）
    pub async fn find_mine_page(
        &self,
        applicant_id: i64,
        offset: u64,
        limit: u64,
    ) -> Result<(Vec<Model>, u64), DbErr> {
        let query = FlowDemoDoc::find().filter(Column::ApplicantId.eq(applicant_id));
        let total = query.clone().count(self.base.db()).await?;
        let rows = query
            .order_by_desc(Column::DocId)
            .offset(offset)
            .limit(limit)
            .all(self.base.db())
            .await?;
        Ok((rows, total))
    }

    /// 管理视图：全部单据（调用方需持有 system:flow:list 权限键，且自行叠加 data_scope）
    ///
    /// 多租户：`tenant_scope = Some(tid)` → 仅本租户单据；`None`（平台）→ 全量。
    pub async fn find_all_page(
        &self,
        status: Option<&str>,
        offset: u64,
        limit: u64,
        tenant_scope: Option<i64>,
    ) -> Result<(Vec<Model>, u64), DbErr> {
        let mut query = FlowDemoDoc::find();
        if let Some(t) = tenant_scope {
            query = query.filter(Column::TenantId.eq(t));
        }
        if let Some(st) = status {
            query = query.filter(Column::Status.eq(st));
        }
        let total = query.clone().count(self.base.db()).await?;
        let rows = query
            .order_by_desc(Column::DocId)
            .offset(offset)
            .limit(limit)
            .all(self.base.db())
            .await?;
        Ok((rows, total))
    }

    /// 按 ID 查询
    pub async fn find_by_id(&self, doc_id: i64) -> Result<Option<Model>, DbErr> {
        FlowDemoDoc::find_by_id(doc_id).one(self.base.db()).await
    }

    /// 插入
    pub async fn insert(&self, model: ActiveModel) -> Result<Model, DbErr> {
        self.base.insert(model).await
    }

    /// 更新
    pub async fn update(&self, model: ActiveModel) -> Result<Model, DbErr> {
        self.base.update(model).await
    }
}
