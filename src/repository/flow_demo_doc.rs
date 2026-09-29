// backend-axum/src/repository/flow_demo_doc.rs
//! flow_demo_doc 数据访问层（示例业务单据：请假申请）

use sea_orm::*;

use crate::entity::flow_demo_doc::{ActiveModel, Column, Entity as FlowDemoDoc, Model};
use crate::repository::base::BaseRepository;

/// 示例单据 Repository
#[derive(Clone)]
pub struct FlowDemoDocRepository {
    base: BaseRepository<FlowDemoDoc>,
}

/// 管理视图的单据可见范围（W-5 / 方案 §7.6 定案：「部门树 + 本人」）
///
/// 单据表不含自定义字段，故 `custom_sql`（`sys_user` 字段白名单语义）**不适用**，
/// 显式不参与过滤；需要"自定义部门"语义时按 `sys_role_dept` 绑定落为 `Depts`。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FlowDocScope {
    /// 全部可见（超管 / `data_scope=1`）
    All,
    /// 按**提交人部门**限定（`data_scope=2/3/4` 解析出的部门集合；空集合 ⇒ 不可见任何单据）
    Depts(Vec<i64>),
    /// 仅本人发起（`data_scope=5`；以及无角色/未知值时的安全降级）
    Applicant(i64),
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

    /// 管理视图：全部单据（调用方需持有 `system:flow:list` 权限键）
    ///
    /// - `tenant_scope`：`Some(tid)` → 仅本租户单据；`None`（平台）→ 全量
    /// - `doc_scope`：调用方按操作者 `data_scope` 解析出的单据可见范围（W-5）
    pub async fn find_all_page(
        &self,
        status: Option<&str>,
        offset: u64,
        limit: u64,
        tenant_scope: Option<i64>,
        doc_scope: &FlowDocScope,
    ) -> Result<(Vec<Model>, u64), DbErr> {
        let mut query = FlowDemoDoc::find();
        if let Some(t) = tenant_scope {
            query = query.filter(Column::TenantId.eq(t));
        }
        if let Some(st) = status {
            query = query.filter(Column::Status.eq(st));
        }
        match doc_scope {
            FlowDocScope::All => {}
            FlowDocScope::Depts(ids) => {
                // 空部门集合表示"不可见任何单据"：直接短路，避免生成 `IN ()` 非法 SQL
                if ids.is_empty() {
                    return Ok((vec![], 0));
                }
                query = query.filter(Column::DeptId.is_in(ids.clone()));
            }
            FlowDocScope::Applicant(uid) => {
                query = query.filter(Column::ApplicantId.eq(*uid));
            }
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

    /// 按状态分页取单据（一致性巡检用，W-9）
    pub async fn find_page_by_status(
        &self,
        status: &str,
        offset: u64,
        limit: u64,
    ) -> Result<Vec<Model>, DbErr> {
        FlowDemoDoc::find()
            .filter(Column::Status.eq(status))
            .order_by_asc(Column::DocId)
            .offset(offset)
            .limit(limit)
            .all(self.base.db())
            .await
    }

    /// 批量取单据标题（已办视图展示用，W-8；一次 `IN` 查询避免 N+1）
    ///
    /// **必须带租户收敛**：`flow_demo_doc.tenant_id` 为提交时写入的申请人租户，
    /// 而单据主键 `doc_id` 是全局自增——不带租户过滤虽不会串 id，
    /// 但与他租户的 id 集合混查会形成越权可见面（与 `find_all_page` 同款纵深防御）。
    /// 调用方传**该流水行自身的 `tenant_id`**（与单据提交时写入的一致）。
    pub async fn find_titles_by_ids(
        &self,
        doc_ids: Vec<i64>,
        tenant_scope: Option<i64>,
    ) -> Result<std::collections::HashMap<i64, String>, DbErr> {
        if doc_ids.is_empty() {
            return Ok(std::collections::HashMap::new());
        }
        let mut query = FlowDemoDoc::find().filter(Column::DocId.is_in(doc_ids));
        if let Some(tid) = tenant_scope {
            query = query.filter(Column::TenantId.eq(tid));
        }
        Ok(query
            .all(self.base.db())
            .await?
            .into_iter()
            .map(|m| (m.doc_id, m.title))
            .collect())
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
