// axum-backend/src/repository/sys_tenant_domain.rs
//! sys_tenant_domain 数据访问层（多租户 Phase 3 域名绑定链路）
//!
//! 域名表语义：`domain` **全局唯一**（唯一索引不分软删，历史占用同样拦截），
//! 故占用探测必须用 [`SysTenantDomainRepository::find_by_domain_any`]（含软删行）。

use sea_orm::sea_query::Expr;
use sea_orm::*;

use crate::entity::sys_tenant_domain::{Column, Entity as SysTenantDomain, Model};
use crate::repository::base::BaseRepository;

/// 租户域名 Repository
#[derive(Clone)]
pub struct SysTenantDomainRepository {
    base: BaseRepository<SysTenantDomain>,
}

impl SysTenantDomainRepository {
    pub fn new(db: DatabaseConnection) -> Self {
        Self {
            base: BaseRepository::new(db),
        }
    }

    pub fn base(&self) -> &BaseRepository<SysTenantDomain> {
        &self.base
    }

    /// 按 domain_id 查询未删除行
    pub async fn find_by_id(&self, domain_id: i64) -> Result<Option<Model>, DbErr> {
        SysTenantDomain::find()
            .filter(Column::DomainId.eq(domain_id))
            .filter(Column::DelFlag.eq("0"))
            .one(self.base.db())
            .await
    }

    /// 按 domain 查询（**含软删行**：唯一索引不分软删，历史占用同样需拦截）
    pub async fn find_by_domain_any(&self, domain: &str) -> Result<Option<Model>, DbErr> {
        SysTenantDomain::find()
            .filter(Column::Domain.eq(domain))
            .one(self.base.db())
            .await
    }

    /// 按 domain 查询**可解析**行为（del_flag='0' + status='0' + verify_status='1'）：
    /// host→tid 解析回源专用，仅返回已验证且启用的绑定。
    pub async fn find_active_by_domain(&self, domain: &str) -> Result<Option<Model>, DbErr> {
        SysTenantDomain::find()
            .filter(Column::Domain.eq(domain))
            .filter(Column::DelFlag.eq("0"))
            .filter(Column::Status.eq("0"))
            .filter(Column::VerifyStatus.eq("1"))
            .one(self.base.db())
            .await
    }

    /// 域名列表（del_flag='0'；`tenant_id=Some(tid)` 时仅本租户，`None` 为平台全量）
    pub async fn list(&self, tenant_id: Option<i64>) -> Result<Vec<Model>, DbErr> {
        let mut query = SysTenantDomain::find().filter(Column::DelFlag.eq("0"));
        if let Some(tid) = tenant_id {
            query = query.filter(Column::TenantId.eq(tid));
        }
        query
            .order_by_asc(Column::TenantId)
            .order_by_asc(Column::IsPrimary)
            .order_by_asc(Column::DomainId)
            .all(self.base.db())
            .await
    }

    /// 按租户查询主域名（is_primary='0'，未删除）
    pub async fn find_primary_by_tenant(&self, tenant_id: i64) -> Result<Option<Model>, DbErr> {
        SysTenantDomain::find()
            .filter(Column::TenantId.eq(tenant_id))
            .filter(Column::IsPrimary.eq("0"))
            .filter(Column::DelFlag.eq("0"))
            .order_by_asc(Column::DomainId)
            .one(self.base.db())
            .await
    }

    /// 该租户未删除域名数量
    pub async fn count_by_tenant(&self, tenant_id: i64) -> Result<u64, DbErr> {
        SysTenantDomain::find()
            .filter(Column::TenantId.eq(tenant_id))
            .filter(Column::DelFlag.eq("0"))
            .count(self.base.db())
            .await
    }

    /// 插入一条域名行（返回完整 Model）
    pub async fn insert(
        &self,
        model: crate::entity::sys_tenant_domain::ActiveModel,
    ) -> Result<Model, DbErr> {
        self.base.insert(model).await
    }

    /// 更新一条域名行（返回更新后的 Model）
    pub async fn update(
        &self,
        model: crate::entity::sys_tenant_domain::ActiveModel,
    ) -> Result<Model, DbErr> {
        self.base.update(model).await
    }

    /// 软删（del_flag='2'，并记录 update_by / update_time）
    pub async fn soft_delete(&self, domain_id: i64, operator: &str) -> Result<u64, DbErr> {
        let res = SysTenantDomain::update_many()
            .col_expr(Column::DelFlag, Expr::value("2"))
            .col_expr(Column::UpdateBy, Expr::value(operator))
            .col_expr(
                Column::UpdateTime,
                Expr::value(crate::common::datetime::now_naive()),
            )
            .filter(Column::DomainId.eq(domain_id))
            .filter(Column::DelFlag.eq("0"))
            .exec(self.base.db())
            .await?;
        Ok(res.rows_affected)
    }
}
