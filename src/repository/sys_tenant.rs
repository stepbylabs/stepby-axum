// stepby-axum/src/repository/sys_tenant.rs
//! sys_tenant 数据访问层（多租户 Phase 3）
//!
//! 租户主表 = 租户身份唯一事实源（`tenant_id` 独立 id 空间，不复用 dept_id）。
//! 本 Repository 只做「租户行」的读写；组织树（sys_dept）与用户统计由服务层组合。

use sea_orm::*;

use crate::entity::sys_tenant::{Column, Entity as SysTenant, Model};
use crate::repository::base::BaseRepository;

/// 租户 Repository
#[derive(Clone)]
pub struct SysTenantRepository {
    base: BaseRepository<SysTenant>,
}

impl SysTenantRepository {
    pub fn new(db: DatabaseConnection) -> Self {
        Self {
            base: BaseRepository::new(db),
        }
    }

    pub fn base(&self) -> &BaseRepository<SysTenant> {
        &self.base
    }

    /// 按 tenant_id 查询未删除租户
    pub async fn find_active_by_id(&self, tenant_id: i64) -> Result<Option<Model>, DbErr> {
        SysTenant::find()
            .filter(Column::TenantId.eq(tenant_id))
            .filter(Column::DelFlag.eq("0"))
            .one(self.base.db())
            .await
    }

    /// 按 tenant_id 查询（含软删行，回收站/恢复链路用）
    pub async fn find_by_id_any(&self, tenant_id: i64) -> Result<Option<Model>, DbErr> {
        SysTenant::find()
            .filter(Column::TenantId.eq(tenant_id))
            .one(self.base.db())
            .await
    }

    /// tenant_code 占用探测（**含软删行**：唯一索引不分软删，软删行经 `_del_{id}` 让位）
    pub async fn find_by_code_any(&self, tenant_code: &str) -> Result<Option<Model>, DbErr> {
        SysTenant::find()
            .filter(Column::TenantCode.eq(tenant_code))
            .one(self.base.db())
            .await
    }

    /// 按 tenant_code 查询**可用**租户（DelFlag='0'；host→tid 解析回源用，status 判定在 service 层）
    pub async fn find_active_by_code(&self, tenant_code: &str) -> Result<Option<Model>, DbErr> {
        SysTenant::find()
            .filter(Column::TenantCode.eq(tenant_code))
            .filter(Column::DelFlag.eq("0"))
            .one(self.base.db())
            .await
    }

    /// 租户名重复探测（仅未删除行；同一名字允许被软删租户占用）
    pub async fn find_active_by_name(&self, tenant_name: &str) -> Result<Option<Model>, DbErr> {
        SysTenant::find()
            .filter(Column::TenantName.eq(tenant_name))
            .filter(Column::DelFlag.eq("0"))
            .one(self.base.db())
            .await
    }

    /// 批量查询 tenant_id → tenant_name（在线用户分层视图/审计展示；不含软删行）
    pub async fn find_name_map(&self, tenant_ids: &[i64]) -> Result<Vec<(i64, String)>, DbErr> {
        if tenant_ids.is_empty() {
            return Ok(Vec::new());
        }
        SysTenant::find()
            .select_only()
            .column(Column::TenantId)
            .column(Column::TenantName)
            .filter(Column::TenantId.is_in(tenant_ids.to_vec()))
            .filter(Column::DelFlag.eq("0"))
            .into_tuple::<(i64, String)>()
            .all(self.base.db())
            .await
    }

    /// 全部启用租户（登录/公开页按域名或在册租户定位时使用）
    pub async fn find_all_active(&self) -> Result<Vec<Model>, DbErr> {
        SysTenant::find()
            .filter(Column::DelFlag.eq("0"))
            .order_by_asc(Column::TenantId)
            .all(self.base.db())
            .await
    }
}
