// axum-backend/src/repository/sys_oauth_provider.rs
//! sys_oauth_provider 数据访问层（OAuth2/OIDC 登录提供商配置表）
//!
//! 继承 BaseRepository 通用 CRUD，扩展提供商特有查询：
//! - 按 provider_code 查询提供商（唯一编码）
//! - 分页查询（name/code/type/status 过滤）
//! - 查询所有启用提供商（登录页展示 + 授权 URL 生成）
//! - 按 ID 列表物理删除

use sea_orm::*;

use crate::common::like_escape;
use crate::entity::sys_oauth_provider::{ActiveModel, Column, Entity as SysOauthProvider, Model};
use crate::repository::base::BaseRepository;

/// OAuth 提供商 Repository
#[derive(Clone)]
pub struct SysOauthProviderRepository {
    base: BaseRepository<SysOauthProvider>,
}

impl SysOauthProviderRepository {
    pub fn new(db: DatabaseConnection) -> Self {
        Self {
            base: BaseRepository::new(db),
        }
    }

    pub fn base(&self) -> &BaseRepository<SysOauthProvider> {
        &self.base
    }

    /// 按 provider_id 查询提供商
    pub async fn find_by_id(&self, provider_id: i64) -> Result<Option<Model>, DbErr> {
        SysOauthProvider::find()
            .filter(Column::ProviderId.eq(provider_id))
            .one(self.base.db())
            .await
    }

    /// 按 provider_code 查询提供商（唯一编码）
    ///
    /// 多租户：仅匹配平台级提供商（tid=0）。本方法只服务于匿名登录链路
    /// （begin_oauth / oauth_callback），匿名请求无租户上下文，租户专属
    /// 提供商（tid≠0）不允许进入匿名授权流程。
    pub async fn find_by_code(&self, provider_code: &str) -> Result<Option<Model>, DbErr> {
        SysOauthProvider::find()
            .filter(Column::ProviderCode.eq(provider_code))
            .filter(Column::TenantId.eq(0))
            .one(self.base.db())
            .await
    }

    /// 按 provider_code 判断是否已存在
    pub async fn exists_by_code(&self, provider_code: &str) -> Result<bool, DbErr> {
        let count = SysOauthProvider::find()
            .filter(Column::ProviderCode.eq(provider_code))
            .count(self.base.db())
            .await?;
        Ok(count > 0)
    }

    /// 查询所有已启用提供商（登录页展示 + 生成授权 URL）
    ///
    /// 多租户：登录页为匿名全局入口，仅展示平台级提供商（tid=0）；
    /// 租户专属提供商（tid≠0）需租户上下文场景，不进入登录页。
    pub async fn find_all_enabled(&self) -> Result<Vec<Model>, DbErr> {
        SysOauthProvider::find()
            .filter(Column::Enabled.eq("1"))
            .filter(Column::TenantId.eq(0))
            .order_by_asc(Column::DisplayOrder)
            .all(self.base.db())
            .await
    }

    /// 分页查询提供商（provider_name 模糊 + provider_code/provider_type/enabled 精确）
    ///
    /// 多租户：tenant_scope 为 Some(tid) 时仅返回该租户（含平台 tid=0 由调用方
    /// 传入 None 表示平台全量可见）。
    #[allow(clippy::too_many_arguments)]
    pub async fn find_page_filtered(
        &self,
        offset: u64,
        limit: u64,
        provider_name: Option<&str>,
        provider_code: Option<&str>,
        provider_type: Option<&str>,
        enabled: Option<&str>,
        tenant_scope: Option<i64>,
    ) -> Result<(Vec<Model>, u64), DbErr> {
        let mut query = SysOauthProvider::find();
        if let Some(tid) = tenant_scope {
            query = query.filter(Column::TenantId.eq(tid));
        }
        if let Some(name) = provider_name {
            query = query.filter(Column::ProviderName.like(format!("%{}%", like_escape(name))));
        }
        if let Some(code) = provider_code {
            query = query.filter(Column::ProviderCode.eq(code));
        }
        if let Some(ty) = provider_type {
            query = query.filter(Column::ProviderType.eq(ty));
        }
        if let Some(en) = enabled {
            query = query.filter(Column::Enabled.eq(en));
        }
        query = query
            .order_by_asc(Column::DisplayOrder)
            .order_by_asc(Column::ProviderId);

        let total = query.clone().count(self.base.db()).await?;
        let rows = query
            .offset(offset)
            .limit(limit)
            .all(self.base.db())
            .await?;
        Ok((rows, total))
    }

    /// 按 ID 列表批量查询提供商
    pub async fn find_by_ids(&self, provider_ids: &[i64]) -> Result<Vec<Model>, DbErr> {
        if provider_ids.is_empty() {
            return Ok(Vec::new());
        }
        SysOauthProvider::find()
            .filter(Column::ProviderId.is_in(provider_ids.to_vec()))
            .all(self.base.db())
            .await
    }

    /// 按 ID 列表物理删除
    pub async fn delete_by_ids(&self, provider_ids: Vec<i64>) -> Result<DeleteResult, DbErr> {
        SysOauthProvider::delete_many()
            .filter(Column::ProviderId.is_in(provider_ids))
            .exec(self.base.db())
            .await
    }

    /// 插入提供商
    pub async fn insert(&self, model: ActiveModel) -> Result<Model, DbErr> {
        self.base.insert(model).await
    }

    /// 更新提供商
    pub async fn update(&self, model: ActiveModel) -> Result<Model, DbErr> {
        self.base.update(model).await
    }
}
