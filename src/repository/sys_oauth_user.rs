// stepby-axum/src/repository/sys_oauth_user.rs
//! sys_oauth_user 数据访问层（第三方身份绑定表）
//!
//! 扩展查询：
//! - 按 (provider, provider_user_id) 查询绑定记录（OAuth 回调身份映射）
//! - 按 user_id 查询某本地账号的全部第三方绑定（绑定管理页）
//! - 更新/写入绑定记录

use sea_orm::*;

use crate::entity::sys_oauth_user::{ActiveModel, Column, Entity as SysOauthUser, Model};
use crate::repository::base::BaseRepository;

/// OAuth 身份绑定 Repository
#[derive(Clone)]
pub struct SysOauthUserRepository {
    base: BaseRepository<SysOauthUser>,
}

impl SysOauthUserRepository {
    pub fn new(db: DatabaseConnection) -> Self {
        Self {
            base: BaseRepository::new(db),
        }
    }

    pub fn base(&self) -> &BaseRepository<SysOauthUser> {
        &self.base
    }

    /// 按 (provider, provider_user_id) 查询绑定记录
    pub async fn find_by_provider_identity(
        &self,
        provider: &str,
        provider_user_id: &str,
    ) -> Result<Option<Model>, DbErr> {
        SysOauthUser::find()
            .filter(Column::Provider.eq(provider))
            .filter(Column::ProviderUserId.eq(provider_user_id))
            .one(self.base.db())
            .await
    }

    /// 查询某本地账号的全部第三方绑定（按 provider_user_id 去重后的历史，含已解绑）
    pub async fn find_by_user_id(&self, user_id: i64) -> Result<Vec<Model>, DbErr> {
        SysOauthUser::find()
            .filter(Column::UserId.eq(user_id))
            .order_by_asc(Column::Provider)
            .all(self.base.db())
            .await
    }

    /// 插入绑定记录
    pub async fn insert(&self, model: ActiveModel) -> Result<Model, DbErr> {
        self.base.insert(model).await
    }

    /// 更新绑定记录
    pub async fn update(&self, model: ActiveModel) -> Result<Model, DbErr> {
        self.base.update(model).await
    }

    /// 按 oauth_id 物理删除绑定记录
    pub async fn delete_by_oauth_id(&self, oauth_id: i64) -> Result<DeleteResult, DbErr> {
        SysOauthUser::delete_by_id(oauth_id)
            .exec(self.base.db())
            .await
    }

    /// 按提供商编码列表物理删除全部绑定（事务内版本）：
    /// 供删除 OAuth Provider 时级联清理孤儿绑定（E1-d）——
    /// provider 行删除后其绑定若无主可依，回调/绑定列表会读到悬空引用。
    pub async fn delete_by_providers_conn<C: ConnectionTrait>(
        &self,
        txn: &C,
        provider_codes: Vec<String>,
    ) -> Result<u64, DbErr> {
        if provider_codes.is_empty() {
            return Ok(0);
        }
        let res = SysOauthUser::delete_many()
            .filter(Column::Provider.is_in(provider_codes))
            .exec(txn)
            .await?;
        Ok(res.rows_affected)
    }
}
