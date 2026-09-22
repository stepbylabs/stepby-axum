// axum-backend/src/repository/sys_oauth_consent.rs
//! sys_oauth_consent 数据访问层（OIDC Provider：用户对客户端的授权同意记录）
//!
//! - 按 (user_id, client_id) 查询已授予 scope；
//! - upsert：存在则更新 scopes/auth_time，不存在则插入（保证 user_id+client_id 唯一）。

use sea_orm::*;

use crate::entity::sys_oauth_consent::{ActiveModel, Column, Entity, Model};
use crate::repository::base::BaseRepository;

/// SSO 授权同意 Repository
#[derive(Clone)]
pub struct SysOauthConsentRepository {
    base: BaseRepository<Entity>,
}

impl SysOauthConsentRepository {
    pub fn new(db: DatabaseConnection) -> Self {
        Self {
            base: BaseRepository::new(db),
        }
    }

    pub fn base(&self) -> &BaseRepository<Entity> {
        &self.base
    }

    /// 按 (user_id, client_id) 查询授权记录
    pub async fn find_by_user_client(
        &self,
        user_id: i64,
        client_id: &str,
    ) -> Result<Option<Model>, DbErr> {
        Entity::find()
            .filter(Column::UserId.eq(user_id))
            .filter(Column::ClientId.eq(client_id))
            .one(self.base.db())
            .await
    }

    /// 写入/更新授权记录（存在即覆盖，否则插入）
    pub async fn upsert(
        &self,
        user_id: i64,
        client_id: &str,
        scopes_json: &str,
        auth_time: chrono::NaiveDateTime,
    ) -> Result<(), DbErr> {
        let db = self.base.db();
        let existing = Entity::find()
            .filter(Column::UserId.eq(user_id))
            .filter(Column::ClientId.eq(client_id))
            .one(db)
            .await?;
        if let Some(row) = existing {
            let mut am: ActiveModel = row.into();
            am.scopes = Set(scopes_json.to_string());
            am.auth_time = Set(Some(auth_time));
            am.update_time = Set(Some(auth_time));
            am.update(db).await?;
        } else {
            let am = ActiveModel {
                consent_id: NotSet,
                user_id: Set(user_id),
                client_id: Set(client_id.to_string()),
                scopes: Set(scopes_json.to_string()),
                auth_time: Set(Some(auth_time)),
                create_time: Set(Some(auth_time)),
                update_time: Set(Some(auth_time)),
            };
            am.insert(db).await?;
        }
        Ok(())
    }
}
