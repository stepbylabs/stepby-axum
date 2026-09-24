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

    /// 按 (user_id, client_id) 查询**有效**授权记录（排除已撤销 del_flag='2'）
    pub async fn find_by_user_client(
        &self,
        user_id: i64,
        client_id: &str,
    ) -> Result<Option<Model>, DbErr> {
        Entity::find()
            .filter(Column::UserId.eq(user_id))
            .filter(Column::ClientId.eq(client_id))
            .filter(Column::DelFlag.ne("2"))
            .one(self.base.db())
            .await
    }

    /// 按 user_id 列出**有效**授权记录（自助"已授权应用"页，v2-I7）
    pub async fn find_by_user(&self, user_id: i64) -> Result<Vec<Model>, DbErr> {
        Entity::find()
            .filter(Column::UserId.eq(user_id))
            .filter(Column::DelFlag.ne("2"))
            .order_by_desc(Column::UpdateTime)
            .all(self.base.db())
            .await
    }

    /// 用户撤销对某 client 的授权。
    ///
    /// v5-E1 语义变更：由软删（del_flag='2'）改为**物理删除**——
    /// ① 组合唯一索引 (user_id, client_id) 要求撤销后可重新同意，软删的旧行会与
    ///    新授权行冲突（多次"同意→撤销"产生多行 del_flag='2' 使唯一键失效）；
    /// ② 审计痕迹由操作日志承接（撤销本身有 oper_log DELETE 记录），与
    ///    delete_clients 清理同意记录的物理删语义一致。
    /// 返回是否确实存在有效授权记录（不存在返回 Ok(false)）。
    pub async fn revoke(&self, user_id: i64, client_id: &str) -> Result<bool, DbErr> {
        let existing = self.find_by_user_client(user_id, client_id).await?;
        let Some(row) = existing else {
            return Ok(false);
        };
        row.delete(self.base.db()).await?;
        Ok(true)
    }

    /// 查询对某客户端存在**有效**授权的全部用户 ID（管理员删客户端时级联吊销其 SSO 令牌，v4-F2）
    pub async fn user_ids_by_client(&self, client_id: &str) -> Result<Vec<i64>, DbErr> {
        let rows = Entity::find()
            .filter(Column::ClientId.eq(client_id))
            .filter(Column::DelFlag.ne("2"))
            .all(self.base.db())
            .await?;
        Ok(rows.into_iter().map(|m| m.user_id).collect())
    }

    /// 删除某 client 的全部授权记录（管理员删除客户端时级联清理，v2-K4）
    pub async fn delete_by_client(&self, client_id: &str) -> Result<(), DbErr> {
        Entity::delete_many()
            .filter(Column::ClientId.eq(client_id))
            .exec(self.base.db())
            .await?;
        Ok(())
    }

    /// 写入/更新授权记录（存在即覆盖，否则插入；`client_name` 为同意时的名称快照）
    /// `tenant_id`：consent 随 user 归属其租户（operator 的 tid，调用方带出）
    pub async fn upsert(
        &self,
        user_id: i64,
        tenant_id: i64,
        client_id: &str,
        client_name_snapshot: &str,
        scopes_json: &str,
        consented_at: chrono::NaiveDateTime,
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
            am.client_name_snapshot = Set(client_name_snapshot.to_string());
            am.consented_at = Set(Some(consented_at));
            am.del_flag = Set("0".to_string());
            am.update_time = Set(Some(consented_at));
            am.update(db).await?;
        } else {
            let am = ActiveModel {
                consent_id: NotSet,
                tenant_id: Set(tenant_id),
                user_id: Set(user_id),
                client_id: Set(client_id.to_string()),
                scopes: Set(scopes_json.to_string()),
                client_name_snapshot: Set(client_name_snapshot.to_string()),
                consented_at: Set(Some(consented_at)),
                del_flag: Set("0".to_string()),
                create_time: Set(Some(consented_at)),
                update_time: Set(Some(consented_at)),
            };
            am.insert(db).await?;
        }
        Ok(())
    }
}
