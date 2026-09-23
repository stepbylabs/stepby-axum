// axum-backend/src/repository/sys_oauth_client.rs
//! sys_oauth_client 数据访问层（OIDC Provider：已注册客户端配置表）
//!
//! 继承 BaseRepository 通用 CRUD，扩展客户端特有查询：
//! - 按 client_id 查询（公开标识，鉴权热路径）
//! - 分页查询（client_name 模糊 + enabled 精确）
//! - 按内部主键 sso_client_id 查询、批量删除、启停

use sea_orm::sea_query::Expr;
use sea_orm::*;

use crate::common::like_escape;
use crate::entity::sys_oauth_client::{ActiveModel, Column, Entity as SysOauthClient, Model};
use crate::repository::base::BaseRepository;

/// SSO 客户端 Repository
#[derive(Clone)]
pub struct SysOauthClientRepository {
    base: BaseRepository<SysOauthClient>,
}

impl SysOauthClientRepository {
    pub fn new(db: DatabaseConnection) -> Self {
        Self {
            base: BaseRepository::new(db),
        }
    }

    pub fn base(&self) -> &BaseRepository<SysOauthClient> {
        &self.base
    }

    /// 按内部主键查询（排除软删）
    pub async fn find_by_pk(&self, sso_client_id: i64) -> Result<Option<Model>, DbErr> {
        SysOauthClient::find()
            .filter(Column::SsoClientId.eq(sso_client_id))
            .filter(Column::DelFlag.ne("2"))
            .one(self.base.db())
            .await
    }

    /// 按 client_id（公开标识）查询（唯一；排除软删——软删的 client 一切协议行为失效）
    pub async fn find_by_client_id(&self, client_id: &str) -> Result<Option<Model>, DbErr> {
        SysOauthClient::find()
            .filter(Column::ClientId.eq(client_id))
            .filter(Column::DelFlag.ne("2"))
            .one(self.base.db())
            .await
    }

    /// client_id 是否已存在（含软删——client_id 唯一约束不因软删释放，防重建同名 client
    /// 继承旧用户授权记录造成静默授权，v2-K4）
    pub async fn exists_by_client_id(&self, client_id: &str) -> Result<bool, DbErr> {
        let count = SysOauthClient::find()
            .filter(Column::ClientId.eq(client_id))
            .count(self.base.db())
            .await?;
        Ok(count > 0)
    }

    /// 分页查询（client_name 模糊 + client_id/enabled 精确；仅有效记录）
    pub async fn find_page_filtered(
        &self,
        offset: u64,
        limit: u64,
        client_name: Option<&str>,
        client_id: Option<&str>,
        enabled: Option<&str>,
    ) -> Result<(Vec<Model>, u64), DbErr> {
        let mut query = SysOauthClient::find().filter(Column::DelFlag.ne("2"));
        if let Some(name) = client_name {
            query = query.filter(Column::ClientName.like(format!("%{}%", like_escape(name))));
        }
        if let Some(cid) = client_id {
            query = query.filter(Column::ClientId.eq(cid));
        }
        if let Some(en) = enabled {
            query = query.filter(Column::Enabled.eq(en));
        }
        query = query.order_by_desc(Column::SsoClientId);

        let total = query.clone().count(self.base.db()).await?;
        let rows = query
            .offset(offset)
            .limit(limit)
            .all(self.base.db())
            .await?;
        Ok((rows, total))
    }

    /// 插入客户端（返回带自增主键的 Model）
    pub async fn insert(&self, model: ActiveModel) -> Result<Model, DbErr> {
        self.base.insert(model).await
    }

    /// 更新客户端
    pub async fn update(&self, model: ActiveModel) -> Result<Model, DbErr> {
        self.base.update(model).await
    }

    /// 软删除（v2-K7/P1-5：对齐 sys_* 规范，del_flag='2'；物理删除会留下孤儿授权记录与
    /// "重建同名 client 继承旧授权"的静默授权风险）
    pub async fn soft_delete_by_ids(&self, ids: Vec<i64>) -> Result<(), DbErr> {
        let now = crate::common::datetime::now_naive();
        SysOauthClient::update_many()
            .col_expr(Column::DelFlag, Expr::value("2"))
            .col_expr(Column::UpdateTime, Expr::value(now))
            .filter(Column::SsoClientId.is_in(ids))
            .exec(self.base.db())
            .await?;
        Ok(())
    }
}
