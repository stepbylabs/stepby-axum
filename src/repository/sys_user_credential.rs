// backend-axum/src/repository/sys_user_credential.rs
//! WebAuthn / Passkey 凭据（sys_user_credential 表）数据访问层。
//!
//! 读取一律按 `del_flag = '0'` 过滤（纵深防御）；删除为**物理删除**（见 service 说明）。

use sea_orm::sea_query::Expr;
use sea_orm::*;

use crate::entity::sys_user_credential::{ActiveModel, Column, Entity as SysUserCredential, Model};
use crate::repository::base::BaseRepository;

/// WebAuthn 凭据 Repository
#[derive(Clone)]
pub struct SysUserCredentialRepository {
    base: BaseRepository<SysUserCredential>,
}

impl SysUserCredentialRepository {
    pub fn new(db: DatabaseConnection) -> Self {
        Self {
            base: BaseRepository::new(db),
        }
    }

    pub fn base(&self) -> &BaseRepository<SysUserCredential> {
        &self.base
    }

    /// 按认证器凭据 ID（Base64url）查询（登录认证热路径）。
    ///
    /// **刻意不按 `tenant_id` 过滤**：`credential_id` 是**认证面键**，登录时尚未解析出租户，
    /// 无法（也不应）用租户做前置过滤——与 `sys_pat::find_by_hash` / `sys_user::find_by_user_name`
    /// 同类（认证面键全局唯一，避免登录链路引入租户解析硬依赖，见项目约定 F-9/原则 A）。
    /// 跨租户面由**调用方**后续的租户闸门（`load_active_user` + 用户可用性校验）闭合。
    /// 该口径已在 `scripts/tenant-audit-allow.json` 的 `queries` 白名单登记理由。
    pub async fn find_by_credential_id(&self, credential_id: &str) -> Result<Option<Model>, DbErr> {
        SysUserCredential::find()
            .filter(Column::CredentialId.eq(credential_id))
            .filter(Column::DelFlag.eq("0"))
            .one(self.base.db())
            .await
    }

    /// 列出某用户全部有效凭据（按创建 id 倒序）。
    ///
    /// 并列 `tenant_id` 过滤（纵深防御）：`user_id` 已全局唯一、单条件即无跨租户面，
    /// 但按项目约定「按业务主体检索须带 tenant 证据」（审计器 R1 口径），显式过滤
    /// 可防"未来 `user_id` 语义变化"时的静默放大。
    pub async fn list_by_user(&self, user_id: i64, tenant_id: i64) -> Result<Vec<Model>, DbErr> {
        SysUserCredential::find()
            .filter(Column::UserId.eq(user_id))
            .filter(Column::TenantId.eq(tenant_id))
            .filter(Column::DelFlag.eq("0"))
            .order_by_desc(Column::CredId)
            .all(self.base.db())
            .await
    }

    /// 某用户是否已有同名凭据（用于"同名重复注册"拒绝）；过滤口径同 [`Self::list_by_user`]。
    pub async fn exists_name(
        &self,
        user_id: i64,
        tenant_id: i64,
        name: &str,
    ) -> Result<bool, DbErr> {
        Ok(SysUserCredential::find()
            .filter(Column::UserId.eq(user_id))
            .filter(Column::TenantId.eq(tenant_id))
            .filter(Column::Name.eq(name))
            .filter(Column::DelFlag.eq("0"))
            .count(self.base.db())
            .await?
            > 0)
    }

    /// 插入一条凭据（自增主键）
    pub async fn insert(&self, model: ActiveModel) -> Result<Model, DbErr> {
        self.base.insert(model).await
    }

    /// 更新签名计数器与最近使用时间（成功认证后）
    pub async fn update_counter(
        &self,
        credential_id: &str,
        sign_count: i64,
        last_used_at: chrono::NaiveDateTime,
    ) -> Result<(), DbErr> {
        SysUserCredential::update_many()
            .col_expr(Column::SignCount, Expr::value(sign_count))
            .col_expr(Column::LastUsedAt, Expr::value(last_used_at))
            .filter(Column::CredentialId.eq(credential_id))
            .exec(self.base.db())
            .await?;
        Ok(())
    }

    /// 按主键删除**归属于指定用户**的凭据（越权保护：user_id 不匹配则 0 行）。
    ///
    /// 返回受影响行数（0 = 不存在或不属于该用户 ⇒ 调用方按 404 处理）。
    pub async fn delete_owned(&self, cred_id: i64, user_id: i64) -> Result<u64, DbErr> {
        let res = SysUserCredential::delete_many()
            .filter(Column::CredId.eq(cred_id))
            .filter(Column::UserId.eq(user_id))
            .exec(self.base.db())
            .await?;
        Ok(res.rows_affected)
    }

    /// 按认证器凭据 ID + 归属用户删除（`PasskeyStore::delete_passkey` 语义）。
    pub async fn delete_by_credential_id(
        &self,
        user_id: i64,
        credential_id: &str,
    ) -> Result<u64, DbErr> {
        let res = SysUserCredential::delete_many()
            .filter(Column::CredentialId.eq(credential_id))
            .filter(Column::UserId.eq(user_id))
            .exec(self.base.db())
            .await?;
        Ok(res.rows_affected)
    }

    /// 重命名指定凭据（`PasskeyStore::update_passkey_name` 语义）
    pub async fn update_name(&self, credential_id: &str, name: &str) -> Result<(), DbErr> {
        SysUserCredential::update_many()
            .col_expr(Column::Name, Expr::value(name.to_string()))
            .filter(Column::CredentialId.eq(credential_id))
            .exec(self.base.db())
            .await?;
        Ok(())
    }
}
