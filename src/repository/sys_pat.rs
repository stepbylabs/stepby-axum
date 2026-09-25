// axum-backend/src/repository/sys_pat.rs
//! 个人访问令牌（sys_pat 表）数据访问层
//!
//! 提供鉴权查库（按 token_hash）、按用户/全量分页、吊销与最近使用时间更新。
//! 插入使用应用生成的 pat_id（uuid），直接走 SeaORM `insert`，不经 BaseRepository::insert
//! （其对 MySQL 非自增主键表返回错误指引）。

use sea_orm::sea_query::Expr;
use sea_orm::*;

use crate::entity::sys_pat::{ActiveModel, Column, Entity as SysPat, Model};
use crate::entity::sys_user;
use crate::repository::base::BaseRepository;

/// 个人访问令牌 Repository
#[derive(Clone)]
pub struct SysPatRepository {
    base: BaseRepository<SysPat>,
}

impl SysPatRepository {
    pub fn new(db: DatabaseConnection) -> Self {
        Self {
            base: BaseRepository::new(db),
        }
    }

    pub fn base(&self) -> &BaseRepository<SysPat> {
        &self.base
    }

    /// 按 token_hash 查询（鉴权热路径）
    pub async fn find_by_hash(&self, token_hash: &str) -> Result<Option<Model>, DbErr> {
        SysPat::find()
            .filter(Column::TokenHash.eq(token_hash))
            .one(self.base.db())
            .await
    }

    /// 插入一条令牌记录（pat_id 由调用方生成）
    pub async fn insert(&self, model: Model) -> Result<(), DbErr> {
        let am: ActiveModel = model.into();
        SysPat::insert(am).exec(self.base.db()).await?;
        Ok(())
    }

    /// 统计某用户当前有效（status='0'）令牌数，用于上限校验
    pub async fn count_active_by_user(&self, user_id: i64) -> Result<u64, DbErr> {
        SysPat::find()
            .filter(Column::UserId.eq(user_id))
            .filter(Column::Status.eq("0"))
            .count(self.base.db())
            .await
    }

    /// 按用户分页查询令牌（自助管理，含已吊销）
    pub async fn find_page_by_user(
        &self,
        user_id: i64,
        offset: u64,
        limit: u64,
    ) -> Result<(Vec<Model>, u64), DbErr> {
        let query = SysPat::find().filter(Column::UserId.eq(user_id));
        let total = query.clone().count(self.base.db()).await?;
        let rows = query
            .order_by_desc(Column::CreateTime)
            .offset(offset)
            .limit(limit)
            .all(self.base.db())
            .await?;
        Ok((rows, total))
    }

    /// 全量分页查询（管理员），可选按 user_id 过滤
    ///
    /// 多租户：`tenant_scope = Some(tid)` → 仅本租户令牌；`None`（平台）→ 全量。
    pub async fn find_page_all(
        &self,
        user_id: Option<i64>,
        offset: u64,
        limit: u64,
        tenant_scope: Option<i64>,
    ) -> Result<(Vec<Model>, u64), DbErr> {
        let mut query = SysPat::find();
        if let Some(t) = tenant_scope {
            query = query.filter(Column::TenantId.eq(t));
        }
        if let Some(uid) = user_id {
            query = query.filter(Column::UserId.eq(uid));
        }
        let total = query.clone().count(self.base.db()).await?;
        let rows = query
            .order_by_desc(Column::CreateTime)
            .offset(offset)
            .limit(limit)
            .all(self.base.db())
            .await?;
        Ok((rows, total))
    }

    /// 吊销令牌（置 status='1'），返回受影响行数
    ///
    /// `owner_user_id` 为 Some 时仅吊销该用户的令牌（自助场景越权保护）；None 为管理员场景。
    pub async fn revoke(&self, pat_id: &str, owner_user_id: Option<i64>) -> Result<u64, DbErr> {
        let mut update = SysPat::update_many()
            .col_expr(Column::Status, Expr::value("1"))
            .col_expr(
                Column::UpdateTime,
                Expr::value(crate::common::datetime::now_naive()),
            )
            .filter(Column::PatId.eq(pat_id));
        if let Some(uid) = owner_user_id {
            update = update.filter(Column::UserId.eq(uid));
        }
        let res = update.exec(self.base.db()).await?;
        Ok(res.rows_affected)
    }

    /// best-effort 更新最近使用时间
    pub async fn touch_last_used(&self, pat_id: &str) -> Result<(), DbErr> {
        SysPat::update_many()
            .col_expr(
                Column::LastUsedAt,
                Expr::value(crate::common::datetime::now_naive()),
            )
            .filter(Column::PatId.eq(pat_id))
            .exec(self.base.db())
            .await?;
        Ok(())
    }

    /// 批量解析 user_id → user_name（供管理员列表显示属主用户名）
    pub async fn find_usernames(&self, user_ids: &[i64]) -> Result<Vec<(i64, String)>, DbErr> {
        if user_ids.is_empty() {
            return Ok(Vec::new());
        }
        let rows = sys_user::Entity::find()
            .filter(sys_user::Column::UserId.is_in(user_ids.iter().copied()))
            .all(self.base.db())
            .await?;
        Ok(rows.into_iter().map(|u| (u.user_id, u.user_name)).collect())
    }
}
