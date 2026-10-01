// stepby-axum/src/repository/sys_web_hook_log.rs
//! sys_web_hook_log 数据访问层（WebHook 推送记录表，物理删除）
//!
//! 继承 BaseRepository 通用 CRUD，扩展记录特有查询：
//! - 按 id 查询
//! - 分页查询（hook_id/event_type/status 过滤）
//! - 查询失败记录（供手动重试）
//! - 单条/批量物理删除、全量清空
//! - 按时间清理过期记录（审计保留期）

use sea_orm::sea_query::Expr;
use sea_orm::*;

use crate::common::like_escape;
use crate::entity::sys_web_hook_log::{ActiveModel, Column, Entity as SysWebHookLog, Model};
use crate::repository::base::BaseRepository;

/// WebHook 推送记录 Repository
#[derive(Clone)]
pub struct SysWebHookLogRepository {
    base: BaseRepository<SysWebHookLog>,
}

impl SysWebHookLogRepository {
    pub fn new(db: DatabaseConnection) -> Self {
        Self {
            base: BaseRepository::new(db),
        }
    }

    pub fn base(&self) -> &BaseRepository<SysWebHookLog> {
        &self.base
    }

    /// 按 id 查询记录
    pub async fn find_by_id(&self, id: i64) -> Result<Option<Model>, DbErr> {
        SysWebHookLog::find_by_id(id).one(self.base.db()).await
    }

    /// 按 ID 列表查询记录（用于重试前校验）
    pub async fn find_by_ids(&self, ids: &[i64]) -> Result<Vec<Model>, DbErr> {
        if ids.is_empty() {
            return Ok(Vec::new());
        }
        SysWebHookLog::find()
            .filter(Column::Id.is_in(ids.to_vec()))
            .all(self.base.db())
            .await
    }

    /// 查询失败记录（status='1'），供手动重试
    pub async fn find_failed_by_ids(&self, ids: &[i64]) -> Result<Vec<Model>, DbErr> {
        if ids.is_empty() {
            return Ok(Vec::new());
        }
        SysWebHookLog::find()
            .filter(Column::Id.is_in(ids.to_vec()))
            .filter(Column::Status.eq("1"))
            .all(self.base.db())
            .await
    }

    /// 分页查询记录（hook_id/event_type/status 过滤）
    #[allow(clippy::too_many_arguments)]
    pub async fn find_page_filtered(
        &self,
        offset: u64,
        limit: u64,
        hook_id: Option<i64>,
        event_type: Option<&str>,
        status: Option<&str>,
        tenant_scope: Option<i64>,
    ) -> Result<(Vec<Model>, u64), DbErr> {
        let mut query = SysWebHookLog::find();
        if let Some(tid) = tenant_scope {
            query = query.filter(Column::TenantId.eq(tid));
        }
        if let Some(hid) = hook_id {
            query = query.filter(Column::HookId.eq(hid));
        }
        if let Some(ev) = event_type {
            query = query.filter(Column::EventType.like(format!("%{}%", like_escape(ev))));
        }
        if let Some(st) = status {
            query = query.filter(Column::Status.eq(st));
        }
        query = query.order_by_desc(Column::Id);

        let total = query.clone().count(self.base.db()).await?;
        let rows = query
            .offset(offset)
            .limit(limit)
            .all(self.base.db())
            .await?;
        Ok((rows, total))
    }

    /// 分页全量查询（导出用）
    #[allow(clippy::too_many_arguments)]
    pub async fn find_all_filtered(
        &self,
        hook_id: Option<i64>,
        event_type: Option<&str>,
        status: Option<&str>,
        tenant_scope: Option<i64>,
    ) -> Result<Vec<Model>, DbErr> {
        let mut query = SysWebHookLog::find();
        if let Some(tid) = tenant_scope {
            query = query.filter(Column::TenantId.eq(tid));
        }
        if let Some(hid) = hook_id {
            query = query.filter(Column::HookId.eq(hid));
        }
        if let Some(ev) = event_type {
            query = query.filter(Column::EventType.like(format!("%{}%", like_escape(ev))));
        }
        if let Some(st) = status {
            query = query.filter(Column::Status.eq(st));
        }
        query
            .order_by_desc(Column::Id)
            .limit(crate::common::page::EXPORT_MAX_ROWS)
            .all(self.base.db())
            .await
    }

    /// 按 ID 列表物理删除
    pub async fn delete_by_ids(&self, ids: Vec<i64>) -> Result<DeleteResult, DbErr> {
        SysWebHookLog::delete_many()
            .filter(Column::Id.is_in(ids))
            .exec(self.base.db())
            .await
    }

    /// 全量清空记录（tenant_scope=Some(t) 时仅清理该租户，None 为平台全量）
    pub async fn delete_all(&self, tenant_scope: Option<i64>) -> Result<DeleteResult, DbErr> {
        let mut q = SysWebHookLog::delete_many();
        if let Some(tid) = tenant_scope {
            q = q.filter(Column::TenantId.eq(tid));
        }
        q.exec(self.base.db()).await
    }

    /// 按指定 hook_id 物理删除（删除回调配置时级联清理记录）
    pub async fn delete_by_hook_id(&self, hook_id: i64) -> Result<DeleteResult, DbErr> {
        SysWebHookLog::delete_many()
            .filter(Column::HookId.eq(hook_id))
            .exec(self.base.db())
            .await
    }

    /// 删除早于指定时间的记录（审计保留期清理；tenant_scope=Some(t) 时仅清理该租户）
    pub async fn delete_older_than(
        &self,
        cutoff: chrono::NaiveDateTime,
        tenant_scope: Option<i64>,
    ) -> Result<DeleteResult, DbErr> {
        let mut q = SysWebHookLog::delete_many().filter(Column::CreateTime.lt(cutoff));
        if let Some(tid) = tenant_scope {
            q = q.filter(Column::TenantId.eq(tid));
        }
        q.exec(self.base.db()).await
    }

    /// 更新补写响应详情（投递完成后回填 status_code/response/error_msg/cost_ms）
    pub async fn finish_log(
        &self,
        id: i64,
        status: &str,
        status_code: Option<i32>,
        response: Option<String>,
        error_msg: Option<String>,
        cost_ms: i32,
    ) -> Result<UpdateResult, DbErr> {
        SysWebHookLog::update_many()
            .col_expr(Column::Status, Expr::value(status.to_string()))
            .col_expr(Column::StatusCode, Expr::value(status_code))
            .col_expr(Column::Response, Expr::value(response))
            .col_expr(Column::ErrorMsg, Expr::value(error_msg))
            .col_expr(Column::CostMs, Expr::value(cost_ms))
            .filter(Column::Id.eq(id))
            .exec(self.base.db())
            .await
    }

    /// 插入记录
    pub async fn insert(&self, model: ActiveModel) -> Result<Model, DbErr> {
        self.base.insert(model).await
    }

    /// 更新记录
    pub async fn update(&self, model: ActiveModel) -> Result<Model, DbErr> {
        self.base.update(model).await
    }
}
