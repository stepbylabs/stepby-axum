// stepby-axum/src/repository/sys_msg_send_log.rs
//! sys_msg_send_log 数据访问层（消息发送记录表）
//!
//! 扩展方法：
//! - 按 to_addr/template_code/channel_code/status 过滤分页查询
//! - 按 ID 列表物理删除
//! - clean 清空（可加 limit 上限）
//! - 批量将指定记录置为待重试 status='2'（retry_log / trigger retry）
//! - 更新 retry_count 与 last_error
//! - 查询待重试批次（status='2' 且 retry_count<max_retry_count）
//! - 按 log_id 更新记录

use sea_orm::sea_query::Expr;
use sea_orm::*;

use crate::common::like_escape;
use crate::common::sort::SortOrder;
use crate::entity::sys_msg_send_log::{ActiveModel, Column, Entity as SysMsgSendLog, Model};
use crate::repository::base::BaseRepository;

/// 消息发送记录 Repository
#[derive(Clone)]
pub struct SysMsgSendLogRepository {
    base: BaseRepository<SysMsgSendLog>,
}

impl SysMsgSendLogRepository {
    pub fn new(db: DatabaseConnection) -> Self {
        Self {
            base: BaseRepository::new(db),
        }
    }

    pub fn base(&self) -> &BaseRepository<SysMsgSendLog> {
        &self.base
    }

    /// 多条件分页查询（to_addr/template_code/channel_code/status 精确过滤）
    ///
    /// `sort`：动态排序（方案 B，白名单已在 service 层解析为 `SortOrder`）；
    /// `None` 时回退默认 `log_id DESC`。
    #[allow(clippy::too_many_arguments)]
    pub async fn find_page_filtered(
        &self,
        offset: u64,
        limit: u64,
        to_addr: Option<&str>,
        template_code: Option<&str>,
        channel_code: Option<&str>,
        status: Option<&str>,
        tenant_scope: Option<i64>,
        sort: Option<SortOrder<Column>>,
    ) -> Result<(Vec<Model>, u64), DbErr> {
        let mut query = SysMsgSendLog::find();
        if let Some(tid) = tenant_scope {
            query = query.filter(Column::TenantId.eq(tid));
        }
        if let Some(addr) = to_addr {
            query = query.filter(Column::ToAddr.like(format!("%{}%", like_escape(addr))));
        }
        if let Some(tc) = template_code {
            query = query.filter(Column::TemplateCode.eq(tc));
        }
        if let Some(cc) = channel_code {
            query = query.filter(Column::ChannelCode.eq(cc));
        }
        if let Some(st) = status {
            query = query.filter(Column::Status.eq(st));
        }

        let total = query.clone().count(self.base.db()).await?;
        // 动态排序（白名单已解析）或默认 log_id DESC
        let rows = match sort {
            Some(s) => query.order_by(s.column, s.dir),
            None => query.order_by_desc(Column::LogId),
        }
        .offset(offset)
        .limit(limit)
        .all(self.base.db())
        .await?;
        Ok((rows, total))
    }

    /// 按 ID 列表物理删除记录
    pub async fn delete_by_ids(&self, log_ids: Vec<i64>) -> Result<DeleteResult, DbErr> {
        SysMsgSendLog::delete_many()
            .filter(Column::LogId.is_in(log_ids))
            .exec(self.base.db())
            .await
    }

    /// 清空发送记录（可选 limit 上限，防误删全表；limit=None 时清空全部）
    ///
    /// tenant_scope=Some(t) 时仅清理该租户记录（mass-clean 必须按租户过滤）。
    pub async fn clean(
        &self,
        limit: Option<u64>,
        tenant_scope: Option<i64>,
    ) -> Result<DeleteResult, DbErr> {
        // limit 仅当存在时限制，避免误删全表；None 表示全部清空
        if let Some(l) = limit {
            let where_clause = match tenant_scope {
                Some(t) => format!("WHERE tenant_id = {t} "),
                None => String::new(),
            };
            let sql = format!(
                "DELETE FROM sys_msg_send_log WHERE log_id IN (SELECT log_id FROM sys_msg_send_log {where_clause}ORDER BY log_id DESC LIMIT {})",
                l
            );
            // execute_unprepared 返回 QueryResult，转换为 DeleteResult（rows_affected 对齐调用方语义）
            return self
                .base
                .db()
                .execute_unprepared(&sql)
                .await
                .map(|qr| DeleteResult {
                    rows_affected: qr.rows_affected(),
                });
        }
        let mut stmt = SysMsgSendLog::delete_many();
        if let Some(t) = tenant_scope {
            stmt = stmt.filter(Column::TenantId.eq(t));
        }
        stmt.exec(self.base.db()).await
    }

    /// 按 ID 列表批量置为待重试 status='2'（触发重试）
    pub async fn mark_pending_retry(&self, log_ids: &[i64]) -> Result<UpdateResult, DbErr> {
        SysMsgSendLog::update_many()
            .col_expr(Column::Status, Expr::value("2"))
            .filter(Column::LogId.is_in(log_ids.to_vec()))
            .exec(self.base.db())
            .await
    }

    /// 查询待重试记录（status='2' 且 retry_count<max_retry_count），按 log_id 升序取 limit 条
    pub async fn find_pending_retry(
        &self,
        limit: u64,
        tenant_scope: Option<i64>,
    ) -> Result<Vec<Model>, DbErr> {
        let mut q = SysMsgSendLog::find();
        q = q.filter(Column::Status.eq("2"));
        // retry_count < max_retry_count（跨库兼容写法：使用原样表达式）
        q = q.filter(Expr::col(Column::RetryCount).lt(Expr::col(Column::MaxRetryCount)));
        if let Some(tid) = tenant_scope {
            q = q.filter(Column::TenantId.eq(tid));
        }
        q.order_by_asc(Column::LogId)
            .limit(limit)
            .all(self.base.db())
            .await
    }

    /// 按 log_id 更新记录（重试后更新状态/retry_count/last_error/send_time）
    pub async fn update(&self, model: ActiveModel) -> Result<Model, DbErr> {
        self.base.update(model).await
    }

    /// 按 ID 列表批量查询记录（单次 SELECT，用于 retry 前校验）
    pub async fn find_by_ids(&self, log_ids: &[i64]) -> Result<Vec<Model>, DbErr> {
        if log_ids.is_empty() {
            return Ok(Vec::new());
        }
        SysMsgSendLog::find()
            .filter(Column::LogId.is_in(log_ids.to_vec()))
            .all(self.base.db())
            .await
    }

    /// 插入发送记录
    pub async fn insert(&self, model: ActiveModel) -> Result<Model, DbErr> {
        self.base.insert(model).await
    }
}
