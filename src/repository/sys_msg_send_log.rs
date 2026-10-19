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

use chrono::NaiveDateTime;
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

    /// 多条件分页查询（to_addr/template_code/channel_code/status 精确过滤；send_time 范围）
    ///
    /// `sort`：动态排序（方案 B，白名单已在 service 层解析为 `SortOrder`）；
    /// `None` 时回退默认 `log_id DESC`。
    /// 时间范围按 `send_time` 过滤（与列表展示的发送时间列一致）；待发送记录
    /// `send_time` 为 NULL，不落入任何范围（语义：查询已发送记录的时间段）。
    #[allow(clippy::too_many_arguments)]
    pub async fn find_page_filtered(
        &self,
        offset: u64,
        limit: u64,
        to_addr: Option<&str>,
        template_code: Option<&str>,
        channel_code: Option<&str>,
        status: Option<&str>,
        begin_time: Option<NaiveDateTime>,
        end_time: Option<NaiveDateTime>,
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
        if let Some(begin) = begin_time {
            query = query.filter(Column::SendTime.gte(begin));
        }
        if let Some(end) = end_time {
            query = query.filter(Column::SendTime.lte(end));
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

    /// 保留期清理：删除 send_time 早于 cutoff 的已完成投递记录（批五十七）
    ///
    /// send_time IS NULL（待发送/重试中）的记录永不清理；
    /// tenant_scope=Some(t) 仅清理该租户；None（平台兜底清理）→ 全量。
    pub async fn delete_older_than(
        &self,
        cutoff: NaiveDateTime,
        tenant_scope: Option<i64>,
    ) -> Result<DeleteResult, DbErr> {
        let mut query = SysMsgSendLog::delete_many()
            .filter(Column::SendTime.is_not_null())
            .filter(Column::SendTime.lt(cutoff));
        if let Some(t) = tenant_scope {
            query = query.filter(Column::TenantId.eq(t));
        }
        query.exec(self.base.db()).await
    }

    /// 清空发送记录（可选 limit 上限，防误删全表；limit=None 时清空全部）
    ///
    /// tenant_scope=Some(t) 时仅清理该租户记录（mass-clean 必须按租户过滤）。
    pub async fn clean(&self, limit: Option<u64>, tenant_scope: Option<i64>) -> Result<u64, DbErr> {
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
                .map(|qr| qr.rows_affected());
        }
        let mut stmt = SysMsgSendLog::delete_many();
        if let Some(t) = tenant_scope {
            stmt = stmt.filter(Column::TenantId.eq(t));
        }
        stmt.exec(self.base.db()).await.map(|d| d.rows_affected)
    }

    /// 按 ID 列表把**失败终态**（status='1'）记录交回重试队列（status='2' 且重算额度）。
    ///
    /// 状态域：0=成功 1=失败（重试耗尽）2=待重试。两个条件都是必要的：
    /// - 带 `status='1'` 过滤：批量入口的选中集常混有成功行，无条件置 '2' 会被
    ///   `find_pending_retry` 重新投递，造成**对已成功收件人的重复短信/邮件**；
    ///   单条 retry_logs 仍允许对任意记录显式重发（操作员点在某一行上的主动动作）。
    /// - 同时把 `retry_count` 归零：失败终态行必然 retry_count>=max，而
    ///   `find_pending_retry` 只取 retry_count<max 的行——只改 status 会让它
    ///   永远停在"待重试"（既不发送也不再判定失败），等于把死信换成死循环。
    ///
    /// 因此 rows_affected 即"真正被交回队列的条数"，可直接提示用户。
    pub async fn mark_pending_retry(&self, log_ids: &[i64]) -> Result<UpdateResult, DbErr> {
        SysMsgSendLog::update_many()
            .col_expr(Column::Status, Expr::value("2"))
            .col_expr(Column::RetryCount, Expr::value(0i32))
            .filter(Column::LogId.is_in(log_ids.to_vec()))
            .filter(Column::Status.eq("1"))
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
