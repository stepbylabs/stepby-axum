// stepby-axum/src/repository/sys_webhook_event.rs
//! WebHook 事件目录（sys_webhook_event 表）数据访问层
//!
//! 提供事件目录分页（过滤 + 动态排序白名单）、按 event_key 存在性校验
//! （订阅字段写入前的合法性闸门）。

use sea_orm::sea_query::Expr;
use sea_orm::*;

use crate::entity::sys_webhook_event::{Column, Entity as SysWebhookEvent, Model};
use crate::common::sort::SortOrder;

/// 事件目录 Repository
#[derive(Clone)]
pub struct SysWebhookEventRepository {
    db: DatabaseConnection,
}

impl SysWebhookEventRepository {
    pub fn new(db: DatabaseConnection) -> Self {
        Self { db }
    }

    /// 分页查询事件目录（可选 event_key 模糊 / name 模糊 / enabled 精确过滤 + 动态排序）
    pub async fn find_page_filtered(
        &self,
        offset: u64,
        limit: u64,
        event_key: Option<&str>,
        name: Option<&str>,
        enabled: Option<&str>,
        sort: Option<SortOrder<Column>>,
    ) -> Result<(Vec<Model>, u64), DbErr> {
        let mut query = SysWebhookEvent::find();
        if let Some(k) = event_key.filter(|s| !s.trim().is_empty()) {
            query = query.filter(Column::EventKey.contains(k.trim()));
        }
        if let Some(n) = name.filter(|s| !s.trim().is_empty()) {
            query = query.filter(Column::Name.contains(n.trim()));
        }
        if let Some(e) = enabled.filter(|s| !s.trim().is_empty()) {
            query = query.filter(Column::Enabled.eq(e.trim()));
        }
        let total = query.clone().count(&self.db).await?;
        let query = match sort {
            Some(s) => query.order_by(s.column, s.dir),
            None => query.order_by_asc(Column::Id),
        };
        let rows = query.offset(offset).limit(limit).all(&self.db).await?;
        Ok((rows, total))
    }

    /// 按 event_key 查询目录事件（存在性校验 / 样例构造）
    pub async fn find_by_event_key(&self, event_key: &str) -> Result<Option<Model>, DbErr> {
        SysWebhookEvent::find()
            .filter(Column::EventKey.eq(event_key))
            .one(&self.db)
            .await
    }

    /// 更新目录事件 enabled（目录下架展示并拒绝新订阅；派发链不查目录，存量 hook 不中断）
    ///
    /// 返回影响行数（0 = 事件不存在，由调用方转 404）。
    pub async fn update_enabled(&self, id: i64, enabled: &str) -> Result<u64, DbErr> {
        let res = SysWebhookEvent::update_many()
            .col_expr(Column::Enabled, Expr::value(enabled.to_string()))
            .filter(Column::Id.eq(id))
            .exec(&self.db)
            .await?;
        Ok(res.rows_affected)
    }
}
