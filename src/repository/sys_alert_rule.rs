// stepby-axum/src/repository/sys_alert_rule.rs
//! sys_alert_rule 数据访问层（告警规则表，物理删除）
//!
//! 继承 BaseRepository 通用 CRUD，扩展告警规则特有查询：
//! - 查询所有启用规则（评估轮询用）
//! - 多条件分页查询（name 模糊 + metric 精确 + enabled 精确）
//! - 触发权抢占（last_fired_at 条件更新，保证并发评估幂等）

use chrono::NaiveDateTime;
use sea_orm::sea_query::Expr;
use sea_orm::*;

use crate::common::like_escape;
use crate::common::sort::SortOrder;
use crate::entity::sys_alert_rule::{ActiveModel, Column, Entity as SysAlertRule, Model};
use crate::repository::base::BaseRepository;

/// 告警规则 Repository
#[derive(Clone)]
pub struct SysAlertRuleRepository {
    base: BaseRepository<SysAlertRule>,
}

impl SysAlertRuleRepository {
    pub fn new(db: DatabaseConnection) -> Self {
        Self {
            base: BaseRepository::new(db),
        }
    }

    pub fn base(&self) -> &BaseRepository<SysAlertRule> {
        &self.base
    }

    /// 按 id 查询单条告警规则
    pub async fn find_by_id(&self, id: i64) -> Result<Option<Model>, DbErr> {
        SysAlertRule::find_by_id(id).one(self.base.db()).await
    }

    /// 查询所有启用规则（评估轮询用，按 id 升序保证多实例评估顺序一致）
    pub async fn find_enabled(&self) -> Result<Vec<Model>, DbErr> {
        SysAlertRule::find()
            .filter(Column::Enabled.eq("1"))
            .order_by_asc(Column::Id)
            .all(self.base.db())
            .await
    }

    /// 多条件分页查询（name 模糊 + metric 精确 + enabled 精确）
    ///
    /// `sort`：动态排序（方案 B，白名单已在 service 层解析为 `SortOrder`）；
    /// `None` 或未命中时回退默认 `id DESC`。
    pub async fn find_page_filtered(
        &self,
        offset: u64,
        limit: u64,
        name: Option<&str>,
        metric: Option<&str>,
        enabled: Option<&str>,
        sort: Option<SortOrder<Column>>,
    ) -> Result<(Vec<Model>, u64), DbErr> {
        let query = Self::build_filter_query(name, metric, enabled);

        let total = query.clone().count(self.base.db()).await?;
        let rows = match sort {
            Some(s) => query.order_by(s.column, s.dir),
            None => query.order_by_desc(Column::Id),
        }
        .offset(offset)
        .limit(limit)
        .all(self.base.db())
        .await?;
        Ok((rows, total))
    }

    /// 导出全量查询（同 find_page_filtered 过滤口径，受 max_rows 上限约束，
    /// 绕过 PageDomain 的分页截断——对齐 sys_audit_change_service.export_changes 范式）
    pub async fn find_all_filtered(
        &self,
        max_rows: u64,
        name: Option<&str>,
        metric: Option<&str>,
        enabled: Option<&str>,
    ) -> Result<Vec<Model>, DbErr> {
        Self::build_filter_query(name, metric, enabled)
            .order_by_desc(Column::Id)
            .limit(max_rows)
            .all(self.base.db())
            .await
    }

    /// 构建多条件查询（分页共用）
    fn build_filter_query(
        name: Option<&str>,
        metric: Option<&str>,
        enabled: Option<&str>,
    ) -> Select<SysAlertRule> {
        let mut query = SysAlertRule::find();
        if let Some(n) = name {
            query = query.filter(Column::Name.like(format!("%{}%", like_escape(n))));
        }
        if let Some(m) = metric {
            query = query.filter(Column::Metric.eq(m));
        }
        if let Some(e) = enabled {
            query = query.filter(Column::Enabled.eq(e));
        }
        query
    }

    /// 抢占触发权（幂等核心）：仅当 `last_fired_at` 为空或早于 `silence_before`
    /// （当前时间 - 静默期）时，把它更新为 `fired_at`；返回影响行数。
    ///
    /// 并发语义：两个评估方同时到达时只有一个 UPDATE 命中（行锁串行化），
    /// 命中方获得发送通知的权利，未命中方判定为静默期内跳过——
    /// 因此评估函数天然幂等可重入，多实例部署也不会重复发送。
    pub async fn claim_fire(
        &self,
        id: i64,
        silence_before: NaiveDateTime,
        fired_at: NaiveDateTime,
    ) -> Result<u64, DbErr> {
        let res = SysAlertRule::update_many()
            .col_expr(Column::LastFiredAt, Expr::value(fired_at))
            .col_expr(Column::UpdatedAt, Expr::value(fired_at))
            .filter(Column::Id.eq(id))
            .filter(
                Condition::any()
                    .add(Column::LastFiredAt.is_null())
                    .add(Column::LastFiredAt.lt(silence_before)),
            )
            .exec(self.base.db())
            .await?;
        Ok(res.rows_affected)
    }

    /// 仅更新 last_fired_at / updated_at（无静默条件，测试与特殊场景用）
    pub async fn update_last_fired(&self, id: i64, fired_at: NaiveDateTime) -> Result<(), DbErr> {
        let res = SysAlertRule::update_many()
            .col_expr(Column::LastFiredAt, Expr::value(fired_at))
            .col_expr(Column::UpdatedAt, Expr::value(fired_at))
            .filter(Column::Id.eq(id))
            .exec(self.base.db())
            .await?;
        let _ = res.rows_affected;
        Ok(())
    }

    /// 插入告警规则
    pub async fn insert(&self, model: ActiveModel) -> Result<Model, DbErr> {
        self.base.insert(model).await
    }

    /// 更新告警规则
    pub async fn update(&self, model: ActiveModel) -> Result<Model, DbErr> {
        self.base.update(model).await
    }

    /// 批量删除告警规则（物理删除）
    pub async fn delete_by_ids(&self, ids: Vec<i64>) -> Result<DeleteResult, DbErr> {
        SysAlertRule::delete_many()
            .filter(Column::Id.is_in(ids))
            .exec(self.base.db())
            .await
    }
}
