// axum-backend/src/repository/sys_oper_log.rs
//! sys_oper_log 数据访问层（操作日志表，物理删除）
//!
//! 继承 BaseRepository 通用 CRUD，扩展操作日志特有查询：
//! - 按操作人查询
//! - 按时间范围查询
//! - 按业务类型查询

use chrono::NaiveDateTime;
use sea_orm::*;

use crate::common::like_escape;
use crate::entity::sys_oper_log::{ActiveModel, Column, Entity as SysOperLog, Model};
use crate::repository::base::BaseRepository;

/// 一天的起始时刻（00:00:00）常量
///
/// 用于按日聚合统计时构造 `NaiveDateTime` 边界，避免重复 `and_hms_opt(0, 0, 0).unwrap()`。
/// NaiveTime::MIN 等价于 00:00:00，是 const 上下文可用的常量。
const MIDNIGHT: chrono::NaiveTime = chrono::NaiveTime::MIN;

/// 操作日志 Repository
#[derive(Clone)]
pub struct SysOperLogRepository {
    base: BaseRepository<SysOperLog>,
}

impl SysOperLogRepository {
    pub fn new(db: DatabaseConnection) -> Self {
        Self {
            base: BaseRepository::new(db),
        }
    }

    pub fn base(&self) -> &BaseRepository<SysOperLog> {
        &self.base
    }

    /// 按 oper_id 查询单条操作日志
    pub async fn find_by_id(&self, oper_id: i64) -> Result<Option<Model>, DbErr> {
        SysOperLog::find_by_id(oper_id).one(self.base.db()).await
    }

    /// 多条件分页查询（title 模糊，business_type 精确，oper_name 模糊，status 精确，时间范围，按 oper_time 倒序）
    #[allow(clippy::too_many_arguments)]
    pub async fn find_page_filtered(
        &self,
        offset: u64,
        limit: u64,
        title: Option<&str>,
        business_type: Option<i32>,
        oper_name: Option<&str>,
        status: Option<&str>,
        begin_time: Option<NaiveDateTime>,
        end_time: Option<NaiveDateTime>,
    ) -> Result<(Vec<Model>, u64), DbErr> {
        let mut query = SysOperLog::find();
        if let Some(t) = title {
            // T-11：title 新数据存 i18n key（module.*），旧数据为中文。
            // 搜索时同时匹配中文原文（LIKE）与对应的 key（精确），保证新旧均可搜到。
            let keys = crate::common::i18n::module_keys_matching(t);
            if keys.is_empty() {
                query = query.filter(Column::Title.like(format!("%{}%", like_escape(t))));
            } else {
                query = query.filter(
                    Condition::any()
                        .add(Column::Title.like(format!("%{}%", like_escape(t))))
                        .add(Column::Title.is_in(keys)),
                );
            }
        }
        if let Some(bt) = business_type {
            query = query.filter(Column::BusinessType.eq(bt));
        }
        if let Some(name) = oper_name {
            query = query.filter(Column::OperName.like(format!("%{}%", like_escape(name))));
        }
        if let Some(st) = status {
            query = query.filter(Column::Status.eq(st));
        }
        if let Some(begin) = begin_time {
            query = query.filter(Column::OperTime.gte(begin));
        }
        if let Some(end) = end_time {
            query = query.filter(Column::OperTime.lte(end));
        }

        let total = query.clone().count(self.base.db()).await?;
        let rows = query
            .order_by_desc(Column::OperTime)
            .offset(offset)
            .limit(limit)
            .all(self.base.db())
            .await?;
        Ok((rows, total))
    }

    /// 批量删除操作日志（物理删除）
    pub async fn delete_by_ids(&self, oper_ids: Vec<i64>) -> Result<DeleteResult, DbErr> {
        SysOperLog::delete_many()
            .filter(Column::OperId.is_in(oper_ids))
            .exec(self.base.db())
            .await
    }

    /// 删除 N 天前的操作日志（按 oper_time 过滤，物理删除）
    ///
    /// 用于保留期清理：仅删除 oper_time < (now - days) 的记录，
    /// 保留最近 N 天日志用于审计。
    pub async fn delete_older_than(&self, cutoff: NaiveDateTime) -> Result<DeleteResult, DbErr> {
        SysOperLog::delete_many()
            .filter(Column::OperTime.lt(cutoff))
            .exec(self.base.db())
            .await
    }

    /// 插入操作日志
    pub async fn insert(&self, model: ActiveModel) -> Result<Model, DbErr> {
        self.base.insert(model).await
    }

    /// 清空操作日志（物理删除全部）
    pub async fn clean_all(&self) -> Result<DeleteResult, DbErr> {
        SysOperLog::delete_many().exec(self.base.db()).await
    }

    /// 按业务类型聚合统计（审计大屏用）
    ///
    /// 返回 Vec<(business_type, count)>，按 count 降序
    pub async fn stats_by_business_type(&self) -> Result<Vec<(Option<i32>, i64)>, DbErr> {
        use sea_orm::sea_query::Expr;
        let rows: Vec<(Option<i32>, i64)> = SysOperLog::find()
            .select_only()
            .column(Column::BusinessType)
            .column_as(Expr::col(Column::OperId).count(), "cnt")
            .group_by(Column::BusinessType)
            .order_by_desc(Expr::col(Column::OperId).count())
            .into_tuple::<(Option<i32>, i64)>()
            .all(self.base.db())
            .await?;
        Ok(rows)
    }

    /// 按操作人聚合 Top N（审计大屏用）
    ///
    /// 返回 Vec<(oper_name, count)>，按 count 降序，限制 N 条
    pub async fn stats_top_operators(&self, limit: u64) -> Result<Vec<(String, i64)>, DbErr> {
        use sea_orm::sea_query::Expr;
        let rows: Vec<(String, i64)> = SysOperLog::find()
            .filter(Column::OperName.is_not_null())
            .select_only()
            .column(Column::OperName)
            .column_as(Expr::col(Column::OperId).count(), "cnt")
            .group_by(Column::OperName)
            .order_by_desc(Expr::col(Column::OperId).count())
            .limit(limit)
            .into_tuple::<(String, i64)>()
            .all(self.base.db())
            .await?;
        Ok(rows)
    }

    /// 按日聚合最近 N 天操作量（审计大屏用）
    ///
    /// 返回 Vec<(date_string, success_count, fail_count)>，按日期升序
    ///
    /// P1 优化: 原实现循环 N 天每天执行 2 次 COUNT（2N 次 RTT），
    /// 改为单次 GROUP BY DATE(oper_time) 聚合查询，再在 Rust 侧补齐无操作日期为零值。
    pub async fn stats_daily(&self, days: i64) -> Result<Vec<(String, i64, i64)>, DbErr> {
        use chrono::Duration;
        use std::collections::HashMap;

        let today = crate::common::datetime::today_utc();
        let start_date = today - Duration::days(days - 1);
        let begin_time = start_date.and_time(MIDNIGHT);

        // 单次聚合查询：按日期分组统计成功/失败数
        let db = self.base.db();
        let backend = db.get_database_backend();

        let (sql, values) = match backend {
            DatabaseBackend::Sqlite => (
                "SELECT strftime('%Y-%m-%d', oper_time) AS d, \
                 SUM(CASE WHEN status='0' THEN 1 ELSE 0 END) AS success, \
                 SUM(CASE WHEN status='1' THEN 1 ELSE 0 END) AS fail \
                 FROM sys_oper_log WHERE oper_time >= ? \
                 GROUP BY d ORDER BY d ASC",
                vec![begin_time.into()],
            ),
            DatabaseBackend::Postgres => (
                "SELECT TO_CHAR(oper_time, 'YYYY-MM-DD') AS d, \
                 SUM(CASE WHEN status='0' THEN 1 ELSE 0 END) AS success, \
                 SUM(CASE WHEN status='1' THEN 1 ELSE 0 END) AS fail \
                 FROM sys_oper_log WHERE oper_time >= $1 \
                 GROUP BY d ORDER BY d ASC",
                vec![begin_time.into()],
            ),
            DatabaseBackend::MySql => (
                "SELECT DATE_FORMAT(oper_time, '%Y-%m-%d') AS d, \
                 SUM(CASE WHEN status='0' THEN 1 ELSE 0 END) AS success, \
                 SUM(CASE WHEN status='1' THEN 1 ELSE 0 END) AS fail \
                 FROM sys_oper_log WHERE oper_time >= ? \
                 GROUP BY d ORDER BY d ASC",
                vec![begin_time.into()],
            ),
        };

        let rows = db
            .query_all(Statement::from_sql_and_values(backend, sql, values))
            .await?;

        // 构建日期→计数映射
        let mut counts: HashMap<String, (i64, i64)> = HashMap::with_capacity(rows.len());
        for row in rows {
            let d: String = row.try_get("", "d")?;
            let success: i64 = row.try_get("", "success").unwrap_or(0);
            let fail: i64 = row.try_get("", "fail").unwrap_or(0);
            counts.insert(d, (success, fail));
        }

        // 补齐无操作日期为零值，保持日期连续
        let mut result = Vec::with_capacity(days as usize);
        for i in 0..days {
            let date = start_date + Duration::days(i);
            let date_str = date.format("%Y-%m-%d").to_string();
            let (success, fail) = counts.get(&date_str).copied().unwrap_or((0, 0));
            result.push((date_str, success, fail));
        }
        Ok(result)
    }

    /// 统计操作日志总数和成功/失败数
    ///
    /// 返回 (total, success, fail)
    pub async fn stats_summary(&self) -> Result<(i64, i64, i64), DbErr> {
        let total = SysOperLog::find()
            .count(self.base.db())
            .await
            .map(|c| i64::try_from(c).unwrap_or(i64::MAX))?;
        let success = SysOperLog::find()
            .filter(Column::Status.eq("0"))
            .count(self.base.db())
            .await
            .map(|c| i64::try_from(c).unwrap_or(i64::MAX))?;
        let fail = SysOperLog::find()
            .filter(Column::Status.eq("1"))
            .count(self.base.db())
            .await
            .map(|c| i64::try_from(c).unwrap_or(i64::MAX))?;
        Ok((total, success, fail))
    }

    /// 查询最近的异常操作日志（status=1，失败），按 oper_time 倒序
    ///
    /// 用于审计合规报告 anomalies 列表。
    pub async fn find_recent_anomalies(&self, limit: u64) -> Result<Vec<Model>, DbErr> {
        SysOperLog::find()
            .filter(Column::Status.eq("1"))
            .order_by_desc(Column::OperTime)
            .limit(limit)
            .all(self.base.db())
            .await
    }

    /// 按操作模块（title）聚合 Top N（审计大屏用）
    ///
    /// 返回 Vec<(module_name, count)>，按 count 降序，限制 N 条。
    /// title 可能为 NULL（旧数据）或 i18n key（module.*），这里按原文分组，
    /// 展示层统一走 module_title() 翻译。
    pub async fn stats_top_modules(&self, limit: u64) -> Result<Vec<(String, i64)>, DbErr> {
        use sea_orm::sea_query::Expr;
        let rows: Vec<(String, i64)> = SysOperLog::find()
            .filter(Column::Title.is_not_null())
            .select_only()
            .column(Column::Title)
            .column_as(Expr::col(Column::OperId).count(), "cnt")
            .group_by(Column::Title)
            .order_by_desc(Expr::col(Column::OperId).count())
            .limit(limit)
            .into_tuple::<(String, i64)>()
            .all(self.base.db())
            .await?;
        Ok(rows)
    }

    /// 统计最近 `window_minutes` 分钟内的操作总数与失败数
    ///
    /// 用于异常操作告警：失败率 = fail / total。
    pub async fn failure_stats_in_window(&self, window_minutes: i64) -> Result<(i64, i64), DbErr> {
        let begin =
            crate::common::datetime::now_naive() - chrono::Duration::minutes(window_minutes);
        let total = SysOperLog::find()
            .filter(Column::OperTime.gte(begin))
            .count(self.base.db())
            .await
            .map(|c| i64::try_from(c).unwrap_or(i64::MAX))?;
        let fail = SysOperLog::find()
            .filter(Column::Status.eq("1"))
            .filter(Column::OperTime.gte(begin))
            .count(self.base.db())
            .await
            .map(|c| i64::try_from(c).unwrap_or(i64::MAX))?;
        Ok((total, fail))
    }

    /// 统计最近 `window_minutes` 分钟内失败操作次数 >= `min_count` 的操作人（Burst）
    ///
    /// 用于异常操作告警：同一账号在窗口内连续失败过多，疑似异常/被攻击。
    pub async fn failure_burst_operators(
        &self,
        window_minutes: i64,
        min_count: i64,
    ) -> Result<Vec<(String, i64)>, DbErr> {
        use sea_orm::sea_query::{Expr, ExprTrait};
        let begin =
            crate::common::datetime::now_naive() - chrono::Duration::minutes(window_minutes);
        let rows: Vec<(String, i64)> = SysOperLog::find()
            .filter(Column::Status.eq("1"))
            .filter(Column::OperTime.gte(begin))
            .filter(Column::OperName.is_not_null())
            .select_only()
            .column(Column::OperName)
            .column_as(Expr::col(Column::OperId).count(), "cnt")
            .group_by(Column::OperName)
            .having(Expr::col(Column::OperId).count().gte(min_count))
            .order_by_desc(Expr::col(Column::OperId).count())
            .into_tuple::<(String, i64)>()
            .all(self.base.db())
            .await?;
        Ok(rows)
    }

    /// 统计最近 `window_minutes` 分钟内失败操作次数 >= `min_count` 的模块（Burst）
    ///
    /// 用于异常操作告警：某模块在窗口内连续/大量失败，疑似接口故障或越权尝试。
    pub async fn failure_burst_modules(
        &self,
        window_minutes: i64,
        min_count: i64,
    ) -> Result<Vec<(String, i64)>, DbErr> {
        use sea_orm::sea_query::{Expr, ExprTrait};
        let begin =
            crate::common::datetime::now_naive() - chrono::Duration::minutes(window_minutes);
        let rows: Vec<(String, i64)> = SysOperLog::find()
            .filter(Column::Status.eq("1"))
            .filter(Column::OperTime.gte(begin))
            .filter(Column::Title.is_not_null())
            .select_only()
            .column(Column::Title)
            .column_as(Expr::col(Column::OperId).count(), "cnt")
            .group_by(Column::Title)
            .having(Expr::col(Column::OperId).count().gte(min_count))
            .order_by_desc(Expr::col(Column::OperId).count())
            .into_tuple::<(String, i64)>()
            .all(self.base.db())
            .await?;
        Ok(rows)
    }
}
