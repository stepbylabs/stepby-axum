// axum-backend/src/repository/sys_logininfor.rs
//! sys_logininfor 数据访问层（登录日志表，物理删除）
//!
//! 继承 BaseRepository 通用 CRUD，扩展登录日志特有查询：
//! - 多条件分页查询
//! - 按用户名删除（解锁用户）
//! - 批量删除 / 清空
//!
//! 注意：ipaddr 字段为全小写（对齐前端 ipaddr 字段，特例）

use chrono::NaiveDateTime;
use sea_orm::*;

use crate::common::like_escape;
use crate::entity::sys_logininfor::{ActiveModel, Column, Entity as SysLogininfor, Model};
use crate::repository::base::BaseRepository;

/// 一天的起始时刻（00:00:00）常量
///
/// 用于按日聚合统计时构造 `NaiveDateTime` 边界，避免重复 `and_hms_opt(0, 0, 0).unwrap()`。
/// NaiveTime::MIN 等价于 00:00:00，是 const 上下文可用的常量。
const MIDNIGHT: chrono::NaiveTime = chrono::NaiveTime::MIN;

/// 登录日志 Repository
#[derive(Clone)]
pub struct SysLogininforRepository {
    base: BaseRepository<SysLogininfor>,
}

impl SysLogininforRepository {
    pub fn new(db: DatabaseConnection) -> Self {
        Self {
            base: BaseRepository::new(db),
        }
    }

    pub fn base(&self) -> &BaseRepository<SysLogininfor> {
        &self.base
    }

    /// 多条件分页查询（ipaddr 模糊，user_name 模糊，status 精确，时间范围，按 login_time 倒序）
    #[allow(clippy::too_many_arguments)]
    pub async fn find_page_filtered(
        &self,
        offset: u64,
        limit: u64,
        ipaddr: Option<&str>,
        user_name: Option<&str>,
        status: Option<&str>,
        begin_time: Option<NaiveDateTime>,
        end_time: Option<NaiveDateTime>,
    ) -> Result<(Vec<Model>, u64), DbErr> {
        let mut query = SysLogininfor::find();
        if let Some(ip) = ipaddr {
            query = query.filter(Column::Ipaddr.like(format!("%{}%", like_escape(ip))));
        }
        if let Some(name) = user_name {
            query = query.filter(Column::UserName.like(format!("%{}%", like_escape(name))));
        }
        if let Some(st) = status {
            query = query.filter(Column::Status.eq(st));
        }
        if let Some(begin) = begin_time {
            query = query.filter(Column::LoginTime.gte(begin));
        }
        if let Some(end) = end_time {
            query = query.filter(Column::LoginTime.lte(end));
        }

        let total = query.clone().count(self.base.db()).await?;
        let rows = query
            .order_by_desc(Column::LoginTime)
            .offset(offset)
            .limit(limit)
            .all(self.base.db())
            .await?;
        Ok((rows, total))
    }

    /// 查询在线用户（最近活跃的登录成功记录）
    ///
    /// 简化实现：查询 status="0"（登录成功）且 login_time >= since 的记录，
    /// 按 login_time 倒序返回。用于在线用户监控页面。
    /// 限制返回数量上限，避免单次查询返回过多记录。
    pub async fn find_online(
        &self,
        since: NaiveDateTime,
        ipaddr: Option<&str>,
        user_name: Option<&str>,
        limit: u64,
    ) -> Result<Vec<Model>, DbErr> {
        let mut query = SysLogininfor::find()
            .filter(Column::Status.eq("0"))
            .filter(Column::LoginTime.gte(since));
        if let Some(ip) = ipaddr {
            query = query.filter(Column::Ipaddr.like(format!("%{}%", like_escape(ip))));
        }
        if let Some(name) = user_name {
            query = query.filter(Column::UserName.like(format!("%{}%", like_escape(name))));
        }
        query
            .order_by_desc(Column::LoginTime)
            .limit(limit)
            .all(self.base.db())
            .await
    }

    /// 批量删除登录日志（物理删除）
    pub async fn delete_by_ids(&self, info_ids: Vec<i64>) -> Result<DeleteResult, DbErr> {
        SysLogininfor::delete_many()
            .filter(Column::InfoId.is_in(info_ids))
            .exec(self.base.db())
            .await
    }

    /// 按用户名删除登录日志（用于解锁用户，清除登录失败记录）
    pub async fn delete_by_user_name(&self, user_name: &str) -> Result<DeleteResult, DbErr> {
        SysLogininfor::delete_many()
            .filter(Column::UserName.eq(user_name))
            .filter(Column::Status.eq("1"))
            .exec(self.base.db())
            .await
    }

    /// 删除 N 天前的登录日志（按 login_time 过滤，物理删除）
    ///
    /// 用于保留期清理：仅删除 login_time < cutoff 的记录，
    /// 保留最近 N 天日志用于审计。
    pub async fn delete_older_than(&self, cutoff: NaiveDateTime) -> Result<DeleteResult, DbErr> {
        SysLogininfor::delete_many()
            .filter(Column::LoginTime.lt(cutoff))
            .exec(self.base.db())
            .await
    }

    /// 插入登录日志
    pub async fn insert(&self, model: ActiveModel) -> Result<Model, DbErr> {
        self.base.insert(model).await
    }

    /// 清空登录日志（物理删除全部）
    pub async fn clean_all(&self) -> Result<DeleteResult, DbErr> {
        SysLogininfor::delete_many().exec(self.base.db()).await
    }

    /// 统计最近 N 天每天的登录成功/失败次数
    /// 返回 Vec<(date_string, success_count, fail_count)>，按日期升序
    ///
    /// C6（批次3）：将原先的 N+1 循环查询（每天 2 次 COUNT，共 2*N 次 DB 往返）
    /// 改为单条 `GROUP BY DATE(login_time)` 聚合查询，用 `COUNT(CASE WHEN ...)`
    /// 一次性得到每天的 success/fail 计数。SQLite / MySQL / PostgreSQL 均支持
    /// `DATE(login_time)` 取日期部分（返回 `YYYY-MM-DD`，与输出格式一致），
    /// 故无需按 backend 分支。输出仍补齐为完整 N 天序列（无数据的日期以 0 填充），
    /// 保持前端 dashboard 契约不变。
    pub async fn daily_stats(&self, days: i64) -> Result<Vec<(String, i64, i64)>, DbErr> {
        use chrono::Duration;
        use std::collections::HashMap;

        let backend = self.base.db().get_database_backend();
        // P1 修复：增加时间下界过滤，避免登录日志无界增长导致全表 GROUP BY 线性劣化
        // （与 sys_oper_log::stats_daily 的带时间过滤实现保持一致）
        let today = crate::common::datetime::today_utc();
        let start_date = today - Duration::days(days - 1);
        let sql = "SELECT DATE(login_time) AS d, \
                   COUNT(CASE WHEN status = '0' THEN 1 END) AS success, \
                   COUNT(CASE WHEN status = '1' THEN 1 END) AS fail \
                   FROM sys_logininfor WHERE login_time >= ? \
                   GROUP BY DATE(login_time) \
                   ORDER BY d ASC";
        let stmt = Statement::from_sql_and_values(backend, sql, [start_date.into()]);
        let rows = self.base.db().query_all(stmt).await?;

        let mut map: HashMap<String, (i64, i64)> = HashMap::new();
        for row in rows {
            let d: String = row.try_get("", "d").unwrap_or_default();
            let success: i64 = row.try_get("", "success").unwrap_or(0);
            let fail: i64 = row.try_get("", "fail").unwrap_or(0);
            map.insert(d, (success, fail));
        }

        let mut result = Vec::new();
        for i in 0..days {
            let date = start_date + Duration::days(i);
            let key = date.format("%Y-%m-%d").to_string();
            let (success, fail) = map.get(&key).copied().unwrap_or((0, 0));
            result.push((key, success, fail));
        }
        Ok(result)
    }

    /// 查询自 since 以来失败登录按 IP 分组，返回 count >= min_count 的 (ip, count) 列表
    ///
    /// 用于登录异常检测（撞库攻击识别）：
    /// - status='1' 表示登录失败
    /// - 按 ipaddr 分组并过滤 NULL
    /// - 仅返回 count >= min_count 的 IP（默认阈值 5 次）
    /// - 按 count 倒序
    pub async fn find_failed_group_by_ip(
        &self,
        since: NaiveDateTime,
        min_count: i64,
    ) -> Result<Vec<(String, i64)>, DbErr> {
        use sea_orm::sea_query::{Expr, ExprTrait};
        // sea_query SimpleExpr 没有 .gte() 方法，使用 .gt(min_count - 1) 等价实现 count >= min_count
        let rows: Vec<(String, i64)> = SysLogininfor::find()
            .filter(Column::Status.eq("1"))
            .filter(Column::LoginTime.gte(since))
            .filter(Column::Ipaddr.is_not_null())
            .select_only()
            .column(Column::Ipaddr)
            .column_as(Expr::col(Column::Ipaddr).count(), "cnt")
            .group_by(Column::Ipaddr)
            .having(Expr::col(Column::Ipaddr).count().gt(min_count - 1))
            .order_by_desc(Expr::col(Column::Ipaddr).count())
            .into_tuple::<(String, i64)>()
            .all(self.base.db())
            .await?;
        Ok(rows)
    }

    /// 统计今日（自当天 00:00 起）登录失败的不重复 IP 数
    ///
    /// 用于 dashboard stats 接口的 todayAnomalyIps 字段。
    pub async fn count_today_failed_ips(&self) -> Result<i64, DbErr> {
        use sea_orm::sea_query::Expr;

        let today = crate::common::datetime::today_utc();
        let begin = today.and_time(MIDNIGHT);
        // C6（批次3）：原实现用 `.all()` 拉全量 IP 再 `.len()` 计数（N 次传输）。
        // 改为单条 `COUNT(DISTINCT ipaddr)` 聚合，直接返回不重复 IP 数，避免拉全表。
        let row: Option<(i64,)> = SysLogininfor::find()
            .filter(Column::Status.eq("1"))
            .filter(Column::LoginTime.gte(begin))
            .filter(Column::Ipaddr.is_not_null())
            .select_only()
            .column_as(Expr::cust("COUNT(DISTINCT ipaddr)"), "c")
            .into_tuple::<(i64,)>()
            .one(self.base.db())
            .await?;
        Ok(row.map(|r| r.0).unwrap_or(0))
    }
}
