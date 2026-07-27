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
        SysLogininfor::delete_many()
            .exec(self.base.db())
            .await
    }

    /// 统计最近 N 天每天的登录成功/失败次数
    /// 返回 Vec<(date_string, success_count, fail_count)>，按日期升序
    ///
    /// M-4 / M-6 TODO：当前为 N+1 查询（每天 2 次 COUNT，共 2*N 次 DB 往返）。
    /// 理想实现是单条 `GROUP BY DATE(login_time)` 聚合查询，用 SeaORM
    /// `select_only() + column_as(Expr::col(Column::LoginTime), "d") + group_by(...)`。
    /// 但项目同时支持 MySQL / PostgreSQL / SQLite，三者的日期截断函数不同：
    /// - MySQL: `DATE(login_time)`
    /// - PostgreSQL: `DATE_TRUNC('day', login_time)` 或 `login_time::date`
    /// - SQLite: `DATE(login_time)`
    ///
    /// sea_query 的 `Expr::col(...)` 未提供跨 DB 的日期截断抽象，
    /// 强行用 `custom_expr` 会破坏多 DB 兼容。故暂保留 N+1 实现，
    /// 后续优化方向：按 DB 分别实现 GROUP BY 聚合，或缓存结果。
    /// N 通常 ≤ 30，2*N 次 COUNT 在索引 (status, login_time) 下性能可接受。
    pub async fn daily_stats(&self, days: i64) -> Result<Vec<(String, i64, i64)>, DbErr> {
        use chrono::{Duration, Local};
        let today = Local::now().date_naive();
        let start_date = today - Duration::days(days - 1);
        let mut result = Vec::new();
        for i in 0..days {
            let date = start_date + Duration::days(i);
            let begin = date.and_time(MIDNIGHT);
            let end = (date + Duration::days(1)).and_time(MIDNIGHT);
            let success = SysLogininfor::find()
                .filter(Column::Status.eq("0"))
                .filter(Column::LoginTime.gte(begin))
                .filter(Column::LoginTime.lt(end))
                .count(self.base.db())
                .await? as i64;
            let fail = SysLogininfor::find()
                .filter(Column::Status.eq("1"))
                .filter(Column::LoginTime.gte(begin))
                .filter(Column::LoginTime.lt(end))
                .count(self.base.db())
                .await? as i64;
            result.push((date.format("%Y-%m-%d").to_string(), success, fail));
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
        use chrono::Local;
        let today = Local::now().date_naive();
        let begin = today.and_time(MIDNIGHT);
        let rows: Vec<(String,)> = SysLogininfor::find()
            .filter(Column::Status.eq("1"))
            .filter(Column::LoginTime.gte(begin))
            .filter(Column::Ipaddr.is_not_null())
            .select_only()
            .column(Column::Ipaddr)
            .group_by(Column::Ipaddr)
            .into_tuple::<(String,)>()
            .all(self.base.db())
            .await?;
        Ok(rows.len() as i64)
    }
}
