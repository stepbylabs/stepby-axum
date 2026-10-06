// stepby-axum/src/repository/sys_logininfor.rs
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
use crate::common::sort::SortOrder;
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
    ///
    /// `last_id`：游标（keyset 深分页）参数。携带时按 `info_id < last_id` 过滤 + `info_id DESC`
    /// 排序，适用于深翻页（避免 OFFSET 线性扫描）；为 `None` 时沿用 `offset/limit` 分页路径。
    ///
    /// `sort`：动态排序（方案 B，白名单已在 service 层解析为 `SortOrder`）。
    /// 与 keyset 互斥——携带 `last_id` 时固定 `PK DESC`（keyset 语义要求单调主键序），
    /// 仅 OFFSET 分页路径应用 `sort`；`None` 时回退默认 `login_time DESC`。
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
        last_id: Option<i64>,
        tenant_scope: Option<i64>,
        tenant_filter: Option<i64>,
        sort: Option<SortOrder<Column>>,
    ) -> Result<(Vec<Model>, u64), DbErr> {
        let mut query = SysLogininfor::find();
        // 多租户 Phase 2：租户用户仅见本租户登录日志；平台 0 不过滤
        if let Some(t) = tenant_scope {
            query = query.filter(Column::TenantId.eq(t));
        }
        // 显式「按租户筛选」（`[ui].tenant_filter`）：与 tenant_scope 相与 ⇒ 只收窄
        if let Some(tid) = tenant_filter {
            query = query.filter(Column::TenantId.eq(tid));
        }
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

        // 过滤条件已齐备，统计总数（与分页模式无关，过滤后计数保持一致）
        let total = query.clone().count(self.base.db()).await?;

        // P1：keyset 深分页（PK < last_id）+ PK DESC；否则走原 OFFSET 深翻页路径
        let rows = if last_id.is_some() {
            crate::common::page::apply_keyset_filter(query, last_id, |id| Column::InfoId.lt(id))
                .order_by_desc(Column::InfoId)
                .limit(limit)
                .all(self.base.db())
                .await?
        } else {
            // OFFSET 分页路径：动态排序（白名单已解析）或默认 login_time DESC
            match sort {
                Some(s) => query.order_by(s.column, s.dir),
                None => query.order_by_desc(Column::LoginTime),
            }
            .offset(offset)
            .limit(limit)
            .all(self.base.db())
            .await?
        };
        Ok((rows, total))
    }

    /// 查询在线用户（最近活跃的登录成功记录）
    ///
    /// 简化实现：查询 status="0"（登录成功）且 login_time >= since 的记录，
    /// 按 login_time 倒序返回。用于在线用户监控页面。
    /// 限制返回数量上限，避免单次查询返回过多记录。
    ///
    /// 多租户：`tenant_scope = Some(tid)` → 仅返回本租户；`None`（平台）→ 全量。
    pub async fn find_online(
        &self,
        since: NaiveDateTime,
        ipaddr: Option<&str>,
        user_name: Option<&str>,
        limit: u64,
        tenant_scope: Option<i64>,
    ) -> Result<Vec<Model>, DbErr> {
        let mut query = SysLogininfor::find()
            .filter(Column::Status.eq("0"))
            .filter(Column::LoginTime.gte(since));
        if let Some(t) = tenant_scope {
            query = query.filter(Column::TenantId.eq(t));
        }
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

    /// 查询某用户名**最近一次成功登录**的归属地（`[risk_control].login_geo_alert` 集成点用）。
    ///
    /// 语义：`status = "0"`（登录成功）按 `login_time` 倒序取 **1 条**，只返回 `login_location`。
    /// 返回 `None` 表示"无可比对的上一跳"（首次成功登录 / 归属地为空）。
    ///
    /// 多租户：`tenant_scope = Some(tid)` → 仅在本租户内比对。**调用方必须传租户**
    /// （同一用户名可能存在于不同租户，跨租户比对既会误报也是跨租户信息泄漏）。
    ///
    /// 调用时机：必须在写入**本次**登录日志**之前**调用，否则"最近一次"会命中本次记录。
    /// 仅在档位 `alert` 时被调用 ⇒ 关闭态零查询（默认 = 现状）。
    pub async fn find_latest_success_location(
        &self,
        user_name: &str,
        tenant_scope: Option<i64>,
    ) -> Result<Option<String>, DbErr> {
        let mut query = SysLogininfor::find()
            .filter(Column::Status.eq("0"))
            .filter(Column::UserName.eq(user_name));
        if let Some(t) = tenant_scope {
            query = query.filter(Column::TenantId.eq(t));
        }
        let row = query
            .order_by_desc(Column::LoginTime)
            .order_by_desc(Column::InfoId)
            .one(self.base.db())
            .await?;
        Ok(row
            .and_then(|m| m.login_location)
            .filter(|s| !s.trim().is_empty()))
    }

    /// 批量删除登录日志（物理删除）
    ///
    /// 多租户：`tenant_scope = Some(tid)` → 仅删除本租户日志；`None`（平台）→ 不过滤。
    pub async fn delete_by_ids(
        &self,
        info_ids: Vec<i64>,
        tenant_scope: Option<i64>,
    ) -> Result<DeleteResult, DbErr> {
        let mut query = SysLogininfor::delete_many().filter(Column::InfoId.is_in(info_ids));
        if let Some(t) = tenant_scope {
            query = query.filter(Column::TenantId.eq(t));
        }
        query.exec(self.base.db()).await
    }

    /// 按用户名删除登录日志（用于解锁用户，清除登录失败记录）
    ///
    /// 多租户：`tenant_scope = Some(tid)` → 仅删除本租户日志；`None`（平台）→ 不过滤。
    pub async fn delete_by_user_name(
        &self,
        user_name: &str,
        tenant_scope: Option<i64>,
    ) -> Result<DeleteResult, DbErr> {
        let mut query = SysLogininfor::delete_many()
            .filter(Column::UserName.eq(user_name))
            .filter(Column::Status.eq("1"));
        if let Some(t) = tenant_scope {
            query = query.filter(Column::TenantId.eq(t));
        }
        query.exec(self.base.db()).await
    }

    /// 删除 N 天前的登录日志（按 login_time 过滤，物理删除）
    ///
    /// 用于保留期清理：仅删除 login_time < cutoff 的记录，
    /// 保留最近 N 天日志用于审计。
    pub async fn delete_older_than(
        &self,
        cutoff: NaiveDateTime,
        tenant_scope: Option<i64>,
    ) -> Result<DeleteResult, DbErr> {
        let mut query = SysLogininfor::delete_many().filter(Column::LoginTime.lt(cutoff));
        if let Some(t) = tenant_scope {
            query = query.filter(Column::TenantId.eq(t));
        }
        query.exec(self.base.db()).await
    }

    /// 按时间范围删除登录日志（物理删除 [begin, end] 区间内日志，边界含端点）
    ///
    /// `begin` / `end` 均可为空：为空表示该侧不设边界（例如仅清理早于 `end` 的日志）。
    /// 供登录日志「按时间范围清理」接口（`DELETE /monitor/logininfor/clean?params[beginTime]=&params[endTime]=`）使用。
    pub async fn delete_by_time_range(
        &self,
        begin: Option<NaiveDateTime>,
        end: Option<NaiveDateTime>,
        tenant_scope: Option<i64>,
    ) -> Result<DeleteResult, DbErr> {
        let mut query = SysLogininfor::delete_many();
        if let Some(t) = tenant_scope {
            query = query.filter(Column::TenantId.eq(t));
        }
        if let Some(b) = begin {
            query = query.filter(Column::LoginTime.gte(b));
        }
        if let Some(e) = end {
            query = query.filter(Column::LoginTime.lte(e));
        }
        query.exec(self.base.db()).await
    }

    /// 插入登录日志
    pub async fn insert(&self, model: ActiveModel) -> Result<Model, DbErr> {
        self.base.insert(model).await
    }

    /// 清空登录日志（物理删除）
    ///
    /// 多租户：`tenant_scope = Some(tid)` → 仅清空本租户日志；`None`（平台）→ 清空全部。
    pub async fn clean_all(&self, tenant_scope: Option<i64>) -> Result<DeleteResult, DbErr> {
        let mut query = SysLogininfor::delete_many();
        if let Some(t) = tenant_scope {
            query = query.filter(Column::TenantId.eq(t));
        }
        query.exec(self.base.db()).await
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
    pub async fn daily_stats(
        &self,
        days: i64,
        tenant_scope: Option<i64>,
    ) -> Result<Vec<(String, i64, i64)>, DbErr> {
        use chrono::Duration;
        use std::collections::HashMap;

        let backend = self.base.db().get_database_backend();
        // P1 修复：增加时间下界过滤，避免登录日志无界增长导致全表 GROUP BY 线性劣化
        // （与 sys_oper_log::stats_daily 的带时间过滤实现保持一致）
        let today = crate::common::datetime::today_utc();
        let start_date = today - Duration::days(days - 1);
        // tenant_scope=Some(t) 时按租户维度统计（报表快照/login 统计多租户隔离）
        // Postgres 需 $n 占位符，Sqlite/MySQL 用 ?（from_sql_and_values 不改写占位符）
        let ph = |i: usize| -> String {
            if backend == DatabaseBackend::Postgres {
                format!("${i}")
            } else {
                "?".to_string()
            }
        };
        let (sql, values): (String, Vec<Value>) = match tenant_scope {
            Some(t) => (
                format!(
                    "SELECT DATE(login_time) AS d, \
                 COUNT(CASE WHEN status = '0' THEN 1 END) AS success, \
                 COUNT(CASE WHEN status = '1' THEN 1 END) AS fail \
                 FROM sys_logininfor WHERE login_time >= {} AND tenant_id = {} \
                 GROUP BY DATE(login_time) \
                 ORDER BY d ASC",
                    ph(1),
                    ph(2)
                ),
                vec![start_date.into(), t.into()],
            ),
            None => (
                format!(
                    "SELECT DATE(login_time) AS d, \
                 COUNT(CASE WHEN status = '0' THEN 1 END) AS success, \
                 COUNT(CASE WHEN status = '1' THEN 1 END) AS fail \
                 FROM sys_logininfor WHERE login_time >= {} \
                 GROUP BY DATE(login_time) \
                 ORDER BY d ASC",
                    ph(1)
                ),
                vec![start_date.into()],
            ),
        };
        let stmt = Statement::from_sql_and_values(backend, sql, values);
        let rows = self.base.db().query_all_raw(stmt).await?;

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
    pub async fn count_today_failed_ips(&self, tenant_scope: Option<i64>) -> Result<i64, DbErr> {
        use sea_orm::sea_query::Expr;

        let today = crate::common::datetime::today_utc();
        let begin = today.and_time(MIDNIGHT);
        // C6（批次3）：原实现用 `.all()` 拉全量 IP 再 `.len()` 计数（N 次传输）。
        // 改为单条 `COUNT(DISTINCT ipaddr)` 聚合，直接返回不重复 IP 数，避免拉全表。
        let mut q = SysLogininfor::find();
        q = q.filter(Column::Status.eq("1"));
        q = q.filter(Column::LoginTime.gte(begin));
        q = q.filter(Column::Ipaddr.is_not_null());
        if let Some(tid) = tenant_scope {
            q = q.filter(Column::TenantId.eq(tid));
        }
        let row: Option<(i64,)> = q
            .select_only()
            .column_as(Expr::cust("COUNT(DISTINCT ipaddr)"), "c")
            .into_tuple::<(i64,)>()
            .one(self.base.db())
            .await?;
        Ok(row.map(|r| r.0).unwrap_or(0))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::datetime;
    use chrono::{Duration, NaiveDateTime};

    fn login_row(
        id: i64,
        user_name: &str,
        ipaddr: &str,
        status: &str,
        t: NaiveDateTime,
    ) -> ActiveModel {
        ActiveModel {
            info_id: Set(id),
            user_name: Set(Some(user_name.to_string())),
            ipaddr: Set(Some(ipaddr.to_string())),
            status: Set(Some(status.to_string())),
            login_time: Set(Some(t)),
            ..Default::default()
        }
    }

    async fn insert_7(db: &DatabaseConnection) -> SysLogininforRepository {
        let repo = SysLogininforRepository::new(db.clone());
        let base = datetime::now_naive();
        for i in 1..=7 {
            let status = if i == 6 { "1" } else { "0" };
            let t = base + Duration::minutes(i);
            let am = login_row(i, &format!("u{i}"), "127.0.0.1", status, t);
            repo.insert(am).await.unwrap();
        }
        repo
    }

    #[tokio::test]
    async fn keyset_returns_strictly_decreasing_pages_no_duplicates() {
        let db = crate::repository::test_support::migrated_db()
            .await
            .unwrap();
        let repo = insert_7(&db).await;
        let size = 3u64;

        let (p0, _) = repo
            .find_page_filtered(0, size, None, None, None, None, None, None, None, None, None)
            .await
            .unwrap();
        assert_eq!(p0.len(), 3);
        assert!(
            p0.iter()
                .zip(p0.iter().skip(1))
                .all(|(a, b)| a.info_id > b.info_id)
        );

        let cursor = p0.last().unwrap().info_id;
        let (p1, _) = repo
            .find_page_filtered(
                0,
                size,
                None,
                None,
                None,
                None,
                None,
                Some(cursor),
                None,
                None,
                None,
            )
            .await
            .unwrap();
        assert_eq!(p1.len(), 3);
        assert!(
            p1.iter()
                .zip(p1.iter().skip(1))
                .all(|(a, b)| a.info_id > b.info_id)
        );

        let mut seen: Vec<i64> = p0.iter().chain(&p1).map(|m| m.info_id).collect();
        seen.sort_unstable();
        let uniq: std::collections::HashSet<_> = seen.iter().collect();
        assert_eq!(seen.len(), uniq.len(), "跨页不应出现重复记录");

        let cursor = p1.last().unwrap().info_id;
        let (p2, _) = repo
            .find_page_filtered(
                0,
                size,
                None,
                None,
                None,
                None,
                None,
                Some(cursor),
                None,
                None,
                None,
            )
            .await
            .unwrap();
        assert_eq!(p2.len(), 1);
        let (p3, _) = repo
            .find_page_filtered(
                0,
                size,
                None,
                None,
                None,
                None,
                None,
                Some(p2[0].info_id),
                None,
                None,
                None,
            )
            .await
            .unwrap();
        assert!(p3.is_empty(), "游标耗尽后应返回空页");
    }

    #[tokio::test]
    async fn keyset_works_alongside_existing_filters() {
        let db = crate::repository::test_support::migrated_db()
            .await
            .unwrap();
        let repo = insert_7(&db).await;
        // 过滤 status='0'（i==6 被排除）
        let (first, total) = repo
            .find_page_filtered(0, 10, None, None, Some("0"), None, None, None, None, None, None)
            .await
            .unwrap();
        assert_eq!(total, 6);
        let cursor = first.last().unwrap().info_id;
        let (next, _) = repo
            .find_page_filtered(
                0,
                10,
                None,
                None,
                Some("0"),
                None,
                None,
                Some(cursor),
                None,
                None,
                None,
            )
            .await
            .unwrap();
        assert!(next.iter().all(|m| m.status.as_deref() == Some("0")));
    }

    #[tokio::test]
    async fn keyset_equals_offset_for_small_datasets() {
        let db = crate::repository::test_support::migrated_db()
            .await
            .unwrap();
        let repo = insert_7(&db).await;
        let size = 3u64;

        let (o0, _) = repo
            .find_page_filtered(0, size, None, None, None, None, None, None, None, None, None)
            .await
            .unwrap();
        let (o1, _) = repo
            .find_page_filtered(3, size, None, None, None, None, None, None, None, None, None)
            .await
            .unwrap();
        let (o2, _) = repo
            .find_page_filtered(6, size, None, None, None, None, None, None, None, None, None)
            .await
            .unwrap();

        let (k0, _) = repo
            .find_page_filtered(0, size, None, None, None, None, None, None, None, None, None)
            .await
            .unwrap();
        let (k1, _) = repo
            .find_page_filtered(
                0,
                size,
                None,
                None,
                None,
                None,
                None,
                Some(k0.last().unwrap().info_id),
                None,
                None,
                None,
            )
            .await
            .unwrap();
        let (k2, _) = repo
            .find_page_filtered(
                0,
                size,
                None,
                None,
                None,
                None,
                None,
                Some(k1.last().unwrap().info_id),
                None,
                None,
                None,
            )
            .await
            .unwrap();

        assert_eq!(o0, k0);
        assert_eq!(o1, k1);
        assert_eq!(o2, k2);
    }
}
