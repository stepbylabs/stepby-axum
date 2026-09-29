// backend-axum/src/repository/sys_frontend_error.rs
//! sys_frontend_error 数据访问层（前端异常与性能监控，物理删除）
//!
//! 继承 BaseRepository 通用 CRUD，扩展前端异常特有查询：
//! - 多条件分页（level / source / name 模糊 / 时间范围，按 create_time 倒序）
//! - 批量插入（前端一次上报多条）
//! - 批量删除 / 保留期清理

use chrono::NaiveDateTime;
use sea_orm::*;

use crate::common::like_escape;
use crate::entity::sys_frontend_error::{ActiveModel, Column, Entity as SysFrontendError, Model};
use crate::repository::base::BaseRepository;

/// 前端异常 Repository
#[derive(Clone)]
pub struct SysFrontendErrorRepository {
    base: BaseRepository<SysFrontendError>,
}

impl SysFrontendErrorRepository {
    pub fn new(db: DatabaseConnection) -> Self {
        Self {
            base: BaseRepository::new(db),
        }
    }

    pub fn db(&self) -> &DatabaseConnection {
        self.base.db()
    }

    /// 按 id 查询单条
    pub async fn find_by_id(&self, id: i64) -> Result<Option<Model>, DbErr> {
        SysFrontendError::find_by_id(id).one(self.base.db()).await
    }

    /// 多条件分页查询（level/source/device_type 精确，name 模糊，时间范围，按 create_time 倒序）
    #[allow(clippy::too_many_arguments)]
    pub async fn find_page_filtered(
        &self,
        offset: u64,
        limit: u64,
        level: Option<&str>,
        source: Option<&str>,
        name: Option<&str>,
        device_type: Option<&str>,
        begin_time: Option<NaiveDateTime>,
        end_time: Option<NaiveDateTime>,
        tenant_scope: Option<i64>,
        tenant_filter: Option<i64>,
    ) -> Result<(Vec<Model>, u64), DbErr> {
        let mut query = SysFrontendError::find();
        // 多租户：租户操作者仅见本租户记录；平台（None）不过滤
        if let Some(t) = tenant_scope {
            query = query.filter(Column::TenantId.eq(t));
        }
        // 显式「按租户筛选」（`[ui].tenant_filter`）：与 tenant_scope 相与 ⇒ 只收窄
        if let Some(tid) = tenant_filter {
            query = query.filter(Column::TenantId.eq(tid));
        }
        if let Some(l) = level {
            query = query.filter(Column::Level.eq(l));
        }
        if let Some(s) = source {
            query = query.filter(Column::Source.eq(s));
        }
        if let Some(n) = name {
            query = query.filter(Column::Name.like(format!("%{}%", like_escape(n))));
        }
        // 设备类型分桶筛选（FCP-011）：mobile / tablet / desktop
        if let Some(d) = device_type {
            query = query.filter(Column::DeviceType.eq(d));
        }
        if let Some(begin) = begin_time {
            query = query.filter(Column::CreateTime.gte(begin));
        }
        if let Some(end) = end_time {
            query = query.filter(Column::CreateTime.lte(end));
        }
        let total = query.clone().count(self.base.db()).await?;
        let rows = query
            .order_by_desc(Column::Id)
            .offset(offset)
            .limit(limit)
            .all(self.base.db())
            .await?;
        Ok((rows, total))
    }

    /// 插入单条
    pub async fn insert(&self, model: ActiveModel) -> Result<Model, DbErr> {
        self.base.insert(model).await
    }

    /// 批量插入（前端一次上报多条）。返回插入条数（单语句批量插入，条数即入参长度）。
    pub async fn insert_many(&self, models: Vec<ActiveModel>) -> Result<u64, DbErr> {
        let n = models.len() as u64;
        if models.is_empty() {
            return Ok(0);
        }
        SysFrontendError::insert_many(models)
            .exec(self.base.db())
            .await?;
        Ok(n)
    }

    /// 批量删除（物理删除）
    ///
    /// 多租户：`tenant_scope = Some(tid)` → 仅删除本租户记录；`None`（平台）→ 不过滤。
    pub async fn delete_by_ids(
        &self,
        ids: Vec<i64>,
        tenant_scope: Option<i64>,
    ) -> Result<DeleteResult, DbErr> {
        let mut query = SysFrontendError::delete_many().filter(Column::Id.is_in(ids));
        if let Some(t) = tenant_scope {
            query = query.filter(Column::TenantId.eq(t));
        }
        query.exec(self.base.db()).await
    }

    /// 删除 N 天前的记录（保留期清理）
    ///
    /// 多租户：`tenant_scope = Some(tid)` → 仅删除本租户记录；`None`（平台）→ 不过滤。
    pub async fn delete_older_than(
        &self,
        cutoff: NaiveDateTime,
        tenant_scope: Option<i64>,
    ) -> Result<DeleteResult, DbErr> {
        let mut query = SysFrontendError::delete_many().filter(Column::CreateTime.lt(cutoff));
        if let Some(t) = tenant_scope {
            query = query.filter(Column::TenantId.eq(t));
        }
        query.exec(self.base.db()).await
    }

    /// 按时间范围删除（边界含端点，任一侧可为空）
    ///
    /// 多租户：`tenant_scope = Some(tid)` → 仅删除本租户记录；`None`（平台）→ 不过滤。
    pub async fn delete_by_time_range(
        &self,
        begin: Option<NaiveDateTime>,
        end: Option<NaiveDateTime>,
        tenant_scope: Option<i64>,
    ) -> Result<DeleteResult, DbErr> {
        let mut query = SysFrontendError::delete_many();
        if let Some(t) = tenant_scope {
            query = query.filter(Column::TenantId.eq(t));
        }
        if let Some(b) = begin {
            query = query.filter(Column::CreateTime.gte(b));
        }
        if let Some(e) = end {
            query = query.filter(Column::CreateTime.lte(e));
        }
        query.exec(self.base.db()).await
    }

    /// 聚合统计：按 source 分组计数（仪表盘/概览用）
    ///
    /// 多租户：`tenant_scope = Some(tid)` → 仅统计本租户；`None`（平台）→ 全量。
    pub async fn stats_by_source(
        &self,
        tenant_scope: Option<i64>,
    ) -> Result<Vec<(String, i64)>, DbErr> {
        use sea_orm::sea_query::Expr;
        let mut query = SysFrontendError::find()
            .select_only()
            .column(Column::Source)
            .column_as(Expr::col(Column::Id).count(), "cnt");
        if let Some(t) = tenant_scope {
            query = query.filter(Column::TenantId.eq(t));
        }
        let rows: Vec<(String, i64)> = query
            .group_by(Column::Source)
            .order_by_desc(Expr::col(Column::Id).count())
            .into_tuple::<(String, i64)>()
            .all(self.base.db())
            .await?;
        Ok(rows)
    }

    /// 聚合统计：最近 N 天每日 error 数（趋势图用）
    ///
    /// 多租户：`tenant_scope = Some(tid)` → 仅统计本租户；`None`（平台）→ 全量。
    pub async fn stats_daily_errors(
        &self,
        days: i64,
        tenant_scope: Option<i64>,
    ) -> Result<Vec<(String, i64)>, DbErr> {
        use chrono::Duration;
        use std::collections::HashMap;
        let today = crate::common::datetime::today_utc();
        let start = today - Duration::days(days - 1);
        let begin_time = start.and_time(chrono::NaiveTime::MIN);
        let db = self.base.db();
        let backend = db.get_database_backend();
        // 租户过滤后缀（单占位符，便于三方言复用）
        let tenant_clause = match (backend, tenant_scope) {
            (DatabaseBackend::Postgres, Some(_)) => " AND $2 = tenant_id",
            (_, Some(_)) => " AND ? = tenant_id",
            (_, None) => "",
        };
        let mut values: Vec<sea_orm::Value> = vec![begin_time.into()];
        if let Some(t) = tenant_scope {
            values.push(t.into());
        }
        let sql = match backend {
            DatabaseBackend::Sqlite => format!(
                "SELECT strftime('%Y-%m-%d', create_time) AS d, COUNT(*) AS c \
                 FROM sys_frontend_error WHERE create_time >= ? AND level='error'{tenant_clause} \
                 GROUP BY d ORDER BY d ASC"
            ),
            DatabaseBackend::Postgres => format!(
                "SELECT TO_CHAR(create_time, 'YYYY-MM-DD') AS d, COUNT(*) AS c \
                 FROM sys_frontend_error WHERE create_time >= $1 AND level='error'{tenant_clause} \
                 GROUP BY d ORDER BY d ASC"
            ),
            DatabaseBackend::MySql => format!(
                "SELECT DATE_FORMAT(create_time, '%Y-%m-%d') AS d, COUNT(*) AS c \
                 FROM sys_frontend_error WHERE create_time >= ? AND level='error'{tenant_clause} \
                 GROUP BY d ORDER BY d ASC"
            ),
        };
        let rows = db
            .query_all(Statement::from_sql_and_values(backend, sql, values))
            .await?;
        let mut counts: HashMap<String, i64> = HashMap::with_capacity(rows.len());
        for row in rows {
            let d: String = row.try_get("", "d")?;
            let c: i64 = row.try_get("", "c").unwrap_or(0);
            counts.insert(d, c);
        }
        let mut result = Vec::with_capacity(days as usize);
        for i in 0..days {
            let date = start + Duration::days(i);
            let date_str = date.format("%Y-%m-%d").to_string();
            let count = counts.get(&date_str).copied().unwrap_or(0);
            result.push((date_str, count));
        }
        Ok(result)
    }
}
