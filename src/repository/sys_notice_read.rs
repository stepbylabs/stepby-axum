// backend-axum/src/repository/sys_notice_read.rs
//! sys_notice_read 数据访问层（通知公告已读记录表）
//!
//! 提供已读记录的插入、查询、未读数统计等功能。

use chrono::NaiveDateTime;
use sea_orm::*;
use serde::Serialize;
use utoipa::ToSchema;

use crate::entity::sys_notice_read::{Column, Entity as SysNoticeRead, Model};
use crate::repository::base::BaseRepository;

/// 通知公告已读记录 Repository
#[derive(Clone)]
pub struct SysNoticeReadRepository {
    base: BaseRepository<SysNoticeRead>,
}

/// 已读用户视图对象（联表查询结果）
#[derive(Debug, Clone, FromQueryResult, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct NoticeReadUserVo {
    pub read_id: i64,
    pub notice_id: i64,
    pub user_id: i64,
    pub read_time: Option<NaiveDateTime>,
    pub user_name: Option<String>,
    pub nick_name: Option<String>,
    pub dept_name: Option<String>,
    pub phonenumber: Option<String>,
}

impl SysNoticeReadRepository {
    pub fn new(db: DatabaseConnection) -> Self {
        Self {
            base: BaseRepository::new(db),
        }
    }

    pub fn base(&self) -> &BaseRepository<SysNoticeRead> {
        &self.base
    }

    /// 标记公告已读（原子化插入，已读则不重复插入）
    ///
    /// 使用数据库原生的冲突忽略语义（INSERT OR IGNORE / ON CONFLICT DO NOTHING），
    /// 避免"先 SELECT 后 INSERT"的 TOCTOU 竞态。依赖 sys_notice_read 表的唯一约束 (notice_id, user_id)。
    pub async fn mark_read(
        &self,
        notice_id: i64,
        user_id: i64,
        tenant_id: i64,
    ) -> Result<(), DbErr> {
        let now = crate::common::datetime::now_naive();
        let db = self.base.db();
        let backend = db.get_database_backend();

        // 各数据库后端的冲突忽略语法不同，按 backend 选择原生 SQL
        // 从属表归属：read 记录随父公告租户（写入时必须带父资源租户）
        let sql = match backend {
            DatabaseBackend::Sqlite => {
                "INSERT OR IGNORE INTO sys_notice_read (notice_id, user_id, read_time, tenant_id) VALUES (?, ?, ?, ?)"
            }
            DatabaseBackend::Postgres => {
                "INSERT INTO sys_notice_read (notice_id, user_id, read_time, tenant_id) VALUES ($1, $2, $3, $4) ON CONFLICT (notice_id, user_id) DO NOTHING"
            }
            DatabaseBackend::MySql => {
                "INSERT IGNORE INTO sys_notice_read (notice_id, user_id, read_time, tenant_id) VALUES (?, ?, ?, ?)"
            }
        };

        let values: Vec<Value> = vec![
            notice_id.into(),
            user_id.into(),
            now.into(),
            tenant_id.into(),
        ];
        let stmt = Statement::from_sql_and_values(backend, sql, values);
        db.execute(stmt).await?;
        Ok(())
    }

    /// 批量标记公告已读（单条 SQL 多值插入，冲突忽略，替代循环 N 次）
    ///
    /// 使用数据库原生的冲突忽略语义（INSERT OR IGNORE / ON CONFLICT DO NOTHING / INSERT IGNORE），
    /// 依赖 sys_notice_read 表的唯一约束 (notice_id, user_id)，避免 TOCTOU 竞态。
    pub async fn mark_read_batch(
        &self,
        notice_ids: Vec<i64>,
        user_id: i64,
        tenant_id: i64,
    ) -> Result<(), DbErr> {
        if notice_ids.is_empty() {
            return Ok(());
        }
        let now = crate::common::datetime::now_naive();
        let db = self.base.db();
        let backend = db.get_database_backend();

        // Postgres 需 $n 占位符，Sqlite/MySQL 用 ?（from_sql_and_values 不改写占位符）
        let ph = |i: usize| -> String {
            if backend == DatabaseBackend::Postgres {
                format!("${i}")
            } else {
                "?".to_string()
            }
        };
        // 构建多值 VALUES 子句：每个 notice_id 一组 4 个占位符
        let values_clause = notice_ids
            .iter()
            .enumerate()
            .map(|(i, _)| {
                let base = i * 4 + 1;
                format!(
                    "({}, {}, {}, {})",
                    ph(base),
                    ph(base + 1),
                    ph(base + 2),
                    ph(base + 3)
                )
            })
            .collect::<Vec<_>>()
            .join(", ");

        let sql = match backend {
            DatabaseBackend::Sqlite => {
                format!(
                    "INSERT OR IGNORE INTO sys_notice_read (notice_id, user_id, read_time, tenant_id) VALUES {}",
                    values_clause
                )
            }
            DatabaseBackend::Postgres => {
                format!(
                    "INSERT INTO sys_notice_read (notice_id, user_id, read_time, tenant_id) VALUES {} ON CONFLICT (notice_id, user_id) DO NOTHING",
                    values_clause
                )
            }
            DatabaseBackend::MySql => {
                format!(
                    "INSERT IGNORE INTO sys_notice_read (notice_id, user_id, read_time, tenant_id) VALUES {}",
                    values_clause
                )
            }
        };

        let mut values: Vec<Value> = Vec::with_capacity(notice_ids.len() * 4);
        for notice_id in &notice_ids {
            values.push((*notice_id).into());
            values.push(user_id.into());
            values.push(now.into());
            values.push(tenant_id.into());
        }

        let stmt = Statement::from_sql_and_values(backend, sql, values);
        db.execute(stmt).await?;
        Ok(())
    }

    /// 查询指定公告的已读用户列表（联表 sys_user + sys_dept）
    ///
    /// 支持 searchValue 模糊匹配登录名/用户名
    ///
    /// 安全说明：使用参数化查询（占位符 + Values），避免 SQL 注入风险。
    /// 注意：Statement::from_sql_and_values 不会改写占位符，Postgres 必须用 $n，
    /// 故此处按 backend 生成占位符（Sqlite/MySQL 用 ?）。
    #[allow(clippy::too_many_arguments)]
    pub async fn find_read_users_page(
        &self,
        offset: u64,
        limit: u64,
        notice_id: i64,
        search_value: Option<&str>,
        tenant_scope: Option<i64>,
    ) -> Result<(Vec<NoticeReadUserVo>, u64), DbErr> {
        let db = self.base.db();
        let backend = db.get_database_backend();

        // Postgres 需 $n 占位符，Sqlite/MySQL 用 ?
        let ph = |i: usize| -> String {
            if backend == DatabaseBackend::Postgres {
                format!("${i}")
            } else {
                "?".to_string()
            }
        };
        // 使用参数化查询构建 WHERE 子句，避免 SQL 注入
        let mut idx = 1usize;
        let mut where_clause = format!("WHERE r.notice_id = {} ", ph(idx));
        let mut values: Vec<Value> = vec![notice_id.into()];

        if let Some(tid) = tenant_scope {
            idx += 1;
            where_clause.push_str(&format!("AND r.tenant_id = {} ", ph(idx)));
            values.push(tid.into());
        }

        if let Some(sv) = search_value
            && !sv.trim().is_empty()
        {
            where_clause.push_str(&format!(
                "AND (u.user_name LIKE {} OR u.nick_name LIKE {}) ",
                ph(idx + 1),
                ph(idx + 2)
            ));
            idx += 2;
            // 安全：调用 like_escape 转义 %/_ 通配符，防止用户输入 % 匹配全表（信息枚举/性能损耗）
            let pattern = format!("%{}%", crate::common::like_escape(sv));
            values.push(pattern.clone().into());
            values.push(pattern.into());
        }

        // count 查询
        let count_sql = format!(
            "SELECT COUNT(*) AS count \
             FROM sys_notice_read r \
             LEFT JOIN sys_user u ON r.user_id = u.user_id \
             LEFT JOIN sys_dept d ON u.dept_id = d.dept_id \
             {}",
            where_clause
        );
        let count_result = db
            .query_one(Statement::from_sql_and_values(
                backend,
                &count_sql,
                values.clone(),
            ))
            .await?;
        let total: u64 = count_result
            .map(|row| u64::try_from(row.try_get::<i64>("", "count").unwrap_or(0)).unwrap_or(0))
            .unwrap_or(0);

        // 分页查询（LIMIT/OFFSET 也参数化）
        let list_sql = format!(
            "SELECT r.read_id, r.notice_id, r.user_id, r.read_time, \
             u.user_name, u.nick_name, d.dept_name, u.phonenumber \
             FROM sys_notice_read r \
             LEFT JOIN sys_user u ON r.user_id = u.user_id \
             LEFT JOIN sys_dept d ON u.dept_id = d.dept_id \
             {} \
             ORDER BY r.read_time DESC \
             LIMIT {} OFFSET {}",
            where_clause,
            ph(idx + 1),
            ph(idx + 2)
        );
        // 追加分页参数到 values
        let mut list_values = values;
        list_values.push((limit as i64).into());
        list_values.push((offset as i64).into());

        let rows = NoticeReadUserVo::find_by_statement(Statement::from_sql_and_values(
            backend,
            &list_sql,
            list_values,
        ))
        .all(db)
        .await?;

        Ok((rows, total))
    }

    /// 统计指定公告的已读用户数
    pub async fn count_read_users(
        &self,
        notice_id: i64,
        tenant_scope: Option<i64>,
    ) -> Result<u64, DbErr> {
        let mut q = SysNoticeRead::find().filter(Column::NoticeId.eq(notice_id));
        if let Some(tid) = tenant_scope {
            q = q.filter(Column::TenantId.eq(tid));
        }
        q.count(self.base.db()).await
    }

    /// 查询用户已读的公告 ID 集合
    pub async fn find_read_notice_ids(
        &self,
        user_id: i64,
        tenant_scope: Option<i64>,
    ) -> Result<Vec<i64>, DbErr> {
        let mut q = SysNoticeRead::find().filter(Column::UserId.eq(user_id));
        if let Some(tid) = tenant_scope {
            q = q.filter(Column::TenantId.eq(tid));
        }
        let rows: Vec<Model> = q.all(self.base.db()).await?;
        Ok(rows.into_iter().map(|r| r.notice_id).collect())
    }

    /// 统计用户未读公告数（总数 - 已读数）
    ///
    /// 优化（DB-13）：原实现两次 COUNT 查询，合并为单次带子查询的查询，DB 往返减半。
    ///
    /// 安全（P0-10）：使用参数化占位符（Postgres 用 $1，其他用 ?）替代 format! 拼接，
    /// 即使 user_id 来源不可信也不会产生 SQL 注入。
    pub async fn count_unread(
        &self,
        user_id: i64,
        tenant_scope: Option<i64>,
    ) -> Result<u64, DbErr> {
        use sea_orm::ConnectionTrait;
        let backend = self.base.db().get_database_backend();
        // 单次查询：公告总数（status='0'）减去该用户已读数
        // tenant_scope=Some(t) 时两处子查询均附加 tenant_id 过滤（按租户维度统计）
        // 参数化：Postgres 使用 $n 占位符，Sqlite/MySQL 使用 ? 占位符
        let (sql, values): (String, Vec<Value>) = match (backend, tenant_scope) {
            (DatabaseBackend::Postgres, Some(t)) => (
                "SELECT (SELECT COUNT(*) FROM sys_notice WHERE status = '0' AND tenant_id = $1) - \
                 (SELECT COUNT(*) FROM sys_notice_read WHERE user_id = $2 AND tenant_id = $1) AS unread"
                    .to_string(),
                vec![t.into(), user_id.into()],
            ),
            (DatabaseBackend::Postgres, None) => (
                "SELECT (SELECT COUNT(*) FROM sys_notice WHERE status = '0') - \
                 (SELECT COUNT(*) FROM sys_notice_read WHERE user_id = $1) AS unread"
                    .to_string(),
                vec![user_id.into()],
            ),
            (_, Some(t)) => (
                "SELECT (SELECT COUNT(*) FROM sys_notice WHERE status = '0' AND tenant_id = ?) - \
                 (SELECT COUNT(*) FROM sys_notice_read WHERE user_id = ? AND tenant_id = ?) AS unread"
                    .to_string(),
                vec![t.into(), user_id.into(), t.into()],
            ),
            (_, None) => (
                "SELECT (SELECT COUNT(*) FROM sys_notice WHERE status = '0') - \
                 (SELECT COUNT(*) FROM sys_notice_read WHERE user_id = ?) AS unread"
                    .to_string(),
                vec![user_id.into()],
            ),
        };
        let stmt = sea_orm::Statement::from_sql_and_values(backend, sql, values);
        let row = self.base.db().query_one(stmt).await?;
        let unread: i64 = row
            .and_then(|r| r.try_get_by_index::<i64>(0).ok())
            .unwrap_or(0);
        Ok(u64::try_from(unread.max(0)).unwrap_or(0))
    }

    /// 删除指定公告的所有已读记录（公告删除时级联清理）
    pub async fn delete_by_notice_ids(&self, notice_ids: Vec<i64>) -> Result<DeleteResult, DbErr> {
        SysNoticeRead::delete_many()
            .filter(Column::NoticeId.is_in(notice_ids))
            .exec(self.base.db())
            .await
    }

    /// 标记用户所有未读公告为已读（"全部已读"功能）
    ///
    /// 实现策略：先查询所有状态正常的公告 ID（status='0'），再查询用户已读的公告 ID，
    /// 计算 diff 后批量 INSERT OR IGNORE。比"全量 INSERT OR IGNORE"更高效：
    /// - 仅插入未读记录，避免对已读记录做无效 INSERT
    /// - 已读数量可能很大（历史累积），但未读通常远小于已读
    ///
    /// 安全：使用参数化查询，user_id 来源可信（Operator 提取），无注入风险。
    ///
    /// 多租户：tenant_scope=Some(t) 时仅处理该租户公告；平台操作者（None）按公告实际
    /// 所属租户分组写入，保证已读记录 tenant_id 与父公告一致。
    pub async fn mark_all_unread_read(
        &self,
        user_id: i64,
        tenant_scope: Option<i64>,
    ) -> Result<u64, DbErr> {
        use crate::entity::sys_notice::{Column as NoticeColumn, Entity as SysNotice};
        use sea_orm::QuerySelect;

        // 1. 查询状态正常的公告 (notice_id, tenant_id)
        let mut nq = SysNotice::find();
        nq = nq.filter(NoticeColumn::Status.eq("0"));
        if let Some(t) = tenant_scope {
            nq = nq.filter(NoticeColumn::TenantId.eq(t));
        }
        let all_notices: Vec<(i64, i64)> = nq
            .select_only()
            .column(NoticeColumn::NoticeId)
            .column(NoticeColumn::TenantId)
            .into_tuple::<(i64, i64)>()
            .all(self.base.db())
            .await?;

        if all_notices.is_empty() {
            return Ok(0);
        }

        // 2. 查询用户已读的公告 ID
        let read_notice_ids = self.find_read_notice_ids(user_id, tenant_scope).await?;

        // 3. 计算未读公告 (notice_id, tenant_id)
        let read_set: std::collections::HashSet<i64> = read_notice_ids.into_iter().collect();
        let unread: Vec<(i64, i64)> = all_notices
            .into_iter()
            .filter(|(id, _)| !read_set.contains(id))
            .collect();

        if unread.is_empty() {
            return Ok(0);
        }

        let marked_count = unread.len() as u64;
        // 4. 按公告所属租户分组批量插入未读记录（依赖唯一约束 + 冲突忽略）
        let mut by_tenant: std::collections::BTreeMap<i64, Vec<i64>> =
            std::collections::BTreeMap::new();
        for (notice_id, tid) in unread {
            by_tenant.entry(tid).or_default().push(notice_id);
        }
        for (tid, ids) in by_tenant {
            self.mark_read_batch(ids, user_id, tid).await?;
        }
        Ok(marked_count)
    }

    /// 删除指定公告的所有已读记录（使用指定连接，用于事务内调用）
    pub async fn delete_by_notice_ids_conn<C: ConnectionTrait>(
        &self,
        conn: &C,
        notice_ids: Vec<i64>,
    ) -> Result<DeleteResult, DbErr> {
        SysNoticeRead::delete_many()
            .filter(Column::NoticeId.is_in(notice_ids))
            .exec(conn)
            .await
    }
}
