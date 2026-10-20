// stepby-axum/src/repository/sys_notice_read.rs
//! sys_notice_read 数据访问层（通知公告已读记录表）
//!
//! 提供已读记录的插入、查询、未读数统计等功能。

use chrono::NaiveDateTime;
use sea_orm::*;
use serde::Serialize;
use std::collections::HashSet;
use utoipa::ToSchema;

use crate::entity::sys_notice_read::{ActiveModel, Column, Entity as SysNoticeRead, Model};
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
    /// §5.55（sea-orm 迁移）：冲突忽略语义改由 sea-query `OnConflict` 生成——
    /// 三方言（INSERT OR IGNORE / ON CONFLICT DO NOTHING / INSERT IGNORE）
    /// 由 ORM 按连接方言自动产出，消除三份手写 SQL 的方言漂移面。
    /// 依赖 sys_notice_read 表的唯一约束 (notice_id, user_id)。
    pub async fn mark_read(
        &self,
        notice_id: i64,
        user_id: i64,
        tenant_id: i64,
    ) -> Result<(), DbErr> {
        let now = crate::common::datetime::now_naive();
        let db = self.base.db();
        // 从属表归属：read 记录随父公告租户（写入时必须带父资源租户）
        let am = ActiveModel {
            notice_id: Set(notice_id),
            user_id: Set(user_id),
            read_time: Set(Some(now)),
            tenant_id: Set(tenant_id),
            ..Default::default()
        };
        let insert = SysNoticeRead::insert(am);
        // 统一用**显式冲突目标列**（b73 轮 13 实证缺陷订正）：
        // 无目标版 `on_conflict_do_nothing()` 在 SQLite 上不注入 ON CONFLICT 子句，重复标记
        // 直接撞 UNIQUE(notice_id, user_id) → 400「数据重复，请检查唯一字段」+ WARN。
        // 本仓同族的批量路径（mark_read_batch）早已因此改用带目标列版本（§5.53），
        // 但单条路径漏改——链路测试 6b「重复标记必须幂等」把这条补齐。
        // 带目标列版本三方言均正确生成（MySQL 走 ON DUPLICATE KEY polyfill），
        // 且目标列与表上的 UNIQUE(notice_id, user_id) 严格对应，不会掩盖其他约束冲突。
        // Conflicted（已存在被忽略）是**正常路径**，不得当错误上抛。
        let _ = insert
            .on_conflict_do_nothing_on([Column::NoticeId, Column::UserId])
            .exec(db)
            .await?;
        Ok(())
    }

    /// 批量标记公告已读（insert_many 多值插入，冲突忽略，替代循环 N 次）
    ///
    /// §5.55（sea-orm 迁移）：多值 VALUES 拼接改由 sea-orm `insert_many` +
    /// `OnConflict` 生成——占位符方言差异（$n vs ?）由 ORM 封装，
    /// 消除手写占位符计数与三份方言 SQL 的漂移面。
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

        let models: Vec<ActiveModel> = notice_ids
            .iter()
            .map(|nid| ActiveModel {
                notice_id: Set(*nid),
                user_id: Set(user_id),
                read_time: Set(Some(now)),
                tenant_id: Set(tenant_id),
                ..Default::default()
            })
            .collect();

        let insert = SysNoticeRead::insert_many(models);
        // §5.53 终：统一 on_conflict_do_nothing_on（显式冲突目标列）——
        // 无目标版 on_conflict_do_nothing 在 insert_many 路径下对 SQLite
        // 实测未注入 ON CONFLICT 子句（UNIQUE 冲突上抛，链路测试实证），
        // 带目标列版本三方言均正确生成（MySQL 走 ON DUPLICATE KEY polyfill）。
        // Conflicted（部分/全部已存在被忽略）是正常路径，不得当错误上抛
        let _ = insert
            .on_conflict_do_nothing_on([Column::NoticeId, Column::UserId])
            .exec(db)
            .await?;
        Ok(())
    }

    /// 查询指定公告的已读用户列表（联表 sys_user + sys_dept）
    ///
    /// 支持 searchValue 模糊匹配登录名/用户名
    ///
    /// `sort`：动态排序（方案 B）。service 层已按 `READ_USER_SORTABLE_COLUMNS` 白名单
    /// 解析为 `(SQL 列表达式, 是否升序)`——表达式全部来自 service 侧常量白名单
    /// （如 `r.read_time` / `u.user_name`），无用户可控的字符串拼接注入面；
    /// `None` 时回退默认 `read_time DESC`。
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
        sort: Option<(&'static str, bool)>,
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
            .query_one_raw(Statement::from_sql_and_values(
                backend,
                &count_sql,
                values.clone(),
            ))
            .await?;
        let total: u64 = count_result
            .map(|row| u64::try_from(row.try_get::<i64>("", "count").unwrap_or(0)).unwrap_or(0))
            .unwrap_or(0);

        // 动态排序（service 层白名单已解析）：expr 来自常量白名单，方向为受限 bool
        let order_clause = match sort {
            Some((expr, true)) => format!("ORDER BY {} ASC ", expr),
            Some((expr, false)) => format!("ORDER BY {} DESC ", expr),
            None => "ORDER BY r.read_time DESC ".to_string(),
        };
        // 分页查询（LIMIT/OFFSET 也参数化）
        let list_sql = format!(
            "SELECT r.read_id, r.notice_id, r.user_id, r.read_time, \
             u.user_name, u.nick_name, d.dept_name, u.phonenumber \
             FROM sys_notice_read r \
             LEFT JOIN sys_user u ON r.user_id = u.user_id \
             LEFT JOIN sys_dept d ON u.dept_id = d.dept_id \
             {} \
             {} \
             LIMIT {} OFFSET {}",
            where_clause,
            order_clause,
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

    /// 查询"这批公告里，当前用户已读了哪些"（b79 P3：列表/顶部公告的逐行已读态）
    ///
    /// 规模收敛：只按 `notice_id IN (本页)` 查询，避免热路径随用户历史已读数线性膨胀
    /// （列表/未读数的**集合级**判定已改由 `SysNoticeRepository::base_query` 的半连接承担）。
    /// 与 `find_read_notice_ids` 的差别是**收敛边界**：后者按用户拉全量已读 ID，
    /// 只能用于"跨页全部已读"这类一次性后台动作；列表接口每页最多 100 行，
    /// 用 `IN (本页 ID)` 把查询钉在页规模内，避免热路径随用户历史已读数线性膨胀。
    ///
    /// 多租户：`tenant_scope` 与同屏的未读数（`SysNoticeRepository::count_by_filter`）**同一个谓词、
    /// 同一张表**——两者若一方按操作者租户、另一方不按，同一屏上就会出现"角标说 0 未读、行却全显示未读"
    /// 的自相矛盾（b79 P3 立案的原始症状正是这种矛盾）。写侧 `mark_read` 落的是
    /// **父公告的 `tenant_id`**（`sys_notice_service.rs` 的 mark_read），而列表侧公告本身已由
    /// `tenant_scope(operator_tid)` 筛过，故租户操作者可见公告的读记录恒等于其操作者租户；
    /// 平台操作者（`tenant_id=0` ⇒ `tenant_scope` 返回 `None`）两侧都不加过滤，代管视角照常。
    pub async fn find_read_notice_ids_in(
        &self,
        user_id: i64,
        tenant_scope: Option<i64>,
        notice_ids: &[i64],
    ) -> Result<HashSet<i64>, DbErr> {
        if notice_ids.is_empty() {
            return Ok(HashSet::new());
        }
        let mut q = SysNoticeRead::find()
            .filter(Column::UserId.eq(user_id))
            .filter(Column::NoticeId.is_in(notice_ids.iter().copied()));
        if let Some(tid) = tenant_scope {
            q = q.filter(Column::TenantId.eq(tid));
        }
        let rows: Vec<Model> = q.all(self.base.db()).await?;
        Ok(rows.into_iter().map(|r| r.notice_id).collect())
    }

    /// 删除指定公告的所有已读记录（事务内版本；公告删除必须与清理已读记录同事务，P0-76）
    ///
    /// 刻意只提供 `_conn` 版本：无事务的独立删除会把"公告已删 / 已读记录残留"的窗口
    /// 暴露成可提交状态（b80 清理掉的那份重复实现正是这种无调用点的第二入口）。
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
