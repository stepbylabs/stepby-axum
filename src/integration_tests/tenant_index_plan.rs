// stepby-axum/src/integration_tests/tenant_index_plan.rs
//! 台账 P2-6：组合索引在**租户数据倾斜**下的执行计划验证（SQLite）。
//!
//! 背景：迁移 `m20260925_000001_multitenant_phase2.rs` 为 27 张表建了单列
//! `idx_{table}_tid`、为大表建 `idx_{table}_tid_time`，但倾斜数据下的执行计划从未验证。
//!
//! 本模块用 `EXPLAIN QUERY PLAN` 验证：承载 `tenant_id` 的既有表 `sys_logininfor`
//! （同时具备 `idx_sys_logininfor_tid` 与 `idx_sys_logininfor_tid_time`）在
//! **某租户行数远多于其它租户**时，带 `tenant_id = ?` 过滤 + `ORDER BY login_time DESC`
//! 的分页查询是否走租户索引（而非全表扫描）。
//!
//! 被测查询由 `sea-orm` DSL 构造，与 `SysLogininforRepository::find_page_filtered`
//! （`src/repository/sys_logininfor.rs:46-98`）的租户过滤 + 排序 + 分页路径逐条对齐，
//! 再用 `QueryTrait::build` 取真实 SQL 交给 `EXPLAIN QUERY PLAN`；同时真实调用
//! `SysLogininforService::get_logininfor_page`（走同一 Repository 路径）核对过滤结果。
//!
//! 判定诚实：若计划器在数据量/统计信息不足时确实选择全表扫描，则如实断言当前行为
//! 并在台账登记（附计划原文）。pg/mysql 方言不在现有 SQLite 测试框架内，见台账 P2-6
//! 「验证结果」（登记为待运维侧执行）。

use sea_orm::{
    ColumnTrait, ConnectionTrait, DatabaseBackend, DatabaseConnection, EntityTrait, QueryFilter,
    QueryOrder, QuerySelect, QueryTrait, Statement,
};

use super::TestContext;
use crate::entity::sys_frontend_error::{Column as FeColumn, Entity as SysFrontendError};
use crate::entity::sys_logininfor::{Column, Entity as SysLogininfor};
use crate::entity::sys_notice_read::{Column as ReadColumn, Entity as SysNoticeRead};
use crate::service::sys_logininfor_service::LogininforQueryDto;

/// 倾斜造数：`tenant_id = tid` 插入 `n` 行登录日志（`base_id` 起递增，避免 PK 冲突）。
///
/// 用递归 CTE 一次性插入（快且不逐行往返）；`login_time` 用 `datetime('now')`。
async fn insert_bulk(db: &DatabaseConnection, tid: i64, n: i64, base_id: i64) {
    let sql = format!(
        "WITH RECURSIVE seq(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM seq WHERE x < {n}) \
         INSERT INTO sys_logininfor (tenant_id, user_id, info_id, user_name, status, login_time) \
         SELECT {tid}, 0, {base_id} + x, 'it_bulk', '0', datetime('now') FROM seq"
    );
    db.execute_unprepared(&sql)
        .await
        .expect("批量插入 sys_logininfor 失败");
}

/// 倾斜造数：`sys_frontend_error`（仅单列 `idx_sys_frontend_error_tid`）插入 `n` 行。
async fn insert_bulk_fe(db: &DatabaseConnection, tid: i64, n: i64, base_id: i64) {
    let sql = format!(
        "WITH RECURSIVE seq(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM seq WHERE x < {n}) \
         INSERT INTO sys_frontend_error (tenant_id, id, level, source, create_time) \
         SELECT {tid}, {base_id} + x, 'error', 'api', datetime('now') FROM seq"
    );
    db.execute_unprepared(&sql)
        .await
        .expect("批量插入 sys_frontend_error 失败");
}

/// 对单列 tid 索引表 `sys_frontend_error` 取 `EXPLAIN QUERY PLAN`（与分页路径同构：
/// `tenant_id` 过滤 + `order_by_desc(id)` + offset/limit）。
async fn explain_fe_page(db: &DatabaseConnection, tid: i64) -> Vec<String> {
    let q = SysFrontendError::find()
        .filter(FeColumn::TenantId.eq(tid))
        .order_by_desc(FeColumn::Id)
        .offset(0)
        .limit(10);
    let built = q.build(DatabaseBackend::Sqlite);
    let explain_sql = format!("EXPLAIN QUERY PLAN {}", built.sql);
    let rows = db
        .query_all_raw(Statement::from_sql_and_values(
            DatabaseBackend::Sqlite,
            explain_sql,
            built.values.map(|v| v.0).unwrap_or_default(),
        ))
        .await
        .expect("EXPLAIN QUERY PLAN 执行失败");
    rows.iter()
        .map(|r| r.try_get::<String>("", "detail").unwrap_or_default())
        .collect()
}

/// 对「与仓库租户过滤查询同构」的 SELECT 取 `EXPLAIN QUERY PLAN` 的 detail 行。
async fn explain_tenant_page(db: &DatabaseConnection, tid: i64) -> Vec<String> {
    // 与 SysLogininforRepository::find_page_filtered 的租户分支对齐：
    // find() + tenant_id 过滤 + order_by_desc(login_time) + offset/limit
    let q = SysLogininfor::find()
        .filter(Column::TenantId.eq(tid))
        .order_by_desc(Column::LoginTime)
        .offset(0)
        .limit(10);
    let built = q.build(DatabaseBackend::Sqlite);
    let explain_sql = format!("EXPLAIN QUERY PLAN {}", built.sql);
    let rows = db
        .query_all_raw(Statement::from_sql_and_values(
            DatabaseBackend::Sqlite,
            explain_sql,
            built.values.map(|v| v.0).unwrap_or_default(),
        ))
        .await
        .expect("EXPLAIN QUERY PLAN 执行失败");
    rows.iter()
        .map(|r| r.try_get::<String>("", "detail").unwrap_or_default())
        .collect()
}

fn logininfor_query() -> LogininforQueryDto {
    LogininforQueryDto {
        page_num: 1,
        page_size: 100,
        // 不参与动态排序（本测试只验证 tenant_scope 维度的索引选择）
        order_by_column: None,
        is_asc: None,
        ipaddr: None,
        user_name: None,
        status: None,
        begin_time: None,
        end_time: None,
        last_id: None,
        // 该集成测试只验证 tenant_scope 维度的索引选择，不叠加显式租户筛选
        tenant_id: None,
    }
}

/// 倾斜数据（1000 : 5）下，稀有租户的 `tenant_id = ?` 过滤查询应走租户索引而非全表扫描，
/// 且真实 Repository/Service 过滤结果与租户隔离一致。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn it_tenant_tid_index_used_under_skewed_data_sqlite() {
    let ctx = TestContext::new().await;
    let db = &ctx.state.db;

    // 倾斜：租户 1 重（1000 行），租户 2 稀（5 行）
    insert_bulk(db, 1, 1000, 1_000_000).await;
    insert_bulk(db, 2, 5, 2_000_000).await;
    // 刷新统计信息（无 ANALYZE 时计划器只有默认估算；显式 ANALYZE 后仍有选择空间）
    db.execute_unprepared("ANALYZE")
        .await
        .expect("ANALYZE 失败");

    // 稀有租户（高选择性）：期望命中租户索引
    let rare_plan = explain_tenant_page(db, 2).await;
    let rare_join = rare_plan.join(" | ");
    assert!(
        rare_plan
            .iter()
            .any(|d| d.contains("idx_sys_logininfor_tid")),
        "稀有租户( tid=2 )查询应走 idx_sys_logininfor_tid(_time)，实际计划: {rare_join}"
    );
    assert!(
        !rare_plan.iter().any(|d| d.contains("SCAN sys_logininfor")),
        "稀有租户( tid=2 )查询不应全表扫描，实际计划: {rare_join}"
    );

    // 真实过滤实现核对：service 分页仅返回承租户行（selector 走同一 Repository 路径）
    let (rows, total) = ctx
        .state
        .logininfor_service
        .get_logininfor_page(logininfor_query(), Some(2))
        .await
        .expect("登录日志分页查询失败");
    assert_eq!(total, 5, "承租户( tid=2 )应仅见 5 行");
    assert!(
        rows.iter().all(|r| r.tenant_id == 2),
        "承租户查询结果不得含它租户行"
    );

    // 重租户计划一并打印，供台账登记（人工审计倾斜侧行为）
    let heavy_plan = explain_tenant_page(db, 1).await;
    println!("[P2-6] sys_logininfor 倾斜 1000:5 稀有租户(tid=2) 计划: {rare_join}");
    println!(
        "[P2-6] sys_logininfor 倾斜 1000:5 重租户(tid=1) 计划: {}",
        heavy_plan.join(" | ")
    );

    // 单列 tid 索引表（sys_frontend_error 仅有 idx_sys_frontend_error_tid，无 _tid_time）：
    // 直接验证迁移所建单列 `idx_{table}_tid` 在倾斜下被选中而非全表扫描。
    insert_bulk_fe(db, 1, 1000, 1_000_000).await;
    insert_bulk_fe(db, 2, 5, 2_000_000).await;
    db.execute_unprepared("ANALYZE")
        .await
        .expect("ANALYZE 失败");

    let fe_plan = explain_fe_page(db, 2).await;
    let fe_join = fe_plan.join(" | ");
    assert!(
        fe_plan
            .iter()
            .any(|d| d.contains("idx_sys_frontend_error_tid")),
        "稀有租户( tid=2 )查询应走 idx_sys_frontend_error_tid，实际计划: {fe_join}"
    );
    assert!(
        !fe_plan
            .iter()
            .any(|d| d.contains("SCAN sys_frontend_error")),
        "稀有租户( tid=2 )查询不应全表扫描，实际计划: {fe_join}"
    );
    println!("[P2-6] sys_frontend_error 倾斜 1000:5 稀有租户(tid=2) 计划: {fe_join}");
}

/// 与 `repository::sys_notice::read_notice_id_subquery` 同构的已读半连接子查询。
///
/// 该子查询在每次公告列表 / `listTop` / 未读徽标查询里都会执行一次；索引前缀若不是
/// `user_id`，平台操作者（不参与 tenant 过滤）就会走 `idx_sys_notice_read_tid` 扫描
/// 整个平台的已读行。这里锁的是**计划形状**而不是耗时（避免把机器快慢带进门禁）。
fn build_read_notice_subquery(
    user_id: i64,
    tenant_scope: Option<i64>,
) -> sea_orm::Select<crate::entity::sys_notice_read::Entity> {
    let mut q = SysNoticeRead::find()
        .filter(ReadColumn::UserId.eq(user_id))
        .select_only()
        .column(ReadColumn::NoticeId);
    if let Some(tid) = tenant_scope {
        q = q.filter(ReadColumn::TenantId.eq(tid));
    }
    q
}

async fn explain_notice_read_subquery(
    db: &DatabaseConnection,
    user_id: i64,
    tenant_scope: Option<i64>,
) -> Vec<String> {
    let built = build_read_notice_subquery(user_id, tenant_scope).build(DatabaseBackend::Sqlite);
    let explain_sql = format!("EXPLAIN QUERY PLAN {}", built.sql);
    let rows = db
        .query_all_raw(Statement::from_sql_and_values(
            DatabaseBackend::Sqlite,
            explain_sql,
            built.values.map(|v| v.0).unwrap_or_default(),
        ))
        .await
        .expect("EXPLAIN QUERY PLAN 执行失败");
    rows.iter()
        .map(|r| r.try_get::<String>("", "detail").unwrap_or_default())
        .collect()
}

/// b81 / §10 N-9：`sys_notice_read (user_id, tenant_id, notice_id)` 必须被平台与租户
/// 两种谓词选中，且删掉索引后判据真的转红（变异控制组）——证明这不是"字符串恒成立"。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn it_notice_read_user_index_used_for_platform_and_tenant_sqlite() {
    let ctx = TestContext::new().await;
    let db = &ctx.state.db;

    // 造数：同一平台用户 500 行已读 + 另一租户 500 行，避免计划器因空表走常量路径
    db.execute_unprepared(
        "WITH RECURSIVE seq(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM seq WHERE x < 500) \
         INSERT INTO sys_notice_read (tenant_id, read_id, notice_id, user_id, read_time) \
         SELECT 0, x, x, 7, datetime('now') FROM seq",
    )
    .await
    .expect("插入 sys_notice_read 平台行失败");
    db.execute_unprepared(
        "WITH RECURSIVE seq(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM seq WHERE x < 500) \
         INSERT INTO sys_notice_read (tenant_id, read_id, notice_id, user_id, read_time) \
         SELECT 2, 1000 + x, 1000 + x, 8, datetime('now') FROM seq",
    )
    .await
    .expect("插入 sys_notice_read 租户行失败");
    db.execute_unprepared("ANALYZE")
        .await
        .expect("ANALYZE 失败");

    let platform_plan = explain_notice_read_subquery(db, 7, None).await;
    let platform = platform_plan.join(" | ");
    assert!(
        platform_plan
            .iter()
            .any(|d| d.contains("idx_sys_notice_read_user_tenant_notice")),
        "平台谓词（仅 user_id）应走 idx_sys_notice_read_user_tenant_notice，实际计划: {platform}"
    );
    assert!(
        platform_plan.iter().any(|d| d.contains("COVERING INDEX")),
        "已读半连接只取 notice_id，应命中覆盖索引而非回表，实际计划: {platform}"
    );

    let tenant_plan = explain_notice_read_subquery(db, 7, Some(0)).await;
    let tenant = tenant_plan.join(" | ");
    assert!(
        tenant_plan
            .iter()
            .any(|d| d.contains("idx_sys_notice_read_user_tenant_notice")),
        "租户谓词（user_id + tenant_id）应走同一索引，实际计划: {tenant}"
    );
    assert!(
        !tenant_plan
            .iter()
            .any(|d| d.contains("SCAN sys_notice_read")),
        "租户谓词不应全表扫描，实际计划: {tenant}"
    );

    // 变异控制组：删掉索引后同一判据必须不再命中 ⇒ 上面的断言受真实 schema 约束
    db.execute_unprepared("DROP INDEX idx_sys_notice_read_user_tenant_notice")
        .await
        .expect("DROP INDEX 失败");
    let without = explain_notice_read_subquery(db, 7, None).await.join(" | ");
    assert!(
        !without.contains("idx_sys_notice_read_user_tenant_notice"),
        "删索引后计划不应再引用它（判据可能是恒真的字符串匹配）：{without}"
    );
    // 还原索引，供同库后续用例保持与迁移后 schema 一致。
    // 索引 DDL 必须走 `migration::ensure_index_ddl`（R-11/R-12 形状锁：方言探测 + SAVEPOINT 隔离），
    // 测试代码也不豁免——否则锁会按"测试可以裸执行"的借口整片失效。
    migration::ensure_index_ddl(
        db,
        "CREATE INDEX idx_sys_notice_read_user_tenant_notice \
         ON sys_notice_read (user_id, tenant_id, notice_id)",
    )
    .await
    .expect("还原索引失败");

    println!("[N-9] 平台谓词计划: {platform}");
    println!("[N-9] 租户谓词计划: {tenant}");
}
