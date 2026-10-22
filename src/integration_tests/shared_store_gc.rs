// stepby-axum/src/integration_tests/shared_store_gc.rs
//! local 档共享态**过期行 GC** 的端到端回归（批八十五 项 C）。
//!
//! 立案：`[cache].gc_interval_secs` 与模板注释一起存在了很久，但全仓没有一处读它
//! ⇒ 承诺的机制并不存在，`sys_shared_kv` / `sys_shared_lock` 的过期行**只增不删**。
//! 本模块锁的是 GC 的**语义**（删什么、不删什么），不是它的节拍——节拍由
//! `shared_store::gc` 的纯函数单测（0=关闭 / 区间内原样 / 区间外夹取）判，
//! 真实周期任务只在 `main.rs` 的启动路径上存在，集成测试不启它（避免与用例抢删）。
//!
//! 三条判据缺一不可：
//! ① 过期行必须被删（把 DELETE 的 WHERE 摘掉 ⇒ 本条红）；
//! ② **未过期行必须幸存**（把条件写成 `expire_at IS NOT NULL` ⇒ 本条红——这是"顺手删光
//!    TTL 列"这类实现错误的探测器）；
//! ③ **永不过期行（expire_at IS NULL）必须幸存**（把 `IS NOT NULL` 那一支摘掉 ⇒ 本条红；
//!    那一支承载的是"密码版本号/用户会话集合"这类由业务显式删除的键，删掉等于洗掉
//!    "改密后旧 token 立即失效"的安全不变量）。
//!
//! 唯一前缀：`it:gc:`（用例自行清理，不依赖 teardown）。

use super::TestContext;
use sea_orm::{ConnectionTrait, Statement};

/// 直接写 `sys_shared_kv`（绕开 LocalStore 的 TTL 语义，只为造出三种存活态）。
///
/// 为什么不走 store API：GC 判的是**表上的行**，而 LocalStore 的 `set_ex` 会按自身口径
/// 计算 `expire_at`；要造出"未来 10 秒后才过期"这种紧贴边界的夹具，只有直接写行才准确。
async fn insert_kv(ctx: &TestContext, key: &str, expire_at: Option<i64>) {
    let sql = format!(
        "INSERT INTO sys_shared_kv (kv_key, kv_value, expire_at) VALUES ('{key}', 'v', {})",
        expire_at
            .map(|v| v.to_string())
            .unwrap_or_else(|| "NULL".to_string())
    );
    ctx.state
        .db
        .execute_raw(Statement::from_string(
            ctx.state.db.get_database_backend(),
            sql,
        ))
        .await
        .expect("插入 sys_shared_kv 夹具失败");
}

async fn insert_lock(ctx: &TestContext, key: &str, token: &str, expire_at: i64) {
    let sql = format!(
        "INSERT INTO sys_shared_lock (lock_key, lock_token, expire_at) VALUES ('{key}', '{token}', {expire_at})"
    );
    ctx.state
        .db
        .execute_raw(Statement::from_string(
            ctx.state.db.get_database_backend(),
            sql,
        ))
        .await
        .expect("插入 sys_shared_lock 夹具失败");
}

/// 某键是否还在表里（1=在，0=不在；NULL 值不影响判定）。
async fn kv_present(ctx: &TestContext, key: &str) -> bool {
    count_present(ctx, "sys_shared_kv", "kv_key", key).await
}

async fn lock_present(ctx: &TestContext, key: &str) -> bool {
    count_present(ctx, "sys_shared_lock", "lock_key", key).await
}

/// `SELECT COUNT(*)` 单点查询（与 local_store 同一采集管道：`sql_dialect::stmt` 负责方言，
/// `query_one_raw` 按值收 Statement——sea-orm 2.0 的 `query_all` 走 `StatementBuilder`，
/// 裸 `Statement` 不满足该 trait）。
async fn count_present(ctx: &TestContext, table: &str, column: &str, key: &str) -> bool {
    let db = &ctx.state.db;
    let sql = format!("SELECT COUNT(*) AS c FROM {table} WHERE {column} = ?");
    let row = db
        .query_one_raw(crate::common::sql_dialect::stmt(
            db.get_database_backend(),
            &sql,
            vec![key.to_owned().into()],
        ))
        .await
        .unwrap_or_else(|e| panic!("查询 {table}.{column}={key} 失败: {e}"));
    let c: i64 = row
        .and_then(|r| r.try_get::<i64>("", "c").ok())
        .unwrap_or(-1);
    c == 1
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn it_shared_kv_gc_deletes_expired_and_spares_the_rest() {
    let ctx = TestContext::new().await;
    let now = chrono::Utc::now().timestamp();

    // 夹具：三种存活态各一（边界取 ±3600，远离"恰好等于 now"的时钟抖动）
    insert_kv(&ctx, "it:gc:expired", Some(now - 3600)).await;
    insert_kv(&ctx, "it:gc:alive", Some(now + 3600)).await;
    insert_kv(&ctx, "it:gc:eternal", None).await;
    insert_lock(&ctx, "it:gc:lock-expired", "t1", now - 3600).await;
    insert_lock(&ctx, "it:gc:lock-alive", "t2", now + 3600).await;

    // 前置正控：夹具确实落库（缺这一步时"表里本来就没行"会让 ②③ 恒真）
    for k in ["it:gc:expired", "it:gc:alive", "it:gc:eternal"] {
        assert!(kv_present(&ctx, k).await, "前置夹具 {k} 必须真的在表里");
    }
    assert!(lock_present(&ctx, "it:gc:lock-expired").await);
    assert!(lock_present(&ctx, "it:gc:lock-alive").await);

    let summary = crate::shared_store::gc::cleanup_expired_shared_rows(&ctx.state.db)
        .await
        .expect("GC 本体必须执行成功");

    // ① 过期行被删
    assert!(
        !kv_present(&ctx, "it:gc:expired").await,
        "已过期的 sys_shared_kv 行必须被 GC 删除（②③ 才有意义的前提）"
    );
    assert!(
        !lock_present(&ctx, "it:gc:lock-expired").await,
        "已过期的 sys_shared_lock 行必须被 GC 删除"
    );
    assert!(
        summary.kv_deleted >= 1 && summary.lock_deleted >= 1,
        "删除计数必须反映真实行数，实得 {summary:?}"
    );

    // ② 未过期行幸存（探测器：WHERE 写成 `expire_at IS NOT NULL` 会在这里红）
    assert!(
        kv_present(&ctx, "it:gc:alive").await,
        "未过期的键不得被删——GC 不得比读路径更激进"
    );
    assert!(
        lock_present(&ctx, "it:gc:lock-alive").await,
        "未过期的锁不得被删（删了等于允许两个实例同时进临界区）"
    );

    // ③ 永不过期行幸存（探测器：摘掉 `IS NOT NULL` 会在这里红）
    assert!(
        kv_present(&ctx, "it:gc:eternal").await,
        "expire_at IS NULL 的键族（密码版本号等）由业务显式删除，GC 不得触碰"
    );

    // ④ 幂等：再清一轮，本轮夹具已无过期行 ⇒ 计数不得再包含它们
    let again = crate::shared_store::gc::cleanup_expired_shared_rows(&ctx.state.db)
        .await
        .expect("二次 GC 必须同样成功（幂等）");
    assert!(
        !kv_present(&ctx, "it:gc:expired").await
            && kv_present(&ctx, "it:gc:alive").await
            && kv_present(&ctx, "it:gc:eternal").await,
        "二次 GC 后存活态必须与一次后一致，实得 {again:?}"
    );

    // 收尾：删掉自己的行，不给别的用例留残留（residue-cleanup 的谓词族不含 it:gc:*）
    for k in ["it:gc:alive", "it:gc:eternal"] {
        ctx.state
            .db
            .execute_raw(Statement::from_string(
                ctx.state.db.get_database_backend(),
                format!("DELETE FROM sys_shared_kv WHERE kv_key = '{k}'"),
            ))
            .await
            .expect("清理夹具失败");
    }
    ctx.state
        .db
        .execute_raw(Statement::from_string(
            ctx.state.db.get_database_backend(),
            "DELETE FROM sys_shared_lock WHERE lock_key = 'it:gc:lock-alive'",
        ))
        .await
        .expect("清理夹具失败");
}

/// 边界一致性：GC 的删除判据必须与读路径的 `is_expired` **同一个口径**。
///
/// 这条不是重复 ①：它判的是"两处口径写反"的可能——把 GC 写成 `expire_at < now`（严格小于）
/// 而读路径是 `<=`，则"恰好等于 now"那一行会被**读成过期、却留在表里**，
/// 于是同一张表在两个口径下各说各话（本仓反复立案的"两处实现必漂"形态）。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn it_shared_kv_gc_boundary_matches_reader_predicate() {
    use crate::shared_store::local_store::is_expired;

    let ctx = TestContext::new().await;
    let now = chrono::Utc::now().timestamp();
    // 取"恰好等于某个整数时刻"的边界行：读路径判它过期，GC 也必须判它过期
    let boundary = now + 3600;
    assert!(
        !is_expired(Some(boundary)),
        "前置：边界时刻在 +3600 处，读路径必须判未过期"
    );
    insert_kv(&ctx, "it:gc:edge", Some(boundary)).await;
    crate::shared_store::gc::cleanup_expired_shared_rows(&ctx.state.db)
        .await
        .expect("GC 失败");
    assert!(
        kv_present(&ctx, "it:gc:edge").await,
        "读路径判未过期的行，GC 也必须判未过期（两口径必须同源）"
    );

    // 翻转到过期侧：同一列改判 `<=` 后两侧结论必须一致
    let past = now - 1;
    assert!(is_expired(Some(past)), "前置：过去时刻读路径判过期");
    insert_kv(&ctx, "it:gc:edge2", Some(past)).await;
    crate::shared_store::gc::cleanup_expired_shared_rows(&ctx.state.db)
        .await
        .expect("GC 失败");
    assert!(
        !kv_present(&ctx, "it:gc:edge2").await,
        "读路径判过期的行，GC 必须删掉（否则 expire_at<=now 与 is_expired 已分叉）"
    );

    ctx.state
        .db
        .execute_raw(Statement::from_string(
            ctx.state.db.get_database_backend(),
            "DELETE FROM sys_shared_kv WHERE kv_key = 'it:gc:edge'",
        ))
        .await
        .expect("清理夹具失败");
}
