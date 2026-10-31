// stepby-axum/src/integration_tests/shared_store_bootstrap.rs
//! Redis 启动回填的端到端回归（b142 项 1）。
//!
//! 立案：`RedisStore::bootstrap_from_db` 是"档位切换无缝"的唯一通道——DB 权威层
//! （`sys_token_revocation` 吊销行 / `sys_user.password_version`）在 Redis 重启、
//! 切库或被清空后必须补回共享态。原实现有三处把失败折成默认值：
//! ① `EXISTS` 失败 ⇒ `unwrap_or(1)` 读成"键已存在"⇒ 吊销键永不补回（已吊销令牌复活）；
//! ② / ③ `SET` 结果与 `pwd_ver` 的 `GET`/`SET` 失败只 `let _ =` 丢弃 ⇒ 日志照打"回填完成"，
//! 运维据此认为安全态已恢复。
//!
//! 本用例锁的是**最终事实**：清空 Redis 后回填必须把两类键都恢复，且 TTL 仍覆盖
//! 剩余吊销期；再调一次必须幂等（不缩短 TTL、不改变值）。
//!
//! 不构造"Redis 写失败"的断面：那需要注入一个会拒绝写入的 Redis 连接，属另一类
//! 依赖注入改造（`RedisStore` 持有 `ConnectionManager`，没有注入点）。失败分支由
//! `redis_store.rs` 内的形状锁覆盖（失败必须计数 + 分档 WARN），两者互补：
//! 本用例证明"成功路径真的回填"，形状锁证明"失败路径不再静默"。

use super::TestContext;
use crate::shared_store::RedisStore;
use sea_orm::{ConnectionTrait, Statement};

/// 读一个字符串键（不存在返回 None）。
async fn redis_get(ctx: &TestContext, key: &str) -> Option<String> {
    let mut conn = ctx.redis();
    redis::cmd("GET")
        .arg(key)
        .query_async(&mut conn)
        .await
        .expect("读取 Redis 键失败")
}

async fn redis_ttl(ctx: &TestContext, key: &str) -> i64 {
    let mut conn = ctx.redis();
    redis::cmd("TTL")
        .arg(key)
        .query_async(&mut conn)
        .await
        .expect("读取 Redis TTL 失败")
}

async fn redis_del(ctx: &TestContext, keys: &[&str]) {
    let mut conn = ctx.redis();
    let mut cmd = redis::cmd("DEL");
    for k in keys {
        cmd.arg(*k);
    }
    let _: i64 = cmd.query_async(&mut conn).await.expect("删除 Redis 键失败");
}

/// 往吊销权威层写一行（expire_at = 现在 + 600 秒）。
async fn insert_revocation(ctx: &TestContext, token_hash: &str) {
    let expire_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("系统时钟早于 UNIX 纪元")
        .as_secs() as i64
        + 600;
    let sql = format!(
        "INSERT INTO sys_token_revocation (token_hash, expire_at, source) \
         VALUES ('{token_hash}', {expire_at}, 'logout')"
    );
    ctx.state
        .db
        .execute_raw(Statement::from_string(
            ctx.state.db.get_database_backend(),
            sql,
        ))
        .await
        .expect("插入 sys_token_revocation 夹具失败");
}

/// 把 admin 的密码版本推到指定值（模拟"改过一次密码"）。
async fn set_password_version(ctx: &TestContext, uid: i64, version: i64) {
    let sql = format!("UPDATE sys_user SET password_version = {version} WHERE user_id = {uid}");
    ctx.state
        .db
        .execute_raw(Statement::from_string(
            ctx.state.db.get_database_backend(),
            sql,
        ))
        .await
        .expect("写 sys_user.password_version 失败");
}

/// 归档回填：清空两类键后调用 `bootstrap_from_db`，必须全部恢复。
///
/// 判据三件事同判：
/// ① `blacklist:{hash}` 存在且值 "1"、TTL 仍覆盖剩余吊销期（>0 且 ≤600）；
/// ② `pwd_ver:{uid}` 等于 DB 列值（回填的是**权威值**，不是默认 0）；
/// ③ **幂等**：再调一次，值不变且 TTL 不被重置/缩短（EXISTS 分支不重写）。
///
/// 反向证伪（盘上变异）：把 EXISTS 失败改回 `unwrap_or(1)`、把 SET 结果改回
/// `let _ =`，本条都不会红——它测的是成功路径的**事实**；失败路径由同文件
/// 的形状锁 `bootstrap_failures_are_counted_and_reported` 判。
#[tokio::test]
async fn bootstrap_restores_revoked_tokens_and_password_versions() {
    let ctx = TestContext::new().await;
    let hash = "it_b142_bootstrap_hash";
    let uid = 1i64;
    let ver = 42i64;

    insert_revocation(&ctx, hash).await;
    set_password_version(&ctx, uid, ver).await;
    // 模拟"Redis 被清空 / 换了新实例"：两类键都不存在
    let blacklist_key = format!("blacklist:{hash}");
    let pwd_ver_key = format!("pwd_ver:{uid}");
    redis_del(&ctx, &[blacklist_key.as_str(), pwd_ver_key.as_str()]).await;
    assert!(redis_get(&ctx, &blacklist_key).await.is_none());
    assert!(redis_get(&ctx, &pwd_ver_key).await.is_none());

    let redis_conn = ctx
        .state
        .redis_conn
        .clone()
        .expect("集成测试固定走 redis 档，redis_conn 必为 Some");
    let store = RedisStore::new(redis_conn, ctx.state.db.clone());
    store.bootstrap_from_db(&ctx.state.db).await;

    // ① 吊销键必须补回（键缺失 = 已吊销令牌重新可用，属"复活"档）
    let value = redis_get(&ctx, &blacklist_key)
        .await
        .expect("吊销键未被回填：已吊销令牌会重新可用");
    assert_eq!(value, "1");
    let ttl = redis_ttl(&ctx, &blacklist_key).await;
    assert!(
        (1..=600).contains(&ttl),
        "吊销键 TTL 必须覆盖剩余吊销期（实测 {ttl}）"
    );

    // ② 密码版本必须等于 DB 权威值
    let pwd_ver = redis_get(&ctx, &pwd_ver_key)
        .await
        .expect("pwd_ver 键未被回填：旧口令版本会继续放行");
    assert_eq!(pwd_ver, ver.to_string(), "回填的必须是 DB 权威值");

    // ③ 幂等：再跑一次不改变值、不重置 TTL
    let ttl_before = redis_ttl(&ctx, &blacklist_key).await;
    store.bootstrap_from_db(&ctx.state.db).await;
    assert_eq!(
        redis_get(&ctx, &blacklist_key).await.as_deref(),
        Some("1"),
        "重复回填不得改变吊销键值"
    );
    let ttl_after = redis_ttl(&ctx, &blacklist_key).await;
    assert!(
        ttl_after <= ttl_before,
        "重复回填不得重置/延长 TTL（{ttl_before} → {ttl_after}）"
    );
    assert_eq!(
        redis_get(&ctx, &pwd_ver_key).await.as_deref(),
        Some(ver.to_string().as_str()),
        "重复回填不得改变 pwd_ver"
    );

    // 用例自清理（Redis 槽位随 context 释放，但 DB 行与键值不应留给同槽位的下一个用例）
    redis_del(&ctx, &[blacklist_key.as_str(), pwd_ver_key.as_str()]).await;
    ctx.state
        .db
        .execute_raw(Statement::from_string(
            ctx.state.db.get_database_backend(),
            format!("DELETE FROM sys_token_revocation WHERE token_hash = '{hash}'"),
        ))
        .await
        .expect("清理 sys_token_revocation 夹具失败");
}

/// 回填只写"DB 权威层领先"的键：Redis 上已有更新的 pwd_ver 时不得写回旧值。
///
/// 这是"回填方向"的判据——如果把 `cur < db_ver` 的比较写反或删掉比较，
/// 每次启动都会把 Redis 上更晚的密码版本**降级**到 DB 列（一列写失败/滞后时
/// 旧口令重新可用）。本用例用"Redis=99 / DB=42"的断面锁住这个方向。
#[tokio::test]
async fn bootstrap_never_downgrades_a_newer_redis_password_version() {
    let ctx = TestContext::new().await;
    let uid = 1i64;
    let pwd_ver_key = format!("pwd_ver:{uid}");
    set_password_version(&ctx, uid, 42).await;

    {
        let mut conn = ctx.redis();
        let _: () = redis::cmd("SET")
            .arg(&pwd_ver_key)
            .arg(99)
            .query_async(&mut conn)
            .await
            .expect("写 pwd_ver 夹具失败");
    }

    let redis_conn = ctx
        .state
        .redis_conn
        .clone()
        .expect("集成测试固定走 redis 档，redis_conn 必为 Some");
    let store = RedisStore::new(redis_conn, ctx.state.db.clone());
    store.bootstrap_from_db(&ctx.state.db).await;

    assert_eq!(
        redis_get(&ctx, &pwd_ver_key).await.as_deref(),
        Some("99"),
        "回填不得把 Redis 上更新的密码版本降级为 DB 旧值"
    );

    redis_del(&ctx, &[pwd_ver_key.as_str()]).await;
}
