// stepby-axum/src/common/write_guard.rs
//! 「读 → 判断 → 写」的跨方言互斥闸（唯一实现）。
//!
//! 立案（b129）：管理类写路径里有多处「先查计数/查父节点，再插入/更新」的形态，中间没有
//! 事务、没有锁、也没有数据库约束兜底 ⇒ 并发两次调用都基于同一份旧快照做判断。四条实测
//! 路径（PAT 每用户配额、部门移动防环、消息重试、租户导航序号）各自的最坏结局见台账 b129 §1。
//!
//! ## 为什么不用 `SELECT … FOR UPDATE`
//!
//! `lock_exclusive()` 只在 MySQL/PG 生效，SQLite 方言不生成 `FOR UPDATE`；而本仓默认部署档
//! 是 SQLite（单文件零依赖），集成测试也跑在 SQLite 上。只靠行锁的修复在测试环境里
//! **无法证伪**——判据会绿着放过同一个缺陷（AGENTS 前言 ⑬「锁的输入必须实测」同族）。
//! `SharedStore::set_nx_ex` 在 local 档是同库表 + 唯一键、redis 档是 SETNX，两档都提供原子
//! 抢占语义，且可以用「预先占键」在串行测试里构造出「另一个请求正在进行」的断面。
//!
//! ## 三条使用约束（缺一即失去意义）
//!
//! 1. **锁必须覆盖整个「读 → 判断 → 写 → 提交」窗口**：抢锁之后才允许读校验用的那一份数据；
//! 2. **释放必须在事务提交之后**：提交前释放 = 另一个请求读不到未提交数据，照旧竞态；
//! 3. **后端不可用一律 fail-closed**：`set_nx_ex` 出错时拒绝本次操作，不得把「抢不到」与
//!    「后端坏了」都当成「可以继续」——后者等于在存储故障时静默关掉保护。
//!
//! TTL 是租约：持锁进程崩溃时锁会自然过期，不会永久锁死该用户/租户的该操作。TTL 只是
//! **止损**，不是互斥窗口的长度依据——正常路径靠显式释放。

use std::future::Future;

use crate::common::error::ServiceError;
use crate::shared_store::SharedStore;

/// 锁键的统一前缀。与 Redis 其他键族（`pat:` / `tenant:` / `session:` 等）分开命名，
/// 避免与业务键撞名——`set_nx_ex` 是同一个键空间，撞名会让业务读到一个 `"1"`。
const LOCK_PREFIX: &str = "lock:";

/// PAT 创建闸：同一用户同时只允许一个「查配额 + 插入」。
pub fn pat_create_key(user_id: i64) -> String {
    format!("{LOCK_PREFIX}pat:create:{user_id}")
}

/// 部门树写闸：按**目标租户**分片（平台代管与租户自管必须落同一条锁，否则两条路径互不互斥）。
pub fn dept_tree_key(tenant_id: i64) -> String {
    format!("{LOCK_PREFIX}dept:tree:{tenant_id}")
}

/// 抢闸 → 执行 → 释放。`on_busy` 在闸已被占用时构造错误（调用方决定 409/429 与文案）。
///
/// `fut` 是惰性的：抢闸失败时它**不会**被执行，所以不要在外面先做有副作用的准备动作。
pub async fn with_write_guard<T, Fut, B>(
    store: &dyn SharedStore,
    key: &str,
    ttl_secs: u64,
    on_busy: B,
    fut: Fut,
) -> Result<T, ServiceError>
where
    B: FnOnce() -> ServiceError,
    Fut: Future<Output = Result<T, ServiceError>>,
{
    let acquired = store.set_nx_ex(key, "1", ttl_secs).await.map_err(|e| {
        // fail-closed：存储不可用时拒绝，而不是放行。放行等于在故障期静默关闭保护，
        // 与 AGENTS A.2「限流/信号量不可用时拒绝而非放行」同口径。
        tracing::error!(lock = key, error = %e, "写路径互斥闸不可用（fail-closed 拒绝本次操作）");
        ServiceError::new(503, crate::tr!("error.common.concurrent_guard_unavailable"))
    })?;
    if !acquired {
        tracing::info!(lock = key, "写路径互斥闸已被占用，拒绝并发请求");
        return Err(on_busy());
    }

    let result = fut.await;

    // 释放失败不是业务失败：TTL 会兜底，但必须留痕（否则「锁泄漏」只能靠下次操作失败才发现）。
    if let Err(e) = store.del(&[key.to_string()]).await {
        tracing::warn!(lock = key, error = %e, "写路径互斥闸释放失败（将随 TTL 过期）");
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shared_store::local_store::LocalStore;

    async fn test_store() -> std::sync::Arc<dyn SharedStore> {
        let db = crate::repository::test_support::migrated_db()
            .await
            .expect("测试库必须迁移成功");
        std::sync::Arc::new(LocalStore::new(db))
    }

    /// 抢到闸时闭包被执行，且执行后闸被释放（同一键可以再次抢到）。
    #[tokio::test]
    async fn guard_runs_body_and_releases_afterwards() {
        let store = test_store().await;
        let key = pat_create_key(7);
        let value = with_write_guard(
            store.as_ref(),
            &key,
            30,
            || ServiceError::bad_request("busy"),
            async { Ok::<_, ServiceError>(41) },
        )
        .await
        .expect("首次应抢到闸");
        assert_eq!(value, 41);
        assert!(
            store.set_nx_ex(&key, "1", 30).await.unwrap(),
            "执行结束后闸必须已释放（否则下一次操作会被永久拒绝）"
        );
    }

    /// 闸已被占用时：闭包**一次都不执行**，返回 on_busy 的错误。
    #[tokio::test]
    async fn busy_guard_never_runs_the_body() {
        let store = test_store().await;
        let key = dept_tree_key(3);
        assert!(
            store.set_nx_ex(&key, "1", 30).await.unwrap(),
            "预占必须成功"
        );

        let ran = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let ran_in_body = ran.clone();
        let err = with_write_guard(
            store.as_ref(),
            &key,
            30,
            || ServiceError::new(429, "busy"),
            async move {
                ran_in_body.store(true, std::sync::atomic::Ordering::SeqCst);
                Ok::<_, ServiceError>(())
            },
        )
        .await
        .expect_err("闸已占用时必须拒绝");
        assert_eq!(err.code, 429);
        assert!(
            !ran.load(std::sync::atomic::Ordering::SeqCst),
            "闸已占用时业务闭包不得执行——否则保护等于不存在"
        );
    }

    /// 闸键必须按用户/租户分片：不同用户、不同租户之间不得互相阻塞。
    #[tokio::test]
    async fn keys_are_scoped_by_user_and_tenant() {
        assert_ne!(pat_create_key(1), pat_create_key(2));
        assert_ne!(dept_tree_key(1), dept_tree_key(2));
        assert!(pat_create_key(9).starts_with(LOCK_PREFIX));
        assert!(dept_tree_key(9).starts_with(LOCK_PREFIX));
    }
    /// 业务闭包返回错误时闸也必须释放：否则一次普通校验失败会把该用户锁到 TTL 到期。
    #[tokio::test]
    async fn guard_releases_after_body_error() {
        let store = test_store().await;
        let key = pat_create_key(11);
        let err = with_write_guard(
            store.as_ref(),
            &key,
            30,
            || ServiceError::new(429, "busy"),
            async { Err::<i32, _>(ServiceError::bad_request("body failed")) },
        )
        .await
        .expect_err("闭包错误必须原样上抛");
        assert_eq!(err.code, 400, "上抛的必须是业务闭包自己的错误");
        assert!(
            store.set_nx_ex(&key, "1", 30).await.unwrap(),
            "业务失败后闸必须已释放（否则失败一次要等 TTL 才能重试）"
        );
    }

    /// 后端不可用必须 fail-closed（503）且闭包不执行；不得把「存储坏了」当成「可以继续」。
    ///
    /// 用**已关闭的连接池**注入故障：这是真实的 store 失败路径，不是桩。
    #[tokio::test]
    async fn guard_is_fail_closed_when_the_store_is_unavailable() {
        let db = crate::repository::test_support::migrated_db()
            .await
            .expect("测试库必须迁移成功");
        // `DatabaseConnection` 是克隆共享同一连接池：关掉克隆即关掉整池，
        // 后续任何查询都会失败 —— 这就是真实的「存储不可用」断面。
        db.clone().close().await.expect("关闭连接池失败");
        let store = LocalStore::new(db);

        let ran = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let ran_in_body = ran.clone();
        let err = with_write_guard(
            &store,
            "lock:test:store_down",
            30,
            || ServiceError::new(429, "busy"),
            async move {
                ran_in_body.store(true, std::sync::atomic::Ordering::SeqCst);
                Ok::<_, ServiceError>(())
            },
        )
        .await
        .expect_err("存储不可用时必须拒绝本次操作");
        assert_eq!(err.code, 503, "存储故障必须映射成 503，而不是放行或 500");
        assert!(
            !ran.load(std::sync::atomic::Ordering::SeqCst),
            "闸不可用时业务闭包不得执行"
        );
        assert!(
            !err.message.is_empty(),
            "必须带可读文案（error.common.concurrent_guard_unavailable）"
        );
    }
}
