// stepby-axum/src/integration_tests/cluster_lock.rs
//! 集群整轮互斥锁（`ClusterLock`）在 **redis 档 SharedStore** 上的多实例端到端回归。
//!
//! 背景（§5.30）：`cluster_mode` 的**档位判定**已有纯函数单测（cluster.rs 的
//! parse/auto 现状/显式覆盖三组），但 **acquire/release/CAS/TTL 的互斥语义此前
//! 仅在 LocalStore 档单测覆盖**——生产部署形态（redis 档、多实例共享同一
//! SharedStore）未被任何测试锁定。本模块在集成测试的隔离 redis 实例上补齐：
//!
//! - **两实例互斥**（`leader` 档语义核心）：A 持锁期间 B 必须被拒；
//! - **锁传递**：A 释放后 B 可获取（CAS 删除真实生效）；
//! - **TTL 过期释放**（防死锁）：短 TTL 过期后 B 可直接获取；
//! - **`needed=false` 短路**（`single`/`all` 档语义）：不占锁、release 空操作无害。

use super::TestContext;
use std::sync::Arc;
use std::time::Duration;

use crate::scheduler::cluster::ClusterLock;
use crate::shared_store::SharedStore;

/// 两实例互斥 + 锁传递（`leader` 档核心语义）。
///
/// 可证伪性：若 `lock_acquire` 退化为无条件成功（丢 NX）或 `lock_release` 丢 CAS，
/// 第①段 B 抢锁将意外成功 / 第②段释放后 B 将继续被拒。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_round_lock_mutual_exclusion_and_handover() {
    let ctx = TestContext::new().await;
    let store: Arc<dyn SharedStore> = ctx.state.store.clone();
    let key = "lock:it:round:mutual";

    // ① 实例 A 抢锁成功；实例 B 同 key 抢锁被拒（多实例互斥核心）
    let a = ClusterLock::acquire(store.clone(), key, true, 30, "inst-a")
        .await
        .expect("实例 A 首次抢锁应成功");
    let b = ClusterLock::acquire(store.clone(), key, true, 30, "inst-b").await;
    assert!(b.is_none(), "实例 B 在 A 持锁期间必须被拒（互斥语义）");

    // ② A 释放（CAS 删 token）⇒ B 可获取（锁传递）
    a.release().await;
    let b = ClusterLock::acquire(store.clone(), key, true, 30, "inst-b")
        .await
        .expect("A 释放后实例 B 应能获取锁");
    b.release().await;
}

/// TTL 过期释放（防死锁语义）：持锁实例崩溃未释放 ⇒ TTL 到期后他人可获取。
///
/// 可证伪性：若 TTL 未设置（持久锁），第二段将因锁未过期而 None ⇒ 变红。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_round_lock_ttl_expiry_prevents_deadlock() {
    let ctx = TestContext::new().await;
    let store: Arc<dyn SharedStore> = ctx.state.store.clone();
    let key = "lock:it:round:ttl";

    let a = ClusterLock::acquire(store.clone(), key, true, 1, "inst-a")
        .await
        .expect("A 短 TTL 抢锁应成功");

    // TTL=1s，等 1.4s 让锁自然过期（模拟持锁实例崩溃）
    tokio::time::sleep(Duration::from_millis(1400)).await;
    let _ = a.release().await; // 迟到的释放（token 已随 TTL 消失）应无副作用

    let b = ClusterLock::acquire(store.clone(), key, true, 30, "inst-b")
        .await
        .expect("TTL 过期后实例 B 应可直接获取（防死锁语义）");
    b.release().await;
}

/// `needed = false`（`single`/`all` 档）短路语义：不占锁、release 空操作无害。
///
/// 可证伪性：若短路路径误写真实锁，第二段 B 抢锁将 None ⇒ 变红。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_round_lock_not_needed_short_circuits() {
    let ctx = TestContext::new().await;
    let store: Arc<dyn SharedStore> = ctx.state.store.clone();
    let key = "lock:it:round:not-needed";

    // single/all 档：acquire 恒成功且不占锁
    let a = ClusterLock::acquire(store.clone(), key, false, 30, "inst-a")
        .await
        .expect("needed=false 恒成功");
    assert!(!a.is_held(), "needed=false 的占位者 is_held 必须为 false");
    a.release().await; // 空操作，不应报错也不应影响真实锁

    // 短路未占锁 ⇒ 同 key 的真实抢锁（needed=true）应成功
    let b = ClusterLock::acquire(store.clone(), key, true, 30, "inst-b")
        .await
        .expect("短路档不得占用真实锁");
    b.release().await;
}
