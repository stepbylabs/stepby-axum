//! 「已持有分布式锁」的 RAII 守卫（b141）：请求路径与后台链写入共用。
//!
//! 立案：`sys_backup_handler::restore` / `ip_location_handler::update` / 操作日志防篡改链
//! （`sys_oper_log_service::attach_chain_hash`）都在业务 `await`
//! **之后**才 `lock_release`。而 handler 的 future 可以被丢弃——客户端断开、外层超时
//! （b140 在 `router/mod.rs` 给全部路由挂了 120s 止损层）、进程收尾都会让它停在 await
//! 点上，此后那行 release **一次都不会执行** ⇒ 锁一直挂到 TTL（本仓两处都是 600s），
//! 期间所有恢复 / IP 库更新请求收到 400「正在进行」，而并没有任何任务在进行。
//!
//! 与 `scheduler/mod.rs` 的 `JobLockGuard` / `scheduler/cluster.rs` 的 `ClusterLock`
//! 同款范式（`SharedStore` 模块文档也写明"供 RAII 守卫在 Drop 中 spawn 异步执行"）：
//! Drop 里 `Handle::try_current()` 取到运行时后派生一个受守卫的任务
//! （`background::run_tracked`：超时 + panic 隔离 + `bg:heldLockRelease` 指标）。
//! 显式 `release()` 与 Drop 兜底**幂等共存**：显式路径先 disarm，CAS 释放本身也幂等。
//!
//! 边界：Drop 时若运行时已关闭（进程收尾、runtime 正在 drop），不 spawn —— 锁由 TTL
//! 自然失效；在那种时刻硬 spawn 会触发"Drop 中 panic 导致双重 panic abort"。

use std::sync::Arc;

use async_trait::async_trait;

use crate::shared_store::{LockHandle, SharedStore, StoreError};

/// 释放能力的最小契约。
///
/// 只抽"释放"一个动作，而不是给 `SharedStore` 造一个假实现（它有一条很宽的方法面）：
/// 单元测试用记录器即可构造"释放成功 / 释放失败 / 只走 Drop"三种断面（与 b126
/// `TokenRevokeOps` 同一取舍）。
#[async_trait]
pub trait LockReleaseOps: Send + Sync {
    async fn release(&self, handle: &LockHandle) -> Result<(), StoreError>;
}

#[async_trait]
impl LockReleaseOps for dyn SharedStore {
    async fn release(&self, handle: &LockHandle) -> Result<(), StoreError> {
        SharedStore::lock_release(self, handle).await
    }
}

/// 已持有的锁：离开作用域自动释放（显式 `release().await` 优先，Drop 兜底）。
pub struct HeldLock<S: LockReleaseOps + ?Sized + 'static> {
    ops: Arc<S>,
    handle: LockHandle,
    armed: bool,
}

impl<S: LockReleaseOps + ?Sized + 'static> HeldLock<S> {
    pub fn new(ops: Arc<S>, handle: LockHandle) -> Self {
        Self {
            ops,
            handle,
            armed: true,
        }
    }

    /// 锁键（日志/断言用）
    pub fn key(&self) -> &str {
        &self.handle.key
    }

    /// 是否仍由本守卫负责释放（测试用于钉住显式释放的 disarm 语义）
    pub fn is_armed(&self) -> bool {
        self.armed
    }

    /// 正常路径释放：等待 CAS 释放完成，并解除 Drop 兜底。
    ///
    /// best-effort：失败只告警（锁在 TTL 到期后自然失效），不影响已完成的业务结果。
    pub async fn release(&mut self) {
        if !self.armed {
            return;
        }
        self.armed = false;
        if let Err(e) = self.ops.release(&self.handle).await {
            tracing::warn!(
                lock_key = %self.handle.key,
                error = %e,
                "锁释放失败（将在 TTL 到期后自然失效）"
            );
        }
    }
}

impl<S: LockReleaseOps + ?Sized + 'static> Drop for HeldLock<S> {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        self.armed = false;
        // 运行时已关闭（进程收尾）时静默跳过：锁由 TTL 自然失效；
        // 此时 spawn 会 panic，而 Drop 中 panic 会升级成双重 panic abort。
        let Ok(rt) = tokio::runtime::Handle::try_current() else {
            return;
        };
        let ops = self.ops.clone();
        let handle = self.handle.clone();
        rt.spawn(crate::common::background::run_tracked(
            "heldLockRelease",
            crate::common::background::LIGHT_DB_BUDGET,
            Some(crate::observability::metrics::MetricsRegistry::global()),
            async move {
                if let Err(e) = ops.release(&handle).await {
                    tracing::warn!(
                        lock_key = %handle.key,
                        error = %e,
                        "锁释放失败（Drop 兜底；将在 TTL 到期后自然失效）"
                    );
                }
            },
        ));
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::time::Duration;

    use tokio::sync::Notify;

    use super::*;

    struct RecordingOps {
        calls: AtomicUsize,
        fail: AtomicBool,
        released: Notify,
    }

    impl RecordingOps {
        fn new(fail: bool) -> Arc<Self> {
            Arc::new(Self {
                calls: AtomicUsize::new(0),
                fail: AtomicBool::new(fail),
                released: Notify::new(),
            })
        }

        fn calls(&self) -> usize {
            self.calls.load(Ordering::SeqCst)
        }
    }

    #[async_trait]
    impl LockReleaseOps for RecordingOps {
        async fn release(&self, _handle: &LockHandle) -> Result<(), StoreError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.released.notify_waiters();
            if self.fail.load(Ordering::SeqCst) {
                return Err(StoreError::Backend("boom".to_string()));
            }
            Ok(())
        }
    }

    fn handle() -> LockHandle {
        LockHandle {
            key: "test:lock".to_string(),
            token: "token-1".to_string(),
        }
    }

    #[tokio::test]
    async fn explicit_release_disarms_the_drop_path() {
        let ops = RecordingOps::new(false);
        let mut guard = HeldLock::new(ops.clone(), handle());
        assert!(guard.is_armed());
        guard.release().await;
        assert!(!guard.is_armed());
        assert_eq!(ops.calls(), 1);
        drop(guard);
        // 已 disarm ⇒ Drop 不得再 spawn 一次释放
        tokio::task::yield_now().await;
        tokio::task::yield_now().await;
        assert_eq!(ops.calls(), 1, "显式释放后 Drop 不得重复释放");
    }

    #[tokio::test]
    async fn drop_without_explicit_release_still_releases() {
        let ops = RecordingOps::new(false);
        {
            let _guard = HeldLock::new(ops.clone(), handle());
            // 模拟 handler future 在业务 await 点被丢弃：不调用 release，直接 drop
        }
        tokio::time::timeout(Duration::from_secs(2), ops.released.notified())
            .await
            .expect("Drop 兜底必须真的发出释放请求");
        assert_eq!(ops.calls(), 1);
    }

    #[tokio::test]
    async fn release_failure_is_best_effort_and_not_retried_by_drop() {
        let ops = RecordingOps::new(true);
        let mut guard = HeldLock::new(ops.clone(), handle());
        guard.release().await; // 不得 panic，也不得逸出错误
        assert!(!guard.is_armed());
        drop(guard);
        tokio::task::yield_now().await;
        assert_eq!(ops.calls(), 1, "失败后由 TTL 兜底，不得在 Drop 里重试");
    }

    #[test]
    fn release_is_idempotent() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let ops = RecordingOps::new(false);
            let mut guard = HeldLock::new(ops.clone(), handle());
            guard.release().await;
            guard.release().await;
            assert_eq!(ops.calls(), 1);
        });
    }

    /// 形状锁：两个高危入口必须持有 RAII 守卫、且不得再直接 `lock_release`
    /// （否则"新增一处手写释放"会静默绕过 Drop 兜底——本批立的案正是这一形状）。
    #[test]
    fn high_risk_lock_sites_use_the_guard_and_never_release_directly() {
        for (name, src) in [
            (
                "sys_backup_handler.rs",
                include_str!("../handler/sys_backup_handler.rs"),
            ),
            (
                "ip_location_handler.rs",
                include_str!("../handler/ip_location_handler.rs"),
            ),
            (
                "sys_oper_log_service.rs",
                include_str!("../service/sys_oper_log_service.rs"),
            ),
        ] {
            assert!(
                src.contains("HeldLock::new("),
                "{name} 必须用 HeldLock 持有锁（Drop 兜底）"
            );
            assert!(
                !src.contains(".lock_release("),
                "{name} 不得直接调用 lock_release —— 释放必须经 HeldLock（显式或 Drop）"
            );
        }
    }
}
