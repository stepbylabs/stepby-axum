// stepby-axum/src/scheduler/cluster.rs
//! 集群模式（`[scheduler].cluster_mode`）与内置定时任务的「整轮互斥锁」。
//!
//! # 为什么需要它
//!
//! 内置定时任务（`flow_timeout_scan` / `mmdb_auto_update` / `msg_send_retry` /
//! `report_sub_due` / `chunk_cleanup`）在多实例部署下需要"同一时刻仅一个实例执行
//! **整轮**"；单实例部署则完全不需要这层锁。
//! 历史实现把该策略散成两个裸 bool / 硬编码常量（`[flow].scan_lock_enabled`
//! 与 mmdb 的"总是加锁"），使用者无法用一句话表达"我这个部署形态是什么"。
//!
//! 按项目准则③（**开关取「模式」而非裸 bool**），收敛为一个模式开关：
//!
//! | 模式 | 语义 | 内置任务的整轮锁 |
//! |---|---|---|
//! | `auto`（**默认**） | 各任务沿用**自身历史开关** ⇒ **不改变任何默认行为** | `flow`：由 `[flow].scan_lock_enabled` 推导；其余四个任务：加锁（历史行为） |
//! | `single` | 明确声明**单实例**部署 | 一律不加锁（省一次 NX 往返） |
//! | `leader` | 多实例**选主**：仅持锁实例执行整轮 | 一律加锁 |
//! | `all` | 每个实例都执行（幂等型任务，如仅刷新本地缓存） | 一律不加锁 |
//!
//! 非法取值回落 `auto`（= 现状，fail-safe 且不改变行为）。
//!
//! # fail-closed 语义
//!
//! 加锁档（`auto` / `leader`）下，共享态存储（Redis / local DB）不可用时加锁任务会
//! **跳过本轮**（多实例下重复执行的代价高于漏跑一轮，下一轮 cron 会重试）。
//! 单实例部署无跨实例竞争，跳过是净损失 ⇒ 应显式置 `single` 消除这层无谓依赖。
//!
//! # 边界（刻意不纳入本开关）
//!
//! `sys_job` 的**逐任务并发锁** `lock:scheduler:{job_id}` 属"同一任务防重入"，与集群
//! 形态无关（**单实例同样需要**），故**不随本开关关闭**。本模块只治理"整轮扫描/整轮更新"
//! 这一层的跨实例互斥。

use std::sync::Arc;

use crate::shared_store::{LockHandle, SharedStore};

/// 内置任务整轮互斥锁的默认 TTL（秒）
pub const DEFAULT_ROUND_LOCK_TTL_SECS: u64 = 300;

/// 集群模式
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ClusterMode {
    /// 沿用各任务自身历史开关（默认；不改变现状）
    #[default]
    Auto,
    /// 单实例部署：不加锁
    Single,
    /// 多实例选主：加锁
    Leader,
    /// 每个实例都执行：不加锁
    All,
}

impl ClusterMode {
    /// 解析模式串；非法值返回 `None`（由 [`ClusterMode::parse_or_auto`] 回落 `auto`）。
    pub fn parse(raw: &str) -> Option<Self> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "auto" => Some(Self::Auto),
            "single" => Some(Self::Single),
            "leader" => Some(Self::Leader),
            "all" => Some(Self::All),
            _ => None,
        }
    }

    /// 解析模式串；非法值回落 [`ClusterMode::Auto`]（= 现状）。
    pub fn parse_or_auto(raw: &str) -> Self {
        Self::parse(raw).unwrap_or_default()
    }

    /// 规范字符串（用于日志与配置回显）
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::Single => "single",
            Self::Leader => "leader",
            Self::All => "all",
        }
    }

    /// 本模式下内置任务**是否需要**"整轮互斥锁"。
    ///
    /// `legacy_enabled` = 该任务自身的历史开关，**仅 `auto` 参考它**：
    /// `auto` 的全部意义就是"回到改造前的行为"，任何其它模式都显式覆盖它。
    pub fn requires_round_lock(self, legacy_enabled: bool) -> bool {
        match self {
            Self::Auto => legacy_enabled,
            Self::Leader => true,
            Self::Single | Self::All => false,
        }
    }
}

/// 已获取的内置任务整轮互斥锁（RAII 风格：显式释放 + [`Drop`] 兜底）。
///
/// `held = false` 表示"本模式下不需要锁"——此时 [`ClusterLock::release`] 是空操作，
/// 因此调用方**无需**区分"取到锁"与"不需要锁"，代码路径唯一。
///
/// 内部持共享态存储句柄与锁句柄（含 fencing token）：释放经
/// `store.lock_release` 的 CAS 完成（仅 token 匹配才删，防误删他实例的锁）。
///
/// **Drop 兜底**：panic / 提前 return 时闭包尾部显式 `release()` 会被跳过，Drop 中
/// spawn 异步释放（幂等 CAS）杜绝锁被一直持有到 TTL 到期。
pub struct ClusterLock {
    store: Arc<dyn SharedStore>,
    handle: Option<LockHandle>,
    held: bool,
}

impl ClusterLock {
    /// 按需取锁。
    ///
    /// - `needed = false`（`single` / `all` 模式）⇒ 直接返回"未持锁"的占位者；
    /// - `needed = true` ⇒ `store.lock_acquire`（SET NX EX + UUID fencing token）：
    ///   - 取到 ⇒ 返回持锁者（调用方执行完后必须 [`release`](Self::release)）；
    ///   - 被他人持有 ⇒ 返回 `None`（**本次调度跳过**）；
    ///   - 存储故障 ⇒ 返回 `None` 并 error 日志（**fail-closed**：多实例下重复执行的代价
    ///     高于漏跑一轮，下一轮 cron 会重试）。
    pub async fn acquire(
        store: Arc<dyn SharedStore>,
        key: &str,
        needed: bool,
        ttl_secs: u64,
        task: &str,
    ) -> Option<Self> {
        if !needed {
            return Some(Self {
                store,
                handle: None,
                held: false,
            });
        }
        match store.lock_acquire(key, ttl_secs).await {
            Ok(Some(handle)) => Some(Self {
                store,
                handle: Some(handle),
                held: true,
            }),
            Ok(None) => {
                tracing::info!("{task}: 其他实例正在执行（锁被持有），跳过本次调度");
                None
            }
            Err(e) => {
                tracing::error!("{task}: 分布式锁获取失败（共享态存储故障），跳过本次调度: {e}");
                None
            }
        }
    }

    /// 释放锁（CAS：仅当锁 token 仍是本实例的 fencing token 时才删除，避免误删他实例的锁）。
    ///
    /// 未持锁（`single` / `all` 模式）时为空操作。best-effort：释放失败不影响调用方
    /// （锁会在 TTL 到期后自然失效）。
    ///
    /// **幂等**：重复调用无害——store 层释放走 CAS（token 不匹配即 0 行/Lua 不删），
    /// 故 [`Drop`] 兜底与显式调用可并存而不冲突。
    pub async fn release(&self) {
        if let Some(handle) = &self.handle
            && let Err(e) = self.store.lock_release(handle).await
        {
            tracing::warn!(
                lock_key = %handle.key,
                error = %e,
                "整轮互斥锁释放失败（将在 TTL 到期后自然失效）"
            );
        }
    }

    /// 本实例是否真的持锁（仅用于日志/断言）
    pub fn is_held(&self) -> bool {
        self.held
    }
}

/// panic / 提前 return 路径兜底：同步 Drop 中 spawn 异步释放，杜绝"整轮锁永久持有"。
///
/// 背景（批次三十）：内置任务闭包（flow_timeout_scan / mmdb_auto_update /
/// msg_send_retry / report_sub_due / chunk_cleanup）**不经过** `execute_with_logging`
/// 的 catch_unwind 包裹，其体内 service 一旦 panic 展开，闭包尾部显式的
/// `round_lock.release().await` 将被跳过 ⇒ 锁一直持有到 TTL 到期（flow 300s /
/// msg_retry 55s / chunk_cleanup 1500s），期间整轮扫描/清理被静默跳过。
/// 与 `JobLockGuard`（`scheduler/mod.rs` Drop → abort_and_spawn_release）同款范式：
/// Drop 是 `&mut self` 但 release 是 async，故 spawn 到运行时执行；释放走 CAS 且幂等，
/// 与闭包尾部的显式 `release()` 并存无冲突（后者先删则 Drop 的 CAS 匹配 0 行）。
impl Drop for ClusterLock {
    fn drop(&mut self) {
        if let Some(handle) = &self.handle {
            let store = self.store.clone();
            let handle = handle.clone();
            // 无运行时上下文（如运行时已关闭期间的 Drop）时静默跳过——锁将由 TTL 自然失效；
            // 用 try_current 避免 Drop 中 spawn 失败 panic 触发双重 panic abort。
            let Ok(rt) = tokio::runtime::Handle::try_current() else {
                return;
            };
            rt.spawn(async move {
                // best-effort：释放失败仅告警（锁在 TTL 到期后自然失效）
                if let Err(e) = store.lock_release(&handle).await {
                    tracing::warn!(
                        lock_key = %handle.key,
                        error = %e,
                        "整轮互斥锁释放失败（Drop 兜底；将在 TTL 到期后自然失效）"
                    );
                }
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 模式解析：合法值准确、非法值回落 `auto`（= 现状，不改变行为）
    #[test]
    fn test_parse_and_fallback() {
        assert_eq!(ClusterMode::parse("auto"), Some(ClusterMode::Auto));
        assert_eq!(ClusterMode::parse("SINGLE"), Some(ClusterMode::Single));
        assert_eq!(ClusterMode::parse(" leader "), Some(ClusterMode::Leader));
        assert_eq!(ClusterMode::parse("all"), Some(ClusterMode::All));
        assert_eq!(ClusterMode::parse("bogus"), None);
        assert_eq!(ClusterMode::parse(""), None);
        // 非法值一律回落 auto（fail-safe：不会意外关闭或开启锁）
        assert_eq!(ClusterMode::parse_or_auto("bogus"), ClusterMode::Auto);
        assert_eq!(ClusterMode::default(), ClusterMode::Auto);
        for m in [
            ClusterMode::Auto,
            ClusterMode::Single,
            ClusterMode::Leader,
            ClusterMode::All,
        ] {
            assert_eq!(ClusterMode::parse(m.as_str()), Some(m), "as_str 必须可回解");
        }
    }

    /// **默认态即现状**（可证伪回归锁）：`auto` 逐条等于改造前的取值
    #[test]
    fn test_auto_mode_preserves_legacy_behavior() {
        let auto = ClusterMode::Auto;
        // flow_timeout_scan：改造前由 `[flow].scan_lock_enabled` 决定
        assert!(
            !auto.requires_round_lock(false),
            "auto + 历史开关关 ⇒ 不加锁（现状）"
        );
        assert!(
            auto.requires_round_lock(true),
            "auto + 历史开关开 ⇒ 加锁（现状）"
        );
        // mmdb_auto_update：改造前**始终**加锁 ⇒ 以 legacy_enabled=true 传入
        assert!(
            auto.requires_round_lock(true),
            "auto 下 mmdb 保持加锁（现状）"
        );
        // msg_send_retry / report_sub_due / chunk_cleanup：同为"改造前始终加锁"的内置任务
        // （§5.55 收散点批三十补完：此前三处硬编码 true 游离于 cluster_mode 之外，
        // 单实例部署仍受共享态存储抖动影响 ⇒ 现统一以 legacy_enabled=true 纳入治理）。
        // 本断言锁定"auto 下三者仍加锁"= 对存量部署零行为变更。
        for task in ["msg_send_retry", "report_sub_due", "chunk_cleanup"] {
            assert!(
                auto.requires_round_lock(true),
                "auto 下 {task} 必须保持加锁（现状，零行为变更）"
            );
        }
    }

    /// 显式模式覆盖历史开关（配置意图优先于 legacy）
    #[test]
    fn test_explicit_modes_override_legacy() {
        assert!(
            ClusterMode::Leader.requires_round_lock(false),
            "leader 忽略 legacy，一律加锁"
        );
        assert!(
            !ClusterMode::Single.requires_round_lock(true),
            "single 忽略 legacy，一律不加锁（明确单实例假设）"
        );
        assert!(
            !ClusterMode::All.requires_round_lock(true),
            "all 忽略 legacy，一律不加锁（每实例都执行）"
        );
    }
}
