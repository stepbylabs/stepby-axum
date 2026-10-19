//! 后台 fire-and-forget 任务的统一范式（AGENTS 工程硬基线 B.6：超时 + 重试上限 + 失败审计）。
//!
//! 为什么要有这一层：`tokio::spawn` 的返回值是 `JoinHandle`，**丢弃它 = 结局无人认领**——
//! panic 被静默吞掉、卡死的任务不会有任何痕迹，而这类调用点全在请求路径的"尾部"
//! （登录日志、PAT 最近使用时间、WS 计数递减、分布式锁释放、AI 历史落库、WebHook 派发）。
//! b72 机械扫描实测 13 处 `tokio::spawn` 既无超时也无 panic 隔离，正是要收口的形态。
//!
//! 口径边界（有意不做的事）：
//! - **长驻循环**（WS 读写环、调度器主循环、投递 worker）不套本函数——对它们"超时"意味着
//!   砍断合法长连接/长任务，属语义倒置；这类点由形状锁显式登记豁免并注明理由。
//! - 本函数**不重试**。重试策略属业务语义（幂等性、退避、上限各不同），
//!   由调用方决定；本层只保证"要么完成，要么留下可观测的失败"。

use std::future::Future;
use std::panic::AssertUnwindSafe;
use std::sync::Arc;
use std::time::{Duration, Instant};

use futures::FutureExt;
use tokio::task::JoinHandle;

use crate::observability::metrics::MetricsRegistry;

/// 轻量 DB 写（遥测 / 计数 / 审计类）默认预算 5s。
///
/// 与 `middleware/oper_log.rs:101 OPER_LOG_TIMEOUT`、`middleware/permission.rs:39
/// PERMISSION_AUDIT_LOG_TIMEOUT` **同源**——三处曾是各自手写的同一个值，收口成一个常量，
/// 避免"改一处漏两处"的漂移。
pub const LIGHT_DB_BUDGET: Duration = Duration::from_secs(5);

/// 受守卫后台任务的结局（同时作为 `stepby_outbound_requests_total{outcome=…}` 的标签值）
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TaskOutcome {
    Completed,
    TimedOut,
    Panicked,
}

impl TaskOutcome {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Completed => "ok",
            Self::TimedOut => "timeout",
            Self::Panicked => "panic",
        }
    }
}

/// 执行一个受守卫的一次性后台任务：超时 → 记 WARN；panic → 隔离并记 WARN；两者都计入指标。
///
/// 供测试直接 await；业务侧用 [`spawn_tracked`]。
pub async fn run_tracked<T: Send + 'static>(
    label: &'static str,
    budget: Duration,
    metrics: Option<Arc<MetricsRegistry>>,
    task: impl Future<Output = T> + Send + 'static,
) -> TaskOutcome {
    let started = Instant::now();
    // Pin<Box<_>> 使 `Unpin` 成立（async block 本身 !Unpin），同时保留 Send 供 spawn 使用
    let outcome =
        match tokio::time::timeout(budget, AssertUnwindSafe(Box::pin(task)).catch_unwind()).await {
            Ok(Ok(_)) => TaskOutcome::Completed,
            // panic payload 可能是任意类型（非 Send），只记"已隔离"，不尝试打印载荷
            Ok(Err(_)) => TaskOutcome::Panicked,
            Err(_) => TaskOutcome::TimedOut,
        };
    let secs = started.elapsed().as_secs_f64();
    match outcome {
        TaskOutcome::Completed => {}
        TaskOutcome::TimedOut => tracing::warn!(
            task = label,
            timeout_ms = budget.as_millis() as u64,
            elapsed_ms = (secs * 1000.0) as u64,
            "后台任务超时未完成（已放弃并留痕，不阻塞请求线程）"
        ),
        TaskOutcome::Panicked => tracing::warn!(
            task = label,
            "后台任务 panic（已隔离于独立任务，不影响请求线程；失败已计数）"
        ),
    }
    if let Some(m) = metrics {
        m.record_outbound(&format!("bg:{label}"), outcome.as_str(), secs);
    }
    outcome
}

/// 在当前运行时上派生一个受守卫的后台任务（丢弃 `JoinHandle` = 有意 detached）。
pub fn spawn_tracked<T: Send + 'static>(
    label: &'static str,
    budget: Duration,
    metrics: Option<Arc<MetricsRegistry>>,
    task: impl Future<Output = T> + Send + 'static,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        run_tracked(label, budget, metrics, task).await;
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};

    fn budget() -> Duration {
        Duration::from_millis(50)
    }

    #[tokio::test]
    async fn completed_task_reports_ok() {
        let done = Arc::new(AtomicBool::new(false));
        let flag = done.clone();
        let outcome = run_tracked("unit_ok", budget(), None, async move {
            flag.store(true, Ordering::SeqCst);
            1u8
        })
        .await;
        assert_eq!(outcome, TaskOutcome::Completed);
        assert!(done.load(Ordering::SeqCst), "被包裹的任务体必须真实执行");
    }

    #[tokio::test]
    async fn panicking_task_is_isolated_not_fatal() {
        // 关键断言：panic 被捕获后调用方仍存活（若未隔离，本测试进程会带着其他测试一起崩）
        let outcome = run_tracked("unit_panic", budget(), None, async {
            panic!("boom: 后台任务内的 panic 必须被隔离");
        })
        .await;
        assert_eq!(outcome, TaskOutcome::Panicked);
    }

    #[tokio::test]
    async fn slow_task_times_out_and_drops_future() {
        // 不用 `start_paused`：那需要给整个 tokio 依赖开 `test-util` feature（改变全 crate 构建配置）。
        // 这里用 20ms 预算 vs 500ms 休眠的**量级差**取确定性，与 rate_limit 既有测试同口径。
        let cancelled = Arc::new(AtomicBool::new(false));
        let flag = cancelled.clone();
        let outcome = run_tracked(
            "unit_timeout",
            Duration::from_millis(20),
            None,
            async move {
                tokio::time::sleep(Duration::from_millis(500)).await;
                flag.store(true, Ordering::SeqCst);
            },
        )
        .await;
        assert_eq!(
            outcome,
            TaskOutcome::TimedOut,
            "超时必须显式定性，不能静默悬挂"
        );
        assert!(
            !cancelled.load(Ordering::SeqCst),
            "超时后 future 必须被 drop（否则任务仍在偷偷跑）"
        );
    }

    #[tokio::test]
    async fn outcome_is_exported_as_bg_component_metric() {
        // 用 default() 而非 global()/test_instance()：本测试要断言"恰好 1 次"，
        // 全局单例会被同批并行的其他测试写入而计数漂移
        let reg = Arc::new(MetricsRegistry::default());
        run_tracked("metered", budget(), Some(reg.clone()), async {}).await;
        let text = reg.render_prometheus();
        assert!(
            text.contains(
                "stepby_outbound_requests_total{component=\"bg:metered\",outcome=\"ok\"} 1"
            ),
            "后台任务结局必须可在 /metrics 观测，实际渲染：{text}"
        );
        assert!(
            text.contains("stepby_outbound_duration_seconds_count{component=\"bg:metered\"} 1"),
            "计数与耗时必须成对出现（避免孤儿系列）"
        );
    }

    #[tokio::test]
    async fn spawn_tracked_detaches_but_still_runs() {
        let ran = Arc::new(AtomicBool::new(false));
        let flag = ran.clone();
        let handle = spawn_tracked("spawned", budget(), None, async move {
            flag.store(true, Ordering::SeqCst);
        });
        let _ = handle.await;
        assert!(ran.load(Ordering::SeqCst));
    }
}
