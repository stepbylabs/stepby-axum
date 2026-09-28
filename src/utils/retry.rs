//! 有界重试工具（bounded retry）
//!
//! 设计要点：
//! - 只做「有限次重试 + 固定间隔退避」这一件事，刻意**不**引入批量缓冲 / 持久化队列 /
//!   文件降级等重型机制——项目定位虽为大而全，但日志写入路径上的过度设计会带来
//!   崩溃丢数据与运维复杂度（台账 R5-RATE-29 / R5-IDEMP-35 明确要求 bounded 方案）。
//! - 重试次数有硬上限：DB 长时间不可用时，后台任务不会被无限占用。
//! - 每次失败记 `warn`；重试耗尽后返回最后一次 `Err`，由调用方补上
//!   「请求路径 / 方法 / 操作人 / 任务名」等可定位上下文再记 `error`，
//!   避免审计记录从日志流中凭空消失（无法反查是哪条操作丢了）。
//! - `interval` 为 `Duration::ZERO` 时跳过 sleep，便于单测快速验证尝试次数。
//!
//! 复用方：`service/sys_oper_log_service`（操作日志写入）、`scheduler`（任务日志写入）。

use std::future::Future;
use std::time::Duration;

/// 有界重试策略
#[derive(Debug, Clone, Copy)]
pub struct RetryPolicy {
    /// 最大尝试次数（含首次），必须 >= 1
    pub max_attempts: u32,
    /// 两次尝试之间的固定间隔
    pub interval: Duration,
}

impl RetryPolicy {
    /// 构造重试策略
    pub const fn new(max_attempts: u32, interval: Duration) -> Self {
        Self {
            max_attempts,
            interval,
        }
    }
}

/// 对可失败的异步操作做有界重试
///
/// 返回语义：
/// - 成功：立即返回 `Ok`（不重试）
/// - 失败且未达上限：`tracing::warn!` 记录后按 `interval` 退避，再试
/// - 达到上限仍失败：返回最后一次 `Err`（此处不记 `error`，交由调用方带上下文记录）
pub async fn retry_async<F, Fut, T, E>(policy: RetryPolicy, mut op: F) -> Result<T, E>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<T, E>>,
    E: std::fmt::Display,
{
    debug_assert!(policy.max_attempts >= 1, "max_attempts 必须 >= 1");
    let mut attempt: u32 = 0;
    loop {
        attempt += 1;
        match op().await {
            Ok(value) => return Ok(value),
            Err(err) => {
                if attempt >= policy.max_attempts {
                    return Err(err);
                }
                tracing::warn!(
                    attempt,
                    max_attempts = policy.max_attempts,
                    interval_ms = policy.interval.as_millis(),
                    error = %err,
                    "操作失败，准备重试"
                );
                if !policy.interval.is_zero() {
                    tokio::time::sleep(policy.interval).await;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU32, Ordering};

    /// 可证伪：重试助手必须先失败两次、第三次成功 ⇒ 返回 Ok 且底层恰好被调用 3 次。
    #[tokio::test]
    async fn retry_succeeds_after_two_failures_with_exactly_three_attempts() {
        let attempts = Arc::new(AtomicU32::new(0));
        let counter = attempts.clone();
        let result: Result<&str, String> = retry_async(RetryPolicy::new(3, Duration::ZERO), || {
            let counter = counter.clone();
            async move {
                let n = counter.fetch_add(1, Ordering::SeqCst) + 1;
                if n < 3 {
                    Err(format!("第 {} 次失败", n))
                } else {
                    Ok("ok")
                }
            }
        })
        .await;
        assert_eq!(result.unwrap(), "ok");
        assert_eq!(
            attempts.load(Ordering::SeqCst),
            3,
            "前两次失败 + 第三次成功 = 恰好 3 次尝试"
        );
    }

    /// 可证伪：一直失败 ⇒ 返回 Err 且恰好尝试 3 次（不得无限重试）。
    #[tokio::test]
    async fn retry_exhausts_budget_and_returns_last_error() {
        let attempts = Arc::new(AtomicU32::new(0));
        let counter = attempts.clone();
        let result: Result<(), String> = retry_async(RetryPolicy::new(3, Duration::ZERO), || {
            let counter = counter.clone();
            async move {
                counter.fetch_add(1, Ordering::SeqCst);
                Err("boom".to_string())
            }
        })
        .await;
        assert_eq!(result.unwrap_err(), "boom");
        assert_eq!(
            attempts.load(Ordering::SeqCst),
            3,
            "重试耗尽必须恰好 3 次，不多不少"
        );
    }

    /// 边界：`max_attempts = 1` 时只调用一次，不得重试。
    #[tokio::test]
    async fn retry_with_single_attempt_calls_once_and_short_circuits() {
        let attempts = Arc::new(AtomicU32::new(0));
        let counter = attempts.clone();
        let result: Result<(), String> = retry_async(RetryPolicy::new(1, Duration::ZERO), || {
            let counter = counter.clone();
            async move {
                counter.fetch_add(1, Ordering::SeqCst);
                Err("single".to_string())
            }
        })
        .await;
        assert_eq!(result.unwrap_err(), "single");
        assert_eq!(
            attempts.load(Ordering::SeqCst),
            1,
            "max_attempts=1 时不得重试"
        );
    }
}
