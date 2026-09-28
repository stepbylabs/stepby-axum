// axum-backend/src/scheduler/registry.rs
//! 定时任务函数注册表
//!
//! 设计要点：
//! - 全局静态注册表，使用 `std::sync::LazyLock`（非 once_cell）
//! - invoke_target 完整字符串作为 key（无 Java Bean 反射）
//! - 任务函数签名：`Fn() -> BoxFuture<'static, Result<String, Box<dyn Error + Send + Sync>>>`
//!   - Ok(String) = 执行成功，返回执行信息
//!   - Err(Box<dyn Error + Send + Sync>) = 执行失败，返回类型化错误（R5-TYPE-19）
//! - 线程安全：RwLock 允许多读单写

use std::collections::HashMap;
use std::error::Error;
use std::sync::Arc;
use std::sync::{LazyLock, RwLock};

use futures::future::BoxFuture;

/// 任务执行函数签名
///
/// R5-TYPE-19：错误类型从 `String` 改为 `Box<dyn Error + Send + Sync>`，
/// 允许任务返回任意类型化错误而非裸字符串，便于上游按错误类型决策。
///
/// - `Ok(msg)` — 执行成功，msg 为执行信息（写入 job_message）
/// - `Err(err)` — 执行失败，err 为类型化错误（`to_string()` 后写入 exception_info）
pub type TaskFn =
    Arc<dyn Fn() -> BoxFuture<'static, Result<String, Box<dyn Error + Send + Sync>>> + Send + Sync>;

/// 全局任务注册表（invoke_target 字符串 → 任务函数）
static TASK_REGISTRY: LazyLock<RwLock<HashMap<String, TaskFn>>> =
    LazyLock::new(|| RwLock::new(HashMap::new()));

/// 注册任务函数
///
/// - `invoke_target`：完整字符串（如 `demoTask.demoNoParams`、`demoTask.demoParams('demo')`）
/// - `func`：任务执行函数
///
/// 如果 invoke_target 已存在，覆盖旧函数（支持热更新）
///
/// 容错：锁中毒时（持有锁的线程曾 panic）通过 `into_inner` 恢复守卫，避免 panic 扩散。
pub fn register_task(invoke_target: &str, func: TaskFn) {
    let mut registry = TASK_REGISTRY.write().unwrap_or_else(|e| e.into_inner());
    registry.insert(invoke_target.to_string(), func);
}

/// 查询任务函数
///
/// 返回 `None` 表示该 invoke_target 未注册
///
/// 容错：锁中毒时恢复守卫，保证查询不因其他线程的 panic 而失败。
pub fn get_task(invoke_target: &str) -> Option<TaskFn> {
    let registry = TASK_REGISTRY.read().unwrap_or_else(|e| e.into_inner());
    registry.get(invoke_target).cloned()
}

/// 列出所有已注册的 invoke_target
///
/// 用于调试和启动日志
///
/// 容错：锁中毒时恢复守卫，返回当前已注册内容。
pub fn list_registered_tasks() -> Vec<String> {
    let registry = TASK_REGISTRY.read().unwrap_or_else(|e| e.into_inner());
    registry.keys().cloned().collect()
}

// ==================== 单元测试 ====================

#[cfg(test)]
mod tests {
    use super::*;

    /// 测试注册后能查到任务函数
    #[tokio::test]
    async fn test_register_and_get_task() {
        let func: TaskFn = Arc::new(|| Box::pin(async { Ok("test ok".to_string()) }));
        register_task("testTask.simple", func);

        let retrieved = get_task("testTask.simple");
        assert!(retrieved.is_some());

        let result = retrieved.unwrap()().await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "test ok");
    }

    /// 测试未注册的 invoke_target 返回 None
    #[test]
    fn test_get_unregistered_task() {
        let result = get_task("nonExistent.task");
        assert!(result.is_none());
    }

    /// 测试列出所有已注册的任务
    #[test]
    fn test_list_registered_tasks() {
        let func: TaskFn = Arc::new(|| Box::pin(async { Ok("ok".to_string()) }));

        // 注册多个任务
        register_task("listTest.task1", func.clone());
        register_task("listTest.task2", func.clone());
        register_task("listTest.task3", func);

        let tasks = list_registered_tasks();
        assert!(tasks.iter().any(|t| t == "listTest.task1"));
        assert!(tasks.iter().any(|t| t == "listTest.task2"));
        assert!(tasks.iter().any(|t| t == "listTest.task3"));
    }
}
