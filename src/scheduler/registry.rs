// stepby-axum/src/scheduler/registry.rs
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

/// 任务函数签名
///
/// R5-TYPE-19：错误类型从 `String` 改为 `Box<dyn Error + Send + Sync>`，
/// 允许任务返回任意类型化错误而非裸字符串，便于上游按错误类型决策。
///
/// - `Ok(msg)` — 执行成功，msg 为执行信息（写入 job_message）
/// - `Err(err)` — 执行失败，err 为类型化错误（`to_string()` 后写入 exception_info）
pub type TaskFn =
    Arc<dyn Fn() -> BoxFuture<'static, Result<String, Box<dyn Error + Send + Sync>>> + Send + Sync>;

/// 任务**可被哪个租户身份触发**（b144 新增，铁律「多租户」的直接落点）。
///
/// 立项：`invoke_target` 是注册表查表（无反射），因此"租户能填什么 target"就是"租户能执行
/// 什么代码"。此前所有注册项一视同仁 ⇒ 租户管理员可以建一条 `sys_job`
/// （行归本租户、`monitor:job` 系 perms 对租户下放）把 target 写成
/// `cleanup_expired_logs`，点「执行一次」就触发**平台级跨租户保留期清理**：
/// 删除所有租户的操作日志/登录日志/审计留痕行，并推进平台级标记
/// `retention:last_success_at`。任务闭包签名里没有操作者上下文，也无从收窄——
/// 这正是 AGENTS 铁律禁止的"读侧与写侧不共用同一租户谓词"的形状。
///
/// 两个档位：
/// - [`TaskScope::PlatformOnly`]：**默认**。跨租户读写或写平台级状态。
///   租户拥有的任务一律拒绝（创建/编辑 + 执行两处），只有平台（`tid = 0`）可触发。
/// - [`TaskScope::TenantNeutral`]：不改状态、或只写调用方自己的行（`demoTask.*` 这类
///   示例任务）。显式登记才可被租户任务触发。
///
/// 默认取"更严"的一侧：新增注册忘了标档位 ⇒ 租户无法触发（少一个能力），
/// 而不是"静默获得一条跨租户写路径"（多一个事故）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaskScope {
    /// 仅平台（`tenant_id = 0`）可触发
    PlatformOnly,
    /// 租户亦可触发（无跨租户副作用）
    TenantNeutral,
}

/// 全局任务注册表（invoke_target 字符串 → 任务函数）
static TASK_REGISTRY: LazyLock<RwLock<HashMap<String, TaskFn>>> =
    LazyLock::new(|| RwLock::new(HashMap::new()));

/// invoke_target → 可触发身份档位（与 `TASK_REGISTRY` 同生命周期）
static TASK_SCOPES: LazyLock<RwLock<HashMap<String, TaskScope>>> =
    LazyLock::new(|| RwLock::new(HashMap::new()));

/// 注册任务函数（**默认 `PlatformOnly`**，见 [`TaskScope`]）
///
/// - `invoke_target`：完整字符串（如 `demoTask.demoNoParams`、`demoTask.demoParams('demo')`）
/// - `func`：任务执行函数
///
/// 如果 invoke_target 已存在，覆盖旧函数（支持热更新）
///
/// 容错：锁中毒时（持有锁的线程曾 panic）通过 `into_inner` 恢复守卫，避免 panic 扩散。
pub fn register_task(invoke_target: &str, func: TaskFn) {
    register_task_with_scope(invoke_target, func, TaskScope::PlatformOnly);
}

/// 注册一个**租户也可触发**的任务（必须逐条给出理由，见调用点注释）。
pub fn register_tenant_neutral_task(invoke_target: &str, func: TaskFn) {
    register_task_with_scope(invoke_target, func, TaskScope::TenantNeutral);
}

/// 注册任务并显式声明档位。
pub fn register_task_with_scope(invoke_target: &str, func: TaskFn, scope: TaskScope) {
    let mut registry = TASK_REGISTRY.write().unwrap_or_else(|e| e.into_inner());
    registry.insert(invoke_target.to_string(), func);
    // 档位与函数必须同批写：分开两次加锁会出现"函数已注册、档位还没有"的窗口，
    // 那个窗口里的判定读不到 scope ⇒ 只能按默认（PlatformOnly）算，方向虽安全，
    // 但 TenantNeutral 的任务会在这一瞬被误拒；同一把写锁内完成则不存在该状态。
    let mut scopes = TASK_SCOPES.write().unwrap_or_else(|e| e.into_inner());
    scopes.insert(invoke_target.to_string(), scope);
}

/// 查询任务档位。
///
/// **返回 `None` 一律按 `PlatformOnly` 处理**（`tenant_may_invoke` 的 fail-closed 方向）：
/// 未注册的 target 本来就在 `get_task` 处被拒，这里再兜一层是防"档位表与函数表漂移"。
pub fn task_scope(invoke_target: &str) -> Option<TaskScope> {
    let scopes = TASK_SCOPES.read().unwrap_or_else(|e| e.into_inner());
    scopes.get(invoke_target).copied()
}

/// 判定：某租户身份能否触发该 `invoke_target`。
///
/// - `operator_tid == 0`（平台）⇒ 恒真；
/// - 否则仅 `TenantNeutral` 放行；未查到档位 ⇒ 拒。
///
/// 纯函数（不查库），便于在**创建/编辑**与**执行**两处共用同一判据（两份实现必漂）。
pub fn tenant_may_invoke(operator_tid: i64, invoke_target: &str) -> bool {
    if operator_tid == 0 {
        return true;
    }
    matches!(task_scope(invoke_target), Some(TaskScope::TenantNeutral))
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
