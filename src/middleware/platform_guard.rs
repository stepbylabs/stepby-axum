// axum-backend/src/middleware/platform_guard.rs
//! 平台专属接口请求层守卫（多租户安全加固 P1-1：第二道防线）
//!
//! 背景：permission 层已把 `tool:gen:*` / `monitor:cache:*` / `system:tenant:domain:*`
//! 从租户角色的可授集合中剔除（迁移 m20260926_000002 + initialize 治理 + 套餐门禁），
//! 本中间件在**请求层**再兜底一次：`/monitor/cache/*` 与 `/tool/gen/*` 仅平台操作者
//! （`tid == 0`）可访问，租户操作者（含租户管理员）一律 403——**不依赖 perms**。
//!
//! 判定语义：
//! - 取操作者上下文，`tid == 0` → 放行；
//! - `tid != 0`（租户操作者）→ 403 `error.tenant.platform_only`；
//! - 操作者上下文缺失 → 同样 403（fail-closed；本中间件只挂在已鉴权路由上）。
//!
//! 关于操作者来源（实测偏差说明）：
//! 任务要求从 `extensions().get::<auth::Operator>()` 取操作者，但经全仓检索确认
//! `Operator` 是**仅供 handler 提取的 FromRequestParts 包装类型**（`src/middleware/auth.rs`），
//! 从未被写入 extensions；`auth_middleware` 写入的是其内部包装的 `Claims`（auth.rs §8）。
//! 若按 `Operator` 读取，则所有已鉴权请求都会命中「扩展缺失」→ 全量 403，属功能性回退。
//! 故此处改为读取 `Claims`——与 `Operator` 提取器读取的**同一份 JWT 声明**，
//! `tid` 语义完全一致（`Operator::tenant_id()` 亦直接返回 `Claims.tid`）。
//! 层序：本中间件挂在子 router 的 `route_layer`，相对父 router 的 `route_layer`（含 auth）
//! 属内层（后执行），故执行时 `Claims` 必已注入；该假设由集成测试证明（平台操作者 200）。

use axum::extract::Request;
use axum::middleware::Next;
use axum::response::Response;

use crate::common::AppError;
use crate::jwt::Claims;

/// 平台专属接口守卫：仅 `tid == 0`（平台操作者）放行，其余（含租户管理员）403。
///
/// 仅用于 `/monitor/cache/*` 与 `/tool/gen/*` 等平台专属路由；挂载方式：
/// `.route_layer(axum::middleware::from_fn(platform_only_guard))`
pub async fn platform_only_guard(req: Request, next: Next) -> Result<Response, AppError> {
    let path = req.uri().path().to_string();
    // 先取出 owned 的操作者上下文（tid + 用户名），避免持有对 req 的借用后再 move req
    let operator = req
        .extensions()
        .get::<Claims>()
        .map(|c| (c.tid, c.sub.clone()));

    match operator {
        Some((0, _)) => Ok(next.run(req).await),
        Some((tenant_id, user_id)) => {
            tracing::warn!(
                user_id = %user_id,
                tenant_id,
                path = %path,
                "租户操作者访问平台专属接口（拒绝，P1-1 第二道防线）"
            );
            Err(AppError::forbidden(&crate::tr!(
                "error.tenant.platform_only"
            )))
        }
        None => {
            // fail-closed：本中间件仅挂在已鉴权路由，操作者缺失说明链路异常，拒绝而非放行
            tracing::warn!(
                path = %path,
                "平台守卫：缺少操作者上下文（fail-closed 拒绝）"
            );
            Err(AppError::forbidden(&crate::tr!(
                "error.tenant.platform_only"
            )))
        }
    }
}
