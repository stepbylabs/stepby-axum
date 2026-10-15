// stepby-axum/src/middleware/platform_guard.rs
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
use axum::http::Method;
use axum::middleware::Next;
use axum::response::Response;

use crate::common::AppError;
use crate::jwt::Claims;

/// 能力位感知：平台专属路由组中，**允许租户操作者**访问的 (方法, 路径, 能力位, 所需档位)
/// 清单。
///
/// 语义：仅当**平台层** `[features]` 中对应能力位**达到该档位**时，该路径才放行租户操作者；
/// 能力位关闭（默认）⇒ 与改造前逐条等价（租户一律 403）。
///
/// "所需档位"是三态能力位的必要维度：`backup.visibility` 的 `view_only` 只放行
/// **列表/详情**，**下载**必须 `full`（下载即拿到备份文件本体；对平台普通角色
/// `tid = 0` ⇒ 服务层不做行级收窄 ⇒ 等于整库数据下载，见 `common::features`）。
///
/// ⚠️ 本守卫是**第二道防线**（请求层），不是唯一闸门。完整的三层开关为：
/// ① 平台 `[features]`（本守卫）→ ② 套餐 `features`（决定相关 perms 是否**可授予**租户角色）
/// → ③ 角色授权（permission 中间件按 perms 放行）。因此即便某租户套餐未开启，
/// 守卫放行后仍会在 permission 层 403（不会形成越权）。
///
/// 服务层的行级收窄（`tenant_id = 操作者租户`）是最后一道：见
/// `sys_backup_service`（租户可见的备份清单被强制收窄为
/// `backup_type = 'tenant_export' AND tenant_id = 自己`）。
///
/// `download/{backupId}` 用**前缀**匹配（路径含动态段），其余为精确匹配。
const TENANT_VISIBLE_ROUTES: &[(Method, &str, &str, &str)] = &[
    (
        Method::GET,
        "/system/backup/list",
        "backup.visibility",
        "view_only",
    ),
    (
        Method::GET,
        "/system/backup/download/",
        "backup.visibility",
        "full",
    ),
    (
        Method::POST,
        "/system/backup/self-export",
        "backup.tenant_self_export",
        "on",
    ),
];

/// 租户操作者是否可访问该 (方法, 路径)：返回命中的 (能力位键, 所需档位)（未命中 = `None`）。
///
/// 纯函数（可单测）：不读全局、不做 IO，只做静态清单匹配，
/// 因此"未登记路径 = 租户不可达"是**结构性**保证（不会因忘写一个分支而放开）。
fn tenant_visible_feature(method: &Method, path: &str) -> Option<(&'static str, &'static str)> {
    // 备份详情 `GET /system/backup/{backupId}`：单个**纯数字**动态段
    // （backupId 为雪花/自增整数；"list"/"self-export" 等静态段因含非数字字符被排除）
    if method == Method::GET
        && let Some(rest) = path.strip_prefix("/system/backup/")
        && !rest.is_empty()
        && rest.chars().all(|c| c.is_ascii_digit())
    {
        return Some(("backup.visibility", "view_only"));
    }
    TENANT_VISIBLE_ROUTES
        .iter()
        .find(|(m, p, _, _)| {
            m == method
                && if p.ends_with('/') {
                    path.starts_with(p)
                } else {
                    path == *p
                }
        })
        .map(|(_, _, feat, required)| (*feat, *required))
}

/// 平台专属接口守卫：仅 `tid == 0`（平台操作者）放行，其余（含租户管理员）403；
/// **但**命中 `TENANT_VISIBLE_ROUTES` 且对应平台层能力位**达到所需档位**时放行租户操作者。
///
/// 仅用于 `/monitor/cache/*`、`/tool/gen/*`、`/system/backup/*` 等平台专属路由；挂载方式：
/// `.route_layer(axum::middleware::from_fn(platform_only_guard))`
pub async fn platform_only_guard(req: Request, next: Next) -> Result<Response, AppError> {
    let path = req.uri().path().to_string();
    let method = req.method().clone();
    // 先取出 owned 的操作者上下文（tid + 用户名），避免持有对 req 的借用后再 move req
    let operator = req
        .extensions()
        .get::<Claims>()
        .map(|c| (c.tid, c.sub.clone()));

    match operator {
        Some((0, _)) => Ok(next.run(req).await),
        Some((tenant_id, user_id)) => {
            // 能力位放行（第二道防线）：平台层达到所需档位 + 路径在租户可见清单内
            if let Some((feat, required)) = tenant_visible_feature(&method, &path)
                && crate::common::features::mode_reaches(
                    crate::common::features::platform_features(),
                    feat,
                    required,
                )
            {
                return Ok(next.run(req).await);
            }
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

#[cfg(test)]
mod tests {
    use super::*;

    /// 租户可见清单是**结构性白名单**：只放行登记过的路径，其余一律 `None`
    #[test]
    fn test_tenant_visible_feature_whitelist() {
        // 只读两件套（列表 + 详情）：`view_only` 档即可
        assert_eq!(
            tenant_visible_feature(&Method::GET, "/system/backup/list"),
            Some(("backup.visibility", "view_only"))
        );
        assert_eq!(
            tenant_visible_feature(&Method::GET, "/system/backup/42"),
            Some(("backup.visibility", "view_only")),
            "备份详情（纯数字 backupId）应与列表同档"
        );
        // 下载：必须 `full` 档（MT-7：只读档不得放行下载）
        assert_eq!(
            tenant_visible_feature(&Method::GET, "/system/backup/download/42"),
            Some(("backup.visibility", "full")),
            "下载面必须要求 full 档"
        );
        assert_eq!(
            tenant_visible_feature(&Method::GET, "/system/backup/logs/42"),
            None,
            "未登记路径必须不可达"
        );
        assert_eq!(
            tenant_visible_feature(&Method::GET, "/system/backup/self-export"),
            None,
            "self-export 是 POST 语义；GET 不匹配（非纯数字段也不匹配详情规则）"
        );
        // 自助导出
        assert_eq!(
            tenant_visible_feature(&Method::POST, "/system/backup/self-export"),
            Some(("backup.tenant_self_export", "on"))
        );
        // 平台代导出（带 tenantId 的越权面）**不得**对租户放行
        assert_eq!(
            tenant_visible_feature(&Method::POST, "/system/backup/tenant-export/9"),
            None,
            "平台代导出必须保持平台专属"
        );
    }

    /// 危险写面与整库下载面：租户**永不**放行（能力位不改变这些路径的判定）
    #[test]
    fn test_tenant_visible_feature_denies_dangerous_writes() {
        for (m, p) in [
            (Method::POST, "/system/backup"),
            (Method::POST, "/system/backup/restore/1"),
            (Method::DELETE, "/system/backup/1"),
            (Method::POST, "/tool/gen/1"),
            (Method::GET, "/monitor/cache/keys"),
        ] {
            assert_eq!(
                tenant_visible_feature(&m, p),
                None,
                "{m} {p} 必须保持平台专属（能力位不得放开）"
            );
        }
    }
}
