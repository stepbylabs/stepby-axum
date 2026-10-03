//! 全局搜索 Handler（Axum 原生实现）
//!
//! 接口路径对齐前端调用规范：
//! - GET /common/global-search?q=&limit= — 跨白名单实体全局搜索
//!
//! 权限取舍（与 common_router 既有跨域实现对齐的处理方式）：
//! - 路由层：登记为"仅登录"（is_login_only_path 白名单），不绑定单一 RBAC 权限键——
//!   因为本接口横跨 10 个域，任何单一权限键都会造成"缺某个列表权限的用户整个接口 403"
//!   或"越权键聚合"的语义混乱；
//! - 数据层：**在 handler 内逐域检查当前用户权限**（复用 permission_middleware 同源的
//!   `menu_service.get_permissions_by_user_id`，超管 `*:*:*` 全域放行），仅检索用户
//!   持有对应 `*:list` 权限的域；无任何域权限时返回空结果而非 403（搜索框不应报错）；
//! - 租户隔离：按操作者 tid 注入各实体 tenant_id 过滤（沿用 dashboard_stats 范式），
//!   域内数据遵循既有租户过滤范式，不放大可见范围。

use std::sync::Arc;

use axum::extract::{Query, State};
use serde::Deserialize;
use utoipa::IntoParams;

use crate::common::{AjaxResult, AppError};
use crate::middleware::Operator;
use crate::service::global_search_service::{self, SearchDomain};
use crate::state::AppState;

/// 全局搜索请求参数
#[derive(Debug, Deserialize, IntoParams)]
#[serde(rename_all = "camelCase")]
pub struct GlobalSearchParams {
    /// 搜索关键词（最短 2 字符，不足返回空结果）
    #[serde(default)]
    pub q: Option<String>,
    /// 返回条数上限（默认 10，硬顶 20）
    pub limit: Option<u64>,
}

/// q 的最短有效字符数（不足直接返回空结果，不打 DB）
const Q_MIN_CHARS: usize = 2;
/// 返回条数硬顶（性能安全：防止 limit 被刷大）
const LIMIT_MAX: u64 = 20;
/// 默认返回条数
const LIMIT_DEFAULT: u64 = 10;

/// GET /common/global-search
/// 全局搜索（跨白名单实体，逐域权限过滤 + 租户隔离）
#[utoipa::path(
    get,
    path = "/common/global-search",
    params(GlobalSearchParams),
    responses(
        (status = 200, description = "搜索成功", body = AjaxResult<Vec<global_search_service::GlobalSearchItem>>),
        (status = 500, description = "服务器错误"),
    ),
    tag = "common"
)]
pub async fn global_search(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    Query(params): Query<GlobalSearchParams>,
) -> Result<AjaxResult<Vec<global_search_service::GlobalSearchItem>>, AppError> {
    // 1. 参数规整：q 最短 2 字符（含首尾空白剥离），limit 硬顶 20 默认 10
    let q = params.q.unwrap_or_default();
    if q.trim().chars().count() < Q_MIN_CHARS {
        // 过短不打 DB，直接空结果（前端搜索框行为契约）
        return Ok(AjaxResult::success(Vec::new()));
    }
    let limit = params
        .limit
        .unwrap_or(LIMIT_DEFAULT)
        .clamp(1, LIMIT_MAX);

    // 2. 解析操作者，取权限列表（与 permission_middleware 同一数据源，含缓存）
    let user_id: i64 = operator
        .user_id()
        .parse()
        .map_err(|_| AppError::internal(&crate::tr!("error.auth.user_id_parse_failed")))?;
    let permissions = state.menu_service.get_permissions_by_user_id(user_id).await?;
    let is_superadmin = permissions.iter().any(|p| p == "*:*:*");
    // 逐域权限判定：超管全域；普通用户仅检索持有对应 *:list 权限的域
    let has_perm =
        |perm: &str| is_superadmin || permissions.iter().any(|p| p == perm);
    let domain_perms: &[(SearchDomain, &str)] = &[
        (SearchDomain::User, "system:user:list"),
        (SearchDomain::Dept, "system:dept:list"),
        (SearchDomain::Tenant, "system:tenant:list"),
        (SearchDomain::Role, "system:role:list"),
        (SearchDomain::Menu, "system:menu:list"),
        (SearchDomain::Job, "monitor:job:list"),
        (SearchDomain::Config, "system:config:list"),
        (SearchDomain::Notice, "system:notice:list"),
        (SearchDomain::Task, "system:task:list"),
        (SearchDomain::Template, "system:msg:template:list"),
    ];
    let domains: Vec<SearchDomain> = domain_perms
        .iter()
        .filter(|(_, perm)| has_perm(perm))
        .map(|(d, _)| *d)
        .collect();
    // 无任何域权限：返回空结果（不 403，搜索框不应报错）
    if domains.is_empty() {
        return Ok(AjaxResult::success(Vec::new()));
    }

    // 3. 租户隔离口径：None = 平台操作者不过滤，Some(tid) = 仅本租户（dashboard_stats 同范式）
    let tenant_scope = crate::common::tenant::tenant_scope(operator.tenant_id());

    // 4. 执行检索（每域 cap 5、前缀优先排序），总条数截断到 limit（硬顶性能安全）
    let mut items = global_search_service::global_search(&state.db, &domains, tenant_scope, &q)
        .await?;
    items.truncate(limit as usize);

    Ok(AjaxResult::success(items))
}
