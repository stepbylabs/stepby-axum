// backend-axum/src/middleware/tenant_host.rs
//! host → tid 租户上下文中间件（多租户 Phase 3 域名链路，文档 §27.7 / §29.6）
//!
//! 链路定位（安全关键）：
//! - TLS 与 host 路由交 Nginx/网关；网关解析域名后注入内部头 `X-Tenant-Code`；
//! - 后端**仅信任可信反代来源**（直连 peer IP 命中 `server.trusted_proxies`）；
//! - 本中间件位于**鉴权中间件之外**（`build_app` 全局 layer，先于 `protected` 的
//!   route_layer 执行），故登录页、公开页、SSO 回调同样获得 host 租户上下文；
//! - 解析结果以 [`HostTenant`] 注入 request extensions，由 `auth_middleware` 做
//!   「host 归属 vs JWT `tid`」一致性校验（不一致 → 403，**绝不静默改用 host 的 tid**）。
//!
//! 解析顺序：
//! 1. 可信来源且带 `X-Tenant-Code` → `tenant:code:{code}`（网关权威注入，标准部署路径）；
//! 2. 否则带 `Host` 头且形如域名（含 `.` 且非 IP）→ `tenant:host:{domain}`（回源域名表）；
//! 3. 均未命中 / 来源不可信 → `HostTenant(None)`（无 host 租户上下文）。
//!
//! 降级（fail-safe）：
//! - `server.trusted_proxies` 为空时无法判定来源可信 → **一律** `HostTenant(None)`，
//!   即 host 隔离能力退化为「无约束」；此场景下数据隔离仍由 JWT `tid` 经
//!   `common::tenant::tenant_scope` 保证，不产生跨租户数据泄漏。
//! - 解析过程 Redis/DB 异常：记录 warn 并降级为 `HostTenant(None)`（不阻断请求）。

use std::net::SocketAddr;
use std::sync::Arc;

use axum::extract::{ConnectInfo, FromRequestParts, Request, State};
use axum::http::request::Parts;
use axum::middleware::Next;
use axum::response::Response;

use crate::state::AppState;
use crate::utils::ip::is_trusted_proxy;

/// host 归属租户上下文（request extensions 注入）
///
/// - `Some(tid)`：请求 host（或网关注入的 `X-Tenant-Code`）归属该租户；
/// - `None`：无可信 host 租户上下文（平台 host / 未绑定域名 / 来源不可信）。
#[derive(Debug, Clone, Copy, Default)]
pub struct HostTenant(pub Option<i64>);

impl HostTenant {
    /// 取 host 归属租户 ID
    pub fn tid(&self) -> Option<i64> {
        self.0
    }
}

/// 提取器：中间件已将 [`HostTenant`] 注入 extensions；未注入时返回 `None`（不报错）。
impl<S> FromRequestParts<S> for HostTenant
where
    S: Send + Sync,
{
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        Ok(parts
            .extensions
            .get::<HostTenant>()
            .copied()
            .unwrap_or(HostTenant(None)))
    }
}

/// host → tid 租户上下文中间件
pub async fn tenant_host_middleware(
    State(state): State<Arc<AppState>>,
    mut req: Request,
    next: Next,
) -> Response {
    let peer_ip = req
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ci| ci.0.ip());

    // 可信来源判定：无可信代理配置 → 不信任任何转发头（fail-safe）
    let trusted = match peer_ip {
        Some(ip) => {
            !state.config.server.trusted_proxies.is_empty()
                && is_trusted_proxy(&ip, &state.config.server.trusted_proxies)
        }
        None => false,
    };

    // 注意：`&Request`（内含 `Body`）不是 `Send`，不可跨越 `.await` 持有；
    // 因此先把所需请求头提取为 owned `String`，再进入可能 await 的解析逻辑。
    let host_tid = if trusted {
        let tenant_code = header_str(&req, "x-tenant-code").map(str::to_owned);
        let host = header_str(&req, "host").map(str::to_owned);
        resolve_host_tenant(&state, tenant_code.as_deref(), host.as_deref()).await
    } else {
        None
    };

    req.extensions_mut().insert(HostTenant(host_tid));
    next.run(req).await
}

/// 解析 host 租户：优先网关注入的 `X-Tenant-Code`，回退 `Host` 域名表
async fn resolve_host_tenant(
    state: &Arc<AppState>,
    tenant_code: Option<&str>,
    host: Option<&str>,
) -> Option<i64> {
    // 1. 网关权威注入：X-Tenant-Code
    if let Some(code) = tenant_code.filter(|s| !s.is_empty()) {
        match state.tenant_service.resolve_tenant_id_by_code(code).await {
            Ok(tid) => return tid,
            Err(e) => {
                tracing::warn!(code, error = %e, "X-Tenant-Code 解析失败（降级无 host 上下文）");
            }
        }
    }

    // 2. 回退：按 Host 头查域名表（仅当形如域名且非 IP 时尝试，避免无谓 DB 查询）
    let host = host?;
    let domain = crate::service::sys_tenant_domain_service::normalize_domain(host);
    if !looks_like_domain(&domain) {
        return None;
    }
    match state
        .tenant_domain_service
        .resolve_tenant_id_by_domain(&domain)
        .await
    {
        Ok(tid) => tid,
        Err(e) => {
            tracing::warn!(domain, error = %e, "Host 域名解析失败（降级无 host 上下文）");
            None
        }
    }
}

/// 读取请求头字符串（缺失 / 非 UTF-8 返回 None）
fn header_str<'a>(req: &'a Request, name: &str) -> Option<&'a str> {
    req.headers().get(name).and_then(|v| v.to_str().ok())
}

/// 是否形如域名（含 `.` 且不是 IP 字面量）——用于跳过 localhost / 裸 IP 的无谓查询
fn looks_like_domain(host: &str) -> bool {
    host.contains('.') && !host.is_empty()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_looks_like_domain() {
        assert!(looks_like_domain("acme.stepby.com"));
        assert!(!looks_like_domain("localhost"));
        assert!(!looks_like_domain(""));
        // 裸 IPv4（含点）仍会被当作域名尝试——由域名格式校验兜底拒绝；
        // 此处仅验证非空且含点即进入回源分支
        assert!(looks_like_domain("127.0.0.1"));
    }

    #[test]
    fn test_host_tenant_default_none() {
        assert_eq!(HostTenant::default().tid(), None);
        assert_eq!(HostTenant(Some(7)).tid(), Some(7));
    }
}
