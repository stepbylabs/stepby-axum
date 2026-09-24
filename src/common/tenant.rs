// axum-backend/src/common/tenant.rs
//! v5-N2 Phase 2：多租户过滤基建。
//!
//! 语义约定（Phase 2 立项默认规则，随实现固化）：
//! - `tid = 0`：平台租户/平台管理员 —— **不过滤**（全量可见，含各租户数据）；
//! - `tid != 0`：租户管理员/租户用户 —— **仅本租户**（读过滤 + 写归属校验）。
//!
//! 单租户现状（所有数据 tid=0、所有用户 tid=0）下行为完全等价，立项后无需
//! 再改过滤规则，只需租户管理功能维护 sys_user.tenant_id 与数据归属。

/// 计算租户过滤值：返回 Some(tid) 表示查询需附加 `tenant_id = tid` 条件；
/// None 表示平台管理员（tid=0）不过滤。
pub fn tenant_scope(tid: i64) -> Option<i64> {
    (tid != 0).then_some(tid)
}

/// 归属校验：operator_tid 为 0（平台管理员）放行任意资源；否则资源必须属于
/// 同一租户。用于按主键操作（update/delete/toggle）前的越权防护。
pub fn tenant_allowed(operator_tid: i64, resource_tid: i64) -> bool {
    operator_tid == 0 || operator_tid == resource_tid
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tenant_scope() {
        assert_eq!(tenant_scope(0), None, "平台管理员不过滤");
        assert_eq!(tenant_scope(5), Some(5), "租户用户按 tid 过滤");
    }

    #[test]
    fn test_tenant_allowed() {
        assert!(tenant_allowed(0, 7), "平台管理员可操作任意租户资源");
        assert!(tenant_allowed(5, 5), "本租户资源可操作");
        assert!(!tenant_allowed(5, 7), "跨租户资源拒绝");
    }
}
