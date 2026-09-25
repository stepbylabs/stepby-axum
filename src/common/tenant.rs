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

// ==================== Phase 3：租户运行时状态（会话吊销/到期三态）====================
//
// 设计（§27.4）：**不**在 JWT 中新增租户版本声明，而是把租户生命周期状态投影为
// 两个 Redis 运行时键，由鉴权中间件逐请求求值：
// - `tenant:state:{tid}`：`'0'` 正常 / `'1'` 宽限只读 / `'2'` 停用；
// - `tenant:exp:{tid}`：到期 UTC 秒（`'0'` = 永不过期）。
//
// 收益：① 存量 JWT 无需改结构即随租户停用/删除立即失效；
// ② 天然支持「宽限期只读」这一非二值状态；③ 平台租户（tid=0）零开销（不读写键）。

/// `tenant:state:{tid}` 取值：正常
pub const TENANT_STATE_ACTIVE: &str = "0";
/// `tenant:state:{tid}` 取值：宽限期只读（已到期但仍在宽限期内）
pub const TENANT_STATE_GRACE: &str = "1";
/// `tenant:state:{tid}` 取值：停用（或超期出宽限期）
pub const TENANT_STATE_DISABLED: &str = "2";

/// 到期宽限天数（到期后仅读、可续费；超出即停用）
pub const TENANT_EXPIRE_GRACE_DAYS: i64 = 7;

/// `tenant:state:{tid}` 键名（运行时状态）
pub fn tenant_state_key(tid: i64) -> String {
    format!("tenant:state:{}", tid)
}

/// `tenant:exp:{tid}` 键名（到期 UTC 秒，0 = 永不过期）
pub fn tenant_expire_key(tid: i64) -> String {
    format!("tenant:exp:{}", tid)
}

/// 租户运行时状态（鉴权中间件逐请求判定结果）
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TenantRuntimeState {
    /// 正常：放行全部请求
    Active,
    /// 宽限只读：放行读请求，拒绝写请求
    Grace,
    /// 停用/超期：拒绝全部请求
    Disabled,
}

/// 求值租户运行时状态（纯函数，便于单测；键缺失时视为 Active——
/// 事实源仍是库表，登录闸门与任何租户变更都会重写这两个键）。
///
/// - `state_raw`：`tenant:state:{tid}` 的值（None = 键不存在）；
/// - `expire_epoch`：`tenant:exp:{tid}` 的值（0 = 永不过期）；
/// - `now_epoch`：当前 UTC 秒。
pub fn eval_tenant_runtime_state(
    state_raw: Option<&str>,
    expire_epoch: i64,
    now_epoch: i64,
) -> TenantRuntimeState {
    if state_raw == Some(TENANT_STATE_DISABLED) {
        return TenantRuntimeState::Disabled;
    }
    if expire_epoch > 0 {
        let grace_secs = TENANT_EXPIRE_GRACE_DAYS * 24 * 3600;
        if now_epoch >= expire_epoch + grace_secs {
            return TenantRuntimeState::Disabled;
        }
        if now_epoch >= expire_epoch {
            return TenantRuntimeState::Grace;
        }
        return TenantRuntimeState::Active;
    }
    if state_raw == Some(TENANT_STATE_GRACE) {
        return TenantRuntimeState::Grace;
    }
    TenantRuntimeState::Active
}

/// 归属校验：operator_tid 为 0（平台管理员）放行任意资源；否则资源必须属于
/// 同一租户。用于按主键操作（update/delete/toggle）前的越权防护。
pub fn tenant_allowed(operator_tid: i64, resource_tid: i64) -> bool {
    operator_tid == 0 || operator_tid == resource_tid
}

/// 按 tenant_id 分组（升序），供后台批量任务"逐组带 tid 上下文执行"。
///
/// 语义：后台任务（WebHook 事件分发 / 报表订阅推送等）**不得**跨租户批量触达，
/// 必须先按租户分组，再对每一组以该组 tid 为上下文独立执行（生成/投递上下文携带该组 tid）。
pub fn group_by_tenant<T>(items: Vec<T>, key: impl Fn(&T) -> i64) -> Vec<(i64, Vec<T>)> {
    let mut map: std::collections::BTreeMap<i64, Vec<T>> = std::collections::BTreeMap::new();
    for item in items {
        let tid = key(&item);
        map.entry(tid).or_default().push(item);
    }
    map.into_iter().collect()
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

    #[test]
    fn test_eval_tenant_runtime_state() {
        // 键缺失 → Active（事实源为库表）
        assert_eq!(
            eval_tenant_runtime_state(None, 0, 1_000),
            TenantRuntimeState::Active
        );
        // 显式停用 → Disabled（无视到期时间）
        assert_eq!(
            eval_tenant_runtime_state(Some(TENANT_STATE_DISABLED), 0, 1_000),
            TenantRuntimeState::Disabled
        );
        // 到期前 → Active；到期后宽限期内 → Grace；超宽限 → Disabled
        assert_eq!(
            eval_tenant_runtime_state(Some(TENANT_STATE_ACTIVE), 2_000, 1_000),
            TenantRuntimeState::Active
        );
        assert_eq!(
            eval_tenant_runtime_state(Some(TENANT_STATE_ACTIVE), 1_000, 1_000),
            TenantRuntimeState::Grace,
            "到达到期时刻即进入宽限只读"
        );
        let beyond = 1_000 + TENANT_EXPIRE_GRACE_DAYS * 24 * 3600;
        assert_eq!(
            eval_tenant_runtime_state(Some(TENANT_STATE_GRACE), 1_000, beyond),
            TenantRuntimeState::Disabled,
            "超出宽限期必须停用"
        );
        // 无到期时间但状态位为宽限（理论不出现，兜底为 Grace）
        assert_eq!(
            eval_tenant_runtime_state(Some(TENANT_STATE_GRACE), 0, 1_000),
            TenantRuntimeState::Grace
        );
    }

    #[test]
    fn test_tenant_runtime_keys() {
        assert_eq!(tenant_state_key(9), "tenant:state:9");
        assert_eq!(tenant_expire_key(9), "tenant:exp:9");
    }
}
