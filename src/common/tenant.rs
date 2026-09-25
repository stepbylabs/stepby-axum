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

/// 平台专属能力 perms 前缀（台账 §3.1 原则 B：平台能力不进租户可授集合）。
///
/// 语义：这些 perms 对应的功能仅平台操作者可用（handler 层另有平台守卫兜底），
/// 因此**不得**随平台普通角色继承或经套餐白名单下放给租户角色，否则形成
/// "菜单可见但请求一律 403"的假入口，或造成跨租户可观测/枚举面（如
/// `/tool/gen/db/list` 可枚举全库表名、`/monitor/cache/*` 可读跨租户会话元数据）。
///
/// - `system:tenant:domain:`：租户域名管理（服务层对租户一律 403）
/// - `tool:gen:`：代码生成（开发期工具，平台专属）
/// - `tool:httpDebug:`：HTTP 调试器（服务端代理发起任意请求，SSRF 面，平台专属）
/// - `monitor:cache:`：缓存监控（平台运维面，含跨租户键名与会话元数据）
/// - `monitor:log:`：实时日志（宿主应用日志，含全平台请求/SQL 日志）
/// - `monitor:slowSql:`：可观测性（慢请求/错误聚合/Redis 指标，跨租户聚合）
/// - `monitor:health:`：健康检查（DB/Redis/磁盘等宿主依赖状态，无租户语义）
/// - `system:backup:`：备份管理（整库 pg_dump/mysqldump 与恢复覆盖现库，
///   下载面即全库数据 ⇒ 授给租户等于跨租户数据外泄；租户级备份粒度见 §27.12-5 待决）
pub const PLATFORM_ONLY_PERM_PREFIXES: &[&str] = &[
    "system:tenant:domain:",
    "tool:gen:",
    "tool:httpDebug:",
    "monitor:cache:",
    "monitor:log:",
    "monitor:slowSql:",
    "monitor:health:",
    "system:backup:",
];

/// 判断 perms 是否属于平台专属能力（前缀匹配，大小写敏感——perms 统一小写）
pub fn is_platform_only_perm(perms: &str) -> bool {
    PLATFORM_ONLY_PERM_PREFIXES
        .iter()
        .any(|p| perms.starts_with(p))
}

/// 归属校验：operator_tid 为 0（平台管理员）放行任意资源；否则资源必须属于
/// 同一租户。用于按主键操作（update/delete/toggle）前的越权防护。
pub fn tenant_allowed(operator_tid: i64, resource_tid: i64) -> bool {
    operator_tid == 0 || operator_tid == resource_tid
}

// ==================== §27.13.1/§27.13.4「表 → 过滤接入」矩阵与授予前门禁 ====================

/// 租户表读路径的过滤接入档位（§27.13.1 矩阵的代码侧登记口径）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TenantFilterTier {
    /// 已接：列表/分页等集合读路径带租户过滤（或按主体键精确收窄，语义等价）。
    Covered,
    /// 未接：表带 `tenant_id` 列但集合读路径未过滤 ⇒ 其 perms **不得**授予租户角色，
    /// 否则形成"先授菜单后补过滤"的跨租户读窗口。
    Tier2,
}

/// perms 前缀 → (承载表, 档位)。与
/// `docs/optimization/tier2-filter-matrix-2026-09-25.md` 同步维护（单测保证双向一致）。
///
/// 说明：仅登记"有菜单面（可由角色授权触达）"的租户表；无菜单面的表
/// （`sys_oauth_consent` / `sys_oauth_user` / `sys_user_pref` 等，仅按主体键查询）
/// 见矩阵文档"按主体键收窄"一节。
pub const TENANT_FILTER_MATRIX: &[(&str, &str, TenantFilterTier)] = &[
    ("system:user:", "sys_user", TenantFilterTier::Covered),
    ("system:dept:", "sys_dept", TenantFilterTier::Covered),
    ("system:role:", "sys_role", TenantFilterTier::Covered),
    ("system:post:", "sys_post", TenantFilterTier::Covered),
    ("system:config:", "sys_config", TenantFilterTier::Covered),
    ("system:dict:", "sys_dict_type/sys_dict_data", TenantFilterTier::Covered),
    ("system:notice:", "sys_notice", TenantFilterTier::Covered),
    ("system:msg:", "sys_msg_template/sys_msg_channel/sys_msg_send_log", TenantFilterTier::Covered),
    ("system:report:", "sys_report/sys_report_sub", TenantFilterTier::Covered),
    ("system:webHook:", "sys_web_hook/sys_web_hook_log", TenantFilterTier::Covered),
    ("system:task:", "sys_task", TenantFilterTier::Covered),
    ("system:flow:", "sys_flow_task/sys_flow_log", TenantFilterTier::Covered),
    ("system:scimgroup:", "sys_scim_group", TenantFilterTier::Covered),
    ("system:pat:", "sys_pat", TenantFilterTier::Covered),
    ("monitor:pat:", "sys_pat", TenantFilterTier::Covered),
    ("monitor:job:", "sys_job/sys_job_log", TenantFilterTier::Covered),
    ("monitor:operlog:", "sys_oper_log", TenantFilterTier::Covered),
    ("monitor:logininfor:", "sys_logininfor", TenantFilterTier::Covered),
    ("monitor:frontendError:", "sys_frontend_error", TenantFilterTier::Covered),
    ("monitor:dashboard:", "sys_user/sys_role/sys_oper_log/sys_logininfor/redis online:*", TenantFilterTier::Covered),
    ("monitor:online:", "redis online:* (OnlineSession)", TenantFilterTier::Covered),
    ("system:tenant:", "sys_tenant/sys_tenant_package", TenantFilterTier::Covered),
    ("system:backup:", "sys_backup_log", TenantFilterTier::Tier2),
];

/// 查表：按最长前缀匹配返回 (承载表, 档位)（`system:tenant:domain:` 等更长前缀优先）。
pub fn tenant_filter_lookup(perms: &str) -> Option<(&'static str, TenantFilterTier)> {
    TENANT_FILTER_MATRIX
        .iter()
        .filter(|(prefix, _, _)| perms.starts_with(prefix))
        .max_by_key(|(prefix, _, _)| prefix.len())
        .map(|(_, table, tier)| (*table, *tier))
}

/// 授予前门禁（§27.13.4）：校验待授予租户角色的 perms 是否可授予。
///
/// 返回 `Err(perms)` 的两种情况：
/// ① 平台专属能力前缀（`is_platform_only_perm`）；
/// ② 命中 tier2（有 `tenant_id` 列但集合读路径未接过滤）表，防"先授菜单后补过滤"。
///
/// 平台角色（operator tid = 0）不调用本门禁，由调用方按 `effective_tid` 早退。
pub fn ensure_menu_filter_coverage<'a>(
    perms_list: impl IntoIterator<Item = &'a str>,
) -> Result<(), &'a str> {
    for perms in perms_list {
        if is_platform_only_perm(perms) {
            return Err(perms);
        }
        if matches!(
            tenant_filter_lookup(perms),
            Some((_, TenantFilterTier::Tier2))
        ) {
            return Err(perms);
        }
    }
    Ok(())
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

    #[test]
    fn test_is_platform_only_perm() {
        assert!(is_platform_only_perm("tool:gen:list"), "代码生成平台专属");
        assert!(is_platform_only_perm("monitor:cache:query"), "缓存监控平台专属");
        assert!(is_platform_only_perm("system:tenant:domain:list"), "域名管理平台专属");
        assert!(!is_platform_only_perm("system:tenant:list"), "租户管理非平台专属");
        assert!(!is_platform_only_perm("system:config:edit"), "config 自助能力可下放");
        assert!(!is_platform_only_perm(""), "空 perms 非平台专属");
    }

    #[test]
    fn test_is_platform_only_perm_batch_p2_4() {
        // P2-4 新增前缀：跨租户可观测面 / 整库备份面 / SSRF 面
        for perms in [
            "tool:httpDebug:list",
            "monitor:log:list",
            "monitor:slowSql:list",
            "monitor:health:list",
            "system:backup:list",
            "system:backup:query",
            "system:backup:add",
            "system:backup:remove",
            "system:backup:edit",
        ] {
            assert!(is_platform_only_perm(perms), "{perms} 应为平台专属");
        }
        // 租户可用的看板/在线监控/限流自助不受影响
        assert!(!is_platform_only_perm("monitor:dashboard:list"));
        assert!(!is_platform_only_perm("monitor:online:list"));
        assert!(!is_platform_only_perm("system:rateLimit:list"));
    }

    #[test]
    fn test_tenant_filter_lookup() {
        assert_eq!(
            tenant_filter_lookup("system:user:list").map(|(_, t)| t),
            Some(TenantFilterTier::Covered)
        );
        assert_eq!(
            tenant_filter_lookup("monitor:online:list").map(|(_, t)| t),
            Some(TenantFilterTier::Covered)
        );
        assert_eq!(
            tenant_filter_lookup("system:backup:query").map(|(_, t)| t),
            Some(TenantFilterTier::Tier2),
            "备份日志集合读路径未接过滤 ⇒ tier2"
        );
        assert_eq!(
            tenant_filter_lookup("unknown:perm").map(|(_, t)| t),
            None,
            "未登记前缀（如第三方/新模块）不触发门禁"
        );
    }

    #[test]
    fn test_ensure_menu_filter_coverage() {
        // Covered 能力放行
        assert!(ensure_menu_filter_coverage(["system:user:list", "system:config:edit"]).is_ok());
        // 平台专属拦截（返回首个不可授予 perms）
        assert_eq!(
            ensure_menu_filter_coverage(["system:user:list", "system:backup:list"]),
            Err("system:backup:list")
        );
        assert_eq!(
            ensure_menu_filter_coverage(["tool:gen:list"]),
            Err("tool:gen:list")
        );
        // 空集合放行（目录菜单无 perms 的场景）
        assert!(ensure_menu_filter_coverage(Vec::<&str>::new()).is_ok());
    }
}
