// stepby-axum/src/common/tenant.rs
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
/// - `system:rateLimit:`：API 限流配置（**宿主级安全配置**，`sys_rate_limit` 无 `tenant_id`
///   列且限流中间件在租户解析**之前**执行 ⇒ 本质无租户维度。若授给租户，其可改/删
///   `/login`、`*`（全局默认）等规则 ⇒ **关闭全平台登录爆破防护**；导出面亦会泄漏全平台
///   路由清单。2026-09-26 复核发现并收敛）
/// - `system:tenantMenu:`：租户自建导航 L3 管理（批次 3）。**语义与 `system:tenant:domain:`
///   同类**——功能面向租户（管理的是本租户的导航结构），但**必须经能力位 `nav.l3` 才可下放**：
///   能力位关闭时若已授菜单，会形成"菜单可见但请求 403"的假入口。故登记在此（默认整面
///   不下放），由共享注册表（`governance::Item::unlocked`）在能力位开启时逐条解锁。
///
/// # 重要：本清单的准确语义
///
/// 不是"这些功能只有平台能用"，而是"**这些 perms 默认不得授予租户角色**"——它同时覆盖
/// 两类：①真正的平台专属能力（`tool:gen:` / `monitor:cache:` …）；②**面向租户但须经
/// 能力位门控才可下放**的能力（`system:tenant:domain:` / `system:tenantMenu:`，两者都由
/// 服务层按 `tenant_id` 收窄，关闭态租户一律 403）。两者共用同一套治理机制
/// （授权拒绝 / 复制剔除 / 启动治理剔除+回填）⇒ 关闭态无假入口、开启态可下放。
/// - `system:aiConfig:`：AI 配置与推理（平台侧模型凭据与全平台对话留痕，无租户维度）
/// - `monitor:alert:`：告警规则（批七十四 B3 补登记）。**请求层早已整组封平台专属**
///   （`router/monitor_alert_router.rs` 给 `/monitor/alert/*` 挂 `platform_only_guard`），
///   但注册表漏了这一族 ⇒ `is_grantable_perm` 判"可授"，而菜单 4110 又发给了 `common`
///   （新租户默认管理员的**模板源**）⇒ 租户操作者看得见"告警规则"菜单、点进去
///   `GET /monitor/alert/list` 必然 403，正是"菜单可见但请求 403"的假入口，
///   且绕开三层开关收敛（授权层放行、请求层拒绝）。
///   指标面为 cpu/mem/disk/全局登录失败（非租户维度）⇒ 真要下放须先做租户级指标采集，另立项。
pub const PLATFORM_ONLY_PERM_PREFIXES: &[&str] = &[
    "system:tenant:domain:",
    "system:tenantMenu:",
    "tool:gen:",
    "tool:httpDebug:",
    "monitor:cache:",
    "monitor:log:",
    "monitor:slowSql:",
    "monitor:health:",
    "monitor:operlogArchive:",
    "monitor:alert:",
    "system:backup:",
    "system:rateLimit:",
    "system:aiConfig:",
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
    (
        "system:dict:",
        "sys_dict_type/sys_dict_data",
        TenantFilterTier::Covered,
    ),
    ("system:notice:", "sys_notice", TenantFilterTier::Covered),
    (
        "system:msg:",
        "sys_msg_template/sys_msg_channel/sys_msg_send_log",
        TenantFilterTier::Covered,
    ),
    (
        "system:report:",
        "sys_report/sys_report_sub",
        TenantFilterTier::Covered,
    ),
    (
        "system:webHook:",
        "sys_web_hook/sys_web_hook_log",
        TenantFilterTier::Covered,
    ),
    ("system:task:", "sys_task", TenantFilterTier::Covered),
    (
        "system:flow:",
        "sys_flow_task/sys_flow_log",
        TenantFilterTier::Covered,
    ),
    (
        "flow:definition:",
        "flow_definition",
        TenantFilterTier::Covered,
    ),
    (
        "report:",
        "report_dataset/report_dashboard",
        TenantFilterTier::Covered,
    ),
    (
        "system:scimgroup:",
        "sys_scim_group",
        TenantFilterTier::Covered,
    ),
    ("system:pat:", "sys_pat", TenantFilterTier::Covered),
    ("monitor:pat:", "sys_pat", TenantFilterTier::Covered),
    (
        "monitor:job:",
        "sys_job/sys_job_log",
        TenantFilterTier::Covered,
    ),
    (
        "monitor:operlog:",
        "sys_oper_log",
        TenantFilterTier::Covered,
    ),
    (
        "monitor:logininfor:",
        "sys_logininfor",
        TenantFilterTier::Covered,
    ),
    (
        "monitor:frontendError:",
        "sys_frontend_error",
        TenantFilterTier::Covered,
    ),
    (
        "monitor:dashboard:",
        "sys_user/sys_role/sys_oper_log/sys_logininfor/redis online:*",
        TenantFilterTier::Covered,
    ),
    (
        "monitor:online:",
        "redis online:* (OnlineSession)",
        TenantFilterTier::Covered,
    ),
    (
        "system:tenant:domain:",
        "sys_tenant_domain",
        TenantFilterTier::Covered,
    ),
    (
        "system:tenant:",
        "sys_tenant/sys_tenant_package",
        TenantFilterTier::Covered,
    ),
    (
        "system:tenantMenu:",
        "sys_tenant_menu",
        TenantFilterTier::Covered,
    ),
    ("system:backup:", "sys_backup_log", TenantFilterTier::Tier2),
    // 以下三条为批七十四 B3 反向对账补登记：**判据不变，只补事实源**——
    // 三条的集合读路径早已按 `tenant_scope`/`operator_tid` 收窄（逐条实测见台账 §3.1），
    // 此前只是没写进矩阵，导致"矩阵里没有 ⇒ 归类不明"的审计盲区。
    (
        "system:dataRule:",
        "sys_data_rule",
        TenantFilterTier::Covered,
    ),
    (
        "system:audit-change:",
        "sys_audit_change",
        TenantFilterTier::Covered,
    ),
    (
        "system:oauth:client:",
        "sys_oauth_client",
        TenantFilterTier::Covered,
    ),
];

/// 查表：按最长前缀匹配返回 (承载表, 档位)（`system:tenant:domain:` 等更长前缀优先）。
pub fn tenant_filter_lookup(perms: &str) -> Option<(&'static str, TenantFilterTier)> {
    TENANT_FILTER_MATRIX
        .iter()
        .filter(|(prefix, _, _)| perms.starts_with(prefix))
        .max_by_key(|(prefix, _, _)| prefix.len())
        .map(|(_, table, tier)| (*table, *tier))
}

/// 判断 perms 是否**可授予**给租户角色/平台普通角色（原则 B 的统一判定，单一事实源）。
///
/// 不可授予的两种情况：
/// ① 平台专属能力前缀（[`is_platform_only_perm`]）——授了即"菜单可见但请求 403"；
/// ② 命中 tier2（表带 `tenant_id` 列但集合读路径未接过滤）——授了即形成跨租户读窗口。
///
/// 三条写入路径共用本判定，保证语义一致（§27.13.4）：
/// - 角色授权（用户主动授予）：[`ensure_menu_filter_coverage`] → 命中即 **拒绝**；
/// - 租户初始化复制平台角色菜单：命中即 **剔除**（否则复制即造出假入口）；
/// - 套餐变更收敛：命中即 **移除**（不只按白名单收敛）。
///
/// 平台角色（tid = 0）不在此判定范围，由调用方按 `effective_tid` 早退。
pub fn is_grantable_perm(perms: &str) -> bool {
    if is_platform_only_perm(perms) {
        return false;
    }
    !matches!(
        tenant_filter_lookup(perms),
        Some((_, TenantFilterTier::Tier2))
    )
}

/// 授予前门禁（§27.13.4）：校验待授予租户角色的 perms 是否可授予。
///
/// 返回 `Err(perms)` 即首个不可授予项，两种情况见 [`is_grantable_perm`]
/// （① 平台专属能力前缀；② 命中 tier2 表，防"先授菜单后补过滤"）。
///
/// 平台角色（operator tid = 0）不调用本门禁，由调用方按 `effective_tid` 早退。
pub fn ensure_menu_filter_coverage<'a>(
    perms_list: impl IntoIterator<Item = &'a str>,
) -> Result<(), &'a str> {
    for perms in perms_list {
        if !is_grantable_perm(perms) {
            return Err(perms);
        }
    }
    Ok(())
}

/// 构造 `perms LIKE <占位符>` 的 SQL 片段（**集中生成，禁止各调用点手拼**）。
///
/// ⚠️ **2026-09-26 事故与教训**：`initialize::ensure_tenant_role_menu_governance` 原实现只把
/// 占位符拼成 `? OR ? OR …`（**漏写 `perms LIKE`**），生成的 SQL 退化为
/// `SELECT menu_id FROM sys_menu WHERE ? OR ? OR …`——字符串常量在 SQLite 布尔上下文中恒为假
/// ⇒ 子查询返回空集 ⇒ `DELETE` 影响 0 行 ⇒ **存量库的平台专属菜单治理从未生效**（且因日志只在
/// `rows_affected() > 0` 时打印而完全静默；实测 role2 仍持 13 个平台专属菜单，含 3800/3802）。
/// 故把该片段的生成收敛到此函数，并由单测 `perms_like_clause_always_has_column` 锁死"必带列名"。
///
/// - `ph(i)`：第 i 个（**1 起**）占位符文本，由调用方按方言提供（Postgres `$i`，其余 `?`）。
pub fn perms_like_clause<F>(prefixes: &[&str], ph: F) -> String
where
    F: Fn(usize) -> String,
{
    prefixes
        .iter()
        .enumerate()
        .map(|(idx, _)| format!("perms LIKE {}", ph(idx + 1)))
        .collect::<Vec<_>>()
        .join(" OR ")
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
        assert!(
            is_platform_only_perm("monitor:cache:query"),
            "缓存监控平台专属"
        );
        assert!(
            is_platform_only_perm("system:tenant:domain:list"),
            "域名管理平台专属"
        );
        assert!(
            !is_platform_only_perm("system:tenant:list"),
            "租户管理非平台专属"
        );
        assert!(
            !is_platform_only_perm("system:config:edit"),
            "config 自助能力可下放"
        );
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
        // 2026-09-26 复核新增：限流配置为**宿主级安全配置**（表无 tenant_id、中间件早于租户
        // 解析执行），授给租户可关闭全平台 `/login` 爆破防护 ⇒ 收敛为平台专属
        for perms in [
            "system:rateLimit:list",
            "system:rateLimit:export",
            "system:rateLimit:edit",
            "system:rateLimit:remove",
        ] {
            assert!(is_platform_only_perm(perms), "{perms} 应为平台专属");
        }
        // 租户可用的看板/在线监控自助不受影响
        assert!(!is_platform_only_perm("monitor:dashboard:list"));
        assert!(!is_platform_only_perm("monitor:online:list"));
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

    #[test]
    fn test_is_grantable_perm() {
        // 业务面 perms 可授予（Covered）；空 perms（目录菜单）视为可授予
        assert!(is_grantable_perm("system:user:list"));
        assert!(is_grantable_perm("system:config:edit"));
        assert!(is_grantable_perm(""));
        // 平台专属前缀不可授予（含域名管理——2026-09-26 复核缺陷所在）
        assert!(!is_grantable_perm("tool:gen:list"));
        assert!(!is_grantable_perm("monitor:cache:query"));
        assert!(!is_grantable_perm("system:tenant:domain:add"));
        assert!(!is_grantable_perm("system:backup:list"));
        // tier2 表 perms 不可授予（备份日志集合读路径未接过滤）
        assert!(!is_grantable_perm("system:backup:query"));
        // 与门禁同源（单一事实源）：不可授予 ⇔ 门禁拒绝
        for p in [
            "system:user:list",
            "system:backup:list",
            "system:tenant:domain:list",
            "unknown:perm",
        ] {
            assert_eq!(
                is_grantable_perm(p),
                ensure_menu_filter_coverage([p]).is_ok(),
                "`{p}` 的判定应与门禁一致（同一事实源）"
            );
        }
    }

    /// §8.7-B 一致性断言（防"常量与迁移清单只改一处"再次发生）。
    ///
    /// 背景：2026-09-26 复核实证 —— `m20260926_000002`（硬编码菜单 ID）与
    /// `m20260926_000005`（5 项前缀）**都不含 `system:tenant:domain:`**，导致走迁移的
    /// 新库中平台普通角色仍持有菜单 3800/3802（域名查询/验证）⇒ 假入口。
    /// 修复 = 新增 `m20260926_000006`（按完整 8 项前缀全量剔除）；本测试锁死该一致性。
    ///
    /// 2026-09-26 第二批：新增 `system:rateLimit:` ⇒ 令 **最新**全量迁移（`m000007`，9 项）
    /// 承担"常量全量"断言，历史迁移只断言"其项仍在常量中（未被删）"。
    /// 2026-09-26 第三批（批次 3）：新增 `system:tenantMenu:` ⇒ 最新全量迁移推进到
    /// `m20260926_000013`（10 项），`m000007` 随之降级为"历史迁移"。
    /// **约束**：今后每新增一个平台专属前缀，都必须同步开一个新迁移（含完整清单），
    /// 否则本测试失败 ⇒ 新库路径不会漏剔。
    ///
    /// `include_str!` 在编译期嵌入源码文本 ⇒ 路径错误即刻暴露，且无运行时 IO。
    #[test]
    fn platform_only_prefixes_match_migration_lists() {
        // 最新全量治理点（必须含**全部**平台专属前缀）
        // 批七十四 B3：新增 `monitor:alert:` ⇒ 最新全量迁移推进到
        // `m20261017_000002_platform_only_alert`（13 项），`m000001` 随之降级为历史迁移。
        const LATEST_SRC: &str =
            include_str!("../../migration/src/migrations/m20261017_000002_platform_only_alert.rs");
        // 历史迁移（其项必须仍在常量中，防"常量删了但迁移还留着"的漂移）
        const M000001_SRC: &str =
            include_str!("../../migration/src/migrations/m20261008_000001_log_archive_anchor.rs");
        const M000013_SRC: &str = include_str!(
            "../../migration/src/migrations/m20260926_000013_platform_only_tenant_menu.rs"
        );
        const M000007_SRC: &str = include_str!(
            "../../migration/src/migrations/m20260926_000007_platform_only_ratelimit.rs"
        );
        const M000006_SRC: &str = include_str!(
            "../../migration/src/migrations/m20260926_000006_platform_only_prefix_full.rs"
        );
        const M000005_SRC: &str = include_str!(
            "../../migration/src/migrations/m20260926_000005_platform_only_prefix_governance.rs"
        );

        // ① 常量每一项都必须出现在**最新**迁移清单中
        for p in PLATFORM_ONLY_PERM_PREFIXES {
            assert!(
                LATEST_SRC.contains(p),
                "平台专属前缀 `{p}` 未出现在最新迁移清单（LATEST_SRC = \
                 m20261017_000002_platform_only_alert）—— 新增前缀必须同步开一个携带\
                 完整清单的新迁移并把 LATEST_SRC 推进过去，否则走迁移的新库不会剔除\
                 对应菜单（假入口）"
            );
        }
        // ①' 历史迁移 m000001（批次十九，12 项）的项必须都还在常量中
        for p in [
            "system:tenant:domain:",
            "system:tenantMenu:",
            "tool:gen:",
            "tool:httpDebug:",
            "monitor:cache:",
            "monitor:log:",
            "monitor:slowSql:",
            "monitor:health:",
            "monitor:operlogArchive:",
            "system:backup:",
            "system:rateLimit:",
            "system:aiConfig:",
        ] {
            assert!(M000001_SRC.contains(p), "m000001 清单项 `{p}` 丢失");
            assert!(
                PLATFORM_ONLY_PERM_PREFIXES.contains(&p),
                "m000001 使用了未在 PLATFORM_ONLY_PERM_PREFIXES 声明的前缀 `{p}`"
            );
        }
        // ①' 历史迁移 m000013（11 项）的项必须都还在常量中
        for p in [
            "system:tenant:domain:",
            "system:tenantMenu:",
            "tool:gen:",
            "tool:httpDebug:",
            "monitor:cache:",
            "monitor:log:",
            "monitor:slowSql:",
            "monitor:health:",
            "system:backup:",
            "system:rateLimit:",
            "system:aiConfig:",
        ] {
            assert!(M000013_SRC.contains(p), "m000013 清单项 `{p}` 丢失");
            assert!(
                PLATFORM_ONLY_PERM_PREFIXES.contains(&p),
                "m000013 使用了未在 PLATFORM_ONLY_PERM_PREFIXES 声明的前缀 `{p}`"
            );
        }
        // ①' 历史迁移 m000007（9 项）的项必须都还在常量中
        for p in [
            "system:tenant:domain:",
            "tool:gen:",
            "tool:httpDebug:",
            "monitor:cache:",
            "monitor:log:",
            "monitor:slowSql:",
            "monitor:health:",
            "system:backup:",
            "system:rateLimit:",
        ] {
            assert!(M000007_SRC.contains(p), "m000007 清单项 `{p}` 丢失");
            assert!(
                PLATFORM_ONLY_PERM_PREFIXES.contains(&p),
                "m000007 使用了未在 PLATFORM_ONLY_PERM_PREFIXES 声明的前缀 `{p}`"
            );
        }
        // ② 历史迁移（m000006，8 项）的项必须都还在常量中
        for p in [
            "system:tenant:domain:",
            "tool:gen:",
            "tool:httpDebug:",
            "monitor:cache:",
            "monitor:log:",
            "monitor:slowSql:",
            "monitor:health:",
            "system:backup:",
        ] {
            assert!(M000006_SRC.contains(p), "m000006 清单项 `{p}` 丢失");
            assert!(
                PLATFORM_ONLY_PERM_PREFIXES.contains(&p),
                "m000006 使用了未在 PLATFORM_ONLY_PERM_PREFIXES 声明的前缀 `{p}`"
            );
        }
        // ③ m000005 的清单项必须都在常量中（迁移不得使用未声明的前缀）
        for p in [
            "tool:httpDebug:",
            "monitor:log:",
            "monitor:slowSql:",
            "monitor:health:",
            "system:backup:",
        ] {
            assert!(M000005_SRC.contains(p), "m000005 清单项 `{p}` 丢失");
            assert!(
                PLATFORM_ONLY_PERM_PREFIXES.contains(&p),
                "m000005 使用了未在 PLATFORM_ONLY_PERM_PREFIXES 声明的前缀 `{p}`"
            );
        }
    }

    /// 2026-09-26 事故回归防线：LIKE 片段**必须**带 `perms LIKE` 列名。
    ///
    /// 原 `initialize` 实现只把占位符拼成 `? OR ? …`，使 SQL 退化为
    /// `WHERE ? OR ? …`（字符串常量作布尔值恒假）⇒ 子查询空集 ⇒ DELETE 0 行 ⇒
    /// **存量库治理静默失效**。本单测锁死"列名存在 + 条件条数与前缀数一致 + 方言占位符编号"。
    #[test]
    fn perms_like_clause_always_has_column() {
        let clause = perms_like_clause(PLATFORM_ONLY_PERM_PREFIXES, |_| "?".to_string());
        assert!(
            clause.contains("perms LIKE"),
            "LIKE 片段必须带列名，否则 `WHERE ? OR ?` 恒为假、治理静默失效"
        );
        assert_eq!(
            clause.matches("perms LIKE").count(),
            PLATFORM_ONLY_PERM_PREFIXES.len(),
            "每个平台专属前缀都要有独立的 LIKE 条件"
        );
        assert_eq!(
            clause.matches('?').count(),
            PLATFORM_ONLY_PERM_PREFIXES.len(),
            "占位符个数应与前缀数一致"
        );
        // Postgres 方言：占位符按 1 起编号
        assert_eq!(
            perms_like_clause(&["tool:gen:"], |i| format!("${i}")),
            "perms LIKE $1"
        );
        // 空前缀集：产出空串（调用方不应据此拼出非法 SQL）
        assert_eq!(perms_like_clause(&[], |_| "?".to_string()), "");
    }

    // ============ 批七十四 B3：矩阵 ↔ 台账文档 **双向**对账锁 ============
    //
    // `TENANT_FILTER_MATRIX` 的文档注释一直声称"与 tier2-filter-matrix-2026-09-25.md
    // 同步维护（单测保证双向一致）"，但全仓**没有**这条单测（本轮实测：该常量的消费点
    // 只有 `features.rs` 的 tier2 判定与本文件的查表函数）。属"注释声明了一条不存在的锁"——
    // 读者会以为漂移会被 CI 拦住，实际不会。本锁补齐该承诺。
    //
    // 对账口径：**前缀集合 ⊆ 双向 + 档位逐条一致**。承载表/接入点两列不参与
    // （代码里是 `sys_dict_type/sys_dict_data`，文档写成 `sys_dict_type / sys_dict_data`
    // 且夹带中文说明——散文格式强判必然漂，那不是契约）。
    #[test]
    fn matrix_matches_ledger_doc() {
        let doc = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../docs/optimization/tier2-filter-matrix-2026-09-25.md");
        let text = std::fs::read_to_string(&doc)
            .unwrap_or_else(|e| panic!("读取矩阵台账 {} 失败: {e}", doc.display()));
        let start = text
            .find("## 2. 矩阵")
            .expect("台账文档缺少「## 2. 矩阵」小节 ⇒ 对账面无从定位（不是通过）");
        let end = text[start..]
            .find("## 3. ")
            .map(|i| start + i)
            .expect("台账文档「## 2」之后没有「## 3」⇒ 小节边界无法确定（不是通过）");
        let seg = &text[start..end];

        // 文档行：| `prefix` | 承载表 | 档位 | 接入点 |
        // 一个单元格可并写多个前缀（`system:pat:/monitor:pat:`），按 '/' 拆分后逐个收。
        let mut doc_rows: Vec<(String, String)> = Vec::new();
        for line in seg.lines() {
            let line = line.trim();
            if !line.starts_with('|') || line.contains("perms 前缀") || line.contains("---") {
                continue;
            }
            let cells: Vec<&str> = line.split('|').map(|c| c.trim()).collect();
            if cells.len() < 4 {
                continue;
            }
            let tier = cells[3].replace('*', "").trim().to_string();
            if tier != "Covered" && tier != "Tier2" {
                continue; // 非矩阵行（说明段/表头残留）
            }
            for token in cells[1].split('/') {
                let prefix = token.trim().trim_matches('`').trim().to_string();
                if prefix.ends_with(':') && prefix.contains(':') {
                    doc_rows.push((prefix, tier.clone()));
                }
            }
        }

        // 控制组：两侧都必须**真看见**内容，否则本锁退化成"0 == 0"的虚锁。
        assert!(
            doc_rows.len() >= 25,
            "台账文档 §2 表格只解析出 {} 行 ⇒ 文档格式变了或小节定位失效，对账没有真跑",
            doc_rows.len()
        );
        assert!(
            TENANT_FILTER_MATRIX.len() >= 25,
            "代码矩阵仅 {} 条 ⇒ 与本批实测基线不符，请先核对常量是否被误删",
            TENANT_FILTER_MATRIX.len()
        );

        let mut only_in_doc: Vec<String> = Vec::new();
        let mut tier_mismatch: Vec<String> = Vec::new();
        for (prefix, doc_tier) in &doc_rows {
            match TENANT_FILTER_MATRIX
                .iter()
                .find(|(p, _, _)| *p == prefix.as_str())
            {
                None => only_in_doc.push(prefix.clone()),
                Some((_, _, tier)) => {
                    let code_tier = match tier {
                        TenantFilterTier::Covered => "Covered",
                        TenantFilterTier::Tier2 => "Tier2",
                    };
                    if code_tier != *doc_tier {
                        tier_mismatch.push(format!("{prefix}: 文档={doc_tier} 代码={code_tier}"));
                    }
                }
            }
        }
        let only_in_code: Vec<&str> = TENANT_FILTER_MATRIX
            .iter()
            .filter(|(p, _, _)| !doc_rows.iter().any(|(dp, _)| dp == p))
            .map(|(p, _, _)| *p)
            .collect();

        assert!(
            only_in_doc.is_empty(),
            "台账文档有、代码矩阵无：{only_in_doc:?} ⇒ 文档声称已接入，事实源没有（必须二选一定性）"
        );
        assert!(
            only_in_code.is_empty(),
            "代码矩阵有、台账文档无：{only_in_code:?} ⇒ 新增前缀未同步文档（AGENTS 开关规范⑥）"
        );
        assert!(
            tier_mismatch.is_empty(),
            "档位两侧不一致：{tier_mismatch:?}"
        );
    }

    /// 反向锁：矩阵里**每一条**前缀都必须能被 `tenant_filter_lookup` 按最长前缀命中自身
    /// （防止出现"更长前缀把短前缀吃掉"导致 tier2 判定失效——`system:tenant:` 与
    /// `system:tenant:domain:` 同挂时，后者必须胜出）。
    #[test]
    fn matrix_lookup_prefers_longest_prefix() {
        for (prefix, table, tier) in TENANT_FILTER_MATRIX {
            let (hit_table, hit_tier) = tenant_filter_lookup(prefix)
                .unwrap_or_else(|| panic!("{prefix} 查表落空 ⇒ 自身前缀都不命中，判据失效"));
            assert_eq!(
                (hit_table, hit_tier),
                (*table, *tier),
                "{prefix} 被更长前缀抢占或档位漂移（矩阵内部前缀包含关系已改变 tier2 判定）"
            );
        }
    }

    /// 平台专属注册表与矩阵的**交集必须有明确语义**：登记为平台专属的前缀若同时出现在
    /// 矩阵中，必须是 Tier2 或被能力位解锁清单覆盖的部分下放前缀（`system:backup:`），
    /// 否则等于两处各说各话。
    #[test]
    fn platform_only_registry_and_matrix_agree() {
        let overlapping: Vec<&str> = PLATFORM_ONLY_PERM_PREFIXES
            .iter()
            .copied()
            .filter(|p| TENANT_FILTER_MATRIX.iter().any(|(mp, _, _)| mp == p))
            .collect();
        // 本轮实测交集：`system:tenant:domain:` / `system:tenantMenu:`（Covered，服务层已按
        // tenant_scope 收窄，但默认整面不下放）与 `system:backup:`（Tier2）。
        // 交集**允许存在**（下放与否由能力位决定，与"表是否接过滤"正交），
        // 但必须逐条在册——新增交集项未审视即红，逼后来者定性。
        const ALLOWED: [&str; 3] = [
            "system:tenant:domain:",
            "system:tenantMenu:",
            "system:backup:",
        ];
        for p in &overlapping {
            assert!(
                ALLOWED.contains(p),
                "平台专属前缀 {p} 新落入矩阵交集，需先定性：它是「表已接租户过滤但默认不下放」\
                 还是「tier2 未接」？两者在授权层的语义不同，不得默认并存"
            );
        }
    }
}
