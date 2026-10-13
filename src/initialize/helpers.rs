// stepby-axum/src/initialize/helpers.rs

use crate::config::Settings;
use crate::config::settings::{CacheMode, RateLimitMode};
use sea_orm::{DatabaseBackend, DatabaseConnection};

/// §4.2 分级守卫：共享态档位与部署形态不匹配时的启动期告警（只告警不阻断）。
///
/// - local + `scheduler.replicas > 1`：SQLite 单写者（max_connections=1）高并发写会 busy 等待
///   ⇒ **WARN**；MySQL/PG 天然共享 ⇒ INFO（提示 WS 定向消息仍为单实例语义）。
/// - local + `scheduler.cluster_mode = "leader"`：整轮互斥走 `sys_shared_lock` CAS，语义成立 ⇒ INFO。
/// - 显式 `mode = "local"` 但 `[redis].url` 有效：Redis 配置被忽略 ⇒ **WARN**（防"配了不生效"误解）。
pub(crate) fn init_cache_mode_guards(
    db: &DatabaseConnection,
    settings: &Settings,
    mode: CacheMode,
) {
    if mode == CacheMode::Local {
        let replicas = settings.scheduler.replicas;
        let cluster_mode = settings.scheduler.cluster_mode.trim().to_ascii_lowercase();
        if replicas > 1 {
            match db.get_database_backend() {
                DatabaseBackend::Sqlite => tracing::warn!(
                    "local 档 + SQLite + 多实例：SQLite 为单写者（max_connections=1），\
                     高并发写将触发 busy 等待；建议切换 MySQL/PostgreSQL 或配置 [redis] 启用 redis 档"
                ),
                _ => tracing::info!(
                    "local 档（DB 共享）可支撑多实例；注意 WS 定向消息仅本实例可见（既有单实例语义）"
                ),
            }
        }
        if cluster_mode == "leader" {
            tracing::info!(
                "local 档 + scheduler.cluster_mode = leader：内置任务整轮互斥走 sys_shared_lock CAS，语义成立"
            );
        }
    }
    // 显式 local（原值小写比对，非法值/缺省不触发）但 Redis url 有效 ⇒ WARN
    if settings.cache.is_explicit_mode("local") {
        let url = &settings.redis.url;
        if !url.trim().is_empty() && !url.contains("CHANGE_ME") {
            tracing::warn!(
                "Redis 配置被忽略（cache.mode=local）；如需 redis 档请改 mode 为 auto/redis"
            );
        }
    }
}

/// 多实例部署 + 限流档位不匹配的启动期自检（只告警不阻断；返回是否命中，便于单测证伪）。
///
/// 语义与 WF-2（`[scheduler].replicas` + `cluster_mode = "auto"`，见 `scheduler/mod.rs`）
/// 与 §4.2（`[cache].mode = "local"` + 多实例，见 [`init_cache_mode_guards`]）**同源**：
/// `[rate_limit].mode = "local"`（默认）是**进程内**令牌桶，多副本时各实例独立计数，
/// 攻击者轮询不同副本即可把配额放大 N 倍（长期登记的 **M-8** 限制）。
///
/// `replicas` 由部署方如实声明（默认 `1`）——`replicas > 1` 且档位仍为 `local` ⇒ 打 **WARN**
/// （拒绝静默放大，与"放开必有守卫 / 拒绝静默失效"准则一致）；`replicas <= 1`（默认）⇒
/// 不触发，对存量单实例部署**零行为变更**（缺省值 = 现状 = 安全态）。
///
/// 修复指引：多实例部署置 `[rate_limit].mode = "redis"`（或环境变量 `RATE_LIMIT_MODE=redis`），
/// 由 Redis 分布式令牌桶共享同一配额；Redis 命令失败时 fail-closed 返回 503。
pub(crate) fn init_rate_limit_guards(settings: &Settings) -> bool {
    if rate_limit_local_multi_instance_misconfigured(
        settings.scheduler.replicas,
        settings.rate_limit.mode(),
    ) {
        tracing::warn!(
            replicas = settings.scheduler.replicas,
            "[rate_limit].mode = local 但 [scheduler].replicas > 1：进程内令牌桶各副本独立计数，\
             攻击者轮询不同副本即可把配额放大 N 倍（M-8）⇒ 多实例部署请置 \
             [rate_limit].mode = \"redis\"（或环境变量 RATE_LIMIT_MODE=redis）"
        );
        return true;
    }
    false
}

/// 纯判定（可单测证伪）：多副本 + `local` 档 = 限流配额可被放大 N 倍。
///
/// 抽为纯函数的原因与 `tenant_host_chain_self_check` 一致——"只写日志的检查无法证伪"，
/// 判定与副作用分离后可用单测锁住四象限（单实例/多实例 × local/redis）。
pub(crate) fn rate_limit_local_multi_instance_misconfigured(
    replicas: u32,
    mode: RateLimitMode,
) -> bool {
    replicas > 1 && mode == RateLimitMode::Local
}

///
/// 治理意义与 `[acme]` / `[events]` 同源：能力位是"放开登录面能力"的唯一入口，
/// 且 `rp_id` / `origin` 是 WebAuthn 的**信任锚**，配错即认证恒失败。故：
/// - 能力位 `off`（默认）⇒ 打 INFO（端点表现为 404，不暴露"存在但被关"）；
/// - 能力位 `on` 且解析出有效 `rp_id` / `origin` ⇒ 打 INFO 列出实际信任锚；
/// - 能力位 `on` 但 `rp_id` / `origin` 未配置、无法从 `[server].cors_origins` 推导、
///   或推导结果非法 ⇒ 打 **WARN**（拒绝静默失效：请求期将返回 503 而非静默失败）。
pub(crate) fn init_webauthn_output(settings: &Settings) {
    use crate::common::features::FeatureSet;

    let on = FeatureSet::sanitized(settings.features.0.clone())
        .is_on(crate::service::webauthn_service::FEATURE_WEBAUTHN);

    match (on, settings.webauthn.resolved(&settings.server)) {
        (false, _) => {
            tracing::info!(
                "WebAuthn/Passkey：[features].auth.webauthn = off（默认；端点表现为 404）"
            );
        }
        (true, Some(r)) => {
            tracing::info!(
                rp_id = %r.rp_id,
                rp_name = %r.rp_name,
                origin = %r.origin,
                state_ttl_secs = r.state_ttl_secs,
                "WebAuthn/Passkey：已启用（rp_id / origin 为 WebAuthn 信任锚，配置变更后浏览器旧凭据将失效）"
            );
        }
        (true, None) => {
            tracing::warn!(
                rp_id = %settings.webauthn.rp_id,
                origin = %settings.webauthn.origin,
                "[features].auth.webauthn = on，但 [webauthn].rp_id / origin 未配置且无法从 \
                 [server].cors_origins 推导（或推导结果非法）⇒ passkey 注册/登录将返回 503\
                 （服务器未就绪）。请显式配置 [webauthn].rp_id 与 [webauthn].origin"
            );
        }
    }
}

/// P2-33：把 `[server].http_status_convention` 注入全局档位，并在 `restful` 档打一行 INFO
/// （便于运维确认"业务失败不再返回 200"这一取向已生效；`legacy` 为默认档，静默）。
pub(crate) fn init_http_status_convention(settings: &Settings) {
    use crate::common::http_status::{HttpStatusConvention, set_convention};

    let convention = HttpStatusConvention::parse(&settings.server.http_status_convention);
    set_convention(convention);
    if convention == HttpStatusConvention::Restful {
        tracing::info!(
            "HTTP 状态码约定 = restful：业务失败不再返回 200（未归类业务码按 400 归类）；\
             标准码与 legacy 档一致"
        );
    }
}

/// #10：把 `[resilience]` 的出站熔断参数注入全局（默认 `off` = 现状：每次都尝试发送）。
///
/// 治理意义：熔断会**改变出站发送行为**（打开期间直接跳过推送），必须让运维一眼看到本实例
/// 是否启用、阈值与冷却（由 [`crate::common::breaker::init`] 打 INFO）；`off` 档不判定、
/// 不记账 ⇒ 与改造前逐字节等价。非法档位在解析时 WARN 并回落 `off`（fail-safe）。
pub(crate) fn init_outbound_breaker(settings: &Settings) {
    let cfg = crate::common::breaker::BreakerConfig::from_settings(settings);
    crate::common::breaker::init(cfg);
}

/// 注入平台层能力位并做**启动治理打印**（幂等：重复调用只保留首次注入）。
///
/// 治理意义：能力位是"放开高危能力"的唯一入口，必须让运维一眼看到本实例放开了什么——
/// 默认全关只打一行 INFO；一旦有开启项则打 WARN 并逐条列出（含模式），避免"隐形放开"。
pub(crate) fn init_feature_flags(settings: &Settings) {
    use crate::common::features::{self, FeatureSet, KNOWN_FEATURES};

    // 净化：未登记键 / 非法模式在此被剔除并告警（fail-closed）
    let effective =
        features::init_platform_features(FeatureSet::sanitized(settings.features.0.clone()));

    let enabled: Vec<String> = KNOWN_FEATURES
        .iter()
        .filter(|def| effective.is_on(def.key))
        .map(|def| format!("{}={}", def.key, effective.mode(def.key)))
        .collect();

    if enabled.is_empty() {
        tracing::info!("能力位：平台层全部关闭（默认安全姿态；租户套餐亦需显式开启）");
    } else {
        tracing::warn!(
            enabled = %enabled.join(", "),
            "能力位：平台层已放开以下能力（租户套餐需同时开启，权限才可下放）。\
             已放开项的服务层必须按 tenant_id 收窄 —— 逐条核对 \
             governance crate 的解锁清单（`governance::Item::unlocked`）的守卫要求"
        );
    }

    // UI 展示策略姿态（`[ui]` 段）：属展示层（非安全边界），无条件打 INFO，
    // 非法取值已在解析时 WARN 并回落 auto。供运维一眼确认"归属列是否只对平台可见"。
    let tenant_column = crate::config::TenantColumnMode::parse(&settings.ui.show_tenant_column);
    tracing::info!(
        mode = tenant_column.as_str(),
        "UI 展示策略：[ui].show_tenant_column（auto = 仅平台操作者可见归属列 ⇒ 历史行为）"
    );

    // 单机模式一致性自检（§5.22）：management=false 时部分配置**会被强制覆盖**，
    // 在此显式 WARN 消除"配了没生效"的运维困惑（拒绝静默失效准则）。
    if !settings.tenant.management {
        // ① [ui] 租户展示配置：单机模式强制隐藏（auth_service 布场门控）
        if tenant_column.as_str() != "never"
            || crate::config::TenantFilterMode::parse(&settings.ui.tenant_filter).as_str() != "off"
        {
            tracing::warn!(
                show_tenant_column = tenant_column.as_str(),
                tenant_filter = %settings.ui.tenant_filter,
                "单机模式（[tenant].management=false）：[ui] 段的租户展示配置将被强制隐藏\
                 （showTenantColumn/showTenantFilter 恒 false）——如需保留请切回多租户模式"
            );
        }
        // ② 租户域能力位：单机模式下端点 403 + 菜单剪除 ⇒ 配置空转
        let tenant_domain_keys = ["nav.l3", "tenant.domain_self_service"];
        let active_tenant_keys: Vec<&str> = tenant_domain_keys
            .iter()
            .filter(|k| effective.is_on(k))
            .copied()
            .collect();
        if !active_tenant_keys.is_empty() {
            tracing::warn!(
                keys = %active_tenant_keys.join(", "),
                "单机模式（[tenant].management=false）：租户域能力位不生效\
                 （端点 403 + 菜单剪除）——如需启用请切回多租户模式"
            );
        }
    }
}

/// 启动打印 ACME 证书需求输出的**有效姿态**（`[acme]` 段）。
///
/// 治理意义与能力位同理：这是"把租户域名清单推出本进程"的唯一出口，必须让运维一眼看到
/// 本实例**是否会**发请求、发到哪。默认 `off` 打 INFO；`mode = webhook` 但地址缺失/非法时
/// 打 **WARN**——否则会静默失效（"以为配了其实没生效"，与 MT-4 反代白名单同类坑）。
pub(crate) fn init_acme_output(settings: &Settings) {
    use crate::config::settings::AcmeMode;

    let cfg = &settings.acme;
    match (cfg.mode(), cfg.effective_webhook()) {
        (AcmeMode::Off, _) => {
            tracing::info!("ACME 证书需求输出：[acme].mode = off（默认，不发任何出站请求）");
        }
        (AcmeMode::Webhook, Some(url)) => {
            tracing::info!(
                url = %url,
                signed = cfg.secret.as_deref().is_some_and(|s| !s.is_empty()),
                timeout_secs = cfg.timeout().as_secs(),
                "ACME 证书需求输出：已启用 webhook（域名验证通过 / 已验证域名删除时推送）"
            );
        }
        (AcmeMode::Webhook, None) => {
            tracing::warn!(
                webhook_url = ?cfg.webhook_url,
                "[acme].mode = webhook 但 webhook_url 缺失或非 http(s) ⇒ 本次运行**不会**推送\
                 （按 off 处理）。请补全 [acme].webhook_url，否则证书需求清单会静默丢失"
            );
        }
    }
}

/// 启动打印**出站领域事件**的**有效姿态**（`[events]` 段）。
///
/// 与 `[acme]` 同源治理逻辑：这是"把领域事件推出本进程"的唯一出口，必须让运维一眼看到
/// 本实例**是否会**发请求、发到哪、推送哪些事件。默认 `off` 打 INFO；
/// `outbound = webhook` 但地址缺失/非法时打 **WARN**——否则会静默失效。
pub(crate) fn init_events_output(settings: &Settings) {
    use crate::config::settings::EventsOutboundMode;

    let cfg = &settings.events;
    match (cfg.mode(), cfg.effective_webhook()) {
        (EventsOutboundMode::Off, _) => {
            tracing::info!(
                "领域事件输出：[events].outbound = off（默认，不发任何出站请求）\
                 —— 需要对接 MQ / 通知 / 数仓时置 webhook 并配置 webhook_url"
            );
        }
        (EventsOutboundMode::Webhook, Some(url)) => {
            tracing::info!(
                url = %url,
                signed = cfg.secret.as_deref().is_some_and(|s| !s.is_empty()),
                timeout_secs = cfg.timeout().as_secs(),
                events = ?crate::service::event_outbox_service::ALL_EVENTS,
                "领域事件输出：已启用 webhook（租户创建 / 启停 / 删除 / 恢复时推送）"
            );
        }
        (EventsOutboundMode::Webhook, None) => {
            tracing::warn!(
                webhook_url = ?cfg.webhook_url,
                "[events].outbound = webhook 但 webhook_url 缺失或非 http(s) ⇒ 本次运行**不会**推送\
                 （按 off 处理）。请补全 [events].webhook_url，否则领域事件会静默丢失"
            );
        }
    }
}
