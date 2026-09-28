// axum-backend/src/config/settings.rs

use serde::Deserialize;
use std::fmt;

/// 全局配置根结构体
///
/// 注意：不 derive(Debug)，改用手动实现以脱敏 config_enc_key
#[derive(Clone, Deserialize)]
pub struct Settings {
    pub server: ServerConfig,
    pub database: DatabaseConfig,
    pub redis: RedisConfig,
    pub jwt: JwtConfig,
    pub log: LogConfig,
    #[serde(default)]
    pub upload: UploadConfig,
    /// IP 归属地查询配置（可选，未配置时使用默认 mmdb 路径）
    #[serde(default)]
    pub ip_location: IpLocationConfig,
    /// 邮件 SMTP 配置（可选，未配置时邮件相关功能降级为仅 sys_notice）
    #[serde(default)]
    pub mail: MailConfig,
    /// 配置加密主密钥（用于 sys_config 表中敏感字段 AES-256-GCM 加解密）
    ///
    /// 通过 CONFIG_ENC_KEY 环境变量注入，不入配置文件。
    /// 启用 IP 库管理（License Key 加密存储）时必须配置，否则相关功能降级。
    #[serde(default)]
    pub config_enc_key: String,
    /// 权限未映射路由的默认处置策略（权限 fail-closed 加固，B3 / W-1）
    ///
    /// - true（**默认**，fail-closed）：未登记权限映射且不在"仅登录白名单"的受保护路由
    ///   **拒绝（403）**并审计，防止新增路由漏登记权限导致越权。
    /// - false（**显式** opt-out，开发/兼容）：此类路由**放行**（fail-open，安全假设被削弱）。
    ///
    /// 默认值与 `from_env_only()`（配置文件全缺失时的回退路径）及集成测试夹具保持一致，
    /// 避免"换配置来源即换安全姿态"的环境漂移。
    ///
    /// 注意：①permission_middleware 仅作用于 protected 路由子树的 route_layer，
    /// 公开路由（/login /health /ws /swagger-ui / 等）不受影响；
    /// ②在 TOML 中本键位于**顶层**，必须写在任何 `[table]` 段之前，
    /// 否则会被解析进上一张表（如 `[log]`）而被静默忽略（曾发生，见单测
    /// `test_shipped_config_template_is_fail_closed`）。
    #[serde(default = "default_deny_by_default")]
    pub permission_deny_by_default: bool,
    /// 可观测性监控配置（慢请求阈值 / 缓冲容量 / Prometheus 指标 token）
    #[serde(default)]
    pub monitor: MonitorConfig,
    /// 系统日志保留策略配置（操作日志 / 登录日志的定期归档清理）
    #[serde(default)]
    pub sys_log: SysLogConfig,
    /// 个人访问令牌（PAT）配置（Tier-S #3）
    #[serde(default)]
    pub pat: PatConfig,
    /// 单点登录 / OIDC Provider 配置（Tier B，默认关闭）
    #[serde(default)]
    pub sso: SsoConfig,
    /// v5-D12：SCIM 2.0 用户目录同步配置（供外部 IdP provisioning 调用，默认关闭）
    #[serde(default)]
    pub scim: ScimConfig,
    /// 审批工作流配置（m20260923_000002；cron 为空 = 禁用超时扫描）
    #[serde(default)]
    pub flow: FlowConfig,
    /// **能力位**默认值（三层开关的最外层：能开什么）。
    ///
    /// 键 = `crate::common::features::KNOWN_FEATURES` 登记的能力位键，值 = 模式串
    /// （如 `off` / `view_only` / `full`）。未登记键与非法模式在启动时被剔除并告警。
    /// **缺省 `{}` = 全关闭**（默认值 = 现状 = 关闭态即安全态）。
    #[serde(default)]
    pub features: FeaturesConfig,
    /// 定时任务调度器配置（集群模式 + 内置任务整轮互斥锁）
    #[serde(default)]
    pub scheduler: SchedulerConfig,
    /// UI 展示策略（`[ui]` 段）：业务列表页归属列等前端展示开关。
    ///
    /// 属于**展示层开关**（不构成服务端安全边界）：默认 `auto` = 仅平台操作者可见
    /// 归属列 = 改造前行为；服务端的数据面隔离始终由 `tenant_scope` 承担。
    #[serde(default)]
    pub ui: UiConfig,
    /// ACME 证书需求输出（`[acme]` 段）：**集成点**而非内置签发器（默认 `off`）。
    #[serde(default)]
    pub acme: AcmeConfig,
    /// 出站**领域事件**集成点（`[events]` 段）：`outbound = "webhook"` 时把租户生命周期等
    /// 领域事件推给使用者自己声明的接收端（用于对接 MQ / 通知 / 数仓），**不内置消息队列**。
    /// 默认 `off` ⇒ 一个字节都不发（与改造前逐字节等价）。
    #[serde(default)]
    pub events: EventsConfig,
    /// WebAuthn / Passkey 配置（`[webauthn]` 段）：能力位 `auth.webauthn` 的配置面。
    #[serde(default)]
    pub webauthn: WebauthnConfig,
    /// 出站**韧性**配置（`[resilience]` 段）：进程内出站 webhook 熔断（#10）。
    ///
    /// 作用于 `[acme]` / `[events]` 共用的出站推送：默认 `off` ⇒ 不判定、不记账、
    /// 每次都尝试发送，与改造前**逐字节等价**。
    #[serde(default)]
    pub resilience: ResilienceConfig,
    /// 全局限流实现配置（`[rate_limit]` 段）：`local`（**默认**，进程内令牌桶 = 现状）| `redis`。
    ///
    /// 收口长期登记项 M-8「多实例限制」：多实例部署时切 `redis` 即可跨实例共享配额。
    /// 默认 `local` ⇒ 与改造前**逐字节等价**（关闭态即安全态）。
    #[serde(default)]
    pub rate_limit: RateLimitSettings,
    /// **风控集成点**（`[risk_control]` 段）：登录面可疑特征（工具型 UA / 异地登录）的
    /// 可插拔处置。全部默认 `off` ⇒ 不判定、不记录额外审计、与改造前**逐字节等价**。
    ///
    /// 按项目准则⑥：这类"需外部数据源/引擎"的能力**不内置实现、也不整块砍掉**，
    /// 而是提供**开关 + 集成点**，由使用者按自身合规要求开启。
    #[serde(default)]
    pub risk_control: RiskControlConfig,
    /// **上传文件病毒扫描集成点**（`[upload_scan]` 段）：默认 `off` ⇒ 不发起任何外部调用。
    ///
    /// 按项目准则⑥提供**可插拔的 HTTP 扫描集成点**（不内置杀毒引擎、也不砍掉上传能力）：
    /// 使用者把 `url` 指向自己的 AV 网关（ClamAV REST / VirusTotal 代理 / 自研）即可开启。
    #[serde(default)]
    pub upload_scan: UploadScanConfig,
}

/// 手动实现 Debug 以脱敏 config_enc_key
impl fmt::Debug for Settings {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Settings")
            .field("server", &self.server)
            .field("database", &self.database)
            .field("redis", &self.redis)
            .field("jwt", &self.jwt)
            .field("log", &self.log)
            .field("upload", &self.upload)
            .field("ip_location", &self.ip_location)
            .field("mail", &self.mail)
            .field("config_enc_key", &"<redacted>")
            .field(
                "permission_deny_by_default",
                &self.permission_deny_by_default,
            )
            .field("monitor", &self.monitor)
            .field("sys_log", &self.sys_log)
            .field("pat", &self.pat)
            .field("sso", &self.sso)
            .field("flow", &self.flow)
            .field("features", &self.features)
            .field("scheduler", &self.scheduler)
            .field("ui", &self.ui)
            .field("acme", &self.acme)
            .field("events", &self.events)
            .field("webauthn", &self.webauthn)
            .field("resilience", &self.resilience)
            .field("rate_limit", &self.rate_limit)
            .field("risk_control", &self.risk_control)
            .field("upload_scan", &self.upload_scan)
            .finish()
    }
}

/// 平台层能力位默认值（`config.toml` 的 `[features]` 段）。
///
/// `#[serde(transparent)]` + `BTreeMap`：TOML 里就是一个扁平表
/// （`nav.l3 = "off"`），无嵌套层级；`BTreeMap` 保证序列化顺序稳定。
///
/// 单一事实源仍是 `crate::common::features::KNOWN_FEATURES`——本结构只承载
/// **平台层的显式覆盖**，未写在此处的能力位一律走注册表默认（`off`）。
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(transparent)]
pub struct FeaturesConfig(pub std::collections::BTreeMap<String, String>);

/// 定时任务调度器配置（`[scheduler]` 段）
///
/// 治理的是**内置定时任务**（`flow_timeout_scan` / `mmdb_auto_update`）的
/// "整轮跨实例互斥"。策略收敛为**模式**（项目准则③），语义与边界见
/// `crate::scheduler::cluster`（`sys_job` 的逐任务防重入锁**不**受本开关影响）。
#[derive(Clone, Debug, Deserialize)]
pub struct SchedulerConfig {
    /// 集群模式：`auto`（**默认**，沿用各任务历史开关 = 现状）| `single` | `leader` | `all`
    ///
    /// - `auto`：`flow` 沿用 `[flow].scan_lock_enabled`；`mmdb` 保持加锁（历史行为）⇒ **默认零行为变更**
    /// - `single`：明确单实例部署 ⇒ 内置任务一律不加锁
    /// - `leader`：多实例选主 ⇒ 内置任务一律加锁
    /// - `all`：每个实例都执行（幂等型任务）⇒ 内置任务一律不加锁
    ///
    /// 非法取值在启动时回落 `auto` 并告警（fail-safe，不改变行为）。
    #[serde(default = "default_cluster_mode")]
    pub cluster_mode: String,
    /// **本部署的实例（副本）数**：仅用于启动期**多副本未选模式**的告警（WF-2 加固）。
    ///
    /// 为什么是"显式声明"而非探针：副本数无法在进程内可靠探测（该结论此前已被否掉）；
    /// 部署方如实声明后，`replicas > 1 且 cluster_mode = auto` 会在启动时打出 WARN，
    /// 避免"多实例并发扫描同一批内置任务"这一静默退化。默认 `1` = 单实例（现状）。
    #[serde(default = "default_scheduler_replicas")]
    pub replicas: u32,
    /// 内置任务整轮互斥锁的默认 TTL（秒，默认 300）
    ///
    /// 仅 `[flow].scan_lock_enabled` 未给出时作为兜底；`flow` 任务仍优先用
    /// `[flow].scan_lock_ttl_secs`（该值需大于单轮扫描最坏耗时）。
    #[serde(default = "default_scheduler_lock_ttl")]
    pub lock_ttl_secs: u64,
}

impl Default for SchedulerConfig {
    fn default() -> Self {
        Self {
            cluster_mode: default_cluster_mode(),
            replicas: default_scheduler_replicas(),
            lock_ttl_secs: default_scheduler_lock_ttl(),
        }
    }
}

fn default_scheduler_replicas() -> u32 {
    1
}

fn default_cluster_mode() -> String {
    crate::scheduler::cluster::ClusterMode::default()
        .as_str()
        .to_string()
}

fn default_scheduler_lock_ttl() -> u64 {
    crate::scheduler::cluster::DEFAULT_ROUND_LOCK_TTL_SECS
}

/// UI 展示策略配置（`[ui]` 段）
///
/// 本项目定位「**大而全**」：能力齐备，让使用者自己选择或配置。
/// 「业务列表页是否显示『所属租户』归属列」原判定为"业务页不加"（F-6，理由：租户用户
/// 看到的天然只有本租户数据，加列零收益）。按项目准则⑥（原判"不进本仓"的项改为
/// **提供集成点/开关**），此处把它做成**三态开关**，默认值 = 现状 = 关闭侧安全
/// （仅平台操作者可见，租户视图零行为变更）。
#[derive(Clone, Debug, Deserialize)]
pub struct UiConfig {
    /// 「所属租户」归属列的展示模式（`auto` | `always` | `never`）
    ///
    /// - `auto`（**默认**）：仅平台操作者（`tid == 0`）可见 ⇒ 等价于改造前行为；
    /// - `always`：平台与租户操作者均可见（租户看到的是自己的租户号或"平台"）；
    /// - `never`：一律不显示。
    ///
    /// 非法取值在启动时回落 `auto` 并告警（fail-safe），不会意外扩大可见面。
    #[serde(default = "default_tenant_column_mode")]
    pub show_tenant_column: String,
    /// 业务列表页「按租户筛选」的可用范围（`off` | `platform` | `always`）
    ///
    /// - `off`（**默认**）：不提供筛选入口 ⇒ 等价于改造前行为；
    /// - `platform`：仅平台操作者可见筛选入口；
    /// - `always`：平台与租户操作者均可见。
    ///
    /// 非法取值回落 `off` 并告警（fail-safe）。筛选在服务层**与 `tenant_scope` 相与**，
    /// 只能收窄 ⇒ 开关不构成安全边界，只决定前端是否给出入口。
    #[serde(default = "default_tenant_filter_mode")]
    pub tenant_filter: String,
}

impl Default for UiConfig {
    fn default() -> Self {
        Self {
            show_tenant_column: default_tenant_column_mode(),
            tenant_filter: default_tenant_filter_mode(),
        }
    }
}

fn default_tenant_column_mode() -> String {
    TenantColumnMode::default().as_str().to_string()
}

fn default_tenant_filter_mode() -> String {
    TenantFilterMode::default().as_str().to_string()
}

/// 「所属租户」归属列的展示模式（`[ui].show_tenant_column`）
///
/// 开关取「模式」而非裸 bool（项目准则③）：`auto` 需要操作者租户上下文才能判定，
/// 裸 bool 无法表达"平台看、租户不看"这一默认语义。
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum TenantColumnMode {
    /// 仅平台操作者（`tid == 0`）可见 —— **默认，等价于改造前行为**
    #[default]
    Auto,
    /// 平台与租户操作者均可见
    Always,
    /// 一律不显示
    Never,
}

/// `TenantColumnMode` 的合法模式串（顺序：默认项在前，便于阅读时确认"默认为现状"）
pub const TENANT_COLUMN_MODES: &[&str] = &["auto", "always", "never"];

impl TenantColumnMode {
    /// 解析配置串；未登记取值一律回落 [`TenantColumnMode::Auto`] 并打 WARN（fail-safe）
    pub fn parse(raw: &str) -> Self {
        let normalized = raw.trim().to_ascii_lowercase();
        match normalized.as_str() {
            "auto" => Self::Auto,
            "always" => Self::Always,
            "never" => Self::Never,
            _ => {
                tracing::warn!(
                    value = %raw,
                    fallback = "auto",
                    allowed = ?TENANT_COLUMN_MODES,
                    "配置 [ui].show_tenant_column 取值非法，已回落 auto（仅平台操作者可见归属列）"
                );
                Self::Auto
            }
        }
    }

    /// 规范模式串（用于启动姿态日志与文档口径）
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::Always => "always",
            Self::Never => "never",
        }
    }

    /// 解析后的**有效展示决策**：给定操作者租户号（`0` = 平台），是否显示归属列。
    ///
    /// 这是前后端唯一的判定口径：后端在 `getInfo` 时算好布尔下发给前端，
    /// 前端不做二次推断（避免"平台/租户"判定散落两处而漂移）。
    pub fn visible_for(self, operator_tid: i64) -> bool {
        match self {
            Self::Auto => operator_tid == 0,
            Self::Always => true,
            Self::Never => false,
        }
    }
}

/// 业务列表页「按租户筛选」的可用范围（`[ui].tenant_filter`）。
///
/// 与 [`TenantColumnMode`] 是**两个正交开关**：归属列管"看不看得见租户号"，
/// 本开关管"能不能按租户号收窄结果"。二者共用同一条"只在平台侧才有意义"的默认语义。
///
/// 安全口径：显式 `tenantId` 过滤在服务层是**与 `tenant_scope` 相与**的（AND），
/// 因此**只能收窄、永不放宽**——租户操作者即使手工传他租户 id，结果集也仍是空集，
/// 不存在越权读面。开关只决定**前端是否给出该筛选入口**。
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum TenantFilterMode {
    /// 不提供筛选入口 —— **默认，等价于改造前行为**
    #[default]
    Off,
    /// 仅平台操作者（`tid == 0`）显示筛选入口
    Platform,
    /// 平台与租户操作者均显示（租户按自己的 tid 筛选同样只收窄）
    Always,
}

/// `TenantFilterMode` 的合法模式串（顺序：默认项在前）
pub const TENANT_FILTER_MODES: &[&str] = &["off", "platform", "always"];

impl TenantFilterMode {
    /// 解析配置串；未登记取值一律回落 [`TenantFilterMode::Off`] 并打 WARN（fail-safe）
    pub fn parse(raw: &str) -> Self {
        match raw.trim().to_ascii_lowercase().as_str() {
            "off" => Self::Off,
            "platform" => Self::Platform,
            "always" => Self::Always,
            _ => {
                tracing::warn!(
                    value = %raw,
                    fallback = "off",
                    allowed = ?TENANT_FILTER_MODES,
                    "配置 [ui].tenant_filter 取值非法，已回落 off（不提供按租户筛选入口）"
                );
                Self::Off
            }
        }
    }

    /// 规范模式串（用于启动姿态日志与文档口径）
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::Platform => "platform",
            Self::Always => "always",
        }
    }

    /// 解析后的**有效决策**：给定操作者租户号（`0` = 平台），是否提供筛选入口。
    /// 与 [`TenantColumnMode::visible_for`] 同源——后端在 `getInfo` 算好布尔下发，前端不二次推断。
    pub fn enabled_for(self, operator_tid: i64) -> bool {
        match self {
            Self::Off => false,
            Self::Platform => operator_tid == 0,
            Self::Always => true,
        }
    }
}

/// ACME 证书需求**输出**配置（`[acme]` 段）——集成点，**不是**内置签发器。
///
/// # 为什么不做内置签发
///
/// 本项目定位「大而全」，但**证书签发属网关职责**：NGINX + certbot、Caddy 自动 HTTPS、
/// Traefik、云 LB/CDN 证书托管各有成熟方案，内置一套反而把用户锁死在单一栈上。
/// 按项目准则⑥（原判"不进本仓"的项改为**提供集成点/开关**），这里只做**输出契约**：
/// 域名集合发生**状态迁移**（验证通过 ⇒ 需要签发；已签发域名被删除 ⇒ 需要吊销/清理）时，
/// 把「证书需求清单」推给用户自己的脚本，由脚本去调 ACME 客户端。
///
/// # 安全姿态
///
/// - 默认 `off` = **不发任何出站请求**（关闭态即现状）；
/// - `mode = webhook` 但 `webhook_url` 缺失/非 http(s) ⇒ 启动 **WARN** 且视为 `off`
///   （不静默：运维能从日志看出"配了但没生效"）；
/// - 推送为 fire-and-forget，失败只打 WARN，**绝不影响**域名绑定/验证业务本身；
/// - `secret` 设置后请求带 `X-Yebot-Signature: sha256=<hmac>`，供接收端验签。
#[derive(Clone, Deserialize)]
pub struct AcmeConfig {
    /// `off`（默认，不发请求）| `webhook`（推送证书需求事件到 `webhook_url`）
    #[serde(default = "default_acme_mode")]
    pub mode: String,
    /// webhook 目标地址（`mode = webhook` 时必填）
    #[serde(default)]
    pub webhook_url: Option<String>,
    /// HMAC-SHA256 签名密钥（可选）
    #[serde(default)]
    pub secret: Option<String>,
    /// 单次推送超时（秒，默认 5；上限 60）
    #[serde(default = "default_acme_timeout_secs")]
    pub timeout_secs: u64,
}

impl Default for AcmeConfig {
    fn default() -> Self {
        Self {
            mode: default_acme_mode(),
            webhook_url: None,
            secret: None,
            timeout_secs: default_acme_timeout_secs(),
        }
    }
}

/// 手动实现 Debug 以**脱敏** `secret`（避免签名密钥进日志）
impl fmt::Debug for AcmeConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AcmeConfig")
            .field("mode", &self.mode)
            .field("webhook_url", &self.webhook_url)
            .field("secret", &self.secret.as_ref().map(|_| "<redacted>"))
            .field("timeout_secs", &self.timeout_secs)
            .finish()
    }
}

/// ACME 输出模式（`[acme].mode`）
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum AcmeMode {
    /// 关闭：不发任何出站请求 —— **默认，等价于改造前行为**
    #[default]
    Off,
    /// 推送证书需求事件到 webhook
    Webhook,
}

/// `AcmeMode` 的合法模式串（顺序：默认项在前）
pub const ACME_MODES: &[&str] = &["off", "webhook"];

impl AcmeMode {
    /// 解析配置串；未登记取值一律回落 [`AcmeMode::Off`] 并打 WARN（fail-safe）
    pub fn parse(raw: &str) -> Self {
        match raw.trim().to_ascii_lowercase().as_str() {
            "webhook" => Self::Webhook,
            "off" => Self::Off,
            _ => {
                tracing::warn!(
                    value = %raw,
                    fallback = "off",
                    allowed = ?ACME_MODES,
                    "配置 [acme].mode 取值非法，已回落 off（不推送证书需求事件）"
                );
                Self::Off
            }
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::Webhook => "webhook",
        }
    }
}

impl AcmeConfig {
    /// 解析后的模式（非法值已由 [`AcmeMode::parse`] 打 WARN 并回落 `off`）
    pub fn mode(&self) -> AcmeMode {
        AcmeMode::parse(&self.mode)
    }

    /// 推送超时（秒）：夹在 `1..=60`，防止配置成 0（立即超时）或过大（拖住请求）
    pub fn timeout(&self) -> std::time::Duration {
        std::time::Duration::from_secs(self.timeout_secs.clamp(1, 60))
    }

    /// **本次运行的有效推送目标**：`None` = 不推送（模式为 `off`，或地址缺失/非法）。
    ///
    /// 地址合法性用 `http://` / `https://` 前缀判定（拒绝 `file:` / `ftp:` 等），
    /// 与"只把数据推到运维自己声明的 HTTP 端点"的契约一致。
    /// 判定实现收敛在 [`crate::common::webhook::url_is_http`]（与 `[events]` 段共用）。
    pub fn effective_webhook(&self) -> Option<&str> {
        if self.mode() != AcmeMode::Webhook {
            return None;
        }
        self.webhook_url
            .as_deref()
            .map(str::trim)
            .filter(|u| crate::common::webhook::url_is_http(u))
    }
}

fn default_acme_mode() -> String {
    AcmeMode::default().as_str().to_string()
}

fn default_acme_timeout_secs() -> u64 {
    5
}

/// 出站**领域事件**集成点（`[events]` 段）——把事件交给用户自己的接收端，
/// **不是**内置消息队列。
///
/// # 定位（项目准则⑥：原判"不进本仓"改为"提供集成点/开关"）
///
/// 需要事件驱动 / MQ / 数据同步的使用者不少，但**不应**由本仓内置
/// Kafka / RabbitMQ / Redis Stream：那会把使用者锁死在单一技术栈上，且绝大多数
/// 中后台场景用不到真正的 MQ。故此处只提供**出站事件契约**——
/// `outbound = "webhook"` 时，领域事件以 HTTP POST 推到使用者自己声明的地址，
/// 由接收端去对接 MQ / 通知 / 数仓 / 审计归档。
///
/// # 安全与关闭态
///
/// - 默认 `off` ⇒ **一个字节都不发**（`effective_webhook()` 返回 `None` 即直接返回），
///   与改造前逐字节等价；
/// - `outbound = webhook` 但地址缺失/非 http(s) ⇒ 启动 **WARN**（拒绝静默失效）；
/// - 推送 fire-and-forget：失败只 `WARN`，**绝不影响**业务事务本身；
/// - 可选 HMAC-SHA256 签名（`X-Yebot-Signature: sha256=<hex>`）供接收端验签。
#[derive(Clone, Deserialize)]
pub struct EventsConfig {
    /// `off`（默认，不发请求）| `webhook`（把领域事件推到 `webhook_url`）
    #[serde(default = "default_events_outbound")]
    pub outbound: String,
    /// webhook 目标地址（`outbound = webhook` 时必填）
    #[serde(default)]
    pub webhook_url: Option<String>,
    /// HMAC-SHA256 签名密钥（可选）
    #[serde(default)]
    pub secret: Option<String>,
    /// 单次推送超时（秒，默认 5；夹取 `1..=60`）
    #[serde(default = "default_events_timeout_secs")]
    pub timeout_secs: u64,
}

impl Default for EventsConfig {
    fn default() -> Self {
        Self {
            outbound: default_events_outbound(),
            webhook_url: None,
            secret: None,
            timeout_secs: default_events_timeout_secs(),
        }
    }
}

/// 手动实现 Debug 以**脱敏** `secret`（避免签名密钥进日志）
impl fmt::Debug for EventsConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EventsConfig")
            .field("outbound", &self.outbound)
            .field("webhook_url", &self.webhook_url)
            .field("secret", &self.secret.as_ref().map(|_| "<redacted>"))
            .field("timeout_secs", &self.timeout_secs)
            .finish()
    }
}

/// 出站事件模式（`[events].outbound`）
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum EventsOutboundMode {
    /// 关闭：不发任何出站请求 —— **默认，等价于改造前行为**
    #[default]
    Off,
    /// 把领域事件推到 webhook
    Webhook,
}

/// `EventsOutboundMode` 的合法模式串（顺序：默认项在前）
pub const EVENTS_OUTBOUND_MODES: &[&str] = &["off", "webhook"];

impl EventsOutboundMode {
    /// 解析配置串；未登记取值一律回落 [`EventsOutboundMode::Off`] 并打 WARN（fail-safe）
    pub fn parse(raw: &str) -> Self {
        match raw.trim().to_ascii_lowercase().as_str() {
            "webhook" => Self::Webhook,
            "off" => Self::Off,
            _ => {
                tracing::warn!(
                    value = %raw,
                    fallback = "off",
                    allowed = ?EVENTS_OUTBOUND_MODES,
                    "配置 [events].outbound 取值非法，已回落 off（不推送领域事件）"
                );
                Self::Off
            }
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::Webhook => "webhook",
        }
    }
}

impl EventsConfig {
    /// 解析后的模式（非法值已由 [`EventsOutboundMode::parse`] 打 WARN 并回落 `off`）
    pub fn mode(&self) -> EventsOutboundMode {
        EventsOutboundMode::parse(&self.outbound)
    }

    /// 推送超时（秒）：夹在 `1..=60`，防止配置成 0（立即超时）或过大（拖住请求）
    pub fn timeout(&self) -> std::time::Duration {
        std::time::Duration::from_secs(self.timeout_secs.clamp(1, 60))
    }

    /// **本次运行的有效推送目标**：`None` = 不推送（模式为 `off`，或地址缺失/非法）。
    pub fn effective_webhook(&self) -> Option<&str> {
        if self.mode() != EventsOutboundMode::Webhook {
            return None;
        }
        self.webhook_url
            .as_deref()
            .map(str::trim)
            .filter(|u| crate::common::webhook::url_is_http(u))
    }
}

fn default_events_outbound() -> String {
    EventsOutboundMode::default().as_str().to_string()
}

fn default_events_timeout_secs() -> u64 {
    5
}

/// 出站**韧性**配置（`[resilience]` 段）—— 进程内出站 webhook 熔断（#10）。
///
/// # 为什么需要它
///
/// `[acme]` 与 `[events]` 都是 **fire-and-forget POST**：目标端点下线时，**每一个事件**都会
/// 重新发一次请求（各带一次连接/超时预算）并打一条 WARN —— 既浪费资源，又用噪声淹没真正的告警。
///
/// # 语义（关闭态 = 现状）
///
/// - `off`（**默认**）：不判定、不记账、每次都尝试发送，与改造前**逐字节等价**；
/// - `on`：同一 URL 连续失败达 `failure_threshold` 次即**打开** ⇒ 冷却期内直接跳过发送，
///   `cooldown_secs` 到期放行**一次探测**（半开），探测成功即恢复（连续失败计数清零）。
///
/// 非法档位取值回落 `off` 并打 WARN（fail-safe，不拒绝启动）；数值越界由
/// [`crate::common::breaker::BreakerConfig::from_settings`] 夹取到上下界。
#[derive(Clone, Debug, Deserialize)]
pub struct ResilienceConfig {
    /// 出站 webhook 熔断档位：`off`（**默认**，= 现状）| `on`
    #[serde(default = "default_outbound_breaker")]
    pub outbound_breaker: String,
    /// 连续失败达到该次数 ⇒ 打开熔断（默认 5；夹取 `1..=1000`）
    #[serde(default = "default_breaker_failure_threshold")]
    pub failure_threshold: u32,
    /// 打开后的冷却秒数，到期放行一次探测（默认 60；夹取 `1..=86400`）
    #[serde(default = "default_breaker_cooldown_secs")]
    pub cooldown_secs: u64,
}

impl Default for ResilienceConfig {
    fn default() -> Self {
        Self {
            outbound_breaker: default_outbound_breaker(),
            failure_threshold: default_breaker_failure_threshold(),
            cooldown_secs: default_breaker_cooldown_secs(),
        }
    }
}

fn default_outbound_breaker() -> String {
    crate::common::breaker::BreakerMode::default()
        .as_str()
        .to_string()
}

fn default_breaker_failure_threshold() -> u32 {
    5
}

fn default_breaker_cooldown_secs() -> u64 {
    60
}

// ==================== 全局限流实现档位（[rate_limit]） ====================

/// 限流实现档位字面量（顺序：默认项在前，便于阅读时确认"默认为现状"）
pub const RATE_LIMIT_MODES: &[&str] = &["local", "redis"];

/// Redis 桶键 TTL 下界 / 上界（秒）
pub const RATE_LIMIT_KEY_TTL_MIN_SECS: u64 = 60;
pub const RATE_LIMIT_KEY_TTL_MAX_SECS: u64 = 86_400;

/// 全局限流实现档位（项目准则③：取「模式」而非裸 bool）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RateLimitMode {
    /// **默认 = 现状**：进程内令牌桶（`Mutex<HashMap>`），单实例下精确、无 Redis 往返。
    #[default]
    Local,
    /// Redis 分布式令牌桶：多实例共享配额（Lua 原子执行）。
    Redis,
}

impl RateLimitMode {
    /// 解析配置串（大小写无关、两端 trim）；未登记取值一律回落 [`RateLimitMode::Local`] 并打 WARN。
    pub fn parse(raw: &str) -> Self {
        match raw.trim().to_ascii_lowercase().as_str() {
            "redis" => Self::Redis,
            "local" => Self::Local,
            other => {
                tracing::warn!(
                    value = %other,
                    fallback = "local",
                    allowed = ?RATE_LIMIT_MODES,
                    "配置 [rate_limit].mode 取值非法，已回落 local（= 现状：进程内令牌桶）"
                );
                Self::Local
            }
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Local => "local",
            Self::Redis => "redis",
        }
    }
}

/// 全局限流实现配置（`[rate_limit]` 段）—— 长期登记项 M-8「多实例限制」的收口开关。
///
/// # 为什么需要它
///
/// 限流中间件（`middleware/rate_limit.rs`）默认用**进程内**令牌桶：单实例下精确，
/// 但多实例部署时各实例**独立计数**，攻击者轮询不同实例即可把配额放大 N 倍。
/// 本段提供 `mode = "redis"` 把令牌桶搬到 Redis，实现跨实例共享配额。
///
/// # 语义（默认 = 现状）
///
/// - `local`（**默认**）：进程内令牌桶，与改造前**逐字节等价**（无 Redis 往返）；
/// - `redis`：Redis 分布式令牌桶；Redis 命令失败时 **fail-closed 返回 503**——
///   限流器不可用却静默放行，等于攻击者获准，与 `get_config_for_route` 的既有
///   fail-closed 口径一致。
///
/// 非法档位取值回落 `local` 并打 WARN（fail-safe，不拒绝启动）；
/// `key_ttl_secs` 越界由 [`RateLimitSettings::key_ttl`] 夹取。
#[derive(Clone, Debug, Deserialize)]
pub struct RateLimitSettings {
    /// 限流实现档位：`local`（**默认**，= 现状）| `redis`
    #[serde(default = "default_rate_limit_mode")]
    pub mode: String,
    /// Redis 桶键 TTL 秒数（默认 300；夹取 `60..=86400`）。
    ///
    /// 实际生效 TTL 还会与「桶自然补满所需秒数 × 2」取大值，避免 TTL 早于补满
    /// 而**提前重置**桶（那会让限流比配置更宽松）。
    #[serde(default = "default_rate_limit_key_ttl_secs")]
    pub key_ttl_secs: u64,
}

impl Default for RateLimitSettings {
    fn default() -> Self {
        Self {
            mode: default_rate_limit_mode(),
            key_ttl_secs: default_rate_limit_key_ttl_secs(),
        }
    }
}

impl RateLimitSettings {
    /// 解析后的档位（非法取值回落 `local` 并打 WARN）
    pub fn mode(&self) -> RateLimitMode {
        RateLimitMode::parse(&self.mode)
    }

    /// 夹取后的 TTL（秒）
    pub fn key_ttl(&self) -> u64 {
        self.key_ttl_secs
            .clamp(RATE_LIMIT_KEY_TTL_MIN_SECS, RATE_LIMIT_KEY_TTL_MAX_SECS)
    }
}

fn default_rate_limit_mode() -> String {
    RateLimitMode::default().as_str().to_string()
}

fn default_rate_limit_key_ttl_secs() -> u64 {
    300
}

// ==================== 风控集成点（[risk_control]） ====================

/// 登录面「工具型 UA」处置档位字面量（顺序：默认项在前 ⇒ "默认为现状"）
pub const LOGIN_UA_FILTER_MODES: &[&str] = &["off", "block", "strict"];

/// 登录面「工具型 UA」处置档位（项目准则③：取「模式」而非裸 bool）。
///
/// 定位：**弱信号**防护（UA 可伪造），用于挡掉批量脚本的"顺手尝试"，**不是**安全边界。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum LoginUaFilterMode {
    /// **默认 = 现状**：不判定 UA。
    #[default]
    Off,
    /// 命中工具型 UA 特征（`curl/`、`wget/`、`python-requests/` 等）⇒ 拒绝登录。
    /// 空 UA **放行**但打 WARN（很多合法 SDK/HTTP/1.0 客户端不发 UA，硬拦误伤面大）。
    Block,
    /// 在 `block` 基础上**同时拒绝空 UA**（适合"只允许浏览器登录"的部署）。
    Strict,
}

impl LoginUaFilterMode {
    /// 解析配置串（大小写无关、两端 trim）；未登记取值一律回落 [`Self::Off`] 并打 WARN。
    pub fn parse(raw: &str) -> Self {
        match raw.trim().to_ascii_lowercase().as_str() {
            "block" => Self::Block,
            "strict" => Self::Strict,
            "off" => Self::Off,
            other => {
                tracing::warn!(
                    value = %other,
                    allowed = ?LOGIN_UA_FILTER_MODES,
                    "配置 [risk_control].login_ua_filter 取值非法，已回落 off（= 现状：不判定 UA）"
                );
                Self::Off
            }
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::Block => "block",
            Self::Strict => "strict",
        }
    }
}

/// 登录面「异地登录」处置档位字面量（顺序：默认项在前 ⇒ "默认为现状"）
pub const LOGIN_GEO_ALERT_MODES: &[&str] = &["off", "alert"];

/// 登录面「异地登录」处置档位。
///
/// **只有「告警」没有「拦截」**是刻意的：地区识别基于 IP 库，VPN / 运营商出口 / 移动网络
/// 都会造成误判，拦截会变成"用户被自己锁在门外"。故本档位只产生**可审计的告警**。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum LoginGeoAlertMode {
    /// **默认 = 现状**：不比对历史登录地区。
    #[default]
    Off,
    /// 与上一次**成功**登录的粗粒度地区不同 ⇒ 打 WARN + 在登录日志 `msg` 中留痕。
    Alert,
}

impl LoginGeoAlertMode {
    /// 解析配置串（大小写无关、两端 trim）；未登记取值一律回落 [`Self::Off`] 并打 WARN。
    pub fn parse(raw: &str) -> Self {
        match raw.trim().to_ascii_lowercase().as_str() {
            "alert" => Self::Alert,
            "off" => Self::Off,
            other => {
                tracing::warn!(
                    value = %other,
                    allowed = ?LOGIN_GEO_ALERT_MODES,
                    "配置 [risk_control].login_geo_alert 取值非法，已回落 off（= 现状：不比对）"
                );
                Self::Off
            }
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::Alert => "alert",
        }
    }
}

/// 内置的「工具型 UA」特征清单（仅当使用者未自定义 `login_ua_blocklist` 时生效）。
///
/// 只收录**明显不是浏览器**的命令行/抓取工具标识；刻意**不含** `node` / `axios` / `okhttp` 等
/// 同时被合法 SDK 使用的标识——它们启用后可能误伤使用者自己的服务端集成（清单可由使用者覆盖）。
pub const DEFAULT_UA_BLOCKLIST: &[&str] = &[
    "curl/",
    "wget/",
    "python-requests/",
    "python-urllib/",
    "go-http-client/",
    "libwww-perl/",
    "java/",
    "httpclient/",
    "scrapy/",
];

/// 风控集成点配置（`[risk_control]` 段）。
///
/// # 关闭态 = 现状
///
/// 两个档位默认均为 `off` ⇒ 不读取 UA 判定、不查历史登录、**不产生额外审计行**，
/// 与改造前逐字节等价。开启后才产生对应行为（可选集成点）。
#[derive(Clone, Debug, Deserialize)]
pub struct RiskControlConfig {
    /// 登录面工具型 UA 处置（`off` | `block` | `strict`），默认 `off`。
    #[serde(default = "default_login_ua_filter")]
    pub login_ua_filter: String,
    /// 自定义工具型 UA 特征清单（**大小写无关的子串匹配**，取小写后比对）。
    /// 留空 ⇒ 使用内置 [`DEFAULT_UA_BLOCKLIST`]。
    #[serde(default)]
    pub login_ua_blocklist: Vec<String>,
    /// 登录面异地告警（`off` | `alert`），默认 `off`。
    #[serde(default = "default_login_geo_alert")]
    pub login_geo_alert: String,
}

impl Default for RiskControlConfig {
    fn default() -> Self {
        Self {
            login_ua_filter: default_login_ua_filter(),
            login_ua_blocklist: Vec::new(),
            login_geo_alert: default_login_geo_alert(),
        }
    }
}

impl RiskControlConfig {
    pub fn ua_filter(&self) -> LoginUaFilterMode {
        LoginUaFilterMode::parse(&self.login_ua_filter)
    }

    pub fn geo_alert(&self) -> LoginGeoAlertMode {
        LoginGeoAlertMode::parse(&self.login_geo_alert)
    }

    /// 生效的 UA 特征清单（已小写化；配置为空 ⇒ 内置默认清单）。
    pub fn ua_patterns(&self) -> Vec<String> {
        let source: Vec<String> = if self.login_ua_blocklist.is_empty() {
            DEFAULT_UA_BLOCKLIST
                .iter()
                .map(|s| (*s).to_string())
                .collect()
        } else {
            self.login_ua_blocklist.clone()
        };
        source
            .into_iter()
            .map(|s| s.trim().to_ascii_lowercase())
            .filter(|s| !s.is_empty())
            .collect()
    }
}

fn default_login_ua_filter() -> String {
    LoginUaFilterMode::default().as_str().to_string()
}

fn default_login_geo_alert() -> String {
    LoginGeoAlertMode::default().as_str().to_string()
}

// ==================== 上传文件病毒扫描集成点（[upload_scan]） ====================

/// 上传扫描档位字面量（顺序：默认项在前 ⇒ "默认为现状"）
pub const UPLOAD_SCAN_MODES: &[&str] = &["off", "http"];

/// 上传扫描档位。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum UploadScanMode {
    /// **默认 = 现状**：不发起任何外部调用。
    #[default]
    Off,
    /// 把文件字节 POST 给使用者配置的扫描端点，按响应判定是否放行。
    Http,
}

impl UploadScanMode {
    pub fn parse(raw: &str) -> Self {
        match raw.trim().to_ascii_lowercase().as_str() {
            "http" => Self::Http,
            "off" => Self::Off,
            other => {
                tracing::warn!(
                    value = %other,
                    allowed = ?UPLOAD_SCAN_MODES,
                    "配置 [upload_scan].mode 取值非法，已回落 off（= 现状：不扫描）"
                );
                Self::Off
            }
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::Http => "http",
        }
    }
}

/// 扫描端点请求超时（秒）默认值与夹取区间。
pub const UPLOAD_SCAN_TIMEOUT_MIN_SECS: u64 = 1;
pub const UPLOAD_SCAN_TIMEOUT_MAX_SECS: u64 = 60;

/// 上传文件病毒扫描集成点配置（`[upload_scan]` 段）——**可插拔，不内置杀毒引擎**。
///
/// # 请求/响应对照表（集成契约）
///
/// 请求：`POST <url>`，`Content-Type: application/octet-stream`，body = 文件原始字节；
/// 请求头 `X-Yebot-Filename: <URL 编码后的文件名>`（避免头注入），
/// `token` 非空时附 `Authorization: Bearer <token>`。
///
/// 响应：HTTP 2xx + JSON `{"clean": true|false, "detail": "可选说明"}`。
/// - `clean=true` ⇒ 放行；
/// - `clean=false` ⇒ 拒绝（400，对外用 i18n 文案，**不回显** `detail` 原文，仅落 tracing，防反射注入）；
/// - 非 2xx / 无 `clean` 字段 / 解析失败 / 连接失败 ⇒ 按 `fail_closed` 处置。
///
/// # fail_closed（默认 true）
///
/// 使用者开启扫描即表示"要把扫描作为上传闸门"：扫描器不可用时**默认拒绝上传**（503），
/// 避免"扫描器挂了就等同于没扫描"。确实希望降级放行的部署可显式置 `fail_closed = false`。
#[derive(Clone, Debug, Deserialize)]
pub struct UploadScanConfig {
    /// 档位（`off` | `http`），默认 `off`。
    #[serde(default = "default_upload_scan_mode")]
    pub mode: String,
    /// 扫描端点 URL（`mode = "http"` 时必填；经 `common::ssrf` 校验，禁内网/元数据地址）。
    #[serde(default)]
    pub url: String,
    /// 可选 Bearer 令牌（面向需要鉴权的 AV 网关）。
    #[serde(default)]
    pub token: String,
    /// 请求超时秒数（默认 10，夹取 1..=60）——扫描是**上传主链路**，超时即 503/放行由 `fail_closed` 决定。
    #[serde(default = "default_upload_scan_timeout_secs")]
    pub timeout_secs: u64,
    /// 扫描器不可用时的姿态：`true`（默认）= 拒绝上传（fail-closed），`false` = 记 WARN 后放行。
    #[serde(default = "default_upload_scan_fail_closed")]
    pub fail_closed: bool,
}

impl Default for UploadScanConfig {
    fn default() -> Self {
        Self {
            mode: default_upload_scan_mode(),
            url: String::new(),
            token: String::new(),
            timeout_secs: default_upload_scan_timeout_secs(),
            fail_closed: default_upload_scan_fail_closed(),
        }
    }
}

impl UploadScanConfig {
    pub fn mode(&self) -> UploadScanMode {
        UploadScanMode::parse(&self.mode)
    }

    /// 生效超时（夹取到 `1..=60` 秒）。
    pub fn timeout(&self) -> std::time::Duration {
        std::time::Duration::from_secs(
            self.timeout_secs
                .clamp(UPLOAD_SCAN_TIMEOUT_MIN_SECS, UPLOAD_SCAN_TIMEOUT_MAX_SECS),
        )
    }
}

fn default_upload_scan_mode() -> String {
    UploadScanMode::default().as_str().to_string()
}

fn default_upload_scan_timeout_secs() -> u64 {
    10
}

fn default_upload_scan_fail_closed() -> bool {
    true
}

/// WebAuthn / Passkey 配置（`[webauthn]` 段）——能力位 `auth.webauthn` 的**配置面**。
///
/// # 定位
///
/// 是否可用由**能力位** `auth.webauthn`（平台层 `[features]`）管辖，本段只承载 RP 参数：
/// - `rp_id` / `origin` 是 WebAuthn 的**信任锚**（分别用于 `authData` 的 rpIdHash 校验与
///   `clientDataJSON.origin` 校验），配错即认证恒失败；
/// - 二者留空时从 `[server].cors_origins` 首个来源**推导兜底**（见 [`Self::resolved`]）——
///   同源部署（后端嵌入前端）下推导结果与浏览器实际 origin 一致，开箱可用；
/// - 能力位开启但推导/配置仍为空或非法时，启动打 **WARN**（拒绝静默失效，参照 `[acme]` /
///   `[events]` 的既有写法），请求期返回 503（服务器未就绪）而非静默 500。
///
/// # 安全姿态
///
/// 默认值（`rp_id` / `origin` 空）= 与"未配置"等价；能力位缺省 `off` ⇒ 端点 404，
/// 与改造前逐字节等价（关闭态即安全态）。
#[derive(Clone, Debug, Deserialize)]
pub struct WebauthnConfig {
    /// 依赖方标识（如 `example.com`；**不含 scheme 与端口**）。留空 ⇒ 从
    /// `[server].cors_origins` 首个来源的 host 推导注册域。
    #[serde(default)]
    pub rp_id: String,
    /// 依赖方显示名（浏览器 passkey 提示中展示）。默认 `Yebot`。
    #[serde(default = "default_webauthn_rp_name")]
    pub rp_name: String,
    /// 期望来源（如 `https://example.com`，**含 scheme**）。留空 ⇒ 取
    /// `[server].cors_origins` 首个来源。
    #[serde(default)]
    pub origin: String,
    /// 挑战 / 会话临时态 TTL（秒，默认 300，至少 1）
    #[serde(default = "default_webauthn_state_ttl_secs")]
    pub state_ttl_secs: u64,
}

impl Default for WebauthnConfig {
    fn default() -> Self {
        Self {
            rp_id: String::new(),
            rp_name: default_webauthn_rp_name(),
            origin: String::new(),
            state_ttl_secs: default_webauthn_state_ttl_secs(),
        }
    }
}

impl WebauthnConfig {
    /// 解析出**本次运行的有效 WebAuthn 参数**；`None` = 未配置且无法推导 / 推导结果非法。
    ///
    /// 推导规则（仅在对应字段为空时启用）：
    /// - `origin` ← `[server].cors_origins` 首个非空来源；
    /// - `rp_id` ← 该 origin 的 host 的**注册域**（去掉最左子域：`app.example.com` ⇒ `example.com`；
    ///   `localhost` / IP 原样保留）。
    ///
    /// ⚠️ 注册域推导是**保守启发式**（取末两段标签），对 `a.b.co.uk` 之类的多级公共后缀不精确；
    /// 生产环境请**显式配置** `rp_id`。推导值仅在"使用者未配置"时兜底，且非法时返回 `None`
    /// （fail-closed，宁可不启用也不放行错误信任锚）。
    pub fn resolved(&self, server: &ServerConfig) -> Option<ResolvedWebauthn> {
        let origin = {
            let explicit = self.origin.trim();
            if !explicit.is_empty() {
                explicit.to_string()
            } else {
                server
                    .cors_origins
                    .iter()
                    .map(|s| s.trim())
                    .find(|s| !s.is_empty())?
                    .to_string()
            }
        };
        let rp_id = {
            let explicit = self.rp_id.trim();
            if !explicit.is_empty() {
                explicit.to_string()
            } else {
                registrable_domain_of_origin(&origin)?
            }
        };
        if !is_valid_rp_id(&rp_id) || !is_valid_webauthn_origin(&origin) {
            return None;
        }
        Some(ResolvedWebauthn {
            rp_id,
            rp_name: self.rp_name.clone(),
            origin,
            state_ttl_secs: self.state_ttl_secs.max(1),
        })
    }
}

/// [`WebauthnConfig::resolved`] 的解析结果（rp_id / origin 必定非空且通过基本合法性校验）。
#[derive(Clone, Debug)]
pub struct ResolvedWebauthn {
    pub rp_id: String,
    pub rp_name: String,
    pub origin: String,
    pub state_ttl_secs: u64,
}

fn default_webauthn_rp_name() -> String {
    "Yebot".to_string()
}

fn default_webauthn_state_ttl_secs() -> u64 {
    300
}

/// `rp_id` 基本合法性：非空、无 scheme/端口/路径分隔符（WebAuthn 规范要求 rp_id 为域名后缀）。
fn is_valid_rp_id(rp_id: &str) -> bool {
    let r = rp_id.trim();
    !r.is_empty() && !r.contains('/') && !r.contains(':') && !r.contains(' ')
}

/// `origin` 基本合法性：必须是可解析的 http(s) 绝对 URL（WebAuthn 只允许 http(s)）。
fn is_valid_webauthn_origin(origin: &str) -> bool {
    let o = origin.trim();
    (o.starts_with("https://") || o.starts_with("http://")) && url::Url::parse(o).is_ok()
}

fn registrable_domain_of_origin(origin: &str) -> Option<String> {
    let url = url::Url::parse(origin.trim()).ok()?;
    let host = url.host_str()?;
    Some(registrable_domain(host))
}

/// 取 host 的注册域（保守启发式，见 [`WebauthnConfig::resolved`] 的说明）。
fn registrable_domain(host: &str) -> String {
    if host.eq_ignore_ascii_case("localhost") || host.parse::<std::net::IpAddr>().is_ok() {
        return host.to_string();
    }
    let labels: Vec<&str> = host.split('.').filter(|s| !s.is_empty()).collect();
    if labels.len() <= 2 {
        host.to_string()
    } else {
        labels[labels.len() - 2..].join(".")
    }
}

/// 系统日志保留策略配置（M2：操作日志 / 登录日志定期归档清理）
///
/// 保留天数由 `retention_days` 控制（默认 `LOG_RETENTION_DAYS`=90 天），
/// 供每日归档任务 `cleanup_expired_logs` 读取（cron: "0 0 3 * * *"）。
#[derive(Clone, Deserialize)]
pub struct SysLogConfig {
    /// 操作日志 / 登录日志保留天数（默认 90 天）
    ///
    /// 每日定时清理早于（当前时间 - retention_days）的日志，避免日志表无限增长。
    #[serde(default = "default_sys_log_retention_days")]
    pub retention_days: i64,
}

impl fmt::Debug for SysLogConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SysLogConfig")
            .field("retention_days", &self.retention_days)
            .finish()
    }
}

impl Default for SysLogConfig {
    fn default() -> Self {
        Self {
            retention_days: default_sys_log_retention_days(),
        }
    }
}

fn default_sys_log_retention_days() -> i64 {
    crate::common::constants::LOG_RETENTION_DAYS
}

/// `permission_deny_by_default` 的缺省值：`true`（fail-closed，W-1）
///
/// 与 `from_env_only()`、集成测试夹具保持一致；只有显式写 `false` 才降级为 fail-open。
fn default_deny_by_default() -> bool {
    true
}

/// 个人访问令牌（PAT）配置（Tier-S #3）
#[derive(Clone, Debug, Deserialize)]
pub struct PatConfig {
    /// 是否启用 PAT 鉴权（关闭时携带 ybt_ 前缀的令牌一律 401）
    #[serde(default = "default_pat_enabled")]
    pub enabled: bool,
    /// 令牌前缀（用于在 auth 中间件区分 JWT 与 PAT；真实 JWT 以 "eyJ" 开头，不会冲突）
    #[serde(default = "default_pat_prefix")]
    pub prefix: String,
    /// 创建令牌时的默认有效期（天），用户未指定时使用；NULL 语义由前端显式传 0/不传控制
    #[serde(default = "default_pat_default_expire_days")]
    pub default_expire_days: i64,
    /// 有效期上限（天）：请求的过期天数超过则裁剪至此值；0 表示允许永不过期
    #[serde(default = "default_pat_max_expire_days")]
    pub max_expire_days: i64,
    /// 每用户最多有效令牌数（防令牌泛滥）
    #[serde(default = "default_pat_max_per_user")]
    pub max_per_user: i64,
}

impl Default for PatConfig {
    fn default() -> Self {
        Self {
            enabled: default_pat_enabled(),
            prefix: default_pat_prefix(),
            default_expire_days: default_pat_default_expire_days(),
            max_expire_days: default_pat_max_expire_days(),
            max_per_user: default_pat_max_per_user(),
        }
    }
}

fn default_pat_enabled() -> bool {
    true
}
fn default_pat_prefix() -> String {
    "ybt_".to_string()
}
fn default_pat_default_expire_days() -> i64 {
    90
}
fn default_pat_max_expire_days() -> i64 {
    365
}
fn default_pat_max_per_user() -> i64 {
    20
}

/// 单点登录 / OIDC Provider 配置（Tier B：本系统作为授权服务器）
#[derive(Clone, Debug, Deserialize)]
pub struct SsoConfig {
    /// 是否启用 SSO（OIDC Provider）端点。默认关闭，需显式开启（生产按需）
    #[serde(default = "default_sso_disabled")]
    pub enabled: bool,
    /// OIDC issuer（发现文档 iss 与端点绝对前缀）。
    /// enabled=true 时必须显式配置且为 https（localhost/127.0.0.1 例外）——
    /// v4-P1-2：不再允许按请求 Host 推导（Host 头可被伪造，issuer 可被诱导）。
    #[serde(default)]
    pub issuer: String,
    /// 授权码有效期（秒，默认 60，短 TTL 一次性使用）
    #[serde(default = "default_sso_code_ttl_secs")]
    pub code_ttl_secs: u64,
    /// ID Token 有效期（秒，默认 3600）
    #[serde(default = "default_sso_id_token_ttl_secs")]
    pub id_token_ttl_secs: u64,
    /// access_token（不透明令牌）有效期（秒，默认 3600）。
    /// v4-P0-A：access_token 与 ID Token 生命周期分离——不再错用 id_token_ttl_secs。
    #[serde(default = "default_sso_access_token_ttl_secs")]
    pub access_token_ttl_secs: u64,
    /// v5-D3：refresh_token 有效期（秒，默认 30 天）。
    /// RT 为不透明令牌（与 AT 同构：SHA-256 → `sso:rt:{hash}` 绑定），轮换式使用——
    /// 每次刷新旧 RT 立即作废并签发新 RT；登出/强退/改密全量吊销。
    #[serde(default = "default_sso_refresh_token_ttl_secs")]
    pub refresh_token_ttl_secs: u64,
    /// v5-D3 尾项（批次 4）：是否启用 **RFC 7662 令牌内省**端点 `POST /sso/introspect`。
    ///
    /// 默认 `false` = 端点 404（= 改造前行为）。原判定"不修"的理由是"AT 已是 RS256 可本地
    /// 验签的 JWT"——**该理由与实际不符**（可本地验签的是 ID Token；`access_token` 自
    /// v4-P0-A 起是**不透明令牌**，只存 `sso:at:{sha256}`）。对不发 JWT 的 AT，内省正是
    /// RFC 7662 的标准机制，故按项目准则⑥补上这个**默认关闭**的集成点。
    /// 开启后需客户端认证（client_secret_basic / client_secret_post），且**只为签发它的
    /// 那个客户端**返回 `active: true`（他客户端查询恒 `active: false`，防跨客户端探测）。
    #[serde(default)]
    pub introspection_enabled: bool,
    /// v5 §14 #24（批次 4）：是否为 **GET /sso/authorize 发码/跳转** 写操作审计日志。
    ///
    /// 默认 `false` = 不写（= 改造前行为）。原判定"不为单端点扩展 oper_log 中间件"，
    /// 但授权端点正是钓鱼/越权排查最需要审计的一环；做成开关后想要审计的部署可自行开启。
    #[serde(default)]
    pub audit_authorize_get: bool,
    /// v5-D9（批次 4）：同意页 `logo_uri` 是否经由本服务**代理**拉取。
    ///
    /// 默认 `false` = 同意页直接加载第三方 logo（= 改造前行为，会把用户 IP/Referer
    /// 泄漏给该第三方主机）。开启后同意页改用同源 `/sso/client-logo/{clientId}`，
    /// 由服务端带 SSRF 防护拉取并短缓存。
    #[serde(default)]
    pub proxy_logo_uri: bool,
    /// v5-D11（本轮按准则⑥改判为**默认关的开关**）：`/sso/userinfo` 响应的**服务端**短 TTL 缓存秒数。
    ///
    /// 原定案"不修"，理由是与原则 C「停用即断链」/ D3「吊销即时生效」冲突——**该冲突是真的**，
    /// 但"性能 vs 吊销即时性"应由部署方自己权衡，故做成显式开关：
    /// - `0`（默认）= **不缓存** = 改造前行为（每次 userinfo 都回查令牌绑定）；
    /// - `> 0` = 按 AT 哈希缓存响应，**硬上限 300 秒**（`USERINFO_CACHE_MAX_SECS`）——
    ///   即开启后最多容忍 300 秒的吊销延迟，绝不允许配成"小时级"。
    ///
    /// ⚠️ 与 `access_token_ttl_secs` 无关：缓存 TTL 短于 AT 有效期时，AT 过期后
    /// 缓存条目虽仍在，但 `userinfo` 不会因缓存命中而绕过"AT 过期即失效"——缓存键以
    /// **AT 哈希**为维度，且 TTL 上限 300s ⇒ 最坏情况是本已吊销的 AT 在 300s 内仍可读 userinfo。
    #[serde(default)]
    pub userinfo_cache_ttl_secs: u64,
    /// v5-D9（SSO-3 **最后一项**，本轮按准则⑥由「登记为单独专题」改判为**默认关的开关**）：
    /// 同意页**服务端票据**。
    ///
    /// # 解决什么
    ///
    /// `POST /sso/consent` 的入参是对 `authorize` 参数的**客户端回显**（clientId / redirectUri /
    /// scope / state / nonce / codeChallenge）。服务端已用 `resolve_redirect_uri` 白名单 +
    /// `scopes_subset` 收敛了实际后果，但"同意参数可被中间人/被诱导的浏览器篡改"这一攻击面
    /// 本身仍在（典型：把 `scope` 换成更大集合、把 `redirectUri` 换成同客户端的另一个地址）。
    ///
    /// # 语义
    ///
    /// - `off`（**默认**）：**完全跳过**票据签发与校验 = 改造前行为，逐字节等价；
    /// - `required`：`authorize` 判定需同意时签发**一次性服务端票据**（随机 id 落 Redis，
    ///   票面 = 上述参数 + 发起用户的 `userId`），经 `/sso-consent?ticket=...` 交给前端；
    ///   `POST /sso/consent` 必须携带该票据，且回显参数与票面**逐字一致**（`None` 与空串归一后比），
    ///   否则一律 400；票据**一次性消费**（校验通过即 DEL，批准/拒绝都消费）且做**归属校验**
    ///   （票面 `userId` 必须等于当前登录用户）。
    ///
    /// ⚠️ 票据是**服务端真相**（随机 id + Redis 票面），不引入新的签名密钥；
    /// Redis 未命中 / 过期 / 被篡改 ⇒ 400（fail-closed）。
    /// ⚠️ 开启会改变同意页契约（前端需回传 `ticket`）——前端已做兼容：后端不下发则字段缺省。
    #[serde(default = "default_sso_consent_ticket_mode")]
    pub consent_ticket: String,
    /// v5-D9：同意票据有效期（秒，默认 300；夹取 `60..=1800`）。
    ///
    /// 票据只需覆盖"用户读完同意页并点按钮"的窗口；过短会让正常用户中途失效，
    /// 过长则扩大重放窗口（票据已一次性，故上限 1800s 足够保守）。
    #[serde(default = "default_sso_consent_ticket_ttl_secs")]
    pub consent_ticket_ttl_secs: u64,
}

impl Default for SsoConfig {
    fn default() -> Self {
        Self {
            enabled: default_sso_disabled(),
            issuer: String::new(),
            code_ttl_secs: default_sso_code_ttl_secs(),
            id_token_ttl_secs: default_sso_id_token_ttl_secs(),
            access_token_ttl_secs: default_sso_access_token_ttl_secs(),
            refresh_token_ttl_secs: default_sso_refresh_token_ttl_secs(),
            introspection_enabled: false,
            audit_authorize_get: false,
            proxy_logo_uri: false,
            userinfo_cache_ttl_secs: 0,
            consent_ticket: default_sso_consent_ticket_mode(),
            consent_ticket_ttl_secs: default_sso_consent_ticket_ttl_secs(),
        }
    }
}

fn default_sso_disabled() -> bool {
    false
}

/// `/sso/userinfo` 服务端缓存的**硬上限**（秒）：即便配置写得更大也被夹到这里。
///
/// 300s 是"性能可感"与"吊销延迟可接受"之间的折中；不允许更长，
/// 以免开关被当成"绕过停用即时断链"的手段。
pub const USERINFO_CACHE_MAX_SECS: u64 = 300;

fn default_sso_code_ttl_secs() -> u64 {
    60
}
fn default_sso_id_token_ttl_secs() -> u64 {
    3600
}
fn default_sso_access_token_ttl_secs() -> u64 {
    3600
}
fn default_sso_refresh_token_ttl_secs() -> u64 {
    30 * 24 * 3600
}

/// 同意票据档位（`[sso].consent_ticket`）
///
/// 开关取「模式」而非裸 bool（项目准则③）：将来若需要"仅记录不拦截"的观察档，
/// 可直接扩 `log_only` 而不破坏现有取值语义。
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum SsoConsentTicketMode {
    /// 关闭：不签发、不校验同意票据 —— **默认，等价于改造前行为**
    #[default]
    Off,
    /// 必须携带服务端签发的一次性票据，且回显参数须与票面逐字一致
    Required,
}

/// `SsoConsentTicketMode` 的合法模式串（顺序：默认项在前）
pub const SSO_CONSENT_TICKET_MODES: &[&str] = &["off", "required"];

impl SsoConsentTicketMode {
    /// 解析配置串（大小写无关、两端 trim）；未登记取值一律回落 [`Self::Off`] 并打 WARN
    /// （fail-safe，不拒绝启动）。
    pub fn parse(raw: &str) -> Self {
        match raw.trim().to_ascii_lowercase().as_str() {
            "required" => Self::Required,
            "off" => Self::Off,
            other => {
                tracing::warn!(
                    value = %other,
                    fallback = "off",
                    allowed = ?SSO_CONSENT_TICKET_MODES,
                    "配置 [sso].consent_ticket 取值非法，已回落 off（= 现状：不校验同意票据）"
                );
                Self::Off
            }
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::Required => "required",
        }
    }
}

/// 同意票据 TTL 的下界 / 上界（秒）
pub const SSO_CONSENT_TICKET_TTL_MIN_SECS: u64 = 60;
pub const SSO_CONSENT_TICKET_TTL_MAX_SECS: u64 = 1800;

impl SsoConfig {
    /// 解析后的同意票模式（非法值已由 [`SsoConsentTicketMode::parse`] 打 WARN 并回落 `off`）
    pub fn consent_ticket_mode(&self) -> SsoConsentTicketMode {
        SsoConsentTicketMode::parse(&self.consent_ticket)
    }

    /// 同意票据有效期（秒）：夹在 `60..=1800`，防止配成 0（立即失效）或过长（扩大重放窗口）
    pub fn consent_ticket_ttl(&self) -> u64 {
        self.consent_ticket_ttl_secs.clamp(
            SSO_CONSENT_TICKET_TTL_MIN_SECS,
            SSO_CONSENT_TICKET_TTL_MAX_SECS,
        )
    }
}

fn default_sso_consent_ticket_mode() -> String {
    SsoConsentTicketMode::default().as_str().to_string()
}

fn default_sso_consent_ticket_ttl_secs() -> u64 {
    300
}

/// v5-D12：SCIM 2.0 用户目录同步配置（RFC 7644 最小可用子集）
#[derive(Clone, Deserialize)]
pub struct ScimConfig {
    /// 是否启用 /scim/v2 端点。默认关闭，需显式开启（SCIM_ENABLED=true）
    #[serde(default = "default_scim_disabled")]
    pub enabled: bool,
    /// SCIM Bearer Token（IdP 服务器对服务器调用的专用凭据，与用户 JWT 无关）。
    /// enabled=true 时必须非空且 ≥32 字符（SCIM_BEARER_TOKEN 环境变量注入）。
    #[serde(default)]
    pub bearer_token: String,
    /// SCIM 凭据归属租户（v5-N2 Phase 3 收口）：该凭据 provisioning 出的用户/组
    /// 归属此租户，读路径亦按此租户过滤。0 = 平台租户（全局 provisioning，不过滤）。
    /// 通过 SCIM_TENANT_ID 环境变量注入。
    #[serde(default)]
    pub tenant_id: i64,
}

impl Default for ScimConfig {
    fn default() -> Self {
        Self {
            enabled: default_scim_disabled(),
            bearer_token: String::new(),
            tenant_id: 0,
        }
    }
}

fn default_scim_disabled() -> bool {
    false
}

/// 可观测性监控配置（慢请求 / 错误聚合 / Prometheus 指标）
#[derive(Clone, Deserialize)]
pub struct MonitorConfig {
    /// /metrics 端点 Bearer token（脱敏）。
    ///
    /// 留空表示 /metrics 匿名可访问（本地 curl / 无鉴权抓取）。
    /// 生产环境强烈建议设置（可通过 MONITOR_METRICS_TOKEN 环境变量注入）。
    #[serde(default)]
    pub metrics_token: String,
    /// 慢请求阈值（毫秒），超过才记录到慢请求缓冲（默认 300ms）
    #[serde(default = "default_slow_request_ms")]
    pub slow_request_ms: u64,
    /// 慢请求缓冲容量（默认 200）
    #[serde(default = "default_slow_capacity")]
    pub slow_capacity: usize,
    /// 错误聚合缓冲容量（默认 500）
    #[serde(default = "default_error_capacity")]
    pub error_capacity: usize,
}

/// 手动实现 Debug 以脱敏 metrics_token
impl fmt::Debug for MonitorConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MonitorConfig")
            .field("metrics_token", &"<redacted>")
            .field("slow_request_ms", &self.slow_request_ms)
            .field("slow_capacity", &self.slow_capacity)
            .field("error_capacity", &self.error_capacity)
            .finish()
    }
}

impl Default for MonitorConfig {
    fn default() -> Self {
        Self {
            metrics_token: String::new(),
            slow_request_ms: default_slow_request_ms(),
            slow_capacity: default_slow_capacity(),
            error_capacity: default_error_capacity(),
        }
    }
}

fn default_slow_request_ms() -> u64 {
    300
}

fn default_slow_capacity() -> usize {
    200
}

fn default_error_capacity() -> usize {
    500
}

#[derive(Debug, Clone, Deserialize)]
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
    /// CORS 允许的 Origin 白名单（生产环境必须显式配置）
    pub cors_origins: Vec<String>,
    /// 可信代理 IP 白名单（CIDR 或精确 IP）
    ///
    /// 仅当直连客户端 IP 在此列表内时，才信任 X-Forwarded-For / X-Real-IP。
    /// 空列表表示不信任任何代理头，直接使用 TCP 对端 IP。
    /// 生产环境应配置为反向代理的真实 IP（如 nginx 所在机器）。
    #[serde(default)]
    pub trusted_proxies: Vec<String>,
    /// 是否启用 API 文档（Swagger UI / OpenAPI JSON），生产环境建议关闭
    #[serde(default = "default_docs_enabled")]
    pub docs_enabled: bool,
    /// P2-33：HTTP 状态码约定（`legacy` | `restful`）。
    ///
    /// - `legacy`（**默认 = 现状**）：已知业务码（400/401/403/404/409/422/429/500/503）
    ///   映射为同名真实 HTTP 状态，未归类业务码回落 `200 OK`（R19-4.3 既有行为）；
    /// - `restful`：业务失败**绝不**返回 200 —— 标准 HTTP 域（400..=599）取该状态，
    ///   2xx 取 200，其余自定义业务码（如 TOTP 的 `1003`）按 `400` 归类
    ///   （便于网关/监控直接按 HTTP 状态码告警，而无需解析 body）。
    ///
    /// ⚠️ 两档差异**只在未归类业务码**上；已知码两档一致。非法值回落 `legacy`（fail-safe）。
    /// 前端 `request.ts` 错误分支已同样识别 `body.code`（含 1003），故切换不会造成断链。
    #[serde(default = "default_http_status_convention")]
    pub http_status_convention: String,
}

/// P2-33 默认档：`legacy`（= 现状零变更）。取值单一事实源在
/// [`crate::common::http_status::HttpStatusConvention`]。
fn default_http_status_convention() -> String {
    crate::common::http_status::HttpStatusConvention::default()
        .as_str()
        .to_string()
}

#[derive(Clone, Deserialize)]
pub struct DatabaseConfig {
    pub url: String,
    pub max_connections: u32,
    pub min_connections: u32,
    pub connect_timeout: u64,
    pub idle_timeout: u64,
    /// 连接最大生命周期（秒，默认 1800=30 分钟）
    ///
    /// 避免长连接因 MySQL wait_timeout / 网络中间件探活失效而出现静默断开。
    #[serde(default = "default_db_max_lifetime_secs")]
    pub max_lifetime_secs: u64,
    /// 从池中获取连接的等待超时（秒，默认 10）
    ///
    /// 超时返回错误（业务层转为 503），而非无限阻塞协程。
    #[serde(default = "default_db_acquire_timeout_secs")]
    pub acquire_timeout_secs: u64,
    /// 语句级超时（秒，默认 60；**0 = 关闭**）
    ///
    /// R9-ERR-004：防止单条 SQL（报表/误操作全表查询）无限占用连接拖垮服务。
    /// - PostgreSQL：连接参数 `statement_timeout`（覆盖全部语句）+
    ///   `idle_in_transaction_session_timeout`（同值，防"开事务后挂起"泄漏）；
    /// - MySQL：连接建立后 `SET SESSION max_execution_time`（⚠️ 仅覆盖 SELECT，
    ///   写语句无服务端语句超时，属 MySQL 引擎限制）；
    /// - SQLite：本地嵌入库无服务端语句超时概念，`busy_timeout=5s` 已兜底锁等待，
    ///   本项对 SQLite 不生效。
    ///
    /// 报表类长查询请按需调大或关闭（0）。连接池初始化时快照到
    /// [`crate::db::limits`]，仓库层零签名穿透读取。
    #[serde(default = "default_db_statement_timeout_secs")]
    pub statement_timeout_secs: u64,
    /// data_scope 部门递归 CTE 深度上限（默认 30）
    ///
    /// `find_descendant_ids` 的 `WITH RECURSIVE` 以 `depth < dept_cte_max_depth`
    /// 纵深防御脏数据成环（PostgreSQL 递归 CTE 无内置上限，SQLite/MySQL 有）。
    /// 写入侧另有防环校验（sys_dept_service），本值属第二道防线。
    #[serde(default = "default_db_dept_cte_max_depth")]
    pub dept_cte_max_depth: u32,
}

/// 手动实现 Debug 以脱敏 url（含数据库密码）
impl fmt::Debug for DatabaseConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DatabaseConfig")
            .field("url", &"<redacted>")
            .field("max_connections", &self.max_connections)
            .field("min_connections", &self.min_connections)
            .field("connect_timeout", &self.connect_timeout)
            .field("idle_timeout", &self.idle_timeout)
            .field("max_lifetime_secs", &self.max_lifetime_secs)
            .field("acquire_timeout_secs", &self.acquire_timeout_secs)
            .field("statement_timeout_secs", &self.statement_timeout_secs)
            .field("dept_cte_max_depth", &self.dept_cte_max_depth)
            .finish()
    }
}

fn default_db_max_lifetime_secs() -> u64 {
    1800
}

fn default_db_acquire_timeout_secs() -> u64 {
    10
}

fn default_db_statement_timeout_secs() -> u64 {
    60
}

fn default_db_dept_cte_max_depth() -> u32 {
    30
}

#[derive(Clone, Deserialize)]
pub struct RedisConfig {
    pub url: String,
}

/// 手动实现 Debug 以脱敏 url（含 Redis 密码）
impl fmt::Debug for RedisConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RedisConfig")
            .field("url", &"<redacted>")
            .finish()
    }
}

#[derive(Clone, Deserialize)]
pub struct JwtConfig {
    pub secret: String,
    pub expire_hours: i64,
    pub issuer: String,
    /// JWT 受众（aud claim），用于防止 token 跨服务复用（SEC-001）
    /// 默认 "yebot"，生产环境应通过配置显式指定
    #[serde(default = "default_jwt_audience")]
    pub audience: String,
    /// **密钥轮换过渡期**：旧签名密钥（仅用于**验签回退**，永不用于签发）。
    ///
    /// 零停机轮换：① 生成新密钥，把**当前密钥**移入本列表、`secret` 换成新密钥 → 滚动发布；
    /// ② 过渡期内新 token 用新密钥签发、旧 token 用旧密钥验签（用户无感）；
    /// ③ 待最长有效期（`expire_hours`）过后清空本列表 ⇒ 轮换完成。
    ///
    /// 缺省为空 ⇒ 与改造前逐字节等价（单密钥）。旧密钥同样受 `validate_secrets`
    /// 强密钥校验（弱密钥 fail-closed 拒绝启动）。
    #[serde(default)]
    pub previous_secrets: Vec<String>,
}

impl JwtConfig {
    /// 验签候选密钥：**当前密钥优先**，其后依次为 `previous_secrets`
    /// （去首尾空白、忽略空串、按值去重）。顺序即优先级。
    pub fn verification_secrets(&self) -> Vec<&str> {
        let mut out: Vec<&str> = vec![self.secret.as_str()];
        for secret in &self.previous_secrets {
            let secret = secret.trim();
            if !secret.is_empty() && !out.contains(&secret) {
                out.push(secret);
            }
        }
        out
    }
}

/// 手动实现 Debug 以脱敏 secret
impl fmt::Debug for JwtConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("JwtConfig")
            .field("secret", &"<redacted>")
            .field("expire_hours", &self.expire_hours)
            .field("issuer", &self.issuer)
            .field("audience", &self.audience)
            .field(
                "previous_secrets",
                &format!("<redacted; {} 项>", self.previous_secrets.len()),
            )
            .finish()
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct LogConfig {
    pub level: String,
    pub sql_logging: bool,
    /// 日志文件输出目录（相对路径，默认 "logs"）
    /// 配置后日志会同时输出到 stdout 和文件（按日轮转）
    #[serde(default = "default_log_file_path")]
    pub file_path: String,
    /// stdout 是否使用 JSON 结构化格式（P2-9，生产环境推荐 true，便于 ELK/Loki 采集）
    /// 文件层始终使用纯文本（grep 友好）
    #[serde(default)]
    pub json_stdout: bool,
}

/// 文件上传配置
#[derive(Debug, Clone, Deserialize)]
pub struct UploadConfig {
    /// 头像存储目录（相对路径，如 "uploads/avatar"）
    #[serde(default = "default_avatar_dir")]
    pub avatar_dir: String,
    /// 头像访问 URL 前缀（如 "/uploads/avatar"）
    #[serde(default = "default_avatar_url_prefix")]
    pub avatar_url_prefix: String,
    /// 允许的头像扩展名白名单（小写，不含点）
    #[serde(default = "default_avatar_allowed_exts")]
    pub avatar_allowed_exts: Vec<String>,
    /// 头像最大字节数
    #[serde(default = "default_avatar_max_size")]
    pub avatar_max_size: usize,
    /// 通用上传文件存储目录（相对路径，如 "uploads/file"）
    #[serde(default = "default_common_dir")]
    pub common_dir: String,
    /// 通用上传文件访问 URL 前缀（如 "/uploads/file"）
    #[serde(default = "default_common_url_prefix")]
    pub common_url_prefix: String,
    /// 通用上传允许的扩展名白名单（小写，不含点）
    #[serde(default = "default_common_allowed_exts")]
    pub common_allowed_exts: Vec<String>,
    /// 通用上传最大字节数
    #[serde(default = "default_common_max_size")]
    pub common_max_size: usize,
    /// 存储后端类型（`local` 或 `s3`），默认 local（F1）
    ///
    /// - `local`：本地文件系统（现有默认行为，配合 `/uploads/*` 静态托管）
    /// - `s3`：S3 兼容对象存储（MinIO / AWS S3 / 阿里云 OSS / 腾讯 COS），
    ///   文件保存到 `s3.bucket` 的 `uploads/...` 前缀下，并通过 `s3.public_endpoint`
    ///   生成可访问 URL（前端无需任何改动）
    #[serde(default = "default_upload_backend")]
    pub backend: String,
    /// S3 兼容对象存储配置（backend=s3 时使用）
    #[serde(default)]
    pub s3: S3StorageConfig,
}

impl Default for UploadConfig {
    fn default() -> Self {
        Self {
            avatar_dir: default_avatar_dir(),
            avatar_url_prefix: default_avatar_url_prefix(),
            avatar_allowed_exts: default_avatar_allowed_exts(),
            avatar_max_size: default_avatar_max_size(),
            common_dir: default_common_dir(),
            common_url_prefix: default_common_url_prefix(),
            common_allowed_exts: default_common_allowed_exts(),
            common_max_size: default_common_max_size(),
            backend: default_upload_backend(),
            s3: S3StorageConfig::default(),
        }
    }
}

fn default_avatar_dir() -> String {
    "uploads/avatar".to_string()
}

/// S3 兼容对象存储配置（F1）
///
/// 支持 MinIO / AWS S3 / 阿里云 OSS / 腾讯 COS 等一切 S3 兼容端点。
/// 存储时对象 key 使用 `uploads/{dir}/{uuid}.{ext}` 前缀，路径风格（path-style）统一，
/// 便于从 `public_endpoint` 直接返回可访问 URL。
#[derive(Clone, Deserialize)]
pub struct S3StorageConfig {
    /// 访问密钥 ID（AK）
    #[serde(default)]
    pub access_key: String,
    /// 访问密钥 Secret（SK，生产环境建议通过 S3_SECRET_KEY 环境变量注入）
    #[serde(default)]
    pub secret_key: String,
    /// S3 端点（如 `https://minio.example.com:9000` 或 `https://s3.cn-north-1.amazonaws.com.cn`）
    #[serde(default)]
    pub endpoint: String,
    /// 区域（如 `us-east-1`、`cn-north-1`）
    #[serde(default = "default_s3_region")]
    pub region: String,
    /// 桶名（Bucket）
    #[serde(default)]
    pub bucket: String,
    /// 寻址风格：`true` 路径风格（MinIO / 阿里云 OSS / 腾讯 COS 默认），
    /// 对象 URI 为 `/{bucket}/{key}`；`false` 虚拟主机风格（AWS S3 推荐），
    /// bucket 作为 endpoint 的子域（`{bucket}.{host}/{key}`），并将 endpoint 设为
    /// `https://s3.{region}.amazonaws.com`。可通过环境变量 `S3_PATH_STYLE=false` 覆盖。
    #[serde(default = "default_s3_path_style")]
    pub path_style: bool,
    /// 对象访问公开 URL 前缀（用于前端拼接访问地址，如 `https://cdn.example.com`）。
    /// 为空时回退使用 `endpoint`。
    #[serde(default)]
    pub public_endpoint: String,
}

/// 手动实现 Debug 以脱敏 secret_key
impl fmt::Debug for S3StorageConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("S3StorageConfig")
            .field("access_key", &self.access_key)
            .field("secret_key", &"<redacted>")
            .field("endpoint", &self.endpoint)
            .field("region", &self.region)
            .field("bucket", &self.bucket)
            .field("path_style", &self.path_style)
            .field("public_endpoint", &self.public_endpoint)
            .finish()
    }
}

impl Default for S3StorageConfig {
    fn default() -> Self {
        Self {
            access_key: String::new(),
            secret_key: String::new(),
            endpoint: String::new(),
            region: default_s3_region(),
            bucket: String::new(),
            path_style: default_s3_path_style(),
            public_endpoint: String::new(),
        }
    }
}

fn default_upload_backend() -> String {
    "local".to_string()
}

fn default_s3_region() -> String {
    "us-east-1".to_string()
}

fn default_s3_path_style() -> bool {
    true
}

/// 日志文件输出目录默认值（P0-67 未修复项）
fn default_log_file_path() -> String {
    "logs".to_string()
}

fn default_avatar_url_prefix() -> String {
    "/uploads/avatar".to_string()
}

fn default_avatar_allowed_exts() -> Vec<String> {
    vec![
        "jpg".to_string(),
        "jpeg".to_string(),
        "png".to_string(),
        "gif".to_string(),
    ]
}

fn default_avatar_max_size() -> usize {
    crate::common::constants::AVATAR_MAX_SIZE
}

fn default_common_dir() -> String {
    "uploads/file".to_string()
}

fn default_common_url_prefix() -> String {
    "/uploads/file".to_string()
}

fn default_common_allowed_exts() -> Vec<String> {
    vec![
        "jpg".to_string(),
        "jpeg".to_string(),
        "png".to_string(),
        "gif".to_string(),
        "pdf".to_string(),
        "doc".to_string(),
        "docx".to_string(),
        "xls".to_string(),
        "xlsx".to_string(),
        "txt".to_string(),
        "zip".to_string(),
    ]
}

fn default_common_max_size() -> usize {
    crate::common::constants::UPLOAD_MAX_SIZE
}

/// 审批工作流配置（m20260923_000002 flow_module）
///
/// - `timeout_scan_cron` 为空 = 禁用超时扫描任务（mmdb_auto_update 同款约定）
/// - `enabled` 为第二开关（运行配置级），两个条件同时满足才注册任务
#[derive(Debug, Clone, Deserialize)]
pub struct FlowConfig {
    /// 超时扫描 cron（6 字段含秒，默认每 10 分钟）；空字符串 = 禁用
    #[serde(default = "default_flow_scan_cron")]
    pub timeout_scan_cron: String,
    /// 是否启用审批超时扫描（第二开关，默认 true）
    #[serde(default = "default_flow_scan_enabled")]
    pub enabled: bool,
    /// 待办 SLA 时长（小时，超过即触发提醒；默认 48h）
    #[serde(default = "default_flow_timeout_hours")]
    pub timeout_hours: i64,
    /// 同一任务的重复提醒间隔（秒，Redis SETNX TTL；默认 3600）
    ///
    /// W-7 起语义收窄为"**首次提醒**的多实例互斥窗口"：提醒只发一次
    /// （DB `last_reminded_at` 为事实源），后续不再重复打扰（待办红点常驻由列表承担）。
    #[serde(default = "default_flow_remind_interval")]
    pub remind_interval_secs: u64,
    /// 升级提醒阈值（小时；默认 72；**0 = 关闭升级**）
    ///
    /// 待办超时超过该时长仍 pending 时，额外提醒一次**申请人部门主管**（不可用时回退 admin），
    /// 形成"首次提醒本人 → 超 N 天升级主管"的闭环（W-7 推荐策略）。
    #[serde(default = "default_flow_escalate_after_hours")]
    pub escalate_after_hours: i64,
    /// 单次扫描最多处理的任务数（分页限量，防止超出任务超时上限）
    #[serde(default = "default_flow_scan_batch")]
    pub scan_batch_limit: u64,
    /// 是否启用**分布式扫描锁**（S-1；默认 `false` = 接受单实例部署假设）
    ///
    /// 单实例部署下无需锁：逐任务 `SET NX` 已能防止重复提醒。多实例部署时须置 `true`，
    /// 否则多实例会**同时**执行整轮扫描（逐任务去重只能收窄不能消除重复提醒/巡检开销）。
    /// 锁 key 为 `lock:scheduler:flow_timeout_scan`，释放走 Lua CAS（防误删他实例的锁）。
    #[serde(default = "default_flow_scan_lock_enabled")]
    pub scan_lock_enabled: bool,
    /// 分布式扫描锁 TTL（秒；默认 300 = 5 分钟）
    ///
    /// 必须**大于**单轮扫描的最坏耗时（`scan_batch_limit` 条任务的提醒 + 巡检），
    /// 否则锁提前过期会导致并发窗口重现；同理过大会在实例崩溃后延长恢复窗口。
    #[serde(default = "default_flow_scan_lock_ttl")]
    pub scan_lock_ttl_secs: u64,
}

fn default_flow_scan_cron() -> String {
    "0 */10 * * * *".to_string()
}
fn default_flow_scan_enabled() -> bool {
    true
}
fn default_flow_timeout_hours() -> i64 {
    48
}
fn default_flow_remind_interval() -> u64 {
    3600
}
fn default_flow_escalate_after_hours() -> i64 {
    72
}
fn default_flow_scan_batch() -> u64 {
    200
}
fn default_flow_scan_lock_enabled() -> bool {
    false
}
fn default_flow_scan_lock_ttl() -> u64 {
    300
}

impl Default for FlowConfig {
    fn default() -> Self {
        Self {
            timeout_scan_cron: default_flow_scan_cron(),
            enabled: default_flow_scan_enabled(),
            timeout_hours: default_flow_timeout_hours(),
            remind_interval_secs: default_flow_remind_interval(),
            escalate_after_hours: default_flow_escalate_after_hours(),
            scan_batch_limit: default_flow_scan_batch(),
            scan_lock_enabled: default_flow_scan_lock_enabled(),
            scan_lock_ttl_secs: default_flow_scan_lock_ttl(),
        }
    }
}

/// IP 归属地查询配置
#[derive(Debug, Clone, Deserialize)]
pub struct IpLocationConfig {
    /// MaxMindDB 离线数据库文件路径（相对路径，默认 "data/GeoLite2-City.mmdb"）
    /// 文件不存在时所有查询返回空字符串，不影响业务流程
    #[serde(default = "default_mmdb_path")]
    pub mmdb_path: String,
    /// ip2region xdb 数据库文件路径（相对路径，可选）
    /// 启用后国内 IP 优先查 xdb（精度到县级行政区划），未命中再查 mmdb
    #[serde(default = "default_xdb_path")]
    pub xdb_path: String,
    /// 是否启用 ip2region 双库混合模式
    #[serde(default = "default_xdb_enabled")]
    pub xdb_enabled: bool,
    /// mmdb 自动更新 cron 表达式（6 字段含秒，默认每周二凌晨 4:00）
    /// 设为空字符串则禁用自动更新
    #[serde(default = "default_mmdb_update_cron")]
    pub auto_update_cron: String,
}

impl Default for IpLocationConfig {
    fn default() -> Self {
        Self {
            mmdb_path: default_mmdb_path(),
            xdb_path: default_xdb_path(),
            xdb_enabled: default_xdb_enabled(),
            auto_update_cron: default_mmdb_update_cron(),
        }
    }
}

fn default_mmdb_path() -> String {
    "data/GeoLite2-City.mmdb".to_string()
}

fn default_xdb_path() -> String {
    "data/ip2region.xdb".to_string()
}

fn default_xdb_enabled() -> bool {
    false
}

fn default_mmdb_update_cron() -> String {
    // 每周二凌晨 4:00（6 字段含秒）
    "0 0 4 * * 2".to_string()
}

/// 邮件 SMTP 配置
///
/// 未配置（enabled=false）时邮件功能优雅降级为仅 sys_notice 入库，不发送实际邮件。
/// 生产环境建议通过环境变量 MAIL_PASSWORD 注入 SMTP 密码，避免明文写入配置文件。
#[derive(Clone, Deserialize)]
pub struct MailConfig {
    /// 是否启用 SMTP 邮件发送（false 时所有邮件操作降级为仅记录 sys_notice）
    #[serde(default)]
    pub enabled: bool,
    /// SMTP 服务器主机（如 smtp.qq.com、smtp.gmail.com）
    #[serde(default)]
    pub host: String,
    /// SMTP 服务器端口（SSL 直连 465，STARTTLS 587）
    #[serde(default = "default_mail_port")]
    pub port: u16,
    /// SMTP 登录用户名（通常为发件邮箱地址）
    #[serde(default)]
    pub username: String,
    /// SMTP 登录密码或授权码（生产环境建议通过 MAIL_PASSWORD 环境变量注入）
    #[serde(default)]
    pub password: String,
    /// 发件人邮箱地址（通常与 username 相同）
    #[serde(default)]
    pub from_email: String,
    /// 发件人显示名称
    #[serde(default = "default_mail_from_name")]
    pub from_name: String,
    /// 是否使用 STARTTLS（端口 587 时通常为 true，端口 465 SSL 直连时为 false）
    #[serde(default = "default_mail_starttls")]
    pub starttls: bool,
}

/// 手动实现 Debug 以脱敏 password
impl fmt::Debug for MailConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MailConfig")
            .field("enabled", &self.enabled)
            .field("host", &self.host)
            .field("port", &self.port)
            .field("username", &self.username)
            .field("password", &"<redacted>")
            .field("from_email", &self.from_email)
            .field("from_name", &self.from_name)
            .field("starttls", &self.starttls)
            .finish()
    }
}

impl Default for MailConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            host: String::new(),
            port: default_mail_port(),
            username: String::new(),
            password: String::new(),
            from_email: String::new(),
            from_name: default_mail_from_name(),
            starttls: default_mail_starttls(),
        }
    }
}

fn default_mail_port() -> u16 {
    465
}

fn default_mail_from_name() -> String {
    "yebot System".to_string()
}

fn default_mail_starttls() -> bool {
    false
}

fn default_docs_enabled() -> bool {
    // 生产环境 fail-closed：默认关闭 Swagger UI，开发环境在 config.toml 显式设 docs_enabled = true
    false
}

fn default_jwt_audience() -> String {
    "yebot".to_string()
}

impl Settings {
    /// 从 toml 配置文件加载，随后用环境变量覆盖敏感字段
    /// 环境变量优先级：DATABASE_URL > REDIS_URL > JWT_SECRET > SERVER_HOST > SERVER_PORT > config.toml
    ///
    /// 配置文件查找链：`path` → 同目录 `config.toml.prod` → 仅环境变量模式。
    /// 这样容器镜像只需注入环境变量（DATABASE_URL/REDIS_URL/JWT_SECRET/...）即可启动，
    /// 无需挂载 `config/config.toml`（该文件已被 .dockerignore 排除，否则会导致启动崩溃）。
    pub fn from_file(path: &str) -> anyhow::Result<Self> {
        let candidates = [path, "config/config.toml.prod"];
        for (idx, cand) in candidates.iter().enumerate() {
            match std::fs::read_to_string(cand) {
                Ok(content) => {
                    let mut settings: Settings = toml::from_str(&content)
                        .map_err(|e| anyhow::anyhow!("解析配置文件 {} 失败: {}", cand, e))?;
                    settings.apply_env_overrides();
                    settings.validate_secrets()?;
                    if idx != 0 {
                        tracing::warn!("配置文件 {} 不存在，已回退使用 {}", path, cand);
                    }
                    return Ok(settings);
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
                Err(e) => {
                    return Err(anyhow::anyhow!("读取配置文件 {} 失败: {}", cand, e));
                }
            }
        }

        // 配置文件全部缺失：回退到仅环境变量模式（容器/无配置文件部署场景）
        tracing::warn!(
            "未找到任何配置文件（{} / config/config.toml.prod），回退到仅环境变量模式",
            path
        );
        Self::from_env_only()
    }

    /// 用环境变量覆盖可注入字段（敏感配置与部署相关参数）
    ///
    /// 覆盖项：DATABASE_URL / REDIS_URL / JWT_SECRET / JWT_EXPIRE_HOURS /
    /// SERVER_HOST / SERVER_PORT / CORS_ORIGINS（可选，逗号分隔）/
    /// MAIL_PASSWORD / CONFIG_ENC_KEY
    fn apply_env_overrides(&mut self) {
        if let Ok(v) = std::env::var("DATABASE_URL") {
            self.database.url = v;
        }
        if let Ok(v) = std::env::var("REDIS_URL") {
            self.redis.url = v;
        }
        if let Ok(v) = std::env::var("JWT_SECRET") {
            self.jwt.secret = v;
        }
        if let Ok(v) = std::env::var("JWT_EXPIRE_HOURS")
            && let Ok(hours) = v.parse::<i64>()
        {
            if hours > 0 {
                self.jwt.expire_hours = hours;
            } else {
                // P2：拒绝 0/负值（会导致 token 立即过期或签发异常），回退默认 24h
                tracing::warn!("JWT_EXPIRE_HOURS={hours} 无效（必须 > 0），回退默认 24 小时");
                self.jwt.expire_hours = 24;
            }
        }
        // 密钥轮换：逗号分隔的旧密钥列表（仅用于验签回退），空项忽略
        if let Ok(v) = std::env::var("JWT_PREVIOUS_SECRETS") {
            self.jwt.previous_secrets = v
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
        }
        if let Ok(v) = std::env::var("SERVER_HOST") {
            self.server.host = v;
        }
        if let Ok(v) = std::env::var("SERVER_PORT")
            && let Ok(port) = v.parse::<u16>()
        {
            self.server.port = port;
        }
        if let Ok(v) = std::env::var("CORS_ORIGINS") {
            let origins: Vec<String> = v
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
            if !origins.is_empty() {
                self.server.cors_origins = origins;
            }
        }
        // 邮件 SMTP 密码通过环境变量注入（避免明文写入配置文件）
        if let Ok(v) = std::env::var("MAIL_PASSWORD") {
            self.mail.password = v;
        }
        // 配置加密主密钥（用于 sys_config 表中敏感字段 AES-256-GCM 加解密）
        // 启用 IP 库管理功能时必须配置，否则 License Key 加密功能失效
        if let Ok(v) = std::env::var("CONFIG_ENC_KEY") {
            self.config_enc_key = v;
        }
        // 权限 fail-closed 开关（B3 / W-1）：未映射路由是否默认拒绝
        // PERMISSION_DENY_BY_DEFAULT=true 时，受保护路由中未登记权限映射且不在"仅登录白名单"的
        // 路径将被拒绝（403），实现 fail-closed，防止新增路由漏登记权限导致越权。
        // 缺省（不设置且配置文件未写）即 true（fail-closed）；显式设 false/0 才降级为 fail-open。
        if let Ok(v) = std::env::var("PERMISSION_DENY_BY_DEFAULT") {
            self.permission_deny_by_default = v == "true" || v == "1";
        }
        // 存储后端类型（F1）：UPLOAD_BACKEND=local|s3
        if let Ok(v) = std::env::var("UPLOAD_BACKEND") {
            self.upload.backend = v;
        }
        // 全局限流实现档位（M-8 收口）：RATE_LIMIT_MODE=local|redis
        // 多实例部署时用环境变量切换（容器场景常无法改配置文件）；非法值由 parse 回落 local 并告警。
        // 缺省（不设置且配置文件未写）即 local（= 现状：进程内令牌桶）。
        if let Ok(v) = std::env::var("RATE_LIMIT_MODE") {
            self.rate_limit.mode = v;
        }
        // S3 兼容对象存储敏感字段通过环境变量注入（避免明文写入配置文件）
        if let Ok(v) = std::env::var("S3_ACCESS_KEY") {
            self.upload.s3.access_key = v;
        }
        if let Ok(v) = std::env::var("S3_SECRET_KEY") {
            self.upload.s3.secret_key = v;
        }
        if let Ok(v) = std::env::var("S3_ENDPOINT") {
            self.upload.s3.endpoint = v;
        }
        if let Ok(v) = std::env::var("S3_REGION") {
            self.upload.s3.region = v;
        }
        if let Ok(v) = std::env::var("S3_BUCKET") {
            self.upload.s3.bucket = v;
        }
        if let Ok(v) = std::env::var("S3_PUBLIC_ENDPOINT") {
            self.upload.s3.public_endpoint = v;
        }
        // 寻址风格开关（F1）：S3_PATH_STYLE=false 切换为虚拟主机风格，缺省保持路径风格
        if let Ok(v) = std::env::var("S3_PATH_STYLE") {
            self.upload.s3.path_style = !(v.eq_ignore_ascii_case("false") || v == "0");
        }
        // 可观测性监控配置（Prometheus 指标 token 脱敏注入，避免明文写入配置文件）
        if let Ok(v) = std::env::var("MONITOR_METRICS_TOKEN") {
            self.monitor.metrics_token = v;
        }
        // 系统日志保留天数（M2）：LOG_RETENTION_DAYS 环境变量覆盖默认 90 天
        if let Ok(v) = std::env::var("LOG_RETENTION_DAYS")
            && let Ok(days) = v.parse::<i64>()
            && days > 0
        {
            self.sys_log.retention_days = days;
        }
        // 单点登录 / OIDC Provider（Tier B）：默认关闭，SSO_ENABLED=true 显式开启
        if let Ok(v) = std::env::var("SSO_ENABLED") {
            self.sso.enabled = v == "true" || v == "1";
        }
        // OIDC issuer（发现文档 iss 与端点绝对前缀），enabled=true 时必须显式配置（v4-P1-2）
        if let Ok(v) = std::env::var("SSO_ISSUER") {
            self.sso.issuer = v;
        }
        // v4-P1-3：TTL 三项支持 env 覆盖（容器场景无法改配置文件）
        if let Ok(v) = std::env::var("SSO_CODE_TTL_SECS")
            && let Ok(n) = v.parse::<u64>()
            && n > 0
        {
            self.sso.code_ttl_secs = n;
        }
        if let Ok(v) = std::env::var("SSO_ID_TOKEN_TTL_SECS")
            && let Ok(n) = v.parse::<u64>()
            && n > 0
        {
            self.sso.id_token_ttl_secs = n;
        }
        if let Ok(v) = std::env::var("SSO_ACCESS_TOKEN_TTL_SECS")
            && let Ok(n) = v.parse::<u64>()
            && n > 0
        {
            self.sso.access_token_ttl_secs = n;
        }
        // v5-D12：SCIM（SCIM_ENABLED=true 显式开启；SCIM_BEARER_TOKEN 为 IdP 调用凭据）
        if let Ok(v) = std::env::var("SCIM_ENABLED") {
            self.scim.enabled = v == "true" || v == "1";
        }
        if let Ok(v) = std::env::var("SCIM_BEARER_TOKEN") {
            self.scim.bearer_token = v;
        }
        // v5-N2 Phase 3：SCIM 凭据归属租户（0=平台租户；非 0 时 provisioning 归属该租户）
        if let Ok(v) = std::env::var("SCIM_TENANT_ID")
            && let Ok(n) = v.parse::<i64>()
        {
            self.scim.tenant_id = n;
        }
    }

    /// 仅从环境变量构建配置（无配置文件场景，如容器通过环境变量注入）
    ///
    /// 必需环境变量：DATABASE_URL、REDIS_URL、JWT_SECRET、SERVER_HOST、SERVER_PORT
    /// 可选环境变量：JWT_EXPIRE_HOURS（默认 24）、CORS_ORIGINS（逗号分隔）、
    ///                MAIL_PASSWORD、CONFIG_ENC_KEY、RUST_LOG（默认 info）
    /// 其余字段使用与结构体一致的内置默认值。
    fn from_env_only() -> anyhow::Result<Self> {
        let database_url = std::env::var("DATABASE_URL").map_err(|_| {
            anyhow::anyhow!("环境变量 DATABASE_URL 未设置（容器部署需通过 -e/compose 注入）")
        })?;
        let redis_url =
            std::env::var("REDIS_URL").map_err(|_| anyhow::anyhow!("环境变量 REDIS_URL 未设置"))?;
        let jwt_secret = std::env::var("JWT_SECRET")
            .map_err(|_| anyhow::anyhow!("环境变量 JWT_SECRET 未设置"))?;
        let server_host = std::env::var("SERVER_HOST")
            .map_err(|_| anyhow::anyhow!("环境变量 SERVER_HOST 未设置"))?;
        let server_port = std::env::var("SERVER_PORT")
            .map_err(|_| anyhow::anyhow!("环境变量 SERVER_PORT 未设置"))?
            .parse::<u16>()
            .map_err(|e| anyhow::anyhow!("SERVER_PORT 解析失败: {}", e))?;
        let jwt_expire_hours = std::env::var("JWT_EXPIRE_HOURS")
            .unwrap_or_else(|_| "24".to_string())
            .parse::<i64>()
            .map_err(|e| anyhow::anyhow!("JWT_EXPIRE_HOURS 解析失败: {}", e))?;

        let mut settings = Settings {
            pat: PatConfig::default(),
            sso: SsoConfig::default(),
            flow: FlowConfig::default(),
            scim: ScimConfig::default(),
            server: ServerConfig {
                host: server_host,
                port: server_port,
                cors_origins: vec![],
                trusted_proxies: vec![],
                docs_enabled: false,
                http_status_convention: default_http_status_convention(),
            },
            database: DatabaseConfig {
                url: database_url,
                max_connections: 20,
                min_connections: 5,
                connect_timeout: 8,
                idle_timeout: 600,
                max_lifetime_secs: 1800,
                acquire_timeout_secs: 10,
                statement_timeout_secs: 60,
                dept_cte_max_depth: 30,
            },
            redis: RedisConfig { url: redis_url },
            jwt: JwtConfig {
                secret: jwt_secret,
                expire_hours: jwt_expire_hours,
                issuer: "yebot".to_string(),
                audience: "yebot".to_string(),
                previous_secrets: vec![],
            },
            log: LogConfig {
                level: std::env::var("RUST_LOG").unwrap_or_else(|_| "info".to_string()),
                sql_logging: false,
                file_path: "logs".to_string(),
                json_stdout: true,
            },
            upload: UploadConfig::default(),
            ip_location: IpLocationConfig::default(),
            mail: MailConfig::default(),
            config_enc_key: std::env::var("CONFIG_ENC_KEY").unwrap_or_default(),
            monitor: MonitorConfig::default(),
            permission_deny_by_default: true,
            sys_log: SysLogConfig::default(),
            features: FeaturesConfig::default(),
            scheduler: SchedulerConfig::default(),
            ui: UiConfig::default(),
            acme: AcmeConfig::default(),
            events: EventsConfig::default(),
            webauthn: WebauthnConfig::default(),
            resilience: ResilienceConfig::default(),
            rate_limit: RateLimitSettings::default(),
            risk_control: RiskControlConfig::default(),
            upload_scan: UploadScanConfig::default(),
        };

        settings.apply_env_overrides();
        settings.validate_secrets()?;
        Ok(settings)
    }

    /// 校验敏感配置不使用默认占位符
    ///
    /// 若 jwt.secret 或 database.url 包含占位符（CHANGE_ME），
    /// 启动时直接报错拒绝，防止生产环境使用不安全配置。
    fn validate_secrets(&self) -> anyhow::Result<()> {
        // B10：显式拒绝弱/占位密钥（大小写不敏感 deny-list），覆盖 CHANGE_ME（旧逻辑）、
        // 测试前缀 yebot_local_test_*、example/password/test_ 等常见弱密钥模式。
        // 使用 deny-list 而非激进熵评分，避免误杀合法开发密钥（向后兼容）。
        let weak_patterns: &[&str] = &[
            "changeme",
            "change_me",
            "test_",
            "yebot_local_test_",
            "example",
            "password",
        ];
        let secret_lower = self.jwt.secret.to_lowercase();
        if weak_patterns.iter().any(|p| secret_lower.contains(p)) {
            anyhow::bail!(
                "jwt.secret 不能使用弱/占位密钥（命中禁止模式），请通过环境变量 JWT_SECRET 设置真实强密钥（至少 32 字符）"
            );
        }
        let db_lower = self.database.url.to_lowercase();
        if db_lower.contains("changeme") || db_lower.contains("change_me") {
            anyhow::bail!(
                "database.url 不能使用默认占位符，请通过环境变量 DATABASE_URL 设置真实数据库连接"
            );
        }
        if self.jwt.secret.len() < 32 {
            anyhow::bail!(
                "jwt.secret 长度不足 32 字符，当前 {} 字符，请设置更强的密钥",
                self.jwt.secret.len()
            );
        }
        // 密钥轮换（多密钥共存）：旧密钥同样参与验签，故强度下限与当前密钥一致——
        // 弱旧密钥会削弱整体签名强度，必须 fail-closed 拒绝启动（不留"过渡期降级"缺口）。
        for (idx, prev) in self.jwt.previous_secrets.iter().enumerate() {
            let prev_lower = prev.to_lowercase();
            if weak_patterns.iter().any(|p| prev_lower.contains(p)) {
                anyhow::bail!(
                    "jwt.previous_secrets[{idx}] 命中弱/占位密钥禁止模式，请移除或更换为真实强密钥"
                );
            }
            if prev.trim().len() < 32 {
                anyhow::bail!(
                    "jwt.previous_secrets[{idx}] 长度不足 32 字符（当前 {} 字符），旧密钥同样需要满足强度下限",
                    prev.trim().len()
                );
            }
        }
        if !self.jwt.previous_secrets.is_empty() {
            tracing::info!(
                count = self.jwt.previous_secrets.len(),
                expire_hours = self.jwt.expire_hours,
                "JWT 密钥轮换过渡期：当前密钥用于签发，previous_secrets 仅用于验签回退；超过最长有效期后请清空该列表"
            );
        }
        // B8：CONFIG_ENC_KEY 用于派生 AES-256-GCM 密钥（crypto.rs 以 SHA256(master_key) 作 KDF）。
        // 若显式配置但熵不足（<32 字符），派生出的密钥可被离线暴力枚举，故强制长度下限。
        // 空值（未配置）保持宽容：系统以明文 fail-open 存储（见 ip_location_service），不在此拦截，
        // 以免破坏依赖空密钥的开发/测试环境。
        if !self.config_enc_key.is_empty() && self.config_enc_key.len() < 32 {
            anyhow::bail!(
                "CONFIG_ENC_KEY 长度不足 32 字符（当前 {} 字符），低熵密钥无法保证 AES-256-GCM 安全，请使用 ≥32 随机字符",
                self.config_enc_key.len()
            );
        }
        // v4-P1-2：SSO 启用时强制显式 issuer（https，localhost/127.0.0.1 例外）。
        // 不再允许按请求 Host 推导 issuer——Host 头可被攻击者伪造，issuer 可被诱导错配。
        if self.sso.enabled {
            let issuer = self.sso.issuer.trim();
            if issuer.is_empty() {
                anyhow::bail!(
                    "SSO_ENABLED=true 时必须显式配置 SSO_ISSUER（https URL），禁止按请求 Host 动态推导（可被伪造）"
                );
            }
            let is_local =
                issuer.starts_with("http://localhost") || issuer.starts_with("http://127.0.0.1");
            if !issuer.starts_with("https://") && !is_local {
                anyhow::bail!(
                    "SSO_ISSUER 必须为 https URL（OIDC 规范要求），当前: {issuer}（本地开发可用 http://localhost 或 http://127.0.0.1）"
                );
            }
        }
        // v5-D12：SCIM 启用时强制显式 Bearer Token（服务器对服务器凭据，低熵即拒绝）
        if self.scim.enabled {
            let bt = self.scim.bearer_token.trim();
            if bt.is_empty() {
                anyhow::bail!("SCIM_ENABLED=true 时必须显式配置 SCIM_BEARER_TOKEN（≥32 随机字符）");
            }
            if bt.len() < 32 {
                anyhow::bail!(
                    "SCIM_BEARER_TOKEN 长度不足 32 字符（当前 {} 字符），低熵令牌无法抵御枚举攻击",
                    bt.len()
                );
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 构造一个通过校验的基准 Settings（jwt.secret 为合法强密钥），供测试复用
    fn make_test_settings() -> Settings {
        Settings {
            pat: PatConfig::default(),
            sso: SsoConfig::default(),
            scim: ScimConfig::default(),
            server: ServerConfig {
                host: "0.0.0.0".to_string(),
                port: 8080,
                cors_origins: vec![],
                trusted_proxies: vec![],
                docs_enabled: false,
                http_status_convention: default_http_status_convention(),
            },
            database: DatabaseConfig {
                url: "postgres://user:pass@host:5432/db".to_string(),
                max_connections: 10,
                min_connections: 1,
                connect_timeout: 8,
                idle_timeout: 600,
                max_lifetime_secs: 1800,
                acquire_timeout_secs: 10,
                statement_timeout_secs: 60,
                dept_cte_max_depth: 30,
            },
            redis: RedisConfig {
                url: "redis://localhost:6379".to_string(),
            },
            jwt: JwtConfig {
                secret: "placeholder-strong-secret-0123456789abcdef".to_string(),
                expire_hours: 24,
                issuer: "yebot".to_string(),
                audience: "yebot".to_string(),
                previous_secrets: vec![],
            },
            log: LogConfig {
                level: "info".to_string(),
                sql_logging: false,
                file_path: "logs".to_string(),
                json_stdout: false,
            },
            upload: UploadConfig::default(),
            ip_location: IpLocationConfig::default(),
            mail: MailConfig::default(),
            config_enc_key: String::new(),
            monitor: MonitorConfig::default(),
            permission_deny_by_default: true,
            flow: FlowConfig::default(),
            sys_log: SysLogConfig::default(),
            features: FeaturesConfig::default(),
            scheduler: SchedulerConfig::default(),
            ui: UiConfig::default(),
            acme: AcmeConfig::default(),
            events: EventsConfig::default(),
            webauthn: WebauthnConfig::default(),
            resilience: ResilienceConfig::default(),
            rate_limit: RateLimitSettings::default(),
            risk_control: RiskControlConfig::default(),
            upload_scan: UploadScanConfig::default(),
        }
    }

    /// W-1 回归：`permission_deny_by_default` 缺键时缺省即 fail-closed（true）
    ///
    /// 防止"换配置来源即换安全姿态"：此前结构体缺省为 false（fail-open），
    /// 而 `from_env_only()` / 集成测试夹具为 true，造成环境漂移。
    /// 以入库模板为基底去掉该键，既覆盖全部必填字段，又直接验证"缺键 == true"。
    #[test]
    fn test_deny_by_default_defaults_to_true() {
        let template = std::fs::read_to_string("config/config.toml.example")
            .expect("config/config.toml.example 应存在");
        let without_key = template
            .lines()
            .filter(|l| !l.trim_start().starts_with("permission_deny_by_default"))
            .collect::<Vec<_>>()
            .join("\n");
        let s: Settings = toml::from_str(&without_key).expect("模板（去掉该键）应可解析");
        assert!(
            s.permission_deny_by_default,
            "permission_deny_by_default 缺省必须为 true（fail-closed）"
        );
    }

    /// v5-D9：同意票档位解析与 TTL 夹取（默认 = 现状；非法值 fail-safe 回落 `off`）。
    #[test]
    fn test_sso_consent_ticket_mode_parse_and_clamp() {
        assert_eq!(
            SsoConsentTicketMode::parse("required"),
            SsoConsentTicketMode::Required
        );
        assert_eq!(
            SsoConsentTicketMode::parse("  REQUIRED  "),
            SsoConsentTicketMode::Required
        );
        assert_eq!(
            SsoConsentTicketMode::parse("off"),
            SsoConsentTicketMode::Off
        );
        for bad in ["", "on", "true", "1", "log_only"] {
            assert_eq!(
                SsoConsentTicketMode::parse(bad),
                SsoConsentTicketMode::Off,
                "{bad:?} 非法取值必须回落 off（默认 = 现状）"
            );
        }
        assert_eq!(SsoConsentTicketMode::default(), SsoConsentTicketMode::Off);
        // 常量清单与枚举双向一致
        assert_eq!(SSO_CONSENT_TICKET_MODES.len(), 2);
        for raw in SSO_CONSENT_TICKET_MODES {
            assert_eq!(SsoConsentTicketMode::parse(raw).as_str(), *raw);
        }
        // 缺省（未写 [sso].consent_ticket）= off + 300s
        let d = SsoConfig::default();
        assert_eq!(d.consent_ticket_mode(), SsoConsentTicketMode::Off);
        assert_eq!(d.consent_ticket_ttl(), 300);
        assert!(!d.consent_ticket.is_empty(), "缺省档位串应为已登记取值");
        // TTL 夹取
        let s = SsoConfig {
            consent_ticket_ttl_secs: 0,
            ..SsoConfig::default()
        };
        assert_eq!(s.consent_ticket_ttl(), SSO_CONSENT_TICKET_TTL_MIN_SECS);
        let s = SsoConfig {
            consent_ticket_ttl_secs: 999_999,
            ..SsoConfig::default()
        };
        assert_eq!(s.consent_ticket_ttl(), SSO_CONSENT_TICKET_TTL_MAX_SECS);
    }

    /// W-1 回归：入库配置模板必须在**顶层**显式 fail-closed
    ///
    /// 曾发生：该键被误写在 `[log]` 段之后，被 TOML 解析进 `log` 表而被**静默忽略**，
    /// 实际生效的是结构体缺省值 —— 安全开关形同虚设。本断言锁住"顶层 + true"两个要点。
    #[test]
    fn test_shipped_config_template_is_fail_closed() {
        // config.toml.example 为唯一入库模板；config.toml / config.toml.prod 均被 .gitignore 排除，
        // 若本机存在则一并校验（缺失时跳过，不算失败）。
        let mut checked = 0usize;
        for path in ["config/config.toml.example", "config/config.toml.prod"] {
            let content = match std::fs::read_to_string(path) {
                Ok(c) => c,
                Err(_) if path.ends_with(".example") => panic!("{path} 缺失（入库模板必须存在）"),
                Err(_) => continue,
            };
            let value: toml::Value =
                toml::from_str(&content).unwrap_or_else(|e| panic!("{path} TOML 解析失败: {e}"));
            assert_eq!(
                value
                    .get("permission_deny_by_default")
                    .and_then(|v| v.as_bool()),
                Some(true),
                "{path} 必须在**顶层**显式 permission_deny_by_default = true；\
                 写在 [table] 段之后会被解析进该表而静默忽略"
            );
            checked += 1;
        }
        assert!(checked >= 1, "至少应校验 config/config.toml.example");
    }

    /// M-8 收口：限流档位解析（**默认 = 现状 local**；非法值 fail-safe 回落 local）+ TTL 夹取
    #[test]
    fn test_rate_limit_mode_parse_and_clamp() {
        assert_eq!(RateLimitMode::parse("redis"), RateLimitMode::Redis);
        assert_eq!(RateLimitMode::parse("  REDIS  "), RateLimitMode::Redis);
        assert_eq!(RateLimitMode::parse("local"), RateLimitMode::Local);
        for bad in ["", "on", "true", "1", "cluster"] {
            assert_eq!(
                RateLimitMode::parse(bad),
                RateLimitMode::Local,
                "{bad:?} 非法取值必须回落 local（默认 = 现状），不得静默改变限流承载方式"
            );
        }
        assert_eq!(RateLimitMode::default(), RateLimitMode::Local);
        // 常量清单与枚举双向一致
        assert_eq!(RATE_LIMIT_MODES.len(), 2);
        for raw in RATE_LIMIT_MODES {
            assert_eq!(RateLimitMode::parse(raw).as_str(), *raw);
        }
        // 缺省（未写 [rate_limit]）= local + 300s
        let d = RateLimitSettings::default();
        assert_eq!(d.mode(), RateLimitMode::Local);
        assert_eq!(d.key_ttl(), 300);
        // TTL 夹取
        let s = RateLimitSettings {
            key_ttl_secs: 0,
            ..RateLimitSettings::default()
        };
        assert_eq!(s.key_ttl(), RATE_LIMIT_KEY_TTL_MIN_SECS);
        let s = RateLimitSettings {
            key_ttl_secs: u64::MAX,
            ..RateLimitSettings::default()
        };
        assert_eq!(s.key_ttl(), RATE_LIMIT_KEY_TTL_MAX_SECS);
        // 入库模板必须保持 local（多实例才显式切 redis）
        let tpl: Settings = toml::from_str(
            &std::fs::read_to_string("config/config.toml.example")
                .expect("config/config.toml.example 应存在"),
        )
        .expect("模板应可解析");
        assert_eq!(
            tpl.rate_limit.mode(),
            RateLimitMode::Local,
            "入库模板不得隐式启用 redis 限流（单实例默认）"
        );
    }

    /// S-1：分布式扫描锁缺省必须**关闭**（明确接受单实例部署假设）
    ///
    /// 与 W-1 相反方向：扫描锁开启时对 Redis 采用 fail-closed，若缺省就开启，
    /// 单实例部署遇到 Redis 抖动会**停止**超时提醒（业务可见的功能倒退）。
    /// 故缺省 false；多实例部署须显式置 true。同时锁 TTL 必须为正数。
    #[test]
    fn test_flow_scan_lock_defaults_to_disabled() {
        let cfg = FlowConfig::default();
        assert!(
            !cfg.scan_lock_enabled,
            "scan_lock_enabled 缺省必须为 false（单实例部署假设；多实例须显式开启）"
        );
        assert!(
            cfg.scan_lock_ttl_secs > 0,
            "scan_lock_ttl_secs 缺省必须为正数（0 会导致锁立即过期，形同无锁）"
        );
        // 缺键解析同样走缺省（老配置文件不写该键不得改变行为）
        let s: Settings = toml::from_str(
            &std::fs::read_to_string("config/config.toml.example")
                .expect("config/config.toml.example 应存在"),
        )
        .expect("模板应可解析");
        assert!(
            !s.flow.scan_lock_enabled,
            "入库模板不得隐式开启扫描锁（保持单实例默认）"
        );
    }

    /// 能力位缺省必须"全关闭"（**关闭态即安全态**）
    ///
    /// 三层开关的最外层（平台 `config`）是"能开什么"的唯一入口：一旦入库模板里
    /// 预置了能力位，所有租户的默认姿态就被悄悄抬高了。故锁死两点：
    /// ① 结构体缺省 = 空覆盖表 ⇒ 全部走注册表默认（`off`）；
    /// ② 入库模板（`config.toml.example` 及本机存在的 `config.toml.prod`）不得预置任何
    ///    非 `off` 的能力位。
    #[test]
    fn test_features_default_to_all_off() {
        use crate::common::features::{FEATURE_OFF, FeatureSet, KNOWN_FEATURES};

        let cfg = FeaturesConfig::default();
        assert!(
            cfg.0.is_empty(),
            "FeaturesConfig 缺省必须为空表（全走注册表默认 off）"
        );
        let set = FeatureSet::sanitized(cfg.0.clone());
        for def in KNOWN_FEATURES {
            assert_eq!(
                set.mode(def.key),
                FEATURE_OFF,
                "{} 在平台层缺省下必须为 off",
                def.key
            );
        }

        for path in ["config/config.toml.example", "config/config.toml.prod"] {
            let content = match std::fs::read_to_string(path) {
                Ok(c) => c,
                Err(_) if path.ends_with(".example") => panic!("{path} 缺失（入库模板必须存在）"),
                Err(_) => continue,
            };
            let s: Settings =
                toml::from_str(&content).unwrap_or_else(|e| panic!("{path} TOML 解析失败: {e}"));
            let set = FeatureSet::sanitized(s.features.0.clone());
            for def in KNOWN_FEATURES {
                assert_eq!(
                    set.mode(def.key),
                    FEATURE_OFF,
                    "{path} 不得预置能力位 {}（默认必须为 off）",
                    def.key
                );
            }
        }
    }

    /// 调度器集群模式缺省必须为 `auto`（= 沿用各任务历史开关 = **默认零行为变更**）
    ///
    /// 若缺省写成 `leader` / `single`，存量部署的"flow 扫描锁默认关 / mmdb 锁默认开"
    /// 会被静默改写 ⇒ 要么多实例重复扫描，要么单实例白付 Redis 往返。
    #[test]
    fn test_scheduler_cluster_mode_defaults_to_auto() {
        use crate::scheduler::cluster::ClusterMode;

        let cfg = SchedulerConfig::default();
        assert_eq!(cfg.cluster_mode, "auto", "缺省必须为 auto");
        assert_eq!(cfg.lock_ttl_secs, 300, "缺省 TTL 必须为 300s");
        assert_eq!(
            ClusterMode::parse_or_auto(&cfg.cluster_mode),
            ClusterMode::Auto
        );

        // 入库模板（含 [scheduler] 段）解析后仍为 auto
        let s: Settings = toml::from_str(
            &std::fs::read_to_string("config/config.toml.example")
                .expect("config/config.toml.example 应存在"),
        )
        .expect("模板应可解析");
        assert_eq!(
            s.scheduler.cluster_mode, "auto",
            "入库模板不得隐式改变集群模式"
        );
    }

    /// `[ui].show_tenant_column` 的默认值必须是 `auto`，且入库模板不得隐式改变它
    #[test]
    fn test_tenant_column_mode_defaults_to_auto() {
        let cfg = UiConfig::default();
        assert_eq!(cfg.show_tenant_column, "auto", "缺省必须为 auto");

        let s: Settings = toml::from_str(
            &std::fs::read_to_string("config/config.toml.example")
                .expect("config/config.toml.example 应存在"),
        )
        .expect("模板应可解析");
        assert_eq!(
            s.ui.show_tenant_column, "auto",
            "入库模板不得隐式改变归属列展示模式"
        );
    }

    /// 归属列三态语义：`auto` 仅平台操作者可见（= 历史行为）、`always` 全可见、`never` 全隐藏
    ///
    /// 可证伪性：若把 `Auto` 分支错写成 `operator_tid != 0`，第 1 组断言立即变红
    /// （那会把"归属列"暴露给租户却对平台隐藏，与"平台运营视图增强"的定案相反）。
    #[test]
    fn test_tenant_column_mode_visible_for() {
        assert!(TenantColumnMode::Auto.visible_for(0), "auto：平台可见");
        assert!(!TenantColumnMode::Auto.visible_for(7), "auto：租户不可见");

        assert!(TenantColumnMode::Always.visible_for(0));
        assert!(
            TenantColumnMode::Always.visible_for(7),
            "always：租户亦可见"
        );

        assert!(!TenantColumnMode::Never.visible_for(0));
        assert!(!TenantColumnMode::Never.visible_for(7), "never：一律隐藏");
    }

    /// 非法取值回落 `auto`（fail-safe），且 `parse` 忽略大小写与首尾空白
    #[test]
    fn test_tenant_column_mode_parse_falls_back_to_auto() {
        assert_eq!(TenantColumnMode::parse("ALWAYS"), TenantColumnMode::Always);
        assert_eq!(TenantColumnMode::parse("  never "), TenantColumnMode::Never);
        for bad in ["", "yes", "true", "on", "view_only"] {
            assert_eq!(
                TenantColumnMode::parse(bad),
                TenantColumnMode::Auto,
                "非法取值 {bad:?} 必须回落 auto"
            );
        }
        // 注册表与解析器一一对应（防"文档列了但解析不认"的漂移）
        for m in TENANT_COLUMN_MODES {
            assert_eq!(&TenantColumnMode::parse(m).as_str(), m);
        }
    }

    /// 验证 Settings Debug 输出不泄漏 config_enc_key
    #[test]
    fn test_settings_debug_redacts_config_enc_key() {
        let settings = Settings {
            pat: PatConfig::default(),
            sso: SsoConfig::default(),
            scim: ScimConfig::default(),
            server: ServerConfig {
                host: "0.0.0.0".to_string(),
                port: 8080,
                cors_origins: vec![],
                trusted_proxies: vec![],
                docs_enabled: false,
                http_status_convention: default_http_status_convention(),
            },
            database: DatabaseConfig {
                url: "postgres://user:supersecret@host:5432/db".to_string(),
                max_connections: 10,
                min_connections: 1,
                connect_timeout: 8,
                idle_timeout: 600,
                max_lifetime_secs: 1800,
                acquire_timeout_secs: 10,
                statement_timeout_secs: 60,
                dept_cte_max_depth: 30,
            },
            redis: RedisConfig {
                url: "redis://:redispass@host:6379".to_string(),
            },
            jwt: JwtConfig {
                secret: "a-very-long-jwt-secret-key-for-testing-32+chars".to_string(),
                expire_hours: 24,
                issuer: "yebot".to_string(),
                audience: "yebot".to_string(),
                previous_secrets: vec![],
            },
            log: LogConfig {
                level: "info".to_string(),
                sql_logging: false,
                file_path: "logs".to_string(),
                json_stdout: false,
            },
            upload: UploadConfig::default(),
            ip_location: IpLocationConfig::default(),
            mail: MailConfig {
                enabled: true,
                host: "smtp.example.com".to_string(),
                port: 465,
                username: "user@example.com".to_string(),
                password: "smtp_password_123".to_string(),
                from_email: "noreply@example.com".to_string(),
                from_name: "Test".to_string(),
                starttls: false,
            },
            config_enc_key: "encryption-key-should-not-leak".to_string(),
            monitor: MonitorConfig::default(),
            permission_deny_by_default: true,
            flow: FlowConfig::default(),
            sys_log: SysLogConfig::default(),
            features: FeaturesConfig::default(),
            scheduler: SchedulerConfig::default(),
            ui: UiConfig::default(),
            acme: AcmeConfig::default(),
            events: EventsConfig::default(),
            webauthn: WebauthnConfig::default(),
            resilience: ResilienceConfig::default(),
            rate_limit: RateLimitSettings::default(),
            risk_control: RiskControlConfig::default(),
            upload_scan: UploadScanConfig::default(),
        };

        let debug_str = format!("{:?}", settings);

        // 敏感字段不应出现在 Debug 输出中
        assert!(
            !debug_str.contains("supersecret"),
            "database URL password leaked"
        );
        assert!(
            !debug_str.contains("redispass"),
            "Redis URL password leaked"
        );
        assert!(
            !debug_str.contains("a-very-long-jwt-secret"),
            "JWT secret leaked"
        );
        assert!(
            !debug_str.contains("smtp_password_123"),
            "Mail password leaked"
        );
        assert!(
            !debug_str.contains("encryption-key-should-not-leak"),
            "config_enc_key leaked"
        );

        // 脱敏标记应存在
        assert!(debug_str.contains("<redacted>"), "Redacted marker missing");
    }

    /// 验证 DatabaseConfig Debug 不泄漏 url
    #[test]
    fn test_database_config_debug_redacts_url() {
        let db_config = DatabaseConfig {
            url: "mysql://root:password123@localhost:3306/yebot".to_string(),
            max_connections: 20,
            min_connections: 5,
            connect_timeout: 8,
            idle_timeout: 600,
            max_lifetime_secs: 1800,
            acquire_timeout_secs: 10,
            statement_timeout_secs: 60,
            dept_cte_max_depth: 30,
        };
        let debug_str = format!("{:?}", db_config);
        assert!(
            !debug_str.contains("password123"),
            "Database URL password leaked in Debug"
        );
        assert!(debug_str.contains("<redacted>"));
    }

    /// v5-D11：userinfo 缓存 TTL **默认 0（关闭 = 改造前行为）** 且**硬上限 300s**。
    /// 若有人把默认值改大、或去掉夹取，本用例即变红（可证伪）。
    #[test]
    fn test_sso_userinfo_cache_ttl_defaults_off_and_clamped() {
        let cfg = SsoConfig::default();
        assert_eq!(
            cfg.userinfo_cache_ttl_secs, 0,
            "默认必须为 0（不缓存 = 改造前行为）"
        );
        let huge = SsoConfig {
            userinfo_cache_ttl_secs: 86_400,
            ..cfg
        };
        assert_eq!(
            huge.userinfo_cache_ttl_secs.min(USERINFO_CACHE_MAX_SECS),
            USERINFO_CACHE_MAX_SECS,
            "TTL 必须被夹到硬上限 300s（不允许把开关当作绕过停用即时断链的手段）"
        );
        assert_eq!(USERINFO_CACHE_MAX_SECS, 300);
    }

    /// P2-33：`[server].http_status_convention` **默认 `legacy`（= 现状零变更）**，
    /// 且取值与 [`crate::common::http_status`] 的档位表同源。若有人把默认改成 `restful`，
    /// 本用例立即变红（可证伪：那意味着存量部署的 HTTP 语义被静默改变）。
    #[test]
    fn test_http_status_convention_default_is_legacy() {
        assert_eq!(
            default_http_status_convention(),
            "legacy",
            "默认档必须是 legacy（= 改造前行为）"
        );
        assert_eq!(
            default_http_status_convention(),
            crate::common::http_status::HttpStatusConvention::default().as_str()
        );
        // 反序列化缺省（旧配置无该键）同样回落 legacy
        let parsed: ServerConfig =
            toml::from_str("host = \"0.0.0.0\"\nport = 8080\ncors_origins = [\"http://x\"]\n")
                .expect("最小 [server] 配置应可解析");
        assert_eq!(parsed.http_status_convention, "legacy");
    }

    /// 验证 JwtConfig Debug 不泄漏 secret
    #[test]
    fn test_jwt_config_debug_redacts_secret() {
        let jwt_config = JwtConfig {
            secret: "my-super-secret-jwt-key-1234567890123456".to_string(),
            expire_hours: 24,
            issuer: "yebot".to_string(),
            audience: "yebot".to_string(),
            previous_secrets: vec![],
        };
        let debug_str = format!("{:?}", jwt_config);
        assert!(
            !debug_str.contains("my-super-secret-jwt-key"),
            "JWT secret leaked in Debug"
        );
        assert!(debug_str.contains("<redacted>"));
    }

    /// 验证 MailConfig Debug 不泄漏 password
    #[test]
    fn test_mail_config_debug_redacts_password() {
        let mail_config = MailConfig {
            enabled: true,
            host: "smtp.qq.com".to_string(),
            port: 465,
            username: "test@qq.com".to_string(),
            password: "qq_auth_code_secret".to_string(),
            from_email: "test@qq.com".to_string(),
            from_name: "Test".to_string(),
            starttls: false,
        };
        let debug_str = format!("{:?}", mail_config);
        assert!(
            !debug_str.contains("qq_auth_code_secret"),
            "Mail password leaked in Debug"
        );
        assert!(debug_str.contains("<redacted>"));
    }

    /// 验证 RedisConfig Debug 不泄漏 url
    #[test]
    fn test_redis_config_debug_redacts_url() {
        let redis_config = RedisConfig {
            url: "redis://:mypassword@localhost:6379/0".to_string(),
        };
        let debug_str = format!("{:?}", redis_config);
        assert!(
            !debug_str.contains("mypassword"),
            "Redis URL password leaked in Debug"
        );
        assert!(debug_str.contains("<redacted>"));
    }

    /// B10：validate_secrets 应拒绝弱/占位密钥，放行合法强密钥（deny-list 向后兼容）
    #[test]
    fn test_validate_secrets_rejects_weak_keys() {
        // 合法强密钥应通过
        let mut s = make_test_settings();
        s.jwt.secret = "a-valid-strong-jwt-secret-key-0123456789abcdef".to_string();
        assert!(s.validate_secrets().is_ok(), "合法强密钥应被接受");

        // 测试前缀 yebot_local_test_* 应被拒
        let mut s2 = make_test_settings();
        s2.jwt.secret = "yebot_local_test_abc1234567890123456789".to_string();
        assert!(s2.validate_secrets().is_err(), "测试前缀密钥应被拒绝");

        // CHANGE_ME 占位（大小写不敏感）应被拒
        let mut s3 = make_test_settings();
        s3.jwt.secret = "CHANGE_ME_please_set_a_real_strong_secret_xx".to_string();
        assert!(s3.validate_secrets().is_err(), "CHANGE_ME 占位密钥应被拒绝");

        // password 弱模式应被拒
        let mut s4 = make_test_settings();
        s4.jwt.secret = "password_12345678901234567890123456789".to_string();
        assert!(s4.validate_secrets().is_err(), "password 弱模式应被拒绝");

        // example 弱模式应被拒
        let mut s5 = make_test_settings();
        s5.jwt.secret = "example_secret_key_012345678901234567890".to_string();
        assert!(s5.validate_secrets().is_err(), "example 弱模式应被拒绝");
    }
}
