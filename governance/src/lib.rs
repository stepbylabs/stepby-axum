// stepby-axum/governance/src/lib.rs
//! # governance —— 治理项注册表（单一事实源）
//!
//! ## 为什么单独成 crate
//!
//! `stepby-axum`（lib）与 `migration`（migration crate）是 workspace 内两个**互不依赖**
//! 的 crate，而两者都需要同一份治理清单：
//!
//! - 平台锁定键 / 平台默认键（`sys_config` 治理列 seed）；
//! - 能力位注册表（键、合法模式、默认档、解锁的 perms）。
//!
//! 在抽本 crate 之前，迁移文件里只能保留一份**同值本地副本**，并靠注释约束
//! 「修改时必须两处同步」。这正是 2026-09-26 那次「裸占位符漏写列名导致治理静默失效」
//! 事故的同一形态：靠纪律同步的复制，迟早漂移。
//!
//! 把数据抽到零依赖 crate 后，**复制路径在物理上消失**：两个使用方都 `pub use` 同一份常量。
//!
//! ## 铁律（与 `common/features.rs` 一致）
//!
//! 1. **开关取「模式」而非裸 bool**：`modes` 是有序档位集合（下标越大越开放）。
//! 2. **默认值 = 现状 = 关闭态即安全态**：能力位 `default_mode` 恒为 [`OFF`]。
//! 3. **档位必须安全单调**：`modes` 下标递增方向必须与「安全性递减」方向一致；
//!    方向因项而异（脱敏的 `full` 最安全，筛选器的 `off` 最安全），故本表**显式**声明
//!    顺序，任何调用点都不得靠数值大小或数组书写顺序之外的隐含约定推断语义。
//! 4. **收敛单向**：平台层是天花板，租户层只能收窄（[`Coverage::Ceiling`]）。
//!
//! ## 本 crate 刻意零依赖
//!
//! 只含 `&'static` 数据与纯函数，不引入任何第三方依赖，保证两个使用方都能低成本依赖。

#![forbid(unsafe_code)]

/// 关闭态字面量（等价于「能力不存在」，是全系统最小权限基准）
pub const OFF: &str = "off";

/// 治理项种类
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// 能力位：由 `config.toml` `[features]`（平台层）与 `sys_tenant_package.features`
    /// （租户套餐层）两层收敛，消费方为 `stepby_axum::common::features::FeatureSet`。
    Feature,
    /// 参数项：由 `sys_config` 行 + 治理列（`scope` / `tenant_editable` /
    /// `visible_to_tenant`）承载。
    Config,
}

/// 覆盖策略：**治理域 + 收敛方向的合一表达**。
///
/// 之所以合一：`sys_config` 原有的「治理域三枚举 + `tenant_editable` 裸 bool」
/// 只能回答「能不能改」，无法回答「只能往哪边改」——而后者才是防「租户越权自开」的关键。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Coverage {
    /// 平台锁定：租户不可见、不可改。seed 为 `scope='platform_only'`。
    Locked,
    /// 租户可见可覆盖，**值域无方向约束**（值本身无有序档位，如主题名）。
    /// seed 为 `scope='platform_default'`。
    Free,
    /// 租户可见可覆盖，但**只能取不比平台更开放的档**（收敛方向：只能更保守）。
    /// seed 为 `scope='platform_default'`，运行期由 `modes` 下标钳制。
    Ceiling,
    /// 租户私有：仅本租户可见可改。seed 为 `scope='tenant_private'`。
    Private,
}

impl Coverage {
    /// `sys_config.scope` 的 seed 取值。
    pub const fn scope(self) -> &'static str {
        match self {
            Coverage::Locked => "platform_only",
            Coverage::Free | Coverage::Ceiling => "platform_default",
            Coverage::Private => "tenant_private",
        }
    }

    /// `sys_config.tenant_editable` 的 seed 取值（`"1"` = 租户可覆盖）。
    pub const fn tenant_editable(self) -> &'static str {
        match self {
            Coverage::Locked => "0",
            Coverage::Free | Coverage::Ceiling | Coverage::Private => "1",
        }
    }

    /// `sys_config.visible_to_tenant` 的 seed 取值（`"1"` = 租户可见）。
    pub const fn visible_to_tenant(self) -> &'static str {
        match self {
            Coverage::Locked => "0",
            Coverage::Free | Coverage::Ceiling | Coverage::Private => "1",
        }
    }

    /// 是否要求「租户只能取更保守档」（需要 `modes` 有序定义配合）。
    pub const fn requires_ceiling(self) -> bool {
        matches!(self, Coverage::Ceiling)
    }
}

/// 单个治理项。
///
/// 字段名刻意与 `common::features::FeatureDef` 对齐（`key` / `modes` / `default_mode`），
/// 使能力位消费点在迁移到注册表时**无需改写字段访问**。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Item {
    /// 治理项键（点分小写；能力位键与 `sys_tenant_package.features` JSON 的 key 一致）
    pub key: &'static str,
    pub kind: Kind,
    /// 有序档位。**必须安全单调递增**（下标越大越开放）；无档位项为空切片。
    pub modes: &'static [&'static str],
    /// 默认档：有档位项必须等于 `modes` 首项；无档位项为 `""`。
    pub default_mode: &'static str,
    pub coverage: Coverage,
    /// 能力位在各档解锁的平台专属 perms：`(所需最低档, perms 清单)`。
    /// 非能力位项恒为空切片。逐条枚举，禁止前缀通配。
    pub unlocked: &'static [(&'static str, &'static [&'static str])],
}

/// 构造能力位项（默认档恒为 [`OFF`]，覆盖策略恒为 [`Coverage::Ceiling`]）。
const fn feat(
    key: &'static str,
    modes: &'static [&'static str],
    unlocked: &'static [(&'static str, &'static [&'static str])],
) -> Item {
    Item {
        key,
        kind: Kind::Feature,
        modes,
        default_mode: OFF,
        coverage: Coverage::Ceiling,
        unlocked,
    }
}

/// 构造参数项（无档位；`Free` / `Ceiling` 由调用方按需选择）。
const fn cfg(key: &'static str, coverage: Coverage) -> Item {
    Item {
        key,
        kind: Kind::Config,
        modes: &[],
        default_mode: "",
        coverage,
        unlocked: &[],
    }
}

/// **能力位注册表**（按 key 字典序）。
///
/// 新增能力位必须在此登记，否则 `FeatureSet::sanitized` 会静默剔除该键。
pub const FEATURES: &[Item] = &[
    // AI 助手（NL2SQL Copilot，v5-A1）：**三层开关的租户层**——
    //   - 平台层：`config.toml` `[ai].enabled`（进程级，默认 false）；
    //   - 租户层：本能力位（off = 端点 403，关闭态即安全态）；
    //   - 角色层：菜单 4100（perms `ai:chat`）走常规 role_menu 授权。
    // `unlocked = &[]`：`ai:chat` 是普通业务权限（非平台专属下放项），
    // 经菜单 4100 的 role_menu 授权即可，不占用"平台专属 perm 解锁"语义
    // （该语义受 features 测试「白名单必须 is_platform_only_perm」双向一致锁约束）。
    // 服务层守卫：`[ai].enabled` off ⇒ 403（明确提示）；PAT 会话 ⇒ 403（B2）；
    // 查询经 `sql_guard` 白名单 + 租户过滤强制注入（v5-A3）。
    feat("ai.copilot", &[OFF, "on"], &[]),
    // WebAuthn / Passkey 登录（默认 off）。登录面能力：开启后用户可自助绑定 passkey，
    // 并在登录页以 passkey（免密码）登录；关闭态 = 端点 404（不暴露"存在但被关"）。
    //
    // `unlocked = &[]`：本能力位解锁的是**登录面**（自助绑定 + 公开登录端点），
    // 不向任何租户下放平台专属 perm ⇒ 无需（也不得）登记解锁清单。
    // 服务层守卫：能力位非 on ⇒ 404；用户不存在/停用/删除 ⇒ 拒绝；凭据归属校验（只能操作自己的）。
    feat("auth.webauthn", &[OFF, "on"], &[]),
    feat(
        "backup.tenant_self_export",
        &[OFF, "on"],
        &[("on", &["system:backup:export"])],
    ),
    // 备份可见性：**分档解锁**。`view_only` 只读（列表 + 详情），`full` 再加下载。
    // 写面/危险面（add 创建整库备份 / edit 恢复覆盖现库 / remove）**恒不下放**。
    // `download` 单独放 `full` 档：下载即拿到备份文件本体，而平台普通角色（role 2）
    // 的 `tid = 0` ⇒ 服务层不做行级收窄 ⇒ 等于整库数据下载。
    feat(
        "backup.visibility",
        &[OFF, "view_only", "full"],
        &[
            ("view_only", &["system:backup:list", "system:backup:query"]),
            ("full", &["system:backup:download"]),
        ],
    ),
    // 流程定义设计器（G-02，三档）：与 report.designer 同构——租户套餐是否开通「流程定义设计」能力。
    //   - `off`（默认）：关闭态即安全态；
    //   - `view`：定义列表/详情/版本对比只读（写面 403）；
    //   - `full`：定义新增/编辑/发布/删除。
    // `unlocked = &[]`：`flow:definition:*` 是普通业务权限（非平台专属下放项），
    // 经菜单 4140-4145 的 role_menu 授权即可，不占用"平台专属 perm 解锁"语义
    //（受 features 测试"白名单必须 is_platform_only_perm"约束）。
    // 服务层守卫：写面（add/edit/publish/remove）按有效档位收敛（批次十二接入）。
    feat("flow.designer", &[OFF, "view", "full"], &[]),
    // 租户自建导航 L3：`view_only` 只给只读入口，`full` 才给写面。
    // 服务层 `SysTenantNavService::resolve_scope` 按同档位守卫，故按档解锁不会造出
    // "菜单可见但请求 403"的假入口。
    feat(
        "nav.l3",
        &[OFF, "view_only", "full"],
        &[
            ("view_only", &["system:tenantMenu:list"]),
            (
                "full",
                &[
                    "system:tenantMenu:add",
                    "system:tenantMenu:edit",
                    "system:tenantMenu:remove",
                ],
            ),
        ],
    ),
    // GDPR 被遗忘权 / 用户匿名化：**平台治理动作**（分档）。
    //   - `off`（默认）：端点表现为 404（能力不存在 = 关闭态即安全态）；
    //   - `precheck`：仅允许**只读预检**（dry-run，返回将被置换的字段与受影响关系计数）；
    //   - `full`：允许真正执行**不可逆**匿名化。
    // 不向租户解锁任何 perm（`unlocked = &[]`）：匿名化是平台级数据治理 + 不可逆写，
    // 只允许平台管理员（`tenant_id == 0`）触发，故不随任何租户套餐下放权限；
    // 两条路由复用既有 `system:user:remove` perm（不新造 perm，避免"菜单可见但请求 403"）。
    feat("privacy.user_erasure", &[OFF, "precheck", "full"], &[]),
    // 报表设计器（G-01，三档）：租户套餐是否开通「报表数据集/大屏」能力。
    //   - `off`（默认）：关闭态即安全态；
    //   - `view`：大屏查看/运行时；
    //   - `full`：数据集管理 + 设计器编辑。
    // `unlocked = &[]`：`report:dataset:*` / `report:dashboard:*` 是普通业务权限
    //（非平台专属下放项），经菜单 4146-4148 的 role_menu 授权即可，不占用
    // "平台专属 perm 解锁"语义（受 features 测试"白名单必须 is_platform_only_perm"约束）。
    // M1 先行登记注册表（switch-catalog 同步），端点消费在 M2 设计器落地时接入。
    feat("report.designer", &[OFF, "view", "full"], &[]),
    // 字段级权限 M2（三层开关的租户层）：租户套餐是否开通「角色字段级权限」能力。
    //   - 平台层（主开关）：`sys_config.sys.fieldPerm.enabled`（服务层第一道判定）；
    //   - 租户层：本能力位（off = 矩阵接口拒绝 + 裁剪恒空，关闭态即安全态）；
    //   - 角色层：`sys_role_field_perm` 行（hidden 语义，服务层并集判定）。
    // `unlocked = &[]`：`system:role:fieldPerm` / `system:role:fieldPermSave` 是普通
    // 业务权限（非平台专属下放项），经菜单 4120/4121 的 role_menu 授权即可，不占用
    // "平台专属 perm 解锁"语义（受 features 测试"白名单必须 is_platform_only_perm"约束）。
    feat("role.field_perm", &[OFF, "on"], &[]),
    // 租户域名自助：开启时域名管理 5 项可授予租户管理员，服务层按 tid 收窄
    // （仅能读写本租户域名）。清单与 `middleware/permission.rs` 的
    // `/system/tenant/domain/*` 权限映射逐条对应。
    feat(
        "tenant.domain_self_service",
        &[OFF, "full"],
        &[(
            "full",
            &[
                "system:tenant:domain:list",
                "system:tenant:domain:add",
                "system:tenant:domain:verify",
                "system:tenant:domain:edit",
                "system:tenant:domain:remove",
            ],
        )],
    ),
];

/// **参数项注册表**（按 key 字典序）。
///
/// 定位：`sys_config` 治理列的 **seed 单一事实源**。运行期真相仍在 DB 行
/// （由启动期幂等收敛把行收敛到本表声明的姿态，而非每次改表都写新迁移）。
pub const CONFIGS: &[Item] = &[
    // ---- ip_location.*（平台锁定：凭据与自动更新开关属安全底线）----
    cfg("ip_location.auto_update_enabled", Coverage::Locked),
    cfg("ip_location.maxmind_account_id", Coverage::Locked),
    cfg("ip_location.maxmind_license_key", Coverage::Locked),
    cfg("ip_location.update_source", Coverage::Locked),
    // ---- sys.account.*（平台锁定：初始密码 / 验证码 / 注册开关）----
    cfg("sys.account.captchaEnabled", Coverage::Locked),
    cfg("sys.account.registerUser", Coverage::Locked),
    // ---- sys.ai.*（AI 助手配置热化，§5.39 AI-01：管理页可改热生效；
    //      平台专属（Locked），api_key 信封加密存储——键值不回显明文）----
    cfg("sys.ai.allowed_tables", Coverage::Locked),
    cfg("sys.ai.api_key", Coverage::Locked),
    cfg("sys.ai.base_url", Coverage::Locked),
    cfg("sys.ai.enabled", Coverage::Locked),
    cfg("sys.ai.model", Coverage::Locked),
    cfg("sys.ai.provider", Coverage::Locked),
    // ---- sys.audit.*（平台锁定：审计告警阈值）----
    cfg("sys.audit.alarm.fail_rate_threshold", Coverage::Locked),
    cfg("sys.audit.alarm.fail_threshold", Coverage::Locked),
    cfg("sys.audit.alarm.window_minutes", Coverage::Locked),
    // ---- sys.fieldPerm.*（平台锁定：字段级权限 M2 第一层平台开关，默认 false = 关闭态即安全态）----
    cfg("sys.fieldPerm.enabled", Coverage::Locked),
    // ---- sys.index.*（§5.23 移除：sideTheme/skinName 为 RuoYi 遗产死键——前端主题
    //      走 localStorage（settings store），后端零消费者，参数页修改不生效；
    //      sys.login.background 同理。历史 seed 行保留（数据不删），仅退出治理注册表）----
    // ---- sys.login.* ----
    cfg("sys.login.blackIPList", Coverage::Locked),
    // ---- sys.upload.backend（G-11 第二档：backend 档位热切换持久化——
    //      空值 = 跟随 config.toml [upload].backend 出厂缺省；非空（local/s3）=
    //      管理页热切换后的运行档位，重启后由启动恢复逻辑重新生效）----
    cfg("sys.upload.backend", Coverage::Locked),
    // ---- sys.upload.s3.*（G-11 OSS 凭据动态化：config.toml [upload.s3] 为出厂缺省，
    //      管理页可改热生效；平台专属（Locked），secret_key 信封加密——键值不回显明文；
    //      仅 backend="s3" 档位下生效，local 档无凭据概念不受影响）----
    cfg("sys.upload.s3.access_key", Coverage::Locked),
    cfg("sys.upload.s3.bucket", Coverage::Locked),
    cfg("sys.upload.s3.endpoint", Coverage::Locked),
    cfg("sys.upload.s3.path_style", Coverage::Locked),
    cfg("sys.upload.s3.public_endpoint", Coverage::Locked),
    cfg("sys.upload.s3.region", Coverage::Locked),
    cfg("sys.upload.s3.secret_key", Coverage::Locked),
    // ---- sys.user.* ----
    // B4 强制首登改密开关（§5.23 补登记：此前有运行时消费但未入注册表，
    // 治理列不收敛属"登记漂移"；Locked 平台锁定——租户不得自行开启强改）
    cfg("sys.user.forceFirstLoginChangePwd", Coverage::Locked),
    cfg("sys.user.initPassword", Coverage::Locked),
    // 批八十四 项 A：口令有效期天数（0=永不过期=现状）与强改密服务端闸门档位
    // （off=现状）。两者共同决定"多少人会被拦"，属平台级安全姿态，租户不得自行放宽
    // ⇒ 与 forceFirstLoginChangePwd 同档 Locked（platform_only、不可见、不可改）。
    // ⚠️ 本表必须按 key **字典序**排列（`test_registry_ordering_and_uniqueness` 硬失败），
    //   故新键插在 initPassword 之后而不是"接着上一批写"。
    cfg("sys.user.pwdChangeGate", Coverage::Locked),
    cfg("sys.user.pwdExpireDays", Coverage::Locked),
];

/// `sys.login.blackIPList` 的运行时消费键（登录链路 IP 黑名单，
/// [`crate::service` 层按此键读 sys_config 缓存]）——常量化避免键名散落。
pub const SYS_LOGIN_BLACK_IP_LIST: &str = "sys.login.blackIPList";

/// 治理注册表兜底补行时写入的 `remark` 固定文案（**单一事实源**）。
///
/// 为什么值得单独成常量：`initialize::ensure_governance_config_rows` 用它建行，而各参数项
/// 自己的存量库兜底（如 `pwd_expire`）要判断"这行的说明文案还是不是兜底文案"以便归一
/// ——两处各写一份字面量，改一处就会让归一逻辑**静默失效**（归一只会发生在
/// `remark = 兜底文案` 的行上，文案不一致 = 一条都不归一，而没有任何报错）。
///
/// 背景（b84 seed_diff 实测）：存量库上"新登记的参数项"由本兜底先建行，于是参数管理页
/// 里它的说明是这句通用文案，而不是迁移种子写的档位语义（对 `off|deny_write|deny_all`
/// 这种"读不出来说明就会配错"的键，这是真实的能力缺口，不只是文案漂移）。
pub const GOVERNANCE_BACKFILL_REMARK: &str = "治理注册表缺行补齐（批次十四）";

/// 参数项的**出厂缺省三元组**（键, 显示名, config_value）——覆盖 `CONFIGS` 全部键。
///
/// 为何必须有本表（批次十四实证）：`ensure_tenant_saas_governance` 的治理收敛
/// **只 UPDATE 既有行的治理列、不 INSERT 新行**，而 G-11 的 8 个 `sys.upload.*`
/// 键从未在任何迁移 seed ⇒ 存量库无行，且 `UploadConfigService` 写入是纯 UPDATE
/// ⇒ **0 行更新不报错 = OSS 管理页保存静默失效**（接口 200 实际未落库）。
/// 启动收敛（`initialize::ensure_governance_config_rows`）按本表 INSERT OR IGNORE
/// 补齐缺行后，该类缺口根治；未来新增参数项必须在此登记（单测双向锁死）。
///
/// 语义约定：
/// - 空串 = 跟随 `config.toml` 出厂缺省（读路径回落）——凭据类键（api_key/secret_key
///   等）缺省恒空串，**绝不把样例凭据 seed 进库**；
/// - config_value 的运行期真相仍是 DB 行，本表只决定"缺行时的初始姿态"。
pub const CONFIG_DEFAULTS: &[(&str, &str, &str)] = &[
    (
        "ip_location.auto_update_enabled",
        "IP 库自动更新开关",
        "false",
    ),
    (
        "ip_location.maxmind_account_id",
        "MaxMind Account ID(加密)",
        "",
    ),
    (
        "ip_location.maxmind_license_key",
        "MaxMind License Key(加密)",
        "",
    ),
    ("ip_location.update_source", "IP 库更新源", "p3terx"),
    ("sys.account.captchaEnabled", "账号自助-验证码开关", "true"),
    ("sys.account.registerUser", "账号自助-注册开关", "false"),
    (
        "sys.ai.allowed_tables",
        "AI 可查询表白名单",
        "sys_user,sys_dept,sys_role,sys_post,sys_config,sys_dict_type,sys_dict_data",
    ),
    ("sys.ai.api_key", "AI API Key", ""),
    (
        "sys.ai.base_url",
        "AI base_url",
        "https://api.openai.com/v1",
    ),
    ("sys.ai.enabled", "AI 助手总开关", "false"),
    ("sys.ai.model", "AI 模型名", "gpt-4o-mini"),
    ("sys.ai.provider", "AI LLM 提供方", "openai"),
    (
        "sys.audit.alarm.fail_rate_threshold",
        "异常操作告警-失败率阈值(%)",
        "30",
    ),
    (
        "sys.audit.alarm.fail_threshold",
        "异常操作告警-失败次数阈值",
        "5",
    ),
    (
        "sys.audit.alarm.window_minutes",
        "异常操作告警-时间窗口(分钟)",
        "5",
    ),
    ("sys.fieldPerm.enabled", "字段级权限开关", "false"),
    ("sys.login.blackIPList", "用户登录-黑名单列表", ""),
    (
        "sys.upload.backend",
        "上传存储后端（local/s3 热切换，空=跟随 config.toml）",
        "",
    ),
    ("sys.upload.s3.access_key", "S3 AccessKey", ""),
    ("sys.upload.s3.bucket", "S3 Bucket", ""),
    ("sys.upload.s3.endpoint", "S3 Endpoint", ""),
    (
        "sys.upload.s3.path_style",
        "S3 路径风格寻址（true/false，空=跟随 config.toml）",
        "",
    ),
    ("sys.upload.s3.public_endpoint", "S3 公开访问前缀", ""),
    ("sys.upload.s3.region", "S3 Region", ""),
    ("sys.upload.s3.secret_key", "S3 SecretKey", ""),
    (
        "sys.user.forceFirstLoginChangePwd",
        "用户首登强制改密开关",
        "false",
    ),
    (
        "sys.user.pwdExpireDays",
        "口令有效期天数",
        // 默认 0 = 永不过期 = 现状（开关规范①：缺省值必须等价于"功能不存在"）
        "0",
    ),
    (
        "sys.user.pwdChangeGate",
        "强改密服务端闸门",
        // 默认 off：只下发标志、不服务端拦截（= 本批之前的行为）
        "off",
    ),
    ("sys.user.initPassword", "用户管理-账号初始密码", "123456"),
];

/// 全量治理项（能力位在前、参数项在后；各自内部按 key 字典序）。
pub fn all() -> impl Iterator<Item = &'static Item> {
    FEATURES.iter().chain(CONFIGS.iter())
}

/// 按键查注册表（未登记返回 `None`）。
pub fn item(key: &str) -> Option<&'static Item> {
    all().find(|i| i.key == key)
}

/// 档位在 `modes` 中的下标（越小越保守）；未登记项/未登记档位返回 `None`。
///
/// **fail-closed**：`None` 表示"该档位未达到任何要求"，调用方必须按不满足处理。
pub fn mode_rank(key: &str, mode: &str) -> Option<usize> {
    item(key).and_then(|i| i.modes.iter().position(|m| *m == mode))
}

/// 取值是否落在该项声明的**值域**内。
///
/// - 未登记项 ⇒ `false`（fail-closed：注册表是值域的单一事实源）；
/// - 有档位项 ⇒ `value` 必须命中 `modes`；
/// - 无档位项（参数项，值域由业务规则另行约束）⇒ `true`。
pub fn is_known_mode(key: &str, value: &str) -> bool {
    match item(key) {
        None => false,
        Some(i) if i.modes.is_empty() => true,
        Some(i) => i.modes.contains(&value),
    }
}

/// **按覆盖策略收敛取值**：返回「不比 `platform` 更开放」的那一档。
///
/// 这是「平台是天花板，租户只能收窄」的**唯一实现**（此前能力位两层收敛与
/// `sys_config` 覆盖各写一套档位比较，属重复事实源）：
/// - 能力位两层收敛（`FeatureSet::narrowed_by`）即本函数的 `Ceiling` 分支；
/// - `sys_config` 的 `Ceiling` 类可覆盖项（如筛选器/脱敏档位）写入时也走这里。
///
/// 语义：
/// - [`Coverage::Locked`] ⇒ 恒返回平台值（租户不得改）；
/// - [`Coverage::Ceiling`] ⇒ 返回平台值与请求值中**较保守**（下标较小）的一档；
/// - [`Coverage::Free`] / [`Coverage::Private`] ⇒ 返回请求值（非法时回落平台值）。
///
/// 返回 `None` 的情形（调用方**必须**回落到平台值，fail-closed）：项未登记、
/// 项无档位、或 `platform` 与 `requested` 均非法。
pub fn converge(key: &str, platform: &str, requested: &str) -> Option<&'static str> {
    let i = item(key)?;
    if i.modes.is_empty() {
        return None;
    }
    let pick = |m: &str| -> Option<&'static str> { i.modes.iter().copied().find(|x| *x == m) };
    let rank = |m: &str| -> Option<usize> { i.modes.iter().position(|x| *x == m) };
    match i.coverage {
        Coverage::Locked => pick(platform),
        Coverage::Free | Coverage::Private => pick(requested).or_else(|| pick(platform)),
        Coverage::Ceiling => match (rank(platform), rank(requested)) {
            (Some(p), Some(r)) => i.modes.get(p.min(r)).copied(),
            (Some(p), None) => i.modes.get(p).copied(),
            (None, Some(r)) => i.modes.get(r).copied(),
            (None, None) => None,
        },
    }
}

/// 平台锁定键（`Coverage::Locked`）清单 —— `sys_config` seed 的第一组。
pub fn locked_keys() -> impl Iterator<Item = &'static str> {
    CONFIGS
        .iter()
        .filter(|i| i.coverage == Coverage::Locked)
        .map(|i| i.key)
}

/// 平台默认可覆盖键（`Coverage::Free` / `Coverage::Ceiling`）清单 —— seed 的第二组。
pub fn default_keys() -> impl Iterator<Item = &'static str> {
    CONFIGS
        .iter()
        .filter(|i| matches!(i.coverage, Coverage::Free | Coverage::Ceiling))
        .map(|i| i.key)
}

/// 租户私有键（`Coverage::Private`）清单 —— seed 的第三组。
pub fn private_keys() -> impl Iterator<Item = &'static str> {
    CONFIGS
        .iter()
        .filter(|i| i.coverage == Coverage::Private)
        .map(|i| i.key)
}

/// 某覆盖策略对应的键清单（seed 按组生成 SQL 时使用）。
pub fn keys_with_coverage(coverage: Coverage) -> impl Iterator<Item = &'static str> {
    CONFIGS
        .iter()
        .filter(move |i| i.coverage == coverage)
        .map(|i| i.key)
}

// ---------------------------------------------------- 普通角色（common）授权策略

/// 平台普通角色 `role_id = 2`（`role_key = common`）——种子授权的唯一目标角色。
pub const COMMON_ROLE_ID: i64 = 2;

/// common 角色 F 按钮中的**只读权限后缀**（§8.2 安全发现的判据，b73 轮 15 提为单一事实源）。
///
/// 为何必须集中于此：`m20260924_000010_common_role_readonly` 把 common 收紧为
/// "页面可见 + 只读按钮"之后，**后续新增菜单的迁移与 `initialize` 兜底**仍沿用 RuoYi
/// 上游习惯把写权限按钮（`:add/:edit/:remove/:export/:save/:publish/:test-send/:revoke`）
/// 一并授权 ⇒ 种子逐批复潮。纯种子库实测 12 处（`monitor:pat:revoke` /
/// `system:webhook:test-send` / `system:webhook:event:edit` /
/// `system:scimgroup:edit|remove` / `system:audit-change:export` /
/// `tool:reportBoard:save` / `flow:definition:add|edit|publish|remove` /
/// `report:dataset:edit`），见 `docs/optimization/quality-batch-73-2026-10-17.md`。
/// **授权点散落而判据只有一处，侵蚀是必然而非偶然**，故所有 common 授权点必须共用本判据。
pub const COMMON_ROLE_READONLY_PERM_SUFFIXES: [&str; 4] = [":list", ":query", ":view", ":center"];

/// 写权限按钮**刻意**授予 common 角色的例外登记（`(menu_id, 理由)`）。
///
/// 例外必须逐条带理由：common 同时是"新建租户默认管理员角色"的**菜单模板复制源**
/// （见 `sys_tenant_service::tenant_role_menu_ids` 与
/// `initialize::ensure_tenant_role_menu_governance` 文档），所以"新业务菜单默认授予
/// common"是产品决策而非疏漏——但只有**作用域限于本人**或**由能力位（默认 off）封顶**
/// 的写权限才可登记；越权面（吊销他人令牌 / 改出站投递配置 / 改 SCIM 组映射 /
/// 导出审计留痕）一律不得登记。
pub const COMMON_ROLE_WRITE_EXCEPTIONS: &[(i64, &str)] = &[
    (
        4131,
        "看板保存作用于**本人**看板（`sys_report_board.user_id` 属主，v1 仅本人可读写），非越权面",
    ),
    (
        4142,
        "批次十三 用户拍板：G-01/G-02 菜单 4140-4148 全量授予 common（common 为租户角色菜单模板源）；\
         写权限仍受 `flow.designer` / `report.designer` 能力位（默认 off）+ 租户过滤三层守卫",
    ),
    (4143, "同 4142（批次十三 拍板：流程定义编辑受能力位封顶）"),
    (4144, "同 4142（批次十三 拍板：流程定义发布受能力位封顶）"),
    (4145, "同 4142（批次十三 拍板：流程定义删除受能力位封顶）"),
    (4147, "同 4142（批次十三 拍板：数据集编辑受能力位封顶）"),
];

/// 例外 menu_id 集合（供 SQL 子句与锁测试共用）。
pub fn common_role_write_exception_ids() -> Vec<i64> {
    COMMON_ROLE_WRITE_EXCEPTIONS
        .iter()
        .map(|(id, _)| *id)
        .collect()
}

/// 方言相关的幂等插入片段（`sys_role_menu` 主键为 `(role_id, menu_id)`，重复插入即跳过）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Dialect {
    Sqlite,
    Postgres,
    MySql,
}

impl Dialect {
    fn insert_prefix(self) -> &'static str {
        match self {
            Dialect::Sqlite => "INSERT OR IGNORE INTO ",
            Dialect::Postgres => "INSERT INTO ",
            Dialect::MySql => "INSERT IGNORE INTO ",
        }
    }

    fn conflict_suffix(self) -> &'static str {
        match self {
            Dialect::Postgres => " ON CONFLICT DO NOTHING",
            Dialect::Sqlite | Dialect::MySql => "",
        }
    }
}

/// SQL 侧的 common 授权判定子句（作用于 `sys_menu` 行），与 [`common_role_may_grant`] 等价。
///
/// 三方言通用：只用 `IN` 与 `LIKE` 后缀匹配，不含方言特有函数；`perms` 均为小写、
/// 无 collation 歧义（与 `m20260924_000010` 原实现一致）。例外 menu_id 由
/// [`COMMON_ROLE_WRITE_EXCEPTIONS`] 展开为 `menu_id IN (…)`，两侧同源。
pub fn common_role_grant_where() -> String {
    let suffix = COMMON_ROLE_READONLY_PERM_SUFFIXES
        .iter()
        .map(|s| format!("perms LIKE '%{s}'"))
        .collect::<Vec<_>>()
        .join(" OR ");
    let exceptions = common_role_write_exception_ids();
    let exception_clause = if exceptions.is_empty() {
        String::new()
    } else {
        let list = exceptions
            .iter()
            .map(|i| i.to_string())
            .collect::<Vec<_>>()
            .join(", ");
        format!(" OR menu_id IN ({list})")
    };
    format!("(menu_type IN ('M', 'C') OR (menu_type = 'F' AND ({suffix})){exception_clause})")
}

/// Rust 侧的 common 授权判定，供生成种子语句时预判（与 SQL 侧同源，不得各写各的）。
///
/// 平台专属 perms 的剔除由 `ensure_tenant_role_menu_governance`（能力位感知）负责，
/// 本谓词只管"读 / 写"维度——两者正交，不得在此混入前缀判断。
pub fn common_role_may_grant(menu_id: i64, menu_type: &str, perms: &str) -> bool {
    if COMMON_ROLE_WRITE_EXCEPTIONS
        .iter()
        .any(|(id, _)| *id == menu_id)
    {
        return true;
    }
    match menu_type {
        "M" | "C" => true,
        "F" => COMMON_ROLE_READONLY_PERM_SUFFIXES
            .iter()
            .any(|s| perms.ends_with(s)),
        _ => false,
    }
}

/// common 授权补种的**语句体**（不含幂等前缀/冲突后缀，交给调用方的方言助手拼接）。
///
/// 形如 `sys_role_menu (role_id, menu_id) SELECT 2, menu_id FROM sys_menu WHERE …`，
/// 可直接喂给迁移侧 `execute_idempotent_insert` 与兜底侧 `flow_insert`——两处都已
/// 负责 `INSERT OR IGNORE` / `ON CONFLICT DO NOTHING` / `INSERT IGNORE` 方言差异。
///
/// 语义：授权结果由 DB 侧套用 [`common_role_grant_where`] ⇒ 调用方即便传入写权限按钮
/// 的 `menu_id`，也**不会**产生越权授权（策略落在数据层，而非依赖调用方自觉）。
/// 幂等：`(role_id, menu_id)` 主键冲突跳过，重复执行 0 行。
pub fn common_role_grant_select_body(menu_ids: &[i64]) -> String {
    let id_list = menu_ids
        .iter()
        .map(|i| i.to_string())
        .collect::<Vec<_>>()
        .join(", ");
    format!(
        "sys_role_menu (role_id, menu_id) SELECT {}, menu_id FROM sys_menu \
         WHERE del_flag = '0' AND menu_id IN ({}) AND {}",
        COMMON_ROLE_ID,
        id_list,
        common_role_grant_where()
    )
}

/// 为**刚补种的菜单**按策略幂等授权 common 角色（`initialize` 兜底唯一合法写法）。
///
/// = 方言前后缀 + [`common_role_grant_select_body`]。
pub fn common_role_backfill_sql(dialect: Dialect, menu_ids: &[i64]) -> String {
    format!(
        "{}{}{}",
        dialect.insert_prefix(),
        common_role_grant_select_body(menu_ids),
        dialect.conflict_suffix()
    )
}

/// common 角色的**声明式目标态重排**（与 `m20260924_000010` 同语义），返回 `(DELETE, INSERT)`。
///
/// ⚠️ 只允许**一次性**路径（迁移）使用，启动兜底**禁止**调用：common 是可被管理员编辑的
/// 普通角色（实测 `PUT /system/role` 对 role_id=2 生效），每次启动重排会静默摧毁
/// 管理员在角色授权页的自定义授权。存量库的既有越权行由运维在管理端收紧，
/// 本项目的存量回收纪律见 AGENTS《开关类能力设计规范》第 6 条。
pub fn common_role_realign_sql() -> (String, String) {
    (
        format!("DELETE FROM sys_role_menu WHERE role_id = {COMMON_ROLE_ID}"),
        format!(
            "INSERT INTO sys_role_menu (role_id, menu_id) \
             SELECT {COMMON_ROLE_ID}, menu_id FROM sys_menu \
             WHERE del_flag = '0' AND {}",
            common_role_grant_where()
        ),
    )
}

/// **窄撤销**：只删除 common 上"违反策略"的授权行，不重排、不触碰合规授权。
///
/// 与 [`common_role_realign_sql`] 的区别是本函数**只减不增**，因此可用于升级路径：
/// 全量重排会连带删掉管理员在授权页手工勾选的合规项，窄撤销只回收策略判定的越权面
/// （写权限 F 按钮 + 已软删菜单），管理员为页面/只读按钮做的授权一律保留。
/// 幂等：第二次执行影响 0 行。
///
/// 同样**禁止**挂到启动兜底（每次启动都会回收管理员事后手工勾选的写按钮）。
pub fn common_role_erosion_sql() -> String {
    format!(
        "DELETE FROM sys_role_menu WHERE role_id = {COMMON_ROLE_ID} AND menu_id IN (\
         SELECT menu_id FROM sys_menu WHERE NOT (del_flag = '0' AND {}))",
        common_role_grant_where()
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    /// 注册表自洽：两张表各自按 key 字典序、key 全局唯一、非空
    #[test]
    fn test_registry_ordering_and_uniqueness() {
        for (name, table) in [("FEATURES", FEATURES), ("CONFIGS", CONFIGS)] {
            assert!(!table.is_empty(), "{name} 不得为空");
            let keys: Vec<&str> = table.iter().map(|i| i.key).collect();
            let mut sorted = keys.clone();
            sorted.sort_unstable();
            assert_eq!(keys, sorted, "{name} 必须按 key 字典序排列");
        }
        let mut seen: HashSet<&str> = HashSet::new();
        for i in all() {
            assert!(seen.insert(i.key), "治理项键重复登记：{}", i.key);
        }
        assert_eq!(seen.len(), FEATURES.len() + CONFIGS.len());
    }

    /// 能力位项：默认档恒为 off 且必须是 `modes` 首项；解锁项的所需档位必须真实登记
    #[test]
    fn test_features_default_off_and_unlock_modes_registered() {
        for f in FEATURES {
            assert_eq!(f.kind, Kind::Feature);
            assert_eq!(f.default_mode, OFF, "{} 默认档必须为 off", f.key);
            assert_eq!(
                f.modes.first().copied(),
                Some(OFF),
                "{} 的 modes 首项约定为 off",
                f.key
            );
            assert!(
                f.modes.contains(&f.default_mode),
                "{} 默认档不在 modes 内",
                f.key
            );
            assert_eq!(
                f.coverage,
                Coverage::Ceiling,
                "能力位必须为 Ceiling（平台是天花板，租户套餐只能收窄）"
            );
            for (required, perms) in f.unlocked {
                assert!(
                    f.modes.contains(required),
                    "{} 为未登记的档位 {required} 声明了解锁清单",
                    f.key
                );
                assert!(!perms.is_empty(), "{} 的 {required} 档解锁清单为空", f.key);
                // 解锁项不得包含 off 档（off = 能力不存在，不能解锁任何东西）
                assert_ne!(*required, OFF, "{} 不得为 off 档声明解锁清单", f.key);
            }
        }
    }

    /// 参数项：无档位（`modes` 空、`default_mode` 空），且不以能力位身份出现
    #[test]
    fn test_configs_have_no_modes() {
        for c in CONFIGS {
            assert_eq!(c.kind, Kind::Config);
            assert!(c.modes.is_empty(), "{} 不应有档位", c.key);
            assert_eq!(
                c.default_mode, "",
                "{} 无档位时 default_mode 必须为空",
                c.key
            );
            assert!(
                c.unlocked.is_empty(),
                "{} 非能力位，不应有 perms 解锁清单",
                c.key
            );
        }
    }

    /// **CONFIG_DEFAULTS 双向一致锁**（批次十四）：缺省三元组的键集必须与
    /// `CONFIGS` 键集完全相等——新增参数项漏登缺省值 ⇒ 启动收敛不补行 ⇒
    /// 复现"G-11 八键存量库无行、纯 UPDATE 写入静默失效"缺陷；多登死键同理。
    #[test]
    fn test_config_defaults_cover_all_configs() {
        let reg: std::collections::BTreeSet<&str> = CONFIGS.iter().map(|c| c.key).collect();
        let defs: std::collections::BTreeSet<&str> =
            CONFIG_DEFAULTS.iter().map(|(k, _, _)| *k).collect();
        assert_eq!(
            reg, defs,
            "CONFIG_DEFAULTS 与 CONFIGS 键集不一致——新增参数项必须同步登记 (key, name, value)"
        );
        for (k, name, _) in CONFIG_DEFAULTS {
            assert!(!name.is_empty(), "{k} 的显示名不得为空");
        }
    }

    /// 覆盖策略 → 治理列 seed 三元组映射（fail-closed 姿态：Locked 必须不可见不可改）
    #[test]
    fn test_coverage_seed_triples() {
        assert_eq!(
            (
                Coverage::Locked.scope(),
                Coverage::Locked.tenant_editable(),
                Coverage::Locked.visible_to_tenant()
            ),
            ("platform_only", "0", "0")
        );
        for c in [Coverage::Free, Coverage::Ceiling] {
            assert_eq!(c.scope(), "platform_default");
            assert_eq!(c.tenant_editable(), "1");
            assert_eq!(c.visible_to_tenant(), "1");
        }
        assert_eq!(Coverage::Private.scope(), "tenant_private");
        assert_eq!(Coverage::Private.tenant_editable(), "1");
        // 只有 Ceiling 要求方向钳制
        assert!(Coverage::Ceiling.requires_ceiling());
        assert!(!Coverage::Locked.requires_ceiling());
        assert!(!Coverage::Free.requires_ceiling());
    }

    /// 分组清单与覆盖策略一致，且三组并集 = 全部参数项（无遗漏、无重复）
    #[test]
    fn test_key_groups_cover_all_configs() {
        let locked: Vec<&str> = locked_keys().collect();
        let defaults: Vec<&str> = default_keys().collect();
        let private: Vec<&str> = private_keys().collect();
        assert_eq!(
            locked.len() + defaults.len() + private.len(),
            CONFIGS.len(),
            "三组并集必须覆盖全部参数项"
        );
        let mut seen: HashSet<&str> = HashSet::new();
        for k in locked.iter().chain(&defaults).chain(&private) {
            assert!(seen.insert(k), "键 {k} 同时落入多个分组");
        }
    }

    /// 键查询与档位比较：未登记项 / 未登记档位一律 fail-closed
    #[test]
    fn test_lookup_fails_closed() {
        assert!(item("nav.l3").is_some());
        assert!(item("not.registered").is_none());
        assert_eq!(mode_rank("nav.l3", "off"), Some(0));
        assert_eq!(mode_rank("nav.l3", "view_only"), Some(1));
        assert_eq!(mode_rank("nav.l3", "full"), Some(2));
        assert_eq!(mode_rank("nav.l3", "bogus"), None);
        assert_eq!(mode_rank("not.registered", "off"), None);
        // 参数项无档位 ⇒ 任何档位串都返回 None
        assert_eq!(mode_rank("sys.index.skinName", "off"), None);
    }

    /// **可证伪收敛锁**：`Ceiling` 下请求值永远无法抬到平台之上。
    ///
    /// 可证伪性：若把 `Ceiling` 误实现为"取请求值"，断言 ② ③ 立即变红
    /// （租户改自己的套餐就能绕过平台关闭姿态 = 越权自开）。
    #[test]
    fn test_converge_ceiling_only_narrows() {
        // ① 租户收窄：平台 full + 请求 view_only ⇒ view_only
        assert_eq!(converge("nav.l3", "full", "view_only"), Some("view_only"));
        // ② 租户不得越权自开：平台 view_only + 请求 full ⇒ view_only
        assert_eq!(converge("nav.l3", "view_only", "full"), Some("view_only"));
        // ③ 平台关闭态不可被绕过：平台 off + 请求 full ⇒ off
        assert_eq!(converge("nav.l3", "off", "full"), Some("off"));
        // ④ 非法请求回落平台值（fail-closed）
        assert_eq!(converge("nav.l3", "full", "bogus"), Some("full"));
        // ⑤ 两值相同 ⇒ 该值
        assert_eq!(converge("nav.l3", "full", "full"), Some("full"));
        // ⑥ 未登记 / 无档位项 ⇒ None（调用方必须回落平台值）
        assert_eq!(converge("not.registered", "off", "off"), None);
        assert_eq!(converge("sys.index.skinName", "dark", "light"), None);
        // ⑦ 单档能力位（off|on）同样受天花板约束
        assert_eq!(
            converge("backup.tenant_self_export", "off", "on"),
            Some("off")
        );
        assert_eq!(
            converge("backup.tenant_self_export", "on", "on"),
            Some("on")
        );
        // ⑧ 平台值非法 + 请求值合法 ⇒ 取请求值（不至于把租户锁死在非法态）
        assert_eq!(converge("nav.l3", "bogus", "view_only"), Some("view_only"));
    }

    /// 值域校验：未登记项 fail-closed；有档位项必须命中；无档位项不拦
    #[test]
    fn test_is_known_mode() {
        assert!(is_known_mode("nav.l3", "view_only"));
        assert!(is_known_mode("nav.l3", "off"));
        assert!(!is_known_mode("nav.l3", "bogus"));
        assert!(!is_known_mode("not.registered", "off"));
        // 无档位项（参数项）：值域由业务规则另行约束，此处不拦
        //（§5.23 后无档位键仅剩 Locked 项——skinName 等死键已移出注册表）
        assert!(is_known_mode(
            "sys.account.captchaEnabled",
            "any-value-passes"
        ));
        // 被移出的死键按"未登记"处理（fail-closed）
        assert!(!is_known_mode("sys.index.skinName", "any-theme-name"));
    }

    /// **档位安全单调锁**：`modes` 是"下标越大越开放"的有序档位集合。
    ///
    /// 可证伪性：若有人在 `modes` 里写重复档位，或把某能力位的解锁清单写成
    /// "写面在前、只读在后"，本用例立即变红——档位语义一旦乱序，
    /// `converge` 的 `min(rank)` 与 `mode_reaches` 的阈值比较都会静默错判。
    #[test]
    fn test_modes_are_safely_monotonic() {
        for f in FEATURES {
            // 档位不得重复（重复会让 position() 只命中首个，语义歧义）
            let uniq: HashSet<&&str> = f.modes.iter().collect();
            assert_eq!(uniq.len(), f.modes.len(), "{} 的 modes 存在重复档位", f.key);
            // 解锁清单的所需档位必须随声明顺序**非递减**（只读面在前、写面/危险面在后）
            let ranks: Vec<usize> = f
                .unlocked
                .iter()
                .map(|(m, _)| {
                    f.modes
                        .iter()
                        .position(|x| x == m)
                        .unwrap_or_else(|| panic!("{} 的解锁档位 {m} 未登记", f.key))
                })
                .collect();
            assert!(
                ranks.windows(2).all(|w| w[0] <= w[1]),
                "{} 的解锁清单档位必须非递减（只读面在前、写面在后）",
                f.key
            );
        }
    }

    // ------------------------------------------------ common 授权策略锁

    /// 策略矩阵：M/C 恒可见；F 只读后缀放行；F 写权限拒绝；例外 menu_id 放行。
    ///
    /// 可证伪性：把 `:center` 从只读集合删除、或把某个写后缀误加进只读集合，
    /// 本用例立即变红（对照组：同一条写权限 perms 挂在例外 id 上必须放行，
    /// 证明放行来自 id 例外而非判据失效）。
    #[test]
    fn test_common_role_policy_matrix() {
        let readonly = [
            ("system:config:list", true),
            ("system:user:query", true),
            ("monitor:server:view", true),
            ("system:user:profile", false),
            ("tool:gen:preview", false),
            ("monitor:cache:list", true),
        ];
        for (perms, want) in readonly {
            assert_eq!(
                common_role_may_grant(900_001, "F", perms),
                want,
                "F 按钮 {perms} 的只读判定应为 {want}"
            );
        }
        // 目录/页面：无论 perms 为何都放行（页面可见由 getRouters 与能力位再剪枝）
        for mt in ["M", "C"] {
            assert!(common_role_may_grant(900_002, mt, ""));
            assert!(common_role_may_grant(900_003, mt, "system:user:remove"));
        }
        // 未知菜单类型一律拒绝（fail-closed，防"新增类型即自动放行"）
        for mt in ["", "F ", "X", "B"] {
            assert!(!common_role_may_grant(900_004, mt, "system:user:list"));
        }
        // 写权限：非例外 id 拒绝；同一 perms 在例外 id 上放行（例外来自 id，不来自判据）
        assert!(!common_role_may_grant(900_005, "F", "system:user:remove"));
        let first_exception = COMMON_ROLE_WRITE_EXCEPTIONS[0];
        assert!(common_role_may_grant(
            first_exception.0,
            "F",
            "system:user:remove"
        ));
    }

    /// 例外登记表自洽：id 唯一、为正、理由非空且不是占位（防止"为消除红灯而登记空理由"）
    #[test]
    fn test_common_role_write_exceptions_are_reasoned() {
        let mut seen: HashSet<i64> = HashSet::new();
        for (id, reason) in COMMON_ROLE_WRITE_EXCEPTIONS {
            assert!(*id > 0, "例外 menu_id 非法：{id}");
            assert!(seen.insert(*id), "例外 menu_id 重复登记：{id}");
            assert!(
                reason.trim().len() >= 8,
                "例外 {id} 的理由过短（{reason}）——例外必须自带可复核依据"
            );
            // 例外只适用于写权限按钮：其 id 不得同时是只读后缀能放行的（那是冗余登记）
            assert!(
                !COMMON_ROLE_READONLY_PERM_SUFFIXES
                    .iter()
                    .any(|s| reason.ends_with(s)),
                "例外 {id} 的理由形似权限后缀，应为说明文字"
            );
        }
        assert!(
            !COMMON_ROLE_WRITE_EXCEPTIONS.is_empty(),
            "例外表为空说明批次十三 拍板被静默丢弃"
        );
    }

    /// SQL 子句与 Rust 谓词同源：子句必须展开全部只读后缀与全部例外 id（缺一即两侧判据漂移）
    #[test]
    fn test_common_role_grant_where_expands_both_sources() {
        let sql = common_role_grant_where();
        assert!(sql.contains("menu_type IN ('M', 'C')"), "{sql}");
        for s in COMMON_ROLE_READONLY_PERM_SUFFIXES {
            // 必须**带闭引号**：`'%:list` 少了结尾 `'` 会让整条语句引号失配，
            // 后续 `:query` 被 SQLite 当作命名参数 ⇒ sqlx 直接报
            // "unsupported SQL parameter format"（b73 轮 15 实测由 initialize 兜底测试抓回）
            assert!(
                sql.contains(&format!("perms LIKE '%{s}'")),
                "子句缺只读后缀 {s}（或引号未闭合）: {sql}"
            );
        }
        assert_eq!(
            sql.matches('\'').count() % 2,
            0,
            "单引号数量必须成对，否则 SQL 语法/参数解析失败: {sql}"
        );
        for id in common_role_write_exception_ids() {
            assert!(
                sql.contains("menu_id IN (") && sql.contains(&id.to_string()),
                "子句缺例外 id {id}"
            );
        }
        // 例外为空的退化态仍必须是合法 SQL（防"空 IN ()"语法错误）
        assert!(
            common_role_write_exception_ids().is_empty() || sql.contains(" OR menu_id IN ("),
            "存在例外登记却未展开 IN 子句: {sql}"
        );
        assert!(
            !sql.contains("IN ()"),
            "空 IN 子句会触发 SQL 语法错误: {sql}"
        );
    }

    /// 兜底补授 SQL 形状锁：必须是 `INSERT … SELECT`（DB 侧套用策略），
    /// 且禁止退回裸 `VALUES (2, id)` 形态——后者正是本次治理根除的侵蚀入口。
    #[test]
    fn test_common_role_backfill_sql_shape() {
        for (dialect, expect_prefix, expect_suffix) in [
            (Dialect::Sqlite, "INSERT OR IGNORE INTO ", ""),
            (Dialect::Postgres, "INSERT INTO ", " ON CONFLICT DO NOTHING"),
            (Dialect::MySql, "INSERT IGNORE INTO ", ""),
        ] {
            let sql = common_role_backfill_sql(dialect, &[3560, 3561]);
            assert!(
                sql.starts_with(expect_prefix),
                "{dialect:?} 前缀不符: {sql}"
            );
            assert!(sql.ends_with(expect_suffix), "{dialect:?} 后缀不符: {sql}");
            assert!(sql.contains("SELECT 2, menu_id FROM sys_menu"), "{sql}");
            assert!(sql.contains("menu_id IN (3560, 3561)"), "{sql}");
            assert!(sql.contains("del_flag = '0'"), "{sql}");
            assert!(
                sql.contains(&common_role_grant_where()),
                "{dialect:?} 未套用策略子句: {sql}"
            );
            assert!(
                !sql.contains("VALUES (2,"),
                "{dialect:?} 退回裸 VALUES 形态，绕过策略: {sql}"
            );
            assert!(
                !sql.contains("IN ()"),
                "空 IN 子句会触发 SQL 语法错误: {sql}"
            );
            assert_eq!(
                sql.matches('\'').count() % 2,
                0,
                "{dialect:?} 单引号未成对: {sql}"
            );
        }
        // 语句体必须是"裸 body"（无前后缀），否则调用方的方言助手会二次拼接出非法 SQL
        let body = common_role_grant_select_body(&[3560, 3561]);
        assert!(
            body.starts_with("sys_role_menu (role_id, menu_id) SELECT"),
            "{body}"
        );
        for frag in ["INSERT", "ON CONFLICT", "IGNORE"] {
            assert!(!body.contains(frag), "语句体不应含 {frag} 片段: {body}");
        }
    }

    /// 声明式重排 SQL 形状锁（迁移专用）：DELETE 只作用 common，INSERT 套用策略子句
    #[test]
    fn test_common_role_realign_sql_shape() {
        let (delete, insert) = common_role_realign_sql();
        assert_eq!(delete, "DELETE FROM sys_role_menu WHERE role_id = 2");
        assert!(insert.starts_with("INSERT INTO sys_role_menu (role_id, menu_id)"));
        assert!(insert.contains("del_flag = '0'"), "{insert}");
        assert!(
            insert.contains(&common_role_grant_where()),
            "重排语句未套用策略子句: {insert}"
        );
        assert!(!insert.contains("DELETE"), "INSERT 语句不得夹带 DELETE");
    }

    /// 窄撤销 SQL 形状锁：只删 common、且**只删违反策略的行**（只减不增 ⇒ 升级路径安全）
    ///
    /// 可证伪性：若有人把子句写成"删除全部 common 授权"（漏掉 `NOT (…)` 包裹），
    /// 本用例会因缺少策略子句而红；若把 role 过滤写丢，会因缺少 `role_id = 2` 而红。
    #[test]
    fn test_common_role_erosion_sql_shape() {
        let sql = common_role_erosion_sql();
        assert!(
            sql.starts_with("DELETE FROM sys_role_menu WHERE role_id = 2 AND menu_id IN ("),
            "{sql}"
        );
        assert!(
            sql.contains(&format!(
                "NOT (del_flag = '0' AND {})",
                common_role_grant_where()
            )),
            "窄撤销未套用策略子句: {sql}"
        );
        assert!(!sql.contains("INSERT"), "窄撤销只减不增: {sql}");
    }
}
