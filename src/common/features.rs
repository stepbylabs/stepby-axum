// axum-backend/src/common/features.rs
//! 能力位（Feature Flags）注册表与租户能力集。
//!
//! # 为什么需要它
//!
//! 本项目是**开源的中后台管理系统**，定位「大而全」：能力要齐备，让使用者自己选择或配置。
//! 因此平台专属能力（如租户域名自助、备份只读可见、L3 自建导航）**不整块砍掉**，而是
//! 收敛为三层开关：
//!
//! 1. **平台层**：`config.toml` 的 `[features]` 段（进程级默认，`OnceLock` 注入）——能开什么；
//! 2. **租户层**：`sys_tenant_package.features`（JSON，本模块 [`FeatureSet`]）——这个租户能开什么；
//! 3. **角色层**：既有角色授权（`sys_role_menu` + `is_grantable_perm`）——这个人能用什么。
//!
//! # 铁律
//!
//! - **开关取「模式」而非裸 bool**：见 [`FeatureDef::modes`]（如 `off | view_only | full`）。
//! - **默认值 = 现状 = 关闭态即安全态**：缺键、未知 key、JSON 解析失败、模式值非法
//!   一律回落到 [`FeatureDef::default_mode`]，且注册表内所有能力位的默认值恒为 `"off"`。
//! - **放开必有守卫**：能力位只负责「可授予性」（[`is_grantable_perm_with_features`]），
//!   真正的数据面隔离由服务层 `tenant_scope` 承担——两者缺一不可。

use std::collections::BTreeMap;
use std::sync::OnceLock;

/// 关闭态字面量（等价于「能力不存在」，是全系统的最小权限基准）
pub const FEATURE_OFF: &str = "off";

/// 单个能力位的定义（模式集合 + 默认模式）
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FeatureDef {
    /// 能力位键（点分小写，与 `sys_tenant_package.features` JSON 的 key 一致）
    pub key: &'static str,
    /// 默认模式（**必须**是 `modes` 中的一项，且注册表内恒为 [`FEATURE_OFF`]）
    pub default_mode: &'static str,
    /// 允许的模式集合（首项约定为 `off`，便于阅读时确认"关闭态即安全态"）
    pub modes: &'static [&'static str],
}

/// **能力位单一事实源**：新增能力位必须在此登记，否则
/// [`FeatureSet::sanitized`] 会静默剔除该键（TS/前端/管理页也据此渲染）。
///
/// 排序：按 key 字典序（`to_json` 用 [`BTreeMap`]，顺序一致便于 diff 与断言）。
pub const KNOWN_FEATURES: &[FeatureDef] = &[
    FeatureDef {
        key: "backup.readonly_visible",
        default_mode: FEATURE_OFF,
        modes: &[FEATURE_OFF, "on"],
    },
    FeatureDef {
        key: "backup.tenant_self_export",
        default_mode: FEATURE_OFF,
        modes: &[FEATURE_OFF, "on"],
    },
    FeatureDef {
        key: "nav.l3",
        default_mode: FEATURE_OFF,
        modes: &[FEATURE_OFF, "view_only", "full"],
    },
    FeatureDef {
        key: "tenant.domain_self_service",
        default_mode: FEATURE_OFF,
        modes: &[FEATURE_OFF, "full"],
    },
];

/// 能力位 → **解锁的平台专属权限白名单**（逐条枚举，禁止前缀通配）。
///
/// 语义：清单内的 perms **仅在对应能力位非 `off` 时**才可授予租户角色；清单外的
/// 平台专属 perms 恒不可授予（见 [`is_grantable_perm_with_features`]）。
///
/// ⚠️ 逐条枚举而非按前缀放开是**刻意的**：`system:backup:` 下
/// `query` 同时映射"详情查询"与"整库下载"两个端点（`GET /system/backup/download/{id}`），
/// 按前缀放开等于把整库导出面下放。批次 2 拆分 download 独立权限后，
/// 本清单才可收录只读子集。
pub const CAPABILITY_UNLOCKED_PERMS: &[(&str, &[&str])] = &[
    // 租户域名自助（批次 1c）：能力位开启时，域名管理 5 项权限可授予租户管理员，
    // 服务层按 tid 收窄（仅能读写本租户域名）。
    // 清单与 `middleware/permission.rs` 的 `/system/tenant/domain/*` 权限映射逐条对应
    // （单测 `test_unlocked_perms_are_actually_registered` 锁死双向一致）。
    (
        "tenant.domain_self_service",
        &[
            "system:tenant:domain:list",
            "system:tenant:domain:add",
            "system:tenant:domain:verify",
            "system:tenant:domain:edit",
            "system:tenant:domain:remove",
        ],
    ),
];

/// **已被开启的能力位解锁的平台专属前缀**（= [`CAPABILITY_UNLOCKED_PERMS`] 中
/// 能力位非 `off` 的项所覆盖的前缀，去重后保持 `PLATFORM_ONLY_PERM_PREFIXES` 的顺序）。
///
/// 用途见 [`platform_only_prefixes_to_strip`]。
pub fn unlocked_platform_only_prefixes(features: &FeatureSet) -> Vec<&'static str> {
    crate::common::tenant::PLATFORM_ONLY_PERM_PREFIXES
        .iter()
        .copied()
        .filter(|prefix| {
            CAPABILITY_UNLOCKED_PERMS.iter().any(|(feat, list)| {
                features.is_on(feat) && list.iter().any(|p| p.starts_with(prefix))
            })
        })
        .collect()
}

/// **启动治理应剔除**的平台专属前缀 = 全部平台专属前缀 − [`unlocked_platform_only_prefixes`]。
///
/// # 为什么必须能力位感知
///
/// `initialize::ensure_tenant_role_menu_governance` 在**每次启动**都会清理存量角色持有的
/// 平台专属菜单授权（防止"菜单可见但请求一律 403"的假入口）。若能力位（如
/// `tenant.domain_self_service`）已开启、管理员据此把域名管理菜单授予租户管理员，
/// 而本清单仍无条件包含该前缀，就会出现 **"刚授完、重启即被收回"** 的权限黑洞——
/// 能力位形同虚设。故：
///
/// - 能力位 `off`（默认）⇒ 该前缀在剔除清单内（= 现状，关闭态即安全态）；
/// - 能力位非 `off` ⇒ 该前缀移出剔除清单（是否授予仍由套餐与角色授权两层决定）。
///
/// # 安全性前提（单测锁死）
///
/// "整前缀免剔"只在**该前缀下的全部 perms 都被白名单收录**时才安全；否则会出现
/// "部分解锁、整前缀免剔"的静默放开。单测
/// `test_strip_list_only_excludes_fully_unlocked_prefixes` 以
/// `middleware/permission.rs` 源码为真值做双向断言。
pub fn platform_only_prefixes_to_strip(features: &FeatureSet) -> Vec<&'static str> {
    let unlocked = unlocked_platform_only_prefixes(features);
    crate::common::tenant::PLATFORM_ONLY_PERM_PREFIXES
        .iter()
        .copied()
        .filter(|p| !unlocked.contains(p))
        .collect()
}

/// 查注册表：返回能力位定义（未知 key 返回 `None`）。
pub fn feature_def(key: &str) -> Option<&'static FeatureDef> {
    KNOWN_FEATURES.iter().find(|f| f.key == key)
}

/// 取能力位的默认模式；未知 key 恒返回 [`FEATURE_OFF`]（fail-closed）。
pub fn feature_default_mode(key: &str) -> &'static str {
    feature_def(key)
        .map(|f| f.default_mode)
        .unwrap_or(FEATURE_OFF)
}

/// 校验 `mode` 是否为 `key` 的合法取值（未知 key 只有 `off` 合法）。
pub fn is_valid_mode(key: &str, mode: &str) -> bool {
    match feature_def(key) {
        Some(def) => def.modes.contains(&mode),
        None => mode == FEATURE_OFF,
    }
}

/// 某租户（或平台默认层）解析后的能力集。
///
/// 内部只存**显式覆盖**项；未覆盖的键由 [`FeatureSet::mode`] 回落到注册表默认模式，
/// 因此 `FeatureSet::default()` == 全 `off` == 现状，天然满足"关闭态即安全态"。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FeatureSet {
    /// key → mode（`BTreeMap` 保证 `to_json` 输出稳定，便于断言与 diff）
    overrides: BTreeMap<String, String>,
}

impl FeatureSet {
    /// 由"显式覆盖"映射构造，并做**白名单净化**：剔除未知 key 与非法模式值。
    ///
    /// 净化是安全边界——用户在 `config.toml` 或套餐 JSON 里写错 key/模式时，
    /// 结果是"该能力位保持默认（off）"而不是"意外开启"。
    ///
    /// ⚠️ **显式 `off` 会被保留**（不因"与默认值相同"而丢弃）：它与"未配置"语义不同——
    /// 未配置 = 跟随上层，显式 `off` = 主动收窄（见 [`FeatureSet::narrowed_by`]）。
    /// 若把两者合并，平台层开启的能力位将无法被租户主动关闭。
    pub fn sanitized(overrides: impl IntoIterator<Item = (String, String)>) -> Self {
        let mut map = BTreeMap::new();
        for (key, mode) in overrides {
            if !is_valid_mode(&key, &mode) {
                tracing::warn!(
                    feature = %key,
                    mode = %mode,
                    "能力位取值非法（未登记 key 或模式不在允许集合内），已忽略并回落到默认模式"
                );
                continue;
            }
            map.insert(key, mode);
        }
        Self { overrides: map }
    }

    /// 解析 `sys_tenant_package.features` 的 JSON 文本（`None`/空白 = 全默认）。
    ///
    /// **解析失败一律回落到全默认（fail-closed）**，并把原文打日志，便于排查配置事故。
    pub fn from_json(raw: Option<&str>) -> Self {
        let Some(raw) = raw else {
            return Self::default();
        };
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return Self::default();
        }
        match serde_json::from_str::<BTreeMap<String, String>>(trimmed) {
            Ok(map) => Self::sanitized(map),
            Err(e) => {
                tracing::warn!(
                    raw = %trimmed,
                    error = %e,
                    "租户套餐 features JSON 解析失败，已回落到全默认（关闭态）"
                );
                Self::default()
            }
        }
    }

    /// 取能力位模式；未显式覆盖时回落注册表默认模式（未知 key 恒 `off`）。
    pub fn mode(&self, key: &str) -> &str {
        match self.overrides.get(key) {
            Some(m) => m.as_str(),
            None => feature_default_mode(key),
        }
    }

    /// 能力位是否处于非关闭态（`off` 之外的一切模式）。
    pub fn is_on(&self, key: &str) -> bool {
        self.mode(key) != FEATURE_OFF
    }

    /// 显式覆盖项（只读视图，用于 API 回显与管理页）。
    pub fn overrides(&self) -> &BTreeMap<String, String> {
        &self.overrides
    }

    /// 是否与"全默认"等价（即不携带任何有效覆盖）。
    pub fn is_default(&self) -> bool {
        self.overrides.is_empty()
    }

    /// 以 `self` 为**上限**（平台层「能开什么」）、`lower` 为**收窄层**（租户套餐
    /// 「这个租户能开什么」）合成有效能力集：**逐键取较不开放的模式**。
    ///
    /// 方向性至关重要：平台层是天花板，租户只能在其内**收窄**，绝不能反向抬高——
    /// 否则租户改自己的套餐就能绕过平台 `[features]` 的关闭姿态（"越权自开"）。
    /// 比较依据是注册表 `modes` 数组下标（下标越小越保守，见 [`FeatureDef::modes`]）。
    pub fn narrowed_by(&self, lower: &FeatureSet) -> FeatureSet {
        let mut map = BTreeMap::new();
        for def in KNOWN_FEATURES {
            let ceiling = self.mode(def.key);
            // 关键区分：`lower` **未配置**该键 = 跟随平台层；**显式配置**才参与收敛比较。
            // 若把"未配置"当作 `off`，租户不写该键就会把平台已开启的能力位压回关闭
            // （与"未配置 = 跟随平台默认"的直觉相反，且会让平台开关形同虚设）。
            let effective = match lower.overrides.get(def.key) {
                None => ceiling,
                Some(request) => {
                    if mode_rank(def.key, ceiling) <= mode_rank(def.key, request) {
                        ceiling
                    } else {
                        request
                    }
                }
            };
            if effective != def.default_mode {
                map.insert(def.key.to_string(), effective.to_string());
            }
        }
        FeatureSet { overrides: map }
    }

    /// 序列化为 JSON（无覆盖时输出 `{}`，可直接落 `sys_tenant_package.features`）。
    pub fn to_json(&self) -> String {
        // BTreeMap<String,String> 的序列化不会失败；失败时退回 `{}`（= 全默认）而非 panic
        serde_json::to_string(&self.overrides).unwrap_or_else(|_| "{}".to_string())
    }
}

/// 模式在注册表 `modes` 中的下标（越小越保守）；未登记模式按最保守（0）处理。
fn mode_rank(key: &str, mode: &str) -> usize {
    feature_def(key)
        .and_then(|def| def.modes.iter().position(|m| *m == mode))
        .unwrap_or(0)
}

/// 平台层能力位（`config.toml` 的 `[features]` 段，启动时注入）。
static PLATFORM_FEATURES: OnceLock<FeatureSet> = OnceLock::new();

/// 注入平台层能力位（幂等：重复调用只保留首次，避免测试/热重载造成姿态漂移）。
///
/// 返回实际生效的平台层能力位。
pub fn init_platform_features(set: FeatureSet) -> &'static FeatureSet {
    if PLATFORM_FEATURES.set(set).is_err() {
        tracing::debug!("平台层能力位已初始化，忽略重复注入");
    }
    platform_features()
}

/// 读取平台层能力位；未初始化时使用 [`FeatureSet::default`]（全 `off`）。
///
/// 未初始化即"全关"是刻意的：单元测试、migration crate 及任何早于启动流程的
/// 调用点都自动处于最小权限姿态，不会因"忘了初始化"而意外放开。
pub fn platform_features() -> &'static FeatureSet {
    PLATFORM_FEATURES
        .get()
        .unwrap_or_else(builtin_default_features)
}

/// 内置默认（全 `off`）的进程级单例，供 [`platform_features`] 未初始化时兜底。
fn builtin_default_features() -> &'static FeatureSet {
    static DEFAULTS: OnceLock<FeatureSet> = OnceLock::new();
    DEFAULTS.get_or_init(FeatureSet::default)
}

/// **能力位感知的"可授予"判定**（`common::tenant::is_grantable_perm` 的能力位版本）。
///
/// 判定顺序：
/// 1. 命中 [`CAPABILITY_UNLOCKED_PERMS`] 且对应能力位非 `off` ⇒ **可授予**
///    （其服务层必须已按 tid 收窄，见该常量文档）；
/// 2. 平台专属前缀 ⇒ 不可授予；
/// 3. 命中 tier2（表带 `tenant_id` 但集合读路径未接过滤）⇒ 不可授予。
///
/// 传入 [`FeatureSet::default`] 时与旧 `is_grantable_perm` **逐条等价**（全 `off` 即现状），
/// 这保证"开关缺省 = 行为不变"。
pub fn is_grantable_perm_with_features(perms: &str, features: &FeatureSet) -> bool {
    if CAPABILITY_UNLOCKED_PERMS
        .iter()
        .any(|(feat, list)| features.is_on(feat) && list.contains(&perms))
    {
        return true;
    }
    if crate::common::tenant::is_platform_only_perm(perms) {
        return false;
    }
    !matches!(
        crate::common::tenant::tenant_filter_lookup(perms),
        Some((_, crate::common::tenant::TenantFilterTier::Tier2))
    )
}

/// 授予前门禁的能力位版本：返回 `Err(perms)` 即首个不可授予项。
pub fn ensure_menu_filter_coverage_with_features<'a>(
    perms_list: impl IntoIterator<Item = &'a str>,
    features: &FeatureSet,
) -> Result<(), &'a str> {
    for perms in perms_list {
        if !is_grantable_perm_with_features(perms, features) {
            return Err(perms);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 注册表自洽：默认模式必须是合法模式，且**恒为 off**（"关闭态即安全态"）
    #[test]
    fn test_registry_defaults_are_all_off() {
        assert!(!KNOWN_FEATURES.is_empty(), "注册表不得为空");
        for def in KNOWN_FEATURES {
            assert!(
                def.modes.contains(&def.default_mode),
                "{} 的 default_mode={} 不在 modes 内",
                def.key,
                def.default_mode
            );
            assert_eq!(
                def.default_mode, FEATURE_OFF,
                "{} 的默认模式必须为 off（默认值 = 现状 = 关闭态即安全态）",
                def.key
            );
            assert_eq!(
                def.modes.first().copied(),
                Some(FEATURE_OFF),
                "{} 的 modes 首项约定为 off",
                def.key
            );
            // key 唯一
            assert_eq!(
                KNOWN_FEATURES.iter().filter(|d| d.key == def.key).count(),
                1,
                "{} 重复登记",
                def.key
            );
        }
        // 注册表按 key 字典序（便于阅读与 diff）
        let keys: Vec<&str> = KNOWN_FEATURES.iter().map(|d| d.key).collect();
        let mut sorted = keys.clone();
        sorted.sort_unstable();
        assert_eq!(keys, sorted, "KNOWN_FEATURES 必须按 key 字典序排列");
    }

    /// 默认能力集：一切能力位为 off，且与旧 `is_grantable_perm` 逐条等价
    #[test]
    fn test_default_features_is_off_and_backward_compatible() {
        let f = FeatureSet::default();
        for def in KNOWN_FEATURES {
            assert_eq!(f.mode(def.key), FEATURE_OFF, "{} 默认必须 off", def.key);
            assert!(!f.is_on(def.key));
        }
        // 未知 key fail-closed
        assert_eq!(f.mode("nope.unknown"), FEATURE_OFF);
        assert!(!f.is_on("nope.unknown"));
        assert!(f.is_default());

        // 缺省能力集下，能力位判定与旧判定逐条一致（开关缺省 = 行为不变）
        for p in [
            "system:user:list",
            "system:config:edit",
            "tool:gen:list",
            "monitor:cache:query",
            "system:tenant:domain:add",
            "system:tenant:domain:query",
            "system:backup:list",
            "system:backup:query",
            "",
        ] {
            assert_eq!(
                is_grantable_perm_with_features(p, &f),
                crate::common::tenant::is_grantable_perm(p),
                "{p} 在缺省能力集下的判定必须与旧判定一致"
            );
        }
    }

    /// JSON 解析：非法输入一律回落到全默认（fail-closed），且不 panic
    #[test]
    fn test_from_json_fails_closed() {
        for raw in [
            None,
            Some(""),
            Some("   "),
            Some("{"),                  // 语法错误
            Some("[1,2,3]"),            // 类型错误
            Some("\"off\""),            // 类型错误
            Some("{\"nav.l3\": true}"), // 值类型错误
        ] {
            let f = FeatureSet::from_json(raw);
            assert!(
                f.is_default(),
                "非法输入 {raw:?} 必须回落到全默认（关闭态）"
            );
        }
    }

    /// JSON 净化：未知 key 与非法模式被剔除，合法项保留
    #[test]
    fn test_from_json_sanitizes_unknown_and_invalid() {
        let f = FeatureSet::from_json(Some(
            r#"{"nav.l3":"full","not.a.feature":"on","backup.readonly_visible":"bogus","tenant.domain_self_service":"full"}"#,
        ));
        assert_eq!(f.mode("nav.l3"), "full");
        assert_eq!(f.mode("tenant.domain_self_service"), "full");
        assert_eq!(f.mode("not.a.feature"), FEATURE_OFF, "未知 key 不生效");
        assert_eq!(
            f.mode("backup.readonly_visible"),
            FEATURE_OFF,
            "非法模式必须回落到默认 off"
        );
        assert_eq!(f.overrides().len(), 2, "只保留 2 条合法覆盖");
    }

    /// 显式 `off` 必须**保留**（它与"未配置 = 跟随上层"语义不同，是"主动收窄"）
    ///
    /// 若在此丢弃显式 `off`，平台层开启的能力位就**无法**被租户主动关闭——
    /// 那是"租户套餐只能开不能关"的实质越权。故本断言锁死"显式 off 一定留在覆盖集里"，
    /// 并配 [`test_narrowed_by_platform_is_ceiling`] 验证它确实能收窄平台默认。
    #[test]
    fn test_from_json_keeps_explicit_off() {
        let f = FeatureSet::from_json(Some(r#"{"nav.l3":"off"}"#));
        assert!(
            !f.is_default(),
            "显式 off 是有信息的覆盖，不得被当作默认丢弃"
        );
        assert_eq!(f.overrides().len(), 1);
        assert_eq!(f.overrides().get("nav.l3").map(String::as_str), Some("off"));
        // 显式 off 能收窄平台默认（平台 full + 租户显式 off ⇒ off）
        let platform = FeatureSet::from_json(Some(r#"{"nav.l3":"full"}"#));
        assert_eq!(platform.narrowed_by(&f).mode("nav.l3"), FEATURE_OFF);
        // 真正的"未配置"才是空覆盖集
        assert!(FeatureSet::from_json(Some("{}")).is_default());
        assert!(FeatureSet::from_json(None).is_default());
    }

    /// 能力位开启后才解锁平台专属 perms；关闭态恒不可授予（**可证伪回归锁**）
    #[test]
    fn test_tenant_domain_self_service_unlocks_only_when_on() {
        let off = FeatureSet::default();
        let on = FeatureSet::from_json(Some(r#"{"tenant.domain_self_service":"full"}"#));

        // 关闭态：域名管理 5 项全部不可授予（= 现状）
        for p in [
            "system:tenant:domain:list",
            "system:tenant:domain:add",
            "system:tenant:domain:verify",
            "system:tenant:domain:edit",
            "system:tenant:domain:remove",
        ] {
            assert!(
                !is_grantable_perm_with_features(p, &off),
                "{p} 在关闭态下必须不可授予"
            );
            assert!(
                is_grantable_perm_with_features(p, &on),
                "{p} 在能力位开启后应可授予"
            );
        }

        // 未列入白名单的平台专属 perms 不受影响（能力位不是"万能钥匙"）
        for p in [
            "tool:gen:list",
            "monitor:cache:query",
            "system:rateLimit:edit",
        ] {
            assert!(
                !is_grantable_perm_with_features(p, &on),
                "{p} 不在解锁白名单内，开启域名自助后仍不可授予"
            );
        }
        // 白名单逐条枚举：不能凭前缀"多解锁"未登记项
        assert!(
            !is_grantable_perm_with_features("system:tenant:domain:superDelete", &on),
            "白名单必须逐条匹配，不得按前缀放开"
        );
    }

    /// **双向一致锁**：解锁白名单内的每一条 perms 必须真实存在于
    /// `middleware/permission.rs` 的权限映射表，且必须是平台专属前缀内的项。
    ///
    /// 缺此断言时，白名单可能写成"不存在的 perms"（形同空条款）或"非平台专属的
    /// 普通 perms"（会误导读者以为该能力位在放开这些权限）。
    #[test]
    fn test_unlocked_perms_are_actually_registered() {
        let src = std::fs::read_to_string("src/middleware/permission.rs")
            .expect("src/middleware/permission.rs 应存在");
        for (feat, perms_list) in CAPABILITY_UNLOCKED_PERMS {
            assert!(
                feature_def(feat).is_some(),
                "解锁白名单引用了未登记的能力位 {feat}"
            );
            for p in *perms_list {
                assert!(
                    src.contains(&format!("\"{p}\"")),
                    "解锁白名单中的 {p} 在 middleware/permission.rs 权限映射中不存在（空条款）"
                );
                assert!(
                    crate::common::tenant::is_platform_only_perm(p),
                    "{p} 不在平台专属前缀内，无需由能力位解锁（白名单条款失效）"
                );
            }
        }
    }

    /// tier2 表在能力位未开时仍被拦截（能力位不得绕过过滤接入门禁）
    #[test]
    fn test_tier2_still_blocked_without_capability() {
        let on = FeatureSet::from_json(Some(
            r#"{"tenant.domain_self_service":"full","backup.readonly_visible":"on"}"#,
        ));
        // backup.readonly_visible 已开，但白名单未收录 backup 项 ⇒ 仍不可授予
        for p in [
            "system:backup:list",
            "system:backup:query",
            "system:backup:add",
        ] {
            assert!(
                !is_grantable_perm_with_features(p, &on),
                "{p} 未登记解锁白名单，不得因开关存在而放开"
            );
        }
    }

    /// `is_on` 对多模式能力位的语义：非 off 即"开启"
    #[test]
    fn test_is_on_with_multi_mode() {
        let f = FeatureSet::from_json(Some(r#"{"nav.l3":"view_only"}"#));
        assert!(f.is_on("nav.l3"), "view_only 亦属开启态");
        assert_eq!(f.mode("nav.l3"), "view_only");
    }

    /// 分层合成：平台层是**天花板**，租户层只能收窄，不能反向抬高
    #[test]
    fn test_narrowed_by_platform_is_ceiling() {
        // ① 平台 full + 租户 view_only ⇒ view_only（租户收窄）
        let platform = FeatureSet::from_json(Some(r#"{"nav.l3":"full"}"#));
        let tenant = FeatureSet::from_json(Some(r#"{"nav.l3":"view_only"}"#));
        assert_eq!(platform.narrowed_by(&tenant).mode("nav.l3"), "view_only");

        // ② 平台 view_only + 租户 full ⇒ view_only（**租户不得越权自开**）
        let platform = FeatureSet::from_json(Some(r#"{"nav.l3":"view_only"}"#));
        let tenant = FeatureSet::from_json(Some(r#"{"nav.l3":"full"}"#));
        assert_eq!(
            platform.narrowed_by(&tenant).mode("nav.l3"),
            "view_only",
            "平台层是天花板，租户套餐不得反向抬高"
        );

        // ③ 平台 off + 租户 full ⇒ off（平台关闭态不可被租户绕过）
        let platform = FeatureSet::default();
        let tenant = FeatureSet::from_json(Some(r#"{"nav.l3":"full"}"#));
        assert_eq!(
            platform.narrowed_by(&tenant).mode("nav.l3"),
            FEATURE_OFF,
            "平台未开启的能力位，租户套餐写 full 也必须保持关闭"
        );

        // ④ 平台 full + 租户未配置 ⇒ full（未配置 = 跟随平台）
        let platform = FeatureSet::from_json(Some(r#"{"nav.l3":"full"}"#));
        assert_eq!(
            platform.narrowed_by(&FeatureSet::default()).mode("nav.l3"),
            "full"
        );

        // ⑤ 结果集内不留"与默认等价"的冗余项
        assert!(platform.narrowed_by(&tenant).to_json().contains("nav.l3"));
        assert!(FeatureSet::default().narrowed_by(&tenant).is_default());
    }

    /// `to_json` → `from_json` 往返稳定（幂等）
    #[test]
    fn test_json_roundtrip_is_stable() {
        let f = FeatureSet::from_json(Some(
            r#"{"backup.readonly_visible":"on","nav.l3":"view_only"}"#,
        ));
        let round = FeatureSet::from_json(Some(&f.to_json()));
        assert_eq!(f, round);
        assert_eq!(f.to_json(), round.to_json());
    }

    /// 从 `permission.rs` 源码里抽取所有以 `prefix` 开头的字符串字面量（去重）。
    ///
    /// 用作"权限映射表真值"：`perms` 在 `permission.rs` 中均以 `"<perms>"` 字面量出现。
    fn perms_literals_with_prefix(src: &str, prefix: &str) -> Vec<String> {
        let needle = format!("\"{prefix}");
        let mut out: Vec<String> = Vec::new();
        let mut rest = src;
        while let Some(i) = rest.find(&needle) {
            let tail = &rest[i + 1..];
            if let Some(end) = tail.find('"') {
                let lit = &tail[..end];
                if !out.iter().any(|s| s == lit) {
                    out.push(lit.to_string());
                }
            }
            rest = &tail[..];
        }
        out
    }

    /// 启动治理剔除清单：默认全剔（现状），仅**整前缀全量解锁**的前缀免剔。
    ///
    /// 可证伪性：
    /// - 若把 `platform_only_prefixes_to_strip` 写成"无条件全剔"（忽略能力位），
    ///   第二段断言会因清单长度不符而变红；
    /// - 若白名单**部分**收录某前缀（如漏了 `:remove`）却整前缀免剔，
    ///   最后一段断言会指名报出缺失的 perms。
    #[test]
    fn test_strip_list_only_excludes_fully_unlocked_prefixes() {
        let all = crate::common::tenant::PLATFORM_ONLY_PERM_PREFIXES;

        // ① 默认（全 off）⇒ 剔除清单 == 全部平台专属前缀（= 现状，关闭态即安全态）
        let stripped = platform_only_prefixes_to_strip(&FeatureSet::default());
        assert_eq!(stripped, all.to_vec(), "缺省能力集下必须全量剔除");
        assert!(unlocked_platform_only_prefixes(&FeatureSet::default()).is_empty());

        // ② 开启域名自助 ⇒ 仅 system:tenant:domain: 免剔，其余不动
        let on = FeatureSet::from_json(Some(r#"{"tenant.domain_self_service":"full"}"#));
        let unlocked = unlocked_platform_only_prefixes(&on);
        assert_eq!(unlocked, vec!["system:tenant:domain:"]);
        let stripped = platform_only_prefixes_to_strip(&on);
        assert_eq!(stripped.len(), all.len() - 1);
        assert!(!stripped.contains(&"system:tenant:domain:"));
        for p in all {
            if *p != "system:tenant:domain:" {
                assert!(stripped.contains(p), "{p} 不在解锁白名单内，必须仍被剔除");
            }
        }

        // ③ 整前缀解锁锁：免剔前缀下**全部** perms 必须都在解锁白名单内
        let src = std::fs::read_to_string("src/middleware/permission.rs")
            .expect("src/middleware/permission.rs 应存在");
        let allowed: Vec<String> = CAPABILITY_UNLOCKED_PERMS
            .iter()
            .filter(|(feat, _)| on.is_on(feat))
            .flat_map(|(_, list)| list.iter().map(|p| (*p).to_string()))
            .collect();
        for prefix in all {
            if stripped.contains(prefix) {
                continue;
            }
            let registered = perms_literals_with_prefix(&src, prefix);
            assert!(
                !registered.is_empty(),
                "{prefix} 被整前缀免剔，却在权限映射表中找不到任何 perms"
            );
            for perm in registered {
                assert!(
                    allowed.contains(&perm),
                    "{perm} 未被解锁白名单收录，却因前缀 {prefix} 免剔而整面放开"
                );
            }
        }
    }

    /// 反向锚点：`unlocked_platform_only_prefixes` 只认**开启**的能力位；
    /// 显式 `off` 与未登记能力位都不产生免剔项。
    #[test]
    fn test_strip_list_ignores_off_capabilities() {
        let explicit_off = FeatureSet::from_json(Some(r#"{"tenant.domain_self_service":"off"}"#));
        assert!(unlocked_platform_only_prefixes(&explicit_off).is_empty());
        assert_eq!(
            platform_only_prefixes_to_strip(&explicit_off),
            crate::common::tenant::PLATFORM_ONLY_PERM_PREFIXES.to_vec()
        );
    }
}
