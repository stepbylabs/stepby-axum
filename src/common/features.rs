// stepby-axum/src/common/features.rs
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

/// 关闭态字面量、能力位定义与能力位注册表：统一由**零依赖共享 crate `governance`** 提供。
///
/// 抽离动机：`migration` crate 无法依赖 lib，此前迁移文件只能保留一份「同值本地副本」
/// 并靠注释约束「修改时必须两处同步」——这正是 2026-09-26「裸占位符漏写列名导致治理
/// 静默失效」事故的同一形态。抽到共享 crate 后**复制路径在物理上消失**：`migration`
/// 与本 crate 引用同一份数据。
///
/// 类型与常量名保留原名（`FeatureDef` / `KNOWN_FEATURES` / `FEATURE_OFF`），
/// 既有调用点的字段访问（`key` / `modes` / `default_mode`）无需任何改写。
pub use governance::{FEATURES as KNOWN_FEATURES, Item as FeatureDef, OFF as FEATURE_OFF};

// 能力位在各档解锁的平台专属 perms：**清单已内联进注册表**（`governance::Item::unlocked`），
// 不再维护平行的第二份数据。
//
// 逐条枚举而非按前缀放开仍是**刻意的**：`system:backup:` 是**部分解锁**前缀
// （`list` / `query` / `download` 三条可下放，创建/恢复/删除仍平台专属），若按前缀放开
// 则等于把整库备份面（含恢复覆盖现库）一并下放；`system:tenant:domain:` 则是
// **整前缀全量收录**的特例——同一套逐条语义对两种情形都成立。
//
// 为什么需要「所需最低档位」：三态能力位（`nav.l3` = 导航只读/写面；`backup.visibility`
// = 备份只读/下载面）的**只读面与危险面必须分别解锁**，否则 `view_only` 下会把
// add/edit/remove 菜单（或备份下载）一并授予 role 2，重造"菜单可见但请求 403"的假入口
// （或更糟：把整库下载面下放给普通角色）。故注册表的 `unlocked` 字段保留
// `(所需最低档位, perms 清单)` 语义，由 `unlocked_capability_perms` 消费。
/// **已被开启的能力位解锁的平台专属 perms 逐条清单**（按注册表 `governance::FEATURES` 顺序）。
///
/// 这是「启动治理」（`initialize::ensure_tenant_role_menu_governance`）的**唯一事实源**：
/// - 剔除条件 = 命中平台专属前缀 **且** 不在本清单内；
/// - 回填条件 = 在本清单内（授予平台普通角色 role 2，作新建租户的菜单模板）。
///
/// # 为什么必须是 **perms 粒度**而非前缀粒度
///
/// 批次 1c 的 `system:tenant:domain:` 是"整前缀全量收录"的特例，前缀粒度与 perms 粒度等价；
/// 但批次 2 的 `system:backup:` 是**部分解锁**（只读 3 条 + 导出 1 条可下放，
/// 创建/恢复/删除仍平台专属）。若按前缀粒度"整前缀免剔 + 整前缀回填"，会把
/// 创建备份 / 恢复（覆盖现库）/ 删除 的菜单一并授予 role 2，重新造出
/// "菜单可见但请求一律 403"的假入口。故本函数只吐逐条 perms，调用点均按 perms 匹配。
///
/// # 为什么还要 **档位阈值**
///
/// 三态能力位（`nav.l3 = off | view_only | full`）的只读面与写面必须分别解锁：
/// `view_only` 只解锁 `list`，`full` 才解锁 add/edit/remove。比较依据是注册表
/// `modes` 数组下标（下标越大越开放），与 [`FeatureSet::narrowed_by`] 同一口径。
///
/// 单测 `test_unlocked_perms_are_perm_granular` 锁死"部分解锁前缀不得整前缀放开"，
/// `test_unlocked_perms_respect_mode_threshold` 锁死"档位不足不得解锁"。
pub fn unlocked_capability_perms(features: &FeatureSet) -> Vec<&'static str> {
    let mut out: Vec<&'static str> = Vec::new();
    for def in KNOWN_FEATURES {
        for (required_mode, perms) in def.unlocked {
            if !mode_reaches(features, def.key, required_mode) {
                continue;
            }
            for p in *perms {
                if !out.contains(p) {
                    out.push(p);
                }
            }
        }
    }
    out
}

/// 有效模式是否**至少开放到** `required_mode` 档（同注册表 `modes` 下标比较）。
///
/// 未登记的能力位 / 未登记的档位串一律视为"未达到"（fail-closed）。
///
/// 公开给请求层守卫使用（`middleware::platform_guard` 按档位放行租户操作者）：
/// 三态能力位的**只读面与危险面必须按档区分**，否则 `view_only` 会把下载面一并放行。
pub fn mode_reaches(features: &FeatureSet, key: &str, required_mode: &str) -> bool {
    let Some(def) = feature_def(key) else {
        return false;
    };
    let idx_of = |m: &str| def.modes.iter().position(|x| *x == m);
    match (idx_of(features.mode(key)), idx_of(required_mode)) {
        (Some(cur), Some(need)) => cur >= need,
        _ => false,
    }
}

/// 设计器类能力位（`report.designer` / `flow.designer`，off|view|full 三档）的
/// **写面**档位判定（纯函数，单一事实源——两个 service 共用，禁止各自复制）。
///
/// - `operator_tid == 0`：平台操作者不受能力位限制（平台内部由 role_menu 授权管，
///   与 `nav.l3` 的"平台跳过能力位"同语义）；
/// - 租户操作者仅 `full` 档可写（`view` 只读、`off` 关闭、非法值 fail-closed 拒绝）。
pub fn designer_write_allowed(operator_tid: i64, mode: &str) -> bool {
    operator_tid == 0 || governance::designer_tier_allows_endpoint(mode, true)
}

/// 设计器类能力位的**读面**档位判定（与 [`designer_write_allowed`] 共用 governance 那一把尺）。
///
/// 立案（b89 项 6）：读面原先**没有任何守卫**，于是 `off` 档租户照常能列表/看详情，
/// 而写按钮一律 403——《开关规范》③"禁止只做前端隐藏而不做服务端守卫"的反面形态
/// （这里是"只做了写面守卫、漏了读面"，效果等于能力位在读面上形同虚设）。
/// 取向与注册表那句 `off（默认）：关闭态即安全态` 一致：**off ⇒ 整面拒绝**，
/// `view` 只读放行，非法值 fail-closed。
pub fn designer_read_allowed(operator_tid: i64, mode: &str) -> bool {
    operator_tid == 0 || governance::designer_tier_allows_endpoint(mode, false)
}

/// 某 perms 对应的菜单节点在该能力集下**是否应当从导航里剪除**（纯函数，`getRouters` 消费）。
///
/// 与端点守卫同一把尺（governance 的两个函数），所以"看得见"与"打得通"不可能再分家：
/// `off` ⇒ 整面剪除；`view` ⇒ 只剪写按钮（消除"按钮在、点了 403"）；`full` ⇒ 不剪。
/// 不在任何设计器面内的 perms ⇒ 一律不剪（平台专属面由 `is_grantable_perm_with_features` 管）。
pub fn designer_menu_hidden(perms: &str, features: &FeatureSet) -> bool {
    let Some(key) = governance::designer_capability_for(perms) else {
        return false;
    };
    governance::designer_tier_hides_menu(features.mode(key), perms)
}

/// 构造 `perms NOT IN ($1, $2, …)` 片段（调用方按方言提供占位符；清单为空时返回 `None`）。
///
/// 与 `common::tenant::perms_like_clause` 配对使用：**集中生成，禁止各调用点手拼**——
/// 2026-09-26 的治理事故正是"裸占位符漏写列名"导致 SQL 恒假、治理静默失效。
pub fn perms_not_in_clause<F>(perms: &[&str], ph: F) -> Option<String>
where
    F: Fn(usize) -> String,
{
    if perms.is_empty() {
        return None;
    }
    Some(format!(
        "perms NOT IN ({})",
        (1..=perms.len()).map(ph).collect::<Vec<_>>().join(", ")
    ))
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
                // 未配置 = 跟随平台层
                None => ceiling,
                // 已显式配置 = 走共享注册表的**单一收敛实现**（平台是天花板，租户只能收窄）。
                // fail-closed：无法判定（未登记项 / 无档位 / 两值皆非法）时回落平台值。
                Some(request) => governance::converge(def.key, ceiling, request).unwrap_or(ceiling),
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

// 档位比较（原 `fn mode_rank`）已收敛到共享注册表的 `governance::converge` /
// `governance::mode_rank`（单一实现）——本地不再保留第二套比较逻辑，避免两处口径漂移。

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
/// 1. 命中注册表 `governance::Item::unlocked` 且对应能力位**达到所需档位** ⇒ **可授予**
///    （其服务层必须已按 tid 收窄，见该常量文档）；
/// 2. 平台专属前缀 ⇒ 不可授予；
/// 3. 命中 tier2（表带 `tenant_id` 但集合读路径未接过滤）⇒ 不可授予。
///
/// 传入 [`FeatureSet::default`] 时与旧 `is_grantable_perm` **逐条等价**（全 `off` 即现状），
/// 这保证"开关缺省 = 行为不变"。
pub fn is_grantable_perm_with_features(perms: &str, features: &FeatureSet) -> bool {
    if unlocked_capability_perms(features).contains(&perms) {
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

    /// 设计器类写面档位判定三档矩阵（report.designer / flow.designer 共用）
    #[test]
    fn test_designer_write_allowed_matrix() {
        // 平台操作者（tid=0）不受能力位影响
        for mode in ["off", "view", "full", "bogus", ""] {
            assert!(
                designer_write_allowed(0, mode),
                "平台 tid=0 在 {mode} 档必须放行"
            );
        }
        // 租户操作者：仅 full 可写（view 只读、off/非法 fail-closed）
        assert!(!designer_write_allowed(7, "off"), "off 档写面拒绝");
        assert!(
            !designer_write_allowed(7, "view"),
            "view 档写面拒绝（只读）"
        );
        assert!(designer_write_allowed(7, "full"), "full 档写面放行");
        assert!(!designer_write_allowed(7, "bogus"), "非法档位 fail-closed");
        assert!(!designer_write_allowed(7, ""), "空档位 fail-closed");
    }

    /// 设计器**读面**档位矩阵（b89 项 6 新立：`off` 整面拒绝、`view` 放行、`full` 放行）
    #[test]
    fn test_designer_read_allowed_matrix() {
        for mode in ["off", "view", "full", "bogus", ""] {
            assert!(
                designer_read_allowed(0, mode),
                "平台 tid=0 在 {mode} 档读面必须放行"
            );
        }
        assert!(
            !designer_read_allowed(7, "off"),
            "off 档读面必须拒绝（关闭态 = 功能不存在，不是'只读可用'）"
        );
        assert!(designer_read_allowed(7, "view"), "view 档读面放行");
        assert!(designer_read_allowed(7, "full"), "full 档读面放行");
        assert!(!designer_read_allowed(7, "bogus"), "非法档位 fail-closed");
        assert!(!designer_read_allowed(7, ""), "空档位 fail-closed");
    }

    /// 设计器**菜单可见性**矩阵：可见性与端点必须同一把尺（两侧各写一遍必漂）
    ///
    /// ⚠ 每个用例必须**同时**给另一个设计器能力位显式 `full`。只喂单键是错的尺：
    /// 注册表默认全 off（见 [`test_registry_defaults_are_all_off`]），于是"面外 perms
    /// 不得被剪"那条反证会被**它自己能力位的默认档**剪红——b89 实测红在
    /// `report:dataset:list 不属于 flow.designer 的面`，而前缀表当时是对的。
    /// 反证的作用域由"另一个能力位正开着"构成，否则它约束的是默认值而不是越面剪除。
    #[test]
    fn test_designer_menu_hidden_matches_endpoint_tier() {
        let set = |pairs: [(&str, &str); 2]| {
            FeatureSet::sanitized(
                pairs
                    .iter()
                    .map(|(k, m)| ((*k).to_string(), (*m).to_string())),
            )
        };
        for (key, read_perm, write_perm, other_key, other_perm) in [
            (
                "flow.designer",
                "flow:definition:list",
                "flow:definition:add",
                "report.designer",
                "report:dataset:list",
            ),
            (
                "report.designer",
                "report:dataset:list",
                "report:dataset:edit",
                "flow.designer",
                "flow:definition:list",
            ),
            (
                "report.designer",
                "report:dashboard:view",
                "report:dashboard:publish",
                "flow.designer",
                "flow:definition:add",
            ),
        ] {
            // off ⇒ 整面剪除（读写都剪）
            assert!(
                designer_menu_hidden(read_perm, &set([(key, "off"), (other_key, "full")])),
                "{read_perm} 在 off 档必须剪除（否则就是'菜单可见但端点 403'的假入口）"
            );
            assert!(
                designer_menu_hidden(write_perm, &set([(key, "off"), (other_key, "full")])),
                "{write_perm} 在 off 档必须剪除"
            );
            // view ⇒ 只剪写按钮（消除"按钮在、点了 403"）
            assert!(
                !designer_menu_hidden(read_perm, &set([(key, "view"), (other_key, "full")])),
                "{read_perm} 在 view 档必须可见（读面放行）"
            );
            assert!(
                designer_menu_hidden(write_perm, &set([(key, "view"), (other_key, "full")])),
                "{write_perm} 在 view 档必须剪除（写面 403，不该留着按钮）"
            );
            // full ⇒ 都可见
            assert!(
                !designer_menu_hidden(read_perm, &set([(key, "full"), (other_key, "off")]))
                    && !designer_menu_hidden(write_perm, &set([(key, "full"), (other_key, "off")])),
                "full 档整面可见"
            );
            // 反证：另一个设计器能力位**开着**时，其面内 perms 不得被本能力位越面剪除
            // （前缀表写串就会在这里红）
            assert!(
                !designer_menu_hidden(other_perm, &set([(key, "off"), (other_key, "full")])),
                "{other_perm} 属于 {other_key} 的面；{key} 关档不得越面剪除"
            );
            // 反证的第二向：本能力位开着时，另一面**关档**也不得反向连坐
            assert!(
                !designer_menu_hidden(read_perm, &set([(key, "full"), (other_key, "off")])),
                "{read_perm} 在 {key}=full 且 {other_key}=off 时必须可见（反向越面剪除）"
            );
        }
        // 设计器之外的 perms 一律不剪（平台专属面另有判据，两者正交）
        let off_flow = set([("flow.designer", "off"), ("report.designer", "full")]);
        for perm in [
            "system:user:list",
            "monitor:online:list",
            "tool:reportBoard:save",
        ] {
            assert!(
                !designer_menu_hidden(perm, &off_flow),
                "{perm} 不在任何设计器面内，不得被剪（误剪会把正常功能做成隐形）"
            );
        }
    }

    /// 前缀表自足：每个登记的设计器能力位必须**真在注册表里**且**确有面内 perms**
    /// （登记了却没人用的前缀 = 剪除判据空转；用了没登记的能力位 = 剪不到）
    #[test]
    fn test_designer_prefix_table_is_live() {
        for (key, prefixes) in governance::DESIGNER_CAPABILITY_PERM_PREFIXES {
            let def = feature_def(key).unwrap_or_else(|| panic!("{key} 未登记进注册表"));
            assert!(
                def.modes.contains(&"full") && def.modes.contains(&"view"),
                "{key} 必须是三档设计器能力位（off|view|full），实际 {:?}",
                def.modes
            );
            assert!(
                !prefixes.is_empty(),
                "{key} 的面内前缀为空 ⇒ 剪除判据在这一面上空转"
            );
            for p in *prefixes {
                assert!(
                    p.ends_with(':'),
                    "前缀 {p} 必须以冒号结尾（防半截前缀越面）"
                );
                assert_eq!(
                    governance::designer_capability_for(&format!("{p}list")),
                    Some(*key),
                    "{p}list 必须归属 {key}"
                );
            }
        }
        // 反证：面外 perms 必须判 None（否则剪除会连坐无关菜单）
        assert_eq!(
            governance::designer_capability_for("system:user:list"),
            None
        );
        assert_eq!(governance::designer_capability_for("flow:task:list"), None);
    }

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
            r#"{"nav.l3":"full","not.a.feature":"on","backup.visibility":"bogus","tenant.domain_self_service":"full"}"#,
        ));
        assert_eq!(f.mode("nav.l3"), "full");
        assert_eq!(f.mode("tenant.domain_self_service"), "full");
        assert_eq!(f.mode("not.a.feature"), FEATURE_OFF, "未知 key 不生效");
        assert_eq!(
            f.mode("backup.visibility"),
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
        for def in KNOWN_FEATURES {
            for (required_mode, perms_list) in def.unlocked {
                assert!(
                    def.modes.contains(required_mode),
                    "解锁白名单为 {} 声明了未登记的所需档位 {required_mode}",
                    def.key
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
    }

    /// **档位阈值**：三态能力位的只读面与写面必须分别解锁（批次 3 `nav.l3`）。
    ///
    /// 可证伪性：若 `unlocked_capability_perms` 退回"只看 `is_on`"，第 2 组断言会立即
    /// 变红（`view_only` 把 add/edit/remove 一并解锁 ⇒ 菜单可见但请求 403 的假入口）。
    #[test]
    fn test_unlocked_perms_respect_mode_threshold() {
        // ① off ⇒ 一条都不解锁
        let off = FeatureSet::default();
        assert!(unlocked_capability_perms(&off).is_empty());

        // ② view_only ⇒ 仅 list；写面（add/edit/remove）不得解锁
        let view_only = FeatureSet::from_json(Some(r#"{"nav.l3":"view_only"}"#));
        assert_eq!(
            unlocked_capability_perms(&view_only),
            vec!["system:tenantMenu:list"]
        );
        for p in [
            "system:tenantMenu:add",
            "system:tenantMenu:edit",
            "system:tenantMenu:remove",
        ] {
            assert!(
                !is_grantable_perm_with_features(p, &view_only),
                "view_only 档不得解锁写面 {p}"
            );
        }
        assert!(is_grantable_perm_with_features(
            "system:tenantMenu:list",
            &view_only
        ));

        // ③ full ⇒ 四项全解锁
        let full = FeatureSet::from_json(Some(r#"{"nav.l3":"full"}"#));
        for p in [
            "system:tenantMenu:list",
            "system:tenantMenu:add",
            "system:tenantMenu:edit",
            "system:tenantMenu:remove",
        ] {
            assert!(
                is_grantable_perm_with_features(p, &full),
                "full 档应解锁 {p}"
            );
        }

        // ④ 单档能力位（off|on）的既有语义不受影响
        let export_on = FeatureSet::from_json(Some(r#"{"backup.tenant_self_export":"on"}"#));
        assert_eq!(
            unlocked_capability_perms(&export_on),
            vec!["system:backup:export"]
        );

        // ⑤ `backup.visibility`（批次 4 / MT-7）：只读档与下载档必须分离。
        //
        // 可证伪性：若把 `download` 也放进 `view_only` 档，第 2 组断言立即变红 ——
        // 那等于让平台普通角色（role 2，tid=0 ⇒ 无行级收窄）**下载整库备份**。
        let view_only_ro = FeatureSet::from_json(Some(r#"{"backup.visibility":"view_only"}"#));
        let mut ro = unlocked_capability_perms(&view_only_ro);
        ro.sort_unstable();
        assert_eq!(
            ro,
            vec!["system:backup:list", "system:backup:query"],
            "view_only 档只应解锁只读两项"
        );
        assert!(
            !is_grantable_perm_with_features("system:backup:download", &view_only_ro),
            "view_only 档不得解锁下载（下载即拿到备份文件本体）"
        );
        assert!(
            !is_grantable_perm_with_features("system:backup:edit", &view_only_ro),
            "view_only 档不得解锁恢复（覆盖现库）"
        );

        let full_bak = FeatureSet::from_json(Some(r#"{"backup.visibility":"full"}"#));
        assert!(
            is_grantable_perm_with_features("system:backup:download", &full_bak),
            "full 档才解锁下载"
        );
        assert!(
            !is_grantable_perm_with_features("system:backup:add", &full_bak)
                && !is_grantable_perm_with_features("system:backup:edit", &full_bak)
                && !is_grantable_perm_with_features("system:backup:remove", &full_bak),
            "写面/危险面即使 full 档也不得解锁（创建整库备份 / 恢复覆盖现库 / 删除）"
        );

        // 请求层守卫用的档位比较（`mode_reaches`）与解锁清单同一口径
        assert!(mode_reaches(
            &view_only_ro,
            "backup.visibility",
            "view_only"
        ));
        assert!(!mode_reaches(&view_only_ro, "backup.visibility", "full"));
        assert!(mode_reaches(&full_bak, "backup.visibility", "full"));
        assert!(!mode_reaches(&off, "backup.visibility", "view_only"));
        assert!(!mode_reaches(&off, "not.a.feature", "view_only"));
    }

    /// 能力位开启后仍受**既有**门禁约束：开关不是"万能钥匙"。
    ///
    /// 批次 2 更新：`backup.visibility` 已收录只读两件套 + 下载一件到解锁白名单
    /// （这是能力位的**预期**放开面，由 `test_unlocked_perms_are_perm_granular` 锁定），
    /// 但备份的**写面与危险面**（add/edit=恢复/remove）即使能力位开到 `full` 也不得授予；
    /// 且未登记的能力位（tier2 表在能力位关闭时）恒被拦截。
    #[test]
    fn test_capability_does_not_bypass_existing_gates() {
        let on = FeatureSet::from_json(Some(
            r#"{"tenant.domain_self_service":"full","backup.visibility":"full"}"#,
        ));
        // 备份写面/危险面：即使只读能力位开启也不可授予
        for p in [
            "system:backup:add",
            "system:backup:edit",
            "system:backup:remove",
        ] {
            assert!(
                !is_grantable_perm_with_features(p, &on),
                "{p} 属平台专属写面，能力位不得放开"
            );
        }
        // 只开域名能力位时，备份只读项仍不可授予（能力位互不越界）
        let only_domain = FeatureSet::from_json(Some(r#"{"tenant.domain_self_service":"full"}"#));
        for p in [
            "system:backup:list",
            "system:backup:query",
            "system:backup:download",
            "system:backup:export",
        ] {
            assert!(
                !is_grantable_perm_with_features(p, &only_domain),
                "{p} 未登记在该能力位的解锁白名单内，不得顺带放开"
            );
        }
        // 未登记的能力位（未知 key）恒为 off ⇒ 不产生任何放开
        let unknown = FeatureSet::from_json(Some(r#"{"backup.everything":"on"}"#));
        assert!(unknown.is_default());
        assert!(!is_grantable_perm_with_features(
            "system:backup:list",
            &unknown
        ));
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
        let f = FeatureSet::from_json(Some(r#"{"backup.visibility":"full","nav.l3":"view_only"}"#));
        let round = FeatureSet::from_json(Some(&f.to_json()));
        assert_eq!(f, round);
        assert_eq!(f.to_json(), round.to_json());
    }

    /// 解锁清单必须是 **perms 粒度**：部分解锁的前缀不得整前缀放开。
    ///
    /// 可证伪性：若把 [`unlocked_capability_perms`] 改成"按前缀收集"（返回该前缀下
    /// `permission.rs` 中的**全部** perms），第二段断言会因 `system:backup:add` 等
    /// 混入清单而变红——那等于把创建备份/恢复（覆盖现库）的菜单也授予 role 2。
    #[test]
    fn test_unlocked_perms_are_perm_granular() {
        // ① 默认（全 off）⇒ 无任何解锁项；启动治理 ① 的 `NOT IN` 子句为空（全量剔除）
        let off = FeatureSet::default();
        assert!(unlocked_capability_perms(&off).is_empty());
        assert!(
            perms_not_in_clause(&unlocked_capability_perms(&off), |i| format!("?{i}")).is_none()
        );

        // ② `backup.visibility = full` ⇒ 恰好 3 条（只读 2 + 下载 1），且**不含**写面
        let ro = FeatureSet::from_json(Some(r#"{"backup.visibility":"full"}"#));
        let mut unlocked = unlocked_capability_perms(&ro);
        unlocked.sort_unstable();
        assert_eq!(
            unlocked,
            vec![
                "system:backup:download",
                "system:backup:list",
                "system:backup:query",
            ],
            "备份可见性能力位（full 档）只应解锁只读子集 + 下载"
        );
        // ②' 仅 `view_only` ⇒ 只读 2 条，**不含**下载（MT-7 的核心诉求）
        let view_only = FeatureSet::from_json(Some(r#"{"backup.visibility":"view_only"}"#));
        let mut unlocked_ro = unlocked_capability_perms(&view_only);
        unlocked_ro.sort_unstable();
        assert_eq!(
            unlocked_ro,
            vec!["system:backup:list", "system:backup:query"],
            "view_only 档不得把下载混入解锁清单"
        );
        for p in [
            "system:backup:add",
            "system:backup:edit",
            "system:backup:remove",
        ] {
            assert!(
                !unlocked_capability_perms(&ro).contains(&p),
                "{p} 属写面/危险面，备份可见性能力位不得解锁"
            );
            assert!(
                !is_grantable_perm_with_features(p, &ro),
                "{p} 在备份可见性能力位下仍必须不可授予"
            );
        }
        // 且解锁子集确实可授予
        for p in &unlocked {
            assert!(is_grantable_perm_with_features(p, &ro), "{p} 应可授予");
        }

        // ③ 开自助导出 ⇒ 仅解锁 `system:backup:export`（不含只读/下载各项，二者独立）
        let ex = FeatureSet::from_json(Some(r#"{"backup.tenant_self_export":"on"}"#));
        assert_eq!(unlocked_capability_perms(&ex), vec!["system:backup:export"]);
        assert!(
            !is_grantable_perm_with_features("system:backup:list", &ex),
            "自助导出能力位不得顺带解锁只读列表"
        );

        // ④ 域名能力位（整前缀全量收录的特例）仍解锁 5 条
        let dom = FeatureSet::from_json(Some(r#"{"tenant.domain_self_service":"full"}"#));
        assert_eq!(unlocked_capability_perms(&dom).len(), 5);

        // ⑤ 两者同开 ⇒ 并集且无重复
        let both = FeatureSet::from_json(Some(
            r#"{"backup.visibility":"full","backup.tenant_self_export":"on"}"#,
        ));
        let list = unlocked_capability_perms(&both);
        assert_eq!(list.len(), 4);
        let mut sorted = list.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), 4, "解锁清单不得出现重复项");

        // ⑥ `view_only` + 自助导出 ⇒ 不含下载（三档与单档能力位互不串档）
        let vt = FeatureSet::from_json(Some(
            r#"{"backup.visibility":"view_only","backup.tenant_self_export":"on"}"#,
        ));
        let mut vt_list = unlocked_capability_perms(&vt);
        vt_list.sort_unstable();
        assert_eq!(
            vt_list,
            vec![
                "system:backup:export",
                "system:backup:list",
                "system:backup:query"
            ],
            "view_only + 自助导出不得顺带放开下载"
        );
    }

    /// `perms NOT IN` 片段：集中生成、带列名、占位符按方言编号
    #[test]
    fn test_perms_not_in_clause() {
        assert!(perms_not_in_clause(&[], |_| "?".to_string()).is_none());
        assert_eq!(
            perms_not_in_clause(&["a", "b"], |i| format!("${i}")).as_deref(),
            Some("perms NOT IN ($1, $2)")
        );
    }
}
