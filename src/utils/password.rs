// stepby-axum/src/utils/password.rs
//! 密码加密与验证工具
//!
//! 使用 Argon2id 算法（2024 年密码哈希竞赛推荐），每用户独立随机盐。
//!
//! 迁移兼容：支持验证旧 MD5 + 固定盐值哈希（升级前已存在的用户密码）。
//! 旧哈希格式：32 位 hex（MD5 摘要）
//! 新哈希格式：Argon2 标准编码字符串（以 `$argon2` 开头）
//!
//! 验证流程：
//! 1. 若 hashed 以 `$argon2` 开头 → 用 Argon2 验证
//! 2. 否则 → 用旧 MD5 + 固定盐值验证，验证成功后调用方应升级为新哈希
//!
//! R19-1.3 密码复杂度策略：
//! `validate_password_complexity` 在新增/重置/修改密码时强制校验，
//! 要求密码至少包含字母与数字两种字符类型，防止纯数字/纯字母弱口令，
//! 并拦截 Top 常见弱口令字典（如 123456、admin123、password 等）。

use std::collections::HashSet;
use std::sync::LazyLock;

use argon2::{
    Algorithm, Argon2, Params, Version,
    password_hash::{PasswordHasher, PasswordVerifier, phc::PasswordHash},
};

// ==================== Argon2id 参数（批七十四 B6：**显式声明**）====================
//
// 为什么不能继续 `Argon2::default()`：默认值由**依赖**决定，不由本仓决定。
// argon2 0.6 的 `Params::default()` 恰好是 RFC 9106 的推荐档（m=19456KiB / t=2 / p=1），
// 而 PHC 编码串会把参数**写进哈希本身**——这意味着将来某次升级把默认值调低时，
// 新写的哈希变弱、旧哈希照常验证通过、单测照常绿、日志零信号：**静默降级**。
// 显式之后：① 参数是本仓的常量，改动必须过 PR；② 新哈希前缀会随常量一起变，
// `argon2_new_hashes_carry_the_explicit_params` 当场红；③ 默认值漂移由
// `explicit_params_equal_current_crate_defaults` 抓住（它钉的是"改造前后行为等价"）。
//
// 取值 = 改造前 `Argon2::default()` 的实际值 ⇒ **默认值 = 现状**，存量哈希一律仍可验证。
pub const ARGON2_ALGORITHM: Algorithm = Algorithm::Argon2id;
pub const ARGON2_VERSION: Version = Version::V0x13;
pub const ARGON2_M_COST_KIB: u32 = 19_456;
pub const ARGON2_T_COST: u32 = 2;
pub const ARGON2_P_COST: u32 = 1;

// 下限用**编译期**钳住而非测试运行期断言：常量被调低时构建即失败，不必等到有人跑到
// 那条单测（弱档一旦合入，新写入的每个口令哈希都低强度，且降级是静默的——PHC 前缀
// 会跟着变，看起来"参数在生效"）。取值口径同 AGENTS B.6 的结构性不变式。
const _: () = assert!(
    ARGON2_M_COST_KIB >= 8 * 1024,
    "m_cost 低于 8 MiB 不满足 OWASP Argon2id 下限"
);
const _: () = assert!(
    ARGON2_T_COST >= 2,
    "t_cost 低于 2 轮不满足 OWASP Argon2id 下限"
);
const _: () = assert!(ARGON2_P_COST >= 1, "p_cost 必须至少为 1");

/// 建参（唯一实现点：加密与验证都必须经此，禁止在别处再 `Argon2::new`/`::default`）
///
/// `Params::new` 的 Err 分支只在常量本身非法时出现，由
/// `tests::explicit_params_are_valid` 转成确定性红灯（而不是运行到登录才 panic）。
fn argon2_inst() -> Argon2<'static> {
    let params = Params::new(ARGON2_M_COST_KIB, ARGON2_T_COST, ARGON2_P_COST, None)
        .expect("Argon2 显式参数必须合法（见 tests::explicit_params_are_valid）");
    Argon2::new(ARGON2_ALGORITHM, ARGON2_VERSION, params)
}

/// 旧密码方案的固定盐值（仅用于验证旧 MD5 哈希，不用于新密码）
const LEGACY_SALT: &str = "stepby_admin";

/// Top 常见弱口令黑名单（来源：Have I Been Pwned / SecLists 公开统计）
///
/// 注：默认管理员初始凭据 `admin123` 也列入黑名单，强制用户首次登录修改密码。
/// 数据库种子密码哈希直接写入，不经过 `validate_password_complexity`，故不影响初始化。
///
/// M-7：使用 `LazyLock<HashSet<&str>>` 替代切片线性搜索，将 O(n) 检查降为 O(1)。
static WEAK_PASSWORDS: LazyLock<HashSet<&str>> = LazyLock::new(|| {
    [
        "123456",
        "12345678",
        "123456789",
        "1234567890",
        "1234567",
        "12345",
        "password",
        "password1",
        "password123",
        "passwd",
        "passw0rd",
        "admin",
        "admin123",
        "admin@123",
        "administrator",
        "root",
        "toor",
        "superuser",
        "qwerty",
        "qwerty123",
        "qwertyuiop",
        "abc123",
        "abcdef",
        "abc123456",
        "letmein",
        "welcome",
        "welcome1",
        "welcome123",
        "monkey",
        "dragon",
        "master",
        "shadow",
        "sunshine",
        "trustno1",
        "login",
        "princess",
        "football",
        "baseball",
        "soccer",
        "iloveyou",
        "starwars",
        "whatever",
        "cheese",
        "000000",
        "111111",
        "666666",
        "888888",
        "999999",
        "1q2w3e4r",
        "1qaz2wsx",
        "qazwsx",
        "test",
        "test123",
        "test1234",
        "guest",
        "guest123",
        "user",
        "user123",
        "default",
    ]
    .iter()
    .copied()
    .collect()
});

/// 密码复杂度校验（R19-1.3）
///
/// 策略：
/// - 必须包含至少 1 个字母（a-z 或 A-Z）
/// - 必须包含至少 1 个数字（0-9）
/// - 不得命中常见弱口令黑名单（大小写不敏感）
/// - 长度范围由 DTO 的 `#[garde(length(...))]` 保证
///
/// 返回 `Ok(())` 表示通过；返回 `Err(String)` 含可向用户展示的错误描述。
///
/// 设计权衡：
/// - 未强制要求大写字母 + 特殊字符，避免与旧用户口令冲突过度
/// - 弱口令黑名单覆盖 Top 50+ 常见弱密码，有效阻止撞库攻击
/// - 默认管理员 `admin123` 凭据在数据库种子阶段直接写入哈希，无需通过本函数
pub fn validate_password_complexity(password: &str) -> Result<(), String> {
    let has_letter = password.chars().any(|c| c.is_ascii_alphabetic());
    let has_digit = password.chars().any(|c| c.is_ascii_digit());

    if !has_letter {
        return Err(crate::tr!("error.password.complexity_letter"));
    }
    if !has_digit {
        return Err(crate::tr!("error.password.complexity_digit"));
    }

    // 弱口令黑名单检查（大小写不敏感）
    let lower = password.to_lowercase();
    if WEAK_PASSWORDS.contains(&lower.as_str()) || WEAK_PASSWORDS.contains(password) {
        return Err(crate::tr!("error.password.complexity_common"));
    }

    Ok(())
}

/// 密码强度评分（0-4，供前端 UX 反馈使用）
///
/// 评分规则：
/// - 长度 ≥8 +1，≥12 再 +1
/// - 字符种类：小写/大写/数字/特殊 四类中 2 类 +1，3 类以上 +1
///
/// 评分含义：
/// - 0-1: 弱（建议修改）
/// - 2: 一般
/// - 3: 较强
/// - 4: 强
pub fn password_strength_score(password: &str) -> u8 {
    let mut score: u8 = 0;

    if password.len() >= crate::common::constants::PASSWORD_LEN_MIN {
        score += 1;
    }
    if password.len() >= crate::common::constants::PASSWORD_LEN_STRONG {
        score += 1;
    }

    let has_lower = password.chars().any(|c| c.is_ascii_lowercase());
    let has_upper = password.chars().any(|c| c.is_ascii_uppercase());
    let has_digit = password.chars().any(|c| c.is_ascii_digit());
    let has_special = password.chars().any(|c| !c.is_ascii_alphanumeric());
    let variety: u8 = [has_lower, has_upper, has_digit, has_special]
        .iter()
        .filter(|b| **b)
        .count() as u8;
    if variety >= 2 {
        score += 1;
    }
    if variety >= 3 {
        score += 1;
    }

    score.min(4)
}

/// 加密密码（Argon2id + 随机盐）
///
/// 返回 Result 而非静默吞错，避免哈希失败时存入空密码。
pub fn encrypt_password(password: &str) -> Result<String, argon2::password_hash::Error> {
    // argon2 0.6：hash_password 单参（内部自动生成随机盐）
    let argon2 = argon2_inst();
    let hash = argon2.hash_password(password.as_bytes())?;
    Ok(hash.to_string())
}

/// 验证密码
///
/// 支持 Argon2 和旧 MD5 两种哈希格式（自动识别）。
/// 返回 `PasswordVerifyResult` 让调用方知道是否需要升级哈希。
pub fn verify_password(password: &str, hashed: &str) -> bool {
    verify_password_with_upgrade_hint(password, hashed).is_valid
}

/// 密码验证结果（含是否需要升级哈希的提示）
#[derive(Debug)]
pub struct PasswordVerifyResult {
    pub is_valid: bool,
    /// 若为 true，表示密码正确但使用的是旧 MD5 哈希，调用方应重新加密并存储
    pub needs_upgrade: bool,
}

impl PasswordVerifyResult {
    pub fn is_valid(&self) -> bool {
        self.is_valid
    }
}

/// 验证密码并返回是否需要升级哈希
///
/// **指标出口只有一条**：内部 `verify_inner` 只决定结局，本函数统一记一次耗时/结局。
/// 原实现有 4 个 `return`，若在每个分支手写计数，新增分支时必漏一条
/// （AGENTS #4 对多出口函数要求 RAII/单点记录，这里是同一形状的"单点包装"）。
pub fn verify_password_with_upgrade_hint(password: &str, hashed: &str) -> PasswordVerifyResult {
    let started = std::time::Instant::now();
    let inner = verify_inner(password, hashed);
    crate::observability::metrics::MetricsRegistry::global().record_credential_verify(
        inner.algorithm,
        inner.outcome,
        started.elapsed().as_secs_f64(),
    );
    PasswordVerifyResult {
        is_valid: inner.is_valid,
        needs_upgrade: inner.needs_upgrade,
    }
}

/// 校验结局的内部视图：结果 + 归因标签（`algorithm` 按**故障面**分桶，见 metrics B6 注释）
struct VerifyInner {
    is_valid: bool,
    needs_upgrade: bool,
    algorithm: &'static str,
    outcome: &'static str,
}

fn verify_inner(password: &str, hashed: &str) -> VerifyInner {
    if hashed.is_empty() {
        return VerifyInner {
            is_valid: false,
            needs_upgrade: false,
            algorithm: "unknown",
            outcome: "empty_hash",
        };
    }

    // 新格式：Argon2 哈希
    if hashed.starts_with("$argon2") {
        if let Ok(parsed) = PasswordHash::new(hashed) {
            let is_valid = argon2_inst()
                .verify_password(password.as_bytes(), &parsed)
                .is_ok();
            return VerifyInner {
                is_valid,
                needs_upgrade: false,
                algorithm: "argon2id",
                outcome: if is_valid { "ok" } else { "mismatch" },
            };
        }
        // 以 `$argon2` 开头却解析不了 = 存储侧数据被截断/污染（不是"密码错"，
        // 混进 mismatch 会让"暴力尝试升高"这条告警看不见它）
        return VerifyInner {
            is_valid: false,
            needs_upgrade: false,
            algorithm: "argon2id",
            outcome: "malformed_hash",
        };
    }

    // 旧格式：MD5 + 固定盐值
    let is_valid = verify_legacy_md5(password, hashed);
    VerifyInner {
        is_valid,
        needs_upgrade: is_valid,
        algorithm: "md5-legacy",
        outcome: if is_valid { "ok" } else { "mismatch" },
    }
}

/// 旧 MD5 + 固定盐值验证（仅用于兼容已存在的旧密码数据）
/// P2 修复: 使用恒定时间比较，避免时序侧信道泄露哈希前缀信息
fn verify_legacy_md5(password: &str, hashed: &str) -> bool {
    use md5::{Digest, Md5};
    let salted = format!("{}{}", password, LEGACY_SALT);
    let mut hasher = Md5::new();
    hasher.update(salted.as_bytes());
    let computed: String = hasher
        .finalize()
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect();
    // 恒定时间比较：先比较长度（长度不同必然不等，但仍遍历完整字节避免长度泄露）
    // 再按位 XOR 累积差异，最终差异为 0 才相等
    constant_time_eq(computed.as_bytes(), hashed.as_bytes())
}

/// 恒定时间字节比较
///
/// 无论内容是否相同，比较耗时仅取决于较短字符串的长度，
/// 不因前缀匹配程度提前返回，避免时序侧信道攻击。
///
/// P2 修复：原实现 `(a.len() ^ b.len()) as u8` 将长度差截断到 8 位，
/// 当长度差为 256 的倍数时（如 32 字节 vs 288 字节）diff 初始为 0，
/// 理论上长度不同但前缀相同的两串会被判等。现改为 usize 累积差异，
/// 并遍历两侧全部字节（长度差计入 diff），彻底消除该缺陷。
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    let mut diff: usize = a.len() ^ b.len();
    // 遍历较长一侧的全部字节：多出部分与 0 异或，确保耗时与较长长度一致，
    // 且长度差完整计入 diff（usize 不会截断）
    let max_len = a.len().max(b.len());
    for i in 0..max_len {
        let x = a.get(i).copied().unwrap_or(0);
        let y = b.get(i).copied().unwrap_or(0);
        diff |= (x ^ y) as usize;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_and_verify_argon2() {
        let password = "admin123";
        let hashed = encrypt_password(password).expect("密码加密失败");
        assert!(!hashed.is_empty());
        assert!(hashed.starts_with("$argon2"));
        assert!(verify_password(password, &hashed));
        assert!(!verify_password("wrong", &hashed));
    }

    #[test]
    fn test_verify_legacy_md5() {
        // 旧 MD5 + 固定盐值 "stepby_admin" 的哈希值
        let password = "admin123";
        let salted = format!("{}{}", password, LEGACY_SALT);
        use md5::{Digest, Md5};
        let mut hasher = Md5::new();
        hasher.update(salted.as_bytes());
        let legacy_hashed: String = hasher
            .finalize()
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect();

        // 验证旧哈希能通过
        assert!(verify_password(password, &legacy_hashed));

        // 验证升级提示
        let result = verify_password_with_upgrade_hint(password, &legacy_hashed);
        assert!(result.is_valid);
        assert!(result.needs_upgrade);
    }

    #[test]
    fn test_verify_empty_hash() {
        assert!(!verify_password("test", ""));
    }

    #[test]
    fn test_password_complexity_valid() {
        // 字母 + 数字 + 不在黑名单
        assert!(validate_password_complexity("stepby2026").is_ok());
        // 含大写字母 + 数字
        assert!(validate_password_complexity("Stepby2026").is_ok());
        // 含特殊字符 + 字母 + 数字
        assert!(validate_password_complexity("Stepby@2026").is_ok());
    }

    #[test]
    fn test_password_complexity_missing_letter() {
        // 纯数字：缺字母
        let err = validate_password_complexity("123456").unwrap_err();
        assert!(err.contains("字母"));
    }

    #[test]
    fn test_password_complexity_missing_digit() {
        // 纯字母：缺数字
        let err = validate_password_complexity("abcdefg").unwrap_err();
        assert!(err.contains("数字"));
    }

    #[test]
    fn test_password_complexity_weak_blacklist() {
        // admin123 现在被黑名单拦截（数据库种子直接写入哈希，不通过此函数）
        let err = validate_password_complexity("admin123").unwrap_err();
        assert!(err.contains("常见"));
        let err = validate_password_complexity("Admin123").unwrap_err();
        assert!(err.contains("常见"));
        let err = validate_password_complexity("password").unwrap_err();
        // password 没有数字，会先报"必须包含数字"
        assert!(err.contains("数字"));
        let err = validate_password_complexity("password1").unwrap_err();
        assert!(err.contains("常见"));
    }

    #[test]
    fn test_password_strength_score() {
        assert_eq!(password_strength_score(""), 0);
        assert_eq!(password_strength_score("abc"), 0);
        assert_eq!(password_strength_score("abcdefgh"), 1); // 长度>=8
        assert_eq!(password_strength_score("abcdefg1"), 2); // 长度>=8 + 2类
        assert_eq!(password_strength_score("Abcdefg1"), 3); // 长度>=8 + 3类
        assert_eq!(password_strength_score("Abcdefg1@"), 3); // 长度>=8(9字符) + 4类=3（饱和前2分）
        assert_eq!(password_strength_score("Abcdefghijk1@"), 4); // 长度>=12(13字符) + 4类 = 4
    }

    // ==================== 批七十四 B6：Argon2 参数显式化 + 校验成本可观测 ====================

    /// ① 显式常量必须**等于改造前 `Argon2::default()` 的实际值**（"默认值 = 现状"的唯一证明）。
    ///
    /// 锁的方向很重要：不是"钉死 19456"，而是"钉住本次改造不改变现状"。将来依赖把默认档
    /// 调低 ⇒ 本条红 ⇒ 强制一次显式决策，而不是让强度悄悄漂走。
    #[test]
    fn explicit_params_equal_current_crate_defaults() {
        let d = Params::default();
        assert_eq!(
            ARGON2_M_COST_KIB,
            d.m_cost(),
            "m_cost 与依赖默认值不一致 ⇒ 本批改造已改变存量强度档"
        );
        assert_eq!(ARGON2_T_COST, d.t_cost(), "t_cost 漂移");
        assert_eq!(ARGON2_P_COST, d.p_cost(), "p_cost 漂移");
        assert_eq!(
            ARGON2_VERSION,
            Version::default(),
            "Version 漂移（V0x13 是 argon2 0.6 唯一写进 PHC 串的版本）"
        );
        assert_eq!(ARGON2_ALGORITHM, Algorithm::default(), "算法漂移");
    }

    /// ② 新写的哈希必须把**显式参数**带在 PHC 前缀里（参数真的在生效，不是只写在常量里）
    #[test]
    fn argon2_new_hashes_carry_the_explicit_params() {
        let hashed = encrypt_password("A1b2c3d4").expect("加密应成功");
        let want = format!(
            "$argon2id$v=19$m={},t={},p={}$",
            ARGON2_M_COST_KIB, ARGON2_T_COST, ARGON2_P_COST
        );
        assert!(
            hashed.starts_with(&want),
            "新哈希前缀应为 {want}…，实际 {hashed}"
        );
        // 常量本身不得低于公认下限由文件头的 `const _: () = assert!(…)` **编译期**钳住；
        // 此处只钉"前缀里真的有这些参数"（否则弱档常量也能对上同一前缀，但那是构建期就红的事）。
    }

    /// ③ 参数合法：把 `argon2_inst()` 的 `expect` 变成确定性红灯，而不是登录时才炸
    #[test]
    fn explicit_params_are_valid() {
        assert!(
            Params::new(ARGON2_M_COST_KIB, ARGON2_T_COST, ARGON2_P_COST, None).is_ok(),
            "显式参数必须能被 argon2 接受"
        );
        let _ = argon2_inst();
    }

    /// ④ 存量兼容：用**依赖默认参数**产出的哈希，改造后的入口必须照常验得过（零行为变更）
    #[test]
    fn default_param_hashes_still_verify_after_explicit_params() {
        let pwd = "Legacy123";
        let legacy = Argon2::default()
            .hash_password(pwd.as_bytes())
            .expect("默认参数加密应成功")
            .to_string();
        assert!(
            verify_password(pwd, &legacy),
            "显式参数改造后无法验证默认参数产出的哈希 ⇒ 存量用户会被锁死"
        );
        assert!(!verify_password("Wrong123", &legacy));
    }

    /// ⑤ 可观测半边：四条结局路径逐例归因正确，且统一入口真的把这一族写进了 /metrics
    ///
    /// `outcome` 必须区分"密码错"与"数据坏"：把 malformed 混进 mismatch，
    /// 暴力尝试升高的告警就看不见存储被截断这类事故（同 C.9 的"按故障面分桶"口径）。
    #[test]
    fn credential_verify_metrics_cover_all_outcome_paths() {
        let good = encrypt_password("Bench12345").expect("加密应成功");
        let cases: [(&str, &str, (&str, &str)); 5] = [
            ("Bench12345", "", ("unknown", "empty_hash")),
            (
                "Bench12345",
                // 非 base64 的盐/摘要段：`PasswordHash::new` 直接 Err（存储被截断/污染的形状）
                "$argon2id$v=19$m=19456,t=2,p=1$@@bad@@$@@bad@@",
                ("argon2id", "malformed_hash"),
            ),
            ("Bench12345", good.as_str(), ("argon2id", "ok")),
            ("Wrong12345", good.as_str(), ("argon2id", "mismatch")),
            (
                "x",
                "d41d8cd98f00b204e9800998ecf8427e",
                ("md5-legacy", "mismatch"),
            ),
        ];
        for (pwd, hashed, want) in cases {
            let inner = verify_inner(pwd, hashed);
            assert_eq!(
                (inner.algorithm, inner.outcome),
                want,
                "结局归因漂移：hashed={hashed:?}"
            );
        }
        // 接线证明（"写了没接线=没写"）：真调用一次统一入口后，渲染文本里必须出现这一族
        let pwd = "Bench12345";
        assert!(verify_password(pwd, &good));
        let text = crate::observability::metrics::MetricsRegistry::global().render_prometheus();
        assert!(
            text.contains("# TYPE stepby_credential_verify_total counter"),
            "/metrics 未渲染凭据校验计数族"
        );
        assert!(
            text.contains("# TYPE stepby_credential_verify_duration_seconds histogram"),
            "/metrics 未渲染凭据校验耗时族"
        );
        assert!(
            text.contains("stepby_credential_verify_total{algorithm=\"argon2id\",outcome=\"ok\"}"),
            "成功路径未按 argon2id/ok 归因: {text}"
        );
    }
}
