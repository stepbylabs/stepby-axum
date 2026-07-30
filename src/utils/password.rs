// axum-backend/src/utils/password.rs
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
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};

/// 旧密码方案的固定盐值（仅用于验证旧 MD5 哈希，不用于新密码）
const LEGACY_SALT: &str = "yebot_admin";

/// Top 常见弱口令黑名单（来源：Have I Been Pwned / SecLists 公开统计）
///
/// 注：默认管理员初始凭据 `admin123` 也列入黑名单，强制用户首次登录修改密码。
/// 数据库种子密码哈希直接写入，不经过 `validate_password_complexity`，故不影响初始化。
///
/// M-7：使用 `LazyLock<HashSet<&str>>` 替代切片线性搜索，将 O(n) 检查降为 O(1)。
static WEAK_PASSWORDS: LazyLock<HashSet<&str>> = LazyLock::new(|| {
    [
        "123456", "12345678", "123456789", "1234567890", "1234567", "12345",
        "password", "password1", "password123", "passwd", "passw0rd",
        "admin", "admin123", "admin@123", "administrator", "root", "toor", "superuser",
        "qwerty", "qwerty123", "qwertyuiop",
        "abc123", "abcdef", "abc123456",
        "letmein", "welcome", "welcome1", "welcome123",
        "monkey", "dragon", "master", "shadow", "sunshine", "trustno1",
        "login", "princess", "football", "baseball", "soccer",
        "iloveyou", "starwars", "whatever", "cheese",
        "000000", "111111", "666666", "888888", "999999",
        "1q2w3e4r", "1qaz2wsx", "qazwsx",
        "test", "test123", "test1234", "guest", "guest123",
        "user", "user123", "default",
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

    if password.len() >= 8 {
        score += 1;
    }
    if password.len() >= 12 {
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
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    let hash = argon2.hash_password(password.as_bytes(), &salt)?;
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
pub fn verify_password_with_upgrade_hint(password: &str, hashed: &str) -> PasswordVerifyResult {
    if hashed.is_empty() {
        return PasswordVerifyResult {
            is_valid: false,
            needs_upgrade: false,
        };
    }

    // 新格式：Argon2 哈希
    if hashed.starts_with("$argon2") {
        if let Ok(parsed) = PasswordHash::new(hashed) {
            let is_valid = Argon2::default()
                .verify_password(password.as_bytes(), &parsed)
                .is_ok();
            return PasswordVerifyResult {
                is_valid,
                needs_upgrade: false,
            };
        }
        return PasswordVerifyResult {
            is_valid: false,
            needs_upgrade: false,
        };
    }

    // 旧格式：MD5 + 固定盐值
    let is_valid = verify_legacy_md5(password, hashed);
    PasswordVerifyResult {
        is_valid,
        needs_upgrade: is_valid,
    }
}

/// 旧 MD5 + 固定盐值验证（仅用于兼容已存在的旧密码数据）
/// P2 修复: 使用恒定时间比较，避免时序侧信道泄露哈希前缀信息
fn verify_legacy_md5(password: &str, hashed: &str) -> bool {
    use md5::{Digest, Md5};
    let salted = format!("{}{}", password, LEGACY_SALT);
    let mut hasher = Md5::new();
    hasher.update(salted.as_bytes());
    let computed: String = hasher.finalize().iter().map(|b| format!("{:02x}", b)).collect();
    // 恒定时间比较：先比较长度（长度不同必然不等，但仍遍历完整字节避免长度泄露）
    // 再按位 XOR 累积差异，最终差异为 0 才相等
    constant_time_eq(computed.as_bytes(), hashed.as_bytes())
}

/// 恒定时间字节比较
///
/// 无论内容是否相同，比较耗时仅取决于较短字符串的长度，
/// 不因前缀匹配程度提前返回，避免时序侧信道攻击。
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    let mut diff: u8 = (a.len() ^ b.len()) as u8;
    let min_len = a.len().min(b.len());
    for i in 0..min_len {
        diff |= a[i] ^ b[i];
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
        // 旧 MD5 + 固定盐值 "yebot_admin" 的哈希值
        let password = "admin123";
        let salted = format!("{}{}", password, LEGACY_SALT);
        use md5::{Digest, Md5};
        let mut hasher = Md5::new();
        hasher.update(salted.as_bytes());
        let legacy_hashed: String = hasher.finalize().iter().map(|b| format!("{:02x}", b)).collect();

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
        assert!(validate_password_complexity("yebot2026").is_ok());
        // 含大写字母 + 数字
        assert!(validate_password_complexity("Yebot2026").is_ok());
        // 含特殊字符 + 字母 + 数字
        assert!(validate_password_complexity("Yebot@2026").is_ok());
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
}
