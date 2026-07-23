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
//! 要求密码至少包含字母与数字两种字符类型，防止纯数字/纯字母弱口令。

use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};

/// 旧密码方案的固定盐值（仅用于验证旧 MD5 哈希，不用于新密码）
const LEGACY_SALT: &str = "yebot_admin";

/// 密码复杂度校验（R19-1.3）
///
/// 策略（兼容默认 admin/admin123，且能拦截纯数字/纯字母等弱口令）：
/// - 长度 5-20（由 DTO 的 `#[validate(length(...))]` 保证，此处不重复校验）
/// - 必须包含至少 1 个字母（a-z 或 A-Z）
/// - 必须包含至少 1 个数字（0-9）
///
/// 返回 `Ok(())` 表示通过；返回 `Err(String)` 含可向用户展示的错误描述。
///
/// 设计权衡：
/// - 未强制要求大写字母 + 特殊字符，避免与默认管理员口令 `admin123` 冲突
///   （项目记忆约束：登录凭据必须为 admin/admin123）
/// - 如需更严格策略，可在 sys_config 中扩展配置项，此处仅提供基线校验
/// - 校验在最入口处（Service 层 validate 之后）执行，确保所有密码写入路径统一覆盖
pub fn validate_password_complexity(password: &str) -> Result<(), String> {
    let has_letter = password.chars().any(|c| c.is_ascii_alphabetic());
    let has_digit = password.chars().any(|c| c.is_ascii_digit());

    if !has_letter {
        return Err("密码必须包含至少 1 个字母".to_string());
    }
    if !has_digit {
        return Err("密码必须包含至少 1 个数字".to_string());
    }
    Ok(())
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
fn verify_legacy_md5(password: &str, hashed: &str) -> bool {
    use md5::{Digest, Md5};
    let salted = format!("{}{}", password, LEGACY_SALT);
    let mut hasher = Md5::new();
    hasher.update(salted.as_bytes());
    let computed: String = hasher.finalize().iter().map(|b| format!("{:02x}", b)).collect();
    computed == hashed
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
        // 字母 + 数字（兼容默认 admin123）
        assert!(validate_password_complexity("admin123").is_ok());
        // 含大写字母 + 数字
        assert!(validate_password_complexity("Admin123").is_ok());
        // 含特殊字符 + 字母 + 数字
        assert!(validate_password_complexity("Admin@123").is_ok());
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
}
