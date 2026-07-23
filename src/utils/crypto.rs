//! 加密工具模块

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::Engine;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use utoipa::ToSchema;

/// 计算 token 的 SHA-256 哈希（hex 编码），用于黑名单 key 以节省内存
pub fn token_hash(token: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    format!("{:x}", hasher.finalize())
}

// ==================== AES-256-GCM 加解密（用于敏感配置加密存储） ====================

/// 加密值前缀，用于在 sys_config.config_value 中标识该值为加密存储
pub const ENCRYPTED_PREFIX: &str = "enc:";

/// AES-256-GCM nonce 长度（12 字节，标准推荐值）
const NONCE_LEN: usize = 12;

/// 从主密钥（任意长度字符串）派生 32 字节 AES-256 密钥
///
/// 使用 SHA-256 派生：无论主密钥长度如何，都生成固定 32 字节的 AES 密钥。
/// 这样配置中的 CONFIG_ENC_KEY 可以是任意长度字符串（建议 ≥32 字符）。
fn derive_aes_key(master_key: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(master_key.as_bytes());
    let result = hasher.finalize();
    let mut key = [0u8; 32];
    key.copy_from_slice(&result);
    key
}

/// 加密敏感配置值
///
/// 使用 AES-256-GCM 加密，输出格式：`enc:base64(nonce || ciphertext || tag)`
///
/// # 参数
/// - `plaintext`：明文
/// - `master_key`：主密钥（任意长度，建议 ≥32 字符）
///
/// # 返回
/// 加密后的字符串（带 `enc:` 前缀），失败返回 anyhow::Error
pub fn encrypt_config_value(plaintext: &str, master_key: &str) -> anyhow::Result<String> {
    let key = derive_aes_key(master_key);
    let cipher = Aes256Gcm::new(&key.into());

    // 生成随机 12 字节 nonce
    let mut nonce_bytes = [0u8; NONCE_LEN];
    use rand::RngCore;
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    // P3-7：aes-gcm 0.10 的 Nonce::from_slice 内部调用 generic_array::GenericArray::from_slice，
    // 该 API 在 generic-array 0.14.7+ 被标记为 deprecated。Nonce::from_slice 仍是 aes-gcm 推荐用法，
    // 升级到 aes-gcm 新 major 版本前用 #[allow(deprecated)] 抑制上游警告。
    #[allow(deprecated)]
    let nonce = Nonce::from_slice(&nonce_bytes);

    // 加密（AES-GCM 自动附加认证标签 tag）
    let ciphertext = cipher
        .encrypt(nonce, plaintext.as_bytes())
        .map_err(|e| anyhow::anyhow!("AES-GCM 加密失败: {}", e))?;

    // 拼接 nonce + ciphertext（含 tag），Base64 编码
    let mut combined = Vec::with_capacity(NONCE_LEN + ciphertext.len());
    combined.extend_from_slice(&nonce_bytes);
    combined.extend_from_slice(&ciphertext);

    let b64 = base64::engine::general_purpose::STANDARD.encode(&combined);
    Ok(format!("{}{}", ENCRYPTED_PREFIX, b64))
}

/// 解密敏感配置值
///
/// 输入应为 `encrypt_config_value` 的输出（带 `enc:` 前缀）。
/// 若输入不包含前缀，则视为明文直接返回（兼容旧数据）。
///
/// # 参数
/// - `stored_value`：存储的值（可能带 `enc:` 前缀，也可能为明文）
/// - `master_key`：主密钥
///
/// # 返回
/// 解密后的明文，失败返回 anyhow::Error
pub fn decrypt_config_value(stored_value: &str, master_key: &str) -> anyhow::Result<String> {
    // 不带前缀视为明文，直接返回（兼容性）
    if !stored_value.starts_with(ENCRYPTED_PREFIX) {
        return Ok(stored_value.to_string());
    }

    let b64 = &stored_value[ENCRYPTED_PREFIX.len()..];
    let combined = base64::engine::general_purpose::STANDARD
        .decode(b64)
        .map_err(|e| anyhow::anyhow!("Base64 解码失败: {}", e))?;

    if combined.len() < NONCE_LEN {
        anyhow::bail!("加密数据长度不足，无法提取 nonce");
    }

    let (nonce_bytes, ciphertext) = combined.split_at(NONCE_LEN);
    // P3-7：同上，Nonce::from_slice 上游 deprecation 警告，待 aes-gcm 新版本解决
    #[allow(deprecated)]
    let nonce = Nonce::from_slice(nonce_bytes);

    let key = derive_aes_key(master_key);
    let cipher = Aes256Gcm::new(&key.into());

    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| anyhow::anyhow!("AES-GCM 解密失败（密钥错误或数据损坏）: {}", e))?;

    String::from_utf8(plaintext).map_err(|e| anyhow::anyhow!("解密后非 UTF-8: {}", e))
}

/// 判断存储值是否为加密格式（带 `enc:` 前缀）
pub fn is_encrypted(stored_value: &str) -> bool {
    stored_value.starts_with(ENCRYPTED_PREFIX)
}

#[cfg(test)]
mod crypto_tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let master_key = "test-master-key-for-aes-256-gcm-encryption";
        let plaintext = "my-secret-license-key-ABC123";
        let encrypted = encrypt_config_value(plaintext, master_key).unwrap();
        assert!(encrypted.starts_with(ENCRYPTED_PREFIX));
        assert_ne!(encrypted, plaintext);
        let decrypted = decrypt_config_value(&encrypted, master_key).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_decrypt_plaintext_compatibility() {
        // 不带前缀的明文应直接返回（兼容旧数据）
        let master_key = "any-key";
        let plaintext = "plain-value";
        let result = decrypt_config_value(plaintext, master_key).unwrap();
        assert_eq!(result, plaintext);
    }

    #[test]
    fn test_wrong_key_fails() {
        let master_key = "correct-key";
        let wrong_key = "wrong-key";
        let plaintext = "secret";
        let encrypted = encrypt_config_value(plaintext, master_key).unwrap();
        let result = decrypt_config_value(&encrypted, wrong_key);
        assert!(result.is_err(), "错误密钥应解密失败");
    }

    #[test]
    fn test_different_encryptions_differ() {
        // 同一明文每次加密结果不同（因 nonce 随机）
        let master_key = "key";
        let plaintext = "same";
        let e1 = encrypt_config_value(plaintext, master_key).unwrap();
        let e2 = encrypt_config_value(plaintext, master_key).unwrap();
        assert_ne!(e1, e2);
        // 但都能解密为同一明文
        assert_eq!(decrypt_config_value(&e1, master_key).unwrap(), plaintext);
        assert_eq!(decrypt_config_value(&e2, master_key).unwrap(), plaintext);
    }

    #[test]
    fn test_is_encrypted() {
        assert!(is_encrypted("enc:abc123"));
        assert!(!is_encrypted("plain"));
        assert!(!is_encrypted(""));
    }
}

/// 在线会话信息（P1-19 方案 B：存储于 Redis `online:{token_hash}`）
///
/// 登录时由 `auth_service::finalize_login` 写入，登出/强退时删除。
/// 替代旧的 `online:{info_id}` → token 方案，解决：
/// - logout 未 DEL online key 导致用户登出后仍显示在线 30 分钟
/// - 30 分钟硬窗口与 JWT 24h 有效期不一致
///
/// JSON 序列化后存入 Redis，list 接口 SCAN + MGET 直接解析，无需查 sys_logininfor 表。
///
/// 字段兼容性：`dept_name` 为 v2.9 新增字段，使用 `#[serde(default)]` 保证旧版本写入的
/// JSON 在反序列化时填默认空字符串，避免旧会话因字段缺失反序列化失败。
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct OnlineSession {
    /// 用户 ID
    pub user_id: i64,
    /// 用户名
    pub username: String,
    /// 登录 IP
    pub ip: String,
    /// 登录时间（`%Y-%m-%d %H:%M:%S` 格式）
    pub login_time: String,
    /// 浏览器类型
    pub browser: String,
    /// 操作系统
    pub os: String,
    /// JWT 唯一 ID（关联 JWT claims.jti）
    pub jti: String,
    /// 部门名称（v2.9 新增，旧 JSON 反序列化时默认空字符串）
    #[serde(default)]
    pub dept_name: String,
}
