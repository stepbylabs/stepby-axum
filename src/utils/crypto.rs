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

/// 加密值前缀（v1，无盐 SHA256 派生），用于标识该值为加密存储
///
/// v1 为历史格式，仅用于解密既有数据，新加密统一使用 [`ENCRYPTED_PREFIX_V2`]。
pub const ENCRYPTED_PREFIX: &str = "enc:";

/// 加密值前缀（v2，PBKDF2-HMAC-SHA256 + 随机盐派生）
///
/// 格式：`enc2:<base64(salt[16] || nonce[12] || ciphertext)>`
pub const ENCRYPTED_PREFIX_V2: &str = "enc2:";

/// AES-256-GCM nonce 长度（12 字节，标准推荐值）
const NONCE_LEN: usize = 12;

/// v2 KDF 盐长度（16 字节）
const SALT_LEN: usize = 16;

/// v2 PBKDF2 迭代次数（HMAC-SHA256）
///
/// 主密钥已强制 ≥32 字符（settings::validate_secrets），高熵前提下 5 万次迭代
/// 即可对低熵场景提供充足防御，同时保持每次解密延迟在可接受范围（数十毫秒）。
const PBKDF2_ITERATIONS: u32 = 50_000;

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

/// v2 密钥派生：PBKDF2-HMAC-SHA256（带随机盐 + 工作因子）
///
/// 替代 v1 的无盐 SHA256（无盐 → 相同主密钥派生结果恒定，且无法抵御低熵密钥离线爆破）。
/// v2 将随机盐与 nonce 一并写入密文信封，派生结果对每个明文/每次加密都不同。
///
/// 使用 `pbkdf2` crate 的泛型 `pbkdf2::<Hmac<Sha256>>` 函数（无需启用 `simple` 特性），
/// 输出 32 字节即 AES-256 密钥。
fn derive_aes_key_v2(master_key: &str, salt: &[u8]) -> [u8; 32] {
    use hmac::Hmac;
    use sha2::Sha256;
    type HmacSha256 = Hmac<Sha256>;
    let mut key = [0u8; 32];
    pbkdf2::pbkdf2::<HmacSha256>(master_key.as_bytes(), salt, PBKDF2_ITERATIONS, &mut key)
        .expect("PBKDF2 密钥派生失败");
    key
}

/// 加密敏感配置值（v2 信封）
///
/// 使用 AES-256-GCM 加密，输出格式：`enc2:<base64(salt[16] || nonce[12] || ciphertext)>`
///
/// 其中 `salt` 为随机 16 字节，参与 PBKDF2-HMAC-SHA256 密钥派生；`nonce` 为随机 12 字节。
/// 每次加密的 salt/nonce 均独立随机，因此即使相同明文 + 相同主密钥，密文也互不相同，
/// 可抵御针对低熵主密钥的离线字典爆破（v1 无盐，相同密钥派生结果恒定，存在此风险）。
///
/// 历史 v1 数据（`enc:` 前缀）仍可被 [`decrypt_config_value`] 解密，但新加密统一使用 v2。
///
/// # 参数
/// - `plaintext`：明文
/// - `master_key`：主密钥（任意长度，建议 ≥32 字符）
///
/// # 返回
/// 加密后的字符串（带 `enc2:` 前缀），失败返回 anyhow::Error
/// v5-E6：敏感列写入口（幂等）。
///
/// - `CONFIG_ENC_KEY` 未配置 → 原样明文（迁移期 fail-open，与 id_token_secret 策略一致）
/// - 值已带 `enc2:`/`enc:` 前缀 → 原样返回（**防双重加密**：出参明文回显→前端回传→重复 seal）
/// - 其余 → 信封加密（失败返回 Err，调用方 fail-closed 拒绝写入）
pub fn seal_sensitive_value(plaintext: &str, master_key: &str) -> anyhow::Result<String> {
    if master_key.is_empty() || plaintext.is_empty() {
        return Ok(plaintext.to_string());
    }
    if plaintext.starts_with(ENCRYPTED_PREFIX) || plaintext.starts_with(ENCRYPTED_PREFIX_V2) {
        return Ok(plaintext.to_string());
    }
    encrypt_config_value(plaintext, master_key)
}

/// v5-E6：敏感列读出口。解密失败（密钥不匹配/数据损坏）时**原样返回存储值**并记日志——
/// 读路径宽松化：密文回显给授权管理员优于整列表 500；明文旧数据（回填前）原样通过。
pub fn unseal_sensitive_value(stored: &str, master_key: &str) -> String {
    if stored.is_empty() {
        return String::new();
    }
    decrypt_config_value(stored, master_key).unwrap_or_else(|e| {
        tracing::error!(
            "敏感值解密失败（原样返回存储值，请检查启动回填与 CONFIG_ENC_KEY）: {}",
            e
        );
        stored.to_string()
    })
}

pub fn encrypt_config_value(plaintext: &str, master_key: &str) -> anyhow::Result<String> {
    // 生成随机盐与 nonce
    let mut salt = [0u8; SALT_LEN];
    let mut nonce_bytes = [0u8; NONCE_LEN];
    use rand::RngCore;
    let mut rng = rand::thread_rng();
    rng.fill_bytes(&mut salt);
    rng.fill_bytes(&mut nonce_bytes);
    // P3-7：aes-gcm 0.10 的 Nonce::from_slice 内部调用 generic_array::GenericArray::from_slice，
    // 该 API 在 generic-array 0.14.7+ 被标记为 deprecated。Nonce::from_slice 仍是 aes-gcm 推荐用法，
    // 升级到 aes-gcm 新 major 版本前用 #[allow(deprecated)] 抑制上游警告。
    #[allow(deprecated)]
    let nonce = Nonce::from_slice(&nonce_bytes);

    let key = derive_aes_key_v2(master_key, &salt);
    let cipher = Aes256Gcm::new(&key.into());

    // 加密（AES-GCM 自动附加认证标签 tag）
    let ciphertext = cipher
        .encrypt(nonce, plaintext.as_bytes())
        .map_err(|e| anyhow::anyhow!("AES-GCM 加密失败: {}", e))?;

    // 拼接 salt + nonce + ciphertext（含 tag），Base64 编码
    let mut combined = Vec::with_capacity(SALT_LEN + NONCE_LEN + ciphertext.len());
    combined.extend_from_slice(&salt);
    combined.extend_from_slice(&nonce_bytes);
    combined.extend_from_slice(&ciphertext);

    let b64 = base64::engine::general_purpose::STANDARD.encode(&combined);
    Ok(format!("{}{}", ENCRYPTED_PREFIX_V2, b64))
}

/// 解密敏感配置值
///
/// 输入前缀决定解析方式：
/// - `enc2:`：v2 信封（`salt[16] || nonce[12] || ciphertext`），使用 PBKDF2 派生的密钥解密
/// - `enc:`：v1 信封（`nonce[12] || ciphertext`），使用无盐 SHA256 派生的密钥解密（历史数据兼容）
/// - 无前缀：视为明文直接返回（兼容未加密的旧数据）
///
/// # 参数
/// - `stored_value`：存储的值（可能带 `enc2:` / `enc:` 前缀，也可能为明文）
/// - `master_key`：主密钥
///
/// # 返回
/// 解密后的明文，失败返回 anyhow::Error
pub fn decrypt_config_value(stored_value: &str, master_key: &str) -> anyhow::Result<String> {
    // 不带任何加密前缀视为明文（兼容旧数据）
    if !stored_value.starts_with(ENCRYPTED_PREFIX) && !stored_value.starts_with(ENCRYPTED_PREFIX_V2)
    {
        // P2 收口（fail-closed）：仅当系统未配置加密密钥时允许明文路径（旧数据兼容）；
        // 密钥已配置时无前缀值视为存储异常（敏感项未加密/被篡改），拒绝返回
        if master_key.is_empty() {
            return Ok(stored_value.to_string());
        }
        anyhow::bail!("敏感值未加密存储（缺少 enc:/enc2: 前缀），拒绝解密");
    }

    // v2 信封（enc2:）：salt[16] || nonce[12] || ciphertext
    if let Some(b64) = stored_value.strip_prefix(ENCRYPTED_PREFIX_V2) {
        let combined = base64::engine::general_purpose::STANDARD
            .decode(b64)
            .map_err(|e| anyhow::anyhow!("Base64 解码失败: {}", e))?;
        if combined.len() < SALT_LEN + NONCE_LEN {
            anyhow::bail!("加密数据长度不足，无法提取 salt/nonce");
        }
        let (salt, rest) = combined.split_at(SALT_LEN);
        let (nonce_bytes, ciphertext) = rest.split_at(NONCE_LEN);
        // P3-7：Nonce::from_slice 上游 deprecation 警告，待 aes-gcm 新版本解决
        #[allow(deprecated)]
        let nonce = Nonce::from_slice(nonce_bytes);

        let key = derive_aes_key_v2(master_key, salt);
        let cipher = Aes256Gcm::new(&key.into());

        let plaintext = cipher
            .decrypt(nonce, ciphertext)
            .map_err(|e| anyhow::anyhow!("AES-GCM 解密失败（密钥错误或数据损坏）: {}", e))?;

        return String::from_utf8(plaintext).map_err(|e| anyhow::anyhow!("解密后非 UTF-8: {}", e));
    }

    // v1 信封（enc:，历史数据兼容）：nonce[12] || ciphertext
    if let Some(b64) = stored_value.strip_prefix(ENCRYPTED_PREFIX) {
        let combined = base64::engine::general_purpose::STANDARD
            .decode(b64)
            .map_err(|e| anyhow::anyhow!("Base64 解码失败: {}", e))?;
        if combined.len() < NONCE_LEN {
            anyhow::bail!("加密数据长度不足，无法提取 nonce");
        }
        let (nonce_bytes, ciphertext) = combined.split_at(NONCE_LEN);
        // P3-7：同上，Nonce::from_slice 上游 deprecation 警告
        #[allow(deprecated)]
        let nonce = Nonce::from_slice(nonce_bytes);

        let key = derive_aes_key(master_key);
        let cipher = Aes256Gcm::new(&key.into());

        let plaintext = cipher
            .decrypt(nonce, ciphertext)
            .map_err(|e| anyhow::anyhow!("AES-GCM 解密失败（密钥错误或数据损坏）: {}", e))?;

        return String::from_utf8(plaintext).map_err(|e| anyhow::anyhow!("解密后非 UTF-8: {}", e));
    }

    // 前缀不匹配（理论上不可达，前面已排除非加密前缀）
    anyhow::bail!("未知的加密前缀")
}

/// 判断存储值是否为加密格式（带 `enc:` 或 `enc2:` 前缀）
pub fn is_encrypted(stored_value: &str) -> bool {
    stored_value.starts_with(ENCRYPTED_PREFIX) || stored_value.starts_with(ENCRYPTED_PREFIX_V2)
}

#[cfg(test)]
mod crypto_tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_roundtrip_v2() {
        let master_key = "test-master-key-for-aes-256-gcm-encryption";
        let plaintext = "my-secret-license-key-ABC123";
        let encrypted = encrypt_config_value(plaintext, master_key).unwrap();
        // 新加密统一使用 v2 信封
        assert!(encrypted.starts_with(ENCRYPTED_PREFIX_V2));
        assert_ne!(encrypted, plaintext);
        let decrypted = decrypt_config_value(&encrypted, master_key).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    /// 构造一个 v1 信封（enc:），用于验证 decrypt_config_value 的向后兼容路径
    fn encrypt_v1(plaintext: &str, master_key: &str) -> String {
        use rand::RngCore;
        let key = derive_aes_key(master_key);
        let cipher = Aes256Gcm::new(&key.into());
        let mut nonce_bytes = [0u8; NONCE_LEN];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        #[allow(deprecated)]
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ciphertext = cipher.encrypt(nonce, plaintext.as_bytes()).unwrap();
        let mut combined = Vec::with_capacity(NONCE_LEN + ciphertext.len());
        combined.extend_from_slice(&nonce_bytes);
        combined.extend_from_slice(&ciphertext);
        format!(
            "{}{}",
            ENCRYPTED_PREFIX,
            base64::engine::general_purpose::STANDARD.encode(&combined)
        )
    }

    #[test]
    fn test_v1_legacy_decrypt_compat() {
        // 历史 v1 数据（enc: 前缀，无盐 SHA256 派生）必须仍可被解密
        let master_key = "test-master-key-for-aes-256-gcm-encryption";
        let plaintext = "legacy-secret-value-XYZ";
        let v1 = encrypt_v1(plaintext, master_key);
        assert!(v1.starts_with(ENCRYPTED_PREFIX));
        assert!(!v1.starts_with(ENCRYPTED_PREFIX_V2));
        let decrypted = decrypt_config_value(&v1, master_key).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_v2_and_v1_distinct_prefixes() {
        let master_key = "test-master-key-for-aes-256-gcm-encryption";
        let v1 = encrypt_v1("same-plain", master_key);
        let v2 = encrypt_config_value("same-plain", master_key).unwrap();
        assert_ne!(v1, v2);
        assert!(v1.starts_with(ENCRYPTED_PREFIX));
        assert!(v2.starts_with(ENCRYPTED_PREFIX_V2));
        assert_eq!(decrypt_config_value(&v1, master_key).unwrap(), "same-plain");
        assert_eq!(decrypt_config_value(&v2, master_key).unwrap(), "same-plain");
    }

    #[test]
    fn test_is_encrypted_v2() {
        assert!(is_encrypted("enc:abc123"));
        assert!(is_encrypted("enc2:abc123"));
        assert!(!is_encrypted("plain"));
        assert!(!is_encrypted(""));
    }

    #[test]
    fn test_decrypt_plaintext_compatibility() {
        // 未配置密钥时，不带前缀的明文直接返回（兼容旧数据）
        let plaintext = "plain-value";
        let result = decrypt_config_value(plaintext, "").unwrap();
        assert_eq!(result, plaintext);
    }

    #[test]
    fn test_decrypt_plaintext_fail_closed_when_key_configured() {
        // P2：密钥已配置时，无前缀敏感值必须拒绝（fail-closed），防止明文绕过加密存储
        let result = decrypt_config_value("plain-value", "any-key");
        assert!(result.is_err(), "密钥已配置时明文路径应被拒绝");
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

    // M-3：OnlineSession exp 字段序列化/反序列化兼容性测试

    #[test]
    fn test_online_session_exp_serialization() {
        // 新会话：exp > 0（JWT 实际过期时间戳）
        let session = OnlineSession {
            user_id: 1,
            username: "admin".to_string(),
            ip: "127.0.0.1".to_string(),
            login_time: "2026-07-31 12:00:00".to_string(),
            browser: "Chrome".to_string(),
            os: "Windows".to_string(),
            jti: "test-jti".to_string(),
            dept_name: "研发部".to_string(),
            source: "login".to_string(),
            exp: 1800000000,
            tenant_id: 0,
        };
        let json = serde_json::to_string(&session).unwrap();
        assert!(json.contains("\"exp\":1800000000"));
        // 反序列化回来 exp 保持一致
        let deserialized: OnlineSession = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.exp, 1800000000);
    }

    #[test]
    fn test_online_session_legacy_json_without_exp() {
        // 旧 JSON（v2.13 前，无 exp 字段）反序列化时 exp 应默认为 0
        let legacy_json = r#"{
            "user_id": 2,
            "username": "ry",
            "ip": "192.168.1.1",
            "login_time": "2026-07-30 10:00:00",
            "browser": "Firefox",
            "os": "Linux",
            "jti": "old-jti",
            "dept_name": "测试部"
        }"#;
        let session: OnlineSession = serde_json::from_str(legacy_json).unwrap();
        assert_eq!(session.exp, 0, "旧 JSON 反序列化时 exp 应默认为 0");
        assert_eq!(session.username, "ry");
        assert_eq!(session.dept_name, "测试部");
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
    /// JWT 过期时间戳（UTC 秒，v2.13 新增用于 force_logout 精确计算黑名单 TTL）
    /// 旧 JSON 反序列化时默认 0，force_logout 时回退到 jwt.expire_hours 保守上界
    #[serde(default)]
    pub exp: i64,
    /// 令牌来源（v4-F2 新增）：`login` = 平台登录会话（缺省），`sso` = SSO Provider 签发的
    /// 不透明 access_token。旧 JSON 反序列化时默认 `login`，在线列表/强退据此区分展示与清理。
    #[serde(default)]
    pub source: String,
    /// 所属租户 ID（Phase 3 新增，`0` = 平台租户）。在线用户域按租户分层展示与
    /// 定向踢线（租户停用/删除/到期）依赖此字段；旧 JSON 反序列化时默认 0，
    /// 踢线侧对 0 值按 `user_id` 回查 `sys_user.tenant_id` 兜底。
    #[serde(default)]
    pub tenant_id: i64,
}
