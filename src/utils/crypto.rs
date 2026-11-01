//! 加密工具模块

use std::sync::OnceLock;

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
    hex_encode_digest(&hasher.finalize())
}

// ==================== AES-256-GCM 加解密（用于敏感配置加密存储） ====================

/// 加密值前缀（v1，无盐 SHA256 派生），用于标识该值为加密存储
///
/// v1 为历史格式，仅用于解密既有数据，新加密统一使用 [`ENCRYPTED_PREFIX_V3`]。
pub const ENCRYPTED_PREFIX: &str = "enc:";

/// 加密值前缀（v2，PBKDF2-HMAC-SHA256 + 随机盐派生）
///
/// 格式：`enc2:<base64(salt[16] || nonce[12] || ciphertext)>`
pub const ENCRYPTED_PREFIX_V2: &str = "enc2:";

/// 加密值前缀（v3，G-14 密钥轮换：在 v2 信封上增加 key_id 段）
///
/// 格式：`enc3:<key_id>:<base64(salt[16] || nonce[12] || ciphertext)>`
///
/// key_id → 密钥的映射约定：
/// - `k1`：当前主密钥（`CONFIG_ENC_KEY`），**新写入恒用 k1**；
/// - `k0`：轮换过渡期旧密钥（`CONFIG_ENC_KEY_PREVIOUS`，可选），仅用于解密存量。
///
/// 轮换流程（零停机）：① 设 PREVIOUS=旧值、KEY=新值 → 启动（读侧 k0/k1 均可解）→
/// ② 启动回填（v5-E6）把 `enc:`/`enc2:`/`enc3:k0` 存量统一 re-encrypt 为 `enc3:k1`
/// → ③ 数据全部迁移后清空 PREVIOUS 重启。与 SSO client_secret 双密钥轮换
/// （`previous_client_secret_hash`）同一套"双密钥读取期"方法论。
pub const ENCRYPTED_PREFIX_V3: &str = "enc3:";

/// 当前主密钥的 key_id（新写入恒用）
pub const CURRENT_KEY_ID: &str = "k1";
/// 轮换过渡期旧密钥的 key_id
pub const PREVIOUS_KEY_ID: &str = "k0";

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
/// - 入参为空串 → 原样返回（空值无需加密，属永久正常态，不参与"待自愈"统计）
/// - `CONFIG_ENC_KEY` 未配置 → 原样明文（迁移期 fail-open，与 id_token_secret 策略一致；
///   **配好密钥后可由启动回填补上**，因此这一支与上一支的整改动作不同，必须分开可观测）
/// - 值已带 `enc3:`/`enc2:`/`enc:` 前缀 → 原样返回（**防双重加密**：出参明文回显→前端回传→重复 seal；
///   格式升级（enc2:→enc3:）由启动回填 [`crate::initialize`] 专职负责，seal 保持纯幂等）
/// - 其余 → 信封加密（enc3:k1，失败返回 Err，调用方**无法**在上层拒绝（`Into<Value>` 由
///   sea-orm 内部调用，没有失败通道），结局见 [`crate::common::encrypted_value::SealOutcome::Degraded`]）
pub fn seal_sensitive_value(plaintext: &str, master_key: &str) -> anyhow::Result<String> {
    // 三种"原样返回"的**原因不同、整改动作也不同**，因此逐条分支而不是一条 `||`：
    // 空值本来就无需加密（永久正常态）；密钥缺失是配置缺位（配好密钥后由 v5-E6 回填自愈）；
    // 已带前缀是幂等（防双重加密）。折叠成一个 `if` 时，调用点只能看见"出参等于入参"，
    // 于是"这条永远不用管"和"这条是因为没配密钥才明文"在观测面上同形（b149 项 17）。
    if plaintext.is_empty() {
        return Ok(plaintext.to_string());
    }
    if master_key.is_empty() {
        return Ok(plaintext.to_string());
    }
    if is_encrypted(plaintext) {
        return Ok(plaintext.to_string());
    }
    encrypt_config_value(plaintext, master_key)
}

/// v5-E6：敏感列读出口。解密失败（密钥不匹配/数据损坏）时**原样返回存储值**并记日志——
/// 读路径宽松化：密文回显给授权管理员优于整列表 500；明文旧数据（回填前）原样通过。
///
/// "明文旧数据"必须在**进解密器之前**分流：旧写法对它照样调 `decrypt_config_value`，
/// 于是读一条历史明文就产生一条 `敏感值解密失败` ERROR——每次读、每行都打，
/// 把真正需要人动手的"带信封却解不开（密钥轮换未登记旧 key_id / 数据损坏）"淹成噪声
/// （AGENTS C.9 的失败归属：返回的串两型相同，日志与计数必须不同）。
/// 返回值语义不变（两型都原样返回 `stored`），只是不再为"本来就不是密文"报错。
pub fn unseal_sensitive_value(stored: &str, master_key: &str) -> String {
    if stored.is_empty() {
        return String::new();
    }
    if !is_encrypted(stored) {
        return stored.to_string();
    }
    decrypt_config_value(stored, master_key).unwrap_or_else(|e| {
        tracing::error!(
            "敏感值解密失败（带信封前缀但解不开，原样返回存储值；请检查 CONFIG_ENC_KEY 与 \
             key_id 是否仍在轮换表内）: {}",
            e
        );
        stored.to_string()
    })
}

/// 加密敏感配置值（G-14：v3 信封，`enc3:k1:<base64(salt[16] || nonce[12] || ciphertext)>`）
///
/// 信封密文段与 v2 完全一致（PBKDF2-HMAC-SHA256 派生 + AES-256-GCM），仅新增 key_id 段
/// 支撑零停机密钥轮换（见 [`ENCRYPTED_PREFIX_V3`] 文档）。salt/nonce 每次独立随机，
/// 相同明文 + 相同主密钥的密文互不相同。
///
/// 历史 v1（`enc:`）/ v2（`enc2:`）数据仍可被 [`decrypt_config_value`] 解密，
/// 新加密统一 v3。签名与 v2 时期保持不变（调用点零改动，格式无缝升级）。
pub fn encrypt_config_value(plaintext: &str, master_key: &str) -> anyhow::Result<String> {
    encrypt_config_value_with_key_id(plaintext, master_key, CURRENT_KEY_ID)
}

/// 按 key_id 加密（v3 信封内核；供启动回填 re-encrypt 与测试使用）
fn encrypt_config_value_with_key_id(
    plaintext: &str,
    master_key: &str,
    key_id: &str,
) -> anyhow::Result<String> {
    // 生成随机盐与 nonce
    let mut salt = [0u8; SALT_LEN];
    let mut nonce_bytes = [0u8; NONCE_LEN];
    use rand::RngCore;
    // OsRng：加密安全 OS RNG（rand 0.9；ThreadRng 在 0.9 也是 CryptoRng，但 OsRng 语义更直白）
    let mut rng = rand::rngs::OsRng;
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
    Ok(format!("{}{}:{}", ENCRYPTED_PREFIX_V3, key_id, b64))
}

/// sha2 0.11 的 finalize() 返回 Array<u8, N>（无 LowerHex），统一 hex 编码辅助
pub fn hex_encode_digest(digest: &[u8]) -> String {
    let mut hex = String::with_capacity(digest.len() * 2);
    for b in digest {
        use std::fmt::Write as _;
        let _ = write!(hex, "{:02x}", b);
    }
    hex
}

// ==================== 运行时主密钥（G-14 通用层：EncryptedString 列类型的密钥源） ====================

/// 运行时主密钥（进程级 OnceLock；AppInitializer 启动时注入 settings.config_enc_key）
static RUNTIME_MASTER_KEY: OnceLock<String> = OnceLock::new();

/// 注入运行时主密钥（启动期调用一次；重复调用为 no-op，首写优先）
pub fn set_runtime_master_key(key: String) {
    let _ = RUNTIME_MASTER_KEY.set(key);
}

/// 读取运行时主密钥（EncryptedString 列类型的 seal/unseal 密钥源）
///
/// 未初始化返回空串——seal/unseal 走既有迁移期 fail-open 策略（原样明文），
/// 与 CONFIG_ENC_KEY 未配置时的全局口径一致；启动回填（v5-E6）兜底存量明文。
pub fn runtime_master_key() -> &'static str {
    RUNTIME_MASTER_KEY.get().map(String::as_str).unwrap_or("")
}

/// 轮换过渡期旧密钥（进程级 OnceLock；AppInitializer 启动时注入
/// `settings.config_enc_key_previous`）
///
/// 批八十五 项 D 收口（台账 N-37 同类）：这里**原先**是 `std::env::var("CONFIG_ENC_KEY_PREVIOUS")`，
/// 于是"配置文件里写的 `config_enc_key_previous`"永远不会参与解密——Settings 侧有字段、
/// 有强度校验（`validate_secrets`）、有环境变量覆盖，唯独消费点只看 env。那正是本仓反复立案的
/// "配了但没生效"形态（两个读取口，其中一个静默无效）。
/// 现在与 `config_enc_key` 同构：**env 只是 Settings 的注入口，不是第二事实源**。
static RUNTIME_PREVIOUS_KEY: OnceLock<String> = OnceLock::new();

/// 注入轮换过渡期旧密钥（启动期调用一次；首写优先，与 [`set_runtime_master_key`] 同口径）。
///
/// 空串**不写入**：空 = "没有轮换期"，必须保持 [`runtime_previous_key`] 返回 `None`
/// 的既有语义（`enc3:k0` 存量在无旧密钥时解密失败并给出可指引的错误）。
pub fn set_runtime_previous_key(key: String) {
    if key.is_empty() {
        return;
    }
    let _ = RUNTIME_PREVIOUS_KEY.set(key);
}

/// 读取轮换过渡期旧密钥（未注入 ⇒ `None`）
pub fn runtime_previous_key() -> Option<&'static str> {
    RUNTIME_PREVIOUS_KEY.get().map(String::as_str)
}

/// 解密敏感配置值（轮换旧密钥自动取启动注入值，见 [`runtime_previous_key`]）
///
/// 见 [`decrypt_config_value_with_previous`]；本函数为常规入口。
pub fn decrypt_config_value(stored_value: &str, master_key: &str) -> anyhow::Result<String> {
    decrypt_config_value_with_previous(stored_value, master_key, runtime_previous_key())
}

/// 解密敏感配置值（显式注入轮换旧密钥——测试友好，避免 env 并行污染）
///
/// 输入前缀决定解析方式：
/// - `enc3:k1`：v3 信封（当前主密钥），`enc3:k0`：v3 信封（`previous` 提供的
///   轮换过渡期旧密钥，`None` 则失败）；密文段格式与 v2 相同
/// - `enc2:`：v2 信封（`salt[16] || nonce[12] || ciphertext`），使用 PBKDF2 派生的密钥解密
/// - `enc:`：v1 信封（`nonce[12] || ciphertext`），使用无盐 SHA256 派生的密钥解密（历史数据兼容）
/// - 无前缀：视为明文直接返回（兼容未加密的旧数据）
///
/// # 参数
/// - `stored_value`：存储的值（可能带 `enc3:` / `enc2:` / `enc:` 前缀，也可能为明文）
/// - `master_key`：当前主密钥
/// - `previous`：轮换过渡期旧密钥（`enc3:k0` 解密用；生产路径传 [`runtime_previous_key`]，
///   即启动期从 Settings 注入的那一把）
///
/// # 返回
/// 解密后的明文，失败返回 anyhow::Error
pub fn decrypt_config_value_with_previous(
    stored_value: &str,
    master_key: &str,
    previous: Option<&str>,
) -> anyhow::Result<String> {
    // 不带任何加密前缀视为明文（兼容旧数据）
    if !is_encrypted(stored_value) {
        // P2 收口（fail-closed）：仅当系统未配置加密密钥时允许明文路径（旧数据兼容）；
        // 密钥已配置时无前缀值视为存储异常（敏感项未加密/被篡改），拒绝返回
        if master_key.is_empty() {
            return Ok(stored_value.to_string());
        }
        anyhow::bail!("敏感值未加密存储（缺少 enc:/enc2:/enc3: 前缀），拒绝解密");
    }

    // v3 信封（enc3:<key_id>:payload）：按 key_id 选择密钥后走 v2 密文段解析
    if let Some(rest) = stored_value.strip_prefix(ENCRYPTED_PREFIX_V3) {
        let (key_id, b64) = rest
            .split_once(':')
            .ok_or_else(|| anyhow::anyhow!("v3 信封缺少 key_id 段"))?;
        let envelope_master_key = match key_id {
            CURRENT_KEY_ID => master_key,
            PREVIOUS_KEY_ID => previous.ok_or_else(|| {
                anyhow::anyhow!(
                    "v3 信封 key_id={PREVIOUS_KEY_ID}（轮换过渡期旧密钥），\
                     但旧密钥未配置，无法解密——请恢复 config_enc_key_previous \
                     （或环境变量 CONFIG_ENC_KEY_PREVIOUS）后重启"
                )
            })?,
            other => anyhow::bail!("未知的 v3 key_id: {other}"),
        };
        return decrypt_v2_payload(b64, envelope_master_key);
    }

    // v2 信封（enc2:）：salt[16] || nonce[12] || ciphertext
    if let Some(b64) = stored_value.strip_prefix(ENCRYPTED_PREFIX_V2) {
        return decrypt_v2_payload(b64, master_key);
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

/// v2/v3 共用的密文段解析（`base64(salt[16] || nonce[12] || ciphertext)`）
fn decrypt_v2_payload(b64: &str, master_key: &str) -> anyhow::Result<String> {
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

    String::from_utf8(plaintext).map_err(|e| anyhow::anyhow!("解密后非 UTF-8: {}", e))
}

/// 判断存储值是否为加密格式（带 `enc:` / `enc2:` / `enc3:` 前缀）
pub fn is_encrypted(stored_value: &str) -> bool {
    stored_value.starts_with(ENCRYPTED_PREFIX)
        || stored_value.starts_with(ENCRYPTED_PREFIX_V2)
        || stored_value.starts_with(ENCRYPTED_PREFIX_V3)
}

#[cfg(test)]
mod crypto_tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_roundtrip_v3() {
        let master_key = "test-master-key-for-aes-256-gcm-encryption";
        let plaintext = "my-secret-license-key-ABC123";
        let encrypted = encrypt_config_value(plaintext, master_key).unwrap();
        // G-14：新加密统一使用 v3 信封（enc3:k1:）
        assert!(encrypted.starts_with(ENCRYPTED_PREFIX_V3));
        assert!(encrypted.starts_with(&format!("{ENCRYPTED_PREFIX_V3}{CURRENT_KEY_ID}:")));
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
        rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);
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
    fn test_v3_v2_v1_distinct_prefixes() {
        let master_key = "test-master-key-for-aes-256-gcm-encryption";
        let v1 = encrypt_v1("same-plain", master_key);
        let v2 = encrypt_v2("same-plain", master_key);
        let v3 = encrypt_config_value("same-plain", master_key).unwrap();
        assert_ne!(v1, v2);
        assert_ne!(v2, v3);
        assert!(v1.starts_with(ENCRYPTED_PREFIX));
        assert!(v2.starts_with(ENCRYPTED_PREFIX_V2));
        assert!(v3.starts_with(ENCRYPTED_PREFIX_V3));
        // 三代格式同密钥下均可解密（G-14 存量兼容不变量）
        assert_eq!(decrypt_config_value(&v1, master_key).unwrap(), "same-plain");
        assert_eq!(decrypt_config_value(&v2, master_key).unwrap(), "same-plain");
        assert_eq!(decrypt_config_value(&v3, master_key).unwrap(), "same-plain");
    }

    /// 构造一个 v2 信封（enc2:，G-14 前的历史格式），用于验证存量兼容路径
    fn encrypt_v2(plaintext: &str, master_key: &str) -> String {
        use rand::RngCore;
        let mut salt = [0u8; SALT_LEN];
        let mut nonce_bytes = [0u8; NONCE_LEN];
        rand::rngs::OsRng.fill_bytes(&mut salt);
        rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);
        #[allow(deprecated)]
        let nonce = Nonce::from_slice(&nonce_bytes);
        let key = derive_aes_key_v2(master_key, &salt);
        let cipher = Aes256Gcm::new(&key.into());
        let ciphertext = cipher.encrypt(nonce, plaintext.as_bytes()).unwrap();
        let mut combined = Vec::with_capacity(SALT_LEN + NONCE_LEN + ciphertext.len());
        combined.extend_from_slice(&salt);
        combined.extend_from_slice(&nonce_bytes);
        combined.extend_from_slice(&ciphertext);
        format!(
            "{}{}",
            ENCRYPTED_PREFIX_V2,
            base64::engine::general_purpose::STANDARD.encode(&combined)
        )
    }

    /// G-14：enc3:k0（轮换过渡期旧密钥）解密路径——previous 注入可解，
    /// 未注入（未配置 CONFIG_ENC_KEY_PREVIOUS 的生产语义）时报错且可指引。
    /// k0 信封手工拼装（v3 密文段与 v2 完全一致，仅前缀/key_id 不同），不经 env（并行安全）。
    #[test]
    fn test_v3_previous_key_rotation() {
        let current = "current-master-key-for-rotation-test";
        let previous = "previous-master-key-for-rotation";
        let plaintext = "rotated-away-secret";

        // k1 roundtrip（当前密钥）
        let sealed_current = encrypt_config_value(plaintext, current).unwrap();
        assert!(decrypt_config_value(&sealed_current, current).is_ok());

        // k0 信封：v2 信封体 + v3 前缀换 key_id
        let v2_envelope = encrypt_v2(plaintext, previous);
        let payload = v2_envelope.strip_prefix(ENCRYPTED_PREFIX_V2).unwrap();
        let k0_envelope = format!("{ENCRYPTED_PREFIX_V3}{PREVIOUS_KEY_ID}:{payload}");

        // ① previous 注入 → 可解
        assert_eq!(
            decrypt_config_value_with_previous(&k0_envelope, current, Some(previous)).unwrap(),
            plaintext
        );
        // ② previous 未注入 → 报错且信息指引恢复旧密钥
        let err = decrypt_config_value_with_previous(&k0_envelope, current, None)
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("CONFIG_ENC_KEY_PREVIOUS"),
            "错误信息应指引恢复旧密钥: {err}"
        );
        // ③ 未知 key_id → 拒绝
        let bad = format!("{ENCRYPTED_PREFIX_V3}k9:{payload}");
        assert!(decrypt_config_value_with_previous(&bad, current, Some(previous)).is_err());
    }

    /// 轮换旧密钥的**唯一**读取口 = 启动注入（Settings → crypto），不再是 crypto 自己读 env。
    ///
    /// 立案（批八十五 项 D）：`Settings.config_enc_key_previous` 有字段、有 `validate_secrets`
    /// 强度校验、有 `CONFIG_ENC_KEY_PREVIOUS` 环境变量覆盖，但消费点 `previous_master_key()`
    /// 直接 `env::var` ⇒ **配置文件里写的旧密钥永远不参与解密**。本用例走的是隐式路径
    /// （`decrypt_config_value`，即 20+ 个生产调用点用的那一个），因此它判的是"注入值真的
    /// 被消费"，不是"显式传参能传进去"（后者由 `test_v3_previous_key_rotation` 判）。
    ///
    /// OnceLock 首写优先、进程态不可逆 ⇒ 本模块所有用例只准用这一个常量
    /// （与 `common/encrypted_value.rs` 里 `KEY` 的同款约束一致）。
    const INJECTED_PREV: &str = "injected-previous-master-key-for-b85";

    #[test]
    fn runtime_injected_previous_key_is_consumed_by_the_implicit_path() {
        set_runtime_previous_key(INJECTED_PREV.to_string());
        // ① 注入值即读取值（空串不得写入，见 ③）
        assert_eq!(
            runtime_previous_key(),
            Some(INJECTED_PREV),
            "启动注入后隐式路径必须看到同一把密钥"
        );

        let current = "current-master-key-for-injection-test";
        let plaintext = "rotated-away-via-settings";
        let payload = encrypt_v2(plaintext, INJECTED_PREV)
            .strip_prefix(ENCRYPTED_PREFIX_V2)
            .expect("v2 信封应带前缀")
            .to_string();
        let k0 = format!("{ENCRYPTED_PREFIX_V3}{PREVIOUS_KEY_ID}:{payload}");

        // ② 隐式路径（生产调用点）必须能解——这一条在改造前是**失败**的：
        //    只有 env 里有旧密钥时才能解，配置文件里的那把进不了这里。
        assert_eq!(
            decrypt_config_value(&k0, current).expect("注入值应被隐式路径消费"),
            plaintext
        );
        // 对照组真受约束：用另一把密钥造的 k0 信封必须解不开（证明 ② 不是"任何密钥都能解"）
        let other_payload = encrypt_v2(plaintext, "a-completely-different-previous-key")
            .strip_prefix(ENCRYPTED_PREFIX_V2)
            .expect("v2 信封应带前缀")
            .to_string();
        let k0_other = format!("{ENCRYPTED_PREFIX_V3}{PREVIOUS_KEY_ID}:{other_payload}");
        assert!(
            decrypt_config_value(&k0_other, current).is_err(),
            "非注入密钥造的 k0 信封不得被解开，否则上一条断言是恒真"
        );

        // ③ 空串不得覆盖已注入值（空 = 没有轮换期，语义上是"不写"而不是"写空"）
        set_runtime_previous_key(String::new());
        assert_eq!(runtime_previous_key(), Some(INJECTED_PREV));
    }

    /// 形状锁：crypto.rs 的**生产码**里不得再出现旧密钥的 env 读取口。
    ///
    /// 为什么需要它：注入点存在但没人调（`initialize` 里那行被删）、或某处又偷偷加回
    /// `env::var`，两种回退都**不会**让上面那条用例变红——前者在测试进程里仍由测试自己
    /// 注入，后者只要注入先发生就照解不误。所以判据必须直接看源码形态。
    ///
    /// 三条反脆弱缺一不可：合成违规必须被抓（否则判据恒真）、不存在的函数名必须返回
    /// `None` 而不是空串、采集面必须有体量下限（读不到文件 ≠ 没有违规）。
    #[test]
    fn previous_key_has_exactly_one_read_port() {
        use crate::common::prod_scan;

        const PAT: &str = "env::var(\"CONFIG_ENC_KEY_PREVIOUS\")";
        let cfg = prod_scan::Scan::default();
        let file = prod_scan::prod_file("src/utils/crypto.rs", &cfg);
        // 实测生产码 187 行有效（`#[cfg(test)]` 之后的夹具不计），地板取 120：
        // 现状腰斩即说明采集面腐化，而不是"违规消失了"。
        assert!(
            file.nonempty_lines() > 120,
            "crypto.rs 只读到 {} 行有效码，采集面坏了，本判据不作数",
            file.nonempty_lines()
        );
        let hits: Vec<&String> = file.lines.iter().filter(|l| l.contains(PAT)).collect();
        assert!(
            hits.is_empty(),
            "crypto.rs 生产码里仍有旧密钥的第二读取口（应只由 initialize 1.05 注入）：{hits:?}"
        );

        // 合成违规必须被抓（判据不能是"永远匹配不上"的假绿）
        let synth = prod_scan::normalize(
            "let k = std::env::var(\"CONFIG_ENC_KEY_PREVIOUS\").ok();\n",
            &prod_scan::Scan::default(),
        );
        assert!(
            synth.iter().any(|l| l.contains(PAT)),
            "扫描器必须抓到合成违规，实得 {synth:?}"
        );
        // 注释里的同形状文本不得算成违规（刀口只能落在代码上）
        let commented = prod_scan::normalize(
            "// 曾经写 std::env::var(\"CONFIG_ENC_KEY_PREVIOUS\")，b85 起改成启动注入\n",
            &prod_scan::Scan::default(),
        );
        assert!(
            !commented.iter().any(|l| l.contains(PAT)),
            "注释形态不得决定判据，实得 {commented:?}"
        );

        // 注：initialize 的注入点本身用文本核对——它是"唯一读取口"的另一半。
        let init = prod_scan::prod_file("src/initialize/mod.rs", &cfg);
        assert!(
            init.lines
                .iter()
                .any(|l| l.contains("set_runtime_previous_key(settings.config_enc_key_previous")),
            "启动注入语句必须存在且取的是 Settings 字段（否则配置文件那一进不了解密路径）"
        );
    }

    #[test]
    fn test_is_encrypted_v2() {
        assert!(is_encrypted("enc:abc123"));
        assert!(is_encrypted("enc2:abc123"));
        assert!(!is_encrypted("plain"));
        assert!(!is_encrypted(""));
    }

    /// 第八批（P0 回归锁）：`seal_sensitive_value` 对已加密值必须**幂等**。
    ///
    /// 背景：启动回填 `id_token_secret` 曾因 ① SQL 判据 `NOT LIKE 'enc:%'` 认不出 `enc2:`
    /// ② 直接调用**无守卫**的 `encrypt_config_value`，导致**每次启动把已加密值再加密一层**
    /// （base64 膨胀 ×4/3），实测单字段涨到 743 MB、全表 4.5 GB。
    /// 本用例钉死"seal 幂等"这一不变量：两个前缀的值经 seal 后**逐字节不变**。
    #[test]
    fn test_seal_sensitive_value_is_idempotent() {
        let master_key = "test-master-key-0123456789abcdef";
        let plaintext = "s3cr3t-32-byte-ish";
        let once = seal_sensitive_value(plaintext, master_key).unwrap();
        assert!(once.starts_with(ENCRYPTED_PREFIX_V3));
        // 再 seal（等价于"回填判定误把密文当明文"）不得改变值
        let twice = seal_sensitive_value(&once, master_key).unwrap();
        assert_eq!(twice, once, "已加密值不得被二次加密（幂等）");
        assert_eq!(twice.len(), once.len(), "长度不得增长");
        // v1 前缀（历史数据）同样幂等
        let v1 = format!("{ENCRYPTED_PREFIX}abc123");
        assert_eq!(seal_sensitive_value(&v1, master_key).unwrap(), v1);
        // 主密钥缺省（fail-open）时原样返回明文
        assert_eq!(seal_sensitive_value(plaintext, "").unwrap(), plaintext);
    }

    /// 第八批：`is_encrypted` 必须同时识别 v1/v2 前缀（启动回填的 SQL 判据由同一
    /// 常量集合拼出，本断言保证"判据与写入格式"永远一致，不再出现 `enc2:` 漏判）。
    #[test]
    fn test_is_encrypted_covers_both_prefixes() {
        let sealed = seal_sensitive_value("x", "test-master-key-0123456789abcdef").unwrap();
        assert!(
            sealed.starts_with(ENCRYPTED_PREFIX_V3),
            "新写入必须是 v3 格式"
        );
        assert!(
            is_encrypted(&sealed),
            "is_encrypted 必须识别本模块自己产出的 v3 格式（否则回填会重复加密）"
        );
        assert!(is_encrypted(&format!("{ENCRYPTED_PREFIX}v1payload")));
        assert!(is_encrypted(&format!("{ENCRYPTED_PREFIX_V2}v2payload")));
        assert!(is_encrypted(&format!("{ENCRYPTED_PREFIX_V3}k1:v3payload")));
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
            "username": "stepby",
            "ip": "192.168.1.1",
            "login_time": "2026-07-30 10:00:00",
            "browser": "Firefox",
            "os": "Linux",
            "jti": "old-jti",
            "dept_name": "测试部"
        }"#;
        let session: OnlineSession = serde_json::from_str(legacy_json).unwrap();
        assert_eq!(session.exp, 0, "旧 JSON 反序列化时 exp 应默认为 0");
        assert_eq!(session.username, "stepby");
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
