// axum-backend/src/jwt/claims.rs

use crate::config::JwtConfig;
use chrono::Utc;
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode};
use serde::{Deserialize, Serialize};
use std::fmt;

/// JWT Claims
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    /// 用户 ID
    pub sub: String,
    /// 用户名
    pub username: String,
    /// 过期时间戳（秒）
    pub exp: usize,
    /// 签发时间戳（秒）
    pub iat: usize,
    /// 签发者
    pub iss: String,
    /// 受众（SEC-001：防止 token 跨服务复用）
    pub aud: String,
    /// JWT 唯一 ID（防止同用户同秒生成的 token 完全相同，导致黑名单冲突）
    pub jti: String,
    /// 密码版本号（P0-R81-007 改进：取代秒级时间戳标记）
    ///
    /// - 改密/重置密码/停用/删除用户时对 `pwd_ver:{user_id}` 计数器 INCR；
    /// - 登录时读取当前版本号写入 claim；
    /// - auth 中间件比较 Redis 当前版本 > claim 版本则拒绝（旧 token 立即失效）。
    /// - `#[serde(default)]` 兼容旧 token（未携带该 claim 视为版本 0，存量用户未改密前版本同为 0，可平滑过渡）。
    #[serde(default)]
    pub pwd_ver: u64,
    /// 个人访问令牌（PAT）授权范围（Tier-S #3）。
    ///
    /// - 登录 JWT 恒为 `None`（`skip_serializing_if` 使其不进入 token 载荷，向后兼容）；
    /// - PAT 鉴权时由 `auth_middleware` 依据令牌记录合成为 `Some(scopes)`，
    ///   `permission_middleware` 据此对请求施加“令牌 scope ∩ 用户当前权限”的细粒度约束。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pat_scopes: Option<Vec<String>>,
    /// v5-N2 Phase 1：租户 ID（多租户前瞻基础设施）。
    ///
    /// - 登录时从用户记录写入（当前恒 0 = 平台单租户，字段语义与 sys_oauth_client 等
    ///   表的预留列一致：默认 0、不参与过滤）；
    /// - `#[serde(default)]` 兼容旧 token（未携带视为 0）；
    /// - 多租户立项（Phase 2）后：登录查库带出真实 tid，Repository 过滤层据此注入
    ///   `tenant_id = tid` 条件——Phase 1 仅打通"签发→携带→访问器"链路，零行为变更。
    #[serde(default)]
    pub tid: i64,
}

/// JWT 错误类型（类型化，替代原 anyhow::Result）
///
/// 将 jsonwebtoken::errors::Error 的多种变体归纳为业务可区分的几类，
/// 使调用方能够针对不同原因返回不同错误提示。
#[derive(Debug)]
pub enum JwtError {
    /// token 已过期（exp 过期），需重新登录
    Expired,
    /// 签名验证失败，token 可能被篡改
    InvalidSignature,
    /// token 格式错误或解析失败（Base64/JSON/UTF-8 解码失败）
    Malformed,
    /// Claims 校验失败（issuer/audience/subject 不匹配，或 nbf 未生效）
    InvalidClaims,
    /// token 签发失败（内部错误，不应暴露给用户）
    GenerateFailed,
}

impl fmt::Display for JwtError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            JwtError::Expired => write!(f, "token 已过期"),
            JwtError::InvalidSignature => write!(f, "token 签名验证失败"),
            JwtError::Malformed => write!(f, "token 格式错误"),
            JwtError::InvalidClaims => write!(f, "token claims 校验失败"),
            JwtError::GenerateFailed => write!(f, "token 签发失败"),
        }
    }
}

impl std::error::Error for JwtError {}

/// 将 jsonwebtoken 底层错误转换为类型化 JwtError
impl From<jsonwebtoken::errors::Error> for JwtError {
    fn from(err: jsonwebtoken::errors::Error) -> Self {
        use jsonwebtoken::errors::ErrorKind;
        match err.kind() {
            ErrorKind::ExpiredSignature => JwtError::Expired,
            ErrorKind::InvalidSignature => JwtError::InvalidSignature,
            ErrorKind::InvalidToken
            | ErrorKind::Base64(_)
            | ErrorKind::Json(_)
            | ErrorKind::Utf8(_) => JwtError::Malformed,
            ErrorKind::InvalidIssuer
            | ErrorKind::InvalidAudience
            | ErrorKind::InvalidSubject
            | ErrorKind::ImmatureSignature => JwtError::InvalidClaims,
            _ => JwtError::Malformed,
        }
    }
}

/// JWT 工具类
pub struct JwtUtils;

impl JwtUtils {
    /// 生成 JWT token 并返回 Claims
    ///
    /// 时间策略说明（P0-R11-001 审查结论）：
    /// JWT 标准要求 exp/iat 使用 UTC 时间戳（RFC 7519），此处使用 Utc::now() 是正确的。
    /// 数据库时间字段（create_time/update_time）使用 crate::common::datetime::now_naive() 用于本地显示。
    /// 两者用途不同，不会混用。部署时需确保容器时区正确（TZ=Asia/Shanghai）。
    ///
    /// M-7：返回 `(token, Claims)` 而非仅 `token`，调用方可直接使用 Claims（如 jti），
    /// 避免刚签发的 token 立即调用 verify_token 重新解码（解析 Base64 + 校验签名），
    /// 浪费约 0.1ms CPU 且增加不必要的错误分支。
    pub fn generate_token(
        user_id: &str,
        username: &str,
        config: &JwtConfig,
        pwd_ver: u64,
        tid: i64,
    ) -> Result<(String, Claims), JwtError> {
        let now = Utc::now();
        let exp = now + chrono::Duration::hours(config.expire_hours);
        let claims = Claims {
            sub: user_id.to_string(),
            username: username.to_string(),
            // R5-TYPE-13：使用 try_from 替代 `as usize`，避免 32 位系统上
            // 2038 年后的时间戳回绕（fail-closed：溢出时返回 0，token 立即过期）
            exp: usize::try_from(exp.timestamp()).unwrap_or(0),
            iat: usize::try_from(now.timestamp()).unwrap_or(0),
            iss: config.issuer.clone(),
            aud: config.audience.clone(),
            jti: uuid::Uuid::new_v4().to_string(),
            pwd_ver,
            pat_scopes: None,
            // v5-N2 Phase 2：登录查库带出真实租户 ID（存量用户默认 0）
            tid,
        };
        // SEC-008：显式指定 Algorithm::HS256，不依赖 Header::default()（默认 HS256 但显式更安全）
        let mut header = Header::new(Algorithm::HS256);
        header.typ = Some("JWT".to_string());
        let token = encode(
            &header,
            &claims,
            &EncodingKey::from_secret(config.secret.as_bytes()),
        )?;
        Ok((token, claims))
    }

    /// 验证 JWT token 并返回 Claims
    ///
    /// SEC-001：校验 issuer + audience，防止 token 跨服务复用
    /// SEC-008：显式指定 Algorithm::HS256，防止 alg=none 攻击
    ///
    /// **密钥轮换（多密钥共存）**：按 `config.verification_secrets()`（当前密钥优先、
    /// 其后为 `previous_secrets`）逐个尝试验签。命中旧密钥即视为"该 token 签发于轮换之前"，
    /// 记 debug 级可观测信号后放行 ⇒ 轮换期间**存量 token 不被登出**（零停机）。
    /// 全部密钥均签名不匹配 ⇒ `InvalidSignature`；过期/格式/claims 类错误与密钥无关，
    /// 立即返回真实原因（不被"换密钥重试"掩盖成签名失败）。
    pub fn verify_token(token: &str, config: &JwtConfig) -> Result<Claims, JwtError> {
        for (idx, secret) in config.verification_secrets().into_iter().enumerate() {
            match Self::verify_with_secret(token, config, secret) {
                Ok(claims) => {
                    if idx > 0 {
                        tracing::debug!(
                            key_index = idx,
                            "JWT 由 previous_secrets 验签通过（密钥轮换过渡期内）"
                        );
                    }
                    return Ok(claims);
                }
                // 签名不匹配 ⇒ 换下一把候选密钥重试（多密钥共存的核心分支）
                Err(JwtError::InvalidSignature) => continue,
                // 过期 / 格式错误 / claims 不符 ⇒ 与密钥无关，立即返回
                Err(err) => return Err(err),
            }
        }
        Err(JwtError::InvalidSignature)
    }

    /// 单密钥验签（[`JwtUtils::verify_token`] 候选循环的单元）：校验 issuer + audience。
    fn verify_with_secret(
        token: &str,
        config: &JwtConfig,
        secret: &str,
    ) -> Result<Claims, JwtError> {
        let mut validation = Validation::new(Algorithm::HS256);
        validation.set_issuer(&[&config.issuer]);
        validation.set_audience(&[&config.audience]);
        let token_data = decode::<Claims>(
            token,
            &DecodingKey::from_secret(secret.as_bytes()),
            &validation,
        )?;
        Ok(token_data.claims)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    /// 构造一份通过校验的基准 JwtConfig（secret 为合法强密钥），供测试复用
    fn test_jwt_config() -> JwtConfig {
        JwtConfig {
            secret: "placeholder-strong-secret-0123456789abcdef".to_string(),
            expire_hours: 24,
            issuer: "yebot".to_string(),
            audience: "yebot".to_string(),
            previous_secrets: vec![],
        }
    }

    /// 用给定 Claims 直接编码一个 token（绕过 generate_token，便于构造异常场景）
    fn encode_claims(claims: &Claims, secret: &str) -> String {
        let mut header = Header::new(Algorithm::HS256);
        header.typ = Some("JWT".to_string());
        encode(
            &header,
            claims,
            &EncodingKey::from_secret(secret.as_bytes()),
        )
        .expect("test encode must succeed")
    }

    #[test]
    fn test_generate_and_verify_roundtrip() {
        let cfg = test_jwt_config();
        let (token, claims) = JwtUtils::generate_token("1", "admin", &cfg, 0, 0)
            .expect("generate_token must succeed");

        let verified = JwtUtils::verify_token(&token, &cfg).expect("verify must succeed");

        assert_eq!(verified.sub, "1");
        assert_eq!(verified.username, "admin");
        assert_eq!(verified.iss, "yebot");
        assert_eq!(verified.aud, "yebot");
        assert_eq!(verified.jti, claims.jti, "jti 应原样往返");
        assert!(verified.exp > verified.iat, "exp 应晚于 iat");
        // 默认 24h 有效期，exp 应大约在 now+24h 附近（容差 1 分钟）
        let now = Utc::now().timestamp() as usize;
        assert!(
            verified.exp >= now + 23 * 3600 && verified.exp <= now + 25 * 3600,
            "exp 应在 24h 附近，实际 exp={}, now={}",
            verified.exp,
            now
        );
    }

    #[test]
    fn test_verify_rejects_expired_token() {
        let cfg = test_jwt_config();
        let now = Utc::now();
        let claims = Claims {
            sub: "1".to_string(),
            username: "admin".to_string(),
            exp: (now - chrono::Duration::hours(1)).timestamp() as usize,
            iat: (now - chrono::Duration::hours(2)).timestamp() as usize,
            iss: cfg.issuer.clone(),
            aud: cfg.audience.clone(),
            jti: "test-jti".to_string(),
            pwd_ver: 0,
            pat_scopes: None,
            tid: 0,
        };
        let token = encode_claims(&claims, &cfg.secret);

        let err = JwtUtils::verify_token(&token, &cfg).unwrap_err();
        assert!(
            matches!(err, JwtError::Expired),
            "过期令牌应返回 Expired，实际得到: {err}"
        );
    }

    #[test]
    fn test_verify_rejects_tampered_signature() {
        use base64::Engine;
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;

        let cfg = test_jwt_config();
        let (token, _) = JwtUtils::generate_token("1", "admin", &cfg, 0, 0)
            .expect("generate_token must succeed");

        // 篡改签名：先 base64url 解码 → 翻转一个字节 → 重新编码。
        // 不做"末尾字符翻转"是因为 HS256 签名为 32 字节 → base64url 为 43 字符（无填充），
        // 其末位携带 2 个留空位，翻转末字符可能触发解码失败而落到 Malformed，造成该测试
        // 依赖运行时间产生随机签名时而时好时坏（flaky）。解码→翻转→重编码可保证得到
        // 长度合法但内容确定错误的签名，稳定返回 InvalidSignature。
        let mut parts: Vec<String> = token.split('.').map(|s| s.to_string()).collect();
        assert_eq!(parts.len(), 3, "JWT 应为三段结构");
        let mut sig = URL_SAFE_NO_PAD
            .decode(parts[2].as_str())
            .expect("合法签名应可 base64url 解码");
        assert!(!sig.is_empty(), "签名不应为空");
        sig[0] ^= 0xFF; // 确定性翻转首个字节
        parts[2] = URL_SAFE_NO_PAD.encode(&sig);
        let bad_token = parts.join(".");

        let err = JwtUtils::verify_token(&bad_token, &cfg).unwrap_err();
        assert!(
            matches!(err, JwtError::InvalidSignature),
            "篡改签名应返回 InvalidSignature，实际得到: {err}"
        );
    }

    #[test]
    fn test_verify_rejects_wrong_issuer() {
        let cfg = test_jwt_config();
        let now = Utc::now();
        let claims = Claims {
            sub: "1".to_string(),
            username: "admin".to_string(),
            exp: (now + chrono::Duration::hours(1)).timestamp() as usize,
            iat: now.timestamp() as usize,
            iss: "evil-issuer".to_string(), // 错误的签发者
            aud: cfg.audience.clone(),
            jti: "test-jti".to_string(),
            pwd_ver: 0,
            pat_scopes: None,
            tid: 0,
        };
        let token = encode_claims(&claims, &cfg.secret);

        let err = JwtUtils::verify_token(&token, &cfg).unwrap_err();
        assert!(
            matches!(err, JwtError::InvalidClaims),
            "iss 不符应返回 InvalidClaims，实际得到: {err}"
        );
    }

    #[test]
    fn test_verify_rejects_wrong_audience() {
        let cfg = test_jwt_config();
        let now = Utc::now();
        let claims = Claims {
            sub: "1".to_string(),
            username: "admin".to_string(),
            exp: (now + chrono::Duration::hours(1)).timestamp() as usize,
            iat: now.timestamp() as usize,
            iss: cfg.issuer.clone(),
            aud: "wrong-audience".to_string(), // 错误的受众
            jti: "test-jti".to_string(),
            pwd_ver: 0,
            pat_scopes: None,
            tid: 0,
        };
        let token = encode_claims(&claims, &cfg.secret);

        let err = JwtUtils::verify_token(&token, &cfg).unwrap_err();
        assert!(
            matches!(err, JwtError::InvalidClaims),
            "aud 不符应返回 InvalidClaims，实际得到: {err}"
        );
    }

    #[test]
    fn test_verify_rejects_wrong_secret() {
        let cfg = test_jwt_config();
        let (token, _) = JwtUtils::generate_token("1", "admin", &cfg, 0, 0)
            .expect("generate_token must succeed");

        // 用不同密钥校验 → 签名不匹配
        let mut wrong_cfg = cfg.clone();
        wrong_cfg.secret = "a-totally-different-secret-key-0123456789".to_string();

        let err = JwtUtils::verify_token(&token, &wrong_cfg).unwrap_err();
        assert!(
            matches!(err, JwtError::InvalidSignature),
            "错误密钥应返回 InvalidSignature，实际得到: {err}"
        );
    }

    // ==================== 密钥轮换（多密钥共存）====================

    /// 轮换过渡期：用**旧密钥**签发的 token，在 `secret=新密钥 + previous_secrets=[旧密钥]`
    /// 下仍可通过验签 —— 这是零停机轮换的核心不变量（存量 token 不被登出）。
    #[test]
    fn test_verify_accepts_token_signed_by_previous_key_during_rotation() {
        const NEW_SECRET: &str = "rotated-new-secret-0123456789abcdefghij";
        const OLD_SECRET: &str = "legacy-old-secret-9876543210zyxwvutsrq";
        let old_cfg = JwtConfig {
            secret: OLD_SECRET.to_string(),
            ..test_jwt_config()
        };
        // 轮换前签发的 token（用旧密钥）
        let (legacy_token, _) =
            JwtUtils::generate_token("7", "legacy", &old_cfg, 0, 0).expect("旧密钥签发应成功");

        // 轮换后的配置：签发密钥为新，旧密钥进入 previous_secrets
        let rotated = JwtConfig {
            secret: NEW_SECRET.to_string(),
            previous_secrets: vec![OLD_SECRET.to_string()],
            ..test_jwt_config()
        };

        let claims = JwtUtils::verify_token(&legacy_token, &rotated)
            .expect("过渡期内旧密钥签发的 token 必须仍可通过验签");
        assert_eq!(claims.sub, "7");
        assert_eq!(claims.username, "legacy");

        // 新密钥签发的 token 同样通过（且不需回退）
        let (fresh_token, _) =
            JwtUtils::generate_token("8", "fresh", &rotated, 0, 0).expect("新密钥签发应成功");
        assert_eq!(
            JwtUtils::verify_token(&fresh_token, &rotated)
                .expect("新 token 应通过")
                .sub,
            "8"
        );
    }

    /// 轮换完成（`previous_secrets` 清空）后，旧密钥签发的 token 必须被拒 —— 轮换真正生效。
    #[test]
    fn test_verify_rejects_previous_key_token_after_rotation_completes() {
        const NEW_SECRET: &str = "rotated-new-secret-0123456789abcdefghij";
        const OLD_SECRET: &str = "legacy-old-secret-9876543210zyxwvutsrq";
        let old_cfg = JwtConfig {
            secret: OLD_SECRET.to_string(),
            ..test_jwt_config()
        };
        let (legacy_token, _) =
            JwtUtils::generate_token("7", "legacy", &old_cfg, 0, 0).expect("旧密钥签发应成功");

        let done = JwtConfig {
            secret: NEW_SECRET.to_string(),
            previous_secrets: vec![],
            ..test_jwt_config()
        };
        let err = JwtUtils::verify_token(&legacy_token, &done).unwrap_err();
        assert!(
            matches!(err, JwtError::InvalidSignature),
            "清空 previous_secrets 后旧 token 应被拒，实际: {err}"
        );
    }

    /// 完全未知的第三把密钥签发的 token 不得通过（回退 ≠ 放行任意密钥）。
    #[test]
    fn test_verify_rejects_unknown_key_when_rotating() {
        let cfg = JwtConfig {
            secret: "rotated-new-secret-0123456789abcdefghij".to_string(),
            previous_secrets: vec!["legacy-old-secret-9876543210zyxwvutsrq".to_string()],
            ..test_jwt_config()
        };
        let attacker = JwtConfig {
            secret: "attacker-key-0123456789abcdefghijklmn".to_string(),
            ..test_jwt_config()
        };
        let (forged, _) = JwtUtils::generate_token("1", "attacker", &attacker, 0, 0)
            .expect("伪造 token 应可编码");

        let err = JwtUtils::verify_token(&forged, &cfg).unwrap_err();
        assert!(
            matches!(err, JwtError::InvalidSignature),
            "未知密钥应被拒，实际: {err}"
        );
    }

    /// 旧密钥签发但**已过期**的 token 应返回 `Expired`（而非被回退逻辑掩盖成 InvalidSignature）。
    #[test]
    fn test_verify_expired_token_signed_by_previous_key_returns_expired() {
        const NEW_SECRET: &str = "rotated-new-secret-0123456789abcdefghij";
        const OLD_SECRET: &str = "legacy-old-secret-9876543210zyxwvutsrq";
        let cfg = JwtConfig {
            secret: NEW_SECRET.to_string(),
            previous_secrets: vec![OLD_SECRET.to_string()],
            ..test_jwt_config()
        };
        let now = Utc::now();
        let claims = Claims {
            sub: "9".to_string(),
            username: "expired".to_string(),
            exp: (now - chrono::Duration::hours(1)).timestamp() as usize,
            iat: (now - chrono::Duration::hours(2)).timestamp() as usize,
            iss: cfg.issuer.clone(),
            aud: cfg.audience.clone(),
            jti: "expired-jti".to_string(),
            pwd_ver: 0,
            pat_scopes: None,
            tid: 0,
        };
        let token = encode_claims(&claims, OLD_SECRET);
        let err = JwtUtils::verify_token(&token, &cfg).unwrap_err();
        assert!(
            matches!(err, JwtError::Expired),
            "旧密钥 + 过期应返回 Expired，实际: {err}"
        );
    }

    /// `verification_secrets`：当前密钥优先、去空串、trim、去重、保序。
    #[test]
    fn test_verification_secrets_order_dedup_and_trim() {
        let cfg = JwtConfig {
            secret: "current-secret".to_string(),
            previous_secrets: vec![
                "  old-a-secret  ".to_string(),
                String::new(),                // 空串 ⇒ 忽略
                "current-secret".to_string(), // 与当前密钥重复 ⇒ 去重
                "old-b-secret".to_string(),
                "old-a-secret".to_string(), // trim 后与首项重复 ⇒ 去重
            ],
            ..test_jwt_config()
        };
        assert_eq!(
            cfg.verification_secrets(),
            vec!["current-secret", "old-a-secret", "old-b-secret"],
            "应为：当前密钥优先 + 去空 + trim + 去重 + 保序"
        );
    }
}
