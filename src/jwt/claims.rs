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
    pub fn verify_token(token: &str, config: &JwtConfig) -> Result<Claims, JwtError> {
        let mut validation = Validation::new(Algorithm::HS256);
        validation.set_issuer(&[&config.issuer]);
        validation.set_audience(&[&config.audience]);
        let token_data = decode::<Claims>(
            token,
            &DecodingKey::from_secret(config.secret.as_bytes()),
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
        let (token, claims) =
            JwtUtils::generate_token("1", "admin", &cfg).expect("generate_token must succeed");

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
        let cfg = test_jwt_config();
        let (token, _) =
            JwtUtils::generate_token("1", "admin", &cfg).expect("generate_token must succeed");

        // 篡改签名段最后一个字符（保持长度，确保是签名校验失败而非格式错误）
        let mut parts: Vec<String> = token.split('.').map(|s| s.to_string()).collect();
        assert_eq!(parts.len(), 3, "JWT 应为三段结构");
        let last = parts[2].clone();
        let new_last = if last.ends_with('A') {
            format!("{}B", &last[..last.len() - 1])
        } else {
            format!("{}A", &last[..last.len() - 1])
        };
        parts[2] = new_last;
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
        let (token, _) =
            JwtUtils::generate_token("1", "admin", &cfg).expect("generate_token must succeed");

        // 用不同密钥校验 → 签名不匹配
        let mut wrong_cfg = cfg.clone();
        wrong_cfg.secret = "a-totally-different-secret-key-0123456789".to_string();

        let err = JwtUtils::verify_token(&token, &wrong_cfg).unwrap_err();
        assert!(
            matches!(err, JwtError::InvalidSignature),
            "错误密钥应返回 InvalidSignature，实际得到: {err}"
        );
    }
}
