// axum-backend/src/jwt/claims.rs

use chrono::Utc;
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use std::fmt;
use crate::config::JwtConfig;

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
    /// 生成 JWT token
    ///
    /// 时间策略说明（P0-R11-001 审查结论）：
    /// JWT 标准要求 exp/iat 使用 UTC 时间戳（RFC 7519），此处使用 Utc::now() 是正确的。
    /// 数据库时间字段（create_time/update_time）使用 Local::now().naive_local() 用于本地显示。
    /// 两者用途不同，不会混用。部署时需确保容器时区正确（TZ=Asia/Shanghai）。
    pub fn generate_token(
        user_id: &str,
        username: &str,
        config: &JwtConfig,
    ) -> Result<String, JwtError> {
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
        Ok(token)
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
