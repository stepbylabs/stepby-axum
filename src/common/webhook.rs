// axum-backend/src/common/webhook.rs
//! 出站 webhook 的**共用内核**。
//!
//! [`crate::config::settings::AcmeConfig`]（证书需求输出）与
//! [`crate::config::settings::EventsConfig`]（领域事件输出）都遵循同一套出站契约
//! （`off | webhook` + http(s) 目标 + 可选 HMAC-SHA256 签名），故把"地址合法性判定"
//! 与"签名算法"收敛到本模块——**单一事实源**，避免两处各写一套后口径漂移。

use hmac::{Hmac, Mac};
use sha2::Sha256;

/// 出站目标地址合法性：仅接受 `http://` / `https://`（两端空白自动裁剪）。
///
/// 刻意拒绝 `file:` / `ftp:` / 相对路径等——出站契约只面向"运维自己声明的 HTTP 端点"，
/// 非 HTTP scheme 一律视为**未配置**（fail-safe，不会把本地文件当推送目标）。
pub fn url_is_http(url: &str) -> bool {
    let url = url.trim();
    url.starts_with("http://") || url.starts_with("https://")
}

/// HMAC-SHA256 签名（hex 小写）。未配置 `secret` 时调用方不应调用本函数。
pub fn sign_hmac_sha256(secret: &str, body: &[u8]) -> String {
    // Hmac::<Sha256>::new_from_slice 对任意长度密钥都成功（HMAC 规范允许）；此处退化为不可达
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes())
        .expect("HMAC 接受任意长度密钥，构造不会失败");
    mac.update(body);
    hex::encode(mac.finalize().into_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 签名对齐**外部已知测试向量**（RFC 2104 常见用例），非自证
    #[test]
    fn test_sign_matches_known_vector() {
        assert_eq!(
            sign_hmac_sha256("key", b"The quick brown fox jumps over the lazy dog"),
            "f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8"
        );
        // 确定性 + 密钥敏感
        assert_eq!(
            sign_hmac_sha256("k", b"body"),
            sign_hmac_sha256("k", b"body")
        );
        assert_ne!(
            sign_hmac_sha256("k1", b"body"),
            sign_hmac_sha256("k2", b"body")
        );
    }

    /// 地址判定：仅 http(s)；裁剪两端空白；其余 scheme / 相对路径 / 空串一律拒绝
    #[test]
    fn test_url_is_http() {
        assert!(url_is_http("https://ops.example.com/hook"));
        assert!(url_is_http("  http://10.0.0.1:9000/hook  "));
        for bad in [
            "file:///etc/passwd",
            "ftp://x/y",
            "ops.example.com",
            "/relative/path",
            "",
        ] {
            assert!(!url_is_http(bad), "{bad} 不应被接受为出站目标");
        }
    }
}
