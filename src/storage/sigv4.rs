//! AWS Signature V4 签名实现（对象存储 S3/MinIO 请求签名）
//!
//! 纯函数实现 SigV4 核心计算，便于脱离网络单测（对齐 AWS 官方文档测试向量）。
//! 上层 [`super::s3::S3Backend`] 复用这些函数组装 canonical request 并发送 HTTP 请求。

use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

type HmacSha256 = Hmac<Sha256>;

/// HMAC-SHA256（SigV4 签名密钥逐级 HMAC 使用）
pub fn hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac =
        <HmacSha256 as Mac>::new_from_slice(key).expect("HMAC key 长度满足要求（任意长度均允许）");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

/// SHA256 十六进制（payload hash / canonical request hash）
pub fn sha256_hex(data: &[u8]) -> String {
    let digest = Sha256::digest(data);
    let mut out = String::with_capacity(64);
    for b in digest {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

/// 请求体 payload 的哈希值（SigV4 `x-amz-content-sha256` 头及 canonical request 末行）
pub fn payload_hash(payload: &[u8]) -> String {
    sha256_hex(payload)
}

/// 组装并排序 canonical headers，返回 `(headers_block, signed_headers)`。
///
/// - `headers_block`：`name:value\n`，name 小写，value 去除首尾空白
/// - `signed_headers`：分号分隔的"小写 name"列表
///
/// 入参 `headers` 为 `(header_name, header_value)` 无序列表，本函数按小写 name 排序。
pub fn canonical_headers(headers: &[(String, String)]) -> (String, String) {
    let mut sorted: Vec<(String, String)> = headers
        .iter()
        .map(|(n, v)| (n.to_ascii_lowercase(), v.trim().to_string()))
        .collect();
    sorted.sort_by(|a, b| a.0.cmp(&b.0));

    let headers_block = sorted
        .iter()
        .map(|(n, v)| format!("{n}:{v}\n"))
        .collect::<String>();
    let signed_headers = sorted
        .iter()
        .map(|(n, _)| n.clone())
        .collect::<Vec<_>>()
        .join(";");
    (headers_block, signed_headers)
}

/// 拼接 SigV4 canonical request 文本。
///
/// - `headers_block` / `signed_headers`：由 [`canonical_headers`] 生成
/// - `canonical_hash`：请求体哈希（[`payload_hash`]）
pub fn canonical_request(
    method: &str,
    canonical_uri: &str,
    canonical_query: &str,
    headers_block: &str,
    signed_headers: &str,
    canonical_hash: &str,
) -> String {
    format!(
        "{method}\n{canonical_uri}\n{canonical_query}\n{headers_block}\n{signed_headers}\n{canonical_hash}"
    )
}

/// 拼接 SigV4 string-to-sign。
///
/// `date` 为 yyyyMMdd（源自 timestamp），`region`/`service` 参与 scope 派生。
pub fn string_to_sign(
    timestamp: &str,
    date: &str,
    region: &str,
    service: &str,
    canonical_hash: &str,
) -> String {
    format!(
        "AWS4-HMAC-SHA256\n{timestamp}\n{date}/{region}/{service}/aws4_request\n{canonical_hash}"
    )
}

/// 派生签名密钥（HMAC 链：date → region → service → aws4_request）
pub fn signing_key(secret: &str, date: &str, region: &str, service: &str) -> Vec<u8> {
    let k_date = hmac_sha256(format!("AWS4{secret}").as_bytes(), date.as_bytes());
    let k_region = hmac_sha256(&k_date, region.as_bytes());
    let k_service = hmac_sha256(&k_region, service.as_bytes());
    hmac_sha256(&k_service, b"aws4_request")
}

/// 字节切片十六进制编码（小写）
pub fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

/// 计算最终签名（string-to-sign 的 HMAC-SHA256 摘要，十六进制）
///
/// 注意：SigV4 的 Authorization 签名是 `HmacSHA256(kSigning, sts)` 的十六进制，
/// 是直接对摘要字节做 hex 编码，**不可**再套一层 SHA256（否则会得出错误的 Authorization）。
pub fn signature(key: &[u8], sts: &str) -> String {
    hex_encode(&hmac_sha256(key, sts.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 对齐 AWS 官方文档《Signature Version 4 Test Suite》的经典用例
    /// （GET /test.txt，虚拟主机 examplebucket，range=bytes=0-9），验证底层密码学运算与
    /// canonical request 组装与官方值一致。
    #[test]
    fn sigv4_matches_aws_documented_get_object_example() {
        // --- 构造 AWS 文档中的 canonical request ---
        let method = "GET";
        let canonical_uri = "/test.txt";
        let canonical_query = "";
        let headers = vec![
            (
                "host".to_string(),
                "examplebucket.s3.amazonaws.com".to_string(),
            ),
            ("range".to_string(), "bytes=0-9".to_string()),
            (
                "x-amz-content-sha256".to_string(),
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".to_string(),
            ),
            ("x-amz-date".to_string(), "20130524T000000Z".to_string()),
        ];
        let (headers_block, signed_headers) = canonical_headers(&headers);
        let body_hash = payload_hash(b"");

        let creq = canonical_request(
            method,
            canonical_uri,
            canonical_query,
            &headers_block,
            &signed_headers,
            &body_hash,
        );

        // AWS 文档给出的 canonical request 文本（仅做关键片段断言，避免风格差异误报）
        assert_eq!(
            headers_block,
            "host:examplebucket.s3.amazonaws.com\nrange:bytes=0-9\nx-amz-content-sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\nx-amz-date:20130524T000000Z\n"
        );
        assert_eq!(signed_headers, "host;range;x-amz-content-sha256;x-amz-date");
        assert!(creq.starts_with("GET\n/test.txt\n\n"));

        // canonical request 的 SHA256 = 官方值 7344ae...
        let canonical_hash = sha256_hex(creq.as_bytes());
        assert_eq!(
            canonical_hash,
            "7344ae5b7ee6c3e7e6b0fe0640412a37625d1fbfff95c48bbb2dc43964946972"
        );

        // --- string-to-sign ---
        let sts = string_to_sign(
            "20130524T000000Z",
            "20130524",
            "us-east-1",
            "s3",
            &canonical_hash,
        );
        let expected_sts = "AWS4-HMAC-SHA256\n20130524T000000Z\n20130524/us-east-1/s3/aws4_request\n7344ae5b7ee6c3e7e6b0fe0640412a37625d1fbfff95c48bbb2dc43964946972";
        assert_eq!(sts, expected_sts);

        // --- signing key + signature ---
        let key = signing_key(
            "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            "20130524",
            "us-east-1",
            "s3",
        );
        let sig = signature(&key, &sts);
        // AWS 文档最终 Authorization 签名值
        assert_eq!(
            sig,
            "f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41"
        );
    }

    /// RFC 4231 测试向量 1（仅 key=0x0b*20 & "Hi There"）：验证底层 HMAC-SHA256 正确。
    #[test]
    fn hmac_sha256_matches_rfc4231_case1() {
        let rfc_key = [0x0b; 20];
        let rfc = hmac_sha256(&rfc_key, b"Hi There");
        assert_eq!(
            hex_encode(&rfc),
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        );
    }

    /// 空 payload 的哈希必须等于 AWS 已知常量（用于 GET/DELETE 无请求体场景）
    #[test]
    fn empty_payload_hash_matches_aws_known_constant() {
        assert_eq!(
            payload_hash(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    /// canonical_headers 对小写/去空白/排序的处理
    #[test]
    fn canonical_headers_sorts_and_lowercases() {
        let (block, signed) = canonical_headers(&[
            ("X-Amz-Date".to_string(), " 20130524T000000Z ".to_string()),
            ("HOST".to_string(), "example.com".to_string()),
        ]);
        assert_eq!(block, "host:example.com\nx-amz-date:20130524T000000Z\n");
        assert_eq!(signed, "host;x-amz-date");
    }
}
