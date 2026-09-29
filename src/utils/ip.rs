// stepby-axum/src/utils/ip.rs
//! 客户端 IP 提取工具
//!
//! 从请求头提取客户端真实 IP，基于可信代理白名单校验 X-Forwarded-For 链。
//! 原 P1-17：从 handler/auth_handler.rs 迁移至 utils/ip.rs，消除 middleware → handler 的反向依赖。

use axum::http::HeaderMap;

/// 从请求头提取客户端 IP
///
/// 安全策略（基于可信代理白名单）：
/// 1. 无可信代理时直接使用 TCP 对端 IP（不信任任何转发头）
/// 2. 直连客户端不在白名单内时，不信任 XFF 头
/// 3. 对提取的字符串做 IP 格式校验，非法则回退到对端 IP
///
/// 注意：trusted_proxies 支持精确 IP（如 "127.0.0.1"）和 CIDR（如 "10.0.0.0/8"）。
/// 生产环境应配置为反向代理的真实 IP，防止客户端伪造 X-Forwarded-For。
pub fn extract_client_ip(
    headers: &HeaderMap,
    peer_ip: std::net::IpAddr,
    trusted_proxies: &[String],
) -> String {
    // 无可信代理时，直接使用 TCP 对端 IP（最安全，不信任任何转发头）
    if trusted_proxies.is_empty() {
        return peer_ip.to_string();
    }

    // 直连客户端不在可信代理白名单内时，不信任 XFF 头
    if !is_trusted_proxy(&peer_ip, trusted_proxies) {
        return peer_ip.to_string();
    }

    // 直连客户端是可信代理：从 X-Forwarded-For 链中提取真实客户端 IP
    if let Some(xff) = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()) {
        // XFF 格式: "client, proxy1, proxy2" — 从右向左跳过可信代理，取第一个不可信 IP
        let ips: Vec<&str> = xff.split(',').map(|s| s.trim()).collect();
        for ip_str in ips.iter().rev() {
            if let Ok(ip) = ip_str.parse::<std::net::IpAddr>()
                && !is_trusted_proxy(&ip, trusted_proxies)
            {
                return ip.to_string();
            }
        }
        // 全部是可信代理（罕见），取最左侧
        if let Some(first) = ips.first()
            && let Ok(ip) = first.parse::<std::net::IpAddr>()
        {
            return ip.to_string();
        }
    }

    // 回退到 X-Real-IP
    if let Some(ip_str) = headers
        .get("x-real-ip")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.trim())
        .filter(|s| s.parse::<std::net::IpAddr>().is_ok())
    {
        return ip_str.to_string();
    }

    peer_ip.to_string()
}

/// 判断 IP 是否在可信代理白名单内
///
/// 支持格式：
/// - 精确 IP：如 "127.0.0.1"、"::1"
/// - CIDR：如 "10.0.0.0/8"、"192.168.0.0/16"
pub(crate) fn is_trusted_proxy(ip: &std::net::IpAddr, trusted: &[String]) -> bool {
    for entry in trusted {
        let entry = entry.trim();
        if entry.is_empty() {
            continue;
        }
        // 精确匹配
        if let Ok(trusted_ip) = entry.parse::<std::net::IpAddr>() {
            if ip == &trusted_ip {
                return true;
            }
            continue;
        }
        // CIDR 匹配
        if let Some((cidr_ip_str, prefix_len_str)) = entry.split_once('/')
            && let (Ok(cidr_ip), Ok(prefix_len)) = (
                cidr_ip_str.parse::<std::net::IpAddr>(),
                prefix_len_str.parse::<u32>(),
            )
            && ip_in_cidr(ip, &cidr_ip, prefix_len)
        {
            return true;
        }
    }
    false
}

/// 判断 IP 是否在 CIDR 范围内
fn ip_in_cidr(ip: &std::net::IpAddr, cidr_ip: &std::net::IpAddr, prefix_len: u32) -> bool {
    match (ip, cidr_ip) {
        (std::net::IpAddr::V4(addr), std::net::IpAddr::V4(cidr)) => {
            if prefix_len > 32 {
                return false;
            }
            let mask: u32 = if prefix_len == 0 {
                0
            } else {
                (!0u32) << (32 - prefix_len)
            };
            (u32::from(*addr) & mask) == (u32::from(*cidr) & mask)
        }
        (std::net::IpAddr::V6(addr), std::net::IpAddr::V6(cidr)) => {
            if prefix_len > 128 {
                return false;
            }
            let addr_bytes = addr.octets();
            let cidr_bytes = cidr.octets();
            let full_bytes = (prefix_len / 8) as usize;
            let remainder_bits = prefix_len % 8;
            // 完整字节比较
            if addr_bytes[..full_bytes] != cidr_bytes[..full_bytes] {
                return false;
            }
            // 剩余位比较
            if remainder_bits > 0 && full_bytes < 16 {
                let mask = (!0u8) << (8 - remainder_bits);
                if (addr_bytes[full_bytes] & mask) != (cidr_bytes[full_bytes] & mask) {
                    return false;
                }
            }
            true
        }
        // IPv4 与 IPv6 不可比
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;
    use std::net::{IpAddr, Ipv4Addr};

    fn make_headers() -> HeaderMap {
        HeaderMap::new()
    }

    #[test]
    fn test_no_trusted_proxies_returns_peer_ip() {
        let headers = make_headers();
        let peer = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        let result = extract_client_ip(&headers, peer, &[]);
        assert_eq!(result, "127.0.0.1");
    }

    #[test]
    fn test_trusted_proxy_xff_extraction() {
        let mut headers = make_headers();
        headers.insert(
            "x-forwarded-for",
            HeaderValue::from_static("203.0.113.5, 10.0.0.1"),
        );
        let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let trusted = vec!["10.0.0.0/8".to_string()];
        let result = extract_client_ip(&headers, peer, &trusted);
        assert_eq!(result, "203.0.113.5");
    }

    #[test]
    fn test_untrusted_peer_ignored_xff() {
        let mut headers = make_headers();
        headers.insert("x-forwarded-for", HeaderValue::from_static("203.0.113.5"));
        let peer = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let trusted = vec!["10.0.0.0/8".to_string()];
        // peer 不在可信代理白名单，直接返回 peer_ip
        let result = extract_client_ip(&headers, peer, &trusted);
        assert_eq!(result, "192.168.1.1");
    }

    #[test]
    fn test_cidr_matching_v4() {
        let ip = "10.0.5.100".parse().unwrap();
        assert!(is_trusted_proxy(&ip, &["10.0.0.0/8".to_string()]));
        assert!(!is_trusted_proxy(&ip, &["192.168.0.0/16".to_string()]));
    }
}
