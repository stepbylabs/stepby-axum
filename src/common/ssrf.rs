//! SSRF 防护模块（服务器端请求伪造防护）
//!
//! 适用范围：在线 HTTP 调试器（/tool/http-debug）、以及任何需要「由服务端发起出站 HTTP 请求」
//! 且目标 URL 由用户/客户端输入的功能。核心目标是阻止攻击者利用该能力访问内网资源
//! （云元数据端点 169.254.169.254、127.0.0.1、内网 IP 段、保留地址等）。
//!
//! 双层校验：
//!   1. `validate_url`：静态校验（不依赖 DNS）——仅允许 http/https；主机名为 IP 字面量时
//!      直接判断是否命中阻断地址段；主机额为域名时使用保留域名后缀黑名单（无法解析/解析
//!      到内网的域名通常不会落在这些后缀下）。
//!   2. `validate_host_resolution`：动态校验——真实解析主机名全部 A/AAAA 地址，只要有一个
//!      命中阻断地址段即拒绝（防止目标域名解析到内网）。
//!
//! 已知边界与缓解（DNS 重绑定）：`validate_host_resolution` 校验通过后再由 `reqwest` 发起请求，
//! 解析与连接之间存在 TOCTOU 窗口，极端恶意场景可利用域名重新解析指向内网。该功能本身受
//! `tool:httpDebug:list` 权限保护且针对管理员，属主流 SSRF 代理的常规防护水平。如需更强约束，
//! 可自行改为「解析成字面 IP → 直连该 IP + Host/SNI 覆盖」模式，但会牺牲调试器的域名灵活性。

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// 允许的出站请求 scheme
pub const ALLOWED_SCHEMES: [&str; 2] = ["http", "https"];

/// 应阻断的 IPv4 地址段（ICS/IANA 保留 + 内网 + 链路本地等）
///
/// 参考 IANA 特殊用途地址注册表与 RFC 5735 / RFC 6303 的常用子集：
/// - 0.0.0.0/8           本网
/// - 10.0.0.0/8          RFC 1918 私有
/// - 100.64.0.0/10       CGNAT 共享地址
/// - 127.0.0.0/8         环回
/// - 169.254.0.0/16      链路本地（含 AWS/GCP/Azure 云元数据端点）
/// - 172.16.0.0/12       RFC 1918 私有
/// - 192.0.0.0/24        IETF 协议分配
/// - 192.0.2.0/24        TEST-NET-1 文档
/// - 192.168.0.0/16      RFC 1918 私有
/// - 198.18.0.0/15       基准测试
/// - 198.51.100.0/24     TEST-NET-2 文档
/// - 203.0.113.0/24      TEST-NET-3 文档
/// - 224.0.0.0/4         组播
/// - 240.0.0.0/4         保留
pub fn is_blocked_ipv4(ip: Ipv4Addr) -> bool {
    let o = ip.octets();
    let a = o[0];
    let b = o[1];
    a == 0                       // 0.0.0.0/8
        || a == 10               // 10.0.0.0/8
        || (a == 100 && (b & 0xC0) == 0x40) // 100.64.0.0/10
        || a == 127              // 127.0.0.0/8
        || (a == 169 && b == 254) // 169.254.0.0/16
        || (a == 172 && (16..=31).contains(&b)) // 172.16.0.0/12
        || (a == 192 && b == 0)  // 192.0.0.0/24
        || (a == 192 && b == 2)  // 192.0.2.0/24
        || (a == 192 && b == 168) // 192.168.0.0/16
        || (a == 198 && (b == 18 || b == 19)) // 198.18.0.0/15
        || (a == 198 && b == 51) // 198.51.100.0/24
        || (a == 203 && b == 0 && o[2] == 113) // 203.0.113.0/24
        || a >= 224 // 224.0.0.0/3（组播 + 保留）
}

/// 需要阻断的 IPv6 地址段
///
/// - ::/128             未指定
/// - ::1/128            环回
/// - ::ffff:0:0/96      IPv4 映射地址（用 as_v4 判定底层 IPv4 段）
/// - fc00::/7           唯一本地地址 ULA
/// - fe80::/10          链路本地
/// - 2001:db8::/32      文档地址
/// - ff00::/8           组播
pub fn is_blocked_ipv6(ip: Ipv6Addr) -> bool {
    // IPv4 映射地址（::ffff:a.b.c.d）——直接套用 IPv4 判定，防止绕过
    if let Some(v4) = ip.to_ipv4_mapped() {
        return is_blocked_ipv4(v4);
    }
    let seg = ip.segments();
    let first16 = seg[0];
    let first32 = ((seg[0] as u32) << 16) | (seg[1] as u32);

    ip.is_unspecified()          // ::
        || ip.is_loopback()      // ::1
        || (first16 & 0xfe00) == 0xfc00 // fc00::/7
        || (first16 & 0xffc0) == 0xfe80 // fe80::/10
        || first32 == 0x20010db8 // 2001:db8::/32 文档
        || (first16 & 0xff00) == 0xff00 // ff00::/8 组播
}

/// 判断任意 IP 是否命中阻断地址段
pub fn is_blocked_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_blocked_ipv4(v4),
        IpAddr::V6(v6) => is_blocked_ipv6(v6),
    }
}

/// 常见不可直接出站解析的保留域名后缀（优先级手写前缀匹配）
///
/// 拦截 localhost / .local / .internal / .localdomain / .home.arpa / .lan 等
/// 仅内网可解析或本轮解析异常的安全后缀，避免误连本机管理面。
fn is_blocked_hostname(host: &str) -> bool {
    let h = host.to_ascii_lowercase();
    let h = h.trim_end_matches('.');
    // 精确匹配
    if h == "localhost" {
        return true;
    }
    // 以保留后缀结尾
    const BLOCKED_SUFFIXES: [&str; 8] = [
        ".localhost",
        ".local",
        ".internal",
        ".localdomain",
        ".lan",
        ".home.arpa",
        ".test",
        ".example",
    ];
    BLOCKED_SUFFIXES.iter().any(|suffix| h.ends_with(suffix))
}

/// 静态校验目标 URL（不发起 DNS 解析）
///
/// - 仅允许 http/https
/// - 必须含主机名
/// - 主机名为 IP 字面量 → 直接判定阻断地址段
/// - 主机名为域名 → 判定保留域名后缀
///
/// 返回 Ok(url) 表示通过静态层；调用方随后应再执行 `validate_host_resolution` 做动态层校验。
pub fn validate_url(url: &str) -> Result<url::Url, String> {
    let parsed = url::Url::parse(url).map_err(|e| format!("URL 格式非法：{e}"))?;

    if !ALLOWED_SCHEMES.contains(&parsed.scheme()) {
        return Err(format!("仅允许 http/https 协议，收到 {}", parsed.scheme()));
    }

    // 主机名判定：优先使用 Host 枚举（IPv6 字面量不含方括号），
    // 避免 host_str() 对 IPv6 返回 "[::1]" 导致 IP 解析失败而绕过阻断。
    match parsed.host() {
        Some(url::Host::Ipv4(v4)) => {
            if is_blocked_ipv4(v4) {
                return Err(format!("禁止访问内网/保留地址 {v4}"));
            }
        }
        Some(url::Host::Ipv6(v6)) => {
            if is_blocked_ipv6(v6) {
                return Err(format!("禁止访问内网/保留地址 {v6}"));
            }
        }
        Some(url::Host::Domain(domain)) => {
            if is_blocked_hostname(domain) {
                return Err(format!("禁止访问保留域名后缀 {domain}"));
            }
        }
        None => return Err("URL 缺少主机名".to_string()),
    }

    Ok(parsed)
}

/// 动态校验：解析主机名全部 A/AAAA 地址，任一定向内网/保留地址段即拒绝
///
/// 解析失败同样视为不通过（返回 Err），避免「解析失败却继续直连」绕过。
pub async fn validate_host_resolution(host: &str, port: u16) -> Result<(), String> {
    let addrs = tokio::net::lookup_host((host, port))
        .await
        .map_err(|e| format!("DNS 解析失败：{host}（{e}）"))?;

    for sa in addrs {
        if is_blocked_ip(sa.ip()) {
            return Err(format!(
                "目标 {host} 解析到内网/保留地址 {}，已拦截",
                sa.ip()
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blocked_ipv4_ranges() {
        assert!(is_blocked_ipv4("127.0.0.1".parse().unwrap()));
        assert!(is_blocked_ipv4("10.0.0.1".parse().unwrap()));
        assert!(is_blocked_ipv4("172.16.0.1".parse().unwrap()));
        assert!(is_blocked_ipv4("172.31.255.255".parse().unwrap()));
        assert!(is_blocked_ipv4("192.168.1.1".parse().unwrap()));
        assert!(is_blocked_ipv4("169.254.169.254".parse().unwrap()));
        assert!(is_blocked_ipv4("0.0.0.0".parse().unwrap()));
        assert!(is_blocked_ipv4("100.64.0.1".parse().unwrap()));
        assert!(is_blocked_ipv4("100.127.255.1".parse().unwrap()));
        assert!(is_blocked_ipv4("192.0.2.9".parse().unwrap()));
        assert!(!is_blocked_ipv4("8.8.8.8".parse().unwrap()));
        assert!(!is_blocked_ipv4("114.114.114.114".parse().unwrap()));
        assert!(!is_blocked_ipv4("1.1.1.1".parse().unwrap()));
    }

    #[test]
    fn blocked_ipv6_ranges() {
        assert!(is_blocked_ipv6("::1".parse().unwrap()));
        assert!(is_blocked_ipv6("::".parse().unwrap()));
        assert!(is_blocked_ipv6("fc00::1".parse().unwrap()));
        assert!(is_blocked_ipv6("fd00::1".parse().unwrap()));
        assert!(is_blocked_ipv6("fe80::1".parse().unwrap()));
        assert!(is_blocked_ipv6("2001:db8::1".parse().unwrap()));
        assert!(!is_blocked_ipv6("2001:4860:4860::8888".parse().unwrap()));
        assert!(!is_blocked_ipv6("2606:4700:4700::1111".parse().unwrap()));
    }

    #[test]
    fn ipv4_mapped_v6_is_blocked_when_v4_blocked() {
        // ::ffff:127.0.0.1 应被识别为标准 IPv4 环回
        assert!(is_blocked_ip("::ffff:127.0.0.1".parse().unwrap()));
    }

    #[test]
    fn blocked_hostname_suffixes() {
        assert!(is_blocked_hostname("localhost"));
        assert!(is_blocked_hostname("svc.local"));
        assert!(is_blocked_hostname("db.internal"));
        assert!(is_blocked_hostname("redis.test"));
        assert!(is_blocked_hostname("example.com.local"));
        assert!(!is_blocked_hostname("github.com"));
        assert!(!is_blocked_hostname("api.example.com"));
    }

    #[test]
    fn validate_url_scheme_and_host() {
        assert!(validate_url("https://github.com").is_ok());
        assert!(validate_url("http://8.8.8.8").is_ok());
        // scheme
        assert!(validate_url("file:///etc/passwd").is_err());
        assert!(validate_url("ftp://example.com").is_err());
        assert!(validate_url("gopher://example.com").is_err());
        // IP 字面量
        assert!(validate_url("http://127.0.0.1").is_err());
        assert!(validate_url("http://169.254.169.254").is_err());
        assert!(validate_url("http://10.0.0.1:8080/status").is_err());
        // 域名保留后缀
        assert!(validate_url("http://localhost:9200").is_err());
        assert!(validate_url("http://smb.internal").is_err());
        // 缺主机名：`http://`（空 authority）应被拒绝；注意 `http:///path` 会被 url 库
        // 规范化为 host="path" 的合法域名，故缺主机名用例需用真正无 authority 的形式。
        assert!(validate_url("http://").is_err());
        assert!(validate_url("https://:443").is_err());
    }

    // ---------- 补充覆盖：补齐各阻断地址段分支 / 主机名后缀 / validate_url 边界 ----------

    #[test]
    fn blocked_ipv4_remaining_ranges() {
        // 192.0.0.0/24（IETF 协议分配）
        assert!(is_blocked_ipv4("192.0.0.1".parse().unwrap()));
        // 198.18.0.0/15（基准测试）
        assert!(is_blocked_ipv4("198.18.0.1".parse().unwrap()));
        assert!(is_blocked_ipv4("198.19.255.255".parse().unwrap()));
        // 198.51.100.0/24（TEST-NET-2）
        assert!(is_blocked_ipv4("198.51.100.7".parse().unwrap()));
        // 203.0.113.0/24（TEST-NET-3）
        assert!(is_blocked_ipv4("203.0.113.9".parse().unwrap()));
        // 224.0.0.0/4 组播
        assert!(is_blocked_ipv4("224.0.0.1".parse().unwrap()));
        assert!(is_blocked_ipv4("239.255.255.255".parse().unwrap()));
        // 240.0.0.0/4 保留
        assert!(is_blocked_ipv4("240.0.0.1".parse().unwrap()));
        assert!(is_blocked_ipv4("255.255.255.255".parse().unwrap()));
    }

    #[test]
    fn blocked_ipv6_remaining_ranges() {
        // ff00::/8 组播（当前用例只覆盖到 fc00/fe80/2001:db8）
        assert!(is_blocked_ipv6("ff02::1".parse().unwrap()));
        assert!(is_blocked_ipv6("ff01::1".parse().unwrap()));
        // IPv4 映射的**公开**地址不应被误判（仅当底层 v4 命中阻断段时才拦截）
        assert!(!is_blocked_ip("::ffff:8.8.8.8".parse().unwrap()));
        // 未映射的普通 V6 环回：走 is_blocked_ip 的 V6 分支
        assert!(is_blocked_ip("::1".parse().unwrap()));
    }

    #[test]
    fn blocked_hostname_remaining_suffixes() {
        // 其余保留后缀
        assert!(is_blocked_hostname("host.localdomain"));
        assert!(is_blocked_hostname("nas.lan"));
        assert!(is_blocked_hostname("printer.home.arpa"));
        assert!(is_blocked_hostname("intranet.test"));
        assert!(is_blocked_hostname("docs.example"));
        // 精确匹配 + 大小写不敏感 + 结尾点剥离
        assert!(is_blocked_hostname("LOCALHOST"));
        assert!(is_blocked_hostname("localhost."));
        assert!(is_blocked_hostname("SVC.LOCAL"));
        // 非保留正常域名仍放行
        assert!(!is_blocked_hostname("www.qq.com"));
        assert!(!is_blocked_hostname("a.internal-x.com")); // 仅子串不算后缀
    }

    #[test]
    fn validate_url_remaining_branches() {
        // 公开 IP + 端口 + 路径 → 放行
        assert!(validate_url("http://8.8.8.8:8080/health?x=1").is_ok());
        // 阻断段内 IP 字面量 → 拒绝
        assert!(validate_url("http://192.0.0.1").is_err());
        assert!(validate_url("http://198.18.0.1").is_err());
        assert!(validate_url("http://198.51.100.1").is_err());
        assert!(validate_url("http://203.0.113.1").is_err());
        assert!(validate_url("http://224.0.0.1").is_err());
        assert!(validate_url("http://240.0.0.1").is_err());
        // IPv6 字面量：公开放行 / 环回拒绝
        assert!(validate_url("http://[2606:4700:4700::1111]").is_ok());
        assert!(validate_url("http://[::1]").is_err());
        assert!(validate_url("http://[fe80::1]").is_err());
    }

    #[tokio::test]
    async fn validate_host_resolution_blocks_localhost() {
        // localhost 解析到环回（127.0.0.1 / ::1）应被拒绝；即使个别环境解析失败
        // （返回 Err "DNS 解析失败"）结果同样为 Err，故本断言在任何环境下均稳定。
        let res = validate_host_resolution("localhost", 80).await;
        assert!(res.is_err(), "localhost 应命中环回拦截，实际 Ok: {res:?}");
    }
}
