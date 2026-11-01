//! SSRF 防护模块（服务器端请求伪造防护）
//!
//! 适用范围：在线 HTTP 调试器（/tool/http-debug）、以及任何需要「由服务端发起出站 HTTP 请求」
//! 且目标 URL 由用户/客户端输入的功能。核心目标是阻止攻击者利用该能力访问内网资源
//! （云元数据端点 169.254.169.254、127.0.0.1、内网 IP 段、保留地址等）。
//!
//! 双层校验（**URL 由调用方逐次伪造**的入口，如在线 HTTP 调试器）：
//!   1. [`validate_url`]：静态校验（不依赖 DNS）——仅允许 http/https；主机名为 IP 字面量时
//!      直接判断是否命中阻断地址段；主机额为域名时使用保留域名后缀黑名单（无法解析/解析
//!      到内网的域名通常不会落在这些后缀下）。
//!   2. [`validate_host_resolution`]：动态校验——真实解析主机名全部 A/AAAA 地址，只要有一个
//!      命中阻断地址段即拒绝（防止目标域名解析到内网）。
//!
//! ## 第二个入口：投递网关（B1）——判据**刻意不同**
//! 消息渠道的 `gateway_url` / `endpoint` 与 IM 机器人的 `webhookUrl` 不是"逐次伪造的 URL"，
//! 而是**管理员写下的存量配置**，而本项目定位是开源自托管：「网关就跑在内网/本机 sidecar」
//! 是主流形态（本仓集成测试正是 `http://127.0.0.1:{port}`）。拿上面那把尺判它，等于把这项
//! 能力对自托管用户整块砍掉。于是这一族只用三条更窄的判据：
//!   1. [`validate_gateway_url_static`]：scheme / 主机名 / 保留后缀同前，但地址段判据换成
//!      [`is_never_gateway_ip`]（只封"任何真实网关都不可能在的位置"：链路本地＝云元数据端点、
//!      [`is_never_gateway_ip`]（只封"任何真实网关都不可能在的位置"：链路本地＝云元数据端点、
//!      未指定段，以及它们的 IPv4-mapped 形态）；
//!   2. [`guard_gateway_url`]：再过一层 DNS（域名解析到元数据段同样拒；解析不了 ⇒ 拒）；
//!   3. [`may_follow_redirect`]：**跳转目标**仍受同主机 + 同一套地址判据约束——前两层判的
//!      都是配置里那个 URL，而 `Location` 头是上一跳给的，那里才是凭据外流的真正出口。
//!
//! 三者的分工由 `the_two_scales_differ_exactly_where_designed` 钉住（"内网必须放、元数据
//! 必须拒"两侧都是判据，缺任何一侧都会被"顺手统一成一把尺"破坏）。
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

/// 「不可能是合法服务地址」的段：**永远**阻断，与部署形态无关。
///
/// 与 [`is_blocked_ip`] 的分工（两条判据刻意不同宽窄，各自服务一个入口）：
/// - `is_blocked_ip` 是"HTTP 调试器"那种**任意 URL 由用户逐次伪造**的入口用的，
///   内网/环回全部拒绝；
/// - 消息网关与机器人 WebHook 的 URL 是**管理员写下的存量配置**，本项目定位是
///   开源自托管，"网关就部署在内网/本机 sidecar"是**主流形态**（本仓集成测试正是
///   `http://127.0.0.1:{port}`）。拿 `is_blocked_ip` 去判它，等于把这项能力对
///   自托管用户砍掉（AGENTS 项目定位：不得为"收益低"整块砍功能）。
///
/// 因此这一层只封"任何真实网关都不可能在的位置"：
/// - `169.254.0.0/16` 链路本地——含 AWS/GCP/Azure/OpenStack 的**元数据端点**
///   `169.254.169.254`，这是 SSRF 的头号目标；
/// - `fe80::/10` 同上（IPv6 链路本地）；
/// - `0.0.0.0/8` 与 `::` 未指定地址（`http://[::]:80` 实际连的是本机，语义含糊且
///   是常见绕过写法）；
/// - IPv4 映射到 IPv6 的 `::ffff:169.254.*`（由 `to_ipv4_mapped` 归一后再判）。
pub fn is_never_gateway_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_link_local() || v4.octets()[0] == 0,
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return v4.is_link_local() || v4.octets()[0] == 0;
            }
            v6.is_unspecified() || (v6.segments()[0] & 0xfe_c0) == 0xfe80
        }
    }
}

/// 消息网关 / 机器人 WebHook 的**静态**校验（不解析 DNS）。
///
/// 复用 `validate_url` 的"仅 http/https + 必须有主机名 + 保留域名后缀"这三条，
/// 但地址段判据换成 [`is_never_gateway_ip`]（理由见该函数注释）。
/// 域名形态的主机要到 [`guard_gateway_url`] 里解析后才能判，所以调用方必须用
/// `guard_gateway_url`（它会先跑本函数再跑 DNS 层）。
pub fn validate_gateway_url_static(url_str: &str) -> Result<url::Url, String> {
    let parsed = url::Url::parse(url_str).map_err(|e| format!("URL 格式非法：{e}"))?;
    if !ALLOWED_SCHEMES.contains(&parsed.scheme()) {
        return Err(format!(
            "网关地址仅允许 http/https 协议，收到 {}",
            parsed.scheme()
        ));
    }
    match parsed.host() {
        Some(url::Host::Ipv4(v4)) if is_never_gateway_ip(IpAddr::V4(v4)) => {
            Err(format!("网关地址不得指向链路本地/元数据段 {v4}"))
        }
        Some(url::Host::Ipv6(v6)) if is_never_gateway_ip(IpAddr::V6(v6)) => {
            Err(format!("网关地址不得指向链路本地/未指定段 {v6}"))
        }
        Some(url::Host::Domain(domain)) => {
            if is_blocked_hostname(domain) {
                return Err(format!("禁止访问保留域名后缀 {domain}"));
            }
            Ok(parsed)
        }
        // IP 字面量且不属"永不可用"段 ⇒ 放行（内网网关是本项目的合法部署形态）
        Some(_) => Ok(parsed),
        None => Err("网关地址缺少主机名".to_string()),
    }
}

/// 一批 DNS 解析结果里第一个「永不可用」的地址（纯函数，`guard_gateway_url` 的 DNS 层判据）。
///
/// 抽出来的理由：DNS 层的结果由解析器给，测试环境里要么解析成功要么失败——
/// 拿真实域名去断"解析到元数据段必须拦"是**与环境耦合**的判据（AGENTS 测试门禁 ④）。
/// 把"拿到一组地址之后怎么判"做成纯函数，元数据段这一支就能确定性地判住。
pub fn first_never_gateway_ip(addrs: impl IntoIterator<Item = IpAddr>) -> Option<IpAddr> {
    addrs.into_iter().find(|ip| is_never_gateway_ip(*ip))
}

/// 网关地址的完整守卫：静态层 + DNS 层（域名解析到元数据段同样拒）。
///
/// DNS 层失败（解析不了）一律**拒绝**（fail-closed，与 `validate_host_resolution` 同向）：
/// 一个连解析都过不了的网关地址，投递必然失败，早报比让 SMTP/HTTP 挂 15s 好。
pub async fn guard_gateway_url(url_str: &str) -> Result<(), String> {
    let parsed = validate_gateway_url_static(url_str)?;
    let Some(host) = parsed.host_str() else {
        return Err("网关地址缺少主机名".to_string());
    };
    // IP 字面量已在静态层判完，无需解析
    if host.parse::<IpAddr>().is_ok() {
        return Ok(());
    }
    let port = parsed.port_or_known_default().unwrap_or(443);
    let addrs: Vec<IpAddr> = tokio::net::lookup_host((host, port))
        .await
        .map_err(|e| format!("网关主机 DNS 解析失败：{host}（{e}）"))?
        .map(|sa| sa.ip())
        .collect();
    if addrs.is_empty() {
        // 解析"成功"但一条地址都没有：连不上是既定事实，早报比让 HTTP 层挂到超时好
        return Err(format!("网关主机未解析到任何地址：{host}"));
    }
    match first_never_gateway_ip(addrs) {
        Some(ip) => Err(format!(
            "网关 {host} 解析到链路本地/元数据地址 {ip}，已拦截"
        )),
        None => Ok(()),
    }
}

/// 出站重定向**是否允许跟随**：只允许「跳到当初配置的那台主机」，并沿用同一套
/// 「永不可用地址」判据挡掉跳转目标是元数据段的情形。
///
/// 为什么需要它（B1 真正的洞在这里）：`reqwest` 默认跟随至多 10 次重定向，而重定向目标
/// **完全由上一跳的 `Location` 头决定**。管理员把 `gateway_url` 填成自己的网关（合法形态），
/// 那个网关（或它前面的反向代理、或被劫持的链路）只要回一个
/// `302 Location: http://169.254.169.254/latest/meta-data/...`，投递客户端就会**带着鉴权头**
/// 自己去敲元数据端点——静态层与 DNS 层都看不见这一跳，因为它们判的是**配置里**那个 URL。
///
/// 判据取"与**最初**配置的地址同主机"而不是"与上一跳同主机"：后者允许 `A→B→C` 逐跳漂移，
/// 一次跨主机跳转就把凭据交到非预期机器手上（SSRF 的重定向绕过正是这条链）。
///
/// 刻意**不比 origin（scheme+host+port）**，只比主机：自托管网关最常见的合法跳转是
/// `http://gw` → `https://gw`（以及换到 TLS 端口），拿严格 origin 判它等于把这条真实
/// 部署形态砍掉（AGENTS 项目定位）。主机不变 ⇒ 凭据不会出这台机器；跨主机才是要封的那一步。
///
/// 拒绝时 reqwest 把 3xx 响应**原样返回**（不是错误），因此调用方现有的
/// `status.is_success()` 判据会把它落成可见的投递失败并留痕——不是静默降级。
pub fn may_follow_redirect(base: &url::Url, target: &url::Url) -> bool {
    // 取不到主机名（结构上不该发生，但 url 库对某些非特殊 scheme 会给 None）⇒ 拒绝
    let (Some(b), Some(t)) = (base.host_str(), target.host_str()) else {
        return false;
    };
    if b != t {
        return false;
    }
    // 同主机仍可能是"字面量元数据地址"（`http://169.254.169.254` 跳到
    // `http://169.254.169.254/other`）：跳转目标必须再过一次静态层的那条 IP 判据。
    // 用 `host()` 枚举而不是 `host_str().parse()`——IPv6 字面量在 `host_str()` 里带方括号，
    // `"[fe80::1]".parse::<IpAddr>()` 失败会让这一支**静默放行**（与 validate_url 同源教训）。
    match target.host() {
        Some(url::Host::Ipv4(v4)) => !is_never_gateway_ip(IpAddr::V4(v4)),
        Some(url::Host::Ipv6(v6)) => !is_never_gateway_ip(IpAddr::V6(v6)),
        _ => true,
    }
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

    // ---------- B1：消息网关 / IM 机器人 WebHook 的地址守卫 ----------

    /// 两条尺的**分工**必须被钉住（这是本批最容易"顺手统一"的地方）：
    /// `is_blocked_ip` 给"URL 由调用方逐次伪造"的 HTTP 调试器用（内网全拒）；
    /// `is_never_gateway_ip` 给"URL 是管理员存量配置"的投递网关用（内网放行、元数据段永拒）。
    /// 拿前者判网关 = 把自托管能力整块砍掉（AGENTS 项目定位）；拿后者判调试器 = 内网全裸。
    #[test]
    fn the_two_scales_differ_exactly_where_designed() {
        // 内网/环回：调试器尺拒、网关尺放（对照组——证明网关尺不是"恒放行"）
        for internal in ["10.0.0.1", "127.0.0.1", "172.16.5.5", "192.168.1.10"] {
            let ip: IpAddr = internal.parse().unwrap();
            assert!(is_blocked_ip(ip), "调试器尺必须拒内网 {internal}");
            assert!(
                !is_never_gateway_ip(ip),
                "网关尺必须放行内网自托管形态 {internal}（拒它就是砍功能）"
            );
        }
        // 元数据/链路本地：两把尺都必须拒
        for never in ["169.254.169.254", "169.254.1.1", "0.0.0.0"] {
            let ip: IpAddr = never.parse().unwrap();
            assert!(is_blocked_ip(ip), "{never} 本就被通用尺拒");
            assert!(is_never_gateway_ip(ip), "{never} 必须被网关尺拒");
        }
        // 公网：两把尺都放（网关尺不是"只放内网"）
        assert!(!is_never_gateway_ip("93.184.216.34".parse().unwrap()));
    }

    /// IPv6 与 IPv4 映射形态同样必须命中"永不可用"段（`::ffff:169.254.*` 是经典绕过写法）
    #[test]
    fn never_gateway_covers_ipv6_and_mapped_forms() {
        assert!(is_never_gateway_ip("fe80::1".parse().unwrap()));
        assert!(is_never_gateway_ip("febf::1".parse().unwrap())); // fe80::/10 上界
        assert!(is_never_gateway_ip("::".parse().unwrap()));
        assert!(is_never_gateway_ip(
            "::ffff:169.254.169.254".parse().unwrap()
        ));
        assert!(is_never_gateway_ip("::ffff:0.0.0.1".parse().unwrap()));
        // 反例：fc00::/7（ULA，自托管合法）、环回、合法链路本地之外的公网 v6
        assert!(!is_never_gateway_ip("fc00::1".parse().unwrap()));
        assert!(!is_never_gateway_ip("fd12::34".parse().unwrap()));
        assert!(!is_never_gateway_ip("::1".parse().unwrap()));
        assert!(!is_never_gateway_ip(
            "2606:4700:4700::1111".parse().unwrap()
        ));
        // fec0:: 属旧 site-local，已不属于 fe80::/10 ⇒ 不拦（按 RFC 4291 的 /10 边界判，
        // 这条反证专门钉住掩码写法：`(seg & 0xfe00) == 0xfe00` 之类写错会把它一并拦掉）
        assert!(!is_never_gateway_ip("fec0::1".parse().unwrap()));
    }

    /// DNS 层判据本体（纯函数，不依赖解析器）：混合定向里必须揪出元数据那一条
    #[test]
    fn dns_layer_branch_is_deterministic() {
        let mixed: [IpAddr; 2] = [
            "93.184.216.34".parse().unwrap(),
            "169.254.169.254".parse().unwrap(),
        ];
        assert_eq!(
            first_never_gateway_ip(mixed),
            Some("169.254.169.254".parse::<IpAddr>().unwrap()),
            "域名解析到元数据段必须被拦（与 IP 字面量同判据）"
        );
        let fine: [IpAddr; 2] = ["8.8.8.8".parse().unwrap(), "10.0.0.5".parse().unwrap()];
        assert_eq!(
            first_never_gateway_ip(fine),
            None,
            "公网 + 内网网关的混合定向必须放行（自托管多栈形态合法）"
        );
        let empty: [IpAddr; 0] = [];
        assert_eq!(
            first_never_gateway_ip(empty),
            None,
            "空集合本身不是「命中」——空集合的拒绝由 guard_gateway_url 单独那一支负责"
        );
    }

    /// 静态层：scheme / 元数据段 / 保留后缀都拒，内网与公网网关都放
    #[test]
    fn gateway_static_scale_branches() {
        // 拒绝：非 http(s)
        for bad in [
            "ftp://gw.example.com/send",
            "file:///etc/passwd",
            "gopher://127.0.0.1:6379",
        ] {
            assert!(
                validate_gateway_url_static(bad).is_err(),
                "非 http(s) 网关地址必须拒：{bad}"
            );
        }
        // 拒绝：永不可用段（v4 / v6 / 未指定）
        for never in [
            "http://169.254.169.254/latest/meta-data/",
            "http://0.0.0.0:8080/send",
            "http://[fe80::1]/send",
            "http://[::]/send",
        ] {
            assert!(
                validate_gateway_url_static(never).is_err(),
                "元数据/链路本地/未指定地址必须拒：{never}"
            );
        }
        // 拒绝：保留域名后缀（与调试器同一份名单）
        assert!(validate_gateway_url_static("http://localhost:9200/send").is_err());
        assert!(validate_gateway_url_static("http://sms.svc.local/send").is_err());
        // 拒绝：缺主机名
        assert!(validate_gateway_url_static("http://").is_err());
        assert!(validate_gateway_url_static("https://:443").is_err());
        // 拒绝：不是 URL
        assert!(validate_gateway_url_static("not a url").is_err());

        // 对照组（**必须放行**，否则等于砍掉自托管）：内网/环回网关
        for internal in [
            "http://127.0.0.1:8081/send",
            "http://10.0.0.1:8080/status",
            "https://192.168.1.10/sms",
            "http://[::1]:9000/hook",
        ] {
            assert!(
                validate_gateway_url_static(internal).is_ok(),
                "内网/环回是自托管主流部署，网关尺必须放行：{internal}"
            );
        }
        // 对照组：公网厂商网关
        for public in [
            "https://open.feishu.cn/open-apis/bot/v2/hook/abc",
            "https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=x",
            "https://oapi.dingtalk.com/robot/send?access_token=y",
        ] {
            assert!(
                validate_gateway_url_static(public).is_ok(),
                "厂商网关地址必须放行：{public}"
            );
        }
    }

    /// C.9：错误串会被写进 `tracing::warn!`，因此**不得**回显带凭据的那一段。
    ///
    /// 厂商 webhook URL 的 `?key=` / `?access_token=` 本身就是凭据，而"URL 不合法"这类
    /// 提示天然想"把原话贴出来给人看"——那一句就是一次凭据落日志。
    #[test]
    fn gateway_errors_never_echo_credentials() {
        let secret = "SUPERSECRETtoken123";
        let cases = [
            format!("ftp://gw.example.com/send?access_token={secret}"),
            format!("http://169.254.169.254/latest?access_token={secret}"),
            format!("http://localhost:9200/?key={secret}"),
        ];
        for raw in cases {
            let err = validate_gateway_url_static(&raw).unwrap_err();
            assert!(
                !err.contains(secret),
                "错误串不得带出查询串里的凭据（它会进日志）：{err}"
            );
            assert!(!err.contains("SUPERSECRET"), "错误串不得带出凭据：{err}");
        }
    }

    /// 完整守卫：IP 字面量走静态层即定（不碰 DNS），域名走 DNS 层。
    ///
    /// `.invalid` 是 RFC 6761 保留的"永不解析"域；本断言在两种子状态下**都成立**：
    /// 解析器正常工作 ⇒ NXDOMAIN ⇒ Err；本机无网络/解析器不可用 ⇒ Err。
    /// 与 `validate_host_resolution_blocks_localhost` 同一条稳定性论证（AGENTS 测试门禁 ④）。
    #[tokio::test]
    async fn gateway_guard_is_fail_closed_for_domains() {
        assert!(
            guard_gateway_url("http://127.0.0.1:8081/send")
                .await
                .is_ok()
        );
        assert!(guard_gateway_url("http://169.254.169.254/").await.is_err());
        assert!(guard_gateway_url("ftp://10.0.0.1/send").await.is_err());
        assert!(
            guard_gateway_url("https://stepby-b144-nonexistent.invalid/send")
                .await
                .is_err(),
            "解析不过的网关主机必须 fail-closed（放行只是把失败推迟到 HTTP 超时）"
        );
    }

    /// 重定向判据（本批真正的洞）：跨主机一律停，同主机（含 http→https 升级）放行，
    /// 且跳转目标是元数据字面量时即使"主机相同"也停。
    #[test]
    fn redirects_may_stay_on_the_same_host_only() {
        let u = |s: &str| url::Url::parse(s).unwrap();
        // 放行：同主机换 scheme / 端口（自托管网关的合法形态）
        assert!(may_follow_redirect(
            &u("http://gw.internal/send"),
            &u("https://gw.internal/send")
        ));
        assert!(may_follow_redirect(
            &u("http://10.0.0.5:8080/a"),
            &u("http://10.0.0.5:8443/a")
        ));
        assert!(may_follow_redirect(
            &u("https://oapi.dingtalk.com/robot/send"),
            &u("https://oapi.dingtalk.com/robot/send?access_token=x")
        ));
        // 拒绝：跨主机（凭据外流 / SSRF pivot）
        assert!(
            !may_follow_redirect(&u("https://gw.internal/send"), &u("https://evil.example/")),
            "跨主机重定向必须停"
        );
        assert!(
            !may_follow_redirect(
                &u("https://gw.internal/send"),
                &u("http://169.254.169.254/")
            ),
            "跳到元数据端点必须停"
        );
        // 拒绝：同主机但目标是"永不可用"字面量（base 也填那个地址时）
        assert!(
            !may_follow_redirect(
                &u("http://169.254.169.254/a"),
                &u("http://169.254.169.254/latest/meta-data/")
            ),
            "同主机不等于可用：跳转目标仍要过永不可用段判据"
        );
        assert!(
            !may_follow_redirect(&u("http://[fe80::1]/a"), &u("http://[fe80::1]/b")),
            "IPv6 字面量同样要判（host_str 带方括号，parse 失败会静默放行）"
        );
        // 活性反证：判据真的在比主机，而不是恒真——把两个不同 URL 换一下必须变结论
        let base = u("https://a.example/send");
        assert!(may_follow_redirect(&base, &u("https://a.example/other")));
        assert!(!may_follow_redirect(&base, &u("https://b.example/other")));
    }
}
