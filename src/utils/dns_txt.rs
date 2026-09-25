// axum-backend/src/utils/dns_txt.rs
//! DNS TXT 记录解析（多租户 Phase 3 域名绑定：自定义域名 DNS TXT 验证）
//!
//! 用途：查询 `_yebot-verify.{domain}` 的 TXT 记录，比对平台下发的 `verify_token`，
//! 从而证明申请人对该域名拥有控制权（子域名由平台分配，走免验证分支，不经本模块）。
//!
//! 设计约束（**不新增第三方 DNS 依赖**）：
//! - 手写 DNS 报文（RFC 1035）：header + QNAME 标签编码 + QTYPE=TXT(16) + QCLASS=IN(1)；
//! - UDP 优先，收到 TC（截断）位则对同一解析器改用 TCP（2 字节长度前缀）重试；
//! - 应答解析支持**名称压缩指针**（0xC0 前缀）与单条 TXT 的**多字符段拼接**；
//! - rcode 语义：0=成功 / 3=NXDOMAIN（返回空列表，不报错）/ 其它（含 SERVFAIL=2）→ Err。
//!
//! 解析器来源（优先级）：
//! 1. 环境变量 `TENANT_DNS_RESOLVERS`（逗号分隔，`ip[:port]`，无端口默认 :53）；
//! 2. 否则读取 unix `/etc/resolv.conf` 的 `nameserver` 行；
//! 3. 都没有则用公共解析器兜底 `1.1.1.1:53`、`8.8.8.8:53`。
//!
//! 合规：不缓存、不主动上报查询结果（仅 service 层在验证失败时以 tracing::warn 记录截断后的值）。

use std::net::SocketAddr;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};

/// 兜底公共解析器（环境变量与 /etc/resolv.conf 均不可用时）
const DEFAULT_RESOLVERS: [&str; 2] = ["1.1.1.1:53", "8.8.8.8:53"];
/// DNS 记录类型 TXT
const DNS_TYPE_TXT: u16 = 16;
/// DNS 类 IN
const DNS_CLASS_IN: u16 = 1;
/// 单条 TXT 值回传上限（运维排查用的截断长度，防止畸形记录刷屏）
const TXT_VALUE_LOG_MAX: usize = 128;
/// UDP 接收缓冲（RFC 1035 经典 512，这里放宽到 4096 以容纳较大 TXT 应答）
const UDP_RECV_BUF: usize = 4096;

/// DNS 查询错误（超时 / 传输 / 报文 / 服务器 rcode）
#[derive(Debug, thiserror::Error)]
pub enum DnsError {
    /// 所有解析器均在超时时间内未应答
    #[error("DNS 查询超时")]
    Timeout,
    /// 底层 IO / socket 错误
    #[error("DNS 传输错误: {0}")]
    Io(String),
    /// 应答报文结构非法（越界 / 长度不匹配 / ID 不匹配等）
    #[error("DNS 报文错误: {0}")]
    Protocol(String),
    /// 服务器返回非 0/3 的 rcode（如 SERVFAIL=2 / REFUSED=5）
    #[error("DNS 服务器返回错误码 rcode={0}")]
    Rcode(u8),
}

/// 查询 `name` 的 TXT 记录，返回各 TXT 记录的值（单条记录内的多字符段已拼接去引号）。
///
/// 逐台解析器尝试，每台超时均为 `timeout`；NXDOMAIN 视为"无记录"返回空列表（不算失败）。
/// 全部解析器失败则返回最后一次错误。
pub async fn lookup_txt(name: &str, timeout: Duration) -> Result<Vec<String>, DnsError> {
    let resolvers = resolver_list();
    let id = rand::random::<u16>();
    let query = build_query(name, id);
    let mut last_err: Option<DnsError> = None;
    for resolver in &resolvers {
        match lookup_one(resolver, &query, id, timeout).await {
            Ok(values) => return Ok(values),
            Err(e) => {
                tracing::debug!(resolver = %resolver, name = %name, error = %e, "TXT 查询失败，尝试下一个解析器");
                last_err = Some(e);
            }
        }
    }
    Err(last_err.unwrap_or_else(|| DnsError::Io("无可用 DNS 解析器".to_string())))
}

/// 对单台解析器执行查询（UDP，TC 截断则 TCP 重试）
async fn lookup_one(
    resolver: &str,
    query: &[u8],
    id: u16,
    timeout: Duration,
) -> Result<Vec<String>, DnsError> {
    let addr = resolve_addr(resolver).await?;
    let udp = async {
        let bind = if addr.is_ipv6() {
            "[::]:0"
        } else {
            "0.0.0.0:0"
        };
        let socket = UdpSocket::bind(bind).await.map_err(io_err)?;
        socket.connect(addr).await.map_err(io_err)?;
        socket.send(query).await.map_err(io_err)?;
        let mut buf = [0u8; UDP_RECV_BUF];
        let n = socket.recv(&mut buf).await.map_err(io_err)?;
        Ok::<Vec<u8>, DnsError>(buf[..n].to_vec())
    };
    let resp = tokio::time::timeout(timeout, udp)
        .await
        .map_err(|_| DnsError::Timeout)??;
    if resp.len() < 12 {
        return Err(DnsError::Protocol("DNS 响应短于头部 12 字节".to_string()));
    }
    if u16::from_be_bytes([resp[0], resp[1]]) != id {
        return Err(DnsError::Protocol("DNS 响应 ID 不匹配".to_string()));
    }
    // TC（truncated）位置位：UDP 应答被截断，改用 TCP 完整重试
    if u16::from_be_bytes([resp[2], resp[3]]) & 0x0200 != 0 {
        tracing::debug!(resolver = %resolver, "DNS 应答 TC 置位，改用 TCP 重试");
        return lookup_one_tcp(addr, query, id, timeout).await;
    }
    parse_txt_response(&resp)
}

/// TCP 形态查询（2 字节长度前缀 + DNS 报文）
async fn lookup_one_tcp(
    addr: SocketAddr,
    query: &[u8],
    id: u16,
    timeout: Duration,
) -> Result<Vec<String>, DnsError> {
    let fut = async {
        let mut stream = TcpStream::connect(addr).await.map_err(io_err)?;
        let len = u16::try_from(query.len())
            .map_err(|_| DnsError::Protocol("DNS 查询报文过长".to_string()))?;
        stream.write_all(&len.to_be_bytes()).await.map_err(io_err)?;
        stream.write_all(query).await.map_err(io_err)?;
        let mut len_buf = [0u8; 2];
        stream.read_exact(&mut len_buf).await.map_err(io_err)?;
        let rlen = u16::from_be_bytes(len_buf) as usize;
        let mut buf = vec![0u8; rlen];
        stream.read_exact(&mut buf).await.map_err(io_err)?;
        Ok::<Vec<u8>, DnsError>(buf)
    };
    let resp = tokio::time::timeout(timeout, fut)
        .await
        .map_err(|_| DnsError::Timeout)??;
    if resp.len() < 12 {
        return Err(DnsError::Protocol("DNS 响应短于头部 12 字节".to_string()));
    }
    if u16::from_be_bytes([resp[0], resp[1]]) != id {
        return Err(DnsError::Protocol("DNS 响应 ID 不匹配".to_string()));
    }
    parse_txt_response(&resp)
}

/// 构造 TXT 查询报文（纯函数，便于单测）
///
/// 结构：12 字节 header（随机 id、RD=1、QDCOUNT=1）+ QNAME + QTYPE=16 + QCLASS=1。
pub fn build_query(name: &str, id: u16) -> Vec<u8> {
    let mut buf = Vec::with_capacity(name.len() + 16);
    buf.extend_from_slice(&id.to_be_bytes());
    // flags：QR=0 / RD=1（递归期望）
    buf.extend_from_slice(&0x0100u16.to_be_bytes());
    buf.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    buf.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT
    buf.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
    buf.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT
    for label in name.trim_end_matches('.').split('.') {
        if label.is_empty() {
            continue;
        }
        let bytes = label.as_bytes();
        // 单标签上限 63（超出截断，避免生成非法报文）
        let take = bytes.len().min(63);
        buf.push(take as u8);
        buf.extend_from_slice(&bytes[..take]);
    }
    buf.push(0); // 名称结束（root label）
    buf.extend_from_slice(&DNS_TYPE_TXT.to_be_bytes());
    buf.extend_from_slice(&DNS_CLASS_IN.to_be_bytes());
    buf
}

/// 解析 TXT 应答报文（纯函数，便于单测）
///
/// - 跳过问题段（支持名称压缩指针）；
/// - 遍历 answer RR，仅取 TYPE=TXT：按 `<len><bytes>` 逐字符段拼接（去首尾引号）；
/// - rcode=3（NXDOMAIN）→ 空列表；其它非 0 rcode → [`DnsError::Rcode`]。
pub fn parse_txt_response(buf: &[u8]) -> Result<Vec<String>, DnsError> {
    if buf.len() < 12 {
        return Err(DnsError::Protocol("DNS 响应短于头部 12 字节".to_string()));
    }
    let flags = u16::from_be_bytes([buf[2], buf[3]]);
    let rcode = (flags & 0x000F) as u8;
    match rcode {
        0 => {}
        // NXDOMAIN：域名不存在，等价于"无此 TXT 记录"，不算错误
        3 => return Ok(Vec::new()),
        other => return Err(DnsError::Rcode(other)),
    }
    let qdcount = u16::from_be_bytes([buf[4], buf[5]]) as usize;
    let ancount = u16::from_be_bytes([buf[6], buf[7]]) as usize;

    let mut pos = 12usize;
    for _ in 0..qdcount {
        pos = skip_name(buf, pos)?;
        pos = pos
            .checked_add(4)
            .filter(|&p| p <= buf.len())
            .ok_or_else(|| DnsError::Protocol("问题段越界".to_string()))?;
    }

    let mut values = Vec::new();
    for _ in 0..ancount {
        pos = skip_name(buf, pos)?;
        // RR 固定头：TYPE(2) + CLASS(2) + TTL(4) + RDLENGTH(2)
        let header_end = pos
            .checked_add(10)
            .filter(|&p| p <= buf.len())
            .ok_or_else(|| DnsError::Protocol("ANSWER 头越界".to_string()))?;
        let rtype = u16::from_be_bytes([buf[pos], buf[pos + 1]]);
        let rdlength = u16::from_be_bytes([buf[pos + 8], buf[pos + 9]]) as usize;
        let rdata_start = header_end;
        let rdata_end = rdata_start
            .checked_add(rdlength)
            .filter(|&p| p <= buf.len())
            .ok_or_else(|| DnsError::Protocol("RDATA 越界".to_string()))?;
        if rtype == DNS_TYPE_TXT {
            let mut value = String::new();
            let mut p = rdata_start;
            while p < rdata_end {
                let seg_len = buf[p] as usize;
                p += 1;
                let seg_end = p
                    .checked_add(seg_len)
                    .filter(|&e| e <= rdata_end)
                    .ok_or_else(|| DnsError::Protocol("TXT 字符段越界".to_string()))?;
                let seg = String::from_utf8_lossy(&buf[p..seg_end]);
                // 去首尾引号（DNS TXT 常以引号包裹），多字符段按 RFC 拼接为一条值
                value.push_str(seg.trim_matches('"'));
                p = seg_end;
            }
            values.push(value);
        }
        pos = rdata_end;
    }
    Ok(values)
}

/// 跳过 DNS 名称（标签序列或压缩指针），返回名称之后的偏移
fn skip_name(buf: &[u8], mut pos: usize) -> Result<usize, DnsError> {
    loop {
        let len = *buf
            .get(pos)
            .ok_or_else(|| DnsError::Protocol("名称越界".to_string()))?;
        match len & 0xC0 {
            0xC0 => {
                // 压缩指针：2 字节即结束（指针目标无需跟随，仅跳过名称）
                return pos
                    .checked_add(2)
                    .filter(|&p| p <= buf.len())
                    .ok_or_else(|| DnsError::Protocol("名称压缩指针越界".to_string()));
            }
            0x00 => {
                pos += 1;
                if len == 0 {
                    return Ok(pos);
                }
                pos = pos
                    .checked_add(len as usize)
                    .filter(|&p| p <= buf.len())
                    .ok_or_else(|| DnsError::Protocol("名称标签越界".to_string()))?;
            }
            _ => return Err(DnsError::Protocol("非法名称标签长度".to_string())),
        }
    }
}

/// 解析器地址（`ip[:port]`）
async fn resolve_addr(resolver: &str) -> Result<SocketAddr, DnsError> {
    tokio::net::lookup_host(resolver)
        .await
        .map_err(io_err)?
        .next()
        .ok_or_else(|| DnsError::Io(format!("无法解析 DNS 解析器地址: {resolver}")))
}

/// 解析器列表（环境变量 → /etc/resolv.conf → 公共兜底）
fn resolver_list() -> Vec<String> {
    if let Ok(raw) = std::env::var("TENANT_DNS_RESOLVERS") {
        let list: Vec<String> = raw.split(',').filter_map(normalize_resolver).collect();
        if !list.is_empty() {
            return list;
        }
    }
    let from_conf = std::fs::read_to_string("/etc/resolv.conf")
        .map(|c| parse_resolv_conf(&c))
        .unwrap_or_default();
    if !from_conf.is_empty() {
        return from_conf;
    }
    DEFAULT_RESOLVERS.iter().map(|s| s.to_string()).collect()
}

/// 规范化单个解析器条目：裸 IP 补默认端口 53，带端口原样保留
fn normalize_resolver(entry: &str) -> Option<String> {
    let s = entry.trim();
    if s.is_empty() {
        return None;
    }
    // 裸 IPv4 / IPv6 地址
    if s.parse::<std::net::IpAddr>().is_ok() {
        return Some(format!("{s}:53"));
    }
    // [IPv6]:port 或 [IPv6]
    if let Some(rest) = s.strip_prefix('[') {
        return Some(if rest.contains("]:") {
            s.to_string()
        } else {
            format!("{s}:53")
        });
    }
    // IPv4:port（含且仅含一个冒号）
    if s.matches(':').count() == 1 {
        return Some(s.to_string());
    }
    // 其它形式（如 IPv6:port 未加方括号）原样透出，交由 lookup_host 解析
    Some(s.to_string())
}

/// 解析 `/etc/resolv.conf` 的 `nameserver` 行
fn parse_resolv_conf(content: &str) -> Vec<String> {
    content
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#') && !l.starts_with(';'))
        .filter_map(|l| {
            let mut parts = l.split_whitespace();
            if parts.next() != Some("nameserver") {
                return None;
            }
            parts.next().and_then(normalize_resolver)
        })
        .collect()
}

/// 把 `std::io::Error` 收敛为 [`DnsError::Io`]
fn io_err(e: std::io::Error) -> DnsError {
    DnsError::Io(e.to_string())
}

/// 截断 TXT 值用于日志（防止畸形记录刷屏；按字符边界安全截断）
pub fn truncate_txt_for_log(value: &str) -> String {
    match value.char_indices().nth(TXT_VALUE_LOG_MAX) {
        Some((idx, _)) => format!("{}…（已截断）", &value[..idx]),
        None => value.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 手工构造一条应答：question + 1 条 answer（名称用压缩指针，TXT 含多字符段）
    fn sample_response(id: u16, flags: u16, txt_segments: &[&[u8]]) -> Vec<u8> {
        let mut resp = Vec::new();
        resp.extend_from_slice(&id.to_be_bytes()); // ID
        resp.extend_from_slice(&flags.to_be_bytes()); // FLAGS
        resp.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
        resp.extend_from_slice(&1u16.to_be_bytes()); // ANCOUNT
        resp.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
        resp.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT
        // question：a.example.com（起始偏移 12）
        resp.push(1);
        resp.extend_from_slice(b"a");
        resp.push(7);
        resp.extend_from_slice(b"example");
        resp.push(3);
        resp.extend_from_slice(b"com");
        resp.push(0);
        resp.extend_from_slice(&DNS_TYPE_TXT.to_be_bytes());
        resp.extend_from_slice(&DNS_CLASS_IN.to_be_bytes());
        // answer：名称 = 指向偏移 12 的压缩指针 0xC0 0x0C
        resp.push(0xC0);
        resp.push(0x0C);
        resp.extend_from_slice(&DNS_TYPE_TXT.to_be_bytes());
        resp.extend_from_slice(&DNS_CLASS_IN.to_be_bytes());
        resp.extend_from_slice(&0u32.to_be_bytes()); // TTL
        let rdata_len: usize = txt_segments.iter().map(|s| 1 + s.len()).sum();
        resp.extend_from_slice(&(rdata_len as u16).to_be_bytes());
        for seg in txt_segments {
            resp.push(seg.len() as u8);
            resp.extend_from_slice(seg);
        }
        resp
    }

    #[test]
    fn test_build_query_encodes_labels_and_qtype_txt() {
        let q = build_query("_yebot-verify.example.com", 0x1234);
        // header：id=0x1234, flags=0x0100, qd=1, an=0, ns=0, ar=0
        assert_eq!(&q[0..2], &[0x12, 0x34]);
        assert_eq!(&q[2..4], &[0x01, 0x00]);
        assert_eq!(&q[4..6], &[0x00, 0x01]);
        assert_eq!(&q[6..12], &[0, 0, 0, 0, 0, 0]);
        // 首标签 "_yebot-verify"（13 字节）
        assert_eq!(q[12], 13);
        assert_eq!(&q[13..26], b"_yebot-verify");
        // 名称以 0 结束，随后 QTYPE=16 / QCLASS=1
        let qtype_pos = q.len() - 4;
        assert_eq!(q[qtype_pos - 1], 0, "名称须以 root label 结束");
        assert_eq!(&q[qtype_pos..qtype_pos + 2], &[0x00, 0x10]);
        assert_eq!(&q[qtype_pos + 2..], &[0x00, 0x01]);
    }

    #[test]
    fn test_parse_compressed_multi_string_txt() {
        // 压缩指针（answer name = 0xC00C）+ 单条 TXT 多字符段拼接
        let resp = sample_response(0x1234, 0x8180, &[b"hello", b"world"]);
        let values = parse_txt_response(&resp).expect("应解析成功");
        assert_eq!(values, vec!["helloworld".to_string()]);
    }

    #[test]
    fn test_parse_strips_quotes() {
        let resp = sample_response(0x0001, 0x8180, &[b"\"tok-abc123\""]);
        let values = parse_txt_response(&resp).expect("应解析成功");
        assert_eq!(values, vec!["tok-abc123".to_string()]);
    }

    #[test]
    fn test_parse_nxdomain_is_empty_ok() {
        // rcode=3（NXDOMAIN）：返回空列表而非错误
        let resp = sample_response(0x0002, 0x8183, &[]);
        assert!(parse_txt_response(&resp).unwrap().is_empty());
    }

    #[test]
    fn test_parse_servfail_is_error() {
        // rcode=2（SERVFAIL）：必须报错
        let resp = sample_response(0x0003, 0x8182, &[]);
        assert!(matches!(parse_txt_response(&resp), Err(DnsError::Rcode(2))));
    }

    #[test]
    fn test_parse_truncated_response_is_error() {
        assert!(parse_txt_response(&[0u8; 8]).is_err());
        // 头部完整但 ANSWER RDATA 越界
        let mut resp = sample_response(0x0004, 0x8180, &[b"abcdef"]);
        resp.truncate(resp.len() - 2);
        assert!(parse_txt_response(&resp).is_err());
    }

    #[test]
    fn test_parse_resolv_conf() {
        let conf = "# comment\nnameserver 10.0.0.1\n; semicolon\nnameserver 2001:db8::1\nbadline\n";
        assert_eq!(
            parse_resolv_conf(conf),
            vec!["10.0.0.1:53".to_string(), "2001:db8::1:53".to_string()]
        );
    }

    #[test]
    fn test_normalize_resolver() {
        assert_eq!(normalize_resolver("1.1.1.1").unwrap(), "1.1.1.1:53");
        assert_eq!(normalize_resolver("1.1.1.1:5353").unwrap(), "1.1.1.1:5353");
        assert_eq!(normalize_resolver(" 8.8.8.8 ").unwrap(), "8.8.8.8:53");
        assert_eq!(normalize_resolver("::1").unwrap(), "::1:53");
        assert_eq!(normalize_resolver("[::1]:5353").unwrap(), "[::1]:5353");
        assert!(normalize_resolver("   ").is_none());
    }

    #[test]
    fn test_truncate_txt_for_log() {
        assert_eq!(truncate_txt_for_log("short"), "short");
        let long = "x".repeat(300);
        assert!(truncate_txt_for_log(&long).len() < long.len());
    }
}
