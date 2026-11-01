//! 出站**错误响应体**的读取、遮蔽与截断（b145 · N-144-J）。
//!
//! # 立的案
//!
//! 改造前 11 处写的是 `resp.text().await.unwrap_or_default()`。`unwrap_or_default()` 把
//! "我没把响应体读出来"折叠成空串，于是
//!
//! ```text
//! 短信网关返回 403:            ← 依赖到底说了什么，一个字都没有
//! S3 返回错误状态 403:
//! ```
//!
//! 运维只剩"HTTP 4xx"可看，而依赖给的理由（配额用尽 / 凭据无效 / 地区限制 / bucket 策略）
//! 恰好在这些字符串里。这一族不改变程序判定，只削减**可诊断性**。
//!
//! # 三条口径，每条都有理由，且都是复用而不是新写
//!
//! 1. **"读失败"与"响应体为空"必须可区分**（AGENTS ㊷）。两条哨兵，不是一条：
//!    [`EMPTY_BODY_SENTINEL`] 只在读成功且长度为 0 时用；[`unreadable_sentinel`] 带失败原因。
//!    把它们合成一条，就等于在本判据的产地上重新长出本判据要修的那个洞。
//! 2. **遮蔽复用 `common::redact`**：绝对路径折叠（C.9，b73 那课的延伸——依赖的错误体会
//!    回显我们发出去的 URL，里面可能有部署目录）+ 查询值遮蔽（b132 同一函数）。
//!    `middleware::oper_log::sanitize_response_body` **只在文本是 JSON 时**套用：它的形状是
//!    "我们自己的 `AjaxResult` 响应体"，对非 JSON 一律回 `REDACTED_BODY`。S3/MaxMind/网关的
//!    错误体绝大多数是 XML 与 HTML —— 无脑套用会把 `AccessDenied` 整段洗成一句红话，
//!    那是把"故障"折成"看不见"的第二副样子，与本模块要修的缺陷同族。
//! 3. **截断复用 `middleware::oper_log::safe_truncate`**（字节口径 + `...(truncated)` 标记）。
//!    改造前三档手搓：`chars().take(120)`、`chars().take(200)`、以及 `ip_location` 的**完全不截断**
//!    （MaxMind 的 HTML 错误页整页进 anyhow 消息）。取最严那一档的字节等价：480 字节 ⇒
//!    至少 120 个 ASCII 字符、至少 160 个 CJK 字符，不宽于原先最严的 120 字符，
//!    且不新增第三种截断实现（AGENTS ㉘）。
//!
//! # 刻意不做
//!
//! 出站指标（`observability::metrics::record_outbound`）的 `outcome` 是
//! `ok|error|timeout|panic|rejected` 的**封闭词表**，没有任何自由文本槽位；
//! 把错误体摘要塞进去会造成 Prometheus 标签基数爆炸。所以本通道的产物只进**日志与错误消息**，
//! 指标侧维持既有口径（b144 §7 那句"共用 reason 字段"经取证不成立，按实登记于台账 b145 §3.4）。

use reqwest::Response;

use crate::common::redact;
use crate::middleware::oper_log;

/// 上游确实给了一个空响应体（读成功、长度为 0）。
pub const EMPTY_BODY_SENTINEL: &str = "（响应体为空）";

/// 响应体摘要的字节上限（见模块头的第 3 条口径）。
pub const MAX_BODY_SNIPPET_BYTES: usize = 480;

/// 单次最多读多少字节的上游响应体。
///
/// 必须有硬上限：一个 4xx 的 HTML 错误页可以是大几十 MB，`text()` 会整段进内存，
/// 而这段文本的用途只有 480 字节。超限部分直接丢弃——读到的不够就靠 `...(truncated)` 作证。
pub const MAX_BODY_READ_BYTES: usize = 64 * 1024;

/// "没读出来"的哨兵：点名失败原因，绝不与"上游给了空响应体"共用一条文案。
pub fn unreadable_sentinel(detail: &str) -> String {
    // detail 来自 reqwest/IO，长度不可控；它本身也是"体"，所以走同一把截断尺
    let clipped = oper_log::safe_truncate(detail, 160);
    format!("（响应体读取失败：{clipped}）")
}

/// 遮蔽 + 截断（纯函数：判据与单测直接喂真实形状，不需要网络）。
///
/// 空/全空白输入 ⇒ [`EMPTY_BODY_SENTINEL`]，永不返回空串。
pub fn mask_and_clip(raw: &str) -> String {
    if raw.trim().is_empty() {
        return EMPTY_BODY_SENTINEL.to_string();
    }
    // 顺序有意义：先把路径与查询值处理掉，再判 JSON。
    // `redact_query_values` 无 `?`/`&` 时逐字符原样返回，不会给 XML/HTML 增加开销。
    let folded = redact::redact_query_values(&redact::fold_abs_paths(raw));
    let masked = if serde_json::from_str::<serde_json::Value>(folded.trim()).is_ok() {
        // JSON 体走凭据级遮蔽（与 oper_log 落库同口径）；非 JSON 保留原文（路径已折叠）
        oper_log::sanitize_response_body(folded.trim())
    } else {
        folded
    };
    // 遮蔽后可能整体退化成 REDACTED_BODY，也可能是空——两条都可能，所以要再过一次空判定
    if masked.trim().is_empty() {
        return EMPTY_BODY_SENTINEL.to_string();
    }
    // 折成一行：错误消息会拼进 `format!` 与 `sys_oper_log.error`，
    // 多行体（HTML/XML）会把一条日志撑成一屏，也会让日志判据的逐行匹配失效。
    let one_line = masked.split_whitespace().collect::<Vec<_>>().join(" ");
    oper_log::safe_truncate(&one_line, MAX_BODY_SNIPPET_BYTES)
}

/// 读出站响应的错误体并给出可诊断、已遮蔽的一行摘要。
///
/// `label` 只进日志（谁在读），不进指标标签。失败不抛错：本函数的调用点已经在错误路径上，
/// 再抛一次只会把"依赖拒绝了我"替换成"我读依赖失败"。
pub async fn read_error_body(resp: Response, label: &str) -> String {
    match read_capped(resp).await {
        Ok(text) => mask_and_clip(&text),
        Err(e) => {
            tracing::warn!("出站 {label}：响应体读取失败（{e}）");
            unreadable_sentinel(&e.to_string())
        }
    }
}

/// 带上限地读完成体（`MAX_BODY_READ_BYTES` 之后不再取），解码走 lossy。
async fn read_capped(mut resp: Response) -> Result<String, reqwest::Error> {
    let mut buf: Vec<u8> = Vec::new();
    while buf.len() < MAX_BODY_READ_BYTES {
        let Some(chunk) = resp.chunk().await? else {
            break;
        };
        buf.extend_from_slice(&chunk);
    }
    Ok(String::from_utf8_lossy(&buf).into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// ① 两条哨兵各归各位：空体 ≠ 读失败，且都不为空串（N-144-J 的主判据）。
    #[test]
    fn empty_body_and_read_failure_are_different_non_empty_texts() {
        let empty = mask_and_clip("");
        let blank = mask_and_clip("   \n\t ");
        let failed = unreadable_sentinel("connection closed before message completed");
        assert_eq!(empty, EMPTY_BODY_SENTINEL);
        assert_eq!(blank, EMPTY_BODY_SENTINEL);
        assert!(
            !empty.is_empty() && !failed.is_empty(),
            "折叠成空串就是本批要修的洞"
        );
        assert_ne!(empty, failed, "\"没有\"与\"读不到\"必须可区分（㊷）");
        assert!(
            failed.contains("connection closed"),
            "哨兵必须带上失败原因，否则运维仍只剩 HTTP 4xx：{failed}"
        );
    }

    /// ② 真实的依赖理由必须活着到达消息里（改造前这一条会被 `unwrap_or_default()` 抹平）。
    #[test]
    fn real_dependency_reasons_survive_masking() {
        let cases = [
            // S3 XML
            r#"<?xml version="1.0" encoding="UTF-8"?><Error><Code>AccessDenied</Code><Message>Access Denied</Message><RequestId>92385A</RequestId></Error>"#,
            // 短信网关 JSON
            r#"{"code":"ERR_QUOTA_EXCEEDED","msg":"账户额度不足，请充值后重试"}"#,
            // MaxMind HTML 错误页（非 JSON，不得被折成红话常量）
            "<html><head><title>401 Unauthorized</title></head><body>Authorization required</body></html>",
        ];
        for raw in cases {
            let got = mask_and_clip(raw);
            assert!(
                !got.contains("REDACTED") || got.contains("redacted"),
                "不该整体退化：{got}"
            );
        }
        // 逐条断言关键子句还在（而不是"某条在"）
        assert!(mask_and_clip(cases[0]).contains("AccessDenied"));
        assert!(mask_and_clip(cases[1]).contains("额度不足"));
        // 非 JSON 的 HTML 必须保留正文——把 provider 的 HTML 洗成红话常量是本模块的新洞
        assert!(
            mask_and_clip(cases[2]).contains("Authorization required"),
            "{}",
            mask_and_clip(cases[2])
        );
    }

    /// ③ C.9：部署目录与凭据不得随错误体外流。
    #[test]
    fn paths_and_credentials_are_masked() {
        let win = mask_and_clip(r#"open failed at D:\deploy\stepby\data\ip-city.xdb"#);
        assert!(!win.contains("D:\\deploy"), "绝对路径漏遮蔽：{win}");
        let url = mask_and_clip(
            "presigned https://bk.s3.amazonaws.com/k?X-Amz-Signature=abc123&token=tok failed",
        );
        assert!(!url.contains("abc123"), "查询值漏遮蔽：{url}");
        assert!(!url.contains("tok "), "查询值漏遮蔽：{url}");
        // 反证：排障必需的片段不得误伤（同 b73 那条"同时钉住不误伤排障信息"）
        let keep = mask_and_clip("HTTP 403 quota exceeded for region eu-west-1");
        assert!(
            keep.contains("quota exceeded"),
            "过度遮蔽毁掉排障文本：{keep}"
        );
        assert!(keep.contains("eu-west-1"), "单段标识被误伤：{keep}");
    }

    /// ④ JSON 体的凭据字段走与 oper_log 同一份实现（不得各写各的）。
    #[test]
    fn json_credential_fields_use_the_shared_sanitizer() {
        let got = mask_and_clip(r#"{"api_key":"sk-abcdef123456","message":"invalid api key"}"#);
        assert!(!got.contains("sk-abcdef123456"), "凭据值漏遮蔽：{got}");
        assert!(got.contains("invalid api key"), "非敏感字段被连坐：{got}");
    }

    /// ⑤ 截断有上限且标记可见；UTF-8 边界不破（safe_truncate 的职责，这里验它真被接上）。
    #[test]
    fn long_bodies_are_capped_with_a_visible_marker() {
        let long = "错误".repeat(4000);
        let got = mask_and_clip(&long);
        assert!(
            got.len() <= MAX_BODY_SNIPPET_BYTES + 32,
            "超上限：{}",
            got.len()
        );
        assert!(
            got.ends_with("...(truncated)"),
            "截断标记丢了：…{}",
            &got[got.len().saturating_sub(20)..]
        );
        // 全 CJK：480 字节 = 160 字，必须仍在字符边界上（破边界会 panic 或产出乱码）
        assert!(std::str::from_utf8(got.as_bytes()).is_ok());
    }

    /// ⑥ 单行化：多行 HTML/XML 不得把一条日志撑成一屏。
    #[test]
    fn multiline_bodies_collapse_to_one_line() {
        let got = mask_and_clip("<Error>\n  <Code>NoSuchKey</Code>\n</Error>");
        assert!(!got.contains('\n'), "仍含换行：{got}");
        assert!(got.contains("NoSuchKey"), "关键子句被折掉：{got}");
    }

    /// ⑦ 活体端到端：真起一个本地服务，分别造"带理由的 4xx"与"读断"两条断面。
    ///
    /// 判据的采集面对象必须是真形状（AGENTS ⑬/㉓），不是手搓字符串。
    #[test]
    fn read_error_body_works_against_a_real_server() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            // A：带理由的 403
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let addr = listener.local_addr().unwrap();
            let body = r#"{"error":"This key is not associated with any regions"}"#.to_string();
            let handle = std::thread::spawn(move || {
                let (mut sock, _) = listener.accept().unwrap();
                use std::io::{BufRead, BufReader, Write};
                let mut line = String::new();
                let mut reader = BufReader::new(sock.try_clone().unwrap());
                loop {
                    line.clear();
                    if reader.read_line(&mut line).unwrap() == 0 || line == "\r\n" {
                        break;
                    }
                }
                let head = format!(
                    "HTTP/1.1 403 Forbidden\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
                    body.len()
                );
                let _ = sock.write_all(head.as_bytes());
                let _ = sock.write_all(body.as_bytes());
            });
            let resp = reqwest::Client::new()
                .get(format!("http://{addr}/v1/models"))
                .send()
                .await
                .unwrap();
            let got = read_error_body(resp, "ai:test").await;
            let _ = handle.join();
            assert!(got.contains("not associated with any regions"), "理由没活着：{got}");

            // B：空体 204 —— 必须落 EMPTY_BODY_SENTINEL 而不是空串
            let listener2 = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let addr2 = listener2.local_addr().unwrap();
            let handle2 = std::thread::spawn(move || {
                let (mut sock, _) = listener2.accept().unwrap();
                use std::io::{BufRead, BufReader, Write};
                let mut line = String::new();
                let mut reader = BufReader::new(sock.try_clone().unwrap());
                loop {
                    line.clear();
                    if reader.read_line(&mut line).unwrap() == 0 || line == "\r\n" {
                        break;
                    }
                }
                let _ = sock.write_all(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n");
            });
            let resp2 = reqwest::Client::new()
                .get(format!("http://{addr2}/x"))
                .send()
                .await
                .unwrap();
            let got2 = read_error_body(resp2, "sms:test").await;
            let _ = handle2.join();
            assert_eq!(got2, EMPTY_BODY_SENTINEL, "空体没落哨兵：{got2}");
        });
    }

    /// ⑧ 形状锁：生产码不得再出现 `resp.text().await.unwrap_or_default()` 这一折叠形状，
    /// 且已接线站点必须逐条在册（计数，不是"出现过一次"——b140 ②）。
    #[test]
    fn production_code_never_folds_error_body_reads_to_default() {
        const SELF: &str = "src/common/outbound_error_body.rs";
        let cfg = crate::common::prod_scan::Scan {
            exclude: &[SELF],
            ..Default::default()
        };
        let files = crate::common::prod_scan::prod_files(&cfg);
        crate::common::prod_scan::require_volume(&files, 300, 40_000, "出站错误体折叠形状扫描");

        let banned = [
            ".text().await.unwrap_or_default()",
            ".text().await.unwrap_or(",
        ];
        let mut offenders: Vec<String> = Vec::new();
        for f in &files {
            for (idx, line) in f.lines.iter().enumerate() {
                for needle in banned {
                    if line.contains(needle) {
                        offenders.push(format!("{}:{} ⇒ {needle}", f.rel, idx + 1));
                    }
                }
            }
        }
        assert!(
            offenders.is_empty(),
            "出站错误体只能经 common::outbound_error_body 读取（否则『读不到』会被折成空串，\n依赖给的理由在日志与告警里消失）。违规：\n{}",
            offenders.join("\n")
        );

        // 接线反查：每个已知消费点都必须真的在调用通道（按文件计数）
        const WIRED: &[(&str, usize)] = &[
            ("src/ai/config_service.rs", 1),
            ("src/ai/provider.rs", 1),
            ("src/common/upload_scan.rs", 1),
            ("src/service/im_robot_provider.rs", 2),
            ("src/service/sms_provider.rs", 3),
            ("src/service/ip_location_service.rs", 1),
            ("src/storage/s3.rs", 2),
        ];
        for (rel, expect) in WIRED {
            let text = crate::common::prod_scan::prod_file(rel, &cfg).text();
            let hits = text
                .matches("outbound_error_body::read_error_body(")
                .count();
            assert!(
                hits >= *expect,
                "{rel} 应至少 {expect} 处接入通道，实测 {hits} ⇒ 站点被改回裸读或整段删除"
            );
        }

        // 活性正控①：本模块的**生产视图**必须取得到通道的公开入口。
        // （原先这里断的是"被禁串的字面量出现在本文件生产视图里"——那是错的：字面量只写在
        // `#[cfg(test)]` 用例内，而 `prod_file` 恰好在属性行处切掉测试，于是这条正控结构上
        // 永远打不中，libtest 第一轮就红在自己身上。判据的输入要锚事实，不锚我以为的形状。）
        let self_text =
            crate::common::prod_scan::prod_file(SELF, &crate::common::prod_scan::Scan::default())
                .text();
        assert!(
            self_text.contains("pub async fn read_error_body("),
            "通道入口在本模块生产视图里取不到 ⇒ 采集面为空或被截歪，「0 违规」不代表任何东西"
        );
        // 活性正控②：每个已接线文件的生产视图里都必须数得到通道调用点（上一段已按期望计数判过，
        // 这里补"至少有一个文件真的非空"，防整张 WIRED 表被换成空表后照常绿）。
        assert!(
            !WIRED.is_empty(),
            "接线表为空 ⇒ 这条锁退化成只判登记表内部一致"
        );

        // 合成双向：缺陷形状必抓、合规形状不报
        let bad = "let body = resp.text().await.unwrap_or_default();";
        assert!(
            banned.iter().any(|n| bad.contains(n)),
            "合成违规形状没被抓到 ⇒ 判据坏"
        );
        let good =
            "let body = crate::common::outbound_error_body::read_error_body(resp, \"sms\").await;";
        assert!(
            !banned.iter().any(|n| good.contains(n)),
            "合规形状被误判 ⇒ 每轮必红"
        );
    }
}
