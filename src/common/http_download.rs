// stepby-axum/src/common/http_download.rs
//! 文件下载的 `Content-Disposition` 响应头**单一实现**（b139）。
//!
//! ## 立项：同一件事写五遍，就有五个严格度
//!
//! b139 勘察实测本仓曾有 5 处各自拼 `attachment; filename="…"`：
//!
//! | 站点 | 非 ASCII 文件名时的实际结局 |
//! | --- | --- |
//! | `common/excel.rs` | 唯一正确：清洗 + RFC 5987 `filename*=UTF-8''` |
//! | `audit/handler.rs` | `&str` 直接进响应头元组（axum 内部转换失败即 500） |
//! | `sys_backup_handler.rs` | `HeaderValue::from_str` 失败回落固定名 `backup` |
//! | `sys_oper_log_handler.rs` | 失败回落固定名 `oper-log-archive.jsonl` |
//! | `tool_gen_handler.rs` | `if let Ok(..)` **静默不设头**（浏览器按 URL 末段猜名） |
//!
//! 三条不同的降级路径里,只有第一条是"设计",后四条都是"没想到"。用户侧统一表现为
//! **下载名不对**（拿到 `backup` / 一串乱码 / URL 末段）,而服务端没有任何信号。
//!
//! ## 口径
//!
//! - 先清洗再编码:移除 CRLF / NUL / 引号 / 反斜杠(防头注入与破坏引号结构),
//!   其余控制字符替换为 `_`,消除首尾空白;
//! - ASCII 文件名直接 `filename="…"`(带引号,允许空格);
//! - 含非 ASCII 时给 ASCII 兜底 `filename="<fallback>"` + `filename*=UTF-8''<RFC5987>`,
//!   浏览器优先使用 `filename*`;
//! - 兜底名本身也必须是 ASCII 可见字符(否则退化为 `download`),保证一定能构造出
//!   合法的 `HeaderValue`——这一步是"失败静默不设头"的对立面:**必有头**。

use axum::http::HeaderValue;

/// 极端兜底名（`build_content_disposition` 的输出已保证 ASCII 可见字符，
/// 因此 `HeaderValue::from_str` 理论上不会失败；这个常量是类型要求的收尾）。
const LAST_RESORT: &str = "attachment; filename=\"download\"";

/// 清洗文件名，防止响应头注入。
///
/// 移除 CRLF、NUL 与控制字符（防头注入），移除引号/反斜杠（防破坏 Content-Disposition
/// 引号结构），消除首尾空白。清洗后仍为空时调用方应提供 ASCII 兜底名。
pub fn sanitize_filename(name: &str) -> String {
    let cleaned: String = name
        .chars()
        .filter(|c| !matches!(c, '\r' | '\n' | '\0' | '"' | '\\'))
        .map(|c| if c.is_control() { '_' } else { c })
        .collect();
    cleaned.trim().to_string()
}

/// RFC 5987 百分号编码（UTF-8 字节）。
///
/// 仅保留 attr-char 字符集（ALPHA / DIGIT / `!#$&+-.^_\`|~`），其余字节按 UTF-8
/// 逐字节 `%XX` 编码，使非 ASCII 文件名可在 `filename*` 中安全传输。
pub fn rfc5987_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len() * 3);
    for b in s.as_bytes() {
        match b {
            b'A'..=b'Z'
            | b'a'..=b'z'
            | b'0'..=b'9'
            | b'!'
            | b'#'
            | b'$'
            | b'&'
            | b'+'
            | b'-'
            | b'.'
            | b'^'
            | b'_'
            | b'`'
            | b'|'
            | b'~' => out.push(*b as char),
            _ => out.push_str(&format!("%{:02X}", b)),
        }
    }
    out
}

/// 构造 `Content-Disposition` 的值（纯字符串，可单测）。
///
/// `fallback` 是含非 ASCII 文件名时给旧客户端的 ASCII 兜底名（不含扩展名的语义由
/// 调用方决定，例如 `export.xlsx` / `backup.sql`）；它本身非 ASCII 或清洗后为空时
/// 退化为 `download`。
pub fn build_content_disposition(filename: &str, fallback: &str) -> String {
    let safe = sanitize_filename(filename);
    let safe_fallback = sanitize_filename(fallback);
    let fallback = if safe_fallback.is_empty() || !safe_fallback.is_ascii() {
        "download"
    } else {
        safe_fallback.as_str()
    };
    if safe.is_empty() {
        return format!("attachment; filename=\"{fallback}\"");
    }
    if safe.is_ascii() {
        format!("attachment; filename=\"{safe}\"")
    } else {
        format!(
            "attachment; filename=\"{fallback}\"; filename*=UTF-8''{}",
            rfc5987_encode(&safe)
        )
    }
}

/// 唯一入口：把文件名直接变成可插入响应头的 `HeaderValue`。
///
/// 与"各处自己 `HeaderValue::from_str` 再各自写一个回落字面量"相反，这里**必有头**：
/// 兜底名经过同一套清洗与 ASCII 校验，因此非 ASCII 文件名不会导致"响应里没有这个头"
/// （b139 之前 `tool_gen_handler` 就是那样）。
pub fn content_disposition_header(filename: &str, fallback: &str) -> HeaderValue {
    HeaderValue::from_str(&build_content_disposition(filename, fallback))
        .unwrap_or_else(|_| HeaderValue::from_static(LAST_RESORT))
}

#[cfg(test)]
mod tests {
    //! 覆盖意图：清洗（注入面）、RFC 5987 编码（非 ASCII 可传输）、
    //! 兜底名的三条降级（空 / 非 ASCII / 正常），以及"任何输入都必有一个头"。

    use super::*;

    #[test]
    fn sanitize_filename_removes_crlf_quotes_and_controls() {
        // CRLF / NUL / 引号 / 反斜杠全部移除，控制字符替换为 _
        assert_eq!(sanitize_filename("a\r\nb"), "ab");
        assert_eq!(sanitize_filename("evil\"; rm -rf /"), "evil; rm -rf /");
        assert_eq!(sanitize_filename("back\\slash"), "backslash");
        assert_eq!(sanitize_filename("nul\0byte"), "nulbyte");
        assert_eq!(sanitize_filename(" tab\x01ctl "), "tab_ctl");
        // 清洗后为空 → 空串（调用方需兜底）
        assert_eq!(sanitize_filename("\"\r\n"), "");
    }

    #[test]
    fn rfc5987_encode_keeps_attr_chars_and_encodes_rest() {
        // attr-char 保留
        assert_eq!(rfc5987_encode("abcXYZ09!$&+-.^_`|~"), "abcXYZ09!$&+-.^_`|~");
        // 空格 / 中文 / 不可打印字符按 UTF-8 逐字节大写 %XX
        assert_eq!(rfc5987_encode("a b"), "a%20b");
        assert_eq!(rfc5987_encode("中"), "%E4%B8%AD");
        assert_eq!(rfc5987_encode("="), "%3D");
        assert_eq!(rfc5987_encode("%"), "%25");
    }

    #[test]
    fn build_content_disposition_handles_ascii_non_ascii_and_empty() {
        // ASCII → 直接带引号
        assert_eq!(
            build_content_disposition("report.xlsx", "export.xlsx"),
            "attachment; filename=\"report.xlsx\""
        );
        // 含空格
        assert_eq!(
            build_content_disposition("my report.xlsx", "export.xlsx"),
            "attachment; filename=\"my report.xlsx\""
        );
        // 非 ASCII → ASCII 兜底 + filename* RFC5987
        let cd = build_content_disposition("用户报表.xlsx", "export.xlsx");
        assert!(cd.starts_with("attachment; filename=\"export.xlsx\"; filename*=UTF-8''"));
        assert!(cd.contains("%E7%94%A8%E6%88%B7")); // 用户
        // 清洗后为空 → 兜底名
        assert_eq!(
            build_content_disposition("\"\r\n", "export.xlsx"),
            "attachment; filename=\"export.xlsx\""
        );
    }

    #[test]
    fn fallback_name_is_validated_too() {
        // 兜底名非 ASCII ⇒ 退化为 download（否则 header 仍会构造失败）
        let cd = build_content_disposition("用户报表.csv", "备份.sql");
        assert!(
            cd.starts_with("attachment; filename=\"download\"; filename*=UTF-8''"),
            "实际: {cd}"
        );
        // 兜底名清洗后为空 ⇒ 同样退化
        assert_eq!(
            build_content_disposition("用户报表.csv", "\"\r\n"),
            format!(
                "attachment; filename=\"download\"; filename*=UTF-8''{}",
                rfc5987_encode("用户报表.csv")
            )
        );
    }

    #[test]
    fn header_always_exists_even_for_hostile_input() {
        // 注入串：清洗后仍是 ASCII 名，头能构造且不含 CRLF
        let head = content_disposition_header("a\r\nSet-Cookie: x=1", "f.bin");
        assert_eq!(head, "attachment; filename=\"aSet-Cookie: x=1\"");
        // 非 ASCII：头仍存在，且带 filename*
        let head = content_disposition_header("归档.jsonl", "archive.jsonl");
        let text = head.to_str().expect("必须是合法 HeaderValue");
        assert!(text.contains("filename*=UTF-8''"), "实际: {text}");
    }

    /// 形状锁：`attachment; filename=` 只能由本模块拼。
    ///
    /// 立项就是本模块文档那张表——5 处各自拼、3 条不同的降级路径。把它收进单一实现之后，
    /// 更需要一条判据挡住"下一个下载端点又手拼一遍"：只靠代码评审，第六处一定会来
    /// （b139 施工中 `batch_gen_code` 就是漏掉的第六处）。
    #[test]
    fn content_disposition_is_built_only_by_this_module() {
        use crate::common::prod_scan::{Scan, normalize, prod_files, require_volume};

        // 本文件必然含被禁形态（`LAST_RESORT` 与文档示例），按扫描器口径豁免自己
        const SELF: &str = "src/common/http_download.rs";
        let files = prod_files(&Scan {
            exclude: &[SELF],
            ..Scan::default()
        });
        require_volume(&files, 300, 20_000, "Content-Disposition 形状锁");

        let mut hits = Vec::new();
        for f in &files {
            for (i, line) in f.lines.iter().enumerate() {
                if line.contains("attachment;") && line.contains("filename=") {
                    hits.push(format!("{}:{} {}", f.rel, i + 1, line.trim()));
                }
            }
        }
        assert!(
            hits.is_empty(),
            "Content-Disposition 必须经 common::http_download 构造，实际发现裸拼:\n{}",
            hits.join("\n")
        );

        // 采集面活性正控：六处已知下载站点必须仍在面里，且都走单一实现
        // （只判"违规 0 处"时，采集面塌成空集也是绿的）
        for rel in [
            "src/common/excel.rs",
            "src/audit/handler.rs",
            "src/handler/sys_backup_handler.rs",
            "src/handler/sys_oper_log_handler.rs",
            "src/handler/tool_gen_handler.rs",
            "src/handler/sys_user_handler.rs",
        ] {
            let f = files
                .iter()
                .find(|f| f.rel == rel)
                .unwrap_or_else(|| panic!("采集面缺 {rel}（不是通过）"));
            assert!(
                f.text()
                    .contains("http_download::content_disposition_header"),
                "{rel} 未接线到 common::http_download"
            );
        }

        // 合成双向：缺陷形状必须被抓，合规写法不得误报
        let bad = normalize(
            "let cd = format!(\"attachment; filename=\\\"{}\\\"\", name);",
            &Scan::default(),
        );
        assert!(
            bad.iter()
                .any(|l| l.contains("attachment;") && l.contains("filename=")),
            "合成违规必须被抓"
        );
        let good = normalize(
            "headers.insert(CONTENT_DISPOSITION, content_disposition_header(&n, \"f.bin\"));",
            &Scan::default(),
        );
        assert!(
            !good
                .iter()
                .any(|l| l.contains("attachment;") && l.contains("filename=")),
            "合规写法不得误报"
        );
    }
}
