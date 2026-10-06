// stepby-axum/src/utils/masking.rs
//! 字段级权限 M1：统一脱敏工具（业务展示口径 + 日志审计口径的单一出口）
//!
//! # 背景（AGENTS.md C9 对齐）
//!
//! C9（日志脱敏强制）要求：敏感字段（密码/密钥/token/PII/身份证/手机号）在
//! 日志与审计中必须脱敏，且**须复用同一脱敏函数，不得各写各的**。此前项目内
//! 的脱敏函数散落在 `middleware/oper_log.rs`（4 个私有 fn：手机号/身份证/邮箱/
//! 银行卡，服务于 sys_oper_log 的 10 字段脱敏口径），无统一出口；M1（字段级
//! 权限）需要在**业务出参**（sys_user 列表/详情的 phonenumber/email）上做
//! 展示型脱敏，口径与日志脱敏并不完全相同。
//!
//! 本模块因此提供**两套明确分层的口径**：
//!
//! 1. **业务展示口径**（`mask_phone` / `mask_email` / `mask_id_card`，底座
//!    `mask_keep`）：用于接口出参的字段级权限掩码。特点：trim 后处理；
//!    邮箱无 `@` 时原样返回（避免破坏非邮箱语义的展示）；身份证按 18/15 位
//!    区分保留位数；掩码结果带可识别形态（含 `****`），供更新流程识别
//!    "未改动的掩码值"并跳过写库（见 `is_masked`）。
//! 2. **日志审计口径**（`log_mask_phone` / `log_mask_idcard` / `log_mask_email`
//!    / `log_mask_bankcard`）：自 `middleware/oper_log.rs` **原样迁移**，行为
//!    与既有 sys_oper_log 脱敏完全一致（固定星号数、短串整值替换为 `***`），
//!    `oper_log.rs` 已改为从本模块引用（re-export 别名），满足 C9
//!    "同一脱敏函数"的要求。两套口径差异是**有意为之**：日志脱敏宁可整值
//!    替换（日志里残值毫无价值），业务展示需要保留辨识度（列表里要能区分
//!    两条记录）。
//!
//! # 安全性约定
//!
//! 全部函数对空串/过短串/多字节字符（全角、中文）/含空白输入安全：
//! - 统一先 `trim`，再按 `char`（而非字节）切片，杜绝 UTF-8 多字节边界 panic；
//! - 过短串在保留位数不足以维持辨识度时整体替换为 `***`（fail-closed）。

// ==================== 业务展示口径（M1 字段级权限） ====================

/// 通用掩码底座：保留前 `keep_prefix` 个字符与后 `keep_suffix` 个字符，
/// 中间以 `*` 填充（星号数 = 总字符数 - 保留数）。
///
/// - 输入先 `trim`；trim 后为空返回空串；
/// - 总字符数 ≤ `keep_prefix + keep_suffix`（保留位数不足以维持辨识度）时
///   整值替换为 `***`（fail-closed，不泄露残值）；
/// - 按 `char` 计数与切片，多字节字符（全角/中文）不 panic。
///
/// # 示例
/// ```
/// use stepby_axum::utils::masking::mask_keep;
/// assert_eq!(mask_keep("13812345678", 3, 4), "138****5678");
/// assert_eq!(mask_keep("  abcd1234  ", 2, 2), "ab****34");
/// assert_eq!(mask_keep("abc", 2, 2), "***");
/// ```
pub fn mask_keep(s: &str, keep_prefix: usize, keep_suffix: usize) -> String {
    let t = s.trim();
    let chars: Vec<char> = t.chars().collect();
    let n = chars.len();
    if n == 0 {
        // 空串原样返回（无值可泄）
        return String::new();
    }
    if n <= keep_prefix + keep_suffix {
        // 保留位数之和已覆盖全串：整体替换，避免"看起来掩码了实际全暴露"
        return "***".to_string();
    }
    let head: String = chars[..keep_prefix].iter().collect();
    let tail: String = chars[n - keep_suffix..].iter().collect();
    let mask = "*".repeat(n - keep_prefix - keep_suffix);
    format!("{head}{mask}{tail}")
}

/// 手机号脱敏（业务展示口径）：
/// - 11 位手机号保留前 3 后 4：`13812345678` → `138****5678`；
/// - 非 11 位保留首尾各 1（中间按实际长度填充星号）；
/// - trim 后处理；过短串（≤2 字符）与空串安全（空串原样，过短整值 `***`）。
pub fn mask_phone(s: &str) -> String {
    let t = s.trim();
    if t.chars().count() == 11 {
        mask_keep(t, 3, 4)
    } else {
        mask_keep(t, 1, 1)
    }
}

/// 邮箱脱敏（业务展示口径）：`@` 前本地部分仅保留首字符，其余以固定
/// `****` 替换，域名原样保留：`alice@example.com` → `a****@example.com`。
///
/// - 空 / 无 `@` / 本地部分为空（以 `@` 开头）：原样返回（非邮箱语义的
///   展示值不应被破坏）；
/// - 保留首字符按 `char` 处理，多字节字符不 panic。
pub fn mask_email(s: &str) -> String {
    let t = s.trim();
    match t.find('@') {
        // 本地部分非空：首字符 + **** + @域名
        Some(at) if at > 0 => {
            let first = t[..at].chars().next().unwrap_or_default();
            format!("{first}****{}", &t[at..])
        }
        // 空串 / 无 @ / @ 开头（本地部分为空）：原样返回
        _ => t.to_string(),
    }
}

/// 身份证号脱敏（业务展示口径）：
/// - 18 位保留前 4 后 4（中间 10 位掩码）；
/// - 15 位保留前 4 后 2（中间 9 位掩码）；
/// - 其它长度视为异常输入，走保守掩码（首尾各 1，过短整值 `***`）；
/// - 含末位 `X` / 全角字符 / 空白均安全（按 `char` 处理 + trim）。
pub fn mask_id_card(s: &str) -> String {
    let t = s.trim();
    match t.chars().count() {
        18 => mask_keep(t, 4, 4),
        15 => mask_keep(t, 4, 2),
        // 异常长度：保守掩码（mask_keep 的过短保护兜底）
        _ => mask_keep(t, 1, 1),
    }
}

/// 判断字符串是否为**掩码形态**（含 `*`）。
///
/// M1 连带约定：详情/编辑回显对非本人非超管返回的是掩码值（必然含 `****`），
/// 前端若未改动直接回传，更新流程须据此识别并跳过该字段，防止掩码串覆盖
/// 真实值。真实手机号/身份证/邮箱不含 `*`，误判风险为零。
pub fn is_masked(s: &str) -> bool {
    s.contains('*')
}

// ==================== 日志审计口径（自 oper_log.rs 原样迁移，行为不变） ====================
//
// C9：sys_oper_log 的 10 字段脱敏口径唯一出口。调用方（middleware/oper_log.rs）
// 通过 `use ... as mask_xxx` 别名保持原有调用点与单测引用不变。

/// 手机号脱敏（日志口径）：保留前 3 后 4，中间 4 位用 * 替换；不足 7 位整值 `***`。
/// 使用 char 迭代避免 UTF-8 多字节边界切片 panic（P0-New-2）
pub fn log_mask_phone(s: &str) -> String {
    let chars: Vec<char> = s.chars().collect();
    if chars.len() < 7 {
        return "***".to_string();
    }
    let head: String = chars[..3].iter().collect();
    let tail: String = chars[chars.len() - 4..].iter().collect();
    format!("{head}****{tail}")
}

/// 身份证号脱敏（日志口径）：保留前 4 后 2，中间 8 位用 * 替换；不足 10 位整值 `***`。
/// 使用 char 迭代避免 UTF-8 多字节边界切片 panic（P0-New-2）
pub fn log_mask_idcard(s: &str) -> String {
    let chars: Vec<char> = s.chars().collect();
    if chars.len() < 10 {
        return "***".to_string();
    }
    let head: String = chars[..4].iter().collect();
    let tail: String = chars[chars.len() - 2..].iter().collect();
    format!("{head}********{tail}")
}

/// 邮箱脱敏（日志口径）：保留首字符和 @ 域名，中间用 * 填充（如 a***@example.com）
/// （P0-33 改进）。非 email 格式或本地部分为空，直接整值 `***`。
/// 使用 char 迭代避免 UTF-8 多字节边界切片 panic
pub fn log_mask_email(s: &str) -> String {
    match s.find('@') {
        Some(at) if at > 0 => {
            let (local, domain) = s.split_at(at);
            let mut chars = local.chars();
            // 仅保留首字符，其余本地部分替换为 ***
            let head = chars.next().map(|c| c.to_string()).unwrap_or_default();
            format!("{head}***{domain}")
        }
        // 非 email 格式或本地部分为空，直接掩码
        _ => "***".to_string(),
    }
}

/// 银行卡号脱敏（日志口径）：保留前 4 后 4，中间用 * 填充（P0-33 改进）；
/// 不足 8 位整值 `***`。
/// 使用 char 迭代避免 UTF-8 多字节边界切片 panic
pub fn log_mask_bankcard(s: &str) -> String {
    let chars: Vec<char> = s.chars().collect();
    if chars.len() < 8 {
        return "***".to_string();
    }
    let head: String = chars[..4].iter().collect();
    let tail: String = chars[chars.len() - 4..].iter().collect();
    let mask: String = "*".repeat(chars.len() - 8);
    format!("{head}{mask}{tail}")
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---------- 业务展示口径：mask_phone ----------

    #[test]
    fn test_mask_phone_11_digits() {
        assert_eq!(mask_phone("13812345678"), "138****5678");
    }

    #[test]
    fn test_mask_phone_non_11_keep_first_last() {
        // 非 11 位：保留首尾各 1
        assert_eq!(mask_phone("12345678"), "1******8");
    }

    #[test]
    fn test_mask_phone_trim() {
        // 含空格输入：trim 后处理
        assert_eq!(mask_phone("  13812345678  "), "138****5678");
    }

    #[test]
    fn test_mask_phone_empty_and_short() {
        assert_eq!(mask_phone(""), "");
        assert_eq!(mask_phone("   "), "");
        assert_eq!(mask_phone("12"), "***"); // 过短：整值替换，不泄露残值
        assert_eq!(mask_phone("123"), "1*3"); // 恰好 3 位：首尾各 1
    }

    #[test]
    fn test_mask_phone_multibyte_no_panic() {
        // 全角/多字节字符：按 char 处理，不得 panic
        assert_eq!(mask_phone("１３８１２３４５６７８"), "１３８****５６７８");
        let _ = mask_phone("手机号码测试一二三四");
    }

    // ---------- 业务展示口径：mask_email ----------

    #[test]
    fn test_mask_email_normal() {
        assert_eq!(mask_email("alice@example.com"), "a****@example.com");
    }

    #[test]
    fn test_mask_email_no_at_keeps_original() {
        // 无 @：原样（业务展示口径，区别于日志口径的整值 ***）
        assert_eq!(mask_email("notanemail"), "notanemail");
    }

    #[test]
    fn test_mask_email_empty_and_at_start() {
        assert_eq!(mask_email(""), "");
        assert_eq!(mask_email("   "), "");
        // @ 开头（本地部分为空）：原样返回，不 panic
        assert_eq!(mask_email("@example.com"), "@example.com");
    }

    #[test]
    fn test_mask_email_trim_and_multibyte() {
        assert_eq!(mask_email("  bob@qq.com "), "b****@qq.com");
        // 多字节首字符
        assert_eq!(mask_email("张三@qq.com"), "张****@qq.com");
    }

    // ---------- 业务展示口径：mask_id_card ----------

    #[test]
    fn test_mask_id_card_18() {
        // 18 位：保留前 4 后 4
        assert_eq!(mask_id_card("110101199001011234"), "1101**********1234");
    }

    #[test]
    fn test_mask_id_card_18_with_x() {
        assert_eq!(mask_id_card("11010119900101123X"), "1101**********123X");
    }

    #[test]
    fn test_mask_id_card_15() {
        // 15 位：保留前 4 后 2（中间 9 位掩码）
        assert_eq!(mask_id_card("110101900101123"), "1101*********23");
    }

    #[test]
    fn test_id_card_abnormal_length_conservative() {
        // 异常长度：保守掩码（首尾各 1）
        assert_eq!(mask_id_card("1234567890"), "1********0");
        assert_eq!(mask_id_card("12345"), "1***5");
        assert_eq!(mask_id_card(""), "");
    }

    // ---------- 业务展示口径：mask_keep 底座 ----------

    #[test]
    fn test_mask_keep_normal() {
        assert_eq!(mask_keep("abcd1234", 2, 2), "ab****34");
        // n=8，keep 4+4 恰好覆盖全串 → 整值替换
        assert_eq!(mask_keep("abcd1234", 4, 4), "***");
    }

    #[test]
    fn test_mask_keep_exactly_one_masked_char() {
        // n=5 > 2+2：中间仅 1 个字符被掩码
        assert_eq!(mask_keep("abcde", 2, 2), "ab*de");
    }

    #[test]
    fn test_mask_keep_empty() {
        assert_eq!(mask_keep("", 1, 1), "");
        assert_eq!(mask_keep("   ", 1, 1), "");
    }

    // ---------- is_masked ----------

    #[test]
    fn test_is_masked() {
        assert!(is_masked("138****5678"));
        assert!(is_masked("a****@example.com"));
        assert!(!is_masked("13812345678"));
        assert!(!is_masked("alice@example.com"));
        assert!(!is_masked(""));
    }

    // ---------- 日志审计口径：与 oper_log 既有行为逐条对齐 ----------

    #[test]
    fn test_log_mask_phone_normal() {
        assert_eq!(log_mask_phone("13812345678"), "138****5678");
    }

    #[test]
    fn test_log_mask_phone_short() {
        assert_eq!(log_mask_phone("123"), "***");
    }

    #[test]
    fn test_log_mask_idcard_normal() {
        assert_eq!(log_mask_idcard("110101199001011234"), "1101********34");
    }

    #[test]
    fn test_log_mask_idcard_short() {
        assert_eq!(log_mask_idcard("12345"), "***");
    }

    #[test]
    fn test_log_mask_email_normal() {
        assert_eq!(log_mask_email("alice@example.com"), "a***@example.com");
    }

    #[test]
    fn test_log_mask_email_no_at() {
        assert_eq!(log_mask_email("notanemail"), "***");
    }

    #[test]
    fn test_log_mask_bankcard_normal() {
        assert_eq!(
            log_mask_bankcard("6222021234567890123"),
            "6222***********0123"
        );
    }

    #[test]
    fn test_log_mask_bankcard_short() {
        assert_eq!(log_mask_bankcard("1234"), "***");
    }
}
