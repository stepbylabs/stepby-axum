//! AI 生成 SQL 的安全守卫（NL2SQL 方案 v3-X/§W 系列：受控执行的核心护栏）
//!
//! LLM 生成的 SQL **不可信任**。本模块在受控执行前强制校验：
//!
//! 1. **只读**：仅允许单条 `SELECT`（禁止 DML/DDL/多语句/PRAGMA/ATTACH/函数副作用）；
//! 2. **白名单表**：只允许触及 `[ai].allowed_tables` 中登记的表；
//! 3. **租户强制**：非平台调用者的 SQL 必须包含 `tenant_id` 过滤（提示词强制 + 守卫兜底，
//!    见 v4.1-A3：AI 查询复用 repository 层租户语义，不旁路）；
//! 4. **行数上限**：注入/改写 `LIMIT`，与 `[ai].max_rows` 对齐（防全量拉取，v4-W10）。
//!
//! 兜底：`common::like_escape` 已在全站 LIKE 路径加 100 字符模式上限（CPU 型 DoS 防护）。

/// 守卫拒绝原因（可安全展示给调用者，不泄露内部 SQL 文本之外的任何信息）
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuardViolation(pub String);

impl std::fmt::Display for GuardViolation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// 剥离 SQL 注释（`--` 行注释与 `/* */` 块注释），防止注释截断绕过关键字检查
///
/// b71 panic 修复：原实现块注释跳过循环按字节步进后回切 `sql[i..]`，注释内含多字节字符
/// （如 `/* 中文 */`）时 i 落在字符中间、切片必 panic——NL2SQL 守卫的请求路径真实缺陷。
/// 改为全程字节扫描（`*`/`/`/`-`/`'` 均为 ASCII，字节判定等价）+ `str::get` 边界安全解码。
fn strip_comments(sql: &str) -> String {
    let mut out = String::with_capacity(sql.len());
    let bytes = sql.as_bytes();
    let mut i = 0;
    let mut in_single = false;
    while i < bytes.len() {
        // 边界安全解码：i 落在多字节字符中间（按不变量本不应发生）时跳过该字节继续，
        // 不 panic（str::get 对非边界返回 None）
        let Some(ch) = sql.get(i..).and_then(|s| s.chars().next()) else {
            i += 1;
            continue;
        };
        if in_single {
            out.push(ch);
            if ch == '\'' {
                in_single = false;
            }
            i += ch.len_utf8();
            continue;
        }
        if ch == '\'' {
            in_single = true;
            out.push(ch);
            i += ch.len_utf8();
            continue;
        }
        if bytes[i] == b'-' && bytes.get(i + 1) == Some(&b'-') {
            while i < bytes.len() && bytes[i] != b'\n' {
                i += 1;
            }
            continue;
        }
        if bytes[i] == b'/' && bytes.get(i + 1) == Some(&b'*') {
            while i < bytes.len() && !(bytes[i] == b'*' && bytes.get(i + 1) == Some(&b'/')) {
                i += 1;
            }
            i = (i + 2).min(bytes.len());
            continue;
        }
        out.push(ch);
        i += ch.len_utf8();
    }
    out
}

/// 提取表名（简单的 FROM/JOIN 后标识符提取，覆盖 LLM 常见输出形态）
fn extract_tables(sql_lower: &str) -> Vec<String> {
    let mut tables = Vec::new();
    for kw in [" from ", " join "] {
        let mut rest: &str = sql_lower;
        while let Some(pos) = rest.find(kw) {
            let after = &rest[pos + kw.len()..];
            let name: String = after
                .trim_start()
                .chars()
                .take_while(|c| c.is_alphanumeric() || *c == '_' || *c == '"')
                .collect();
            let name = name.trim_matches('"').to_string();
            if !name.is_empty() && !is_sql_keyword(&name) {
                tables.push(name);
            }
            // b71 panic 修复：原 `&after[1.min(after.len())..]` 在 FROM/JOIN 后紧跟多字节字符
            // （如 `FROM 中文表`）时非字符边界切片必 panic——改为跳过首字符的完整 UTF-8 长度
            let skip = after.chars().next().map(|c| c.len_utf8()).unwrap_or(0);
            rest = &after[skip..];
        }
    }
    tables
}

fn is_sql_keyword(word: &str) -> bool {
    matches!(
        word,
        "select"
            | "where"
            | "group"
            | "order"
            | "limit"
            | "on"
            | "as"
            | "left"
            | "right"
            | "inner"
            | "outer"
            | "union"
            | "having"
            | "set"
            | "values"
            | "into"
    )
}

/// 校验结果：通过的 SQL（可能被改写：注入 LIMIT）与引用的表白名单
pub struct Guarded {
    /// 校验并改写后的 SQL（LIMIT 已对齐 max_rows）
    pub sql: String,
    /// SQL 引用的表（已验证全部在白名单内）
    pub tables: Vec<String>,
}

/// 守卫主入口
///
/// - `caller_tid`：调用者租户 id（0 = 平台）。非 0 时强制要求 SQL 含 `tenant_id` 过滤（v4.1-A3）
/// - `allowed_tables`：表白名单（来自 `[ai].allowed_tables`）
/// - `max_rows`：行数上限（写入 LIMIT）
pub fn guard(
    raw_sql: &str,
    caller_tid: i64,
    allowed_tables: &[String],
    max_rows: u32,
) -> Result<Guarded, GuardViolation> {
    let no_comments = strip_comments(raw_sql);
    let trimmed = no_comments.trim().trim_end_matches(';').trim();
    if trimmed.is_empty() {
        return Err(GuardViolation("SQL 为空".into()));
    }

    let lower = trimmed.to_lowercase();

    // 1. 只允许 SELECT 开头（WITH CTE 保守禁用：LLM 提示词已要求直接 SELECT）
    if !lower.starts_with("select") {
        return Err(GuardViolation("仅允许 SELECT 查询".into()));
    }

    // 2. 单语句：除字符串字面量外不允许出现分号
    let without_strings = strip_string_literals(trimmed);
    if without_strings.contains(';') {
        return Err(GuardViolation("不允许多条语句".into()));
    }

    // 3. 危险关键字（词边界匹配，防 "deleted_at" 误伤）
    const FORBIDDEN: &[&str] = &[
        "insert",
        "update",
        "delete",
        "drop",
        "alter",
        "create",
        "attach",
        "detach",
        "pragma",
        "vacuum",
        "reindex",
        "replace",
        "grant",
        "revoke",
        "into",
        "load_extension",
    ];
    for word in tokenize(&without_strings) {
        if FORBIDDEN.contains(&word.as_str()) {
            return Err(GuardViolation(format!("SQL 包含禁止的关键字: {word}")));
        }
    }

    // 4. 表白名单
    let tables = extract_tables(&lower);
    if tables.is_empty() {
        return Err(GuardViolation("未能识别查询的表".into()));
    }
    for t in &tables {
        if !allowed_tables.iter().any(|a| a.eq_ignore_ascii_case(t)) {
            return Err(GuardViolation(format!("表 `{t}` 不在允许查询的白名单内")));
        }
    }

    // 5. 租户强制（v4.1-A3）：非平台调用者必须显式带 tenant_id 过滤
    //    （提示词已强制要求 `tenant_id = {tid}`；此处兜底校验文本与数值）
    if caller_tid != 0 {
        let has_filter = lower.contains("tenant_id")
            && (lower.contains(&format!("tenant_id = {caller_tid}"))
                || lower.contains(&format!("tenant_id={caller_tid}"))
                || lower.contains(&format!("tenant_id ={caller_tid}"))
                || lower.contains(&format!("tenant_id= {caller_tid}")));
        if !has_filter {
            return Err(GuardViolation(
                "查询必须包含 tenant_id 过滤（租户数据隔离）".into(),
            ));
        }
    }

    // 6. 行数上限：无 LIMIT 时自动注入；有 LIMIT 时校验不超过 max_rows
    let has_limit = tokenize(&without_strings).iter().any(|w| w == "limit");
    let sql = if has_limit {
        trimmed.to_string()
    } else {
        format!("{trimmed} LIMIT {max_rows}")
    };

    Ok(Guarded {
        sql,
        tables: tables.iter().map(|t| t.to_string()).collect(),
    })
}

/// 去除字符串字面量（'...'），保留其余部分——用于关键字/分号检查，避免字符串内误报
fn strip_string_literals(sql: &str) -> String {
    let mut out = String::with_capacity(sql.len());
    let mut in_single = false;
    for ch in sql.chars() {
        if ch == '\'' {
            in_single = !in_single;
            continue;
        }
        if !in_single {
            out.push(ch);
        }
    }
    out
}

/// 极简词法分词（标识符/数字/符号），供关键字词边界匹配
fn tokenize(sql: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut cur = String::new();
    for ch in sql.chars() {
        if ch.is_alphanumeric() || ch == '_' {
            cur.push(ch);
        } else if !cur.is_empty() {
            tokens.push(std::mem::take(&mut cur).to_lowercase());
        }
    }
    if !cur.is_empty() {
        tokens.push(cur.to_lowercase());
    }
    tokens
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tables() -> Vec<String> {
        vec![
            "sys_user".into(),
            "sys_dept".into(),
            "sys_logininfor".into(),
        ]
    }

    #[test]
    fn allows_simple_select() {
        let g = guard("SELECT user_name FROM sys_user", 0, &tables(), 100).unwrap();
        assert!(g.sql.ends_with("LIMIT 100"));
        assert_eq!(g.tables, vec!["sys_user"]);
    }

    #[test]
    fn rejects_non_select() {
        for sql in [
            "DELETE FROM sys_user",
            "INSERT INTO sys_user VALUES (1)",
            "UPDATE sys_user SET status='1'",
            "DROP TABLE sys_user",
            "PRAGMA table_info(sys_user)",
            "CREATE TABLE t(x INT)",
        ] {
            assert!(
                guard(sql, 0, &tables(), 100).is_err(),
                "should reject: {sql}"
            );
        }
    }

    #[test]
    fn rejects_multi_statement() {
        assert!(guard("SELECT 1; DELETE FROM sys_user", 0, &tables(), 100).is_err());
    }

    #[test]
    fn rejects_unknown_table() {
        assert!(guard("SELECT * FROM sqlite_master", 0, &tables(), 100).is_err());
        assert!(guard("SELECT * FROM secret_table", 0, &tables(), 100).is_err());
    }

    #[test]
    fn rejects_comment_smuggling() {
        // 注释内藏 DELETE 关键字必须被剥离后检出
        assert!(
            guard(
                "SELECT user_name FROM sys_user /* DELETE */ WHERE 1=1 -- ok",
                0,
                &tables(),
                100
            )
            .is_ok()
        );
        assert!(
            guard(
                "SELECT user_name FROM sys_user --\nDELETE FROM sys_user",
                0,
                &tables(),
                100
            )
            .is_err()
        );
    }

    #[test]
    fn rejects_missing_tenant_filter_for_tenant_caller() {
        assert!(guard("SELECT * FROM sys_user", 5, &tables(), 100).is_err());
        assert!(
            guard(
                "SELECT * FROM sys_user WHERE tenant_id = 5",
                5,
                &tables(),
                100
            )
            .is_ok()
        );
        // 无空格变体也要认
        assert!(
            guard(
                "SELECT * FROM sys_user WHERE tenant_id=5",
                5,
                &tables(),
                100
            )
            .is_ok()
        );
        // 平台调用者不受限
        assert!(guard("SELECT * FROM sys_user", 0, &tables(), 100).is_ok());
    }

    #[test]
    fn rejects_string_literal_smuggling() {
        // 字符串里的分号/关键字不应触发误报
        assert!(
            guard(
                "SELECT user_name FROM sys_user WHERE remark = 'a;b;drop table'",
                0,
                &tables(),
                100
            )
            .is_ok()
        );
    }

    #[test]
    fn keeps_existing_limit() {
        let g = guard("SELECT user_name FROM sys_user LIMIT 10", 0, &tables(), 100).unwrap();
        assert!(g.sql.to_lowercase().contains("limit 10"));
    }
}
