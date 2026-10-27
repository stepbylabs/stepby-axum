//! AI 生成 SQL 的安全守卫（NL2SQL 方案 v3-X/§W 系列：受控执行的核心护栏）
//!
//! LLM 生成的 SQL **不可信任**。本模块在受控执行前强制校验：
//!
//! 1. **只读**：仅允许**一条、顶层一个** `SELECT`（禁止 DML/DDL/多语句/PRAGMA/ATTACH/
//!    子查询/UNION/函数副作用）。子查询与 UNION 一律拒绝——它们能在 `WHERE` 之外
//!    再造一个不带租户谓词的读面，而文本级守卫无法把谓词归属到内层查询；
//! 2. **白名单表**：`FROM` / `JOIN` 后的**每一个**表引用（含逗号连写、反引号/双引号
//!    标识符、JOIN 链）都必须命中 `[ai].allowed_tables`；
//! 3. **租户强制**：非平台调用者（`caller_tid != 0`）必须对**每一个表引用**给出
//!    `<别名>.tenant_id = <本租户>` 谓词（单表可免别名），且该谓词必须是独立的
//!    `WHERE`/`AND`/`ON` 连接项——被括号包住、被 `IS NULL` 之类二次运算、或数字
//!    只是前缀相同（`tenant_id = 50` 冒充 `= 5`）都不算；`OR` 同样拒绝（它能把
//!    谓词变成"可选条件"）；
//! 4. **行数上限**：缺 `LIMIT` 时追加；已有 `LIMIT` 且超过 `[ai].max_rows` 时**改写**
//!    成上限（此前只判"有没有 LIMIT"⇒ `LIMIT 100000000` 原样放行）；
//! 5. **危险函数**：`pg_read_file` / `load_file` / `pg_sleep` / `randomblob` 这类
//!    读文件、探测网络、拖垮 CPU/内存的函数在 `SELECT` 里同样有副作用，按函数调用
//!    形状（`name(`，允许中间空白）拒绝。
//!
//! **残余风险如实登记**：这是文本级守卫，不是数据库行级安全。谓词的"形状正确"
//! 不等于语义正确（例如 `WHERE tenant_id = 5 AND (tenant_id = 6)` 会查空，但不会
//! 越权；而把谓词嵌进更复杂的布尔表达式仍可能改变语义）。真正的边界应由数据库
//! 只读账号 + 行级安全兜底；本模块负责把 LLM 最常见的越权形态挡在执行之前。
//!
//! 字符串处理口径：反斜杠**不**当转义符（MySQL 与标准 SQL 解释不一致）。取"先结束
//! 字符串"的保守解释 ⇒ 会看到更多关键字/分号，方向是拒绝而不是放行。

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

/// 词法单元：只区分"词"与"标点"，字符串字面量在词法化时跳过（含其内容）。
#[derive(Debug, Clone, PartialEq, Eq)]
enum Tok {
    Word {
        text: String,
        start: usize,
        end: usize,
    },
    Punct {
        ch: char,
        start: usize,
        end: usize,
    },
}

impl Tok {
    fn word(&self) -> Option<&str> {
        match self {
            Tok::Word { text, .. } => Some(text),
            Tok::Punct { .. } => None,
        }
    }
}

/// 极简词法：字符串字面量整体跳过（`''` 相邻写法的净效果同样是"全部跳过"），
/// 引号标识符（`"x"` / `` `x` ``）折叠成词，其余按"字母数字/下划线/美元符"切词。
fn lex(sql: &str) -> Vec<Tok> {
    let mut out = Vec::new();
    let bytes = sql.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let Some(ch) = sql.get(i..).and_then(|s| s.chars().next()) else {
            i += 1;
            continue;
        };
        if ch.is_whitespace() {
            i += ch.len_utf8();
            continue;
        }
        if ch == '\'' {
            i += ch.len_utf8();
            while i < bytes.len() {
                let Some(c) = sql.get(i..).and_then(|s| s.chars().next()) else {
                    i += 1;
                    continue;
                };
                i += c.len_utf8();
                if c == '\'' {
                    break;
                }
            }
            continue;
        }
        if ch == '"' || ch == '`' {
            let quote = ch;
            let start = i;
            i += quote.len_utf8();
            let mut content = String::new();
            while i < bytes.len() {
                let Some(c) = sql.get(i..).and_then(|s| s.chars().next()) else {
                    i += 1;
                    continue;
                };
                i += c.len_utf8();
                if c == quote {
                    // 双写引号是字面引号（`"a""b"`）
                    let doubled = sql
                        .get(i..)
                        .and_then(|s| s.chars().next())
                        .is_some_and(|next| next == quote);
                    if doubled {
                        content.push(quote);
                        i += quote.len_utf8();
                        continue;
                    }
                    break;
                }
                content.push(c);
            }
            out.push(Tok::Word {
                text: content.to_lowercase(),
                start,
                end: i,
            });
            continue;
        }
        if ch.is_alphanumeric() || ch == '_' || ch == '$' {
            let start = i;
            while i < bytes.len() {
                let Some(c) = sql.get(i..).and_then(|s| s.chars().next()) else {
                    break;
                };
                if c.is_alphanumeric() || c == '_' || c == '$' {
                    i += c.len_utf8();
                } else {
                    break;
                }
            }
            out.push(Tok::Word {
                text: sql[start..i].to_lowercase(),
                start,
                end: i,
            });
            continue;
        }
        out.push(Tok::Punct {
            ch,
            start: i,
            end: i + ch.len_utf8(),
        });
        i += ch.len_utf8();
    }
    out
}

/// 一个表引用：`name` 是（可能带 schema 的）名字，`alias` 是可直接用于谓词限定的名字
/// （无别名时等于 name）。
#[derive(Debug, Clone, PartialEq, Eq)]
struct TableRef {
    name: String,
    alias: String,
}

/// 会终止 `FROM` 表清单的保留字
fn is_clause_keyword(w: &str) -> bool {
    matches!(
        w,
        "where"
            | "group"
            | "order"
            | "limit"
            | "having"
            | "union"
            | "on"
            | "using"
            | "join"
            | "left"
            | "right"
            | "inner"
            | "outer"
            | "cross"
            | "full"
            | "natural"
            | "except"
            | "intersect"
            | "window"
            | "qualify"
            | "for"
            | "offset"
    )
}

/// 出现在"表位置"但本身不是表名的保留字（遇到即说明这里是子查询/关键字）
fn is_table_position_keyword(w: &str) -> bool {
    matches!(w, "select" | "with" | "lateral" | "only" | "values")
}

/// 提取 `FROM` / `JOIN` 后的全部表引用（含逗号连写与别名）。
///
/// 逗号连写是此前的白名单绕过面：`FROM sys_user, secret_table` 原先只抽出 `sys_user`。
fn extract_table_refs(tokens: &[Tok]) -> Vec<TableRef> {
    let mut out: Vec<TableRef> = Vec::new();
    let mut expect_table = false;
    let mut after_table: Option<usize> = None;
    let mut expect_alias = false;
    let mut i = 0;
    while i < tokens.len() {
        match &tokens[i] {
            Tok::Word { text, .. } => {
                let w = text.as_str();
                if w == "from" || w == "join" {
                    expect_table = true;
                    after_table = None;
                    expect_alias = false;
                    i += 1;
                    continue;
                }
                if expect_table {
                    if is_table_position_keyword(w) {
                        expect_table = false;
                        i += 1;
                        continue;
                    }
                    let mut name = w.to_string();
                    let mut end_idx = i;
                    // schema.table / db.table：整段留作 name（白名单通常只有裸表名，
                    // 因此限定名会被拒——保守方向）
                    if matches!(tokens.get(i + 1), Some(Tok::Punct { ch: '.', .. }))
                        && let Some(Tok::Word { text: second, .. }) = tokens.get(i + 2)
                    {
                        name = format!("{name}.{second}");
                        end_idx = i + 2;
                    }
                    out.push(TableRef {
                        name: name.clone(),
                        alias: name,
                    });
                    expect_table = false;
                    after_table = Some(out.len() - 1);
                    expect_alias = false;
                    i = end_idx + 1;
                    continue;
                }
                if let Some(idx) = after_table {
                    if expect_alias {
                        out[idx].alias = w.to_string();
                        expect_alias = false;
                        i += 1;
                        continue;
                    }
                    if w == "as" {
                        expect_alias = true;
                        i += 1;
                        continue;
                    }
                    if is_clause_keyword(w) {
                        after_table = None;
                        i += 1;
                        continue;
                    }
                    // 裸别名
                    out[idx].alias = w.to_string();
                    i += 1;
                    continue;
                }
                i += 1;
            }
            Tok::Punct { ch: ',', .. } => {
                if after_table.is_some() {
                    after_table = None;
                    expect_table = true;
                }
                i += 1;
            }
            Tok::Punct { ch: '(', .. } => {
                // 子查询已在 guard 层被单 SELECT 规则拒绝；这里保守结束表名期待
                if expect_table {
                    expect_table = false;
                }
                i += 1;
            }
            _ => i += 1,
        }
    }
    out
}

/// 非平台调用者的租户谓词校验：每个表引用都必须有 `<别名>.tenant_id = tid`
/// （单表允许不带别名），且该谓词必须是 `WHERE`/`AND`/`ON` 的直接连接项。
fn tenant_filter_matches(
    tokens: &[Tok],
    refs: &[TableRef],
    tid: i64,
) -> Result<(), GuardViolation> {
    let mut qualified: Vec<String> = Vec::new();
    let mut unqualified = 0usize;
    let mut i = 0;
    while i < tokens.len() {
        // 形状：[alias .] tenant_id = <数字>
        let (qual, name_idx) = match (tokens.get(i), tokens.get(i + 1)) {
            (Some(Tok::Word { text, .. }), Some(Tok::Punct { ch: '.', .. })) if matches!(tokens.get(i + 2), Some(Tok::Word { text: t, .. }) if t == "tenant_id") => {
                (Some(text.clone()), i + 2)
            }
            (Some(Tok::Word { text, .. }), _) if text == "tenant_id" => (None, i),
            _ => {
                i += 1;
                continue;
            }
        };
        if !matches!(tokens.get(name_idx + 1), Some(Tok::Punct { ch: '=', .. })) {
            i += 1;
            continue;
        }
        let Some(Tok::Word { text: num, .. }) = tokens.get(name_idx + 2) else {
            i += 1;
            continue;
        };
        if num.parse::<i64>() != Ok(tid) {
            i += 1;
            continue;
        }
        // 前缀必须恰好是 WHERE/AND/ON（括号、逗号、其它运算符都不算）
        let prev_idx = if qual.is_some() {
            i.checked_sub(1)
        } else {
            name_idx.checked_sub(1)
        };
        let prev_ok = prev_idx
            .and_then(|p| tokens.get(p))
            .and_then(Tok::word)
            .is_some_and(|w| matches!(w, "where" | "and" | "on"));
        if !prev_ok {
            i += 1;
            continue;
        }
        // 后缀必须是子句边界（`IS NOT NULL`、`+ 1`、`)` 等都不算）
        let next_ok = match tokens.get(name_idx + 3) {
            None => true,
            Some(Tok::Word { text, .. }) => {
                matches!(
                    text.as_str(),
                    "and" | "group" | "order" | "limit" | "having"
                )
            }
            Some(_) => false,
        };
        if !next_ok {
            i += 1;
            continue;
        }
        match qual {
            Some(q) => qualified.push(q),
            None => unqualified += 1,
        }
        i = name_idx + 3;
    }

    if refs.len() == 1 {
        let r = &refs[0];
        if qualified.iter().any(|q| q == &r.alias) || unqualified > 0 {
            return Ok(());
        }
        return Err(GuardViolation(format!(
            "查询必须包含 `tenant_id = {tid}` 过滤（租户数据隔离）"
        )));
    }

    let missing: Vec<String> = refs
        .iter()
        .filter(|r| !qualified.iter().any(|q| q == &r.alias))
        .map(|r| format!("`{}`（别名 `{}`）", r.name, r.alias))
        .collect();
    if missing.is_empty() {
        Ok(())
    } else {
        Err(GuardViolation(format!(
            "多表查询里每张表都必须带 `<别名>.tenant_id = {tid}` 过滤；缺少：{}",
            missing.join("、")
        )))
    }
}

/// 行数上限：缺 `LIMIT` 追加；已有 `LIMIT` 且超限时**改写计数值**。
///
/// 支持 `LIMIT n`、`LIMIT n OFFSET m`、`LIMIT m, n` 三种形态；其它形态（表达式、
/// 绑定参数、每页条数与 `FOR UPDATE` 等尾部子句）一律拒绝——改写必须能定位到
/// "哪一个数字是行数"，否则宁可让 LLM 重写。
fn enforce_limit(sql: &str, tokens: &[Tok], max_rows: u32) -> Result<String, GuardViolation> {
    let max_rows = max_rows.max(1);
    let limit_positions: Vec<usize> = tokens
        .iter()
        .enumerate()
        .filter(|(_, t)| t.word() == Some("limit"))
        .map(|(i, _)| i)
        .collect();
    if limit_positions.is_empty() {
        return Ok(format!("{sql} LIMIT {max_rows}"));
    }
    if limit_positions.len() > 1 {
        return Err(GuardViolation("只允许一个顶层 LIMIT".into()));
    }
    let li = limit_positions[0];
    let is_digits = |s: &str| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit());

    let (count_idx, after_idx) = match tokens.get(li + 1) {
        Some(Tok::Word { text: n, .. }) if is_digits(n) => match tokens.get(li + 2) {
            None => (li + 1, li + 2),
            Some(Tok::Word { text: w, .. }) if w == "offset" => {
                let Some(Tok::Word { text: m, .. }) = tokens.get(li + 3) else {
                    return Err(GuardViolation("LIMIT OFFSET 形态无法识别".into()));
                };
                if !is_digits(m) {
                    return Err(GuardViolation("LIMIT OFFSET 形态无法识别".into()));
                }
                (li + 1, li + 4)
            }
            Some(Tok::Punct { ch: ',', .. }) => {
                let Some(Tok::Word { text: n2, .. }) = tokens.get(li + 3) else {
                    return Err(GuardViolation("LIMIT m, n 形态无法识别".into()));
                };
                if !is_digits(n2) {
                    return Err(GuardViolation("LIMIT m, n 形态无法识别".into()));
                }
                (li + 3, li + 4)
            }
            Some(_) => return Err(GuardViolation("LIMIT 之后不应再有其它子句".into())),
        },
        _ => {
            return Err(GuardViolation(
                "LIMIT 形态无法识别（只接受十进制行数）".into(),
            ));
        }
    };
    if after_idx != tokens.len() {
        return Err(GuardViolation("LIMIT 之后不应再有其它子句".into()));
    }
    let Tok::Word {
        text: count_text,
        start,
        end,
        ..
    } = &tokens[count_idx]
    else {
        return Err(GuardViolation("LIMIT 形态无法识别".into()));
    };
    let count: u64 = count_text
        .parse()
        .map_err(|_| GuardViolation("LIMIT 数值溢出".into()))?;
    if count <= max_rows as u64 {
        return Ok(sql.to_string());
    }
    let mut out = String::with_capacity(sql.len() + 2);
    out.push_str(&sql[..*start]);
    out.push_str(&max_rows.to_string());
    out.push_str(&sql[*end..]);
    Ok(out)
}

/// 校验结果：通过的 SQL（可能被改写：注入/收敛 LIMIT）与引用的表白名单
pub struct Guarded {
    /// 校验并改写后的 SQL（LIMIT 已对齐 max_rows）
    pub sql: String,
    /// SQL 引用的表（已验证全部在白名单内；同一表多次出现会重复列出）
    pub tables: Vec<String>,
}

/// `SELECT` 里同样有副作用/放大器的函数名（按函数调用形状匹配）
const DANGEROUS_FUNCS: &[&str] = &[
    // 文件读写 / 目录枚举
    "pg_read_file",
    "pg_read_binary_file",
    "pg_ls_dir",
    "pg_stat_file",
    "lo_import",
    "lo_export",
    "load_file",
    "openrowset",
    "opendatasource",
    // 网络/扩展调用
    "dblink",
    "dblink_connect",
    "dblink_exec",
    // 进程/CPU 停顿
    "pg_sleep",
    "pg_sleep_for",
    "pg_sleep_until",
    "pg_terminate_backend",
    "pg_cancel_backend",
    // 内存放大器
    "randomblob",
    "zeroblob",
    "benchmark",
    "sleep",
    "sys_eval",
    "sys_exec",
    "xp_cmdshell",
];

const FORBIDDEN_KEYWORDS: &[&str] = &[
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

/// 守卫主入口
///
/// - `caller_tid`：调用者租户 id（0 = 平台）。非 0 时逐表强制 `tenant_id` 过滤
/// - `allowed_tables`：表白名单（来自 `[ai].allowed_tables`）
/// - `max_rows`：行数上限（缺失时写入 LIMIT；超限时改写）
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
    let tokens = lex(trimmed);

    // 1. 只允许单条 SELECT 开头
    let Some(Tok::Word { text: first, .. }) = tokens.first() else {
        return Err(GuardViolation("仅允许 SELECT 查询".into()));
    };
    if first != "select" {
        return Err(GuardViolation("仅允许 SELECT 查询".into()));
    }

    // 2. 单语句 / 单 SELECT（子查询同样再造一个读面）
    if tokens
        .iter()
        .any(|t| matches!(t, Tok::Punct { ch: ';', .. }))
    {
        return Err(GuardViolation("不允许多条语句".into()));
    }
    if tokens.iter().any(|t| t.word() == Some("union")) {
        return Err(GuardViolation(
            "不允许 UNION（可用 OR 之外的 IN 列表，或拆成多次查询）".into(),
        ));
    }
    let select_count = tokens.iter().filter(|t| t.word() == Some("select")).count();
    if select_count > 1 {
        return Err(GuardViolation(
            "不允许子查询（内层查询会绕过逐表 tenant_id 过滤，请改用 JOIN）".into(),
        ));
    }

    // 3. 危险关键字（词边界匹配，防 "deleted_at" 误伤）
    for token in &tokens {
        if let Some(word) = token.word()
            && FORBIDDEN_KEYWORDS.contains(&word)
        {
            return Err(GuardViolation(format!("SQL 包含禁止的关键字: {word}")));
        }
    }

    // 4. 危险函数（`name(` 形状，允许函数名与括号之间有空白）
    for (i, token) in tokens.iter().enumerate() {
        let Some(word) = token.word() else { continue };
        if DANGEROUS_FUNCS.contains(&word)
            && matches!(tokens.get(i + 1), Some(Tok::Punct { ch: '(', .. }))
        {
            return Err(GuardViolation(format!("SQL 包含禁止的函数调用: {word}")));
        }
    }

    // 5. 表白名单（FROM/JOIN 的每一个表引用，含逗号连写）
    let refs = extract_table_refs(&tokens);
    if refs.is_empty() {
        return Err(GuardViolation("未能识别查询的表".into()));
    }
    for r in &refs {
        if !allowed_tables
            .iter()
            .any(|a| a.eq_ignore_ascii_case(&r.name))
        {
            return Err(GuardViolation(format!(
                "表 `{}` 不在允许查询的白名单内",
                r.name
            )));
        }
    }

    // 6. 租户强制
    if caller_tid != 0 {
        if tokens.iter().any(|t| t.word() == Some("or")) {
            return Err(GuardViolation(
                "租户查询不允许 OR（会把 tenant_id 过滤变成可选条件）".into(),
            ));
        }
        tenant_filter_matches(&tokens, &refs, caller_tid)?;
    }

    // 7. 行数上限
    let sql = enforce_limit(trimmed, &tokens, max_rows)?;

    Ok(Guarded {
        sql,
        tables: refs.into_iter().map(|r| r.name).collect(),
    })
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

    /// b98 立案：逗号连写的第二个表原先抽取不到 ⇒ `FROM sys_user, secret` 能过白名单。
    #[test]
    fn rejects_comma_joined_unlisted_table() {
        assert!(guard("SELECT * FROM sys_user, secret_table", 0, &tables(), 100).is_err());
        assert!(
            guard(
                "SELECT * FROM sys_user u, sys_dept d WHERE u.dept_id = d.dept_id",
                0,
                &tables(),
                100
            )
            .is_ok(),
            "两个都在白名单内的逗号连写必须放行（对照组）"
        );
    }

    /// 反引号/双引号里的表名同样要过白名单（词法把它们折叠成词）。
    #[test]
    fn quoted_table_names_are_still_checked() {
        assert!(guard("SELECT * FROM `secret_table`", 0, &tables(), 100).is_err());
        assert!(guard("SELECT * FROM \"secret_table\"", 0, &tables(), 100).is_err());
        assert!(guard("SELECT * FROM `sys_user`", 0, &tables(), 100).is_ok());
    }

    /// 子查询/UNION 一律拒绝：它们能在 WHERE 之外再造一个无租户谓词的读面。
    #[test]
    fn rejects_subqueries_and_union() {
        for sql in [
            "SELECT user_name FROM sys_user WHERE user_id IN (SELECT user_id FROM sys_dept)",
            "SELECT (SELECT COUNT(*) FROM sys_dept) FROM sys_user",
            "SELECT user_name FROM sys_user UNION SELECT user_name FROM sys_dept",
            "SELECT * FROM (SELECT * FROM sys_user) x",
        ] {
            assert!(
                guard(sql, 0, &tables(), 100).is_err(),
                "should reject: {sql}"
            );
        }
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

    /// b98 立案：`tenant_id = 50` 曾经命中 `tenant_id = 5` 的子串判据 ⇒ 越租过滤。
    #[test]
    fn tenant_number_must_match_exactly() {
        assert!(
            guard(
                "SELECT * FROM sys_user WHERE tenant_id = 50",
                5,
                &tables(),
                100
            )
            .is_err(),
            "50 不是 5，前缀相同不得放行"
        );
        assert!(
            guard(
                "SELECT * FROM sys_user WHERE tenant_id = 5 AND status = '1'",
                5,
                &tables(),
                100
            )
            .is_ok()
        );
    }

    /// b98 立案：谓词被二次运算（`IS NOT NULL` / `+1` / 括号包裹）后不再起过滤作用。
    #[test]
    fn tenant_predicate_must_be_a_plain_connector() {
        for sql in [
            "SELECT * FROM sys_user WHERE tenant_id = 5 IS NOT NULL",
            "SELECT * FROM sys_user WHERE (tenant_id = 5)",
            "SELECT * FROM sys_user WHERE tenant_id = 5 + 1",
            "SELECT * FROM sys_user WHERE tenant_id = 5 OR 1=1",
            "SELECT tenant_id = 5 FROM sys_user",
        ] {
            assert!(
                guard(sql, 5, &tables(), 100).is_err(),
                "should reject: {sql}"
            );
        }
    }

    /// b98 立案：JOIN 里只给主表过滤时，从表仍可读到其他租户的行。
    #[test]
    fn tenant_join_requires_predicate_per_table() {
        let one_filter = "SELECT u.user_name, d.dept_name FROM sys_user u JOIN sys_dept d ON u.dept_id = d.dept_id WHERE u.tenant_id = 5";
        assert!(guard(one_filter, 5, &tables(), 100).is_err());

        let both = "SELECT u.user_name, d.dept_name FROM sys_user u JOIN sys_dept d ON u.dept_id = d.dept_id WHERE u.tenant_id = 5 AND d.tenant_id = 5";
        assert!(guard(both, 5, &tables(), 100).is_ok());

        // 逗号连写同样逐表要求
        let comma_one =
            "SELECT u.user_name, d.dept_name FROM sys_user u, sys_dept d WHERE u.tenant_id = 5";
        assert!(guard(comma_one, 5, &tables(), 100).is_err());
    }

    #[test]
    fn rejects_string_literal_smuggling() {
        // 字符串里的分号/关键字/tenant_id 都不应参与判定
        assert!(
            guard(
                "SELECT user_name FROM sys_user WHERE remark = 'a;b;drop table'",
                0,
                &tables(),
                100
            )
            .is_ok()
        );
        assert!(
            guard(
                "SELECT user_name FROM sys_user WHERE remark = 'tenant_id = 5'",
                5,
                &tables(),
                100
            )
            .is_err(),
            "字符串里的 tenant_id 不算过滤条件"
        );
    }

    #[test]
    fn keeps_existing_limit() {
        let g = guard("SELECT user_name FROM sys_user LIMIT 10", 0, &tables(), 100).unwrap();
        assert!(g.sql.to_lowercase().contains("limit 10"));
    }

    /// b98 立案：文档写着"有 LIMIT 时校验不超过 max_rows"，实现却只判有没有 LIMIT。
    #[test]
    fn clamps_existing_limit_over_max_rows() {
        let g = guard(
            "SELECT user_name FROM sys_user LIMIT 100000000",
            0,
            &tables(),
            100,
        )
        .expect("必须通过并收敛");
        assert!(g.sql.ends_with("LIMIT 100"), "实际: {}", g.sql);

        let g = guard(
            "SELECT user_name FROM sys_user LIMIT 500 OFFSET 20",
            0,
            &tables(),
            100,
        )
        .expect("OFFSET 形态必须支持");
        assert!(g.sql.ends_with("LIMIT 100 OFFSET 20"), "实际: {}", g.sql);

        let g = guard(
            "SELECT user_name FROM sys_user LIMIT 20, 500",
            0,
            &tables(),
            100,
        )
        .expect("MySQL 逗号形态必须支持");
        assert!(g.sql.ends_with("LIMIT 20, 100"), "实际: {}", g.sql);
    }

    #[test]
    fn rejects_unrecognized_limit_forms() {
        for sql in [
            "SELECT user_name FROM sys_user LIMIT ?",
            "SELECT user_name FROM sys_user LIMIT 1+1",
            "SELECT user_name FROM sys_user LIMIT 10 FOR UPDATE",
        ] {
            assert!(
                guard(sql, 0, &tables(), 100).is_err(),
                "should reject: {sql}"
            );
        }
    }

    /// b98 立案：`SELECT pg_read_file(...) FROM 白名单表` 全是只读语法，但会读服务器文件。
    #[test]
    fn rejects_dangerous_functions() {
        for sql in [
            "SELECT pg_read_file('/etc/passwd') FROM sys_user",
            "SELECT pg_read_file ('/etc/passwd') FROM sys_user",
            "SELECT load_file('/etc/passwd') FROM sys_user",
            "SELECT randomblob(1000000000) FROM sys_user",
            "SELECT sleep(10) FROM sys_user",
            "SELECT pg_sleep(10) FROM sys_user",
        ] {
            assert!(
                guard(sql, 0, &tables(), 100).is_err(),
                "should reject: {sql}"
            );
        }
        // 普通函数不得误伤
        for sql in [
            "SELECT COUNT(*), COALESCE(MAX(user_id), 0) FROM sys_user",
            "SELECT SUBSTR(user_name, 1, 2) FROM sys_user",
        ] {
            assert!(guard(sql, 0, &tables(), 100).is_ok(), "should allow: {sql}");
        }
    }
}
