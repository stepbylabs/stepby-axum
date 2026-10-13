//! 数据权限加深：自定义部门 SQL（`custom_sql`）的安全解析与条件构建。
//! 权威口径与消费面矩阵见 docs/optimization/data-scope-matrix-2026-10-07.md（双路径之二）。
//!
//! # 动机
//!
//! `sys_role.data_scope = "2"`（自定义数据权限）原本仅支持「勾选部门」（sys_role_dept）。
//! 本模块允许在自定义模式下额外附加一条简单的**白名单列条件**（如：
//! `status = '0' AND dept_id >= 100`），扩展数据权限到"按字段过滤"。
//!
//! # 安全性（防 SQL 注入）
//!
//! `custom_sql` 存储于 DB，仅管理员可通过角色编辑接口写入；但为避免误配置或绕过权限
//! 的恶意值，运行时绝**不**把该片段拼接为裸 SQL。相反：
//!
//! 1. 先由 [`parse_custom_sql`] 对片段做严格白名单解析——支持极小子集文法：
//!    `column op value [AND column op value ...]`；
//! 2. 仅允许列出列名（由调用方传入的 `allowed_columns` 白名单决定）；
//! 3. 仅允许 7 种运算符（= != > < >= <= LIKE）与两类字面量（整数 / 单引号字符串）；
//! 4. 拒绝任何与文法不符的输入（含 `;`、`--`、`UNION`、`(`、函数调用、双引号等）。
//!
//! 解析成功后得到结构化的 [`CustomCondition`]，交给查询层用 SeaORM 的 `Column::eq(值)`
//! 等**参数化**方式重建条件 —— 片段里的值只作为绑定参数，绝不经 SQL 文本进入数据库。
//!
//! # 文法
//!
//! 形如 `col op value`，多个条件用 `AND`（不区分大小写、允许空白）连接：
//!
//! ```text
//! condition := column op value
//! column    := [A-Za-z_][A-Za-z0-9_]*   （且须在调用方白名单中）
//! op        := "=" | "!=" | ">" | "<" | ">=" | "<=" | "LIKE"
//! value     := integer | 'string'   （字符串用单引号包裹，内嵌 '' 表示转义 ')
//! ```

use std::fmt;

use sea_orm::sea_query::{Condition, SimpleExpr};

/// 单个解析后的自定义条件（已通过白名单校验）
#[derive(Debug, Clone, PartialEq)]
pub struct CustomCondition {
    /// 目标列名（**必须**在调用方白名单内，否则解析失败或丢弃）
    pub column: String,
    /// 运算符
    pub op: Op,
    /// 字面值（整数或字符串）
    pub value: Value,
}

/// 允许的运算符子集
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Op {
    Eq,
    Ne,
    Gt,
    Gte,
    Lt,
    Lte,
    Like,
}

/// 字面值（仅整数与字符串两种）
#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    Int(i64),
    Str(String),
}

impl Value {
    pub fn as_i64(&self) -> Option<i64> {
        match self {
            Value::Int(v) => Some(*v),
            Value::Str(_) => None,
        }
    }
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Value::Str(s) => Some(s),
            Value::Int(_) => None,
        }
    }
}

/// 解析失败的错误信息
#[derive(Debug, Clone, PartialEq)]
pub struct ParseError(pub String);

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "custom_sql 解析失败: {}", self.0)
    }
}

impl std::error::Error for ParseError {}

/// 默认允许列：`sys_user` 可被自定义数据权限过滤的列（用户列表路径）。
///
/// 白名单是防注入的第二道闸门——即使文法允许某标识符，只要不在白名单内即被拒绝。
pub const USER_CUSTOM_COLUMNS: &[&str] = &[
    "user_id",
    "dept_id",
    "user_name",
    "nick_name",
    "phonenumber",
    "email",
    "status",
    "sex",
];

/// 把 `custom_sql` 的原始片段字符串切分为若干子条件（按 `AND` 连接）。
///
/// 用逐字符扫描，仅在**引号外**识别 ` AND ` 分隔符（不区分大小写），避免在字符串
/// 字面量内含 `AND`（如 `user_name = 'Rock AND Roll'`）时被误切。
fn split_and_fragments(input: &str) -> Vec<String> {
    let bytes = input.as_bytes();
    let mut in_quote = false;
    let mut conn = Vec::new();
    let mut start = 0usize;
    let mut i = 0usize;

    while i < bytes.len() {
        let c = bytes[i] as char;
        match c {
            '\'' => {
                // 处理转义 ''：两个连续单引号视为字符串内的一个字面引号
                if in_quote && i + 1 < bytes.len() && bytes[i + 1] == b'\'' {
                    i += 2;
                    continue;
                }
                in_quote = !in_quote;
                i += 1;
            }
            _ if !in_quote && c.is_whitespace() && i + 5 <= bytes.len() => {
                // 在引号外识别分隔符 " AND "（不区分大小写，前后为空白界定）
                let word_is_and = input
                    .get(i + 1..i + 4)
                    .map(|s| s.eq_ignore_ascii_case("and"))
                    .unwrap_or(false);
                let after_is_space = input
                    .get(i + 4..i + 5)
                    .map(|s| s.chars().next().unwrap().is_whitespace())
                    .unwrap_or(false);
                if word_is_and && after_is_space {
                    conn.push(input[start..i].to_string());
                    i += 5;
                    start = i;
                } else {
                    i += 1;
                }
            }
            _ => i += 1,
        }
    }
    // 收尾：若末尾还有非空余留片段，则追加；若无片段则整体按单一片段处理
    if conn.is_empty() {
        if input.trim().is_empty() {
            return conn;
        }
        return vec![input.trim().to_owned()];
    }
    if !input[start..].trim().is_empty() {
        conn.push(input[start..].trim().to_string());
    }
    conn.into_iter().filter(|p| !p.trim().is_empty()).collect()
}

/// 解析单条 `col op value` 子条件。
fn parse_single(fragment: &str) -> Result<CustomCondition, ParseError> {
    let trimmed = fragment.trim();
    if trimmed.is_empty() {
        return Err(ParseError("空条件".into()));
    }
    // 明确拒绝明显注入载荷：分号、注释、子查询括号、UNION、引号混乱等
    for bad in [
        ";", "--", "/*", "*/", "(", ")", ",", "\"", "`", "UNION", "SELECT", "DROP", "DELETE",
        "UPDATE", "INSERT", " OR ",
    ] {
        if trimmed.to_uppercase().contains(bad) {
            return Err(ParseError(format!("包含非法关键字/字符: {bad}")));
        }
    }

    let re = regex::Regex::new(
        r"^\s*([A-Za-z_][A-Za-z0-9_]*)\s*(=|!=|>=|<=|LIKE|>|<)\s*('(?:''|[^'])*'|-?[0-9]+)\s*$",
    )
    .expect("静态正则");
    let caps = re
        .captures(trimmed)
        .ok_or_else(|| ParseError("不符合 `column op value` 简单文法".into()))?;

    let column = caps[1].to_string();
    let op = match caps[2].to_uppercase().as_str() {
        "=" => Op::Eq,
        "!=" => Op::Ne,
        ">" => Op::Gt,
        ">=" => Op::Gte,
        "<" => Op::Lt,
        "<=" => Op::Lte,
        "LIKE" => Op::Like,
        _ => return Err(ParseError(format!("不支持的运算符: {}", &caps[2]))),
    };

    let raw_value = caps[3].to_string();
    let value = if raw_value.starts_with('\'') {
        // 去掉首尾单引号，反转义 '' → '
        let inner = raw_value[1..raw_value.len() - 1].to_string();
        Value::Str(inner.replace("''", "'"))
    } else {
        let v: i64 = raw_value
            .parse()
            .map_err(|_| ParseError("整数解析失败".into()))?;
        Value::Int(v)
    };

    Ok(CustomCondition { column, op, value })
}

/// 解析并白名单校验一整段 `custom_sql`。
///
/// - `fragment`：DB 中存储的原始片段（形如 `status = '0' AND dept_id >= 100`）
/// - `allowed_columns`：本次查询允许使用的列名白名单
///
/// 返回通过校验的条件列表；任何一环不合法即返回 [`ParseError`]（调用方应 fail-closed，
/// 即忽略该自定义过滤或拒绝请求，但**绝不**把片段当 SQL 执行）。
pub fn parse_custom_sql(
    fragment: &str,
    allowed_columns: &[&str],
) -> Result<Vec<CustomCondition>, ParseError> {
    let fragment = fragment.trim();
    if fragment.is_empty() {
        return Ok(Vec::new());
    }
    let pieces = split_and_fragments(fragment);
    let mut out = Vec::with_capacity(pieces.len());
    for p in &pieces {
        let c = parse_single(p)?;
        if !allowed_columns.contains(&c.column.as_str()) {
            return Err(ParseError(format!("列不在白名单内: {}", c.column)));
        }
        out.push(c);
    }
    if out.is_empty() {
        return Err(ParseError("未能解析出任何有效条件".into()));
    }
    Ok(out)
}

/// 从 operator 的角色中提取自定义数据权限条件。
///
/// 仅收集 `data_scope == "2"`（自定义）角色的 `custom_sql`，取第一个非空且可解析者。
///
/// **fail-closed 语义（5-1 修复，v4 §V4-E3）**：解析失败（含注入尝试 / 列不在白名单）返回
/// `Err`，由调用方**拒绝本次请求**——"不把片段当 SQL 执行"只防住了注入，防不住越权；
/// 若静默返回 `Ok(None)`，该角色将失去字段级过滤（数据范围被放大），属于 fail-open。
pub fn derive_user_custom_conditions(
    roles: &[crate::entity::sys_role::Model],
) -> Result<Option<Vec<CustomCondition>>, ParseError> {
    for r in roles {
        if r.data_scope.as_deref() != Some("2") {
            continue;
        }
        let Some(sql) = r.custom_sql.as_deref() else {
            continue;
        };
        match parse_custom_sql(sql, USER_CUSTOM_COLUMNS) {
            Ok(conds) if !conds.is_empty() => return Ok(Some(conds)),
            Ok(_) => continue,
            Err(e) => {
                tracing::warn!(
                    role_id = r.role_id,
                    "custom_sql 解析失败，拒绝本次请求（fail-closed）: {}",
                    e
                );
                return Err(e);
            }
        }
    }
    Ok(None)
}

/// 把一组自定义条件 + 解析器组合成一条 `Condition`（参数化）。
///
/// `resolver` 负责把 `CustomCondition` 映射为参数化的 `SimpleExpr`（例如
/// `Column::Status.eq("0")`）。返回 `None` 表示没有任何逻辑可附加（条件为空或全部被丢弃），
/// 调用方照常继续原查询。
pub fn build_filter(
    conditions: &[CustomCondition],
    resolver: impl Fn(&CustomCondition) -> Option<SimpleExpr>,
) -> Option<Condition> {
    if conditions.is_empty() {
        return None;
    }
    let mut out = Condition::all();
    let mut added = false;
    for c in conditions {
        if let Some(expr) = resolver(c) {
            out = out.add(expr);
            added = true;
        }
    }
    if added { Some(out) } else { None }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_simple_single_condition() {
        let conds = parse_custom_sql("status = '0'", USER_CUSTOM_COLUMNS).unwrap();
        assert_eq!(conds.len(), 1);
        assert_eq!(conds[0].column, "status");
        assert_eq!(conds[0].op, Op::Eq);
        assert_eq!(conds[0].value, Value::Str("0".to_string()));
    }

    #[test]
    fn parses_and_of_multiple_conditions() {
        let conds =
            parse_custom_sql("status = '0' AND dept_id >= 100", USER_CUSTOM_COLUMNS).unwrap();
        assert_eq!(conds.len(), 2);
        assert_eq!(conds[0].column, "status");
        assert_eq!(conds[1].column, "dept_id");
        assert_eq!(conds[1].op, Op::Gte);
        assert_eq!(conds[1].value, Value::Int(100));
    }

    #[test]
    fn parses_integer_and_string_value_unescape() {
        let conds = parse_custom_sql("sex = 'O''Brien'", USER_CUSTOM_COLUMNS).unwrap();
        assert_eq!(conds[0].value, Value::Str("O'Brien".to_string()));
        let conds = parse_custom_sql("user_id != 0", USER_CUSTOM_COLUMNS).unwrap();
        assert_eq!(conds[0].op, Op::Ne);
        assert_eq!(conds[0].value, Value::Int(0));
    }

    #[test]
    fn empty_or_all_whitespace_returns_empty() {
        assert_eq!(parse_custom_sql("", USER_CUSTOM_COLUMNS).unwrap().len(), 0);
        assert_eq!(
            parse_custom_sql("   ", USER_CUSTOM_COLUMNS).unwrap().len(),
            0
        );
    }

    #[test]
    fn rejects_injection_attempts() {
        let bad = [
            "1=1; DROP TABLE sys_user",
            "'x' OR '1'='1",
            "status = '0' -- comment",
            "status = '0' UNION SELECT * FROM sys_user",
            "(select 1)",
            "status = \"0\"",             // 双引号
            "status = '0'; drop table x", // 分号
            "col`name` = 1",              // 反引号
            "dept_id = SLEEP(5)",         // 函数调用
            "user_name LIKE '%'; --",     // 注释
            "'Bad AND (inject' = 1",      // 括号
        ];
        for s in bad {
            assert!(
                parse_custom_sql(s, USER_CUSTOM_COLUMNS).is_err(),
                "应拒绝输入: {s}"
            );
        }
    }

    #[test]
    fn rejects_column_not_in_whitelist() {
        assert!(parse_custom_sql("password = 'x'", USER_CUSTOM_COLUMNS).is_err());
        assert!(parse_custom_sql("login_ip = '1.1.1.1'", USER_CUSTOM_COLUMNS).is_err());
    }

    #[test]
    fn accepts_only_allowed_columns() {
        // 白名单内的列才通过
        let ok = parse_custom_sql(
            "status LIKE '0%' AND user_name = 'admin'",
            USER_CUSTOM_COLUMNS,
        );
        assert!(ok.is_ok());
        assert_eq!(ok.unwrap().len(), 2);
    }

    #[test]
    fn build_filter_appends_parameterized_condition_to_query() {
        // build_filter 仅在 resolver 能产出 SimpleExpr 时才组装（参数化，不拼 SQL）。
        // 这里用受控映射验证：能解析的列得到 Some 条件；被丢弃的列不影响结果。
        use sea_orm::ColumnTrait;
        let conds = parse_custom_sql("status = '0'", USER_CUSTOM_COLUMNS).unwrap();
        let mapped = build_filter(&conds, |c| match c.column.as_str() {
            "status" => {
                Some(crate::entity::sys_user::Column::Status.eq(c.value.as_str().unwrap_or("")))
            }
            _ => None,
        });
        assert!(mapped.is_some());
    }

    #[test]
    fn build_filter_drops_unresolvable_and_returns_none() {
        let conds = parse_custom_sql("status = '0'", USER_CUSTOM_COLUMNS).unwrap();
        assert!(build_filter(&conds, |_| None).is_none());
    }

    #[test]
    fn build_filter_returns_none_for_empty_input() {
        assert!(build_filter(&[], |_| None).is_none());
    }

    /// 构造一个可复用的最小 sys_role::Model（测试专用）
    fn role(
        id: i64,
        scope: Option<&str>,
        custom_sql: Option<&str>,
    ) -> crate::entity::sys_role::Model {
        crate::entity::sys_role::Model {
            tenant_id: 0,
            is_system: false,
            role_id: id,
            role_name: format!("role-{id}"),
            role_key: format!("key-{id}"),
            role_sort: 0,
            data_scope: scope.map(|s| s.to_owned()),
            custom_sql: custom_sql.map(|s| s.to_owned()),
            menu_check_strictly: None,
            dept_check_strictly: None,
            status: "0".to_owned(),
            del_flag: None,
            create_by: None,
            create_time: None,
            update_by: None,
            update_time: None,
            remark: None,
        }
    }

    #[test]
    fn derive_picks_custom_scope_role_custom_sql() {
        // (a) data_scope=custom + custom_sql → 应提取出自定义条件
        let roles = vec![role(1, Some("2"), Some("status = '0'"))];
        let conds = derive_user_custom_conditions(&roles).unwrap().unwrap();
        assert_eq!(conds.len(), 1);
        assert_eq!(conds[0].column, "status");
    }

    #[test]
    fn derive_ignores_non_custom_scope() {
        // (b) data_scope=本部门(3) → 不生成自定义条件（走部门过滤路径）
        assert!(
            derive_user_custom_conditions(&[role(1, Some("3"), None)])
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn derive_rejects_injection_safely() {
        // (d) 注入尝试的 custom_sql → Err（fail-closed：调用方拒绝请求，绝不拼 SQL）
        assert!(
            derive_user_custom_conditions(&[role(1, Some("2"), Some("1=1; DROP TABLE sys_user"))])
                .is_err()
        );
    }

    #[test]
    fn derive_ignores_invalid_custom_sql_on_noncustom_role_first() {
        // 多角色：先一个 data_scope=2 但 custom_sql 非法，随后的合法角色不应被采用
        // （fail-closed：出现非法时整体拒绝本次请求，保护数据权限不绕过）
        let roles = vec![
            role(1, Some("2"), Some("1=1; DROP TABLE sys_user")),
            role(2, Some("2"), Some("status = '0'")),
        ];
        assert!(derive_user_custom_conditions(&roles).is_err());
    }

    // ---------- Value::as_i64 / as_str ----------

    #[test]
    fn value_as_i64_only_for_int() {
        assert_eq!(Value::Int(42).as_i64(), Some(42));
        assert_eq!(Value::Int(-7).as_i64(), Some(-7));
        assert_eq!(Value::Str("42".to_string()).as_i64(), None);
    }

    #[test]
    fn value_as_str_only_for_string() {
        assert_eq!(Value::Str("abc".to_string()).as_str(), Some("abc"));
        assert_eq!(Value::Str(String::new()).as_str(), Some(""));
        assert_eq!(Value::Int(1).as_str(), None);
    }

    // ---------- split_and_fragments 引号内 AND 不误切 ----------

    #[test]
    fn split_keeps_and_inside_string_literal() {
        let parts = split_and_fragments("user_name = 'Rock AND Roll' AND status = '0'");
        assert_eq!(
            parts,
            vec![
                "user_name = 'Rock AND Roll'".to_string(),
                "status = '0'".to_string(),
            ]
        );
    }

    #[test]
    fn split_handles_escaped_quote_inside_string() {
        let parts = split_and_fragments("user_name = 'O''Brien' AND status = '0'");
        assert_eq!(parts.len(), 2);
        assert_eq!(parts[0], "user_name = 'O''Brien'");
        assert_eq!(parts[1], "status = '0'");
    }

    #[test]
    fn parse_custom_sql_and_inside_string_is_preserved() {
        let conds = parse_custom_sql(
            "user_name = 'Rock AND Roll' AND status = '0'",
            USER_CUSTOM_COLUMNS,
        )
        .unwrap();
        assert_eq!(conds.len(), 2);
        assert_eq!(conds[0].column, "user_name");
        assert_eq!(conds[0].value, Value::Str("Rock AND Roll".to_string()));
        assert_eq!(conds[1].column, "status");
        assert_eq!(conds[1].value, Value::Str("0".to_string()));
    }

    // ---------- 运算符与字面量更多分支 ----------

    #[test]
    fn parses_like_op_and_wildcard_value() {
        let conds = parse_custom_sql("user_name LIKE 'admin%'", USER_CUSTOM_COLUMNS).unwrap();
        assert_eq!(conds[0].op, Op::Like);
        assert_eq!(conds[0].value, Value::Str("admin%".to_string()));
    }

    #[test]
    fn parses_comparison_operators() {
        let conds = parse_custom_sql(
            "dept_id > 100 AND dept_id < 200 AND dept_id >= 150 AND dept_id <= 160 AND dept_id != 0",
            USER_CUSTOM_COLUMNS,
        )
        .unwrap();
        assert_eq!(conds.len(), 5);
        assert_eq!(conds[0].op, Op::Gt);
        assert_eq!(conds[1].op, Op::Lt);
        assert_eq!(conds[2].op, Op::Gte);
        assert_eq!(conds[3].op, Op::Lte);
        assert_eq!(conds[4].op, Op::Ne);
        assert_eq!(conds[0].value, Value::Int(100));
        assert_eq!(conds[1].value, Value::Int(200));
    }

    #[test]
    fn parses_negative_integer_value() {
        let conds = parse_custom_sql("dept_id = -5", USER_CUSTOM_COLUMNS).unwrap();
        assert_eq!(conds[0].value, Value::Int(-5));
    }

    #[test]
    fn rejects_trailing_and() {
        // "status = '0' AND"（AND 后无内容）不符合文法 → Err
        assert!(parse_custom_sql("status = '0' AND", USER_CUSTOM_COLUMNS).is_err());
    }

    #[test]
    fn rejects_unsupported_op_text() {
        // 非法运算符写法（如用 "==" 或 "eq"）→ Err
        assert!(parse_custom_sql("dept_id == 100", USER_CUSTOM_COLUMNS).is_err());
        assert!(parse_custom_sql("dept_id eq 100", USER_CUSTOM_COLUMNS).is_err());
    }

    // ---------- derive 更多分支 ----------

    #[test]
    fn derive_skips_role_without_custom_scope_value() {
        // data_scope 为 None 的角色跳过
        assert!(
            derive_user_custom_conditions(&[role(1, None, Some("status = '0'"))])
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn derive_continues_when_custom_sql_is_none() {
        // data_scope=2 但 custom_sql 为 None → 继续，最终 None
        assert!(
            derive_user_custom_conditions(&[role(1, Some("2"), None)])
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn derive_continues_when_custom_sql_is_blank() {
        // data_scope=2 但 custom_sql 为空白（解析为空）→ 继续，最终 None
        assert!(
            derive_user_custom_conditions(&[role(1, Some("2"), Some("   "))])
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn derive_picks_first_valid_custom_role() {
        // 第一个 data_scope != 2，第二个 data_scope=2 且合法 → 采用第二个
        let roles = vec![
            role(1, Some("1"), None),
            role(2, Some("2"), Some("status = '0'")),
        ];
        let conds = derive_user_custom_conditions(&roles).unwrap().unwrap();
        assert_eq!(conds.len(), 1);
        assert_eq!(conds[0].column, "status");
    }

    // ---------- build_filter 部分可解析 ----------

    #[test]
    fn build_filter_appends_when_some_resolvable() {
        use sea_orm::ColumnTrait;
        let conds =
            parse_custom_sql("status = '0' AND dept_id >= 100", USER_CUSTOM_COLUMNS).unwrap();
        // 仅 status 可解析，dept_id 被丢弃 → 仍应组装出 Some 条件
        let mapped = build_filter(&conds, |c| match c.column.as_str() {
            "status" => {
                Some(crate::entity::sys_user::Column::Status.eq(c.value.as_str().unwrap_or("")))
            }
            _ => None,
        });
        assert!(mapped.is_some());
    }
}
