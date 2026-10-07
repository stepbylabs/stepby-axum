// stepby-axum/src/common/dataset_sql.rs
//! 数据集 SQL 模板白名单校验器（G-01 M1，批次七）
//!
//! **安全模型**：`report_dataset.sql_template` 是**管理员预注册**的参数化模板，
//! 运行期只做参数绑定（`Statement::from_sql_and_values`，占位符 `:name` → 方言参数），
//! **绝不拼接用户输入**。本模块是写入侧 fail-closed 校验器：
//! - 仅允许**单条 SELECT**；拒绝 DML/DDL/TCL（INSERT/UPDATE/DELETE/DROP/CREATE/...）；
//! - 拒绝多语句（`;` 分隔的第二条语句）、拒绝注释截断（`--` / `/* */`）；
//! - 拒绝 UNION（防止借 UNION 偷带任意子查询）、拒绝子查询括号嵌套（首版从简）；
//! - 占位符仅 `:param` 命名形态，参数名限标识符字符，且与 params_schema 声明一致（调用方核对）；
//! - **只读兜底**：DB 连接账号建议收窄为只读（部署文档级），纵深防御。
//!
//! 校验器是**纯函数 + 全量单测**；与 `custom_scope.rs`（数据权限白名单文法）同一设计哲学。

/// 校验结果：Ok(占位符参数名列表)
pub fn validate_select_template(sql: &str) -> Result<Vec<String>, String> {
    let sql = sql.trim();
    if sql.is_empty() {
        return Err("SQL 模板不能为空".to_string());
    }
    // 1. 去字符串字面量后做关键字扫描（字面量内的关键字不误伤）
    let stripped = strip_string_literals(sql);
    let upper = stripped.to_ascii_uppercase();
    // 2. 必须以 SELECT 开头
    if !upper.starts_with("SELECT") {
        return Err("仅允许 SELECT 查询".to_string());
    }
    // 3. DML/DDL/TCL 黑名单（词边界匹配，防列名误伤）
    let banned = [
        "INSERT", "UPDATE", "DELETE", "DROP", "CREATE", "ALTER", "TRUNCATE", "REPLACE", "MERGE",
        "GRANT", "REVOKE", "ATTACH", "DETACH", "PRAGMA", "VACUUM", "EXEC", "EXECUTE", "CALL",
    ];
    for b in banned {
        if has_word(&upper, b) {
            return Err(format!("SQL 模板包含禁止的关键字: {b}"));
        }
    }
    // 4. UNION / 括号子查询 / 注释 / 多语句
    if has_word(&upper, "UNION") {
        return Err("不允许 UNION（复杂查询请拆为视图或数据集）".to_string());
    }
    if stripped.contains('(') {
        return Err("首版不支持括号子查询（请用视图封装后 SELECT）".to_string());
    }
    if upper.contains("--") || upper.contains("/*") {
        return Err("不允许 SQL 注释".to_string());
    }
    // 5. 多语句：去掉字面量后若存在分号，则只允许**末尾一个**分号
    let semis: Vec<usize> = stripped
        .char_indices()
        .filter(|(_, c)| *c == ';')
        .map(|(i, _)| i)
        .collect();
    if semis.len() > 1 || (semis.len() == 1 && semis[0] != stripped.trim_end().len() - 1) {
        return Err("仅允许单条语句（禁止 `;` 分隔多语句）".to_string());
    }
    // 6. 占位符：`:name` 命名形态，参数名限标识符；去重后返回
    let mut params: Vec<String> = Vec::new();
    let bytes = sql.as_bytes();
    let mut i = 0usize;
    let mut in_quote = false;
    while i < bytes.len() {
        let c = bytes[i] as char;
        match c {
            '\'' => {
                if in_quote && i + 1 < bytes.len() && bytes[i + 1] == b'\'' {
                    i += 2;
                    continue;
                }
                in_quote = !in_quote;
                i += 1;
            }
            ':' if !in_quote => {
                let start = i + 1;
                let mut end = start;
                while end < bytes.len() {
                    let ch = bytes[end] as char;
                    if ch.is_ascii_alphanumeric() || ch == '_' {
                        end += 1;
                    } else {
                        break;
                    }
                }
                if end > start {
                    let name = sql[start..end].to_string();
                    if !params.contains(&name) {
                        params.push(name);
                    }
                    i = end;
                    continue;
                }
                i += 1;
            }
            _ => i += 1,
        }
    }
    Ok(params)
}

/// 去掉字符串字面量内容（保留结构），供关键字扫描使用（防 `SELECT 'DELETE FROM x'` 误报/漏报）
fn strip_string_literals(sql: &str) -> String {
    let bytes = sql.as_bytes();
    let mut out = String::with_capacity(sql.len());
    let mut in_quote = false;
    let mut i = 0usize;
    while i < bytes.len() {
        let c = bytes[i] as char;
        if c == '\'' {
            if in_quote && i + 1 < bytes.len() && bytes[i + 1] == b'\'' {
                i += 2;
                continue;
            }
            in_quote = !in_quote;
            out.push(' ');
            i += 1;
            continue;
        }
        if in_quote {
            out.push(' ');
        } else {
            out.push(c);
        }
        i += 1;
    }
    out
}

/// 词边界匹配（前后为非字母数字下划线）
fn has_word(haystack: &str, word: &str) -> bool {
    let bytes = haystack.as_bytes();
    let wb = word.as_bytes();
    if wb.len() > bytes.len() {
        return false;
    }
    for i in 0..=(bytes.len() - wb.len()) {
        if &bytes[i..i + wb.len()] == wb {
            let before_ok = i == 0 || !is_word_char(bytes[i - 1]);
            let after_ok = i + wb.len() == bytes.len() || !is_word_char(bytes[i + wb.len()]);
            if before_ok && after_ok {
                return true;
            }
        }
    }
    false
}

fn is_word_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_simple_select() {
        let p =
            validate_select_template("SELECT user_id, user_name FROM sys_user WHERE status = '0'")
                .unwrap();
        assert!(p.is_empty());
    }

    #[test]
    fn test_valid_with_named_param() {
        let p = validate_select_template(
            "SELECT user_id, user_name FROM sys_user WHERE dept_id = :deptId AND status = '0'",
        )
        .unwrap();
        assert_eq!(p, vec!["deptId".to_string()]);
    }

    #[test]
    fn test_non_select_rejected() {
        assert!(validate_select_template("DELETE FROM sys_user").is_err());
        assert!(validate_select_template("UPDATE sys_user SET status = '1'").is_err());
        assert!(validate_select_template("INSERT INTO sys_user VALUES (1)").is_err());
    }

    #[test]
    fn test_empty_rejected() {
        assert!(validate_select_template("").is_err());
        assert!(validate_select_template("   ").is_err());
    }

    #[test]
    fn test_multi_statement_rejected() {
        assert!(
            validate_select_template("SELECT 1; DELETE FROM sys_user").is_err(),
            "分号多语句应拒绝"
        );
    }

    #[test]
    fn test_trailing_semi_allowed() {
        assert!(validate_select_template("SELECT 1 FROM sys_user WHERE 1 = :v;").is_ok());
    }

    #[test]
    fn test_union_rejected() {
        assert!(
            validate_select_template(
                "SELECT user_id FROM sys_user UNION SELECT password FROM sys_user"
            )
            .is_err()
        );
    }

    #[test]
    fn test_subquery_paren_rejected() {
        assert!(
            validate_select_template(
                "SELECT user_id FROM sys_user WHERE dept_id IN (SELECT dept_id FROM sys_dept)"
            )
            .is_err()
        );
    }

    #[test]
    fn test_comment_rejected() {
        assert!(validate_select_template("SELECT user_id FROM sys_user -- comment").is_err());
        assert!(validate_select_template("SELECT /* hidden */ user_id FROM sys_user").is_err());
    }

    #[test]
    fn test_drop_in_literal_not_false_positive() {
        // 字面量里的关键字不误伤
        assert!(
            validate_select_template(
                "SELECT user_name FROM sys_user WHERE remark = 'DROP TABLE x'"
            )
            .is_ok()
        );
    }

    #[test]
    fn test_pragma_rejected() {
        assert!(validate_select_template("PRAGMA table_info(sys_user)").is_err());
    }

    #[test]
    fn test_param_in_literal_not_counted() {
        let p = validate_select_template(
            "SELECT user_name FROM sys_user WHERE remark = ':fake' AND dept_id = :real",
        )
        .unwrap();
        assert_eq!(p, vec!["real".to_string()]);
    }

    #[test]
    fn test_param_dedup() {
        let p = validate_select_template(
            "SELECT user_name FROM sys_user WHERE dept_id = :d OR leader_id = :d",
        )
        .unwrap();
        assert_eq!(p, vec!["d".to_string()]);
    }

    #[test]
    fn test_keyword_as_column_prefix_not_banned() {
        // 列名含黑名单词前缀不误伤（如 updated_by）
        assert!(validate_select_template("SELECT updated_by FROM sys_user").is_ok());
    }
}
