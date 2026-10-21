//! 方言占位符单一事实源（b83 新增）。
//!
//! ## 为什么必须有这个模块
//!
//! `src/shared_store/local_store.rs:80` 的注释长期写着"占位符统一写 `?`，sea-orm 负责 PG 端
//! `$n` 转译"。**这句话是错的**，而且是全仓 41 处裸 SQL（`LocalStore` 31 条 + 生产码 10 条）
//! 的写法来源。实测取证（本机 `postgres:17-alpine` 容器，与
//! `deploy/docker-compose.db.yml` 交付的镜像同版本）：
//!
//! ```text
//! PREPARE p1 AS SELECT 1 WHERE 1 = ?;   ⇒ ERROR: syntax error at or near ";"
//! PREPARE p2 AS SELECT 1 WHERE 1 = $1;  ⇒ PREPARE（成功）
//! ```
//!
//! 库侧原因（读 sea-orm 2.0.4 源码，不是推测）：`Statement::from_sql_and_values` 只把 SQL
//! **原样存下**（`statement.rs:64-73`），`?` → `$n` 的 `inject_parameters` 仅出现在
//! `impl fmt::Display for Statement`（`statement.rs:76-95`，调试打印用）；执行路径
//! `driver/sqlx_postgres.rs:346-351` 是
//! `sqlx::query_with(AssertSqlSafe(stmt.sql), SqlxValues(values))`——`?` 从未被改写。
//!
//! 后果不是"报错难看"而是**功能在 PG 部署下整块不可用**：登录密码版本双写、令牌吊销回填、
//! AI 会话历史、共享态（`cache.mode = local`）的全部读写，都会在第一根 `?` 上语法失败。
//!
//! ## 口径
//!
//! - SQLite / MySQL：`?` 原生可用，原样透传。
//! - Postgres：把**单引号字面量之外**的 `?` 依序换成 `$1..$n`。
//! - 已知不适用的形态（本模块故意不猜，出现即应在评审时改写法）：dollar-quoted
//!   `$$ … $$` 体内含 `?`、PG 的 `?` / `?|` / `?&` 操作符（jsonb 存在性判断）。
//!   其中 `?|` / `?&` 是可判定的，由
//!   `unambiguous_operator_forms_are_absent_and_bare_operator_is_a_pinned_limitation`
//!   扫全仓生产码钉为 0 处；裸 `?` 作操作符与作占位符文本上不可区分，**不做半可靠扫描**
//!   （实测那条启发式会把 22 处普通占位符报成违规），只把"它会被改坏"钉成断言 ⇒
//!   引入该写法的人必须先动本模块。

use sea_orm::{DatabaseBackend, Statement, Value};

/// 把 `?` 依序改写为 `$1..$n`（Postgres 风格）。单引号字面量内的 `?` 不动，
/// `''`（SQL 转义的单引号）不结束字面量。无 `?` 时返回原串的拷贝（幂等）。
pub fn to_pg_placeholders(sql: &str) -> String {
    let mut out = String::with_capacity(sql.len() + 8);
    let mut in_literal = false;
    let mut idx = 0usize;
    let mut chars = sql.chars().peekable();
    while let Some(c) = chars.next() {
        if in_literal {
            out.push(c);
            if c == '\'' {
                match chars.peek() {
                    // '' = 字面量内的转义单引号，继续留在字面量里
                    Some('\'') => {
                        out.push(chars.next().unwrap());
                    }
                    _ => in_literal = false,
                }
            }
            continue;
        }
        match c {
            '\'' => {
                in_literal = true;
                out.push(c);
            }
            '?' => {
                idx += 1;
                out.push_str(&format!("${idx}"));
            }
            _ => out.push(c),
        }
    }
    out
}

/// 以真实后端构造参数化语句：Postgres 走 `to_pg_placeholders`，其余原样。
///
/// 形参 bound 与 `Statement::from_sql_and_values` 完全一致
/// （sea-orm 2.0.4 `statement.rs:56-60`：`I: IntoIterator<Item = Value>`），
/// 所以数组 `[v.into(); N]` 与 `Vec<Value>` 两种既有写法都能直接搬过来。
///
/// 生产码里所有裸 SQL 都应经这里（或经 `LocalStore::stmt` 这一层薄封装）。
/// 已经手写 `$n` 的语句同样安全：不含 `?` 时转换是恒等的。
pub fn stmt<I: IntoIterator<Item = Value>>(
    backend: DatabaseBackend,
    sql: &str,
    values: I,
) -> Statement {
    if matches!(backend, DatabaseBackend::Postgres) {
        let rewritten = to_pg_placeholders(sql);
        Statement::from_sql_and_values(backend, rewritten, values)
    } else {
        Statement::from_sql_and_values(backend, sql, values)
    }
}

/// 同上，但实参是运行期拼出来的 `Vec<Value>`（`LocalStore::stmt` 的形状）。
pub fn stmt_vec(backend: DatabaseBackend, sql: &str, values: Vec<Value>) -> Statement {
    stmt(backend, sql, values)
}

#[cfg(test)]
mod tests {
    //! 覆盖意图：改写规则的四条边界（顺序、字面量、转义引号、幂等）+ 三档后端的透传方向，
    //! 外加一条"本模块不猜"的反证——PG 的 `?` 操作符与 dollar-quote 不在支持面内，
    //! 出现时必须由判据红出来，而不是被静默改坏成一条语义不同的 SQL。

    use super::*;

    #[test]
    fn rewrites_in_positional_order() {
        assert_eq!(
            to_pg_placeholders("INSERT INTO t (a, b, c) VALUES (?, ?, ?)"),
            "INSERT INTO t (a, b, c) VALUES ($1, $2, $3)"
        );
        // 同一序号不复用：三个 ? 必须是三个不同参数
        assert_eq!(
            to_pg_placeholders("? = ? AND ? <> ?"),
            "$1 = $2 AND $3 <> $4"
        );
    }

    #[test]
    fn keeps_question_marks_inside_string_literals() {
        assert_eq!(
            to_pg_placeholders("SELECT * FROM t WHERE note = 'a?b' AND k = ?"),
            "SELECT * FROM t WHERE note = 'a?b' AND k = $1"
        );
        // '' 是字面量内的转义单引号，不结束字面量——否则后面的 ? 会被误当成占位符
        assert_eq!(
            to_pg_placeholders("WHERE title = 'it''s ? fine' AND id = ?"),
            "WHERE title = 'it''s ? fine' AND id = $1"
        );
    }

    #[test]
    fn is_identity_without_question_marks_and_when_already_dollar_style() {
        let plain = "SELECT 1 FROM sys_config WHERE config_key = $1";
        assert_eq!(
            to_pg_placeholders(plain),
            plain,
            "已写 $n 的语句必须不被二次改写"
        );
        let none = "CREATE INDEX idx ON t (a)";
        assert_eq!(to_pg_placeholders(none), none);
        // 再跑一遍仍是自身（幂等：$n 里不含 ?）
        assert_eq!(
            to_pg_placeholders(&to_pg_placeholders("a = ? AND b = ?")),
            "a = $1 AND b = $2"
        );
    }

    #[test]
    fn non_postgres_backends_pass_through_unchanged() {
        for backend in [DatabaseBackend::Sqlite, DatabaseBackend::MySql] {
            let s = stmt(
                backend,
                "SELECT * FROM t WHERE a = ?",
                [Value::Int(Some(1))],
            );
            assert_eq!(
                s.sql, "SELECT * FROM t WHERE a = ?",
                "{backend:?} 必须原样透传"
            );
        }
        let pg = stmt(
            DatabaseBackend::Postgres,
            "SELECT * FROM t WHERE a = ?",
            [Value::Int(Some(1))],
        );
        assert_eq!(pg.sql, "SELECT * FROM t WHERE a = $1");
        assert_eq!(pg.db_backend, DatabaseBackend::Postgres);
    }

    #[test]
    fn stmt_vec_shape_matches_stmt() {
        let a = stmt_vec(
            DatabaseBackend::Postgres,
            "UPDATE t SET v = ? WHERE k = ?",
            vec![Value::String(Some("x".into())), Value::Int(Some(3))],
        );
        assert_eq!(a.sql, "UPDATE t SET v = $1 WHERE k = $2");
        assert_eq!(
            a.values.as_ref().map(|v| v.0.len()),
            Some(2),
            "参数个数必须与改写后的占位符个数一致"
        );
    }

    /// 已知不支持面：PG 的 jsonb 存在性操作符 `?` / `?|` / `?&` 会被转换器当占位符。
    ///
    /// **只做可判定的一半**：`?|` 与 `?&` 是操作符独有形态（占位符不可能长成这样），
    /// 扫到即红。裸 `?` 作操作符与作占位符在文本上不可区分——本批首跑用宽松启发式
    /// （"DML 行里含 ` ? `"）扫出 22 处"违规"，全是普通占位符，那条判据纯属噪声；
    /// 按 b82 §15 N-25 的纪律：**宁可有一条台账，不要有一条会漏报/误报的锁**。
    /// 但把"它确实会被改坏"钉成断言，任何引入该写法的改动都必须先来动本模块。
    #[test]
    fn unambiguous_operator_forms_are_absent_and_bare_operator_is_a_pinned_limitation() {
        // ① 局限为真的证据（不是"这可用"，而是"这会被改坏"）
        assert_eq!(to_pg_placeholders("meta ? 'key'"), "meta $1 'key'");
        assert_eq!(
            to_pg_placeholders("meta ?| array['a','b']"),
            "meta $1| array['a','b']"
        );

        // ② 可判定的一半：全仓生产 SQL 里 `?|` / `?&` 必须为 0 处
        let cfg = crate::common::prod_scan::Scan {
            strip_test_code: true,
            comments: crate::common::prod_scan::Comments::Blank,
            exclude: &["src/common/sql_dialect.rs"],
            roots: &["src", "migration/src"],
            ..Default::default()
        };
        let files = crate::common::prod_scan::prod_files(&cfg);
        assert!(
            files.len() >= 200,
            "只扫了 {} 个文件 ⇒ 采集面定位失效，本锁即将空转（不是通过）",
            files.len()
        );
        let offenders: Vec<String> = files
            .iter()
            .flat_map(|f| {
                f.lines
                    .iter()
                    .enumerate()
                    .filter(|(_, l)| l.contains("?|") || l.contains("?&"))
                    .map(move |(i, l)| format!("{}:{} {}", f.rel, i + 1, l.trim()))
            })
            .collect();
        assert!(
            offenders.is_empty(),
            "出现 PG jsonb 操作符 ?| / ?&，占位符转换器会把它改坏成语义不同的 SQL，必须先改写：
{}",
            offenders.join(
                "
"
            )
        );
    }
}
