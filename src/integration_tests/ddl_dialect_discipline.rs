// stepby-axum/src/integration_tests/ddl_dialect_discipline.rs
//! 索引 DDL 方言纪律总锁（批七十七 R-11 / R-12 新增）
//!
//! ## 本锁钉住的两类根因（都由实测照出来，不是推测）
//!
//! **R-11 吞错误文案式幂等**。旧 `IndexDdlExt` 与各 initialize 兜底副本的做法是
//! 「先执行，报错再看文案里有没有 `Duplicate key name` / `42P07` / `already exists`，
//! 有就当成功」。这只在 MySQL 成立：
//! - MySQL 8.0.46 实测重复建索引 → `ERROR 1061 Duplicate key name`（吞了无害）；
//! - PostgreSQL 里**事务内任何一条语句失败，整个事务进入 aborted 状态**，之后每条
//!   语句只会拿到 `current transaction is aborted`；而 sea-orm 是**一条迁移一个事务**。
//!   于是吞掉首错实际废掉了这条迁移剩下的所有语句，报出来的还是与首错无关的二级错。
//!   实证：`--down` 回滚后重放卡在 `m20260925_000003_tenant_phase3`
//!   （`uk_sys_tenant_migration_map_old` 索引残留 → 首错即「索引已存在」）。
//!
//! **R-12 `IF NOT EXISTS` 在 MySQL 上是语法错误**。同一批兜底副本的另一半做法是
//! 「SQLite/PG 用 `CREATE INDEX IF NOT EXISTS`，MySQL 整段跳过、注释写「交由 migration
//! 补齐」」。两句都不成立：
//! - MySQL 8.0.46 实测 `CREATE INDEX IF NOT EXISTS idx ON t (c)` → `ERROR 1064`（该子句
//!   是 MariaDB 扩展）。`ensure_flow_graph_doc_table` 无条件执行它，而启动链是
//!   `.map_err(...)?`——MySQL 存量库每次启动都在这里硬失败；
//! - 架构约定是**存量库启动不跑 `Migrator::up`**（见 `initialize/mod.rs` 的
//!   `run_migrator_if_fresh_db`），所以「MySQL 跳过」= 索引/唯一约束在 MySQL 存量库上
//!   永远缺失（sys_pat / sys_user_credential / sys_user_dept / sys_scim_group /
//!   flow 索引全中），不是「等 migration 补齐」。
//!
//! ## 唯一正确的做法（现收口成一份实现）
//! `migration::ensure_index_ddl`：先按方言探测索引存在性（sqlite `sqlite_master` /
//! PG `pg_indexes` / MySQL `information_schema.statistics`，索引名走绑定参数），
//! 已存在直接跳过；确实要建时用 `SAVEPOINT` 隔离这一条语句，失败 `ROLLBACK TO SAVEPOINT`
//! 保住事务、错误原样上抛。因此 DDL 文本里既不需要 `IF NOT EXISTS`，也不需要按方言分支。
//!
//! 口径说明：迁移侧（`migration/src/migrations/`）**不套 B/C 判据**——已发布迁移的
//! `up()` 不改（存量库按其原样跑过，改了无法复验；且新执行器对 `IF NOT EXISTS` 形态
//! 兼容，留着无害），只要求它不再靠错误文案兜（判据 A 覆盖 `migration/src`）。
//!
//! 判据 A 的 marker 字面量在本文件里是**数据**而不是违例，因此扫描器整体跳过本文件；
//! 相应地，「扫描器真的会判红」由 `test_scanners_flag_synthetic_violations` 自证。

use std::path::{Path, PathBuf};

fn axum_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// 递归收集 `.rs` 文件（跳过 target/.git）；目录读不到即硬失败——校验没跑不得当成通过
fn collect_rs(dir: &Path, out: &mut Vec<PathBuf>) {
    let entries = std::fs::read_dir(dir).unwrap_or_else(|e| panic!("读取 {:?} 失败: {e}", dir));
    for entry in entries {
        let entry = entry.expect("read_dir 条目");
        let path = entry.path();
        let ftype = entry.file_type().expect("file_type");
        if ftype.is_dir() {
            let name = path.file_name().map(|n| n.to_string_lossy().to_string());
            if name.as_deref() == Some("target") || name.as_deref() == Some(".git") {
                continue;
            }
            collect_rs(&path, out);
        } else if path.extension().and_then(|x| x.to_str()) == Some("rs") {
            out.push(path);
        }
    }
}

fn files_under(rel_dir: &str) -> Vec<PathBuf> {
    let mut out = Vec::new();
    collect_rs(&axum_dir().join(rel_dir), &mut out);
    out.sort();
    out
}

fn read(p: &Path) -> String {
    std::fs::read_to_string(p).unwrap_or_else(|e| panic!("读取 {:?} 失败: {e}", p))
}

fn file_name(p: &Path) -> String {
    p.file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_default()
}

/// 本锁自身：判据字面量在这里是数据，整体排除
fn is_self_lock(p: &Path) -> bool {
    file_name(p) == "ddl_dialect_discipline.rs"
}

/// 取一行的代码部分：整行注释（`//` / `///` / `//!` / `/*` / 续行 `*`）视为空，
/// 行尾注释按第一个 `//` 截断。各判据关键字都不含 `//`，截断不会漏判。
fn code_of(line: &str) -> &str {
    let trimmed = line.trim_start();
    if trimmed.starts_with("//") || trimmed.starts_with("/*") || trimmed.starts_with('*') {
        return "";
    }
    match line.find("//") {
        Some(i) => &line[..i],
        None => line,
    }
}

/// 索引 DDL 字面量的形状（大写化后判）：`CREATE [UNIQUE] INDEX …`，
/// 含 `CREATE {kind}INDEX {name} ON …` 这种按方言拼出来的形态。
fn is_index_ddl_literal(upper: &str) -> bool {
    upper.contains("CREATE")
        && (upper.contains("INDEX ") || upper.contains("INDEX(") || upper.contains("INDEX {"))
}

/// 判据 A：错误文案容错（R-11）。`already exists` 只在被当作**错误串比较**时判红，
/// 否则会把 `table already exists` 这类正常 SQL/文档片段误伤。
/// `可能已存在` 是本仓吞错点的固定指纹（历轮 7 处兜底副本的日志措辞都用它）：
/// 「无条件执行 → Err 里猜原因」的形态一律判红，注释行由 `code_of` 排除。
fn tolerance_marker(line_code: &str) -> Option<&'static str> {
    for m in ["Duplicate key name", "42P07", "no such index", "可能已存在"] {
        if line_code.contains(m) {
            return Some(m);
        }
    }
    for v in [
        ".contains(\"already exists\")",
        ".ends_with(\"already exists\")",
    ] {
        if line_code.contains(v) {
            return Some("already exists");
        }
    }
    None
}

/// 判据 B：`CREATE … INDEX IF NOT EXISTS`（R-12，MySQL 8.0 实测 1064）。
fn broken_if_not_exists(line_code: &str) -> bool {
    let up = line_code.to_ascii_uppercase();
    up.contains("CREATE") && up.contains("INDEX IF NOT EXISTS")
}

/// 能直接发 SQL 的执行器入口（`ensure_index_ddl` 不在列——它是本锁指定的正解）
const RAW_EXECUTORS: [&str; 4] = [
    "execute_raw(",
    "execute_unprepared(",
    "flow_exec(",
    "db.exec(",
];

/// 索引 DDL 字面量是否由统一执行器发起（±6 行窗口内出现 `ensure_index_ddl`）。
/// 只用于 C2 判定"来源字面量是不是已被收口"，不单独作为判据（数组形态会让窗口法误判）。
fn literal_covered(lines: &[&str], idx: usize) -> bool {
    let lo = idx.saturating_sub(6);
    let hi = (idx + 6).min(lines.len().saturating_sub(1));
    lines[lo..=hi]
        .iter()
        .any(|l| code_of(l).contains("ensure_index_ddl"))
}

/// 判据 C：索引 DDL 字面量不得由统一执行器之外的入口发起。行级启发式两条：
/// - **C1 紧贴语句**：执行器调用行起，到该语句的 `.await` 为止（最多 6 行）里出现
///   索引 DDL 字面量 → 判红（抓 `execute_raw(…, "CREATE INDEX …")` 直写形态）；
/// - **C2 变量来源**：执行器调用行参数里没有字符串字面量（即传的是变量），就往回看
///   15 行；若那里有**未被 `ensure_index_ddl` 收口的**索引 DDL 字面量 → 判红
///   （抓 `let idx = ["CREATE INDEX …"]; for s in idx { flow_exec(db, s) }` 这种副本）。
///
/// 按执行器定位而非按字面量定位，所以「数组字面量 + 末尾统一 `ensure_index_ddl(db, stmt)`」
/// 放过；真正的方言正确性另有活库 smoke 兜（本锁只防同类形态回潮）。
fn executor_runs_index_ddl(lines: &[&str], idx: usize) -> bool {
    let code = code_of(lines[idx]);
    if !RAW_EXECUTORS.iter().any(|e| code.contains(e)) {
        return false;
    }
    // C1：本语句范围内（执行器行 → .await 行，上限 6 行）
    let hi = (idx + 6).min(lines.len().saturating_sub(1));
    for (offset, line) in lines[idx..=hi].iter().enumerate() {
        let stmt_code = code_of(line);
        if is_index_ddl_literal(&stmt_code.to_ascii_uppercase()) {
            return true;
        }
        if offset > 0 && stmt_code.contains(".await") {
            break;
        }
    }
    // C2：参数是变量时回溯其来源
    if code.contains('"') {
        return false;
    }
    let lo = idx.saturating_sub(15);
    (lo..idx).any(|j| {
        is_index_ddl_literal(&code_of(lines[j]).to_ascii_uppercase()) && !literal_covered(lines, j)
    })
}

/// 扫描一个文件：返回违例行（文件名:行号: 说明）与「看到的索引 DDL 字面量行数」。
/// `apply_b_and_c=false` 时只跑判据 A（迁移侧口径）。
fn scan_file(path: &Path, apply_b_and_c: bool) -> (Vec<String>, usize) {
    let src = read(path);
    let lines: Vec<&str> = src.lines().collect();
    let name = file_name(path);
    let mut hits = Vec::new();
    let mut literals = 0usize;
    for (i, raw) in lines.iter().enumerate() {
        let code = code_of(raw);
        if code.trim().is_empty() {
            continue;
        }
        if is_index_ddl_literal(&code.to_ascii_uppercase()) {
            literals += 1;
        }
        if let Some(m) = tolerance_marker(code) {
            hits.push(format!(
                "{name}:{}: 仍按错误文案判幂等（{m}）→ 请用 migration::ensure_index_ddl",
                i + 1
            ));
        }
        if !apply_b_and_c {
            continue;
        }
        if broken_if_not_exists(code) {
            hits.push(format!(
                "{name}:{}: 索引 DDL 带 IF NOT EXISTS（MySQL 8.0 实测 1064）→ 交执行器探测",
                i + 1
            ));
        }
        if executor_runs_index_ddl(&lines, i) {
            hits.push(format!(
                "{name}:{}: 索引 DDL 由 ensure_index_ddl 之外的执行器发起",
                i + 1
            ));
        }
    }
    (hits, literals)
}

/// 把源码里的一行（可能带 `\` 续行、`format!(…)` 包裹、行尾逗号）还原成可喂给
/// 解析器的 SQL 文本：取首个 `"` 与末个 `"` 之间的内容，并去掉续行反斜杠。
fn literal_sql(lines: &[&str], idx: usize) -> Option<String> {
    let mut buf = code_of(lines[idx]).to_string();
    let mut j = idx;
    while buf.trim_end().ends_with('\\') {
        j += 1;
        let Some(next) = lines.get(j) else { break };
        let cont = code_of(next).trim().replace('\\', "");
        buf = format!("{} {}", buf.trim_end().trim_end_matches('\\'), cont);
    }
    let start = buf.find('"')?;
    let end = buf.rfind('"')?;
    if end <= start {
        return None;
    }
    Some(buf[start + 1..end].replace('\\', ""))
}

/// 判据 D：兜底段里每条索引 DDL 字面量都必须真能被 `migration::parse_index_ddl` 解析。
/// 解析失败时执行器**不会报错**，而是退化成「不探测、直接执行」——幂等性静默消失，
/// MySQL 存量库上表现为 1061（`ON sys_pat(token_hash)` 不带空格的形态就是这么在
/// 活库 smoke 里暴露的）。sqlite 测试环永远照不出这种退化，所以在这里静态钉住。
#[test]
fn test_every_fallback_index_ddl_is_parseable() {
    let mut checked = 0usize;
    let mut unparsed = Vec::new();
    for f in files_under("src/initialize") {
        if is_self_lock(&f) {
            continue;
        }
        let src = read(&f);
        let lines: Vec<&str> = src.lines().collect();
        for (i, raw) in lines.iter().enumerate() {
            if !is_index_ddl_literal(&code_of(raw).to_ascii_uppercase()) {
                continue;
            }
            let Some(sql) = literal_sql(&lines, i) else {
                unparsed.push(format!("{}:{}: 取不出 SQL 字面量", file_name(&f), i + 1));
                continue;
            };
            checked += 1;
            if migration::parse_index_ddl(&sql).is_none() {
                unparsed.push(format!(
                    "{}:{}: parse_index_ddl 解析失败 → 执行器会退化成不探测：{sql}",
                    file_name(&f),
                    i + 1
                ));
            }
        }
    }
    assert!(
        checked >= 15,
        "判据 D 只解析了 {checked} 条索引 DDL（预期 ≥15）：判据空转，不得当成通过"
    );
    assert!(
        unparsed.is_empty(),
        "索引 DDL 写法超出统一执行器的解析面（幂等会静默失效）\n{}",
        unparsed.join("\n")
    );
}

/// 判据 D 自身的变异证伪：不带空格的列清单形态必须解析成功，畸形形态必须返回 None。
#[test]
fn test_parser_covers_the_fallback_literal_shapes() {
    let (name, table) = migration::parse_index_ddl(
        "CREATE UNIQUE INDEX uk_sys_pat_token_hash ON sys_pat(token_hash)",
    )
    .expect("`ON tbl(col)` 不带空格是兜底段的真实写法，解析器必须认");
    assert_eq!(name, "uk_sys_pat_token_hash");
    assert_eq!(table, "sys_pat");
    assert!(migration::parse_index_ddl("ALTER TABLE t ADD COLUMN c INT").is_none());
    assert!(
        migration::parse_index_ddl("CREATE {kind}INDEX a ON t (b)").is_none(),
        "插值出来的关键字必须判为「不认识」——靠判据 D 静态拦截，不得静默退化成不探测"
    );
}

#[test]
fn test_no_error_text_idempotency_tolerance() {
    let mut offenders = Vec::new();
    let mut checked = 0usize;
    for dir in ["src", "migration/src"] {
        for f in files_under(dir) {
            if is_self_lock(&f) {
                continue;
            }
            checked += 1;
            let (hits, _) = scan_file(&f, false);
            offenders.extend(hits);
        }
    }
    assert!(
        checked >= 150,
        "扫描面异常小（{checked} 个 .rs）：判据没真跑，不得当成通过"
    );
    assert!(
        offenders.is_empty(),
        "R-11 回潮：按错误文案判幂等（PG 事务里首错即 aborted，吞错等于废掉后续语句）\n{}",
        offenders.join("\n")
    );
}

#[test]
fn test_startup_index_ddl_is_dialect_safe() {
    let mut offenders = Vec::new();
    let mut literals = 0usize;
    let mut checked = 0usize;
    for f in files_under("src") {
        if is_self_lock(&f) {
            continue;
        }
        checked += 1;
        let (hits, n) = scan_file(&f, true);
        offenders.extend(hits);
        literals += n;
    }
    // 零空洞：本判据必须真的看到索引 DDL 面（当前 src/ 兜底段有 19 处字面量）
    assert!(
        literals >= 15,
        "扫描只看到 {literals} 处索引 DDL 字面量（预期 ≥15）：判据空转，不得当成通过"
    );
    assert!(
        checked >= 100,
        "扫描面异常小（{checked} 个 .rs）：判据没真跑，不得当成通过"
    );
    assert!(
        offenders.is_empty(),
        "R-11/R-12 回潮：兜底段索引 DDL 未走统一执行器\n{}",
        offenders.join("\n")
    );
}

/// 变异证伪：三条判据必须真的会判红——否则上面两条锁是虚锁。
#[test]
fn test_scanners_flag_synthetic_violations() {
    let bad_tolerance = r#"
        let msg = e.to_string();
        if !(msg.contains("Duplicate key name") || msg.contains("42P07")) {
            return Err(e.into());
        }
        if msg.ends_with("already exists") { return Ok(()); }
        tracing::debug!("索引创建跳过: no such index");
        tracing::debug!("列补建跳过（可能已存在）: {}", e);
    "#;
    let flagged: Vec<&str> = bad_tolerance
        .lines()
        .filter_map(|l| tolerance_marker(code_of(l)))
        .collect();
    // 同一行两个 marker 只算一行，因此预期 4 行命中
    assert_eq!(
        flagged,
        vec![
            "Duplicate key name",
            "already exists",
            "no such index",
            "可能已存在"
        ],
        "判据 A 对合成违例的检出与预期不符"
    );

    assert!(
        broken_if_not_exists("        \"CREATE UNIQUE INDEX IF NOT EXISTS uk_a ON t (c)\","),
        "判据 B 漏判直写形态"
    );
    assert!(
        broken_if_not_exists(
            "            format!(\"CREATE {kind}INDEX IF NOT EXISTS {idx} ON {t} ({cols})\"),"
        ),
        "判据 B 漏判按方言拼子句形态"
    );
    assert!(
        !broken_if_not_exists("        \"CREATE TABLE IF NOT EXISTS t (id BIGINT)\","),
        "判据 B 误伤 CREATE TABLE IF NOT EXISTS（三方言合法）"
    );

    let bare: Vec<&str> = r#"    db.execute_raw(Statement::from_string(
        backend,
        "CREATE INDEX idx_b ON t (c)".to_string(),
    ))
    .await?;"#
        .lines()
        .collect();
    assert!(
        executor_runs_index_ddl(&bare, 0),
        "判据 C 没认出 execute_raw 直发索引 DDL"
    );

    let shaped: Vec<&str> = r#"    let indexes = [
        "CREATE UNIQUE INDEX uk_x ON t1 (a)",
        "CREATE INDEX idx_x ON t2 (b)",
    ];
    for stmt in indexes {
        migration::ensure_index_ddl(db, stmt).await?;
    }"#
    .lines()
    .collect();
    for i in 0..shaped.len() {
        assert!(
            !executor_runs_index_ddl(&shaped, i),
            "判据 C 误伤已收口形态（第 {i} 行不该判红）"
        );
    }

    // 对照组必须真受约束：只把执行器换成 raw，同一批字面量就该判红
    let mutated: Vec<&str> = r#"    let indexes = [
        "CREATE UNIQUE INDEX uk_x ON t1 (a)",
        "CREATE INDEX idx_x ON t2 (b)",
    ];
    for stmt in indexes {
        db.execute_unprepared(stmt).await?;
    }"#
    .lines()
    .collect();
    assert!(
        executor_runs_index_ddl(&mutated, 5),
        "判据 C 对「数组字面量 + raw 执行器」组合漏判"
    );

    // 反向对照：收口调用之后紧跟一条 raw 语句（传 format! 变量）不该被 C2 误伤
    // ——这正是首轮实测里 flow.rs/schema.rs 两处假阳性的形态
    let after: Vec<&str> = r#"    migration::ensure_index_ddl(
        db,
        "CREATE UNIQUE INDEX uk_y ON t (a)",
    )
    .await?;
    db.execute_raw(Statement::from_string(
        backend,
        format!("INSERT INTO t (a) VALUES (1)"),
    ))
    .await?;"#
        .lines()
        .collect();
    assert!(
        !executor_runs_index_ddl(&after, 5),
        "判据 C2 误伤收口之后的独立 raw 语句"
    );
}

/// 对照面：真实代码里「已收口」的调用点必须存在且不少于 8 处，
/// 否则说明判据 C 是靠「根本没有索引 DDL」蒙过的。
#[test]
fn test_unified_executor_is_actually_adopted() {
    let mut sites = 0usize;
    for f in files_under("src/initialize") {
        let src = read(&f);
        sites += src
            .lines()
            .filter(|l| code_of(l).contains("ensure_index_ddl("))
            .count();
    }
    assert!(
        sites >= 8,
        "统一执行器在 initialize 下只有 {sites} 处调用（预期 ≥8）：收口未落地"
    );
}
