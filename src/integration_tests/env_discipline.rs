//! 进程环境改动的收容锁（b85 收口）。
//!
//! 立锁的事实（本轮实测，不是推演）：`build_isolated_state*` 原先把 `dotenvy::dotenv()` 排在
//! `Settings::from_file()` **之后**。`dotenvy` 是逐行写环境变量的，而 `from_file` 在同一条语句里
//! 读环境并做 fail-closed 校验 ⇒ 本进程第一个用例看不到 `.env`（恒绿），之后并发进来的用例
//! 可能读到**装载到一半**的 `.env`。本机 `.env` 里 `SSO_ENABLED`（第 36 行）排在 `SSO_ISSUER`
//! （第 38 行）之前，于是校验在 `sso.enabled=true` 而 `issuer` 仍是空默认值的那一刻抛
//! 「SSO_ENABLED=true 时必须显式配置 SSO_ISSUER」。
//!
//! 症状是**三条 login 用例在并发轮里随机红、`--test-threads=1` 恒绿**（b85 提交后复跑实测：
//! 同一份代码两次全量，一次 64 把全绿、一次 `libtest` EXIT=101）。这正是 AGENTS ④
//! "判据自身不得与环境耦合"的形态——绿红由并行度决定，比红更难发现。
//!
//! 修法是把装载收进 `Once::call_once` 并排在 `from_file` 之前（后到的线程阻塞等装载完成，
//! 读侧只会看到"全有"或"全无"）。这条顺序本身由本锁钉住：
//! 一旦有人把 `set_var`/`dotenv` 挪回块外、或把 `from_file` 挪到块之前，本锁先红。

use crate::common::prod_scan::{Comments, Scan, prod_file, prod_files, require_volume};

/// 需要收容的进程环境改动站点。
///
/// 用 `concat!` 拼装而不是直接写字面量：本文件自己就是判据的采集面之一，
/// 字面量会让扫描器把自己的源码判成违规（同 `prod_scan` 的 SCANNER_SELF 那条理由，
/// 但这里连"豁免自家文件"都不必——模式串在源码里根本不成串）。
const ENV_NEEDLES: &[&str] = &[
    concat!("env::set", "_var"),
    concat!("env::remove", "_var"),
    concat!("dotenvy::", "dotenv"),
];

/// 装载块与校验读的先后顺序，全部按"掩码后的行号"判（注释不参与，行号不错位）。
fn line_with(lines: &[String], needle: &str) -> Option<usize> {
    lines.iter().position(|l| l.contains(needle)).map(|i| i + 1)
}

/// `TEST_ENV.call_once(...)` 块的行跨度。
///
/// 终止条件取 `cargo fmt` 保证的独立一行 `});`（与本仓其余大括号匹配判据同口径：
/// 与其在掩码文本里做括号计数——字符串字面量里的 `}` 会把计数带跑——不如把判据绑在
/// 格式化器唯一会写出的那个形态上，并且它变了 `fmt` 门禁会先红）。
fn once_block_span(lines: &[String]) -> Option<(usize, usize)> {
    let start = line_with(lines, "TEST_ENV.call_once")?;
    let end = lines[start..]
        .iter()
        .position(|l| l.trim() == "});")
        .map(|i| start + i + 1)?;
    Some((start, end))
}

/// 落在块外（或根本没有块）的环境改动站点。
fn env_sites_outside(rel: &str, lines: &[String], block: Option<(usize, usize)>) -> Vec<String> {
    let mut bad = Vec::new();
    for (idx, line) in lines.iter().enumerate() {
        let ln = idx + 1;
        if !ENV_NEEDLES.iter().any(|n| line.contains(n)) {
            continue;
        }
        match block {
            Some((s, e)) if ln >= s && ln <= e => {}
            Some(_) => bad.push(format!(
                "{rel}:{ln} 在装载块之外改动进程环境：{}",
                line.trim()
            )),
            None => bad.push(format!(
                "{rel}:{ln} 所在模块没有装载块，却改动了进程环境：{}",
                line.trim()
            )),
        }
    }
    bad
}

fn harness_cfg<'a>() -> Scan<'a> {
    Scan {
        // 本锁判的正是测试码里的环境改动 ⇒ 不得在 `#[cfg(test)]` 处截断，且采集面就是测试树
        strip_test_code: false,
        comments: Comments::Blank,
        include_integration_tests: true,
        // 本文件是判据自己的家：夹具文本必然含被禁形态（同 `prod_scan::SCANNER_SELF` 那条理由）。
        // 豁免的只是"这一份文件"，采集面体量下限仍由 `require_volume` 把住，不是把规则关掉。
        exclude: &["src/integration_tests/env_discipline.rs"],
        roots: &["src/integration_tests"],
    }
}

#[test]
fn real_tree_keeps_every_env_site_inside_the_once_block() {
    let files = prod_files(&harness_cfg());
    // 采集面自证：这个目录实测有几十个 .rs，腰斩即说明根路径写错（不是"违规消失了"）
    require_volume(&files, 30, 3_000, "集成测试树的环境改动收容");

    let mut bad: Vec<String> = Vec::new();
    for f in &files {
        let block = if f.rel == "src/integration_tests/mod.rs" {
            once_block_span(&f.lines)
        } else {
            None
        };
        bad.extend(env_sites_outside(&f.rel, &f.lines, block));
    }
    assert!(
        bad.is_empty(),
        "进程环境改动必须全部收在装载块内：\n  {}",
        bad.join("\n  ")
    );

    let harness = prod_file("src/integration_tests/mod.rs", &harness_cfg());
    let block = once_block_span(&harness.lines).expect("harness 必须有 TEST_ENV.call_once 装载块");
    // 顺序判据（本锁存在的理由）：装载块必须**早于**第一次 `Settings::from_file`，
    // 否则并发用例仍可能读到半份 .env。
    let load = line_with(&harness.lines, "dotenvy::").expect("装载块内必须有 dotenv 调用");
    let read = line_with(&harness.lines, "Settings::from_file").expect("harness 必须加载配置文件");
    assert!(
        load >= block.0 && load <= block.1 && read > block.1,
        "顺序不变式被破坏：dotenv 第 {load} 行、from_file 第 {read} 行、装载块 {block:?} \
         ⇒ dotenv 必须在块内，且 from_file 必须排在块之后"
    );
}

#[test]
fn synthetic_violation_is_caught_and_compliant_shape_is_not() {
    let block_lines: Vec<String> = [
        "    static TEST_ENV: Once = Once::new();",
        "    TEST_ENV.call_once(|| {",
        "        let _ = dotenvy::dotenv();",
        "    });",
        "    let s = Settings::from_file(p);",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    let span = once_block_span(&block_lines);
    assert_eq!(
        span,
        Some((2, 4)),
        "跨度应由 call_once 起到独立成行的 }}); 止"
    );
    // 合规：改动在块内 ⇒ 不得报
    assert!(env_sites_outside("m.rs", &block_lines, span).is_empty());
    // 违规：块外一行 set_var ⇒ 必须点名，且行号指向那一行
    let mut violating = block_lines.clone();
    violating.push("        std::env::set_var(\"X\", \"1\");".to_string());
    let got = env_sites_outside("m.rs", &violating, span);
    assert_eq!(got.len(), 1, "块外的改动必须被抓：{got:?}");
    assert!(
        got[0].starts_with("m.rs:6"),
        "上报行号必须指向真实那一行：{got:?}"
    );
    // 反证：没有块时任何改动都不许放行（不得把"找不到块"读成"没有约束"）
    let orphan: Vec<String> = vec!["    std::env::set_var(\"X\", \"1\");".to_string()];
    assert_eq!(env_sites_outside("m.rs", &orphan, None).len(), 1);
}

#[test]
fn the_lock_is_falsifiable_by_reordering_load_after_read() {
    // 把本次修复"退回去"的形状（dotenv 排在 from_file 之后）必须被顺序判据抓到——
    // 否则本锁只是在读自己的假设。
    let reverted: Vec<String> = [
        "    static TEST_ENV: Once = Once::new();",
        "    TEST_ENV.call_once(|| {",
        "        let _ = dotenvy::dotenv();",
        "    });",
        "    let s = Settings::from_file(p);",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    let block = once_block_span(&reverted).unwrap();
    let load = line_with(&reverted, "dotenvy::").unwrap();
    let read = line_with(&reverted, "Settings::from_file").unwrap();
    assert!(read > block.1, "本夹具本身就是合法顺序，不能拿它当反例");
    // 反例：装载挪到读之后（把块整体下移一行）
    let moved: Vec<String> = [
        "    let s = Settings::from_file(p);",
        "    static TEST_ENV: Once = Once::new();",
        "    TEST_ENV.call_once(|| {",
        "        let _ = dotenvy::dotenv();",
        "    });",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    let block2 = once_block_span(&moved).unwrap();
    let load2 = line_with(&moved, "dotenvy::").unwrap();
    let read2 = line_with(&moved, "Settings::from_file").unwrap();
    assert!(
        !(load2 >= block2.0 && load2 <= block2.1 && read2 > block2.1),
        "把 from_file 挪回装载块之前必须让顺序判据转红（实得 dotenv={load2} from_file={read2} 块={block2:?}）"
    );
    assert!(load >= block.0 && load <= block.1);
}
