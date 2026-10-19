// stepby-axum/src/integration_tests/flow_action_dict.rs
//! 批七十六 R-1 + R-4 总锁：字典 `sys_flow_action` 的值域必须**恰好等于**审批引擎
//! 实际可写入 `sys_flow_log.action` 的取值集合（双向，缺一边就判红）。
//!
//! 缺陷背景（`docs/optimization/quality-batch-76-2026-10-19.md` §7 R-1）：
//! 加签/减签/委派三个动作上线时，迁移 §4.5 与 `initialize::flow` 的字典种子都漏了
//! 对应行，而**没有任何机械门禁能发现**——实体注释、前端类型联合、字典三处各自声明
//! 动作集合，靠人肉对齐必然再漂。本文件把判据变成机械的：
//!
//! 1. 从 `sys_flow_service.rs` 源码穷举 `write_log(…)` 第 5 实参与
//!    `action: Set("…")` 的字面量（不硬编码清单 ⇒ 新增动作忘了种字典会直接判红）；
//! 2. 走 HTTP `/system/dict/data/type/sys_flow_action` 读**测试隔离库**（该库由
//!    `Migrator::up` 全量迁移建立 ⇒ 校验的是迁移侧真实落库结果，不是源码字符串）；
//! 3. 再比两侧种子文件（迁移 `rows` 段 + `initialize::flow` 的 `action_rows` 段），
//!    保证"迁移侧已补、兜底侧忘了"的同族漂移同样判红。
//!
//! 恒真防护见 `test_flow_action_lock_is_not_vacuous`：抽取器与比较器都在合成样本上
//! 验过"能抓到缺失"，不是只比两个硬编码常量。

use std::collections::BTreeSet;
use std::path::PathBuf;

use super::TestContext;

fn repo_file(rel: &str) -> String {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(rel);
    // 读不到就硬失败：校验没跑不得当成通过（house 口径）
    std::fs::read_to_string(&p)
        .unwrap_or_else(|e| panic!("读取 {p:?} 失败，字典覆盖总锁无法执行: {e}"))
}

/// 在 char 数组里查找 `needle`（纯 ASCII）的所有出现位置（char 下标）。
///
/// 全程按 char 计数：`sys_flow_service.rs` 里中文注释密集，混用字节偏移会把
/// 实参切分点整体错位（表现为"抽不到动作字面量"这种假绿）。
fn find_all(hay: &[char], needle: &str) -> Vec<usize> {
    let n: Vec<char> = needle.chars().collect();
    if n.is_empty() || hay.len() < n.len() {
        return Vec::new();
    }
    let mut hits = Vec::new();
    'outer: for i in 0..=(hay.len() - n.len()) {
        for (k, c) in n.iter().enumerate() {
            if hay[i + k] != *c {
                continue 'outer;
            }
        }
        hits.push(i);
    }
    hits
}

/// 从 `open`（左括号之后的 char 下标）开始按顶层逗号切分实参。
/// 处理字符串/字符字面量与嵌套括号，避免 `"a(b"` 之类把切分打乱。
fn split_top_level_args(src: &[char], open: usize) -> (Vec<String>, bool) {
    let mut args = Vec::new();
    let mut cur = String::new();
    let mut depth = 1usize;
    let mut i = open;
    let mut quote: Option<char> = None;
    while i < src.len() {
        let c = src[i];
        if let Some(q) = quote {
            cur.push(c);
            if c == '\\' && i + 1 < src.len() {
                cur.push(src[i + 1]);
                i += 2;
                continue;
            }
            if c == q {
                quote = None;
            }
        } else if c == '"' || c == '\'' {
            quote = Some(c);
            cur.push(c);
        } else if c == '(' {
            depth += 1;
            cur.push(c);
        } else if c == ')' {
            depth -= 1;
            if depth == 0 {
                args.push(cur);
                return (args, true);
            }
            cur.push(c);
        } else if c == ',' && depth == 1 {
            args.push(std::mem::take(&mut cur));
        } else {
            cur.push(c);
        }
        i += 1;
    }
    (args, false)
}

/// 判断 `needle` 命中点之前紧邻的是不是 `fn `（函数定义而非调用）。
fn is_definition(hay: &[char], hit: usize) -> bool {
    // 回退跳过空白，取 hit 前最后一个非空白字符
    let mut j = hit;
    while j > 0 && (hay[j - 1] == ' ' || hay[j - 1] == '\t' || hay[j - 1] == '\n') {
        j -= 1;
    }
    if j == 0 {
        return false;
    }
    let prev = hay[j - 1];
    prev == 'n' && j >= 2 && hay[j - 2] == 'f'
}

/// 若整段就是一个字符串字面量则返回其内容，否则 None。
fn quoted_only(s: &str) -> Option<String> {
    let t = s.trim();
    let inner = t
        .strip_prefix('"')
        .and_then(|x| x.strip_suffix('"'))
        .filter(|_| t.len() >= 2 && !t[1..t.len() - 1].contains('"'));
    inner.map(|v| v.to_string())
}

/// 从 `sys_flow_service.rs` 源码穷举引擎可写入的 action 字面量集合。
///
/// 返回 `(字面量集合, 非字面量第 5 实参集合)`。后者必须为空——若哪天动作值改成
/// 运行期拼装的变量，静态穷举就不再是全量真值，锁必须显式失效而不是静默变虚锁。
fn engine_actions(service_src: &str) -> (BTreeSet<String>, BTreeSet<String>) {
    let chars: Vec<char> = service_src.chars().collect();
    let mut lits = BTreeSet::new();
    let mut non_lits = BTreeSet::new();

    for hit in find_all(&chars, "write_log(") {
        if is_definition(&chars, hit) {
            continue;
        }
        let open = hit + "write_log(".chars().count();
        let (args, closed) = split_top_level_args(&chars, open);
        if closed && args.len() >= 5 {
            // write_log(biz_type, biz_id, round_no, node_seq, action, …)
            let a = args[4].trim().to_string();
            match quoted_only(&a) {
                Some(v) => {
                    lits.insert(v);
                }
                None => {
                    non_lits.insert(a.replace('\n', " "));
                }
            }
        }
    }
    // 直接列写形态：`action: Set("…")` / `… Action, Expr::value("…")`
    for pat in ["action: Set(", "Action, Expr::value("] {
        let n = pat.chars().count();
        for hit in find_all(&chars, pat) {
            let start = hit + n;
            if start < chars.len()
                && chars[start] == '"'
                && let Some(end) = (start + 1..chars.len()).find(|&k| chars[k] == '"')
            {
                lits.insert(chars[start + 1..end].iter().collect());
            }
        }
    }
    (lits, non_lits)
}

/// 比较器：引擎动作里哪些不在字典值域内（排序，便于断言与报错）。
fn missing_from_dict(actions: &BTreeSet<String>, dict: &BTreeSet<String>) -> Vec<String> {
    actions
        .iter()
        .filter(|a| !dict.contains(*a))
        .cloned()
        .collect()
}

/// 反方向比较器：字典值里哪些引擎永不写入（批七十六 R-4 新增的判据）。
///
/// 只有单向"引擎 ⊆ 字典"时，往字典塞一个"将来也许会用到"的预留值是完全静默的——
/// `auto_approve`（716）就这样挂着"字典里有、引擎不写、前端不译"的状态跨过一次上线，
/// 而它与 `sys_flow_service.rs:852`「唯一审批人=提交人 ⇒ 显式 400」的设计直接矛盾。
/// 反向判据把这类值当场暴露，两个方向合起来才是"字典=引擎动作域"这一条真值声明。
fn reserved_in_dict(actions: &BTreeSet<String>, dict: &BTreeSet<String>) -> Vec<String> {
    dict.iter()
        .filter(|d| !actions.contains(*d))
        .cloned()
        .collect()
}

/// 取某个源文件里 `let <binding>` 到其后第一个 `];` 之间的片段（种子数组体）。
fn array_block(src: &str, binding: &str) -> String {
    let head = format!("let {binding}");
    let start = src
        .find(&head)
        .unwrap_or_else(|| panic!("种子侧未找到 `{head}` 数组，字典覆盖校验无法执行"));
    let rest = &src[start..];
    let end = rest
        .find("];")
        .unwrap_or_else(|| panic!("`{head}` 数组未闭合，无法界定校验范围"));
    rest[..end].to_string()
}

/// 从 `(code, label, value, label_en)` 形态的种子数组里抽出**字典值**集合（第 3 元）。
///
/// 只认"第 1 元是纯数字"的元组 ⇒ 跳过同一行里的类型标注 `(i64, &str, &str, &str)`
/// （它的首元是 `i64`，不是数字）。这样"兜底侧多种了一个值"能被量化抓住，
/// 而不是只靠"逐个引擎动作都在"这种单向存在性判定。
fn seed_dict_values(block: &str) -> BTreeSet<String> {
    let chars: Vec<char> = block.chars().collect();
    let mut out = BTreeSet::new();
    for hit in find_all(&chars, "(") {
        let (args, closed) = split_top_level_args(&chars, hit + 1);
        if !closed || args.len() < 3 {
            continue;
        }
        let first = args[0].trim();
        if first.is_empty() || !first.chars().all(|c| c.is_ascii_digit()) {
            continue;
        }
        if let Some(v) = quoted_only(&args[2]) {
            out.insert(v);
        }
    }
    out
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_flow_action_dict_covers_engine_actions() {
    let ctx = TestContext::new().await;
    let service_src = repo_file("src/service/sys_flow_service.rs");
    let (actions, non_literal) = engine_actions(&service_src);
    assert!(
        non_literal.is_empty(),
        "write_log 第 5 实参出现非字面量 {non_literal:?}：静态穷举不再等于引擎全集，\
         本锁需改为运行期口径后重新启用（不得放着不管变成虚锁）"
    );
    assert!(
        actions.len() >= 9,
        "引擎动作全集只抽到 {} 个（{actions:?}）——抽取器失效，判红",
        actions.len()
    );

    // 1) 字典侧真值：走 API 读**测试隔离库**（该库由 Migrator::up 全量迁移建立）
    let v = ctx.get_json("/system/dict/data/type/sys_flow_action").await;
    let rows = v["data"]
        .as_array()
        .unwrap_or_else(|| panic!("字典查询应返回数组，实际: {v}"));
    let dict: BTreeSet<String> = rows
        .iter()
        .filter_map(|r| r["dictValue"].as_str().map(String::from))
        .collect();
    assert!(
        !dict.is_empty(),
        "sys_flow_action 字典为空：迁移种子未落库，本锁无法成立"
    );
    let missing = missing_from_dict(&actions, &dict);
    assert!(
        missing.is_empty(),
        "引擎可写入但字典 sys_flow_action 缺失的动作: {missing:?}\
         （已落库字典值: {dict:?}）——需追加补充迁移把缺失动作种进字典"
    );
    // R-4 反向：字典里不得有引擎永不写入的预留值（迁移 m20261019_000001 摘除 auto_approve
    // 之后，测试隔离库的值域必须与引擎全集**恰好相等**）
    let reserved = reserved_in_dict(&actions, &dict);
    assert!(
        reserved.is_empty(),
        "字典 sys_flow_action 存在引擎永不写入的预留值: {reserved:?}\
         （引擎动作全集: {actions:?}）——要么补写入点，要么追加迁移摘除，\
         留一个永远不出现的枚举值就是下一轮漂移的土壤"
    );

    // 2) 种子两侧同构：迁移侧（老 §4.5 + 批七十六补充）与 initialize 兜底侧
    let mig_old = array_block(
        &repo_file("migration/src/migrations/m20260923_000002_flow_module.rs"),
        "action_rows",
    );
    let mig_new = array_block(
        &repo_file("migration/src/migrations/m20261018_000001_flow_action_dict.rs"),
        "rows",
    );
    let init_block = array_block(&repo_file("src/initialize/flow.rs"), "action_rows");
    for a in &actions {
        let needle = format!("\"{a}\"");
        assert!(
            mig_old.contains(&needle) || mig_new.contains(&needle),
            "迁移侧种子（§4.5 / m20261018_000001）缺动作 {a}：字典值与引擎将不一致"
        );
        assert!(
            init_block.contains(&needle),
            "initialize::flow 的 action_rows 缺动作 {a}：存量库兜底侧与迁移侧漂移"
        );
    }
    // R-4 反向同样适用于兜底种子：全新库由这条路径落字典，"多种一个预留值"与
    // "漏种一个动作"是同一种漂移的两个方向，只锁一边等于没锁。
    // （老迁移 m20260923_000002 是已发布历史，不改写；它的多余值由 m20261019_000001
    //  在库侧删除，上面"字典值 ⊆ 引擎动作"的实测判定已经覆盖那条路径。）
    let seeded = seed_dict_values(&init_block);
    let extra: Vec<&String> = seeded.difference(&actions).collect();
    let absent: Vec<&String> = actions.difference(&seeded).collect();
    assert!(
        extra.is_empty() && absent.is_empty(),
        "initialize::flow 兜底种子与引擎动作域不一致：兜底多出 {extra:?}，兜底缺少 {absent:?}\
         （多出的值就是 R-4 的复发形态，缺少则回到 R-1）"
    );

    // 3) 双语标签与前端 i18n 不漂移：批七十六新增三个动作的中文标签须逐字一致
    for (value, zh) in [
        ("delegate", "委托"),
        ("countersign_add", "加签"),
        ("countersign_del", "减签"),
    ] {
        let pair = format!("\"{zh}\", \"{value}\"");
        assert!(
            init_block.contains(&pair),
            "initialize 侧 {value} 的中文标签应为「{zh}」（与前端 i18n flow.action 对齐）"
        );
        assert!(
            mig_new.contains(&pair),
            "迁移侧 {value} 的中文标签应为「{zh}」（与前端 i18n flow.action 对齐）"
        );
    }
}

/// 恒真防护：抽取器与比较器都要在合成样本上"抓得到问题"，否则上面的锁可能是虚锁。
#[test]
fn test_flow_action_lock_is_not_vacuous() {
    // ① 抽取器只认第 5 实参；非常量的第 5 实参必须被单独登记（控制组真受约束）
    let synthetic = r#"
        self.write_log(
            &task.biz_type,
            task.biz_id,
            task.round_no,
            Some(task.node_seq),
            "synthetic_act",
            Some("pending"),
        )
        .await;
        self.write_log(&t.biz_type, t.biz_id, t.round_no, None, other_var, None).await;
        async fn write_log(&self, biz_type: &str, biz_id: i64, round_no: i32,
                           node_seq: Option<i32>, action: &str) {}
    "#;
    let (lits, non_lits) = engine_actions(synthetic);
    assert!(
        lits.contains("synthetic_act"),
        "抽取器漏掉了字面量动作：总锁将恒真"
    );
    assert!(
        !lits.contains("pending"),
        "抽取器把第 6 实参当成了动作 ⇒ 实参位序解析错误"
    );
    assert_eq!(
        non_lits.iter().cloned().collect::<Vec<_>>(),
        vec!["other_var".to_string()],
        "非常量第 5 实参必须被登记（否则引擎全集不再可静态穷举时锁会静默变虚）"
    );
    assert!(
        !lits.contains("biz_type") && !lits.contains("action"),
        "函数定义行被当调用解析：抽到了形参名"
    );

    // ② 比较器必须能抓到"字典少一行"这一真实故障形态
    let mut actions = BTreeSet::new();
    actions.insert("countersign_del".to_string());
    let mut dict = BTreeSet::new();
    dict.insert("submit".to_string());
    assert_eq!(
        missing_from_dict(&actions, &dict),
        vec!["countersign_del".to_string()],
        "比较器在字典缺值时必须报出缺失项，否则总锁恒真"
    );
    // 对照组：字典补齐后必须为绿（证明上一条不是恒假）
    dict.insert("countersign_del".to_string());
    assert!(missing_from_dict(&actions, &dict).is_empty());

    // ③ 字符串内含括号/转义不得打乱切分（真实文件里中文密集，偏移错乱会静默漏报）
    let tricky = r#"self.write_log("a(b", 1, 1, None, "ok_act", None);"#;
    let (lits, _) = engine_actions(tricky);
    assert!(
        lits.contains("ok_act"),
        "字符串内含左括号导致实参切分错位：抽取器不稳健"
    );

    // ④ array_block 定位失败必须硬失败，不能返回空串把校验洗绿
    let blocked = array_block(
        "let action_rows: &[(i64, &str)] = &[(1, \"x\")];",
        "action_rows",
    );
    assert!(blocked.contains("\"x\""));
    assert!(
        std::panic::catch_unwind(|| array_block("nothing here", "action_rows")).is_err(),
        "种子数组缺失时应 panic（读不到≠通过）"
    );

    // ⑤ 反向比较器（R-4）：字典里的预留值必须被报出，且补齐动作后不误报
    let mut acts5 = BTreeSet::new();
    acts5.insert("submit".to_string());
    let mut dict5 = BTreeSet::new();
    dict5.insert("submit".to_string());
    dict5.insert("auto_approve".to_string());
    assert_eq!(
        reserved_in_dict(&acts5, &dict5),
        vec!["auto_approve".to_string()],
        "反向比较器抓不到预留值 ⇒ R-4 判据恒真"
    );
    dict5.remove("auto_approve");
    assert!(
        reserved_in_dict(&acts5, &dict5).is_empty(),
        "值域对齐时反向判据必须为绿（否则是恒假）"
    );

    // ⑥ 兜底种子抽取器：按"首元是纯数字"取第 3 元，既不能把类型标注当数据行，
    //    也不能把真实数据行漏掉（漏掉 ⇒ 双向锁退化成恒真）
    let blk6 = r#"let action_rows: &[(i64, &str, &str, &str)] = &[
        (710, "提交", "submit", "To Submit"),
        (716, "自动通过", "auto_approve", "Auto Approve"),
    ]"#;
    let seeded6 = seed_dict_values(blk6);
    assert!(
        seeded6.contains("submit") && seeded6.contains("auto_approve"),
        "兜底种子值抽取失败：{seeded6:?}（类型标注行会把抽取带偏）"
    );
    assert_eq!(seeded6.len(), 2, "类型标注元组被当成数据行计入：{seeded6:?}");
    // 对照组：单引号/嵌套括号密集时仍只取到字典值
    let blk6b = r#"let action_rows: &[(i64, &str)] = &[(900, "a(b", "tricky_val")];"#;
    assert_eq!(
        seed_dict_values(blk6b).into_iter().collect::<Vec<_>>(),
        vec!["tricky_val".to_string()],
        "实参切分在第 2 元被括号打乱 ⇒ 抽取器不稳健"
    );
}
