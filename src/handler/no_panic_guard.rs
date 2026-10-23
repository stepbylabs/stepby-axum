//! 生产代码防 panic 守卫（批六十六）。
//!
//! 背景：handler 是请求路径的终点——一旦 panic，axum 会中断整条连接（无 HTTP 状态码、
//! 无 `code/msg` 契约、无审计留痕），属"错误响应契约统一"硬基线（AGENTS.md C-8）的破坏。
//! 实证：`sso_handler` 的 `serde_json::to_value(result).unwrap()`、`gen_table_service`
//! 的 `models.pop().unwrap()` 均为"理论上不可能"但语义错误的 panic；
//! 批六十六已改为统一错误响应。
//!
//! 本测试把已治理完成的不变量**锁死**：生产码（`#[cfg(test)]` 之前）不得出现 `.unwrap()`。
//! `expect(...)` 带明确不变量说明、且有对应的错误分级，另行评审放行。
//!
//! 批八十八把扫描面从 `src/handler/**` **扩到全 `src` 生产码**（集成测试树仍由
//! `prod_scan` 的默认口径排除）。动手前先量了存量：全 `src` 含测试码共 98 处 `unwrap()`，
//! 其中 **96 处在 `src/integration_tests/**`**（测试里 unwrap 是合法表达），生产码只剩两处，
//! 且都在请求路径上——`common::sql_dialect::to_pg_placeholders` 的 `chars.next().unwrap()`
//! 与 `common::custom_scope` 分隔符识别的 `s.chars().next().unwrap()`。两处本批改为
//! `Peekable::next_if_eq` / `Option::is_some_and` 吃掉，"取不到"这条路从类型上不存在了。
//!
//! 同批删掉了 `MATCH_GUARD_DIRS` 那份目录豁免清单，理由逐条实测而非推断：
//! ① 它**一条都不生效**——唯一的调用点只扫 `src/handler/`，清单里五个目录都在树下之外；
//! ② 它**没有必要**——那五个目录（initialize/repository/middleware/scheduler/bin）的
//! 生产码视图里 `unwrap()` 实测 0 处，它们当初被豁免是因为含"穷尽匹配守卫"型 `unreachable!`，
//! 而本锁的needle从来只有 `unwrap()`。把"结构上不可到达"的 panic 与"取一下 Option"的 panic
//! 混在同一张豁免表里，正是让后者在 4 个目录里静默长回来的通道。
//! `unreachable!` 那一族的正当性另立新锁（[`backend_fallback_arms_must_name_the_backend`]）。

#[cfg(test)]
mod no_panic_mod {
    use crate::common::prod_scan::{
        Comments, ProdFile, Scan, normalize, prod_file, prod_files, require_volume,
    };

    #[test]
    fn production_code_must_not_use_unwrap() {
        let files = prod_surface();
        require_volume(&files, 80, 20_000, "生产码 unwrap 守卫采集面");
        let violations = collect_unwrap_violations(&files);
        println!(
            "[no_panic] 生产码采集面 {} 个文件 / unwrap() 命中 {} 处",
            files.len(),
            violations.len()
        );
        assert!(
            violations.is_empty(),
            "生产代码禁止 .unwrap()（命中 panic 守卫）——panic 会中断整条请求连接，\
             无 HTTP 状态码、无 `code/msg` 契约、无审计留痕：\n{}",
            violations.join("\n")
        );
    }

    #[test]
    fn gen_table_service_must_not_panic_on_empty_import_result() {
        // 批六十六回归锁：`import_table` 不得以 panic 表达"契约不满足"
        let prod = prod_file("src/service/gen_table_service.rs", &Scan::default());
        assert!(
            !prod.text().contains("models.pop().unwrap()"),
            "gen_table_service::import_table 仍使用 models.pop().unwrap() —— panic 会中断 request task"
        );
    }

    // ============================ 后端兜底臂归因（批八十八 项 A）============================

    /// sea-orm 的 `DatabaseBackend`（`DbBackend` 只是别名）带 `#[non_exhaustive]`
    /// （`db_connection.rs:100-112`），跨 crate 的 match 不写兜底臂直接
    /// `E0004: non-exhaustive patterns: _ not covered`——本批用 rustc 最小双 crate 探针实测过。
    /// 所以这一族 `unreachable!` **消不掉**，属上游强加的形态。
    ///
    /// ⚠ 这同时**订正**了原 `MATCH_GUARD_DIRS` 注释里的说法。原话是"该类 panic 属**编译期
    /// 可发现**的穷尽性检查，新增 DB 后端变体时会立即暴露"——恰好反了：**有**兜底臂时新增
    /// 变体不会编译失败，而是走到 panic。"立即暴露"是这条注释承诺了却没有的那一半。
    ///
    /// 于是保留 panic 的唯一正当理由只剩"结构上不可能到达，且到达时必须响亮"；
    /// 而它原本的代价（不点名是哪个后端）由本锁消掉：兜底臂必须绑定变量并以 Debug 内插
    /// 点名后端名，让"上游被迫的兜底"仍然可归因。
    /// 模式串用 `concat!` 拼装，免得本判据在自己的源码里看到被禁形态（同 b85 `env_discipline`）。
    const ARM_MARK: &str = concat!("unreachable!(", "\"unknown backend");

    /// 行集里的兜底臂（1-based 行号 + 已 trim 的文本）。
    ///
    /// 输入必须来自 [`prod_scan`] 的归一视图：注释行被置空但**保留行号**，
    /// 于是"文档里写了一句兜底臂示例"不会被当成代码，而上报的行号仍指得到真实文件。
    fn find_fallback_arms(lines: &[String]) -> Vec<(usize, String)> {
        lines
            .iter()
            .enumerate()
            .filter(|(_, l)| l.contains(ARM_MARK))
            .map(|(i, l)| (i + 1, l.trim().to_string()))
            .collect()
    }

    /// 单条兜底臂的归因判据（纯函数：真实树与合成夹具共用同一份实现）。
    /// 返回 `Some(说明)` 即"到达了却说不出是谁"。
    fn fallback_arm_violation(arm: &str) -> Option<String> {
        let arm = arm.trim();
        let (pat, body) = match arm.split_once("=>") {
            Some(parts) => parts,
            None => {
                return Some(format!(
                    "兜底臂没写成 `<绑定名> => unreachable!(…)` 形态，无从确定它绑了谁: {arm}"
                ));
            }
        };
        let binding = pat.trim();
        if binding.is_empty() || binding == "_" {
            return Some(format!(
                "兜底臂用通配 `_`（或空模式）而不绑定后端 ⇒ panic 永远说不出是哪个后端: {arm}"
            ));
        }
        if !is_plain_ident(binding) {
            return Some(format!(
                "兜底臂的模式 `{binding}` 不是单个标识符 ⇒ 判据认不出它点名了谁（要放行请先在这里讨论形态，不要放宽本判据）: {arm}"
            ));
        }
        let needle = format!("{{{binding}");
        let Some(at) = body.find(&needle) else {
            return Some(format!(
                "兜底臂的 panic 文案没有内插它绑定的后端变量 `{binding}`（应写成 {{{binding}:?}}）: {arm}"
            ));
        };
        let rest = &body[at + needle.len()..];
        match rest.chars().next() {
            Some('}') | Some(':') => {}
            _ => {
                return Some(format!(
                    "文案里的 `{needle}…` 是**另一个名字**（比 `{binding}` 长），不是它绑定的后端 ⇒ 归因指向了错变量: {arm}"
                ));
            }
        }
        let Some(spec_end) = rest.find('}') else {
            return Some(format!("文案里的 `{{{binding}` 没有闭合的 `}}`: {arm}"));
        };
        if !rest[..spec_end].contains('?') {
            return Some(format!(
                "兜底臂必须用 Debug 内插（`{{{binding}:?}}`）——`DbBackend` 没有 Display，`{{{binding}}}` 既编译不过也读不出变体名: {arm}"
            ));
        }
        None
    }

    fn is_plain_ident(s: &str) -> bool {
        let mut chars = s.chars();
        match chars.next() {
            Some(c) if c.is_ascii_alphabetic() || c == '_' => {}
            _ => return false,
        }
        chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
    }

    /// **每一处**后端兜底臂都必须点名它拒绝的后端。
    ///
    /// 立案依据（本批取证）：兜底臂因 `#[non_exhaustive]` 不可避免，而
    /// "有兜底臂 ⇒ 新增变体不会编译失败，而是走到 panic"——所以唯一还能保住的是**可归因性**。
    /// 采集面与条数由本测试自己打印（文档不抄数），低于地板即红：
    /// 兜底臂"消失"到 20 处以下只可能是采集面塌了，不可能是有人把 26 处 match 全改完了。
    #[test]
    fn backend_fallback_arms_must_name_the_backend() {
        let files = prod_surface();
        require_volume(&files, 80, 20_000, "后端兜底臂归因锁采集面");
        let mut arms = 0usize;
        let mut violations = Vec::new();
        for f in &files {
            for (ln, text) in find_fallback_arms(&f.lines) {
                arms += 1;
                if let Some(why) = fallback_arm_violation(&text) {
                    violations.push(format!("  {}:{ln}  {why}", f.rel));
                }
            }
        }
        println!(
            "[backend_arm] 采集面 {} 个文件 / 兜底臂 {arms} 处 / 不可归因 {} 处",
            files.len(),
            violations.len()
        );
        assert!(
            arms >= 20,
            "后端兜底臂只数到 {arms} 处（地板 20）——本批实测真实树 26 处（不含集成测试）。 \
             这个数字掉下来只能是采集面腐化（目录改名/口径变更），不是\"兜底臂被消灭了\""
        );
        assert!(
            violations.is_empty(),
            "后端兜底臂必须绑定并以 Debug 点名后端，否则到达时只留下\"unknown backend\"一句空话：\n{}",
            violations.join("\n")
        );
    }

    /// 判据自身的双向证明：合规形态必须放行（否则 26 处真码会一起红，说明刀钝在了错误的一侧），
    /// 四种不可归因形态必须各自被抓。正控条数也进断言——"期望值全是 0 的用例行"
    /// 本身打印通过的形状，AGENTS 门禁表前言 ㉖ 立过案。
    #[test]
    fn backend_arm_judge_is_falsifiable() {
        let cases: &[(&str, bool)] = &[
            // 真实树在用的形态（含 `#?` 变体）⇒ 必须放行
            (
                r#"backend => unreachable!("unknown backend: {backend:?}"),"#,
                true,
            ),
            (r#"b => unreachable!("unknown backend: {b:#?}"),"#, true),
            // 四种"到达了却说不出是谁"⇒ 必须各自被抓
            (r#"backend => unreachable!("unknown backend"),"#, false),
            (
                r#"b => unreachable!("unknown backend: {backend:?}"),"#,
                false,
            ),
            (r#"_ => unreachable!("unknown backend"),"#, false),
            (r#"unreachable!("unknown backend: {backend:?}"),"#, false),
            (
                r#"backend => unreachable!("unknown backend: {backend}"),"#,
                false,
            ),
            (
                r#"b => unreachable!("unknown backend: {backend_longer:?}"),"#,
                false,
            ),
        ];
        let mut ok = 0usize;
        let mut caught = 0usize;
        let mut misses = Vec::new();
        for (arm, compliant) in cases {
            let violation = fallback_arm_violation(arm);
            match (*compliant, violation) {
                (true, None) => ok += 1,
                (true, Some(why)) => misses.push(format!("合规形态被误判: {arm} ⇒ {why}")),
                (false, None) => misses.push(format!("不可归因形态没被抓: {arm}")),
                (false, Some(_)) => caught += 1,
            }
        }
        println!(
            "[backend_arm] 合成夹具 {}/{} 通过（正控 {ok} / 反证 {caught}）",
            ok + caught,
            cases.len()
        );
        assert!(misses.is_empty(), "判据自身判错：\n{}", misses.join("\n"));
        assert!(ok >= 2, "正控（必须放行的合规形态）只剩 {ok} 条，低于 2");
        assert!(
            caught >= 6,
            "反证（必须被抓的形态）只剩 {caught} 条，低于 6"
        );

        // 注释里的示例串不得当成代码（口径由 prod_scan 保证，这里钉的是本锁真的吃这个口径）
        let src = "// 例：backend => unreachable!(\"unknown backend\") 是不允许的写法\nbackend => unreachable!(\"unknown backend: {backend:?}\"),\n";
        let view = normalize(
            src,
            &Scan {
                strip_test_code: false,
                comments: Comments::Blank,
                ..Default::default()
            },
        );
        let arms = find_fallback_arms(&view);
        assert_eq!(
            arms.len(),
            1,
            "注释里的那句示例必须被置空，真实那行必须被数到（两条同时成立才说明口径没退化）"
        );
        assert_eq!(arms[0].0, 2, "上报行号必须指到真实文件的第 2 行");
        assert_eq!(
            fallback_arm_violation(&arms[0].1),
            None,
            "真实树上在用的这一形态必须被判合规"
        );
    }

    /// 全 `src` 生产码视图（`unwrap()` 守卫与兜底臂归因**共用同一份采集口径**——
    /// 两份实现必漂，这是本仓立过至少四次的案）。
    ///
    /// 批八十八把这里从"自写遍历 + 在整份原文上找那个字面量当刀口"迁到共用的 `prod_scan`：
    /// 那句 naive 刀口正是 b82 前言 ⑬ 的成因（本文件的模块文档里就写着那个字面量，
    /// 于是一度只看得到前 8 行）。迁移只换采集管道，判据不变。
    /// 豁免本文件：下面那批合成夹具里的被禁形态不是违规。
    fn prod_surface() -> Vec<ProdFile> {
        prod_files(&Scan {
            exclude: &["src/handler/no_panic_guard.rs"],
            ..Default::default()
        })
    }

    /** 行集里命中 `unwrap()` 的行（1-based 行号 + 文本）；输入已是生产码归一视图 */
    fn find_unwrap_lines(lines: &[String]) -> Vec<(usize, String)> {
        lines
            .iter()
            .enumerate()
            .filter(|(_, l)| l.contains("unwrap()"))
            .map(|(i, l)| (i + 1, l.trim().to_string()))
            .collect()
    }

    /// 违规清单：与兜底臂那条共用 [`find_unwrap_lines`]，只是把行号换成 `文件:行` 形态上报。
    fn collect_unwrap_violations(files: &[ProdFile]) -> Vec<String> {
        files
            .iter()
            .flat_map(|f| {
                find_unwrap_lines(&f.lines)
                    .into_iter()
                    .map(move |(ln, text)| format!("  {}:{ln}  {text}", f.rel))
            })
            .collect()
    }

    /// 控制组：采集口径必须真的在"截断测试码"与"豁免本文件"两侧都生效。
    /// 没有这条，"扫到 0 处违规"与"一条都没扫"在数据集里逐字节同形（前言 ⑥）。
    #[test]
    fn scan_surface_cuts_test_code_and_skips_itself() {
        let files = prod_surface();
        require_volume(&files, 80, 20_000, "unwrap 守卫采集面控制组");
        assert!(
            !files
                .iter()
                .any(|f| f.rel == "src/handler/no_panic_guard.rs"),
            "本文件必须被豁免：夹具里的被禁形态不是违规"
        );
        // 反向对照：默认口径确实**不含**集成测试树，但开关一开就必须看得见（否则两向皆可过）
        assert!(
            !files
                .iter()
                .any(|f| f.rel.starts_with("src/integration_tests/")),
            "默认口径不得把集成测试树算进生产码——那里实测有 96 处 `unwrap()`，混进来会让守卫恒红"
        );
        let with_it = prod_files(&Scan {
            include_integration_tests: true,
            exclude: &["src/handler/no_panic_guard.rs"],
            ..Default::default()
        });
        assert!(
            with_it
                .iter()
                .any(|f| f.rel.starts_with("src/integration_tests/")),
            "`include_integration_tests` 必须真的生效"
        );
        // 合成违规证明刀是快的：生产行必须点名、属性之后的不得混进来
        let synthetic = normalize(
            "fn h() { value.unwrap() }\n#[cfg(test)]\nmod t { fn g() { other.unwrap() } }\n",
            &Scan::default(),
        );
        let hit = find_unwrap_lines(&synthetic);
        assert_eq!(
            hit,
            vec![(1usize, "fn h() { value.unwrap() }".to_string())],
            "生产码里的 unwrap 必须被点名，`#[cfg(test)]` 之后的不得混进来"
        );
    }
}
