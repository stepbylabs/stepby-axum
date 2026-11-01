//! 「失败被折成正常值」的**共用**判据实现（b149 项 18 立项，收 b148 之前散在三处的私有谓词）。
//!
//! # 为什么需要一条共用实现
//!
//! 同一句纪律（「`Err` 不得被读成『没有这件事』」）在本仓此前有三份**互不相等**的尺：
//! - `service/sys_report_service.rs` 的 `folds_errors_into_defaults`：只判
//!   `unwrap_or(0)` / `unwrap_or_default()` / `.ok()` 三支，且只认带 `.await` 的语句；
//! - `shared_store/redis_store.rs` 的 `reports_bootstrap_failures`：判 `unwrap_or(1)` 与
//!   `let _: Result<(), _>`，但作用域锁死在 `bootstrap_from_db` 一个函数；
//! - `middleware/response_cache.rs` 的 `read_full_body` 腿：只判 `unwrap_or_default()`。
//!
//! 三份各自少一支，于是 `unwrap_or(false)`（跨实例抢占键失败被读成「别人抢到了」）与
//! `unwrap_or(None)`（缓存读失败被读成「未命中」）这两型**长期没有任何判据覆盖**——
//! 本批实测 `set_nx_ex(..).await.unwrap_or(false)` 在生产码有 2 处、
//! `store.get(..).await.unwrap_or(None)` 有 2 处，全部静默。
//!
//! 共用实现的取值方向取**最严的那一支**（不是取交集）：取交集等于借"统一"之名放松另外两把锁
//! （b87 §6 的同一条纪律）。
//!
//! # 判据的方向为什么必须要求"同一语句里有 `.await`"
//!
//! `map.get(&k).copied().unwrap_or(0)`、`s.parse::<i64>().unwrap_or(0)` 这类是**合法的默认值**
//! （没有失败通道被丢弃）。把这条判据做成"见到 `unwrap_or` 就红"会误报一片，结局是被放宽掉
//! （AGENTS 前言 ⑯(c)：前置条件不成立的判据是每轮产出噪声的负资产）。所以本尺只认
//! **同一条语句里确实有一次 `Err` 来源**（`.await`）的形状。

/// 一条被抓住的折叠。`needle` 是缺陷形态本身，`line` 是**1 起**的行号
/// （报错必须指到真实行，否则人照着提示去改另一行——AGENTS ⑨/㉘ 的同族）。
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct FoldHazard {
    pub needle: &'static str,
    pub line: usize,
}

/// 「把 `Err` 折成值」的形态清单。方向一律是**宽进**（多抓几种写法），因为这一族的
/// 历史形态就是"换个写法就绕过去"：`.ok()` 被抓就改 `.unwrap_or_default()`。
const FOLD_NEEDLES: &[&str] = &[
    "unwrap_or(0)",
    "unwrap_or(1)",
    // 跨实例抢占键/开关：Err 与"没抢到"在这两支下不可区分（本批 sys_flow_service 的真实缺陷）。
    "unwrap_or(false)",
    "unwrap_or(true)",
    // 缓存/共享态读：Err 与"未命中"不可区分（本批 sso_handler 的真实缺陷）。
    "unwrap_or(None)",
    "unwrap_or_default()",
    // 收 Result 又丢掉结局的注解形写法——`let _: Result<(), _> =` 比 `_ =` 更"像被处理过"。
    "let _: Result",
    ".ok()",
];

/// 「同步锁中毒被折成空值」的形态：`Mutex` 中毒后 `.ok()` 返回 `None`，于是
/// "审计字段没写到" 与 "锁被前一个 panic 弄坏了" 在界面上同形。
const POISON_NEEDLES: &[&str] = &[".lock().ok()", "if let Ok("];

// 编译期把"needle 表 ↔ 夹具表"的数量钉住：删一支 needle 而不删对应夹具 ⇒ 构建失败；
// 加一支 needle 而不加夹具 ⇒ 同样失败。这一族锁的历史形态就是"needle 拼错/漏写而
// 真实树照样全绿"（前言 ⑥/⑬/㉘），只靠运行时逐条断言仍要有人记得跑。
const _: () = assert!(FOLD_NEEDLES.len() == 8);
const _: () = assert!(POISON_NEEDLES.len() == 2);

/// 行尾归一：判据读的是**语义**，CRLF 工作树不得让跨行语句的判据结构性失效
/// （AGENTS ㉘/b140(i) 那条"行尾漂移是判据假红的隐形来源"）。
fn normalized(code: &str) -> String {
    code.replace("\r\n", "\n")
}

/// 1 起的行号（`at` 为字符偏移；调用方保证 `at` 落在 `code` 的字符边界上——
/// 所有 needle 都是 ASCII，`find` 返回的偏移必然是边界）。
fn line_of(code: &str, at: usize) -> usize {
    code[..at].matches('\n').count() + 1
}

/// 取 `at` 所在语句（按 `;` 切，边界取"上一个 `;` 之后"到"下一个 `;`"）。
///
/// 为什么按语句而不是按行：真实缺陷常写成跨行链式
/// （`q.count(db)\n .await\n .map(..)\n .unwrap_or(0);`），按行判会把 `.await` 与
/// `unwrap_or` 拆到两行里，于是**每一条跨行写法都恰好漏掉**（b148 项 24 实测过同族）。
fn statement_range(code: &str, at: usize) -> (usize, usize) {
    let start = code[..at].rfind(';').map(|p| p + 1).unwrap_or(0);
    let end = code[at..].find(';').map(|p| at + p).unwrap_or(code.len());
    (start, end)
}

/// 一次 `Err` 来源被折成值：同一语句内既有 needle 又有 `.await`。
pub fn folds_errors_into_defaults(code: &str) -> Vec<FoldHazard> {
    let code = normalized(code);
    let mut out = Vec::new();
    for needle in FOLD_NEEDLES {
        let mut from = 0usize;
        while let Some(rel) = code[from..].find(needle) {
            let at = from + rel;
            let (start, end) = statement_range(&code, at);
            if code[start..end].contains(".await") {
                out.push(FoldHazard {
                    needle,
                    line: line_of(&code, at),
                });
            }
            from = at + needle.len();
        }
    }
    out.sort();
    out.dedup();
    out
}

/// 同步锁中毒被折成"没有值"：同一语句内既有 `.lock()` 又有中毒吞掉形态。
///
/// 这一支**不要求** `.await`——`Mutex::lock` 本身就是同步的，套上那条前提会结构性打不中。
pub fn lock_poison_folds(code: &str) -> Vec<FoldHazard> {
    let code = normalized(code);
    let mut out = Vec::new();
    for needle in POISON_NEEDLES {
        let mut from = 0usize;
        while let Some(rel) = code[from..].find(needle) {
            let at = from + rel;
            let (start, end) = statement_range(&code, at);
            let stmt = &code[start..end];
            if stmt.contains(".lock()") || stmt.contains(".read().") || stmt.contains(".write().") {
                out.push(FoldHazard {
                    needle,
                    line: line_of(&code, at),
                });
            }
            from = at + needle.len();
        }
    }
    out.sort();
    out.dedup();
    out
}

/// 两个集合的并（按 needle+line 去重后排序），供"两类都要查"的调用点用一份实现。
pub fn all_hazards(code: &str) -> Vec<FoldHazard> {
    let mut out = folds_errors_into_defaults(code);
    out.extend(lock_poison_folds(code));
    out.sort();
    out.dedup();
    out
}

/// 同一语句内「指定接收者 + 指定折叠形态 + 一次 `.await`」三者同时成立。
///
/// 为什么需要这一把而不直接用 [`folds_errors_into_defaults`]：后者判的是整族
/// 「有 `Err` 来源被折成值」，本仓仍有**尚未立案**的成员（`try_get` 解码那一族 74 处
/// 已按实登记为待处置）；这一把只锁**已经关掉、且不得再长回来**的具体形状，
/// 于是允许表小到可以逐条写自足理由（AGENTS ㉘：登记表必须逐条自足）。
/// `receiver` 与 `fold` 都按字面匹配——两者都是 ASCII，且都是**缺陷形状本身**，
/// 不需要正则（写正则会把 needle 的语义藏在转义里，判据红时无法复述它抓的是什么）。
pub fn shape_hits(code: &str, receiver: &'static str, fold: &'static str) -> Vec<FoldHazard> {
    let code = normalized(code);
    let mut out = Vec::new();
    let mut from = 0usize;
    while let Some(rel) = code[from..].find(fold) {
        let at = from + rel;
        let (start, end) = statement_range(&code, at);
        let stmt = &code[start..end];
        if stmt.contains(".await") && stmt.contains(receiver) {
            out.push(FoldHazard {
                needle: fold,
                line: line_of(&code, at),
            });
        }
        from = at + fold.len();
    }
    out.sort();
    out.dedup();
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 逐支双向：每一支 needle 都必须**真的能被抓到**。
    ///
    /// 这一条是本模块存在的理由：只写"真实树 0 处"的锁，needle 拼错时永远打不中、
    /// 而报告长得和干净一模一样（AGENTS ⑥/⑬/㉘——本仓第四次抓到同形状）。
    #[test]
    fn every_fold_needle_is_actually_caught() {
        let fixtures = [
            "let n = q.count(db).await.unwrap_or(0);",
            "let exists: i64 = cmd(EXISTS).await.unwrap_or(1);",
            "let acquired = store.set_nx_ex(&k, \"1\", ttl).await.unwrap_or(false);",
            "let live = store.exists(&k).await.unwrap_or(true);",
            "let hit: Option<String> = store.get(&k).await.unwrap_or(None);",
            "let body = resp.text().await.unwrap_or_default();",
            "let _: Result<(), _> = store.set_ex(&k, &v, ttl).await;",
            "let doc = repo.find_by_id(id).await.ok();",
        ];
        // 夹具与 `FOLD_NEEDLES` **逐支配对**：只断"抓到一条"的话，某支 needle 被删掉后
        // 同一份文本仍可能被另一支误打误撞抓到（`unwrap_or_default()` 与 `.ok()` 之外
        // 的形状并不互斥），于是"这条腿断了"读成"这条腿还在"。
        let expected = [
            "unwrap_or(0)",
            "unwrap_or(1)",
            "unwrap_or(false)",
            "unwrap_or(true)",
            "unwrap_or(None)",
            "unwrap_or_default()",
            "let _: Result",
            ".ok()",
        ];
        assert_eq!(
            expected.len(),
            FOLD_NEEDLES.len(),
            "夹具表必须与 needle 表逐支对齐（needle 表 {} 支 / 夹具表 {} 支）",
            FOLD_NEEDLES.len(),
            expected.len()
        );
        for ((needle_index, code), want) in fixtures.iter().enumerate().zip(expected) {
            let hits = folds_errors_into_defaults(code);
            assert_eq!(
                hits.len(),
                1,
                "夹具 #{needle_index}（{code}）必须恰被抓到一次，实际 {hits:?}"
            );
            assert_eq!(
                hits[0].needle, want,
                "夹具 #{needle_index}（{code}）必须由 {want} 这一支抓到 ⇒                  抓到的是别的支就是巧合，这一支本身没有牙"
            );
        }
    }

    /// 跨行链式写法必须仍能命中（按行判的尺会在这里漏，而真实缺陷正是这个形状）。
    #[test]
    fn multiline_chain_is_in_scope() {
        let code = "let n = q.count(db)\n    .await\n    .map(|c| c as i64)\n    .unwrap_or(0);\n";
        let hits = folds_errors_into_defaults(code);
        assert_eq!(hits.len(), 1, "跨行链式必须命中：{hits:?}");
        assert_eq!(hits[0].needle, "unwrap_or(0)");
        assert_eq!(hits[0].line, 4, "行号必须落在 needle 那一行，不是语句首行");
    }

    /// 合法默认值**不得**被抓：没有 `Err` 来源的 `unwrap_or` 不是这一族。
    ///
    /// 反方向如果放松，判据会误报一片，最终被人调宽——那才是真正失去防线（前言 ⑯(c)）。
    #[test]
    fn legitimate_defaults_are_not_folds() {
        let code = "\
let day_count = trend_map.get(&date_str).copied().unwrap_or(0);
let timeout = secs.max(1) as u64;
let parsed = s.parse::<i64>().unwrap_or(-1);
";
        assert!(
            folds_errors_into_defaults(code).is_empty(),
            "无 `.await` 的默认值不得算折叠：{code}"
        );
    }

    /// 中毒腿：必须不要求 `.await`（`Mutex::lock` 是同步的，套上那条前提就结构性打不中）。
    #[test]
    fn poison_shape_is_caught_without_await() {
        let code = "\
impl T {
    fn set(&self, v: i64) {
        if let Ok(mut guard) = self.0.lock() {
            *guard = Some(v);
        }
    }
    fn get(&self) -> Option<i64> {
        self.0.lock().ok().and_then(|g| *g)
    }
}
";
        let hits = lock_poison_folds(code);
        assert_eq!(hits.len(), 2, "两支中毒形态都要抓到：{hits:?}");
        // 同一份代码在"折叠"尺下必须为空——两把尺查的不是同一件事，不得互顶。
        assert!(
            folds_errors_into_defaults(code).is_empty(),
            "中毒形态不含 `.await`，折叠尺看不见它是预期的"
        );
    }

    /// 干净实现不得报（`into_inner()` 兜中毒的写法在本仓是合规的）。
    #[test]
    fn poison_recovered_shape_is_clean() {
        let code = "let mut guard = self.0.lock().unwrap_or_else(|e| e.into_inner());\n";
        assert!(lock_poison_folds(code).is_empty(), "{code}");
        assert!(
            folds_errors_into_defaults(code).is_empty(),
            "同步 `lock()` 不该被折叠尺抓到"
        );
    }

    #[test]
    fn union_covers_both_legs() {
        let code = "\
let hit = store.get(&k).await.unwrap_or(None);
let guard = self.0.lock().ok();
";
        let hits = all_hazards(code);
        assert_eq!(hits.len(), 2, "并集要同时含两支：{hits:?}");
    }

    /// 活性反证：`all_hazards` 不得只是"两条各自跑一遍然后各自都可能恒空"。
    /// 同一份缺陷文本必须被两把尺**分别**抓到（否则 `union` 退化成只有一条腿）。
    #[test]
    fn each_leg_is_independently_load_bearing() {
        let fold_only = "let hit = store.get(&k).await.unwrap_or(None);\n";
        let poison_only = "let guard = self.lock().ok();\n";
        assert_eq!(folds_errors_into_defaults(fold_only).len(), 1);
        assert!(folds_errors_into_defaults(poison_only).is_empty());
        assert_eq!(lock_poison_folds(poison_only).len(), 1);
        assert!(lock_poison_folds(fold_only).is_empty());
        assert_eq!(all_hazards(fold_only).len(), 1);
        assert_eq!(all_hazards(poison_only).len(), 1);
    }

    /// 行尾归一正控：同一份缺陷写成 CRLF 必须得到**同样的结论与同样的行号**
    /// （b140(i)：工作树行尾漂成 CRLF 而 `git status` 一字不显，跨行哨兵因此永不成立）。
    #[test]
    fn crlf_input_gets_the_same_verdict() {
        let lf = "let a = q.count(db)\n    .await\n    .unwrap_or(0);\n";
        let crlf = lf.replace('\n', "\r\n");
        assert_eq!(
            folds_errors_into_defaults(&crlf),
            folds_errors_into_defaults(lf),
            "行尾不得改变判定"
        );
        let hits = folds_errors_into_defaults(&crlf);
        assert_eq!(hits.first().map(|h| h.line), Some(3));
    }

    /// 采集面自证：空文本必须得出"零命中"，而**真实存在折叠**的文本必须非零——
    /// 这一条挡住"解析器坏了 ⇒ 永远干净"（前言 ⑥）。
    #[test]
    fn empty_input_is_clean_but_nonempty_defect_is_not() {
        assert!(folds_errors_into_defaults("").is_empty());
        assert!(lock_poison_folds("").is_empty());
        assert!(
            !folds_errors_into_defaults("let x = call().await.unwrap_or_default();").is_empty()
        );
    }

    // ---- 生产码形状锁（b149 项 18 / 27）------------------------------------

    /// 一把已关掉、且不得再长回来的具体形状。
    struct LockedShape {
        /// 接收者锚点：这一族的**语义身份**（哪一次调用被折了）
        receiver: &'static str,
        /// 折叠形态：被折成的那个值
        fold: &'static str,
        /// 为什么这一形状必须为 0（不是"这算不算错误"，而是"失败之后谁能看见什么"）
        why: &'static str,
    }

    /// 允许表：`文件 + 折叠形态 + 应有条数 + 自足理由`。
    struct Allowed {
        file: &'static str,
        fold: &'static str,
        count: usize,
        why: &'static str,
    }

    /// 本批锁定的三型。方向取**具体形状**而不是整族：`try_get` 解码那一族（74 处）
    /// 尚未立案，拿 `folds_errors_into_defaults` 全族判会把"没立案"读成"有缺陷"，
    /// 结果只能是放宽（前言 ⑯(c)）。
    const LOCKED_SHAPES: &[LockedShape] = &[
        LockedShape {
            receiver: "set_nx_ex(",
            fold: "unwrap_or(",
            why: "跨实例抢占键：`Err` 被读成「没抢到」⇒ 与真的被别的副本抢到不可区分，\
                  多副本下该做的事整轮不做且无人知晓",
        },
        LockedShape {
            receiver: ".get(",
            fold: "unwrap_or(None)",
            why: "共享态缓存读：`Err` 被读成「未命中」⇒ 存储故障时每次请求都重新走\
                  完整验证链（等于缓存整层消失），而症状只是「变慢了」",
        },
        LockedShape {
            receiver: ".await",
            fold: "let _: Result",
            why: "注解形丢弃：写了类型注解看着像「处理过了」，实际结局整条丢掉，\
                  既不计数也不留痕",
        },
    ];

    /// 逐条带理由的豁免。空表时不需要条目；一旦有合法站点必须**逐条**写理由，
    /// 且本轮没出现 ⇒ 报撤销（未命中的豁免等于把闸和它的证据一起注销，b144）。
    const FOLD_ALLOW: &[Allowed] = &[];

    /// 生产码里这三型必须 0 处（除允许表逐条登记过的以外）。
    ///
    /// 判据按 (文件, 形态) 计数而**不按行号**：`cargo fmt` 一折行行号就漂，
    /// 判据会红在自己的输入上（b128 `anchor_form` 的同一课）。
    /// 三个方向一次判完：**未登记必红** / **条数不符必红** / **登记未命中必报撤销**
    /// （b144：未命中的豁免等于把闸和它的证据一起注销）。
    #[test]
    fn production_code_has_no_unlisted_fold_shapes() {
        let cfg = crate::common::prod_scan::Scan {
            strip_test_code: true,
            comments: crate::common::prod_scan::Comments::Blank,
            include_integration_tests: false,
            // 本文件是判据实现，`shape_hits` 的合成夹具里就有这三型；
            // 它只在测试构建存在，但仍显式剔掉，免得「needle 写在判据自己身上」
            // 这一族洞（前言 ㉞）在这里复发。
            exclude: &["src/common/fold_scan.rs"],
            roots: &["src"],
        };
        let files = crate::common::prod_scan::prod_files(&cfg);
        crate::common::prod_scan::require_volume(&files, 300, 40_000, "折叠形状锁的生产码采集面");

        let mut problems: Vec<String> = Vec::new();
        for s in LOCKED_SHAPES {
            let join_lines = |v: &[usize]| {
                v.iter()
                    .map(|l| l.to_string())
                    .collect::<Vec<_>>()
                    .join(",")
            };
            // 实测：文件 → (条数, 行号)
            let mut measured: std::collections::BTreeMap<String, (usize, Vec<usize>)> =
                std::collections::BTreeMap::new();
            for f in &files {
                let hits = shape_hits(&f.text(), s.receiver, s.fold);
                if hits.is_empty() {
                    continue;
                }
                let e = measured.entry(f.rel.clone()).or_insert((0, Vec::new()));
                e.0 += hits.len();
                for h in hits {
                    e.1.push(h.line);
                }
            }
            // 登记：同形态的条目按文件取
            let allow: std::collections::BTreeMap<&str, (usize, &str)> = FOLD_ALLOW
                .iter()
                .filter(|a| a.fold == s.fold)
                .map(|a| (a.file, (a.count, a.why)))
                .collect();

            for (file, (count, lines)) in &measured {
                match allow.get(file.as_str()) {
                    None => problems.push(format!(
                        "未登记：{file} 的 {} ×{count}（行 {}）。\n  这一型锁的是：{}",
                        s.fold,
                        join_lines(lines),
                        s.why
                    )),
                    Some((want, _why)) if *want != *count => problems.push(format!(
                        "条数不符：{file} 的 {} 登记 {want} 条 / 实测 {count} 条（行 {}）",
                        s.fold,
                        join_lines(lines)
                    )),
                    Some(_) => {}
                }
            }
            for file in allow.keys() {
                if !measured.contains_key(*file) {
                    problems.push(format!(
                        "登记未命中：{} 的 {} 本轮 0 处 ⇒ 撤销这条（未命中的豁免不产生红，\
                         但闸已经不约束任何东西了）",
                        file, s.fold
                    ));
                }
            }
        }

        assert!(
            problems.is_empty(),
            "折叠形状锁破防（{} 条）：\n{}",
            problems.len(),
            problems.join("\n")
        );
    }

    /// 允许表自身可证伪：每一条都必须指得着一个**真在采集面里**的文件。
    ///
    /// 空表时这一条同样成立（不循环 ⇒ 不红），但它挡住"登记了一条不存在的路径
    /// ⇒ 永远不命中也永远不报"的形状（前言 ⑥ 的否定面必须先在采集面里）。
    #[test]
    fn allow_entries_point_at_real_scanned_files() {
        let cfg = crate::common::prod_scan::Scan {
            strip_test_code: true,
            comments: crate::common::prod_scan::Comments::Blank,
            include_integration_tests: false,
            exclude: &["src/common/fold_scan.rs"],
            roots: &["src"],
        };
        let rels: Vec<String> = crate::common::prod_scan::prod_files(&cfg)
            .iter()
            .map(|f| f.rel.clone())
            .collect();
        for a in FOLD_ALLOW {
            assert!(
                rels.iter().any(|r| r == a.file),
                "允许表条目 {} 不在采集面里（路径写错或该文件已删 ⇒ 这条登记是死的）",
                a.file
            );
            assert!(
                a.count > 0 && a.why.chars().count() >= 12,
                "允许表条目 {}/{} 必须条数 >0 且理由自足（≥12 字符）",
                a.file,
                a.fold
            );
        }
    }

    /// 锁的刀口必须真能落下：合成违规被抓、合规写法不误报、缺一个前提不报。
    #[test]
    fn shape_lock_is_falsifiable() {
        // ① 抢占键被折成 false：必须抓
        let bad = "let ok = store.set_nx_ex(&k, \"1\", ttl).await.unwrap_or(false);\n";
        assert_eq!(
            shape_hits(bad, "set_nx_ex(", "unwrap_or(").len(),
            1,
            "抢占键折叠必须被抓（合成违规）"
        );
        // ② 合规：没有失败通道（同步 map，没有 `.await`）
        let good = "let v = map.get(&k).copied().unwrap_or(None);\n";
        assert!(
            shape_hits(good, ".get(", "unwrap_or(None)").is_empty(),
            "没有 `Err` 来源的默认值不得算折叠：{good}"
        );
        // ③ 有 `.await` 但接收者不是被锁的那一个 ⇒ 不属于这一形状
        let other = "let v = repo.get(&k).await.unwrap_or(None);\n";
        assert_eq!(
            shape_hits(other, "store.get(", "unwrap_or(None)").len(),
            0,
            "接收者对不上不得算这条形状"
        );
        assert_eq!(
            shape_hits(other, ".get(", "unwrap_or(None)").len(),
            1,
            "同一形状换个接收者变量名仍必须在 `.get(` 口径下被抓"
        );
        // ④ 跨行链式必须命中（按行判的尺会在这里漏，真实缺陷正是这个形状）
        let multiline =
            "let ok = store\n    .set_nx_ex(&k, \"1\", ttl)\n    .await\n    .unwrap_or(false);\n";
        assert_eq!(
            shape_hits(multiline, "set_nx_ex(", "unwrap_or(").len(),
            1,
            "跨行链式不得从刀口下溜过去"
        );
        // ⑤ 注解形丢弃：`let _: Result` 与 `.await` 同语句
        let annotated = "let _: Result<(), _> = store.set_ex(&k, &v, ttl).await;\n";
        assert_eq!(shape_hits(annotated, ".await", "let _: Result").len(), 1);
        // ⑥ 同一文本在"整族"尺下也必须被抓（两把尺不是互替关系）
        assert_eq!(folds_errors_into_defaults(annotated).len(), 1);
    }

    /// 锁的输入必须非空且形状对：本批新通道与接线点在生产码视图里**取得到**，
    /// 否则上一条锁的"0 处"可能只是"一条都没扫到"（前言 ⑥/⑬）。
    #[test]
    fn the_files_this_batch_changed_are_in_the_face() {
        let cfg = crate::common::prod_scan::Scan {
            strip_test_code: true,
            comments: crate::common::prod_scan::Comments::Blank,
            include_integration_tests: false,
            exclude: &[],
            roots: &["src"],
        };
        let sso = crate::common::prod_scan::prod_file("src/handler/sso_handler.rs", &cfg);
        assert!(
            sso.text().contains("store_outcome::read_key("),
            "SSO 缓存读必须走三态通道（生产码视图里取不到 ⇒ 本批接线没落地）"
        );
        assert!(
            !sso.text().contains(".await.unwrap_or(None)"),
            "SSO 文件里不得再出现被折成未命中的缓存读"
        );
        let flow = crate::common::prod_scan::prod_file("src/service/sys_flow_service.rs", &cfg);
        assert!(
            flow.text().contains("store_outcome::acquire_window("),
            "流程提醒/升级窗口必须走结局三态"
        );
    }
}
