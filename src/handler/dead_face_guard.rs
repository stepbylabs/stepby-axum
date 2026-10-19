//! 死面与假跳板总锁（批七十四 轮 28，AGENTS「真实实现，禁止假功能」+ §一.8）。
//!
//! 本批删掉了三类"看起来存在、实际不起作用"的东西：
//! - **假跳板**：`sys_web_hook_service::http_client_override` 注释写"单元测试注入替换出站转发"，
//!   但全仓只有声明与两处 `= None`，**从不读取**——测试并没有跳板，注释在给假功能背书；
//! - **撒谎的自检**：四处 `fn _type_assert(...)` 自称"供 router 挂载处的类型自检"，实际零调用者，
//!   而 router 挂载时编译器本来就校验 handler 签名——它唯一的作用是压掉 unused import 警告；
//! - **同判据两份实现**：`can_receive` / `filter_receivable` 与在用的 `allows_delivery` 写的是
//!   同一个 DND 判据（免打扰窗口条件在两处各一份），前者零调用者。
//!
//! 删完之后，本锁把"不许再长回来"钉住。判据一律是**形状**而不是数量：
//! `#[allow(dead_code)]` 只允许出现在带理由的登记位（当前为空集 ⇒ 任何新增即红），
//! 而控制组用合成源码证明扫描器真能抓到（0 处必须是"没有"，不能是"看不见"）。

#[cfg(test)]
mod dead_face_guard_lock {
    use crate::common::prod_scan::{self, Comments, Scan};

    /// 本文件自身：内含被禁字面量的合成源码，必须排除（同 `api_contract_guard` 口径）
    const SELF: &str = "src/handler/dead_face_guard.rs";

    /// 本锁的采集口径：**不截断 `#[cfg(test)]`**——死码抑制写在测试里同样是掩盖；
    /// 注释行置空以保行号（上报行号必须与真实文件对齐，见下方 `scan` 的注释）。
    fn scan_cfg() -> Scan<'static> {
        Scan {
            strip_test_code: false,
            comments: Comments::Blank,
            exclude: &[SELF],
            ..Default::default()
        }
    }

    /// 列出 src 下所有 .rs（相对路径，排除本文件）。
    /// 三处判据共用同一次遍历口径，避免"某个扫描器漏了子目录"这种自曝盲区。
    fn all_rs() -> Vec<String> {
        prod_scan::rel_paths("src")
            .into_iter()
            .filter(|rel| rel != SELF)
            .collect()
    }

    /// 收集 src 下所有**非注释**行（含测试码——死码抑制在测试里同样是掩盖）
    fn prod_lines(rel: &str) -> Vec<String> {
        prod_scan::prod_file(rel, &scan_cfg()).lines
    }

    /// 扫描源码行：返回 `(行号, 该抑制属性保护的下一个非空行)`。
    /// 抽成按**行切片**工作的纯函数（不是字节偏移）是为了让控制组能喂合成源码——
    /// 本仓 b74 已经两次抓到"扫描器自身把行号当字节号"这类缺陷，自己写的时候就得防。
    fn scan(lines: &[&str]) -> Vec<(usize, String)> {
        let mut hits = Vec::new();
        for (i, raw) in lines.iter().enumerate() {
            let t = raw.trim_start();
            if t.starts_with("//") {
                continue;
            }
            // 用 `contains` 而不是 `starts_with`：实测把抑制挂在上一行尾部
            // （`}#[allow(dead_code)]`，语法合法且 rustfmt 不改）会绕过按行首判定，
            // 于是"0 处"可能只是"看不见"。行内形态 `#[allow(dead_code)] fn x(){}` 同理要抓。
            if t.contains("#[allow(dead_code)]") {
                let next = lines[i + 1..]
                    .iter()
                    .map(|l| l.trim())
                    .find(|l| !l.is_empty() && !l.starts_with("///"))
                    .unwrap_or("<文件尾>")
                    .to_string();
                hits.push((i + 1, next));
            }
        }
        hits
    }

    fn repo_suppressions() -> Vec<(String, usize, String)> {
        let mut out = Vec::new();
        for rel in all_rs() {
            let text = prod_lines(&rel).join("\n");
            for (line_no, guarded) in scan(&text.lines().collect::<Vec<_>>()) {
                out.push((rel.clone(), line_no, guarded));
            }
        }
        out.sort();
        out
    }

    /// 棘轮：`#[allow(dead_code)]` 当前必须是**空集**。
    /// 本轮把 13 处抑制全部处理掉（8 处属"已接线却仍压制"、5 处随死码一起删除），
    /// 保留这个判据是为了让"新加一个死函数再压一下"当场变红——抑制等于让编译器
    /// 失去未来发现死码的能力，与本仓"零调用者必须删除或接线"的纪律直接冲突。
    #[test]
    fn dead_code_suppressions_are_all_removed() {
        let hits = repo_suppressions();
        assert!(
            hits.is_empty(),
            "仓库里又出现了 #[allow(dead_code)] 抑制：{hits:?}\n\
             请删除零调用者符号，或把它接线到真实调用点（见 b74 §3.12）"
        );
    }

    /// 控制组：扫描器必须能抓到合成抑制——否则上面那句"0 处"可能只是"看不见"
    #[test]
    fn scanner_catches_a_synthetic_suppression() {
        let synth = "\
pub struct Foo;
#[allow(dead_code)]
fn never_called() {}
";
        let hits = scan(&synth.lines().collect::<Vec<_>>());
        assert_eq!(hits.len(), 1, "合成抑制必须被抓到，抓到行 = {hits:?}");
        assert_eq!(hits[0].0, 2, "行号应指向属性行");
        assert!(
            hits[0].1.contains("fn never_called"),
            "应报出被保护的下一个 item，实际 {:?}",
            hits[0].1
        );
        // 挂在上一行尾（`}#[allow(dead_code)]`，实测的绕过形态）与行内形态也必须抓到
        let glued = "}#[allow(dead_code)]\nfn glue() {}\n#[allow(dead_code)] fn inline() {}\n";
        assert_eq!(
            scan(&glued.lines().collect::<Vec<_>>()).len(),
            2,
            "行尾悬挂与行内两种形态都不得漏"
        );
    }

    /// 控制组反向：注释里提到 `#[allow(dead_code)]`（治理文档常这么写）不得算违规
    #[test]
    fn comment_mention_is_not_a_suppression() {
        let synth = "// b74：原先这里挂着 #[allow(dead_code)]，已随死码删除\nfn live() {}\n";
        assert!(
            scan(&synth.lines().collect::<Vec<_>>()).is_empty(),
            "注释里的提及不得被判成抑制"
        );
        // 行号对账：注释被置空后，真抑制上报的必须是**真实文件行号**
        let numbered = "// 说明\n// 说明二\n\n#[allow(dead_code)]\nfn later() {}\n";
        let hits = scan(&numbered.lines().collect::<Vec<_>>());
        assert_eq!(hits.len(), 1, "第 4 行的抑制必须被抓到：{hits:?}");
        assert_eq!(hits[0].0, 4, "上报行号必须等于真实文件行号");
    }

    /// 假跳板不得复活：全仓不得再出现 `http_client_override`
    #[test]
    fn fake_http_client_injection_hook_must_not_return() {
        for rel in all_rs() {
            for (i, l) in prod_lines(&rel).iter().enumerate() {
                assert!(
                    !l.contains("http_client_override"),
                    "{rel}:{} 又出现了从未读取的出站跳板字段",
                    i + 1
                );
            }
        }
    }

    /// 撒谎的自检不得复活：`_type_assert` 四处已删（router 挂载时编译器本就校验签名）
    #[test]
    fn lying_type_assert_stubs_must_not_return() {
        let mut found: Vec<String> = Vec::new();
        for rel in all_rs() {
            if prod_lines(&rel).iter().any(|l| l.contains("_type_assert")) {
                found.push(rel);
            }
        }
        assert!(
            found.is_empty(),
            "出现了只为压 unused import 的假自检：{found:?}"
        );
    }

    /// 偏好投递判定必须只有一个入口，且 DND 条件只有一份实现
    #[test]
    fn notification_preference_judgment_has_one_entry() {
        let prod = prod_lines("src/service/sys_user_pref_service.rs").join("\n");
        for gone in ["can_receive", "filter_receivable"] {
            assert!(
                !prod.contains(gone),
                "零调用者的包装 {gone} 又长回来了（同判据两处实现必然漂移）"
            );
        }
        assert!(
            prod.contains("SysUserPrefService::dnd_active(p, now_hm)"),
            "allows_delivery 必须复用唯一 DND 判据 dnd_active，不得内联再写一份"
        );
        // DND 条件的物理实现只能有一处：窗口判定调用点计数
        let window_calls = prod
            .match_indices("is_in_dnd_window(&p.dnd_start, &p.dnd_end,")
            .count();
        assert_eq!(
            window_calls, 1,
            "免打扰窗口判定在偏好服务里应恰有 1 处实现，实际 {window_calls} 处"
        );
    }

    /// 投递路径必须真的调用这个唯一入口（写了没接线＝没写）
    #[test]
    fn delivery_paths_consume_the_single_entry() {
        for rel in [
            "src/service/sys_msg_service.rs",
            "src/service/sys_notice_service.rs",
        ] {
            let prod = prod_lines(rel).join("\n");
            assert!(
                prod.contains("allows_delivery("),
                "{rel} 不再复用 allows_delivery ⇒ 投递偏好判定出现了第二份实现"
            );
        }
    }

    /// 被删的两个仓储方法不得因"以后可能用到"而复活（存疑则保留的判据是**有调用点**）
    #[test]
    fn removed_raw_inserts_stay_removed() {
        for rel in [
            "src/repository/sys_report_board.rs",
            "src/repository/sys_user_pref.rs",
        ] {
            let prod = prod_lines(rel).join("\n");
            assert!(
                !prod.contains("fn insert_raw"),
                "{rel} 又出现了零调用者的 insert_raw"
            );
        }
    }

    /// 探针：确认本锁真的在看这些文件（防止扫描根写错导致全绿空转）。
    /// 只断"数量 > 0"是不够的——数量 45 也算"扫到了些东西"却漏掉大半；因此同时钉
    /// 三个**必然存在**的文件名与一个数量下界（实测 457 个 .rs，留一半余量）。
    #[test]
    fn scanner_root_and_targets_are_reachable() {
        // `all_rs()` 走共享采集器：目录不可读或扫到 0 个文件会直接 panic（不是返回空集）
        let files = all_rs();
        for must in [
            "src/service/sys_user_pref_service.rs",
            "src/service/sys_web_hook_service.rs",
            "src/handler/api_contract_guard.rs",
        ] {
            assert!(
                files.iter().any(|f| f == must),
                "遍历结果缺少 {must} ⇒ 扫描根或排除条件写错了，本锁此刻是空转的"
            );
        }
        assert!(
            files.len() > 200,
            "扫描到的 .rs 文件数过少（{}）说明遍历写错了",
            files.len()
        );
    }
}
