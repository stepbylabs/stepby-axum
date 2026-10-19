//! 生产码扫描器（**仅测试构建存在**，`#[cfg(test)] mod prod_scan;`）。
//!
//! ## 为什么要有这一个文件
//!
//! 本仓的形状锁（garde 执行锁、i18n 键锁、fail-closed 锁、死面锁、出站指标锁、时间口径锁）
//! 都需要"把 `src/**/*.rs` 的生产码按行喂给判据"。批七十五立项时实测全仓有**六份各自复刻**
//! 的实现（`common/i18n.rs`、`common/datetime.rs`、`handler/api_contract_guard.rs`、
//! `handler/dead_face_guard.rs`、`handler/fail_closed_guard.rs`、
//! `handler/outbound_metrics_guard.rs`），而它们的语义**并不一致**：
//!
//! | 维度 | 不一致的地方 | 后果 |
//! |---|---|---|
//! | 是否截断 `#[cfg(test)]` | 有的截、有的刻意不截（死码抑制在测试里同样是掩盖） | 同一形态在两把锁里一边可见一边不可见 |
//! | 注释行 | 有的**置空保行号**、有的**直接剔除** | 剔除的那把上报行号与真实文件错位，下一次施工白跑 |
//! | 自豁免 | 各写各的文件名常量 | 漏写即"锁扫到自己→把自己豁免掉"，或反过来被自己的模式串误伤 |
//! | 体量下限 | 只有一份有（`>200`） | 其余五份在路径/目录改名后**静默扫到 0 文件**，锁变恒绿 |
//!
//! 最后一条是这批改造的真正动机：扫描器扫不到文件时不报错、判据循环空转、测试照样绿——
//! 这与批七十三轮 18"判据方向对、测量对象错"同族，属"看不见问题的那种绿"，
//! 比缺检查更危险。所以下面把四件事收进一处，并把**体量下限做成必选项**（`require_volume`）。
//!
//! ## 判据代码不动
//!
//! 本文件只负责"采集与归一"。各锁的判据（匹配什么形态、怎么裁决）留在原模块里，
//! 迁移只换采集管道——这样任何一把锁的行为变化都只能来自判据本身，不会来自采集面。

use std::path::{Path, PathBuf};

/// 注释行的处理方式。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Comments {
    /// 注释行**置空但保留行号**（推荐；死面锁的"上报行号必须对得上真实文件"依赖它）。
    Blank,
    /// 注释行直接剔除（会让行号错位，仅保留给确实只关心内容序列的判据）。
    Drop,
    /// 剔除 `//`、`/* …` 与块注释续行 `* …`（时间口径锁的形态）。
    DropBlocks,
}

/// 一次扫描的采集口径。默认值即推荐口径。
#[derive(Debug, Clone, Copy)]
pub struct Scan<'a> {
    /// 是否在 `#[cfg(test)]` 处截断（true ⇒ 只看生产码）。
    pub strip_test_code: bool,
    /// 注释行处理方式。
    pub comments: Comments,
    /// 是否把 `src/integration_tests/**` 纳入扫描面。
    pub include_integration_tests: bool,
    /// 额外的豁免文件（相对路径，`/` 分隔）。各锁在这里填**自己**的文件名，
    /// 避免判据被自家源码里的模式串命中。
    pub exclude: &'a [&'a str],
    /// 采集根（相对 crate 根，`/` 分隔）。默认只有 `src`；
    /// 需要连隔壁 crate 一起扫的锁（如时间口径锁扫 `migration/src`）在这里加。
    /// **每个根都必须至少扫到一个 `.rs`**，否则直接 panic——空采集面不是通过。
    pub roots: &'a [&'a str],
}

impl Default for Scan<'_> {
    fn default() -> Self {
        Self {
            strip_test_code: true,
            comments: Comments::Blank,
            include_integration_tests: false,
            exclude: &[],
            roots: &["src"],
        }
    }
}

/// 一个被扫到的文件：相对路径（`/` 分隔）+ 已按口径归一的行集。
#[derive(Debug, Clone)]
pub struct ProdFile {
    pub rel: String,
    pub lines: Vec<String>,
}

impl ProdFile {
    pub fn text(&self) -> String {
        self.lines.join("\n")
    }

    /// 有效行数（剔除空行）——用来给单文件体量下限做探针。
    pub fn nonempty_lines(&self) -> usize {
        self.lines.iter().filter(|l| !l.trim().is_empty()).count()
    }
}

/// 扫描器自身的文件**永远**不进扫描面：它必然含有"被禁形态"的示例串与判据字面量，
/// 让每把锁再去豁免一次就是六份清单等着漂移。
const SCANNER_SELF: &str = "src/common/prod_scan.rs";

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        // 目录不存在 = 采集面塌了，绝不能静默返回空集（那正是"恒绿"的来源）
        panic!(
            "prod_scan: 目录不可读（采集面缺失，不是\"没有违规\"）: {}",
            dir.display()
        );
    };
    for e in entries.flatten() {
        let p = e.path();
        if p.is_dir() {
            if p.file_name().is_some_and(|n| n == "target") {
                continue;
            }
            walk(&p, out);
        } else if p.extension().is_some_and(|x| x == "rs") {
            out.push(p);
        }
    }
}

/// 递归收集一个目录下的 `.rs`（跳过 `target`）；目录不可读即 panic。
pub fn walk_rs(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    walk(dir, &mut out);
    out.sort();
    out
}

/// 一个目录下的 `.rs` **相对路径**清单（供"只需要文件名、内容按需再读"的锁使用）。
///
/// 与 [`prod_files`] 同一套遍历与自豁免规则：两把锁如果一份用 `prod_files`、一份用自己
/// 写的遍历，目录改名时就会一个红一个绿。
pub fn rel_paths(dir_rel: &str) -> Vec<String> {
    let root = repo_root();
    let dir = root.join(dir_rel);
    let found = walk_rs(&dir);
    assert!(
        !found.is_empty(),
        "prod_scan: 目录 {dir_rel}（{}）下没读到 .rs ⇒ 采集面定位失效（不是通过）",
        dir.display()
    );
    found
        .iter()
        .filter_map(|p| {
            p.strip_prefix(&root)
                .ok()
                .map(|r| r.to_string_lossy().replace('\\', "/"))
        })
        .filter(|rel| rel != SCANNER_SELF)
        .collect()
}

/// 把源码文本按 [`Scan`] 口径归一成行集（纯函数，便于控制组直接喂合成源码）。
pub fn normalize(text: &str, cfg: &Scan<'_>) -> Vec<String> {
    let body = if cfg.strip_test_code {
        match text.find("#[cfg(test)]") {
            Some(idx) => &text[..idx],
            None => text,
        }
    } else {
        text
    };
    match cfg.comments {
        Comments::Blank => body
            .lines()
            .map(|l| {
                if l.trim_start().starts_with("//") {
                    String::new()
                } else {
                    l.to_string()
                }
            })
            .collect(),
        Comments::Drop => body
            .lines()
            .filter(|l| !is_line_comment(l))
            .map(str::to_string)
            .collect(),
        Comments::DropBlocks => body
            .lines()
            .filter(|l| {
                let t = l.trim_start();
                !(t.starts_with("//") || t.starts_with("/*") || t.starts_with('*'))
            })
            .map(str::to_string)
            .collect(),
    }
}

fn is_line_comment(l: &str) -> bool {
    l.trim_start().starts_with("//")
}

/// 按口径采集 [`Scan::roots`] 下的文件（路径排序后返回，保证多轮结果可比）。
///
/// 每个根都必须至少产出一个 `.rs`：根路径写错（目录改名/挪位）时采集面静默变空，
/// 判据循环空转、测试全绿——这是本文件存在的首要理由，所以这里直接 panic 而不是返回空集。
pub fn prod_files(cfg: &Scan<'_>) -> Vec<ProdFile> {
    let root = repo_root();
    let mut paths = Vec::new();
    for r in cfg.roots {
        let dir = root.join(r);
        let found = walk_rs(&dir);
        assert!(
            !found.is_empty(),
            "prod_scan: 根 {r}（{}）下没读到 .rs ⇒ 采集面定位失效，本锁即将空转（不是通过）",
            dir.display()
        );
        paths.extend(found);
    }
    paths.sort();
    paths.dedup();

    let mut out = Vec::new();
    for p in paths {
        let rel = p
            .strip_prefix(&root)
            .unwrap_or(p.as_path())
            .to_string_lossy()
            .replace('\\', "/");
        if rel == SCANNER_SELF || cfg.exclude.contains(&rel.as_str()) {
            continue;
        }
        if !cfg.include_integration_tests && rel.starts_with("src/integration_tests/") {
            continue;
        }
        let text = std::fs::read_to_string(&p)
            .unwrap_or_else(|e| panic!("prod_scan: 读取 {rel} 失败: {e}"));
        let lines = normalize(&text, cfg);
        out.push(ProdFile { rel, lines });
    }
    out
}

/// 读取**单个**文件并按口径归一（登记表按文件名逐条对账的锁用它；文件缺失即响亮失败）。
pub fn prod_file(rel: &str, cfg: &Scan<'_>) -> ProdFile {
    let path = repo_root().join(rel);
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("prod_scan: 登记表指向的文件必须存在: {rel}（{e}）"));
    ProdFile {
        rel: rel.to_string(),
        lines: normalize(&text, cfg),
    }
}

/// 体量下限探针：**每个**使用本扫描器的锁都必须先过它。
///
/// 判据循环跑在空集合上是绿的，而"绿"在这里没有任何含义——所以这里把"扫到了多少文件、
/// 多少行"变成硬前置。`min_files`/`min_lines` 由调用方按该扫描面的**实测**值给出，
/// 取一个远低于现状的地板（现状腰斩即说明采集面腐化，而不是"违规消失了"）。
pub fn require_volume(files: &[ProdFile], min_files: usize, min_lines: usize, what: &str) {
    let lines: usize = files.iter().map(|f| f.nonempty_lines()).sum();
    assert!(
        files.len() >= min_files,
        "{what}: 采集面只剩 {} 个文件（地板 {min_files}）——这通常意味着目录/路径改名让扫描器扫不到东西，\
         属于\"锁静默失效\"而不是\"违规归零\"",
        files.len()
    );
    assert!(
        lines >= min_lines,
        "{what}: 采集面只剩 {lines} 行有效码（地板 {min_lines}），同上——不得当作\"通过\""
    );
}

/// 控制组：合成源码必须能被下游判据抓到，同时注释里的模式串不得被当成代码。
///
/// 抽成公开函数是因为六把锁都需要同一个证明；各自再写一遍就又回到六个版本的扫描器了。
#[cfg(test)]
mod selftests {
    use super::*;

    #[test]
    fn blank_comments_keep_line_numbers() {
        let src = "fn a() {\n    // let bad = (page_num - 1) * page_size;\n    let b = 1;\n}\n";
        let cfg = Scan {
            strip_test_code: false,
            comments: Comments::Blank,
            ..Default::default()
        };
        let lines = normalize(src, &cfg);
        assert_eq!(lines.len(), 4, "置空不删行，行号必须与真实文件对齐");
        assert_eq!(lines[1], "", "注释行必须被清空");
        assert_eq!(lines[2], "    let b = 1;");
        // 对照：Drop 口径确实会错位（保留它是因为有判据只关心内容序列）
        let drop = Scan {
            comments: Comments::Drop,
            ..cfg
        };
        assert_eq!(normalize(src, &drop).len(), 3);
    }

    #[test]
    fn cfg_test_cut_excludes_test_code() {
        let src = "fn prod() { bad_thing(); }\n#[cfg(test)]\nmod tests {\n    fn t() { bad_thing(); }\n}\n";
        let cut = normalize(src, &Scan::default());
        assert!(
            !cut.join("\n").contains("mod tests"),
            "默认口径必须截断测试码"
        );
        assert!(cut.join("\n").contains("prod()"));
        let full = normalize(
            src,
            &Scan {
                strip_test_code: false,
                ..Default::default()
            },
        );
        assert!(
            full.join("\n").contains("mod tests"),
            "死码抑制在测试里同样是掩盖——不截断时必须看得见测试码"
        );
    }

    #[test]
    fn scanner_collects_a_real_volume_and_excludes_itself() {
        let files = prod_files(&Scan::default());
        // 本 crate 的 src 至少上百个 .rs；地板取现状的零头，腰斩即红
        require_volume(&files, 80, 20_000, "prod_scan 自检");
        assert!(
            !files.iter().any(|f| f.rel == SCANNER_SELF),
            "扫描器自身必须被排除（自家模式串不是违规）"
        );
        assert!(
            !files
                .iter()
                .any(|f| f.rel.starts_with("src/integration_tests/")),
            "默认不含集成测试目录"
        );
        let with_it = prod_files(&Scan {
            include_integration_tests: true,
            ..Default::default()
        });
        assert!(
            with_it
                .iter()
                .any(|f| f.rel.starts_with("src/integration_tests/")),
            "开关必须真的生效（否则两向皆可通过）"
        );
        assert!(with_it.len() > files.len());
    }

    #[test]
    fn exclude_list_is_honored() {
        let files = prod_files(&Scan {
            exclude: &["src/common/page.rs"],
            ..Default::default()
        });
        assert!(
            !files.iter().any(|f| f.rel == "src/common/page.rs"),
            "调用方豁免清单必须真的生效"
        );
    }

    #[test]
    fn an_empty_root_fails_loudly_and_block_comments_are_stripped() {
        // 根路径写错 ⇒ 必须 panic，而不是"扫到 0 个文件然后全绿"
        let cfg = Scan {
            roots: &["src/definitely_not_a_real_dir_b75"],
            ..Default::default()
        };
        assert!(
            std::panic::catch_unwind(move || prod_files(&cfg)).is_err(),
            "空采集面必须响亮失败——返回空集会让所有下游锁变成恒绿"
        );

        // DropBlocks：块注释与其续行都要剔掉（时间口径锁的形态）
        let src = "// line\n/* block\n * cont\nlet a = 1;\n";
        let got = normalize(
            src,
            &Scan {
                strip_test_code: false,
                comments: Comments::DropBlocks,
                ..Default::default()
            },
        );
        assert_eq!(
            got,
            vec!["let a = 1;".to_string()],
            "DropBlocks 必须同时剔掉 //、/* 与块注释续行 * "
        );
        // 控制组：Blank 口径下行数不变（行号保真是另一把锁的前提）
        let kept = normalize(
            src,
            &Scan {
                strip_test_code: false,
                ..Default::default()
            },
        );
        assert_eq!(kept.len(), 4);
    }

    #[test]
    fn volume_probe_catches_a_collapsed_scan_surface() {
        // 探针自身也要能失败：给一份小集合，地板抬高必须红
        let files = vec![ProdFile {
            rel: "src/x.rs".into(),
            lines: vec!["fn a() {}".into()],
        }];
        assert!(
            std::panic::catch_unwind(|| require_volume(&files, 5, 100, "控制组")).is_err(),
            "地板判据必须能失败，否则它只是个装饰"
        );
        require_volume(&files, 1, 1, "控制组正例");
    }
}
