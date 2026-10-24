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
        cut_at_test_attr(text)
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

/// 找**代码里**的 `#[cfg(test)]` 并在此截断；注释行里的同名文字不是截断点。
///
/// 原来这里是一句 `text.find("#[cfg(test)]")`——在**整份原文**上找第一个字面量，
/// 于是一行模块文档 `//! …本文件 \`#[cfg(test)]\` 用例…` 就把整份生产代码从扫描器视野里删掉了。
/// b82 实测代价：`src/common/outbound_client.rs` 的 `build_with` 两处构造点变成 0 处，
/// 两把出站指标锁报的是"登记表条目已腐化"（指向完全错误的方向），
/// 而全仓 11 个文件在注释里写着这个字面量——`src/common/mod.rs` 的第 25 行注释
/// 让**每一把**用默认口径的锁只看得到它的 24 行，且历来如此、无人报错。
/// 这正是本文件自己立项的理由（第 13 行那张表："同一形态在两把锁里一边可见一边不可见"）。
fn cut_at_test_attr(text: &str) -> &str {
    let mut offset = 0usize;
    // `split_inclusive` 保留分隔符 ⇒ 偏移量逐字节精确（CRLF 也不会让截点漂移一行里的一个字节）
    for line in text.split_inclusive('\n') {
        let bare = line.trim_end_matches(['\n', '\r']);
        let t = bare.trim_start();
        let in_comment = t.starts_with("//") || t.starts_with("/*") || t.starts_with('*');
        if !in_comment && let Some(off) = bare.find("#[cfg(test)]") {
            return &text[..offset + off];
        }
        offset += line.len();
    }
    text
}

/// 由**声明侧**派生"整个文件只在测试构建里编译"的模块相对路径集合（`/` 分隔）。
///
/// 立案（b89 项 5）：`src/common/mod.rs` 写着 `#[cfg(test)] pub mod fuzz_invariants;`、
/// `src/repository/mod.rs` 写着 `#[cfg(test)] pub mod test_support;`——这两个文件**自身没有**
/// `#[cfg(test)]` 刀口，于是默认口径把整份**测试码**当成生产码视图。今天的后果是"误红方向"
/// （有人在测试里写 `unwrap()` 会被判成"生产代码禁止 unwrap"，把人支使去改一处本来合法的断言，
/// 前言 ⑨ 那一族），而判据一旦扩词汇表（本批加了 `unreachable!` 归因锁），这一面就会
/// 把测试断言当成生产缺陷点名。
///
/// 排除只认两种形状，且方向取"宁可多算生产码"：属性行**逐字符**等于 `#[cfg(test)]`，
/// 且下一个非空非注释行是 `(pub )? mod NAME;`。`#[cfg(all(test, feature = "x"))]`、
/// `#[cfg(not(test))]` 与**无属性**的 `mod NAME;` 一律不排除（b84 在产物新鲜度闸上是同一条纪律）。
/// 声明为 `#[cfg(test)]` 的模块在生产二进制里**结构上不存在**（不存在 ⇒ 编译不过），
/// 所以这一侧的排除没有"把真生产文件静默剔出采集面"这条路。
pub fn test_only_module_files(roots: &[&str]) -> std::collections::HashSet<String> {
    let root = repo_root();
    test_only_module_files_under(&root, roots)
}

/// 上面那层的实现（把 crate 根提成参数，合成夹具才能用临时树证明"三种形状各自排除/不排除"，
/// 而不是只在真实树上取一次数）。
fn test_only_module_files_under(root: &Path, roots: &[&str]) -> std::collections::HashSet<String> {
    let mut out = std::collections::HashSet::new();
    for r in roots {
        for p in walk_rs(&root.join(r)) {
            let fname = p.file_name().and_then(|n| n.to_str()).unwrap_or_default();
            // 只有这三种文件承载 `mod` 声明
            if fname != "mod.rs" && fname != "lib.rs" && fname != "main.rs" {
                continue;
            }
            let Ok(text) = std::fs::read_to_string(&p) else {
                continue; // 声明侧读不到 ⇒ 不排除（保守方向），由调用方的体量下限负责响亮失败
            };
            let dir = p.parent().unwrap_or(root);
            let mut pending = false;
            for line in text.split('\n') {
                let t = line.trim();
                if t == "#[cfg(test)]" {
                    pending = true;
                    continue;
                }
                if t.is_empty() || t.starts_with("//") {
                    continue;
                }
                let decl = t
                    .strip_prefix("pub mod ")
                    .or_else(|| t.strip_prefix("mod "))
                    .and_then(|rest| rest.strip_suffix(';'))
                    .map(|m| m.trim());
                if pending {
                    if let Some(name) = decl.filter(|m| !m.is_empty()) {
                        for cand in [format!("{name}.rs"), format!("{name}/mod.rs")] {
                            let full = dir.join(&cand);
                            if full.is_file()
                                && let Ok(rel) = full.strip_prefix(root)
                            {
                                out.insert(rel.to_string_lossy().replace('\\', "/"));
                            }
                        }
                    }
                    pending = false;
                }
            }
        }
    }
    out
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

    // 只在"只看生产码"的口径下剔除测试专用模块（`strip_test_code = false` 时必须看得见它们）
    let test_only = if cfg.strip_test_code {
        test_only_module_files(cfg.roots)
    } else {
        std::collections::HashSet::new()
    };

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
        if test_only.contains(&rel) {
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

    /// 注释里出现 `#[cfg(test)]` **不得**成为截断点（b82 实测缺陷，两侧都要钉）：
    /// 早截 ⇒ 生产码从扫描器视野消失，锁报"登记表条目已腐化"把人往错方向支使；
    /// 完全不截 ⇒ 测试码混进生产视图，死码抑制冒充合规。
    #[test]
    fn comment_mentioning_cfg_test_is_not_the_cut_point() {
        let src = "//! 说明：`#[cfg(test)]` 用例住在本文件。\nfn prod() { build_client(); }\n#[cfg(test)]\nmod tests {\n    fn t() { build_client(); }\n}\n";
        let view = normalize(src, &Scan::default()).join("\n");
        assert!(
            view.contains("fn prod()"),
            "模块文档里写了那个字面量就把整份生产码丢掉 ⇒ 采集面静默归零（本用例即回归锁）"
        );
        assert!(
            !view.contains("mod tests"),
            "真正的属性仍必须截断——修注释不能把刀钝掉"
        );
        // 对照：块注释与 `*` 续行同样不是截断点
        let block = "/* 见 #[cfg(test)] */\nfn prod2() {}\n#[cfg(test)]\nmod t2 {}\n";
        let v2 = normalize(block, &Scan::default()).join("\n");
        assert!(v2.contains("fn prod2()"), "块注释里的字面量也不许当刀");
        assert!(!v2.contains("mod t2"));
    }

    /// CRLF 行的字节偏移必须逐字节精确：早一个字节会咬掉属性名，晚一个字节会把 `\n` 混进生产视图。
    #[test]
    fn cut_offsets_are_byte_exact_under_crlf() {
        let src = "fn a() {}\r\n#[cfg(test)]\r\nmod t {}\r\n";
        let body = cut_at_test_attr(src);
        assert_eq!(body, "fn a() {}\r\n", "截点必须正好落在属性之前");
        assert!(
            normalize(src, &Scan::default())
                .join("\n")
                .contains("fn a() {}"),
            "生产函数必须在视图里"
        );
    }

    /// 真实文件侧的对账：b82 那次事故的红字面就是这两处构造点从实测里消失了。
    /// 这里钉的是"锁的输入没坏"，与锁自己的判据（`outbound_metrics_guard`）分属两层。
    #[test]
    fn real_files_keep_their_production_body() {
        let oc = prod_file(
            "src/common/outbound_client.rs",
            &Scan {
                comments: Comments::Drop,
                ..Default::default()
            },
        );
        let view = oc.lines.join("\n");
        assert!(
            view.contains("pub fn build_with("),
            "outbound_client.rs 的模块文档（第 29 行）里写着 `#[cfg(test)]`——它一度让 \
             `build_with` 从生产视图里整体消失"
        );
        let sites = oc
            .lines
            .iter()
            .filter(|l| l.contains("Client::builder("))
            .count();
        assert_eq!(
            sites, 2,
            "主路径 + 回退路径两处构造点必须都数得到（登记表按重数对账，少一处就是一条假腐化）"
        );
    }

    /// **把既有限制钉成断言**：刀口取"第一个真属性"，所以文件里靠后出现的 `#[cfg(test)]`
    /// 之后的生产声明一并看不见。`src/common/mod.rs` 实测：第 26 行是 `pub(crate) mod prod_scan`，
    /// 其后的 `pub mod redact/response/…/webhook` 等声明不在生产视图内。
    /// 这条不是"证明它是对的"，而是"改它必须显式改这里"——把截断换成括号配对删块会同时改变
    /// 十余把锁的输入，属另立批次的影响面，不能顺手动（见台账 b82 §15 N-23）。
    #[test]
    fn first_attribute_wins_limitation_is_pinned() {
        let md = prod_file("src/common/mod.rs", &Scan::default());
        let view = md.lines.join("\n");
        assert!(
            view.contains("pub mod outbound_client;"),
            "刀口之前的声明必须看得见"
        );
        assert!(
            !view.contains("pub mod webhook;"),
            "刀口之后的声明当前不可见——这是既有限制；若本断言转红，说明有人把截断改成了\
             删块，此时必须同步复核所有用默认口径的锁并更新台账 N-23"
        );
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

    /// b89 项 5：测试专用模块不得进生产码视图，但**开关关掉时必须看得见**
    /// （单向门=假绿方向：一旦"排除"写成无条件，`strip_test_code = false` 的那几把锁
    /// 也会跟着少掉两个文件而无人报错）。
    #[test]
    fn test_only_modules_leave_the_production_view_but_stay_visible() {
        let set = test_only_module_files(&["src"]);
        for rel in [
            "src/common/fuzz_invariants.rs",
            "src/repository/test_support.rs",
        ] {
            assert!(
                set.contains(rel),
                "{rel} 由 `#[cfg(test)] mod` 声明 ⇒ 必须被判成测试专用模块（真实树上两处声明本轮实测）"
            );
        }
        // 对照组：无属性的 `pub mod` 必须**不**在集合里（按名字排除就是 b84 立过的那条捷径）
        for rel in ["src/common/webhook.rs", "src/repository/base.rs"] {
            assert!(
                !set.contains(rel),
                "{rel} 是无属性声明的生产模块，不得被排除：{set:?}"
            );
        }
        let prod_view = prod_files(&Scan::default());
        for f in &prod_view {
            assert!(
                !set.contains(f.rel.as_str()),
                "生产码视图里出现了测试专用模块 {}",
                f.rel
            );
        }
        let full_view = prod_files(&Scan {
            strip_test_code: false,
            ..Default::default()
        });
        assert!(
            full_view
                .iter()
                .any(|f| f.rel == "src/common/fuzz_invariants.rs"),
            "`strip_test_code = false` 必须仍能看见测试专用模块（{} 个文件里没有它 ⇒ 单向门）",
            full_view.len()
        );
    }

    /// 派生的**形状**判据必须可证伪：三种写法各自该排除/不该排除，用临时树跑。
    /// 只在真实树上取一次数等于"本轮恰好没有该排除的模块"也算通过（前言 ⑥）。
    #[test]
    fn test_only_derivation_is_falsifiable_on_shapes() {
        let root = std::env::temp_dir().join(format!(
            "stepby_prod_scan_derive_{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        let src = root.join("src");
        std::fs::create_dir_all(&src).expect("临时树建不出来就无法证明派生在形状上工作");
        let write = |name: &str, text: &str| {
            std::fs::write(src.join(name), text).expect("临时夹具写入失败");
        };
        write("gated.rs", "fn a() {}\n");
        write("allattr.rs", "fn a() {}\n");
        write("nottest.rs", "fn a() {}\n");
        write("bare.rs", "fn a() {}\n");
        write(
            "mod.rs",
            "#[cfg(test)]\npub mod gated;\n\
             #[cfg(all(test, feature = \"x\"))]\nmod allattr;\n\
             #[cfg(not(test))]\nmod nottest;\n\
             mod bare;\n",
        );
        let set = test_only_module_files_under(&root, &["src"]);
        let _ = std::fs::remove_dir_all(&root);
        assert!(
            set.contains("src/gated.rs"),
            "逐字符等于 `#[cfg(test)]` 的声明必须排除其模块：{set:?}"
        );
        for rel in ["src/allattr.rs", "src/nottest.rs", "src/bare.rs"] {
            assert!(
                !set.contains(rel),
                "{rel} 的声明形状不构成'只在测试里编译'，不得排除（宁可多算生产码）：{set:?}"
            );
        }
    }
}
