//! i18n key 存在性防回归测试（L-3 收尾）
//!
//! 背景：`tr!("error.msg.xxx")` 走 rust-i18n（`lib.rs` 以 `i18n!("locales", fallback = "zh-CN")`
//! 加载）。**key 缺失不会产生编译错误**——运行时查不到就直接把 key 字符串本身当文案返回
//! （2026-10-03 实锤：`sys_msg_service` 全模块 `error.msg.*` 共 14 个 key 在 en-US.yml 完整、
//! 在 zh-CN.yml 整域缺失，中文请求全部显示 "error.msg.mail_disabled" 这类裸 key）。
//!
//! 防回归手段：扫描全部源码提取 `tr!("...")` 使用的 key 字面量，断言每个 key 在
//! locales/zh-CN.yml 与 locales/en-US.yml **双双存在**。
//!
//! 实现说明：
//! - 不做行为判定（`t!(key) != key`）：`fallback = "zh-CN"` 会让"en 缺失但 zh 有"漏报；
//!   故直接解析 YAML 源文件按 key path 判存在。
//! - YAML 解析为**专用简易版**：locales 文件只使用"嵌套 mapping + 标量"结构，
//!   按缩进栈建 key path 即可；不引入 serde_yaml 依赖（零新依赖、纯 std + regex）。

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

/// 递归收集 dir 下所有 .rs 文件路径。
fn collect_rs_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return,
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_rs_files(&path, out);
        } else if path.extension().and_then(|e| e.to_str()) == Some("rs") {
            out.push(path);
        }
    }
}

/// 从全部源码中提取 `tr!("key")` 使用的 key 字面量。
///
/// 覆盖三种调用形态：单行 `tr!("a.b")`、换行参数 `tr!(\n        "a.b",`、
/// 带插值 `tr!("a.b", name = x)`；`crate::tr!` 亦被 `tr!\(` 子串覆盖。
fn extract_tr_keys(crate_root: &Path) -> BTreeSet<String> {
    let mut files = Vec::new();
    collect_rs_files(&crate_root.join("src"), &mut files);
    let re = regex::Regex::new(r#"tr!\s*\(\s*"([a-z0-9_.]+)""#).expect("正则编译失败");
    let mut keys = BTreeSet::new();
    for f in &files {
        let Ok(content) = std::fs::read_to_string(f) else {
            continue;
        };
        // 跳过注释行：doc/行注释中的 tr!("...") 是用法示例（如 i18n.rs 宏文档），
        // 不是真实调用；仅扫描代码行避免误报示例 key
        let code_lines = content.lines().filter(|l| {
            let t = l.trim_start();
            !(t.starts_with("//"))
        });
        let code = code_lines.collect::<Vec<_>>().join("\n");
        for cap in re.captures_iter(&code) {
            keys.insert(cap[1].to_string());
        }
    }
    keys
}

/// 解析 locales/*.yml，返回全部 key path 集合（如 "error.msg.channel_not_found"）。
///
/// 专用简易解析：仅匹配 `缩进 key:` 行构建嵌套 path（locales 文件不含列表/锚点等复杂语法）；
/// 注释行、纯值行、空行均跳过。
fn parse_locale_key_paths(path: &Path) -> BTreeSet<String> {
    let content =
        std::fs::read_to_string(path).unwrap_or_else(|e| panic!("读取 {} 失败: {e}", path.display()));
    // (indent, key) 栈：栈顶为最近一层 mapping 的当前节点
    let mut stack: Vec<(usize, String)> = Vec::new();
    let mut keys = BTreeSet::new();
    for line in content.lines() {
        let trimmed = line.trim_start();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        // 仅取 "key:" 或 "key: value" 形式；列表项 "- x" 与续行不是 mapping 键
        let indent = line.len() - line.trim_start().len();
        let body = trimmed;
        let Some(colon) = body.find(':') else {
            continue;
        };
        let name = body[..colon].trim();
        // 值首字符若为引号/百分号等说明冒号在引号字符串内（如 `key: "a: %{v}"`），
        // 但此处 name 取冒号前的裸键，仅需过滤掉 name 含非法字符的行（防御性）
        if name.is_empty() || !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
            continue;
        }
        // 弹出所有缩进 >= 当前的层（同级或子级结束）
        while stack.last().map(|(i, _)| *i >= indent).unwrap_or(false) {
            stack.pop();
        }
        let path = {
            let mut p = stack.iter().map(|(_, k)| k.as_str()).collect::<Vec<_>>();
            p.push(name);
            p.join(".")
        };
        keys.insert(path);
        stack.push((indent, name.to_string()));
    }
    keys
}

fn crate_root() -> PathBuf {
    PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap_or_else(|_| ".".to_string()))
}

/// 核心断言：tr! 使用的每个 key 在 zh-CN.yml 与 en-US.yml 双双存在。
///
/// 失败信息直接列出缺失 key 与补齐指引，防止再出现"整域缺失"的静默回归。
#[test]
fn all_tr_keys_exist_in_both_locale_files() {
    let root = crate_root();
    let used = extract_tr_keys(&root);
    assert!(
        !used.is_empty(),
        "未扫描到任何 tr! key——扫描逻辑或源码目录失效，请检查"
    );
    let zh = parse_locale_key_paths(&root.join("locales/zh-CN.yml"));
    let en = parse_locale_key_paths(&root.join("locales/en-US.yml"));
    assert!(
        zh.contains("error.common.not_found") || zh.contains("error.msg.mail_disabled"),
        "zh-CN.yml key path 解析异常（未找到已知存在的基准 key），解析器需检查"
    );

    let mut missing_zh: Vec<&String> = used.iter().filter(|k| !zh.contains(*k)).collect();
    let mut missing_en: Vec<&String> = used.iter().filter(|k| !en.contains(*k)).collect();
    missing_zh.sort();
    missing_en.sort();

    assert!(
        missing_zh.is_empty(),
        "以下 tr! key 在 locales/zh-CN.yml 缺失（中文请求将显示裸 key），请补齐：\n{}",
        missing_zh.iter().map(|s| s.as_str()).collect::<Vec<_>>().join("\n")
    );
    assert!(
        missing_en.is_empty(),
        "以下 tr! key 在 locales/en-US.yml 缺失（英文请求将回退 zh-CN 或显示裸 key），请补齐：\n{}",
        missing_en.iter().map(|s| s.as_str()).collect::<Vec<_>>().join("\n")
    );
}
