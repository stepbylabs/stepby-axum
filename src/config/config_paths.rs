// stepby-axum/src/config/config_paths.rs
//! 配置文件里的**未知路径**识别（批八十五 项 B）。
//!
//! 立案（台账 N-40）：b84 只把**顶层**条目接进了启动 WARN（`Settings::unknown_keys`
//! 由 `#[serde(flatten)]` 收集）。但 serde 对**已知段里拼错的子键**是静默忽略的——
//! `[sso] introsction_enabled = true` 不报错、不生效、不留痕，而它和"整段拼错"是同一类
//! 故障（"以为配了其实没配"），运维排查成本完全一样。补 flatten 兜底要动 30 个结构体，
//! 且每加一个字段都得同步 ⇒ 改成"配置文档 ⊖ 已知路径表"这一条单点判据。
//!
//! 已知路径表 `config_schema::KNOWN_CONFIG_PATHS` 由根仓
//! `scripts/config_parity_scan.py --emit-schema` 从**同一套结构体解析器**生成
//! （不是手写清单，也不会是第二事实源——陈旧性由 `--check-schema` 与本模块的
//! 真实模板正控双向钉住）。
//!
//! 三条设计约束：
//! 1. **只 WARN、不拒绝、不回落**：未知条目一律按忽略处理，与改造前逐字节等价。
//!    `deny_unknown_fields` 会让存量部署因历史遗留键直接起不来，方向错。
//! 2. **只碰键名、不碰值**（AGENTS C.9）：未知条目本身可能就是误写进配置的凭据，
//!    所以本模块的输出物是 `Vec<String>` 路径，`toml::Value` 不出函数。
//! 3. **开放前缀整支跳过**：`[features]` 的键集由能力位注册表管（那是另一把锁），
//!    在这里逐个报成"拼错的键"会把真信号淹成噪声。
//! 4. **解析失败返回空集**（fail-safe）：本判据不得让应用起不来；能走到这里说明
//!    `toml::from_str::<Settings>` 已成功，理论上不会失败，但判据坏了不是故障现场。

use crate::config::config_schema::{KNOWN_CONFIG_PATHS, OPEN_CONFIG_PREFIXES};
use toml::Value;

/// 该路径是否落在"键集开放"的前缀内（自身开放，或开放前缀的任意后代）。
fn is_open(path: &str) -> bool {
    OPEN_CONFIG_PREFIXES
        .iter()
        .any(|o| *o == path || path.starts_with(&format!("{o}.")))
}

fn is_known(path: &str) -> bool {
    KNOWN_CONFIG_PATHS.contains(&path)
}

/// 拼接点分路径（根段的键名就是路径本身）。
fn join(prefix: &str, key: &str) -> String {
    if prefix.is_empty() {
        key.to_string()
    } else {
        format!("{prefix}.{key}")
    }
}

/// 遍历一个节点：表 ⇒ 继续下钻（结构体是段，段里的段还是段），其余 ⇒ 当作叶子判已知性。
fn walk(node: &Value, prefix: &str, out: &mut Vec<String>) {
    match node {
        Value::Table(tbl) => {
            // 非根的表本身不是叶子：它是某个结构体字段（或子段），只判它的子键。
            // 但如果这个表**不在**已知表里（整段拼错，如 `[oidc]`），子键逐个报会淹掉
            // 真正的结论（"这一段不认识"），所以先判该表是否有任何已知后代：
            // 一个后代都没有 ⇒ 只报段本身。
            if !prefix.is_empty() && !has_known_descendant(prefix, node) {
                out.push(prefix.to_string());
                return;
            }
            for (k, v) in tbl {
                let path = join(prefix, k);
                match v {
                    Value::Table(_) => walk(v, &path, out),
                    _ => {
                        if !is_open(&path) && !is_known(&path) {
                            out.push(path);
                        }
                    }
                }
            }
        }
        _ => {
            if !is_open(prefix) && !is_known(prefix) {
                out.push(prefix.to_string());
            }
        }
    }
}

/// `prefix` 这一段里是否至少有一个"看起来属于已知配置"的键（按首段前缀比对，
/// 因此对 `[oidc] enabled = true` 这种整段拼错能给出**一条**结论而不是 N 条）。
fn has_known_descendant(prefix: &str, node: &Value) -> bool {
    let head = format!("{prefix}.");
    if KNOWN_CONFIG_PATHS.iter().any(|p| p.starts_with(&head)) {
        return true;
    }
    // 表里可能还嵌着子表（`[a.b]` 形态）：子表名本身是已知路径的下一段 ⇒ 也算有后代。
    if let Value::Table(tbl) = node {
        return tbl.keys().any(|k| {
            let sub = join(prefix, k);
            is_open(&sub)
                || KNOWN_CONFIG_PATHS
                    .iter()
                    .any(|p| p.starts_with(&format!("{sub}.")))
        });
    }
    false
}

/// 配置文件原文 → **未被任何已知字段消费**的点分路径（只含键名，升序去重）。
///
/// 入参是 `Settings::from_file` 已经读过的那份文本；解析失败返回空集（见模块头第 4 条）。
///
/// 这里刻意解析成 `toml::Table` 而不是 `raw.parse::<toml::Value>()`：后者的 `FromStr`
/// 解析的是**单个值**（`"abc"` / `1` / `[1,2]`），整份 TOML 文档在它那里一律 Err ⇒
/// 本函数恒返回空集。那种实现能同时通过所有"不得报"用例而只在"必须报"用例上红
/// （AGENTS 门禁全景 ⑥"自检只期望抛错等于没测"的镜像形态：自检只期望空集也一样）。
pub(crate) fn unknown_config_paths(raw: &str) -> Vec<String> {
    let root = match toml::from_str::<toml::Table>(raw) {
        Ok(t) => t,
        Err(_) => return Vec::new(),
    };
    let mut out = Vec::new();
    walk(&Value::Table(root), "", &mut out);
    out.sort();
    out.dedup();
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// ① 本批评案的形状：**已知段里**拼错的子键必须报（b84 通道看不见这一类）。
    #[test]
    fn typo_subkey_inside_known_section_is_reported() {
        let raw = "[sso]\nenabled = true\nintrosction_enabled = true\n";
        let got = unknown_config_paths(raw);
        assert_eq!(
            got,
            vec!["sso.introsction_enabled".to_string()],
            "已知段里拼错的子键必须点名（实际只有顶层条目被收集是 b84 的已知边界）"
        );
    }

    /// ② 对照组真受约束：同一位置**拼对**的子键必须一条不报。
    ///    （摘掉 `is_known` 这一支，① 与 ② 会同时红——但摘掉 `is_open` 只有 ④ 红）
    #[test]
    fn correct_subkey_is_not_reported() {
        let raw = "[sso]\nenabled = true\nintrospection_enabled = true\n";
        assert_eq!(unknown_config_paths(raw), Vec::<String>::new());
    }

    /// ③ 整段拼错 ⇒ **只报段名一条**，不刷 N 条子键（结论要能一眼指向成因）。
    #[test]
    fn unknown_section_reports_the_section_once_not_every_subkey() {
        let raw = "[oidc]\nenabled = true\ncode_ttl_secs = 60\nissuer = \"https://x\"\n";
        assert_eq!(
            unknown_config_paths(raw),
            vec!["oidc".to_string()],
            "整段不认识时报段名一条即可——报三条会把'段名拼错'这个单一成因淹成噪声"
        );
    }

    /// ④ 开放前缀（`[features]` 能力位）整支跳过：任意键都合法，键集由注册表那把锁管。
    #[test]
    fn open_prefix_accepts_any_subkey() {
        let raw = "[features]\n\"nav.l3\" = \"off\"\nbrand_new_capability_bit = \"full\"\n";
        assert_eq!(unknown_config_paths(raw), Vec::<String>::new());
    }

    /// ⑤ 顶层标量键（`config_version` 这一型）按裸键名判，不得当成"未知段"。
    #[test]
    fn top_level_scalar_keys_are_known() {
        assert_eq!(
            unknown_config_paths("config_version = 3\n"),
            Vec::<String>::new()
        );
        assert_eq!(
            unknown_config_paths("config_versyon = 3\n"),
            vec!["config_versyon".to_string()]
        );
    }

    /// ⑥ 数组叶子只判自身路径（本仓无 `[[table]]` 配置段；有也不得崩）。
    #[test]
    fn array_leaves_are_judged_as_themselves() {
        let raw = "[server]\ncors_origins = [\"https://a\"]\norigins_x = [1, 2]\n";
        assert_eq!(
            unknown_config_paths(raw),
            vec!["server.origins_x".to_string()]
        );
    }

    /// ⑦ 反脆弱（fail-safe）：坏 TOML 必须返回**空集**而不是 panic——本判据不得让应用起不来。
    #[test]
    fn broken_toml_degrades_to_empty_not_panic() {
        assert_eq!(
            unknown_config_paths("[sso\nenabled = "),
            Vec::<String>::new()
        );
        assert_eq!(unknown_config_paths(""), Vec::<String>::new());
    }

    /// ⑧ 真实文件正控：**本仓模板的每个生效键都必须被 schema 接住**。
    ///    这是 Rust 侧的独立载体——`--check-schema` 挂了、或生成物被手工改坏，这里就红。
    #[test]
    fn shipped_template_contains_no_unknown_paths() {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/config/config.toml.example");
        let raw = std::fs::read_to_string(path)
            .unwrap_or_else(|e| panic!("模板读不到（{path}）：{e} —— 判据源缺失不得当作通过"));
        let got = unknown_config_paths(&raw);
        assert!(
            got.is_empty(),
            "config.toml.example 里有 {} 个键不在生成物 schema 中：{got:?}",
            got.len()
        );
        // 正控的对照：模板里至少得有几百个键，读到一个空集合说明解析没跑起来
        let keys = raw
            .lines()
            .filter(|l| l.contains('=') && !l.trim().starts_with('#'))
            .count();
        assert!(keys > 80, "模板只数到 {keys} 行含 `=`，采集面坏了");
    }

    /// ⑨ 已知限制钉死（改它必先红）：子表**嵌套超过两层**时按最具体路径报，
    ///    而不是报最外层段——即"整段拼错只报一条"仅适用于直接子层全不认识的情形。
    #[test]
    fn deeply_nested_unknown_paths_are_reported_per_leaf() {
        let raw = "[upload.s3.deep]\nk1 = 1\nk2 = 2\n";
        let got = unknown_config_paths(raw);
        assert_eq!(
            got,
            vec!["upload.s3.deep".to_string()],
            "upload 段认识、s3 认识、deep 不认识 ⇒ 报最外层不认识的那一支"
        );
    }

    /// ⑩ 形状锁：开放前缀与已知路径不得有交集（交集意味着同一位置两套口径，
    ///    而 `is_open` 先判 ⇒ 具名键的拼错永远报不出来）。
    #[test]
    fn open_prefixes_and_known_paths_do_not_overlap() {
        for o in OPEN_CONFIG_PREFIXES {
            assert!(
                !KNOWN_CONFIG_PATHS.contains(o),
                "{o} 同时是具名键与开放前缀——生成物或结构体解析自相矛盾"
            );
            for p in KNOWN_CONFIG_PATHS {
                assert!(
                    !p.starts_with(&format!("{o}.")),
                    "{p} 既在已知表里又落在开放前缀 {o} 下——运行时该键的拼错永远报不出来"
                );
            }
        }
        assert!(
            !OPEN_CONFIG_PREFIXES.is_empty(),
            "开放前缀表为空 = 解析器不再认识 map 字段，features 那一型会被逐键误报"
        );
    }

    /// ⑪ 采集面下限：已知路径表不得缩水到无意义（生成物被截断/写坏时先在这里响）。
    #[test]
    fn known_paths_collection_is_healthy() {
        assert!(
            KNOWN_CONFIG_PATHS.len() >= 120,
            "schema 只有 {} 条路径（下限 120）——生成物坏了，不得据此判'没有未知键'",
            KNOWN_CONFIG_PATHS.len()
        );
        assert!(
            KNOWN_CONFIG_PATHS.windows(2).all(|w| w[0] < w[1]),
            "生成物必须严格升序且无重复：否则 --check-schema 的字节比对会被排序抖动欺骗"
        );
    }
}
