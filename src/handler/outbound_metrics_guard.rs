//! 出站组件指标覆盖总锁（批七十四 轮 28，AGENTS 工程硬基线 B.4）。
//!
//! B.4 要求"新增外部依赖组件必须自带 Prometheus 指标"。b72 落了统一口径
//! （`stepby_outbound_requests_total{component,outcome}` + `_duration_seconds{component}`，
//! 多出口函数用 RAII `OutboundGuard`），但**没有任何一把锁能回答"该记的地方都记了吗"**——
//! 与本轮 §一.7 立案时的原话同构："b72 的指标靠人自觉加"。本锁把它变成可判定的形状：
//!
//! 1. 全仓枚举 `reqwest::Client` 的**构造点**（出站能力的物理来源：没有客户端就发不出请求）；
//! 2. 每个构造点必须能在登记表里找到一条**结局**说明，且该说明可机械验证：
//!    - `ThisFn`：出站就发生在这个函数里，函数体必须含 `OutboundGuard::start("…")` 或
//!      `record_outbound("…")`；
//!    - `SameFile`：构造点是工厂/字段初始化（`new()` / `try_new()`），发送路径在同文件别处；
//!    - `Caller`：本文件只是 provider，**由调用方统一计数**（在 provider 里再记一次就是双计）。
//! 3. 登记表与实测集合**双向对账**：新构造点未登记 ⇒ 红；登记了但构造点已消失 ⇒ 也红。
//!
//! 为什么不按"文件"或"函数是否含 guard"简单判：`sys_msg_service` 在调用
//! `sms_provider` / `im_robot_provider` 之后统一 `record_outbound("sms"|"im_robot", …)`，
//! provider 自己的 `new()` 里没有计数——按"构造点函数必须含 guard"会把它误判成缺指标，
//! 于是"修锁"就会变成"再记一次"（**口径失真比缺指标更糟**，B.4 原话）。
//!
//! 自检控制组（同 [`super::api_contract_guard`] / [`super::fail_closed_guard`] 的纪律）：
//! 合成一个"构造了客户端但没有任何计数"的函数，判据必须**转红**；合成"已守卫"必须放行。
//! 少了这一条，本锁可能是"永远返回空"的虚锁。
//!
//! 本文件自身被扫描器排除：控制组里的合成源码含被禁字面量，不排除会自指误报
//! （与 [`super::api_contract_guard`] 对 `common/redact.rs` 的处理同口径）。

#[cfg(test)]
mod outbound_metrics_guard_lock {
    use std::collections::BTreeMap;
    use std::path::{Path, PathBuf};

    /// 扫描器自身（合成源码里含被禁字面量，必须排除）
    const SELF: &str = "src/handler/outbound_metrics_guard.rs";

    /// 一个构造点的结局说明
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum Disposition {
        /// 出站发生在构造点所在函数内，函数体必须出现该 needle
        ThisFn(&'static str),
        /// 构造点是工厂函数，发送路径在同文件别处
        SameFile(&'static str),
        /// 由调用方文件统一计数（needle 为该调用方文件必须出现的子串）
        Caller(&'static str, &'static str),
    }

    /// 登记表：`(相对路径, 所在函数, 结局)`。**同一文件同名函数可重复**（多个 provider 的
    /// `new()`），比对按重数（multiset）进行，因此这里重复登记是有意义的。
    const REGISTRY: &[(&str, &str, Disposition)] = &[
        (
            "src/ai/config_service.rs",
            "test_connectivity",
            Disposition::ThisFn(r#"OutboundGuard::start("ai_config_test")"#),
        ),
        (
            "src/ai/config_service.rs",
            "probe_reachability",
            Disposition::Caller("src/handler/health_probes.rs", r#"record_outbound"#),
        ),
        (
            "src/ai/provider.rs",
            "new",
            Disposition::SameFile(r#"OutboundGuard::start("ai")"#),
        ),
        // 批八十一：出站客户端构造收进 common::outbound_client（系统信任库缺失时回落内嵌
        // 根证书，构造期绝不 panic——v0.3.0 冒烟在 debian:*-slim 上实测照出的启动期 panic）。
        // 原先散在 sms_provider/im_robot_provider/sys_oauth_service 的 6 个构造点因此消失，
        // 结局计数仍留在各自调用方（本锁按"构造点"登记，故这里指向两个真实消费方：
        // 两处 `Client::builder()` = 主路径 + 回退路径，重数必须与实测一致）。
        (
            "src/common/outbound_client.rs",
            "build_with",
            Disposition::Caller(
                "src/service/sys_oauth_service.rs",
                r#"OutboundGuard::start("oauth_token")"#,
            ),
        ),
        (
            "src/common/outbound_client.rs",
            "build_with",
            Disposition::Caller("src/service/sys_msg_service.rs", r#""sms""#),
        ),
        (
            "src/common/upload_scan.rs",
            "scan_bytes",
            Disposition::ThisFn(r#"OutboundGuard::start("upload_scan")"#),
        ),
        (
            "src/handler/sso_handler.rs",
            "client_logo",
            Disposition::ThisFn(r#"OutboundGuard::start("sso_logo")"#),
        ),
        (
            "src/service/acme_service.rs",
            "spawn_emit",
            Disposition::ThisFn(r#"OutboundGuard::start("acme")"#),
        ),
        (
            "src/service/event_outbox_service.rs",
            "spawn_emit",
            Disposition::ThisFn(r#"OutboundGuard::start("outbox")"#),
        ),
        (
            "src/service/ip_location_service.rs",
            "download_from_p3terx",
            Disposition::ThisFn(r#"OutboundGuard::start("ip_geo:p3terx")"#),
        ),
        (
            "src/service/ip_location_service.rs",
            "download_from_maxmind",
            Disposition::ThisFn(r#"OutboundGuard::start("ip_geo:maxmind")"#),
        ),
        (
            "src/storage/s3.rs",
            "try_new",
            Disposition::Caller("src/storage/mod.rs", "storage:"),
        ),
    ];

    fn root() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
    }

    /// 生产码（`#[cfg(test)]` 之前）并剔除 `//` 行——治理点的注释会引用被禁形态作说明
    fn prod_lines(rel: &str) -> Vec<String> {
        crate::common::prod_scan::prod_file(
            rel,
            &crate::common::prod_scan::Scan {
                comments: crate::common::prod_scan::Comments::Drop,
                ..Default::default()
            },
        )
        .lines
    }

    /// 折叠空白，便于跨行匹配 `record_outbound(\n "webhook", …)` 这类多行调用
    fn fold_ws(s: &str) -> String {
        s.split_whitespace().collect::<Vec<_>>().join("")
    }

    fn is_construction(line: &str) -> bool {
        // 覆盖 `reqwest::Client::builder()`、`reqwest::Client::new()`，以及
        // `use reqwest::Client;` 之后的 `Client::builder()` 简写形态
        line.contains("reqwest::Client::builder(")
            || line.contains("reqwest::Client::new(")
            || line.contains("Client::builder(")
            || line.contains("Client::new(")
    }

    /// 一行是否是**函数头**（`fn` 之前只允许可见性与限定词，否则是类型标注之类的 `fn` 出现）
    fn fn_head_of(trimmed: &str) -> Option<String> {
        let idx = trimmed.find("fn ")?;
        let before = trimmed[..idx].trim();
        if !before.is_empty() {
            let only_qualifiers = before.split_whitespace().all(|w| {
                [
                    "pub", "async", "unsafe", "const", "extern", "default", "safe",
                ]
                .contains(&w)
                    || w.starts_with("pub(")
            });
            if !only_qualifiers {
                return None;
            }
        }
        let name: String = trimmed[idx + 3..]
            .chars()
            .take_while(|c| c.is_alphanumeric() || *c == '_')
            .collect();
        if name.is_empty() { None } else { Some(name) }
    }

    /// 由构造点行号回溯所在函数，并截取"函数体窗口"（到下一个同层或更外层的 `fn` 头为止）
    fn enclosing_fn(lines: &[String], idx: usize) -> (String, String) {
        let mut name = String::from("<无所属函数>");
        let mut start = 0usize;
        for j in (0..=idx.min(lines.len().saturating_sub(1))).rev() {
            if let Some(n) = fn_head_of(lines[j].trim_start()) {
                name = n;
                start = j;
                break;
            }
        }
        let base_indent = lines[start].len() - lines[start].trim_start().len();
        // 函数体止于"下一个同缩进（或更浅）的函数头"
        let end = lines
            .iter()
            .enumerate()
            .skip(start + 1)
            .find(|(_, l)| {
                let ind = l.len() - l.trim_start().len();
                ind <= base_indent && fn_head_of(l.trim_start()).is_some()
            })
            .map_or(lines.len(), |(j, _)| j);
        (name, lines[start..end].join("\n"))
    }

    /// 全仓实测构造点集合：`{(文件, 函数): 重数}`
    fn detected_sites() -> BTreeMap<(String, String), usize> {
        let mut out: BTreeMap<(String, String), usize> = BTreeMap::new();
        for rel in crate::common::prod_scan::rel_paths("src") {
            if rel == SELF {
                continue;
            }
            let lines = prod_lines(&rel);
            for (i, l) in lines.iter().enumerate() {
                if is_construction(l) {
                    let (name, _) = enclosing_fn(&lines, i);
                    *out.entry((rel.clone(), name)).or_insert(0) += 1;
                }
            }
        }
        out
    }

    fn registry_multiset() -> BTreeMap<(String, String), usize> {
        let mut out: BTreeMap<(String, String), usize> = BTreeMap::new();
        for (file, f, _) in REGISTRY {
            *out.entry(((*file).to_string(), (*f).to_string()))
                .or_insert(0) += 1;
        }
        out
    }

    /// 判据核心：给定"构造点所在函数体 + 该文件 + 调用方文件"，是否真的记了结局。
    /// 抽成函数是为了能被合成源码喂进控制组。
    fn disposition_satisfied(
        disp: Disposition,
        fn_body: &str,
        file_prod: &str,
        caller_prod: Option<&str>,
    ) -> bool {
        let (needle, haystack) = match disp {
            Disposition::ThisFn(n) => (n, fn_body.to_string()),
            Disposition::SameFile(n) => (n, file_prod.to_string()),
            Disposition::Caller(_, n) => (n, caller_prod.unwrap_or("").to_string()),
        };
        let hay = fold_ws(&haystack);
        // 两条匹配口径：needle 可能是 `OutboundGuard::start("x")`（去空白后可精确匹配），
        // 也可能是多行 `record_outbound(` 里的 `"x",`（折叠后同样连续）
        let hit = hay.contains(&fold_ws(needle));
        // 结局必须真的进过统一出口，否则"匹配到一个字符串常量"不等于记了指标
        let recorded = hay.contains("record_outbound(") || hay.contains("OutboundGuard::start(");
        hit && recorded
    }

    #[test]
    fn client_construction_sites_are_fully_registered() {
        let detected = detected_sites();
        let registered = registry_multiset();
        let mut unregistered: Vec<String> = Vec::new();
        for (k, n) in &detected {
            let r = registered.get(k).copied().unwrap_or(0);
            if r < *n {
                unregistered.push(format!("{}::{}（实测 {n} 处 / 登记 {r} 处）", k.0, k.1));
            }
        }
        let mut stale: Vec<String> = Vec::new();
        for (k, n) in &registered {
            let d = detected.get(k).copied().unwrap_or(0);
            if d < *n {
                stale.push(format!("{}::{}（登记 {n} 处 / 实测 {d} 处）", k.0, k.1));
            }
        }
        assert!(
            unregistered.is_empty() && stale.is_empty(),
            "reqwest::Client 构造点与登记表双向对账失败。\n新增未登记（新出站面必须说明结局归谁记，AGENTS B.4）：{unregistered:?}\n登记但已不存在（构造点被删/改名，请同步删条目）：{stale:?}"
        );
    }

    #[test]
    fn every_registered_site_records_an_outcome() {
        let mut bad: Vec<String> = Vec::new();
        let mut cache: BTreeMap<String, String> = BTreeMap::new();
        let mut load = |rel: &str| -> String {
            if let Some(s) = cache.get(rel) {
                return s.clone();
            }
            let s = prod_lines(rel).join("\n");
            cache.insert(rel.to_string(), s.clone());
            s
        };
        for (file, fname, disp) in REGISTRY {
            let prod = load(file);
            let lines: Vec<String> = prod.lines().map(str::to_string).collect();
            let fn_body = lines
                .iter()
                .position(|l| fn_head_of(l.trim_start()).as_deref() == Some(*fname))
                .map(|i| enclosing_fn(&lines, i).1)
                .unwrap_or_else(|| panic!("{file} 里找不到函数 {fname}（登记表条目已腐化）"));
            let caller_prod = match disp {
                Disposition::Caller(cf, _) => Some(load(cf)),
                _ => None,
            };
            if !disposition_satisfied(*disp, &fn_body, &prod, caller_prod.as_deref()) {
                bad.push(format!("{file}::{fname} ⇒ 未满足 {disp:?}"));
            }
        }
        assert!(
            bad.is_empty(),
            "以下出站构造点的结局在代码里找不到（指标缺位或被改走）：\n{}",
            bad.join("\n")
        );
    }

    /// B.4 的点名教训：同一接口的不同故障面**不得被平均掉**——IdP 取 token 与取
    /// userinfo 是两种故障形态，必须两个桶都在。
    #[test]
    fn oauth_token_and_userinfo_remain_separate_buckets() {
        let prod = prod_lines("src/service/sys_oauth_service.rs").join("\n");
        for label in ["oauth_token", "oauth_userinfo"] {
            assert!(
                prod.contains(&format!(r#"OutboundGuard::start("{label}")"#)),
                "sys_oauth_service 必须保留 {label} 独立桶（合并成一个 oauth 桶会掩盖失败阶段）"
            );
        }
    }

    /// 探针家族必须走 `probe:<name>`（B.5 口径），且 `ai` 探针确实是
    /// `probe_reachability`（否则登记表里那条 `Caller` 说明就成了谎话）
    #[test]
    fn ai_probe_outcome_is_recorded_by_the_probe_wrapper() {
        let probes = prod_lines("src/handler/health_probes.rs").join("\n");
        assert!(
            probes.contains(r#"BASIC_PROBES: &[&str] = &["#) && probes.contains("\"ai\""),
            "ai 必须在 BASIC_PROBES 清单内"
        );
        assert!(
            fold_ws(&probes).contains(&fold_ws(r#"record_outbound( &format!("probe:{name}""#)),
            "探针结局必须以 probe:<name> 记入出站指标（B.5 口径）"
        );
    }

    // ---------- 控制组：证明本锁不是"永远返回空"的虚锁 ----------

    const SYNTH_UNGUARDED: &str = "\
pub struct Svc;
impl Svc {
    pub async fn fetch(&self) -> Result<(), String> {
        let client = reqwest::Client::builder().build().map_err(|e| e.to_string())?;
        client.get(\"https://x\").send().await.map_err(|e| e.to_string())?;
        Ok(())
    }
}
";

    const SYNTH_GUARDED: &str = "\
pub struct Svc;
impl Svc {
    pub async fn fetch(&self) -> Result<(), String> {
        let client = reqwest::Client::builder().build().map_err(|e| e.to_string())?;
        let mut g = crate::observability::metrics::OutboundGuard::start(\"synth_face\");
        let r = client.get(\"https://x\").send().await;
        if r.is_ok() {
            g.succeeded();
        }
        r.map_err(|e| e.to_string())
    }
}
";

    #[test]
    fn scanner_detects_a_synthetic_construction_site() {
        let lines: Vec<String> = SYNTH_UNGUARDED.lines().map(str::to_string).collect();
        let idx = lines
            .iter()
            .position(|l| is_construction(l))
            .expect("合成源码必须被识别出构造点（识别不出来则本锁对新增出站面全盲）");
        let (name, body) = enclosing_fn(&lines, idx);
        assert_eq!(name, "fetch", "回溯到的所属函数应为 fetch");
        assert!(
            !disposition_satisfied(
                Disposition::ThisFn(r#"OutboundGuard::start("synth_face")"#),
                &body,
                SYNTH_UNGUARDED,
                None,
            ),
            "未守卫的站点必须判红——能过就说明这条锁是虚锁"
        );
    }

    #[test]
    fn scanner_accepts_a_synthetic_guarded_site() {
        let lines: Vec<String> = SYNTH_GUARDED.lines().map(str::to_string).collect();
        let idx = lines
            .iter()
            .position(|l| is_construction(l))
            .expect("合成源码必须被识别出构造点");
        let (name, body) = enclosing_fn(&lines, idx);
        assert_eq!(name, "fetch");
        assert!(
            disposition_satisfied(
                Disposition::ThisFn(r#"OutboundGuard::start("synth_face")"#),
                &body,
                SYNTH_GUARDED,
                None,
            ),
            "已守卫的站点必须放行——判它红说明本锁只会制造噪声"
        );
    }

    /// 多行 `record_outbound(` 形态（webhook 就是这种写法）必须也能被折叠匹配，
    /// 否则本锁会对"手写计数"家族失明
    #[test]
    fn multiline_record_outbound_call_is_matched() {
        let hay = "\
async fn send() {
    crate::observability::metrics::MetricsRegistry::global().record_outbound(
        \"webhook\",
        \"ok\",
        1.0,
    );
}
";
        assert!(
            disposition_satisfied(Disposition::SameFile(r#""webhook""#), "", hay, None),
            "多行 record_outbound 必须匹配（折叠空白口径）"
        );
    }

    /// 只出现组件名字符串、但没有真正记指标的文件不得算覆盖
    #[test]
    fn bare_label_without_a_call_is_not_coverage() {
        let hay = r#"
async fn send() {
    let component = "webhook";
    tracing::info!(component, "只打了日志");
}
"#;
        assert!(
            !disposition_satisfied(Disposition::SameFile(r#""webhook""#), "", hay, None),
            "没有 record_outbound/OutboundGuard 的文件里，出现组件名不构成覆盖"
        );
    }

    #[test]
    fn registry_files_all_exist() {
        let mut missing: Vec<&str> = Vec::new();
        for (f, _, d) in REGISTRY {
            if !Path::new(&root().join(f)).exists() {
                missing.push(f);
            }
            if let Disposition::Caller(cf, _) = d
                && !Path::new(&root().join(cf)).exists()
            {
                missing.push(cf);
            }
        }
        assert!(missing.is_empty(), "登记表引用了不存在的文件：{missing:?}");
    }
}
