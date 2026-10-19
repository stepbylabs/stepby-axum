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
    let content = std::fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("读取 {} 失败: {e}", path.display()));
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
        missing_zh
            .iter()
            .map(|s| s.as_str())
            .collect::<Vec<_>>()
            .join("\n")
    );
    assert!(
        missing_en.is_empty(),
        "以下 tr! key 在 locales/en-US.yml 缺失（英文请求将回退 zh-CN 或显示裸 key），请补齐：\n{}",
        missing_en
            .iter()
            .map(|s| s.as_str())
            .collect::<Vec<_>>()
            .join("\n")
    );
}

// ==================== 批七十五 B7：中间件层拒绝的文案必须真的走协商 ====================

use super::TestContext;
use axum::body::Body;
use axum::extract::connect_info::ConnectInfo;
use axum::http::{Method, Request};
use std::net::SocketAddr;

/// 发一条请求，返回 `(HTTP 状态, body.msg)`。`lang` 为 `None` 时**不带** Accept-Language。
async fn get_msg(
    ctx: &TestContext,
    uri: &str,
    lang: Option<&str>,
    extra: Option<(&str, &str)>,
) -> (u16, String) {
    let mut builder = Request::builder()
        .method(Method::GET)
        .uri(uri)
        .header("authorization", format!("Bearer {}", ctx.token));
    if let Some(l) = lang {
        builder = builder.header("accept-language", l);
    }
    if let Some((name, value)) = extra {
        builder = builder.header(name, value);
    }
    let mut req = builder.body(Body::empty()).expect("构造请求失败");
    let peer: SocketAddr = (ctx.peer_ip, 4321).into();
    req.extensions_mut().insert(ConnectInfo(peer));
    let (status, v) = ctx.send_raw(req).await;
    (
        status.as_u16(),
        v["msg"].as_str().unwrap_or_default().to_string(),
    )
}

/// 中间件层拒绝（414 请求行 / 431 请求头）的 msg 必须**随 Accept-Language 切换**。
///
/// 为什么必须测这一面：`router/mod.rs` 注释声明守卫"挂在 locale 之内 ⇒ 错误文案能吃到
/// 协商后的 locale"，而批七十五之前**没有任何载体**证明它——层级挪一格（或 `tr!` 在
/// task-local 之外求值）就会变成"英文用户永远收到中文"，而所有单测照常绿。
/// 同批把 404 兜底与 408 超时体两处**硬编码中文**出口也改走 `tr!` +
/// `common::response::transport_error`；它们的键存在性由上面的
/// `all_tr_keys_exist_in_both_locale_files` 总锁覆盖，
/// 而"这一面在真机上本地化"由本用例的 414/431 两支证明（同一层级、同一机制）。
///
/// ⚠️ 刻意**不测**未匹配路径的 404 兜底：未匹配请求落哪一层由
/// `embedded_assets::is_embedded_mode()` 决定（嵌入模式返回 SPA HTML 200，分离模式才返回
/// JSON 404），而集成测试跑在哪一档取决于构建形态与环境变量——批七十五实测本用例的
/// `/system/definitely-no-such-endpoint-b75` 得 **200**，正是这个模式差异，不是缺陷。
/// 拿一个随构建形态漂移的出口做断言，只会造出一口"环境耦合假失败"的锁。
///
/// 三侧判据：① en 得英文且非裸 key；② zh 得中文；③ **对照组**——缺 Accept-Language 必须
/// 落回 `fallback = "zh-CN"`（`lib.rs` 的 `i18n!` 声明），而不是裸 key 或空串。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn middleware_rejection_messages_follow_negotiated_locale() {
    let ctx = TestContext::new().await;
    let long_query = "x".repeat(40_000);
    let long_header = "z".repeat(70_000);

    // 两个中间件层拒绝出口（都在业务层之前，无需构造数据，且与嵌入/分离模式无关）
    let cases: &[(&str, u16, Option<(&str, &str)>)] = &[
        (&format!("/system/user/list?title={long_query}"), 414, None),
        (
            "/system/user/list?pageNum=1",
            431,
            Some(("x-huge", &long_header)),
        ),
    ];

    for (uri, expect_http, extra) in cases {
        let (http, en) = get_msg(&ctx, uri, Some("en-US"), *extra).await;
        assert_eq!(http, *expect_http, "{uri} 应落 {expect_http}，实际 {http}");
        let (zh_http, zh) = get_msg(&ctx, uri, Some("zh-CN"), *extra).await;
        assert_eq!(
            zh_http, *expect_http,
            "{uri} 应落 {expect_http}，实际 {zh_http}"
        );
        let (none_http, none) = get_msg(&ctx, uri, None, *extra).await;
        assert_eq!(
            none_http, *expect_http,
            "{uri} 应落 {expect_http}，实际 {none_http}"
        );

        for (label, msg) in [("en", &en), ("zh", &zh), ("缺省", &none)] {
            assert!(
                !msg.is_empty() && !msg.contains("error."),
                "{expect_http} 的 {label} 文案是裸 key 或空串（键未落在正确的节下）: {msg:?}"
            );
        }
        assert_ne!(
            en, zh,
            "{expect_http} 的中英文案完全相同 ⇒ locale 协商对这道闸没生效\
             （守卫挂在 locale 之外）：en={en:?} zh={zh:?}"
        );
        // 对照组：不带 Accept-Language 必须落回 fallback 档（= zh-CN，见 lib.rs 的 i18n! 声明）
        assert_eq!(
            none, zh,
            "{expect_http} 缺 Accept-Language 时应回退 fallback 档（zh-CN），\
             实际 none={none:?} zh={zh:?}"
        );
    }

    // 超长输入与巨型头值都不得被回显进错误体（查询串常含 token、头里就是凭据，C.9）
    let (_, en) = get_msg(
        &ctx,
        &format!("/system/user/list?title={long_query}"),
        Some("en-US"),
        Some(("x-huge", &long_header)),
    )
    .await;
    assert!(
        !en.contains(&"x".repeat(32)) && !en.contains(&"z".repeat(32)),
        "错误体回显了用户超长输入或头值: {en}"
    );
}
