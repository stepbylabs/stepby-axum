//! 出站 HTTP 客户端构造的单一事实源。
//!
//! ## 为什么要有这个模块（批八十一，v0.3.0 本机打包冒烟实测照出）
//! 各服务的 `reqwest::Client` 原先在**构造时**直接 `.expect("…不可恢复的编程错误")`。
//! 这个前提在两类宿主上不成立：`debian:*-slim` / distroless 之外的一批最小镜像里**没有
//! `ca-certificates`**，rustls 的 platform-verifier 取不到任何系统根证书，
//! `Client::builder().build()` 当场返回
//! `reqwest::Error { kind: Builder, source: General("No CA certificates were loaded from the system") }`。
//! 而 `SysOauthService::new()` 挂在 `state.rs` 的 AppState 构造里＝**启动路径**，于是
//! "零配置单文件"的发布产物在这类宿主上直接 panic 退出，前端/接口/定时任务全部起不来。
//! 实测取证：`--platform linux/arm64 debian:bookworm-slim` 起 v0.3.0 产物，初始化日志跑到
//! `cleanup_expired_logs` 之后 `thread 'main' panicked at src/service/sys_oauth_service.rs:385`。
//!
//! ## 判据
//! 1. **本模块不得 panic**。构造失败是运维事实（宿主缺信任库），不是编程错误；把它 panic 掉
//!    等于用一个可选依赖杀整个进程（AGENTS #5「可选依赖未配置 ⇒ SKIPPED，不误杀实例」同源，
//!    只是这一处此前没人把"缺根证书"算进"未配置"）。
//! 2. **失败不等于砍能力**（项目定位铁律）：系统信任库不可用时回落到**内嵌 Mozilla 根证书**
//!    （`webpki-roots`），出站在任何宿主上都照常可用，且校验强度不降——绝不做
//!    "关掉证书校验"那类假可用。
//! 3. 回落必须**留痕**（WARN）：运维需要知道自己在跑内嵌根证书（内嵌集合随版本发布，
//!    系统侧的撤销/轮换不会自动生效），因此这不是可以静默长期化的状态。
//!
//! ## 为什么回落要显式列 `rustls` 依赖
//! `reqwest::ClientBuilder::tls_backend_preconfigured` 靠 `dyn Any` downcast 到
//! **reqwest 自己那份** `rustls::ClientConfig`。类型不同版本 ⇒ 不认识 ⇒ 退化成
//! `TlsBackend::UnknownPreconfigured`（构造期不报错，第一次 TLS 握手才失败）。所以
//! `rustls` / `webpki-roots` 显式写进 Cargo.toml，并由
//! `fallback_client_builds`（本文件 `#[cfg(test)]` 用例，rustdoc 链不到私有 test 项）在构造期判住，而不是赌版本对齐。

use std::time::Duration;

/// 内嵌根证书 → rustls 客户端配置。
///
/// provider 显式取 `aws_lc_rs`（与 reqwest 的 `rustls` feature 同源）：不显式取时
/// `ClientConfig::builder()` 依赖"进程级默认 provider"，一旦依赖图同时出现 ring 与
/// aws-lc-rs 就会在运行期抛「no process-level CryptoProvider available」——
/// 那正是本模块要消除的那类"构造期炸进程"。
fn bundled_client_config() -> Result<rustls::ClientConfig, String> {
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    // 空集合必须是响亮错误而不是"能构建但谁都验不过"：webpki-roots 升级若改变常量形状，
    // 这里先红，否则得到一个"TLS 全败"的远端现象，本地毫无线索。
    if roots.is_empty() {
        return Err("内嵌根证书集合为空（webpki-roots 常量形状可能已变）".to_string());
    }
    let provider = rustls::crypto::aws_lc_rs::default_provider();
    let cfg = rustls::ClientConfig::builder_with_provider(provider.into())
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
        .map_err(|e| e.to_string())?
        .with_root_certificates(roots)
        .with_no_client_auth();
    Ok(cfg)
}

/// 两路都失败时的错误串：**必须以组件名开头**并带上两路的原话，
/// 否则运维只看到一句 "builder error"，无从知道是哪个出站组件、缺的是哪一路信任库。
fn failure_message(label: &str, primary: &str, secondary: &str) -> String {
    format!("{label}: 系统信任库不可用（{primary}）且内嵌根证书不可用（{secondary}）")
}

/// 构造带超时的出站客户端；**永不 panic**（失败返回 Err，由调用方降级为请求期错误）。
pub fn build(label: &str, connect: Duration, total: Duration) -> Result<reqwest::Client, String> {
    build_with(label, |b| b.connect_timeout(connect).timeout(total))
}

/// 组件自带出站形状时的通用入口（webhook 要禁重定向 + 专属 UA，调试器要手动逐跳跟随）。
///
/// `label` 只进日志与错误串，不做指标标签——出站口径在请求侧
/// （`OutboundGuard` / `record_outbound`），把"部署态缺信任库"记成请求结局会污染
/// 出站故障率（AGENTS B.4「口径失真比缺指标更糟」）。
/// `configure` 会**同时**作用于主路径与回退路径：回落只换 TLS 信任来源，
/// 不得顺手丢掉超时/重定向/UA 这些组件级约束（否则"能出网但语义变了"）。
pub fn build_with(
    label: &str,
    configure: impl Fn(reqwest::ClientBuilder) -> reqwest::ClientBuilder,
) -> Result<reqwest::Client, String> {
    match configure(reqwest::Client::builder()).build() {
        Ok(client) => Ok(client),
        Err(primary) => {
            let primary = primary.to_string();
            match bundled_client_config() {
                Ok(cfg) => {
                    let fb = configure(reqwest::Client::builder()).tls_backend_preconfigured(cfg);
                    match fb.build() {
                        Ok(client) => {
                            tracing::warn!(
                                "组件 {label} 无法使用系统信任库（{primary}），已回落到内嵌根证书出站；\
                                 建议在宿主上安装 ca-certificates 以跟随系统轮换"
                            );
                            Ok(client)
                        }
                        Err(e) => Err(failure_message(label, &primary, &e.to_string())),
                    }
                }
                Err(e) => Err(failure_message(label, &primary, &e)),
            }
        }
    }
}

/// 投递类出站客户端的**唯一**构造入口（短信网关 / 云厂商 endpoint / IM 机器人 WebHook）。
///
/// 与 [`build`] 的差别只有一条，但这一条正是凭据外流的出口：**重定向策略**。
/// `reqwest` 默认跟随至多 10 次跳转，而跳转目标由上一跳的 `Location` 头决定 ——
/// 配置校验（scheme / 元数据段 / DNS）判的都是**管理员写下的那个 URL**，一次
/// `302 → http://169.254.169.254/…` 或 `302 → https://attacker/` 会让客户端**带着
/// 鉴权头**自己走过去，前面两层守卫完全看不见（B1 真正的洞在这一层）。
///
/// 因此这一族只跟随"仍在当初那台主机上"的跳转（含 `http→https` 升级与换端口，
/// 那是自托管网关的合法形态），其余一律停。判据本体在
/// [`crate::common::ssrf::may_follow_redirect`]（纯函数，可直接单测）。
///
/// 停下来的结局是**可见的失败**而不是静默降级：reqwest 对"策略拒绝跟随"返回的是那个
/// 3xx 响应本身，各 provider 现有的 `status.is_success()` 分支会把它落成投递失败并进入
/// 重试链与发送记录（AGENTS B.6）。
pub fn build_delivery_client(
    label: &str,
    connect: Duration,
    total: Duration,
) -> Result<reqwest::Client, String> {
    build_with(label, |b| {
        b.connect_timeout(connect)
            .timeout(total)
            .redirect(reqwest::redirect::Policy::custom(delivery_redirect))
    })
}

/// `Policy::custom` 的闭包本体：取"最初配置的那个地址"作基准来比。
///
/// `Attempt::previous()` 在 reqwest 0.13.5 是 `&[Url]`（**跳转链**，第 0 项即原始 URL），
/// 不是 `Option<&Response>`——按"上一跳"比会允许 `A→B→C` 逐跳漂移，一次跨主机跳转就把
/// 凭据交出去；按链首比才是"不许离开这台主机"。
fn delivery_redirect(attempt: reqwest::redirect::Attempt<'_>) -> reqwest::redirect::Action {
    if should_follow_delivery_redirect(attempt.previous().first(), attempt.url()) {
        attempt.follow()
    } else {
        attempt.stop()
    }
}

/// 纯函数判据（上面那段闭包的可测面）：拿不到链首地址 ⇒ **不跟**（fail-closed）。
pub fn should_follow_delivery_redirect(base: Option<&url::Url>, target: &url::Url) -> bool {
    match base {
        Some(b) => crate::common::ssrf::may_follow_redirect(b, target),
        None => false,
    }
}

/// 投递路径的守卫反查：凡"在本函数段内发起 `.send().await`"的函数，段内必须出现
/// `guard_gateway_url(`。
///
/// 分段口径：函数段 = 该发送行往上**最近**的一个 `fn` 头行，到下一个 `fn` 头行为止。
/// 不追求完整 AST（那要引模板解析），只要求"守卫与发送在同一个函数里"——本仓 provider
/// 全是这个形状，而"在别的函数里过一次守卫"对本判据没有意义（守卫必须在发请求前跑）。
/// 取不到任何发送行 ⇒ 返回空表：**这与"扫不到即通过"是同一族风险**，所以调用侧另有
/// `send_paths_missing_gateway_guard_is_falsifiable` 的合成正控 + 真实树"发送点数 ≥5"的
/// 采集面自证。
#[cfg(test)]
fn send_paths_missing_gateway_guard(text: &str, rel: &str) -> Vec<String> {
    let lines: Vec<&str> = text.split('\n').collect();
    let is_fn_head = |l: &str| {
        let t = l.trim_start();
        [
            "fn ",
            "pub fn ",
            "async fn ",
            "pub async fn ",
            "pub(crate) async fn ",
            "pub(crate) fn ",
        ]
        .iter()
        .any(|p| t.starts_with(p))
    };
    let heads: Vec<usize> = (0..lines.len()).filter(|i| is_fn_head(lines[*i])).collect();
    let mut hits = Vec::new();
    for (idx, l) in lines.iter().enumerate() {
        // 发送点判据取 `.send()` **所在行**：本仓真实写法是链式换行
        // （`.send()` 与 `.await` 分处两行），按"同一行同时含两者"去匹配会一条都数不到
        // ——采集面自证正是为了在第一时间暴露这种"口径自己坏了"的形态（AGENTS ⑥）。
        if !l.contains(".send()") {
            continue;
        }
        // 最近的、行号 ≤ idx 的函数头
        let Some(&start) = heads.iter().rev().find(|h| **h <= idx) else {
            hits.push(format!(
                "{rel}:{} 发送点找不到所属函数（分段口径失效）",
                idx + 1
            ));
            continue;
        };
        let end = heads
            .iter()
            .find(|h| **h > idx)
            .copied()
            .unwrap_or(lines.len());
        let body = lines[start..end].join("\n");
        if !body.contains("guard_gateway_url(") {
            hits.push(format!(
                "{rel}:{} 函数段（自第 {} 行起）内未过 guard_gateway_url：{}",
                idx + 1,
                start + 1,
                l.trim()
            ));
        }
    }
    hits
}

/// 采集面自证：这两个文件里"真的在发请求"的行数必须 ≥5（五个 provider 各一条）。
/// 少了说明分段/匹配口径腐化，此时"0 违规"没有任何含义（AGENTS ⑥「零捕获 ≠ PASS」）。
#[cfg(test)]
fn send_line_count(text: &str) -> usize {
    text.split('\n').filter(|l| l.contains(".send()")).count()
}

/// **投递族的采集面由源码事实派生**（b144 补）：凡生产码里出现
/// `outbound_client::build_delivery_client(` 的文件，就是"把管理员配的 URL 交给 reqwest"
/// 这一族的一员。
///
/// 为什么不能按文件名枚举：`every_gateway_send_path_guarded_its_url` 原先写死两个 provider
/// 文件名，于是**新增第三个投递 provider 时它不在采集面里**——守卫漏写不会红，
/// 而这一族漏守卫的后果正是"SSRF 两层校验被一次 302 绕过"（B1 立的就是这一族）。
/// 派生只认**投递构造点**这一个事实，判据口径（守卫必须在发送函数体内）一字未放宽。
#[cfg(test)]
fn delivery_family_files() -> Vec<crate::common::prod_scan::ProdFile> {
    crate::common::prod_scan::prod_files(&crate::common::prod_scan::Scan {
        exclude: &["src/common/outbound_client.rs"],
        ..Default::default()
    })
    .into_iter()
    .filter(|f| f.text().contains("outbound_client::build_delivery_client("))
    .collect()
}

/// 生产码里"构造出站客户端"的形状判据：`Client::builder() … .build()` 之后**紧跟**
/// `.expect(` / `.unwrap()` 即违规。
///
/// 为什么要一条形状锁而不是只改这几处：同类构造点散在 `ai/`、`service/`、`storage/` 里是
/// 长尾（`handler::outbound_metrics_guard` 的登记表就是那份清单），
/// 下一次新增照样会顺手写下"这不可能失败"。
///
/// 判据必须**沿链走到 `.build()`**再判断尾巴：本批修掉的 6 处真实现场全都写成
/// `builder().connect_timeout(…).timeout(…).build().expect(…)`，若只匹配
/// `builder().build().expect(` 这一紧凑形态，这把锁会对真正的违规形态视而不见
/// （合成违规第一次跑就报了 0 命中，正是这个盲区——虚锁比缺锁更坏）。
/// 折叠空白以覆盖跨行写法；切片点全部落在 ASCII 模式串的边界上。
#[cfg(test)]
fn construction_panics(text: &str) -> Vec<String> {
    let folded: String = text.split_whitespace().collect::<Vec<_>>().join("");
    let tails = [".expect(", ".unwrap()"];
    let mut hits = Vec::new();
    // `Client::new()` 没有中间链，build 步长取 0
    for (head, build_len) in [
        ("Client::builder()", ".build()".len()),
        ("Client::new()", 0usize),
    ] {
        let mut from = 0usize;
        while let Some(rel) = folded[from..].find(head) {
            let after_head = from + rel + head.len();
            let rest = &folded[after_head..];
            let tail_start = if build_len == 0 {
                0usize
            } else {
                match rest.find(".build()") {
                    Some(bl) => bl + build_len,
                    // 链上没有 .build()（例如只建了 builder 就交给别处）⇒ 不构成"构造期 panic"
                    None => {
                        from = after_head;
                        continue;
                    }
                }
            };
            let tail = &rest[tail_start..];
            for t in tails {
                if tail.starts_with(t) {
                    hits.push(format!("{head}…build(){t}"));
                }
            }
            from = after_head + tail_start;
        }
    }
    hits
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 内嵌集合非空且数量级对得上（Mozilla 根证书集 ~140+）。
    /// 只判 `!is_empty()` 不够：一条残缺的根就能把"回落可用"变成"回落全败"。
    #[test]
    fn bundled_root_store_is_populated() {
        let mut roots = rustls::RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        assert!(
            roots.len() > 100,
            "内嵌根证书数量异常：{}（期望 >100，webpki-roots 常量形状可能已变）",
            roots.len()
        );
    }

    /// 反证：判据真的在数东西——空 RootCertStore 必须被 `bundled_client_config` 的空集合
    /// 分支挡住。这里直接判空集合的 len，证明">100"不是恒真比较（拿 0 去比必然假）。
    #[test]
    fn empty_root_store_would_not_pass_the_floor() {
        let empty = rustls::RootCertStore::empty();
        assert_eq!(empty.len(), 0, "控制组失效：空集合应有 0 条根");
        assert!(empty.len() <= 100, "控制组失效：空集合必须落在判据的拒绝侧");
    }

    /// 回落路径本身必须真能建成客户端（这条同时钉住 downcast 类型与 reqwest 期望一致：
    /// 类型不匹配时 reqwest 退化成 UnknownPreconfigured，而它到**第一次请求**才报错，
    /// 所以判据只能放在构造期）
    #[test]
    fn fallback_client_builds() {
        let cfg = bundled_client_config().expect("内嵌根证书配置构建失败");
        let client = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(15))
            .tls_backend_preconfigured(cfg)
            .build()
            .expect("内嵌根证书客户端构建失败");
        // 客户端可用性的最小可判证据：能组装出一个真实请求（0.13 的 Client 没有 timeout()
        // 访问器，所以不判超时配置——超时由 builder 参数与本模块的调用点表共同约束）
        let req = client
            .post("https://example.com/token")
            .form(&[("code", "x")])
            .build();
        assert!(req.is_ok(), "回落客户端必须能组装出站请求：{req:?}");
    }

    /// 本机（有系统信任库的宿主）走主路径 ⇒ Ok，不触发回落
    #[test]
    fn build_succeeds_on_host_with_system_roots() {
        assert!(
            build("unit-test", Duration::from_secs(5), Duration::from_secs(30)).is_ok(),
            "本宿主应能直接用系统信任库构建出站客户端"
        );
    }

    /// 失败出口是 Err 而不是 panic——本模块存在的全部理由。
    /// 用**非法 UA**（含 NUL，HeaderValue 必拒）制造确定性的 builder 失败，
    /// 一次同时判三件事：①失败返回 Err 而非 panic；②错误串点名组件；
    /// ③`configure` 确实作用在**两条**路径上——若回退路径漏掉它，回退会成功而本用例拿 Ok，
    /// 于是"组件级约束（超时/重定向/UA）在回落时被丢掉"这类缺陷会被静默放走。
    #[test]
    fn build_with_invalid_config_errors_without_panic() {
        let r = build_with("unit-bad-ua", |b| b.user_agent("bad\u{0}agent"));
        match r {
            Ok(_) => panic!("非法 UA 必须让两条路径都构建失败，拿到 Ok 说明回落丢掉了 configure"),
            Err(msg) => {
                assert!(msg.contains("unit-bad-ua"), "错误串必须点名组件：{msg}");
                assert!(
                    msg.contains("系统信任库不可用") && msg.contains("内嵌根证书不可用"),
                    "错误串必须同时给出两条路径的原因：{msg}"
                );
            }
        }
    }

    /// 组件自带出站形状（webhook 的禁重定向 + 专属 UA）在主路径上必须能建成客户端。
    ///
    /// 刻意**不**去回读 UA/超时做断言：reqwest 0.13 把客户端默认头与超时合并在 `send()`
    /// 里，`RequestBuilder::build()` 之后读不到（实测拿到 None），那种断言只会以
    /// "测试写错了"的形式假失败。"configure 同时作用在两条路径上"这一性质由
    /// [`build_with_invalid_config_errors_without_panic`] 反向钉住——回退路径若漏掉它，
    /// 那条用例会拿到 Ok 而判红。
    #[test]
    fn build_with_accepts_component_shape() {
        let r = build_with("unit-webhook-shape", |b| {
            b.redirect(reqwest::redirect::Policy::none())
                .connect_timeout(Duration::from_secs(10))
                .user_agent("stepby-webhook/1.0")
        });
        assert!(r.is_ok(), "webhook 形态的出站客户端应能建成：{r:?}");
    }

    /// 错误串自足：组件名 + 两路原话都在（否则日志里无从定位是哪个出站组件）
    #[test]
    fn failure_message_is_self_describing() {
        let msg = failure_message("oauth", "No CA certificates were loaded", "roots empty");
        assert!(msg.contains("oauth"), "必须点名组件：{msg}");
        assert!(
            msg.contains("No CA certificates were loaded"),
            "必须带主路径原因：{msg}"
        );
        assert!(msg.contains("roots empty"), "必须带回退路径原因：{msg}");
        // 控制组：label 为空时"点名"这条判据必须失效（证明 assert 真的在判字符串内容）
        let no_name = failure_message("", "a", "b");
        assert!(!no_name.contains("oauth"), "判据不得恒真");
    }

    /// 形状锁正控：合成违规必须被抓住。两种形态都判——
    /// ①本批修掉的**真实**形态（builder 与 build 之间夹着超时链）；②紧凑形态。
    /// 只测②会漏掉①，而①才是仓库里实际存在过的写法（第一次上线时就是这样：紧凑形态
    /// 命中 0，真实现场照样扫不出来——虚锁比缺锁更坏）。
    #[test]
    fn panic_scanner_catches_synthetic_violation() {
        let real_shape = [
            "let http: reqwest::Client = reqwest::Client::builder()",
            "    .connect_timeout(Duration::from_secs(5))",
            "    .timeout(Duration::from_secs(15))",
            "    .build()",
            "    .expect(\"不会失败\");",
        ]
        .join("\n");
        assert_eq!(
            construction_panics(&real_shape),
            vec!["Client::builder()…build().expect(".to_string()],
            "真实违规形态（带中间链）必须被抓住"
        );
        let compact = r"let c = reqwest::Client::builder().build().unwrap();".to_string();
        assert_eq!(
            construction_panics(&compact).len(),
            1,
            "紧凑 .unwrap() 形态也必须被抓"
        );
        let ctor_new = r#"let c = reqwest::Client::new().expect("x");"#.to_string();
        assert_eq!(
            construction_panics(&ctor_new).len(),
            1,
            "Client::new() 形态也必须被抓"
        );
    }

    /// 形状锁反例：合规写法必须放行（否则锁把正确实现判红，结局是被当噪声关掉）
    #[test]
    fn panic_scanner_accepts_compliant_site() {
        let ok = [
            r#"let r = crate::common::outbound_client::build("oauth", c, t).map(Some).unwrap_or_else(|e| None);"#,
            "let client = reqwest::Client::builder().timeout(t).build().map_err(|e| e.to_string())?;",
            "let b = reqwest::Client::builder();",
        ]
        .join("\n");
        assert!(
            construction_panics(&ok).is_empty(),
            "合规写法不得报红：{:?}",
            construction_panics(&ok)
        );
    }

    /// 全仓生产码总锁：任何 `Client::builder()` 之后接 `.expect/.unwrap` 都算违规。
    /// 采集面走 [`crate::common::prod_scan`]（与 outbound_metrics_guard / fail_closed_guard
    /// 同一管道，体量下限由 `require_volume` 兜住——空采集面不是通过）。
    #[test]
    fn production_code_has_no_panic_on_client_construction() {
        const SELF: &str = "src/common/outbound_client.rs";
        let files = crate::common::prod_scan::prod_files(&crate::common::prod_scan::Scan {
            exclude: &[SELF],
            ..Default::default()
        });
        // 下限取一个明显低于实际规模的数（本仓 src 有数百个 .rs / 数十万行）：
        // 它的用处是"目录改名或采集面腐化时响亮失败"，不是精确断言。
        crate::common::prod_scan::require_volume(&files, 100, 50_000, "出站构造 panic 扫描面");
        let offenders: Vec<String> = files
            .iter()
            .filter_map(|f| {
                let hits = construction_panics(&f.text());
                if hits.is_empty() {
                    None
                } else {
                    Some(format!("{}: {}", f.rel, hits.join(", ")))
                }
            })
            .collect();
        assert!(
            offenders.is_empty(),
            "出站客户端构造必须走 common::outbound_client::build（失败降级为请求期错误），\
             不得在构造期 panic。违规：\n{}",
            offenders.join("\n")
        );
    }

    /// **出站客户端只有一个构造出口**（b144 补）。
    ///
    /// 与上一把锁的分工（两条腿互不顶班）：`production_code_has_no_panic_on_client_construction`
    /// 判的是「构造失败不得炸进程」；一把只盯 panic 形状，于是**把失败吞成 WARN/`Err`** 的
    /// 裸构造全部合法——而那一类失败的后果是「这项能力在这台宿主上静默消失」，
    /// 比炸进程更难发现（b81 实测的 `debian:*-slim` 无 `ca-certificates`：
    /// 裸 `build()` 必返 Err，内嵌根证书回落只有本模块有）。b144 实测这样的站点有 **9 处**
    /// （outbox/acme/av_scan/sso/s3/ip_geo×2/ai_config×2 中的 8 处 + AI provider 的
    /// `Client::new()` 兜底——那条在同一个失败场景里自己 panic）。
    ///
    /// 采集面**由事实派生**（全 `src` 生产码视图，注释已 blank，所以注释里怎么写都不参与），
    /// 不按文件名枚举——按名字枚举正是上一批 `every_gateway_send_path_guarded_its_url` 的洞。
    #[test]
    fn outbound_client_has_a_single_construction_site() {
        const SELF: &str = "src/common/outbound_client.rs";
        let files = crate::common::prod_scan::prod_files(&crate::common::prod_scan::Scan {
            exclude: &[SELF],
            ..Default::default()
        });
        crate::common::prod_scan::require_volume(&files, 100, 50_000, "出站构造出口扫描面");
        let offenders: Vec<String> = files
            .iter()
            .filter_map(|f| {
                let text = f.text();
                let mut found: Vec<String> = Vec::new();
                for needle in ["Client::builder()", "Client::new()"] {
                    if text.contains(needle) {
                        found.push(needle.to_string());
                    }
                }
                if found.is_empty() {
                    None
                } else {
                    Some(format!("{}: {}", f.rel, found.join(", ")))
                }
            })
            .collect();
        assert!(
            offenders.is_empty(),
            "出站客户端只能经 common::outbound_client 构造（否则拿不到内嵌根证书回落、\
             也拿不到投递类的跳转策略）。违规：\n{}",
            offenders.join("\n")
        );

        // 双向：合规形状不得报（否则每轮必红，结局是被放宽）
        let compliant =
            "let c = crate::common::outbound_client::build_with(\"x\", |b| b.timeout(t));";
        assert!(
            !compliant.contains("Client::builder()") && !compliant.contains("Client::new()"),
            "合规形状被误判"
        );
        // 活性正控：本判据的两个针必须真的能抓到形状（被排除的 SELF 文件里就有它们）
        let self_text =
            crate::common::prod_scan::prod_file(SELF, &crate::common::prod_scan::Scan::default())
                .text();
        assert!(
            self_text.contains("Client::builder()"),
            "针失效：{SELF} 的生产视图里已找不到 Client::builder() ⇒ 采集口径或本模块形状变了，\
             此时『0 违规』不代表任何东西"
        );
    }

    // ---------- B1：投递类客户端的重定向策略 ----------

    /// 一个按顺序应答的本地 HTTP 服务（每个请求一条连接，`Connection: close`）。
    /// `hits` 记录**实际到达的**请求条数——它才是"跟没跟跳转"的事实通道，
    /// 而不是"我们没写跟随代码"这种推断（AGENTS 测试门禁 ⑭：落地必须是运行时事实）。
    #[cfg(test)]
    fn serve_in_order(
        listener: std::net::TcpListener,
        responses: Vec<String>,
        hits: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    ) -> std::thread::JoinHandle<()> {
        std::thread::spawn(move || {
            use std::io::{BufRead, BufReader, Read, Write};
            for resp in responses {
                let Ok((mut stream, _)) = listener.accept() else {
                    return;
                };
                let Ok(owned) = stream.try_clone() else {
                    return;
                };
                let mut reader = BufReader::new(owned);
                let mut line = String::new();
                reader.read_line(&mut line).ok();
                let mut content_length = 0usize;
                loop {
                    let mut header = String::new();
                    if reader.read_line(&mut header).unwrap_or(0) == 0 {
                        break;
                    }
                    let lower = header.to_ascii_lowercase();
                    if let Some(rest) = lower.strip_prefix("content-length:") {
                        content_length = rest.trim().parse().unwrap_or(0);
                    }
                    if header.trim().is_empty() {
                        break;
                    }
                }
                if content_length > 0 {
                    let mut body = vec![0u8; content_length];
                    reader.read_exact(&mut body).ok();
                }
                hits.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                stream.write_all(resp.as_bytes()).ok();
                stream.flush().ok();
            }
        })
    }

    #[cfg(test)]
    fn close_headers(body: &str) -> String {
        format!(
            "HTTP/1.1 {body}\r\nConnection: close\r\nContent-Length: 0\r\n\r\n",
            body = body
        )
    }

    /// 跨主机跳转**必须不跟随**：目标是云元数据端点时，跟随就等于"用平台自己的鉴权头
    /// 去敲 169.254.169.254"。静态层与 DNS 层都看不见这一跳（它们判的是配置里的 URL）。
    #[tokio::test]
    async fn delivery_client_refuses_cross_host_redirect() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let hits = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let responses = vec![
            "HTTP/1.1 302 Found\r\nLocation: http://169.254.169.254/latest/meta-data/\r\n\
             Connection: close\r\nContent-Length: 0\r\n\r\n"
                .to_string(),
        ];
        let serve = serve_in_order(listener, responses, hits.clone());

        let client = build_delivery_client(
            "unit-redirect",
            Duration::from_secs(2),
            Duration::from_secs(5),
        )
        .expect("投递客户端必须能建成（本宿主有系统信任库）");
        let resp = client
            .post(format!("http://{addr}/send"))
            .json(&serde_json::json!({ "phone": "138" }))
            .send()
            .await
            .expect("302 响应必须原样返回（策略拒绝跟随 ≠ 请求失败）");
        assert_eq!(
            resp.status().as_u16(),
            302,
            "跨主机跳转必须停在 302 本体上，让调用方的 is_success() 判成可见失败"
        );
        assert_eq!(
            hits.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "只允许到达原始那一跳：第二条说明客户端跟着跳转去了别处"
        );
        serve.join().unwrap();
    }

    /// 对照组（**必须照常跟随**）：同主机换路径/换端口是自托管网关的合法形态
    /// （`http://gw` → `https://gw`、网关内部重写路径）。把这一支也封掉就是砍功能
    /// （AGENTS 项目定位），所以它和上一条必须**同批**成立，缺一半都不算证伪。
    #[tokio::test]
    async fn delivery_client_follows_same_host_redirect() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let hits = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let responses = vec![
            format!(
                "HTTP/1.1 307 Temporary Redirect\r\nLocation: http://{addr}/final\r\n\
                 Connection: close\r\nContent-Length: 0\r\n\r\n"
            ),
            close_headers("200 OK"),
        ];
        let serve = serve_in_order(listener, responses, hits.clone());

        let client = build_delivery_client(
            "unit-redirect-ok",
            Duration::from_secs(2),
            Duration::from_secs(5),
        )
        .expect("投递客户端必须能建成");
        let resp = client
            .post(format!("http://{addr}/send"))
            .json(&serde_json::json!({ "phone": "138" }))
            .send()
            .await
            .expect("同主机跳转必须能跟完");
        assert_eq!(
            resp.status().as_u16(),
            200,
            "对照组失效：同主机跳转没跟到底"
        );
        assert_eq!(
            hits.load(std::sync::atomic::Ordering::SeqCst),
            2,
            "必须真的发出第二条请求（第一条是 307）"
        );
        serve.join().unwrap();
    }

    /// 纯函数侧：拿不到链首地址 ⇒ **不跟**（fail-closed，不能因为"比不了"就放行）
    #[test]
    fn redirect_decision_is_fail_closed_without_a_base() {
        let target = url::Url::parse("http://127.0.0.1:1/send").unwrap();
        assert!(
            !should_follow_delivery_redirect(None, &target),
            "链首地址缺失时必须拒绝跟随"
        );
        let base = url::Url::parse("http://gw.internal/send").unwrap();
        assert!(
            should_follow_delivery_redirect(
                Some(&base),
                &url::Url::parse("http://gw.internal/x").unwrap()
            ),
            "同主机必须放行（对照组）"
        );
    }

    /// 接线反查（**按计数**，不是"存在一次"）：投递族的每一个构造点都必须
    /// 走 `build_delivery_client`，且**不得**残留裸 `outbound_client::build(`。
    ///
    /// 为什么计数而不是布尔：同一文件里多个 provider 的 `new()` 形状完全相同
    /// （outbound_metrics_guard 早就登记过"同文件同名函数可重复，比对按重数"这一口径），
    /// 只要求"出现过一次"的话，撤掉其中任何一处都照常绿（AGENTS ㉘/66(c) 同一族）。
    ///
    /// b144 将采集面从"两个文件名"换成**由源码事实派生的投递族**：`expect(...)` 那两行
    /// 是**承诺面**（删掉一个 provider 必须可见），派生集合是**事实面**（新增第三个
    /// 投递 provider 自动进这一族）。两者还要互相钉住——派生集合少了承诺里的文件，
    /// 说明口径腐化而不是"这个文件不在了"（AGENTS ㉗：分母要么来自承诺、要么来自事实，
    /// 混用等于取最松的那把尺；这里要求两侧同时成立）。
    #[test]
    fn delivery_providers_use_the_redirect_safe_constructor() {
        let expect = |rel: &str, delivery: usize| {
            let f = crate::common::prod_scan::prod_file(rel, &Default::default());
            let text = f.text();
            let plain = text.matches("outbound_client::build(").count();
            let guarded = text
                .matches("outbound_client::build_delivery_client(")
                .count();
            assert_eq!(
                guarded, delivery,
                "{rel} 应有 {delivery} 处投递客户端构造点走 build_delivery_client，实测 {guarded}"
            );
            assert_eq!(
                plain, 0,
                "{rel} 残留 {plain} 处裸 outbound_client::build(（默认跟随任意跳转），必须改走投递构造点"
            );
        };
        expect("src/service/sms_provider.rs", 3);
        expect("src/service/im_robot_provider.rs", 2);

        // 事实面：派生出的每一个投递文件都不得混用裸 build(（新增成员自动受同一条约束）
        let family = delivery_family_files();
        let names: Vec<&str> = family.iter().map(|f| f.rel.as_str()).collect();
        for rel in [
            "src/service/sms_provider.rs",
            "src/service/im_robot_provider.rs",
        ] {
            assert!(
                names.contains(&rel),
                "派生采集面漏掉了承诺文件 {rel} ⇒ 派生口径坏了（而不是「这个文件不算数」）：{names:?}"
            );
        }
        for f in &family {
            let plain = f.text().matches("outbound_client::build(").count();
            assert_eq!(
                plain, 0,
                "投递族成员 {} 混用 {plain} 处裸 outbound_client::build(：\
                 同一份配置 URL 既能被守卫也能被任意跳转，按族判据必须一并改走投递构造点",
                f.rel
            );
        }
    }

    /// 配置侧接线反查：每一个"把配置里的 URL 交给 reqwest"的方法都必须先过 DNS 层守卫。
    /// 采集面**由源码事实派生**（投递族 = 出现 `build_delivery_client(` 的生产文件），
    /// 而不是手抄一份文件名清单——新增 provider 时清单不会提醒任何人（b144 收口补：
    /// 此前这里写死两个文件名，第三个投递 provider 漏守卫照样绿，而这一族漏守卫的后果
    /// 正是 B1 立案要防的"一次 302 绕过两层校验并带走凭据"）。
    #[test]
    fn every_gateway_send_path_guarded_its_url() {
        let mut unguarded = Vec::new();
        let mut send_lines = 0usize;
        let family = delivery_family_files();
        assert!(
            family.len() >= 2,
            "派生采集面失效：投递族只扫到 {} 个文件（地板 2）——这是扫描口径坏了，\
             不是「违规归零」",
            family.len()
        );
        for f in &family {
            let text = f.text();
            send_lines += send_line_count(&text);
            unguarded.extend(send_paths_missing_gateway_guard(&text, &f.rel));
        }
        assert!(
            send_lines >= 5,
            "采集面自证失效：投递族里只数到 {send_lines} 条发送点（期望 ≥5），\
             此时『0 违规』不代表任何东西——是分段口径腐化了"
        );
        assert!(
            unguarded.is_empty(),
            "以下出站方法把配置 URL 直接交给 reqwest，却没有先过 guard_gateway_url：\n{}",
            unguarded.join("\n")
        );
    }

    /// 上一把锁的活性正控：合成一个"没守卫的发送路径"必须被点名（否则锁可能是虚锁），
    /// 且合规写法必须不报（否则这把锁会把正确实现判红、结局是被当噪声关掉）。
    #[test]
    fn send_paths_missing_gateway_guard_is_falsifiable() {
        let bad = "impl P {\n    pub async fn send(&self, cfg: &C) -> Result<(), String> {\n        let http = http_of(&self.http, \"x\")?;\n        let resp = http.post(&cfg.webhook_url).json(&cfg.b).send().await.map_err(|e| e.to_string())?;\n        Ok(())\n    }\n}";
        let hits = send_paths_missing_gateway_guard(bad, "synthetic.rs");
        assert_eq!(hits.len(), 1, "合成违规必须被抓（抓不到即虚锁）：{hits:?}");
        let ok = "impl P {\n    pub async fn send(&self, cfg: &C) -> Result<(), String> {\n        crate::common::ssrf::guard_gateway_url(&cfg.webhook_url).await?;\n        let resp = http.post(&cfg.webhook_url).send().await.map_err(|e| e.to_string())?;\n        Ok(())\n    }\n}";
        assert!(
            send_paths_missing_gateway_guard(ok, "synthetic.rs").is_empty(),
            "合规写法不得报红"
        );
        // 守卫在**另一个函数**里过 ≠ 本发送点被保护（分段口径的反证：不得跨函数洗白）
        let split = "fn helper() -> bool {\n    true\n}\nfn guarded() {\n    block_on(crate::common::ssrf::guard_gateway_url(\"x\"));\n}\nimpl P {\n    pub async fn send(&self, cfg: &C) -> Result<(), String> {\n        let resp = http.post(&cfg.u).send().await.map_err(|e| e.to_string())?;\n        Ok(())\n    }\n}";
        assert_eq!(
            send_paths_missing_gateway_guard(split, "synthetic.rs").len(),
            1,
            "守卫写在隔壁函数里不得算数"
        );
    }
}
