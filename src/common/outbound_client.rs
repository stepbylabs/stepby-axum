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
}
