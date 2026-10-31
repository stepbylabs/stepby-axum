//! 请求层超时：**按路由分档**，而不是全应用一把尺。
//!
//! ## 立案事实（b140）
//!
//! 此前 [`crate::router`] 在应用最外层挂了一个**固定 120 秒**的 `tower::timeout`
//! （原 `REQUEST_TIMEOUT_SECS`），覆盖**全部**路由。而同一份代码里写着三处更长的内部预算：
//!
//! | 内部预算 | 取值 | 位置 |
//! |---|---|---|
//! | 备份/恢复子进程 | [`crate::service::sys_backup_service::BACKUP_TIMEOUT_SECS`] = 300s | dump 与 restore 的 `tokio::process` |
//! | IP 库镜像下载 | [`crate::service::ip_location_service::IP_DOWNLOAD_TIMEOUT_SECS`] = 300s | P3TERX / MaxMind 两个 `reqwest::Client` |
//! | 恢复互斥锁 TTL | 600s（注释自陈"防卡死"） | `handler::sys_backup_handler::restore` |
//!
//! 也就是说：**代码自己承认这些操作可以跑到 300 秒**，而传输层在 120 秒就把 handler 的
//! future 丢弃了。子进程一律 `kill_on_drop(true)` ⇒ 后果不是"请求失败"这么轻：
//!
//! 1. `mysql < dump.sql` / `psql -f` 在**灌到一半**时被杀 ⇒ 库处于部分恢复态（无事务回滚，
//!    因为恢复本来就是逐语句外部进程）；
//! 2. handler future 被丢弃 ⇒ 紧随其后的 `store.lock_release(&lock_handle)` **永不执行**
//!    ⇒ 恢复锁泄漏到 600s TTL，期间所有恢复请求一律 400，而运维看到的是"另一个恢复正在进行"
//!    ——一个并不在进行的恢复。
//!
//! 两个方向的错误都在这条链上：调大全局超时会让普通请求失去 Slowloris 防护；
//! 调小内部预算会让大库备份根本做不完。所以这里做的是**分档**，不是"折中一个数"。
//!
//! ## 档位关系（编译期钳住，不靠人记住）
//!
//! 长任务档 = `max(全部内部预算) + 余量`。这条关系由 `const _: () = assert!(…)` 钉住：
//! 任何人把某个内部预算调到 ≥ 长任务档，**构建即失败**，而不是等到某次真实恢复被腰斩。
//!
//! ## 为什么在中间件里自己匹配路径，而不用 `MatchedPath`
//!
//! 本层挂在 router **之外**（与改造前的 `.timeout()` 同一槽位，见 `router/mod.rs` 的注释），
//! 而 `MatchedPath` 是路由完成后才写进 extensions 的——在外层读不到。限流档位之所以能用
//! `MatchedPath`，是因为它挂在受保护路由之内。因此这里按**路由模板**逐段匹配原始路径，
//! 模板集合由 [`crate::middleware::request_timeout::LONG_RUNNING_ROUTES`] 登记，并由形状锁逐条对账 `src/router/**` 的真实注册
//! （写错一个字的模板 = 该路由静默回到 120s 档 = 本批修的那个缺陷复活）。

use std::future::Future;
use std::time::Duration;

use axum::extract::Request;
use axum::http::{Method, StatusCode};
use axum::middleware::Next;
use axum::response::Response;

use crate::service::{ip_location_service, sys_backup_service};

/// 普通请求的处理总时长上限（沿用改造前的值，**一字未改**）：覆盖 Slowloris 慢速攻击
/// 与一切正常业务接口。只有确实存在更长内部预算的端点才进 [`LONG_RUNNING_ROUTES`]。
pub const DEFAULT_TIMEOUT_SECS: u64 = 120;

/// 长任务档相对最长内部预算的余量（秒）。
///
/// 取 60 的理由：预算只覆盖"子进程/下载本体"，而 handler 在预算之外还要做落库、清理缓存、
/// 写审计。没有余量时，"预算刚好用完"的那一次会同时被两层判成超时，归因会指向错误的一层。
const TIMEOUT_SLACK_SECS: u64 = 60;

/// 全部在请求路径上等待的**最长内部预算**（秒）。新增长预算必须同时进这一条，
/// 否则下面的编译期断言会抓住它。
const MAX_INTERNAL_BUDGET_SECS: u64 = {
    let a = sys_backup_service::BACKUP_TIMEOUT_SECS;
    let b = ip_location_service::IP_DOWNLOAD_TIMEOUT_SECS;
    if a > b { a } else { b }
};

/// 长任务档的总时长上限（秒）：**由内部预算派生**，不是另一个记住的数字。
pub const LONG_RUNNING_TIMEOUT_SECS: u64 = MAX_INTERNAL_BUDGET_SECS + TIMEOUT_SLACK_SECS;

// 关系钉住：长任务档必须**严格大于**每一个内部预算，否则本层仍是那条把 300s 操作砍成
// 半截的闸。常量比较在编译期完成——把它调小不会"测试没跑到所以没发现"，而是构建失败。
const _: () = assert!(LONG_RUNNING_TIMEOUT_SECS > sys_backup_service::BACKUP_TIMEOUT_SECS);
const _: () = assert!(LONG_RUNNING_TIMEOUT_SECS > ip_location_service::IP_DOWNLOAD_TIMEOUT_SECS);
// 余量下限同样是编译期事实：它是上面两条"长档 = 预算 + 余量"能成立的前提，
// 有人把余量调到 0 时，长档与 300s 预算相等 ⇒ 预算用完的那一次仍被本层判成超时。
const _: () = assert!(
    TIMEOUT_SLACK_SECS >= 30,
    "余量至少覆盖 handler 在预算之外的落库/清缓存/审计开销"
);

/// 走长任务档的路由模板（与 `src/router/**` 注册**逐字一致**，由形状锁对账）。
///
/// 只登记"handler 在请求 future 内等待 ≥ 一个长预算"的端点。刻意**不**登记的同类：
/// - `GET /system/backup/download/{backupId}`：流式出 body，`next.run()` 的 future 只到
///   **响应头就绪**为止，body 不在本层计时——把下载卷进来只会让档位失去意义；
/// - `POST /system/backup/self-export`、归档下载：同一形状（流式）。
pub const LONG_RUNNING_ROUTES: &[(&Method, &str)] = &[
    (&Method::POST, "/system/backup"),
    (&Method::POST, "/system/backup/restore/{backupId}"),
    (&Method::POST, "/system/ipLocation/update"),
];

/// 某个请求应得的超时档（纯函数，便于逐条证伪）。
///
/// 未命中 [`LONG_RUNNING_ROUTES`] ⇒ 一律默认档（**fail-closed 取更严的一侧**：
/// 新增长任务端点却忘了登记，症状是"那次操作被 120s 砍断"——形状锁会先一步把它拦下，
/// 见 `long_running_routes_are_registered_in_the_router`）。
pub fn timeout_budget(method: &Method, path: &str) -> Duration {
    Duration::from_secs(LONG_RUNNING_ROUTES.iter().fold(
        DEFAULT_TIMEOUT_SECS,
        |acc, (m, template)| {
            if m == method && path_matches_template(template, path) {
                LONG_RUNNING_TIMEOUT_SECS.max(acc)
            } else {
                acc
            }
        },
    ))
}

/// 按路由模板匹配原始路径：`{x}` 段匹配**任意非空**一段，其余逐字相等。
///
/// 刻意不做事前缀匹配——`/system/backup/restore/1/extra` 不是那条路由，命中它等于
/// 给一个不存在的路径发放长预算（慢速攻击者只要构造这种路径就能拿到 360s 的挂起窗口）。
pub fn path_matches_template(template: &str, path: &str) -> bool {
    let t = trim_slashes(template);
    let p = trim_slashes(path);
    let mut tseg = t.split('/');
    let mut pseg = p.split('/');
    loop {
        match (tseg.next(), pseg.next()) {
            (Some(ts), Some(ps)) => {
                if is_wildcard(ts) {
                    if ps.is_empty() {
                        return false;
                    }
                } else if ts != ps {
                    return false;
                }
            }
            (None, None) => return true,
            _ => return false,
        }
    }
}

/// 去掉首尾各一个 `/`（模板与真实路径都以 `/` 开头，统一后按段比较；
/// 尾斜杠差异不该让一条路由静默降档）。
///
/// **两步必须串在同一份中间值上**：`strip_suffix` 的回落只能是"已去掉前导斜杠的那一份"，
/// 写回原始 `s` 会让两侧归一不对称——模板带尾斜杠时被剥成 4 段、路径不带尾斜杠时又退回
/// 带前导空段的 5 段，于是 `path_matches_template("…/{id}/", "…/7")` 恒为 `false`。
/// 症状恰好是本模块要防的那一件事：一条登记过的路由**静默回默认档**。
fn trim_slashes(s: &str) -> &str {
    let s = s.strip_prefix('/').unwrap_or(s);
    s.strip_suffix('/').unwrap_or(s)
}

/// `{x}` 形态的占位段（axum 0.8 语法；`:x` 是 0.6 老写法，本仓不用，形状锁另有判据）。
fn is_wildcard(seg: &str) -> bool {
    seg.starts_with('{') && seg.ends_with('}') && seg.len() > 2
}

/// 应用一个请求的超时：命中长任务档则用长档，否则用默认档；超时产出与既有错误契约
/// 逐字段一致的 408（`body.code == 408` + 本地化 `msg`，不经 `map_status`）。
pub async fn apply_timeout<F>(budget: Duration, fut: F) -> Response
where
    F: Future<Output = Response>,
{
    match tokio::time::timeout(budget, fut).await {
        Ok(response) => response,
        Err(_) => crate::common::response::transport_error(
            StatusCode::REQUEST_TIMEOUT,
            crate::tr!("error.common.request_timeout"),
        ),
    }
}

/// 中间件入口（挂在应用最外层，槽位与改造前的 `.timeout()` 一致）。
pub async fn request_timeout_guard(request: Request, next: Next) -> Response {
    let budget = timeout_budget(request.method(), request.uri().path());
    apply_timeout(budget, next.run(request)).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;

    /// 长任务端点必须拿到长档——**逐条**判，而不是"表里有个数"。
    #[test]
    fn long_running_routes_get_the_long_tier() {
        let cases = [
            (&Method::POST, "/system/backup"),
            (&Method::POST, "/system/backup/restore/7"),
            (&Method::POST, "/system/ipLocation/update"),
        ];
        assert!(
            cases.len() == LONG_RUNNING_ROUTES.len(),
            "档位判据的用例数必须与登记表同数：登记 {} 条 / 判据 {} 条",
            LONG_RUNNING_ROUTES.len(),
            cases.len()
        );
        for (method, path) in cases {
            let budget = timeout_budget(method, path);
            assert_eq!(
                budget.as_secs(),
                LONG_RUNNING_TIMEOUT_SECS,
                "{method} {path} 必须走长档（否则 300s 的操作仍被砍断）"
            );
        }
    }

    /// 同路径族的**其它**方法/路径必须留在默认档——这是"长档不得外溢"的一侧。
    ///
    /// 尤其 `GET /system/backup`：axum 里它与 POST 共用路径，method 不匹配时 405，
    /// 给它长档等于给一个不存在的操作挂 360s 的挂起窗口。
    #[test]
    fn everything_else_stays_on_the_default_tier() {
        let cases = [
            (&Method::GET, "/system/backup"),
            (&Method::GET, "/system/backup/list"),
            (&Method::GET, "/system/backup/7"),
            (&Method::POST, "/system/backup/restore"),
            (&Method::POST, "/system/backup/restore/7/extra"),
            (&Method::POST, "/system/backup/restorex/7"),
            (&Method::POST, "/system/ipLocation/reload"),
            (&Method::PUT, "/system/ipLocation/update"),
            (&Method::POST, "/system/login"),
            (&Method::GET, "/monitor/server"),
        ];
        for (method, path) in cases {
            assert_eq!(
                timeout_budget(method, path).as_secs(),
                DEFAULT_TIMEOUT_SECS,
                "{method} {path} 不得拿到长档"
            );
        }
    }

    /// 模板匹配的形状细节：尾斜杠不降档、空段不放行、通配段必须恰好一段。
    #[test]
    fn template_matching_shapes() {
        assert!(path_matches_template(
            "/system/backup/restore/{backupId}",
            "/system/backup/restore/7"
        ));
        assert!(path_matches_template(
            "/system/backup/restore/{backupId}/",
            "/system/backup/restore/7"
        ));
        // 反方向的同一枚尺：归一必须**对称**。只剥模板的尾斜杠、把路径的尾斜杠留在原地，
        // 两侧段数就不等（本批 `trim_slashes` 的回落写回原始串，正是这一型）。
        assert!(path_matches_template(
            "/system/backup/restore/{backupId}",
            "/system/backup/restore/7/"
        ));
        assert!(
            !path_matches_template("/x/{id}", "/x/"),
            "空段不得命中通配——否则是给不存在的路径发长档"
        );
        assert!(!path_matches_template("/x/{id}", "/x/1/2"));
        assert!(!path_matches_template("/x/{id}", "/x"));
        // 路径侧的字面花括号**必须**照常命中：axum 的 `{id}` 是一个参数段，`{id}` 这三个字符
        // 本身就是一个合法的段值（`GET /x/%7Bid%7D` 解码后正是它，未认证者也能构造出来）。
        // 判"带花括号就不算命中"看着像防呆，实际是给一次真实存在的请求降档——若那条路由
        // 恰好登记在长档，它会被砍在默认档上，正是本模块要防的事。
        assert!(
            path_matches_template("/x/{id}", "/x/{id}"),
            "匹配必须是纯段数比较，不得对路径里的字面花括号另开判据"
        );
    }

    /// 档位关系：判的是**真实入口拿到的实际档位**，不是常量算术。
    ///
    /// 为什么这里不写 `assert!(LONG_RUNNING_TIMEOUT_SECS > …)`：那件事已经由模块顶部的
    /// `const _: () = assert!(…)` 在**编译期**钉住（比任何测试都早，且不会因为"这一轮没人跑到
    /// 这条测试"而失效；clippy 的 `assertions_on_constants` 也正是把这个方向指回 const 块）。
    /// 常量比较判不到的是**这一半**：登记表与匹配函数串起来之后，那条路由**实际**拿到的档位
    /// 是否仍大于它自己的内部预算——本批 `trim_slashes` 的归一缺陷（尾斜杠模板恒不命中）
    /// 恰好只在"走真实函数"这一侧才暴露，常量断言对它永远是绿的。
    #[test]
    fn tier_relations_are_derived_not_remembered() {
        let backup = timeout_budget(&Method::POST, "/system/backup");
        assert!(
            backup.as_secs() > sys_backup_service::BACKUP_TIMEOUT_SECS,
            "整库备份实际拿到 {}s，不大于其子进程预算 ⇒ 半截备份依旧会被本层砍断",
            backup.as_secs()
        );
        let ip = timeout_budget(&Method::POST, "/system/ipLocation/update");
        assert!(
            ip.as_secs() > ip_location_service::IP_DOWNLOAD_TIMEOUT_SECS,
            "IP 库热更新实际拿到 {}s，不大于其下载预算 ⇒ 下载仍会被砍断",
            ip.as_secs()
        );
        assert_eq!(
            DEFAULT_TIMEOUT_SECS, 120,
            "默认档变更需同步 config.toml.example 与本模块文档"
        );
    }

    /// **活体对照**：慢 future 在短预算下必须产出与既有契约逐字段一致的 408，
    /// 在长预算下必须正常返回。这条不测档位表，只测"超时这一件事真的发生了"。
    #[tokio::test]
    async fn timeout_produces_the_unified_408_body() {
        // 快：必须原样穿过
        let fast = apply_timeout(Duration::from_millis(500), async {
            Response::new(Body::from("ok"))
        })
        .await;
        assert_eq!(fast.status(), StatusCode::OK);

        // 慢：必须在预算处被截断，且状态是 408（不是 500、不是裸状态码）
        let slow = apply_timeout(Duration::from_millis(20), async {
            tokio::time::sleep(Duration::from_millis(2_000)).await;
            Response::new(Body::from("never"))
        })
        .await;
        assert_eq!(slow.status(), StatusCode::REQUEST_TIMEOUT);

        let bytes = axum::body::to_bytes(slow.into_body(), 64 * 1024)
            .await
            .expect("408 必须有可读响应体");
        let body: serde_json::Value = serde_json::from_slice(&bytes).expect("408 必须是 JSON");
        assert_eq!(
            body["code"].as_i64(),
            Some(408),
            "错误契约：body.code == HTTP 状态"
        );
        let msg = body["msg"].as_str().unwrap_or_default();
        assert!(!msg.is_empty(), "msg 不得为空");
        assert!(
            !msg.starts_with("error."),
            "键查无文案（tr! 缺键时返回键名本身）: {msg}"
        );
    }

    /// 接线反查：中间件必须真的挂在 router 上，且**旧的固定 `.timeout()` 不得残留**。
    ///
    /// 只判"生产码里出现了函数名"是不够的——同一份文本也可能只活在注释里，
    /// 所以这里读的是去掉注释行之后的真实注册语句。
    #[test]
    fn middleware_is_mounted_and_the_flat_timeout_is_gone() {
        let src =
            std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/router/mod.rs"))
                .expect("router/mod.rs 必须可读（本锁的输入缺失，而非通过）");
        let code: Vec<&str> = src
            .lines()
            .filter(|l| !l.trim_start().starts_with("//"))
            .collect();
        let joined = code.join("\n");
        assert!(
            joined.contains("request_timeout_guard"),
            "分档超时中间件未挂进 router（写了没接线=没写）"
        );
        assert!(
            !joined.contains(".timeout("),
            "router 里仍残留固定 `.timeout(...)`：两条超时同时生效时，较短的那条说了算"
        );
        assert!(
            !joined.contains("REQUEST_TIMEOUT_SECS"),
            "旧的单一超时常量仍在 router 被引用"
        );
    }

    /// 形状锁：登记的每条模板**必须**是 router 真实注册的路由（与限流档位同一纪律）。
    ///
    /// 为什么单独锁：模板写错一个字（`backupId` 拼成 `id` 不影响匹配，但 `/system/backup`
    /// 少写一段、或路由改名成 `/system/backup/create`）会让该端点**静默回到 120s 档**，
    /// 症状与本批立项时完全一致——半截恢复 + 锁泄漏——而没有任何一行为此变红。
    #[test]
    fn long_running_routes_are_registered_in_the_router() {
        let registry = crate::common::prod_scan::router_registry();
        let registered: Vec<String> = crate::common::prod_scan::route_blocks(&registry)
            .into_iter()
            .map(|(path, _)| path)
            .collect();
        assert!(
            registered.len() > 200,
            "路由采集面异常（只数到 {} 条）⇒ 本锁失效，而非路由为空",
            registered.len()
        );
        let mut missing = Vec::new();
        for (_, template) in LONG_RUNNING_ROUTES {
            let needle = format!("\"{template}\"");
            if !registry.contains(&needle) {
                missing.push(*template);
            }
        }
        assert!(
            missing.is_empty(),
            "以下长任务档模板在 router 中找不到同字面量的路由模板（将静默回落默认 120s 档）：{missing:?}"
        );
    }

    /// 形状锁反向：router 里**确实**带着 300s 内部预算的长任务端点不得漏登记。
    ///
    /// 这一条是"新增长任务入口时忘了进档"的载体。判据取代码事实而不是清单：
    /// 备份与 IP 库两条写路径的调用点必须各有一条长档模板覆盖。
    #[test]
    fn every_long_budget_entrypoint_has_a_tier() {
        let covered = |path: &str| {
            LONG_RUNNING_ROUTES
                .iter()
                .any(|(_, template)| *template == path || template.starts_with(path))
        };
        // handler 在请求 future 内 await 子进程/下载的三处
        assert!(
            covered("/system/backup"),
            "整库备份（POST /system/backup）必须有长档"
        );
        assert!(covered("/system/backup/restore/"), "备份恢复必须有长档");
        assert!(
            covered("/system/ipLocation/update"),
            "IP 库热更新必须有长档"
        );

        // 调用点必须真的还在请求路径上（若将来改成后台任务，本锁要先红一次，
        // 由人来撤档——档位不得悄悄留着不管）
        let backup_src = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/src/handler/sys_backup_handler.rs"
        ))
        .expect("备份 handler 必须可读");
        assert!(
            backup_src.contains(".restore_backup("),
            "restore handler 已不再直接 await 恢复体 ⇒ 请复核长档登记是否还需要"
        );
    }

    /// 本锁自身可证伪：正控（真实模板命中采集面）与反证（未注册形态必须不命中）成对。
    #[test]
    fn tier_shape_lock_is_falsifiable() {
        let registry = crate::common::prod_scan::router_registry();
        // 正控：真实模板必须命中
        assert!(registry.contains("\"/system/backup/restore/{backupId}\""));
        // 反证：同一路径族的**未注册**形态必须不命中（写成真实数字路径就静默失配）
        assert!(!registry.contains("\"/system/backup/restore/7\""));
        assert!(!registry.contains("\"/system/backup/create\""));
        // 采集器活性：route_blocks 必须真解析出注册条目（解析器坏 = 空集 = 形状锁恒绿）
        let parsed = crate::common::prod_scan::route_blocks(&registry);
        assert!(
            parsed.iter().any(|(p, _)| p == "/system/backup"),
            "采集器必须解析出 POST 建备那条根路由（当前 {} 条）",
            parsed.len()
        );
    }

    /// **跨仓镜像锁**：前端等待上限必须严格大于本层的长任务档。
    ///
    /// 为什么这一条要长在后端：`stepby-vue` 自己有一份对账（`api/blobTimeout.guard.test.ts`，
    /// b138 立），但它比的是**子进程预算**（300s），而 b140 之前服务端真正的天花板是
    /// 固定 120s——前端"必须等得比服务端久"那句注释所依赖的事实**从来没被任何一侧核对过**，
    /// 于是 330s 的前端上限对着 120s 的服务端超时，症状正是前端注释里写的那句
    /// "任务还在正常跑，前端已经 abort"（这次反过来了：是**服务端**先 abort，且会杀掉子进程）。
    ///
    /// 方向必须是"客户端 > 服务端"：客户端先撤 ⇒ 连接断开 ⇒ handler future 被丢弃 ⇒
    /// `kill_on_drop` 杀掉半截恢复；服务端先撤 ⇒ 客户端收到一个可归因的 408 JSON。
    #[test]
    fn frontend_waits_longer_than_the_server_tier() {
        let mirror = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../stepby-vue/src/utils/timeouts.ts");
        let raw = std::fs::read_to_string(&mirror).unwrap_or_else(|e| {
            panic!(
                "读不到前端超时镜像 {}：{e}（判据源缺失必须响亮失败，不得静默跳过）",
                mirror.display()
            )
        });
        // 刀口只能落在代码上（前言 ⑬）：这份文件为了说明取值理由，把常量名与数字
        // 写进了 JSDoc，按 marker 直接检索会读到注释正文——所以逐行剔除注释行。
        let code_lines: Vec<&str> = raw
            .lines()
            .map(str::trim)
            .filter(|l| !(l.starts_with("//") || l.starts_with('*') || l.starts_with("/*")))
            .collect();
        let hits: Vec<&&str> = code_lines
            .iter()
            .filter(|l| l.starts_with("export const LONG_TASK_TIMEOUT"))
            .collect();
        assert_eq!(
            hits.len(),
            1,
            "前端镜像里 `export const LONG_TASK_TIMEOUT` 必须**恰好一条**（读到 0 条＝解析通道腐化，\
             读到多条＝有人把常量挪进了注释外的地方）：{hits:?}"
        );
        let value = hits[0]
            .split(['=', ';'])
            .nth(1)
            .unwrap_or_default()
            .trim()
            .replace('_', "");
        let client_ms: u64 = value
            .parse()
            .unwrap_or_else(|_| panic!("前端长任务上限解析不出数字：{:?}", hits[0]));
        assert!(
            client_ms > LONG_RUNNING_TIMEOUT_SECS * 1000,
            "前端 LONG_TASK_TIMEOUT={client_ms}ms 必须严格大于服务端长任务档 \
             {LONG_RUNNING_TIMEOUT_SECS}s，否则客户端先撤会杀掉服务端正在跑的子进程"
        );
    }
}
