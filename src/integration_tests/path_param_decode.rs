// stepby-axum/src/integration_tests/path_param_decode.rs
//! 路径段百分号解码**往返**契约（批七十四 轮 28，§一.9 的后端一半）。
//!
//! 前端把自由字符串拼进请求路径的 9 处站点已统一 `encodeURIComponent`
//! （`stepby-vue/src/api/**`，并由 `src/api/urlPathSegment.guard.test.ts` 钉住）。
//! 但"前端编码 + 后端不解码"仍然是缺陷：编码只解决"能不能表达"，不解决
//! "有没有真的往返成功"。本测试证明 axum 侧（matchit 百分号解码 → `Path<String>`）
//! 取到的是**原值**，并按原值命中数据行。
//!
//! 判据三侧（缺一即假绿）：
//! 1. 编码形态必须命中原值那一行（正向）；
//! 2. **对照组**：不含特殊字符的普通键必须照常命中（否则"永远查不到"也能骗过①）；
//! 3. 反向：把原值裸发（`#` 未编码）时**不得**命中该行——证明编码是真有必要，
//!    而不是"怎么发都一样"。
//!
//! 逐例收集结果后统一断言（不在循环里 panic）：失败信息必须一次看全四种形态，
//! 否则"第一个红的 case"会掩盖后面还红了几条。

use super::TestContext;
use crate::entity::sys_config;
use axum::body::Body;
use axum::extract::connect_info::ConnectInfo;
use axum::http::{HeaderName, HeaderValue, Method, Request};
use sea_orm::{ActiveValue::Set, ColumnTrait, EntityTrait, QueryFilter};
use std::net::SocketAddr;

/// 直接落库一行参数（绕过表单的字符集校验，专门构造"键名含特殊字符"的形态）
async fn seed_config(ctx: &TestContext, key: &str, value: &str) {
    let am = sys_config::ActiveModel {
        tenant_id: Set(0),
        config_name: Set(Some(format!("路径解码用例 {key}"))),
        config_key: Set(key.to_string()),
        config_value: Set(Some(value.to_string())),
        config_type: Set(Some("N".to_string())),
        ..Default::default()
    };
    sys_config::Entity::insert(am)
        .exec(&ctx.state.db)
        .await
        .expect("播种参数配置应成功");
}

/// GET 并返回 `(HTTP 码, 业务码, data 字段, msg 字段)`——非 200 不 panic，供逐例对账
async fn get_code(ctx: &TestContext, uri: &str) -> (u16, i64, String, String) {
    let mut req = Request::builder()
        .method(Method::GET)
        .uri(uri)
        .header("authorization", format!("Bearer {}", ctx.token))
        .body(Body::empty())
        .expect("构造请求失败");
    // 与 harness 同一 peer IP：限流按 (租户,IP) 分桶，缺 ConnectInfo 会落到默认桶
    let peer: SocketAddr = (ctx.peer_ip, 4321).into();
    req.extensions_mut().insert(ConnectInfo(peer));
    let (status, v) = ctx.send_raw(req).await;
    (
        status.as_u16(),
        v["code"].as_i64().unwrap_or(-1),
        v["data"].as_str().unwrap_or_default().to_string(),
        v["msg"].as_str().unwrap_or_default().to_string(),
    )
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn it_path_segment_percent_encoding_roundtrips() {
    let ctx = TestContext::new().await;

    // (原值键名, 前端 encodeURIComponent 后的形态)
    let cases = [
        ("it.dot-key", "it.dot-key"),
        ("it#hash-key", "it%23hash-key"),
        ("it space key", "it%20space%20key"),
        ("it/slash/key", "it%2Fslash%2Fkey"),
    ];
    for (raw, _) in &cases {
        seed_config(&ctx, raw, &format!("v::{raw}")).await;
    }

    // ① 正向 + ② 对照：每个编码形态都必须命中原值那一行
    let mut bad: Vec<String> = Vec::new();
    for (raw, encoded) in &cases {
        let (http, code, data, _) =
            get_code(&ctx, &format!("/system/config/configKey/{encoded}")).await;
        let want = format!("v::{raw}");
        if http != 200 || code != 200 || data != want {
            bad.push(format!(
                "原值={raw} 编码={encoded} ⇒ HTTP {http} code={code} data={data:?}（期望 {want:?}）"
            ));
        }
    }

    // ③ 反向：把含 `#` 的原值裸发 ⇒ `#` 之后被当片段丢弃，路径落到 `it`，
    //    必须取不到该行（若这里"照样命中"，说明①没有真检验任何东西）
    let (raw_http, raw_code, raw_data, _) =
        get_code(&ctx, "/system/config/configKey/it#hash-key").await;
    assert_ne!(
        raw_data, "v::it#hash-key",
        "未编码的 `#` 原值竟命中了目标行 ⇒ 本测试的编码必要性判据失效"
    );

    assert!(
        bad.is_empty(),
        "路径段百分号编码未往返命中（逐例）：\n{}\n裸发原值侧记录：HTTP {raw_http} code={raw_code} data={raw_data:?}",
        bad.join("\n")
    );
    // 反向侧必须"没命中"，同时不能把整条链路弄崩（404/业务码非 200 都算诚实拒绝）
    assert!(
        raw_code != 200,
        "裸发 `#` 竟然返回业务码 200 —— 说明命中的是别的行，判据③不成立"
    );

    // 清理：删除播种行（teardown 兜底，避免污染 seed_diff / 其它用例的分页断言）
    for (raw, _) in &cases {
        let _ = sys_config::Entity::delete_many()
            .filter(sys_config::Column::ConfigKey.eq(raw.to_string()))
            .exec(&ctx.state.db)
            .await;
    }
}

/// 请求行长度上限（批七十四 B2）：三侧判据。
///
/// 改造前实测（本文件的前一版探测）：1KB / 7KB / 14KB / **59KB** 查询串一律 HTTP 200
/// 进业务层——`DefaultBodyLimit` 只作用于请求体，查询串完全没有上限。
///
/// - ① 超限 ⇒ 414 + 统一错误体（`code` 与 HTTP 同码，C.8）；
/// - ② **对照组**：默认档之下、远超真实最长查询串的 8KB 必须照常 200（否则就是
///   "为安全把合法请求挡掉"）；
/// - ③ 翻档 `max_uri_bytes = 0` ⇒ 同一超长请求回到 200（"0 = 不限制"的回退口径真实可用，
///   不是写在注释里的假开关）。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn it_overlong_query_string_is_rejected() {
    let ctx = TestContext::new().await;
    let huge = format!("/system/user/list?title={}", "x".repeat(40_000));
    let (http, code, _, msg) = get_code(&ctx, &huge).await;
    assert_eq!(http, 414, "超长查询串必须被拒（414），实际 HTTP {http}");
    assert_eq!(
        code, 414,
        "错误体 code 必须与 HTTP 同码（C.8），实际 {code}"
    );
    // ①b 文案三判据。b74 新登记的缺陷类别：rust_i18n **查不到键时把键名原样返回**，
    // 于是 HTTP 414 对、`code` 对、`msg` 却是 `error.common.uri_too_long`（本批实测
    // `error.dataRule.*` 八条就是这个形状）。键解析总锁见 `common::i18n::tests`，
    // 这里是它在真实出网上的那一面。
    assert!(
        !msg.is_empty() && !msg.contains("error."),
        "414 文案必须是本地化文本而不是 i18n 键名（键名出现在响应体＝键没落在正确的节下），\
         实际 msg={msg:?}"
    );
    assert!(
        msg.contains("16384"),
        "文案必须回显**实际生效**的上限（管理员调档后要知道现在是多少，C.7 反例），\
         实际 msg={msg:?}"
    );
    // 用户超长输入不得被回显进错误体（查询串常含 token / 验证码，C.9）
    assert!(
        !msg.contains(&"x".repeat(64)),
        "错误体回显了用户超长输入: {msg}"
    );

    // ② 对照组：8KB 仍远在默认 16KB 之下，必须照常处理
    let ok = format!("/system/user/list?title={}", "y".repeat(8_000));
    let (ok_http, ok_code, _, _) = get_code(&ctx, &ok).await;
    assert_eq!(
        ok_code, 200,
        "8KB 查询串（合法量级）被挡 ⇒ 上限取小了：HTTP {ok_http} code={ok_code}"
    );

    // ③ 翻档为 0 ⇒ 完全不设限（部署态开关必须在用例内显式声明，不依赖 ambient config）
    let off = TestContext::new_with(&[], |s| s.server.max_uri_bytes = 0).await;
    let (off_http, off_code, _, _) = get_code(&off, &huge).await;
    assert_eq!(
        off_code, 200,
        "max_uri_bytes=0 应回到改造前行为（不设限），实际 HTTP {off_http} code={off_code}"
    );
}

/// 带一个额外请求头的 GET（批七十五 B7 请求头闸门用）
async fn get_with_header(ctx: &TestContext, name: &str, value: &str) -> (u16, i64, String, String) {
    let mut req = Request::builder()
        .method(Method::GET)
        .uri("/system/user/list?pageNum=1&pageSize=10")
        .header("authorization", format!("Bearer {}", ctx.token))
        .header(name, value)
        .body(Body::empty())
        .expect("构造请求失败");
    let peer: SocketAddr = (ctx.peer_ip, 4321).into();
    req.extensions_mut().insert(ConnectInfo(peer));
    let (status, v) = ctx.send_raw(req).await;
    (
        status.as_u16(),
        v["code"].as_i64().unwrap_or(-1),
        v["data"].as_str().unwrap_or_default().to_string(),
        v["msg"].as_str().unwrap_or_default().to_string(),
    )
}

/// 批七十五 B7：请求行计量必须是**整条 request-target**，不能只有"路径+查询串"。
///
/// 旧判据量 `Uri::path_and_query()`，它只覆盖 origin-form：
/// - absolute-form（`GET http://host/a?b=1`，代理转发的标准形态）里 `http://host`
///   整段不计入 ⇒ **换个请求行写法就绕过上限**；
/// - authority-form（`CONNECT host:443`）计量恒为 0（实测，见
///   `uri_limit::tests::request_target_len_matches_serialized_uri` 的控制组）。
/// options-form（`OPTIONS *`）新旧口径都是 1，不在被绕过之列。
///
/// 判据双侧：同一查询串在 origin-form 恰好等于上限 ⇒ 必须放行（200）；
/// 加上 `http://localhost:8080` 前缀后整条超上限 ⇒ 必须 414。
/// 只有前一条会红才说明计量真的换了对象，否则本用例可以靠"永远放行"骗过。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn it_absolute_form_request_line_is_measured_whole() {
    let ctx = TestContext::new_with(&[], |s| s.server.max_uri_bytes = 100).await;

    // 恰好等于上限的 origin-form：95 字节路径 + 补位 ⇒ 长度 = 100
    let prefix = "/system/user/list?title=";
    let pq = format!("{prefix}{}", "x".repeat(100 - prefix.len()));
    assert_eq!(
        pq.len(),
        100,
        "构造前提失效：origin-form 应恰好等于上限（等号必须放行）"
    );
    let (http, code, _, msg) = get_code(&ctx, &pq).await;
    assert_eq!(
        code, 200,
        "恰好等于上限的请求必须照常处理，实际 HTTP {http} code={code} msg={msg}"
    );

    // 同一条请求换成 absolute-form：整条 request-target = 21 + 100 > 100 ⇒ 必须 414
    let abs = format!("http://localhost:8080{pq}");
    assert!(
        abs.len() > 100,
        "构造前提失效：absolute-form 应超上限（实际 {} 字节）",
        abs.len()
    );
    let (a_http, a_code, _, a_msg) = get_code(&ctx, &abs).await;
    assert_eq!(
        a_http, 414,
        "absolute-form 的 scheme+authority 必须计入请求行计量（旧口径在此放行），\
         实际 HTTP {a_http} code={a_code}"
    );
    assert_eq!(
        a_code, 414,
        "错误体 code 必须与 HTTP 同码（C.8），实际 {a_code}"
    );
    assert!(
        !a_msg.contains("error.") && a_msg.contains("100"),
        "文案须是本地化文本且回显**实际档位**，实际 msg={a_msg:?}"
    );
    assert!(
        !a_msg.contains(&"x".repeat(32)),
        "错误体不得回显用户超长输入: {a_msg}"
    );
}

/// 批七十五 B7：请求头字节上限（431）。三侧判据与 414 完全同构。
///
/// 现状边界（写进配置注释，此处只做行为证明）：hyper 默认封 100 **条**、
/// 整个请求头块受读缓冲 417792 字节约束，但没有"按字节"这一维的独立档位；
/// 本闸把这一维收到可配档位，且**跑在解析之后**（挡过大请求进业务层，不是解析器上限）。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn it_overlong_request_headers_are_rejected_with_431() {
    // ① 超限：512 字节档位 + 1KB 头值
    let ctx = TestContext::new_with(&[], |s| s.server.max_header_bytes = 512).await;
    let (http, code, _, msg) = get_with_header(&ctx, "x-huge", &"z".repeat(1024)).await;
    assert_eq!(
        http, 431,
        "超限请求头必须被拒（431），实际 HTTP {http} code={code}"
    );
    assert_eq!(
        code, 431,
        "错误体 code 必须与 HTTP 同码（C.8），实际 {code}"
    );
    assert!(
        !msg.is_empty() && !msg.contains("error."),
        "431 文案必须是本地化文本而不是 i18n 键名，实际 msg={msg:?}"
    );
    assert!(
        msg.contains("512"),
        "文案必须回显**实际生效**的上限（C.7 反例：显示一个值、行为是另一个值），实际 {msg:?}"
    );
    assert!(
        !msg.contains(&"z".repeat(32)),
        "头值绝不进错误体（Authorization / Cookie 都是凭据，C.9）: {msg}"
    );

    // ② 对照组：默认档（64 KiB）下同一 1KB 头必须照常处理——否则上限取小了
    let def = TestContext::new().await;
    let (d_http, d_code, _, d_msg) = get_with_header(&def, "x-huge", &"z".repeat(1024)).await;
    assert_eq!(
        d_code, 200,
        "1KB 头远在默认 64KiB 之下却被挡 ⇒ 上限取小了：HTTP {d_http} code={d_code} msg={d_msg}"
    );

    // ③ 翻档 0 ⇒ 不设限（回退口径必须真实可用，不是写在注释里的假开关）
    let off = TestContext::new_with(&[], |s| s.server.max_header_bytes = 0).await;
    let (o_http, o_code, _, _) = get_with_header(&off, "x-huge", &"z".repeat(1024)).await;
    assert_eq!(
        o_code, 200,
        "max_header_bytes=0 应回到改造前行为（不设限），实际 HTTP {o_http} code={o_code}"
    );

    // ④ 重复同名头逐条计入（否则"拆成 100 个小头"即可绕过）
    let many = TestContext::new_with(&[], |s| s.server.max_header_bytes = 512).await;
    let mut req = Request::builder()
        .method(Method::GET)
        .uri("/system/user/list?pageNum=1&pageSize=10")
        .header("authorization", format!("Bearer {}", many.token))
        .body(Body::empty())
        .expect("构造请求失败");
    for i in 0..20 {
        let value = format!("p{i}-{}", "p".repeat(60));
        req.headers_mut().append(
            HeaderName::from_static("x-pad"),
            HeaderValue::from_str(&value).expect("头值应为合法 ASCII"),
        );
    }
    let peer: SocketAddr = (many.peer_ip, 4321).into();
    req.extensions_mut().insert(ConnectInfo(peer));
    let (m_http, m_v) = many.send_raw(req).await;
    assert_eq!(
        m_http.as_u16(),
        431,
        "多条小头累加超限同样必须被拒（判据按总量而非单条），实际: {m_v}"
    );
}

/// 六类自由字符串路径参数的**提取形状**：必须是 `Path<String>`（走框架解码），/// 而不是自己从 URI 里切字符串。这是"为什么在 configKey 上取证即可覆盖全族"的依据。
#[test]
fn free_string_path_params_are_extracted_by_the_framework() {
    let sites = [
        (
            "src/handler/monitor_cache_handler.rs",
            "Path(cache_name): Path<String>",
        ),
        (
            "src/handler/monitor_cache_handler.rs",
            "Path(cache_key): Path<String>",
        ),
        (
            "src/handler/sys_logininfor_handler.rs",
            "Path(user_name): Path<String>",
        ),
        (
            "src/handler/sys_config_handler.rs",
            "Path(config_key): Path<String>",
        ),
        (
            "src/handler/sys_dict_handler.rs",
            "Path(dict_type): Path<String>",
        ),
    ];
    for (rel, needle) in sites {
        let src =
            std::fs::read_to_string(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(rel))
                .unwrap_or_else(|e| panic!("读取 {rel} 失败: {e}"));
        assert!(
            src.contains(needle),
            "{rel} 缺少 `{needle}` ⇒ 该路径参数不再由框架解码，前端编码将不再往返无损"
        );
    }
}

/// 缓存前缀白名单的**编码态与明文态必须同一结局**（b74 F1 同族，本批实测过的一条）。
///
/// `/monitor/cache/getKeys/{cacheName}` 的入参是本仓固定白名单
/// （`sys_config:` / `dict:` / `captcha:` …），**这些名字本身含冒号** ⇒ 前端
/// `encodeURIComponent` 后必然变成 `sys_config%3A`。axum 的 `Path<String>` 会把
/// `%3A` 解回 `:`，所以两种形态必须命中同一个白名单项：
/// - 若哪天改成手工切 URI（不解码），编码态会落进"不允许操作缓存前缀"的 400，
///   缓存页显示空列表——**看起来像"缓存是空的"，实际是入参没还原**，属静默失效；
/// - 本判据同时钉住"编码形态不被多解一次"（`sys_config%253A` 不该被解成 `sys_config:`）。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn it_cache_prefix_encoded_form_matches_plain_form() {
    let ctx = TestContext::new().await;
    let plain = get_code(&ctx, "/monitor/cache/getKeys/sys_config:").await;
    let encoded = get_code(&ctx, "/monitor/cache/getKeys/sys_config%3A").await;
    assert_eq!(
        plain.1, encoded.1,
        "同一缓存前缀的明文态/编码态业务码不一致：明文 {plain:?} vs 编码 {encoded:?}"
    );
    assert_eq!(
        encoded.1, 200,
        "编码态缓存前缀必须被识别（400 = 入参未还原，缓存页会伪装成\"空缓存\"）：{encoded:?}"
    );

    // 反向对照：双重编码不得被"顺手解一层"洗成合法前缀
    let double = get_code(&ctx, "/monitor/cache/getKeys/sys_config%253A").await;
    assert_ne!(
        double.1, 200,
        "双重编码形态不得被认成合法前缀（会把误传的键名静默解析成另一个目标）：{double:?}"
    );
}
