// backend-axum/src/integration_tests/response_cache.rs
//! P3-6：HTTP 响应缓存层集成测试
//!
//! 通过真实应用栈（build_app + 隔离 DB/Redis）验证缓存中间件行为。
//!
//! 设计要点（与收紧后的白名单语义一致，规避"写操作 → 缓存不失效 → 脏读"）：
//! - 白名单仅保留纯静态下拉 `/system/dict/type/optionselect`；该接口幂等且内容
//!   与用户/会话无关，两次请求响应体应全等（命中缓存不重查）。
//! - 可变资源接口（`dict/data/type/*`、`configKey/*` 等）**不进入白名单**，
//!   故"改数据后再查"必然反映最新状态，绝无脏读。
//! - 非 GET（如 POST）不缓存，写操作真实落库、响应即时。

use axum::body::to_bytes;
use axum::http::Method;
use tower::ServiceExt;

use super::TestContext;

/// 原始 GET 请求，返回 (Content-Type, 响应体字节)。
async fn raw_get(ctx: &TestContext, uri: &str) -> (String, Vec<u8>) {
    let resp = ctx
        .app
        .clone()
        .oneshot(ctx.request(Method::GET, uri, None))
        .await
        .expect("请求执行失败");
    let (parts, body) = resp.into_parts();
    let ct = parts
        .headers
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let bytes = to_bytes(body, usize::MAX)
        .await
        .expect("读取响应体失败")
        .to_vec();
    (ct, bytes)
}

/// 断言原始字节响应体的业务码 code == 200。
fn assert_ok_bytes(bytes: &[u8]) {
    let v: serde_json::Value = serde_json::from_slice(bytes).expect("响应应为合法 JSON");
    assert_eq!(v["code"], 200, "业务码应为 200，实际: {v}");
}

/// (a) 白名单纯静态下拉：`/system/dict/type/optionselect` 两次响应体全等（命中缓存），
/// 且 Content-Type 一致。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_whitelist_optionselect_is_cached() {
    let ctx = TestContext::new().await;

    let (ct1, b1) = raw_get(&ctx, "/system/dict/type/optionselect").await;
    assert_ok_bytes(&b1);
    let (ct2, b2) = raw_get(&ctx, "/system/dict/type/optionselect").await;
    assert_eq!(
        b1, b2,
        "字典类型下拉为白名单 GET，两次响应体应原样复用（命中缓存）"
    );
    assert_eq!(ct1, ct2, "命中缓存时 Content-Type 应一致");
    assert!(!b1.is_empty(), "响应体不应为空");
}

/// (b) 可变资源接口不入缓存：`/system/dict/data/type/*` 改为数据后再查必反映最新状态。
///
/// 强证明缓存未污染可变资源：先创建字典类型+数据并用 type 查询，随后「删除数据」，
/// 再次查询该 type 应返回空——若误入缓存则会返回删除前的数据（脏读）。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_mutable_dict_data_not_cached() {
    let ctx = TestContext::new().await;

    // 创建独立字典类型
    ctx.post_json(
        "/system/dict/type",
        serde_json::json!({
            "dictName": "缓存可变验证",
            "dictType": "it_cache_var_type",
            "status": "0",
            "remark": "response_cache"
        }),
    )
    .await;

    // 新增一条字典数据
    ctx.post_json(
        "/system/dict/data",
        serde_json::json!({
            "dictSort": 1,
            "dictLabel": "可变标签",
            "dictValue": "VAR",
            "dictType": "it_cache_var_type",
            "status": "0",
        }),
    )
    .await;

    // 按类型查询：应查到 1 条
    let (_, b1) = raw_get(&ctx, "/system/dict/data/type/it_cache_var_type").await;
    let binding1 = serde_json::from_slice::<serde_json::Value>(&b1).expect("响应应为 JSON");
    let data1 = binding1["data"].as_array().expect("data 应为数组");
    assert_eq!(data1.len(), 1, "应查到 1 条字典数据，实际: {b1:?}");

    // 删除该条数据（写操作，不走缓存、真实落库）
    let dict_code = data1[0]["dictCode"].as_i64().expect("dictCode 应为数字");
    ctx.delete_json(&format!("/system/dict/data/{}", dict_code))
        .await;

    // 再次按类型查询：因 dict/data/type/* 不入缓存，应返回空（真实反映删除），而非命中旧缓存
    let (_, b2) = raw_get(&ctx, "/system/dict/data/type/it_cache_var_type").await;
    let binding2 = serde_json::from_slice::<serde_json::Value>(&b2).expect("响应应为 JSON");
    let data2 = binding2["data"].as_array().expect("data 应为数组");
    assert_eq!(
        data2.len(),
        0,
        "可变资源接口未命中缓存，删除后应返回空（无脏读），实际: {b2:?}"
    );
}

/// (b') 可变资源接口不入缓存：`configKey/*` 修改后再查必反映最新值。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_mutable_config_not_cached() {
    let ctx = TestContext::new().await;

    // 新增参数
    ctx.post_json(
        "/system/config",
        serde_json::json!({
            "configName": "缓存可变参数",
            "configKey": "it.cache.var",
            "configValue": "v1",
            "configType": "Y",
        }),
    )
    .await;

    // 按 key 查：v1
    let (_, b1) = raw_get(&ctx, "/system/config/configKey/it.cache.var").await;
    let binding_c1 = serde_json::from_slice::<serde_json::Value>(&b1).expect("响应应为 JSON");
    let val1 = binding_c1["data"].as_str().map(|s| s.to_string());
    assert_eq!(val1.as_deref(), Some("v1"), "首次查询应为 v1，实际: {b1:?}");

    // 修改为 v2（写操作真实落库）
    let v = ctx
        .get_json("/system/config/list?configKey=it.cache.var")
        .await;
    let config_id = v["rows"][0]["configId"].as_i64().expect("应查到 configId");
    ctx.put_json(
        "/system/config",
        serde_json::json!({
            "configId": config_id,
            "configKey": "it.cache.var",
            "configValue": "v2",
        }),
    )
    .await;

    // 再次按 key 查：应为 v2（configKey/* 不入缓存，反映最新值，无脏读）
    let (_, b2) = raw_get(&ctx, "/system/config/configKey/it.cache.var").await;
    let binding_c2 = serde_json::from_slice::<serde_json::Value>(&b2).expect("响应应为 JSON");
    let val2 = binding_c2["data"].as_str().map(|s| s.to_string());
    assert_eq!(
        val2.as_deref(),
        Some("v2"),
        "可变资源配置未命中缓存，改后应反映 v2（无脏读），实际: {b2:?}"
    );
}

/// (c) 非白名单 GET：不缓存（连续两次 body 随数据变化而变化，不被缓存拦截）。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_non_whitelist_get_not_cached() {
    let ctx = TestContext::new().await;

    // 首次 GET：空列表（新增前）
    let (_, b1) = raw_get(&ctx, "/system/dict/data/list?dictType=it_noncache_type").await;
    let rows1 = serde_json::from_slice::<serde_json::Value>(&b1).expect("响应应为 JSON")["rows"]
        .as_array()
        .expect("rows 应为数组")
        .len();

    // 先建类型再新增数据，确保可真实落库
    ctx.post_json(
        "/system/dict/type",
        serde_json::json!({
            "dictName": "非白名单验证",
            "dictType": "it_noncache_type",
            "status": "0",
            "remark": "response_cache"
        }),
    )
    .await;
    ctx.post_json(
        "/system/dict/data",
        serde_json::json!({
            "dictSort": 1,
            "dictLabel": "非缓存标签",
            "dictValue": "NC",
            "dictType": "it_noncache_type",
            "status": "0",
        }),
    )
    .await;

    // 再次 GET：因非白名单不缓存，应反映新增数据（body 与 rows 均变化）
    let (_, b2) = raw_get(&ctx, "/system/dict/data/list?dictType=it_noncache_type").await;
    let rows2 = serde_json::from_slice::<serde_json::Value>(&b2).expect("响应应为 JSON")["rows"]
        .as_array()
        .expect("rows 应为数组")
        .len();
    assert_eq!(rows1, 0, "首次应无数据，实际 {rows1}");
    assert_eq!(
        rows2, 1,
        "非白名单 GET 应反映新增数据（未被缓存），实际 {rows2}"
    );
    assert_ne!(b1, b2, "非白名单 GET 响应体应随数据变化而变化");
}

/// (d) 幂等 POST：不被缓存（写操作真实落库、响应即时，走原逻辑）。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_post_not_cached() {
    let ctx = TestContext::new().await;

    // 先建类型
    ctx.post_json(
        "/system/dict/type",
        serde_json::json!({
            "dictName": "POST验证",
            "dictType": "it_post_type",
            "status": "0",
        }),
    )
    .await;

    // POST 写操作应真实执行并立即响应成功
    ctx.post_json(
        "/system/dict/data",
        serde_json::json!({
            "dictSort": 1,
            "dictLabel": "POST标签",
            "dictValue": "P",
            "dictType": "it_post_type",
            "status": "0",
        }),
    )
    .await;

    // POST 后立即 GET 应能看到新记录 → 证明 POST 未被缓存层吞掉/延迟
    let v = ctx
        .get_json("/system/dict/data/list?dictType=it_post_type")
        .await;
    let rows = v["rows"].as_array().expect("rows 应为数组");
    assert_eq!(rows.len(), 1, "POST 应真实写库并立即可查，实际: {v}");

    // 第二个不同 body 的 POST 也应真实执行（缓存不拦截写操作）
    ctx.post_json(
        "/system/dict/data",
        serde_json::json!({
            "dictSort": 2,
            "dictLabel": "POST标签2",
            "dictValue": "P2",
            "dictType": "it_post_type",
            "status": "0",
        }),
    )
    .await;
    let v2 = ctx
        .get_json("/system/dict/data/list?dictType=it_post_type")
        .await;
    let rows2 = v2["rows"].as_array().expect("rows 应为数组");
    assert_eq!(rows2.len(), 2, "第二个 POST 应真实执行，实际: {v2}");
}
