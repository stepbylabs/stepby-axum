// axum-backend/src/integration_tests/sys_rate_limit.rs
//! API 限流配置模块链路集成测试：
//! - 分页列表 / 详情（种子全局默认 "*"）
//! - 新增 → 修改 → 删除 / 状态切换（enabled 布尔开关）
//! - 异常路径（查询不存在的配置 → 404）

use axum::body::Body;
use axum::extract::connect_info::ConnectInfo;
use axum::http::{Request, StatusCode};
use std::net::SocketAddr;

use super::TestContext;

/// 限流配置全链路（CRUD + 状态切换 + 异常路径）。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_rate_limit_chain() {
    let ctx = TestContext::new().await;

    // 1. 分页列表（种子含全局默认 "*"）
    let v = ctx
        .get_json("/system/rateLimit/list?pageNum=1&pageSize=10")
        .await;
    let rows = v["rows"].as_array().expect("rows 应为数组");
    assert!(!rows.is_empty(), "种子应至少 1 条限流配置，实际: {v}");

    // 2. 详情（定位全局默认 "*" 并校验字段）
    let default_id = rows
        .iter()
        .find(|r| r["routePattern"] == "*")
        .and_then(|r| r["id"].as_i64())
        .expect("种子应有全局默认限流配置");
    let v = ctx
        .get_json(&format!("/system/rateLimit/{}", default_id))
        .await;
    assert_eq!(v["data"]["id"], default_id, "详情 id 应匹配，实际: {v}");
    assert_eq!(
        v["data"]["routePattern"].as_str(),
        Some("*"),
        "全局默认 routePattern 应为 *，实际: {v}"
    );

    // 3. 新增限流规则（it_rl_ 前缀避免与种子冲突）
    let v = ctx
        .post_json(
            "/system/rateLimit",
            serde_json::json!({
                "routePattern": "it_rl_test",
                "capacity": 50,
                "refillPerSecond": 5.0,
                "enabled": true,
                "description": "集成测试限流规则"
            }),
        )
        .await;
    ctx.assert_ok(&v);

    // 4. 按 routePattern 查询到新规则
    let v = ctx
        .get_json("/system/rateLimit/list?routePattern=it_rl_test")
        .await;
    let rows = v["rows"].as_array().expect("rows 应为数组");
    assert_eq!(rows.len(), 1, "应查到 1 条新限流规则，实际: {v}");
    let rl_id = rows[0]["id"].as_i64().expect("id 应为数字");

    // 5. 修改（调整容量与补充速率）
    let v = ctx
        .put_json(
            "/system/rateLimit",
            serde_json::json!({
                "id": rl_id,
                "routePattern": "it_rl_test",
                "capacity": 200,
                "refillPerSecond": 20.0,
                "enabled": true,
                "description": "集成测试限流规则改"
            }),
        )
        .await;
    ctx.assert_ok(&v);
    let v = ctx.get_json(&format!("/system/rateLimit/{}", rl_id)).await;
    assert_eq!(v["data"]["capacity"], 200, "修改后容量应为 200，实际: {v}");

    // 6. 状态切换（enabled 由 true 改为 false = 禁用）
    let v = ctx
        .put_json(
            "/system/rateLimit",
            serde_json::json!({
                "id": rl_id,
                "routePattern": "it_rl_test",
                "capacity": 200,
                "refillPerSecond": 20.0,
                "enabled": false,
                "description": "集成测试限流规则改"
            }),
        )
        .await;
    ctx.assert_ok(&v);
    let v = ctx.get_json(&format!("/system/rateLimit/{}", rl_id)).await;
    assert_eq!(
        v["data"]["enabled"], false,
        "状态切换后 enabled 应为 false，实际: {v}"
    );

    // 7. 删除限流规则（物理删除 + 失效缓存）
    let v = ctx
        .delete_json(&format!("/system/rateLimit/{}", rl_id))
        .await;
    ctx.assert_ok(&v);
    let v = ctx
        .get_json("/system/rateLimit/list?routePattern=it_rl_test")
        .await;
    let rows = v["rows"].as_array().expect("rows 应为数组");
    assert!(rows.is_empty(), "删除后不应再查到该限流规则，实际: {v}");

    // 8. 异常路径：查询不存在的限流配置 → 404
    let mut req = Request::builder()
        .method("GET")
        .uri("/system/rateLimit/999999")
        .header("authorization", format!("Bearer {}", ctx.token))
        .body(Body::empty())
        .expect("构造请求失败");
    req.extensions_mut()
        .insert(ConnectInfo(SocketAddr::from((ctx.peer_ip, 4321))));
    let (status, v) = ctx.send_raw(req).await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "查询不存在的限流配置应返回 404，实际: {status} {v}"
    );
}
