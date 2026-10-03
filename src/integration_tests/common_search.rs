// stepby-axum/src/integration_tests/common_search.rs
//! 全局搜索 + 数据库连接池监控链路集成测试：
//! - GET /monitor/db-pool：200 且字段齐全（dbKind 非空、poolSize/numIdle/busy/maxConn 数值）
//! - GET /common/global-search：命中已知记录（q=admin 命中 user 域）、
//!   q 过短空结果、limit 硬顶生效、title/url 非空
//!
//! 数据说明：
//! - 测试库使用 sqlite + 全量迁移种子（admin/admin123 用户必在），dbKind 断言为 "sqlite"；
//! - admin 是超管（`*:*:*`），global-search 逐域权限检查全域放行。

use super::TestContext;

/// GET /monitor/db-pool：200 且字段齐全。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_db_pool_endpoint() {
    let ctx = TestContext::new().await;

    let v = ctx.get_json("/monitor/db-pool").await;
    let data = v["data"]
        .as_object()
        .expect("data 应为对象，实际: {v}");

    // 测试隔离库为 sqlite，dbKind 必须真实反映方言且非空
    let db_kind = data["dbKind"]
        .as_str()
        .expect("dbKind 应为字符串，实际: {v}");
    assert!(!db_kind.is_empty(), "dbKind 不应为空，实际: {v}");
    assert_eq!(db_kind, "sqlite", "测试库为 sqlite，实际: {v}");

    // 数值字段齐全：poolSize / numIdle / busy / maxConn
    assert!(
        data["poolSize"].is_number(),
        "poolSize 应为数字，实际: {v}"
    );
    assert!(
        data["numIdle"].is_number(),
        "numIdle 应为数字，实际: {v}"
    );
    assert!(data["busy"].is_number(), "busy 应为数字，实际: {v}");
    assert!(
        data["maxConn"].is_number(),
        "maxConn 应为数字，实际: {v}"
    );
    assert!(
        data["maxConn"].as_u64().unwrap_or(0) > 0,
        "maxConn 应大于 0（来自 settings.database.max_connections），实际: {v}"
    );
    // 语义一致性：busy = poolSize - numIdle（下溢保护为 0）
    let pool_size = data["poolSize"].as_u64().unwrap_or(0);
    let num_idle = data["numIdle"].as_u64().unwrap_or(0);
    let busy = data["busy"].as_u64().unwrap_or(0);
    assert_eq!(
        busy,
        pool_size.saturating_sub(num_idle),
        "busy 应等于 poolSize - numIdle，实际: {v}"
    );
}

/// GET /common/global-search：命中已知记录 + 过短空结果 + limit 生效 + title/url 非空。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_global_search_chain() {
    let ctx = TestContext::new().await;

    // 1. 命中已知记录：q=admin 应命中 user 域的 admin 用户（前缀命中排前）
    let v = ctx.get_json("/common/global-search?q=admin").await;
    let items = v["data"]
        .as_array()
        .expect("data 应为数组，实际: {v}");
    assert!(!items.is_empty(), "q=admin 应至少命中 admin 用户，实际: {v}");
    let user_hit = items
        .iter()
        .find(|i| i["type"] == "user")
        .expect("q=admin 应命中 user 域，实际: {v}");
    assert_eq!(
        user_hit["title"].as_str(),
        Some("admin"),
        "应命中 admin 用户名，实际: {v}"
    );

    // 2. 全部结果字段契约：type/id/title/url 齐全且 title/url 非空
    for item in items {
        assert!(
            !item["title"].as_str().unwrap_or("").is_empty(),
            "title 不应为空，实际: {item}"
        );
        assert!(
            !item["url"].as_str().unwrap_or("").is_empty(),
            "url 不应为空，实际: {item}"
        );
        assert!(
            item["url"].as_str().unwrap_or("").starts_with('/'),
            "url 应为前端路由路径（/ 开头），实际: {item}"
        );
        assert!(item["id"].is_i64(), "id 应为整数，实际: {item}");
    }

    // 3. q 过短（1 字符）→ 空结果（不打 DB）
    let v = ctx.get_json("/common/global-search?q=a").await;
    let items = v["data"].as_array().expect("data 应为数组，实际: {v}");
    assert!(
        items.is_empty(),
        "q 长度不足 2 字符应返回空结果，实际: {v}"
    );

    // 4. limit 硬顶生效：limit=1 时总条数不超过 1
    let v = ctx.get_json("/common/global-search?q=admin&limit=1").await;
    let items = v["data"].as_array().expect("data 应为数组，实际: {v}");
    assert!(
        items.len() <= 1,
        "limit=1 时总条数应不超过 1，实际: {v}"
    );
    assert!(
        !items.is_empty(),
        "q=admin&limit=1 仍应命中至少 1 条，实际: {v}"
    );

    // 5. limit 缺省默认 10 且不超过 20：limit=100 超额请求被钳制
    let v = ctx.get_json("/common/global-search?q=admin&limit=100").await;
    let items = v["data"].as_array().expect("data 应为数组，实际: {v}");
    assert!(
        items.len() <= 20,
        "limit 硬顶 20，实际: {v}"
    );
}
