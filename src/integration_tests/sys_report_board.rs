// stepby-axum/src/integration_tests/sys_report_board.rs
//! 报表看板（配置化只读报表 v1）链路集成测试：
//! - 数据源白名单端点：/sources 返回白名单清单
//! - 保存/回读 config（创建 → 详情 → 更新 → 清单 → 删除）
//! - 白名单外 sourceKey → 400（防任意 URL/SQL 注入面）
//! - 他人配置不可读（404 语义，不区分"不存在"与"非本人"）
//! - 同名看板 400；非法 range 400

use axum::body::Body;
use axum::extract::connect_info::ConnectInfo;
use axum::http::{Method, Request, StatusCode};
use std::net::SocketAddr;

use super::{TestContext, login};

/// 合法看板配置 JSON（一张折线卡片，数据源在白名单内）
fn valid_config() -> serde_json::Value {
    serde_json::json!({
        "cards": [
            {
                "id": "c1",
                "title": "登录趋势",
                "chartType": "line",
                "sourceKey": "login_trend",
                "size": { "w": 2, "h": 1 }
            }
        ]
    })
}

/// 以指定 bearer 令牌构造请求（自动补 ConnectInfo 扩展，限流/审计按测试隔离）。
fn bearer_json_request(
    ctx: &TestContext,
    bearer: &str,
    method: Method,
    uri: &str,
    body: Option<serde_json::Value>,
) -> Request<Body> {
    let builder = Request::builder()
        .method(method)
        .uri(uri)
        .header("authorization", format!("Bearer {bearer}"));
    let mut req = match body {
        Some(b) => builder
            .header("content-type", "application/json")
            .body(Body::from(b.to_string()))
            .expect("构造请求失败"),
        None => builder.body(Body::empty()).expect("构造请求失败"),
    };
    req.extensions_mut()
        .insert(ConnectInfo(SocketAddr::from((ctx.peer_ip, 4321))));
    req
}

/// 全链路：sources → 创建/回读/更新/清单/删除 + 异常路径。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_report_board_chain() {
    let ctx = TestContext::new().await;

    // 1. 数据源白名单端点：返回 6 个登记数据源
    let v = ctx.get_json("/tool/report-board/sources").await;
    ctx.assert_ok(&v);
    let items = v["data"].as_array().expect("sources 应为数组");
    assert_eq!(items.len(), 6, "白名单应有 6 个数据源，实际: {items:?}");
    assert!(
        items
            .iter()
            .any(|s| s["sourceKey"].as_str() == Some("login_trend")),
        "白名单应含 login_trend，实际: {items:?}"
    );

    // 2. 创建看板 → 返回强类型 config
    let v = ctx
        .post_json(
            "/tool/report-board",
            serde_json::json!({
                "name": "运维大屏",
                "config": valid_config(),
                "enabled": "1"
            }),
        )
        .await;
    ctx.assert_ok(&v);
    let board_id = v["data"]["id"].as_i64().expect("应返回看板 id");
    assert_eq!(
        v["data"]["config"]["cards"][0]["sourceKey"].as_str(),
        Some("login_trend"),
        "创建返回应含强类型 config，实际: {v}"
    );

    // 3. 回读详情（持久化验证）
    let v = ctx
        .get_json(&format!("/tool/report-board/{board_id}"))
        .await;
    ctx.assert_ok(&v);
    assert_eq!(
        v["data"]["config"]["cards"][0]["chartType"].as_str(),
        Some("line"),
        "回读 chartType 应为 line，实际: {v}"
    );

    // 4. 更新：追加一张卡片（饼图，消息投递分布）
    let mut cfg2 = valid_config();
    cfg2["cards"].as_array_mut().unwrap().push(serde_json::json!({
        "id": "c2",
        "title": "消息投递",
        "chartType": "pie",
        "sourceKey": "msg_delivery",
        "size": { "w": 1, "h": 2 }
    }));
    let v = ctx
        .put_json(
            &format!("/tool/report-board/{board_id}"),
            serde_json::json!({ "config": cfg2 }),
        )
        .await;
    ctx.assert_ok(&v);
    assert_eq!(
        v["data"]["config"]["cards"].as_array().unwrap().len(),
        2,
        "更新后应有 2 张卡片，实际: {v}"
    );

    // 5. 清单包含该看板
    let v = ctx.get_json("/tool/report-board/list").await;
    ctx.assert_ok(&v);
    let rows = v["data"].as_array().expect("list 应为数组");
    assert!(
        rows.iter().any(|b| b["id"].as_i64() == Some(board_id)),
        "清单应含新建看板，实际: {rows:?}"
    );

    // 6. 数据端点：白名单源 → 200（趋势源 items 长度=range 天数）
    let v = ctx
        .get_json("/tool/report-board/data/login_trend?range=7d")
        .await;
    ctx.assert_ok(&v);
    assert_eq!(
        v["data"]["items"].as_array().unwrap().len(),
        7,
        "7d 范围应返回 7 个数据点，实际: {v}"
    );
    // 非法 range → 400
    let (status, _) = ctx
        .send_raw(bearer_json_request(
            &ctx,
            &ctx.token,
            Method::GET,
            "/tool/report-board/data/login_trend?range=1d",
            None,
        ))
        .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "非法 range 应 400，实际: {status}"
    );

    // 7. 白名单外 sourceKey → 400（路径段不含斜杠/空格，单段匹配）
    for bad in ["evil.example.com", "SELECT_1", "unknown_source"] {
        let (status, _) = ctx
            .send_raw(bearer_json_request(
                &ctx,
                &ctx.token,
                Method::GET,
                &format!("/tool/report-board/data/{bad}"),
                None,
            ))
            .await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "白名单外 sourceKey {bad:?} 应 400，实际: {status}"
        );
    }
    // 保存配置引用白名单外 sourceKey → 400
    let mut evil = valid_config();
    evil["cards"][0]["sourceKey"] = serde_json::json!("http://evil.example.com");
    let (status, _) = ctx
        .send_raw(bearer_json_request(
            &ctx,
            &ctx.token,
            Method::POST,
            "/tool/report-board",
            Some(serde_json::json!({ "name": "evil", "config": evil })),
        ))
        .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "白名单外 sourceKey 保存应 400，实际: {status}"
    );

    // 8. 同名看板 → 400
    let (status, _) = ctx
        .send_raw(bearer_json_request(
            &ctx,
            &ctx.token,
            Method::POST,
            "/tool/report-board",
            Some(serde_json::json!({ "name": "运维大屏", "config": valid_config() })),
        ))
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "同名看板应 400");

    // 9. 删除后回读 → 404
    let v = ctx
        .delete_json(&format!("/tool/report-board/{board_id}"))
        .await;
    ctx.assert_ok(&v);
    let (status, _) = ctx
        .send_raw(bearer_json_request(
            &ctx,
            &ctx.token,
            Method::GET,
            &format!("/tool/report-board/{board_id}"),
            None,
        ))
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "已删看板回读应 404");
}

/// 属主隔离：他人配置不可读/不可改/不可删（404 语义）+ 租户行随属主。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_report_board_owner_isolation() {
    let ctx = TestContext::new().await;

    // 1. admin 创建看板
    let v = ctx
        .post_json(
            "/tool/report-board",
            serde_json::json!({ "name": "admin看板", "config": valid_config() }),
        )
        .await;
    ctx.assert_ok(&v);
    let board_id = v["data"]["id"].as_i64().expect("应返回看板 id");

    // 2. 创建普通用户并登录（role_id=2 已关联 4130/4131 菜单种子）
    let uname = "it_board_other";
    let v = ctx
        .post_json(
            "/system/user",
            serde_json::json!({
                "deptId": 103,
                "userName": uname,
                "nickName": "看板他人",
                "email": "stepby@tzkj.net",
                "phonenumber": "13800008888",
                "sex": "0",
                "password": "Stepby@12345",
                "status": "0",
                "roleIds": [2]
            }),
        )
        .await;
    ctx.assert_ok(&v);
    let other_token = login(&ctx.app, ctx.peer_ip, uname, "Stepby@12345").await;

    // 3. 他人读 admin 看板 → 404（语义化：不暴露存在性）
    let (status, _) = ctx
        .send_raw(bearer_json_request(
            &ctx,
            &other_token,
            Method::GET,
            &format!("/tool/report-board/{board_id}"),
            None,
        ))
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "他人读看板应 404");

    // 4. 他人改/删 admin 看板 → 404
    for (method, body) in [
        (
            Method::PUT,
            Some(serde_json::json!({ "name": "hijack" })),
        ),
        (Method::DELETE, None),
    ] {
        let (status, _) = ctx
            .send_raw(bearer_json_request(
                &ctx,
                &other_token,
                method.clone(),
                &format!("/tool/report-board/{board_id}"),
                body,
            ))
            .await;
        assert_eq!(
            status,
            StatusCode::NOT_FOUND,
            "他人 {method} 看板应 404，实际: {status}"
        );
    }

    // 5. 他人清单不含 admin 看板（v1 仅本人语义）
    let req = bearer_json_request(
        &ctx,
        &other_token,
        Method::GET,
        "/tool/report-board/list",
        None,
    );
    let v = ctx.send_json(req).await;
    ctx.assert_ok(&v);
    let rows = v["data"].as_array().expect("list 应为数组");
    assert!(
        rows.iter().all(|b| b["id"].as_i64() != Some(board_id)),
        "他人清单不应包含 admin 看板，实际: {rows:?}"
    );

    // 6. admin 本人仍可读（属主校验未误伤）
    let v = ctx
        .get_json(&format!("/tool/report-board/{board_id}"))
        .await;
    ctx.assert_ok(&v);
}
