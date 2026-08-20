// axum-backend/src/integration_tests/sys_logininfor.rs
//! 登录日志模块链路集成测试：
//! - 分页列表（登录成功/失败均写入日志）+ 每日统计
//! - 解锁用户（unlock：普通用户成功 / 超管保护 403）
//! - 批量删除（正常 + 非法 id 400；有效但不存在的 id 幂等返回成功，无 404 分支）
//! - 清空全部日志（clean）
//! - 导出（export，Excel 二进制）
//!
//! 说明：迁移种子无登录日志。admin 登录（成功 status='0'）与一次错误密码登录
//! （失败 status='1'）各产生一条日志。unlock 为物理删除该用户名 status='1' 记录，
//! 服务端对不存在用户幂等返回成功，不返回 404；超管账号受 403 保护不可解锁。

use axum::body::Body;
use axum::extract::connect_info::ConnectInfo;
use axum::http::{Method, Request, StatusCode};
use std::net::SocketAddr;

use super::TestContext;
use tower::ServiceExt;

/// 发起一次该用户名的错误密码登录（产生 status='1' 失败登录日志）。
async fn trigger_failed_login(ctx: &TestContext, username: &str) {
    let mut req = Request::builder()
        .method("POST")
        .uri("/login")
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({
                "username": username,
                "password": "wrong-password",
                "code": "",
                "uuid": ""
            })
            .to_string(),
        ))
        .expect("构造登录请求失败");
    req.extensions_mut()
        .insert(ConnectInfo(SocketAddr::from((ctx.peer_ip, 4321))));
    let (_, v) = ctx.send_raw(req).await;
    assert_ne!(v["code"], 200, "错误密码登录业务码不应为 200，实际: {v}");
}

/// 登录日志分页列表 + 每日统计。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn it_lgi_list_and_stats() {
    let ctx = TestContext::new().await;

    // 1. 分页列表：admin 成功登录已写入 1 条 status='0' 日志
    let v = ctx
        .get_json("/monitor/logininfor/list?pageNum=1&pageSize=10")
        .await;
    let rows = v["rows"].as_array().expect("rows 应为数组，实际: {v}");
    assert!(!rows.is_empty(), "登录成功应写入登录日志，实际: {v}");
    assert!(
        v["total"].as_u64().unwrap_or(0) >= rows.len() as u64,
        "total 应 >= rows 数，实际: {v}"
    );
    let admin_row = rows
        .iter()
        .find(|r| r["userName"] == "admin")
        .expect("列表应包含 admin 的登录日志，实际: {v}");
    assert!(
        admin_row["status"].as_str() == Some("0"),
        "admin 成功登录 status 应为 0，实际: {v}"
    );

    // 2. 再触发一次失败登录 → 列表新增 1 条 status='1' 日志
    trigger_failed_login(&ctx, "it_lgi_user").await;
    let v = ctx
        .get_json("/monitor/logininfor/list?userName=it_lgi_user&status=1&pageNum=1&pageSize=10")
        .await;
    let rows = v["rows"].as_array().expect("rows 应为数组，实际: {v}");
    assert_eq!(
        rows.len(),
        1,
        "失败登录应产生 1 条 status=1 日志，实际: {v}"
    );
    assert_eq!(
        rows[0]["userName"].as_str(),
        Some("it_lgi_user"),
        "userName 应为 it_lgi_user，实际: {v}"
    );

    // 3. 每日统计（daily_stats 补齐为完整 N 天序列，结构断言）
    let v = ctx.get_json("/monitor/logininfor/stats?days=3").await;
    let data = v["data"].as_array().expect("data 应为数组，实际: {v}");
    assert!(!data.is_empty(), "stats 不应为空，实际: {v}");
    for item in data {
        assert!(
            item["date"].is_string() && item["success"].is_number() && item["fail"].is_number(),
            "stats 每项应含 date/success/fail，实际: {v}"
        );
    }
}

/// 登录日志解锁 + 批量删除异常 + 清空 + 导出。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn it_lgi_unlock_delete_clean_export() {
    let ctx = TestContext::new().await;

    // 1. 构造失败登录数据（it_lgi_user）
    trigger_failed_login(&ctx, "it_lgi_user").await;

    // 2. 解锁普通用户 it_lgi_user → 200，清空其失败日志
    let v = ctx
        .post_json(
            &format!("/monitor/logininfor/unlock/{}", "it_lgi_user"),
            serde_json::json!({}),
        )
        .await;
    ctx.assert_ok(&v);
    let v = ctx
        .get_json("/monitor/logininfor/list?userName=it_lgi_user&status=1&pageNum=1&pageSize=10")
        .await;
    assert!(
        v["rows"].as_array().expect("rows 数组").is_empty(),
        "解锁后不应再有 it_lgi_user 的失败日志，实际: {v}"
    );

    // 3. 解锁超管 admin → 403（超管保护）
    let (status, v) = ctx
        .send_raw(ctx.request(
            Method::POST,
            "/monitor/logininfor/unlock/admin",
            Some(serde_json::json!({})),
        ))
        .await;
    assert_ne!(v["code"], 200, "解锁超管业务码不应为 200，实际: {v}");
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "解锁超管应 403，实际: {status}"
    );

    // 4. 解锁不存在的用户 → 服务端幂等成功（无 404 分支）
    let v = ctx
        .post_json(
            "/monitor/logininfor/unlock/it_lgi_nonexistent",
            serde_json::json!({}),
        )
        .await;
    ctx.assert_ok(&v);

    // 5. 批量删除：普通 id → 200（取一条现存日志）
    let v = ctx
        .get_json("/monitor/logininfor/list?pageNum=1&pageSize=10")
        .await;
    let info_id = v["rows"]
        .as_array()
        .expect("rows 数组")
        .first()
        .map(|r| r["infoId"].as_i64().expect("infoId 应为数字"))
        .expect("应存在登录日志");
    let v = ctx
        .delete_json(&format!("/monitor/logininfor/{}", info_id))
        .await;
    ctx.assert_ok(&v);

    // 6. 批量删除：非法 id（非数字）→ 400
    let (status, v) = ctx
        .send_raw(ctx.request(Method::DELETE, "/monitor/logininfor/abc", None))
        .await;
    assert_ne!(v["code"], 200, "非法 id 业务码不应为 200，实际: {v}");
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "非法 id 应返回 400，实际: {status}"
    );

    // 7. 批量删除：有效但不存在的 id → 幂等返回成功（无 404 分支）
    let v = ctx.delete_json("/monitor/logininfor/999999").await;
    ctx.assert_ok(&v);

    // 8. 清空全部日志 → 200，列表应为空
    let v = ctx.delete_json("/monitor/logininfor/clean").await;
    ctx.assert_ok(&v);
    let v = ctx
        .get_json("/monitor/logininfor/list?pageNum=1&pageSize=10")
        .await;
    assert!(
        v["rows"].as_array().expect("rows 数组").is_empty(),
        "清空后不应再有登录日志，实际: {v}"
    );

    // 9. 导出（export，POST x-www-form-urlencoded）→ HTTP 200 + Excel content-type
    let mut req = Request::builder()
        .method("POST")
        .uri("/monitor/logininfor/export")
        .header("authorization", format!("Bearer {}", ctx.token))
        .header("content-type", "application/x-www-form-urlencoded")
        .body(Body::from(String::new()))
        .expect("构造导出请求失败");
    req.extensions_mut()
        .insert(ConnectInfo(SocketAddr::from((ctx.peer_ip, 4321))));
    let resp = ctx
        .app
        .clone()
        .oneshot(req)
        .await
        .expect("导出请求执行失败");
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "导出应返回 200，实际: {}",
        resp.status()
    );
    let content_type = resp
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(
        content_type.contains("spreadsheetml"),
        "导出应返回 Excel content-type，实际: {content_type}"
    );
}