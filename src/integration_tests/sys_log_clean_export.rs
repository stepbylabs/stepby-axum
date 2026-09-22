// axum-backend/src/integration_tests/sys_log_clean_export.rs
//! M2 集成测试：sys_oper_log / sys_logininfor 的「按时间范围清理」与「导出」链路。
//!
//! 覆盖：
//! - DELETE /monitor/operlog/clean?beginTime=&endTime=   admin 按时间范围清理成功 + 无权限用户 403
//! - DELETE /monitor/logininfor/clean?beginTime=&endTime= admin 按时间范围清理成功 + 无权限用户 403
//! - POST   /monitor/operlog/export                       返回 xlsx 二进制 + 无权限用户 403
//! - POST   /monitor/logininfor/export                    返回 xlsx 二进制 + 无权限用户 403
//!
//! 权限基线：
//! - 种子角色 role_id=2「普通角色」关联全部菜单（含 monitor:*），因此 403 用例改用
//!   **无角色用户**（空权限集），其对任意受保护端点均返回 403。

use axum::body::Body;
use axum::extract::connect_info::ConnectInfo;
use axum::http::{Method, Request, StatusCode};
use std::net::SocketAddr;
use tower::ServiceExt;

use super::{TestContext, login};

/// 创建无角色用户（空权限集）并登录，返回其 token（用于 403 断言）。
async fn create_noperm_user_and_token(ctx: &TestContext) -> String {
    let uname = "it_noperm";
    let v = ctx
        .post_json(
            "/system/user",
            serde_json::json!({
                "deptId": 103,
                "userName": uname,
                "nickName": "无权限测试",
                "email": "it.noperm@yebot.dev",
                "phonenumber": "13800009999",
                "sex": "0",
                "password": "Yebot@12345",
                "status": "0"
            }),
        )
        .await;
    ctx.assert_ok(&v);
    login(&ctx.app, ctx.peer_ip, uname, "Yebot@12345").await
}

/// 用指定 token 构建请求（用于非 admin 权限断言）。
fn request_with_token(ctx: &TestContext, method: Method, uri: &str, token: &str) -> Request<Body> {
    let mut req = Request::builder()
        .method(method)
        .uri(uri)
        .header("authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .expect("构造请求失败");
    req.extensions_mut()
        .insert(ConnectInfo(SocketAddr::from((ctx.peer_ip, 4321))));
    req
}

/// 构造带鉴权头 + ConnectInfo 的 form-urlencoded 导出请求（admin）。
fn form_request(ctx: &TestContext, uri: &str) -> Request<Body> {
    let mut req = Request::builder()
        .method("POST")
        .uri(uri)
        .header("authorization", format!("Bearer {}", ctx.token))
        .header("content-type", "application/x-www-form-urlencoded")
        .body(Body::from(String::new()))
        .expect("构造 form 请求失败");
    req.extensions_mut()
        .insert(ConnectInfo(SocketAddr::from((ctx.peer_ip, 4321))));
    req
}

/// DELETE /monitor/operlog/clean：admin 按时间范围清理成功 + 无权限用户 403。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn it_operlog_clean_range_and_403() {
    let ctx = TestContext::new().await;
    let noperm = create_noperm_user_and_token(&ctx).await;

    // admin 按时间范围清理（兼容前端 addDateRange 的 params[beginTime]/params[endTime]，也用 beginTime/endTime）
    let (status, v) = ctx
        .send_raw(ctx.request(
            Method::DELETE,
            "/monitor/operlog/clean?beginTime=2020-01-01&endTime=2030-12-31",
            None,
        ))
        .await;
    assert_eq!(status, StatusCode::OK, "按范围清空应 HTTP 200，实际: {v}");
    assert_eq!(v["code"], 200, "按范围清空业务码应 200，实际: {v}");
    assert!(
        v["data"]["affected"].is_number(),
        "按范围清理应返回 affected 数量，实际: {v}"
    );

    // 无权限用户调用 clean → 403
    let (status, v) = ctx
        .send_raw(request_with_token(
            &ctx,
            Method::DELETE,
            "/monitor/operlog/clean",
            &noperm,
        ))
        .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "无权限用户清空操作日志应 403，实际: {status} {v}"
    );
}

/// DELETE /monitor/logininfor/clean：admin 按时间范围清理成功 + 无权限用户 403。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn it_logininfor_clean_range_and_403() {
    let ctx = TestContext::new().await;
    let noperm = create_noperm_user_and_token(&ctx).await;

    let (status, v) = ctx
        .send_raw(ctx.request(
            Method::DELETE,
            "/monitor/logininfor/clean?beginTime=2020-01-01&endTime=2030-12-31",
            None,
        ))
        .await;
    assert_eq!(status, StatusCode::OK, "按范围清空应 HTTP 200，实际: {v}");
    assert_eq!(v["code"], 200, "按范围清空业务码应 200，实际: {v}");
    assert!(
        v["data"]["affected"].is_number(),
        "按范围清理应返回 affected 数量，实际: {v}"
    );

    let (status, v) = ctx
        .send_raw(request_with_token(
            &ctx,
            Method::DELETE,
            "/monitor/logininfor/clean",
            &noperm,
        ))
        .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "无权限用户清空登录日志应 403，实际: {status} {v}"
    );
}

/// POST /monitor/operlog/export：admin 返回 xlsx 二进制 + 无权限用户 403。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn it_operlog_export_xlsx_and_403() {
    let ctx = TestContext::new().await;
    let noperm = create_noperm_user_and_token(&ctx).await;

    let resp = ctx
        .app
        .clone()
        .oneshot(form_request(&ctx, "/monitor/operlog/export"))
        .await
        .expect("操作日志导出请求执行失败");
    let ct = resp
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(
        ct.contains("spreadsheetml"),
        "操作日志导出应返回 Excel content-type，实际: {ct}"
    );

    let (status, v) = ctx
        .send_raw(request_with_token(
            &ctx,
            Method::POST,
            "/monitor/operlog/export",
            &noperm,
        ))
        .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "无权限用户导出操作日志应 403，实际: {status} {v}"
    );
}

/// POST /monitor/logininfor/export：admin 返回 xlsx 二进制 + 无权限用户 403。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn it_logininfor_export_xlsx_and_403() {
    let ctx = TestContext::new().await;
    let noperm = create_noperm_user_and_token(&ctx).await;

    let resp = ctx
        .app
        .clone()
        .oneshot(form_request(&ctx, "/monitor/logininfor/export"))
        .await
        .expect("登录日志导出请求执行失败");
    let ct = resp
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(
        ct.contains("spreadsheetml"),
        "登录日志导出应返回 Excel content-type，实际: {ct}"
    );

    let (status, v) = ctx
        .send_raw(request_with_token(
            &ctx,
            Method::POST,
            "/monitor/logininfor/export",
            &noperm,
        ))
        .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "无权限用户导出登录日志应 403，实际: {status} {v}"
    );
}
