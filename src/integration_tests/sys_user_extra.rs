// axum-backend/src/integration_tests/sys_user_extra.rs
//! 用户模块 导入/导出/头像 链路集成测试：
//! - 导出用户列表 POST /system/user/export（form 编码，返回 xlsx 二进制）
//! - 下载导入模板 POST /system/user/importTemplate（返回 xlsx 模板）
//! - 批量导入用户 POST /system/user/importData（multipart file .xlsx → data.success 上报）
//!   + 失败分支：非 .xlsx 文件名（import.csv）→ 400
//! - 头像上传 POST /system/user/profile/avatar（multipart 字段 avatarfile → imgUrl）
//!
//! 说明：admin 为超管会短路 permission 中间件；multipart/二进制请求无法用 TestContext::request
//! （仅支持 JSON/空 body），故按 file_common.rs 惯例自行构造带鉴权头 + ConnectInfo 的原始请求。

use std::net::SocketAddr;

use axum::body::{Body, to_bytes};
use axum::extract::connect_info::ConnectInfo;
use axum::http::{Method, Request, StatusCode, header};
use tower::ServiceExt;

use super::TestContext;

/// 构造 multipart/form-data 请求体（单个字段），供上传测试使用。
fn multipart_body(
    boundary: &str,
    field: &str,
    filename: &str,
    content_type: &str,
    data: &[u8],
) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(
        format!(
            "--{boundary}\r\nContent-Disposition: form-data; name=\"{field}\"; filename=\"{filename}\"\r\nContent-Type: {content_type}\r\n\r\n"
        )
        .as_bytes(),
    );
    body.extend_from_slice(data);
    body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
    body
}

/// 构造带鉴权头 + ConnectInfo + 自定义 Content-Type 的原始请求。
fn raw_request(
    ctx: &TestContext,
    method: Method,
    uri: &str,
    content_type: &str,
    body: Vec<u8>,
) -> Request<Body> {
    let mut req = Request::builder()
        .method(method)
        .uri(uri)
        .header("authorization", format!("Bearer {}", ctx.token))
        .header("content-type", content_type)
        .body(Body::from(body))
        .expect("构造请求失败");
    req.extensions_mut()
        .insert(ConnectInfo(SocketAddr::from((ctx.peer_ip, 4321))));
    req
}

/// 用模板行列生成一份可被导入的 xlsx 字节（表头 + 一行合法数据）。
/// 依赖种子部门 103「研发部门」存在。
fn build_valid_import_xlsx() -> Vec<u8> {
    use crate::common::excel::{ImportColumn, build_import_template_bytes};
    let columns = [
        ImportColumn {
            header: ("登录名称", "Login Name"),
            sample: "it_user_xlsx",
            width: 18.0,
        },
        ImportColumn {
            header: ("用户姓名", "Nickname"),
            sample: "导入测试",
            width: 14.0,
        },
        ImportColumn {
            header: ("部门名称", "Department"),
            sample: "研发部门",
            width: 18.0,
        },
        ImportColumn {
            header: ("手机号码", "Phone"),
            sample: "13800138000",
            width: 18.0,
        },
        ImportColumn {
            header: ("邮箱", "Email"),
            sample: "it.user.import@yebot.dev",
            width: 26.0,
        },
        ImportColumn {
            header: ("性别", "Gender"),
            sample: "男",
            width: 10.0,
        },
        ImportColumn {
            header: ("状态", "Status"),
            sample: "正常",
            width: 10.0,
        },
    ];
    build_import_template_bytes("导入用户", &columns, true).expect("生成导入模板失败")
}

/// 从 xlsx 二进制响应体中回读首行表头，断言确实产出了合法 Excel。
async fn assert_xlsx_header(resp: axum::response::Response, expect_header: &str) {
    assert_eq!(resp.status(), StatusCode::OK, "应返回 HTTP 200");
    let ct = resp
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(
        ct.to_lowercase().contains("spreadsheetml"),
        "content-type 应含 spreadsheetml，实际: {ct}"
    );
    let body = to_bytes(resp.into_body(), 8 << 20)
        .await
        .expect("读取 xlsx 响应体失败");
    let rows = crate::common::excel::read_xlsx_rows(&body).expect("响应体应为合法 xlsx");
    assert!(!rows.is_empty(), "xlsx 应有数据行");
    assert!(
        rows[0].iter().any(|c| c.contains(expect_header)),
        "表头应包含 {expect_header}，实际: {:?}",
        rows[0]
    );
}

/// 用户列表导出：POST /system/user/export（form 编码，空表单）→ HTTP 200 + xlsx。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_user_export_xlsx() {
    let ctx = TestContext::new().await;

    // export 使用 Form 提取器，须声明 application/x-www-form-urlencoded（空表单走默认分页）。
    let req = raw_request(
        &ctx,
        Method::POST,
        "/system/user/export",
        "application/x-www-form-urlencoded",
        Vec::new(),
    );
    let resp = ctx
        .app
        .clone()
        .oneshot(req)
        .await
        .expect("导出请求执行失败");
    // 空表单分页仅导出当前页，可能不足以覆盖 admin 行，这里只验证 xlsx + 表头。
    assert_xlsx_header(resp, "用户编号").await;
}

/// 导入模板下载：POST /system/user/importTemplate（无 body）→ HTTP 200 + xlsx。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_user_import_template_download() {
    let ctx = TestContext::new().await;

    let req = ctx.request(Method::POST, "/system/user/importTemplate", None);
    let resp = ctx
        .app
        .clone()
        .oneshot(req)
        .await
        .expect("导入模板请求执行失败");
    assert_xlsx_header(resp, "登录名称").await;
}

/// 用户批量导入：POST /system/user/importData?updateSupport=1（multipart file .xlsx）
/// → code 200 且 data.success 上报成功数 ≥ 1。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_user_import_data_success() {
    let ctx = TestContext::new().await;

    let boundary = "it-import-boundary";
    let xlsx = build_valid_import_xlsx();
    let body = multipart_body(
        boundary,
        "file",
        "import.xlsx",
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        &xlsx,
    );
    let req = raw_request(
        &ctx,
        Method::POST,
        "/system/user/importData?updateSupport=1",
        &format!("multipart/form-data; boundary={boundary}"),
        body,
    );
    let v = ctx.send_json(req).await;
    let success = v["data"]["success"].as_u64().unwrap_or(0);
    assert!(
        success >= 1,
        "导入应上报成功数 ≥ 1，实际 data.success={success}，完整响应: {v}"
    );

    // 反查：导入的 it_user_xlsx 用户应存在于列表
    let v = ctx
        .get_json("/system/user/list?userName=it_user_xlsx")
        .await;
    let rows = v["rows"].as_array().expect("rows 应为数组");
    assert!(
        rows.iter().any(|r| r["userName"] == "it_user_xlsx"),
        "导入的用户应能查到，实际: {v}"
    );
}

/// 导入失败分支：POST /system/user/importData 上传非 .xlsx 文件名（import.csv）→ HTTP 400。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_user_import_data_rejects_non_xlsx() {
    let ctx = TestContext::new().await;

    let boundary = "it-import-err-boundary";
    let body = multipart_body(boundary, "file", "import.csv", "text/csv", b"a,b,c");
    let req = raw_request(
        &ctx,
        Method::POST,
        "/system/user/importData",
        &format!("multipart/form-data; boundary={boundary}"),
        body,
    );
    let (status, v) = ctx.send_raw(req).await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "非 .xlsx 导入应返回 400，实际 status={status} body={v}"
    );
}

/// 头像上传：POST /system/user/profile/avatar（multipart 字段 avatarfile，PNG 字节）
/// → code 200 且 imgUrl 存在。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_user_avatar_upload() {
    let ctx = TestContext::new().await;

    let boundary = "it-avatar-boundary";
    let png: &[u8] = &[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0x00, 0x00];
    let body = multipart_body(boundary, "avatarfile", "avatar.png", "image/png", png);
    let req = raw_request(
        &ctx,
        Method::POST,
        "/system/user/profile/avatar",
        &format!("multipart/form-data; boundary={boundary}"),
        body,
    );
    let v = ctx.send_json(req).await;
    let img_url = v["imgUrl"].as_str().unwrap_or("");
    assert!(!img_url.is_empty(), "头像上传应返回 imgUrl，实际: {v}");
    assert!(
        img_url.ends_with(".png"),
        "imgUrl 应为 png 路径，实际: {img_url}"
    );
}
