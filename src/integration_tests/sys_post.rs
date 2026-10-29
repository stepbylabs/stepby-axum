// stepby-axum/src/integration_tests/sys_post.rs
//! 岗位模块链路集成测试：
//! - 分页列表 / 下拉选项 / 详情
//! - 新增 → 修改 → 删除 / 状态切换（通过 PUT）
//! - 导出（POST + Form，仅断言 HTTP 200，避免解析二进制内容）

use axum::body::Body;
use axum::extract::connect_info::ConnectInfo;
use axum::http::{Request, StatusCode};
use std::net::SocketAddr;

use super::TestContext;

/// 岗位全链路（CRUD + 状态切换 + 导出）。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_post_chain() {
    let ctx = TestContext::new().await;

    // 1. 分页列表（种子 4 个岗位：ceo/se/hr/user）
    let v = ctx
        .get_json("/system/post/list?pageNum=1&pageSize=10")
        .await;
    let rows = v["rows"].as_array().expect("rows 应为数组");
    assert!(rows.len() >= 4, "种子应至少 4 个岗位，实际: {v}");

    // 2. 下拉选项（data 数组）
    let v = ctx.get_json("/system/post/optionselect").await;
    let data = v["data"].as_array().expect("data 应为数组");
    assert!(data.len() >= 4, "岗位下拉应至少 4 项，实际: {v}");

    // 3. 详情（种子岗位 1：ceo）
    let v = ctx.get_json("/system/post/1").await;
    assert_eq!(v["data"]["postId"], 1, "岗位详情 postId 应为 1，实际: {v}");
    assert_eq!(
        v["data"]["postCode"].as_str(),
        Some("ceo"),
        "种子岗位 1 编码应为 ceo，实际: {v}"
    );

    // 4. 新增岗位（it_post 前缀避免与种子冲突）
    let v = ctx
        .post_json(
            "/system/post",
            serde_json::json!({
                "postCode": "it_post",
                "postName": "集成测试岗位",
                "postSort": 99,
                "status": "0",
                "remark": "集成测试"
            }),
        )
        .await;
    ctx.assert_ok(&v);

    // 5. 按编码模糊查询到新岗位
    let v = ctx.get_json("/system/post/list?postCode=it_post").await;
    let rows = v["rows"].as_array().expect("rows 应为数组");
    assert_eq!(rows.len(), 1, "应查到 1 个新岗位，实际: {v}");
    let post_id = rows[0]["postId"].as_i64().expect("postId 应为数字");

    // 6. 修改岗位
    let v = ctx
        .put_json(
            "/system/post",
            serde_json::json!({
                "postId": post_id,
                "postCode": "it_post",
                "postName": "集成测试岗位改",
                "postSort": 100,
                "status": "0"
            }),
        )
        .await;
    ctx.assert_ok(&v);
    let v = ctx.get_json(&format!("/system/post/{}", post_id)).await;
    assert_eq!(
        v["data"]["postName"].as_str(),
        Some("集成测试岗位改"),
        "修改后的岗位名称应生效，实际: {v}"
    );

    // 7. 状态切换（通过 PUT 将 status 由 0 改为 1 = 停用）
    let v = ctx
        .put_json(
            "/system/post",
            serde_json::json!({
                "postId": post_id,
                "postCode": "it_post",
                "postName": "集成测试岗位改",
                "postSort": 100,
                "status": "1"
            }),
        )
        .await;
    ctx.assert_ok(&v);
    let v = ctx.get_json(&format!("/system/post/{}", post_id)).await;
    assert_eq!(
        v["data"]["status"].as_str(),
        Some("1"),
        "状态切换后 status 应为 1，实际: {v}"
    );

    // 8. 导出岗位（POST + application/x-www-form-urlencoded，返回 Excel 二进制，仅断言 HTTP 200）
    let mut req = Request::builder()
        .method("POST")
        .uri("/system/post/export")
        .header("authorization", format!("Bearer {}", ctx.token))
        .header("content-type", "application/x-www-form-urlencoded")
        .body(Body::from("pageNum=1&pageSize=10"))
        .expect("构造导出请求失败");
    req.extensions_mut()
        .insert(ConnectInfo(SocketAddr::from((ctx.peer_ip, 4321))));
    let (status, _v) = ctx.send_raw(req).await;
    assert_eq!(status, StatusCode::OK, "岗位导出应返回 HTTP 200");

    // 9. 删除岗位（软删除 + post_code 重命名释放唯一索引）
    let v = ctx.delete_json(&format!("/system/post/{}", post_id)).await;
    ctx.assert_ok(&v);
    let v = ctx.get_json("/system/post/list?postCode=it_post").await;
    let rows = v["rows"].as_array().expect("rows 应为数组");
    assert!(rows.is_empty(), "删除后不应再查到该岗位，实际: {v}");

    // 10. 异常路径：删除不存在的岗位 → 404
    let mut req = Request::builder()
        .method("DELETE")
        .uri("/system/post/999999")
        .header("authorization", format!("Bearer {}", ctx.token))
        .body(Body::empty())
        .expect("构造删除请求失败");
    req.extensions_mut()
        .insert(ConnectInfo(SocketAddr::from((ctx.peer_ip, 4321))));
    let (status, v) = ctx.send_raw(req).await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "删除不存在的岗位应返回 404，实际: {status} {v}"
    );
}

/// b131：`DELETE /system/post/974,974` 曾被判成「岗位不存在」并**整批回滚**。
///
/// 根因是批量删除在事务里逐行重查：第一轮已软删 974，第二轮按 id 再读就命中
/// `del_flag='2'` ⇒ 报不存在 ⇒ 事务回滚，结果一行都没删。重复 id 是合法幂等入参
/// （前端重复拼参 / 脚本重试），必须先去重再进循环。
///
/// 三条判据：① 重复 id ⇒ 200 且行真的删掉；② 审计恰 1 行（去重后不会为同一行写两遍
/// 删除留痕）；③ 对照组单 id 照常 200——否则"永远 200"也能满足 ①。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_post_batch_delete_dedupes_repeated_ids() {
    let ctx = TestContext::new().await;

    let v = ctx
        .post_json(
            "/system/post",
            serde_json::json!({
                "postCode": "it_post_dup",
                "postName": "重复id删除岗位",
                "postSort": 97,
                "status": "0"
            }),
        )
        .await;
    ctx.assert_ok(&v);
    let v = ctx.get_json("/system/post/list?postCode=it_post_dup").await;
    let post_id = v["rows"][0]["postId"]
        .as_i64()
        .expect("应查到新岗位 postId");

    // ① 重复 id：200 且行真的删掉（修复前 404 且零删除）
    let v = ctx
        .delete_json(&format!("/system/post/{post_id},{post_id}"))
        .await;
    ctx.assert_ok(&v);
    let v = ctx.get_json("/system/post/list?postCode=it_post_dup").await;
    assert!(
        v["rows"].as_array().map(|a| a.is_empty()).unwrap_or(false),
        "重复 id 的批量删除必须真的删掉，实际: {v}"
    );

    // ② 审计：恰好一行 DELETE 留痕（同一行不得因入参重复写两遍）
    let v = ctx
        .get_json(&format!(
            "/system/audit-change/list?tableName=sys_post&rowPk={post_id}&action=DELETE"
        ))
        .await;
    assert_eq!(
        v["total"].as_u64(),
        Some(1),
        "重复 id 只应留一条 DELETE 审计，实际: {v}"
    );
    assert_eq!(
        v["rows"][0]["operatorName"].as_str(),
        Some("admin"),
        "删除留痕必须能归因到操作人，实际: {v}"
    );

    // ③ 对照组：单 id 删除照常成功
    let v = ctx
        .post_json(
            "/system/post",
            serde_json::json!({
                "postCode": "it_post_single",
                "postName": "单id删除岗位",
                "postSort": 96,
                "status": "0"
            }),
        )
        .await;
    ctx.assert_ok(&v);
    let v = ctx
        .get_json("/system/post/list?postCode=it_post_single")
        .await;
    let single_id = v["rows"][0]["postId"].as_i64().expect("应查到对照组岗位");
    let v = ctx.delete_json(&format!("/system/post/{single_id}")).await;
    ctx.assert_ok(&v);
    let v = ctx
        .get_json("/system/post/list?postCode=it_post_single")
        .await;
    assert!(
        v["rows"].as_array().map(|a| a.is_empty()).unwrap_or(false),
        "对照组：单 id 删除必须真的删掉，实际: {v}"
    );
}
