// stepby-axum/src/integration_tests/sys_notice.rs
//! 通知公告模块链路集成测试：
//! - 分页列表 / 顶部公告（含未读数）/ 详情
//! - 新增 → 查询 → 修改 → 删除
//! - 标记单条已读 / 批量标记已读 / 全部未读标记已读

use axum::body::Body;
use axum::extract::connect_info::ConnectInfo;
use axum::http::{Request, StatusCode};
use std::net::SocketAddr;

use super::TestContext;

/// 通知公告全链路（CRUD + 三种已读标记 + 异常路径）。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_notice_chain() {
    let ctx = TestContext::new().await;

    // 1. 分页列表（种子 2 条：notice_id=1 公告类型 2，notice_id=2 通知类型 1）
    let v = ctx
        .get_json("/system/notice/list?pageNum=1&pageSize=10")
        .await;
    let rows = v["rows"].as_array().expect("rows 应为数组");
    assert!(rows.len() >= 2, "种子应至少 2 条通知公告，实际: {v}");

    // 2. 顶部公告（data 数组 + 未读数 unreadCount）
    let v = ctx.get_json("/system/notice/listTop").await;
    let top_rows = v["data"].as_array().expect("listTop data 应为数组");
    assert!(!top_rows.is_empty(), "顶部公告不应为空，实际: {v}");
    assert!(
        v["unreadCount"].is_number(),
        "listTop 应返回未读数 unreadCount，实际: {v}"
    );

    // 3. 详情（种子公告 1：类型为公告 2）
    let v = ctx.get_json("/system/notice/1").await;
    assert_eq!(v["data"]["noticeId"], 1, "详情 noticeId 应为 1，实际: {v}");
    assert_eq!(
        v["data"]["noticeType"].as_str(),
        Some("2"),
        "种子公告 1 类型应为 2，实际: {v}"
    );
    assert!(
        v["data"]["noticeTitle"]
            .as_str()
            .unwrap_or("")
            .contains("Stepby"),
        "种子公告标题应包含 Stepby，实际: {v}"
    );

    // 4. 新增通知公告（it_notice_ 前缀避免与种子冲突）
    let v = ctx
        .post_json(
            "/system/notice",
            serde_json::json!({
                "noticeTitle": "it_notice_集成测试通知",
                "noticeType": "1",
                "noticeContent": "it_notice 内容",
                "status": "0",
                "remark": "集成测试"
            }),
        )
        .await;
    ctx.assert_ok(&v);

    // 5. 按标题模糊查询到新公告
    let v = ctx
        .get_json("/system/notice/list?noticeTitle=it_notice_")
        .await;
    let rows = v["rows"].as_array().expect("rows 应为数组");
    assert_eq!(rows.len(), 1, "应查到 1 条新公告，实际: {v}");
    let notice_id = rows[0]["noticeId"].as_i64().expect("noticeId 应为数字");

    // 6. 标记单条已读（Query 参数 noticeId）
    let v = ctx
        .post_json(
            &format!("/system/notice/markRead?noticeId={}", notice_id),
            serde_json::json!({}),
        )
        .await;
    ctx.assert_ok(&v);

    // 6b. **重复标记同一条已读必须幂等成功**（b73 轮 13 线上实证缺陷：UI 上"已读"按钮重复点击、
    //     两个标签页同时标记、或先经 listTop 自动标记后再点，都会二次命中 (notice_id,user_id)
    //     唯一约束 → 旧实现返回 400「数据重复，请检查唯一字段」并打 WARN 污染日志。
    //     标记已读是"状态设定"型操作，重复执行不得改变结果、也不得报错。）
    let v = ctx
        .post_json(
            &format!("/system/notice/markRead?noticeId={}", notice_id),
            serde_json::json!({}),
        )
        .await;
    ctx.assert_ok(&v);

    // 6c. 重复标记后，已读记录仍只有一条（幂等不能变成"多写一行"）
    let v = ctx
        .get_json(&format!(
            "/system/notice/readUsers/list?noticeId={}&pageNum=1&pageSize=10",
            notice_id
        ))
        .await;
    let read_rows = v["rows"].as_array().expect("readUsers rows 应为数组");
    let mine = read_rows
        .iter()
        .filter(|r| r["userName"].as_str() == Some("admin"))
        .count();
    assert_eq!(mine, 1, "重复标记后 admin 的已读记录应恰为 1 条，实际: {v}");

    // 6d. **逐行已读态必须由服务端给出**（b79 P3：前端 store 与通知中心一直按
    //     `row.isRead` 渲染，而 list/listTop 返回的是裸 model ⇒ 该字段从未存在，
    //     刷新后 readIds 重建为空、全部退回"未读"，与同一时刻服务端算出的
    //     `unreadCount=0` 互相矛盾。M87 真机取证：markReadAll 返回 200，刷新后仍是「未读」。）
    let v = ctx
        .get_json("/system/notice/list?pageNum=1&pageSize=50")
        .await;
    let all_rows = v["rows"].as_array().expect("rows 应为数组");
    let marked = all_rows
        .iter()
        .find(|r| r["noticeId"].as_i64() == Some(notice_id))
        .expect("列表里应能找到刚新增的公告");
    assert_eq!(
        marked["isRead"].as_bool(),
        Some(true),
        "已标记的公告必须带 isRead=true（字段缺失即为本次缺陷的复现），实际: {marked}"
    );
    // 对照组：同一页里**没标记过**的公告必须是 false——否则实现可以是"isRead 恒真"
    let unmarked: Vec<&serde_json::Value> = all_rows
        .iter()
        .filter(|r| {
            r["noticeId"].as_i64() != Some(notice_id) && r["isRead"].as_bool() == Some(false)
        })
        .collect();
    assert!(
        !unmarked.is_empty(),
        "未标记的公告应显示 isRead=false（对照组，防恒真实现），实际页大小={}",
        all_rows.len()
    );
    // 顶部公告同样逐行带已读态（铃铛与通知中心共用同一个 store.readIds 来源）
    let v = ctx.get_json("/system/notice/listTop").await;
    let top = v["data"].as_array().expect("listTop data 应为数组");
    assert!(
        top.iter().all(|r| r["isRead"].is_boolean()),
        "listTop 每一行都必须是布尔 isRead，实际: {top:?}"
    );

    // 7. 批量标记已读（Query 参数 ids，逗号分隔）
    let v = ctx
        .post_json(
            &format!("/system/notice/markReadAll?ids={}", notice_id),
            serde_json::json!({}),
        )
        .await;
    ctx.assert_ok(&v);

    // 8. 全部未读标记已读（返回标记条数）
    let v = ctx
        .post_json("/system/notice/markAllUnreadRead", serde_json::json!({}))
        .await;
    ctx.assert_ok(&v);
    assert!(
        v["data"].is_number(),
        "markAllUnreadRead 应返回标记条数，实际: {v}"
    );

    // 8b. "全部已读"之后，列表侧的逐行态必须随之翻转（同一事实源，不得两套口径）
    let v = ctx
        .get_json("/system/notice/list?pageNum=1&pageSize=50")
        .await;
    let after = v["rows"].as_array().expect("rows 应为数组");
    assert!(
        !after.is_empty() && after.iter().all(|r| r["isRead"].as_bool() == Some(true)),
        "全部标记已读后所有行应为 isRead=true，实际: {:?}",
        after
            .iter()
            .map(|r| (r["noticeId"].clone(), r["isRead"].clone()))
            .collect::<Vec<_>>()
    );

    // 9. 修改通知公告
    let v = ctx
        .put_json(
            "/system/notice",
            serde_json::json!({
                "noticeId": notice_id,
                "noticeTitle": "it_notice_集成测试通知改",
                "noticeType": "2",
                "noticeContent": "it_notice 内容改",
                "status": "0"
            }),
        )
        .await;
    ctx.assert_ok(&v);
    let v = ctx.get_json(&format!("/system/notice/{}", notice_id)).await;
    assert_eq!(
        v["data"]["noticeTitle"].as_str(),
        Some("it_notice_集成测试通知改"),
        "修改后的公告标题应生效，实际: {v}"
    );

    // 10. 删除通知公告（物理删除，级联清理已读记录）
    let v = ctx
        .delete_json(&format!("/system/notice/{}", notice_id))
        .await;
    ctx.assert_ok(&v);
    let v = ctx
        .get_json("/system/notice/list?noticeTitle=it_notice_")
        .await;
    let rows = v["rows"].as_array().expect("rows 应为数组");
    assert!(rows.is_empty(), "删除后不应再查到该公告，实际: {v}");

    // 11. 异常路径：删除不存在的公告 → 404
    let mut req = Request::builder()
        .method("DELETE")
        .uri("/system/notice/999999")
        .header("authorization", format!("Bearer {}", ctx.token))
        .body(Body::empty())
        .expect("构造删除请求失败");
    req.extensions_mut()
        .insert(ConnectInfo(SocketAddr::from((ctx.peer_ip, 4321))));
    let (status, v) = ctx.send_raw(req).await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "删除不存在的公告应返回 404，实际: {status} {v}"
    );
}
