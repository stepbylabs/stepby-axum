// stepby-axum/src/integration_tests/sys_notice.rs
//! 通知公告模块链路集成测试：
//! - 分页列表 / 顶部公告（含未读数）/ 详情
//! - 新增 → 查询 → 修改 → 删除
//! - 标记单条已读 / 批量标记已读 / 全部未读标记已读
//! - **可见性口径一致性**（b80 P-B）：状态筛选、服务端已读筛选，以及
//!   「角标未读数 == 未读列表 total == 全部已读标记条数」三者同源

use axum::body::Body;
use axum::extract::connect_info::ConnectInfo;
use axum::http::{Method, Request, StatusCode};
use std::net::SocketAddr;

use super::TestContext;

/// 建一条夹具公告并按标题回查 ID（物理删除型表，测试结束统一清掉）
async fn create_notice(ctx: &TestContext, title: &str, notice_type: &str, status: &str) -> i64 {
    let v = ctx
        .post_json(
            "/system/notice",
            serde_json::json!({
                "noticeTitle": title,
                "noticeType": notice_type,
                "noticeContent": "it_visibility 内容",
                "status": status
            }),
        )
        .await;
    ctx.assert_ok(&v);
    let v = ctx
        .get_json(&format!(
            "/system/notice/list?noticeTitle={}&pageNum=1&pageSize=10",
            title
        ))
        .await;
    let rows = v["rows"].as_array().cloned().unwrap_or_default();
    let hit = rows
        .iter()
        .find(|r| r["noticeTitle"].as_str() == Some(title))
        .unwrap_or_else(|| panic!("按标题 {title} 应回查到刚建的夹具，实际: {v}"));
    hit["noticeId"]
        .as_i64()
        .unwrap_or_else(|| panic!("夹具 noticeId 应为数字: {hit}"))
}

/// 顶部接口的两个计数：`(未读角标, 可见总数)`
///
/// 取 `/listTop` 而不是新加一个计数端点：铃铛与通知中心本来就要调它，两个数必须由同一次
/// 往返、同一谓词产出，否则"卡片上的已读数"与"角标"来自两次快照，抖动时又会互相矛盾。
async fn top_counts(ctx: &TestContext) -> (u64, u64) {
    let v = ctx.get_json("/system/notice/listTop").await;
    let unread = v["unreadCount"]
        .as_u64()
        .unwrap_or_else(|| panic!("listTop 应返回未读数，实际: {v}"));
    let total = v["totalCount"]
        .as_u64()
        .unwrap_or_else(|| panic!("listTop 应返回可见总数 totalCount，实际: {v}"));
    (unread, total)
}

/// 未读角标数（`/listTop` 的 `unreadCount`，与通知中心同屏显示的那个数）
async fn unread_badge(ctx: &TestContext) -> u64 {
    top_counts(ctx).await.0
}

/// 带查询串取分页（返回 `total` 与 `noticeId` 集合）
async fn list_ids(ctx: &TestContext, qs: &str) -> (u64, Vec<i64>) {
    let v = ctx
        .get_json(&format!("/system/notice/list?pageSize=100&{}", qs))
        .await;
    let total = v["total"]
        .as_u64()
        .unwrap_or_else(|| panic!("list total 应为数字，实际: {v}"));
    let rows = v["rows"].as_array().cloned().unwrap_or_default();
    let ids: Vec<i64> = rows.iter().filter_map(|r| r["noticeId"].as_i64()).collect();
    (total, ids)
}

/// 公告可见性口径一致性（b80 P-B）
///
/// 钉住四件事，每件都对应改造前一个**同时存在且互相矛盾**的界面结论：
/// ① `status` 查询位真的进 SQL（改造前 DTO 没这个字段，serde 静默丢弃 ⇒ 前端筛选是假控件）；
/// ② `isRead` 由服务端筛选，`total` 是**筛选后**的总数（改造前前端只过滤当前页，total 仍是全量）；
/// ③ 角标未读数 == 未读列表 total == 「全部已读」标记条数（改造前角标是"总数−已读数"的算术差）；
/// ④ **已读公告被关闭后未读数不得变化**——这一条是 ③ 的变异对照：旧实现会少 1。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_notice_visibility_consistency() {
    let ctx = TestContext::new().await;

    // 三条夹具：A 通知（正常）、B 公告（正常）、C 通知（关闭态，用户面不得出现）
    let a = create_notice(&ctx, "it_vis_a_normal", "1", "0").await;
    let b = create_notice(&ctx, "it_vis_b_announce", "2", "0").await;
    let c = create_notice(&ctx, "it_vis_c_closed", "1", "1").await;

    // ① 状态筛选：status=0 含 A/B 不含 C；status=1 含 C 不含 A/B；不带 status 三者全含
    let (_, ids_normal) = list_ids(&ctx, "status=0").await;
    assert!(
        ids_normal.contains(&a) && ids_normal.contains(&b),
        "status=0 必须含两条正常夹具，实际 ids={ids_normal:?}"
    );
    assert!(
        !ids_normal.contains(&c),
        "status=0 不得含关闭态夹具 C={c}（筛选被静默丢弃的复现），实际 ids={ids_normal:?}"
    );
    let (_, ids_closed) = list_ids(&ctx, "status=1").await;
    assert!(
        ids_closed.contains(&c),
        "status=1 必须含关闭态夹具 C={c}，实际 ids={ids_closed:?}"
    );
    assert!(
        !ids_closed.contains(&a) && !ids_closed.contains(&b),
        "status=1 不得含正常夹具 A={a} B={b}（对照组，防筛选反向接错），实际 ids={ids_closed:?}"
    );
    let (_, ids_all) = list_ids(&ctx, "pageNum=1").await;
    assert!(
        ids_all.contains(&a) && ids_all.contains(&b) && ids_all.contains(&c),
        "不带 status 必须三者全含（管理面全量口径不变），实际 ids={ids_all:?}"
    );

    // 顶部铃铛只给正常态（与 status=0 同一谓词）
    let top = ctx.get_json("/system/notice/listTop").await;
    let top_ids: Vec<i64> = top["data"]
        .as_array()
        .cloned()
        .unwrap_or_default()
        .iter()
        .filter_map(|r| r["noticeId"].as_i64())
        .collect();
    assert!(
        !top_ids.contains(&c),
        "listTop 不得出现关闭态夹具 C={c}，实际 top={top_ids:?}"
    );

    // ②③ 服务端已读筛选 + 角标同源。
    //    `isRead` 与 `status` 是**两个独立轴**，角标数的是"可见面的未读"
    //    = `status=0 AND 未读`，所以这条等式两边必须都给全两个轴——只给 isRead=0
    //    会把关闭态未读公告（夹具 C）也数进来，等式自己就错了。
    let (unread_total_0, unread_ids_0) = list_ids(&ctx, "isRead=0&status=0").await;
    let (badge_0, visible_0) = top_counts(&ctx).await;
    assert_eq!(
        badge_0, unread_total_0,
        "角标未读数必须等于『未读列表』的 total（两条路径必须同一谓词）"
    );
    // totalCount 必须等于 list?status=0 的 total —— 卡片"全部"的分母与列表同源，
    // 否则前端用它减 unreadCount 得到的"已读"是个无主数字
    let (visible_list_total, _) = list_ids(&ctx, "status=0").await;
    assert_eq!(
        visible_0, visible_list_total,
        "totalCount 必须等于 list?status=0 的 total，实际 {visible_0} vs {visible_list_total}"
    );
    assert!(
        visible_0 >= badge_0,
        "已读数若为负即口径分家：totalCount={visible_0} < unreadCount={badge_0}"
    );
    assert!(
        unread_ids_0.contains(&a) && unread_ids_0.contains(&b),
        "新建夹具未读过，必须出现在未读列表里，实际 ids={unread_ids_0:?}"
    );
    assert!(
        !unread_ids_0.contains(&c),
        "关闭态夹具 C 不得进未读列表（它未读但不在可见面内），实际 ids={unread_ids_0:?}"
    );

    // 标记 A 已读 ⇒ 角标与未读列表同时 -1，且 A 从未读侧移到已读侧
    ctx.assert_ok(
        &ctx.post_json(
            &format!("/system/notice/markRead?noticeId={a}"),
            serde_json::json!({}),
        )
        .await,
    );
    let (unread_total_1, unread_ids_1) = list_ids(&ctx, "isRead=0&status=0").await;
    let badge_1 = unread_badge(&ctx).await;
    assert_eq!(badge_1, unread_total_1, "标记后两者仍必须相等");
    assert_eq!(
        unread_total_1 + 1,
        unread_total_0,
        "标记一条未读后未读总数必须恰好减 1（改造前 {badge_0}→{badge_1}）"
    );
    assert!(
        !unread_ids_1.contains(&a) && unread_ids_1.contains(&b),
        "A 必须离开未读列表、B 必须仍在，实际 ids={unread_ids_1:?}"
    );
    let (_, read_ids) = list_ids(&ctx, "isRead=1&status=0").await;
    assert!(
        read_ids.contains(&a),
        "已读列表必须含刚标记的 A={a}（对照组：证明 isRead 不是恒等于未读），实际 ids={read_ids:?}"
    );

    // ④ 把**已读的** A 关闭：它本就不在未读集合里 ⇒ 未读数不得变化。
    //    旧实现是 COUNT(status='0) - COUNT(已读行)，A 从前者消失却仍留在后者 ⇒ 这里必然少 1。
    ctx.assert_ok(
        &ctx.put_json(
            "/system/notice",
            serde_json::json!({
                "noticeId": a,
                "noticeTitle": "it_vis_a_normal",
                "noticeType": "1",
                "status": "1"
            }),
        )
        .await,
    );
    let (unread_total_2, _) = list_ids(&ctx, "isRead=0&status=0").await;
    let badge_2 = unread_badge(&ctx).await;
    assert_eq!(badge_2, unread_total_2, "关闭后两者仍必须相等");
    assert_eq!(
        badge_2, badge_1,
        "关闭一条**已读**公告不得改变未读数（算术差实现会在此少 1：{badge_1} → {badge_2}）"
    );
    let (_, read_ids_after_close) = list_ids(&ctx, "isRead=1&status=0").await;
    assert!(
        !read_ids_after_close.contains(&a),
        "已关闭的 A={a} 不得留在用户可见的已读列表里（与角标同一可见面）",
    );
    // 关闭 A 本身是**可见性变更**：可见总数应恰好 -1。这条同时充当下面
    // "标记已读不改总数"的基准快照——拿关闭前的 visible_0 去比会把正常变更判成缺陷。
    let (_, visible_after_close) = top_counts(&ctx).await;
    assert_eq!(
        visible_after_close + 1,
        visible_0,
        "关闭一条正常公告后可见总数应恰好 -1：{visible_0} → {visible_after_close}"
    );

    // ③「全部已读」标记条数 == 调用前的角标数；调用后角标与未读列表同时归零
    let badge_before = unread_badge(&ctx).await;
    let v = ctx
        .post_json("/system/notice/markAllUnreadRead", serde_json::json!({}))
        .await;
    ctx.assert_ok(&v);
    let marked = v["data"]
        .as_u64()
        .expect("markAllUnreadRead 应返回标记条数");
    assert_eq!(
        marked, badge_before,
        "标记条数必须等于调用前的角标未读数（同源判据，改造前两者可以不等）"
    );
    let (badge_after_all, visible_after_all) = top_counts(&ctx).await;
    assert_eq!(badge_after_all, 0, "全部已读后角标必须归零");
    let (unread_total_3, _) = list_ids(&ctx, "isRead=0&status=0").await;
    assert_eq!(unread_total_3, 0, "全部已读后未读列表必须为空");
    // 三数闭合：全部 = 已读 + 未读；未读为 0 ⇒ 全部必须都在已读侧，且总数不因标记而变
    let (read_total_3, _) = list_ids(&ctx, "isRead=1&status=0").await;
    assert_eq!(
        visible_after_all, read_total_3,
        "全部已读后 totalCount 必须等于已读列表 total：{visible_after_all} vs {read_total_3}"
    );
    assert_eq!(
        visible_after_all, visible_after_close,
        "标记已读不得改变可见总数（只改已读态）：{visible_after_close} → {visible_after_all}"
    );

    // 白名单拒绝：非法查询位必须 400 且给出可读原因（不得静默当未填 ⇒ 假控件复活）
    for (qs, leaf, echoed) in [("isRead=9", "isRead", "9"), ("status=2", "status", "2")] {
        let mut req = Request::builder()
            .method(Method::GET)
            .uri(format!("/system/notice/list?pageSize=10&{qs}"))
            .header("authorization", format!("Bearer {}", ctx.token))
            .body(Body::empty())
            .expect("构造请求失败");
        req.extensions_mut()
            .insert(ConnectInfo(SocketAddr::from((ctx.peer_ip, 4321))));
        let (status, body) = ctx.send_raw(req).await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "{leaf} 非法值应 400，实际: {status} {body}"
        );
        assert_eq!(body["code"], 400, "{leaf} 非法值业务码应 400，实际: {body}");
        let msg = body["msg"].as_str().unwrap_or("");
        assert!(!msg.is_empty(), "{leaf} 非法值必须给出可读原因: {body}");
        assert!(
            !msg.contains("error."),
            "{leaf} 的 msg 是原始 i18n 键（键未解析）: {msg}"
        );
        // 文案必须点名是哪个参数、并以非法值收尾（两份 locale 的模板都是"…当前值: %{value}"）
        assert!(msg.starts_with(leaf), "msg 必须点名参数 {leaf}: {msg}");
        assert!(
            msg.trim_end().ends_with(echoed),
            "msg 必须以非法值 {echoed} 收尾（回显用户给的原值）: {msg}"
        );
    }

    // 夹具清理（物理删除会级联清理 sys_notice_read，不留孤儿读记录）
    let v = ctx
        .delete_json(&format!("/system/notice/{a},{b},{c}"))
        .await;
    ctx.assert_ok(&v);
    for id in [a, b, c] {
        let (_, ids) = list_ids(&ctx, "pageNum=1&noticeTitle=it_vis_").await;
        assert!(!ids.contains(&id), "夹具 {id} 删除后不应再出现在列表里");
    }
    let read = ctx
        .get_json(&format!(
            "/system/notice/readUsers/list?noticeId={a}&pageNum=1&pageSize=10"
        ))
        .await;
    assert!(
        read["rows"]
            .as_array()
            .cloned()
            .unwrap_or_default()
            .is_empty(),
        "公告删除必须级联清理其已读记录，实际: {read}"
    );
}

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
