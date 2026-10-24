//! 报表中心 + 定时订阅推送模块链路集成测试：
//! - 报表定义：分页列表 / 详情 / 新增 → 修改 → 删除 / 启停 / 手动预览快照 / 参数校验
//! - 报表订阅：分页列表 / 详情 / 新增 → 修改 → 删除 / 启停 / 手动触发推送 / 参数校验
//!
//! 说明：
//! - 种子仅在迁移中写入菜单元数据，报表定义与订阅表均为空，初始列表为空。
//! - 快照/推送走既有聚合逻辑，推送邮件经 MailerService（未启用时自动 no-op），
//!   站内信写入 sys_msg_send_log，均为纯查询/插入，无副作用，可安全触发。
//! - 数据前缀：it_rpt_

use super::TestContext;
use axum::http::{Method, StatusCode};

/// 新增一条 custom 类型报表并返回 report_id（供报表与订阅链路复用）。
async fn create_custom_report(ctx: &TestContext, code: &str, name: &str) -> i64 {
    let v = ctx
        .post_json(
            "/system/report",
            serde_json::json!({
                "reportCode": code,
                "reportName": name,
                "reportType": "custom",
                "config": r#"{"k":"v"}"#,
                "status": "0",
                "remark": "集成测试报表"
            }),
        )
        .await;
    ctx.assert_ok(&v);
    v["data"]["reportId"]
        .as_i64()
        .expect("报表新增应返回 reportId")
}

/// 报表定义全链路：空列表 → 新增 → 列表 → 详情 → 修改 → 预览 → 启停 → 删除 + 参数校验。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_report_chain() {
    let ctx = TestContext::new().await;

    // 1. 初始列表应为空（无种子报表定义）
    let v = ctx
        .get_json("/system/report/list?pageNum=1&pageSize=10")
        .await;
    let rows = v["rows"].as_array().expect("rows 应为数组");
    assert!(rows.is_empty(), "初始不应有报表定义，实际: {v}");

    // 2. 新增报表定义
    let report_id = create_custom_report(&ctx, "it_rpt_custom", "it_rpt_custom_name").await;

    // 3. 按 reportCode 过滤查询到新报表
    let v = ctx
        .get_json("/system/report/list?reportCode=it_rpt_custom")
        .await;
    let rows = v["rows"].as_array().expect("rows 应为数组");
    assert_eq!(rows.len(), 1, "应查到 1 条新报表，实际: {v}");
    assert_eq!(
        rows[0]["reportCode"], "it_rpt_custom",
        "报表编码应匹配，实际: {v}"
    );

    // 4. 详情
    let v = ctx.get_json(&format!("/system/report/{}", report_id)).await;
    assert_eq!(
        v["data"]["reportId"], report_id,
        "报表详情 reportId 应匹配，实际: {v}"
    );
    assert_eq!(
        v["data"]["reportName"], "it_rpt_custom_name",
        "报表名称应匹配，实际: {v}"
    );
    assert_eq!(
        v["data"]["reportType"], "custom",
        "报表类型应匹配，实际: {v}"
    );

    // 5. 修改报表定义
    let v = ctx
        .put_json(
            "/system/report",
            serde_json::json!({
                "reportId": report_id,
                "reportCode": "it_rpt_custom",
                "reportName": "it_rpt_custom_edited",
                "reportType": "custom",
                "config": r#"{"k":"v"}"#,
                "status": "0",
                "remark": "集成测试修改"
            }),
        )
        .await;
    ctx.assert_ok(&v);
    let v = ctx.get_json(&format!("/system/report/{}", report_id)).await;
    assert_eq!(
        v["data"]["reportName"], "it_rpt_custom_edited",
        "修改后报表名称应生效，实际: {v}"
    );

    // 6. 手动预览快照（custom 类型 data 透传配置 JSON，不落库不推送）
    let v = ctx
        .post_json(
            &format!("/system/report/{}/preview", report_id),
            serde_json::json!({}),
        )
        .await;
    assert_eq!(
        v["data"]["reportCode"], "it_rpt_custom",
        "预览应返回报表编码，实际: {v}"
    );
    assert_eq!(
        v["data"]["reportType"], "custom",
        "预览应返回报表类型，实际: {v}"
    );
    assert_eq!(
        v["data"]["data"]["k"], "v",
        "custom 预览快照应透传配置 JSON，实际: {v}"
    );

    // 7. 报表启停（0→1：启用→停用）
    let v = ctx
        .put_json(
            &format!("/system/report/{}/status", report_id),
            serde_json::json!({ "status": "1" }),
        )
        .await;
    ctx.assert_ok(&v);
    let v = ctx.get_json(&format!("/system/report/{}", report_id)).await;
    assert_eq!(v["data"]["status"], "1", "报表状态应为 1(停用)，实际: {v}");

    // 8. 删除报表定义（级联逻辑删除其下订阅）
    let v = ctx
        .delete_json(&format!("/system/report/{}", report_id))
        .await;
    ctx.assert_ok(&v);

    // 9. 删除后详情应 404
    let (status, _) = ctx
        .send_raw(ctx.request(Method::GET, &format!("/system/report/{}", report_id), None))
        .await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "删除后查询报表应 404，实际: {status}"
    );

    // 10. 重复 report_code 新增应拒绝（400）
    let dup_id = create_custom_report(&ctx, "it_rpt_dup", "it_rpt_dup_name").await;
    let (status, v) = ctx
        .send_raw(ctx.request(
            Method::POST,
            "/system/report",
            Some(serde_json::json!({
                "reportCode": "it_rpt_dup",
                "reportName": "it_rpt_dup_again",
                "reportType": "custom",
                "config": r#"{"k":"v"}"#,
                "status": "0"
            })),
        ))
        .await;
    assert_ne!(v["code"], 200, "重复编码业务码不应为 200，实际: {v}");
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "重复编码应 400，实际: {status}"
    );
    let v = ctx.delete_json(&format!("/system/report/{}", dup_id)).await;
    ctx.assert_ok(&v);

    // 11. 非法报表类型新增应拒绝（400）
    let (status, v) = ctx
        .send_raw(ctx.request(
            Method::POST,
            "/system/report",
            Some(serde_json::json!({
                "reportCode": "it_rpt_bad_type",
                "reportName": "it_rpt_bad_type",
                "reportType": "foo",
                "config": r#"{"k":"v"}"#,
                "status": "0"
            })),
        ))
        .await;
    assert_ne!(v["code"], 200, "非法类型业务码不应为 200，实际: {v}");
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "非法报表类型应 400，实际: {status}"
    );

    // 12. 非法 config JSON 新增应拒绝（400）
    let (status, v) = ctx
        .send_raw(ctx.request(
            Method::POST,
            "/system/report",
            Some(serde_json::json!({
                "reportCode": "it_rpt_bad_config",
                "reportName": "it_rpt_bad_config",
                "reportType": "custom",
                "config": "not a json",
                "status": "0"
            })),
        ))
        .await;
    assert_ne!(v["code"], 200, "非法 config 业务码不应为 200，实际: {v}");
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "非法 config JSON 应 400，实际: {status}"
    );

    // 13. 空 id 列表删除应返回 400
    let (status, v) = ctx
        .send_raw(ctx.request(Method::DELETE, "/system/report/,", None))
        .await;
    assert_ne!(v["code"], 200, "空 id 删除业务码不应为 200，实际: {v}");
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "空 id 删除应返回 400，实际: {status}"
    );
}

/// 报表订阅全链路：创建父报表 → 新增订阅 → 列表 → 详情 → 修改 → 启停 → 手动推送 → 删除 + 参数校验。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_report_sub_chain() {
    let ctx = TestContext::new().await;

    // G-16：站内信改走 SysMsgService::send 统一投递内核——前置 seed report_push
    // 模板（site 渠道由 flow 种子保证；生产环境由 initialize 幂等 seed 等价覆盖）
    let v = ctx
        .post_json(
            "/system/msg/template",
            serde_json::json!({
                "templateName": "it_rpt_报表推送模板",
                "templateCode": "report_push",
                "channelCode": "site",
                "templateSubject": "报表推送：{{report_name}}",
                "templateContent": "{{content}}",
                "status": "0"
            }),
        )
        .await;
    ctx.assert_ok(&v);

    // 1. 创建父报表（保持启用，供订阅推送）
    let report_id = create_custom_report(&ctx, "it_rpt_sub_parent", "it_rpt_sub_parent_name").await;

    // 2. 新增订阅（站内信推送至 user_id=1）
    let v = ctx
        .post_json(
            "/system/report/sub",
            serde_json::json!({
                "reportId": report_id,
                "subName": "it_rpt_sub_name",
                "cron": "0 0 9 * * *",
                "pushEmail": "0",
                "receiveEmail": null,
                "pushSysMsg": "1",
                "receiveUserIds": "1",
                "status": "0",
                "remark": "集成测试订阅"
            }),
        )
        .await;
    ctx.assert_ok(&v);
    let sub_id = v["data"]["subId"].as_i64().expect("订阅新增应返回 subId");

    // 3. 按 subName 过滤查询到新订阅
    let v = ctx
        .get_json("/system/report/sub/list?subName=it_rpt_sub_name")
        .await;
    let rows = v["rows"].as_array().expect("rows 应为数组");
    assert_eq!(rows.len(), 1, "应查到 1 条新订阅，实际: {v}");

    // 4. 订阅详情
    let v = ctx
        .get_json(&format!("/system/report/sub/{}", sub_id))
        .await;
    assert_eq!(
        v["data"]["subId"], sub_id,
        "订阅详情 subId 应匹配，实际: {v}"
    );
    assert_eq!(
        v["data"]["reportId"], report_id,
        "订阅应关联父报表，实际: {v}"
    );

    // 5. 修改订阅
    let v = ctx
        .put_json(
            "/system/report/sub",
            serde_json::json!({
                "subId": sub_id,
                "reportId": report_id,
                "subName": "it_rpt_sub_edited",
                "cron": "0 0 9 * * *",
                "pushEmail": "0",
                "receiveEmail": null,
                "pushSysMsg": "1",
                "receiveUserIds": "1",
                "status": "0",
                "remark": "集成测试修改"
            }),
        )
        .await;
    ctx.assert_ok(&v);
    let v = ctx
        .get_json(&format!("/system/report/sub/{}", sub_id))
        .await;
    assert_eq!(
        v["data"]["subName"], "it_rpt_sub_edited",
        "修改后订阅名称应生效，实际: {v}"
    );

    // 6. 订阅启停（0→1：启用→停用）
    let v = ctx
        .put_json(
            &format!("/system/report/sub/{}/status", sub_id),
            serde_json::json!({ "status": "1" }),
        )
        .await;
    ctx.assert_ok(&v);
    let v = ctx
        .get_json(&format!("/system/report/sub/{}", sub_id))
        .await;
    assert_eq!(v["data"]["status"], "1", "订阅状态应为 1(停用)，实际: {v}");

    // 7. 手动触发订阅推送（父报表仍启用；站内信写入 sys_msg_send_log，邮件 no-op）
    let v = ctx
        .post_json(
            &format!("/system/report/sub/{}/run", sub_id),
            serde_json::json!({}),
        )
        .await;
    assert_eq!(
        v["data"]["reportName"], "it_rpt_sub_parent_name",
        "推送应返回报表名称，实际: {v}"
    );
    assert_eq!(
        v["data"]["emailsSent"], 0,
        "未启用邮件推送，应 0 封，实际: {v}"
    );
    assert_eq!(
        v["data"]["siteMsgs"], 1,
        "站内信应推送给 1 个用户，实际: {v}"
    );

    // 8. 订阅参数校验（均为 400，确定性）
    // 8.1 无任何推送渠道
    let (status, v) = ctx
        .send_raw(ctx.request(
            Method::POST,
            "/system/report/sub",
            Some(serde_json::json!({
                "reportId": report_id,
                "subName": "it_rpt_bad_channel",
                "cron": "0 0 9 * * *",
                "pushEmail": "0",
                "receiveEmail": null,
                "pushSysMsg": "0",
                "receiveUserIds": null,
                "status": "0"
            })),
        ))
        .await;
    assert_ne!(v["code"], 200, "无推送渠道业务码不应为 200，实际: {v}");
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "无推送渠道应 400，实际: {status}"
    );

    // 8.2 非法 cron 表达式
    let (status, v) = ctx
        .send_raw(ctx.request(
            Method::POST,
            "/system/report/sub",
            Some(serde_json::json!({
                "reportId": report_id,
                "subName": "it_rpt_bad_cron",
                "cron": "not a cron",
                "pushEmail": "0",
                "receiveEmail": null,
                "pushSysMsg": "1",
                "receiveUserIds": "1",
                "status": "0"
            })),
        ))
        .await;
    assert_ne!(v["code"], 200, "非法 cron 业务码不应为 200，实际: {v}");
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "非法 cron 应 400，实际: {status}"
    );

    // 8.3 邮件渠道但收件邮箱非法
    let (status, v) = ctx
        .send_raw(ctx.request(
            Method::POST,
            "/system/report/sub",
            Some(serde_json::json!({
                "reportId": report_id,
                "subName": "it_rpt_bad_email",
                "cron": "0 0 9 * * *",
                "pushEmail": "1",
                "receiveEmail": "bad-email",
                "pushSysMsg": "0",
                "receiveUserIds": null,
                "status": "0"
            })),
        ))
        .await;
    assert_ne!(v["code"], 200, "非法邮箱业务码不应为 200，实际: {v}");
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "非法收件邮箱应 400，实际: {status}"
    );

    // 8.4 站内信渠道但目标用户为空
    let (status, v) = ctx
        .send_raw(ctx.request(
            Method::POST,
            "/system/report/sub",
            Some(serde_json::json!({
                "reportId": report_id,
                "subName": "it_rpt_bad_users",
                "cron": "0 0 9 * * *",
                "pushEmail": "0",
                "receiveEmail": null,
                "pushSysMsg": "1",
                "receiveUserIds": "",
                "status": "0"
            })),
        ))
        .await;
    assert_ne!(v["code"], 200, "空目标用户业务码不应为 200，实际: {v}");
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "空目标用户应 400，实际: {status}"
    );

    // 8.5 关联的报表不存在
    let (status, v) = ctx
        .send_raw(ctx.request(
            Method::POST,
            "/system/report/sub",
            Some(serde_json::json!({
                "reportId": 999999,
                "subName": "it_rpt_bad_report",
                "cron": "0 0 9 * * *",
                "pushEmail": "0",
                "receiveEmail": null,
                "pushSysMsg": "1",
                "receiveUserIds": "1",
                "status": "0"
            })),
        ))
        .await;
    assert_ne!(v["code"], 200, "报表不存在业务码不应为 200，实际: {v}");
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "关联报表不存在应 400，实际: {status}"
    );

    // 9. 删除订阅
    let v = ctx
        .delete_json(&format!("/system/report/sub/{}", sub_id))
        .await;
    ctx.assert_ok(&v);

    // 10. 删除后详情应 404
    let (status, _) = ctx
        .send_raw(ctx.request(Method::GET, &format!("/system/report/sub/{}", sub_id), None))
        .await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "删除后查询订阅应 404，实际: {status}"
    );

    // 11. 空 id 列表删除应返回 400
    let (status, v) = ctx
        .send_raw(ctx.request(Method::DELETE, "/system/report/sub/,", None))
        .await;
    assert_ne!(v["code"], 200, "空 id 删除业务码不应为 200，实际: {v}");
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "空 id 删除应返回 400，实际: {status}"
    );
}

/// b89 项 1：报表订阅接收人的租户收敛（跨租户投递回归锁）。
///
/// 立案形状：`receive_user_ids` 过去只校验"非空可解析"，投递时逐个 `to_addr = uid` 落
/// `sys_msg_send_log` ⇒ 订阅（tenant 9010）里填上他租用户（9020）就把本报表内容投进了
/// 另一租户的站内信。这一把同时验三件事：
/// ① 投递侧真的按 `sub.tenant_id` 剔出他租接收人（不是只改了写侧）；
/// ② 被剔出的那个用户**一条 send_log 都没有**（"少投了"与"投错了"都算失败）；
/// ③ 写侧对不存在的接收人给 400，而对在册用户照常 200（对照组真受约束）。
#[tokio::test]
async fn test_report_sub_recipients_are_tenant_scoped() {
    use axum::http::Method;
    use sea_orm::{ActiveModelTrait, ColumnTrait, EntityTrait, QueryFilter, Set};

    const TID_A: i64 = 9010;
    const TID_B: i64 = 9020;
    const UID_A: i64 = 9301;
    const UID_B: i64 = 9302;
    const SUB_ID: i64 = 94001;

    let ctx = TestContext::new().await;
    let db = &ctx.state.db;

    // 站内信必须有 report_push 模板，否则投递整批跳过 ⇒ 断言会 vacuous 成立
    let v = ctx
        .post_json(
            "/system/msg/template",
            serde_json::json!({
                "templateName": "it_rpt_scope_报表推送模板",
                "templateCode": "report_push",
                "channelCode": "site",
                "templateSubject": "报表推送：{{report_name}}",
                "templateContent": "{{content}}",
                "status": "0"
            }),
        )
        .await;
    ctx.assert_ok(&v);

    for (uid, tid) in [(UID_A, TID_A), (UID_B, TID_B)] {
        crate::entity::sys_user::ActiveModel {
            user_id: Set(uid),
            user_name: Set(format!("it_rpt_scope_{uid}")),
            nick_name: Set(format!("IT-RPT-SCOPE-{uid}")),
            tenant_id: Set(tid),
            status: Set(Some("0".to_string())),
            del_flag: Set(Some("0".to_string())),
            ..Default::default()
        }
        .insert(db)
        .await
        .expect("插入接收人失败");
    }

    let report_id = create_custom_report(&ctx, "it_rpt_scope_parent", "it_rpt_scope_report").await;

    // 直插一条属于租户 A 的订阅，接收人写成「A 的用户 + B 的用户」
    crate::entity::sys_report_sub::ActiveModel {
        sub_id: Set(SUB_ID),
        tenant_id: Set(TID_A),
        report_id: Set(report_id),
        sub_name: Set("it_rpt_scope_sub".to_string()),
        cron: Set("0 0 3 1 1 *".to_string()),
        push_email: Set("0".to_string()),
        receive_email: Set(None),
        push_sys_msg: Set("1".to_string()),
        receive_user_ids: Set(Some(format!("{UID_A},{UID_B}"))),
        status: Set("0".to_string()),
        ..Default::default()
    }
    .insert(db)
    .await
    .expect("插入订阅失败");

    // ① + ②：手动触发推送——平台代管身份执行，投递归属仍按 sub.tenant_id 收敛
    let v = ctx
        .post_json(
            &format!("/system/report/sub/{}/run", SUB_ID),
            serde_json::json!({}),
        )
        .await;
    assert_eq!(
        v["data"]["siteMsgs"].as_i64(),
        Some(1),
        "只应给本租户接收人投 1 封，实际: {v}"
    );

    let delivered = crate::entity::sys_msg_send_log::Entity::find()
        .filter(
            crate::entity::sys_msg_send_log::Column::ToAddr
                .is_in(vec![UID_A.to_string(), UID_B.to_string()]),
        )
        .all(db)
        .await
        .expect("查投递记录失败");
    let addrs: Vec<&str> = delivered.iter().map(|r| r.to_addr.as_str()).collect();
    assert!(
        addrs.contains(&UID_A.to_string().as_str()),
        "本租户接收人必须收到，实际: {addrs:?}"
    );
    assert!(
        !addrs.contains(&UID_B.to_string().as_str()),
        "他租接收人一条都不许出现（这就是立案的越权投递），实际: {addrs:?}"
    );

    // ③ 写侧：不存在的接收人必须 400（而不是静默收下、到投递时才少发）
    let (status, v) = ctx
        .send_raw(ctx.request(
            Method::POST,
            "/system/report/sub",
            Some(serde_json::json!({
                "reportId": report_id,
                "subName": "it_rpt_scope_bad",
                "cron": "0 0 9 * * *",
                "pushEmail": "0",
                "receiveEmail": null,
                "pushSysMsg": "1",
                "receiveUserIds": "999999",
                "status": "0"
            })),
        ))
        .await;
    assert_eq!(
        status,
        axum::http::StatusCode::BAD_REQUEST,
        "不存在的接收人应 400，实际: {v}"
    );

    // ③ 对照组：种子 admin（user_id=1，平台在册）必须照常 200——
    // 否则这条判据可以是"任何接收人都拒"，而那样它什么也没检验
    let v = ctx
        .post_json(
            "/system/report/sub",
            serde_json::json!({
                "reportId": report_id,
                "subName": "it_rpt_scope_ok",
                "cron": "0 0 9 * * *",
                "pushEmail": "0",
                "receiveEmail": null,
                "pushSysMsg": "1",
                "receiveUserIds": "1",
                "status": "0"
            }),
        )
        .await;
    ctx.assert_ok(&v);
}
