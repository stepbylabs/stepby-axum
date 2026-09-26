//! 「显式清空」（`clearFields`）契约的**真实 HTTP 链路**集成测试（批次 4）。
//!
//! `common::clear_fields` 自身有 5 条纯函数单测；本文件补的是**端到端**证据：
//! 经 `handler → serde → garde → service → sea-orm → SQLite` 全链后，
//! 「未声明清空 = 保持现值」与「声明清空 = 真正写 NULL」是否真的成立
//! （单测覆盖不到 serde 缺省、DTO 白名单映射与 SQL 写入）。
//!
//! 覆盖：
//! 1. 渠道：不传 `configJson` 的部分更新**不得**擦除既有（已加密）配置；
//! 2. 渠道：`clearFields: ["configJson"]` ⇒ 详情接口可见 **null**；
//! 3. 渠道：白名单外字段 ⇒ **HTTP 400** 且 message 含字段名（fail-closed，不静默忽略）；
//! 4. 渠道：同字段「既提交非空值 + 又声明清空」⇒ **HTTP 400**（消除语义歧义）；
//! 5. 租户：`contactName` 与**根部门** `leader` 的「保持 / 清空」两态（含 `sys_dept` 行核对）。

use axum::http::{Method, StatusCode};
use sea_orm::{ConnectionTrait, DatabaseBackend, Statement};

use super::TestContext;

/// 建一个带明文 `configJson` 的 sms 渠道（sms 走模拟投递，无需真实网关）。
async fn seed_channel(ctx: &TestContext, code: &str) -> (i64, String) {
    let plain = r#"{"access_key":"k","secret_key":"s"}"#.to_string();
    let v = ctx
        .post_json(
            "/system/msg/channel",
            serde_json::json!({
                "channelName": "it_cf_渠道",
                "channelCode": code,
                "channelType": "sms",
                "configJson": plain,
                "status": "0"
            }),
        )
        .await;
    ctx.assert_ok(&v);
    let id = v["data"]["channelId"].as_i64().expect("channelId 应为数字");
    (id, plain)
}

/// 读取渠道详情中的 `configJson`（`null` / 缺键均返回 `None`）。
async fn detail_config(ctx: &TestContext, channel_id: i64) -> Option<String> {
    let v = ctx
        .get_json(&format!("/system/msg/channel/{}", channel_id))
        .await;
    v["data"]["configJson"].as_str().map(str::to_string)
}

/// 渠道配置的「保持现值」与「显式清空」两态（本批核心语义）。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_channel_config_json_keep_then_explicit_clear() {
    let ctx = TestContext::new().await;
    let (id, plain) = seed_channel(&ctx, "it_cf_keep").await;
    assert_eq!(
        detail_config(&ctx, id).await.as_deref(),
        Some(plain.as_str()),
        "新增后详情应回显明文配置"
    );

    // ① 只改名称（不传 configJson）⇒ 配置必须保持（回退：原缺陷会在此被擦成 NULL）
    let v = ctx
        .put_json(
            "/system/msg/channel",
            serde_json::json!({
                "channelId": id,
                "channelName": "it_cf_渠道改名",
                "channelCode": "it_cf_keep",
                "channelType": "sms",
                "status": "0"
            }),
        )
        .await;
    ctx.assert_ok(&v);
    assert_eq!(
        detail_config(&ctx, id).await.as_deref(),
        Some(plain.as_str()),
        "未声明 clearFields 时既有配置不得被擦除"
    );

    // ② 显式声明清空 ⇒ 写 NULL（且详情可见）
    let v = ctx
        .put_json(
            "/system/msg/channel",
            serde_json::json!({
                "channelId": id,
                "channelName": "it_cf_渠道改名",
                "channelCode": "it_cf_keep",
                "channelType": "sms",
                "status": "0",
                "clearFields": ["configJson"]
            }),
        )
        .await;
    ctx.assert_ok(&v);
    assert_eq!(
        detail_config(&ctx, id).await,
        None,
        "声明 clearFields 后配置应为 null"
    );
}

/// 白名单外字段（fail-closed）与「值 + 清空」冲突（400）。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_channel_clear_fields_rejects_unknown_and_conflict() {
    let ctx = TestContext::new().await;
    let (id, plain) = seed_channel(&ctx, "it_cf_reject").await;

    let edit_body = |extra: serde_json::Value| {
        let mut b = serde_json::json!({
            "channelId": id,
            "channelName": "it_cf_渠道",
            "channelCode": "it_cf_reject",
            "channelType": "sms",
            "status": "0"
        });
        b.as_object_mut()
            .expect("body 应为对象")
            .extend(extra.as_object().expect("extra 应为对象").clone());
        b
    };

    // ① 非白名单字段（channelName 可清空语义不存在）⇒ 400，且 message 点名该字段
    let (status, v) = ctx
        .send_raw(ctx.request(
            Method::PUT,
            "/system/msg/channel",
            Some(edit_body(
                serde_json::json!({ "clearFields": ["channelName"] }),
            )),
        ))
        .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "白名单外字段应 400，实际: {status} {v}"
    );
    assert_eq!(v["code"], 400, "业务码应为 400，实际: {v}");
    assert!(
        v["msg"]
            .as_str()
            .unwrap_or_default()
            .contains("channelName"),
        "错误信息应包含非法字段名，实际: {v}"
    );

    // ② 同时提交非空值 + 声明清空 ⇒ 400（歧义必须显式报错，不得任选其一静默生效）
    let (status, v) = ctx
        .send_raw(ctx.request(
            Method::PUT,
            "/system/msg/channel",
            Some(edit_body(serde_json::json!({
                "configJson": plain,
                "clearFields": ["configJson"]
            }))),
        ))
        .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "值/清空冲突应 400，实际: {status} {v}"
    );
    assert_eq!(v["code"], 400, "业务码应为 400，实际: {v}");
    assert!(
        v["msg"].as_str().unwrap_or_default().contains("configJson"),
        "错误信息应包含冲突字段名，实际: {v}"
    );

    // ③ 两次失败请求都不得产生副作用：配置仍是原值
    assert_eq!(
        detail_config(&ctx, id).await.as_deref(),
        Some(plain.as_str()),
        "被拒请求不得改动配置"
    );
}

/// 租户链路：`contactName`（`sys_tenant` 行）与 `leader`（**根部门**行）的保持 / 清空两态。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_tenant_clear_fields_keep_then_clear_root_dept() {
    let ctx = TestContext::new().await;

    // 播种：租户行 + 其组织树根部门行（显式给定可清空字段的初值）
    ctx.state
        .db
        .execute(Statement::from_string(
            DatabaseBackend::Sqlite,
            "INSERT INTO sys_tenant (tenant_id, tenant_code, tenant_name, dept_id, contact_name, \
             contact_phone, contact_email, account_count, status, del_flag, create_time, update_time) \
             VALUES (9101, 'it_cf', 'it_cf_租户', 9101, '联系人甲', '13800000000', \
             'a@example.com', 0, '0', '0', datetime('now'), datetime('now'))"
                .to_string(),
        ))
        .await
        .expect("播种租户失败");
    ctx.state
        .db
        .execute(Statement::from_string(
            DatabaseBackend::Sqlite,
            "INSERT INTO sys_dept (tenant_id, dept_id, dept_name, leader, phone, email, status, \
             del_flag, create_time) \
             VALUES (9101, 9101, 'it_cf_租户', '负责人乙', '13900000000', 'b@example.com', '0', \
             '0', datetime('now'))"
                .to_string(),
        ))
        .await
        .expect("播种根部门失败");

    let dept_row = |field: &'static str| {
        let db = ctx.state.db.clone();
        async move {
            let row = db
                .query_one(Statement::from_string(
                    DatabaseBackend::Sqlite,
                    format!("SELECT {field} FROM sys_dept WHERE dept_id = 9101"),
                ))
                .await
                .expect("查询根部门失败")
                .expect("根部门行应存在");
            row.try_get::<Option<String>>("", field)
                .expect("读取字段失败")
        }
    };
    let tenant_contact = || {
        let db = ctx.state.db.clone();
        async move {
            let row = db
                .query_one(Statement::from_string(
                    DatabaseBackend::Sqlite,
                    "SELECT contact_name FROM sys_tenant WHERE tenant_id = 9101".to_string(),
                ))
                .await
                .expect("查询租户失败")
                .expect("租户行应存在");
            row.try_get::<Option<String>>("", "contact_name")
                .expect("读取 contact_name 失败")
        }
    };

    // ① 只改名称（不传联系信息、不声明清空）⇒ 租户行与根部门行**均保持现值**
    let v = ctx
        .put_json(
            "/system/tenant",
            serde_json::json!({ "tenantId": 9101, "tenantName": "it_cf_租户改名" }),
        )
        .await;
    ctx.assert_ok(&v);
    assert_eq!(
        tenant_contact().await.as_deref(),
        Some("联系人甲"),
        "未声明清空时 contactName 应保持"
    );
    assert_eq!(
        dept_row("leader").await.as_deref(),
        Some("负责人乙"),
        "未声明清空时根部门 leader 应保持"
    );

    // ② 显式清空 contactName + leader（后者落在**根部门**行，验证同口径）
    let v = ctx
        .put_json(
            "/system/tenant",
            serde_json::json!({
                "tenantId": 9101,
                "tenantName": "it_cf_租户改名",
                "clearFields": ["contactName", "leader"]
            }),
        )
        .await;
    ctx.assert_ok(&v);
    assert_eq!(
        tenant_contact().await,
        None,
        "声明清空后 contactName 应为 NULL"
    );
    assert_eq!(
        dept_row("leader").await,
        None,
        "声明清空后根部门 leader 应为 NULL"
    );
    // 未声明清空的邻近字段不得被连带清空
    assert_eq!(
        dept_row("phone").await.as_deref(),
        Some("13900000000"),
        "未声明的 phone 不应被连带清空"
    );
}
