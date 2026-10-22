// stepby-axum/src/integration_tests/oauth_unbind_http.rs
//! `DELETE /oauth2/unbind` 的 HTTP 层闭环（批八十五 项 C）。
//!
//! 此前这条端点在 `endpoint-coverage-reasons.json` 里登记为
//! `needs-fixture: 要先有"已绑定的 OAuth 账号"；dev 库 admin 未绑` ——夹具确实要一行绑定记录，
//! 但**绑一行记录不需要外部授权服务器**：`sys_oauth_user` 就是普通表，`user_erasure.rs`
//! 已经在用 ActiveModel 直插夹具造匿名化前置。所以这条从来不是"测不了"，而是没人接。
//!
//! 本文件判到五件事，每件都落库复核：
//! ① 自助解绑成功后行真的消失；② 重复解绑 ⇒ 404 `error.oauth.no_binding`（幂等不静默成功）；
//! ③ **主体键收窄**：A 账号解不掉 B 账号的绑定（这条端点挂的是"仅登录"白名单，
//!    没有 perm 位，隔离全靠 `WHERE user_id = 操作者`——谓词写错就是横向越权）；
//! ④ 跨租户的另一账号绑定不得被连坐；⑤ 不带 `provider` 参数 ⇒ 400，
//!    不得退化成"解绑全部"（缺参数被读成空集合是本仓反复出现的那一族）。

use super::TestContext;
use crate::entity::sys_oauth_user::ActiveModel as OAuthUserActiveModel;
use axum::http::Method;
use sea_orm::{ActiveModelTrait, ConnectionTrait, DatabaseBackend, Set, Statement, Value};

/// 解绑夹具的 provider 名（用 `github`/`gitee` 两个字面值即可区分两支路径）
const MINE: &str = "github";
const OTHERS: &str = "gitee";
/// 属于另一租户的第三个账号（tenant 7）——用来判"跨租不连坐"
const OTHER_TENANT_UID: i64 = 300;

/// 直插一条绑定（`tenant_id` 显式给，验证读写两侧都按主体键收窄）
async fn insert_binding(ctx: &TestContext, tid: i64, uid: i64, provider: &str) {
    OAuthUserActiveModel {
        tenant_id: Set(tid),
        user_id: Set(uid),
        provider: Set(provider.into()),
        provider_user_id: Set(format!("{provider}-uid-{uid}")),
        ..Default::default()
    }
    .insert(&ctx.state.db)
    .await
    .expect("插入第三方绑定失败");
}

/// 按 (user_id, provider) 数行：解绑判据必须看到库里的事实，不能只看响应体
async fn binding_rows(ctx: &TestContext, uid: i64, provider: &str) -> i64 {
    let row = ctx
        .state
        .db
        .query_one_raw(Statement::from_sql_and_values(
            DatabaseBackend::Sqlite,
            "SELECT COUNT(*) AS n FROM sys_oauth_user WHERE user_id = ? AND provider = ?",
            [Value::from(uid), Value::from(provider)],
        ))
        .await
        .expect("计数查询失败")
        .expect("COUNT 必有一行");
    row.try_get::<i64>("", "n").expect("n 列应为整数")
}

/// ①②③④：正常解绑闭环 + 重复解绑 + 横向越权 + 跨租不连坐。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_oauth_unbind_http_closes_the_loop() {
    let ctx = TestContext::new().await;
    // admin = user_id 1 / tid 0（TestContext 用 admin 登录，见 mod.rs 的 login）
    insert_binding(&ctx, 0, 1, MINE).await;
    insert_binding(&ctx, 0, 2, OTHERS).await;
    insert_binding(&ctx, 7, OTHER_TENANT_UID, MINE).await;
    // 夹具自证（没有这一步，"删掉了"可以由"根本没插进去"蒙过——AGENTS《门禁全景》⑥）
    assert_eq!(
        binding_rows(&ctx, 1, MINE).await,
        1,
        "本人绑定行必须先在库里"
    );
    assert_eq!(
        binding_rows(&ctx, 2, OTHERS).await,
        1,
        "他人绑定行必须先在库里"
    );

    // 列表端点必须看得见（同一张表的读侧，证明这条链路的两侧都通）
    let v = ctx.get_json("/oauth2/my-bindings").await;
    let list = v["data"].as_array().cloned().unwrap_or_default();
    assert!(
        list.iter().any(|b| b["provider"].as_str() == Some(MINE)),
        "my-bindings 必须列出刚插的绑定，实际 {v}"
    );

    // ① 本人解绑 ⇒ 200 + msg.success.default + 行消失
    let (status, body) = ctx
        .send_raw(ctx.request(
            Method::DELETE,
            &format!("/oauth2/unbind?provider={MINE}"),
            None,
        ))
        .await;
    assert_eq!(
        status,
        axum::http::StatusCode::OK,
        "本人解绑应 200，实际 {body}"
    );
    assert_eq!(body["code"], 200, "业务码 200，实际 {body}");
    assert_eq!(
        body["msg"], "操作成功",
        "成功文案必须是 msg.success.default 的当前语言文本，实际 {body}"
    );
    assert_eq!(binding_rows(&ctx, 1, MINE).await, 0, "解绑后库里行必须消失");
    // 列表侧同步收敛（否则"解绑成功"只写在响应里）
    let v = ctx.get_json("/oauth2/my-bindings").await;
    let list = v["data"].as_array().cloned().unwrap_or_default();
    assert!(
        !list.iter().any(|b| b["provider"].as_str() == Some(MINE)),
        "解绑后 my-bindings 不得再列出该 provider，实际 {v}"
    );

    // ② 重复解绑 ⇒ 404 + no_binding 文案（不得静默成功）
    let (status, body) = ctx
        .send_raw(ctx.request(
            Method::DELETE,
            &format!("/oauth2/unbind?provider={MINE}"),
            None,
        ))
        .await;
    assert_eq!(
        status,
        axum::http::StatusCode::NOT_FOUND,
        "重复解绑应 404，实际 {body}"
    );
    assert_eq!(body["code"], 404, "业务码与 HTTP 同向，实际 {body}");
    assert_eq!(
        body["msg"], "该第三方账号尚未绑定本地账号",
        "拒绝文案必须是 error.oauth.no_binding，实际 {body}"
    );

    // ③ 横向越权：admin(1) 解 user 2 的 gitee ⇒ 404 且 user 2 的行必须还在
    let (status, body) = ctx
        .send_raw(ctx.request(
            Method::DELETE,
            &format!("/oauth2/unbind?provider={OTHERS}"),
            None,
        ))
        .await;
    assert_eq!(
        status,
        axum::http::StatusCode::NOT_FOUND,
        "解他人绑定应 404，实际 {body}"
    );
    assert_eq!(
        binding_rows(&ctx, 2, OTHERS).await,
        1,
        "他人绑定不得被连坐删除（隔离全靠 WHERE user_id）"
    );

    // ④ 跨租户同 provider：他租账号(300/tid7)也挂着 github，admin 解绑不得碰到它。
    //    这一支在①之后仍然成立 ⇒ 同时证明"按主体键收窄"不是"按 provider 全局删"。
    assert_eq!(
        binding_rows(&ctx, OTHER_TENANT_UID, MINE).await,
        1,
        "他租户同 provider 的绑定必须幸存"
    );
}

/// ⑤ 缺参数与空值：都不许退化成"解绑全部"。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_oauth_unbind_requires_a_provider_value() {
    let ctx = TestContext::new().await;
    insert_binding(&ctx, 0, 1, MINE).await;
    insert_binding(&ctx, 0, 1, OTHERS).await;

    // 不带 provider ⇒ Query 反序列化失败 ⇒ 400（不得当成"provider 为空"再删个遍）
    let (status, body) = ctx
        .send_raw(ctx.request(Method::DELETE, "/oauth2/unbind", None))
        .await;
    assert_eq!(
        status,
        axum::http::StatusCode::BAD_REQUEST,
        "缺 provider 必须 400，实际 {status} {body}"
    );
    assert_eq!(
        binding_rows(&ctx, 1, MINE).await,
        1,
        "缺参数不得删除任何绑定"
    );
    assert_eq!(
        binding_rows(&ctx, 1, OTHERS).await,
        1,
        "缺参数不得删除任何绑定（另一支）"
    );

    // 空 provider ⇒ 无此行 ⇒ 404，同样不得误删
    let (status, body) = ctx
        .send_raw(ctx.request(Method::DELETE, "/oauth2/unbind?provider=", None))
        .await;
    assert_eq!(
        status,
        axum::http::StatusCode::NOT_FOUND,
        "空 provider 应 404，实际 {body}"
    );
    assert_eq!(
        binding_rows(&ctx, 1, MINE).await,
        1,
        "空 provider 不得删掉真实绑定"
    );
}
