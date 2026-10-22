// stepby-axum/src/integration_tests/pwd_expiry.rs
//! 口令有效期 + 服务端强改密闸门（批八十四 项 A）的集成判据。
//!
//! 这一族用例存在的理由：**关掉时逐字段等价于改造前**与**打开时链路真能走完**必须分别被证明。
//! 只测打开态，就等于允许"默认态改变了现状"；只测关闭态，就等于允许能力是假的。
//!
//! 档位/开关都是 `sys_config` 热键（非部署态 config.toml 段）⇒ 不进
//! `build_isolated_state_with` 的钳制表；翻转一律走"直改库 + 失效 `config:def:` 缓存"
//! （与 `switch_states.rs` 同口径），且每个用例有自己的隔离库，互不污染。

use axum::body::Body;
use axum::http::{Method, Request, StatusCode};
use sea_orm::{ConnectionTrait, DatabaseBackend, Statement};

use super::{TestContext, login, next_peer_ip};
use crate::common::pwd_policy;

/// 翻热键并失效缓存（平台默认层 `config:def:{key}`，见 `sys_config_service` 两层缓存口径）。
async fn set_config(ctx: &TestContext, key: &str, value: &str) {
    ctx.state
        .db
        .execute_raw(Statement::from_string(
            DatabaseBackend::Sqlite,
            format!("UPDATE sys_config SET config_value='{value}' WHERE config_key='{key}'"),
        ))
        .await
        .unwrap_or_else(|e| panic!("写 sys_config[{key}] 失败: {e}"));
    let mut conn = ctx.redis();
    redis::cmd("DEL")
        .arg(format!("config:def:{key}"))
        .query_async::<()>(&mut conn)
        .await
        .expect("失效配置缓存失败");
}

/// 清掉"初始口令未改"标志（让判据只由过期时间戳决定）。
async fn clear_change_flag(ctx: &TestContext, user_name: &str) {
    let affected = ctx
        .state
        .db
        .execute_raw(Statement::from_string(
            DatabaseBackend::Sqlite,
            format!("UPDATE sys_user SET must_change_pwd = '0' WHERE user_name = '{user_name}'"),
        ))
        .await
        .expect("清标志失败");
    assert_eq!(
        affected.rows_affected(),
        1,
        "清标志必须恰好命中 1 个用户（{user_name}）"
    );
}

/// 把某用户的口令年龄推到 N 天前（模拟"很久没改过密码"）。
async fn age_password(ctx: &TestContext, user_name: &str, days: i64) {
    let affected = ctx
        .state
        .db
        .execute_raw(Statement::from_string(
            DatabaseBackend::Sqlite,
            format!(
                "UPDATE sys_user SET pwd_update_time = datetime('now', '-{days} days') WHERE user_name = '{user_name}'"
            ),
        ))
        .await
        .expect("调整口令年龄失败");
    assert_eq!(
        affected.rows_affected(),
        1,
        "口令年龄回拨必须恰好命中 1 个用户（{user_name}）——命中 0 行时后面的判据全是空跑"
    );
}

async fn get_info_body(ctx: &TestContext, token: &str) -> serde_json::Value {
    let (status, v) = ctx
        .send_raw(
            Request::builder()
                .method(Method::GET)
                .uri("/getInfo")
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .expect("构造 getInfo 请求失败"),
        )
        .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "/getInfo 必须 200，实际 {status} {v}"
    );
    v
}

/// 以指定 token 打一个业务端点，回状态码与响应体。
async fn as_token(
    ctx: &TestContext,
    token: &str,
    method: &str,
    uri: &str,
    body: Option<serde_json::Value>,
) -> (StatusCode, serde_json::Value) {
    let builder = Request::builder().method(method).uri(uri);
    let req = match body {
        Some(b) => builder
            .header("authorization", format!("Bearer {token}"))
            .header("content-type", "application/json")
            .body(Body::from(b.to_string()))
            .expect("构造请求失败"),
        None => builder
            .header("authorization", format!("Bearer {token}"))
            .body(Body::empty())
            .expect("构造请求失败"),
    };
    ctx.send_raw(req).await
}

/// 建一个可登录的测试用户（走真实 `POST /system/user`，顺带覆盖"建号即记口令年龄"）。
async fn create_loginable_user(ctx: &TestContext, user_name: &str, password: &str) -> i64 {
    let v = ctx
        .post_json(
            "/system/user",
            serde_json::json!({
                "deptId": 103,
                "userName": user_name,
                "nickName": user_name,
                "email": format!("{user_name}@stepby.test"),
                "phonenumber": "13900001234",
                "password": password,
                "status": "0",
                "roleIds": [1]
            }),
        )
        .await;
    ctx.assert_ok(&v);
    let list = ctx
        .get_json(&format!("/system/user/list?userName={user_name}"))
        .await;
    list["rows"][0]["userId"]
        .as_i64()
        .unwrap_or_else(|| panic!("应查到 {user_name} 的 userId，实际 {list}"))
}

/// ① 默认关闭态：`/getInfo` 的两个口令位必须与改造前逐字段等价（全 false），
///    且业务端点照常放行——这条是"默认值=现状"的可证伪单测，不是注释声明。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn off_state_keeps_getinfo_and_traffic_unchanged() {
    let ctx = TestContext::new().await;
    let v = get_info_body(&ctx, &ctx.token).await;
    assert_eq!(
        v["isPasswordExpired"].as_bool(),
        Some(false),
        "days 默认 0 ⇒ 过期位必须恒 false（现状）"
    );
    assert_eq!(
        v["mustChangePassword"].as_bool(),
        Some(false),
        "强改开关默认 false ⇒ 强制位必须恒 false（现状）"
    );
    // 关闭态下即便把口令年龄推到 400 天前也不得有任何行为变化（闸门 off）
    age_password(&ctx, "admin", 400).await;
    let (status, body) = as_token(&ctx, &ctx.token, "GET", "/system/post/list", None).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "关闭态业务读必须照常，实际 {status} {body}"
    );
    let v = get_info_body(&ctx, &ctx.token).await;
    assert_eq!(
        v["isPasswordExpired"].as_bool(),
        Some(false),
        "days=0 时不得因为有时间戳就判过期（策略与事实必须两把钥匙）"
    );
}

/// ② 只开有效期、不开强改：事实位翻真，但**不拦任何请求**（三段台阶的第二段）。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn expire_days_reports_fact_without_blocking() {
    let ctx = TestContext::new().await;
    set_config(&ctx, pwd_policy::PWD_EXPIRE_DAYS_CONFIG_KEY, "30").await;
    age_password(&ctx, "admin", 40).await;

    let v = get_info_body(&ctx, &ctx.token).await;
    assert_eq!(
        v["isPasswordExpired"].as_bool(),
        Some(true),
        "days=30 + 40 天前设置的口令 ⇒ 必须报过期，实际 {v}"
    );
    assert_eq!(
        v["mustChangePassword"].as_bool(),
        Some(false),
        "强改总闸未开 ⇒ 只报事实，不驱动强制（平台开关是天花板）"
    );
    let (status, body) = as_token(
        &ctx,
        &ctx.token,
        "POST",
        "/system/post",
        Some(serde_json::json!({
            "postName": "过期但不拦", "postCode": "it_expire_readonly", "postSort": 9, "status": "0"
        })),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "gate=off 时写操作必须照常（默认安全态不得变成默认拦截态），实际 {status} {body}"
    );
}

/// ③ 强改总闸 + `deny_write`：写拦读放；改密后闭环放行。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn deny_write_blocks_mutations_then_self_service_clears_gate() {
    let ctx = TestContext::new().await;
    set_config(&ctx, pwd_policy::FORCE_PWD_CHANGE_CONFIG_KEY, "true").await;
    set_config(&ctx, pwd_policy::PWD_CHANGE_GATE_CONFIG_KEY, "deny_write").await;
    set_config(&ctx, pwd_policy::PWD_EXPIRE_DAYS_CONFIG_KEY, "30").await;
    // 迁移会把 admin 标成"初始口令未改"（must_change_pwd='1'）。这里显式清掉，
    // 才能让下面的 403 **唯一**归因到口令过期这一条通道上——两因混在一起时，
    // 判据通过了也不知道自己判的是哪一支（本表"闸门不得与环境耦合"同源纪律）。
    clear_change_flag(&ctx, "admin").await;
    age_password(&ctx, "admin", 400).await;

    let (status, _) = as_token(&ctx, &ctx.token, "GET", "/system/post/list", None).await;
    assert_eq!(status, StatusCode::OK, "deny_write 档读必须放行");

    let (status, body) = as_token(
        &ctx,
        &ctx.token,
        "POST",
        "/system/post",
        Some(serde_json::json!({
            "postName": "被拦的写", "postCode": "it_gate_block", "postSort": 9, "status": "0"
        })),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "deny_write 档必须 403 拦写，实际 {status} {body}"
    );
    let msg = body["msg"].as_str().unwrap_or_default().to_string();
    assert!(
        !msg.contains("error.") && !msg.is_empty(),
        "错误文案必须是已解析的 i18n 文本，实际 {msg:?}"
    );
    assert!(msg.contains("过期"), "口令过期应给出可辨文案，实际 {msg:?}");

    // 自助改密在白名单内（否则闸门把唯一出路也锁了 = 不可完成的设计缺陷）
    let (status, body) = as_token(
        &ctx,
        &ctx.token,
        "PUT",
        "/system/user/profile/updatePwd",
        Some(serde_json::json!({ "oldPassword": "admin123", "newPassword": "Gatecleared9" })),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "白名单里的改密必须可通过（这是闸门的唯一出口），实际 {status} {body}"
    );

    // 改密后旧 token 失效（pwd_ver 语义）⇒ 用新口令重新登录，闸门必须放行
    let peer = next_peer_ip();
    let token2 = login(&ctx.app, peer, "admin", "Gatecleared9").await;
    let v = get_info_body(&ctx, &token2).await;
    assert_eq!(
        v["isPasswordExpired"].as_bool(),
        Some(false),
        "改密即刷新口令年龄 ⇒ 过期位必须归 false"
    );
    let (status, body) = as_token(
        &ctx,
        &token2,
        "POST",
        "/system/post",
        Some(serde_json::json!({
            "postName": "改密后的写", "postCode": "it_gate_after", "postSort": 9, "status": "0"
        })),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "改密后同一写操作必须恢复正常（业务链路跑通），实际 {status} {body}"
    );
}

/// ④ `deny_all`：业务读也拦，但 `getInfo` / `profile` / `updatePwd` / `getRouters` 必须仍可，
///    并证明权限层被前置抢占（拿到的是口令文案而非"无权限"）。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn deny_all_blocks_reads_but_keeps_the_whole_exit_path_open() {
    let ctx = TestContext::new().await;
    set_config(&ctx, pwd_policy::FORCE_PWD_CHANGE_CONFIG_KEY, "true").await;
    set_config(&ctx, pwd_policy::PWD_CHANGE_GATE_CONFIG_KEY, "deny_all").await;
    age_password(&ctx, "admin", 400).await;

    let (status, body) = as_token(&ctx, &ctx.token, "GET", "/system/post/list", None).await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "deny_all 档业务读必须被拦，实际 {status} {body}"
    );

    // 出口面逐个验（少任何一个 = 用户走不出去）。`/logout` 必须排在最后——
    // 它会注销当前 token，排在中间就让后面的判据全打在"会话已注销"上（本批实测踩过）。
    for (method, uri) in [
        ("GET", "/getInfo"),
        ("GET", "/getRouters"),
        ("GET", "/system/user/profile"),
        ("POST", "/logout"),
    ] {
        let (status, body) = as_token(&ctx, &ctx.token, method, uri, None).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "deny_all 档下 {method} {uri} 必须在白名单内放行，实际 {status} {body}"
        );
    }
    // 文案必须是**口令类**且可解析（不是通用 403、也不是原始键名）
    let msg = body["msg"].as_str().unwrap_or_default().to_string();
    assert!(
        !msg.contains("error.") && !msg.is_empty(),
        "错误文案必须是已解析的 i18n 文本，实际 {msg:?}"
    );
    assert!(msg.contains("口令"), "须是口令类文案，实际 {msg:?}");
}

/// ⑤ 非法档位回落 off：不得因为配错就拦人（fail-safe 的行为证明，而非注释）。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn illegal_gate_value_falls_back_to_off() {
    let ctx = TestContext::new().await;
    set_config(&ctx, pwd_policy::FORCE_PWD_CHANGE_CONFIG_KEY, "true").await;
    set_config(&ctx, pwd_policy::PWD_CHANGE_GATE_CONFIG_KEY, "server").await;
    age_password(&ctx, "admin", 400).await;
    let (status, body) = as_token(
        &ctx,
        &ctx.token,
        "POST",
        "/system/post",
        Some(serde_json::json!({
            "postName": "非法档", "postCode": "it_gate_illegal", "postSort": 9, "status": "0"
        })),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "非法档位必须回落 off（不拦人），实际 {status} {body}"
    );
}

/// ⑥ 迁移/兜底落地事实：建列即回填口令年龄，两个热键种子默认值就是关闭态。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn column_backfilled_and_seeds_default_to_off() {
    let ctx = TestContext::new().await;
    let nulls = ctx
        .state
        .db
        .query_all_raw(Statement::from_string(
            DatabaseBackend::Sqlite,
            "SELECT COUNT(*) AS c FROM sys_user WHERE pwd_update_time IS NULL".to_string(),
        ))
        .await
        .expect("查回填结果失败")
        .pop()
        .and_then(|r| r.try_get::<i64>("", "c").ok())
        .expect("计数行应可解析");
    assert_eq!(
        nulls, 0,
        "pwd_update_time 必须已全部回填（存量库不回填=策略看不见他们）"
    );

    let rows = ctx
        .state
        .db
        .query_all_raw(Statement::from_string(
            DatabaseBackend::Sqlite,
            format!(
                "SELECT config_key, config_value FROM sys_config WHERE config_key IN ('{}','{}')",
                pwd_policy::PWD_EXPIRE_DAYS_CONFIG_KEY,
                pwd_policy::PWD_CHANGE_GATE_CONFIG_KEY
            ),
        ))
        .await
        .expect("查种子失败");
    let got: std::collections::BTreeMap<String, String> = rows
        .iter()
        .map(|r| {
            (
                r.try_get::<String>("", "config_key").unwrap(),
                r.try_get::<String>("", "config_value").unwrap(),
            )
        })
        .collect();
    assert_eq!(
        got.get(pwd_policy::PWD_EXPIRE_DAYS_CONFIG_KEY)
            .map(String::as_str),
        Some("0"),
        "有效期种子必须种关闭态"
    );
    assert_eq!(
        got.get(pwd_policy::PWD_CHANGE_GATE_CONFIG_KEY)
            .map(String::as_str),
        Some("off"),
        "闸门种子必须种关闭态"
    );
    assert_eq!(got.len(), 2, "两键种子必须都在册，实际 {got:?}");
}

/// ⑦ 多租户/跨账号边界：闸门读的是**这个账号**的口令姿态，同租户另一账号不受连坐。
///    （AGENTS 铁律①：派生状态的成立前提必须由代码路径保证，不能只在注释里声明）
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn gate_is_per_account_not_per_tenant() {
    let ctx = TestContext::new().await;
    // 顺序即判据：**先建号，再翻闸门**。翻档后 admin 自己也是"初始口令未改"状态，
    // 建号请求会撞自己的闸门（实测正是这个顺序问题让本用例首轮判红）——
    // 这也说明运维开启 deny_* 前需要先解除自己的待改状态，文档已按实测写明。
    let pwd = "ItPwd#202601";
    create_loginable_user(&ctx, "it_gate_locked", pwd).await;
    create_loginable_user(&ctx, "it_gate_clean", pwd).await;
    set_config(&ctx, pwd_policy::FORCE_PWD_CHANGE_CONFIG_KEY, "true").await;
    set_config(&ctx, pwd_policy::PWD_CHANGE_GATE_CONFIG_KEY, "deny_all").await;
    set_config(&ctx, pwd_policy::PWD_EXPIRE_DAYS_CONFIG_KEY, "30").await;

    // 两个账号都清掉"初始口令未改"标志，并把差异**只**留在口令年龄一列上：
    // locked 拨回 400 天，clean 保持"刚刚设置过"。这样"谁被拦"只有一个解释。
    clear_change_flag(&ctx, "it_gate_locked").await;
    clear_change_flag(&ctx, "it_gate_clean").await;
    age_password(&ctx, "it_gate_locked", 400).await;

    let peer = next_peer_ip();
    let token_locked = login(&ctx.app, peer, "it_gate_locked", pwd).await;
    let peer = next_peer_ip();
    let token_clean = login(&ctx.app, peer, "it_gate_clean", pwd).await;

    let (status, body) = as_token(&ctx, &token_locked, "GET", "/system/post/list", None).await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "过期账号必须被拦，实际 {status} {body}"
    );
    let (status, body) = as_token(&ctx, &token_clean, "GET", "/system/post/list", None).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "同租户未过期账号不得连坐（闸门按 claims.sub 精确取行），实际 {status} {body}"
    );
}
