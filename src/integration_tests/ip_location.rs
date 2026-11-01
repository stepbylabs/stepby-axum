// stepby-axum/src/integration_tests/ip_location.rs
//! IP 归属地库管理链路集成测试：
//! - GET  /system/ipLocation/status   状态结构断言
//! - GET  /system/ipLocation/config   脱敏配置结构断言
//! - PUT  /system/ipLocation/config   保存快乐路径（p3terx）+ 参数校验失败分支（400）
//!
//! 说明：
//! - /system/ipLocation/* 为受保护路由；admin 是超管（*:*:*，权限中间件短路）可直接访问。
//! - 测试环境 mmdb/xdb 库文件可能不存在，服务优雅降级：mmdbLoaded/xdbLoaded 为布尔并反映真实状态，
//!   此处只断言字段结构（is_boolean），不断言具体加载值，保证文件存在与否都稳定通过。
//! - update / reload 会真实下载/读取 IP 库文件，依赖外部环境，**下载链路**不在集成测试覆盖范围内；
//!   `POST /update` 只覆盖它的入参闸门（源非法 / maxmind 缺凭据 ⇒ 400，且抢锁与换文件之前就被拒）。
//! - 所有断言仅做加法（put_json 快乐路径 / send_raw 校验分支），不触发任何真实外部调用。

use axum::http::{Method, StatusCode};

use super::TestContext;

/// IP 库状态：断言结构字段存在且类型正确（文件加载状态为布尔，实时反映文件是否存在）。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn it_ipl_status_structure() {
    let ctx = TestContext::new().await;

    let v = ctx.get_json("/system/ipLocation/status").await;
    let d = &v["data"];
    assert!(
        d["mmdbLoaded"].is_boolean(),
        "mmdbLoaded 应为布尔，实际: {v}"
    );
    assert!(d["mmdbPath"].is_string(), "mmdbPath 应为字符串，实际: {v}");
    assert!(d["mmdbSize"].is_number(), "mmdbSize 应为数字，实际: {v}");
    assert!(
        d["xdbEnabled"].is_boolean(),
        "xdbEnabled 应为布尔，实际: {v}"
    );
    assert!(d["xdbLoaded"].is_boolean(), "xdbLoaded 应为布尔，实际: {v}");
    assert!(
        d["autoUpdateCron"].is_string(),
        "autoUpdateCron 应为字符串，实际: {v}"
    );
    assert!(
        !d["currentSource"].as_str().unwrap_or("").is_empty() && d["currentSource"].is_string(),
        "currentSource 应为非空字符串（默认 p3terx），实际: {v}"
    );
    assert!(
        d["maxmindAccountIdConfigured"].is_boolean(),
        "maxmindAccountIdConfigured 应为布尔，实际: {v}"
    );
    assert!(
        d["maxmindLicenseKeyConfigured"].is_boolean(),
        "maxmindLicenseKeyConfigured 应为布尔，实际: {v}"
    );
}

/// IP 库配置读取 + 保存快乐路径：GET 结构 → PUT(p3terx) → GET 反映更新。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn it_ipl_config_get_and_save_ok() {
    let ctx = TestContext::new().await;

    // 1. GET config：脱敏结构
    let v = ctx.get_json("/system/ipLocation/config").await;
    let d = &v["data"];
    assert!(
        d["updateSource"].is_string(),
        "updateSource 应为字符串，实际: {v}"
    );
    assert!(
        d["maxmindAccountIdConfigured"].is_boolean(),
        "maxmindAccountIdConfigured 应为布尔，实际: {v}"
    );
    assert!(
        d["maxmindLicenseKeyConfigured"].is_boolean(),
        "maxmindLicenseKeyConfigured 应为布尔，实际: {v}"
    );
    assert!(
        d["autoUpdateEnabled"].is_boolean(),
        "autoUpdateEnabled 应为布尔，实际: {v}"
    );

    // 2. 保存：切到 p3terx（空凭据，不要求 CONFIG_ENC_KEY），纯 DB upsert，稳定通过
    let v = ctx
        .put_json(
            "/system/ipLocation/config",
            serde_json::json!({
                "updateSource": "p3terx",
                "maxmindAccountId": "",
                "maxmindLicenseKey": "",
                "autoUpdateEnabled": false,
                "clearCredentials": false
            }),
        )
        .await;
    ctx.assert_ok(&v);

    // 3. 保存后 GET 反映 updateSource=p3terx
    let v = ctx.get_json("/system/ipLocation/config").await;
    assert_eq!(
        v["data"]["updateSource"].as_str(),
        Some("p3terx"),
        "保存后 updateSource 应为 p3terx，实际: {v}"
    );
}

/// IP 库配置保存参数校验失败分支（无外部依赖，命中 handler 显式 bad_request 即 400）。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn it_ipl_config_save_validation_errors() {
    let ctx = TestContext::new().await;
    let uri = "/system/ipLocation/config";

    // 1. 非法 update_source → 400（source_invalid）
    let (status, v) = ctx
        .send_raw(ctx.request(
            Method::PUT,
            uri,
            Some(serde_json::json!({
                "updateSource": "bad_source",
                "maxmindAccountId": "",
                "maxmindLicenseKey": "",
                "autoUpdateEnabled": false,
                "clearCredentials": false
            })),
        ))
        .await;
    assert_ne!(
        v["code"], 200,
        "非法 update_source 业务码不应为 200，实际: {v}"
    );
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "非法 update_source 应 400，实际: {status}"
    );

    // 2. 切到 maxmind 但未提供凭据 → 400（maxmind_credentials_required）
    let (status, v) = ctx
        .send_raw(ctx.request(
            Method::PUT,
            uri,
            Some(serde_json::json!({
                "updateSource": "maxmind",
                "maxmindAccountId": "",
                "maxmindLicenseKey": "",
                "autoUpdateEnabled": false,
                "clearCredentials": false
            })),
        ))
        .await;
    assert_ne!(v["code"], 200, "maxmind 缺凭据业务码不应为 200，实际: {v}");
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "maxmind 缺凭据应 400，实际: {status}"
    );
}

/// `POST /system/ipLocation/update` 的入参闸门（b82 新增，实测抓回两处契约漂移）。
///
/// 修前的真实响应（本机取证）：`?source=e2e90bad` ⇒ **HTTP 500** `{"code":500,"msg":"系统内部错误，
/// 请联系管理员"}`——因为 service 用 `anyhow` 把 `FromStr` 的 Err 一路抛出，而兄弟端点
/// `PUT /config` 对同一个非法值给的是 400 + `source_invalid`。同一个参数两套契约，
/// 违反 C.8；且缺凭据分支同样以 500 呈现，还会先抢走 10 分钟更新锁。
///
/// 三侧判据（缺一即虚锁）：
/// ① 非法源 ⇒ 400 且文案可解析（不得是 500、不得回显裸键名、不得把用户输入写进响应）；
/// ② **对照组证明闸门不是"一律拒绝"**：`?source=MAXMIND`（大写，归一化后合法）也 400，
///    但**失败原因必须换成凭据缺失**——两条 400 的 msg 不同，才证明闸门按语义分派；
/// ③ 无副作用：闸门跑完后 `GET /status` 的库文件事实（size/loaded/currentSource）逐字段不变，
///    且没有一次"更新任务正在进行中"——拒绝发生在抢锁与任何文件 IO 之前。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn it_ipl_update_gate_rejects_before_side_effects() {
    let ctx = TestContext::new().await;

    let before = ctx.get_json("/system/ipLocation/status").await;

    // ① 非法更新源 → 400（修前是 500）
    let (status, v) = ctx
        .send_raw(ctx.request(
            Method::POST,
            "/system/ipLocation/update?source=e2e90bad",
            None,
        ))
        .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "非法 source 应 400（不得以 500 呈现参数错误），实际: {status} {v}"
    );
    assert_eq!(v["code"], 400, "业务码应与 HTTP 同值，实际: {v}");
    let msg_bad = v["msg"].as_str().unwrap_or_default().to_string();
    assert!(!msg_bad.is_empty(), "拒绝必须给可读原因，实际: {v}");
    assert!(
        !msg_bad.starts_with("error."),
        "文案必须是已解析的 i18n 文本，不得回显键名，实际: {msg_bad}"
    );
    assert!(
        !msg_bad.contains("e2e90bad"),
        "不得把用户输入原样写进错误响应，实际: {msg_bad}"
    );

    // ② 对照组：大写 maxmind 归一化后被接受为「合法源」，于是撞到凭据闸门而不是源闸门
    let (status, v) = ctx
        .send_raw(ctx.request(
            Method::POST,
            "/system/ipLocation/update?source=MAXMIND",
            None,
        ))
        .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "maxmind 未配凭据应 400 而非 500，实际: {status} {v}"
    );
    let msg_cred = v["msg"].as_str().unwrap_or_default().to_string();
    assert!(
        msg_cred != msg_bad,
        "两条 400 的原因必须不同，否则闸门退化成一律拒绝：bad={msg_bad} cred={msg_cred}"
    );
    assert!(
        !msg_cred.contains("更新任务正在进行中"),
        "闸门不得排在抢锁之后（否则被拒的请求也会占用 10 分钟锁），实际: {msg_cred}"
    );

    // ③ 无副作用：库文件事实逐字段不变
    let after = ctx.get_json("/system/ipLocation/status").await;
    for key in ["mmdbLoaded", "mmdbSize", "currentSource"] {
        assert_eq!(
            before["data"][key], after["data"][key],
            "{key} 应逐字段不变（两次拒绝之间不得发生下载或换文件），前={before} 后={after}"
        );
    }
}

/// b145（N-144-I 写侧断面）：**"解不开的凭据"不得被一次无关保存抹掉，也不得挡住那次保存**。
///
/// 立的案是双向的，两个方向各是一个真实缺陷：
/// - 旧写法的"字段留空 = 沿用原值"其实读的是**解密后的明文**；密文解不开时那是空串，
///   于是"只翻自动更新开关"这一类与凭据无关的保存，会把库里唯一还有救的密文写成空
///   ——读失败驱动了一次写（AGENTS b133 ①），且界面上看不见任何异常。
/// - 反过来，为堵住这一条而加的"解不开就不许保存"闸门又会拦住本可安全完成的无关保存，
///   把人支使去重填一个他并不打算改的凭据。修法是把"不碰这一列"做成一条真实写路径
///   （`Option<&str>`），两个缺陷同时消失，不需要任何拒绝。
///
/// 因此本用例四件事同判：坏凭据**可见**（present + unreadable）、无关保存**照常成功**、
/// 密文**一字未改**、切 maxmind 时给的是"无法解密"而不是"请填写凭据"；
/// 最后一条对照证明正常凭据的保存路径没有被顺手关掉（否则"永远拒绝"也能满足前三条）。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn it_ipl_unreadable_credential_survives_unrelated_save() {
    use sea_orm::{ConnectionTrait, DatabaseBackend, Statement, Value};

    const ACCOUNT_KEY: &str = "ip_location.maxmind_account_id";
    const LICENSE_KEY: &str = "ip_location.maxmind_license_key";
    /// 不是 `enc3:` 信封格式的串 ⇒ 解密必然失败，正好造出"存了但读不出"这一档
    const BROKEN: &str = "b145-not-a-valid-envelope";

    let ctx = TestContext::new().await;
    let db = &ctx.state.db;

    // 0. 先把两列清成"真的没存过"，取回那一条理由——后面要证明"解不开"给的是**另一句**话。
    //    （只判"文案非空且键已解析"是不够的：两条 400 就算措辞相同也能全绿，
    //     而"两条理由必须不同"才是这个缺陷的分因判据。）
    let v = ctx
        .put_json(
            "/system/ipLocation/config",
            serde_json::json!({
                "updateSource": "p3terx",
                "maxmindAccountId": "",
                "maxmindLicenseKey": "",
                "autoUpdateEnabled": false,
                "clearCredentials": true
            }),
        )
        .await;
    ctx.assert_ok(&v);
    // 负路径必须走 send_raw：harness 的 put_json 内部就断言 code 200（mod.rs 的 send_json），
    // 拿它打 400 分支会先红在取数通道上（本批首跑即为此）。
    let (status, v) = ctx
        .send_raw(ctx.request(
            Method::PUT,
            "/system/ipLocation/config",
            Some(serde_json::json!({
                "updateSource": "maxmind",
                "maxmindAccountId": "",
                "maxmindLicenseKey": "",
                "autoUpdateEnabled": false,
                "clearCredentials": false
            })),
        ))
        .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "没存过凭据切 maxmind 必须 400，实际: {status} {v}"
    );
    assert_eq!(
        v["code"], 400,
        "边界契约：body.code 与 HTTP 同步，实际: {v}"
    );
    let msg_not_stored = v["msg"].as_str().unwrap_or_default().to_string();

    let read_row = |key: &'static str| {
        let db = db.clone();
        async move {
            let row = db
                .query_one_raw(Statement::from_sql_and_values(
                    DatabaseBackend::Sqlite,
                    "SELECT config_value FROM sys_config WHERE config_key = ?",
                    [Value::from(key)],
                ))
                .await
                .expect("读取 sys_config 失败")
                .expect("该行必须存在（上一步刚写过）");
            row.try_get::<Option<String>>("", "config_value")
                .expect("config_value 取不出")
                .unwrap_or_default()
        }
    };

    // 1. 直接把两列写成不可解的串（模拟"主密钥轮换过"之后的存量库）
    for key in [ACCOUNT_KEY, LICENSE_KEY] {
        let changed = db
            .execute_raw(Statement::from_sql_and_values(
                DatabaseBackend::Sqlite,
                "UPDATE sys_config SET config_value = ? WHERE config_key = ?",
                [Value::from(BROKEN), Value::from(key)],
            ))
            .await
            .expect("写入坏凭据失败")
            .rows_affected();
        assert_eq!(
            changed, 1,
            "{key} 必须命中已有种子行（否则夹具写不到正确的键上）"
        );
    }

    // 2. 状态面必须把"存了但解不开"说清楚：present=true、unreadable=true，而旧的
    //    *Configured（= 解密成功过）仍是 false——三个数各说各话才是可运维的
    let st = ctx.get_json("/system/ipLocation/status").await;
    let d = &st["data"];
    assert_eq!(d["configAvailable"], true, "配置这一路读到了，实际: {st}");
    assert_eq!(
        d["accountIdPresent"], true,
        "凭据在库里必须报 present，实际: {st}"
    );
    assert_eq!(
        d["accountIdUnreadable"], true,
        "解不开必须单独成态，不得折成\"没配\"，实际: {st}"
    );
    assert_eq!(d["licenseKeyPresent"], true, "实际: {st}");
    assert_eq!(d["licenseKeyUnreadable"], true, "实际: {st}");
    assert_eq!(
        d["maxmindAccountIdConfigured"], false,
        "解不开时\"已配置\"仍为假（这一位说的是能不能用，不是存没存），实际: {st}"
    );

    // 3. 一次与凭据无关的保存（只翻自动更新开关，凭据字段留空）必须成功
    let v = ctx
        .put_json(
            "/system/ipLocation/config",
            serde_json::json!({
                "updateSource": "p3terx",
                "maxmindAccountId": "",
                "maxmindLicenseKey": "",
                "autoUpdateEnabled": true,
                "clearCredentials": false
            }),
        )
        .await;
    ctx.assert_ok(&v);
    assert_eq!(
        read_row(ACCOUNT_KEY).await,
        BROKEN,
        "坏凭据必须原样留在库里——被空字段覆盖就是\"读失败驱动了一次写\""
    );
    assert_eq!(read_row(LICENSE_KEY).await, BROKEN, "同上");
    // 而这一句确实生效了（不是"整次保存被静默忽略"的假绿）
    let after = ctx.get_json("/system/ipLocation/config").await;
    assert_eq!(
        after["data"]["autoUpdateEnabled"], true,
        "无关保存的改动必须落库，实际: {after}"
    );

    // 4. 切到 maxmind 而凭据解不开 ⇒ 400，且点名"无法解密"而不是"请填写凭据"
    let (status, v) = ctx
        .send_raw(ctx.request(
            Method::PUT,
            "/system/ipLocation/config",
            Some(serde_json::json!({
                "updateSource": "maxmind",
                "maxmindAccountId": "",
                "maxmindLicenseKey": "",
                "autoUpdateEnabled": true,
                "clearCredentials": false
            })),
        ))
        .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "解不开的凭据切 maxmind 必须 400，实际: {status} {v}"
    );
    assert_eq!(
        v["code"], 400,
        "边界契约：body.code 与 HTTP 同步，实际: {v}"
    );
    let msg = v["msg"].as_str().unwrap_or_default().to_string();
    assert!(!msg.trim().is_empty(), "文案不得为空，实际: {v}");
    assert!(
        !msg.contains("error."),
        "i18n 键没解析会把键名直接给用户（C.9/i18n 锁同族），实际: {msg}"
    );
    assert_ne!(
        msg, msg_not_stored,
        "\"存了但解不开\"与\"根本没存\"必须给两句不同的话，否则运维会去重填一个库里本来就有的凭据\
         （⑨：错误提示把人支使去把事实签反）。not_stored={msg_not_stored} unreadable={msg}"
    );

    // 5. 对照组：真的重填一对凭据 ⇒ 保存成功且状态转为"可用"（证明上面四条不是"永远拒绝"）
    let v = ctx
        .put_json(
            "/system/ipLocation/config",
            serde_json::json!({
                "updateSource": "maxmind",
                "maxmindAccountId": "1234",
                "maxmindLicenseKey": "lic-key-for-test",
                "autoUpdateEnabled": true,
                "clearCredentials": false
            }),
        )
        .await;
    ctx.assert_ok(&v);
    let st = ctx.get_json("/system/ipLocation/status").await;
    assert_eq!(
        st["data"]["maxmindAccountIdConfigured"], true,
        "重填之后凭据必须解密可用，实际: {st}"
    );
    assert_eq!(
        st["data"]["accountIdUnreadable"], false,
        "重填之后不得还挂着\"无法解密\"，实际: {st}"
    );
    assert_eq!(st["data"]["currentSource"], "maxmind", "实际: {st}");
    // 覆盖写进去的新值必须真的在库里（而不是"看起来成功"）
    assert_ne!(
        read_row(ACCOUNT_KEY).await,
        BROKEN,
        "重填必须真的覆盖掉坏密文"
    );
}
