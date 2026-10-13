// stepby-axum/src/integration_tests/sys_user_pref.rs
//! 用户消息偏好 / 免打扰模块链路集成测试：
//! - GET 获取默认偏好结构（无记录时返回全量接收 + 免打扰关闭）
//! - PUT 保存偏好（部分更新，合并返回完整 VO）→ 回读验证持久化
//! - 非法取值异常路径

use axum::body::Body;
use axum::extract::connect_info::ConnectInfo;
use axum::http::{Request, StatusCode};
use std::net::SocketAddr;

use super::TestContext;

/// 用户消息偏好全链路（默认结构 → 保存 → 回读 → 局部更新 → 非法值拒绝）。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_user_pref_chain() {
    let ctx = TestContext::new().await;

    // 1. 获取默认偏好结构（admin 无记录：全量接收 + 免打扰关闭）
    let v = ctx.get_json("/system/profile/pref").await;
    assert_eq!(
        v["data"]["userId"], 1,
        "偏好 userId 应为 admin(1)，实际: {v}"
    );
    assert_eq!(
        v["data"]["emailNotify"].as_str(),
        Some("1"),
        "默认 emailNotify 应为 1，实际: {v}"
    );
    assert_eq!(
        v["data"]["sysmsgNotify"].as_str(),
        Some("1"),
        "默认 sysmsgNotify 应为 1，实际: {v}"
    );
    assert_eq!(
        v["data"]["announceNotify"].as_str(),
        Some("1"),
        "默认 announceNotify 应为 1，实际: {v}"
    );
    assert_eq!(
        v["data"]["dndEnabled"].as_str(),
        Some("0"),
        "默认 dndEnabled 应为 0，实际: {v}"
    );

    // 2. 保存偏好（PUT，返回合并后完整 VO）
    let v = ctx
        .put_json(
            "/system/profile/pref",
            serde_json::json!({
                "emailNotify": "0",
                "sysmsgNotify": "1",
                "announceNotify": "1",
                "dndEnabled": "1",
                "dndStart": "22:00",
                "dndEnd": "06:00"
            }),
        )
        .await;
    ctx.assert_ok(&v);
    assert_eq!(
        v["data"]["emailNotify"].as_str(),
        Some("0"),
        "保存后 emailNotify 应为 0，实际: {v}"
    );
    assert_eq!(
        v["data"]["dndStart"].as_str(),
        Some("22:00"),
        "保存后 dndStart 应为 22:00，实际: {v}"
    );

    // 3. 回读验证持久化
    let v = ctx.get_json("/system/profile/pref").await;
    assert_eq!(
        v["data"]["emailNotify"].as_str(),
        Some("0"),
        "回读 emailNotify 应为 0，实际: {v}"
    );
    assert_eq!(
        v["data"]["dndEnabled"].as_str(),
        Some("1"),
        "回读 dndEnabled 应为 1，实际: {v}"
    );
    assert_eq!(
        v["data"]["dndStart"].as_str(),
        Some("22:00"),
        "回读 dndStart 应为 22:00，实际: {v}"
    );
    assert_eq!(
        v["data"]["dndEnd"].as_str(),
        Some("06:00"),
        "回读 dndEnd 应为 06:00，实际: {v}"
    );

    // 4. 局部更新（只改 sysmsgNotify，其余字段沿用现有值）
    let v = ctx
        .put_json(
            "/system/profile/pref",
            serde_json::json!({ "sysmsgNotify": "0" }),
        )
        .await;
    ctx.assert_ok(&v);
    assert_eq!(
        v["data"]["sysmsgNotify"].as_str(),
        Some("0"),
        "局部更新后 sysmsgNotify 应为 0，实际: {v}"
    );
    assert_eq!(
        v["data"]["emailNotify"].as_str(),
        Some("0"),
        "未更新的 emailNotify 应沿用 0，实际: {v}"
    );

    // 5. 异常路径：非法取值 emailNotify=5 → 400
    let mut req = Request::builder()
        .method("PUT")
        .uri("/system/profile/pref")
        .header("authorization", format!("Bearer {}", ctx.token))
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({ "emailNotify": "5" }).to_string(),
        ))
        .expect("构造请求失败");
    req.extensions_mut()
        .insert(ConnectInfo(SocketAddr::from((ctx.peer_ip, 4321))));
    let (status, v) = ctx.send_raw(req).await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "非法偏好取值应返回 400，实际: {status} {v}"
    );
}
