//! WebSocket 实时通知链路集成测试（补 M7：ws_handler 此前 0% 覆盖）
//!
//! WebSocket 升级无法通过 `tower::oneshot` 模拟（需要真实 TCP 会话），因此本模块
//! 启动一个真实 HTTP 服务（`axum::serve` + `TcpListener` 临时端口），用
//! `tokio-tungstenite` 客户端做真实握手与收发，覆盖：
//! - 成功握手 → 收到欢迎消息（system）
//! - 全局广播（`ws_handler::broadcast`）→ 客户端收到 notice
//! - 用户定向推送（`broadcast_to_user`）→ 仅目标用户收到
//! - 文本 ping → 服务端回 pong
//! - 子协议承载鉴权（`Sec-WebSocket-Protocol: bearer.<jwt>`）+ 回显
//! - 未授权（无 token / 无效 token）→ HTTP 401 拒绝
//! - 黑名单 token（已登出）→ HTTP 401 拒绝（C7-3）
//! - 每用户连接数上限 → 第 21 个返回 HTTP 429，且计数归零（C7-2 / 启动重置）
//!
//! 与其它集成测试一致：独立 sqlite + 独立 Redis DB + 独立 peer IP，可并行。

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::http::HeaderValue;
use futures_util::{SinkExt, StreamExt};
use tokio::net::TcpListener;
use tokio::time::{sleep, timeout};
use tokio_tungstenite::tungstenite::Message as WsFrame;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;

use crate::state::AppState;

use super::{RedisSlot, build_isolated_state, login, next_peer_ip};

/// 客户端 WebSocket 流类型（真实 TCP，非 TLS）。
type WsStream =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

/// 每个测试的 WS 环境：真实服务地址 + admin token + AppState（用于广播/黑名单/计数断言）。
struct WsEnv {
    addr: SocketAddr,
    /// admin/admin123 登录得到的合法 JWT
    token: String,
    /// admin 的用户 ID（种子数据固定为 1）
    user_id: i64,
    state: Arc<AppState>,
    /// 测试断言专用的原生 Redis 连接（redis 档；裸 redis::cmd 断言用）
    redis: redis::aio::ConnectionManager,
    _slot: RedisSlot,
}

/// 在 127.0.0.1 临时端口启动真实 HTTP 服务（含 `/ws` 路由），返回监听地址。
async fn start_server(state: Arc<AppState>) -> SocketAddr {
    let app = crate::router::build_app(state);
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("绑定测试端口失败");
    let addr = listener.local_addr().expect("获取监听地址失败");
    tokio::spawn(async move {
        let router = app.into_make_service_with_connect_info::<SocketAddr>();
        if let Err(e) = axum::serve(listener, router).await {
            eprintln!("测试 WS 服务异常退出: {e}");
        }
    });
    addr
}

/// 构建隔离状态 + 登录 admin + 启动真实服务。
async fn setup() -> WsEnv {
    let (state, slot) = build_isolated_state().await;
    // redis 档测试：从 AppState 取回原生 Redis 连接，供黑名单/连接计数断言使用
    let redis = state
        .redis_conn
        .clone()
        .expect("集成测试固定走 redis 档，redis_conn 必为 Some");
    let app = crate::router::build_app(state.clone());
    let peer_ip = next_peer_ip();
    let token = login(&app, peer_ip, "admin", "admin123").await;
    let addr = start_server(state.clone()).await;
    WsEnv {
        addr,
        token,
        user_id: 1,
        state,
        redis,
        _slot: slot,
    }
}

/// 用 query 参数 token 建立 WS 连接（走 fallback 鉴权路径）。
async fn connect(addr: SocketAddr, token: &str) -> WsStream {
    let url = format!("ws://{addr}/ws?token={token}");
    let (ws, _resp) = tokio_tungstenite::connect_async(&url)
        .await
        .expect("WS 握手应成功");
    ws
}

/// 期望握手失败并返回 HTTP 状态码（401/429 等非升级响应）。
async fn connect_expect_status(addr: SocketAddr, token: &str) -> u16 {
    let url = format!("ws://{addr}/ws?token={token}");
    match tokio_tungstenite::connect_async(&url).await {
        Err(tokio_tungstenite::tungstenite::Error::Http(resp)) => resp.status().as_u16(),
        Err(e) => panic!("期望收到 HTTP 拒绝，实际为其他错误: {e}"),
        Ok(_) => panic!("期望连接被拒绝，实际握手成功"),
    }
}

/// 带超时读取下一帧文本（避免测试挂起）。返回文本内容。
async fn recv_text(ws: &mut WsStream, label: &str) -> String {
    let frame = timeout(Duration::from_secs(5), ws.next())
        .await
        .unwrap_or_else(|_| panic!("{label}: 等待服务端消息超时"))
        .expect("{label}: 连接意外关闭");
    match frame {
        Ok(WsFrame::Text(text)) => text.to_string(),
        other => panic!("{label}: 期望文本帧，实际: {other:?}"),
    }
}

// ==================== 测试用例 ====================

#[tokio::test]
async fn ws_upgrade_welcome_and_broadcast() {
    let env = setup().await;
    let mut ws = connect(env.addr, &env.token).await;

    // 1. 握手成功后应收到欢迎消息（system 类型）
    let welcome = recv_text(&mut ws, "欢迎").await;
    let v: serde_json::Value = serde_json::from_str(&welcome).expect("欢迎消息 JSON 解析失败");
    assert_eq!(v["type"], "system", "欢迎消息类型应为 system，实际: {v}");
    assert_eq!(v["data"]["userId"], env.user_id);

    // 2. 服务端全局广播 → 客户端应收到 notice 消息
    crate::handler::ws_handler::broadcast(
        &env.state,
        "notice",
        serde_json::json!({ "title": "系统公告", "id": 888 }),
    );
    let broadcast_msg = recv_text(&mut ws, "广播").await;
    let v: serde_json::Value =
        serde_json::from_str(&broadcast_msg).expect("广播消息 JSON 解析失败");
    assert_eq!(v["type"], "notice", "广播类型应为 notice，实际: {v}");
    assert_eq!(v["data"]["id"], 888);
    ws.close(None).await.ok();
}

#[tokio::test]
async fn ws_user_directed_message_and_pong() {
    let env = setup().await;
    let mut ws = connect(env.addr, &env.token).await;
    let _welcome = recv_text(&mut ws, "欢迎").await;

    // 1. 用户定向推送 → 仅本连接收到（含身份信息的消息不广播）
    env.state.broadcast_to_user(
        env.user_id,
        "system",
        serde_json::json!({ "forceLogout": true }),
    );
    let dir = recv_text(&mut ws, "定向").await;
    let v: serde_json::Value = serde_json::from_str(&dir).expect("定向消息 JSON 解析失败");
    assert_eq!(v["data"]["forceLogout"], true);

    // 2. 客户端发文本 ping → 服务端回 pong
    ws.send(WsFrame::Text("ping".into()))
        .await
        .expect("发送 ping 失败");
    let pong = recv_text(&mut ws, "pong").await;
    let v: serde_json::Value = serde_json::from_str(&pong).expect("pong JSON 解析失败");
    assert_eq!(v["type"], "pong", "ping 应收到 pong 响应，实际: {v}");
    ws.close(None).await.ok();
}

#[tokio::test]
async fn ws_auth_via_sec_protocol_header_and_echo() {
    // 推荐鉴权路径：token 放在 Sec-WebSocket-Protocol 子协议头，不出现在 URL/日志。
    let env = setup().await;
    // 先由 IntoClientRequest 生成带完整握手头（Sec-WebSocket-Key/Upgrade/Version 等）的
    // 请求，再叠加 Sec-WebSocket-Protocol 头携带 token。避免手搓 Request 因缺关键头报
    // Protocol(InvalidHeader("sec-websocket-key"))。
    let mut request = format!("ws://{}/ws", env.addr)
        .into_client_request()
        .expect("构造子协议握手请求失败");
    request.headers_mut().insert(
        "sec-websocket-protocol",
        HeaderValue::from_str(&format!("bearer.{}", env.token)).expect("token 可作为合法头部值"),
    );
    let (mut ws, resp) = tokio_tungstenite::connect_async(request)
        .await
        .expect("子协议鉴权握手应成功");
    // 服务端必须回显子协议，否则浏览器会拒绝握手（从响应头读取所选协议）
    let echoed = resp
        .headers()
        .get("sec-websocket-protocol")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    assert_eq!(
        echoed,
        Some(format!("bearer.{}", env.token)),
        "服务端应回显客户端子协议"
    );
    let welcome = recv_text(&mut ws, "欢迎").await;
    let v: serde_json::Value = serde_json::from_str(&welcome).expect("欢迎消息 JSON 解析失败");
    assert_eq!(v["type"], "system");
    ws.close(None).await.ok();
}

#[tokio::test]
async fn ws_reject_unauthenticated_and_blacklisted() {
    let env = setup().await;

    // 1. 无 token → 401
    let status = connect_expect_status(env.addr, "").await;
    assert_eq!(status, 401, "无 token 应被拒绝");

    // 2. 无效（伪造）token → 401
    let status = connect_expect_status(env.addr, "invalid.jwt.token").await;
    assert_eq!(status, 401, "无效 token 应被拒绝");

    // 3. 合法 token 但已登出（加入黑名单）→ 401（C7-3）
    let hash = crate::utils::crypto::token_hash(&env.token);
    let key = format!("blacklist:{hash}");
    {
        let mut conn = env.redis.clone();
        redis::cmd("SET")
            .arg(&key)
            .arg("1")
            .query_async::<()>(&mut conn)
            .await
            .expect("写入黑名单失败");
    }
    let status = connect_expect_status(env.addr, &env.token).await;
    assert_eq!(status, 401, "黑名单 token 应被拒绝");
    // 清理黑名单，避免影响其它并行测试（此测试独占 Redis DB，其实不必要，但保持整洁）
    {
        let mut conn = env.redis.clone();
        let _: Option<()> = redis::cmd("DEL")
            .arg(&key)
            .query_async(&mut conn)
            .await
            .ok();
    }
}

#[tokio::test]
async fn ws_connection_limit_enforced_and_reset_on_close() {
    // C7-2：每用户最多 20 个并发连接；超限的 21 个返回 429；关闭后计数归零。
    let env = setup().await;
    let mut conns: Vec<WsStream> = Vec::new();

    // 前 20 个连接全部成功
    for i in 0..20 {
        let mut ws = connect(env.addr, &env.token).await;
        let _ = recv_text(&mut ws, &format!("连接{i}欢迎前缀")).await;
        conns.push(ws);
    }

    // 确认 Redis 计数为 20
    let count: i64 = {
        let mut conn = env.redis.clone();
        redis::cmd("GET")
            .arg(format!("ws_conn:{}", env.user_id))
            .query_async::<Option<i64>>(&mut conn)
            .await
            .expect("读取连接计数失败")
            .unwrap_or(0)
    };
    assert_eq!(count, 20, "20 个活跃连接时计数应为 20");

    // 第 21 个 → 429
    let status = connect_expect_status(env.addr, &env.token).await;
    assert_eq!(status, 429, "超过每用户最大连接数应被拒绝");

    // 关闭所有连接后，计数应回到 0
    drop(conns);
    sleep(Duration::from_millis(800)).await; // 等服务端 handle_ws 退出并 DECR
    {
        let mut conn = env.redis.clone();
        let remaining: i64 = redis::cmd("GET")
            .arg(format!("ws_conn:{}", env.user_id))
            .query_async::<Option<i64>>(&mut conn)
            .await
            .expect("读取连接计数失败")
            .unwrap_or(0);
        assert_eq!(remaining, 0, "全部连接关闭后计数应归零，实际: {remaining}");
    }
}
