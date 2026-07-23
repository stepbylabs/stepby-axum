//! WebSocket 实时通知 Handler
//!
//! 设计要点：
//! - 通过 query 参数 token 鉴权（与 auth_middleware 不同，WS 升级前无法使用 layer）
//! - 全局广播通道：AppState 中的 `ws_broadcast` 维护所有活跃连接
//! - 消息类型：notice(通知公告)、operLog(操作日志)、system(系统消息)
//! - 心跳机制：服务端每 30s 发送 ping，客户端回复 ping 时回 pong

use std::sync::Arc;
use std::time::Duration;

use axum::extract::{Query, State, WebSocketUpgrade};
use axum::extract::ws::{WebSocket, Message};
use axum::response::Response;
use futures::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use tracing::info;

use crate::state::AppState;
use crate::jwt::JwtUtils;

#[derive(Debug, Deserialize)]
pub struct WsAuthQuery {
    /// JWT token（query 参数鉴权）
    pub token: String,
}

/// WebSocket 推送消息体
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WsMessage {
    /// 消息类型：notice / operLog / system / pong / ping
    pub r#type: String,
    /// 消息内容（JSON）
    pub data: serde_json::Value,
    /// 时间戳（毫秒）
    pub timestamp: i64,
}

impl WsMessage {
    pub fn new(msg_type: &str, data: serde_json::Value) -> Self {
        Self {
            r#type: msg_type.to_string(),
            data,
            timestamp: chrono::Utc::now().timestamp_millis(),
        }
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string(self).unwrap_or_else(|_| "{}".to_string())
    }
}

/// GET /ws?token=xxx
/// WebSocket 升级握手
///
/// 鉴权流程：
/// 1. 从 query 提取 token
/// 2. JwtUtils::verify_token 验证签名和过期时间
/// 3. 验证失败返回 401（在 upgrade 之前）
/// 4. 验证通过则升级为 WebSocket，订阅全局广播
pub async fn ws_handler(
    ws: WebSocketUpgrade,
    State(state): State<Arc<AppState>>,
    Query(query): Query<WsAuthQuery>,
) -> Result<Response, axum::http::StatusCode> {
    // 鉴权：验证 JWT
    let claims = JwtUtils::verify_token(&query.token, &state.config.jwt)
        .map_err(|_| axum::http::StatusCode::UNAUTHORIZED)?;

    let user_id: i64 = claims.sub.parse().unwrap_or(0);
    let user_name = claims.username.clone();

    info!(user_id = user_id, user_name = %user_name, "WebSocket 连接建立");

    Ok(ws.on_upgrade(move |socket| handle_ws(socket, state, user_id, user_name)))
}

/// 处理单个 WebSocket 连接
async fn handle_ws(socket: WebSocket, state: Arc<AppState>, user_id: i64, user_name: String) {
    let (mut sender, mut receiver) = socket.split();
    let mut rx = state.ws_broadcast.subscribe();

    // 发送连接成功消息
    let welcome = WsMessage::new(
        "system",
        serde_json::json!({
            "message": "WebSocket 连接成功",
            "userId": user_id,
            "userName": user_name
        }),
    );
    let _ = sender.send(Message::Text(welcome.to_json().into())).await;

    // 心跳定时器：每 30 秒发送一次 ping
    let mut heartbeat = tokio::time::interval(Duration::from_secs(30));
    heartbeat.tick().await; // 立即触发一次（跳过）

    loop {
        tokio::select! {
            // 接收全局广播消息并转发给客户端
            Ok(msg) = rx.recv() => {
                let text = msg.to_json();
                if sender.send(Message::Text(text.into())).await.is_err() {
                    break;
                }
            }
            // 接收客户端消息（ping/pong/业务消息）
            Some(Ok(msg)) = receiver.next() => {
                match msg {
                    Message::Text(text) => {
                        // 客户端发送 ping，回复 pong
                        if text.as_str() == "ping" {
                            let pong = WsMessage::new("pong", serde_json::json!({"time": chrono::Utc::now().timestamp_millis()}));
                            let _ = sender.send(Message::Text(pong.to_json().into())).await;
                        }
                    }
                    Message::Close(_) => break,
                    _ => {}
                }
            }
            // 心跳：每 30 秒发送一次 ping
            _ = heartbeat.tick() => {
                let ping = WsMessage::new("ping", serde_json::json!({"time": chrono::Utc::now().timestamp_millis()}));
                if sender.send(Message::Text(ping.to_json().into())).await.is_err() {
                    break;
                }
            }
        }
    }

    info!(user_id = user_id, "WebSocket 连接关闭");
}

/// 向所有连接的客户端广播消息（供其他模块调用）
pub fn broadcast(state: &AppState, msg_type: &str, data: serde_json::Value) {
    let msg = WsMessage::new(msg_type, data);
    let _ = state.ws_broadcast.send(msg);
}
