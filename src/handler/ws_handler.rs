//! WebSocket 实时通知 Handler
//!
//! 设计要点：
//! - 鉴权 token 优先通过 `Sec-WebSocket-Protocol` 子协议头传递（避免出现在 URL/日志中）
//! - 兼容旧前端：仍支持 `?token=xxx` query 参数（fallback）
//! - 全局广播通道：AppState 中的 `ws_broadcast` 维护所有活跃连接
//! - 消息类型：notice(通知公告)、operLog(操作日志)、system(系统消息)
//! - 心跳机制：服务端每 30s 发送 ping，客户端回复 pong；90s 无响应则断开（C7-1）
//! - 连接限制：每用户最多 5 个并发 WS 连接，防止 DoS（C7-2）
//! - 黑名单校验：JWT 验证后检查 Redis 黑名单，已登出 token 拒绝连接（C7-3）
//! - Close 帧：断开前发送 Close 帧，符合 RFC 6455 规范（C7-4）

use std::sync::Arc;
use std::time::Duration;

use axum::extract::{Query, State, WebSocketUpgrade};
use axum::extract::ws::{WebSocket, Message};
use axum::http::HeaderMap;
use axum::response::Response;
use futures::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

use crate::state::AppState;
use crate::jwt::JwtUtils;

/// 每用户最大并发 WebSocket 连接数
const MAX_WS_CONN_PER_USER: u32 = 5;

/// 心跳间隔（秒）
const HEARTBEAT_INTERVAL_SECS: u64 = 30;

/// 心跳超时（秒）：连续 3 次心跳无 pong 响应则断开
const HEARTBEAT_TIMEOUT_SECS: u64 = 90;

#[derive(Debug, Deserialize)]
pub struct WsAuthQuery {
    /// JWT token（query 参数鉴权，兼容旧前端，不推荐）
    ///
    /// 安全提示：token 出现在 URL 中会被记录到访问日志、浏览器历史、Referer 头。
    /// 推荐前端改用 `Sec-WebSocket-Protocol` 子协议头传递 token（见下方 headers 参数）。
    pub token: Option<String>,
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

/// 从 `Sec-WebSocket-Protocol` 头部提取 token
///
/// 前端使用方式：`new WebSocket(url, ['bearer.<jwt>'])`，
/// 浏览器会在握手请求中带上 `Sec-WebSocket-Protocol: bearer.<jwt>` 头。
/// 服务端必须回显相同的子协议，否则浏览器会拒绝握手。
fn extract_token_from_protocol(headers: &HeaderMap) -> Option<String> {
    headers
        .get("sec-websocket-protocol")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| {
            // 协议头格式：`bearer.<jwt>` 或多个逗号分隔
            s.split(',')
                .map(|p| p.trim())
                .find_map(|p| p.strip_prefix("bearer.").map(|t| t.to_string()))
        })
}

/// 检查 token 是否在 Redis 黑名单中（fail-closed：Redis 异常时拒绝连接）
///
/// 复用 auth_middleware 的黑名单机制：登出时将 token_hash 加入 `blacklist:{token_hash}` key
async fn is_token_blacklisted(state: &AppState, token: &str) -> Result<bool, axum::http::StatusCode> {
    let token_hash = crate::utils::crypto::token_hash(token);
    let blacklist_key = format!("blacklist:{}", token_hash);
    let mut conn = state.redis.clone();
    let is_blacklisted: Option<String> = redis::cmd("GET")
        .arg(&blacklist_key)
        .query_async(&mut conn)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "WebSocket 黑名单查询失败（fail-closed 拒绝连接）");
            axum::http::StatusCode::SERVICE_UNAVAILABLE
        })?;
    Ok(is_blacklisted.is_some())
}

/// 原子化增加用户 WS 连接计数，返回当前连接数
///
/// 使用 Redis INCR 原子操作，支持多实例部署
/// 若返回值 > MAX_WS_CONN_PER_USER，调用方需 DECR 回滚并拒绝连接
async fn incr_ws_conn_count(state: &AppState, user_id: i64) -> Result<u32, axum::http::StatusCode> {
    let key = format!("ws_conn:{}", user_id);
    let mut conn = state.redis.clone();
    let count: u32 = redis::cmd("INCR")
        .arg(&key)
        .query_async(&mut conn)
        .await
        .map_err(|e| {
            tracing::error!(user_id = user_id, error = %e, "WebSocket 连接计数 INCR 失败（fail-closed 拒绝连接）");
            axum::http::StatusCode::SERVICE_UNAVAILABLE
        })?;
    // 设置过期时间（防泄漏：用户异常断开未触发 DECR 时，计数最终归零）
    // 过期时间 = JWT 有效期 + 缓冲，这里用 24 小时
    let _: () = redis::cmd("EXPIRE")
        .arg(&key)
        .arg(86400i64) // 24h
        .query_async(&mut conn)
        .await
        .unwrap_or(());
    Ok(count)
}

/// 减少用户 WS 连接计数（best-effort：失败仅记日志）
///
/// P2 修复: 原实现 DECR + GET + 条件 DEL 共 3 次 RTT 且非原子，并发关闭时存在竞态
/// （DECR 后 GET 可能读到对方 DECR 后的值，误判 count<=0 而 DEL key）。
/// 改用 Lua 脚本原子化执行 DECR → 判断 ≤0 → DEL，单次 RTT 且无竞态。
async fn decr_ws_conn_count(state: &AppState, user_id: i64) {
    let key = format!("ws_conn:{}", user_id);
    let mut conn = state.redis.clone();
    let script = r#"
        local v = redis.call('DECR', KEYS[1])
        if v <= 0 then
            redis.call('DEL', KEYS[1])
        end
        return v
    "#;
    let _: redis::RedisResult<i64> = redis::cmd("EVAL")
        .arg(script)
        .arg(1) // number of keys
        .arg(&key)
        .query_async(&mut conn)
        .await;
}

/// RAII 守卫：确保 WebSocket 连接计数在任何情况下（包括 Future 被取消/drop）都能 DECR
///
/// P2 修复：原实现在 handle_ws 末尾调用 decr_ws_conn_count，但当 Future 被外部
/// 取消（drop）时，await 点之后的代码不会执行，导致连接计数泄漏。使用 RAII 模式
/// 在 Drop 中 spawn 异步任务执行 DECR，确保计数最终归零。
struct WsConnGuard {
    state: Arc<AppState>,
    user_id: i64,
    armed: bool,
}

impl WsConnGuard {
    fn new(state: Arc<AppState>, user_id: i64) -> Self {
        Self {
            state,
            user_id,
            armed: true,
        }
    }

    /// 主动解除（正常关闭时调用，避免 Drop 中重复 DECR）
    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for WsConnGuard {
    fn drop(&mut self) {
        if self.armed {
            let state = self.state.clone();
            let user_id = self.user_id;
            // Drop 不能 await，spawn 异步任务执行 DECR
            tokio::spawn(async move {
                decr_ws_conn_count(&state, user_id).await;
            });
        }
    }
}

/// GET /ws 或 /ws?token=xxx
/// WebSocket 升级握手
///
/// 鉴权流程（优先级从高到低）：
/// 1. 从 `Sec-WebSocket-Protocol` 头提取 `bearer.<jwt>` 形式的 token（推荐）
/// 2. 从 query 参数提取 token（兼容旧前端）
/// 3. JwtUtils::verify_token 验证签名和过期时间
/// 4. Redis 黑名单校验（C7-3：已登出 token 拒绝连接）
/// 5. 连接数限制校验（C7-2：每用户最多 5 个并发连接）
/// 6. 验证通过则升级为 WebSocket，订阅全局广播
pub async fn ws_handler(
    ws: WebSocketUpgrade,
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(query): Query<WsAuthQuery>,
) -> Result<Response, axum::http::StatusCode> {
    // 优先从 Sec-WebSocket-Protocol 头提取 token
    let token = extract_token_from_protocol(&headers)
        .or(query.token)
        .ok_or(axum::http::StatusCode::UNAUTHORIZED)?;

    // 鉴权：验证 JWT 签名 + 过期时间
    let claims = JwtUtils::verify_token(&token, &state.config.jwt)
        .map_err(|_| axum::http::StatusCode::UNAUTHORIZED)?;

    // C7-3：Redis 黑名单校验（fail-closed）
    if is_token_blacklisted(&state, &token).await? {
        warn!(user_id = %claims.sub, "WebSocket 拒绝连接：token 已登出（黑名单）");
        return Err(axum::http::StatusCode::UNAUTHORIZED);
    }

    // P2 修复: JWT sub 解析失败时拒绝连接，而非回退 user_id=0（可能导致越权/计数错乱）
    let user_id: i64 = claims.sub.parse().map_err(|_| {
        warn!(sub = %claims.sub, "WebSocket 拒绝连接：JWT sub 不是有效数字");
        axum::http::StatusCode::UNAUTHORIZED
    })?;
    let user_name = claims.username.clone();

    // C7-2：连接数限制（每用户最多 MAX_WS_CONN_PER_USER 个并发连接）
    let conn_count = incr_ws_conn_count(&state, user_id).await?;
    if conn_count > MAX_WS_CONN_PER_USER {
        // 超限：回滚 INCR 并拒绝连接
        decr_ws_conn_count(&state, user_id).await;
        warn!(user_id = user_id, count = conn_count, "WebSocket 拒绝连接：超过每用户最大连接数");
        return Err(axum::http::StatusCode::TOO_MANY_REQUESTS);
    }

    info!(user_id = user_id, user_name = %user_name, conn_count = conn_count, "WebSocket 连接建立");

    // 若客户端通过 Sec-WebSocket-Protocol 发起握手，需回显子协议以满足浏览器要求
    let protocols = headers
        .get("sec-websocket-protocol")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| {
            // 取第一个 protocol 作为回显（浏览器要求服务端必须从客户端提供的列表中选一个）
            s.split(',').next().map(|p| p.trim().to_string())
        });

    let upgrade = match protocols {
        Some(p) => ws.protocols([p]),
        None => ws,
    };

    Ok(upgrade.on_upgrade(move |socket| handle_ws(socket, state, user_id, user_name)))
}

/// 处理单个 WebSocket 连接
///
/// 安全设计：
/// - C7-1 心跳超时：90 秒无 pong 响应则主动断开（3 次心跳周期）
/// - C7-4 Close 帧：断开前发送 Close 帧，符合 RFC 6455
/// - 连接计数：函数退出时自动 DECR（使用 RAII 模式确保执行）
async fn handle_ws(socket: WebSocket, state: Arc<AppState>, user_id: i64, user_name: String) {
    // P2 修复: RAII 守卫确保连接计数在任何退出路径（包括 Future 被 drop）都能 DECR
    let mut conn_guard = WsConnGuard::new(state.clone(), user_id);

    let (mut sender, mut receiver) = socket.split();
    let mut rx = state.ws_broadcast.subscribe();

    // 发送连接成功消息（P3 修复: 改用 tr!() 宏，遵循项目 i18n 规范）
    let welcome = WsMessage::new(
        "system",
        serde_json::json!({
            "message": crate::tr!("websocket.connected"),
            "userId": user_id,
            "userName": user_name
        }),
    );
    let _ = sender.send(Message::Text(welcome.to_json().into())).await;

    // C7-1：心跳定时器 + 超时检测
    let mut heartbeat = tokio::time::interval(Duration::from_secs(HEARTBEAT_INTERVAL_SECS));
    heartbeat.tick().await; // 立即触发一次（跳过）

    // C7-1：超时检测定时器 — 每 30 秒检查一次客户端是否活跃
    // 用 interval 而非 sleep_until，确保即使广播消息频繁也能定期检测
    let mut timeout_check = tokio::time::interval(Duration::from_secs(HEARTBEAT_INTERVAL_SECS));
    timeout_check.tick().await; // 跳过首次立即触发

    // 记录最后一次收到客户端消息的时间（用于超时检测）
    let mut last_msg_time = tokio::time::Instant::now();
    let heartbeat_timeout = Duration::from_secs(HEARTBEAT_TIMEOUT_SECS);

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
                last_msg_time = tokio::time::Instant::now(); // 更新最后活跃时间
                match msg {
                    Message::Text(text) => {
                        // 客户端发送 ping，回复 pong
                        if text.as_str() == "ping" {
                            let pong = WsMessage::new("pong", serde_json::json!({"time": chrono::Utc::now().timestamp_millis()}));
                            let _ = sender.send(Message::Text(pong.to_json().into())).await;
                        }
                    }
                    Message::Pong(_) => {
                        // 浏览器原生 Pong 帧（对应服务端 Ping 帧），更新 last_msg_time
                    }
                    Message::Close(_) => break,
                    _ => {}
                }
            }
            // C7-1：心跳超时检测 — 每 30 秒检查，90 秒无客户端响应则断开
            _ = timeout_check.tick() => {
                let elapsed = last_msg_time.elapsed();
                if elapsed >= heartbeat_timeout {
                    warn!(user_id = user_id, elapsed_secs = elapsed.as_secs(), "WebSocket 心跳超时，主动断开");
                    // C7-4：发送 Close 帧后断开
                    let _ = sender.send(Message::Close(None)).await;
                    break;
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

    // C7-4：连接关闭前发送 Close 帧（RFC 6455 规范）
    // 注：sender 可能已关闭，忽略错误
    let _ = sender.send(Message::Close(None)).await;

    // C7-2：减少连接计数（best-effort）
    // P2 修复: 先 disarm 守卫，再手动 DECR，避免 Drop 中重复 spawn
    conn_guard.disarm();
    decr_ws_conn_count(&state, user_id).await;

    info!(user_id = user_id, "WebSocket 连接关闭");
}

/// 向所有连接的客户端广播消息（供其他模块调用）
pub fn broadcast(state: &AppState, msg_type: &str, data: serde_json::Value) {
    let msg = WsMessage::new(msg_type, data);
    let _ = state.ws_broadcast.send(msg);
}
