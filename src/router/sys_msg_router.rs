//! 消息渠道与模板管理模块路由注册
//!
//! 路由结构（前缀 /system/msg）：
//! - /system/msg/channel/list              GET     分页查询消息渠道
//! - /system/msg/channel/{channelId}       GET     查询渠道详情
//! - /system/msg/channel                   POST    新增消息渠道
//! - /system/msg/channel                   PUT     修改消息渠道
//! - /system/msg/channel/{channelIds}      DELETE  批量删除消息渠道
//! - /system/msg/channel/test/{channelId}  POST    渠道连通性测试
//! - /system/msg/template/list             GET     分页查询消息模板
//! - /system/msg/template/{templateId}     GET     查询模板详情
//! - /system/msg/template                  POST    新增消息模板
//! - /system/msg/template                  PUT     修改消息模板
//! - /system/msg/template/{templateIds}    DELETE  批量删除消息模板
//! - /system/msg/log/list                  GET     分页查询发送记录
//! - /system/msg/log/{logIds}              DELETE  批量删除发送记录
//! - /system/msg/log/clean                 DELETE  清空发送记录
//! - /system/msg/send                      POST    直接发送
//! - /system/msg/log/retry/{logIds}        POST    重试指定发送记录
//! - /system/msg/log/retryPending/{batch}  POST    触发待重试批次批量重试
//! - /system/msg/log/markPending/{logIds}  POST    将发送记录标记为待重试
//!
//! 权限由 permission_middleware 中间件按 (method, path) 映射执行：
//! - system:msg:channel:list/query/add/edit/remove/test
//! - system:msg:template:list/query/add/edit/remove
//! - system:msg:log:list/remove/clean/retry（send / retry / markPending 对齐 log:retry）

use axum::Router;
use axum::routing::{delete, get, post, put};
use std::sync::Arc;

use crate::handler::sys_msg_handler;
use crate::state::AppState;

/// 消息渠道与模板管理模块路由
pub fn msg_routes() -> Router<Arc<AppState>> {
    Router::new()
        // ===== 消息渠道 =====
        // GET /system/msg/channel/list 分页查询消息渠道
        .route(
            "/system/msg/channel/list",
            get(sys_msg_handler::channel_list),
        )
        // GET /system/msg/channel/{channelId} 查询渠道详情 / DELETE 批量删除消息渠道
        // （GET 详情 与 DELETE 批量在同一路径段上共存，避免 axum 通配段 {channelId}/{channelIds} 冲突）
        .route(
            "/system/msg/channel/{channelId}",
            get(sys_msg_handler::channel_info).delete(sys_msg_handler::channel_remove),
        )
        // POST /system/msg/channel 新增消息渠道
        .route("/system/msg/channel", post(sys_msg_handler::channel_add))
        // PUT /system/msg/channel 修改消息渠道
        .route("/system/msg/channel", put(sys_msg_handler::channel_edit))
        // POST /system/msg/channel/test/{channelId} 渠道连通性测试
        .route(
            "/system/msg/channel/test/{channelId}",
            post(sys_msg_handler::channel_test),
        )
        // ===== 消息模板 =====
        // GET /system/msg/template/list 分页查询消息模板
        .route(
            "/system/msg/template/list",
            get(sys_msg_handler::template_list),
        )
        // GET /system/msg/template/{templateId} 查询模板详情 / DELETE 批量删除消息模板
        // （GET 详情 与 DELETE 批量在同一路径段上共存，避免通配段 {templateId}/{templateIds} 冲突）
        .route(
            "/system/msg/template/{templateId}",
            get(sys_msg_handler::template_info).delete(sys_msg_handler::template_remove),
        )
        // POST /system/msg/template 新增消息模板
        .route("/system/msg/template", post(sys_msg_handler::template_add))
        // PUT /system/msg/template 修改消息模板
        .route("/system/msg/template", put(sys_msg_handler::template_edit))
        // ===== 发送记录 =====
        // GET /system/msg/log/list 分页查询发送记录
        .route("/system/msg/log/list", get(sys_msg_handler::send_log_list))
        // DELETE /system/msg/log/{logIds} 批量删除发送记录（静态 clean 路由优先于动态路由）
        .route(
            "/system/msg/log/{logIds}",
            delete(sys_msg_handler::send_log_remove),
        )
        // DELETE /system/msg/log/clean 清空发送记录
        .route(
            "/system/msg/log/clean",
            delete(sys_msg_handler::send_log_clean),
        )
        // POST /system/msg/send 直接发送
        // b71 契约审计：编排预留，零前端调用（UI 走模板发送面）→ router/mod.rs 清单 ③
        .route("/system/msg/send", post(sys_msg_handler::send))
        // POST /system/msg/log/retry/{logIds} 重试指定发送记录
        .route(
            "/system/msg/log/retry/{logIds}",
            post(sys_msg_handler::retry_logs),
        )
        // POST /system/msg/log/retryPending/{batch} 触发待重试批次批量重试
        // b71 契约审计：编排预留，零前端调用 → router/mod.rs 清单 ③
        .route(
            "/system/msg/log/retryPending/{batch}",
            post(sys_msg_handler::retry_pending),
        )
        // POST /system/msg/log/markPending/{logIds} 将发送记录标记为待重试
        // b71 契约审计：编排预留，零前端调用 → router/mod.rs 清单 ③
        .route(
            "/system/msg/log/markPending/{logIds}",
            post(sys_msg_handler::mark_pending_retry),
        )
}
