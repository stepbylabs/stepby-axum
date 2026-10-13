//! 报表中心 + 定时订阅推送模块路由注册
//!
//! 受保护路由（需 auth_middleware + permission_middleware）：
//! - GET    /system/report/list                      分页查询报表定义
//! - GET    /system/report/{reportId}                查询报表详情
//! - POST   /system/report                           新增报表定义
//! - PUT    /system/report                           修改报表定义
//! - DELETE /system/report/{reportIds}               批量删除报表定义
//! - PUT    /system/report/{reportId}/status         报表启停
//! - POST   /system/report/{reportId}/preview        手动预览报表快照
//! - GET    /system/report/sub/list                  分页查询报表订阅
//! - GET    /system/report/sub/{subId}               查询订阅详情
//! - POST   /system/report/sub                       新增报表订阅
//! - PUT    /system/report/sub                       修改报表订阅
//! - DELETE /system/report/sub/{subIds}              批量删除报表订阅
//! - PUT    /system/report/sub/{subId}/status        订阅启停
//! - POST   /system/report/sub/{subId}/run           手动触发订阅推送
//!
//! 权限映射（permission_middleware）：
//! - system:report:list/query/add/edit/remove/status/preview
//! - system:report:sub:list/query/add/edit/remove/status/run

use axum::Router;
use axum::routing::{get, post, put};
use std::sync::Arc;

use crate::handler::sys_report_handler;
use crate::state::AppState;

/// 受保护报表路由
pub fn report_routes() -> Router<Arc<AppState>> {
    Router::new()
        // ===== 报表定义（/system/report） =====
        // GET /system/report/list 分页查询
        .route("/system/report/list", get(sys_report_handler::report_list))
        // GET 详情 / DELETE 批量删除（同 {reportId} 段；删除段按 GET 段命名避免路由冲突）
        .route(
            "/system/report/{reportId}",
            get(sys_report_handler::report_info).delete(sys_report_handler::report_remove),
        )
        // PUT /{reportId}/status 启停
        .route(
            "/system/report/{reportId}/status",
            put(sys_report_handler::report_status),
        )
        // POST /{reportId}/preview 预览快照
        .route(
            "/system/report/{reportId}/preview",
            post(sys_report_handler::report_preview),
        )
        // POST /system/report 新增；PUT /system/report 修改
        .route(
            "/system/report",
            post(sys_report_handler::report_add).put(sys_report_handler::report_edit),
        )
        // ===== 报表订阅（/system/report/sub） =====
        // GET /system/report/sub/list 分页查询
        .route("/system/report/sub/list", get(sys_report_handler::sub_list))
        // GET 详情 / DELETE 批量删除
        .route(
            "/system/report/sub/{subId}",
            get(sys_report_handler::sub_info).delete(sys_report_handler::sub_remove),
        )
        // PUT /sub/{subId}/status 启停
        .route(
            "/system/report/sub/{subId}/status",
            put(sys_report_handler::sub_status),
        )
        // POST /sub/{subId}/run 手动触发推送
        .route(
            "/system/report/sub/{subId}/run",
            post(sys_report_handler::sub_run),
        )
        // POST /system/report/sub 新增；PUT /system/report/sub 修改
        .route(
            "/system/report/sub",
            post(sys_report_handler::sub_add).put(sys_report_handler::sub_edit),
        )
}
