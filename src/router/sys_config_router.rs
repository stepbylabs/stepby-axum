//! 参数配置模块路由注册
//!
//! 路由结构：
//! - /system/config/list                 分页查询（system:config:list）
//! - /system/config/configKey/{configKey} 按 key 查询值（仅需登录，无权限要求）
//! - /system/config/refreshCache         刷新缓存（system:config:remove）
//! - /system/config/{configId}           详情（system:config:query）
//! - /system/config                      新增/修改（system:config:add / system:config:edit）
//! - /system/config/{configIds}          批量删除（system:config:remove）
//! - /system/config/export               导出（system:config:export）
//!
//! 注意：静态路由（list、configKey、refreshCache、export）需在动态路由 {configId} 之前注册，
//! axum 0.8 优先匹配静态段。

use axum::Router;
use axum::routing::{delete, get, post, put};
use std::sync::Arc;

use crate::handler::{sys_config_handler, upload_config_handler};
use crate::state::AppState;

/// 参数配置模块路由
pub fn config_routes() -> Router<Arc<AppState>> {
    Router::new()
        // G-11：OSS 存储配置（平台专属，handler 内 tenant_id==0 门控；test 为静态段优先注册）
        .route(
            "/system/uploadConfig",
            get(upload_config_handler::get_config),
        )
        .route(
            "/system/uploadConfig",
            put(upload_config_handler::update_config),
        )
        .route(
            "/system/uploadConfig/test",
            post(upload_config_handler::test_config),
        )
        // b71 契约审计：编排预留，零前端调用（存储后端切换走 API）→ router/mod.rs 清单 ③
        .route(
            "/system/uploadConfig/switchBackend",
            post(upload_config_handler::switch_backend),
        )
        // 静态路由优先注册
        .route("/system/config/list", get(sys_config_handler::list))
        .route(
            "/system/config/configKey/{configKey}",
            get(sys_config_handler::get_config_by_key),
        )
        .route(
            "/system/config/governance-locked",
            get(sys_config_handler::governance_locked_keys),
        )
        .route(
            "/system/config/refreshCache",
            delete(sys_config_handler::refresh_cache),
        )
        .route("/system/config/export", post(sys_config_handler::export))
        // 集合资源
        .route("/system/config", post(sys_config_handler::add))
        .route("/system/config", put(sys_config_handler::edit))
        // 动态路由最后注册
        .route(
            "/system/config/{configId}",
            get(sys_config_handler::get_info),
        )
        .route(
            "/system/config/{configId}",
            delete(sys_config_handler::remove),
        )
}
