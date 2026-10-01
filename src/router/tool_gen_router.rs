//! 代码生成模块路由注册
//!
//! 路由结构：
//! - /tool/gen/list                 GET    分页查询生成表列表
//! - /tool/gen/db/list              GET    查询数据库表列表
//! - /tool/gen/{tableId}            GET    查询表详细信息
//! - /tool/gen/importTable          POST   导入表
//! - /tool/gen/createTable          POST   创建表
//! - /tool/gen                      PUT    修改生成配置
//! - /tool/gen/{tableIds}           DELETE 删除表
//! - /tool/gen/preview/{tableId}    GET    预览生成代码
//! - /tool/gen/genCode/{tableName}  GET    生成代码
//! - /tool/gen/batchGenCode         GET    批量生成代码（多表打包 ZIP）
//! - /tool/gen/synchDb/{tableName}  POST   同步数据库
//!
//! 注意：静态路由（list、db/list、importTable、createTable、batchGenCode）需在动态路由 {tableId} 之前注册。

use std::sync::Arc;

use axum::Router;
use axum::routing::{get, post, put};

use crate::handler::tool_gen_handler;
use crate::middleware::platform_guard::platform_only_guard;
use crate::state::AppState;

/// 代码生成模块路由
///
/// P1-1：整组 `/tool/gen/*` 为平台专属能力，挂 [`platform_only_guard`] 请求层守卫，
/// 租户操作者（含租户管理员）一律 403（不依赖 perms，作为权限层的第二道防线）。
pub fn gen_routes() -> Router<Arc<AppState>> {
    Router::new()
        // 静态路由优先注册
        .route("/tool/gen/list", get(tool_gen_handler::list))
        .route("/tool/gen/db/list", get(tool_gen_handler::db_list))
        .route(
            "/tool/gen/importTable",
            post(tool_gen_handler::import_table),
        )
        .route(
            "/tool/gen/createTable",
            post(tool_gen_handler::create_table),
        )
        .route(
            "/tool/gen/batchGenCode",
            get(tool_gen_handler::batch_gen_code),
        )
        .route(
            "/tool/gen/preview/{tableId}",
            get(tool_gen_handler::preview),
        )
        .route(
            "/tool/gen/genCode/{tableName}",
            get(tool_gen_handler::gen_code),
        )
        .route(
            "/tool/gen/synchDb/{tableName}",
            post(tool_gen_handler::synch_db),
        )
        // 动态路由：GET 查询详情 + DELETE 删除共用同一路径模式
        .route(
            "/tool/gen/{tableId}",
            get(tool_gen_handler::get_table).delete(tool_gen_handler::delete_table),
        )
        .route("/tool/gen", put(tool_gen_handler::update_table))
        .route_layer(axum::middleware::from_fn(platform_only_guard))
}
