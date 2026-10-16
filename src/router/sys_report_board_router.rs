//! 报表看板模块路由注册（配置化只读报表 v1）
//!
//! 受保护路由（需 auth_middleware + permission_middleware）：
//! - GET    /tool/report-board/list              本人看板清单
//! - POST   /tool/report-board                   创建看板
//! - GET    /tool/report-board/{boardId}         看板详情
//! - PUT    /tool/report-board/{boardId}         更新看板
//! - DELETE /tool/report-board/{boardId}         删除看板
//! - GET    /tool/report-board/sources           数据源清单（白名单）
//! - GET    /tool/report-board/data/{sourceKey}  数据源数据
//!
//! 权限映射（permission_middleware，见 middleware/permission.rs）：
//! - tool:reportBoard:list（读：list/info/sources/data）
//! - tool:reportBoard:save（写：add/edit/remove）
//!
//! 路由冲突说明：/sources、/data 为静态段，axum matchit 静态段优先于 {boardId}
//! 参数段，二者可共存。

use axum::Router;
use axum::routing::{get, post};
use std::sync::Arc;

use crate::handler::sys_report_board_handler;
use crate::state::AppState;

/// 受保护报表看板路由
pub fn report_board_routes() -> Router<Arc<AppState>> {
    Router::new()
        // GET /list 本人看板清单；POST 创建
        .route(
            "/tool/report-board/list",
            get(sys_report_board_handler::board_list),
        )
        .route(
            "/tool/report-board",
            post(sys_report_board_handler::board_add),
        )
        // GET 详情 / PUT 更新 / DELETE 删除（同 {boardId} 段）
        // b71 契约审计：GET 详情零前端调用（同路径 PUT/DELETE 在用），保留 REST 完整性 → router/mod.rs 清单 ①
        .route(
            "/tool/report-board/{boardId}",
            get(sys_report_board_handler::board_info)
                .put(sys_report_board_handler::board_edit)
                .delete(sys_report_board_handler::board_remove),
        )
        // GET /sources 数据源清单（静态段，优先于 {boardId} 匹配）
        .route(
            "/tool/report-board/sources",
            get(sys_report_board_handler::source_list),
        )
        // GET /data/{sourceKey} 数据源数据
        .route(
            "/tool/report-board/data/{sourceKey}",
            get(sys_report_board_handler::source_data),
        )
}
