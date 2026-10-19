// stepby-axum/src/router/report_dataset_router.rs
//! 报表数据集与大屏路由（G-01 M1；需挂在鉴权中间件下）

use axum::Router;
use axum::routing::{delete, get, post, put};
use std::sync::Arc;

use crate::handler::report_dataset_handler;
use crate::state::AppState;

pub fn report_routes() -> Router<Arc<AppState>> {
    Router::new()
        .route(
            "/report/dataset/list",
            get(report_dataset_handler::dataset_list),
        )
        .route(
            "/report/dataset/preview",
            post(report_dataset_handler::dataset_preview),
        )
        .route(
            // 删除段按 GET 段命名（{datasetId}/{dashboardId}）避免 axum 0.8 同位置不同参数名构建期冲突
            "/report/dataset/{datasetId}",
            delete(report_dataset_handler::dataset_remove),
        )
        .route(
            "/report/dataset/{datasetId}",
            get(report_dataset_handler::dataset_info),
        )
        // SQL 明文回填（编辑专用；edit 权限键在 permission.rs 把关）
        // 批七十六出清单：数据集编辑对话框打开时经 api/report.ts getDatasetSql 回填
        // （DatasetVo 恒不含明文，不回填则改名也必须重敲整段 SQL）
        .route(
            "/report/dataset/{datasetId}/sql",
            post(report_dataset_handler::dataset_sql),
        )
        .route("/report/dataset", post(report_dataset_handler::dataset_add))
        .route("/report/dataset", put(report_dataset_handler::dataset_edit))
        .route(
            "/report/dashboard/list",
            get(report_dataset_handler::dashboard_list),
        )
        .route(
            "/report/dashboard/{dashboardId}",
            delete(report_dataset_handler::dashboard_remove),
        )
        .route(
            "/report/dashboard/{dashboardId}",
            get(report_dataset_handler::dashboard_info),
        )
        .route(
            "/report/dashboard",
            post(report_dataset_handler::dashboard_save),
        )
}
