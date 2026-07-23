//! 字典模块路由注册
//!
//! 路由结构：
//! - /system/dict/type/* — 字典类型管理（6 个接口）
//! - /system/dict/data/* — 字典数据管理（6 个接口）

use std::sync::Arc;
use axum::Router;
use axum::routing::{delete, get, post, put};

use crate::handler::sys_dict_handler;
use crate::state::AppState;

/// 字典模块路由（字典类型 + 字典数据）
pub fn dict_routes() -> Router<Arc<AppState>> {
    Router::new()
        // ===== 字典类型 =====
        .route("/system/dict/type/list", get(sys_dict_handler::dict_type_list))
        .route("/system/dict/type/optionselect", get(sys_dict_handler::dict_type_optionselect))
        .route("/system/dict/type/refreshCache", delete(sys_dict_handler::dict_type_refresh_cache))
        // POST /system/dict/type/export 导出字典类型列表
        .route("/system/dict/type/export", post(sys_dict_handler::dict_type_export))
        .route("/system/dict/type/{dictId}", get(sys_dict_handler::dict_type_get_info))
        .route("/system/dict/type", post(sys_dict_handler::dict_type_add))
        .route("/system/dict/type", put(sys_dict_handler::dict_type_edit))
        .route("/system/dict/type/{dictId}", delete(sys_dict_handler::dict_type_remove))
        // ===== 字典数据 =====
        .route("/system/dict/data/list", get(sys_dict_handler::dict_data_list))
        .route("/system/dict/data/type/{dictType}", get(sys_dict_handler::dict_data_by_type))
        // POST /system/dict/data/export 导出字典数据列表
        .route("/system/dict/data/export", post(sys_dict_handler::dict_data_export))
        .route("/system/dict/data/{dictCode}", get(sys_dict_handler::dict_data_get_info))
        .route("/system/dict/data", post(sys_dict_handler::dict_data_add))
        .route("/system/dict/data", put(sys_dict_handler::dict_data_edit))
        .route("/system/dict/data/{dictCode}", delete(sys_dict_handler::dict_data_remove))
}
