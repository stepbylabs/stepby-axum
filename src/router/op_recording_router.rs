//! 操作录制与回放路由注册
//!
//! ## 为什么运行详情挂在录制下面（`{recordingId}/runs/{runId}`）而不是 `/run/{runId}`
//!
//! 同级上同时存在静态段与参数段（`run` vs `{recordingId}`）时，axum 的路由树虽然按
//! "静态优先"匹配，但一旦未来再加一个静态段，歧义就从"不会发生"变成"取决于注册顺序"。
//! 本模块**不留这种可能性**：除 `/list` 外，全部路径都在同一个参数段之下，运行详情用
//! 两级归属（录制 → 运行）表达，顺带让服务层能用同一条租户谓词校验两行。

use axum::Router;
use axum::routing::{get, post};
use std::sync::Arc;

use crate::handler::op_recording_handler;
use crate::state::AppState;

/// 唯一的静态段（新增静态段前先读模块注释）
pub const STATIC_SEGMENTS: &[&str] = &["list"];

pub fn op_recording_routes() -> Router<Arc<AppState>> {
    Router::new()
        // 静态段
        .route("/tool/recording/list", get(op_recording_handler::list))
        // 抬头
        .route(
            "/tool/recording",
            post(op_recording_handler::create).put(op_recording_handler::update),
        )
        .route(
            "/tool/recording/{recordingId}",
            get(op_recording_handler::detail).delete(op_recording_handler::remove),
        )
        // 步骤
        .route(
            "/tool/recording/{recordingId}/steps",
            post(op_recording_handler::append_step).delete(op_recording_handler::clear_steps),
        )
        .route(
            "/tool/recording/{recordingId}/steps/{stepId}",
            axum::routing::delete(op_recording_handler::remove_step),
        )
        // 回放
        .route(
            "/tool/recording/{recordingId}/replay",
            post(op_recording_handler::replay),
        )
        .route(
            "/tool/recording/{recordingId}/runs",
            get(op_recording_handler::list_runs),
        )
        .route(
            "/tool/recording/{recordingId}/runs/{runId}",
            get(op_recording_handler::run_detail),
        )
        // 导出（POST：与全仓导出族一致，且能复用前端唯一的 `download()` 失败分类通道）
        .route(
            "/tool/recording/{recordingId}/export",
            post(op_recording_handler::export),
        )
}
