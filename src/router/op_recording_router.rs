//! 操作录制与回放路由注册
//!
//! ## 为什么运行详情挂在录制下面（`{recordingId}/runs/{runId}`）而不是 `/run/{runId}`
//!
//! 同级上同时存在静态段与参数段（`run` vs `{recordingId}`）时，axum 的路由树虽然按
//! "静态优先"匹配，但一旦未来再加一个静态段，歧义就从"不会发生"变成"取决于注册顺序"。
//! 本模块**不留这种可能性**：除 [`STATIC_SEGMENTS`] 列出的段外，全部路径都在同一个
//! 参数段之下，运行详情用两级归属（录制 → 运行）表达，顺带让服务层能用同一条租户谓词
//! 校验两行。
//!
//! ## b148 新增第二个静态段 `import`：为什么它是安全的
//!
//! `import` 只注册 **POST**，而同级的 `{recordingId}` 只注册 GET/DELETE——两者方法集不
//! 相交，静态优先匹配不会把"某个 id 恰好叫 import"（不可能，id 是整数）抢走。唯一的
//! 可观测差异是 `GET /tool/recording/import` 得到 405（而不是被当成 `{recordingId}`
//! 解析后回 400）；405 正是"这个路径存在但不支持该方法"的准确答复。

use axum::Router;
use axum::routing::{get, post};
use std::sync::Arc;

use crate::handler::op_recording_handler;
use crate::state::AppState;

/// 静态段清单（新增静态段前先读模块注释：必须与同级参数段的方法集不相交）
pub const STATIC_SEGMENTS: &[&str] = &["list", "import"];

pub fn op_recording_routes() -> Router<Arc<AppState>> {
    Router::new()
        // 静态段
        .route("/tool/recording/list", get(op_recording_handler::list))
        .route(
            "/tool/recording/import",
            post(op_recording_handler::import_script),
        )
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
            axum::routing::put(op_recording_handler::update_step)
                .delete(op_recording_handler::remove_step),
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
