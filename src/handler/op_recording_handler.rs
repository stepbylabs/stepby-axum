//! 操作录制与回放 Handler（Axum 原生实现）
//!
//! 接口路径对齐前端 `src/api/tool/recording.ts`：
//! - GET    /tool/recording/list                     分页查询录制
//! - GET    /tool/recording/{recordingId}            详情（抬头 + 步骤）
//! - POST   /tool/recording                          新建录制
//! - POST   /tool/recording/import                   导入 JSON 脚本（导出件的逆运算）
//! - PUT    /tool/recording                          编辑（名称/说明/状态）
//! - DELETE /tool/recording/{recordingIds}           批量删除（连带步骤与运行记录）
//! - POST   /tool/recording/{recordingId}/steps      追加一步（API 方式写入）
//! - PUT    /tool/recording/{recordingId}/steps/{stepId}   就地改一步（seq 不变）
//! - DELETE /tool/recording/{recordingId}/steps/{stepId}  删一步并收敛序号
//! - DELETE /tool/recording/{recordingId}/steps      清空步骤
//! - POST   /tool/recording/{recordingId}/replay     启动回放（异步；dryRun=true 只预检）
//! - GET    /tool/recording/{recordingId}/export     导出脚本（curl / http / json）
//! - GET    /tool/recording/{recordingId}/runs       最近回放记录
//! - GET    /tool/recording/run/{runId}              单次回放详情（逐步骤结论）
//!
//! ## 为什么回放要在这里把令牌取出来
//!
//! 回放用**触发者自己的身份**重发请求（不做任何提权，见回放服务模块注释），因此令牌必须
//! 在 handler 层从请求头取出后交给后台任务；它是本模块唯一处理凭据的地方，**不写日志、
//! 不入库、不出现在错误消息里**。

use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use std::sync::Arc;

use crate::common::constants::MAX_BATCH_DELETE_SIZE;
use crate::common::{AjaxResult, AppError, TableDataInfo};
use crate::middleware::Operator;
use crate::service::op_recording::{
    RecordingCreateDto, RecordingDetailVo, RecordingImportDto, RecordingQueryDto,
    RecordingUpdateDto, ScriptFormat, StepWriteDto,
};
use crate::service::op_recording_replay::{ReplayOptions, ReplayStartVo, RunDetailVo};
use crate::state::AppState;
use crate::utils::parse_id_list;

/// 回放基址：**由服务端配置决定，不由录制内容决定**。
///
/// 取 `server.port` 拼 `127.0.0.1`：回放必须走真实 HTTP 链路（中间件/权限/限流/审计全在），
/// 而监听地址是什么（0.0.0.0 / 具体网卡）与"本机能不能连上自己"无关。
/// `port = 0` 表示未配置监听端口（单测/嵌入式场景），此时不能回放——返回 400 而不是
/// 猜一个端口去连（猜错会连到别的服务上）。
fn self_base_url(state: &AppState) -> Result<String, AppError> {
    let port = state.config.server.port;
    if port == 0 {
        return Err(AppError::bad_request(
            "回放需要服务端监听端口（[server].port）已配置；当前为 0，无法确定回放目标",
        ));
    }
    Ok(format!("http://127.0.0.1:{port}"))
}

/// GET /tool/recording/list
#[utoipa::path(
    get,
    path = "/tool/recording/list",
    params(RecordingQueryDto),
    responses((status = 200, description = "查询成功")),
    tag = "tool-recording"
)]
pub async fn list(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    Query(query): Query<RecordingQueryDto>,
) -> Result<TableDataInfo<crate::entity::sys_op_recording::Model>, AppError> {
    let (rows, total) = state
        .op_recording_service
        .page(
            query,
            crate::common::tenant::tenant_scope(operator.tenant_id()),
        )
        .await?;
    Ok(TableDataInfo::new(total, rows))
}

/// GET /tool/recording/{recordingId}
#[utoipa::path(
    get,
    path = "/tool/recording/{recordingId}",
    params(("recordingId" = i64, Path, description = "录制 ID")),
    responses((status = 200, description = "查询成功"), (status = 404, description = "不存在")),
    tag = "tool-recording"
)]
pub async fn detail(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    Path(recording_id): Path<i64>,
) -> Result<AjaxResult<RecordingDetailVo>, AppError> {
    let detail = state
        .op_recording_service
        .detail(
            recording_id,
            crate::common::tenant::tenant_scope(operator.tenant_id()),
        )
        .await?;
    Ok(AjaxResult::success(detail))
}

/// POST /tool/recording
#[utoipa::path(
    post,
    path = "/tool/recording",
    request_body = RecordingCreateDto,
    responses((status = 200, description = "创建成功")),
    tag = "tool-recording"
)]
pub async fn create(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    axum::Json(payload): axum::Json<RecordingCreateDto>,
) -> Result<AjaxResult<crate::entity::sys_op_recording::Model>, AppError> {
    let model = state
        .op_recording_service
        .create(
            payload,
            operator.tenant_id(),
            Some(operator.user_id_i64()?),
            operator.username(),
        )
        .await?;
    Ok(AjaxResult::success(model))
}

/// POST /tool/recording/import
///
/// 导入 = 导出的逆运算：把一份 JSON 快照变成一条可回放的本地录制。
/// 与「新建 + 逐步追加」的区别只有一个：**整条事务**——要么这条录制连同全部步骤成立，
/// 要么库里什么都不留（半条录制在界面上看起来是能用的，那是最坏的一种假象）。
#[utoipa::path(
    post,
    path = "/tool/recording/import",
    request_body = RecordingImportDto,
    responses(
        (status = 200, description = "导入成功（返回抬头 + 步骤）"),
        (status = 400, description = "脚本内容不合法（点名第几步）"),
    ),
    tag = "tool-recording"
)]
pub async fn import_script(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    axum::Json(payload): axum::Json<RecordingImportDto>,
) -> Result<AjaxResult<RecordingDetailVo>, AppError> {
    let detail = state
        .op_recording_service
        .import_recording(
            payload,
            operator.tenant_id(),
            Some(operator.user_id_i64()?),
            operator.username(),
            crate::common::datetime::now_naive(),
        )
        .await?;
    Ok(AjaxResult::success(detail))
}

/// PUT /tool/recording
#[utoipa::path(
    put,
    path = "/tool/recording",
    request_body = RecordingUpdateDto,
    responses((status = 200, description = "更新成功")),
    tag = "tool-recording"
)]
pub async fn update(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    axum::Json(payload): axum::Json<RecordingUpdateDto>,
) -> Result<AjaxResult<u64>, AppError> {
    let affected = state
        .op_recording_service
        .update(
            payload,
            crate::common::tenant::tenant_scope(operator.tenant_id()),
        )
        .await?;
    Ok(AjaxResult::success(affected))
}

/// DELETE /tool/recording/{recordingIds}
#[utoipa::path(
    delete,
    path = "/tool/recording/{recordingIds}",
    params(("recordingIds" = String, Path, description = "逗号分隔的录制 ID")),
    responses((status = 200, description = "删除成功")),
    tag = "tool-recording"
)]
pub async fn remove(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    Path(ids): Path<String>,
) -> Result<AjaxResult<u64>, AppError> {
    let ids = parse_id_list::<i64>(&ids)?;
    if ids.len() > MAX_BATCH_DELETE_SIZE {
        return Err(AppError::bad_request(&format!(
            "单次最多删除 {MAX_BATCH_DELETE_SIZE} 条录制"
        )));
    }
    let removed = state
        .op_recording_service
        .delete(
            &ids,
            crate::common::tenant::tenant_scope(operator.tenant_id()),
        )
        .await?;
    Ok(AjaxResult::success(removed))
}

/// POST /tool/recording/{recordingId}/steps
#[utoipa::path(
    post,
    path = "/tool/recording/{recordingId}/steps",
    params(("recordingId" = i64, Path, description = "录制 ID")),
    request_body = StepWriteDto,
    responses((status = 200, description = "追加成功")),
    tag = "tool-recording"
)]
pub async fn append_step(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    Path(recording_id): Path<i64>,
    axum::Json(payload): axum::Json<StepWriteDto>,
) -> Result<AjaxResult<crate::entity::sys_op_recording_step::Model>, AppError> {
    let model = state
        .op_recording_service
        .append_step(
            recording_id,
            operator.tenant_id(),
            crate::common::tenant::tenant_scope(operator.tenant_id()),
            payload,
            crate::common::datetime::now_naive(),
        )
        .await?;
    Ok(AjaxResult::success(model))
}

/// PUT /tool/recording/{recordingId}/steps/{stepId}
///
/// 就地改一步：`seq` 不变（改期望状态码不是"挪动这一步"），`headers` 不参与编辑
/// （它是采集产物，见仓储层同名方法文档）。
#[utoipa::path(
    put,
    path = "/tool/recording/{recordingId}/steps/{stepId}",
    params(
        ("recordingId" = i64, Path, description = "录制 ID"),
        ("stepId" = i64, Path, description = "步骤 ID")
    ),
    request_body = StepWriteDto,
    responses(
        (status = 200, description = "保存成功"),
        (status = 400, description = "内容不合法 / 录制已归档"),
        (status = 404, description = "录制或步骤不存在"),
    ),
    tag = "tool-recording"
)]
pub async fn update_step(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    Path((recording_id, step_id)): Path<(i64, i64)>,
    axum::Json(payload): axum::Json<StepWriteDto>,
) -> Result<AjaxResult<crate::entity::sys_op_recording_step::Model>, AppError> {
    let model = state
        .op_recording_service
        .update_step(
            recording_id,
            step_id,
            crate::common::tenant::tenant_scope(operator.tenant_id()),
            payload,
            crate::common::datetime::now_naive(),
        )
        .await?;
    Ok(AjaxResult::success(model))
}

/// DELETE /tool/recording/{recordingId}/steps/{stepId}
#[utoipa::path(
    delete,
    path = "/tool/recording/{recordingId}/steps/{stepId}",
    params(
        ("recordingId" = i64, Path, description = "录制 ID"),
        ("stepId" = i64, Path, description = "步骤 ID")
    ),
    responses((status = 200, description = "删除成功")),
    tag = "tool-recording"
)]
pub async fn remove_step(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    Path((recording_id, step_id)): Path<(i64, i64)>,
) -> Result<AjaxResult<i32>, AppError> {
    let count = state
        .op_recording_service
        .delete_step(
            recording_id,
            step_id,
            crate::common::tenant::tenant_scope(operator.tenant_id()),
        )
        .await?;
    Ok(AjaxResult::success(count))
}

/// DELETE /tool/recording/{recordingId}/steps
#[utoipa::path(
    delete,
    path = "/tool/recording/{recordingId}/steps",
    params(("recordingId" = i64, Path, description = "录制 ID")),
    responses((status = 200, description = "清空成功")),
    tag = "tool-recording"
)]
pub async fn clear_steps(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    Path(recording_id): Path<i64>,
) -> Result<AjaxResult<i32>, AppError> {
    let count = state
        .op_recording_service
        .clear_steps(
            recording_id,
            crate::common::tenant::tenant_scope(operator.tenant_id()),
        )
        .await?;
    Ok(AjaxResult::success(count))
}

/// POST /tool/recording/{recordingId}/replay
///
/// 重活入口：**取闸必须排在启动回放之前**（`try_enter` 在本函数第一句之后立刻调用），
/// 否则闸满时后台回放已经开始，背压变成了"跑完再告诉你忙"。
#[utoipa::path(
    post,
    path = "/tool/recording/{recordingId}/replay",
    params(("recordingId" = i64, Path, description = "录制 ID")),
    request_body = ReplayOptions,
    responses((status = 200, description = "已启动"), (status = 429, description = "闸满")),
    tag = "tool-recording"
)]
pub async fn replay(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    Path(recording_id): Path<i64>,
    headers: HeaderMap,
    axum::Json(options): axum::Json<ReplayOptions>,
) -> Result<AjaxResult<ReplayStartVo>, AppError> {
    // 预检不发请求、也不占重活许可：它做的只是字符串渲染。
    if options.dry_run {
        let detail = state
            .op_recording_service
            .detail(
                recording_id,
                crate::common::tenant::tenant_scope(operator.tenant_id()),
            )
            .await?;
        let preview = crate::service::op_recording_replay::preview_steps(
            &detail.steps,
            &self_base_url(&state)?,
            &options,
        )?;
        return Ok(AjaxResult::success(ReplayStartVo {
            run_id: 0,
            task_id: 0,
            total: preview.len() as i32,
            preview: Some(preview),
        }));
    }

    // 重活闸：回放会连续出网 N 次并可能写对端业务数据
    let _permit = crate::common::resource_gate::try_enter(
        crate::common::resource_gate::HeavyEntry::RecordingReplay,
    )?;

    let token = crate::middleware::auth::extract_bearer_token(&headers)?;
    let vo = state
        .op_recording_replay_service
        .start(
            state.clone(),
            recording_id,
            operator.tenant_id(),
            crate::common::tenant::tenant_scope(operator.tenant_id()),
            operator.username(),
            Some(operator.user_id_i64()?),
            token,
            &self_base_url(&state)?,
            options,
        )
        .await?;
    Ok(AjaxResult::success(vo))
}

/// POST /tool/recording/{recordingId}/export
///
/// 用 POST 而不是 GET：本仓导出族统一走 `download()`（前端唯一处理"HTTP 200 + JSON 错误体 /
/// 0 字节载荷 / 保存通道失败"三条失败出口的通道），而它是 POST 形态。为 REST 纯洁性另写一条
/// GET 下载链，等于把 b145 刚收敛的失败分类再分裂一次。
#[utoipa::path(
    post,
    path = "/tool/recording/{recordingId}/export",
    params(
        ("recordingId" = i64, Path, description = "录制 ID"),
        ("format" = Option<String>, Query, description = "curl | http | json，默认 curl")
    ),
    responses((status = 200, description = "脚本内容")),
    tag = "tool-recording"
)]
pub async fn export(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    Path(recording_id): Path<i64>,
    Query(query): Query<ExportQuery>,
) -> Result<Response, AppError> {
    let format = ScriptFormat::parse(query.format.as_deref().unwrap_or("curl"))
        .ok_or_else(|| AppError::bad_request("format 只能是 curl / http / json"))?;
    let (filename, content_type, content) = state
        .op_recording_service
        .export_script(
            recording_id,
            crate::common::tenant::tenant_scope(operator.tenant_id()),
            format,
            &self_base_url(&state)?,
        )
        .await?;

    let mut headers = HeaderMap::new();
    headers.insert(
        axum::http::header::CONTENT_DISPOSITION,
        crate::common::http_download::content_disposition_header(&filename, "recording.txt"),
    );
    if let Ok(val) = axum::http::HeaderValue::from_str(&content_type) {
        headers.insert(axum::http::header::CONTENT_TYPE, val);
    }
    if let Ok(val) = axum::http::HeaderValue::from_str(&content.len().to_string()) {
        headers.insert(axum::http::header::CONTENT_LENGTH, val);
    }
    Ok((StatusCode::OK, headers, content).into_response())
}

/// 导出查询参数
#[derive(Debug, Clone, serde::Deserialize, utoipa::IntoParams)]
#[serde(rename_all = "camelCase")]
pub struct ExportQuery {
    pub format: Option<String>,
}

/// GET /tool/recording/{recordingId}/runs
#[utoipa::path(
    get,
    path = "/tool/recording/{recordingId}/runs",
    params(
        ("recordingId" = i64, Path, description = "录制 ID"),
        ("limit" = Option<u64>, Query, description = "最近 N 次，默认 20")
    ),
    responses((status = 200, description = "查询成功")),
    tag = "tool-recording"
)]
pub async fn list_runs(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    Path(recording_id): Path<i64>,
    Query(query): Query<RunsQuery>,
) -> Result<AjaxResult<Vec<crate::entity::sys_op_recording_run::Model>>, AppError> {
    let rows = state
        .op_recording_replay_service
        .runs_of(
            recording_id,
            crate::common::tenant::tenant_scope(operator.tenant_id()),
            query.limit.unwrap_or(20),
        )
        .await?;
    Ok(AjaxResult::success(rows))
}

/// 运行列表查询参数
#[derive(Debug, Clone, serde::Deserialize, utoipa::IntoParams)]
#[serde(rename_all = "camelCase")]
pub struct RunsQuery {
    pub limit: Option<u64>,
}

/// GET /tool/recording/{recordingId}/runs/{runId}
///
/// 两级归属校验：运行行必须属于该录制，且两者都要通过租户谓词。只查 `run_id` 会让
/// 一次猜测遍历拿到他租户的回放明细（其中含请求路径与响应片段）。
#[utoipa::path(
    get,
    path = "/tool/recording/{recordingId}/runs/{runId}",
    params(
        ("recordingId" = i64, Path, description = "录制 ID"),
        ("runId" = i64, Path, description = "运行 ID")
    ),
    responses((status = 200, description = "查询成功")),
    tag = "tool-recording"
)]
pub async fn run_detail(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    Path((recording_id, run_id)): Path<(i64, i64)>,
) -> Result<AjaxResult<RunDetailVo>, AppError> {
    let scope = crate::common::tenant::tenant_scope(operator.tenant_id());
    // 先确认录制可见（否则 404，不泄漏"这个 runId 存在"）
    let _ = state
        .op_recording_service
        .detail(recording_id, scope)
        .await?;
    let detail = state
        .op_recording_replay_service
        .run_detail(run_id, scope)
        .await?;
    if detail.run.recording_id != recording_id {
        return Err(AppError::not_found("回放记录不存在"));
    }
    Ok(AjaxResult::success(detail))
}
