//! AI 助手 Handler（NL2SQL v4.1：三层开关 + PAT 拒绝 + 受控执行）
//!
//! - `POST /ai/chat`：`ai:chat` perm（fail-closed 权限映射）+ 能力位 `ai.copilot`
//!   + 平台层 `[ai].enabled` 三重校验；PAT 会话一律 403（v4.1-B2）。

use axum::{
    Json,
    extract::{Query, State},
};
use serde::Deserialize;
use serde_json::{Value, json};
use std::sync::Arc;

use crate::ai::FEATURE_AI_COPILOT;
use crate::ai::config_service;
use crate::ai::service::AiService;
use crate::common::{AjaxResult, AppError, ValidatedJson};
use crate::middleware::auth::Operator;
use crate::state::AppState;
use crate::tr;

#[derive(Debug, Deserialize, garde::Validate)]
pub struct AiChatDto {
    /// 自然语言问题（≤500 字）
    #[garde(length(min = 1, max = 500))]
    pub question: String,
}

/// b72（AGENTS A.2 资源硬上限 + 背压）：占用一个推理许可。
///
/// 闸满 ⇒ 记 `stepby_outbound_requests_total{component="ai",outcome="rejected"}` + WARN + 429
/// （`error.ai.busy`）。`/ai/chat` 与 `/ai/replay` **共用本函数**，两条入口的背压口径不得分叉。
///
/// 上限取 `[ai].max_concurrency`（启动只读，改后需重启）：刻意不读 `sys.ai.*` 运行态热配置，
/// 否则会出现"管理端改了上限、闸门仍是首次建闸的值"的行为分裂（AGENTS C.7 配置归类明确）。
fn admit_inference(state: &AppState) -> Result<tokio::sync::OwnedSemaphorePermit, AppError> {
    crate::ai::gate::inference_gate(state.config.ai.max_concurrency)
        .try_admit()
        .ok_or_else(|| {
            crate::observability::metrics::MetricsRegistry::global()
                .record_outbound("ai", "rejected", 0.0);
            tracing::warn!(
                limit = state.config.ai.max_concurrency,
                "AI 推理并发闸已满，请求被拒（429）"
            );
            AppError::new(429, tr!("error.ai.busy"))
        })
}

/// POST /ai/chat —— 自然语言问数据
pub async fn chat(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    ValidatedJson(dto): ValidatedJson<AiChatDto>,
) -> Result<Json<Value>, AppError> {
    // 1. 平台层开关（§5.39 AI-01：运行时有效配置 sys.ai.* 覆盖 config.toml）
    let effective = state.ai_config_service.get_effective().await?;
    if !effective.enabled {
        return Err(AppError::forbidden(&tr!("error.ai.disabled")));
    }
    // 2. PAT 会话拒绝（v4.1-B2：AI 面板仅对交互式会话开放）
    if operator.is_pat() {
        return Err(AppError::forbidden(&tr!("error.ai.pat_forbidden")));
    }
    // 3. 租户层能力位 ai.copilot（平台租户恒 on——平台层开关已单独校验；租户 fail-closed）
    let tid = operator.tenant_id();
    let fs = state.tenant_service.tenant_features(tid).await?;
    if tid != 0 && !fs.is_on(FEATURE_AI_COPILOT) {
        return Err(AppError::forbidden(&tr!("error.ai.capability_off")));
    }
    // 4. 角色层：ai:chat 由 permission_middleware fail-closed 校验（路由映射已登记）。

    // 4.5 b72（AGENTS A.2）：推理并发闸，闸满立即 429（口径见 [`admit_inference`]）
    let _inference_permit = admit_inference(&state)?;

    let service = AiService::new(state.db.clone(), effective.clone());
    let started = std::time::Instant::now();
    let uid: i64 = operator.user_id().parse().unwrap_or(0);
    // AI-02：成功/失败都留痕（spawn 不阻塞响应；写入失败仅日志）
    let outcome = match service.chat(&dto.question, tid).await {
        Ok(o) => o,
        Err(e) => {
            let db = state.db.clone();
            let eff = effective.clone();
            let q = dto.question.clone();
            let emsg = e.to_string();
            crate::common::background::spawn_tracked(
                "ai_save_history",
                crate::common::background::LIGHT_DB_BUDGET,
                Some(crate::observability::metrics::MetricsRegistry::global()),
                async move {
                    let svc = AiService::new(db, eff);
                    svc.save_history(
                        tid,
                        uid,
                        &q,
                        "",
                        &[],
                        &[],
                        0,
                        started.elapsed().as_millis(),
                        false,
                        Some(&emsg),
                        None,
                    )
                    .await;
                },
            );
            return Err(AppError::bad_request(&format!("AI 查询失败: {e}")));
        }
    };
    {
        let db = state.db.clone();
        let eff = effective.clone();
        let q = dto.question.clone();
        let oc = outcome.clone();
        crate::common::background::spawn_tracked(
            "ai_save_history",
            crate::common::background::LIGHT_DB_BUDGET,
            Some(crate::observability::metrics::MetricsRegistry::global()),
            async move {
                let svc = AiService::new(db, eff);
                svc.save_history(
                    tid,
                    uid,
                    &q,
                    &oc.sql,
                    &oc.tables,
                    &oc.columns,
                    oc.rows.len(),
                    started.elapsed().as_millis(),
                    true,
                    None,
                    oc.token_usage,
                )
                .await;
            },
        );
    }

    Ok(Json(json!({
        "code": 200,
        "msg": "ok",
        "data": {
            "answer": outcome.answer,
            "sql": outcome.sql,
            "tables": outcome.tables,
            "columns": outcome.columns,
            "rows": outcome.rows,
            "rowCount": outcome.rows.len(),
            "tokenUsage": outcome.token_usage,
        }
    })))
}

/// GET /ai/tables —— 白名单表 schema（供前端展示"可查询范围"）
pub async fn tables(
    State(state): State<Arc<AppState>>,
    operator: Operator,
) -> Result<AjaxResult<Value>, AppError> {
    let effective = state.ai_config_service.get_effective().await?;
    if !effective.enabled {
        return Err(AppError::forbidden(&tr!("error.ai.disabled")));
    }
    if operator.is_pat() {
        return Err(AppError::forbidden(&tr!("error.ai.pat_forbidden")));
    }
    let service = AiService::new(state.db.clone(), effective);
    let schema = service.build_schema().await?;
    let data = Value::Array(
        schema
            .into_iter()
            .map(|t| {
                json!({
                    "table": t.name,
                    "columns": t.columns
                        .into_iter()
                        .map(|(c, ty)| json!({"name": c, "type": ty}))
                        .collect::<Vec<_>>(),
                })
            })
            .collect(),
    );
    Ok(AjaxResult::success(data))
}

// ==================== AI-01：运行时配置管理（§5.39，平台专属） ====================

/// 平台操作者门控（非平台租户一律 403）
fn ensure_platform(operator: &Operator) -> Result<(), AppError> {
    if operator.tenant_id() != 0 {
        return Err(AppError::forbidden(&tr!("error.common.forbidden")));
    }
    Ok(())
}

/// GET /system/aiConfig —— 读有效配置（api_key 掩码回显，永不返回明文）
pub async fn get_config(
    State(state): State<Arc<AppState>>,
    operator: Operator,
) -> Result<AjaxResult<config_service::AiConfigMaskedVo>, AppError> {
    ensure_platform(&operator)?;
    Ok(AjaxResult::success(state.ai_config_service.masked().await?))
}

/// PUT /system/aiConfig —— 更新配置（api_key 传空保留原值；SSRF 校验 base_url；
/// 写后 refreshCache 热生效）
pub async fn update_config(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    ValidatedJson(dto): ValidatedJson<config_service::AiConfigUpdateDto>,
) -> Result<AjaxResult<serde_json::Value>, AppError> {
    ensure_platform(&operator)?;
    let operator_name = operator.user_id();
    state.ai_config_service.update(&dto).await?;
    tracing::info!(operator = %operator_name, "AI 助手配置已由平台管理员更新");
    Ok(AjaxResult::success_msg(&tr!("msg.success.operation")))
}

/// POST /system/aiConfig/test —— 连通性测试（独立 10s 超时，返回延迟或错误摘要）
pub async fn test_config(
    State(state): State<Arc<AppState>>,
    operator: Operator,
) -> Result<AjaxResult<serde_json::Value>, AppError> {
    ensure_platform(&operator)?;
    let msg = state.ai_config_service.test_connectivity().await?;
    Ok(AjaxResult::success_msg(&msg))
}

// ==================== AI-02：查询历史（§5.42） ====================

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AiHistoryPageDto {
    pub page: Option<u64>,
    pub size: Option<u64>,
    /// 管理视图租户筛选（仅平台 tid=0 有效；租户管理员被 service 强制本租户）
    pub tenant_filter: Option<i64>,
}

/// GET /system/ai/history —— 本人历史分页（ai:chat 自查）
pub async fn list_my_history(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    Query(q): Query<AiHistoryPageDto>,
) -> Result<Json<Value>, AppError> {
    let tid = operator.tenant_id();
    let uid: i64 = operator.user_id().parse().unwrap_or(0);
    let effective = state.ai_config_service.get_effective().await?;
    let service = AiService::new(state.db.clone(), effective);
    let (items, total) = service
        .list_my_history(tid, uid, q.page.unwrap_or(1), q.size.unwrap_or(20))
        .await
        .map_err(|e| AppError::internal(&format!("查询历史失败: {e}")))?;
    Ok(Json(
        json!({ "code": 200, "msg": "ok", "data": { "items": items, "total": total } }),
    ))
}

/// GET /system/ai/history/admin —— 管理/平台视图（monitor:aiHistory:list）
pub async fn list_admin_history(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    Query(q): Query<AiHistoryPageDto>,
) -> Result<Json<Value>, AppError> {
    let tid = operator.tenant_id();
    let effective = state.ai_config_service.get_effective().await?;
    let service = AiService::new(state.db.clone(), effective);
    let (items, total) = service
        .list_admin_history(
            tid,
            q.tenant_filter,
            q.page.unwrap_or(1),
            q.size.unwrap_or(20),
        )
        .await
        .map_err(|e| AppError::internal(&format!("查询历史失败: {e}")))?;
    Ok(Json(
        json!({ "code": 200, "msg": "ok", "data": { "items": items, "total": total } }),
    ))
}

/// GET /system/ai/history/admin/export —— AI 问数历史导出（Excel，monitor:aiHistory:list）
pub async fn export_admin_history(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    Query(q): Query<AiHistoryPageDto>,
) -> Result<axum::response::Response, AppError> {
    let tid = operator.tenant_id();
    let effective = state.ai_config_service.get_effective().await?;
    let service = AiService::new(state.db.clone(), effective);
    let items = service
        .export_admin_history(tid, q.tenant_filter, crate::common::page::EXPORT_MAX_ROWS)
        .await
        .map_err(|e| AppError::internal(&format!("导出历史失败: {e}")))?;

    use crate::common::excel::{CellValue, ExcelColumn, export_to_excel_with_fields};
    let columns = [
        ExcelColumn {
            key: "id",
            header: ("历史ID", "History ID"),
            getter: |r: &serde_json::Value| CellValue::Number(r["id"].as_i64().unwrap_or(0) as f64),
        },
        ExcelColumn {
            key: "tenantId",
            header: ("租户ID", "Tenant ID"),
            getter: |r: &serde_json::Value| {
                CellValue::Number(r["tenantId"].as_i64().unwrap_or(0) as f64)
            },
        },
        ExcelColumn {
            key: "userId",
            header: ("用户ID", "User ID"),
            getter: |r: &serde_json::Value| {
                CellValue::Number(r["userId"].as_i64().unwrap_or(0) as f64)
            },
        },
        ExcelColumn {
            key: "question",
            header: ("问题", "Question"),
            getter: |r: &serde_json::Value| {
                CellValue::Text(r["question"].as_str().unwrap_or_default().into())
            },
        },
        ExcelColumn {
            key: "sql",
            header: ("SQL", "SQL"),
            getter: |r: &serde_json::Value| {
                CellValue::Text(r["sql"].as_str().unwrap_or_default().into())
            },
        },
        ExcelColumn {
            key: "rowsCount",
            header: ("行数", "Rows"),
            getter: |r: &serde_json::Value| {
                CellValue::Number(r["rowsCount"].as_i64().unwrap_or(0) as f64)
            },
        },
        ExcelColumn {
            key: "durationMs",
            header: ("耗时(ms)", "Duration (ms)"),
            getter: |r: &serde_json::Value| {
                CellValue::Number(r["durationMs"].as_i64().unwrap_or(0) as f64)
            },
        },
        ExcelColumn {
            key: "success",
            header: ("状态", "Status"),
            getter: |r: &serde_json::Value| {
                CellValue::Text(
                    if r["success"].as_bool() == Some(true) {
                        "成功"
                    } else {
                        "失败"
                    }
                    .into(),
                )
            },
        },
        ExcelColumn {
            key: "errorMsg",
            header: ("错误信息", "Error"),
            getter: |r: &serde_json::Value| {
                CellValue::Text(r["errorMsg"].as_str().unwrap_or_default().into())
            },
        },
        ExcelColumn {
            key: "createTime",
            header: ("时间", "Time"),
            getter: |r: &serde_json::Value| {
                CellValue::Text(r["createTime"].as_str().unwrap_or_default().into())
            },
        },
    ];

    export_to_excel_with_fields(
        &crate::tr!("excel.sheet.ai_history"),
        "ai_chat_history",
        &columns,
        &items,
        None,
        false,
    )
    .await
}

/// DELETE /system/ai/history/{id} —— 删除本人历史（横向越权防护在 service 层）
pub async fn remove_my_history(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    axum::extract::Path(id): axum::extract::Path<i64>,
) -> Result<Json<Value>, AppError> {
    let tid = operator.tenant_id();
    let uid: i64 = operator.user_id().parse().unwrap_or(0);
    let effective = state.ai_config_service.get_effective().await?;
    let service = AiService::new(state.db.clone(), effective);
    let deleted = service
        .delete_my_history(tid, uid, id)
        .await
        .map_err(|e| AppError::internal(&format!("删除历史失败: {e}")))?;
    Ok(Json(
        json!({ "code": 200, "msg": "ok", "data": { "deleted": deleted } }),
    ))
}

/// POST /ai/replay —— 重放本人历史（AI-02 决策 2；三层校验同 chat，
/// 历史 SQL 重新过 sql_guard——白名单/租户范围变更后重放被拒是预期语义）
#[derive(Debug, Deserialize, garde::Validate)]
pub struct AiReplayDto {
    #[garde(range(min = 1))]
    pub history_id: i64,
}

pub async fn replay(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    ValidatedJson(dto): ValidatedJson<AiReplayDto>,
) -> Result<Json<Value>, AppError> {
    // 1. 平台层开关（运行时有效配置）
    let effective = state.ai_config_service.get_effective().await?;
    if !effective.enabled {
        return Err(AppError::forbidden(&tr!("error.ai.disabled")));
    }
    // 2. PAT 会话拒绝（与 chat 同口径：AI 面板仅交互式会话）
    if operator.is_pat() {
        return Err(AppError::forbidden(&tr!("error.ai.pat_forbidden")));
    }
    // 3. 租户层能力位
    let tid = operator.tenant_id();
    let fs = state.tenant_service.tenant_features(tid).await?;
    if tid != 0 && !fs.is_on(FEATURE_AI_COPILOT) {
        return Err(AppError::forbidden(&tr!("error.ai.capability_off")));
    }
    // 重放同样是一次真实推理 ⇒ 与 chat 共用同一个并发闸（不得一条有闸一条没有）
    let _inference_permit = admit_inference(&state)?;
    let uid: i64 = operator.user_id().parse().unwrap_or(0);
    let service = AiService::new(state.db.clone(), effective.clone());
    let started = std::time::Instant::now();
    let outcome = match service.replay(dto.history_id, tid, uid).await {
        Ok(o) => o,
        Err(e) => {
            let db = state.db.clone();
            let eff = effective.clone();
            let q = format!("重放#{id}", id = dto.history_id);
            let emsg = e.to_string();
            crate::common::background::spawn_tracked(
                "ai_save_history",
                crate::common::background::LIGHT_DB_BUDGET,
                Some(crate::observability::metrics::MetricsRegistry::global()),
                async move {
                    let svc = AiService::new(db, eff);
                    svc.save_history(
                        tid,
                        uid,
                        &q,
                        "",
                        &[],
                        &[],
                        0,
                        started.elapsed().as_millis(),
                        false,
                        Some(&emsg),
                        None,
                    )
                    .await;
                },
            );
            return Err(AppError::bad_request(&format!("重放失败: {e}")));
        }
    };
    {
        let db = state.db.clone();
        let eff = effective.clone();
        let q = outcome.answer.clone();
        let oc = outcome.clone();
        crate::common::background::spawn_tracked(
            "ai_save_history",
            crate::common::background::LIGHT_DB_BUDGET,
            Some(crate::observability::metrics::MetricsRegistry::global()),
            async move {
                let svc = AiService::new(db, eff);
                svc.save_history(
                    tid,
                    uid,
                    &q,
                    &oc.sql,
                    &oc.tables,
                    &oc.columns,
                    oc.rows.len(),
                    started.elapsed().as_millis(),
                    true,
                    None,
                    oc.token_usage,
                )
                .await;
            },
        );
    }
    Ok(Json(json!({
        "code": 200,
        "msg": "ok",
        "data": {
            "answer": outcome.answer,
            "sql": outcome.sql,
            "tables": outcome.tables,
            "columns": outcome.columns,
            "rows": outcome.rows,
            "rowCount": outcome.rows.len(),
        }
    })))
}
