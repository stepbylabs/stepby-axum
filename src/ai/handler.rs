//! AI 助手 Handler（NL2SQL v4.1：三层开关 + PAT 拒绝 + 受控执行）
//!
//! - `POST /ai/chat`：`ai:chat` perm（fail-closed 权限映射）+ 能力位 `ai.copilot`
//!   + 平台层 `[ai].enabled` 三重校验；PAT 会话一律 403（v4.1-B2）。

use axum::{Json, extract::State};
use serde::Deserialize;
use serde_json::{Value, json};
use std::sync::Arc;

use crate::ai::FEATURE_AI_COPILOT;
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

/// POST /ai/chat —— 自然语言问数据
pub async fn chat(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    ValidatedJson(dto): ValidatedJson<AiChatDto>,
) -> Result<Json<Value>, AppError> {
    // 1. 平台层开关（fail-closed + 明确降级提示，UX v5-D「错误路径」）
    if !state.config.ai.enabled {
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

    let service = AiService::new(state.db.clone(), state.config.ai.clone());
    let outcome = service
        .chat(&dto.question, tid)
        .await
        .map_err(|e| AppError::bad_request(&format!("AI 查询失败: {e}")))?;

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

/// GET /ai/tables —— 白名单表 schema（供前端展示"可查询范围"）
pub async fn tables(
    State(state): State<Arc<AppState>>,
    operator: Operator,
) -> Result<AjaxResult<Value>, AppError> {
    if !state.config.ai.enabled {
        return Err(AppError::forbidden(&tr!("error.ai.disabled")));
    }
    if operator.is_pat() {
        return Err(AppError::forbidden(&tr!("error.ai.pat_forbidden")));
    }
    let service = AiService::new(state.db.clone(), state.config.ai.clone());
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
