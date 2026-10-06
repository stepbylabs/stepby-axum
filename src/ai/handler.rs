//! AI 助手 Handler（NL2SQL v4.1：三层开关 + PAT 拒绝 + 受控执行）
//!
//! - `POST /ai/chat`：`ai:chat` perm（fail-closed 权限映射）+ 能力位 `ai.copilot`
//!   + 平台层 `[ai].enabled` 三重校验；PAT 会话一律 403（v4.1-B2）。

use axum::{Json, extract::State};
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
            tokio::spawn(async move {
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
                )
                .await;
            });
            return Err(AppError::bad_request(&format!("AI 查询失败: {e}")));
        }
    };
    {
        let db = state.db.clone();
        let eff = effective.clone();
        let q = dto.question.clone();
        let oc = outcome.clone();
        tokio::spawn(async move {
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
            )
            .await;
        });
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
    Ok(AjaxResult::success(
        state.ai_config_service.masked().await?,
    ))
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
    Ok(AjaxResult::success_msg(&tr!("common.success")))
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

