// stepby-axum/src/handler/data_rule_handler.rs
//! DP-01 数据权限规则管理端（平台/租户管理员）
//!
//! - GET  /system/dataRule/list  规则分页清单
//! - POST /system/dataRule       新建/更新（rule_id 缺省=新建）
//! - DELETE /system/dataRule/{id} 软删（清关联即时收敛）

use crate::common::{AppError, TableDataInfo};
use crate::middleware::Operator;
use crate::service::data_rule_service::{DataRuleDto, DataRuleService, DataRuleVo};
use crate::state::AppState;
use axum::Json;
use axum::extract::{Path, Query, State};
use serde::Deserialize;
use std::sync::Arc;

#[derive(Debug, Deserialize)]
pub struct DataRuleListQuery {
    pub page: Option<u64>,
    pub size: Option<u64>,
}

/// GET /system/dataRule/list
pub async fn list(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    Query(q): Query<DataRuleListQuery>,
) -> Result<TableDataInfo<DataRuleVo>, AppError> {
    let tid = operator.tenant_id();
    let page = q.page.unwrap_or(1).max(1);
    let size = q.size.unwrap_or(20).clamp(1, 100);
    let service = DataRuleService::new(std::sync::Arc::new(state.db.clone()));
    let (rows, total) = service.list(tid, page, size).await?;
    Ok(TableDataInfo::new(total, rows))
}

/// POST /system/dataRule（新建/更新）
pub async fn save(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    Json(dto): Json<DataRuleDto>,
) -> Result<Json<serde_json::Value>, AppError> {
    let tid = operator.tenant_id();
    let uid_str = operator.user_id().to_string();
    let service = DataRuleService::new(std::sync::Arc::new(state.db.clone()));
    let rule_id = service.save(dto, tid, &uid_str).await?;
    Ok(Json(serde_json::json!({
        "code": 200,
        "msg": "ok",
        "data": { "ruleId": rule_id }
    })))
}

/// DELETE /system/dataRule/{id}
pub async fn remove(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    Path(id): Path<i64>,
) -> Result<Json<serde_json::Value>, AppError> {
    let tid = operator.tenant_id();
    let service = DataRuleService::new(std::sync::Arc::new(state.db.clone()));
    service.remove(id, tid).await?;
    Ok(Json(serde_json::json!({ "code": 200, "msg": "ok" })))
}
