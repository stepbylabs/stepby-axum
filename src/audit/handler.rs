// stepby-axum/src/audit/handler.rs
//! 审计变更留痕 Handler（数据变更审计合规域）
//!
//! 接口路径对齐前端调用规范：
//! - GET /system/audit-change/list   分页查询变更留痕
//! - GET /system/audit-change/{id}   变更详情（前后快照 + 字段差异）
//! - GET /system/audit-change/export CSV 导出（含操作人/表/主键/action/变更字段/时间）

use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::response::{IntoResponse, Response};

use crate::common::error::AppError;
use crate::common::response::{AjaxResult, TableDataInfo};
use crate::entity::sys_audit_change::Model as SysAuditChangeModel;
use crate::middleware::Operator;
use crate::service::sys_audit_change_service::AuditChangeQueryDto;
use crate::state::AppState;

/// GET /system/audit-change/list
/// 分页查询变更留痕
#[utoipa::path(
    get,
    path = "/system/audit-change/list",
    params(AuditChangeQueryDto),
    responses(
        (status = 200, description = "查询成功", body = TableDataInfo<SysAuditChangeModel>),
        (status = 500, description = "服务器错误"),
    ),
    tag = "system-audit-change"
)]
pub async fn list(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    Query(query): Query<AuditChangeQueryDto>,
) -> Result<TableDataInfo<SysAuditChangeModel>, AppError> {
    let (rows, total) = state
        .audit_change_service
        .get_change_page(query, crate::common::tenant::tenant_scope(operator.tenant_id()))
        .await?;
    Ok(TableDataInfo::new(total, rows))
}

/// GET /system/audit-change/{id}
/// 变更留痕详情（含前后快照 JSON 与字段差异清单）
#[utoipa::path(
    get,
    path = "/system/audit-change/{id}",
    params(
        ("id" = i64, Path, description = "变更记录 ID")
    ),
    responses(
        (status = 200, description = "查询成功", body = AjaxResult<SysAuditChangeModel>),
        (status = 404, description = "变更记录不存在"),
    ),
    tag = "system-audit-change"
)]
pub async fn get_info(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    Path(id): Path<i64>,
) -> Result<AjaxResult<SysAuditChangeModel>, AppError> {
    // 多租户：详情查询同样按租户收敛（查到非本租户行视为不存在）
    let model = state.audit_change_service.get_change_detail(id).await?;
    let scope = crate::common::tenant::tenant_scope(operator.tenant_id());
    if let Some(tid) = scope
        && model.tenant_id != tid
    {
        return Err(AppError::not_found(&crate::tr!(
            "error.audit_change.not_found"
        )));
    }
    Ok(AjaxResult::success(model))
}

/// GET /system/audit-change/export
/// 导出变更留痕为 CSV（UTF-8 带 BOM，Excel 直接打开不乱码）
///
/// 导出列：ID / 操作人 ID / 操作人 / 表名 / 行主键 / 动作 / 变更字段 / 操作时间
/// （before/after 快照体积大且含业务数据，不进导出，审计回查走详情接口）
#[utoipa::path(
    get,
    path = "/system/audit-change/export",
    params(AuditChangeQueryDto),
    responses(
        (status = 200, description = "导出成功", content_type = "text/csv"),
        (status = 500, description = "服务器错误"),
    ),
    tag = "system-audit-change"
)]
pub async fn export(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    Query(query): Query<AuditChangeQueryDto>,
) -> Result<Response, AppError> {
    let rows = state
        .audit_change_service
        .export_changes(query, crate::common::tenant::tenant_scope(operator.tenant_id()))
        .await?;

    let csv = build_csv(&rows);
    let filename = format!(
        "audit_change_{}.csv",
        chrono::Local::now().format("%Y%m%d%H%M%S")
    );
    let mut out = Vec::with_capacity(csv.len() + 3);
    // UTF-8 BOM：Excel 识别中文表头
    out.extend_from_slice(&[0xEF, 0xBB, 0xBF]);
    out.extend_from_slice(csv.as_bytes());

    let content_disposition = format!("attachment; filename=\"{filename}\"");
    Ok((
        [
            ("content-type", "text/csv; charset=utf-8"),
            ("content-disposition", content_disposition.as_str()),
        ],
        out,
    )
        .into_response())
}

/// CSV 字段转义：含逗号 / 引号 / 换行的字段用双引号包裹，内部引号翻倍（RFC 4180）
fn csv_escape(field: &str) -> String {
    if field.contains(',') || field.contains('"') || field.contains('\n') || field.contains('\r') {
        format!("\"{}\"", field.replace('"', "\"\""))
    } else {
        field.to_string()
    }
}

/// 构造变更留痕 CSV 文本（表头中文，Excel 直接打开可读）
fn build_csv(rows: &[SysAuditChangeModel]) -> String {
    let mut out = String::from("ID,操作人ID,操作人,表名,行主键,动作,变更字段,操作时间\r\n");
    for r in rows {
        let changed = r.changed_fields.replace(['"', '\n', '\r'], " ");
        let line = [
            r.id.to_string(),
            r.operator_id.map(|v| v.to_string()).unwrap_or_default(),
            r.operator_name.clone().unwrap_or_default(),
            r.table_name.clone(),
            r.row_pk.clone(),
            r.action.clone(),
            changed,
            r.operated_at.format("%Y-%m-%d %H:%M:%S").to_string(),
        ]
        .iter()
        .map(|f| csv_escape(f))
        .collect::<Vec<_>>()
        .join(",");
        out.push_str(&line);
        out.push_str("\r\n");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::csv_escape;

    #[test]
    fn csv_escape_plain_field_untouched() {
        assert_eq!(csv_escape("sys_user"), "sys_user");
        assert_eq!(csv_escape("42"), "42");
    }

    #[test]
    fn csv_escape_quotes_special_fields() {
        assert_eq!(csv_escape("a,b"), "\"a,b\"");
        assert_eq!(csv_escape("he\"llo"), "\"he\"\"llo\"");
        assert_eq!(csv_escape("a\nb"), "\"a\nb\"");
    }
}
