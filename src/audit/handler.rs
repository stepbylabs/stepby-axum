// stepby-axum/src/audit/handler.rs
//! 审计变更留痕 Handler（数据变更审计合规域）
//!
//! 接口路径对齐前端调用规范：
//! - GET /system/audit-change/list   分页查询变更留痕
//! - GET /system/audit-change/{id}   变更详情（前后快照 + 字段差异）
//! - GET /system/audit-change/export CSV 导出（含操作人/表/主键/action/变更字段/时间）

use std::sync::Arc;

use axum::extract::{ConnectInfo, Path, Query, State};
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Response};
use std::net::SocketAddr;

use crate::common::error::AppError;
use crate::common::response::{AjaxResult, TableDataInfo};
use crate::entity::sys_audit_change::Model as SysAuditChangeModel;
use crate::middleware::Operator;
use crate::repository::sys_audit_change::AuditChangeExportRow;
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
        .get_change_page(
            query,
            crate::common::tenant::tenant_scope(operator.tenant_id()),
        )
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
    ConnectInfo(peer_addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Query(query): Query<AuditChangeQueryDto>,
) -> Result<Response, AppError> {
    // 导出族与 16 条 xlsx 端点共用同一把闸（export:excel，8 路）。CSV 不经
    // `excel::export_to_excel_with_fields` 构造点，因此必须在这里自己持有许可：
    // 路由层的 `precheck` 只做"闸满即早拒"，不占许可 ⇒ 光有它时并发的 CSV 导出
    // 谁都不占用预算，闸对这条链路只剩一个恒真的判断。
    let _gate = crate::common::resource_gate::try_enter(
        crate::common::resource_gate::HeavyEntry::ExcelExport,
    )?;
    // 审计面记录"导出了哪个子集"（b137）：筛选条件在 query 被消费前留一份；
    // 分页参数不记（导出是全量语义，页码无意义）。
    let filter = serde_json::json!({
        "tableName": query.table_name,
        "rowPk": query.row_pk,
        "action": query.action,
        "operatorName": query.operator_name,
        "beginTime": query.begin_time,
        "endTime": query.end_time,
    });
    let rows = state
        .audit_change_service
        .export_changes(
            query,
            crate::common::tenant::tenant_scope(operator.tenant_id()),
        )
        .await?;

    // b137：全量变更留痕 CSV 是 GET 外带面（oper_log 中间件只记写方法）。
    // 行已取回、即将返回时才留痕；失败路径（500）不落审计。
    let client_ip = crate::utils::ip::extract_client_ip(
        &headers,
        peer_addr.ip(),
        &state.config.server.trusted_proxies,
    );
    crate::common::egress_audit::record_egress(
        &state,
        &operator,
        &client_ip,
        crate::common::egress_audit::EgressEvent {
            kind: crate::common::egress_audit::EgressKind::AuditChangeExport,
            // 查询串不进 oper_url（可能含搜索词），筛选条件见 oper_param
            oper_url: "/system/audit-change/export".to_string(),
            oper_param: filter,
            detail: serde_json::json!({ "rows": rows.len() }),
            target_tenant_id: None,
        },
    );

    let csv = build_csv(&rows);
    let filename = format!(
        "audit_change_{}.csv",
        chrono::Local::now().format("%Y%m%d%H%M%S")
    );
    let mut out = Vec::with_capacity(csv.len() + 3);
    // UTF-8 BOM：Excel 识别中文表头
    out.extend_from_slice(&[0xEF, 0xBB, 0xBF]);
    out.extend_from_slice(csv.as_bytes());

    // b139：文件名头部走单一实现（此前直接拼 `&str`，非 ASCII 名进入响应头元组时
    // 由 axum 内部转换失败——审计 CSV 的默认名是 ASCII，但调用链没有理由依赖这一点）。
    let content_disposition =
        crate::common::http_download::content_disposition_header(&filename, "audit_change.csv");
    let mut response = ([("content-type", "text/csv; charset=utf-8")], out).into_response();
    response
        .headers_mut()
        .insert("content-disposition", content_disposition);
    // 与 xlsx 导出同一口径：触及 EXPORT_MAX_ROWS 上限几乎必然是被截断。
    // 不标出来的话，审计员手里是一份"看起来完整"的半份数据（前端据此弹提示）。
    if is_export_truncated(rows.len()) {
        response.headers_mut().insert(
            "X-Export-Truncated",
            axum::http::HeaderValue::from_static("true"),
        );
    }
    Ok(response)
}

/// 导出是否被行数上限截断（纯函数，便于对上限边界做双向断言）
fn is_export_truncated(row_count: usize) -> bool {
    row_count as u64 >= crate::common::page::EXPORT_MAX_ROWS
}

/// 纯十进制数值形态（可选符号 + 整数/小数 + 可选指数）。
///
/// 与前端 `utils/csv.ts` 的 `NUMERIC` 同口径。刻意不用 `f64::from_str` 单独判定：
/// Rust 会接受 `inf` / `NaN`，而 `+inf` 在 Excel 里正是"以 + 开头、按钮求值"的形态。
fn is_plain_number(field: &str) -> bool {
    if field.is_empty()
        || !field
            .bytes()
            .all(|b| b.is_ascii_digit() || matches!(b, b'+' | b'-' | b'.' | b'e' | b'E'))
    {
        return false;
    }
    field.parse::<f64>().is_ok_and(f64::is_finite)
}

/// CSV 公式注入防护（OWASP）：Excel / WPS / LibreOffice 打开 CSV 时，以
/// `=` `+` `-` `@`、制表符或回车开头的单元格会被当公式求值——`=HYPERLINK(...)`
/// 可外带数据、`=cmd|' /C calc'!A0` 在旧版 DDE 下可执行命令。留痕里的
/// `operator_name` / `row_pk` / `changed_fields` 全部来自业务数据，导出人（平台
/// 审计员）与被导出内容的写入者不是同一个人，所以这是可达的攻击链。
///
/// 前缀单引号把单元格固定成文本；纯数字（含负数）保持原样——给 `-42` 加前缀会
/// 把本来正确的数值列变成文本列，而 `-42` 本身不会被求值。
fn neutralize_formula(field: &str) -> String {
    let dangerous = field.starts_with(['=', '+', '-', '@', '\t', '\r']);
    if dangerous && !is_plain_number(field) {
        format!("'{field}")
    } else {
        field.to_string()
    }
}

/// CSV 字段转义：先做公式前缀中和，再按 RFC 4180 引号规则处理
/// （含逗号 / 引号 / 换行的字段用双引号包裹，内部引号翻倍）。
///
/// 顺序不可换：先引号后加前缀会产出 `"'=…"` 这类把单引号放进引号内的形态，不同
/// 表格软件对它的解释不一致；先前缀再整体加引号，才能保证每个软件读到的都是一
/// 个以 `'` 开头的文本单元格。
fn csv_escape(field: &str) -> String {
    let neutralized = neutralize_formula(field);
    if neutralized.contains(',')
        || neutralized.contains('"')
        || neutralized.contains('\n')
        || neutralized.contains('\r')
    {
        format!("\"{}\"", neutralized.replace('"', "\"\""))
    } else {
        neutralized
    }
}

/// 构造变更留痕 CSV 文本（表头中文，Excel 直接打开可读）
fn build_csv(rows: &[AuditChangeExportRow]) -> String {
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
    use super::{
        AuditChangeExportRow, build_csv, csv_escape, is_export_truncated, is_plain_number,
    };

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
        assert_eq!(csv_escape("a\rb"), "\"a\rb\"");
    }

    /// OWASP CSV 注入六类起始字符全部必须被中和（前缀单引号），且引号规则照旧。
    #[test]
    fn csv_escape_neutralizes_every_formula_prefix() {
        assert_eq!(csv_escape("=1+1"), "'=1+1");
        assert_eq!(csv_escape("+1+1"), "'+1+1");
        assert_eq!(csv_escape("-1+1"), "'-1+1");
        assert_eq!(csv_escape("@SUM(A1)"), "'@SUM(A1)");
        assert_eq!(csv_escape("\tcmd"), "'\tcmd");
        assert_eq!(csv_escape("\r=1"), "\"'\r=1\"");
        // 危险前缀 + 需要引号：前缀必须先于引号（结果整体是一个以 ' 开头的字段）
        assert_eq!(
            csv_escape("=HYPERLINK(\"http://evil\",\"x\")"),
            "\"'=HYPERLINK(\"\"http://evil\"\",\"\"x\"\")\""
        );
        assert_eq!(csv_escape("=SUM(A1,B1)"), "\"'=SUM(A1,B1)\"");
        // 普通中文 / 已带单引号的文本不重复加前缀
        assert_eq!(csv_escape("张三"), "张三");
        assert_eq!(csv_escape("'=1+1"), "'=1+1");
    }

    /// 纯数字豁免：负数是合法数值列，加前缀会把它变成文本（且它本身不会被求值）。
    /// `inf` / `NaN` 这类 `f64` 能解析但不是十进制的形态不得豁免。
    #[test]
    fn csv_escape_keeps_plain_numbers_and_rejects_non_decimal() {
        assert_eq!(csv_escape("-42"), "-42");
        assert_eq!(csv_escape("+3.5"), "+3.5");
        assert_eq!(csv_escape("-1e3"), "-1e3");
        assert_eq!(csv_escape(".5"), ".5");
        assert_eq!(csv_escape("+inf"), "'+inf");
        assert_eq!(csv_escape("-NaN"), "'-NaN");
        for plain in ["1", "-1.5", "+2e3", ".5"] {
            assert!(is_plain_number(plain), "{plain} 应判定为纯数字");
        }
        for not_plain in ["", " 1", "1,000", "inf", "+inf", "NaN", "1e", "--1"] {
            assert!(!is_plain_number(not_plain), "{not_plain} 不得判定为纯数字");
        }
    }

    /// 截断判据的双向边界：刚好到上限必须报截断，少一行必须不报。
    /// 若只测"到上限为 true"，把 `>=` 改成 `>` 也能过——"不误报"这一侧同样要钉。
    #[test]
    fn export_truncation_flag_is_exact_at_the_limit() {
        let max = crate::common::page::EXPORT_MAX_ROWS as usize;
        assert!(!is_export_truncated(0));
        assert!(!is_export_truncated(max - 1));
        assert!(is_export_truncated(max));
        assert!(is_export_truncated(max + 1));
    }

    /// 端到端：危险的操作人昵称与主键进 CSV 后必须是文本；数值列保持数值形态。
    #[test]
    fn build_csv_neutralizes_dangerous_business_fields() {
        let row = AuditChangeExportRow {
            id: 9,
            operator_id: Some(-1),
            operator_name: Some("=HYPERLINK(\"http://evil\",\"x\")".into()),
            table_name: "sys_user".into(),
            row_pk: "+1+1".into(),
            action: "UPDATE".into(),
            changed_fields: "[\"status\"]".into(),
            operated_at: chrono::NaiveDate::from_ymd_opt(2026, 10, 27)
                .expect("合法日期")
                .and_hms_opt(1, 2, 3)
                .expect("合法时间"),
        };
        let csv = build_csv(&[row]);
        assert!(
            csv.contains("9,-1,\"'=HYPERLINK(\"\"http://evil\"\",\"\"x\"\")\",sys_user,'+1+1"),
            "危险字段必须被中和且数值列保持原样: {csv}"
        );
    }
}
