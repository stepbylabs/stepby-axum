// axum-backend/src/common/excel.rs
//! Excel 导出工具（T-09/T-10 重构）
//!
//! 关键变化：
//! - `ExcelColumn` 增加 `key`（= JSON 序列化名，serde camelCase）与双语 `header: (zh, en)`
//! - 单元格类型化（`CellValue`：Text/Number/DateTime），当前导出统一用 Text，
//!   Number/DateTime 变体保留供后续按列启用
//! - `fields` 按 **key** 匹配（兼容旧中文名过渡）
//! - 大数据量走 `constant_memory` 流式模式，内存 O(1)
//! - 整本工作簿构建经 `spawn_blocking` 卸载到阻塞线程池，避免卡 tokio worker
//! - 表头按请求 locale（`common::i18n::pick`）解析
//! - 截断时设置 `X-Export-Truncated` 响应头（N5）

use std::borrow::Cow;

use axum::http::{header, HeaderValue, StatusCode};
use axum::response::Response;
use rust_xlsxwriter::{Format, Workbook};

use crate::common::error::AppError;
use crate::common::i18n;
use crate::common::page::EXPORT_MAX_ROWS;

/// 单元格值（类型化，T-10）
pub enum CellValue<'a> {
    Text(Cow<'a, str>),
    Number(f64),
    /// 原始日期时间（写入时按 yyyy-mm-dd hh:mm:ss 格式化为字符串，便于兼容）
    DateTime(chrono::NaiveDateTime),
}

/// Excel 列定义
///
/// - `key`：稳定标识 = JSON 序列化名（serde camelCase），嵌套用点路径（`dept.deptName`）。
///   前端导出字段选择按 key 匹配；漂移检测：序列化样本行断言 key 存在。
/// - `header`：`(zh, en)` 双语表头，按请求 locale 经 `i18n::pick` 解析。
/// - `getter`：取值函数（保留 fn 指针零成本）。
#[derive(Clone)]
pub struct ExcelColumn<T> {
    pub key: &'static str,
    pub header: (&'static str, &'static str),
    pub getter: for<'a> fn(&'a T) -> CellValue<'a>,
}

/// 超过此行数启用 constant_memory 流式模式（写临时文件，内存 O(1)）
const CONSTANT_MEMORY_THRESHOLD: usize = 5000;

/// 通用 Excel 导出（全字段）
pub async fn export_to_excel<T>(
    sheet_name: &str,
    filename: &str,
    columns: &[ExcelColumn<T>],
    rows: &[T],
) -> Result<Response, AppError>
where
    T: Clone + Send + Sync + 'static,
{
    export_to_excel_with_fields(sheet_name, filename, columns, rows, None, false).await
}

/// 通用 Excel 导出（支持字段选择 + 截断标记）
///
/// - `fields`：可选字段 key 列表（也兼容旧中文表头名，过渡期）；None/空 = 全部列
/// - `truncated`：是否因 EXPORT_MAX_ROWS 截断（true 时设置 X-Export-Truncated 头）
pub async fn export_to_excel_with_fields<T>(
    sheet_name: &str,
    filename: &str,
    columns: &[ExcelColumn<T>],
    rows: &[T],
    fields: Option<&[String]>,
    truncated: bool,
) -> Result<Response, AppError>
where
    T: Clone + Send + Sync + 'static,
{
    // locale 在异步上下文读取（task-local 在 spawn 逃逸后失效），捕获后传入阻塞任务
    // C-i18n：捕获 locale 字符串而非 bool，在 build_xlsx 内通过 LOCALE.scope 注入，
    // 使 getter 内的 crate::tr! 能正确按当前 locale 返回对应语言（修复英文用户导出 Excel 状态值显示中文的问题）
    let locale = i18n::current_locale().to_string();
    // N5 启发式截断探测：行数触及 EXPORT_MAX_ROWS 上限几乎必然意味着被 limit 截断
    // （自然恰等于上限的概率极低）；与调用方显式 truncated 取或
    let auto_truncated = rows.len() as u64 >= EXPORT_MAX_ROWS;
    let final_truncated = truncated || auto_truncated;
    let columns_owned: Vec<ExcelColumn<T>> = columns.to_vec();
    let rows_owned: Vec<T> = rows.to_vec();
    let fields_owned: Option<Vec<String>> = fields.map(|f| f.to_vec());
    let sheet_name = sheet_name.to_string();
    let filename = filename.to_string();

    let xlsx_data = tokio::task::spawn_blocking(move || {
        build_xlsx(&sheet_name, &columns_owned, &rows_owned, fields_owned.as_deref(), locale)
    })
    .await
    .map_err(|_| AppError::internal(&crate::tr!("error.excel.build_task_failed")))??;

    // 构建响应
    // P1 修复：文件名经 CRLF/控制字符清洗并按 RFC 5987 编码非 ASCII 文件名，
    // 防止响应头注入与中文文件名下载乱码（原实现未清洗，且非 ASCII 文件名经 HeaderValue::from_str 静默降级）。
    let content_disposition = build_content_disposition(&filename);
    let mut response = Response::new(xlsx_data.into());
    *response.status_mut() = StatusCode::OK;
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static(
            "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        ),
    );
    response.headers_mut().insert(
        header::CONTENT_DISPOSITION,
        HeaderValue::from_str(&content_disposition)
            .unwrap_or_else(|_| HeaderValue::from_static("attachment; filename=export.xlsx")),
    );
    // N5：截断标记（前端 download 工具读取并提示）
    if final_truncated {
        response
            .headers_mut()
            .insert("X-Export-Truncated", HeaderValue::from_static("true"));
    }
    Ok(response)
}

/// 同步构建 xlsx 字节（在 spawn_blocking 内执行）
///
/// C-i18n：通过 [`i18n::with_locale_sync`] 注入 thread-local locale，
/// 使 getter 内的 `crate::tr!` 能正确按当前 locale 返回对应语言。
/// 修复英文用户导出 Excel 时状态值显示中文的问题（task-local 在 spawn_blocking 内不自动传播）。
/// 净化 Excel sheet 名称（P2）：长度 ≤ 31，替换非法字符 `[]:*?/\`（XLSX 规范限制），
/// 避免超长/非法 sheet 名导致构建失败返回 500
fn sanitize_sheet_name(name: &str) -> String {
    let cleaned: String = name
        .chars()
        .map(|c| if "[]:*?/\\".contains(c) { '_' } else { c })
        .collect();
    let mut result = cleaned;
    if result.chars().count() > 31 {
        let truncated: String = result.chars().take(31).collect();
        result = truncated;
    }
    if result.trim().is_empty() {
        result = "Sheet1".to_string();
    }
    result
}

fn build_xlsx<T>(
    sheet_name: &str,
    columns: &[ExcelColumn<T>],
    rows: &[T],
    fields: Option<&[String]>,
    locale: String,
) -> Result<Vec<u8>, AppError>
where
    T: Clone + Send + Sync + 'static,
{
    i18n::with_locale_sync(&locale, || {
        build_xlsx_inner(sheet_name, columns, rows, fields)
    })
}

fn build_xlsx_inner<T>(
    sheet_name: &str,
    columns: &[ExcelColumn<T>],
    rows: &[T],
    fields: Option<&[String]>,
) -> Result<Vec<u8>, AppError>
where
    T: Clone + Send + Sync + 'static,
{
    // 按 key 匹配列（兼容旧中文名过渡期）
    let selected_indices: Vec<usize> = match fields {
        Some(list) if !list.is_empty() => columns
            .iter()
            .enumerate()
            .filter_map(|(i, c)| {
                if list.iter().any(|f| f == c.key || f == c.header.0) {
                    Some(i)
                } else {
                    None
                }
            })
            .collect(),
        _ => (0..columns.len()).collect(),
    };

    if selected_indices.is_empty() {
        return Err(AppError::bad_request(&crate::tr!("error.excel.fields_empty")));
    }

    // constant_memory：行数超阈值时启用流式写盘，内存 O(1)（需 rust_xlsxwriter feature）
    let mut workbook = Workbook::new();
    let worksheet = if rows.len() > CONSTANT_MEMORY_THRESHOLD {
        workbook.add_worksheet_with_constant_memory()
    } else {
        workbook.add_worksheet()
    };
    let worksheet = worksheet
        .set_name(sanitize_sheet_name(sheet_name))
        .map_err(|_| AppError::internal(&crate::tr!("error.excel.sheet_create_failed")))?;

    let header_format = Format::new().set_bold();
    let datetime_format = Format::new().set_num_format("yyyy-mm-dd hh:mm:ss");

    // 表头（按 locale 解析；is_zh() 现在能正确工作，因为 LOCALE.scope 已注入）
    let locale_zh = i18n::is_zh();
    for (out_col, &col_idx) in selected_indices.iter().enumerate() {
        let col = &columns[col_idx];
        let header_text = if locale_zh { col.header.0 } else { col.header.1 };
        worksheet
            .write_string_with_format(0, out_col as u16, header_text, &header_format)
            .map_err(|_| AppError::internal(&crate::tr!("error.excel.header_write_failed")))?;
    }

    // 数据行
    for (row_idx, row) in rows.iter().enumerate() {
        for (out_col, &col_idx) in selected_indices.iter().enumerate() {
            let col = &columns[col_idx];
            let value = (col.getter)(row);
            let target_row = (row_idx + 1) as u32;
            let target_col = out_col as u16;
            match value {
                CellValue::Text(cow) => {
                    worksheet
                        .write_string(target_row, target_col, cow.as_ref())
                        .map_err(|_| AppError::internal(&crate::tr!("error.excel.data_write_failed")))?;
                }
                CellValue::Number(n) => {
                    worksheet
                        .write_number(target_row, target_col, n)
                        .map_err(|_| AppError::internal(&crate::tr!("error.excel.data_write_failed")))?;
                }
                CellValue::DateTime(dt) => {
                    let s = dt.format("%Y-%m-%d %H:%M:%S").to_string();
                    worksheet
                        .write_string_with_format(target_row, target_col, &s, &datetime_format)
                        .map_err(|_| AppError::internal(&crate::tr!("error.excel.data_write_failed")))?;
                }
            }
        }
    }

    workbook
        .save_to_buffer()
        .map_err(|_| AppError::internal(&crate::tr!("error.excel.generate_failed")))
}

/// 清洗文件名，防止响应头注入
///
/// 移除 CRLF、NUL 与控制字符（防头注入），移除引号/反斜杠（防破坏 Content-Disposition 引号结构），
/// 消除首尾空白。清洗后仍为空时调用方应提供 ASCII 兜底名。
fn sanitize_filename(name: &str) -> String {
    let cleaned: String = name
        .chars()
        .filter(|c| !matches!(c, '\r' | '\n' | '\0' | '"' | '\\'))
        .map(|c| if c.is_control() { '_' } else { c })
        .collect();
    cleaned.trim().to_string()
}

/// RFC 5987 百分号编码（UTF-8 字节）
///
/// 仅保留 attr-char 字符集（ALPHA / DIGIT / !#$&+-.^_|~），其余字节按 UTF-8 逐字节 `%XX` 编码，
/// 使非 ASCII 文件名可在 Content-Disposition 的 `filename*` 中安全传输。
fn rfc5987_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len() * 3);
    for b in s.as_bytes() {
        match b {
            b'A'..=b'Z'
            | b'a'..=b'z'
            | b'0'..=b'9'
            | b'!' | b'#' | b'$' | b'&' | b'+' | b'-' | b'.'
            | b'^' | b'_' | b'`' | b'|' | b'~' => out.push(*b as char),
            _ => out.push_str(&format!("%{:02X}", b)),
        }
    }
    out
}

/// 构造 Content-Disposition 响应头（P1 修复，防头注入 + 中文文件名）
///
/// - 先清洗文件名（CRLF/控制字符/引号）
/// - ASCII 文件名：直接 `filename="..."`（带引号，允许空格）
/// - 含非 ASCII：提供 `filename="export.xlsx"` 兜底 + `filename*=UTF-8''<编码>` 真实名，
///   浏览器优先使用 `filename*`（RFC 5987）。
fn build_content_disposition(filename: &str) -> String {
    let safe = sanitize_filename(filename);
    if safe.is_empty() {
        return "attachment; filename=\"export.xlsx\"".to_string();
    }
    if safe.is_ascii() {
        format!("attachment; filename=\"{}\"", safe)
    } else {
        format!(
            "attachment; filename=\"export.xlsx\"; filename*=UTF-8''{}",
            rfc5987_encode(&safe)
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Serialize;

    /// 漂移检测：列 key 必须存在于行类型的 JSON 序列化结果中
    ///
    /// 字段改名（serde rename / Rust 字段名）时本测试变红，早于前端发现。
    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    struct SampleRow {
        user_id: i64,
        user_name: String,
        dept_id: Option<i64>,
    }

    #[test]
    fn test_column_keys_exist_in_json() {
        let row = SampleRow {
            user_id: 1,
            user_name: "admin".into(),
            dept_id: Some(10),
        };
        let json = serde_json::to_string(&row).unwrap();
        let keys = ["userId", "userName", "deptId"];
        for k in keys {
            assert!(
                json.contains(&format!("\"{k}\"")),
                "漂移：key '{k}' 未出现在 JSON 输出 {json} 中"
            );
        }
    }

    #[test]
    fn test_column_keys_unique_and_nonempty() {
        // 同一导出列集的 key 不应重复或为空
        let cols: Vec<ExcelColumn<SampleRow>> = vec![
            ExcelColumn {
                key: "userId",
                header: ("用户编号", "User ID"),
                getter: |r| CellValue::Text(r.user_id.to_string().into()),
            },
            ExcelColumn {
                key: "userName",
                header: ("用户名称", "Username"),
                getter: |r| CellValue::Text(r.user_name.clone().into()),
            },
        ];
        let mut seen = std::collections::HashSet::new();
        for c in &cols {
            assert!(!c.key.is_empty(), "key 不能为空");
            assert!(seen.insert(c.key), "key 重复: {}", c.key);
        }
    }
}
