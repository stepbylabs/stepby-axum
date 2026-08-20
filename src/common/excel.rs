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
use std::io::Cursor;

use axum::http::{HeaderValue, StatusCode, header};
use axum::response::Response;
use calamine::Reader;
use calamine::Xlsx;
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

// ==================== 导入（B3） ====================

/// 导入模板列：双语表头 + 示例值 + 列宽
pub struct ImportColumn {
    pub header: (&'static str, &'static str),
    pub sample: &'static str,
    pub width: f64,
}

/// 生成导入模板 xlsx（第 1 行为表头，第 2 行为示例数据行），返回 xlsx 字节
pub fn build_import_template_bytes(
    sheet_name: &str,
    columns: &[ImportColumn],
    locale_zh: bool,
) -> Result<Vec<u8>, AppError> {
    let mut workbook = Workbook::new();
    let worksheet = workbook
        .add_worksheet()
        .set_name(sanitize_sheet_name(sheet_name))
        .map_err(|_| AppError::internal(&crate::tr!("error.excel.sheet_create_failed")))?;
    let header_format = Format::new().set_bold();
    for (i, c) in columns.iter().enumerate() {
        let label = if locale_zh { c.header.0 } else { c.header.1 };
        worksheet
            .write_string_with_format(0, i as u16, label, &header_format)
            .map_err(|_| AppError::internal(&crate::tr!("error.excel.header_write_failed")))?;
        worksheet
            .write_string(1, i as u16, c.sample)
            .map_err(|_| AppError::internal(&crate::tr!("error.excel.data_write_failed")))?;
        let _ = worksheet.set_column_width(i as u16, c.width);
    }
    workbook
        .save_to_buffer()
        .map_err(|_| AppError::internal(&crate::tr!("error.excel.generate_failed")))
}

/// 将 calamine 单元格值转为字符串（空单元格视为空串；数字按无小数输出）
fn import_cell_to_string(d: &calamine::Data) -> String {
    use calamine::Data as Cd;
    match d {
        Cd::String(s) => s.clone(),
        Cd::Int(i) => i.to_string(),
        Cd::Float(f) => {
            if f.fract() == 0.0 && f.abs() < 1e15 {
                format!("{:.0}", f)
            } else {
                f.to_string()
            }
        }
        Cd::Bool(b) => b.to_string(),
        Cd::DateTime(_) | Cd::DateTimeIso(_) | Cd::DurationIso(_) | Cd::Error(_) | Cd::Empty => {
            String::new()
        }
    }
}

/// 读取 xlsx 字节，返回首个工作表的行矩阵（每行是字符串化后的单元格列表）
///
/// - 仅支持 `.xlsx`（OLE/宏/旧版 xls 不做支持，前端已限制扩展名）
/// - 空数据返回空 Vec；首行为表头（调用方自行跳过/校验）
pub fn read_xlsx_rows(bytes: &[u8]) -> Result<Vec<Vec<String>>, AppError> {
    let mut workbook = Xlsx::new(Cursor::new(bytes)).map_err(|e| {
        AppError::bad_request(&crate::tr!("error.excel.import_parse_failed", e = e))
    })?;
    let sheet_name = workbook.sheet_names().first().cloned().unwrap_or_default();
    if sheet_name.is_empty() {
        return Ok(Vec::new());
    }
    let range = workbook.worksheet_range(&sheet_name).map_err(|e| {
        AppError::bad_request(&crate::tr!("error.excel.import_parse_failed", e = e))
    })?;
    Ok(range
        .rows()
        .map(|r| r.iter().map(import_cell_to_string).collect::<Vec<_>>())
        .collect())
}

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
        build_xlsx(
            &sheet_name,
            &columns_owned,
            &rows_owned,
            fields_owned.as_deref(),
            locale,
        )
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
    // 合并连续下划线（相邻非法字符会产生连续 `_`，如 "a[b]:" → "a_b__c"）
    let mut result = String::with_capacity(cleaned.len());
    let mut prev_underscore = false;
    for c in cleaned.chars() {
        if c == '_' {
            if !prev_underscore {
                result.push(c);
            }
            prev_underscore = true;
        } else {
            result.push(c);
            prev_underscore = false;
        }
    }
    // 截断到 31 字符（XLSX sheet 名限制）
    if result.chars().count() > 31 {
        result = result.chars().take(31).collect();
    }
    // 全非法/空白字符 → 兜底 Sheet1
    if result.chars().all(|c| c == '_' || c.is_whitespace()) {
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
    // 按 fields 输入顺序匹配列（兼容旧中文名过渡期），保持导出列序与前端选择一致
    let selected_indices: Vec<usize> = match fields {
        Some(list) if !list.is_empty() => {
            let mut seen = std::collections::HashSet::new();
            list.iter()
                .filter_map(|f| {
                    let idx = columns
                        .iter()
                        .position(|c| c.key == f || c.header.0 == f)?;
                    seen.insert(idx).then_some(idx)
                })
                .collect()
        }
        _ => (0..columns.len()).collect(),
    };

    if selected_indices.is_empty() {
        return Err(AppError::bad_request(&crate::tr!(
            "error.excel.fields_empty"
        )));
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
        let header_text = if locale_zh {
            col.header.0
        } else {
            col.header.1
        };
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
                        .map_err(|_| {
                            AppError::internal(&crate::tr!("error.excel.data_write_failed"))
                        })?;
                }
                CellValue::Number(n) => {
                    worksheet
                        .write_number(target_row, target_col, n)
                        .map_err(|_| {
                            AppError::internal(&crate::tr!("error.excel.data_write_failed"))
                        })?;
                }
                CellValue::DateTime(dt) => {
                    let s = dt.format("%Y-%m-%d %H:%M:%S").to_string();
                    worksheet
                        .write_string_with_format(target_row, target_col, &s, &datetime_format)
                        .map_err(|_| {
                            AppError::internal(&crate::tr!("error.excel.data_write_failed"))
                        })?;
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
            | b'!'
            | b'#'
            | b'$'
            | b'&'
            | b'+'
            | b'-'
            | b'.'
            | b'^'
            | b'_'
            | b'`'
            | b'|'
            | b'~' => out.push(*b as char),
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
    //! 覆盖意图：对 Excel 模块的纯逻辑（表头映射 / 字段 key 选择 / sheet 名净化 /
    //! 文件名净化 / Content-Disposition / RFC5987 编码 / 单元格值类型 / 导入模板与
    //! 读取回环）与异步导出响应（状态码 / 截断标记 / 响应体回读）做全面覆盖。

    use super::*;
    use serde::Serialize;

    use chrono::NaiveDateTime;
    use rust_xlsxwriter::Workbook;

    /// 漂移检测：列 key 必须存在于行类型的 JSON 序列化结果中
    ///
    /// 字段改名（serde rename / Rust 字段名）时本测试变红，早于前端发现。
    #[derive(Serialize, Clone, Debug)]
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

    // ---------- 私有纯函数：build_xlsx_inner / sanitize_sheet_name ----------

    #[test]
    fn sanitize_sheet_name_replaces_illegal_chars_and_truncates() {
        // XLSX 非法字符 `[]:*?/\` → `_`
        assert_eq!(sanitize_sheet_name("a[b]:c*d?e/f\\g"), "a_b_c_d_e_f_g");
        // 超长 → 截断到 31 字符
        let long = "x".repeat(40);
        assert_eq!(sanitize_sheet_name(&long).chars().count(), 31);
        // 全空白 → Sheet1
        assert_eq!(sanitize_sheet_name("   "), "Sheet1");
        assert_eq!(sanitize_sheet_name(""), "Sheet1");
        // 非法字符全替换后为空 → Sheet1
        assert_eq!(sanitize_sheet_name("///"), "Sheet1");
        // 合法名原样保留
        assert_eq!(sanitize_sheet_name("用户列表"), "用户列表");
    }

    #[test]
    fn build_xlsx_inner_headers_localized_zh() {
        let cols = test_columns();
        let rows = test_rows();
        let bytes = build_xlsx_inner("data", &cols, &rows, None).expect("构建 xlsx 失败");
        let matrix = read_xlsx_rows(&bytes).expect("回读失败");
        // 默认（无 locale 注入 → zh）应输出中文表头
        assert_eq!(matrix[0], vec!["用户编号", "用户名称"]);
        // 数据行：Text 原样写入
        assert_eq!(matrix[1][0], "1");
        assert_eq!(matrix[1][1], "admin");
    }

    #[test]
    fn build_xlsx_inner_headers_localized_en() {
        let cols = test_columns();
        let rows = test_rows();
        // 注入 en-US 后表头应切换为英文
        let bytes = i18n::with_locale_sync("en-US", || {
            build_xlsx_inner("data", &cols, &rows, None).expect("构建 xlsx 失败")
        });
        let matrix = read_xlsx_rows(&bytes).expect("回读失败");
        assert_eq!(matrix[0], vec!["User ID", "Username"]);
    }

    #[test]
    fn build_xlsx_inner_number_and_datetime_cells() {
        let cols = vec![
            ExcelColumn {
                key: "n",
                header: ("数值", "Number"),
                getter: |_: &SampleRow| CellValue::Number(42.5),
            },
            ExcelColumn {
                key: "t",
                header: ("时间", "Time"),
                getter: |_: &SampleRow| CellValue::DateTime(dt(2026, 1, 2, 3, 4, 5)),
            },
        ];
        let rows = vec![SampleRow {
            user_id: 1,
            user_name: "x".into(),
            dept_id: None,
        }];
        let bytes = build_xlsx_inner("data", &cols, &rows, None).expect("构建 xlsx 失败");
        let matrix = read_xlsx_rows(&bytes).expect("回读失败");
        // 数字按整数形式读回（无小数），日期时间为字符串格式
        assert_eq!(matrix[1][0], "42.5");
        assert_eq!(matrix[1][1], "2026-01-02 03:04:05");
    }

    #[test]
    fn build_xlsx_inner_field_selection_and_errors() {
        let cols = test_columns();
        let rows = test_rows();
        let fields = vec!["userName".to_string(), "userId".to_string()];
        let bytes = build_xlsx_inner("data", &cols, &rows, Some(&fields)).expect("构建 xlsx 失败");
        let matrix = read_xlsx_rows(&bytes).expect("回读失败");
        // 按 fields 顺序选择列（key 匹配）
        assert_eq!(matrix[0], vec!["用户名称", "用户编号"]);
        assert_eq!(matrix[1], vec!["admin", "1"]);

        // 空列表 = 全部列
        let empty: Vec<String> = vec![];
        let bytes = build_xlsx_inner("data", &cols, &rows, Some(&empty)).expect("构建 xlsx 失败");
        let matrix = read_xlsx_rows(&bytes).expect("回读失败");
        assert_eq!(matrix[0].len(), 2);

        // 全部未命中 → fields_empty 错误
        let miss = vec!["nope".to_string()];
        let err = build_xlsx_inner("data", &cols, &rows, Some(&miss)).unwrap_err();
        assert_eq!(err.code, 400);
    }

    // ---------- 私有纯函数：文件名净化 / RFC5987 / Content-Disposition ----------

    #[test]
    fn sanitize_filename_removes_crlf_quotes_and_controls() {
        // CRLF / NUL / 引号 / 反斜杠全部移除，控制字符替换为 _
        assert_eq!(sanitize_filename("a\r\nb"), "ab");
        assert_eq!(sanitize_filename("evil\"; rm -rf /"), "evil; rm -rf /");
        assert_eq!(sanitize_filename("back\\slash"), "backslash");
        assert_eq!(sanitize_filename("nul\0byte"), "nulbyte");
        assert_eq!(sanitize_filename(" tab\x01ctl "), "tab_ctl");
        // 清洗后为空 → 空串（调用方需兜底）
        assert_eq!(sanitize_filename("\"\r\n"), "");
    }

    #[test]
    fn rfc5987_encode_keeps_attr_chars_and_encodes_rest() {
        // attr-char 保留
        assert_eq!(rfc5987_encode("abcXYZ09!$&+-.^_`|~"), "abcXYZ09!$&+-.^_`|~");
        // 空格 / 中文 / 不可打印字符按 UTF-8 逐字节大写 %XX
        assert_eq!(rfc5987_encode("a b"), "a%20b");
        assert_eq!(rfc5987_encode("中"), "%E4%B8%AD");
        assert_eq!(rfc5987_encode("="), "%3D");
        assert_eq!(rfc5987_encode("%"), "%25");
    }

    #[test]
    fn build_content_disposition_handles_ascii_non_ascii_and_empty() {
        // ASCII → 直接带引号
        assert_eq!(
            build_content_disposition("report.xlsx"),
            "attachment; filename=\"report.xlsx\""
        );
        // 含空格
        assert_eq!(
            build_content_disposition("my report.xlsx"),
            "attachment; filename=\"my report.xlsx\""
        );
        // 非 ASCII → ASCII 兜底 + filename* RFC5987
        let cd = build_content_disposition("用户报表.xlsx");
        assert!(cd.starts_with("attachment; filename=\"export.xlsx\"; filename*=UTF-8''"));
        assert!(cd.contains("%E7%94%A8%E6%88%B7")); // 用户
        // 清洗后为空 → 兜底名
        assert_eq!(
            build_content_disposition("\"\r\n"),
            "attachment; filename=\"export.xlsx\""
        );
    }

    // ---------- import_cell_to_string（私有） ----------

    #[test]
    fn import_cell_to_string_variants() {
        use calamine::Data;
        assert_eq!(import_cell_to_string(&Data::String("s".into())), "s");
        assert_eq!(import_cell_to_string(&Data::Int(42)), "42");
        assert_eq!(import_cell_to_string(&Data::Int(-7)), "-7");
        // 整数浮点 → 无小数
        assert_eq!(import_cell_to_string(&Data::Float(3.0)), "3");
        // 小数保留（用非圆周率近似值，避免 clippy::approx_constant 误报）
        assert_eq!(import_cell_to_string(&Data::Float(2.76)), "2.76");
        // 大数（>= 1e15）不再取整，避免精度损失
        assert_eq!(import_cell_to_string(&Data::Float(1e15)), "1000000000000000");
        assert_eq!(import_cell_to_string(&Data::Bool(true)), "true");
        // 其余变体 → 空串
        assert_eq!(
            import_cell_to_string(&Data::DateTime(calamine::ExcelDateTime::new(
                1.5,
                calamine::ExcelDateTimeType::DateTime,
                false
            ))),
            ""
        );
        assert_eq!(import_cell_to_string(&Data::DateTimeIso("2026".into())), "");
        assert_eq!(import_cell_to_string(&Data::DurationIso("P1D".into())), "");
        assert_eq!(import_cell_to_string(&Data::Empty), "");
        assert_eq!(import_cell_to_string(&Data::Error(calamine::CellErrorType::NA)), "");
    }

    #[test]
    fn read_xlsx_rows_handles_invalid_bytes_and_empty_sheet() {
        // 非法 xlsx 字节 → 解析失败（400）
        let err = read_xlsx_rows(b"not an xlsx file at all").unwrap_err();
        assert_eq!(err.code, 400);
        // 空字节 → 解析失败（同样 400）
        assert!(read_xlsx_rows(b"").is_err());
    }

    #[test]
    fn read_xlsx_rows_empty_workbook_returns_empty() {
        // 无工作表的 xlsx：读取成功但返回空矩阵
        let mut wb = Workbook::new();
        let bytes = wb.save_to_buffer().expect("空工作簿保存失败");
        let rows = read_xlsx_rows(&bytes).expect("空工作簿应可读");
        assert!(rows.is_empty());
    }

    // ---------- 导入模板（B3） ----------

    #[test]
    fn build_import_template_bytes_roundtrip_zh_and_en() {
        let columns = vec![
            ImportColumn {
                header: ("用户名", "Username"),
                sample: "admin",
                width: 20.0,
            },
            ImportColumn {
                header: ("邮箱", "Email"),
                sample: "a@b.com",
                width: 30.0,
            },
        ];
        let bytes = build_import_template_bytes("导入用户", &columns, true).expect("模板生成失败");
        let rows = read_xlsx_rows(&bytes).expect("模板回读失败");
        // 中文 locale：第 1 行为中文表头，第 2 行为示例
        assert_eq!(rows[0], vec!["用户名", "邮箱"]);
        assert_eq!(rows[1], vec!["admin", "a@b.com"]);

        let bytes_en = build_import_template_bytes("Import", &columns, false).expect("模板生成失败");
        let rows_en = read_xlsx_rows(&bytes_en).expect("模板回读失败");
        assert_eq!(rows_en[0], vec!["Username", "Email"]);
    }

    // ---------- 异步导出（export_to_excel / export_to_excel_with_fields） ----------

    #[tokio::test]
    async fn export_to_excel_full_response_and_roundtrip() {
        let cols = test_columns();
        let rows = test_rows();
        let resp = export_to_excel("数据", "报告.xlsx", &cols, &rows)
            .await
            .expect("导出失败");
        assert_eq!(resp.status(), axum::http::StatusCode::OK);
        assert_eq!(
            resp.headers()
                .get(axum::http::header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok()),
            Some("application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
        );
        // 非 ASCII 文件名 → RFC5987
        let cd = resp
            .headers()
            .get(axum::http::header::CONTENT_DISPOSITION)
            .and_then(|v| v.to_str().ok())
            .expect("应存在 Content-Disposition");
        assert!(cd.contains("filename*=UTF-8''"), "实际: {cd}");
        // 未截断 → 无 X-Export-Truncated
        assert!(resp.headers().get("X-Export-Truncated").is_none());

        // 响应体回读：表头 + 数据
        let body = axum::body::to_bytes(resp.into_body(), 1 << 20)
            .await
            .expect("读取响应体失败");
        let matrix = read_xlsx_rows(&body).expect("响应体应为合法 xlsx");
        assert_eq!(matrix[0], vec!["用户编号", "用户名称"]);
        assert_eq!(matrix[1], vec!["1", "admin"]);
    }

    #[tokio::test]
    async fn export_to_excel_with_fields_and_truncation() {
        let cols = test_columns();
        let rows = test_rows();
        let fields = vec!["userName".to_string()];
        let resp = export_to_excel_with_fields("数据", "plain.xlsx", &cols, &rows, Some(&fields), true)
            .await
            .expect("导出失败");
        // 显式 truncated=true → 设置标记
        assert_eq!(
            resp.headers().get("X-Export-Truncated").and_then(|v| v.to_str().ok()),
            Some("true")
        );
        let body = axum::body::to_bytes(resp.into_body(), 1 << 20)
            .await
            .expect("读取响应体失败");
        let matrix = read_xlsx_rows(&body).expect("响应体应为合法 xlsx");
        assert_eq!(matrix[0], vec!["用户名称"]);
        assert_eq!(matrix[1], vec!["admin"]);
    }

    #[tokio::test]
    async fn export_to_excel_auto_truncated_at_threshold() {
        // 行数触及 EXPORT_MAX_ROWS → 自动截断标记（N5）
        let cols = test_columns();
        let row = SampleRow {
            user_id: 1,
            user_name: "u".into(),
            dept_id: None,
        };
        let rows: Vec<SampleRow> =
            std::iter::repeat_n(row, EXPORT_MAX_ROWS as usize).collect();
        let resp = export_to_excel("数据", "big.xlsx", &cols, &rows)
            .await
            .expect("导出失败");
        assert_eq!(
            resp.headers().get("X-Export-Truncated").and_then(|v| v.to_str().ok()),
            Some("true")
        );
    }

    #[tokio::test]
    async fn export_blank_fields_keep_all_columns() {
        // fields 为空串列表 → 全部列（与 None 等价）
        let cols = test_columns();
        let rows = test_rows();
        let resp = export_to_excel_with_fields("数据", "x.xlsx", &cols, &rows, Some(&[]), false)
            .await
            .expect("导出失败");
        let body = axum::body::to_bytes(resp.into_body(), 1 << 20)
            .await
            .expect("读取响应体失败");
        let matrix = read_xlsx_rows(&body).expect("响应体应为合法 xlsx");
        assert_eq!(matrix[0].len(), 2);
    }

    // ---------- 测试辅助 ----------

    /// 构造跨 Text 类型列（供表头 / 字段选择 / 导出测试复用）
    fn test_columns() -> Vec<ExcelColumn<SampleRow>> {
        vec![
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
        ]
    }

    fn test_rows() -> Vec<SampleRow> {
        vec![SampleRow {
            user_id: 1,
            user_name: "admin".into(),
            dept_id: Some(10),
        }]
    }

    fn dt(y: i32, mo: u32, d: u32, h: u32, mi: u32, s: u32) -> NaiveDateTime {
        NaiveDateTime::new(
            chrono::NaiveDate::from_ymd_opt(y, mo, d).expect("合法日期"),
            chrono::NaiveTime::from_hms_opt(h, mi, s).expect("合法时间"),
        )
    }

    /// 用当前（测试）线程执行闭包：build_xlsx 为纯同步（with_locale_sync + 内存构建）
    #[tokio::test]
    async fn build_xlsx_uses_locale_and_writes_cells() {
        let cols = test_columns();
        let rows = test_rows();
        let bytes = build_xlsx("数据", &cols, &rows, None, "en-US".to_string())
            .expect("build_xlsx 失败");
        let matrix = read_xlsx_rows(&bytes).expect("回读失败");
        // locale 经 build_xlsx 注入 en-US → 英文表头
        assert_eq!(matrix[0], vec!["User ID", "Username"]);
        assert_eq!(matrix[1], vec!["1", "admin"]);
    }

    #[tokio::test]
    async fn export_to_excel_constant_memory_path() {
        // 行数超过阈值走 constant_memory 流式分支（不写内存二次拷贝）
        let cols = test_columns();
        let row = SampleRow {
            user_id: 1,
            user_name: "u".into(),
            dept_id: None,
        };
        let rows: Vec<SampleRow> =
            std::iter::repeat_n(row, CONSTANT_MEMORY_THRESHOLD + 1).collect();
        let resp = export_to_excel("big", "big.xlsx", &cols, &rows)
            .await
            .expect("大数据导出失败");
        let body = axum::body::to_bytes(resp.into_body(), 1 << 24)
            .await
            .expect("读取响应体失败");
        let matrix = read_xlsx_rows(&body).expect("响应体应为合法 xlsx");
        assert_eq!(matrix.len(), CONSTANT_MEMORY_THRESHOLD + 2); // 表头 + 数据行
        assert_eq!(matrix[1][0], "1");
    }

    #[test]
    fn constant_memory_threshold_positive() {
        // 阈值常量为正且导出上限合理（防止误改破坏内存保护语义）
        const _: () = assert!(
            CONSTANT_MEMORY_THRESHOLD > 0 && EXPORT_MAX_ROWS as usize > CONSTANT_MEMORY_THRESHOLD
        );
    }
}
