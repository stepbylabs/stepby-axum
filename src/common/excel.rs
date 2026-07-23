// axum-backend/src/common/excel.rs
//! Excel 导出工具
//!
//! 基于 rust_xlsxwriter 生成 .xlsx 二进制流，返回 axum::response::Response
//! 对齐 ruoyi-vue3-ts 前端 proxy.download() 的 blob 期望

use std::borrow::Cow;

use axum::http::{header, HeaderValue, StatusCode};
use axum::response::Response;
use rust_xlsxwriter::{Format, Workbook};

use crate::common::error::AppError;

/// Excel 列定义
///
/// R5-TYPE-17：getter 返回 `Cow<'a, str>` 而非 `String`，避免对已有 `&str` 字段
/// 强制分配。返回借用字符串时零拷贝，返回计算值时使用 `Cow::Owned`。
pub struct ExcelColumn<T> {
    /// 表头名称
    pub header: &'static str,
    /// 字段提取函数（从行数据提取字符串值，可借用或拥有）
    pub getter: for<'a> fn(&'a T) -> Cow<'a, str>,
}

/// 通用 Excel 导出
///
/// - `sheet_name`：工作表名称
/// - `filename`：下载文件名（不含扩展名）
/// - `columns`：列定义
/// - `rows`：数据行
///
/// 返回 `Response`，Content-Type 为 xlsx，Content-Disposition 为 attachment
pub fn export_to_excel<T>(
    sheet_name: &str,
    filename: &str,
    columns: &[ExcelColumn<T>],
    rows: &[T],
) -> Result<Response, AppError> {
    export_to_excel_with_fields(sheet_name, filename, columns, rows, None)
}

/// 通用 Excel 导出（支持字段选择）
///
/// - `fields`：可选字段列表（按表头名称匹配）。为 None 或空时导出全部列；
///   否则仅导出表头在 fields 列表中的列，顺序以 columns 原顺序为准
pub fn export_to_excel_with_fields<T>(
    sheet_name: &str,
    filename: &str,
    columns: &[ExcelColumn<T>],
    rows: &[T],
    fields: Option<&[String]>,
) -> Result<Response, AppError> {
    // 根据 fields 过滤列索引（保持原 columns 顺序）
    let selected_indices: Vec<usize> = match fields {
        Some(list) if !list.is_empty() => {
            columns
                .iter()
                .enumerate()
                .filter_map(|(i, c)| {
                    if list.iter().any(|f| f == c.header) {
                        Some(i)
                    } else {
                        None
                    }
                })
                .collect()
        }
        _ => (0..columns.len()).collect(),
    };

    if selected_indices.is_empty() {
        return Err(AppError::bad_request("导出字段列表为空或无匹配字段"));
    }

    let mut workbook = Workbook::new();
    let worksheet = workbook
        .add_worksheet()
        .set_name(sheet_name)
        .map_err(|e| AppError::internal(&format!("创建工作表失败: {}", e)))?;

    // 表头格式
    let header_format = Format::new().set_bold();

    // 写入表头（按 selected_indices 顺序）
    for (out_col, &col_idx) in selected_indices.iter().enumerate() {
        let col = &columns[col_idx];
        worksheet
            .write_string_with_format(0, out_col as u16, col.header, &header_format)
            .map_err(|e| AppError::internal(&format!("写入表头失败: {}", e)))?;
    }

    // 写入数据行
    for (row_idx, row) in rows.iter().enumerate() {
        for (out_col, &col_idx) in selected_indices.iter().enumerate() {
            let col = &columns[col_idx];
            let value = (col.getter)(row);
            worksheet
                .write_string((row_idx + 1) as u32, out_col as u16, value.as_ref())
                .map_err(|e| AppError::internal(&format!("写入数据失败: {}", e)))?;
        }
    }

    // 生成二进制数据
    let xlsx_data = workbook
        .save_to_buffer()
        .map_err(|e| AppError::internal(&format!("生成 Excel 失败: {}", e)))?;

    // 构建响应
    let content_disposition = format!("attachment; filename={}.xlsx", filename);
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

    Ok(response)
}
