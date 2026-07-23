//! 代码生成模块 Service 层
//!
//! 职责：
//! - 代码生成业务表 CRUD（分页查询、详情、新增、修改、批量删除）
//! - 导入表（读取数据库元数据 → 生成 gen_table + gen_table_column 记录）
//! - 预览代码（Tera 模板渲染）
//! - 生成代码（ZIP 打包下载）
//! - 同步数据库（从数据库更新表字段信息）
//!
//! 模板引擎：Tera（运行时模板，支持从目录加载）
//! 模板目录：templates/gen/

use std::collections::HashMap;
use std::error::Error as StdError;

use chrono::NaiveDateTime;
use sea_orm::{DatabaseConnection, ConnectionTrait, Set};
use sea_orm::sea_query::{Alias, ColumnDef, Index, Table};
use serde::{Deserialize, Serialize};
use tera::{Kwargs, State, Tera, TeraResult, Value};
use utoipa::{IntoParams, ToSchema};
use validator::Validate;

use crate::common::error::ServiceError;
use crate::common::page::{default_page_num, default_page_size, PageDomain};
use crate::entity::gen_table::{ActiveModel as GenTableActiveModel, Model as GenTableModel};
use crate::entity::gen_table_column::{ActiveModel as GenTableColumnActiveModel, Model as GenTableColumnModel};
use crate::repository::gen_table::{DbColumnInfo, GenTableRepository};

// ==================== DTO ====================

/// 代码生成业务表分页查询 DTO
#[derive(Debug, Clone, Deserialize, IntoParams)]
#[serde(rename_all = "camelCase")]
pub struct GenTableQueryDto {
    #[serde(default = "default_page_num")]
    pub page_num: u64,
    #[serde(default = "default_page_size")]
    pub page_size: u64,
    pub table_name: Option<String>,
    pub table_comment: Option<String>,
    #[serde(alias = "params[beginTime]", default)]
    pub begin_time: Option<String>,
    #[serde(alias = "params[endTime]", default)]
    pub end_time: Option<String>,
}

impl From<&GenTableQueryDto> for PageDomain {
    fn from(dto: &GenTableQueryDto) -> Self {
        PageDomain {
            page_num: dto.page_num,
            page_size: dto.page_size,
            order_by_column: None,
            is_asc: None,
        }
    }
}

/// 数据库表分页查询 DTO（导入表用）
#[derive(Debug, Clone, Deserialize, IntoParams)]
#[serde(rename_all = "camelCase")]
pub struct DbTableQueryDto {
    #[serde(default = "default_page_num")]
    pub page_num: u64,
    #[serde(default = "default_page_size")]
    pub page_size: u64,
    pub table_name: Option<String>,
    pub table_comment: Option<String>,
}

/// 修改代码生成业务表 DTO
#[derive(Debug, Deserialize, Validate, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct GenTableEditDto {
    pub table_id: i64,
    pub table_name: String,
    pub table_comment: Option<String>,
    pub class_name: Option<String>,
    pub function_name: Option<String>,
    pub function_author: Option<String>,
    pub tpl_category: Option<String>,
    pub tpl_web_type: Option<String>,
    pub package_name: Option<String>,
    pub module_name: Option<String>,
    pub business_name: Option<String>,
    pub gen_type: Option<String>,
    pub gen_path: Option<String>,
    pub options: Option<String>,
    pub remark: Option<String>,
    pub sub_table_name: Option<String>,
    pub sub_table_fk_name: Option<String>,
    /// 列信息（修改时一起提交）
    pub columns: Option<Vec<GenTableColumnEditDto>>,
}

/// 修改代码生成列 DTO
#[derive(Debug, Deserialize, Validate, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct GenTableColumnEditDto {
    pub column_id: Option<i64>,
    pub column_name: Option<String>,
    pub column_comment: Option<String>,
    pub column_type: Option<String>,
    pub java_type: Option<String>,
    pub java_field: Option<String>,
    pub is_pk: Option<String>,
    pub is_increment: Option<String>,
    pub is_required: Option<String>,
    pub is_insert: Option<String>,
    pub is_edit: Option<String>,
    pub is_list: Option<String>,
    pub is_query: Option<String>,
    pub query_type: Option<String>,
    pub html_type: Option<String>,
    pub dict_type: Option<String>,
    pub sort: Option<i32>,
}

/// 代码生成详情响应
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GenTableInfoVo {
    pub info: GenTableModel,
    pub rows: Vec<GenTableColumnModel>,
    pub tables: Vec<GenTableModel>,
}

// ==================== 结构化建表 DTO（方案 A：消除 SQL 注入） ====================

/// 支持的列类型枚举
///
/// 仅允许常见 DDL 类型，由后端映射到各数据库方言：
/// - VARCHAR/CHAR → string_len(n) / char()
/// - TEXT/LONGTEXT → text()（SQLite/PG/MySQL 均支持）
/// - INT/BIGINT/SMALLINT/TINYINT → integer()/big_integer()/small_integer()/tiny_integer()
/// - DECIMAL/DOUBLE → decimal_len_len_unsigned()/double()
/// - DATE/DATETIME/TIMESTAMP → date()/date_time()/date_time()
/// - BOOLEAN → boolean()
#[derive(Debug, Clone, Deserialize, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub enum ColumnDataType {
    /// 变长字符串（需指定长度，默认 255）
    Varchar,
    /// 定长字符（需指定长度，默认 1）
    Char,
    /// 文本（无长度）
    Text,
    /// 长文本（MySQL 方言 LONGTEXT，SQLite/PG 退化为 TEXT）
    LongText,
    /// 32 位整数
    Int,
    /// 64 位整数
    Bigint,
    /// 16 位整数
    Smallint,
    /// 8 位整数（MySQL 方言 TINYINT，SQLite/PG 退化为 SMALLINT）
    Tinyint,
    /// 定点小数（需指定精度和小数位）
    Decimal,
    /// 浮点数
    Double,
    /// 日期（YYYY-MM-DD）
    Date,
    /// 日期时间（YYYY-MM-DD HH:MM:SS）
    Datetime,
    /// 时间戳
    Timestamp,
    /// 布尔值
    Boolean,
}

impl ColumnDataType {
    /// 是否需要长度参数
    fn needs_length(&self) -> bool {
        matches!(self, Self::Varchar | Self::Char | Self::Decimal)
    }

    /// 是否需要小数位参数（仅 DECIMAL）
    fn needs_precision(&self) -> bool {
        matches!(self, Self::Decimal)
    }
}

/// 结构化建表列定义 DTO
#[derive(Debug, Clone, Deserialize, Serialize, Validate, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct CreateTableColumnDto {
    /// 列名（必填，白名单：字母/数字/下划线，长度 1-64）
    #[validate(length(min = 1, max = 64, message = "列名长度必须在1-64之间"))]
    pub column_name: String,
    /// 列类型（必填）
    pub data_type: ColumnDataType,
    /// 长度（VARCHAR/CHAR 必填，DECIMAL 必填表示精度）
    #[validate(range(min = 1, max = 65535, message = "长度必须在1-65535之间"))]
    pub length: Option<u32>,
    /// 小数位（仅 DECIMAL，必须 < length）
    #[validate(range(min = 0, max = 30, message = "小数位必须在0-30之间"))]
    pub precision: Option<u32>,
    /// 是否主键
    #[serde(default)]
    pub is_primary_key: bool,
    /// 是否自增（仅整数类型，且必须为主键）
    #[serde(default)]
    pub is_auto_increment: bool,
    /// 是否非空
    #[serde(default)]
    pub is_not_null: bool,
    /// 是否唯一
    #[serde(default)]
    pub is_unique: bool,
    /// 默认值（字符串形式，由后端按类型校验）
    pub default_value: Option<String>,
    /// 列注释
    pub column_comment: Option<String>,
}

/// 结构化建表 DTO（方案 A：消除 SQL 注入）
///
/// 通过结构化字段描述表结构，由后端用 sea-query 声明式构造 DDL，
/// 自动适配 PostgreSQL/MySQL/SQLite 方言，完全消除 SQL 注入风险。
#[derive(Debug, Clone, Deserialize, Validate, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct CreateTableDto {
    /// 表名（必填，白名单：字母/数字/下划线，长度 1-64，必须以字母开头）
    #[validate(length(min = 1, max = 64, message = "表名长度必须在1-64之间"))]
    pub table_name: String,
    /// 表注释
    pub table_comment: Option<String>,
    /// 列定义列表（至少 1 列）
    #[validate(length(min = 1, message = "至少需要定义1列"))]
    pub columns: Vec<CreateTableColumnDto>,
    /// 是否同时导入到 gen_table（代码生成业务表）
    #[serde(default = "default_import_to_gen")]
    pub import_to_gen: bool,
}

fn default_import_to_gen() -> bool {
    true
}

/// 结构化建表响应
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct CreateTableResultVo {
    /// 表名
    pub table_name: String,
    /// 生成的 SQL（用于日志记录和调试，不返回给前端）
    #[serde(skip_serializing)]
    pub generated_sql: String,
    /// 是否已导入到 gen_table
    pub imported_to_gen: bool,
    /// 生成的 gen_table_id（如果 import_to_gen=true）
    pub table_id: Option<i64>,
}

/// 预览代码响应（文件名 → 代码内容）
pub type PreviewCodeVo = HashMap<String, String>;

// ==================== 辅助函数 ====================

/// 解析时间字符串
fn parse_time(s: &str) -> Result<NaiveDateTime, ServiceError> {
    NaiveDateTime::parse_from_str(s, "%Y-%m-%d")
        .map_err(|_| ServiceError::bad_request(&format!("时间格式不正确: {}", s)))
}

/// 将数据库列类型映射为 Rust 类型
///
/// 参考 sea-orm 的类型映射规则
fn column_type_to_rust_type(column_type: &str) -> String {
    let ct = column_type.to_uppercase();
    if ct.contains("BIGINT") || ct.contains("INT") || ct.contains("INTEGER") {
        "i64".to_string()
    } else if ct.contains("TINYINT") {
        "i8".to_string()
    } else if ct.contains("SMALLINT") {
        "i16".to_string()
    } else if ct.contains("FLOAT") {
        "f32".to_string()
    } else if ct.contains("DOUBLE") || ct.contains("DECIMAL") || ct.contains("NUMERIC") {
        "f64".to_string()
    } else if ct.contains("BOOL") {
        "bool".to_string()
    } else if ct.contains("DATE") || ct.contains("TIME") || ct.contains("DATETIME") || ct.contains("TIMESTAMP") {
        "Option<chrono::NaiveDateTime>".to_string()
    } else {
        // 默认 String 类型（VARCHAR/TEXT/CHAR 等）
        "String".to_string()
    }
}

/// 将数据库列名（snake_case）转换为 Rust 字段名（保持 snake_case）
/// 若列名是数据库关键字则添加 raw_ 前缀
fn column_name_to_rust_field(column_name: &str) -> String {
    let reserved = ["type", "ref", "match", "mod", "move", "as", "fn", "if", "in", "let", "pub", "use", "where", "self", "super", "crate", "extern"];
    let name = column_name.to_lowercase();
    if reserved.contains(&name.as_str()) {
        format!("raw_{}", name)
    } else {
        name
    }
}

/// 将表名（snake_case）转换为类名（PascalCase）
fn table_name_to_class_name(table_name: &str) -> String {
    table_name
        .split('_')
        .map(|s| {
            let mut chars = s.chars();
            match chars.next() {
                Some(first) => first.to_uppercase().collect::<String>() + chars.as_str(),
                None => String::new(),
            }
        })
        .collect()
}

/// 校验 SQL 标识符（表名/列名）
///
/// 白名单规则：字母/数字/下划线，长度 1-64，必须以字母开头
/// 防止 SQL 注入和数据库关键字冲突
fn validate_identifier(name: &str, field_name: &str) -> Result<(), ServiceError> {
    if name.is_empty() || name.len() > 64 {
        return Err(ServiceError::bad_request(&format!(
            "{} 长度必须在1-64之间", field_name
        )));
    }
    if !name.chars().next().map(|c| c.is_ascii_alphabetic() || c == '_').unwrap_or(false) {
        return Err(ServiceError::bad_request(&format!(
            "{} 必须以字母或下划线开头", field_name
        )));
    }
    if !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
        return Err(ServiceError::bad_request(&format!(
            "{} 只能包含字母、数字、下划线", field_name
        )));
    }
    Ok(())
}

/// 将 ColumnDataType 映射到 sea-query ColumnDef 类型方法
fn apply_data_type(
    col_def: &mut ColumnDef,
    data_type: &ColumnDataType,
    length: Option<u32>,
    precision: Option<u32>,
) {
    match data_type {
        ColumnDataType::Varchar => {
            let len = length.unwrap_or(255);
            col_def.string_len(len);
        }
        ColumnDataType::Char => {
            let len = length.unwrap_or(1);
            col_def.char_len(len);
        }
        ColumnDataType::Text => {
            col_def.text();
        }
        ColumnDataType::LongText => {
            // SQLite/PG 没有 LONGTEXT，用 TEXT 替代
            col_def.text();
        }
        ColumnDataType::Int => {
            col_def.integer();
        }
        ColumnDataType::Bigint => {
            col_def.big_integer();
        }
        ColumnDataType::Smallint => {
            col_def.small_integer();
        }
        ColumnDataType::Tinyint => {
            // SQLite/PG 没有 TINYINT，sea-query 的 tiny_integer 会自动适配
            col_def.tiny_integer();
        }
        ColumnDataType::Decimal => {
            let len = length.unwrap_or(10);
            let prec = precision.unwrap_or(0);
            col_def.decimal_len(len, prec);
        }
        ColumnDataType::Double => {
            col_def.double();
        }
        ColumnDataType::Date => {
            col_def.date();
        }
        ColumnDataType::Datetime => {
            col_def.date_time();
        }
        ColumnDataType::Timestamp => {
            col_def.date_time();
        }
        ColumnDataType::Boolean => {
            col_def.boolean();
        }
    }
}

/// 应用默认值到 ColumnDef
///
/// 按类型校验默认值合法性：
/// - 数值类型：解析为数字
/// - 布尔类型：true/false
/// - 字符串类型：直接使用（已通过 serde 反序列化，无注入风险）
fn apply_default_value(
    col_def: &mut ColumnDef,
    data_type: &ColumnDataType,
    default: &str,
) -> Result<(), ServiceError> {
    match data_type {
        ColumnDataType::Int | ColumnDataType::Bigint | ColumnDataType::Smallint | ColumnDataType::Tinyint => {
            default.parse::<i64>().map_err(|_| {
                ServiceError::bad_request(&format!("整数类型默认值 {} 不是有效数字", default))
            })?;
            col_def.default(default.to_string());
        }
        ColumnDataType::Decimal | ColumnDataType::Double => {
            default.parse::<f64>().map_err(|_| {
                ServiceError::bad_request(&format!("小数类型默认值 {} 不是有效数字", default))
            })?;
            col_def.default(default.to_string());
        }
        ColumnDataType::Boolean => {
            let normalized = default.to_lowercase();
            if !["true", "false", "0", "1"].contains(&normalized.as_str()) {
                return Err(ServiceError::bad_request(&format!(
                    "布尔类型默认值 {} 必须是 true/false/0/1", default
                )));
            }
            col_def.default(normalized);
        }
        _ => {
            // 字符串/日期/文本类型：用单引号包裹（sea-query 会自动转义）
            col_def.default(default.to_string());
        }
    }
    Ok(())
}

/// 根据列的 HTML 显示类型推断默认值
fn infer_html_type(column_type: &str, column_name: &str) -> String {
    let ct = column_type.to_uppercase();
    let name = column_name.to_lowercase();
    if ct.contains("TEXT") || ct.contains("CLOB") {
        "textarea".to_string()
    } else if ct.contains("DATE") || ct.contains("TIME") {
        "datetime".to_string()
    } else if name.contains("image") || name.contains("avatar") || name.contains("logo") {
        "imageUpload".to_string()
    } else if name.contains("file") || name.contains("attachment") {
        "upload".to_string()
    } else if name.contains("content") {
        "editor".to_string()
    } else if name == "status" || name == "type" || name == "sex" || name.contains("_type") {
        "select".to_string()
    } else {
        "input".to_string()
    }
}

// ==================== Service 实现 ====================

/// 代码生成模块 Service
pub struct GenTableService {
    repo: GenTableRepository,
}

impl GenTableService {
    pub fn new(db: DatabaseConnection) -> Self {
        Self {
            repo: GenTableRepository::new(db),
        }
    }

    /// 分页查询代码生成业务表
    pub async fn get_page(
        &self,
        query: GenTableQueryDto,
    ) -> Result<(Vec<GenTableModel>, u64), ServiceError> {
        let page = PageDomain::from(&query);
        let offset = page.offset();
        let limit = page.limit();

        let begin = match query.begin_time.as_deref() {
            Some(s) => Some(parse_time(s)?),
            None => None,
        };
        let end = match query.end_time.as_deref() {
            Some(s) => Some(parse_time(s)?),
            None => None,
        };

        let (rows, total) = self
            .repo
            .find_page_filtered(
                offset,
                limit,
                query.table_name.as_deref(),
                query.table_comment.as_deref(),
                begin,
                end,
            )
            .await?;
        Ok((rows, total))
    }

    /// 查询数据库表列表（导入表用，排除已导入的表）
    pub async fn get_db_table_page(
        &self,
        query: DbTableQueryDto,
    ) -> Result<(Vec<crate::repository::gen_table::DbTableInfo>, u64), ServiceError> {
        let page = PageDomain {
            page_num: query.page_num,
            page_size: query.page_size,
            order_by_column: None,
            is_asc: None,
        };
        let offset = page.offset();
        let limit = page.limit();
        let (rows, total) = self
            .repo
            .find_db_tables(offset, limit, query.table_name.as_deref(), query.table_comment.as_deref())
            .await?;
        Ok((rows, total))
    }

    /// 查询代码生成业务表详情（包含列信息和所有表列表）
    pub async fn get_info(&self, table_id: i64) -> Result<GenTableInfoVo, ServiceError> {
        let info = self
            .repo
            .find_by_id(table_id)
            .await?
            .ok_or_else(|| ServiceError::not_found("代码生成业务表不存在"))?;
        let rows = self.repo.find_columns_by_table_id(table_id).await?;
        let tables = self.repo.find_all().await?;
        Ok(GenTableInfoVo { info, rows, tables })
    }

    /// 导入表
    ///
    /// 流程：
    /// 1. 根据 table_name 从数据库元数据读取表结构
    /// 2. 创建 gen_table 记录（默认配置）
    /// 3. 为每个字段创建 gen_table_column 记录（自动推断类型、显示类型等）
    pub async fn import_table(
        &self,
        table_name: &str,
        operator: &str,
    ) -> Result<GenTableModel, ServiceError> {
        // 1. 查重
        if self.repo.find_by_name(table_name).await?.is_some() {
            return Err(ServiceError::bad_request(&format!(
                "表 {} 已导入，请勿重复导入",
                table_name
            )));
        }

        // 2. 读取表元数据
        let columns = self.repo.find_db_columns(table_name).await?;
        if columns.is_empty() {
            return Err(ServiceError::not_found(&format!(
                "表 {} 不存在或没有字段",
                table_name
            )));
        }

        // 3. 读取表注释
        let db_tables = self.repo.find_db_tables(0, i32::MAX as u64, Some(table_name), None).await?;
        let table_comment = db_tables
            .0
            .iter()
            .find(|t| t.table_name == table_name)
            .map(|t| t.table_comment.clone())
            .unwrap_or_default();

        // 4. 创建 gen_table 记录
        let class_name = table_name_to_class_name(table_name);
        let now = chrono::Local::now().naive_local();
        let table_am = GenTableActiveModel {
            table_name: Set(table_name.to_string()),
            table_comment: Set(if table_comment.is_empty() { None } else { Some(table_comment) }),
            class_name: Set(Some(class_name.clone())),
            tpl_category: Set(Some("crud".to_string())),
            tpl_web_type: Set(Some("element-plus".to_string())),
            package_name: Set(Some("yebot".to_string())),
            module_name: Set(Some("system".to_string())),
            business_name: Set(Some(table_name.replace('_', ""))),
            function_name: Set(Some(class_name.clone())),
            function_author: Set(Some("yebot".to_string())),
            gen_type: Set(Some("0".to_string())),
            gen_path: Set(Some("/".to_string())),
            options: Set(None),
            create_by: Set(Some(operator.to_string())),
            create_time: Set(Some(now)),
            update_by: Set(Some(operator.to_string())),
            update_time: Set(Some(now)),
            remark: Set(None),
            sub_table_name: Set(None),
            sub_table_fk_name: Set(None),
            ..Default::default()
        };
        let table_model = self.repo.insert(table_am).await?;

        // 5. 创建 gen_table_column 记录
        let mut column_ams: Vec<GenTableColumnActiveModel> = Vec::new();
        for (idx, col) in columns.iter().enumerate() {
            let rust_type = column_type_to_rust_type(&col.column_type);
            let rust_field = column_name_to_rust_field(&col.column_name);
            let is_pk = if col.column_key == "PRI" { "1" } else { "0" };
            let is_increment = if col.extra.contains("auto_increment") { "1" } else { "0" };
            let is_required = if col.is_nullable == "NO" && is_pk == "0" { "1" } else { "0" };
            let html_type = infer_html_type(&col.column_type, &col.column_name);

            // 默认：主键不参与插入/编辑/查询；其他字段都参与
            let (is_insert, is_edit, is_list, is_query) = if is_pk == "1" {
                ("0", "0", "0", "0")
            } else {
                ("1", "1", "1", "0")
            };

            let column_am = GenTableColumnActiveModel {
                table_id: Set(table_model.table_id),
                column_name: Set(Some(col.column_name.clone())),
                column_comment: Set(Some(col.column_comment.clone())),
                column_type: Set(Some(col.column_type.clone())),
                java_type: Set(Some(rust_type)),
                java_field: Set(Some(rust_field)),
                is_pk: Set(Some(is_pk.to_string())),
                is_increment: Set(Some(is_increment.to_string())),
                is_required: Set(Some(is_required.to_string())),
                is_insert: Set(Some(is_insert.to_string())),
                is_edit: Set(Some(is_edit.to_string())),
                is_list: Set(Some(is_list.to_string())),
                is_query: Set(Some(is_query.to_string())),
                query_type: Set(Some("EQ".to_string())),
                html_type: Set(Some(html_type)),
                dict_type: Set(Some(String::new())),
                // R5-TYPE-14：使用 try_from 替代 `as i32`，避免列数超过 i32::MAX 时溢出
                sort: Set(Some(i32::try_from(idx).map(|n| n + 1).unwrap_or(i32::MAX))),
                create_by: Set(Some(operator.to_string())),
                create_time: Set(Some(now)),
                update_by: Set(Some(operator.to_string())),
                update_time: Set(Some(now)),
                ..Default::default()
            };
            column_ams.push(column_am);
        }
        self.repo.insert_columns(column_ams).await?;

        Ok(table_model)
    }

    /// 创建表（手动创建，不从数据库导入）
    ///
    /// 简化实现：仅创建 gen_table 记录，不创建列记录
    pub async fn create_table(
        &self,
        dto: GenTableEditDto,
        operator: &str,
    ) -> Result<GenTableModel, ServiceError> {
        let now = chrono::Local::now().naive_local();
        let am = GenTableActiveModel {
            table_name: Set(dto.table_name),
            table_comment: Set(dto.table_comment),
            class_name: Set(dto.class_name),
            tpl_category: Set(dto.tpl_category.or(Some("crud".to_string()))),
            tpl_web_type: Set(dto.tpl_web_type.or(Some("element-plus".to_string()))),
            package_name: Set(dto.package_name),
            module_name: Set(dto.module_name),
            business_name: Set(dto.business_name),
            function_name: Set(dto.function_name),
            function_author: Set(dto.function_author),
            gen_type: Set(dto.gen_type.or(Some("0".to_string()))),
            gen_path: Set(dto.gen_path),
            options: Set(dto.options),
            create_by: Set(Some(operator.to_string())),
            create_time: Set(Some(now)),
            update_by: Set(Some(operator.to_string())),
            update_time: Set(Some(now)),
            remark: Set(dto.remark),
            sub_table_name: Set(dto.sub_table_name),
            sub_table_fk_name: Set(dto.sub_table_fk_name),
            ..Default::default()
        };
        let model = self.repo.insert(am).await?;

        // 如果有列信息，一起创建
        if let Some(columns) = dto.columns {
            let mut column_ams: Vec<GenTableColumnActiveModel> = Vec::new();
            for col in columns {
                let column_am = GenTableColumnActiveModel {
                    table_id: Set(model.table_id),
                    column_name: Set(col.column_name),
                    column_comment: Set(col.column_comment),
                    column_type: Set(col.column_type),
                    java_type: Set(col.java_type),
                    java_field: Set(col.java_field),
                    is_pk: Set(col.is_pk),
                    is_increment: Set(col.is_increment),
                    is_required: Set(col.is_required),
                    is_insert: Set(col.is_insert),
                    is_edit: Set(col.is_edit),
                    is_list: Set(col.is_list),
                    is_query: Set(col.is_query),
                    query_type: Set(col.query_type.or(Some("EQ".to_string()))),
                    html_type: Set(col.html_type),
                    dict_type: Set(col.dict_type.or(Some(String::new()))),
                    sort: Set(col.sort),
                    create_by: Set(Some(operator.to_string())),
                    create_time: Set(Some(now)),
                    update_by: Set(Some(operator.to_string())),
                    update_time: Set(Some(now)),
                    ..Default::default()
                };
                column_ams.push(column_am);
            }
            self.repo.insert_columns(column_ams).await?;
        }

        Ok(model)
    }

    /// 结构化建表（方案 A：消除 SQL 注入）
    ///
    /// 流程：
    /// 1. 校验表名（白名单：字母开头 + 字母/数字/下划线，长度 1-64）
    /// 2. 校验列名（同表名规则）
    /// 3. 校验列类型与长度/精度参数一致性
    /// 4. 用 sea-query 声明式构造 TableCreateStatement（自动适配三库方言）
    /// 5. 通过 ConnectionTrait::execute 执行 DDL
    /// 6. 可选：导入到 gen_table + gen_table_column（复用 import_table 逻辑）
    ///
    /// 安全保证：
    /// - 不接收任何原始 SQL，完全消除 SQL 注入
    /// - 表名/列名通过白名单正则校验，禁止特殊字符
    /// - 类型枚举固定，无法传入任意类型
    pub async fn create_table_structured(
        &self,
        dto: CreateTableDto,
        operator: &str,
    ) -> Result<CreateTableResultVo, ServiceError> {
        // 1. 校验表名（白名单：字母开头 + 字母/数字/下划线）
        validate_identifier(&dto.table_name, "表名")?;
        if !dto.table_name.chars().next().map(|c| c.is_ascii_alphabetic()).unwrap_or(false) {
            return Err(ServiceError::bad_request("表名必须以字母开头"));
        }

        // 2. 查重：检查表是否已存在
        if self.repo.find_by_name(&dto.table_name).await?.is_some() {
            return Err(ServiceError::bad_request(&format!(
                "表 {} 已存在于 gen_table，请勿重复创建",
                dto.table_name
            )));
        }
        if self.is_db_table_exists(&dto.table_name).await? {
            return Err(ServiceError::bad_request(&format!(
                "表 {} 已存在于数据库，请勿重复创建",
                dto.table_name
            )));
        }

        // 3. 校验所有列
        let mut col_names = std::collections::HashSet::new();
        for col in &dto.columns {
            validate_identifier(&col.column_name, "列名")?;
            if !col_names.insert(col.column_name.as_str()) {
                return Err(ServiceError::bad_request(&format!(
                    "列名 {} 重复",
                    col.column_name
                )));
            }
            // 类型与长度/精度一致性校验
            if col.data_type.needs_length() && col.length.is_none() {
                return Err(ServiceError::bad_request(&format!(
                    "列 {} 的类型 {:?} 需要指定长度",
                    col.column_name, col.data_type
                )));
            }
            if col.data_type.needs_precision() && col.precision.is_none() {
                return Err(ServiceError::bad_request(&format!(
                    "列 {} 的类型 Decimal 需要指定小数位",
                    col.column_name
                )));
            }
            if let (Some(len), Some(prec)) = (col.length, col.precision)
                && prec >= len
            {
                return Err(ServiceError::bad_request(&format!(
                    "列 {} 的小数位 {} 必须小于长度 {}",
                    col.column_name, prec, len
                )));
            }
            // 自增必须为主键且为整数类型
            if col.is_auto_increment {
                if !col.is_primary_key {
                    return Err(ServiceError::bad_request(&format!(
                        "列 {} 设置自增但未设置主键",
                        col.column_name
                    )));
                }
                if !matches!(col.data_type, ColumnDataType::Int | ColumnDataType::Bigint) {
                    return Err(ServiceError::bad_request(&format!(
                        "列 {} 设置自增但类型 {:?} 不是整数类型",
                        col.column_name, col.data_type
                    )));
                }
            }
        }

        // 4. 至少一个主键（推荐但非强制，SQLite 允许无主键表）
        let has_pk = dto.columns.iter().any(|c| c.is_primary_key);
        if !has_pk {
            tracing::warn!("表 {} 未定义主键", dto.table_name);
        }

        // 5. 构造 sea-query TableCreateStatement
        let mut create_stmt = Table::create()
            .table(Alias::new(&dto.table_name))
            .if_not_exists()
            .to_owned();

        for col in &dto.columns {
            let mut col_def = ColumnDef::new(Alias::new(&col.column_name));
            // 类型映射
            apply_data_type(&mut col_def, &col.data_type, col.length, col.precision);

            // 约束
            if col.is_not_null || col.is_primary_key {
                col_def.not_null();
            }
            if col.is_auto_increment {
                col_def.auto_increment();
            }
            if col.is_unique && !col.is_primary_key {
                col_def.unique_key();
            }
            // 默认值
            if let Some(ref default) = col.default_value
                && !default.is_empty()
            {
                apply_default_value(&mut col_def, &col.data_type, default)?;
            }
            // 注释（sea-query 的 comment 方法支持三库）
            if let Some(ref comment) = col.column_comment
                && !comment.is_empty()
            {
                col_def.comment(comment.clone());
            }
            create_stmt.col(&mut col_def);
        }

        // 主键约束（若有多列主键或需显式声明）
        let pk_cols: Vec<&str> = dto.columns.iter()
            .filter(|c| c.is_primary_key)
            .map(|c| c.column_name.as_str())
            .collect();
        if pk_cols.len() > 1 {
            // 多列主键用复合主键
            let pk_name = format!("pk_{}", dto.table_name);
            let mut pk_index = Index::create().name(&pk_name).to_owned();
            for col_name in &pk_cols {
                pk_index.col(Alias::new(*col_name));
            }
            create_stmt.primary_key(&mut pk_index);
        }

        // 表注释
        if let Some(ref comment) = dto.table_comment
            && !comment.is_empty()
        {
            create_stmt.comment(comment.clone());
        }

        // 6. 根据当前数据库方言生成 SQL 并执行
        let db = self.repo.base().db();
        let backend = db.get_database_backend();
        let sql = backend.build(&create_stmt).to_string();

        tracing::info!("结构化建表 SQL: {}", sql);

        // 执行 DDL
        db.execute(backend.build(&create_stmt)).await
            .map_err(|e| ServiceError::internal(&format!("建表失败: {}", e)))?;

        // 7. 可选：导入到 gen_table
        let mut table_id = None;
        let mut imported_to_gen = false;
        if dto.import_to_gen {
            match self.import_table(&dto.table_name, operator).await {
                Ok(model) => {
                    table_id = Some(model.table_id);
                    imported_to_gen = true;
                }
                Err(e) => {
                    // 导入失败不影响建表结果，记录警告
                    tracing::warn!("表 {} 建表成功但导入 gen_table 失败: {}", dto.table_name, e);
                }
            }
        }

        Ok(CreateTableResultVo {
            table_name: dto.table_name,
            generated_sql: sql,
            imported_to_gen,
            table_id,
        })
    }

    /// 检查表是否已存在于数据库（通过元数据查询）
    async fn is_db_table_exists(&self, table_name: &str) -> Result<bool, ServiceError> {
        let (rows, _) = self.repo.find_db_tables(0, 1, Some(table_name), None).await?;
        Ok(rows.iter().any(|t| t.table_name == table_name))
    }

    /// 修改代码生成业务表配置
    pub async fn update_table(
        &self,
        dto: GenTableEditDto,
        operator: &str,
    ) -> Result<GenTableModel, ServiceError> {
        let existing = self
            .repo
            .find_by_id(dto.table_id)
            .await?
            .ok_or_else(|| ServiceError::not_found("代码生成业务表不存在"))?;

        let now = chrono::Local::now().naive_local();
        let mut am: GenTableActiveModel = existing.into();
        am.table_name = Set(dto.table_name);
        am.table_comment = Set(dto.table_comment);
        am.class_name = Set(dto.class_name);
        am.tpl_category = Set(dto.tpl_category);
        am.tpl_web_type = Set(dto.tpl_web_type);
        am.package_name = Set(dto.package_name);
        am.module_name = Set(dto.module_name);
        am.business_name = Set(dto.business_name);
        am.function_name = Set(dto.function_name);
        am.function_author = Set(dto.function_author);
        am.gen_type = Set(dto.gen_type);
        am.gen_path = Set(dto.gen_path);
        am.options = Set(dto.options);
        am.remark = Set(dto.remark);
        am.sub_table_name = Set(dto.sub_table_name);
        am.sub_table_fk_name = Set(dto.sub_table_fk_name);
        am.update_by = Set(Some(operator.to_string()));
        am.update_time = Set(Some(now));

        let model = self.repo.update(am).await?;

        // 如果有列信息，更新列（先删后插）
        if let Some(columns) = dto.columns {
            let mut column_ams: Vec<GenTableColumnActiveModel> = Vec::new();
            for col in columns {
                let column_am = GenTableColumnActiveModel {
                    table_id: Set(dto.table_id),
                    column_name: Set(col.column_name),
                    column_comment: Set(col.column_comment),
                    column_type: Set(col.column_type),
                    java_type: Set(col.java_type),
                    java_field: Set(col.java_field),
                    is_pk: Set(col.is_pk),
                    is_increment: Set(col.is_increment),
                    is_required: Set(col.is_required),
                    is_insert: Set(col.is_insert),
                    is_edit: Set(col.is_edit),
                    is_list: Set(col.is_list),
                    is_query: Set(col.is_query),
                    query_type: Set(col.query_type.or(Some("EQ".to_string()))),
                    html_type: Set(col.html_type),
                    dict_type: Set(col.dict_type.or(Some(String::new()))),
                    sort: Set(col.sort),
                    create_by: Set(Some(operator.to_string())),
                    create_time: Set(Some(now)),
                    update_by: Set(Some(operator.to_string())),
                    update_time: Set(Some(now)),
                    ..Default::default()
                };
                column_ams.push(column_am);
            }
            self.repo.update_columns(dto.table_id, column_ams).await?;
        }

        Ok(model)
    }

    /// 批量删除代码生成业务表（级联清理列记录）
    pub async fn delete_tables(&self, table_ids: Vec<i64>) -> Result<(), ServiceError> {
        // 校验存在
        for id in &table_ids {
            if self.repo.find_by_id(*id).await?.is_none() {
                return Err(ServiceError::not_found(&format!("表 ID {} 不存在", id)));
            }
        }
        // 级联清理列
        self.repo.delete_columns_by_table_ids(table_ids.clone()).await?;
        // 删除表
        self.repo.delete_by_ids(table_ids).await?;
        Ok(())
    }

    /// 同步数据库（从数据库更新表字段信息）
    ///
    /// 流程：
    /// 1. 根据 table_name 读取最新数据库列元数据
    /// 2. 删除旧的 gen_table_column 记录
    /// 3. 重新生成 gen_table_column 记录
    pub async fn synch_db(&self, table_name: &str, operator: &str) -> Result<(), ServiceError> {
        let table = self
            .repo
            .find_by_name(table_name)
            .await?
            .ok_or_else(|| ServiceError::not_found(&format!("表 {} 未导入", table_name)))?;

        let columns: Vec<DbColumnInfo> = self.repo.find_db_columns(table_name).await?;
        if columns.is_empty() {
            return Err(ServiceError::not_found(&format!("表 {} 不存在或没有字段", table_name)));
        }

        let now = chrono::Local::now().naive_local();
        let mut column_ams: Vec<GenTableColumnActiveModel> = Vec::new();
        for (idx, col) in columns.iter().enumerate() {
            let rust_type = column_type_to_rust_type(&col.column_type);
            let rust_field = column_name_to_rust_field(&col.column_name);
            let is_pk = if col.column_key == "PRI" { "1" } else { "0" };
            let is_increment = if col.extra.contains("auto_increment") { "1" } else { "0" };
            let is_required = if col.is_nullable == "NO" && is_pk == "0" { "1" } else { "0" };
            let html_type = infer_html_type(&col.column_type, &col.column_name);
            let (is_insert, is_edit, is_list, is_query) = if is_pk == "1" {
                ("0", "0", "0", "0")
            } else {
                ("1", "1", "1", "0")
            };

            let column_am = GenTableColumnActiveModel {
                table_id: Set(table.table_id),
                column_name: Set(Some(col.column_name.clone())),
                column_comment: Set(Some(col.column_comment.clone())),
                column_type: Set(Some(col.column_type.clone())),
                java_type: Set(Some(rust_type)),
                java_field: Set(Some(rust_field)),
                is_pk: Set(Some(is_pk.to_string())),
                is_increment: Set(Some(is_increment.to_string())),
                is_required: Set(Some(is_required.to_string())),
                is_insert: Set(Some(is_insert.to_string())),
                is_edit: Set(Some(is_edit.to_string())),
                is_list: Set(Some(is_list.to_string())),
                is_query: Set(Some(is_query.to_string())),
                query_type: Set(Some("EQ".to_string())),
                html_type: Set(Some(html_type)),
                dict_type: Set(Some(String::new())),
                // R5-TYPE-14：使用 try_from 替代 `as i32`，避免列数超过 i32::MAX 时溢出
                sort: Set(Some(i32::try_from(idx).map(|n| n + 1).unwrap_or(i32::MAX))),
                create_by: Set(Some(operator.to_string())),
                create_time: Set(Some(now)),
                update_by: Set(Some(operator.to_string())),
                update_time: Set(Some(now)),
                ..Default::default()
            };
            column_ams.push(column_am);
        }
        self.repo.update_columns(table.table_id, column_ams).await?;
        Ok(())
    }

    /// 预览生成代码
    ///
    /// 使用 Tera 模板引擎渲染所有模板文件，返回文件名 → 代码内容映射
    pub async fn preview(&self, table_id: i64) -> Result<PreviewCodeVo, ServiceError> {
        let info = self
            .repo
            .find_by_id(table_id)
            .await?
            .ok_or_else(|| ServiceError::not_found("代码生成业务表不存在"))?;
        let columns = self.repo.find_columns_by_table_id(table_id).await?;

        Self::render_templates(&info, &columns)
    }

    /// 生成代码（返回 ZIP 文件字节流）
    pub async fn gen_code(&self, table_name: &str) -> Result<Vec<u8>, ServiceError> {
        let table = self
            .repo
            .find_by_name(table_name)
            .await?
            .ok_or_else(|| ServiceError::not_found(&format!("表 {} 未导入", table_name)))?;
        let columns = self.repo.find_columns_by_table_id(table.table_id).await?;

        let files = Self::render_templates(&table, &columns)?;

        // 打包为 ZIP
        let mut buf = Vec::new();
        {
            let mut zip = zip::ZipWriter::new(std::io::Cursor::new(&mut buf));
            let options =
                zip::write::SimpleFileOptions::default().compression_method(zip::CompressionMethod::Deflated);

            for (path, content) in &files {
                zip.start_file(path, options).map_err(|e| {
                    ServiceError::internal(&format!("ZIP 写入失败: {}", e))
                })?;
                use std::io::Write;
                zip.write_all(content.as_bytes()).map_err(|e| {
                    ServiceError::internal(&format!("ZIP 写入失败: {}", e))
                })?;
            }
            zip.finish().map_err(|e| {
                ServiceError::internal(&format!("ZIP 完成失败: {}", e))
            })?;
        }

        Ok(buf)
    }

    /// 批量生成代码（多表打包到同一 ZIP）
    ///
    /// 与 `gen_code` 的差异：
    /// - 多表的渲染结果合并写入同一 ZIP
    /// - 每张表的文件路径加表名子目录前缀（如 `sys_user/entity.rs`、`sys_role/entity.rs`）避免冲突
    ///
    /// 注意：调用方需做表名白名单校验和数量上限控制（已在 handler 层完成）。
    pub async fn batch_gen_code(&self, table_names: &[String]) -> Result<Vec<u8>, ServiceError> {
        let mut buf = Vec::new();
        {
            let mut zip = zip::ZipWriter::new(std::io::Cursor::new(&mut buf));
            let options =
                zip::write::SimpleFileOptions::default().compression_method(zip::CompressionMethod::Deflated);

            for table_name in table_names {
                let table = self
                    .repo
                    .find_by_name(table_name)
                    .await?
                    .ok_or_else(|| {
                        ServiceError::not_found(&format!("表 {} 未导入", table_name))
                    })?;
                let columns = self.repo.find_columns_by_table_id(table.table_id).await?;
                let files = Self::render_templates(&table, &columns)?;

                // 表名子目录前缀（已在 handler 层做白名单校验，仅含字母/数字/下划线，无路径穿越风险）
                let prefix = sanitize_path_component(table_name)?;
                for (path, content) in &files {
                    // 在原路径前加 `{table_name}/` 前缀，避免多表文件名冲突
                    let prefixed_path = format!("{}/{}", prefix, path);
                    zip.start_file(&prefixed_path, options).map_err(|e| {
                        ServiceError::internal(&format!("ZIP 写入失败: {}", e))
                    })?;
                    use std::io::Write;
                    zip.write_all(content.as_bytes()).map_err(|e| {
                        ServiceError::internal(&format!("ZIP 写入失败: {}", e))
                    })?;
                }
            }

            zip.finish().map_err(|e| {
                ServiceError::internal(&format!("ZIP 完成失败: {}", e))
            })?;
        }

        Ok(buf)
    }

    /// 执行建表 SQL（用于 createTable 接口）
    ///
    /// 安全说明：
    /// - 仅允许以 `CREATE TABLE` 开头的 SQL（大小写不敏感）
    /// - 防止误执行 DROP/UPDATE/DELETE 等危险语句
    ///
    /// P0-1 未完全修复项：createTable 接口已禁用（SQL 注入风险），
    /// 请通过 migration 管理表结构。保留此方法仅为兼容性，不应再被调用。
    #[deprecated(note = "createTable 接口已禁用（SQL 注入风险），请通过 migration 管理表结构")]
    #[allow(deprecated)] // 内部调用 repository 的同名 deprecated 方法，此处允许
    pub async fn execute_create_sql(&self, sql: &str) -> Result<(), ServiceError> {
        let trimmed = sql.trim_start();
        let upper = trimmed.to_uppercase();
        if !upper.starts_with("CREATE TABLE") {
            return Err(ServiceError::bad_request(
                "仅允许执行 CREATE TABLE 语句",
            ));
        }
        // 禁止包含分号后的额外语句（基础防注入）
        // 允许末尾单个分号，但不允许中间分号
        let body = trimmed.trim_end_matches(';').trim();
        if body.contains(';') {
            return Err(ServiceError::bad_request(
                "SQL 语句不允许包含分号（禁止多语句执行）",
            ));
        }
        self.repo.execute_create_sql(body).await?;
        Ok(())
    }

    /// 渲染所有模板
    ///
    /// 模板从内嵌字符串加载（编译时嵌入），避免运行时文件依赖
    fn render_templates(
        table: &GenTableModel,
        columns: &[GenTableColumnModel],
    ) -> Result<PreviewCodeVo, ServiceError> {
        let mut tera = Tera::default();

        // 先注册过滤器（Tera 2.0 在 add_raw_templates 时会编译模板，
        // 必须在添加模板之前注册过滤器，否则会报 "Unknown filter" 错误）
        tera.register_filter("pascal_case", pascal_case_filter);
        tera.register_filter("camel_case", camel_case_filter);
        tera.register_filter("upper_camel", upper_camel_filter);

        // 注册内嵌模板
        tera.add_raw_templates(vec![
            ("entity.rs", ENTITY_TEMPLATE),
            ("repository.rs", REPOSITORY_TEMPLATE),
            ("service.rs", SERVICE_TEMPLATE),
            ("handler.rs", HANDLER_TEMPLATE),
            ("router.rs", ROUTER_TEMPLATE),
            ("api.ts", API_TS_TEMPLATE),
            ("index.vue", INDEX_VUE_TEMPLATE),
            ("migration.sql", MIGRATION_SQL_TEMPLATE),
        ])
        .map_err(|e| ServiceError::internal(&format!("Tera 模板加载失败: {}", e)))?;

        // 构建上下文
        let mut ctx = tera::Context::new();
        ctx.insert("table", table);
        ctx.insert("columns", columns);

        // 提取主键字段
        let pk_column = columns.iter().find(|c| c.is_pk.as_deref() == Some("1"));
        ctx.insert("pk_column", &pk_column);

        // 生成类名和模块路径
        let class_name = table.class_name.clone().unwrap_or_default();
        let module_name = table.module_name.clone().unwrap_or_default();
        let business_name = table.business_name.clone().unwrap_or_default();
        ctx.insert("class_name", &class_name);
        ctx.insert("module_name", &module_name);
        ctx.insert("business_name", &business_name);
        ctx.insert("table_name", &table.table_name);

        // Zip Slip 防护：校验用户可编辑字段不含路径穿越字符（.. / \ 空字符），
        // 防止恶意 table_name/module_name 构造的 ZIP 条目路径在解压时写入预期目录之外。
        let table_name_safe = sanitize_path_component(&table.table_name)?;
        let module_name_safe = sanitize_path_component(&module_name)?;
        let _ = sanitize_path_component(&business_name)?;
        let _ = sanitize_path_component(&class_name)?;

        // 生成文件名映射（使用净化后的路径组件）
        let templates: Vec<(&str, &str, String)> = vec![
            ("entity.rs", "entity.rs", format!("src/entity/{}.rs", table_name_safe)),
            ("repository.rs", "repository.rs", format!("src/repository/{}.rs", table_name_safe)),
            ("service.rs", "service.rs", format!("src/service/{}_service.rs", table_name_safe)),
            ("handler.rs", "handler.rs", format!("src/handler/{}_handler.rs", table_name_safe)),
            ("router.rs", "router.rs", format!("src/router/{}_router.rs", table_name_safe)),
            ("api.ts", "api.ts", format!("src/api/{}/{}.ts", module_name_safe, table_name_safe)),
            ("index.vue", "index.vue", format!("src/views/{}/{}/index.vue", module_name_safe, table_name_safe)),
            ("migration.sql", "migration.sql", format!("migration/{}.sql", table_name_safe)),
        ];

        let mut result: HashMap<String, String> = HashMap::new();
        for (tpl_name, _alias, out_path) in templates {
            let rendered = tera.render(tpl_name, &ctx).map_err(|e| {
                // 包含完整的错误链信息（Tera 错误通常有嵌套 source）
                let full_msg = format!("{}", e);
                let source_msg = e.source().map(|s| format!("{}", s)).unwrap_or_default();
                let detail = if source_msg.is_empty() {
                    format!("模板渲染失败 ({}): {}", tpl_name, full_msg)
                } else {
                    format!("模板渲染失败 ({}): {} -> {}", tpl_name, full_msg, source_msg)
                };
                tracing::error!("代码生成模板渲染失败: {}", detail);
                ServiceError::internal(&detail)
            })?;
            result.insert(out_path, rendered);
        }

        Ok(result)
    }
}

// ==================== 路径安全 ====================

/// 校验路径组件，防止 Zip Slip 路径穿越攻击
///
/// 拒绝包含 `..`、`/`、`\`、空字符的路径组件。
/// 这些字符可能被用于构造恶意 ZIP 条目路径，导致解压时文件被写入预期目录之外。
///
/// 返回原字符串（校验通过时），失败返回 ServiceError::bad_request。
fn sanitize_path_component(name: &str) -> Result<String, ServiceError> {
    if name.is_empty() {
        return Ok(String::new());
    }
    if name.contains('\0') {
        return Err(ServiceError::bad_request("路径组件包含非法空字符"));
    }
    if name.contains("..") || name.contains('/') || name.contains('\\') {
        return Err(ServiceError::bad_request(&format!(
            "路径组件包含非法字符（不允许 .. / \\）：{}",
            name
        )));
    }
    Ok(name.to_string())
}

// ==================== Tera 过滤器 ====================

/// PascalCase 过滤器（如 user_info → UserInfo）
///
/// tera 2.0 过滤器签名：`(Arg, Kwargs, &State) -> TeraResult<Value>`，
/// 其中 Arg 实现 `ArgFromValue`（此处直接用 `&str` 自动从 Value 提取字符串）。
/// 使用 `Value::safe_string` 构造返回值，避免代码生成时被 HTML 转义。
fn pascal_case_filter(value: &str, _kwargs: Kwargs, _state: &State) -> TeraResult<Value> {
    let result: String = pascal_case_transform(value);
    Ok(Value::safe_string(&result))
}

/// camelCase 过滤器（如 user_info → userInfo）
fn camel_case_filter(value: &str, _kwargs: Kwargs, _state: &State) -> TeraResult<Value> {
    let pascal = pascal_case_transform(value);
    let mut chars = pascal.chars();
    let result = match chars.next() {
        Some(first) => first.to_lowercase().collect::<String>() + chars.as_str(),
        None => String::new(),
    };
    Ok(Value::safe_string(&result))
}

/// UpperCamelCase 过滤器（同 pascal_case，语义别名）
fn upper_camel_filter(value: &str, kwargs: Kwargs, state: &State) -> TeraResult<Value> {
    pascal_case_filter(value, kwargs, state)
}

/// 共用的 PascalCase 转换逻辑
fn pascal_case_transform(s: &str) -> String {
    s.split('_')
        .map(|word| {
            let mut chars = word.chars();
            match chars.next() {
                Some(first) => first.to_uppercase().collect::<String>() + chars.as_str(),
                None => String::new(),
            }
        })
        .collect()
}

// ==================== Tera 模板（内嵌） ====================

/// Entity 模板
const ENTITY_TEMPLATE: &str = r#"//! {{ table.tableName }} 实体定义
//!
//! {{ table.tableComment | default(value="") }}

use chrono::NaiveDateTime;
use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

use crate::common::datetime;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize)]
#[sea_orm(table_name = "{{ table.tableName }}")]
#[serde(rename_all = "camelCase")]
pub struct Model {
{% for col in columns %}    {% if col.isPk == "1" %}#[sea_orm(primary_key)]
    {% endif %}pub {{ col.javaField }}: {% if col.isPk != "1" and col.isRequired != "1" %}Option<{% endif %}{{ col.javaType }}{% if col.isPk != "1" and col.isRequired != "1" %}>{% endif %},
{% endfor %}}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

#[async_trait::async_trait]
impl ActiveModelBehavior for ActiveModel {}
"#;

/// Repository 模板
const REPOSITORY_TEMPLATE: &str = r#"//! {{ table.tableName }} 数据访问层

use sea_orm::*;

use crate::entity::{{ table.tableName }}::{ActiveModel, Column, Entity as {{ table.className }}, Model};
use crate::repository::base::BaseRepository;

#[derive(Clone)]
pub struct {{ table.className }}Repository {
    base: BaseRepository<{{ table.className }}>,
}

impl {{ table.className }}Repository {
    pub fn new(db: DatabaseConnection) -> Self {
        Self { base: BaseRepository::new(db) }
    }

    pub fn base(&self) -> &BaseRepository<{{ table.className }}> { &self.base }

    pub async fn find_by_id(&self, id: i64) -> Result<Option<Model>, DbErr> {
        {{ table.className }}::find().filter(Column::{{ pk_column.javaField | pascal_case }}.eq(id)).one(self.base.db()).await
    }

    pub async fn find_all(&self) -> Result<Vec<Model>, DbErr> {
        {{ table.className }}::find().all(self.base.db()).await
    }

    pub async fn insert(&self, model: ActiveModel) -> Result<Model, DbErr> {
        self.base.insert(model).await
    }

    pub async fn update(&self, model: ActiveModel) -> Result<Model, DbErr> {
        self.base.update(model).await
    }

    pub async fn delete_by_id(&self, id: i64) -> Result<DeleteResult, DbErr> {
        {{ table.className }}::delete_many().filter(Column::{{ pk_column.javaField | pascal_case }}.eq(id)).exec(self.base.db()).await
    }
}
"#;

/// Service 模板
const SERVICE_TEMPLATE: &str = r#"//! {{ table.tableName }} 模块 Service 层

use sea_orm::{DatabaseConnection, Set};
use serde::Deserialize;
use validator::Validate;

use crate::common::error::ServiceError;
use crate::entity::{{ table.tableName }}::{ActiveModel, Model};
use crate::repository::{{ table.tableName }}::{{ table.className }}Repository;

pub struct {{ table.className }}Service {
    repo: {{ table.className }}Repository,
}

impl {{ table.className }}Service {
    pub fn new(db: DatabaseConnection) -> Self {
        Self { repo: {{ table.className }}Repository::new(db) }
    }

    pub async fn get_all(&self) -> Result<Vec<Model>, ServiceError> {
        Ok(self.repo.find_all().await?)
    }

    pub async fn get_by_id(&self, id: i64) -> Result<Model, ServiceError> {
        self.repo.find_by_id(id).await?.ok_or_else(|| ServiceError::not_found("记录不存在"))
    }

    pub async fn create(&self, dto: {{ table.className }}AddDto, operator: &str) -> Result<Model, ServiceError> {
        let now = chrono::Local::now().naive_local();
        let mut am = ActiveModel { ..Default::default() };
{% for col in columns %}{% if col.isInsert == "1" and col.isPk != "1" %}        am.{{ col.javaField }} = Set(dto.{{ col.javaField }});
{% endif %}{% endfor %}        am.create_by = Set(Some(operator.to_string()));
        am.create_time = Set(Some(now));
        Ok(self.repo.insert(am).await?)
    }

    pub async fn update(&self, dto: {{ table.className }}EditDto, operator: &str) -> Result<Model, ServiceError> {
        let existing = self.get_by_id(dto.{{ pk_column.javaField }}).await?;
        let now = chrono::Local::now().naive_local();
        let mut am: ActiveModel = existing.into();
{% for col in columns %}{% if col.isEdit == "1" %}        am.{{ col.javaField }} = Set(dto.{{ col.javaField }});
{% endif %}{% endfor %}        am.update_by = Set(Some(operator.to_string()));
        am.update_time = Set(Some(now));
        Ok(self.repo.update(am).await?)
    }

    pub async fn delete(&self, id: i64) -> Result<(), ServiceError> {
        self.repo.delete_by_id(id).await?;
        Ok(())
    }
}

#[derive(Debug, Deserialize, Validate)]
#[serde(rename_all = "camelCase")]
pub struct {{ table.className }}AddDto {
{% for col in columns %}{% if col.isInsert == "1" and col.isPk != "1" %}    pub {{ col.javaField }}: {% if col.isRequired == "1" %}{{ col.javaType }}{% else %}Option<{{ col.javaType }}>{% endif %},
{% endif %}{% endfor %}}

#[derive(Debug, Deserialize, Validate)]
#[serde(rename_all = "camelCase")]
pub struct {{ table.className }}EditDto {
    pub {{ pk_column.javaField }}: i64,
{% for col in columns %}{% if col.isEdit == "1" %}    pub {{ col.javaField }}: {% if col.isRequired == "1" %}{{ col.javaType }}{% else %}Option<{{ col.javaType }}>{% endif %},
{% endif %}{% endfor %}}
"#;

/// Handler 模板
const HANDLER_TEMPLATE: &str = r#"//! {{ table.tableName }} 模块 Handler

use std::sync::Arc;
use axum::extract::{Path, State};
use axum::Json;

use crate::common::{AjaxResult, AppError, TableDataInfo};
use crate::middleware::Operator;
use crate::service::{{ table.tableName }}_service::{{ table.className }}Service;
use crate::state::AppState;

pub async fn list(State(state): State<Arc<AppState>>) -> Result<TableDataInfo<crate::entity::{{ table.tableName }}::Model>, AppError> {
    let rows = state.{{ table.tableName | camel_case }}_service.get_all().await?;
    Ok(TableDataInfo::new(rows.len() as u64, rows))
}

pub async fn get_info(State(state): State<Arc<AppState>>, Path(id): Path<i64>) -> Result<AjaxResult<crate::entity::{{ table.tableName }}::Model>, AppError> {
    let model = state.{{ table.tableName | camel_case }}_service.get_by_id(id).await?;
    Ok(AjaxResult::success(model))
}

pub async fn add(State(state): State<Arc<AppState>>, operator: Operator, Json(dto): Json<crate::service::{{ table.tableName }}_service::{{ table.className }}AddDto>) -> Result<AjaxResult<()>, AppError> {
    state.{{ table.tableName | camel_case }}_service.create(dto, operator.username()).await?;
    Ok(AjaxResult::success_msg("新增成功"))
}

pub async fn edit(State(state): State<Arc<AppState>>, operator: Operator, Json(dto): Json<crate::service::{{ table.tableName }}_service::{{ table.className }}EditDto>) -> Result<AjaxResult<()>, AppError> {
    state.{{ table.tableName | camel_case }}_service.update(dto, operator.username()).await?;
    Ok(AjaxResult::success_msg("修改成功"))
}

pub async fn remove(State(state): State<Arc<AppState>>, Path(id): Path<i64>) -> Result<AjaxResult<()>, AppError> {
    state.{{ table.tableName | camel_case }}_service.delete(id).await?;
    Ok(AjaxResult::success_msg("删除成功"))
}
"#;

/// Router 模板
const ROUTER_TEMPLATE: &str = r#"//! {{ table.tableName }} 模块路由

use std::sync::Arc;
use axum::Router;
use axum::routing::{get, post, put, delete};

use crate::handler::{{ table.tableName }}_handler;
use crate::state::AppState;

pub fn {{ table.tableName | camel_case }}_routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/{{ table.moduleName }}/{{ table.tableName }}/list", get({{ table.tableName }}_handler::list))
        .route("/{{ table.moduleName }}/{{ table.tableName }}/{{ '{' }}{{ pk_column.javaField }}{{ '}' }}", get({{ table.tableName }}_handler::get_info))
        .route("/{{ table.moduleName }}/{{ table.tableName }}", post({{ table.tableName }}_handler::add))
        .route("/{{ table.moduleName }}/{{ table.tableName }}", put({{ table.tableName }}_handler::edit))
        .route("/{{ table.moduleName }}/{{ table.tableName }}/{{ '{' }}{{ pk_column.javaField }}{{ '}' }}", delete({{ table.tableName }}_handler::remove))
}
"#;

/// 前端 API TypeScript 模板
const API_TS_TEMPLATE: &str = r#"import request from '@/utils/request'

// 查询{{ table.functionName }}列表
export function list(query: any) {
  return request({
    url: '/{{ table.moduleName }}/{{ table.tableName }}/list',
    method: 'get',
    params: query
  })
}

// 查询{{ table.functionName }}详细
export function get{{ table.className }}(id: number) {
  return request({
    url: '/{{ table.moduleName }}/{{ table.tableName }}/' + id,
    method: 'get'
  })
}

// 新增{{ table.functionName }}
export function add{{ table.className }}(data: any) {
  return request({
    url: '/{{ table.moduleName }}/{{ table.tableName }}',
    method: 'post',
    data
  })
}

// 修改{{ table.functionName }}
export function update{{ table.className }}(data: any) {
  return request({
    url: '/{{ table.moduleName }}/{{ table.tableName }}',
    method: 'put',
    data
  })
}

// 删除{{ table.functionName }}
export function del{{ table.className }}(id: number) {
  return request({
    url: '/{{ table.moduleName }}/{{ table.tableName }}/' + id,
    method: 'delete'
  })
}
"#;

/// 前端 Vue 列表页模板
const INDEX_VUE_TEMPLATE: &str = r#"<template>
  <div class="app-container">
    <el-row :gutter="20" class="mb8">
      <el-col :span="1.5">
        <el-button type="primary" plain icon="Plus" @click="handleAdd">新增</el-button>
      </el-col>
    </el-row>

    <el-table v-loading="loading" :data="list">
{% for col in columns %}{% if col.isList == "1" %}      <el-table-column label="{{ col.columnComment }}" prop="{{ col.javaField | camel_case }}" />
{% endif %}{% endfor %}      <el-table-column label="操作" width="180">
        <template #default="scope">
          <el-button type="primary" link icon="Edit" @click="handleEdit(scope.row)">修改</el-button>
          <el-button type="danger" link icon="Delete" @click="handleDelete(scope.row)">删除</el-button>
        </template>
      </el-table-column>
    </el-table>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { list, get{{ table.className }}, add{{ table.className }}, update{{ table.className }}, del{{ table.className }} } from '@/api/{{ table.moduleName }}/{{ table.tableName }}'

const loading = ref(false)
const list = ref([])

async function getList() {
  loading.value = true
  try {
    const res = await list({})
    list.value = res.rows || res.data || []
  } finally {
    loading.value = false
  }
}

function handleAdd() {
  // TODO: 打开新增对话框
}

function handleEdit(row: any) {
  // TODO: 打开编辑对话框
}

async function handleDelete(row: any) {
  await del{{ table.className }}(row.{{ pk_column.javaField | camel_case }})
  getList()
}

onMounted(() => {
  getList()
})
</script>
"#;

/// SQL 迁移脚本模板
const MIGRATION_SQL_TEMPLATE: &str = r#"-- {{ table.functionName }} 表结构（仅供参考，实际表结构由数据库元数据导入）
-- 表名: {{ table.tableName }}
-- 描述: {{ table.tableComment | default(value="") }}

CREATE TABLE IF NOT EXISTS {{ table.tableName }} (
{% for col in columns %}    {{ col.columnName }} {{ col.columnType }}{% if col.isRequired == "1" %} NOT NULL{% endif %}{% if col.isPk == "1" %} PRIMARY KEY{% endif %}{% if col.isIncrement == "1" %} AUTOINCREMENT{% endif %}{% if not loop.last %},{% endif %}

{% endfor %});
"#;
