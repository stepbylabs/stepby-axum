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

use std::collections::{BTreeMap, HashMap};
use std::error::Error as StdError;

use futures::future::FutureExt;
use garde::Validate;
use sea_orm::sea_query::{Alias, ColumnDef, Index, Table, TableCreateStatement};
use sea_orm::{ConnectionTrait, DatabaseConnection, Set, TransactionTrait};
use serde::{Deserialize, Serialize};
use tera::{Kwargs, State, Tera, TeraResult, Value};
use utoipa::{IntoParams, ToSchema};

use crate::common::error::ServiceError;
use crate::common::page::{PageDomain, default_page_num, default_page_size};
use crate::common::sort::{self, SortOrder};
use crate::entity::gen_table::{
    ActiveModel as GenTableActiveModel, Column as GenTableCol, Model as GenTableModel,
};
use crate::entity::gen_table_column::{
    ActiveModel as GenTableColumnActiveModel, Model as GenTableColumnModel,
};
use crate::repository::gen_table::{DbColumnInfo, DbTableSortColumn, GenTableRepository};

// ==================== DTO ====================

/// 代码生成业务表分页查询 DTO
#[derive(Debug, Clone, Deserialize, IntoParams)]
#[serde(rename_all = "camelCase")]
pub struct GenTableQueryDto {
    #[serde(default = "default_page_num")]
    pub page_num: u64,
    #[serde(default = "default_page_size")]
    pub page_size: u64,
    /// 排序字段（前端表头 prop，camelCase/snake_case 均可；经列白名单映射后生效，
    /// 未命中白名单回退默认排序，绝不透传任意列）
    #[serde(default)]
    pub order_by_column: Option<String>,
    /// 排序方向 asc / ascending / desc / descending（缺省 desc）
    #[serde(default)]
    pub is_asc: Option<String>,
    pub table_name: Option<String>,
    pub table_comment: Option<String>,
    #[serde(alias = "params[beginTime]", default)]
    pub begin_time: Option<String>,
    #[serde(alias = "params[endTime]", default)]
    pub end_time: Option<String>,
}

impl From<&GenTableQueryDto> for PageDomain {
    fn from(dto: &GenTableQueryDto) -> Self {
        // 动态排序透传：先 sanitize（格式白名单），列级白名单在 service 查询时解析
        let mut page = PageDomain {
            page_num: dto.page_num,
            page_size: dto.page_size,
            order_by_column: dto.order_by_column.clone(),
            is_asc: dto.is_asc.clone(),
        };
        page.sanitize_order_fields();
        page
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
    /// 排序字段（前端表头 prop，camelCase/snake_case 均可；经列白名单映射后生效，
    /// 未命中白名单回退默认排序，绝不透传任意列）
    #[serde(default)]
    pub order_by_column: Option<String>,
    /// 排序方向 asc / ascending / desc / descending（缺省 desc）
    #[serde(default)]
    pub is_asc: Option<String>,
    pub table_name: Option<String>,
    pub table_comment: Option<String>,
}

/// 修改代码生成业务表 DTO
#[derive(Debug, Deserialize, Validate, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct GenTableEditDto {
    #[garde(skip)]
    pub table_id: i64,
    #[garde(skip)]
    pub table_name: String,
    #[garde(skip)]
    pub table_comment: Option<String>,
    #[garde(skip)]
    pub class_name: Option<String>,
    #[garde(skip)]
    pub function_name: Option<String>,
    #[garde(skip)]
    pub function_author: Option<String>,
    #[garde(skip)]
    pub tpl_category: Option<String>,
    #[garde(skip)]
    pub tpl_web_type: Option<String>,
    #[garde(skip)]
    pub package_name: Option<String>,
    #[garde(skip)]
    pub module_name: Option<String>,
    #[garde(skip)]
    pub business_name: Option<String>,
    #[garde(skip)]
    pub gen_type: Option<String>,
    #[garde(skip)]
    pub gen_path: Option<String>,
    #[garde(skip)]
    pub options: Option<String>,
    #[garde(skip)]
    pub remark: Option<String>,
    #[garde(skip)]
    pub sub_table_name: Option<String>,
    #[garde(skip)]
    pub sub_table_fk_name: Option<String>,
    /// 列信息（修改时一起提交）
    #[garde(skip)]
    pub columns: Option<Vec<GenTableColumnEditDto>>,
}

/// 修改代码生成列 DTO
#[derive(Debug, Clone, Deserialize, Validate, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct GenTableColumnEditDto {
    #[garde(skip)]
    pub column_id: Option<i64>,
    #[garde(skip)]
    pub column_name: Option<String>,
    #[garde(skip)]
    pub column_comment: Option<String>,
    #[garde(skip)]
    pub column_type: Option<String>,
    #[garde(skip)]
    pub rust_type: Option<String>,
    #[garde(skip)]
    pub rust_field: Option<String>,
    #[garde(skip)]
    pub is_pk: Option<String>,
    #[garde(skip)]
    pub is_increment: Option<String>,
    #[garde(skip)]
    pub is_required: Option<String>,
    #[garde(skip)]
    pub is_insert: Option<String>,
    #[garde(skip)]
    pub is_edit: Option<String>,
    #[garde(skip)]
    pub is_list: Option<String>,
    #[garde(skip)]
    pub is_query: Option<String>,
    #[garde(skip)]
    pub query_type: Option<String>,
    #[garde(skip)]
    pub html_type: Option<String>,
    #[garde(skip)]
    pub dict_type: Option<String>,
    #[garde(skip)]
    pub sort: Option<i32>,
}

/// 代码生成详情响应
#[derive(Debug, Serialize, ToSchema)]
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
    #[garde(length(min = 1, max = 64))]
    pub column_name: String,
    /// 列类型（必填）
    #[garde(skip)]
    pub data_type: ColumnDataType,
    /// 长度（VARCHAR/CHAR 必填，DECIMAL 必填表示精度）
    #[garde(range(min = 1, max = 65535))]
    pub length: Option<u32>,
    /// 小数位（仅 DECIMAL，必须 < length）
    #[garde(range(min = 0, max = 30))]
    pub precision: Option<u32>,
    /// 是否主键
    #[serde(default)]
    #[garde(skip)]
    pub is_primary_key: bool,
    /// 是否自增（仅整数类型，且必须为主键）
    #[serde(default)]
    #[garde(skip)]
    pub is_auto_increment: bool,
    /// 是否非空
    #[serde(default)]
    #[garde(skip)]
    pub is_not_null: bool,
    /// 是否唯一
    #[serde(default)]
    #[garde(skip)]
    pub is_unique: bool,
    /// 默认值（字符串形式，由后端按类型校验）
    #[garde(skip)]
    pub default_value: Option<String>,
    /// 列注释
    #[garde(skip)]
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
    #[garde(length(min = 1, max = 64))]
    pub table_name: String,
    /// 表注释
    #[garde(skip)]
    pub table_comment: Option<String>,
    /// 列定义列表（至少 1 列）
    #[garde(length(min = 1))]
    pub columns: Vec<CreateTableColumnDto>,
    /// 是否同时导入到 gen_table（代码生成业务表）
    #[serde(default = "default_import_to_gen")]
    #[garde(skip)]
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
///
/// b139：`BTreeMap` 而非 `HashMap`——ZIP 条目顺序由此确定，同样的表生成两次得到
/// **逐字节相同**的压缩包（可做校验和/缓存/跨环境比对）。`HashMap` 的迭代顺序随机，
/// 于是 `genCode` 每点一次产出的 ZIP 字节都不同，而内容其实完全一致。
pub type PreviewCodeVo = BTreeMap<String, String>;

/// 单张表导入的准备数据（校验 + 只读元数据已就绪，待事务内写入）
///
/// `build_column_ams` 为 move 闭包：以 owned 值捕获列信息/操作人/时间，
/// 在表记录插入拿到 table_id 后再构造列 ActiveModel，避免生命周期冲突。
struct ImportPrepared {
    table_am: GenTableActiveModel,
    build_column_ams: Box<dyn FnOnce(i64) -> Vec<GenTableColumnActiveModel> + Send>,
}

// ==================== 辅助函数 ====================

/// 将数据库列类型映射为 Rust 类型
///
/// 参考 sea-orm 的类型映射规则
fn column_type_to_rust_type(column_type: &str) -> String {
    let ct = column_type.to_uppercase();
    // ⚠️ 判定顺序敏感：`TINYINT` / `SMALLINT` 都**包含** `INT`，必须排在通用
    // `INT` 之前，否则 `i8` / `i16` 分支恒不可达（第八批由
    // `test_column_type_mapping_only_emits_rust_types` 实测暴露的既有缺陷）。
    if ct.contains("BIGINT") {
        "i64".to_string()
    } else if ct.contains("TINYINT") {
        "i8".to_string()
    } else if ct.contains("SMALLINT") {
        "i16".to_string()
    } else if ct.contains("INT") || ct.contains("INTEGER") {
        "i64".to_string()
    } else if ct.contains("FLOAT") {
        "f32".to_string()
    } else if ct.contains("DOUBLE") || ct.contains("DECIMAL") || ct.contains("NUMERIC") {
        "f64".to_string()
    } else if ct.contains("BOOL") {
        "bool".to_string()
    } else if ct.contains("DATE")
        || ct.contains("TIME")
        || ct.contains("DATETIME")
        || ct.contains("TIMESTAMP")
    {
        // 时态列返回**内层**类型：可空性由模板按 `isRequired` 统一包 `Option<...>`。
        // 若在此处预先包裹，`entity.tera` / `service.tera` 会对可空列二次包裹，
        // 产出 `Option<Option<chrono::NaiveDateTime>>`（sea_orm 派生实体/ DTO 均无法编译）。
        "chrono::NaiveDateTime".to_string()
    } else {
        // 默认 String 类型（VARCHAR/TEXT/CHAR 等）
        "String".to_string()
    }
}

/// 将数据库列名（snake_case）转换为 Rust 字段名（保持 snake_case）
/// 若列名是数据库关键字则添加 raw_ 前缀
fn column_name_to_rust_field(column_name: &str) -> String {
    let reserved = [
        "type", "ref", "match", "mod", "move", "as", "fn", "if", "in", "let", "pub", "use",
        "where", "self", "super", "crate", "extern",
    ];
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
        return Err(ServiceError::bad_request(&crate::tr!(
            "error.gen.field_length_invalid",
            field = field_name
        )));
    }
    if !name
        .chars()
        .next()
        .map(|c| c.is_ascii_alphabetic() || c == '_')
        .unwrap_or(false)
    {
        return Err(ServiceError::bad_request(&crate::tr!(
            "error.gen.field_start_invalid",
            field = field_name
        )));
    }
    if !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
        return Err(ServiceError::bad_request(&crate::tr!(
            "error.gen.field_char_invalid",
            field = field_name
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
        ColumnDataType::Int
        | ColumnDataType::Bigint
        | ColumnDataType::Smallint
        | ColumnDataType::Tinyint => {
            default.parse::<i64>().map_err(|_| {
                ServiceError::bad_request(&format!(
                    "{}: {default}",
                    crate::tr!("error.gen.int_default")
                ))
            })?;
            col_def.default(default.to_string());
        }
        ColumnDataType::Decimal | ColumnDataType::Double => {
            default.parse::<f64>().map_err(|_| {
                ServiceError::bad_request(&format!(
                    "{}: {default}",
                    crate::tr!("error.gen.decimal_default")
                ))
            })?;
            col_def.default(default.to_string());
        }
        ColumnDataType::Boolean => {
            let normalized = default.to_lowercase();
            if !["true", "false", "0", "1"].contains(&normalized.as_str()) {
                return Err(ServiceError::bad_request(&crate::tr!(
                    "error.gen.bool_default_invalid",
                    value = default
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

/// 允许排序的列白名单（数据库列名 snake_case；前端 prop 经 camel_to_snake 归一后匹配）。
///
/// 覆盖 gen_table 业务展示列；`options` / `gen_path` / `create_by` 等配置或内部列不开放动态排序。
const SORTABLE_COLUMNS: &[(&str, GenTableCol)] = &[
    ("table_id", GenTableCol::TableId),
    ("table_name", GenTableCol::TableName),
    ("table_comment", GenTableCol::TableComment),
    ("create_time", GenTableCol::CreateTime),
    ("update_time", GenTableCol::UpdateTime),
];

/// 数据库元数据表列表允许排序的列白名单（`find_db_tables` 为原始 SQL 查询、无 sea-orm Entity）。
///
/// 前端 prop 经 camel_to_snake 归一后映射到 [`DbTableSortColumn`]，SQL 端映射为
/// SELECT 输出列别名（编译期常量），保持与 sea-orm 参数化路径同等安全语义。
const DB_TABLE_SORTABLE_COLUMNS: &[(&str, DbTableSortColumn)] = &[
    ("table_name", DbTableSortColumn::TableName),
    ("table_comment", DbTableSortColumn::TableComment),
];

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
        // 动态排序：白名单命中才生效，未命中/缺省由 repository 回退默认排序
        let sort = page.order_by_column.as_deref().and_then(|prop| {
            sort::resolve_column::<crate::entity::gen_table::Entity>(prop, SORTABLE_COLUMNS)
                .map(|col| SortOrder::new(col, sort::parse_direction(page.is_asc.as_deref())))
        });

        let begin = match query.begin_time.as_deref() {
            Some(s) => Some(crate::common::datetime::parse_query_date(s)?),
            None => None,
        };
        let end = match query.end_time.as_deref() {
            Some(s) => Some(crate::common::datetime::parse_query_date(s)?),
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
                sort,
            )
            .await?;
        Ok((rows, total))
    }

    /// 查询数据库表列表（导入表用，排除已导入的表）
    pub async fn get_db_table_page(
        &self,
        query: DbTableQueryDto,
    ) -> Result<(Vec<crate::repository::gen_table::DbTableInfo>, u64), ServiceError> {
        // 动态排序透传：先 sanitize（格式白名单），列级白名单在下方解析
        let mut page = PageDomain {
            page_num: query.page_num,
            page_size: query.page_size,
            order_by_column: query.order_by_column.clone(),
            is_asc: query.is_asc.clone(),
        };
        page.sanitize_order_fields();
        let offset = page.offset();
        let limit = page.limit();
        // 动态排序：元数据查询无 sea-orm Entity，白名单映射到 DbTableSortColumn
        // （等价语义：命中才生效，未命中/缺省由 repository 回退默认排序）
        let sort = page.order_by_column.as_deref().and_then(|prop| {
            let key = sort::camel_to_snake(prop);
            DB_TABLE_SORTABLE_COLUMNS
                .iter()
                .find(|(name, _)| *name == key)
                .map(|(_, col)| SortOrder::new(*col, sort::parse_direction(page.is_asc.as_deref())))
        });
        let (rows, total) = self
            .repo
            .find_db_tables(
                offset,
                limit,
                query.table_name.as_deref(),
                query.table_comment.as_deref(),
                sort,
            )
            .await?;
        Ok((rows, total))
    }

    /// 查询代码生成业务表详情（包含列信息和所有表列表）
    pub async fn get_info(&self, table_id: i64) -> Result<GenTableInfoVo, ServiceError> {
        let info = self
            .repo
            .find_by_id(table_id)
            .await?
            .ok_or_else(|| ServiceError::not_found(&crate::tr!("error.gen.table_not_found")))?;
        let rows = self.repo.find_columns_by_table_id(table_id).await?;
        let tables = self.repo.find_all().await?;
        Ok(GenTableInfoVo { info, rows, tables })
    }

    /// 导入单张表（兼容单表入口，复用批量导入的原子事务）
    ///
    /// 流程：
    /// 1. 根据 table_name 从数据库元数据读取表结构（查重校验 + 标识符校验）
    /// 2. 创建 gen_table 记录（默认配置）
    /// 3. 为每个字段创建 gen_table_column 记录（自动推断类型、显示类型等）
    pub async fn import_table(
        &self,
        table_name: &str,
        operator: &str,
    ) -> Result<GenTableModel, ServiceError> {
        let mut models = self.import_tables(&[table_name], operator).await?;
        // import_tables 保证成功时每张表均有记录；单表必有 1 条
        // 批六十六：import_tables 契约失败时返回统一错误而非 panic——
        // panic 会中断 request task（无状态码、无留痕），违背"错误响应契约统一"硬基线。
        match models.pop() {
            Some(m) => Ok(m),
            None => Err(ServiceError::internal(&crate::tr!("error.common.internal"))),
        }
    }

    /// 批量导入表（单事务原子：任一张表失败则整体回滚）
    ///
    /// 相比逐个调用 `import_table`，本方法将所有表的查重校验、表结构读取、
    /// 记录写入收敛到一个数据库事务内，保证"全部成功或全部失败"，
    /// 避免部分导入造成的数据不一致（如残留无列的 gen_table 记录）。
    ///
    /// 实现要点：
    /// 1. 准备阶段（`prepare_import`）：查重 + 标识符校验 + 只读元数据读取，不落库；
    ///    任一张表校验失败则整体中止，避免部分写入后再回滚。
    /// 2. 写入阶段：单个事务内逐表插入 gen_table + gen_table_column。
    pub async fn import_tables(
        &self,
        table_names: &[&str],
        operator: &str,
    ) -> Result<Vec<GenTableModel>, ServiceError> {
        // 1. 准备阶段：校验 + 查重 + 读取元数据（不落库）
        let mut prepared: Vec<ImportPrepared> = Vec::with_capacity(table_names.len());
        for table_name in table_names {
            prepared.push(self.prepare_import(table_name, operator).await?);
        }

        // 2. 单事务写入：所有表 + 所有列（失败整体回滚）
        let repo = self.repo.clone();
        let models = self
            .repo
            .base()
            .db()
            .transaction::<_, Vec<GenTableModel>, ServiceError>(|txn| {
                let repo = repo.clone();
                let operator = operator.to_string();
                async move {
                    let mut inserted = Vec::with_capacity(prepared.len());
                    for item in prepared {
                        // 在事务内插入表，获取 table_id
                        let table_model = repo.base().insert_conn(txn, item.table_am).await?;
                        // 用 table_id 构造列并插入
                        let column_ams = (item.build_column_ams)(table_model.table_id);
                        if !column_ams.is_empty() {
                            repo.insert_columns_conn(txn, column_ams).await?;
                        }
                        // 审计合规域：INSERT 变更留痕（同事务提交/回滚；gen_table 列明细
                        // 随表行快照语义覆盖，不逐列重复留痕）
                        crate::service::sys_audit_change_service::audit_insert(
                            txn,
                            "gen_table",
                            &table_model.table_id.to_string(),
                            &table_model,
                            None, // import 签名仅携带操作人用户名，ID 由回查补齐
                            Some(operator.as_str()),
                        )
                        .await?;
                        inserted.push(table_model);
                    }
                    Ok(inserted)
                }
                .boxed()
            })
            .await
            .map_err(|e| match e {
                sea_orm::TransactionError::Transaction(se) => se,
                sea_orm::TransactionError::Connection(db_err) => {
                    tracing::error!(error = %db_err, "import_tables 事务连接错误");
                    ServiceError::internal(&crate::tr!("error.common.tx_failed"))
                }
            })?;

        Ok(models)
    }

    /// 准备单张表导入数据（查重校验 + 只读元数据，不落库）
    ///
    /// 该函数在事务开启前执行，只做校验与元数据读取；
    /// 返回的 [`ImportPrepared`] 携带可落库的 ActiveModel 与列构造闭包。
    async fn prepare_import(
        &self,
        table_name: &str,
        operator: &str,
    ) -> Result<ImportPrepared, ServiceError> {
        // 1. 查重
        if self.repo.find_by_name(table_name).await?.is_some() {
            return Err(ServiceError::bad_request(&crate::tr!(
                "error.gen.table_already_imported",
                name = table_name
            )));
        }

        // 2. 读取表元数据
        let columns = self.repo.find_db_columns(table_name).await?;
        if columns.is_empty() {
            return Err(ServiceError::not_found(&crate::tr!(
                "error.gen.table_no_columns_or_not_exist",
                name = table_name
            )));
        }

        // 2.1 校验表名和所有列名符合 Rust 标识符规范（防止生成无法编译的代码）
        validate_identifier(table_name, "table_name")?;
        for col in &columns {
            validate_identifier(&col.column_name, "column_name")?;
        }

        // 3. 读取表注释（仅需 1 条匹配）
        let db_tables = self
            .repo
            .find_db_tables(0, 1, Some(table_name), None, None)
            .await?;
        let table_comment = db_tables
            .0
            .iter()
            .find(|t| t.table_name == table_name)
            .map(|t| t.table_comment.clone())
            .unwrap_or_default();

        // 4. 创建 gen_table 记录
        let class_name = table_name_to_class_name(table_name);
        let now = crate::common::datetime::now_naive();
        let table_am = GenTableActiveModel {
            table_name: Set(table_name.to_string()),
            table_comment: Set(if table_comment.is_empty() {
                None
            } else {
                Some(table_comment)
            }),
            class_name: Set(Some(class_name.clone())),
            tpl_category: Set(Some("crud".to_string())),
            tpl_web_type: Set(Some("element-plus".to_string())),
            package_name: Set(Some("stepby".to_string())),
            module_name: Set(Some("system".to_string())),
            business_name: Set(Some(table_name.replace('_', ""))),
            function_name: Set(Some(class_name.clone())),
            function_author: Set(Some("stepby".to_string())),
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
        // 5. 预构造列 ActiveModel 的闭包（table_id 待表插入后填充）
        // P1 修复: 闭包以 move 捕获 owned 值（columns/operator_str/now），
        // 避免事务 async 块捕获引用导致 'static 生命周期冲突
        let operator_str = operator.to_string();
        let build_column_ams = move |table_id: i64| -> Vec<GenTableColumnActiveModel> {
            columns
                .into_iter()
                .enumerate()
                .map(|(idx, col)| {
                    let rust_type = column_type_to_rust_type(&col.column_type);
                    let rust_field = column_name_to_rust_field(&col.column_name);
                    let is_pk = if col.column_key == "PRI" { "1" } else { "0" };
                    let is_increment = if col.extra.contains("auto_increment") {
                        "1"
                    } else {
                        "0"
                    };
                    let is_required = if col.is_nullable == "NO" && is_pk == "0" {
                        "1"
                    } else {
                        "0"
                    };
                    let html_type = infer_html_type(&col.column_type, &col.column_name);

                    // 默认：主键不参与插入/编辑/查询；其他字段都参与
                    let (is_insert, is_edit, is_list, is_query) = if is_pk == "1" {
                        ("0", "0", "0", "0")
                    } else {
                        ("1", "1", "1", "0")
                    };

                    GenTableColumnActiveModel {
                        table_id: Set(table_id),
                        column_name: Set(Some(col.column_name)),
                        column_comment: Set(Some(col.column_comment)),
                        column_type: Set(Some(col.column_type)),
                        rust_type: Set(Some(rust_type)),
                        rust_field: Set(Some(rust_field)),
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
                        create_by: Set(Some(operator_str.clone())),
                        create_time: Set(Some(now)),
                        update_by: Set(Some(operator_str.clone())),
                        update_time: Set(Some(now)),
                        ..Default::default()
                    }
                })
                .collect()
        };

        Ok(ImportPrepared {
            table_am,
            build_column_ams: Box::new(build_column_ams),
        })
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
    /// 构造结构化建表语句（sea-query 声明式，跨库方言无关）
    ///
    /// 抽离自 `create_table_structured` 以便单测覆盖主键约束生成逻辑。
    /// - 单列主键：在列定义上显式 `PRIMARY KEY`（原 bug：sea-query 不会因 is_primary_key 自动加约束，导致生成表缺失主键）
    /// - 复合主键：循环后以复合索引统一声明 `PRIMARY KEY`
    fn build_create_table_sql(dto: &CreateTableDto) -> Result<TableCreateStatement, ServiceError> {
        let mut create_stmt = Table::create()
            .table(Alias::new(&dto.table_name))
            .if_not_exists()
            .to_owned();

        // 预计算主键列（用于区分单列/复合主键的约束声明）
        let pk_cols: Vec<&str> = dto
            .columns
            .iter()
            .filter(|c| c.is_primary_key)
            .map(|c| c.column_name.as_str())
            .collect();

        for col in &dto.columns {
            let mut col_def = ColumnDef::new(Alias::new(&col.column_name));
            apply_data_type(&mut col_def, &col.data_type, col.length, col.precision);

            // 约束
            if col.is_primary_key {
                if pk_cols.len() == 1 {
                    // 单列主键：在列定义上显式声明 PRIMARY KEY
                    col_def.primary_key();
                } else {
                    // 复合主键：列仍需 NOT NULL，PK 约束在循环后统一以复合索引声明
                    col_def.not_null();
                }
            } else if col.is_not_null {
                col_def.not_null();
            }
            if col.is_auto_increment {
                col_def.auto_increment();
            }
            if col.is_unique && !col.is_primary_key {
                col_def.unique_key();
            }
            if let Some(ref default) = col.default_value
                && !default.is_empty()
            {
                apply_default_value(&mut col_def, &col.data_type, default)?;
            }
            if let Some(ref comment) = col.column_comment
                && !comment.is_empty()
            {
                col_def.comment(comment.clone());
            }
            create_stmt.col(&mut col_def);
        }

        if pk_cols.len() > 1 {
            let pk_name = format!("pk_{}", dto.table_name);
            let mut pk_index = Index::create().name(&pk_name).to_owned();
            for col_name in &pk_cols {
                pk_index.col(Alias::new(*col_name));
            }
            create_stmt.primary_key(&mut pk_index);
        }

        if let Some(ref comment) = dto.table_comment
            && !comment.is_empty()
        {
            create_stmt.comment(comment.clone());
        }

        Ok(create_stmt)
    }

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
        if !dto
            .table_name
            .chars()
            .next()
            .map(|c| c.is_ascii_alphabetic())
            .unwrap_or(false)
        {
            return Err(ServiceError::bad_request(&crate::tr!(
                "error.gen.table_name_start"
            )));
        }

        // 2. 查重：检查表是否已存在
        if self.repo.find_by_name(&dto.table_name).await?.is_some() {
            return Err(ServiceError::bad_request(&crate::tr!(
                "error.gen.table_already_in_gen",
                name = &dto.table_name
            )));
        }
        if self.is_db_table_exists(&dto.table_name).await? {
            return Err(ServiceError::bad_request(&crate::tr!(
                "error.gen.table_already_in_db",
                name = &dto.table_name
            )));
        }

        // 3. 校验所有列
        let mut col_names = std::collections::HashSet::new();
        for col in &dto.columns {
            validate_identifier(&col.column_name, "列名")?;
            if !col_names.insert(col.column_name.as_str()) {
                return Err(ServiceError::bad_request(&crate::tr!(
                    "error.gen.column_name_duplicate",
                    name = &col.column_name
                )));
            }
            // 类型与长度/精度一致性校验
            if col.data_type.needs_length() && col.length.is_none() {
                return Err(ServiceError::bad_request(&crate::tr!(
                    "error.gen.column_type_length_required",
                    name = &col.column_name,
                    ty = format!("{:?}", col.data_type)
                )));
            }
            if col.data_type.needs_precision() && col.precision.is_none() {
                return Err(ServiceError::bad_request(&crate::tr!(
                    "error.gen.column_decimal_scale_required",
                    name = &col.column_name
                )));
            }
            if let (Some(len), Some(prec)) = (col.length, col.precision)
                && prec >= len
            {
                return Err(ServiceError::bad_request(&crate::tr!(
                    "error.gen.column_decimal_scale_invalid",
                    name = &col.column_name,
                    scale = prec,
                    length = len
                )));
            }
            // 自增必须为主键且为整数类型
            if col.is_auto_increment {
                if !col.is_primary_key {
                    return Err(ServiceError::bad_request(&crate::tr!(
                        "error.gen.column_auto_inc_no_pk",
                        name = &col.column_name
                    )));
                }
                if !matches!(col.data_type, ColumnDataType::Int | ColumnDataType::Bigint) {
                    return Err(ServiceError::bad_request(&crate::tr!(
                        "error.gen.column_auto_inc_not_int",
                        name = &col.column_name,
                        ty = format!("{:?}", col.data_type)
                    )));
                }
            }
        }

        // 4. 至少一个主键（推荐但非强制，SQLite 允许无主键表）
        let has_pk = dto.columns.iter().any(|c| c.is_primary_key);
        if !has_pk {
            tracing::warn!("表 {} 未定义主键", dto.table_name);
        }

        // 5+6. 构造 sea-query 建表语句并按当前数据库方言生成 SQL
        // 语句构造逻辑抽离至 build_create_table_sql（便于单测覆盖主键约束生成，见 gen_table_sql_tests）
        let db = self.repo.base().db();
        let backend = db.get_database_backend();
        let create_stmt = Self::build_create_table_sql(&dto)?;
        let sql = backend.build(&create_stmt).to_string();

        tracing::info!("结构化建表 SQL: {}", sql);

        // 执行 DDL
        // P2 修复: 错误详情写日志，对外仅返回通用文案，避免泄露 DB schema 细节
        db.execute_raw(backend.build(&create_stmt))
            .await
            .map_err(|e| {
                tracing::error!(error = %e, table = %dto.table_name, "建表执行失败");
                ServiceError::internal(&crate::tr!("error.gen.create_table_failed"))
            })?;

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
        let (rows, _) = self
            .repo
            .find_db_tables(0, 1, Some(table_name), None, None)
            .await?;
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
            .ok_or_else(|| ServiceError::not_found(&crate::tr!("error.gen.table_not_found")))?;

        let now = crate::common::datetime::now_naive();
        // 审计合规域：变更前快照（existing 被 into() 转移前计算）
        let before_snapshot = serde_json::to_value(&existing).unwrap_or(serde_json::Value::Null);
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

        am.update_by = Set(Some(operator.to_string()));
        am.update_time = Set(Some(now));

        // 如果有列信息，更新列（先删后插）——列 ActiveModel 预构建于事务外（只读 dto）
        let column_ams_opt: Option<Vec<GenTableColumnActiveModel>> = dto.columns.map(|columns| {
            columns
                .into_iter()
                .map(|col| GenTableColumnActiveModel {
                    table_id: Set(dto.table_id),
                    column_name: Set(col.column_name),
                    column_comment: Set(col.column_comment),
                    column_type: Set(col.column_type),
                    rust_type: Set(col.rust_type),
                    rust_field: Set(col.rust_field),
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
                })
                .collect()
        });

        // 单事务：主表更新 + 审计留痕 + 列先删后插原子化
        // （原实现主表裸写 + 列独立事务，存在"主表已更新、列更新失败"的不一致窗口——一并修复）
        let repo = self.repo.clone();
        let table_id = dto.table_id;
        let model = repo
            .base()
            .db()
            .transaction::<_, GenTableModel, ServiceError>(|txn| {
                let repo = repo.clone();
                let am = am;
                let before_snapshot = before_snapshot.clone();
                let column_ams_inner = column_ams_opt.clone();
                let operator = operator.to_string();
                Box::pin(async move {
                    // 主表更新
                    let model = repo.base().update_conn(txn, am).await?;
                    // 审计合规域：UPDATE 变更留痕（同事务提交/回滚；gen_table_column 明细
                    // 随表行快照语义覆盖，不逐列重复留痕）
                    crate::service::sys_audit_change_service::audit_update(
                        txn,
                        "gen_table",
                        &model.table_id.to_string(),
                        &before_snapshot,
                        &model,
                        None, // update_table 签名仅携带操作人用户名，ID 由回查补齐
                        Some(operator.as_str()),
                    )
                    .await?;
                    // 列先删后插（有提交列信息时）
                    if let Some(cols) = column_ams_inner {
                        repo.update_columns_conn(txn, table_id, cols).await?;
                    }
                    Ok(model)
                })
            })
            .await
            .map_err(|e| match e {
                sea_orm::TransactionError::Transaction(se) => se,
                sea_orm::TransactionError::Connection(db_err) => {
                    tracing::error!("编辑表事务连接错误: {}", db_err);
                    ServiceError::internal(&crate::tr!("error.common.tx_failed"))
                }
            })?;

        Ok(model)
    }

    /// 批量删除代码生成业务表（级联清理列记录）
    pub async fn delete_tables(&self, table_ids: Vec<i64>) -> Result<(), ServiceError> {
        if table_ids.is_empty() {
            return Ok(());
        }
        // 批量校验存在性（单次查询替代 N 次 find_by_id）
        // b130：先去重保序再判缺失——`?ids=735,735` 是完全合法的幂等请求，
        // 用原始长度当分母会把它判成「不存在」并零删除（台账 b130 §1）。
        let table_ids = crate::common::batch_ids::dedupe_preserving_order(&table_ids);
        let existing = self.repo.find_by_ids(table_ids.clone()).await?;
        if existing.len() != table_ids.len() {
            let existing_ids: std::collections::HashSet<i64> =
                existing.iter().map(|t| t.table_id).collect();
            for id in &table_ids {
                if !existing_ids.contains(id) {
                    return Err(ServiceError::not_found(&crate::tr!(
                        "error.gen.table_id_not_found",
                        id = id
                    )));
                }
            }
        }
        // P1 修复: 级联删除需在事务中执行，避免列删除成功但表删除失败时产生孤儿数据
        let repo = self.repo.clone();
        self.repo
            .base()
            .db()
            .transaction::<_, (), ServiceError>(|txn| {
                let table_ids_inner = table_ids.clone();
                let before_snapshot = existing.clone();
                async move {
                    // 级联清理列
                    repo.delete_columns_by_table_ids_conn(txn, table_ids_inner.clone())
                        .await?;
                    // 删除表
                    repo.delete_by_ids_conn(txn, table_ids_inner).await?;
                    // 审计合规域：DELETE 变更留痕（同事务提交/回滚；逐表 before 快照）
                    for t in &before_snapshot {
                        crate::service::sys_audit_change_service::audit_delete(
                            txn,
                            "gen_table",
                            &t.table_id.to_string(),
                            t,
                            None, // delete 签名无操作人上下文，操作人两列留空（列可空）
                            None,
                        )
                        .await?;
                    }
                    Ok(())
                }
                .boxed()
            })
            .await
            .map_err(|e| match e {
                sea_orm::TransactionError::Transaction(se) => se,
                sea_orm::TransactionError::Connection(db_err) => {
                    tracing::error!("代码生成表删除事务连接错误: {}", db_err);
                    ServiceError::internal(&crate::tr!("error.common.tx_failed"))
                }
            })?;
        Ok(())
    }

    /// 同步数据库（从数据库更新表字段信息）
    ///
    /// 流程：
    /// 1. 根据 table_name 读取最新数据库列元数据
    /// 2. 删除旧的 gen_table_column 记录
    /// 3. 重新生成 gen_table_column 记录
    pub async fn synch_db(&self, table_name: &str, operator: &str) -> Result<(), ServiceError> {
        let table = self.repo.find_by_name(table_name).await?.ok_or_else(|| {
            ServiceError::not_found(&crate::tr!(
                "error.gen.table_not_imported",
                name = table_name
            ))
        })?;

        let columns: Vec<DbColumnInfo> = self.repo.find_db_columns(table_name).await?;
        if columns.is_empty() {
            return Err(ServiceError::not_found(&crate::tr!(
                "error.gen.table_no_columns",
                name = table_name
            )));
        }

        let now = crate::common::datetime::now_naive();
        let mut column_ams: Vec<GenTableColumnActiveModel> = Vec::new();
        for (idx, col) in columns.iter().enumerate() {
            let rust_type = column_type_to_rust_type(&col.column_type);
            let rust_field = column_name_to_rust_field(&col.column_name);
            let is_pk = if col.column_key == "PRI" { "1" } else { "0" };
            let is_increment = if col.extra.contains("auto_increment") {
                "1"
            } else {
                "0"
            };
            let is_required = if col.is_nullable == "NO" && is_pk == "0" {
                "1"
            } else {
                "0"
            };
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
                rust_type: Set(Some(rust_type)),
                rust_field: Set(Some(rust_field)),
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
        // P1 修复: 先删后插需在事务中执行，避免删除成功但插入失败时列记录全部丢失
        let repo = self.repo.clone();
        let table_id = table.table_id;
        self.repo
            .base()
            .db()
            .transaction::<_, (), ServiceError>(|txn| {
                let column_ams_inner = column_ams.clone();
                async move {
                    repo.update_columns_conn(txn, table_id, column_ams_inner)
                        .await?;
                    Ok(())
                }
                .boxed()
            })
            .await
            .map_err(|e| match e {
                sea_orm::TransactionError::Transaction(se) => se,
                sea_orm::TransactionError::Connection(db_err) => {
                    tracing::error!("同步数据库事务连接错误: {}", db_err);
                    ServiceError::internal(&crate::tr!("error.common.tx_failed"))
                }
            })?;
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
            .ok_or_else(|| ServiceError::not_found(&crate::tr!("error.gen.table_not_found")))?;
        let columns = self.repo.find_columns_by_table_id(table_id).await?;

        Self::render_templates(&info, &columns)
    }

    /// 生成代码（返回 ZIP 文件字节流）
    ///
    /// `path_prefix` 是**压缩包内路径前缀**（b139）。改造前后端从不读 `gen_table.gen_path`、
    /// 也从不写磁盘，而前端提示写着"成功生成到自定义路径：{path}"——一个字段存了 140 轮
    /// 却没有任何消费者，用户点了只得到一句谎报。现在它决定 ZIP 条目路径：
    /// 留空/只有分隔符 = 平铺；`module/system` = 全部条目落在该目录下。
    pub async fn gen_code(
        &self,
        table_name: &str,
        path_prefix: Option<&str>,
    ) -> Result<Vec<u8>, ServiceError> {
        let table = self.repo.find_by_name(table_name).await?.ok_or_else(|| {
            ServiceError::not_found(&crate::tr!(
                "error.gen.table_not_imported",
                name = table_name
            ))
        })?;
        let columns = self.repo.find_columns_by_table_id(table.table_id).await?;

        let files = Self::render_templates(&table, &columns)?;
        let prefix = sanitize_zip_path_prefix(path_prefix)?;

        // 打包为 ZIP
        let mut buf = Vec::new();
        {
            let mut zip = zip::ZipWriter::new(std::io::Cursor::new(&mut buf));
            let options = zip::write::SimpleFileOptions::default()
                .compression_method(zip::CompressionMethod::Deflated);

            for (path, content) in &files {
                let entry = if prefix.is_empty() {
                    path.clone()
                } else {
                    format!("{}/{}", prefix, path)
                };
                zip.start_file(&entry, options).map_err(|_| {
                    ServiceError::internal(&crate::tr!("error.gen.zip_write_failed"))
                })?;
                use std::io::Write;
                zip.write_all(content.as_bytes()).map_err(|_| {
                    ServiceError::internal(&crate::tr!("error.gen.zip_write_failed"))
                })?;
            }
            zip.finish()
                .map_err(|_| ServiceError::internal(&crate::tr!("error.gen.zip_finish_failed")))?;
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
        if table_names.is_empty() {
            return Ok(Vec::new());
        }
        // 批量查询表与列（消除 N+1：原实现每表 2 次 DB 查询，现降为 2 次总查询）
        let tables = self.repo.find_by_names(table_names.to_vec()).await?;
        // 按 table_name 建立索引以便按入参顺序查找（保持原循环顺序）
        let table_by_name: HashMap<&str, &GenTableModel> =
            tables.iter().map(|t| (t.table_name.as_str(), t)).collect();
        let table_ids: Vec<i64> = tables.iter().map(|t| t.table_id).collect();
        let all_columns = self.repo.find_columns_by_table_ids(table_ids).await?;
        // 按 table_id 分组列（查询已按 table_id、sort 升序，分组后每表内列顺序保持不变）
        let mut columns_by_table: HashMap<i64, Vec<GenTableColumnModel>> = HashMap::new();
        for col in all_columns {
            columns_by_table.entry(col.table_id).or_default().push(col);
        }

        let mut buf = Vec::new();
        {
            let mut zip = zip::ZipWriter::new(std::io::Cursor::new(&mut buf));
            let options = zip::write::SimpleFileOptions::default()
                .compression_method(zip::CompressionMethod::Deflated);

            for table_name in table_names {
                let table = table_by_name.get(table_name.as_str()).ok_or_else(|| {
                    ServiceError::not_found(&crate::tr!(
                        "error.gen.table_not_imported",
                        name = table_name
                    ))
                })?;
                let columns = columns_by_table
                    .get(&table.table_id)
                    .cloned()
                    .unwrap_or_default();
                let files = Self::render_templates(table, &columns)?;

                // 表名子目录前缀（已在 handler 层做白名单校验，仅含字母/数字/下划线，无路径穿越风险）
                let prefix = sanitize_path_component(table_name)?;
                for (path, content) in &files {
                    // 在原路径前加 `{table_name}/` 前缀，避免多表文件名冲突
                    let prefixed_path = format!("{}/{}", prefix, path);
                    zip.start_file(&prefixed_path, options).map_err(|_| {
                        ServiceError::internal(&crate::tr!("error.gen.zip_write_failed"))
                    })?;
                    use std::io::Write;
                    zip.write_all(content.as_bytes()).map_err(|_| {
                        ServiceError::internal(&crate::tr!("error.gen.zip_write_failed"))
                    })?;
                }
            }

            zip.finish()
                .map_err(|_| ServiceError::internal(&crate::tr!("error.gen.zip_finish_failed")))?;
        }

        Ok(buf)
    }

    /// 渲染所有模板
    ///
    /// 模板从内嵌字符串加载（编译时嵌入），避免运行时文件依赖
    fn render_templates(
        table: &GenTableModel,
        columns: &[GenTableColumnModel],
    ) -> Result<PreviewCodeVo, ServiceError> {
        // 模板注册表为进程级单例（b71：8 份模板是 `include_str!` 编译期常量，
        // 原实现每次请求重新解析编译一遍；过滤器与模板的注册次序见 `build_gen_tera`）
        let tera = GEN_TERA
            .as_ref()
            .map_err(|_| ServiceError::internal(&crate::tr!("error.gen.template_load_failed")))?;

        // 构建上下文
        let mut ctx = tera::Context::new();
        ctx.insert("table", table);
        ctx.insert("columns", columns);

        // W-18：flow（审批单据）模板开关
        //
        // `tpl_category = "flow"` 时，7 处模板（entity / service / handler / router /
        // api / index / migration）按 `{% if is_flow %}` 追加「审批投影列 + 提交审批动作」，
        // 其余部分与 crud 完全一致——避免为模板差异复制 7 份文件造成双维护。
        // 生成的适配层调用真实引擎（`engine_open_round` + `resolve_node_assignees`），
        // 不产生 mock 或占位实现。
        let is_flow = table.tpl_category.as_deref() == Some("flow");
        ctx.insert("is_flow", &is_flow);

        // entity 模板是否需要 `use chrono::NaiveDateTime;`：
        // ① flow 投影列（submitted_at / finished_at）固定需要；② 任一时态列需要。
        // 在 Rust 侧判定后注入（与 is_flow 同款做法），避免模板内做集合推导。
        let needs_naive = is_flow
            || columns.iter().any(|c| {
                c.rust_type
                    .as_deref()
                    .is_some_and(|t| t.contains("NaiveDateTime"))
            });
        ctx.insert("needs_naive", &needs_naive);

        // 提取主键字段
        let pk_column = columns.iter().find(|c| c.is_pk.as_deref() == Some("1"));
        ctx.insert("pk_column", &pk_column);

        // 多租户感知（gen-tenant 修复，2026-10-05）：列清单含 `tenant_id` 列时，
        // service/handler 模板生成租户归属与过滤逻辑——写入归属由 operator 决定
        // （防 dto 前端伪造），读改删按 `tenant_scope: Option<i64>` 收敛（None = 平台全量，
        // 对齐项目 tenant_scope 范式）。
        let has_tenant_id = columns
            .iter()
            .any(|c| c.column_name.as_deref() == Some("tenant_id"));
        ctx.insert("has_tenant_id", &has_tenant_id);

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
            (
                "entity.rs",
                "entity.rs",
                format!("src/entity/{}.rs", table_name_safe),
            ),
            (
                "repository.rs",
                "repository.rs",
                format!("src/repository/{}.rs", table_name_safe),
            ),
            (
                "service.rs",
                "service.rs",
                format!("src/service/{}_service.rs", table_name_safe),
            ),
            (
                "handler.rs",
                "handler.rs",
                format!("src/handler/{}_handler.rs", table_name_safe),
            ),
            (
                "router.rs",
                "router.rs",
                format!("src/router/{}_router.rs", table_name_safe),
            ),
            (
                "api.ts",
                "api.ts",
                format!("src/api/{}/{}.ts", module_name_safe, table_name_safe),
            ),
            (
                "index.vue",
                "index.vue",
                format!(
                    "src/views/{}/{}/index.vue",
                    module_name_safe, table_name_safe
                ),
            ),
            (
                "migration.sql",
                "migration.sql",
                format!("migration/{}.sql", table_name_safe),
            ),
        ];

        let mut result: BTreeMap<String, String> = BTreeMap::new();
        for (tpl_name, _alias, out_path) in templates {
            let rendered = tera.render(tpl_name, &ctx).map_err(|e| {
                // 包含完整的错误链信息（Tera 错误通常有嵌套 source）
                let full_msg = format!("{}", e);
                let source_msg = e.source().map(|s| format!("{}", s)).unwrap_or_default();
                let detail = if source_msg.is_empty() {
                    crate::tr!(
                        "error.gen.template_render_failed",
                        name = tpl_name,
                        msg = full_msg
                    )
                } else {
                    crate::tr!(
                        "error.gen.template_render_failed",
                        name = tpl_name,
                        msg = format!("{} -> {}", full_msg, source_msg)
                    )
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

/// 清洗 ZIP 条目路径前缀（b139，`gen_code` 的 `path` 参数）。
///
/// 语义是**包内目录**，不是磁盘路径。三类输入必须挡住：
/// 1. 绝对路径（`/x`、`C:\x`）——部分解压器会把它解释为落盘根目录；
/// 2. `..` 段——Zip Slip：解压器若不做二次校验就会写到包外；
/// 3. 反斜杠 / NUL / 控制字符——不同解压器对分隔符与转义的解释不一致。
///
/// 空串或只含分隔符 = 平铺（与参数缺省同义，不是错误）。每段复用
/// [`sanitize_path_component`]，与批量生成的表名子目录同一套判据。
fn sanitize_zip_path_prefix(raw: Option<&str>) -> Result<String, ServiceError> {
    const MAX_PREFIX_LEN: usize = 200;
    let Some(raw) = raw else {
        return Ok(String::new());
    };
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Ok(String::new());
    }
    if trimmed.len() > MAX_PREFIX_LEN
        || trimmed.contains('\\')
        || trimmed.contains('\0')
        || trimmed.chars().any(|c| c.is_control())
    {
        return Err(ServiceError::bad_request(&crate::tr!(
            "error.gen.path_component_invalid",
            name = raw
        )));
    }
    // 连续的 `/` 与 `.` 段按"无意义"处理（`a//b` == `a/b`），不当作错误——
    // 用户的输入习惯不该让一次生成失败，但目录语义必须归一。
    let segments: Vec<&str> = trimmed
        .split('/')
        .filter(|s| !s.is_empty() && *s != ".")
        .collect();
    // 只有分隔符（数据库 `gen_path` 的默认值就是 `/`）⇒ 平铺，不是绝对路径错误。
    if segments.is_empty() {
        return Ok(String::new());
    }
    // 到这里还有段却以 `/` 开头 ⇒ 绝对路径（`/etc`），部分解压器会落盘到根目录。
    if trimmed.starts_with('/') {
        return Err(ServiceError::bad_request(&crate::tr!(
            "error.gen.path_component_invalid",
            name = raw
        )));
    }
    let mut clean: Vec<String> = Vec::with_capacity(segments.len());
    for seg in segments {
        let clean_seg = sanitize_path_component(seg)?;
        // ZIP 条目名要跨平台可解压：Windows 的保留字符在解压时会被拒绝或截断，
        // 与其让用户拿到一个"在某台机器上解不开"的包，不如在入口直接说清楚。
        if clean_seg
            .chars()
            .any(|c| matches!(c, '<' | '>' | ':' | '"' | '|' | '?' | '*'))
        {
            return Err(ServiceError::bad_request(&crate::tr!(
                "error.gen.path_component_invalid",
                name = seg
            )));
        }
        clean.push(clean_seg);
    }
    Ok(clean.join("/"))
}

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
        return Err(ServiceError::bad_request(&crate::tr!(
            "error.gen.path_empty_component"
        )));
    }
    if name.contains("..") || name.contains('/') || name.contains('\\') {
        return Err(ServiceError::bad_request(&crate::tr!(
            "error.gen.path_component_invalid",
            name = name
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

// ==================== Tera 模板（外置 templates/ 目录） ====================

// 模板内容外置于 `templates/` 目录，通过 include_str! 在编译期嵌入，
// 避免 gen_table_service.rs 体积过大，同时便于独立编辑与版本管理。
// 各模板与 gen_code / preview 流程一一对应，修改模板后无需改动服务代码。

/// Entity 模板
const ENTITY_TEMPLATE: &str = include_str!("../../templates/entity.tera");
/// Repository 模板
const REPOSITORY_TEMPLATE: &str = include_str!("../../templates/repository.tera");
/// Service 模板
const SERVICE_TEMPLATE: &str = include_str!("../../templates/service.tera");
/// Handler 模板
const HANDLER_TEMPLATE: &str = include_str!("../../templates/handler.tera");
/// Router 模板
const ROUTER_TEMPLATE: &str = include_str!("../../templates/router.tera");
/// 前端 API 模板（TypeScript）
const API_TS_TEMPLATE: &str = include_str!("../../templates/api.tera");
/// 前端页面模板（Vue）
const INDEX_VUE_TEMPLATE: &str = include_str!("../../templates/index.tera");
/// SQL 迁移脚本模板
const MIGRATION_SQL_TEMPLATE: &str = include_str!("../../templates/migration.tera");

/// 构造代码生成器模板注册表。
///
/// 过滤器必须**先于**模板注册：Tera 2.0 在 `add_raw_templates` 时即编译模板，
/// 晚注册过滤器会报 "Unknown filter"。
fn build_gen_tera() -> TeraResult<Tera> {
    let mut tera = Tera::default();
    tera.register_filter("pascal_case", pascal_case_filter);
    tera.register_filter("camel_case", camel_case_filter);
    tera.register_filter("upper_camel", upper_camel_filter);
    tera.add_raw_templates(vec![
        ("entity.rs", ENTITY_TEMPLATE),
        ("repository.rs", REPOSITORY_TEMPLATE),
        ("service.rs", SERVICE_TEMPLATE),
        ("handler.rs", HANDLER_TEMPLATE),
        ("router.rs", ROUTER_TEMPLATE),
        ("api.ts", API_TS_TEMPLATE),
        ("index.vue", INDEX_VUE_TEMPLATE),
        ("migration.sql", MIGRATION_SQL_TEMPLATE),
    ])?;
    Ok(tera)
}

/// b71 性能治理：8 份模板全为 `include_str!` 编译期常量，原实现**每次请求**
/// （`gen_code` / `preview` / `batchGenCode` / ZIP 下载）重新解析编译一遍。
/// 提为进程级单例后只编译一次；渲染期只读（`Tera::render` 取 `&self`）。
///
/// 缓存的是 `TeraResult`：编译失败被**固化**为持续 500（走既有
/// `error.gen.template_load_failed` 契约），而不是把构建期问题升级成请求路径 panic。
static GEN_TERA: std::sync::LazyLock<TeraResult<Tera>> = std::sync::LazyLock::new(build_gen_tera);

#[cfg(test)]
mod gen_table_sql_tests {
    use super::*;
    use sea_orm::DatabaseBackend;

    fn mk_col(
        name: &str,
        pk: bool,
        not_null: bool,
        auto_inc: bool,
        unique: bool,
    ) -> CreateTableColumnDto {
        CreateTableColumnDto {
            column_name: name.to_string(),
            data_type: ColumnDataType::Bigint,
            length: None,
            precision: None,
            is_primary_key: pk,
            is_auto_increment: auto_inc,
            is_not_null: not_null,
            is_unique: unique,
            default_value: None,
            column_comment: None,
        }
    }

    fn mk_dto(columns: Vec<CreateTableColumnDto>) -> CreateTableDto {
        CreateTableDto {
            table_name: "demo_tbl".to_string(),
            table_comment: None,
            columns,
            import_to_gen: false,
        }
    }

    #[test]
    fn test_single_pk_generates_primary_key() {
        // 单列主键必须生成 PRIMARY KEY 约束（修复：原实现仅 NOT NULL 导致生成表缺失 PK）
        let dto = mk_dto(vec![
            mk_col("id", true, true, true, false),
            mk_col("name", false, true, false, false),
        ]);
        let stmt = GenTableService::build_create_table_sql(&dto).unwrap();
        let sql = DatabaseBackend::Sqlite.build(&stmt).to_string();
        assert!(
            sql.to_uppercase().contains("PRIMARY KEY"),
            "单列主键应生成 PRIMARY KEY，实际 SQL: {}",
            sql
        );
    }

    #[test]
    fn test_composite_pk_generates_primary_key() {
        let dto = mk_dto(vec![
            mk_col("tenant_id", true, true, false, false),
            mk_col("id", true, true, false, false),
            mk_col("val", false, true, false, false),
        ]);
        let stmt = GenTableService::build_create_table_sql(&dto).unwrap();
        let sql = DatabaseBackend::Sqlite.build(&stmt).to_string();
        assert!(
            sql.to_uppercase().contains("PRIMARY KEY"),
            "复合主键应生成 PRIMARY KEY，实际 SQL: {}",
            sql
        );
    }

    #[test]
    fn test_no_pk_has_no_primary_key() {
        let dto = mk_dto(vec![mk_col("id", false, true, false, false)]);
        let stmt = GenTableService::build_create_table_sql(&dto).unwrap();
        let sql = DatabaseBackend::Sqlite.build(&stmt).to_string();
        assert!(
            !sql.to_uppercase().contains("PRIMARY KEY"),
            "无主键不应生成 PRIMARY KEY，实际 SQL: {}",
            sql
        );
    }
}

// ==================== 模板渲染测试（验证外置 templates/ 目录） ====================

/// 验证模板外置后 `include_str!` 嵌入的模板仍能正常渲染完整流程，
/// 保证 gen_code / preview 链路（8 个模板 → ZIP/预览）不受重构影响。
#[cfg(test)]
mod gen_table_template_tests {
    use super::*;

    fn mk_table() -> GenTableModel {
        GenTableModel {
            table_id: 1,
            table_name: "sys_user".to_string(),
            table_comment: Some("用户表".to_string()),
            sub_table_name: None,
            sub_table_fk_name: None,
            class_name: Some("SysUser".to_string()),
            tpl_category: Some("crud".to_string()),
            tpl_web_type: Some("element-plus".to_string()),
            package_name: Some("stepby".to_string()),
            module_name: Some("system".to_string()),
            business_name: Some("user".to_string()),
            function_name: Some("用户管理".to_string()),
            function_author: Some("stepby".to_string()),
            gen_type: Some("0".to_string()),
            gen_path: Some("/".to_string()),
            options: None,
            create_by: None,
            create_time: None,
            update_by: None,
            update_time: None,
            remark: None,
        }
    }

    fn mk_column() -> GenTableColumnModel {
        GenTableColumnModel {
            column_id: 1,
            table_id: 1,
            column_name: Some("user_id".to_string()),
            column_comment: Some("用户ID".to_string()),
            column_type: Some("BIGINT".to_string()),
            rust_type: Some("i64".to_string()),
            rust_field: Some("user_id".to_string()),
            is_pk: Some("1".to_string()),
            is_increment: Some("1".to_string()),
            is_required: Some("1".to_string()),
            is_insert: Some("0".to_string()),
            is_edit: Some("0".to_string()),
            is_list: Some("0".to_string()),
            is_query: Some("0".to_string()),
            query_type: Some("EQ".to_string()),
            html_type: Some("input".to_string()),
            dict_type: Some(String::new()),
            sort: Some(1),
            create_by: None,
            create_time: None,
            update_by: None,
            update_time: None,
        }
    }

    #[test]
    fn test_render_templates_externalized() {
        let table = mk_table();
        let columns = vec![mk_column()];
        let files = GenTableService::render_templates(&table, &columns).unwrap();

        // 8 个模板均应渲染成功
        assert_eq!(files.len(), 8, "应渲染 8 个文件，实际 {}", files.len());

        // entity.rs：包含实体结构体与表名注解
        let entity = files
            .get("src/entity/sys_user.rs")
            .expect("缺少 entity.rs 文件");
        assert!(entity.contains("pub struct Model"), "entity 缺少结构体");
        assert!(entity.contains("#[sea_orm(table_name = \"sys_user\")]"));

        // repository.rs：包含 Repository 与类名
        let repo = files
            .get("src/repository/sys_user.rs")
            .expect("缺少 repository.rs 文件");
        assert!(repo.contains("SysUserRepository"));

        // service.rs：包含 Service 结构
        let service = files
            .get("src/service/sys_user_service.rs")
            .expect("缺少 service.rs 文件");
        assert!(service.contains("SysUserService"));

        // gen-tenant 修复断言：mk_column 列清单不含 tenant_id → 不生成租户过滤
        assert!(
            !service.contains("tenant_scope"),
            "无 tenant_id 列时不应生成租户过滤，实际片段: {}",
            &service[..service.len().min(600)]
        );
    }

    #[test]
    fn test_tenant_scope_generated_when_tenant_id_column_present() {
        // gen-tenant 修复（2026-10-05）：列含 tenant_id 时——
        // ① service 查询生成 tenant_scope 过滤（读路径租户隔离）
        // ② create 由 operator_tid 决定租户归属（防 dto 前端伪造）
        // ③ router 生成 PERM_ROUTE_TABLE 集成清单注释（权限登记防遗漏）
        let table = mk_table();
        let mut tenant_col = mk_column();
        tenant_col.column_name = Some("tenant_id".to_string());
        tenant_col.rust_field = Some("tenant_id".to_string());
        tenant_col.is_pk = Some("0".to_string());
        tenant_col.is_insert = Some("1".to_string());
        tenant_col.is_edit = Some("0".to_string());
        let id_col = mk_column();
        let columns = vec![id_col, tenant_col];
        let files = GenTableService::render_templates(&table, &columns).unwrap();

        let service = files
            .get("src/service/sys_user_service.rs")
            .expect("缺少 service.rs 文件");
        assert!(
            service.contains("tenant_scope: Option<i64>"),
            "含 tenant_id 列时应生成 tenant_scope 过滤参数"
        );
        assert!(
            service.contains("Column::TenantId.eq(tid)"),
            "查询应生成 TenantId 过滤"
        );
        assert!(
            service.contains("am.tenant_id = Set(operator_tid)"),
            "create 应由 operator_tid 决定租户归属（防 dto 伪造）"
        );

        let handler = files
            .get("src/handler/sys_user_handler.rs")
            .expect("缺少 handler.rs 文件");
        assert!(
            handler.contains("tenant_scope_of"),
            "handler 应生成 tenant_scope 提取 helper"
        );

        let router = files
            .get("src/router/sys_user_router.rs")
            .expect("缺少 router.rs 文件");
        assert!(
            router.contains("PERM_ROUTE_TABLE"),
            "router 应含权限映射集成清单注释（防权限空洞）"
        );
        assert!(
            router.contains("sys_menu"),
            "router 集成清单应提示菜单种子登记"
        );
    }

    #[test]
    fn test_render_templates_externalized_tail_assertions() {
        let table = mk_table();
        let columns = vec![mk_column()];
        let files = GenTableService::render_templates(&table, &columns).unwrap();

        // handler.rs：包含 Handler 函数
        let handler = files
            .get("src/handler/sys_user_handler.rs")
            .expect("缺少 handler.rs 文件");
        assert!(handler.contains("pub async fn list"));

        // router.rs：包含路由注册
        let router = files
            .get("src/router/sys_user_router.rs")
            .expect("缺少 router.rs 文件");
        assert!(router.contains("Router"));

        // api.ts：包含 request 引用
        let api = files
            .get("src/api/system/sys_user.ts")
            .expect("缺少 api.ts 文件");
        assert!(api.contains("from '@/utils/request'"));

        // index.vue：包含 template 标签
        let vue = files
            .get("src/views/system/sys_user/index.vue")
            .expect("缺少 index.vue 文件");
        assert!(vue.contains("<template>"));

        // migration.sql：包含 CREATE TABLE
        let sql = files
            .get("migration/sys_user.sql")
            .expect("缺少 migration.sql 文件");
        assert!(sql.to_uppercase().contains("CREATE TABLE"));
    }

    /// W-18：`tpl_category = "flow"`（审批单据）应生成**真实可用**的审批适配层：
    /// 审批投影列 + 提交审批动作（调用真实引擎 `engine_open_round` / 复用
    /// `resolve_node_assignees`）；且普通 crud 分类**不得**混入审批内容。
    #[test]
    fn test_render_templates_flow_category_emits_approval_adapter() {
        let mut table = mk_table();
        table.tpl_category = Some("flow".to_string());
        let columns = vec![mk_column()];
        let files = GenTableService::render_templates(&table, &columns).unwrap();

        // flow 与 crud 的输出文件集合一致（仅内容按 is_flow 分支差异）
        assert_eq!(files.len(), 8, "flow 应仍输出 8 个文件");

        // entity：审批投影列
        let entity = files
            .get("src/entity/sys_user.rs")
            .expect("缺少 entity.rs 文件");
        for field in [
            "pub status: String",
            "pub current_round: i32",
            "pub current_node_seq: Option<i32>",
            "pub applicant_id: Option<i64>",
            "pub applicant_name: Option<String>",
            "pub dept_id: Option<i64>",
            "pub submitted_at: Option<NaiveDateTime>",
            "pub finished_at: Option<NaiveDateTime>",
        ] {
            assert!(
                entity.contains(field),
                "flow 实体缺少审批投影列 `{field}`，实际:\n{entity}"
            );
        }

        // service：真实引擎接线（不得出现 mock/占位）
        let service = files
            .get("src/service/sys_user_service.rs")
            .expect("缺少 service.rs 文件");
        assert!(service.contains("pub const BIZ_TYPE: &str = \"sys_user\""));
        assert!(service.contains("pub fn flow_nodes() -> Vec<NodeSpec>"));
        assert!(service.contains("pub async fn submit_flow("));
        assert!(
            service.contains("engine_open_round("),
            "flow service 必须调用真实引擎开轮"
        );
        assert!(
            service.contains("resolve_node_assignees("),
            "flow service 必须复用引擎审批人解析（不得复制引擎规则）"
        );
        assert!(
            service.contains("biz_type::is_registered(BIZ_TYPE)"),
            "未登记业务类型必须显式失败（不静默放行）"
        );
        assert!(
            service.contains("rows_affected != 1"),
            "单据投影回写必须用条件更新做并发幂等"
        );
        // W-19：推进路径（/system/flow/act）需要注册项（链提供者 + 投影回写），
        // 只登记 ALL 会让审批通过/驳回时取不到注册项而失败
        assert!(
            service.contains("pub const fn flow_registration() -> BizTypeRegistration"),
            "flow service 必须生成登记项构造函数（供 biz_type::REGISTRY 追加）"
        );
        assert!(
            service.contains("fn flow_chain("),
            "flow service 必须生成审批链提供者（推进路径用）"
        );
        assert!(
            service.contains("fn flow_projection_sync("),
            "flow service 必须生成投影回写函数（推进路径用）"
        );
        assert!(
            service.contains("REGISTRY"),
            "登记说明必须指向 biz_type::REGISTRY（否则推进路径取不到注册项）"
        );
        // 归属 / 租户一致性校验（安全边界，缺失即可被越权提交）
        assert!(
            service.contains("error.gen.flow_only_applicant_can_submit"),
            "重提交必须校验仅原申请人可提交"
        );
        assert!(
            service.contains("error.gen.flow_tenant_mismatch"),
            "提交必须校验单据租户与申请人租户一致"
        );

        // handler / router / api：提交审批出入口
        let handler = files
            .get("src/handler/sys_user_handler.rs")
            .expect("缺少 handler.rs 文件");
        assert!(handler.contains("pub async fn submit_flow("));
        assert!(handler.contains(".submit_flow(id, applicant_id"));

        let router = files
            .get("src/router/sys_user_router.rs")
            .expect("缺少 router.rs 文件");
        assert!(router.contains("/system/sys_user/submit/{user_id}"));
        assert!(router.contains("sys_user_handler::submit_flow"));

        let api = files
            .get("src/api/system/sys_user.ts")
            .expect("缺少 api.ts 文件");
        assert!(api.contains("export function submitFlowSysUser(id: number)"));

        // index.vue：审批状态列 + 提交审批按钮
        let vue = files
            .get("src/views/system/sys_user/index.vue")
            .expect("缺少 index.vue 文件");
        assert!(vue.contains("审批状态"));
        assert!(vue.contains("handleSubmitFlow"));
        assert!(vue.contains("submitFlowSysUser"));

        // migration.sql：审批投影列 DDL
        let sql = files
            .get("migration/sys_user.sql")
            .expect("缺少 migration.sql 文件");
        assert!(sql.contains("status VARCHAR(16) NOT NULL DEFAULT 'draft'"));
        assert!(sql.contains("current_round INT NOT NULL DEFAULT 0"));

        // 反向：crud 分类不得泄漏任何审批内容
        let mut crud_table = table.clone();
        crud_table.tpl_category = Some("crud".to_string());
        let crud_files = GenTableService::render_templates(&crud_table, &columns).unwrap();
        let crud_service = crud_files
            .get("src/service/sys_user_service.rs")
            .expect("缺少 crud service.rs 文件");
        assert!(
            !crud_service.contains("submit_flow"),
            "crud 分类不应生成审批动作"
        );
        let crud_sql = crud_files
            .get("migration/sys_user.sql")
            .expect("缺少 crud migration.sql 文件");
        assert!(
            !crud_sql.contains("current_round"),
            "crud 分类不应包含审批投影列"
        );
        let crud_entity = crud_files
            .get("src/entity/sys_user.rs")
            .expect("缺少 crud entity.rs 文件");
        assert!(
            !crud_entity.contains("current_round"),
            "crud 实体不应包含审批投影列"
        );
    }

    /// 【第六轮】生成代码**真编译**校验暴露的 6 处缺陷的回归锁。
    ///
    /// 背景：`is_flow` 分支此前只做字符串断言，从未编译过。第六轮把 flow 分类渲染结果
    /// 落到 crate 内真实路径并跑 `cargo clippy --lib -- -D warnings`，暴露并修复：
    /// ① 时态列 `rust_type` 预包裹 `Option<...>` → 实体/DTO 二次包裹 `Option<Option<..>>`；
    /// ② 生成 service 从 `sys_flow_service` 顶层导入 `RoundChain`/`BizTypeRegistration`
    ///    （二者实际定义在 `biz_type` 子模块）→ 解析失败；
    /// ③ 生成 handler 用 camelCase AppState 字段名 + 非 snake_case 路由函数名（不符合本仓惯例）；
    /// ④ 生成 handler 导入未使用的 `Service` 类型；
    /// ⑤ 生成 entity 固定导入未使用的 `crate::common::datetime`；
    /// ⑥ 生成 service 的重提交归属校验用嵌套 if → clippy::collapsible_if。
    ///
    /// 本测试把这些「生成的 Rust 必须长什么样」钉死，防止模板回退。
    #[test]
    fn test_generated_code_is_clippy_clean_by_construction() {
        let dt = |name: &str| {
            let mut c = mk_column();
            c.column_name = Some(name.to_string());
            c.rust_field = Some(name.to_string());
            c.column_type = Some("DATETIME".to_string());
            c.rust_type = Some(column_type_to_rust_type("DATETIME"));
            c.is_pk = Some("0".to_string());
            c.is_required = Some("0".to_string());
            c.is_insert = Some("1".to_string());
            c.is_edit = Some("1".to_string());
            c.is_list = Some("1".to_string());
            c
        };

        // ---------- ① 时态列不得二次包裹 ----------
        let mut crud = mk_table();
        crud.tpl_category = Some("crud".to_string());
        let mut cols = vec![mk_column(), dt("create_time")];
        let files = GenTableService::render_templates(&crud, &cols).unwrap();
        let entity = files.get("src/entity/sys_user.rs").unwrap();
        assert!(
            !entity.contains("Option<Option<"),
            "时态列被二次包裹为 Option<Option<..>>，实际:\n{entity}"
        );
        assert!(
            entity.contains("pub create_time: Option<chrono::NaiveDateTime>"),
            "可空时态列应为 Option<chrono::NaiveDateTime>，实际:\n{entity}"
        );
        assert!(
            entity.contains("use chrono::NaiveDateTime;"),
            "含时态列的实体必须导入 NaiveDateTime，实际:\n{entity}"
        );
        // ⑤ 生成实体不得导入未使用的 datetime 辅助模块
        assert!(
            !entity.contains("use crate::common::datetime;"),
            "生成实体不应导入未使用的 crate::common::datetime，实际:\n{entity}"
        );
        // 生成 service 的 DTO 同样不得二次包裹
        let service_crud = files.get("src/service/sys_user_service.rs").unwrap();
        assert!(
            !service_crud.contains("Option<Option<"),
            "DTO 时态字段被二次包裹，实际:\n{service_crud}"
        );

        // 无时态列 + 非 flow ⇒ 不得导入 NaiveDateTime（否则 unused import）
        cols = vec![mk_column()];
        let files = GenTableService::render_templates(&crud, &cols).unwrap();
        let entity_plain = files.get("src/entity/sys_user.rs").unwrap();
        assert!(
            !entity_plain.contains("use chrono::NaiveDateTime;"),
            "无时态列且非 flow 的实体不应导入 NaiveDateTime，实际:\n{entity_plain}"
        );

        // ---------- flow 分类：② ③ ④ ⑥ ----------
        let mut flow = mk_table();
        flow.tpl_category = Some("flow".to_string());
        let files = GenTableService::render_templates(&flow, &cols).unwrap();

        // flow 投影列固定使用 NaiveDateTime
        let entity_flow = files.get("src/entity/sys_user.rs").unwrap();
        assert!(
            entity_flow.contains("use chrono::NaiveDateTime;"),
            "flow 实体（含投影列）必须导入 NaiveDateTime，实际:\n{entity_flow}"
        );

        // ② RoundChain / BizTypeRegistration 必须从 biz_type 子模块导入
        let service = files.get("src/service/sys_user_service.rs").unwrap();
        assert!(
            service.contains("biz_type::{self, BizTypeRegistration, RoundChain}"),
            "RoundChain/BizTypeRegistration 必须从 biz_type 子模块导入，实际:\n{service}"
        );
        assert!(
            !service.contains("ApproverPolicy, BizTypeRegistration"),
            "不得从 sys_flow_service 顶层导入 BizTypeRegistration（解析会失败），实际:\n{service}"
        );

        // ⑥ 重提交归属校验必须是 let-chain（嵌套 if 会触发 clippy::collapsible_if）
        assert!(
            service.contains(
                "if let Some(prev) = doc.applicant_id\n            && prev != applicant_id"
            ),
            "重提交归属校验应使用 let-chain 形式，实际:\n{service}"
        );

        // ③ ④ 生成的 Rust 标识符与 AppState 字段必须是 snake_case，且不导入未使用的 Service 类型
        let handler = files.get("src/handler/sys_user_handler.rs").unwrap();
        assert!(
            handler.contains("state.sys_user_service."),
            "handler 必须以 snake_case 表名访问 AppState 字段，实际:\n{handler}"
        );
        assert!(
            !handler.contains("sysUser_service"),
            "handler 不得使用 camelCase AppState 字段名，实际:\n{handler}"
        );
        assert!(
            !handler.contains("use crate::service::sys_user_service::SysUserService;"),
            "handler 不应导入未使用的 Service 类型，实际:\n{handler}"
        );

        let router = files.get("src/router/sys_user_router.rs").unwrap();
        assert!(
            router.contains("pub fn sys_user_routes()"),
            "路由注册函数名应为 snake_case，实际:\n{router}"
        );
        assert!(
            !router.contains("sysUser_routes"),
            "路由注册函数名不得为 camelCase，实际:\n{router}"
        );
    }

    /// 【第七轮】生成**前端**产物必须能通过 `vue-tsc --noEmit` 的回归锁。
    ///
    /// 背景：`api.tera` / `index.tera` 此前也从未被类型检查过。第七轮把 flow 分类渲染的
    /// `.ts` / `.vue` 落到 stepby-vue 真实路径并跑 `vue-tsc --noEmit`，暴露 3 处真实缺陷：
    /// ① `import { list } from '@/api/...'` 与页面内 `const list = ref([])` **重名冲突**
    ///    （TS2440）——**crud 与 flow 的所有生成页面都编译失败**；
    /// ② `:row-key="(row) => row.id"` 参数隐式 any（TS7006，本仓 `noImplicitAny`）；
    /// ③ `list(query: any)` 未标注返回类型 ⇒ 推断为 `AxiosResponse`，调用处
    ///    `res.rows` / `res.data` 报 TS2339（`request` 拦截器实际已解包为 `res.data`）。
    #[test]
    fn test_generated_frontend_is_typecheck_clean_by_construction() {
        let mut table = mk_table();
        table.tpl_category = Some("flow".to_string());
        let columns = vec![mk_column()];
        let files = GenTableService::render_templates(&table, &columns).unwrap();

        // ① API 函数名带实体前缀，杜绝与页面 `const list` 重名
        let api = files
            .get("src/api/system/sys_user.ts")
            .expect("缺少 api.ts");
        assert!(
            api.contains("export function listSysUser(query: any): Promise<any>"),
            "list 必须带实体前缀（避免与页面 const list 冲突），实际:\n{api}"
        );
        assert!(
            !api.contains("export function list("),
            "不得导出裸 `list`（会与页面局部 `const list` 冲突），实际:\n{api}"
        );
        // ③ 全部函数显式标注解包后的返回类型
        for sig in [
            "export function getSysUser(id: number): Promise<any>",
            "export function addSysUser(data: any): Promise<any>",
            "export function updateSysUser(data: any): Promise<any>",
            "export function delSysUser(id: number): Promise<any>",
            "export function submitFlowSysUser(id: number): Promise<any>",
        ] {
            assert!(
                api.contains(sig),
                "api.ts 缺少标注返回类型的签名 `{sig}`，实际:\n{api}"
            );
        }

        // ② 页面：导入前缀名 + `row-key` 用字符串属性名（不产生隐式 any）
        let vue = files
            .get("src/views/system/sys_user/index.vue")
            .expect("缺少 index.vue");
        assert!(
            vue.contains(
                "import { listSysUser, addSysUser, updateSysUser, delSysUser, submitFlowSysUser }"
            ),
            "页面必须导入带前缀的 API 函数，实际:\n{vue}"
        );
        assert!(
            vue.contains("await listSysUser({})"),
            "页面取列表必须调用带前缀的 API 函数，实际:\n{vue}"
        );
        assert!(
            vue.contains("row-key=\"userId\""),
            "row-key 应使用字符串属性名（避免隐式 any），实际:\n{vue}"
        );
        assert!(
            !vue.contains(":row-key=\"(row) =>"),
            "不得使用未标注类型的箭头函数作 row-key（TS7006），实际:\n{vue}"
        );
    }

    /// 【第八批】列类型映射必须只产出 **Rust 类型**（杜绝 Java 遗留值回潮）。
    ///
    /// 背景：`gen_table_column` 的两列原为早期 Java 版本的遗留命名 `java_type`/`java_field`
    /// （第八批已重命名为 `rust_type`/`rust_field`），而前端编辑表格的下拉此前
    /// 提供的是 **Java 类型**（`Long`/`Integer`/`BigDecimal`/`Date`…）——这些值会被
    /// 模板**原样**写进实体/DTO 字段声明 ⇒ 生成无法编译的 Rust。
    /// 本用例把"映射产出的类型集合"钉死，任何一侧回潮即红。
    #[test]
    fn test_column_type_mapping_only_emits_rust_types() {
        // 与 `entity/gen_table_column.rs` 的 `rust_type` 语义、以及前端
        // `views/tool/gen/editTable.vue` 的 `rustType` 下拉项**必须逐项一致**
        const CANONICAL: [&str; 8] = [
            "i64",
            "i8",
            "i16",
            "f32",
            "f64",
            "bool",
            "String",
            "chrono::NaiveDateTime",
        ];
        let cases = [
            ("BIGINT", "i64"),
            ("INT", "i64"),
            ("INTEGER", "i64"),
            ("TINYINT", "i8"),
            ("SMALLINT", "i16"),
            ("FLOAT", "f32"),
            ("DOUBLE", "f64"),
            ("DECIMAL(10,2)", "f64"),
            ("NUMERIC", "f64"),
            ("BOOLEAN", "bool"),
            ("DATE", "chrono::NaiveDateTime"),
            ("TIME", "chrono::NaiveDateTime"),
            ("DATETIME", "chrono::NaiveDateTime"),
            ("TIMESTAMP", "chrono::NaiveDateTime"),
            ("VARCHAR(100)", "String"),
            ("TEXT", "String"),
            ("CHAR(4)", "String"),
        ];
        for (physical, expect) in cases {
            let got = column_type_to_rust_type(physical);
            assert_eq!(
                got, expect,
                "物理类型 {physical} 应映射为 Rust 类型 {expect}"
            );
            assert!(
                CANONICAL.contains(&got.as_str()),
                "映射产出 `{got}` 不在规范 Rust 类型集合内（Java 遗留值回潮）"
            );
        }
        // 显式反例：Java 类型名不得出现在映射结果中
        for java_ty in ["Long", "Integer", "Double", "BigDecimal", "Date", "Boolean"] {
            assert!(
                !CANONICAL.contains(&java_ty),
                "规范集合不得含 Java 类型 `{java_ty}`"
            );
        }
    }

    // ---------- b139：ZIP 条目路径前缀（`gen_code` 的 `path` 参数） ----------

    #[test]
    fn zip_path_prefix_normalizes_harmless_input() {
        // 缺省 / 空 / 只有分隔符 ⇒ 平铺。`/` 是数据库 `gen_path` 的默认值，
        // 把它当"绝对路径"拒绝会让默认配置直接不可用（这条是本批的边界面）。
        assert_eq!(sanitize_zip_path_prefix(None).unwrap(), "");
        assert_eq!(sanitize_zip_path_prefix(Some("")).unwrap(), "");
        assert_eq!(sanitize_zip_path_prefix(Some("   ")).unwrap(), "");
        assert_eq!(sanitize_zip_path_prefix(Some("/")).unwrap(), "");
        assert_eq!(sanitize_zip_path_prefix(Some("///")).unwrap(), "");
        // 连续分隔符与 `.` 段归一
        assert_eq!(
            sanitize_zip_path_prefix(Some("module//./system/")).unwrap(),
            "module/system"
        );
        // 首尾空白不影响语义
        assert_eq!(
            sanitize_zip_path_prefix(Some(" module/system ")).unwrap(),
            "module/system"
        );
    }

    #[test]
    fn zip_path_prefix_rejects_traversal_and_absolute_inputs() {
        // `..` 段（Zip Slip）：必须拒绝，且不能只是"归一掉"
        assert!(sanitize_zip_path_prefix(Some("..")).is_err());
        assert!(sanitize_zip_path_prefix(Some("a/../b")).is_err());
        assert!(sanitize_zip_path_prefix(Some("a/..")).is_err());
        // 绝对路径（还有段时）
        assert!(sanitize_zip_path_prefix(Some("/etc")).is_err());
        assert!(sanitize_zip_path_prefix(Some("/a/b")).is_err());
        // 反斜杠 / NUL / 控制字符
        assert!(sanitize_zip_path_prefix(Some("a\\b")).is_err());
        assert!(sanitize_zip_path_prefix(Some("a\0b")).is_err());
        assert!(sanitize_zip_path_prefix(Some("a\r\nb")).is_err());
        // Windows 保留字符（解压端会拒绝或截断）
        for bad in ["a:b", "a?b", "a*b", "a|b", "a<b", "a>b", "a\"b"] {
            assert!(
                sanitize_zip_path_prefix(Some(bad)).is_err(),
                "{bad} 应被拒绝"
            );
        }
        // 长度上限
        assert!(sanitize_zip_path_prefix(Some(&"a".repeat(201))).is_err());
        assert!(sanitize_zip_path_prefix(Some(&"a".repeat(200))).is_ok());
    }
}
