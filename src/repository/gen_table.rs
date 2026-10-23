// stepby-axum/src/repository/gen_table.rs
//! gen_table + gen_table_column 数据访问层（代码生成模块）
//!
//! 提供：
//! - gen_table 分页查询、详情、新增、修改、删除
//! - gen_table_column 按表 ID 查询、批量插入、批量删除
//! - 数据库表元数据查询（读取 information_schema / sqlite_master）

use chrono::NaiveDateTime;
use sea_orm::*;
use serde::Serialize;
use utoipa::ToSchema;

use crate::common::like_escape;
use crate::common::sort::SortOrder;
use crate::entity::gen_table::{
    ActiveModel as GenTableActiveModel, Column as GenTableColumn, Entity as GenTable,
    Model as GenTableModel,
};
use crate::entity::gen_table_column::{
    ActiveModel as GenTableColumnActiveModel, Column as GenColumn, Entity as GenTableColumnEntity,
    Model as GenTableColumnModel,
};
use crate::repository::base::BaseRepository;

/// 数据库表元数据视图（用于导入表时读取数据库现有表结构）
#[derive(Debug, Clone, FromQueryResult, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct DbTableInfo {
    pub table_name: String,
    pub table_comment: String,
}

/// 数据库列元数据视图（用于导入表时读取表字段结构）
#[derive(Debug, Clone, FromQueryResult)]
pub struct DbColumnInfo {
    pub column_name: String,
    pub column_type: String,
    pub column_comment: String,
    pub is_nullable: String,
    pub column_key: String,
    pub extra: String,
    pub ordinal_position: i64,
}

/// 数据库表元数据列表的可排序列（`find_db_tables` 为原始 SQL 查询、无 sea-orm Entity）
///
/// 前端 prop 经 service 层白名单映射到此枚举，SQL 端映射为 SELECT 输出列别名
/// （编译期常量，非用户输入拼接），保持与 sea-orm 参数化路径同等安全语义：
/// 不透传任意列，防止按未预期列排序探测表结构。
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum DbTableSortColumn {
    /// 表名
    TableName,
    /// 表注释（SQLite 元数据无注释概念，恒为空串，按此列排序合法但无效果）
    TableComment,
}

/// 代码生成业务表 Repository
#[derive(Clone)]
pub struct GenTableRepository {
    base: BaseRepository<GenTable>,
}

impl GenTableRepository {
    pub fn new(db: DatabaseConnection) -> Self {
        Self {
            base: BaseRepository::new(db),
        }
    }

    pub fn base(&self) -> &BaseRepository<GenTable> {
        &self.base
    }

    /// 分页查询代码生成业务表
    ///
    /// `sort`：动态排序（方案 B，白名单已在 service 层解析为 `SortOrder`）；
    /// `None` 或未命中时回退默认 `table_id DESC`。
    pub async fn find_page_filtered(
        &self,
        offset: u64,
        limit: u64,
        table_name: Option<&str>,
        table_comment: Option<&str>,
        begin_time: Option<NaiveDateTime>,
        end_time: Option<NaiveDateTime>,
        sort: Option<SortOrder<GenTableColumn>>,
    ) -> Result<(Vec<GenTableModel>, u64), DbErr> {
        let mut query = GenTable::find();
        if let Some(name) = table_name {
            query =
                query.filter(GenTableColumn::TableName.like(format!("%{}%", like_escape(name))));
        }
        if let Some(comment) = table_comment {
            query = query
                .filter(GenTableColumn::TableComment.like(format!("%{}%", like_escape(comment))));
        }
        if let Some(begin) = begin_time {
            query = query.filter(GenTableColumn::CreateTime.gte(begin));
        }
        if let Some(end) = end_time {
            query = query.filter(GenTableColumn::CreateTime.lte(end));
        }

        let total = query.clone().count(self.base.db()).await?;
        let rows = match sort {
            Some(s) => query.order_by(s.column, s.dir),
            None => query.order_by_desc(GenTableColumn::TableId),
        }
        .offset(offset)
        .limit(limit)
        .all(self.base.db())
        .await?;
        Ok((rows, total))
    }

    /// 按 table_id 查询代码生成业务表
    pub async fn find_by_id(&self, table_id: i64) -> Result<Option<GenTableModel>, DbErr> {
        GenTable::find()
            .filter(GenTableColumn::TableId.eq(table_id))
            .one(self.base.db())
            .await
    }

    /// 按 table_name 查询代码生成业务表（用于查重）
    pub async fn find_by_name(&self, table_name: &str) -> Result<Option<GenTableModel>, DbErr> {
        GenTable::find()
            .filter(GenTableColumn::TableName.eq(table_name))
            .one(self.base.db())
            .await
    }

    /// 按 table_id 列表批量查询代码生成业务表（单次查询替代 N 次 find_by_id）
    pub async fn find_by_ids(&self, table_ids: Vec<i64>) -> Result<Vec<GenTableModel>, DbErr> {
        if table_ids.is_empty() {
            return Ok(Vec::new());
        }
        GenTable::find()
            .filter(GenTableColumn::TableId.is_in(table_ids))
            .all(self.base.db())
            .await
    }

    /// 按 table_name 列表批量查询代码生成业务表（单次查询替代 N 次 find_by_name）
    pub async fn find_by_names(
        &self,
        table_names: Vec<String>,
    ) -> Result<Vec<GenTableModel>, DbErr> {
        if table_names.is_empty() {
            return Ok(Vec::new());
        }
        GenTable::find()
            .filter(GenTableColumn::TableName.is_in(table_names))
            .all(self.base.db())
            .await
    }

    /// 新增代码生成业务表
    pub async fn insert(&self, model: GenTableActiveModel) -> Result<GenTableModel, DbErr> {
        self.base.insert(model).await
    }

    /// 修改代码生成业务表
    pub async fn update(&self, model: GenTableActiveModel) -> Result<GenTableModel, DbErr> {
        self.base.update(model).await
    }

    /// 按 ID 列表删除代码生成业务表
    pub async fn delete_by_ids(&self, table_ids: Vec<i64>) -> Result<DeleteResult, DbErr> {
        GenTable::delete_many()
            .filter(GenTableColumn::TableId.is_in(table_ids))
            .exec(self.base.db())
            .await
    }

    /// 查询所有代码生成业务表（用于详情页 tables 下拉）
    ///
    /// 限制 500 条避免无界增长，超过时下拉应改为远程搜索
    pub async fn find_all(&self) -> Result<Vec<GenTableModel>, DbErr> {
        GenTable::find()
            .order_by_desc(GenTableColumn::TableId)
            .limit(crate::common::constants::DROPDOWN_MAX_ROWS)
            .all(self.base.db())
            .await
    }

    // ============ 数据库表元数据查询（用于导入表） ============

    /// 查询数据库中所有未导入的业务表
    ///
    /// 排除已存在于 gen_table 中的表，排除系统表
    ///
    /// `sort`：动态排序（方案 B，白名单已在 service 层解析为 `SortOrder`）。
    /// 列名为编译期常量映射（三库均支持按 SELECT 输出列别名排序），方向由枚举解析，
    /// 无注入面；`None` 回退原有默认排序（按表名升序）。
    pub async fn find_db_tables(
        &self,
        offset: u64,
        limit: u64,
        table_name: Option<&str>,
        table_comment: Option<&str>,
        sort: Option<SortOrder<DbTableSortColumn>>,
    ) -> Result<(Vec<DbTableInfo>, u64), DbErr> {
        let db = self.base.db();
        let backend = db.get_database_backend();

        // 动态排序子句：列枚举 → SELECT 输出列别名（table_name / table_comment），
        // 方向枚举 → ASC/DESC；None 回退各分支原默认（SQLite 按原生列 name，PG/MySQL 按 table_name）
        let order_by: String = match sort {
            Some(s) => {
                let col = match s.column {
                    DbTableSortColumn::TableName => "table_name",
                    DbTableSortColumn::TableComment => "table_comment",
                };
                match s.dir {
                    sea_orm::Order::Asc => format!("{col} ASC"),
                    _ => format!("{col} DESC"),
                }
            }
            None => match backend {
                DatabaseBackend::Sqlite => "name".to_string(),
                _ => "table_name".to_string(),
            },
        };

        // 获取已导入的表名列表
        let imported: Vec<String> = GenTable::find()
            .all(db)
            .await?
            .into_iter()
            .map(|t| t.table_name)
            .collect();

        // 构建参数化查询（P0: 防止 SQL 注入，原手动转义 replace('\'',"''") + format! 拼接存在风险）
        // LIKE 模式通过参数值传入，使用 like_escape 转义 % 和 \，并附加 ESCAPE '\\' 子句确保跨库一致。
        // P0-9 修复：排除已导入表的 NOT IN 条件下沉到 SQL（参数化），
        // 使 DB 层分页与 COUNT 均在过滤后执行，修复"先 DB 分页再内存过滤导致
        // total 恒 ≤ pageSize 且跨页漏表/重复"的缺陷。
        let (sql, count_sql, data_values, count_values): (String, String, Vec<Value>, Vec<Value>) =
            match backend {
                DatabaseBackend::Sqlite => {
                    let mut base_where = "type='table' AND name NOT LIKE 'sqlite_%' AND name NOT LIKE '_cf_%' AND name NOT LIKE 'AUTHS_%'".to_string();
                    // SQLite _cf_ 通配符误用修复：`_cf_%` 中 `_` 是单字符通配符，会误排除 xcfX 等表；
                    // 意图为字面前缀 `_cf_`，改用 ESCAPE 转义（P1）
                    base_where = base_where.replace(
                        "name NOT LIKE '_cf_%'",
                        "name NOT LIKE '\\_cf\\_%' ESCAPE '\\'",
                    );
                    let mut where_clause = base_where;
                    let mut vals: Vec<Value> = Vec::new();
                    if !imported.is_empty() {
                        // 排除已导入表（参数化 NOT IN）
                        where_clause.push_str(" AND name NOT IN (");
                        where_clause.push_str(&vec!["?"; imported.len()].join(","));
                        where_clause.push(')');
                        vals.extend(imported.iter().cloned().map(Value::from));
                    }
                    if let Some(name) = table_name {
                        where_clause.push_str(" AND name LIKE ? ESCAPE '\\'");
                        vals.push(format!("%{}%", like_escape(name)).into());
                    }
                    if let Some(comment) = table_comment {
                        where_clause.push_str(" AND sql LIKE ? ESCAPE '\\'");
                        vals.push(format!("%{}%", like_escape(comment)).into());
                    }
                    let mut data_vals = vals.clone();
                    data_vals.push((limit as i64).into());
                    data_vals.push((offset as i64).into());
                    let sql = format!(
                        "SELECT name AS table_name, '' AS table_comment FROM sqlite_master WHERE {} ORDER BY {order_by} LIMIT ? OFFSET ?",
                        where_clause
                    );
                    let count_sql = format!(
                        "SELECT COUNT(*) AS count FROM sqlite_master WHERE {}",
                        where_clause
                    );
                    (sql, count_sql, data_vals, vals)
                }
                DatabaseBackend::Postgres => {
                    let mut where_clause =
                        "table_schema='public' AND table_type='BASE TABLE'".to_string();
                    let mut vals: Vec<Value> = Vec::new();
                    let mut idx = 1usize;
                    if !imported.is_empty() {
                        let placeholders: Vec<String> = (0..imported.len())
                            .map(|i| format!("${}", idx + i))
                            .collect();
                        where_clause.push_str(&format!(
                            " AND table_name NOT IN ({})",
                            placeholders.join(",")
                        ));
                        vals.extend(imported.iter().cloned().map(Value::from));
                        idx += imported.len();
                    }
                    if let Some(name) = table_name {
                        where_clause
                            .push_str(&format!(" AND table_name LIKE ${} ESCAPE '\\'", idx));
                        vals.push(format!("%{}%", like_escape(name)).into());
                        idx += 1;
                    }
                    if let Some(comment) = table_comment {
                        where_clause.push_str(&format!(
                        " AND obj_description((quote_ident(table_schema)||'.'||quote_ident(table_name))::regclass, 'pg_class') LIKE ${} ESCAPE '\\'",
                        idx
                    ));
                        vals.push(format!("%{}%", like_escape(comment)).into());
                        idx += 1;
                    }
                    let mut data_vals = vals.clone();
                    data_vals.push((limit as i64).into());
                    data_vals.push((offset as i64).into());
                    let sql = format!(
                        "SELECT table_name, COALESCE(obj_description((quote_ident(table_schema)||'.'||quote_ident(table_name))::regclass, 'pg_class'), '') AS table_comment \
                     FROM information_schema.tables WHERE {} ORDER BY {order_by} LIMIT ${} OFFSET ${}",
                        where_clause,
                        idx,
                        idx + 1
                    );
                    let count_sql = format!(
                        "SELECT COUNT(*) AS count FROM information_schema.tables WHERE {}",
                        where_clause
                    );
                    (sql, count_sql, data_vals, vals)
                }
                DatabaseBackend::MySql => {
                    let mut where_clause =
                        "table_schema = DATABASE() AND table_type = 'BASE TABLE'".to_string();
                    let mut vals: Vec<Value> = Vec::new();
                    if !imported.is_empty() {
                        where_clause.push_str(" AND table_name NOT IN (");
                        where_clause.push_str(&vec!["?"; imported.len()].join(","));
                        where_clause.push(')');
                        vals.extend(imported.iter().cloned().map(Value::from));
                    }
                    if let Some(name) = table_name {
                        where_clause.push_str(" AND table_name LIKE ? ESCAPE '\\'");
                        vals.push(format!("%{}%", like_escape(name)).into());
                    }
                    if let Some(comment) = table_comment {
                        where_clause.push_str(" AND table_comment LIKE ? ESCAPE '\\'");
                        vals.push(format!("%{}%", like_escape(comment)).into());
                    }
                    let mut data_vals = vals.clone();
                    data_vals.push((limit as i64).into());
                    data_vals.push((offset as i64).into());
                    let sql = format!(
                        "SELECT table_name, IFNULL(table_comment, '') AS table_comment \
                     FROM information_schema.tables WHERE {} ORDER BY {order_by} LIMIT ? OFFSET ?",
                        where_clause
                    );
                    let count_sql = format!(
                        "SELECT COUNT(*) AS count FROM information_schema.tables WHERE {}",
                        where_clause
                    );
                    (sql, count_sql, data_vals, vals)
                }
                backend => unreachable!("unknown backend: {backend:?}"),
            };

        let rows = DbTableInfo::find_by_statement(Statement::from_sql_and_values(
            backend,
            &sql,
            data_values,
        ))
        .all(db)
        .await?;

        // 精确总数：COUNT 查询（已排除已导入表，P0-9 修复：不再用当前页内存过滤行数充当 total）
        let total: i64 = db
            .query_one_raw(Statement::from_sql_and_values(
                backend,
                &count_sql,
                count_values,
            ))
            .await?
            .and_then(|row| row.try_get("", "count").ok())
            .unwrap_or(0);

        Ok((rows, std::cmp::max(total, 0) as u64))
    }

    /// 查询指定表的列元数据（用于导入表时生成 gen_table_column 记录）
    ///
    /// 安全说明：使用参数化查询防止 SQL 注入（P0）。
    /// SQLite 的 PRAGMA 语句不支持参数绑定，改为校验 table_name 为合法标识符。
    pub async fn find_db_columns(&self, table_name: &str) -> Result<Vec<DbColumnInfo>, DbErr> {
        let db = self.base.db();
        let backend = db.get_database_backend();

        match backend {
            DatabaseBackend::Sqlite => {
                // SAFETY: SQLite PRAGMA 不支持参数绑定，必须通过 format! 拼接。
                // 通过 is_valid_identifier 校验 table_name 仅含 [a-zA-Z0-9_] 且不以数字开头，
                // 确保无法构造注入 payload。修改此校验逻辑前请务必评估注入风险。
                if !is_valid_identifier(table_name) {
                    return Err(DbErr::Custom(crate::tr!(
                        "error.gen.invalid_table_name_with_value",
                        name = table_name
                    )));
                }
                let sql = format!("PRAGMA table_info('{}')", table_name);
                // PRAGMA table_info 返回：cid, name, type, notnull, dflt_value, pk
                let raw_rows = db
                    .query_all_raw(Statement::from_sql_and_values(backend, &sql, vec![]))
                    .await?;
                let mut result = Vec::new();
                for row in raw_rows {
                    let name: String = row.try_get("", "name")?;
                    let col_type: String = row.try_get("", "type")?;
                    let notnull: i64 = row.try_get("", "notnull")?;
                    let pk: i64 = row.try_get("", "pk")?;
                    // SQLite PRAGMA 不直接提供 comment，使用空字符串
                    result.push(DbColumnInfo {
                        column_name: name,
                        column_type: col_type,
                        column_comment: String::new(),
                        is_nullable: if notnull == 0 { "YES" } else { "NO" }.to_string(),
                        column_key: if pk > 0 { "PRI" } else { "" }.to_string(),
                        extra: if pk > 0 { "auto_increment" } else { "" }.to_string(),
                        ordinal_position: pk,
                    });
                }
                Ok(result)
            }
            DatabaseBackend::Postgres => {
                let sql = "SELECT column_name, data_type AS column_type, COALESCE(col_description((quote_ident(table_schema)||'.'||quote_ident(table_name))::regclass, ordinal_position), '') AS column_comment, \
                     CASE WHEN is_nullable='YES' THEN 'YES' ELSE 'NO' END AS is_nullable, \
                     CASE WHEN column_default LIKE 'nextval%' THEN 'PRI' ELSE '' END AS column_key, \
                     CASE WHEN column_default LIKE 'nextval%' THEN 'auto_increment' ELSE '' END AS extra, \
                     ordinal_position::bigint \
                     FROM information_schema.columns WHERE table_name=$1 AND table_schema='public' ORDER BY ordinal_position";
                DbColumnInfo::find_by_statement(Statement::from_sql_and_values(
                    backend,
                    sql,
                    vec![table_name.into()],
                ))
                .all(db)
                .await
            }
            DatabaseBackend::MySql => {
                let sql = "SELECT column_name, column_type, IFNULL(column_comment, '') AS column_comment, \
                     is_nullable, column_key, extra, ordinal_position \
                     FROM information_schema.columns WHERE table_schema = DATABASE() AND table_name = ? ORDER BY ordinal_position";
                DbColumnInfo::find_by_statement(Statement::from_sql_and_values(
                    backend,
                    sql,
                    vec![table_name.into()],
                ))
                .all(db)
                .await
            }
            _ => Ok(Vec::new()),
        }
    }

    // ============ gen_table_column 操作 ============

    /// 按 table_id 查询所有列
    pub async fn find_columns_by_table_id(
        &self,
        table_id: i64,
    ) -> Result<Vec<GenTableColumnModel>, DbErr> {
        GenTableColumnEntity::find()
            .filter(GenColumn::TableId.eq(table_id))
            .order_by_asc(GenColumn::Sort)
            .all(self.base.db())
            .await
    }

    /// 按 table_id 列表批量查询所有列（单次查询替代 N 次 find_columns_by_table_id）
    ///
    /// 结果按 table_id 升序、sort 升序排列，调用方按 table_id 分组即可保持每表内列的顺序。
    pub async fn find_columns_by_table_ids(
        &self,
        table_ids: Vec<i64>,
    ) -> Result<Vec<GenTableColumnModel>, DbErr> {
        if table_ids.is_empty() {
            return Ok(Vec::new());
        }
        GenTableColumnEntity::find()
            .filter(GenColumn::TableId.is_in(table_ids))
            .order_by_asc(GenColumn::TableId)
            .order_by_asc(GenColumn::Sort)
            .all(self.base.db())
            .await
    }

    /// 批量新增列（单次 INSERT，替代循环 N 次）
    pub async fn insert_columns(
        &self,
        columns: Vec<GenTableColumnActiveModel>,
    ) -> Result<(), DbErr> {
        if columns.is_empty() {
            return Ok(());
        }
        GenTableColumnEntity::insert_many(columns)
            .exec(self.base.db())
            .await?;
        Ok(())
    }

    /// 按 table_id 删除所有列（修改配置时先删后插）
    pub async fn delete_columns_by_table_id(&self, table_id: i64) -> Result<DeleteResult, DbErr> {
        GenTableColumnEntity::delete_many()
            .filter(GenColumn::TableId.eq(table_id))
            .exec(self.base.db())
            .await
    }

    /// 按 table_id 列表删除所有列（删除表时级联清理）
    pub async fn delete_columns_by_table_ids(
        &self,
        table_ids: Vec<i64>,
    ) -> Result<DeleteResult, DbErr> {
        GenTableColumnEntity::delete_many()
            .filter(GenColumn::TableId.is_in(table_ids))
            .exec(self.base.db())
            .await
    }

    /// 按 table_id 更新列（先删后插）
    pub async fn update_columns(
        &self,
        table_id: i64,
        columns: Vec<GenTableColumnActiveModel>,
    ) -> Result<(), DbErr> {
        self.delete_columns_by_table_id(table_id).await?;
        self.insert_columns(columns).await
    }

    // ---- 事务版本方法（P1 修复：gen_table_service 删除/同步需事务保证一致性） ----

    /// 批量新增列（事务版本）
    pub async fn insert_columns_conn(
        &self,
        txn: &DatabaseTransaction,
        columns: Vec<GenTableColumnActiveModel>,
    ) -> Result<(), DbErr> {
        if columns.is_empty() {
            return Ok(());
        }
        GenTableColumnEntity::insert_many(columns).exec(txn).await?;
        Ok(())
    }

    /// 按 table_id 删除所有列（事务版本）
    pub async fn delete_columns_by_table_id_conn(
        &self,
        txn: &DatabaseTransaction,
        table_id: i64,
    ) -> Result<DeleteResult, DbErr> {
        GenTableColumnEntity::delete_many()
            .filter(GenColumn::TableId.eq(table_id))
            .exec(txn)
            .await
    }

    /// 按 table_id 列表删除所有列（事务版本）
    pub async fn delete_columns_by_table_ids_conn(
        &self,
        txn: &DatabaseTransaction,
        table_ids: Vec<i64>,
    ) -> Result<DeleteResult, DbErr> {
        GenTableColumnEntity::delete_many()
            .filter(GenColumn::TableId.is_in(table_ids))
            .exec(txn)
            .await
    }

    /// 按 table_id 批量删除表记录（事务版本）
    pub async fn delete_by_ids_conn(
        &self,
        txn: &DatabaseTransaction,
        table_ids: Vec<i64>,
    ) -> Result<DeleteResult, DbErr> {
        GenTable::delete_many()
            .filter(GenTableColumn::TableId.is_in(table_ids))
            .exec(txn)
            .await
    }

    /// 按 table_id 更新列（先删后插）— 事务版本
    ///
    /// P1 修复: 将先删后插包裹在事务中，避免删除成功但插入失败时列记录全部丢失
    pub async fn update_columns_conn(
        &self,
        txn: &DatabaseTransaction,
        table_id: i64,
        columns: Vec<GenTableColumnActiveModel>,
    ) -> Result<(), DbErr> {
        self.delete_columns_by_table_id_conn(txn, table_id).await?;
        self.insert_columns_conn(txn, columns).await
    }
}

/// 校验字符串是否为合法 SQL 标识符（仅字母、数字、下划线，且不以数字开头）
///
/// 用于 SQLite PRAGMA 等不支持参数绑定的场景，防止 SQL 注入。
fn is_valid_identifier(s: &str) -> bool {
    if s.is_empty() {
        return false;
    }
    let mut chars = s.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    if !(first.is_ascii_alphabetic() || first == '_') {
        return false;
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}
