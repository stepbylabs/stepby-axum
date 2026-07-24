// axum-backend/src/repository/gen_table.rs
//! gen_table + gen_table_column 数据访问层（代码生成模块）
//!
//! 提供：
//! - gen_table 分页查询、详情、新增、修改、删除
//! - gen_table_column 按表 ID 查询、批量插入、批量删除
//! - 数据库表元数据查询（读取 information_schema / sqlite_master）

use chrono::NaiveDateTime;
use sea_orm::*;
use serde::Serialize;

use crate::common::like_escape;
use crate::entity::gen_table::{ActiveModel as GenTableActiveModel, Column as GenTableColumn, Entity as GenTable, Model as GenTableModel};
use crate::entity::gen_table_column::{ActiveModel as GenTableColumnActiveModel, Column as GenColumn, Entity as GenTableColumnEntity, Model as GenTableColumnModel};
use crate::repository::base::BaseRepository;

/// 数据库表元数据视图（用于导入表时读取数据库现有表结构）
#[derive(Debug, Clone, FromQueryResult, Serialize)]
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
    pub async fn find_page_filtered(
        &self,
        offset: u64,
        limit: u64,
        table_name: Option<&str>,
        table_comment: Option<&str>,
        begin_time: Option<NaiveDateTime>,
        end_time: Option<NaiveDateTime>,
    ) -> Result<(Vec<GenTableModel>, u64), DbErr> {
        let mut query = GenTable::find();
        if let Some(name) = table_name {
            query = query.filter(GenTableColumn::TableName.like(format!("%{}%", like_escape(name))));
        }
        if let Some(comment) = table_comment {
            query = query.filter(GenTableColumn::TableComment.like(format!("%{}%", like_escape(comment))));
        }
        if let Some(begin) = begin_time {
            query = query.filter(GenTableColumn::CreateTime.gte(begin));
        }
        if let Some(end) = end_time {
            query = query.filter(GenTableColumn::CreateTime.lte(end));
        }

        let total = query.clone().count(self.base.db()).await?;
        let rows = query
            .offset(offset)
            .limit(limit)
            .order_by_desc(GenTableColumn::TableId)
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
    pub async fn find_by_names(&self, table_names: Vec<String>) -> Result<Vec<GenTableModel>, DbErr> {
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
            .limit(500)
            .all(self.base.db())
            .await
    }

    // ============ 数据库表元数据查询（用于导入表） ============

    /// 查询数据库中所有未导入的业务表
    ///
    /// 排除已存在于 gen_table 中的表，排除系统表
    pub async fn find_db_tables(
        &self,
        offset: u64,
        limit: u64,
        table_name: Option<&str>,
        table_comment: Option<&str>,
    ) -> Result<(Vec<DbTableInfo>, u64), DbErr> {
        let db = self.base.db();
        let backend = db.get_database_backend();

        // 获取已导入的表名列表
        let imported: Vec<String> = GenTable::find()
            .all(db)
            .await?
            .into_iter()
            .map(|t| t.table_name)
            .collect();

        // 构建参数化查询（P0: 防止 SQL 注入，原手动转义 replace('\'',"''") + format! 拼接存在风险）
        // LIKE 模式通过参数值传入，使用 like_escape 转义 % 和 \，并附加 ESCAPE '\\' 子句确保跨库一致。
        let (sql, count_sql, data_values, count_values): (String, String, Vec<Value>, Vec<Value>) = match backend {
            DatabaseBackend::Sqlite => {
                let base_where = "type='table' AND name NOT LIKE 'sqlite_%' AND name NOT LIKE '_cf_%' AND name NOT LIKE 'AUTHS_%'";
                let mut where_clause = base_where.to_string();
                let mut vals: Vec<Value> = Vec::new();
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
                    "SELECT name AS table_name, '' AS table_comment FROM sqlite_master WHERE {} ORDER BY name LIMIT ? OFFSET ?",
                    where_clause
                );
                let count_sql = format!(
                    "SELECT COUNT(*) AS count FROM sqlite_master WHERE {}",
                    where_clause
                );
                (sql, count_sql, data_vals, vals)
            }
            DatabaseBackend::Postgres => {
                let base_where = "table_schema='public' AND table_type='BASE TABLE'";
                let mut where_clause = base_where.to_string();
                let mut vals: Vec<Value> = Vec::new();
                let mut idx = 1usize;
                if let Some(name) = table_name {
                    where_clause.push_str(&format!(" AND table_name LIKE ${} ESCAPE '\\'", idx));
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
                     FROM information_schema.tables WHERE {} ORDER BY table_name LIMIT ${} OFFSET ${}",
                    where_clause, idx, idx + 1
                );
                let count_sql = format!(
                    "SELECT COUNT(*) AS count FROM information_schema.tables WHERE {}",
                    where_clause
                );
                (sql, count_sql, data_vals, vals)
            }
            DatabaseBackend::MySql => {
                let base_where = "table_schema = DATABASE() AND table_type = 'BASE TABLE'";
                let mut where_clause = base_where.to_string();
                let mut vals: Vec<Value> = Vec::new();
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
                     FROM information_schema.tables WHERE {} ORDER BY table_name LIMIT ? OFFSET ?",
                    where_clause
                );
                let count_sql = format!(
                    "SELECT COUNT(*) AS count FROM information_schema.tables WHERE {}",
                    where_clause
                );
                (sql, count_sql, data_vals, vals)
            }
        };

        let rows = DbTableInfo::find_by_statement(Statement::from_sql_and_values(backend, &sql, data_values))
            .all(db)
            .await?;

        // 过滤掉已导入的表
        let filtered: Vec<DbTableInfo> = rows
            .into_iter()
            .filter(|r| !imported.contains(&r.table_name))
            .collect();

        // count 查询（也需过滤）
        let total_result = db.query_one(Statement::from_sql_and_values(backend, &count_sql, count_values)).await?;
        let total_all: u64 = total_result
            .map(|row| u64::try_from(row.try_get::<i64>("", "count").unwrap_or(0)).unwrap_or(0))
            .unwrap_or(0);
        // 估算过滤后总数（精确值需要单独查询，这里用近似值）
        let imported_count = imported.len() as u64;
        let total = total_all.saturating_sub(imported_count);

        Ok((filtered, total))
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
                // PRAGMA 不支持参数绑定，校验 table_name 为合法标识符防止注入
                if !is_valid_identifier(table_name) {
                    return Err(DbErr::Custom(format!("非法表名: {}", table_name)));
                }
                let sql = format!("PRAGMA table_info('{}')", table_name);
                // PRAGMA table_info 返回：cid, name, type, notnull, dflt_value, pk
                let raw_rows = db.query_all(Statement::from_sql_and_values(backend, &sql, vec![])).await?;
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
                DbColumnInfo::find_by_statement(Statement::from_sql_and_values(backend, sql, vec![table_name.into()]))
                    .all(db)
                    .await
            }
            DatabaseBackend::MySql => {
                let sql = "SELECT column_name, column_type, IFNULL(column_comment, '') AS column_comment, \
                     is_nullable, column_key, extra, ordinal_position \
                     FROM information_schema.columns WHERE table_schema = DATABASE() AND table_name = ? ORDER BY ordinal_position";
                DbColumnInfo::find_by_statement(Statement::from_sql_and_values(backend, sql, vec![table_name.into()]))
                    .all(db)
                    .await
            }
        }
    }

    // ============ gen_table_column 操作 ============

    /// 执行建表 SQL（用于 createTable 接口）
    ///
    /// 安全说明：
    /// - 仅允许执行 CREATE TABLE 语句
    /// - 通过 `execute_unprepared` 执行原始 SQL
    ///
    /// P0-1 未完全修复项：createTable 接口已禁用，请通过 migration 管理表结构。
    #[deprecated(note = "createTable 接口已禁用，请通过 migration 管理表结构")]
    pub async fn execute_create_sql(&self, sql: &str) -> Result<ExecResult, DbErr> {
        let db = self.base.db();
        db.execute_unprepared(sql).await
    }

    /// 按 table_id 查询所有列
    pub async fn find_columns_by_table_id(&self, table_id: i64) -> Result<Vec<GenTableColumnModel>, DbErr> {
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
    pub async fn insert_columns(&self, columns: Vec<GenTableColumnActiveModel>) -> Result<(), DbErr> {
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
    pub async fn delete_columns_by_table_ids(&self, table_ids: Vec<i64>) -> Result<DeleteResult, DbErr> {
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
}

/// 校验字符串是否为合法 SQL 标识符（仅字母、数字、下划线，且不以数字开头）
///
/// 用于 SQLite PRAGMA 等不支持参数绑定的场景，防止 SQL 注入。
fn is_valid_identifier(s: &str) -> bool {
    if s.is_empty() {
        return false;
    }
    let mut chars = s.chars();
    let first = chars.next().unwrap();
    if !(first.is_ascii_alphabetic() || first == '_') {
        return false;
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}
