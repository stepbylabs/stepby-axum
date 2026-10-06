//! AI 助手 Service：编排「能力校验 → schema 构建 → LLM 生成 SQL → 守卫 → 受控执行」

use anyhow::{Context as _, Result};
use sea_orm::{ConnectionTrait, DatabaseConnection, DbBackend, Statement};
use serde_json::{Value, json};

use crate::ai::provider::{AiProvider, OpenAiCompatibleProvider};
use crate::ai::sql_guard;
use crate::config::settings::AiConfig;

/// 表/列的轻量 schema 描述（喂给 LLM 的知识面 = 白名单表结构，别无其它）
pub struct TableSchema {
    pub name: String,
    pub columns: Vec<(String, String)>,
}

#[derive(Clone)]
pub struct AiChatOutcome {
    /// LLM 生成的 SQL（已经守卫校验/改写）
    pub sql: String,
    /// SQL 引用的表
    pub tables: Vec<String>,
    /// 结果列名
    pub columns: Vec<String>,
    /// 结果行（每行一个 JSON 数组）
    pub rows: Vec<Value>,
    /// LLM 文本（含其解释）
    pub answer: String,
}

pub struct AiService {
    pub db: DatabaseConnection,
    pub config: AiConfig,
}

impl AiService {
    pub fn new(db: DatabaseConnection, config: AiConfig) -> Self {
        Self { db, config }
    }

    fn provider(&self) -> OpenAiCompatibleProvider {
        OpenAiCompatibleProvider::new(
            &self.config.base_url,
            &self.config.api_key,
            &self.config.model,
            self.config.timeout_secs,
        )
    }

    /// 白名单表的 schema 描述（跨三库：SQLite PRAGMA / PG & MySQL information_schema）
    pub async fn build_schema(&self) -> Result<Vec<TableSchema>> {
        let backend = self.db.get_database_backend();
        let mut out = Vec::new();
        for table in &self.config.allowed_tables {
            let cols = match backend {
                DbBackend::Sqlite => {
                    let stmt =
                        Statement::from_string(backend, format!("PRAGMA table_info({table})"));
                    let rows = self.db.query_all(stmt).await?;
                    rows.iter()
                        .map(|r| {
                            Ok((
                                r.try_get::<String>("", "name").unwrap_or_default(),
                                r.try_get::<String>("", "type").unwrap_or_default(),
                            ))
                        })
                        .collect::<Result<Vec<_>, sea_orm::DbErr>>()?
                }
                DbBackend::Postgres => {
                    let stmt = Statement::from_string(
                        backend,
                        format!(
                            "SELECT column_name AS name, data_type AS type FROM information_schema.columns WHERE table_name = '{table}' ORDER BY ordinal_position"
                        ),
                    );
                    let rows = self.db.query_all(stmt).await?;
                    rows.iter()
                        .map(|r| {
                            Ok((
                                r.try_get::<String>("", "name").unwrap_or_default(),
                                r.try_get::<String>("", "type").unwrap_or_default(),
                            ))
                        })
                        .collect::<Result<Vec<_>, sea_orm::DbErr>>()?
                }
                DbBackend::MySql => {
                    let stmt = Statement::from_string(
                        backend,
                        format!(
                            "SELECT column_name AS name, data_type AS type FROM information_schema.columns WHERE table_name = '{table}' AND table_schema = DATABASE() ORDER BY ordinal_position"
                        ),
                    );
                    let rows = self.db.query_all(stmt).await?;
                    rows.iter()
                        .map(|r| {
                            Ok((
                                r.try_get::<String>("", "name").unwrap_or_default(),
                                r.try_get::<String>("", "type").unwrap_or_default(),
                            ))
                        })
                        .collect::<Result<Vec<_>, sea_orm::DbErr>>()?
                }
            };
            if !cols.is_empty() {
                out.push(TableSchema {
                    name: table.clone(),
                    columns: cols,
                });
            }
        }
        Ok(out)
    }

    fn system_prompt(&self, schema: &[TableSchema], caller_tid: i64) -> String {
        let mut schema_text = String::new();
        for t in schema {
            schema_text.push_str(&format!(
                "- {}({})\n",
                t.name,
                t.columns
                    .iter()
                    .map(|(c, ty)| format!("{c} {ty}"))
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }
        let tenant_rule = if caller_tid != 0 {
            format!(
                "6. 你生成的 SQL **必须**包含 `WHERE tenant_id = {caller_tid}` 过滤条件（多租户数据隔离，不可省略）。"
            )
        } else {
            "6. 调用者是平台操作者，可查询全部租户数据（无需 tenant_id 条件）。".to_string()
        };
        format!(
            "你是后台管理系统的只读数据查询助手（NL2SQL）。把用户的自然语言问题转换为一条 SQL 查询。\n\
             规则：\n\
             1. 只能生成一条 SELECT 语句，禁止任何写操作/多语句/注释。\n\
             2. 只允许使用下列白名单表及其列，禁止查询其它任何表。\n\
             3. 输出格式：先给出 SQL（用 ```sql ``` 代码块包裹），再用一两句话说明查询意图。除 SQL 外不要输出其它代码。\n\
             4. 优先 SELECT 明确列而非 *；结果集尽量精简。\n\
             5. 时间字段为 TEXT/DATETIME 格式（YYYY-MM-DD HH:MM:SS）。\n\
             6. {tenant_rule}\n\
             7. 日期比较使用字符串比较即可（如 create_time >= '2026-01-01'）。\n\n\
             白名单表：\n{schema_text}"
        )
    }

    /// 从 LLM 文本提取 SQL（优先 ```sql 代码块；否则找以 SELECT 开头的首行）
    fn extract_sql(answer: &str) -> Option<String> {
        if let Some(start) = answer.find("```sql") {
            let after = &answer[start + 6..];
            if let Some(end) = after.find("```") {
                let s = after[..end].trim();
                if !s.is_empty() {
                    return Some(s.to_string());
                }
            }
        }
        if let Some(start) = answer.find("```") {
            let after = &answer[start + 3..];
            if let Some(end) = after.find("```") {
                let s = after[..end].trim();
                if s.to_uppercase().starts_with("SELECT") {
                    return Some(s.to_string());
                }
            }
        }
        answer
            .lines()
            .map(str::trim)
            .find(|l| l.to_uppercase().starts_with("SELECT"))
            .map(|s| s.trim_end_matches(';').to_string())
    }

    /// 受控执行守卫通过的 SQL，返回 (列名, 行数组)。
    /// 走 sea-orm 池透出的 sqlx 连接池（三库 Row::columns 均可用）。
    async fn execute_rows(&self, sql: &str) -> Result<(Vec<String>, Vec<Value>)> {
        use sqlx::{Column, Row};
        let backend = self.db.get_database_backend();
        let sql_owned = sql.to_string();
        let (columns, rows): (Vec<String>, Vec<Vec<Value>>) = match backend {
            DbBackend::Sqlite => {
                let pool = self.db.get_sqlite_connection_pool();
                let rows = sqlx::query(&sql_owned).fetch_all(pool).await?;
                let columns: Vec<String> = rows
                    .first()
                    .map(|r| r.columns().iter().map(|c| c.name().to_string()).collect())
                    .unwrap_or_default();
                let mut data = Vec::with_capacity(rows.len());
                for r in &rows {
                    let mut row = Vec::with_capacity(columns.len());
                    for i in 0..columns.len() {
                        let v: Value = r.try_get(i).unwrap_or(Value::Null);
                        row.push(v);
                    }
                    data.push(row);
                }
                (columns, data)
            }
            DbBackend::Postgres => {
                let pool = self.db.get_postgres_connection_pool();
                let rows = sqlx::query(&sql_owned).fetch_all(pool).await?;
                let columns: Vec<String> = rows
                    .first()
                    .map(|r| r.columns().iter().map(|c| c.name().to_string()).collect())
                    .unwrap_or_default();
                let mut data = Vec::with_capacity(rows.len());
                for r in &rows {
                    let mut row = Vec::with_capacity(columns.len());
                    for i in 0..columns.len() {
                        let v: Value = r.try_get(i).unwrap_or(Value::Null);
                        row.push(v);
                    }
                    data.push(row);
                }
                (columns, data)
            }
            DbBackend::MySql => {
                let pool = self.db.get_mysql_connection_pool();
                let rows = sqlx::query(&sql_owned).fetch_all(pool).await?;
                let columns: Vec<String> = rows
                    .first()
                    .map(|r| r.columns().iter().map(|c| c.name().to_string()).collect())
                    .unwrap_or_default();
                let mut data = Vec::with_capacity(rows.len());
                for r in &rows {
                    let mut row = Vec::with_capacity(columns.len());
                    for i in 0..columns.len() {
                        let v: Value = r.try_get(i).unwrap_or(Value::Null);
                        row.push(v);
                    }
                    data.push(row);
                }
                (columns, data)
            }
        };
        let rows_json = rows
            .into_iter()
            .map(|row| {
                json!(
                    columns
                        .iter()
                        .cloned()
                        .zip(row.into_iter())
                        .collect::<std::collections::BTreeMap<String, Value>>()
                )
            })
            .collect();
        Ok((columns, rows_json))
    }

    /// 主编排：question → LLM → 守卫 → 受控执行
    pub async fn chat(&self, question: &str, caller_tid: i64) -> Result<AiChatOutcome> {
        let q = question.trim();
        if q.is_empty() {
            anyhow::bail!("问题不能为空");
        }
        if q.chars().count() > 500 {
            anyhow::bail!("问题过长（≤500 字）");
        }
        let schema = self.build_schema().await?;
        if schema.is_empty() {
            anyhow::bail!("白名单表 schema 为空（请检查 [ai].allowed_tables）");
        }
        let system_prompt = self.system_prompt(&schema, caller_tid);
        let answer = self.provider().complete(&system_prompt, q).await?;
        let raw_sql =
            Self::extract_sql(&answer).context("未能从 AI 回复中提取 SQL，请换个问法或稍后再试")?;
        let guarded = sql_guard::guard(
            &raw_sql,
            caller_tid,
            &self.config.allowed_tables,
            self.config.max_rows,
        )
        .map_err(|v| anyhow::anyhow!("AI 生成的 SQL 未通过安全校验: {v}"))?;
        let (columns, rows) = self.execute_rows(&guarded.sql).await?;
        Ok(AiChatOutcome {
            sql: guarded.sql,
            tables: guarded.tables,
            columns,
            rows,
            answer,
        })
    }

    // ==================== AI-02：查询历史持久化（§5.39/§5.41） ====================

    /// 写入一条历史（**spawn 调用，失败仅 error 日志不阻塞响应**）。
    /// 不存结果集本体（SQL 可重放设计，§5.39 决策 2）；guard 拒绝也留痕（success='0'）。
    #[allow(clippy::too_many_arguments)]
    pub async fn save_history(
        &self,
        tenant_id: i64,
        user_id: i64,
        question: &str,
        sql: &str,
        tables: &[String],
        columns: &[String],
        rows_count: usize,
        duration_ms: u128,
        success: bool,
        error_msg: Option<&str>,
    ) {
        let backend = self.db.get_database_backend();
        let stmt = Statement::from_sql_and_values(
            backend,
            "INSERT INTO ai_chat_history (tenant_id, user_id, question, sql_text, tables_used, columns_json, rows_count, duration_ms, success, error_msg, create_time) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)",
            [
                tenant_id.into(),
                user_id.into(),
                question.into(),
                sql.into(),
                tables.join(",").into(),
                serde_json::to_string(columns).unwrap_or_else(|_| "[]".into()).into(),
                (rows_count as i64).into(),
                (duration_ms as i64).into(),
                (if success { "1" } else { "0" }).into(),
                error_msg.unwrap_or_default().into(),
            ],
        );
        if let Err(e) = self.db.execute(stmt).await {
            tracing::error!("AI 历史写入失败: {e}");
        }
    }

    /// 本人历史分页（user_id 强制过滤，租户隔离由 tenant_id 双条件兜底）
    pub async fn list_my_history(
        &self,
        tenant_id: i64,
        user_id: i64,
        page: u64,
        size: u64,
    ) -> Result<(Vec<serde_json::Value>, i64), anyhow::Error> {
        let backend = self.db.get_database_backend();
        let size = size.clamp(1, 100);
        let offset = (page.saturating_sub(1)).saturating_mul(size);
        let total_row = self
            .db
            .query_one(Statement::from_sql_and_values(
                backend,
                "SELECT COUNT(*) AS c FROM ai_chat_history WHERE tenant_id = ? AND user_id = ?",
                [tenant_id.into(), user_id.into()],
            ))
            .await?;
        let total: i64 = total_row
            .and_then(|r| r.try_get::<i64>("", "c").ok())
            .unwrap_or(0);
        let rows = self
            .db
            .query_all(Statement::from_sql_and_values(
                backend,
                "SELECT id, question, sql_text, tables_used, rows_count, duration_ms, success, error_msg, create_time \
                 FROM ai_chat_history WHERE tenant_id = ? AND user_id = ? ORDER BY id DESC LIMIT ? OFFSET ?",
                [
                    tenant_id.into(),
                    user_id.into(),
                    (size as i64).into(),
                    (offset as i64).into(),
                ],
            ))
            .await?;
        let items = rows
            .iter()
            .map(|r| {
                serde_json::json!({
                    "id": r.try_get::<i64>("", "id").unwrap_or(0),
                    "question": r.try_get::<String>("", "question").unwrap_or_default(),
                    "sql": r.try_get::<String>("", "sql_text").unwrap_or_default(),
                    "tables": r.try_get::<String>("", "tables_used").unwrap_or_default(),
                    "rowsCount": r.try_get::<i64>("", "rows_count").unwrap_or(0),
                    "durationMs": r.try_get::<i64>("", "duration_ms").unwrap_or(0),
                    "success": r.try_get::<String>("", "success").unwrap_or_default() == "1",
                    "errorMsg": r.try_get::<Option<String>>("", "error_msg").unwrap_or_default(),
                    "createTime": r.try_get::<String>("", "create_time").unwrap_or_default(),
                })
            })
            .collect();
        Ok((items, total))
    }

    /// 管理/平台视图历史分页（租户管理员=本租户全量；平台=跨租户 tenant_id 可选）
    pub async fn list_admin_history(
        &self,
        caller_tid: i64,
        tenant_filter: Option<i64>,
        page: u64,
        size: u64,
    ) -> Result<(Vec<serde_json::Value>, i64), anyhow::Error> {
        let backend = self.db.get_database_backend();
        let size = size.clamp(1, 100);
        let offset = (page.saturating_sub(1)).saturating_mul(size);
        // 平台（tid=0）：tenant_filter 有值查单租户，无值跨全量；租户管理员：强制本租户
        let (where_sql, binds): (String, Vec<sea_orm::Value>) = if caller_tid == 0 {
            match tenant_filter {
                Some(t) => ("WHERE tenant_id = ?".into(), vec![t.into()]),
                None => (String::new(), vec![]),
            }
        } else {
            ("WHERE tenant_id = ?".into(), vec![caller_tid.into()])
        };
        let total_row = self
            .db
            .query_one(Statement::from_sql_and_values(
                backend,
                format!("SELECT COUNT(*) AS c FROM ai_chat_history {where_sql}").as_str(),
                binds.clone(),
            ))
            .await?;
        let total: i64 = total_row
            .and_then(|r| r.try_get::<i64>("", "c").ok())
            .unwrap_or(0);
        let rows = self
            .db
            .query_all(Statement::from_sql_and_values(
                backend,
                format!(
                    "SELECT id, tenant_id, user_id, question, sql_text, tables_used, rows_count, duration_ms, success, error_msg, create_time \
                     FROM ai_chat_history {where_sql} ORDER BY id DESC LIMIT ? OFFSET ?"
                )
                .as_str(),
                {
                    let mut b = binds.clone();
                    b.push((size as i64).into());
                    b.push((offset as i64).into());
                    b
                },
            ))
            .await?;
        let items = rows
            .iter()
            .map(|r| {
                serde_json::json!({
                    "id": r.try_get::<i64>("", "id").unwrap_or(0),
                    "tenantId": r.try_get::<i64>("", "tenantId").unwrap_or(0),
                    "userId": r.try_get::<i64>("", "userId").unwrap_or(0),
                    "question": r.try_get::<String>("", "question").unwrap_or_default(),
                    "sql": r.try_get::<String>("", "sql_text").unwrap_or_default(),
                    "tables": r.try_get::<String>("", "tables_used").unwrap_or_default(),
                    "rowsCount": r.try_get::<i64>("", "rows_count").unwrap_or(0),
                    "durationMs": r.try_get::<i64>("", "duration_ms").unwrap_or(0),
                    "success": r.try_get::<String>("", "success").unwrap_or_default() == "1",
                    "errorMsg": r.try_get::<Option<String>>("", "error_msg").unwrap_or_default(),
                    "createTime": r.try_get::<String>("", "create_time").unwrap_or_default(),
                })
            })
            .collect();
        Ok((items, total))
    }

    /// 删除本人历史（横向越权防护：仅本人行可删）
    pub async fn delete_my_history(
        &self,
        tenant_id: i64,
        user_id: i64,
        id: i64,
    ) -> Result<bool, anyhow::Error> {
        let backend = self.db.get_database_backend();
        let res = self
            .db
            .execute(Statement::from_sql_and_values(
                backend,
                "DELETE FROM ai_chat_history WHERE id = ? AND tenant_id = ? AND user_id = ?",
                [id.into(), tenant_id.into(), user_id.into()],
            ))
            .await?;
        Ok(res.rows_affected() > 0)
    }
}
