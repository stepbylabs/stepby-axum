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

#[derive(Clone, Debug)]
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
    /// §5.57 token 用量观测（provider 未上报时为 None）
    pub token_usage: Option<crate::ai::provider::TokenUsage>,
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
                    let rows = self.db.query_all_raw(stmt).await?;
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
                    let rows = self.db.query_all_raw(stmt).await?;
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
                    let rows = self.db.query_all_raw(stmt).await?;
                    rows.iter()
                        .map(|r| {
                            Ok((
                                r.try_get::<String>("", "name").unwrap_or_default(),
                                r.try_get::<String>("", "type").unwrap_or_default(),
                            ))
                        })
                        .collect::<Result<Vec<_>, sea_orm::DbErr>>()?
                }
                backend => unreachable!("unknown backend: {backend:?}"),
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
        // SAFETY §5.52（sqlx 0.9 SqlSafeStr 审计）：sql 为 LLM 生成且已过 sql_guard
        // 四重守卫（只读 SELECT/表白名单/租户过滤/LIMIT）——该守卫正是本模块的
        // 安全边界，AssertSqlSafe 为官方人工审计豁免通道。
        let backend = self.db.get_database_backend();
        let sql_owned = sql.to_string();
        let (columns, rows): (Vec<String>, Vec<Vec<Value>>) = match backend {
            DbBackend::Sqlite => {
                let pool = self.db.get_sqlite_connection_pool();
                let rows = sqlx::query(sqlx::AssertSqlSafe(sql_owned.clone()))
                    .fetch_all(pool)
                    .await?;
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
                let rows = sqlx::query(sqlx::AssertSqlSafe(sql_owned.clone()))
                    .fetch_all(pool)
                    .await?;
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
                let rows = sqlx::query(sqlx::AssertSqlSafe(sql_owned.clone()))
                    .fetch_all(pool)
                    .await?;
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
            backend => unreachable!("unknown backend: {backend:?}"),
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
        // §5.57 token 观测：complete_detailed 返回文本 + provider 上报的用量（None=未上报）
        let completion = self.provider().complete_detailed(&system_prompt, q).await?;
        let answer = completion.text;
        let token_usage = completion.usage;
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
            token_usage,
        })
    }

    // ==================== AI-02：查询历史持久化（§5.39/§5.41） ====================

    /// 重放本人历史（AI-02 决策 2"SQL 可重放"）：
    /// ①本人行校验（横向越权防护）②**重新过 sql_guard**（白名单/租户过滤可能已
    /// 变更，绝不信任历史 SQL 直执行）③受控执行。失败留痕行（sql_text 空）不可重放。
    pub async fn replay(
        &self,
        history_id: i64,
        tenant_id: i64,
        user_id: i64,
    ) -> Result<AiChatOutcome> {
        let backend = self.db.get_database_backend();
        let row = self
            .db
            .query_one_raw(crate::common::sql_dialect::stmt(
                backend,
                "SELECT question, sql_text FROM ai_chat_history WHERE id = ? AND tenant_id = ? AND user_id = ?",
                [history_id.into(), tenant_id.into(), user_id.into()],
            ))
            .await?
            .context("历史记录不存在或无权重放")?;
        let question: String = row.try_get("", "question")?;
        let sql: String = row.try_get("", "sql_text")?;
        if sql.trim().is_empty() {
            anyhow::bail!("该历史为失败留痕（无可重放 SQL）");
        }
        let guarded = sql_guard::guard(
            &sql,
            tenant_id,
            &self.config.allowed_tables,
            self.config.max_rows,
        )
        .map_err(|v| {
            anyhow::anyhow!("历史 SQL 未通过当前安全校验（白名单或租户范围可能已变更）: {v}")
        })?;
        let (columns, rows) = self.execute_rows(&guarded.sql).await?;
        Ok(AiChatOutcome {
            sql: guarded.sql,
            tables: guarded.tables,
            columns,
            rows,
            answer: format!("重放自历史 #{history_id}：{question}"),
            // 重放不调用 LLM——无用量数据
            token_usage: None,
        })
    }

    /// 写入一条历史（**spawn 调用，失败仅 error 日志不阻塞响应**）。
    /// 不存结果集本体（SQL 可重放设计，§5.39 决策 2）；guard 拒绝也留痕（success='0'）。
    /// §5.57：usage 为 provider 返回的 token 用量（None = provider 未上报）。
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
        usage: Option<crate::ai::provider::TokenUsage>,
    ) {
        let backend = self.db.get_database_backend();
        let stmt = crate::common::sql_dialect::stmt(
            backend,
            "INSERT INTO ai_chat_history (tenant_id, user_id, question, sql_text, tables_used, columns_json, rows_count, duration_ms, success, error_msg, prompt_tokens, completion_tokens, total_tokens, create_time) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            [
                tenant_id.into(),
                user_id.into(),
                question.into(),
                sql.into(),
                tables.join(",").into(),
                serde_json::to_string(columns)
                    .unwrap_or_else(|_| "[]".into())
                    .into(),
                (rows_count as i64).into(),
                (duration_ms as i64).into(),
                (if success { "1" } else { "0" }).into(),
                error_msg.unwrap_or_default().into(),
                usage.map(|u| u.prompt_tokens).into(),
                usage.map(|u| u.completion_tokens).into(),
                usage.map(|u| u.total_tokens).into(),
                // b83：原交给 `CURRENT_TIMESTAMP`（SQLite 落 UTC、MySQL/PG 落会话时区，
                // compose 给 PG 设 TZ=Asia/Shanghai ⇒ 同语句差 8 小时）。历史表要与
                // 保留期清理、列表排序同口径，一律走 `now_naive()` 这一份事实源。
                crate::common::datetime::now_naive().into(),
            ],
        );
        if let Err(e) = self.db.execute_raw(stmt).await {
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
            .query_one_raw(crate::common::sql_dialect::stmt(
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
            .query_all_raw(crate::common::sql_dialect::stmt(
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
            .query_one_raw(crate::common::sql_dialect::stmt(
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
            .query_all_raw(crate::common::sql_dialect::stmt(
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
                    // 列名是 `tenant_id` / `user_id`（见上面的 SELECT）；按 camelCase 去取会恒得 0，
                    // 而 `unwrap_or(0)` 把"取不到列"洗成合法值 ⇒ 前端两列对每行都显示 0（b97 实测）。
                    "tenantId": r.try_get::<i64>("", "tenant_id").unwrap_or(0),
                    "userId": r.try_get::<i64>("", "user_id").unwrap_or(0),
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

    /// 导出管理/平台视图历史（§5.55 AI-02 结果导出）：
    /// 与 list_admin_history 同口径（租户过滤一致），但 size 上限放宽到
    /// EXPORT_MAX_ROWS（导出语义）——复用同一 SQL 生成路径。
    pub async fn export_admin_history(
        &self,
        caller_tid: i64,
        tenant_filter: Option<i64>,
        max_rows: u64,
    ) -> Result<Vec<serde_json::Value>, anyhow::Error> {
        let size = max_rows.clamp(1, crate::common::page::EXPORT_MAX_ROWS);
        let (items, _) = self
            .list_admin_history(caller_tid, tenant_filter, 1, size)
            .await?;
        Ok(items)
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
            .execute_raw(crate::common::sql_dialect::stmt(
                backend,
                "DELETE FROM ai_chat_history WHERE id = ? AND tenant_id = ? AND user_id = ?",
                [id.into(), tenant_id.into(), user_id.into()],
            ))
            .await?;
        Ok(res.rows_affected() > 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sea_orm::Database;

    /// 管理视图的 `tenantId` / `userId` 必须取自真实列名 `tenant_id` / `user_id`。
    ///
    /// 立据（b97）：原实现按 **camelCase** 去 `try_get` 列，而 SELECT 选的是 snake_case
    /// ⇒ 两列恒为 0，前端「租户 / 用户」两列对每一行都显示 0；`try_get(...).unwrap_or(0)`
    /// 把"取不到列"洗成了一个合法值，所以断言必须落在**真实值**上（0 恰好也是缺省值）。
    #[tokio::test]
    async fn admin_history_maps_tenant_and_user_from_snake_case_columns() {
        let db = Database::connect("sqlite::memory:")
            .await
            .expect("内存库建连");
        db.execute_unprepared(
            "CREATE TABLE ai_chat_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                tenant_id INTEGER NOT NULL,
                user_id INTEGER NOT NULL,
                question TEXT NOT NULL DEFAULT '',
                sql_text TEXT NOT NULL DEFAULT '',
                tables_used TEXT NOT NULL DEFAULT '',
                rows_count INTEGER NOT NULL DEFAULT 0,
                duration_ms INTEGER NOT NULL DEFAULT 0,
                success TEXT NOT NULL DEFAULT '1',
                error_msg TEXT,
                create_time TEXT NOT NULL DEFAULT ''
            )",
        )
        .await
        .expect("建表");
        db.execute_unprepared(
            "INSERT INTO ai_chat_history (tenant_id, user_id, question, rows_count, create_time) \
             VALUES (7, 9, 'q', 3, '2026-10-26 00:00:00')",
        )
        .await
        .expect("插入夹具");

        let svc = AiService::new(db, AiConfig::default());
        let (items, total) = svc.list_admin_history(0, None, 1, 10).await.expect("查询");
        assert_eq!(total, 1);
        assert_eq!(items[0]["tenantId"], 7, "必须取自 tenant_id 列");
        assert_eq!(items[0]["userId"], 9, "必须取自 user_id 列");
        assert_eq!(items[0]["question"], "q");
        assert_eq!(items[0]["rowsCount"], 3);
        assert_eq!(items[0]["success"], true);
    }
}
