// stepby-axum/src/service/sys_audit_change_service.rs
//! 审计合规域 Service 层（业务数据变更留痕）
//!
//! 职责：
//! - 变更留痕写入：[`record_change`]（供各业务 service 在事务内调用，
//!   计算 before/after 字段级 diff、敏感列脱敏、落库 sys_audit_change）
//! - 操作人补齐：[`resolve_operator`]（service 层签名通常只带用户名或用户 ID 之一，
//!   在事务内回查 sys_user 补齐 (id, name)，回查失败降级不阻断业务）
//! - 变更记录分页 / 详情 / 导出查询
//!
//! 不依赖任何 Web 框架类型（axum / tower / tower-http）

use sea_orm::{ConnectionTrait, DatabaseConnection, Set};
use serde::Deserialize;
use serde_json::Value;
use utoipa::{IntoParams, ToSchema};

use crate::common::error::ServiceError;
use crate::common::page::{PageDomain, default_page_num, default_page_size};
use crate::common::sort::{self, SortOrder};
use crate::entity::sys_audit_change::{
    ActiveModel as AuditChangeActiveModel, Column as AuditChangeColumn, Entity, Model,
};
// 动作常量随 service 一并 re-export，业务调用点免探 entity 路径
pub use crate::entity::sys_audit_change::{ACTION_DELETE, ACTION_INSERT, ACTION_UPDATE};
use crate::repository::sys_audit_change::SysAuditChangeRepository;

// ==================== 变更留痕写入（供业务 service 在事务内调用） ====================

/// 敏感列名关键字（小写匹配）：快照中键名包含任一关键字的值打码为 "***"。
///
/// 覆盖 password / pwd（密码）、secret（回调签名密钥 / 客户端密钥）、
/// token（PAT / 第三方令牌）三类高危列；快照仅用于审计回溯，无需还原原值。
const SENSITIVE_KEY_MARKS: &[&str] = &["password", "pwd", "secret", "token"];

/// 敏感值打码占位符
const MASK: &str = "***";

/// 记录一条业务数据变更留痕（审计合规域入口）。
///
/// 由业务写路径在**既有事务内**调用（`conn` 传事务句柄），变更记录与业务写入
/// 同事务提交/回滚——审计留痕完整性优先：本函数失败会令业务事务一并回滚，
/// 杜绝"变更已发生但无痕"的合规缺口。sys_audit_change 表由迁移
/// `m20261003_000001_audit_change` 与 initialize 兜底共同保证存在。
///
/// # 参数
/// - `conn`：数据库连接或事务句柄（`ConnectionTrait`）
/// - `table`：被变更的表名（如 `sys_user`）
/// - `pk`：被变更行的主键值（字符串化）
/// - `action`：`INSERT` / `UPDATE` / `DELETE`（见 entity 常量）
/// - `before`：变更前快照（原始 JSON；INSERT 传 None；敏感列在本函数内统一打码）
/// - `after`：变更后快照（原始 JSON；DELETE 传 None；敏感列在本函数内统一打码）
/// - `operator`：(操作人用户 ID, 用户名)。ID 未知传 0、用户名未知传空串
///   （可先用 [`resolve_operator`] 回查补齐）
pub async fn record_change<C: ConnectionTrait>(
    conn: &C,
    table: &str,
    pk: &str,
    action: &str,
    before: Option<Value>,
    after: Option<Value>,
    operator: (i64, String),
) -> Result<(), sea_orm::DbErr> {
    // 1. 敏感列脱敏（内聚在审计层，调用方传原始快照即可）
    let before = before.map(sanitize_snapshot);
    let after = after.map(sanitize_snapshot);

    // 2. 字段级 diff：比较前后快照键值差异生成 changed_fields（JSON 数组）
    let changed = diff_changed_fields(before.as_ref(), after.as_ref());

    // 3. 租户归属提取：优先取快照内的 tenant_id（业务表多租户行自描述）。
    //    实体 Model 带 serde rename_all=camelCase，序列化键为 tenantId；
    //    手工构造的快照可能是 snake_case——两种键名都尝试，兼容两端。
    //    缺省不设置该列（落 DB 默认值 0 = 平台）
    let pick_tenant = |v: &Value| -> Option<i64> {
        v.get("tenantId")
            .or_else(|| v.get("tenant_id"))
            .and_then(Value::as_i64)
    };
    let tenant_id = before
        .as_ref()
        .and_then(pick_tenant)
        .or_else(|| after.as_ref().and_then(pick_tenant));

    // 4. 序列化快照（INSERT 时 before 为 None、DELETE 时 after 为 None 由调用方保证）
    let before_json = before
        .as_ref()
        .map(|v| serde_json::to_string(v).unwrap_or_else(|_| "{}".to_string()));
    let after_json = after
        .as_ref()
        .map(|v| serde_json::to_string(v).unwrap_or_else(|_| "{}".to_string()));

    let mut am = AuditChangeActiveModel {
        table_name: Set(table.to_string()),
        row_pk: Set(pk.to_string()),
        action: Set(action.to_string()),
        changed_fields: Set(serde_json::to_string(&changed).unwrap_or_else(|_| "[]".to_string())),
        before_data: Set(before_json),
        after_data: Set(after_json),
        // 操作人 ID=0 或名为空视为未知（0 不映射到任何真实用户；空串存 NULL）
        operator_id: Set(if operator.0 > 0 { Some(operator.0) } else { None }),
        operator_name: Set(if operator.1.is_empty() {
            None
        } else {
            Some(operator.1)
        }),
        operated_at: Set(crate::common::datetime::now_naive()),
        ..Default::default()
    };
    // tenant_id：有快照依据才显式写入，否则交由 DB 默认值 0
    if let Some(tid) = tenant_id {
        am.tenant_id = Set(tid);
    }

    use sea_orm::EntityTrait;
    Entity::insert(am).exec(conn).await?;
    Ok(())
}

/// 敏感列脱敏：递归遍历 JSON，键名含敏感关键字的字符串值替换为 "***"。
///
/// 业务模型快照均为扁平对象，递归仅作纵深防御（嵌套结构同样覆盖）。
pub fn sanitize_snapshot(value: Value) -> Value {
    match value {
        Value::Object(map) => {
            let mut out = serde_json::Map::with_capacity(map.len());
            for (k, v) in map {
                let kl = k.to_ascii_lowercase();
                if SENSITIVE_KEY_MARKS.iter().any(|m| kl.contains(m)) {
                    out.insert(k, Value::String(MASK.to_string()));
                } else {
                    out.insert(k, sanitize_snapshot(v));
                }
            }
            Value::Object(out)
        }
        Value::Array(arr) => Value::Array(arr.into_iter().map(sanitize_snapshot).collect()),
        other => other,
    }
}

/// 计算前后快照的字段级差异，返回发生变化的字段名清单（按字母序稳定输出）。
///
/// 口径：
/// - INSERT（before=None）：全部 after 键视为新变更字段
/// - DELETE（after=None）：全部 before 键视为被移除字段
/// - UPDATE：键值不同的字段（含单侧新增/删除的键）
pub fn diff_changed_fields(before: Option<&Value>, after: Option<&Value>) -> Vec<String> {
    let mut changed: Vec<String> = Vec::new();
    match (before, after) {
        (None, Some(Value::Object(map))) => changed.extend(map.keys().cloned()),
        (Some(Value::Object(map)), None) => changed.extend(map.keys().cloned()),
        (Some(Value::Object(b)), Some(Value::Object(a))) => {
            // 并集遍历：值不同（含单侧存在）即视为变更
            let mut keys: std::collections::BTreeSet<&String> = b.keys().collect();
            keys.extend(a.keys());
            for k in keys {
                if b.get(k) != a.get(k) {
                    changed.push(k.clone());
                }
            }
        }
        _ => {}
    }
    changed.sort();
    changed.dedup();
    changed
}

/// 回查补齐操作人 (user_id, user_name)。
///
/// 业务 service 的既有签名通常只携带操作人用户名（`operator: &str`）或用户 ID
/// （`operator_user_id: i64`）之一；本函数在事务连接内按缺失侧回查 sys_user 补齐：
/// - 两者都有 → 原样返回（零查询）
/// - 有 ID 无名 → 按 user_id 查 user_name
/// - 有名无 ID → 按 user_name 查 user_id（排除软删行，取第一条）
/// - 均无 → (0, "")
///
/// 回查失败降级为 (0, name) / (id, "")，**不阻断业务事务**——操作人信息缺失
/// 可接受（列可空），业务写入失败不可接受。
pub async fn resolve_operator<C: ConnectionTrait>(
    conn: &C,
    user_id: Option<i64>,
    user_name: Option<&str>,
) -> (i64, String) {
    use sea_orm::{DatabaseBackend, Statement};

    let backend = conn.get_database_backend();
    let marker = |sql: &str| -> String {
        if backend == DatabaseBackend::Postgres {
            sql.replace("?", "$1")
        } else {
            sql.to_string()
        }
    };

    match (user_id, user_name) {
        (Some(id), Some(name)) => (id, name.to_string()),
        (Some(id), None) => {
            let sql = marker("SELECT user_name FROM sys_user WHERE user_id = ? LIMIT 1");
            let row = conn
                .query_one(Statement::from_sql_and_values(
                    backend,
                    &sql,
                    [id.into()],
                ))
                .await
                .ok()
                .flatten();
            let name = row
                .and_then(|r| r.try_get::<String>("", "user_name").ok())
                .unwrap_or_default();
            (id, name)
        }
        (None, Some(name)) => {
            // 排除软删行：软删用户 user_name 已被释放改写，不会撞正常名
            let sql = marker("SELECT user_id FROM sys_user WHERE user_name = ? AND (del_flag IS NULL OR del_flag <> '2') LIMIT 1");
            let row = conn
                .query_one(Statement::from_sql_and_values(
                    backend,
                    &sql,
                    [name.into()],
                ))
                .await
                .ok()
                .flatten();
            let id = row
                .and_then(|r| r.try_get::<i64>("", "user_id").ok())
                .unwrap_or(0);
            (id, name.to_string())
        }
        (None, None) => (0, String::new()),
    }
}

// ==================== DTO ====================

/// 变更留痕分页查询 DTO
#[derive(Debug, Clone, Deserialize, IntoParams, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct AuditChangeQueryDto {
    #[serde(default = "default_page_num")]
    pub page_num: u64,
    #[serde(default = "default_page_size")]
    pub page_size: u64,
    /// 排序字段（前端表头 prop，camelCase/snake_case 均可；经列白名单映射后生效）
    #[serde(default)]
    pub order_by_column: Option<String>,
    /// 排序方向 asc / ascending / desc / descending（缺省 desc）
    #[serde(default)]
    pub is_asc: Option<String>,
    /// 表名（精确）
    pub table_name: Option<String>,
    /// 行主键（精确）
    pub row_pk: Option<String>,
    /// 变更动作（精确：INSERT / UPDATE / DELETE）
    pub action: Option<String>,
    /// 操作人用户名（模糊）
    pub operator_name: Option<String>,
    /// 开始时间（兼容前端 addDateRange 嵌套格式 params[beginTime]）
    #[serde(alias = "params[beginTime]", default)]
    pub begin_time: Option<String>,
    /// 结束时间（兼容前端 addDateRange 嵌套格式 params[endTime]）
    #[serde(alias = "params[endTime]", default)]
    pub end_time: Option<String>,
}

impl From<&AuditChangeQueryDto> for PageDomain {
    fn from(dto: &AuditChangeQueryDto) -> Self {
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

/// 允许排序的列白名单（数据库列名 snake_case；前端 prop 经 camel_to_snake 归一后匹配）。
///
/// 覆盖审计列表业务展示列；before_data / after_data / changed_fields 等大字段与
/// tenant_id / row_pk 等内部列不开放动态排序。
pub const SORTABLE_COLUMNS: &[(&str, AuditChangeColumn)] = &[
    ("operated_at", AuditChangeColumn::OperatedAt),
    ("table_name", AuditChangeColumn::TableName),
    ("action", AuditChangeColumn::Action),
    ("operator_name", AuditChangeColumn::OperatorName),
];

// ==================== Service 实现 ====================

/// 审计变更模块 Service
#[derive(Clone)]
pub struct SysAuditChangeService {
    repo: SysAuditChangeRepository,
}

impl SysAuditChangeService {
    pub fn new(db: DatabaseConnection) -> Self {
        Self {
            repo: SysAuditChangeRepository::new(db),
        }
    }

    /// 分页查询变更留痕
    ///
    /// 过滤：table_name / row_pk / action 精确、operator_name 模糊、时间范围；
    /// 动态排序走白名单（未命中回退默认 id DESC）。
    pub async fn get_change_page(
        &self,
        query: AuditChangeQueryDto,
        tenant_scope: Option<i64>,
    ) -> Result<(Vec<Model>, u64), ServiceError> {
        let page = PageDomain::from(&query);
        let offset = page.offset();
        let limit = page.limit();
        // 动态排序：白名单命中才生效，未命中/缺省由 repository 回退默认排序
        let sort = page.order_by_column.as_deref().and_then(|prop| {
            sort::resolve_column::<Entity>(prop, SORTABLE_COLUMNS)
                .map(|col| SortOrder::new(col, sort::parse_direction(page.is_asc.as_deref())))
        });

        let begin = match query.begin_time.as_deref() {
            Some(s) if !s.is_empty() => Some(crate::common::datetime::parse_query_date(s)?),
            _ => None,
        };
        let end = match query.end_time.as_deref() {
            Some(s) if !s.is_empty() => Some(crate::common::datetime::parse_query_date(s)?),
            _ => None,
        };

        let (rows, total) = self
            .repo
            .find_page_filtered(
                offset,
                limit,
                query.table_name.as_deref(),
                query.row_pk.as_deref(),
                query.action.as_deref(),
                query.operator_name.as_deref(),
                begin,
                end,
                tenant_scope,
                sort,
            )
            .await?;
        Ok((rows, total))
    }

    /// 查询变更留痕详情
    pub async fn get_change_detail(&self, id: i64) -> Result<Model, ServiceError> {
        self.repo
            .base()
            .find_by_id(id)
            .await?
            .ok_or_else(|| ServiceError::not_found(&crate::tr!("error.audit_change.not_found")))
    }

    /// 导出变更留痕（受 EXPORT_MAX_ROWS 限制，绕过 PageDomain 的 100 行截断）
    ///
    /// 与页面列表同过滤口径；导出 DTO 未暴露排序参数，走默认排序（id DESC）。
    pub async fn export_changes(
        &self,
        query: AuditChangeQueryDto,
        tenant_scope: Option<i64>,
    ) -> Result<Vec<Model>, ServiceError> {
        let begin = match query.begin_time.as_deref() {
            Some(s) if !s.is_empty() => Some(crate::common::datetime::parse_query_date(s)?),
            _ => None,
        };
        let end = match query.end_time.as_deref() {
            Some(s) if !s.is_empty() => Some(crate::common::datetime::parse_query_date(s)?),
            _ => None,
        };

        let rows = self
            .repo
            .find_all_filtered(
                crate::common::page::EXPORT_MAX_ROWS,
                query.table_name.as_deref(),
                query.row_pk.as_deref(),
                query.action.as_deref(),
                query.operator_name.as_deref(),
                begin,
                end,
                tenant_scope,
            )
            .await?;
        Ok(rows)
    }
}

// ==================== 审计快捷入口（收敛业务域接入样板） ====================
//
// 2026-10-04 全链路核查补录：sys_audit_change 写入方此前仅 user/role/config/web_hook
// 四域，其余域接入需重复"resolve_operator + to_value 快照 + record_change"三步样板
// （每处 ~18 行）。本组快捷函数把样板收敛为一行调用，按 action 语义拆分：
// - INSERT：before 恒 None
// - UPDATE：before/after 均必需（字段级 diff 的意义所在）
// - DELETE：after 恒 None
// 操作人信息缺失侧由 resolve_operator 在事务内回查补齐（既有口径不变）。

/// INSERT 变更留痕快捷入口（`after` 传插入后的 Model 引用）
pub async fn audit_insert<C: ConnectionTrait, S: serde::Serialize>(
    conn: &C,
    table: &str,
    pk: &str,
    after: &S,
    operator_user_id: Option<i64>,
    operator_name: Option<&str>,
) -> Result<(), sea_orm::DbErr> {
    let operator = resolve_operator(conn, operator_user_id, operator_name).await;
    let after = serde_json::to_value(after).unwrap_or(Value::Null);
    record_change(conn, table, pk, ACTION_INSERT, None, Some(after), operator).await
}

/// UPDATE 变更留痕快捷入口（`before` 传事务内改前快照、`after` 传改后 Model 引用）
pub async fn audit_update<C: ConnectionTrait, B: serde::Serialize, A: serde::Serialize>(
    conn: &C,
    table: &str,
    pk: &str,
    before: &B,
    after: &A,
    operator_user_id: Option<i64>,
    operator_name: Option<&str>,
) -> Result<(), sea_orm::DbErr> {
    let operator = resolve_operator(conn, operator_user_id, operator_name).await;
    let before = serde_json::to_value(before).unwrap_or(Value::Null);
    let after = serde_json::to_value(after).unwrap_or(Value::Null);
    record_change(conn, table, pk, ACTION_UPDATE, Some(before), Some(after), operator).await
}

/// DELETE 变更留痕快捷入口（`before` 传事务内删除前 Model 引用）
pub async fn audit_delete<C: ConnectionTrait, S: serde::Serialize>(
    conn: &C,
    table: &str,
    pk: &str,
    before: &S,
    operator_user_id: Option<i64>,
    operator_name: Option<&str>,
) -> Result<(), sea_orm::DbErr> {
    let operator = resolve_operator(conn, operator_user_id, operator_name).await;
    let before = serde_json::to_value(before).unwrap_or(Value::Null);
    record_change(conn, table, pk, ACTION_DELETE, Some(before), None, operator).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn diff_insert_lists_all_after_keys() {
        let after = json!({"status": "0", "del_flag": "0", "nick_name": "A"});
        let mut changed = diff_changed_fields(None, Some(&after));
        changed.sort();
        assert_eq!(changed, vec!["del_flag", "nick_name", "status"]);
    }

    #[test]
    fn diff_delete_lists_all_before_keys() {
        let before = json!({"user_name": "bob", "status": "1"});
        let mut changed = diff_changed_fields(Some(&before), None);
        changed.sort();
        assert_eq!(changed, vec!["status", "user_name"]);
    }

    #[test]
    fn diff_update_only_changed_keys() {
        let before = json!({"status": "0", "email": "a@x.com", "same": 1});
        let after = json!({"status": "1", "email": "a@x.com", "same": 1});
        assert_eq!(diff_changed_fields(Some(&before), Some(&after)), vec!["status"]);
    }

    #[test]
    fn diff_update_includes_added_and_removed_keys() {
        let before = json!({"old_key": 1, "keep": 2});
        let after = json!({"new_key": 3, "keep": 2});
        let mut changed = diff_changed_fields(Some(&before), Some(&after));
        changed.sort();
        assert_eq!(changed, vec!["new_key", "old_key"]);
    }

    #[test]
    fn sanitize_masks_sensitive_keys_case_insensitive() {
        let v = json!({
            "user_name": "bob",
            "password": "$argon2id$hash",
            "PassWord": "x",
            "secret": "hmac-key",
            "accessToken": "tok-123",
            "nested": { "client_secret": "s", "plain": 1 }
        });
        let masked = sanitize_snapshot(v);
        assert_eq!(masked["user_name"], "bob");
        assert_eq!(masked["password"], "***");
        assert_eq!(masked["PassWord"], "***");
        assert_eq!(masked["secret"], "***");
        assert_eq!(masked["accessToken"], "***");
        assert_eq!(masked["nested"]["client_secret"], "***");
        assert_eq!(masked["nested"]["plain"], 1);
    }

    #[test]
    fn sanitize_keeps_non_object_values() {
        assert_eq!(sanitize_snapshot(json!(42)), json!(42));
        assert_eq!(sanitize_snapshot(json!([1, 2])), json!([1, 2]));
        assert_eq!(sanitize_snapshot(json!(null)), json!(null));
    }

    /// 快捷入口端到端：同一事务内 INSERT/UPDATE/DELETE 三连写，
    /// 断言 action 语义（before/after 侧）、操作人回查与敏感列脱敏全部正确落库。
    #[tokio::test]
    async fn audit_helpers_write_correct_action_semantics() {
        use sea_orm::TransactionTrait;
        let db = crate::repository::test_support::migrated_db().await.unwrap();
        let after_model = json!({"id": 7_i64, "name": "demo", "password": "plain-secret"});

        let txn = db.begin().await.unwrap();
        audit_insert(&txn, "sys_demo", "7", &after_model, None, Some("admin"))
            .await
            .unwrap();
        audit_update(
            &txn,
            "sys_demo",
            "7",
            &after_model,
            &json!({"id": 7_i64, "name": "demo2"}),
            None,
            Some("admin"),
        )
        .await
        .unwrap();
        audit_delete(
            &txn,
            "sys_demo",
            "7",
            &json!({"id": 7_i64, "name": "demo2"}),
            None,
            Some("admin"),
        )
        .await
        .unwrap();
        txn.commit().await.unwrap();

        use sea_orm::{EntityTrait, QueryOrder};
        let rows = crate::entity::sys_audit_change::Entity::find()
            .order_by_asc(crate::entity::sys_audit_change::Column::Id)
            .all(&db)
            .await
            .unwrap();
        assert_eq!(rows.len(), 3);

        // INSERT：before 为空、after 有值且敏感列已打码；操作人按用户名回查成功（admin=1）
        assert_eq!(rows[0].action, "INSERT");
        assert!(rows[0].before_data.is_none());
        let after0: Value = serde_json::from_str(rows[0].after_data.as_deref().unwrap()).unwrap();
        assert_eq!(after0["password"], "***");
        assert_eq!(rows[0].operator_name.as_deref(), Some("admin"));
        assert_eq!(rows[0].operator_id, Some(1));

        // UPDATE：两侧均有值，changed_fields 捕获 name 变更（password 值未变不重复计入）
        assert_eq!(rows[1].action, "UPDATE");
        let changed1: Vec<String> =
            serde_json::from_str(rows[1].changed_fields.as_str()).unwrap();
        assert!(changed1.contains(&"name".to_string()));

        // DELETE：after 为空、before 有值
        assert_eq!(rows[2].action, "DELETE");
        assert!(rows[2].after_data.is_none());
        let before2: Value = serde_json::from_str(rows[2].before_data.as_deref().unwrap()).unwrap();
        assert_eq!(before2["name"], "demo2");
    }
}
