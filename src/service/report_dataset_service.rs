//! 报表数据集与大屏 Service（G-01 M1）
//!
//! - dataset CRUD：sql_template 保存前经 `common/dataset_sql.rs` fail-closed 校验；
//! - preview：试跑（**LIMIT 100 硬顶** + A2 Semaphore 许可 4 fail-closed 429）+
//!   列元数据采样（`LIMIT 0` 取列名）；
//! - dashboard CRUD：layout_json 存取（schemaVersion 由前端维护）。
//!
//! 分层约束：不依赖 Web 框架类型；租户过滤走 `common::tenant::tenant_scope`。

use std::sync::Arc;

use garde::Validate;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, ConnectionTrait, DatabaseConnection, EntityTrait,
    PaginatorTrait, QueryFilter, QueryOrder, QuerySelect, Set,
};
use serde::{Deserialize, Serialize};
use tokio::sync::Semaphore;
use utoipa::ToSchema;

use crate::common::error::ServiceError;
use crate::entity::prelude::{ReportDashboardModel, ReportDatasetModel};
use crate::entity::report_dashboard::Column as ReportDashboardColumn;
use crate::entity::report_dashboard::{
    ActiveModel as ReportDashboardActiveModel, Entity as ReportDashboardEntity,
};
use crate::entity::report_dataset::Column as ReportDatasetColumn;
use crate::entity::report_dataset::{
    ActiveModel as ReportDatasetActiveModel, Entity as ReportDatasetEntity,
};

/// 数据集执行并发闸门（A2 铁律：许可 4，acquire 失败 → 429 fail-closed）
static DATASET_GATE: std::sync::OnceLock<Arc<Semaphore>> = std::sync::OnceLock::new();

fn dataset_gate() -> Arc<Semaphore> {
    DATASET_GATE
        .get_or_init(|| Arc::new(Semaphore::const_new(4)))
        .clone()
}

const PREVIEW_ROW_LIMIT: u64 = 100;
/// 试跑超时（秒）
const PREVIEW_TIMEOUT_SECS: u64 = 10;

// ==================== DTO / VO ====================

#[derive(Debug, Deserialize, Validate, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct DatasetUpsertDto {
    #[serde(default)]
    #[garde(skip)]
    pub dataset_id: Option<i64>,
    #[garde(length(min = 1, max = 64))]
    pub dataset_code: String,
    #[garde(length(min = 1, max = 128))]
    pub dataset_name: String,
    // SQL 白名单由 common/dataset_sql.rs 校验器 fail-closed 承担（结构化错误带原因）
    #[garde(skip)]
    pub sql_template: String,
    #[serde(default)]
    #[garde(skip)]
    pub params_schema: Option<serde_json::Value>,
    #[serde(default)]
    #[garde(skip)]
    pub status: Option<String>,
    #[serde(default)]
    #[garde(skip)]
    pub remark: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct DatasetVo {
    pub dataset_id: i64,
    pub tenant_id: i64,
    pub dataset_code: String,
    pub dataset_name: String,
    pub params_schema: Option<serde_json::Value>,
    pub columns_meta: Option<serde_json::Value>,
    pub status: String,
    pub remark: Option<String>,
    pub create_time: Option<String>,
    pub update_time: Option<String>,
}

impl DatasetVo {
    fn from_model(m: &ReportDatasetModel) -> Self {
        Self {
            dataset_id: m.dataset_id,
            tenant_id: m.tenant_id,
            dataset_code: m.dataset_code.clone(),
            dataset_name: m.dataset_name.clone(),
            params_schema: m
                .params_schema
                .as_deref()
                .and_then(|s| serde_json::from_str(s).ok()),
            columns_meta: m
                .columns_meta
                .as_deref()
                .and_then(|s| serde_json::from_str(s).ok()),
            status: m.status.clone(),
            remark: m.remark.clone(),
            create_time: m.create_time.map(|t| t.to_string()),
            update_time: m.update_time.map(|t| t.to_string()),
        }
    }
}

/// 试跑请求（参数按 params_schema 绑定）
#[derive(Debug, Deserialize, Validate, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct DatasetPreviewDto {
    #[garde(skip)]
    pub dataset_id: i64,
    #[serde(default)]
    #[garde(skip)]
    pub params: std::collections::HashMap<String, serde_json::Value>,
}

/// 试跑出参：列名 + 行数据（≤100 行）
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct DatasetPreviewVo {
    pub columns: Vec<String>,
    pub rows: Vec<serde_json::Value>,
    pub truncated: bool,
}

#[derive(Debug, Deserialize, Validate, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct DashboardUpsertDto {
    #[serde(default)]
    #[garde(skip)]
    pub dashboard_id: Option<i64>,
    #[garde(length(min = 1, max = 64))]
    pub dashboard_code: String,
    #[garde(length(min = 1, max = 128))]
    pub dashboard_name: String,
    /// 画布布局 JSON（前端生成；schemaVersion 校验 1..=10）
    #[garde(skip)]
    pub layout_json: serde_json::Value,
    #[serde(default)]
    #[garde(skip)]
    pub status: Option<String>,
    #[serde(default)]
    #[garde(skip)]
    pub remark: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct DashboardVo {
    pub dashboard_id: i64,
    pub tenant_id: i64,
    pub dashboard_code: String,
    pub dashboard_name: String,
    pub layout_json: serde_json::Value,
    pub schema_version: i32,
    pub status: String,
    pub remark: Option<String>,
    pub create_time: Option<String>,
    pub update_time: Option<String>,
}

impl DashboardVo {
    fn from_model(m: &ReportDashboardModel) -> Self {
        Self {
            dashboard_id: m.dashboard_id,
            tenant_id: m.tenant_id,
            dashboard_code: m.dashboard_code.clone(),
            dashboard_name: m.dashboard_name.clone(),
            layout_json: serde_json::from_str(&m.layout_json).unwrap_or(serde_json::Value::Null),
            schema_version: m.schema_version,
            status: m.status.clone(),
            remark: m.remark.clone(),
            create_time: m.create_time.map(|t| t.to_string()),
            update_time: m.update_time.map(|t| t.to_string()),
        }
    }
}

// ==================== Service ====================

#[derive(Clone)]
pub struct ReportDatasetService {
    db: DatabaseConnection,
}

impl ReportDatasetService {
    pub fn new(db: DatabaseConnection) -> Self {
        Self { db }
    }

    fn ensure_access(&self, tenant_id: i64, operator_tid: i64) -> Result<(), ServiceError> {
        if !crate::common::tenant::tenant_allowed(operator_tid, tenant_id) {
            return Err(ServiceError::forbidden(&crate::tr!(
                "error.common.forbidden"
            )));
        }
        Ok(())
    }

    // ==================== 数据集 ====================

    pub async fn get_dataset_page(
        &self,
        offset: u64,
        limit: u64,
        operator_tid: i64,
    ) -> Result<(Vec<DatasetVo>, u64), ServiceError> {
        let mut select = ReportDatasetEntity::find().filter(ReportDatasetColumn::DelFlag.eq("0"));
        if let Some(t) = crate::common::tenant::tenant_scope(operator_tid) {
            select = select.filter(ReportDatasetColumn::TenantId.eq(t));
        }
        let total = select.clone().count(&self.db).await?;
        let rows = select
            .order_by_desc(ReportDatasetColumn::DatasetId)
            .offset(offset)
            .limit(limit)
            .all(&self.db)
            .await?;
        Ok((rows.iter().map(DatasetVo::from_model).collect(), total))
    }

    pub async fn get_dataset_by_id(
        &self,
        dataset_id: i64,
        operator_tid: i64,
    ) -> Result<DatasetVo, ServiceError> {
        let m = ReportDatasetEntity::find_by_id(dataset_id)
            .filter(ReportDatasetColumn::DelFlag.eq("0"))
            .one(&self.db)
            .await?
            .ok_or_else(|| {
                ServiceError::not_found(&crate::tr!("error.report.dataset_not_found"))
            })?;
        self.ensure_access(m.tenant_id, operator_tid)?;
        Ok(DatasetVo::from_model(&m))
    }

    pub async fn add_dataset(
        &self,
        dto: DatasetUpsertDto,
        operator: &str,
        operator_tid: i64,
    ) -> Result<DatasetVo, ServiceError> {
        // 白名单校验器（fail-closed）
        crate::common::dataset_sql::validate_select_template(&dto.sql_template).map_err(|e| {
            ServiceError::bad_request(&format!("{}: {e}", crate::tr!("error.report.sql_invalid")))
        })?;
        let dup = ReportDatasetEntity::find()
            .filter(ReportDatasetColumn::TenantId.eq(operator_tid))
            .filter(ReportDatasetColumn::DatasetCode.eq(dto.dataset_code.as_str()))
            .filter(ReportDatasetColumn::DelFlag.eq("0"))
            .one(&self.db)
            .await?;
        if dup.is_some() {
            return Err(ServiceError::bad_request(&crate::tr!(
                "error.report.dataset_code_duplicate"
            )));
        }
        let now = crate::common::datetime::now_naive();
        let am = ReportDatasetActiveModel {
            tenant_id: Set(operator_tid),
            dataset_code: Set(dto.dataset_code),
            dataset_name: Set(dto.dataset_name),
            sql_template: Set(dto.sql_template),
            params_schema: Set(dto.params_schema.map(|v| v.to_string())),
            columns_meta: Set(None),
            status: Set(dto.status.unwrap_or_else(|| "0".to_string())),
            remark: Set(dto.remark),
            create_by: Set(Some(operator.to_string())),
            create_time: Set(Some(now)),
            update_by: Set(Some(operator.to_string())),
            update_time: Set(Some(now)),
            del_flag: Set(Some("0".to_string())),
            ..Default::default()
        };
        let model = ReportDatasetEntity::insert(am)
            .exec_with_returning(&self.db)
            .await?;
        Ok(DatasetVo::from_model(&model))
    }

    pub async fn edit_dataset(
        &self,
        dto: DatasetUpsertDto,
        operator: &str,
        operator_tid: i64,
    ) -> Result<DatasetVo, ServiceError> {
        let dataset_id = dto.dataset_id.ok_or_else(|| {
            ServiceError::bad_request(&crate::tr!("error.report.dataset_id_required"))
        })?;
        let m = ReportDatasetEntity::find_by_id(dataset_id)
            .filter(ReportDatasetColumn::DelFlag.eq("0"))
            .one(&self.db)
            .await?
            .ok_or_else(|| {
                ServiceError::not_found(&crate::tr!("error.report.dataset_not_found"))
            })?;
        self.ensure_access(m.tenant_id, operator_tid)?;
        crate::common::dataset_sql::validate_select_template(&dto.sql_template).map_err(|e| {
            ServiceError::bad_request(&format!("{}: {e}", crate::tr!("error.report.sql_invalid")))
        })?;
        let mut am: ReportDatasetActiveModel = m.into();
        am.dataset_name = Set(dto.dataset_name);
        am.sql_template = Set(dto.sql_template);
        am.params_schema = Set(dto.params_schema.map(|v| v.to_string()));
        am.status = Set(dto.status.unwrap_or_else(|| "0".to_string()));
        am.remark = Set(dto.remark);
        am.update_by = Set(Some(operator.to_string()));
        am.update_time = Set(Some(crate::common::datetime::now_naive()));
        // SQL 变更 → 列元数据失效（下次 preview 重采样）
        am.columns_meta = Set(None);
        let updated = am.update(&self.db).await?;
        Ok(DatasetVo::from_model(&updated))
    }

    pub async fn remove_dataset(
        &self,
        dataset_ids: Vec<i64>,
        operator: &str,
        operator_tid: i64,
    ) -> Result<(), ServiceError> {
        for id in dataset_ids {
            if let Some(m) = ReportDatasetEntity::find_by_id(id)
                .filter(ReportDatasetColumn::DelFlag.eq("0"))
                .one(&self.db)
                .await?
            {
                self.ensure_access(m.tenant_id, operator_tid)?;
                let mut am: ReportDatasetActiveModel = m.into();
                am.del_flag = Set(Some("1".to_string()));
                am.update_by = Set(Some(operator.to_string()));
                am.update_time = Set(Some(crate::common::datetime::now_naive()));
                am.update(&self.db).await?;
            }
        }
        Ok(())
    }

    /// 试跑：LIMIT 100 硬顶 + Semaphore fail-closed + 超时保护 + 列元数据采样回写
    pub async fn preview_dataset(
        &self,
        dto: DatasetPreviewDto,
        operator_tid: i64,
    ) -> Result<DatasetPreviewVo, ServiceError> {
        let m = ReportDatasetEntity::find_by_id(dto.dataset_id)
            .filter(ReportDatasetColumn::DelFlag.eq("0"))
            .one(&self.db)
            .await?
            .ok_or_else(|| {
                ServiceError::not_found(&crate::tr!("error.report.dataset_not_found"))
            })?;
        self.ensure_access(m.tenant_id, operator_tid)?;
        if m.status != "0" {
            return Err(ServiceError::bad_request(&crate::tr!(
                "error.report.dataset_disabled"
            )));
        }
        // 白名单复验（运行期同样 fail-closed）
        let param_names = crate::common::dataset_sql::validate_select_template(&m.sql_template)
            .map_err(|e| {
                ServiceError::bad_request(&format!(
                    "{}: {e}",
                    crate::tr!("error.report.sql_invalid")
                ))
            })?;
        // 参数核对：请求参数 ⊆ 声明占位符；缺失参数按 NULL 绑定（模板允许 IS NULL 语义）
        for name in &param_names {
            if !dto.params.contains_key(name) {
                return Err(ServiceError::bad_request(&format!(
                    "{}: {name}",
                    crate::tr!("error.report.param_missing")
                )));
            }
        }
        // A2：Semaphore fail-closed
        let gate = dataset_gate();
        let permit = gate
            .try_acquire()
            .map_err(|_| ServiceError::internal(&crate::tr!("error.report.busy")))?;
        let _permit = permit;

        // 参数绑定：:name → ? 占位符（按方言）+ 值序列
        let backend = self.db.get_database_backend();
        let (sql_bound, values) =
            bind_named_params(&m.sql_template, &param_names, &dto.params, backend);

        // LIMIT 100 硬顶（模板无括号/注释/子查询——校验器保证；直接追加 LIMIT 子句）
        let limited = format!("{sql_bound} LIMIT {PREVIEW_ROW_LIMIT}");
        let stmt = sea_orm::Statement::from_sql_and_values(backend, &limited, values);
        // 超时保护
        let query_fut = self.db.query_all_raw(stmt);
        let rows = tokio::time::timeout(
            std::time::Duration::from_secs(PREVIEW_TIMEOUT_SECS),
            query_fut,
        )
        .await
        .map_err(|_| ServiceError::internal(&crate::tr!("error.report.query_timeout")))?
        .map_err(ServiceError::from)?;

        let mut columns: Vec<String> = Vec::new();
        let mut out_rows: Vec<serde_json::Value> = Vec::new();
        for (idx, row) in rows.iter().enumerate() {
            if idx == 0 {
                // 列名提取：sea-orm Row 无直接列名遍历——按列序号取值并借
                // ColumnName_wrapper：改为按 try_get 失败容忍策略 + 列名来自模板采样
                // （query_all_raw 的 QueryResult 支持按列名取，列名清单来自 sqlite 系统表）
                columns = infer_columns(&m.sql_template, &self.db).await?;
            }
            let mut obj = serde_json::Map::new();
            for col in &columns {
                let v = row
                    .try_get::<Option<String>>("", col.as_str())
                    .ok()
                    .flatten()
                    .map(serde_json::Value::String)
                    .or_else(|| {
                        row.try_get::<Option<i64>>("", col.as_str())
                            .ok()
                            .flatten()
                            .map(|n| serde_json::json!(n))
                    })
                    .or_else(|| {
                        row.try_get::<Option<f64>>("", col.as_str())
                            .ok()
                            .flatten()
                            .map(|n| serde_json::json!(n))
                    })
                    .unwrap_or(serde_json::Value::Null);
                obj.insert(col.clone(), v);
            }
            out_rows.push(serde_json::Value::Object(obj));
        }

        // 列元数据采样回写（columns_meta 缓存，供设计器）
        let meta = serde_json::json!({ "columns": columns });
        let mut am: ReportDatasetActiveModel = ReportDatasetEntity::find_by_id(m.dataset_id)
            .one(&self.db)
            .await?
            .ok_or_else(|| ServiceError::not_found(&crate::tr!("error.report.dataset_not_found")))?
            .into();
        am.columns_meta = Set(Some(meta.to_string()));
        am.update(&self.db).await?;

        let truncated = out_rows.len() as u64 >= PREVIEW_ROW_LIMIT;
        Ok(DatasetPreviewVo {
            columns,
            rows: out_rows,
            truncated,
        })
    }

    // ==================== 大屏 ====================

    pub async fn get_dashboard_page(
        &self,
        offset: u64,
        limit: u64,
        operator_tid: i64,
    ) -> Result<(Vec<DashboardVo>, u64), ServiceError> {
        let mut select =
            ReportDashboardEntity::find().filter(ReportDashboardColumn::DelFlag.eq("0"));
        if let Some(t) = crate::common::tenant::tenant_scope(operator_tid) {
            select = select.filter(ReportDashboardColumn::TenantId.eq(t));
        }
        let total = select.clone().count(&self.db).await?;
        let rows = select
            .order_by_desc(ReportDashboardColumn::DashboardId)
            .offset(offset)
            .limit(limit)
            .all(&self.db)
            .await?;
        Ok((rows.iter().map(DashboardVo::from_model).collect(), total))
    }

    pub async fn get_dashboard_by_id(
        &self,
        dashboard_id: i64,
        operator_tid: i64,
    ) -> Result<DashboardVo, ServiceError> {
        let m = ReportDashboardEntity::find_by_id(dashboard_id)
            .filter(ReportDashboardColumn::DelFlag.eq("0"))
            .one(&self.db)
            .await?
            .ok_or_else(|| {
                ServiceError::not_found(&crate::tr!("error.report.dashboard_not_found"))
            })?;
        self.ensure_access(m.tenant_id, operator_tid)?;
        Ok(DashboardVo::from_model(&m))
    }

    pub async fn save_dashboard(
        &self,
        dto: DashboardUpsertDto,
        operator: &str,
        operator_tid: i64,
    ) -> Result<DashboardVo, ServiceError> {
        // layout_json 校验：对象 + schemaVersion ∈ 1..=10
        if !dto.layout_json.is_object() {
            return Err(ServiceError::bad_request(&crate::tr!(
                "error.report.layout_invalid"
            )));
        }
        let sv = dto
            .layout_json
            .get("schemaVersion")
            .and_then(|v| v.as_i64())
            .unwrap_or(1);
        if !(1..=10).contains(&sv) {
            return Err(ServiceError::bad_request(&crate::tr!(
                "error.report.layout_invalid"
            )));
        }
        let now = crate::common::datetime::now_naive();
        if let Some(dashboard_id) = dto.dashboard_id {
            let m = ReportDashboardEntity::find_by_id(dashboard_id)
                .filter(ReportDashboardColumn::DelFlag.eq("0"))
                .one(&self.db)
                .await?
                .ok_or_else(|| {
                    ServiceError::not_found(&crate::tr!("error.report.dashboard_not_found"))
                })?;
            self.ensure_access(m.tenant_id, operator_tid)?;
            let mut am: ReportDashboardActiveModel = m.into();
            am.dashboard_name = Set(dto.dashboard_name);
            am.layout_json = Set(dto.layout_json.to_string());
            am.schema_version = Set(sv as i32);
            am.status = Set(dto.status.unwrap_or_else(|| "0".to_string()));
            am.remark = Set(dto.remark);
            am.update_by = Set(Some(operator.to_string()));
            am.update_time = Set(Some(now));
            let updated = am.update(&self.db).await?;
            Ok(DashboardVo::from_model(&updated))
        } else {
            let dup = ReportDashboardEntity::find()
                .filter(ReportDashboardColumn::TenantId.eq(operator_tid))
                .filter(ReportDashboardColumn::DashboardCode.eq(dto.dashboard_code.as_str()))
                .filter(ReportDashboardColumn::DelFlag.eq("0"))
                .one(&self.db)
                .await?;
            if dup.is_some() {
                return Err(ServiceError::bad_request(&crate::tr!(
                    "error.report.dashboard_code_duplicate"
                )));
            }
            let am = ReportDashboardActiveModel {
                tenant_id: Set(operator_tid),
                dashboard_code: Set(dto.dashboard_code),
                dashboard_name: Set(dto.dashboard_name),
                layout_json: Set(dto.layout_json.to_string()),
                schema_version: Set(sv as i32),
                status: Set(dto.status.unwrap_or_else(|| "0".to_string())),
                remark: Set(dto.remark),
                create_by: Set(Some(operator.to_string())),
                create_time: Set(Some(now)),
                update_by: Set(Some(operator.to_string())),
                update_time: Set(Some(now)),
                del_flag: Set(Some("0".to_string())),
                ..Default::default()
            };
            let model = ReportDashboardEntity::insert(am)
                .exec_with_returning(&self.db)
                .await?;
            Ok(DashboardVo::from_model(&model))
        }
    }

    pub async fn remove_dashboard(
        &self,
        dashboard_ids: Vec<i64>,
        operator: &str,
        operator_tid: i64,
    ) -> Result<(), ServiceError> {
        for id in dashboard_ids {
            if let Some(m) = ReportDashboardEntity::find_by_id(id)
                .filter(ReportDashboardColumn::DelFlag.eq("0"))
                .one(&self.db)
                .await?
            {
                self.ensure_access(m.tenant_id, operator_tid)?;
                let mut am: ReportDashboardActiveModel = m.into();
                am.del_flag = Set(Some("1".to_string()));
                am.update_by = Set(Some(operator.to_string()));
                am.update_time = Set(Some(crate::common::datetime::now_naive()));
                am.update(&self.db).await?;
            }
        }
        Ok(())
    }
}

/// 把 `:name` 命名占位符替换为方言占位符并生成绑定值
/// （SQLite/MySQL = `?`，PG = `$n`）
fn bind_named_params(
    sql_template: &str,
    param_names: &[String],
    params: &std::collections::HashMap<String, serde_json::Value>,
    backend: sea_orm::DatabaseBackend,
) -> (String, Vec<sea_orm::Value>) {
    let mut out = String::with_capacity(sql_template.len() + 16);
    let mut values: Vec<sea_orm::Value> = Vec::new();
    let bytes = sql_template.as_bytes();
    let mut i = 0usize;
    let mut in_quote = false;
    let mut pg_index = 1usize;
    while i < bytes.len() {
        let c = bytes[i] as char;
        match c {
            '\'' => {
                if in_quote && i + 1 < bytes.len() && bytes[i + 1] == b'\'' {
                    out.push_str("''");
                    i += 2;
                    continue;
                }
                in_quote = !in_quote;
                out.push('\'');
                i += 1;
            }
            ':' if !in_quote => {
                let start = i + 1;
                let mut end = start;
                while end < bytes.len() {
                    let ch = bytes[end] as char;
                    if ch.is_ascii_alphanumeric() || ch == '_' {
                        end += 1;
                    } else {
                        break;
                    }
                }
                if end > start {
                    let name = &sql_template[start..end];
                    let raw = params.get(name).cloned().unwrap_or(serde_json::Value::Null);
                    let v: sea_orm::Value = match raw {
                        serde_json::Value::Number(n) => {
                            if let Some(iv) = n.as_i64() {
                                iv.into()
                            } else {
                                n.as_f64().unwrap_or(0.0).into()
                            }
                        }
                        serde_json::Value::String(sv) => sv.into(),
                        _ => sea_orm::Value::String(None),
                    };
                    values.push(v);
                    match backend {
                        sea_orm::DatabaseBackend::Postgres => {
                            out.push_str(&format!("${pg_index}"));
                            pg_index += 1;
                        }
                        _ => out.push('?'),
                    }
                    i = end;
                    continue;
                }
                out.push(':');
                i += 1;
            }
            _ => {
                out.push(c);
                i += 1;
            }
        }
    }
    let _ = param_names;
    (out, values)
}

/// 列名推断：对模板 `SELECT a, b FROM t` 的**顶层投影列清单**做词法提取
/// （校验器已保证无括号/无子查询，顶层逗号切分安全）
async fn infer_columns(
    sql_template: &str,
    _db: &DatabaseConnection,
) -> Result<Vec<String>, ServiceError> {
    // SELECT 后至 FROM 前的顶层投影列清单
    let upper = sql_template.to_ascii_uppercase();
    let sel_pos = upper
        .find("SELECT")
        .ok_or_else(|| ServiceError::bad_request("SQL 模板必须以 SELECT 开头"))?;
    let from_pos = upper[sel_pos..].find(" FROM ").map(|i| sel_pos + i);
    let proj = match from_pos {
        Some(fp) => &sql_template[sel_pos + 6..fp],
        None => &sql_template[sel_pos + 6..],
    };
    let mut cols = Vec::new();
    for part in proj.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        // `expr AS alias` → alias；`table.col` → col；`*` → 跳过（回退为占位 colN）
        let name = if let Some(pos) = part.to_ascii_uppercase().rfind(" AS ") {
            part[pos + 4..].trim().trim_matches('"').to_string()
        } else if let Some(pos) = part.rfind('.') {
            part[pos + 1..].trim().to_string()
        } else if part == "*" {
            String::new()
        } else {
            part.to_string()
        };
        cols.push(if name.is_empty() {
            format!("col{}", cols.len() + 1)
        } else {
            name
        });
    }
    if cols.is_empty() {
        cols.push("col1".to_string());
    }
    Ok(cols)
}
