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
use sea_orm::sea_query::Expr;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, ConnectionTrait, DatabaseConnection, EntityTrait,
    PaginatorTrait, QueryFilter, QueryOrder, QuerySelect, Set, TransactionTrait,
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

/// 能力位键（governance 注册表 `report.designer`：off | view | full，默认 off）
const DESIGNER_FEATURE_KEY: &str = "report.designer";
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

    /// 设计器写面守卫（能力位 `report.designer` 的端点消费——批次十二收口 M1 悬置项）。
    ///
    /// - 平台操作者（tid=0）不受能力位限制（平台内部由 role_menu 授权管，与 nav.l3 同语义）；
    /// - 租户操作者需**有效档位 = `full`**（`view` 只读：列表/详情/预览可用、写面 403；
    ///   `off`/非法值 fail-closed 拒绝）；
    /// - 有效能力集 = 平台 `[features]` 天花板 ∩ 租户套餐（`tenant_features_conn`）。
    async fn ensure_designer_write(&self, operator_tid: i64) -> Result<(), ServiceError> {
        if operator_tid == 0 {
            return Ok(());
        }
        let features =
            crate::service::sys_tenant_service::tenant_features_conn(&self.db, operator_tid)
                .await
                .map_err(|e| ServiceError::internal(&format!("tenant features: {e}")))?;
        if crate::common::features::designer_write_allowed(
            operator_tid,
            features.mode(DESIGNER_FEATURE_KEY),
        ) {
            Ok(())
        } else {
            Err(ServiceError::forbidden(&crate::tr!(
                "error.report.designer_disabled"
            )))
        }
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

    /// 取 SQL 模板明文（编辑回填专用；仅持 report:dataset:edit 者可达——权限在路由键层把关）
    pub async fn get_dataset_sql(
        &self,
        dataset_id: i64,
        operator_tid: i64,
    ) -> Result<String, ServiceError> {
        let m = ReportDatasetEntity::find_by_id(dataset_id)
            .filter(ReportDatasetColumn::DelFlag.eq("0"))
            .one(&self.db)
            .await?
            .ok_or_else(|| {
                ServiceError::not_found(&crate::tr!("error.report.dataset_not_found"))
            })?;
        self.ensure_access(m.tenant_id, operator_tid)?;
        Ok(m.sql_template)
    }

    pub async fn add_dataset(
        &self,
        dto: DatasetUpsertDto,
        operator: &str,
        operator_tid: i64,
    ) -> Result<DatasetVo, ServiceError> {
        self.ensure_designer_write(operator_tid).await?;
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
        self.ensure_designer_write(operator_tid).await?;
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
        self.ensure_designer_write(operator_tid).await?;
        if dataset_ids.is_empty() {
            return Ok(());
        }
        // B-1：批量软删收敛进单事务——中途失败不得留下"部分已删部分未删"的半成品。
        // b71 N+1 治理：原循环逐条 find_by_id + update（2N 次往返），收敛为事务内
        // 一次 is_in 批查 + 按入参顺序逐条 ensure_access（报错顺序不变）+ 单条批量 UPDATE。
        let txn = self
            .db
            .begin()
            .await
            .map_err(|e| ServiceError::internal(&format!("开启事务失败: {e}")))?;
        let rows = ReportDatasetEntity::find()
            .filter(ReportDatasetColumn::DatasetId.is_in(dataset_ids.clone()))
            .all(&txn)
            .await?;
        let mut by_id: std::collections::HashMap<i64, ReportDatasetModel> =
            rows.into_iter().map(|m| (m.dataset_id, m)).collect();
        let mut deletable: Vec<i64> = Vec::new();
        for id in dataset_ids {
            if let Some(m) = by_id
                .remove(&id)
                .filter(|mm| mm.del_flag.as_deref() == Some("0"))
            {
                self.ensure_access(m.tenant_id, operator_tid)?;
                deletable.push(id);
            }
        }
        if !deletable.is_empty() {
            ReportDatasetEntity::update_many()
                .col_expr(
                    ReportDatasetColumn::DelFlag,
                    Expr::value(Some("1".to_string())),
                )
                .col_expr(
                    ReportDatasetColumn::UpdateBy,
                    Expr::value(Some(operator.to_string())),
                )
                .col_expr(
                    ReportDatasetColumn::UpdateTime,
                    Expr::value(Some(crate::common::datetime::now_naive())),
                )
                .filter(ReportDatasetColumn::DatasetId.is_in(deletable))
                .exec(&txn)
                .await?;
        }
        txn.commit()
            .await
            .map_err(|e| ServiceError::internal(&format!("提交事务失败: {e}")))?;
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
                // 列名提取（G-01 M3 优化）：临时视图探针取真实列名（表达式列含数据库
                // 默认命名）；探针失败（方言差异/权限）回退词法推断——fail-open 但结果
                // 恒为合法列名清单，下游 try_get 失败容忍为 Null
                columns = match probe_columns_via_temp_view(&self.db, &m.sql_template).await {
                    Some(c) => c,
                    None => infer_columns(&m.sql_template, &self.db)
                        .await
                        .unwrap_or_else(|_| vec!["col1".to_string()]),
                };
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
        self.ensure_designer_write(operator_tid).await?;
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
        self.ensure_designer_write(operator_tid).await?;
        if dashboard_ids.is_empty() {
            return Ok(());
        }
        // b71：与同文件 `remove_dataset` 同族收散点（该批只改了 dataset 侧，dashboard 为遗漏项）。
        // 一次修两件事：① 循环逐条 find_by_id + update（2N 次往返）→ 事务内一次 is_in 批查 +
        // 单条批量 UPDATE；② 原实现**根本没有事务**，中途失败会留下"部分看板已软删、部分未删"
        // 的半成品且调用方无感知——补上与 dataset 侧一致的 B-1 单事务口径。
        let txn = self
            .db
            .begin()
            .await
            .map_err(|e| ServiceError::internal(&format!("开启事务失败: {e}")))?;
        let rows = ReportDashboardEntity::find()
            .filter(ReportDashboardColumn::DashboardId.is_in(dashboard_ids.clone()))
            .filter(ReportDashboardColumn::DelFlag.eq("0"))
            .all(&txn)
            .await?;
        let mut by_id: std::collections::HashMap<i64, ReportDashboardModel> =
            rows.into_iter().map(|m| (m.dashboard_id, m)).collect();
        let mut deletable: Vec<i64> = Vec::new();
        for id in dashboard_ids {
            if let Some(m) = by_id.remove(&id) {
                self.ensure_access(m.tenant_id, operator_tid)?;
                deletable.push(id);
            }
        }
        if !deletable.is_empty() {
            let now = crate::common::datetime::now_naive();
            ReportDashboardEntity::update_many()
                .col_expr(
                    ReportDashboardColumn::DelFlag,
                    Expr::value(Some("1".to_string())),
                )
                .col_expr(
                    ReportDashboardColumn::UpdateBy,
                    Expr::value(Some(operator.to_string())),
                )
                .col_expr(ReportDashboardColumn::UpdateTime, Expr::value(Some(now)))
                .filter(ReportDashboardColumn::DashboardId.is_in(deletable))
                .exec(&txn)
                .await?;
        }
        txn.commit()
            .await
            .map_err(|e| ServiceError::internal(&format!("提交事务失败: {e}")))?;
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
/// 列元数据采样（G-01 M3 优化）：**临时视图探针**取真实列名——
/// `CREATE TEMPORARY VIEW __rs_probe AS {template}` 后按方言读视图列
/// （sqlite `PRAGMA table_info` / mysql+pg `information_schema.columns`），
/// 表达式列也能拿到数据库引擎的默认命名；探针失败回退词法推断。
///
/// 为何安全：探针 SQL 只由**已过白名单校验的模板**拼成（运行时可信代码路径），
/// 临时视图会话结束自动清理（且显式 DROP）；`database_id` 仅用于日志。
async fn probe_columns_via_temp_view(
    db: &DatabaseConnection,
    sql_template: &str,
) -> Option<Vec<String>> {
    let backend = db.get_database_backend();
    let probe_name = "__rs_probe";
    let create = format!("CREATE TEMPORARY VIEW {probe_name} AS {sql_template}");
    if db
        .execute_raw(sea_orm::Statement::from_string(backend, create))
        .await
        .is_err()
    {
        return None;
    }
    let read_sql = match backend {
        sea_orm::DatabaseBackend::Sqlite => {
            format!("PRAGMA table_info({probe_name})")
        }
        _ => format!(
            "SELECT column_name FROM information_schema.columns WHERE table_name = '{probe_name}' \
             ORDER BY ordinal_position"
        ),
    };
    let rows = db
        .query_all_raw(sea_orm::Statement::from_string(backend, read_sql))
        .await
        .ok()?;
    // 显式清理（TEMP 视图随连接关闭自动消失，但连接是池化的——必须主动 DROP）。
    // ⚠️ 必须 `.await`（clippy::let_underscore_future 实证）：裸 `let _ =` 创建 future 后
    // 立即丢弃 ⇒ DROP 语句**从未发往数据库**，池化连接携带残留临时视图归还——
    // "池化连接必须主动清"的意图此前从未真正生效。清理失败不阻断探针（列已取到）。
    let _drop_result = db
        .execute_raw(sea_orm::Statement::from_string(
            backend,
            format!("DROP VIEW IF EXISTS {probe_name}"),
        ))
        .await;
    let mut cols = Vec::new();
    for row in &rows {
        let name: Option<String> = match backend {
            // PRAGMA table_info 返回列名在 "name" 字段
            sea_orm::DatabaseBackend::Sqlite => {
                row.try_get::<Option<String>>("", "name").ok().flatten()
            }
            _ => row
                .try_get::<Option<String>>("", "column_name")
                .ok()
                .flatten()
                .or_else(|| {
                    // MySQL 返回大写列别名
                    row.try_get::<Option<String>>("", "COLUMN_NAME")
                        .ok()
                        .flatten()
                }),
        };
        if let Some(n) = name
            && !n.is_empty()
        {
            cols.push(n);
        }
    }
    if cols.is_empty() { None } else { Some(cols) }
}

async fn infer_columns(
    sql_template: &str,
    _db: &DatabaseConnection,
) -> Result<Vec<String>, ServiceError> {
    // SELECT 后至 FROM 前的顶层投影列清单
    let upper = sql_template.to_ascii_uppercase();
    let sel_pos = upper
        .find("SELECT")
        .ok_or_else(|| ServiceError::bad_request(&crate::tr!("error.report.sql_must_select")))?;
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
