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

    /// 设计器读面守卫（b89 项 6 补的第二半；与 [`Self::ensure_designer_write`] 同一把尺）。
    ///
    /// 原状：读面无守卫 ⇒ `off` 档租户照常列表/预览/看大屏，写按钮却 403。
    /// 这既让能力位在读面上形同虚设，也让 `getRouters` 的整面剪退化成"仅显示层隐藏"
    /// （《开关规范》③ 明确禁止）。
    async fn ensure_designer_read(&self, operator_tid: i64) -> Result<(), ServiceError> {
        if operator_tid == 0 {
            return Ok(());
        }
        let features =
            crate::service::sys_tenant_service::tenant_features_conn(&self.db, operator_tid)
                .await
                .map_err(|e| ServiceError::internal(&format!("tenant features: {e}")))?;
        if crate::common::features::designer_read_allowed(
            operator_tid,
            features.mode(DESIGNER_FEATURE_KEY),
        ) {
            Ok(())
        } else {
            Err(ServiceError::forbidden(&crate::tr!(
                "error.report.designer_off"
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
        self.ensure_designer_read(operator_tid).await?;
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
        self.ensure_designer_read(operator_tid).await?;
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
    ///
    /// 按**写面**守卫：这一支的用途就是"编辑对话框回填 SQL"，路由键也挂 `report:dataset:edit`
    /// （b89 项 6：读面/写面的分类以路由键为准，不按方法名前缀猜）。
    pub async fn get_dataset_sql(
        &self,
        dataset_id: i64,
        operator_tid: i64,
    ) -> Result<String, ServiceError> {
        self.ensure_designer_write(operator_tid).await?;
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
        // (id, 原 code)：改名值必须逐行不同，故把原 code 一起带出来（上面已从 map 里移出）
        let mut deletable: Vec<(i64, String)> = Vec::new();
        for id in dataset_ids {
            if let Some(m) = by_id
                .remove(&id)
                .filter(|mm| mm.del_flag.as_deref() == Some("0"))
            {
                self.ensure_access(m.tenant_id, operator_tid)?;
                deletable.push((id, m.dataset_code));
            }
        }
        if !deletable.is_empty() {
            // 逐行 UPDATE 而非一次 `is_in`：软删必须**同时释放唯一键** `uq_report_dataset_code`
            // （唯一索引不含 del_flag），而每行要写入的改名值各不相同 ⇒ 批量语句拼不出。
            // 保留批量读（上方一次 is_in 批查）以维持"错误顺序按入参、无 2N 次往返"的既有语义。
            let now = crate::common::datetime::now_naive();
            for (id, code) in &deletable {
                ReportDatasetEntity::update_many()
                    .col_expr(
                        ReportDatasetColumn::DelFlag,
                        Expr::value(Some("1".to_string())),
                    )
                    .col_expr(
                        ReportDatasetColumn::DatasetCode,
                        Expr::value(crate::common::soft_delete_key::freed_key(code, *id, 64)),
                    )
                    .col_expr(
                        ReportDatasetColumn::UpdateBy,
                        Expr::value(Some(operator.to_string())),
                    )
                    .col_expr(ReportDatasetColumn::UpdateTime, Expr::value(now))
                    .filter(ReportDatasetColumn::DatasetId.eq(*id))
                    .exec(&txn)
                    .await?;
            }
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
        self.ensure_designer_read(operator_tid).await?;
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
        let (sql_bound, values) = bind_named_params(&m.sql_template, &dto.params, backend)
            .map_err(|detail| {
                ServiceError::bad_request(&format!(
                    "{}: {detail}",
                    crate::tr!("error.report.param_type_invalid")
                ))
            })?;

        // LIMIT 100 硬顶（模板无括号/注释/子查询——校验器保证；直接追加 LIMIT 子句）。
        // ⚠️ 追加前必须剥掉末尾分号：校验器**放行** `SELECT … ;` 形态，而直接拼接会得到
        // `SELECT … ; LIMIT 100`——驱动视角是两条语句，请求期整体失败（批七十五 B4 变异
        // 实测：SQLite/sqlx 报多语句、MySQL·PG 报语法错，三档一律 500）。保存侧校验通过、
        // 试跑侧永久 500 的"口径漂移"就是本缺陷的用户可见面。
        let limited = preview_limited_sql(&sql_bound);
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

        // 列名提取（G-01 M3 优化）：临时视图探针取真实列名（表达式列含数据库默认命名）；
        // 探针失败（方言差异/权限）回退词法推断——fail-open 但结果恒为合法列名清单，
        // 下游 try_get 失败容忍为 Null。
        // ⚠️ 必须在遍历行**之前**做：此前它挂在 `idx == 0` 分支里，于是"合法但当前 0 行"
        // 的查询（新表、筛选无命中）拿到空 columns ⇒ 设计器字段选择器整块空，
        // 还把空清单当采样结果写进 columns_meta 缓存（批七十五 B4）。
        let columns = match probe_columns_via_temp_view(&self.db, &m.sql_template).await {
            Some(c) => c,
            None => infer_columns(&m.sql_template, &self.db)
                .await
                .unwrap_or_else(|_| vec!["col1".to_string()]),
        };
        let mut out_rows: Vec<serde_json::Value> = Vec::new();
        for row in &rows {
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
        self.ensure_designer_read(operator_tid).await?;
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
        self.ensure_designer_read(operator_tid).await?;
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
        let mut deletable: Vec<(i64, String)> = Vec::new();
        for id in dashboard_ids {
            if let Some(m) = by_id.remove(&id) {
                self.ensure_access(m.tenant_id, operator_tid)?;
                deletable.push((id, m.dashboard_code));
            }
        }
        if !deletable.is_empty() {
            // 与 `remove_dataset` 同口径：软删同时释放 `uq_report_dashboard_code`
            // （唯一索引不含 del_flag，逐行改名值不同 ⇒ 只能逐行 UPDATE，仍在同一事务内）
            let now = crate::common::datetime::now_naive();
            for (id, code) in &deletable {
                ReportDashboardEntity::update_many()
                    .col_expr(
                        ReportDashboardColumn::DelFlag,
                        Expr::value(Some("1".to_string())),
                    )
                    .col_expr(
                        ReportDashboardColumn::DashboardCode,
                        Expr::value(crate::common::soft_delete_key::freed_key(code, *id, 64)),
                    )
                    .col_expr(
                        ReportDashboardColumn::UpdateBy,
                        Expr::value(Some(operator.to_string())),
                    )
                    .col_expr(ReportDashboardColumn::UpdateTime, Expr::value(now))
                    .filter(ReportDashboardColumn::DashboardId.eq(*id))
                    .exec(&txn)
                    .await?;
            }
        }
        txn.commit()
            .await
            .map_err(|e| ServiceError::internal(&format!("提交事务失败: {e}")))?;
        Ok(())
    }
}

/// preview 的 `LIMIT` 硬顶拼接（本文件**唯一**的"往模板后追加子句"点）。
///
/// 收成一个具名函数是为了让形状锁能按"变量绑定"判定：追加点写成
/// `format!("{sql_bound} LIMIT …")` 这种直接拼接时，锁会红（见
/// `dataset_sql_append_lock_catches_synthetic_unnormalized_append`）。
fn preview_limited_sql(sql_bound: &str) -> String {
    let body = crate::common::dataset_sql::strip_trailing_semicolon(sql_bound);
    format!("{body} LIMIT {PREVIEW_ROW_LIMIT}")
}

/// 把 `:name` 命名占位符替换为方言占位符并生成绑定值
/// （SQLite/MySQL = `?`，PG = `$n`）。
///
/// `Err(明细)` = 该参数的值**无法**映射成 SQL 标量（数组 / 对象 / 无法解析的数值 / 缺失）。
///
/// 立案（b89 项 4）：原实现把这些形状一律落成 `Value::String(None)`（= SQL NULL）。
/// 调用方传 `{"flag": true}` 得到的是 `WHERE flag = NULL` ⇒ **空结果 + HTTP 200 + 零提示**：
/// 错的是返回的数据而不是请求，而"数据集试跑"这一面的用户正是拿它判断 SQL 对不对的人，
/// 空集会被读成"库里确实没这条数据"。JSON `null` 仍按 SQL NULL 绑定（模板作者写
/// `IS NULL` 语义时使用），但**只有 null 这一种**映射到 NULL。
/// 参数缺失在更早的核对里就 400（`error.report.param_missing`）；这里返回 Err 是第二道，
/// 免得调用方漏判时又退回"洗成 NULL"的老形状。
fn bind_named_params(
    sql_template: &str,
    params: &std::collections::HashMap<String, serde_json::Value>,
    backend: sea_orm::DatabaseBackend,
) -> Result<(String, Vec<sea_orm::Value>), String> {
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
                    let raw = match params.get(name) {
                        Some(v) => v.clone(),
                        None => return Err(format!("{name}（取值缺失）")),
                    };
                    let v: sea_orm::Value = match raw {
                        serde_json::Value::Number(n) => {
                            if let Some(iv) = n.as_i64() {
                                iv.into()
                            } else if let Some(fv) = n.as_f64() {
                                fv.into()
                            } else {
                                // 原先是 `as_f64().unwrap_or(0.0)`：把"解析不出数值"洗成 0
                                // 送进 WHERE ⇒ 结果集换了而请求照样 200。
                                return Err(format!("{name}（数值 {n} 无法解析）"));
                            }
                        }
                        serde_json::Value::String(sv) => sv.into(),
                        serde_json::Value::Bool(b) => sea_orm::Value::Bool(Some(b)),
                        // 唯一的 NULL 通道：JSON null 显式表达"这一位就是 SQL NULL"
                        serde_json::Value::Null => sea_orm::Value::String(None),
                        serde_json::Value::Array(_) | serde_json::Value::Object(_) => {
                            return Err(format!("{name}（数组/对象不能直接绑定）"));
                        }
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
    Ok((out, values))
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::prod_scan::{self, Scan};

    const FILE: &str = "src/service/report_dataset_service.rs";
    const NORMALIZER: &str = "strip_trailing_semicolon";

    /// 一个"往 SQL 后追加子句"的拼接点：行号 + 它插值的槽位内容。
    #[derive(Debug)]
    struct AppendSite {
        line_no: usize,
        text: String,
        /// ` LIMIT ` **之前**的插值槽（`{body}` → `"body"`，`{}` → `""`）
        slots: Vec<String>,
    }

    /// 采集追加点（生产码行视图，注释已按口径置空）。
    fn append_sites(lines: &[String]) -> Vec<AppendSite> {
        let mut out = Vec::new();
        for (idx, line) in lines.iter().enumerate() {
            let Some(pos) = line.find(" LIMIT ") else {
                continue;
            };
            if !line.contains("format!") {
                continue;
            }
            let head = &line[..pos];
            let mut slots = Vec::new();
            let bytes = head.as_bytes();
            let mut i = 0usize;
            while i < bytes.len() {
                if bytes[i] == b'{'
                    && bytes.get(i + 1) != Some(&b'{')
                    && let Some(close) = head[i + 1..].find('}')
                {
                    let inner = head[i + 1..i + 1 + close].to_string();
                    // `{x:?}` 之类的格式串取变量名部分
                    slots.push(inner.split(':').next().unwrap_or_default().to_string());
                    i += close + 2;
                    continue;
                }
                i += 1;
            }
            out.push(AppendSite {
                line_no: idx + 1,
                text: line.clone(),
                slots,
            });
        }
        out
    }

    /// 判据：追加点必须先归一语句终止符。两种合规形态——
    /// ① 该行自带 `strip_trailing_semicolon`（就地归一）；
    /// ② 它插值的每个具名槽都由一条 `let 名称 = … strip_trailing_semicolon(…)` 绑定。
    /// 裸 `{}` 位置槽无法归因 ⇒ 只允许形态①。
    fn violations(lines: &[String]) -> Vec<String> {
        let mut bad = Vec::new();
        for site in append_sites(lines) {
            if site.text.contains(NORMALIZER) {
                continue;
            }
            let attributed = !site.slots.is_empty()
                && site.slots.iter().all(|slot| {
                    let let_prefix = format!("let {slot} ");
                    let let_mut = format!("let mut {slot} ");
                    !slot.is_empty()
                        && lines.iter().any(|l| {
                            let t = l.trim_start();
                            (t.starts_with(let_prefix.as_str()) || t.starts_with(let_mut.as_str()))
                                && t.contains(NORMALIZER)
                        })
                });
            if !attributed {
                bad.push(format!("第 {} 行: {}", site.line_no, site.text.trim()));
            }
        }
        bad
    }

    #[test]
    fn preview_appends_limit_only_through_the_terminator_normalizer() {
        let file = prod_scan::prod_file(FILE, &Scan::default());
        let sites = append_sites(&file.lines);
        // 体量探针：本文件必须真的有一个追加点。为 0 说明函数被删/改名，
        // 那时"零违规"毫无意义（恒绿锁）。
        assert!(
            !sites.is_empty(),
            "{FILE} 里必须存在 LIMIT 追加点（否则本锁空转）"
        );
        let bad = violations(&file.lines);
        assert!(
            bad.is_empty(),
            "SQL 追加子句前必须剥末尾分号，否则拼出的是两条语句，请求期整体失败\
             （B4 实测三档方言一律 500）：\n{}",
            bad.join("\n")
        );
    }

    /// 变异证伪 + 对照组：合成源码必须被抓到，合规形态必须放过，注释不得误伤。
    #[test]
    fn dataset_sql_append_lock_catches_synthetic_unnormalized_append() {
        #[derive(Debug)]
        enum Expect {
            Violation,
            Clean,
            /// 采集口径把它当注释/非代码 ⇒ 连追加点都不该识别出来
            NotCode,
        }
        let cases: &[(&str, Expect)] = &[
            // ① B4 缺陷本体：直接拼绑定后的 SQL
            (
                "    let limited = format!(\"{sql_bound} LIMIT {PREVIEW_ROW_LIMIT}\");",
                Expect::Violation,
            ),
            // ② 位置槽无法归因
            (
                "    let limited = format!(\"{} LIMIT 100\", sql_bound);",
                Expect::Violation,
            ),
            // ③ 槽名有 let 绑定，但绑定没走归一函数（换成别的"看似归一"的清洗同样违规）
            (
                "    let body = sql_bound.trim();\n    let limited = format!(\"{body} LIMIT 100\");",
                Expect::Violation,
            ),
            // ④ 合规：具名槽由归一函数绑定
            (
                "    let body = crate::common::dataset_sql::strip_trailing_semicolon(sql);\n    \
                 let limited = format!(\"{body} LIMIT 100\");",
                Expect::Clean,
            ),
            // ⑤ 合规：就地归一（位置槽 + 行内归一函数）
            (
                "    let limited = format!(\"{} LIMIT 100\", \
                 crate::common::dataset_sql::strip_trailing_semicolon(sql));",
                Expect::Clean,
            ),
            // ⑥ 注释里的违规形态不是代码：采集口径置空注释，否则文档串会误伤锁
            (
                "    // let q = format!(\"{sql_bound} LIMIT 100\"); 历史缺陷说明",
                Expect::NotCode,
            ),
        ];
        for (src, expect) in cases {
            let lines = prod_scan::normalize(src, &Scan::default());
            let sites = append_sites(&lines);
            let bad = violations(&lines);
            match expect {
                Expect::NotCode => assert!(
                    sites.is_empty(),
                    "注释不应被识别为追加点: {src}\n实际: {sites:?}"
                ),
                Expect::Clean => {
                    assert!(!sites.is_empty(), "用例应至少被识别为一个追加点: {src}");
                    assert!(
                        bad.is_empty(),
                        "合规形态被误判为违规（锁会挡住正确写法）: {src}\n实际: {bad:?}"
                    );
                }
                Expect::Violation => {
                    assert!(!sites.is_empty(), "用例应至少被识别为一个追加点: {src}");
                    assert!(
                        !bad.is_empty(),
                        "违规形态未被抓到 ⇒ 本锁是虚锁: {src}\n行: {lines:?}"
                    );
                }
            }
        }
    }

    /// helper 的行为锁：分号被剥、硬顶恒为 `PREVIEW_ROW_LIMIT`、无分号模板正文不被吞。
    #[test]
    fn preview_limited_sql_keeps_the_hard_cap_inside_the_statement_body() {
        assert_eq!(
            preview_limited_sql("SELECT user_id FROM sys_user WHERE status = ?;"),
            "SELECT user_id FROM sys_user WHERE status = ? LIMIT 100"
        );
        assert_eq!(
            preview_limited_sql("SELECT user_id FROM sys_user"),
            "SELECT user_id FROM sys_user LIMIT 100"
        );
        assert!(
            preview_limited_sql("SELECT 1;").ends_with(&format!("LIMIT {PREVIEW_ROW_LIMIT}")),
            "硬顶常量必须真的落到语句尾部"
        );
    }

    /// b89 项 4 回归锁：绑定只看**能否映射成标量**，映射不了必须点名参数，
    /// 不得静默洗成 NULL（洗成 NULL 的请求照样 200，错的是返回的数据）。
    fn params(
        pairs: &[(&str, serde_json::Value)],
    ) -> std::collections::HashMap<String, serde_json::Value> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.clone()))
            .collect()
    }

    /// 四类标量各绑各的形状；`null` 是**唯一**允许落成 SQL NULL 的一档
    #[test]
    fn bind_named_params_maps_scalars_and_keeps_null_explicit() {
        use sea_orm::DatabaseBackend;
        let p = params(&[
            ("id", serde_json::json!(7)),
            ("ratio", serde_json::json!(1.5)),
            ("name", serde_json::json!("bob")),
            ("flag", serde_json::json!(true)),
            ("maybe", serde_json::json!(null)),
        ]);
        let (sql, values) = bind_named_params(
            "SELECT 1 FROM t WHERE a = :id AND b = :ratio AND c = :name AND d = :flag AND e = :maybe",
            &p,
            DatabaseBackend::Sqlite,
        )
        .expect("标量必须全部可绑定");
        assert_eq!(
            sql,
            "SELECT 1 FROM t WHERE a = ? AND b = ? AND c = ? AND d = ? AND e = ?"
        );
        assert_eq!(values.len(), 5, "五个占位符必须五个绑定");
        assert!(
            matches!(values[0], sea_orm::Value::BigInt(Some(7))),
            "整数应绑成 BigInt，实际 {:?}",
            values[0]
        );
        assert!(
            matches!(values[3], sea_orm::Value::Bool(Some(true))),
            "布尔必须绑成 Bool，而不是 NULL（本项缺陷的原形）"
        );
        assert!(
            matches!(values[4], sea_orm::Value::String(None)),
            "JSON null 仍按 SQL NULL 绑定"
        );
    }

    /// PG 走 `$n` 且序号**按出现顺序**递增（同一名字出现两次 ⇒ 两个序号、两份值）
    #[test]
    fn bind_named_params_numbers_postgres_placeholders_per_occurrence() {
        use sea_orm::DatabaseBackend;
        let p = params(&[("lo", serde_json::json!(1)), ("hi", serde_json::json!(9))]);
        let (sql, values) = bind_named_params(
            "SELECT 1 FROM t WHERE a > :lo AND a < :hi AND b <> :lo",
            &p,
            DatabaseBackend::Postgres,
        )
        .expect("标量必须全部可绑定");
        assert_eq!(sql, "SELECT 1 FROM t WHERE a > $1 AND a < $2 AND b <> $3");
        assert_eq!(values.len(), 3, "重复出现的名字不得合并序号");
    }

    /// 数组 / 对象 / 缺失 ⇒ Err 且**点名是哪个参数**（只报"绑定失败"等于没报）
    #[test]
    fn bind_named_params_rejects_unmappable_values_and_names_them() {
        use sea_orm::DatabaseBackend;
        for (label, value, want_in_msg) in [
            ("数组", serde_json::json!([1, 2]), "ids"),
            ("对象", serde_json::json!({"a": 1}), "ids"),
        ] {
            let p = params(&[("ids", value)]);
            let err = bind_named_params(
                "SELECT 1 FROM t WHERE id IN (:ids)",
                &p,
                DatabaseBackend::Sqlite,
            )
            .expect_err(&format!("{label}不得被洗成 NULL"));
            assert!(
                err.contains(want_in_msg),
                "{label} 的错误必须点名参数 {want_in_msg}，实际：{err}"
            );
        }
        // 缺失：调用方本应在更早的核对里 400，这里是第二道，不得退回静默 NULL
        let err = bind_named_params(
            "SELECT 1 FROM t WHERE id = :ids",
            &std::collections::HashMap::new(),
            DatabaseBackend::Sqlite,
        )
        .expect_err("缺失参数不得静默绑成 NULL");
        assert!(err.contains("ids"), "必须点名缺哪个参数：{err}");
    }

    /// 引用名之外的字符串**不算**占位符（引号里的 `:not_a_param` 必须原样保留）
    ///
    /// 这条是采集面的对照组：掩码器一旦把引号内文本当占位符替换，绑定数就会超过参数数，
    /// "绑了没人用的值"与"该绑的没绑"在同一份 SQL 上同时发生。
    #[test]
    fn bind_named_params_ignores_colons_inside_string_literals() {
        use sea_orm::DatabaseBackend;
        let p = params(&[("id", serde_json::json!(3))]);
        let (sql, values) = bind_named_params(
            "SELECT 'a :not_a_param b' FROM t WHERE id = :id",
            &p,
            DatabaseBackend::Sqlite,
        )
        .expect("引号内的冒号不参与绑定");
        assert!(
            sql.contains("'a :not_a_param b'"),
            "字面量必须逐字保留，实际：{sql}"
        );
        assert_eq!(values.len(), 1, "只该有一个绑定，实际 {}", values.len());
    }
}
