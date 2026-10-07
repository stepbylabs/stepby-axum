//! 流程定义 Service（G-02 M1：存储 + 校验 + 版本发布）
//!
//! 分层约束：不依赖 Web 框架类型；graph_json 保存前经 `common/flow_graph.rs`
//! 白名单校验器**复验**（防绕过前端直投 API）。
//! M2 接入点：`FlowGraph` → `NodeSpec` 转换喂给 `sys_flow_service` 推进内核。

use garde::Validate;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, DatabaseConnection, EntityTrait, PaginatorTrait, QueryFilter,
    QueryOrder, QuerySelect, Set,
};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::common::error::ServiceError;
use crate::common::flow_graph::FlowGraph;
use crate::entity::flow_definition::{ActiveModel as FlowDefActiveModel, Entity as FlowDefEntity};
use crate::entity::prelude::FlowDefinitionModel;

/// 能力位键（governance 注册表 `flow.designer`：off | view | full，默认 off）
const DESIGNER_FEATURE_KEY: &str = "flow.designer";

/// 流程定义出参 VO（graph_json 原样返回——结构已校验，非密文）
#[derive(Debug, Clone, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct FlowDefVo {
    pub flow_id: i64,
    pub tenant_id: i64,
    pub flow_code: String,
    pub flow_name: String,
    pub graph_json: String,
    pub version: i32,
    pub is_latest: String,
    pub status: String,
    pub remark: Option<String>,
    pub create_time: Option<String>,
    pub update_time: Option<String>,
}

impl FlowDefVo {
    fn from_model(m: &FlowDefinitionModel) -> Self {
        Self {
            flow_id: m.flow_id,
            tenant_id: m.tenant_id,
            flow_code: m.flow_code.clone(),
            flow_name: m.flow_name.clone(),
            graph_json: m.graph_json.clone(),
            version: m.version,
            is_latest: m.is_latest.clone(),
            status: m.status.clone(),
            remark: m.remark.clone(),
            create_time: m.create_time.map(|t| t.to_string()),
            update_time: m.update_time.map(|t| t.to_string()),
        }
    }
}

/// 新增/修改 DTO（graph_json 必须通过白名单校验器）
#[derive(Debug, Deserialize, Validate, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct FlowDefUpsertDto {
    #[serde(default)]
    #[garde(skip)]
    pub flow_id: Option<i64>,
    #[garde(length(min = 1, max = 64))]
    pub flow_code: String,
    #[garde(length(min = 1, max = 128))]
    pub flow_name: String,
    #[garde(skip)]
    pub graph_json: String,
    #[serde(default)]
    #[garde(skip)]
    pub remark: Option<String>,
}

/// 发布结果（新版本号）
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct FlowDefPublishVo {
    pub flow_id: i64,
    pub version: i32,
}

#[derive(Clone)]
pub struct FlowDefinitionService {
    db: DatabaseConnection,
}

impl FlowDefinitionService {
    pub fn new(db: DatabaseConnection) -> Self {
        Self { db }
    }

    /// 校验归属：operator_tid≠0 时仅本租户；0 = 平台全量
    fn ensure_access(
        &self,
        m: &FlowDefinitionModel,
        operator_tid: i64,
    ) -> Result<(), ServiceError> {
        if !crate::common::tenant::tenant_allowed(operator_tid, m.tenant_id) {
            return Err(ServiceError::forbidden(&crate::tr!(
                "error.common.forbidden"
            )));
        }
        Ok(())
    }

    /// 设计器写面守卫（能力位 `flow.designer` 的端点消费——批次十二随注册表同批接入）。
    ///
    /// - 平台操作者（tid=0）不受能力位限制（与 nav.l3 / report.designer 同语义）；
    /// - 租户操作者需**有效档位 = `full`**（`view` 只读：列表/详情/版本对比可用、
    ///   写面 403；`off`/非法值 fail-closed 拒绝）；
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
                "error.flow.def_designer_disabled"
            )))
        }
    }

    /// 分页查询（租户过滤；del_flag='0'）
    pub async fn get_page(
        &self,
        offset: u64,
        limit: u64,
        flow_code: Option<&str>,
        operator_tid: i64,
    ) -> Result<(Vec<FlowDefVo>, u64), ServiceError> {
        let mut select =
            FlowDefEntity::find().filter(crate::entity::flow_definition::Column::DelFlag.eq("0"));
        if let Some(t) = crate::common::tenant::tenant_scope(operator_tid) {
            select = select.filter(crate::entity::flow_definition::Column::TenantId.eq(t));
        }
        if let Some(code) = flow_code.filter(|c| !c.is_empty()) {
            select = select.filter(
                crate::entity::flow_definition::Column::FlowCode
                    .like(format!("%{}%", crate::common::like_escape(code))),
            );
        }
        let total = select.clone().count(&self.db).await?;
        let rows = select
            .order_by_desc(crate::entity::flow_definition::Column::FlowId)
            .offset(offset)
            .limit(limit)
            .all(&self.db)
            .await?;
        Ok((rows.iter().map(FlowDefVo::from_model).collect(), total))
    }

    /// 详情
    pub async fn get_by_id(
        &self,
        flow_id: i64,
        operator_tid: i64,
    ) -> Result<FlowDefVo, ServiceError> {
        let m = FlowDefEntity::find_by_id(flow_id)
            .filter(crate::entity::flow_definition::Column::DelFlag.eq("0"))
            .one(&self.db)
            .await?
            .ok_or_else(|| ServiceError::not_found(&crate::tr!("error.flow.def_not_found")))?;
        self.ensure_access(&m, operator_tid)?;
        Ok(FlowDefVo::from_model(&m))
    }

    /// 新增（draft，version=1；graph_json 复验 fail-closed）
    pub async fn add(
        &self,
        dto: FlowDefUpsertDto,
        operator: &str,
        operator_tid: i64,
    ) -> Result<FlowDefVo, ServiceError> {
        self.ensure_designer_write(operator_tid).await?;
        FlowGraph::parse_and_validate(&dto.graph_json).map_err(|e| {
            ServiceError::bad_request(&format!("{}: {e}", crate::tr!("error.flow.graph_invalid")))
        })?;
        // code 全租户查重（同租户下唯一）
        let dup = FlowDefEntity::find()
            .filter(crate::entity::flow_definition::Column::TenantId.eq(operator_tid))
            .filter(crate::entity::flow_definition::Column::FlowCode.eq(dto.flow_code.as_str()))
            .filter(crate::entity::flow_definition::Column::DelFlag.eq("0"))
            .one(&self.db)
            .await?;
        if dup.is_some() {
            return Err(ServiceError::bad_request(&crate::tr!(
                "error.flow.def_code_duplicate"
            )));
        }
        let now = crate::common::datetime::now_naive();
        let am = FlowDefActiveModel {
            tenant_id: Set(operator_tid),
            flow_code: Set(dto.flow_code),
            flow_name: Set(dto.flow_name),
            graph_json: Set(dto.graph_json),
            version: Set(1),
            is_latest: Set("0".to_string()),
            status: Set("0".to_string()),
            create_by: Set(Some(operator.to_string())),
            create_time: Set(Some(now)),
            update_by: Set(Some(operator.to_string())),
            update_time: Set(Some(now)),
            remark: Set(dto.remark),
            del_flag: Set(Some("0".to_string())),
            ..Default::default()
        };
        let model = FlowDefEntity::insert(am)
            .exec_with_returning(&self.db)
            .await?;
        Ok(FlowDefVo::from_model(&model))
    }

    /// 修改（草稿态改图/名称；已发布版本不可改图——改图请走"发布新版本"）
    pub async fn edit(
        &self,
        dto: FlowDefUpsertDto,
        operator: &str,
        operator_tid: i64,
    ) -> Result<FlowDefVo, ServiceError> {
        let flow_id = dto
            .flow_id
            .ok_or_else(|| ServiceError::bad_request(&crate::tr!("error.flow.def_id_required")))?;
        self.ensure_designer_write(operator_tid).await?;
        let m = FlowDefEntity::find_by_id(flow_id)
            .filter(crate::entity::flow_definition::Column::DelFlag.eq("0"))
            .one(&self.db)
            .await?
            .ok_or_else(|| ServiceError::not_found(&crate::tr!("error.flow.def_not_found")))?;
        self.ensure_access(&m, operator_tid)?;
        if m.status == "1" && m.graph_json != dto.graph_json {
            return Err(ServiceError::bad_request(&crate::tr!(
                "error.flow.def_published_immutable"
            )));
        }
        if m.graph_json != dto.graph_json {
            FlowGraph::parse_and_validate(&dto.graph_json).map_err(|e| {
                ServiceError::bad_request(&format!(
                    "{}: {e}",
                    crate::tr!("error.flow.graph_invalid")
                ))
            })?;
        }
        let mut am: FlowDefActiveModel = m.clone().into();
        am.flow_name = Set(dto.flow_name);
        am.graph_json = Set(dto.graph_json);
        am.remark = Set(dto.remark);
        am.update_by = Set(Some(operator.to_string()));
        am.update_time = Set(Some(crate::common::datetime::now_naive()));
        let updated = am.update(&self.db).await?;
        Ok(FlowDefVo::from_model(&updated))
    }

    /// 发布：version+1 新行（原行 is_latest='0' 保留历史），新行 is_latest='1' + status='1'
    pub async fn publish(
        &self,
        flow_id: i64,
        operator: &str,
        operator_tid: i64,
    ) -> Result<FlowDefPublishVo, ServiceError> {
        self.ensure_designer_write(operator_tid).await?;
        let m = FlowDefEntity::find_by_id(flow_id)
            .filter(crate::entity::flow_definition::Column::DelFlag.eq("0"))
            .one(&self.db)
            .await?
            .ok_or_else(|| ServiceError::not_found(&crate::tr!("error.flow.def_not_found")))?;
        self.ensure_access(&m, operator_tid)?;
        // 发布前复验图
        FlowGraph::parse_and_validate(&m.graph_json).map_err(|e| {
            ServiceError::bad_request(&format!("{}: {e}", crate::tr!("error.flow.graph_invalid")))
        })?;
        let now = crate::common::datetime::now_naive();
        let new_version = m.version + 1;
        // 同 code 历史 is_latest 全部归 '0'
        if let Some(old) = FlowDefEntity::find()
            .filter(crate::entity::flow_definition::Column::TenantId.eq(m.tenant_id))
            .filter(crate::entity::flow_definition::Column::FlowCode.eq(m.flow_code.as_str()))
            .filter(crate::entity::flow_definition::Column::IsLatest.eq("1"))
            .one(&self.db)
            .await?
        {
            let mut old_am: FlowDefActiveModel = old.into();
            old_am.is_latest = Set("0".to_string());
            old_am.update_time = Set(Some(now));
            old_am.update(&self.db).await?;
        }
        // 新版本行（从当前行复制图）
        let am = FlowDefActiveModel {
            tenant_id: Set(m.tenant_id),
            flow_code: Set(m.flow_code.clone()),
            flow_name: Set(m.flow_name.clone()),
            graph_json: Set(m.graph_json.clone()),
            version: Set(new_version),
            is_latest: Set("1".to_string()),
            status: Set("1".to_string()),
            create_by: Set(Some(operator.to_string())),
            create_time: Set(Some(now)),
            update_by: Set(Some(operator.to_string())),
            update_time: Set(Some(now)),
            remark: Set(m.remark.clone()),
            del_flag: Set(Some("0".to_string())),
            ..Default::default()
        };
        let inserted = FlowDefEntity::insert(am)
            .exec_with_returning(&self.db)
            .await?;
        Ok(FlowDefPublishVo {
            flow_id: inserted.flow_id,
            version: inserted.version,
        })
    }

    /// 删除（软删；已发布版本同样可删——实例按 version 快照推进不受影响）
    pub async fn remove(
        &self,
        flow_ids: Vec<i64>,
        operator: &str,
        operator_tid: i64,
    ) -> Result<(), ServiceError> {
        self.ensure_designer_write(operator_tid).await?;
        for fid in flow_ids {
            if let Some(m) = FlowDefEntity::find_by_id(fid)
                .filter(crate::entity::flow_definition::Column::DelFlag.eq("0"))
                .one(&self.db)
                .await?
            {
                self.ensure_access(&m, operator_tid)?;
                let mut am: FlowDefActiveModel = m.into();
                am.del_flag = Set(Some("1".to_string()));
                am.update_by = Set(Some(operator.to_string()));
                am.update_time = Set(Some(crate::common::datetime::now_naive()));
                am.update(&self.db).await?;
            }
        }
        Ok(())
    }
}
