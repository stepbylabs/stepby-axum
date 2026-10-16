//! 任务进度中心 Service 层
//!
//! 职责：
//! - 创建任务（pending）
//! - 更新任务进度（progress / current / total）
//! - 完成任务（success / failed）
//! - 任务分页查询 / 详情 / 批量删除
//! - 通过 WS 广播 taskProgress 事件，前端浮层组件实时显示

use garde::Validate;
use sea_orm::{DatabaseConnection, Set};
use serde::Deserialize;
use utoipa::{IntoParams, ToSchema};

use crate::common::error::ServiceError;
use crate::common::page::{PageDomain, default_page_num, default_page_size};
use crate::common::sort::{self, SortOrder};
use crate::entity::sys_task::{
    ActiveModel as SysTaskActiveModel, Column as TaskColumn, Model as SysTaskModel,
};
use crate::repository::sys_task::SysTaskRepository;
use crate::state::AppState;

// ==================== DTO ====================

/// 任务分页查询 DTO
#[derive(Debug, Clone, Deserialize, IntoParams, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct TaskQueryDto {
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
    pub task_type: Option<String>,
    pub status: Option<String>,
    pub operator: Option<String>,
    /// 开始时间（兼容前端 addDateRange 嵌套格式 `params[beginTime]`）
    #[serde(alias = "params[beginTime]", default)]
    pub begin_time: Option<String>,
    /// 结束时间（兼容前端 addDateRange 嵌套格式 `params[endTime]`）
    #[serde(alias = "params[endTime]", default)]
    pub end_time: Option<String>,
}

impl From<&TaskQueryDto> for PageDomain {
    fn from(dto: &TaskQueryDto) -> Self {
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

/// 任务创建 DTO
///
/// P1：补齐 garde 校验（此前 task_type/task_name 无长度上限、total 无范围），
/// 任意字符串可直接入库。
#[derive(Debug, Deserialize, Validate, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct TaskCreateDto {
    /// 任务类型（export/import/backup/other）
    #[garde(length(min = 1, max = 20))]
    pub task_type: String,
    /// 任务名称
    #[garde(length(min = 1, max = 200))]
    pub task_name: String,
    /// 任务总量（默认 0）
    #[serde(default)]
    #[garde(range(min = 0, max = 1_000_000_000))]
    pub total: i64,
    /// 操作人 user_id（P0-2：taskProgress 定向推送目标；None 表示系统任务，不推送 WS）
    #[serde(default)]
    #[garde(skip)]
    pub operator_id: Option<i64>,
}

// ==================== 辅助函数 ====================

// ==================== Service 实现 ====================

/// 允许排序的任务列白名单（数据库列名 snake_case；前端 prop 经 camel_to_snake 归一后匹配）。
///
/// 覆盖任务进度业务展示列（主键、类型、名称、状态、进度、总量、当前完成数、操作人、时间）；
/// `tenant_id` / `operator_id` 等内部列与大文本列（result_msg）不开放动态排序。
const TASK_SORTABLE_COLUMNS: &[(&str, TaskColumn)] = &[
    ("task_id", TaskColumn::TaskId),
    ("task_type", TaskColumn::TaskType),
    ("task_name", TaskColumn::TaskName),
    ("status", TaskColumn::Status),
    ("progress", TaskColumn::Progress),
    ("total", TaskColumn::Total),
    ("current", TaskColumn::Current),
    ("operator", TaskColumn::Operator),
    ("create_time", TaskColumn::CreateTime),
    ("update_time", TaskColumn::UpdateTime),
];

/// 任务进度 Service
pub struct SysTaskService {
    task_repo: SysTaskRepository,
}

impl SysTaskService {
    pub fn new(db: DatabaseConnection) -> Self {
        Self {
            task_repo: SysTaskRepository::new(db),
        }
    }

    /// 创建任务（pending 状态）
    ///
    /// 创建后立即 WS 广播 taskProgress 事件，前端浮层组件显示进度条
    pub async fn create_task(
        &self,
        dto: TaskCreateDto,
        operator: &str,
        operator_tid: i64,
        state: &AppState,
    ) -> Result<SysTaskModel, ServiceError> {
        // P1：参数校验（task_type/task_name 长度、total 范围）
        crate::common::i18n::validate(&dto)?;
        let now = crate::common::datetime::now_naive();
        let am = SysTaskActiveModel {
            // 多租户 Phase 2：任务单据归属提交人/归属人租户
            tenant_id: Set(operator_tid),
            task_type: Set(dto.task_type),
            task_name: Set(dto.task_name),
            status: Set("pending".to_string()),
            progress: Set(0),
            total: Set(dto.total),
            current: Set(0),
            result_msg: Set(None),
            operator: Set(Some(operator.to_string())),
            operator_id: Set(dto.operator_id),
            create_time: Set(Some(now)),
            update_time: Set(Some(now)),
            ..Default::default()
        };
        let model = self.task_repo.insert(am).await?;

        // P0-2 越权广播修复：taskProgress 定向推送给任务创建者（operator_id），
        // 不再全局广播避免跨用户信息泄漏；operator_id 为 None（系统任务）时不推送 WS。
        Self::push_task_progress(state, &model);
        Ok(model)
    }

    /// 更新任务进度（progress / current / total）
    ///
    /// progress 自动根据 current/total 计算（若 total > 0）
    pub async fn update_progress(
        &self,
        task_id: i64,
        current: i64,
        total: Option<i64>,
        state: &AppState,
    ) -> Result<SysTaskModel, ServiceError> {
        let existing = self
            .task_repo
            .find_by_id(task_id)
            .await?
            .ok_or_else(|| ServiceError::not_found(&crate::tr!("error.task.not_found")))?;

        let total = total.unwrap_or(existing.total);
        let progress = if total > 0 {
            ((current as f64 / total as f64) * 100.0).min(100.0) as i32
        } else {
            existing.progress
        };

        // 多租户：系统侧（定时/异步）更新按任务行自身 tid 归属，禁止回落到 0
        let owner_tid = existing.tenant_id;
        let now = crate::common::datetime::now_naive();
        let mut am: SysTaskActiveModel = existing.into();
        am.tenant_id = Set(owner_tid);
        am.status = Set("running".to_string());
        am.progress = Set(progress);
        am.current = Set(current);
        am.total = Set(total);
        am.update_time = Set(Some(now));

        let model = self.task_repo.update(am).await?;

        // P0-2：定向推送给任务创建者
        Self::push_task_progress(state, &model);
        Ok(model)
    }

    /// 完成任务（success）
    pub async fn complete_task(
        &self,
        task_id: i64,
        result_msg: Option<String>,
        state: &AppState,
    ) -> Result<SysTaskModel, ServiceError> {
        let existing = self
            .task_repo
            .find_by_id(task_id)
            .await?
            .ok_or_else(|| ServiceError::not_found(&crate::tr!("error.task.not_found")))?;

        let final_current = existing.total;
        // 多租户：系统侧更新按任务行自身 tid 归属，禁止回落到 0
        let owner_tid = existing.tenant_id;
        let now = crate::common::datetime::now_naive();
        let mut am: SysTaskActiveModel = existing.into();
        am.tenant_id = Set(owner_tid);
        am.status = Set("success".to_string());
        am.progress = Set(100);
        am.current = Set(final_current);
        am.result_msg = Set(result_msg);
        am.update_time = Set(Some(now));

        let model = self.task_repo.update(am).await?;

        // P0-2：定向推送给任务创建者（含结果消息）
        Self::push_task_progress(state, &model);
        Ok(model)
    }

    /// 标记任务失败
    pub async fn fail_task(
        &self,
        task_id: i64,
        error_msg: String,
        state: &AppState,
    ) -> Result<SysTaskModel, ServiceError> {
        let existing = self
            .task_repo
            .find_by_id(task_id)
            .await?
            .ok_or_else(|| ServiceError::not_found(&crate::tr!("error.task.not_found")))?;

        // 多租户：系统侧更新按任务行自身 tid 归属，禁止回落到 0
        let owner_tid = existing.tenant_id;
        let now = crate::common::datetime::now_naive();
        let mut am: SysTaskActiveModel = existing.into();
        am.tenant_id = Set(owner_tid);
        am.status = Set("failed".to_string());
        am.result_msg = Set(Some(error_msg));
        am.update_time = Set(Some(now));

        let model = self.task_repo.update(am).await?;

        // P0-2：定向推送给任务创建者（含失败原因）
        Self::push_task_progress(state, &model);
        Ok(model)
    }

    /// 定向推送 taskProgress 到任务创建者（P0-2 越权广播修复）
    ///
    /// operator_id 为 None（系统任务/历史数据无归属用户）时不推送 WS，
    /// 任务进度仍可通过任务中心分页查询获取，不产生跨用户信息泄漏。
    fn push_task_progress(state: &AppState, model: &SysTaskModel) {
        if let Some(operator_id) = model.operator_id {
            state.broadcast_to_user(
                operator_id,
                "taskProgress",
                serde_json::json!({
                    "taskId": model.task_id,
                    "taskType": model.task_type,
                    "taskName": model.task_name,
                    "status": model.status,
                    "progress": model.progress,
                    "total": model.total,
                    "current": model.current,
                    "resultMsg": model.result_msg
                }),
            );
        }
    }

    /// 分页查询任务
    ///
    /// 多租户 Phase 2：tenant_scope=Some(tid) 仅返回本租户任务；None（平台 0）不过滤。
    pub async fn get_task_page(
        &self,
        query: TaskQueryDto,
        tenant_scope: Option<i64>,
    ) -> Result<(Vec<SysTaskModel>, u64), ServiceError> {
        let page = PageDomain::from(&query);
        let offset = page.offset();
        let limit = page.limit();
        // 动态排序：白名单命中才生效，未命中/缺省由 repository 回退默认排序
        let sort = page.order_by_column.as_deref().and_then(|prop| {
            sort::resolve_column::<crate::entity::sys_task::Entity>(prop, TASK_SORTABLE_COLUMNS)
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
            .task_repo
            .find_page_filtered(
                offset,
                limit,
                query.task_type.as_deref(),
                query.status.as_deref(),
                query.operator.as_deref(),
                begin,
                end,
                tenant_scope,
                sort,
            )
            .await?;
        Ok((rows, total))
    }

    /// 查询任务详情
    ///
    /// 多租户：tenant_scope=Some(tid) 时跨租户任务视为不存在（404）。
    pub async fn get_task_by_id(
        &self,
        task_id: i64,
        tenant_scope: Option<i64>,
    ) -> Result<SysTaskModel, ServiceError> {
        let model = self
            .task_repo
            .find_by_id(task_id)
            .await?
            .ok_or_else(|| ServiceError::not_found(&crate::tr!("error.task.not_found")))?;
        if let Some(t) = tenant_scope
            && model.tenant_id != t
        {
            return Err(ServiceError::not_found(&crate::tr!("error.task.not_found")));
        }
        Ok(model)
    }

    /// 批量删除任务
    ///
    /// 多租户越权防护：任一所选任务跨越操作者租户即整体拒绝（平台操作者放行）。
    pub async fn delete_tasks(&self, ids: Vec<i64>, operator_tid: i64) -> Result<(), ServiceError> {
        // b71 N+1 治理：原循环逐个 find_by_id 仅做租户校验（N 次查询），收敛为一次 is_in 批查。
        // 语义不变：存在的任务逐一校验租户归属，任一越权即整体拒绝；不存在的 id 放行（物理删除本就无行）。
        let tasks = self.task_repo.find_by_ids(ids.clone()).await?;
        for task in &tasks {
            if !crate::common::tenant::tenant_allowed(operator_tid, task.tenant_id) {
                return Err(ServiceError::forbidden(&crate::tr!(
                    "error.common.forbidden"
                )));
            }
        }
        self.task_repo.delete_by_ids(ids).await?;
        Ok(())
    }
}
