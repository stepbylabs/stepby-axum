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
use crate::entity::sys_task::{ActiveModel as SysTaskActiveModel, Model as SysTaskModel};
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
    pub task_type: Option<String>,
    pub status: Option<String>,
    pub operator: Option<String>,
    /// 开始时间（兼容前端 addDateRange 嵌套格式 params[beginTime]）
    #[serde(alias = "params[beginTime]", default)]
    pub begin_time: Option<String>,
    /// 结束时间（兼容前端 addDateRange 嵌套格式 params[endTime]）
    #[serde(alias = "params[endTime]", default)]
    pub end_time: Option<String>,
}

impl From<&TaskQueryDto> for PageDomain {
    fn from(dto: &TaskQueryDto) -> Self {
        PageDomain {
            page_num: dto.page_num,
            page_size: dto.page_size,
            order_by_column: None,
            is_asc: None,
        }
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
        state: &AppState,
    ) -> Result<SysTaskModel, ServiceError> {
        // P1：参数校验（task_type/task_name 长度、total 范围）
        crate::common::i18n::validate(&dto)?;
        let now = crate::common::datetime::now_naive();
        let am = SysTaskActiveModel {
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

        let now = crate::common::datetime::now_naive();
        let mut am: SysTaskActiveModel = existing.into();
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
        let now = crate::common::datetime::now_naive();
        let mut am: SysTaskActiveModel = existing.into();
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

        let now = crate::common::datetime::now_naive();
        let mut am: SysTaskActiveModel = existing.into();
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
    pub async fn get_task_page(
        &self,
        query: TaskQueryDto,
    ) -> Result<(Vec<SysTaskModel>, u64), ServiceError> {
        let page = PageDomain::from(&query);
        let offset = page.offset();
        let limit = page.limit();

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
            )
            .await?;
        Ok((rows, total))
    }

    /// 查询任务详情
    pub async fn get_task_by_id(&self, task_id: i64) -> Result<SysTaskModel, ServiceError> {
        self.task_repo
            .find_by_id(task_id)
            .await?
            .ok_or_else(|| ServiceError::not_found(&crate::tr!("error.task.not_found")))
    }

    /// 批量删除任务
    pub async fn delete_tasks(&self, ids: Vec<i64>) -> Result<(), ServiceError> {
        self.task_repo.delete_by_ids(ids).await?;
        Ok(())
    }
}
