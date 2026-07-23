//! 任务进度中心 Service 层
//!
//! 职责：
//! - 创建任务（pending）
//! - 更新任务进度（progress / current / total）
//! - 完成任务（success / failed）
//! - 任务分页查询 / 详情 / 批量删除
//! - 通过 WS 广播 taskProgress 事件，前端浮层组件实时显示

use chrono::NaiveDateTime;
use sea_orm::{DatabaseConnection, Set};
use serde::Deserialize;
use utoipa::{IntoParams, ToSchema};

use crate::common::error::ServiceError;
use crate::common::page::{default_page_num, default_page_size, PageDomain};
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
#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct TaskCreateDto {
    /// 任务类型（export/import/backup/other）
    pub task_type: String,
    /// 任务名称
    pub task_name: String,
    /// 任务总量（默认 0）
    #[serde(default)]
    pub total: i64,
}

// ==================== 辅助函数 ====================

/// 解析时间字符串（%Y-%m-%d 格式），失败返回 ServiceError
fn parse_time(s: &str) -> Result<NaiveDateTime, ServiceError> {
    NaiveDateTime::parse_from_str(s, "%Y-%m-%d")
        .map_err(|_| ServiceError::bad_request(&format!("时间格式不正确: {}", s)))
}

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
        let now = chrono::Local::now().naive_local();
        let am = SysTaskActiveModel {
            task_type: Set(dto.task_type),
            task_name: Set(dto.task_name),
            status: Set("pending".to_string()),
            progress: Set(0),
            total: Set(dto.total),
            current: Set(0),
            result_msg: Set(None),
            operator: Set(Some(operator.to_string())),
            create_time: Set(Some(now)),
            update_time: Set(Some(now)),
            ..Default::default()
        };
        let model = self.task_repo.insert(am).await?;

        // WS 广播任务创建
        let _ = crate::handler::ws_handler::broadcast(
            state,
            "taskProgress",
            serde_json::json!({
                "taskId": model.task_id,
                "taskType": model.task_type,
                "taskName": model.task_name,
                "status": model.status,
                "progress": model.progress,
                "total": model.total,
                "current": model.current
            }),
        );
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
            .ok_or_else(|| ServiceError::not_found("任务不存在"))?;

        let total = total.unwrap_or(existing.total);
        let progress = if total > 0 {
            ((current as f64 / total as f64) * 100.0).min(100.0) as i32
        } else {
            existing.progress
        };

        let now = chrono::Local::now().naive_local();
        let mut am: SysTaskActiveModel = existing.into();
        am.status = Set("running".to_string());
        am.progress = Set(progress);
        am.current = Set(current);
        am.total = Set(total);
        am.update_time = Set(Some(now));

        let model = self.task_repo.update(am).await?;

        // WS 广播进度更新
        let _ = crate::handler::ws_handler::broadcast(
            state,
            "taskProgress",
            serde_json::json!({
                "taskId": model.task_id,
                "taskType": model.task_type,
                "taskName": model.task_name,
                "status": model.status,
                "progress": model.progress,
                "total": model.total,
                "current": model.current
            }),
        );
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
            .ok_or_else(|| ServiceError::not_found("任务不存在"))?;

        let final_current = existing.total;
        let now = chrono::Local::now().naive_local();
        let mut am: SysTaskActiveModel = existing.into();
        am.status = Set("success".to_string());
        am.progress = Set(100);
        am.current = Set(final_current);
        am.result_msg = Set(result_msg);
        am.update_time = Set(Some(now));

        let model = self.task_repo.update(am).await?;

        let _ = crate::handler::ws_handler::broadcast(
            state,
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
            .ok_or_else(|| ServiceError::not_found("任务不存在"))?;

        let now = chrono::Local::now().naive_local();
        let mut am: SysTaskActiveModel = existing.into();
        am.status = Set("failed".to_string());
        am.result_msg = Set(Some(error_msg));
        am.update_time = Set(Some(now));

        let model = self.task_repo.update(am).await?;

        let _ = crate::handler::ws_handler::broadcast(
            state,
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
        Ok(model)
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
            Some(s) if !s.is_empty() => Some(parse_time(s)?),
            _ => None,
        };
        let end = match query.end_time.as_deref() {
            Some(s) if !s.is_empty() => Some(parse_time(s)?),
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
            .ok_or_else(|| ServiceError::not_found("任务不存在"))
    }

    /// 批量删除任务
    pub async fn delete_tasks(&self, ids: Vec<i64>) -> Result<(), ServiceError> {
        self.task_repo.delete_by_ids(ids).await?;
        Ok(())
    }
}
