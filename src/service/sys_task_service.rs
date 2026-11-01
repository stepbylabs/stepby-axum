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

/// 允许的任务类型白名单。
///
/// 为什么收成白名单（b148）：`task_type` 是前端筛选与标签映射的**唯一键**。开放任意字符串
/// 的后果不是"更灵活"，而是"能入库但解释不了"——列表里既筛不出来（筛选项是有限集），
/// 也说不清是什么任务。改造前实体注释写的是 `export/import/backup/other`，而真实取值是
/// `operlog_export` 与 `replay`，**注释与代码完全对不上**，照着注释写新代码必然造出第三种写法。
///
/// 新增类型要同时改三处：本常量、前端 `task.form.taskType*` 的筛选项、实体注释。
pub const TASK_TYPES: &[&str] = &["operlog_export", "replay", "other"];

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
        // b148：类型必须是白名单里的一种，否则这条任务在任务中心既筛不出也解释不了
        if !TASK_TYPES.contains(&dto.task_type.as_str()) {
            return Err(ServiceError::bad_request(&format!(
                "{}: {}（{}）",
                crate::common::i18n::pick("不支持的任务类型", "Unsupported task type"),
                dto.task_type,
                TASK_TYPES.join(" / ")
            )));
        }
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
    ///
    /// b144 A5：**终态是终点**。改造前这里是"读整行 → 无条件写 `status=running`"，
    /// 于是归档任务的迟到回调/双执行者会把已经 `success`/`failed` 的行倒着改回
    /// `running`：管理端进度条从"已完成"重新走起来，而实际工作早已结束（既不是重试也
    /// 不是新任务）。判断放在 `WHERE status IN (pending, running)` 里，与写成为同一个
    /// 原子决定（AGENTS A.1 第三条——不需要额外一把锁）。
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

        let total = total.unwrap_or(existing.total).max(0);
        // b148：完成数不得越界。上报 `current > total` 时界面会出现"120 / 100"，而进度又被
        // 钳到 100——两个数互相矛盾，看的人分不清是"跑多了"还是"总量填错了"。负数同理：
        // 进度条会反向。这里按总量收敛并留一条 WARN，让越界这件事**有痕迹**而不是被抹平。
        let current = current.max(0);
        let current = if total > 0 && current > total {
            tracing::warn!(
                task_id = task_id,
                current = current,
                total = total,
                "任务进度上报超出总量：按总量收敛（调用方应修上报口径）"
            );
            total
        } else {
            current
        };
        let progress = if total > 0 {
            (((current as f64 / total as f64) * 100.0).round() as i32).clamp(0, 100)
        } else {
            existing.progress.clamp(0, 100)
        };
        let now = crate::common::datetime::now_naive();

        let written = self
            .task_repo
            .advance_progress_if_open(task_id, progress, current, total, now)
            .await?;
        match written {
            Some(model) => {
                // P0-2：定向推送给任务创建者
                Self::push_task_progress(state, &model);
                Ok(model)
            }
            // 没有行被写 ⇒ 该行已不在未结束态（或刚好被并发落终态）。**不推送**——
            // 推送会把前端浮层里已收起的进度条重新点亮。
            None => {
                let row =
                    self.task_repo.find_by_id(task_id).await?.ok_or_else(|| {
                        ServiceError::not_found(&crate::tr!("error.task.not_found"))
                    })?;
                tracing::warn!(
                    task_id = task_id,
                    status = %row.status,
                    "任务进度更新被忽略：该行已处于终态（迟到的回调不得把已结束的任务改回 running）"
                );
                Ok(row)
            }
        }
    }

    /// 完成任务（success）
    ///
    /// b144 A5：同 `update_progress`——终态之间不得互相覆盖。重复完成（幂等）返回现状
    /// 且不重复推送；已失败的行**不能**被一条迟到的成功回调改成成功（那是把真实故障
    /// 洗成"这轮跑好了"，比进度条倒走更坏）。
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
        let written = self
            .task_repo
            .settle_if_open(task_id, "success", 100, final_current, result_msg, now)
            .await?;
        match written {
            Some(model) => {
                Self::push_task_progress(state, &model);
                Ok(model)
            }
            None => {
                let row =
                    self.task_repo.find_by_id(task_id).await?.ok_or_else(|| {
                        ServiceError::not_found(&crate::tr!("error.task.not_found"))
                    })?;
                match row.status.as_str() {
                    // 幂等：同一任务被重复标记完成（重试、双执行者）⇒ 现状即答案
                    "success" => {
                        tracing::debug!(task_id = task_id, "任务已完成，重复 complete 幂等返回");
                    }
                    other => {
                        tracing::warn!(
                            task_id = task_id,
                            status = %other,
                            "任务 complete 被忽略：该行已落终态且不是 success（迟到的成功回调不得改写失败结论）"
                        );
                    }
                }
                Ok(row)
            }
        }
    }

    /// 标记任务失败
    ///
    /// b144 A5：同上——已成功的行不得被一条迟到的失败回调改成失败（那会把已完成的事实
    /// 抹掉，而归档文件其实已经产出）。
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
        // 进度与当前值保持原样（失败不代表"什么都没做完"，进度是事实）
        let written = self
            .task_repo
            .settle_if_open(
                task_id,
                "failed",
                existing.progress,
                existing.current,
                Some(error_msg),
                now,
            )
            .await?;
        match written {
            Some(model) => {
                Self::push_task_progress(state, &model);
                Ok(model)
            }
            None => {
                let row =
                    self.task_repo.find_by_id(task_id).await?.ok_or_else(|| {
                        ServiceError::not_found(&crate::tr!("error.task.not_found"))
                    })?;
                match row.status.as_str() {
                    "failed" => {
                        tracing::debug!(task_id = task_id, "任务已失败，重复 fail 幂等返回");
                    }
                    other => {
                        tracing::warn!(
                            task_id = task_id,
                            status = %other,
                            "任务 fail 被忽略：该行已落终态且不是 failed（已成功的事实不被抹掉）"
                        );
                    }
                }
                Ok(row)
            }
        }
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
        // b148：未结束的任务不得删除。删掉之后，后台执行者的下一次进度/终态回调会拿到 404
        // （一次真实工作变成一条"任务不存在"的告警），而界面上它已经"处理完了"——既看不到
        // 进度也看不到失败原因。等它落了终态再删，删掉的才是**事实**。
        if let Some(open) = tasks
            .iter()
            .find(|t| matches!(t.status.as_str(), "pending" | "running"))
        {
            return Err(ServiceError::bad_request(&format!(
                "{}: #{}（{}）",
                crate::common::i18n::pick(
                    "任务尚未结束，请等它结束再删除",
                    "Task has not finished yet; delete it after it settles"
                ),
                open.task_id,
                open.status
            )));
        }
        self.task_repo.delete_by_ids(ids).await?;
        Ok(())
    }
}
