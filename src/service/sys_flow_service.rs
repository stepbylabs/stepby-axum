// axum-backend/src/service/sys_flow_service.rs
//! 审批工作流 Service（方案 B′：`sys_flow_task` 事实源 + `sys_flow_log` 流水，无 flow_instance）
//!
//! 设计依据：docs/optimization/topic-workflow-approval-final-2026-09-23.md（v5 + 第六/七轮）
//!
//! 核心规则（与方案一一对应）：
//! - **审批人提交时快照**写入 task 行（不运行时重算；V3-E1 崩塌点 1）；
//! - **并发控制作用于 task 行**：条件更新 `WHERE status='pending'` + rows_affected 判定（V3-E1 崩塌点 2）；
//! - 单据 `status` / `current_round` / `current_node_seq` 是**派生投影**，与 task/log 同一事务内同步；
//! - 撤回/驳回终止 → 同单据全部 pending task 转 cancelled（V4-E4 task 行状态机）；
//! - 重新提交 → `round_no + 1`（V4-E1 唯一索引含轮次）；
//! - **写动作仅限本人 JWT 会话**（禁 PAT，V7-E1 方案 S）+ **禁止提交人自审**（V2 §6-4）；
//! - 归属校验：待办 = assignee 本人；我发起 = applicant 本人；管理视图 = `system:flow:list`（V2-P0-2）；
//! - 审批流水（`sys_flow_log`）是业务凭证，**永不纳入日志保留期清理**（V2-P0-1）；
//! - 系统动作（超时提醒/自动通过）`operator_id = NULL`（对齐 `sys_task.operator_id=None`）。
//!
//! 分层约束：本 Service 不持有 AppState（service/mod.rs：不依赖 Web 类型）。
//! 通知采用「service 返回待通知列表，调用方（handler / scheduler）执行」的模型 —— 见 `FlowOutcome`。

use std::sync::Arc;

use chrono::NaiveDateTime;
use sea_orm::*;

use crate::common::error::ServiceError;
use crate::entity::flow_demo_doc::{
    ActiveModel as FlowDemoDocActiveModel, Entity as FlowDemoDocEntity,
};
use crate::entity::{
    flow_demo_doc, sys_dept, sys_flow_log, sys_flow_task, sys_role, sys_user, sys_user_role,
};
use crate::repository::flow_demo_doc::FlowDemoDocRepository;
use crate::repository::sys_flow_log::SysFlowLogRepository;
use crate::repository::sys_flow_task::SysFlowTaskRepository;
use crate::service::sys_msg_service::{SendDto, SysMsgService};

pub const BIZ_TYPE_DEMO: &str = "demo_doc";

// ==================== 审批人策略（编译期枚举，V2 §2.2 / V3 §1.1） ====================

/// 审批人策略：编译期枚举，提交时解析一次并**快照**进 task 行（不运行时重算）。
/// 策略变更 = 发版（D2 定案）；运营期换人用转办，不改策略。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApproverPolicy {
    /// 提交人部门主管（sys_dept.leader_user_id）
    DeptLeader,
    /// 指定角色下的全部启用用户
    Role { role_key: &'static str },
    /// 指定用户
    User { user_id: i64 },
}

/// 会签/或签判定
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Quorum {
    /// 全部通过才算节点通过
    All,
    /// 任一通过即节点通过
    Any,
}

/// 单个审批节点规格
#[derive(Debug, Clone)]
pub struct NodeSpec {
    pub node_seq: i32,
    pub node_name: &'static str,
    pub policies: Vec<ApproverPolicy>,
    pub quorum: Quorum,
}

/// 示例单据的审批链
///
/// - single：两级单审（部门主管 → 管理员）
/// - countersign：一级会签（部门主管 与 管理员 全部通过，Quorum::All）
pub fn demo_nodes(flow_mode: &str) -> Vec<NodeSpec> {
    match flow_mode {
        "countersign" => vec![NodeSpec {
            node_seq: 1,
            node_name: "主管与管理员会签",
            policies: vec![
                ApproverPolicy::DeptLeader,
                ApproverPolicy::Role { role_key: "admin" },
            ],
            quorum: Quorum::All,
        }],
        _ => vec![
            NodeSpec {
                node_seq: 1,
                node_name: "部门主管审批",
                policies: vec![ApproverPolicy::DeptLeader],
                quorum: Quorum::Any,
            },
            NodeSpec {
                node_seq: 2,
                node_name: "管理员审批",
                policies: vec![ApproverPolicy::Role { role_key: "admin" }],
                quorum: Quorum::Any,
            },
        ],
    }
}

// ==================== DTO 与返回结构 ====================

/// 提交示例请假单 DTO
#[derive(Debug, Clone, serde::Deserialize, garde::Validate, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct FlowSubmitDto {
    /// 单据标题
    #[garde(length(chars, min = 1, max = 200))]
    pub title: String,
    /// 请假类型（annual/sick/personal）
    #[garde(ascii)]
    pub leave_type: String,
    /// 请假天数（1-365）
    #[garde(range(min = 1, max = 365))]
    pub days: i32,
    /// 事由
    #[garde(length(chars, max = 500))]
    pub reason: Option<String>,
    /// 审批模式（single/countersign）
    #[garde(ascii)]
    pub flow_mode: String,
}

/// 审批动作 DTO
#[derive(Debug, serde::Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct FlowActionDto {
    /// 动作（approve/reject/withdraw/transfer）
    pub action: String,
    /// 审批意见
    pub comment: Option<String>,
    /// 转办目标 user_id（仅 transfer 必填）
    pub to_user_id: Option<i64>,
}

#[derive(Debug, serde::Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct FlowPageQuery {
    pub page_num: Option<u64>,
    pub page_size: Option<u64>,
    pub status: Option<String>,
}

fn page_args(query: &FlowPageQuery) -> (u64, u64) {
    let size = query.page_size.unwrap_or(10).clamp(1, 100);
    let num = query.page_num.unwrap_or(1).max(1);
    ((num - 1) * size, size)
}

/// 提交/重提交结果：单据 + 首轮待通知的审批人列表（通知由调用方执行）
#[derive(Debug)]
pub struct FlowSubmitOutcome {
    pub doc: flow_demo_doc::Model,
    pub notify_assignees: Vec<i64>,
}

/// 审批动作结果：任务 + 待通知列表 + 办结通知（可选）
#[derive(Debug)]
pub struct FlowActOutcome {
    pub task: sys_flow_task::Model,
    /// 需要推送"新待办"的用户（推进下一节点 / 转办目标）
    pub notify_assignees: Vec<i64>,
    /// 需要推送"已办结"的申请人 + 终态（approved/rejected）
    pub notify_finished: Option<(i64, &'static str)>,
}

/// 超时扫描结果：提醒数/跳过数 + 待通知列表（scheduler 执行 WS 与站内审计）
#[derive(Debug, Default)]
pub struct FlowScanOutcome {
    pub reminded: u64,
    pub skipped: u64,
    /// (assignee_id, title)
    pub notify: Vec<(i64, String)>,
}

// ==================== Service ====================

/// 审批工作流 Service（不 Clone：持有消息 Service，AppState 内单实例构造）
pub struct SysFlowService {
    db: DatabaseConnection,
    config: Arc<crate::config::Settings>,
    msg_service: SysMsgService,
}

impl SysFlowService {
    pub fn new(
        db: DatabaseConnection,
        config: Arc<crate::config::Settings>,
        msg_service: SysMsgService,
    ) -> Self {
        Self {
            db,
            config,
            msg_service,
        }
    }

    // ---------- 策略解析（提交时快照） ----------

    /// 解析单个策略为审批人列表。解析失败**显式报错**，不静默跳过（V2-P0-5）。
    async fn resolve_policy(
        &self,
        policy: &ApproverPolicy,
        applicant_dept_id: Option<i64>,
    ) -> Result<Vec<i64>, ServiceError> {
        match policy {
            ApproverPolicy::User { user_id } => Ok(vec![*user_id]),
            ApproverPolicy::DeptLeader => {
                let dept_id = applicant_dept_id.ok_or_else(|| {
                    ServiceError::bad_request(&crate::tr!("error.flow.dept_missing"))
                })?;
                let dept = sys_dept::Entity::find_by_id(dept_id)
                    .one(&self.db)
                    .await?
                    .ok_or_else(|| {
                        ServiceError::not_found(&crate::tr!("error.flow.dept_not_found"))
                    })?;
                match dept.leader_user_id {
                    Some(uid) if uid > 0 => Ok(vec![uid]),
                    // 显式报错而非静默跳过：静默跳过会让单据卡死在无审批人状态（V2-P0-5）
                    _ => Err(ServiceError::bad_request(&crate::tr!(
                        "error.flow.leader_missing"
                    ))),
                }
            }
            ApproverPolicy::Role { role_key } => {
                let role = sys_role::Entity::find()
                    .filter(sys_role::Column::RoleKey.eq(*role_key))
                    .one(&self.db)
                    .await?
                    .ok_or_else(|| {
                        ServiceError::not_found(&crate::tr!("error.flow.role_not_found"))
                    })?;
                let urs = sys_user_role::Entity::find()
                    .filter(sys_user_role::Column::RoleId.eq(role.role_id))
                    .all(&self.db)
                    .await?;
                let mut ids: Vec<i64> = Vec::new();
                for ur in urs {
                    if let Some(u) = sys_user::Entity::find_by_id(ur.user_id)
                        .one(&self.db)
                        .await?
                    {
                        // 仅启用且未删除的用户可作为审批人
                        if u.status.as_deref() == Some("0") && u.del_flag.as_deref() != Some("2") {
                            ids.push(u.user_id);
                        }
                    }
                }
                if ids.is_empty() {
                    return Err(ServiceError::bad_request(&crate::tr!(
                        "error.flow.role_no_active_user"
                    )));
                }
                Ok(ids)
            }
        }
    }

    /// 解析节点全部审批人（去重）；**提交人不在审批人之列**（V2 §6-4 / 自检 S3）：
    /// 若解析结果包含提交人，则剔除并回退 admin（user_id=1）；admin 自身提交且无其他审批人时保留 admin。
    async fn resolve_node_assignees(
        &self,
        spec: &NodeSpec,
        applicant_id: i64,
        applicant_dept_id: Option<i64>,
    ) -> Result<Vec<i64>, ServiceError> {
        let mut ids: Vec<i64> = Vec::new();
        for p in &spec.policies {
            for uid in self.resolve_policy(p, applicant_dept_id).await? {
                if !ids.contains(&uid) {
                    ids.push(uid);
                }
            }
        }
        if ids.contains(&applicant_id) {
            // 提交人出现在审批人列 → 剔除；剔除后仍有他人 → 回退 admin 补位（节点可跑）；
            // 剔除后为空 → 该节点唯一审批人就是提交人（全链自审）→ **拒绝提交**（防单据卡死，V2 §6-4）
            ids.retain(|id| *id != applicant_id);
            if ids.is_empty() {
                return Err(ServiceError::bad_request(&crate::tr!(
                    "error.flow.self_approve_chain"
                )));
            }
            if !ids.contains(&1) {
                ids.push(1);
            }
        }
        Ok(ids)
    }

    // ---------- 提交（创建示例单据并发起审批） ----------

    /// 提交示例请假单并创建第一轮审批任务（单事务：doc + tasks + log）
    pub async fn submit_demo(
        &self,
        applicant_id: i64,
        applicant_name: &str,
        dto: FlowSubmitDto,
    ) -> Result<FlowSubmitOutcome, ServiceError> {
        let user = sys_user::Entity::find_by_id(applicant_id)
            .one(&self.db)
            .await?
            .ok_or_else(|| ServiceError::not_found(&crate::tr!("error.flow.user_not_found")))?;
        let dept_id = user.dept_id;
        let specs = demo_nodes(&dto.flow_mode);
        let first = specs
            .first()
            .cloned()
            .ok_or_else(|| ServiceError::bad_request(&crate::tr!("error.flow.mode_invalid")))?;
        let assignees = self
            .resolve_node_assignees(&first, applicant_id, dept_id)
            .await?;

        let now = crate::common::datetime::now_naive();
        let due_at = now + chrono::Duration::hours(self.config.flow.timeout_hours);
        let node_task_type = if first.quorum == Quorum::All {
            "countersign"
        } else {
            "single"
        };
        // 事务闭包要求 'static：克隆捕获字段，避免借用外层局部变量
        let first_node_seq = first.node_seq;
        let first_node_name = first.node_name.to_string();
        let applicant_name_owned = applicant_name.to_string();

        let db = &self.db;
        let doc = db
            .transaction::<_, flow_demo_doc::Model, ServiceError>(|txn| {
                let dto = dto.clone();
                let applicant_name = applicant_name_owned.clone();
                let assignees = assignees.clone();
                Box::pin(async move {
                    let doc_am = FlowDemoDocActiveModel {
                        title: Set(dto.title.clone()),
                        applicant_id: Set(applicant_id),
                        applicant_name: Set(Some(applicant_name)),
                        dept_id: Set(dept_id),
                        leave_type: Set(dto.leave_type.clone()),
                        days: Set(dto.days),
                        reason: Set(dto.reason.clone()),
                        flow_mode: Set(dto.flow_mode.clone()),
                        status: Set("pending".to_string()),
                        current_round: Set(1),
                        current_node_seq: Set(Some(first_node_seq)),
                        submitted_at: Set(Some(now)),
                        ..Default::default()
                    };
                    let res = FlowDemoDocEntity::insert(doc_am)
                        .exec(txn)
                        .await
                        .map_err(super::sys_flow_service::db_to_svc)?;
                    let doc = FlowDemoDocEntity::find_by_id(res.last_insert_id)
                        .one(txn)
                        .await
                        .map_err(super::sys_flow_service::db_to_svc)?
                        .ok_or_else(|| {
                            ServiceError::internal(&crate::tr!("error.flow.doc_not_found"))
                        })?;

                    for uid in &assignees {
                        let task_am = sys_flow_task::ActiveModel {
                            biz_type: Set(BIZ_TYPE_DEMO.to_string()),
                            biz_id: Set(doc.doc_id),
                            round_no: Set(1),
                            node_seq: Set(first_node_seq),
                            node_name: Set(Some(first_node_name.clone())),
                            assignee_id: Set(*uid),
                            task_type: Set(node_task_type.to_string()),
                            status: Set("pending".to_string()),
                            title: Set(Some(dto.title.clone())),
                            applicant_id: Set(applicant_id),
                            due_at: Set(Some(due_at)),
                            ..Default::default()
                        };
                        sys_flow_task::Entity::insert(task_am)
                            .exec(txn)
                            .await
                            .map_err(super::sys_flow_service::db_to_svc)?;
                    }

                    let log_am = sys_flow_log::ActiveModel {
                        biz_type: Set(BIZ_TYPE_DEMO.to_string()),
                        biz_id: Set(doc.doc_id),
                        round_no: Set(1),
                        node_seq: Set(None),
                        action: Set("submit".to_string()),
                        from_status: Set(Some("draft".to_string())),
                        to_status: Set(Some("pending".to_string())),
                        operator_id: Set(Some(applicant_id)),
                        comment: Set(dto.reason.clone()),
                        acted_at: Set(Some(now)),
                        ..Default::default()
                    };
                    sys_flow_log::Entity::insert(log_am)
                        .exec(txn)
                        .await
                        .map_err(super::sys_flow_service::db_to_svc)?;

                    Ok(doc)
                })
            })
            .await
            .map_err(super::sys_flow_service::tx_to_svc)?;

        Ok(FlowSubmitOutcome {
            doc,
            notify_assignees: assignees,
        })
    }

    // ---------- 审批动作 ----------

    /// 审批动作入口（同意/驳回/撤回/转办）
    ///
    /// - `operator_id`：当前登录用户
    /// - `is_pat`：是否 PAT 会话（写动作一律拒绝，V7-E1 方案 S）
    pub async fn act(
        &self,
        operator_id: i64,
        is_pat: bool,
        task_id: i64,
        dto: FlowActionDto,
    ) -> Result<FlowActOutcome, ServiceError> {
        if is_pat {
            return Err(ServiceError::bad_request(&crate::tr!(
                "error.flow.pat_forbidden"
            )));
        }
        match dto.action.as_str() {
            "approve" | "reject" => self.approve_or_reject(operator_id, task_id, &dto).await,
            "withdraw" => {
                self.withdraw(operator_id, task_id, dto.comment.as_deref())
                    .await
            }
            "transfer" => {
                let to = dto.to_user_id.ok_or_else(|| {
                    ServiceError::bad_request(&crate::tr!("error.flow.to_user_required"))
                })?;
                self.transfer(operator_id, task_id, to, dto.comment.as_deref())
                    .await
            }
            _ => Err(ServiceError::bad_request(&crate::tr!(
                "error.flow.action_invalid"
            ))),
        }
    }

    /// 同意 / 驳回（条件更新 + 会签聚合 + 推进/终止）
    async fn approve_or_reject(
        &self,
        operator_id: i64,
        task_id: i64,
        dto: &FlowActionDto,
    ) -> Result<FlowActOutcome, ServiceError> {
        let task = self.load_task_for_act(task_id, operator_id).await?;
        let approve = dto.action == "approve";

        // 条件更新（并发安全 + 幂等；V3-E1 崩塌点 2 修正后的正确落点）
        let new_task_status = if approve { "approved" } else { "rejected" };
        let affected = self
            .task_repo()
            .update_status_if_pending(task_id, new_task_status, dto.comment.as_deref())
            .await?;
        if affected == 0 {
            return Err(ServiceError::bad_request(&crate::tr!(
                "error.flow.task_not_pending"
            )));
        }

        let now = crate::common::datetime::now_naive();
        let mut outcome = FlowActOutcome {
            task: task.clone(),
            notify_assignees: vec![],
            notify_finished: None,
        };

        // 驳回：终止型（同单当前轮全部 pending → cancelled；V4-E4）
        if !approve {
            self.task_repo()
                .cancel_pending_by_biz(&task.biz_type, task.biz_id, task.round_no)
                .await?;
            self.write_log(
                &task.biz_type,
                task.biz_id,
                task.round_no,
                Some(task.node_seq),
                "reject",
                Some("pending"),
                Some("rejected"),
                Some(operator_id),
                None,
                dto.comment.as_deref(),
                now,
            )
            .await?;
            self.update_doc_status(
                task.biz_id,
                "rejected",
                task.round_no,
                Some(task.node_seq),
                Some(now),
            )
            .await?;
            outcome.notify_finished = Some((task.applicant_id, "rejected"));
            return Ok(outcome);
        }

        // 同意：聚合判定当前节点（会签 All / 或签 Any）
        let rows = self
            .task_repo()
            .find_by_biz_round(&task.biz_type, task.biz_id, task.round_no)
            .await?;
        let same_node: Vec<&sys_flow_task::Model> = rows
            .iter()
            .filter(|r| r.node_seq == task.node_seq)
            .collect();
        let node_done = match task.task_type.as_str() {
            "countersign" => same_node.iter().all(|r| r.status == "approved"),
            _ => same_node.iter().any(|r| r.status == "approved"),
        };

        let mut to_status = "pending";

        if node_done {
            // 当前节点完成 → 找下一个节点或办结
            let doc = self.doc_by_id(task.biz_id).await?;
            let specs = demo_nodes(&doc.flow_mode);
            let next = specs.iter().find(|s| s.node_seq > task.node_seq);
            match next {
                Some(next_spec) => {
                    // 推进下一节点（按提交人部门解析，快照）
                    let assignees = self
                        .resolve_node_assignees(next_spec, task.applicant_id, doc.dept_id)
                        .await?;
                    let due_at = now + chrono::Duration::hours(self.config.flow.timeout_hours);
                    let next_task_type = if next_spec.quorum == Quorum::All {
                        "countersign"
                    } else {
                        "single"
                    };
                    let db = &self.db;
                    let next_name = next_spec.node_name.to_string();
                    let next_seq = next_spec.node_seq;
                    let task_biz_type = task.biz_type.clone();
                    let task_title = task.title.clone();
                    let task_applicant_name = task.applicant_name.clone();
                    db.transaction::<_, (), ServiceError>(|txn| {
                        let assignees = assignees.clone();
                        Box::pin(async move {
                            for uid in &assignees {
                                let am = sys_flow_task::ActiveModel {
                                    biz_type: Set(task_biz_type.clone()),
                                    biz_id: Set(task.biz_id),
                                    round_no: Set(task.round_no),
                                    node_seq: Set(next_seq),
                                    node_name: Set(Some(next_name.clone())),
                                    assignee_id: Set(*uid),
                                    task_type: Set(next_task_type.to_string()),
                                    status: Set("pending".to_string()),
                                    title: Set(task_title.clone()),
                                    applicant_id: Set(task.applicant_id),
                                    applicant_name: Set(task_applicant_name.clone()),
                                    due_at: Set(Some(due_at)),
                                    ..Default::default()
                                };
                                sys_flow_task::Entity::insert(am)
                                    .exec(txn)
                                    .await
                                    .map_err(super::sys_flow_service::db_to_svc)?;
                            }
                            // doc 派生列推进
                            let doc_am = FlowDemoDocActiveModel {
                                doc_id: Set(task.biz_id),
                                current_node_seq: Set(Some(next_seq)),
                                update_time: Set(Some(now)),
                                ..Default::default()
                            };
                            FlowDemoDocEntity::update(doc_am)
                                .exec(txn)
                                .await
                                .map_err(super::sys_flow_service::db_to_svc)?;
                            Ok(())
                        })
                    })
                    .await
                    .map_err(super::sys_flow_service::tx_to_svc)?;
                    outcome.notify_assignees = assignees;
                }
                None => {
                    // 全部节点完成 → 办结（同单残余 pending 全部取消）
                    to_status = "approved";
                    self.task_repo()
                        .cancel_pending_by_biz(&task.biz_type, task.biz_id, task.round_no)
                        .await?;
                    self.update_doc_status(
                        task.biz_id,
                        "approved",
                        task.round_no,
                        Some(task.node_seq),
                        Some(now),
                    )
                    .await?;
                    outcome.notify_finished = Some((task.applicant_id, "approved"));
                }
            }
        }

        self.write_log(
            &task.biz_type,
            task.biz_id,
            task.round_no,
            Some(task.node_seq),
            "approve",
            Some("pending"),
            Some(to_status),
            Some(operator_id),
            None,
            dto.comment.as_deref(),
            now,
        )
        .await?;

        outcome.task = self.task_by_id(task_id).await?;
        Ok(outcome)
    }

    /// 撤回（发起人，按单据维度）：docId → 当前轮 pending task → 撤回（V4-E4 task 行状态机）
    pub async fn withdraw_by_doc(
        &self,
        operator_id: i64,
        is_pat: bool,
        doc_id: i64,
        comment: Option<&str>,
    ) -> Result<FlowActOutcome, ServiceError> {
        if is_pat {
            return Err(ServiceError::bad_request(&crate::tr!(
                "error.flow.pat_forbidden"
            )));
        }
        let doc = self.doc_by_id(doc_id).await?;
        if doc.applicant_id != operator_id {
            return Err(ServiceError::forbidden(&crate::tr!(
                "error.flow.withdraw_only_applicant"
            )));
        }
        let task = self
            .task_repo()
            .find_first_pending_by_biz(BIZ_TYPE_DEMO, doc_id)
            .await?
            .ok_or_else(|| ServiceError::bad_request(&crate::tr!("error.flow.task_not_pending")))?;
        self.withdraw(operator_id, task.task_id, comment).await
    }

    /// 撤回（发起人）：同单当前轮全部 pending → cancelled，doc → withdrawn（V4-E4）
    async fn withdraw(
        &self,
        operator_id: i64,
        task_id: i64,
        comment: Option<&str>,
    ) -> Result<FlowActOutcome, ServiceError> {
        let task = self.task_by_id(task_id).await?;
        if task.applicant_id != operator_id {
            return Err(ServiceError::forbidden(&crate::tr!(
                "error.flow.withdraw_only_applicant"
            )));
        }
        let affected = self
            .task_repo()
            .cancel_pending_by_biz(&task.biz_type, task.biz_id, task.round_no)
            .await?;
        if affected == 0 {
            return Err(ServiceError::bad_request(&crate::tr!(
                "error.flow.task_not_pending"
            )));
        }
        let now = crate::common::datetime::now_naive();
        self.write_log(
            &task.biz_type,
            task.biz_id,
            task.round_no,
            None,
            "withdraw",
            Some("pending"),
            Some("withdrawn"),
            Some(operator_id),
            None,
            comment,
            now,
        )
        .await?;
        self.update_doc_status(task.biz_id, "withdrawn", task.round_no, None, Some(now))
            .await?;
        Ok(FlowActOutcome {
            task,
            notify_assignees: vec![],
            notify_finished: None,
        })
    }

    /// 转办：pending 行改派（保留原行，assignee 更新；V4-E4）
    async fn transfer(
        &self,
        operator_id: i64,
        task_id: i64,
        to_user_id: i64,
        comment: Option<&str>,
    ) -> Result<FlowActOutcome, ServiceError> {
        let task = self.load_task_for_act(task_id, operator_id).await?;
        if to_user_id == operator_id {
            return Err(ServiceError::bad_request(&crate::tr!(
                "error.flow.transfer_to_self"
            )));
        }
        if to_user_id == task.applicant_id {
            return Err(ServiceError::bad_request(&crate::tr!(
                "error.flow.self_approve_forbidden"
            )));
        }
        // 目标用户必须启用且未删除
        let target = sys_user::Entity::find_by_id(to_user_id)
            .one(&self.db)
            .await?
            .ok_or_else(|| ServiceError::not_found(&crate::tr!("error.flow.user_not_found")))?;
        if target.status.as_deref() != Some("0") || target.del_flag.as_deref() == Some("2") {
            return Err(ServiceError::bad_request(&crate::tr!(
                "error.flow.user_disabled"
            )));
        }

        let affected = self
            .task_repo()
            .transfer_if_pending(task_id, to_user_id)
            .await?;
        if affected == 0 {
            return Err(ServiceError::bad_request(&crate::tr!(
                "error.flow.task_not_pending"
            )));
        }
        let now = crate::common::datetime::now_naive();
        self.write_log(
            &task.biz_type,
            task.biz_id,
            task.round_no,
            Some(task.node_seq),
            "transfer",
            Some("pending"),
            Some("pending"),
            Some(operator_id),
            Some(to_user_id),
            comment,
            now,
        )
        .await?;
        Ok(FlowActOutcome {
            task: self.task_by_id(task_id).await?,
            notify_assignees: vec![to_user_id],
            notify_finished: None,
        })
    }

    // ---------- 重新提交（round_no + 1；V4-E1 轮次设计） ----------

    /// 重新提交（draft/rejected/withdrawn 状态的单据，发起人本人）：轮次 +1，重建任务
    pub async fn resubmit_demo(
        &self,
        operator_id: i64,
        is_pat: bool,
        doc_id: i64,
        comment: Option<&str>,
    ) -> Result<FlowSubmitOutcome, ServiceError> {
        if is_pat {
            return Err(ServiceError::bad_request(&crate::tr!(
                "error.flow.pat_forbidden"
            )));
        }
        let doc = self.doc_by_id(doc_id).await?;
        if doc.applicant_id != operator_id {
            return Err(ServiceError::forbidden(&crate::tr!(
                "error.flow.withdraw_only_applicant"
            )));
        }
        if doc.status == "pending" {
            return Err(ServiceError::bad_request(&crate::tr!(
                "error.flow.task_not_pending"
            )));
        }
        let new_round = doc.current_round + 1;
        let specs = demo_nodes(&doc.flow_mode);
        let first = specs
            .first()
            .cloned()
            .ok_or_else(|| ServiceError::bad_request(&crate::tr!("error.flow.mode_invalid")))?;
        let assignees = self
            .resolve_node_assignees(&first, doc.applicant_id, doc.dept_id)
            .await?;
        let now = crate::common::datetime::now_naive();
        let due_at = now + chrono::Duration::hours(self.config.flow.timeout_hours);
        let node_task_type = if first.quorum == Quorum::All {
            "countersign"
        } else {
            "single"
        };
        // 事务闭包要求 'static：把捕获的字段提前克隆为拥有值（避免借用外层局部变量）
        let first_node_seq = first.node_seq;
        let first_node_name = first.node_name.to_string();
        let applicant_id_snap = doc.applicant_id;
        let applicant_name_snap = doc.applicant_name.clone();
        let doc_title_snap = doc.title.clone();
        let doc_status_snap = doc.status.clone();
        let comment_owned = comment.map(|c| c.to_string());

        let db = &self.db;
        db.transaction::<_, (), ServiceError>(|txn| {
            let assignees = assignees.clone();
            let doc_title = doc_title_snap.clone();
            let doc_status = doc_status_snap.clone();
            let comment_owned = comment_owned.clone();
            Box::pin(async move {
                for uid in &assignees {
                    let am = sys_flow_task::ActiveModel {
                        biz_type: Set(BIZ_TYPE_DEMO.to_string()),
                        biz_id: Set(doc_id),
                        round_no: Set(new_round),
                        node_seq: Set(first_node_seq),
                        node_name: Set(Some(first_node_name.clone())),
                        assignee_id: Set(*uid),
                        task_type: Set(node_task_type.to_string()),
                        status: Set("pending".to_string()),
                        title: Set(Some(doc_title.clone())),
                        applicant_id: Set(applicant_id_snap),
                        applicant_name: Set(applicant_name_snap.clone()),
                        due_at: Set(Some(due_at)),
                        ..Default::default()
                    };
                    sys_flow_task::Entity::insert(am)
                        .exec(txn)
                        .await
                        .map_err(super::sys_flow_service::db_to_svc)?;
                }
                let log_am = sys_flow_log::ActiveModel {
                    biz_type: Set(BIZ_TYPE_DEMO.to_string()),
                    biz_id: Set(doc_id),
                    round_no: Set(new_round),
                    node_seq: Set(None),
                    action: Set("submit".to_string()),
                    from_status: Set(Some(doc_status)),
                    to_status: Set(Some("pending".to_string())),
                    operator_id: Set(Some(operator_id)),
                    comment: Set(comment_owned),
                    acted_at: Set(Some(now)),
                    ..Default::default()
                };
                sys_flow_log::Entity::insert(log_am)
                    .exec(txn)
                    .await
                    .map_err(super::sys_flow_service::db_to_svc)?;
                // doc 派生列推进（round +1，状态回 pending，清办结时间）
                let doc_am = FlowDemoDocActiveModel {
                    doc_id: Set(doc_id),
                    status: Set("pending".to_string()),
                    current_round: Set(new_round),
                    current_node_seq: Set(Some(first.node_seq)),
                    submitted_at: Set(Some(now)),
                    finished_at: Set(None),
                    update_time: Set(Some(now)),
                    ..Default::default()
                };
                FlowDemoDocEntity::update(doc_am)
                    .exec(txn)
                    .await
                    .map_err(super::sys_flow_service::db_to_svc)?;
                Ok(())
            })
        })
        .await
        .map_err(super::sys_flow_service::tx_to_svc)?;

        Ok(FlowSubmitOutcome {
            doc: self.doc_by_id(doc_id).await?,
            notify_assignees: assignees,
        })
    }

    // ---------- 查询 ----------

    /// 我的待办（assignee = 当前用户；**不套 data_scope**，V2-P0-2）
    pub async fn todo_page(
        &self,
        operator_id: i64,
        query: FlowPageQuery,
    ) -> Result<(Vec<sys_flow_task::Model>, u64), ServiceError> {
        let (offset, limit) = page_args(&query);
        Ok(self
            .task_repo()
            .find_todo_page(operator_id, offset, limit)
            .await?)
    }

    /// 待办数量（红点）
    pub async fn pending_count(&self, operator_id: i64) -> Result<u64, ServiceError> {
        Ok(self.task_repo().count_pending(operator_id).await?)
    }

    /// 我发起的单据（applicant = 当前用户）
    pub async fn mine_page(
        &self,
        operator_id: i64,
        query: FlowPageQuery,
    ) -> Result<(Vec<flow_demo_doc::Model>, u64), ServiceError> {
        let (offset, limit) = page_args(&query);
        Ok(self
            .doc_repo()
            .find_mine_page(operator_id, offset, limit)
            .await?)
    }

    /// 管理视图：全部单据（**调用方须持有 system:flow:list**；data_scope 由调用方叠加，V3-E4）
    pub async fn all_page(
        &self,
        query: FlowPageQuery,
    ) -> Result<(Vec<flow_demo_doc::Model>, u64), ServiceError> {
        let (offset, limit) = page_args(&query);
        let status = query.status.as_deref();
        Ok(self.doc_repo().find_all_page(status, offset, limit).await?)
    }

    /// 任务详情 + 单据信息 + 时间线（assignee / 发起人 / 持有 system:flow:list 者可看）
    pub async fn task_detail(
        &self,
        operator_id: i64,
        is_manager: bool,
        task_id: i64,
    ) -> Result<serde_json::Value, ServiceError> {
        let task = self.task_by_id(task_id).await?;
        if task.assignee_id != operator_id && task.applicant_id != operator_id && !is_manager {
            return Err(ServiceError::forbidden(&crate::tr!(
                "error.flow.not_assignee"
            )));
        }
        let timeline = self
            .log_repo()
            .find_timeline(&task.biz_type, task.biz_id)
            .await?;
        let doc = self.doc_by_id(task.biz_id).await.ok();
        Ok(serde_json::json!({
            "task": task,
            "doc": doc,
            "timeline": timeline,
        }))
    }

    // ---------- 超时扫描（scheduler 调用；V7-E1 路径② / V5 §1.2） ----------

    /// 超时扫描（带 Redis；由 scheduler 调用，避免 Service 持有连接管理器之外的资源）
    pub async fn scan_timeouts_with_redis(
        &self,
        redis: &mut redis::aio::ConnectionManager,
        limit: u64,
    ) -> Result<FlowScanOutcome, ServiceError> {
        let now = crate::common::datetime::now_naive();
        let candidates = self.task_repo().find_timeout_candidates(now, limit).await?;
        let mut outcome = FlowScanOutcome::default();
        let interval = self.config.flow.remind_interval_secs;
        for task in candidates {
            let key = format!("flow_remind:{}", task.task_id);
            // SETNX + TTL 去重；Redis 故障时宁可重复也不漏报（login_anomaly_detector 范式）
            let acquired: Option<String> = redis::cmd("SET")
                .arg(&key)
                .arg("1")
                .arg("NX")
                .arg("EX")
                .arg(interval)
                .query_async(redis)
                .await
                .unwrap_or(None);
            if acquired.is_none() {
                outcome.skipped += 1;
                continue;
            }
            let now2 = crate::common::datetime::now_naive();
            // 流水（系统动作：operator_id = NULL，V4 §4-22）
            let _ = self
                .write_log(
                    &task.biz_type,
                    task.biz_id,
                    task.round_no,
                    Some(task.node_seq),
                    "timeout_remind",
                    None,
                    None,
                    None,
                    None,
                    Some("超时待审批提醒"),
                    now2,
                )
                .await;
            let _ = self.task_repo().touch_reminded(task.task_id, now2).await;
            // 站内审计（send_log；用户可见性以"待办列表"为准，WS 仅加速——此处无 AppState 不发 WS）
            let title = task.title.clone().unwrap_or_default();
            self.send_site_audit(task.assignee_id, &title).await;
            outcome.notify.push((task.assignee_id, title));
            outcome.reminded += 1;
        }
        Ok(outcome)
    }

    /// 发送站内审计消息（site 渠道；to_addr = 字符串化 user_id，V7-E3）
    ///
    /// 供 handler / scheduler 调用（通知的最终执行点）；失败不阻断业务。
    pub async fn send_site_audit(&self, user_id: i64, title: &str) {
        let dto = SendDto {
            template_code: "flow_todo".to_string(),
            channel_code: Some("site".to_string()),
            to_addr: user_id.to_string(),
            params: std::collections::HashMap::from([("title".to_string(), title.to_string())]),
        };
        if let Err(e) = self.msg_service.send(dto, "system").await {
            tracing::warn!("flow 站内提醒发送失败（不阻断业务）: {}", e.message);
        }
    }

    // ---------- 内部工具 ----------

    fn task_repo(&self) -> SysFlowTaskRepository {
        SysFlowTaskRepository::new(self.db.clone())
    }

    fn log_repo(&self) -> SysFlowLogRepository {
        SysFlowLogRepository::new(self.db.clone())
    }

    fn doc_repo(&self) -> FlowDemoDocRepository {
        FlowDemoDocRepository::new(self.db.clone())
    }

    async fn task_by_id(&self, task_id: i64) -> Result<sys_flow_task::Model, ServiceError> {
        self.task_repo()
            .find_by_id(task_id)
            .await?
            .ok_or_else(|| ServiceError::not_found(&crate::tr!("error.flow.task_not_found")))
    }

    async fn doc_by_id(&self, doc_id: i64) -> Result<flow_demo_doc::Model, ServiceError> {
        self.doc_repo()
            .find_by_id(doc_id)
            .await?
            .ok_or_else(|| ServiceError::not_found(&crate::tr!("error.flow.doc_not_found")))
    }

    /// 审批动作前置校验：仅 assignee 本人可操作（水平越权防护，V2-P0-4）
    async fn load_task_for_act(
        &self,
        task_id: i64,
        operator_id: i64,
    ) -> Result<sys_flow_task::Model, ServiceError> {
        let task = self.task_by_id(task_id).await?;
        if task.assignee_id != operator_id {
            return Err(ServiceError::forbidden(&crate::tr!(
                "error.flow.not_assignee"
            )));
        }
        Ok(task)
    }

    /// 写流水（统一入口）
    #[allow(clippy::too_many_arguments)]
    async fn write_log(
        &self,
        biz_type: &str,
        biz_id: i64,
        round_no: i32,
        node_seq: Option<i32>,
        action: &str,
        from_status: Option<&str>,
        to_status: Option<&str>,
        operator_id: Option<i64>,
        to_user_id: Option<i64>,
        comment: Option<&str>,
        now: NaiveDateTime,
    ) -> Result<sys_flow_log::Model, ServiceError> {
        let am = sys_flow_log::ActiveModel {
            biz_type: Set(biz_type.to_string()),
            biz_id: Set(biz_id),
            round_no: Set(round_no),
            node_seq: Set(node_seq),
            action: Set(action.to_string()),
            from_status: Set(from_status.map(|s| s.to_string())),
            to_status: Set(to_status.map(|s| s.to_string())),
            operator_id: Set(operator_id),
            to_user_id: Set(to_user_id),
            comment: Set(comment.map(|c| c.to_string())),
            acted_at: Set(Some(now)),
            ..Default::default()
        };
        self.log_repo()
            .insert(am)
            .await
            .map_err(super::sys_flow_service::db_to_svc)
    }

    /// 推进示例单据派生列
    async fn update_doc_status(
        &self,
        doc_id: i64,
        status: &str,
        round_no: i32,
        node_seq: Option<i32>,
        now: Option<NaiveDateTime>,
    ) -> Result<(), ServiceError> {
        let finished = if matches!(status, "approved" | "rejected") {
            now
        } else {
            None
        };
        let am = FlowDemoDocActiveModel {
            doc_id: Set(doc_id),
            status: Set(status.to_string()),
            current_round: Set(round_no),
            current_node_seq: Set(node_seq),
            finished_at: Set(finished),
            update_time: Set(now),
            ..Default::default()
        };
        self.doc_repo().update(am).await?;
        Ok(())
    }
}

/// DbErr → ServiceError（事务闭包内统一映射）
pub(super) fn db_to_svc(e: DbErr) -> ServiceError {
    ServiceError::from(e)
}

/// 事务错误解包
pub(super) fn tx_to_svc(e: TransactionError<ServiceError>) -> ServiceError {
    match e {
        TransactionError::Connection(db) => ServiceError::from(db),
        TransactionError::Transaction(s) => s,
    }
}
