// stepby-axum/src/service/sys_flow_service.rs
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
    flow_demo_doc, flow_graph_doc, sys_dept, sys_flow_log, sys_flow_task, sys_role, sys_user,
    sys_user_role,
};
use crate::repository::flow_demo_doc::{FlowDemoDocRepository, FlowDocScope};
use crate::repository::sys_flow_log::SysFlowLogRepository;
use crate::repository::sys_flow_task::SysFlowTaskRepository;
use crate::service::sys_msg_service::{SendDto, SysMsgService};

/// 业务单据类型注册表（W-19）
///
/// 审批引擎（`sys_flow_task` + `sys_flow_log`）本身**与单据类型无关**：单据只用
/// `(biz_type, biz_id)` 定位，轮次 / 节点 / 审批人由引擎维护。新增一种业务单据只需两步，
/// **零表结构变更**：
/// 1. 在本模块登记业务类型常量并加入 `ALL`（供校验 / 遍历 / 治理引用）；
/// 2. 在 `REGISTRY` 追加注册项（审批链提供者 + 单据投影回写——见 `BizTypeRegistration`），
///    并写一层单据适配：开轮时调用 `engine_open_round`（插单据 + 开审批同事务）。
///
/// 第 2 步使**推进路径**（`/system/flow/act` 的同意/驳回）同样与单据类型无关：
/// 引擎按 `task.biz_type` 取注册项 → 链由注册项给出、投影由注册项回写，
/// 因此新类型**无需**改动引擎即可跑通「提交 → 审批 → 办结」全链。
///
/// 单据表本身**不泛化**（`flow_demo_doc` / 未来各业务表结构互不相同），
/// 泛化边界止于引擎：引擎不知道任何单据表，业务类型由适配层显式传入。
pub mod biz_type {
    use std::future::Future;
    use std::pin::Pin;

    use super::*;

    /// 示例请假单（`flow_demo_doc` 表；内置演示与集成测试用）
    pub const DEMO_DOC: &str = "demo_doc";

    /// 图驱动单据（`flow_graph_doc` 表；批次十六：任一已发布流程图驱动审批）
    pub const GRAPH_DOC: &str = "flow_graph_doc";

    /// 全部**内置**业务单据类型（新增类型必须在此登记）
    pub const ALL: &[&str] = &[DEMO_DOC, GRAPH_DOC];

    /// 是否为已登记的内置业务单据类型
    pub fn is_registered(biz_type: &str) -> bool {
        ALL.contains(&biz_type)
    }

    /// 单轮审批链上下文（**推进**时由适配层按业务类型提供）
    #[derive(Debug, Clone)]
    pub struct RoundChain {
        /// 本轮节点链（`node_seq` 升序）
        pub nodes: Vec<NodeSpec>,
        /// 申请人部门快照（`DeptLeader` 策略定位用）。
        /// `None` = 由引擎回退读取申请人当前部门（见 `approve_or_reject`）。
        pub dept_id: Option<i64>,
    }

    /// 审批链提供者：引擎**不感知任何单据表**，链由业务适配层给出。
    ///
    /// - 内置示例：数据驱动 —— 链取自 `flow_demo_doc.flow_mode`（提交时快照进单据）；
    /// - 生成/自研单据：返回自己的常量链（gen_table flow 模板的 `flow_nodes()`）。
    pub type ChainProvider = fn(
        &DatabaseConnection,
        i64,
    ) -> Pin<
        Box<dyn Future<Output = Result<RoundChain, ServiceError>> + Send + 'static>,
    >;

    /// 单据派生投影回写入口（由适配层实现，引擎在推进后调用）。
    ///
    /// 投影列契约（生成模板与示例单据一致）：`status` / `current_round` /
    /// `current_node_seq` / `finished_at` / `update_time` / `tenant_id`。
    pub type ProjectionSync =
        fn(
            &DatabaseConnection,
            i64,
            FlowProjection,
        ) -> Pin<Box<dyn Future<Output = Result<(), ServiceError>> + Send + 'static>>;

    /// 业务类型注册项：引擎推进路径的**唯一**事实源
    pub struct BizTypeRegistration {
        /// 业务类型（须与 `ALL` 严格一致；单测锁定）
        pub biz_type: &'static str,
        /// 审批链提供者
        pub chain: ChainProvider,
        /// 单据派生投影回写入口
        pub sync_projection: ProjectionSync,
    }

    /// 内置示例单据的链提供者（链取自单据 `flow_mode`；部门取提交时快照）
    fn demo_chain(
        db: &DatabaseConnection,
        biz_id: i64,
    ) -> Pin<Box<dyn Future<Output = Result<RoundChain, ServiceError>> + Send + 'static>> {
        let db = db.clone();
        Box::pin(async move {
            let doc = FlowDemoDocEntity::find_by_id(biz_id)
                .one(&db)
                .await
                .map_err(db_to_svc)?
                .ok_or_else(|| ServiceError::not_found(&crate::tr!("error.flow.doc_not_found")))?;
            Ok(RoundChain {
                nodes: demo_nodes(&doc.flow_mode),
                dept_id: doc.dept_id,
            })
        })
    }

    /// 内置示例单据的投影回写（`flow_demo_doc` 派生列）
    fn demo_projection_sync(
        db: &DatabaseConnection,
        biz_id: i64,
        p: FlowProjection,
    ) -> Pin<Box<dyn Future<Output = Result<(), ServiceError>> + Send + 'static>> {
        let db = db.clone();
        Box::pin(async move {
            let am = FlowDemoDocActiveModel {
                tenant_id: Set(p.tenant_id),
                doc_id: Set(biz_id),
                status: Set(p.status),
                current_round: Set(p.current_round),
                current_node_seq: Set(p.current_node_seq),
                finished_at: Set(p.finished_at),
                update_time: Set(Some(p.now)),
                ..Default::default()
            };
            FlowDemoDocEntity::update(am)
                .exec(&db)
                .await
                .map_err(db_to_svc)?;
            Ok(())
        })
    }

    /// 图驱动单据的链提供者（批次十六）：按提交时绑定的 flow_id 版本快照取图，
    /// 用**冻结在单据里的字段快照**重放静态路由（确定性——同单据重放同路径），
    /// 再把途经的 approve 节点转成线性 NodeSpec 链喂引擎。
    fn graph_chain(
        db: &DatabaseConnection,
        biz_id: i64,
    ) -> Pin<Box<dyn Future<Output = Result<RoundChain, ServiceError>> + Send + 'static>> {
        let db = db.clone();
        Box::pin(async move {
            let doc = crate::entity::flow_graph_doc::Entity::find_by_id(biz_id)
                .one(&db)
                .await
                .map_err(db_to_svc)?
                .ok_or_else(|| {
                    ServiceError::not_found(&crate::tr!("error.flow.graph_doc_not_found"))
                })?;
            // 版本快照：按 doc.flow_id 取图（提交时绑定，后续发版不影响在途单据）
            let def = crate::entity::prelude::FlowDefinition::find_by_id(doc.flow_id)
                .one(&db)
                .await
                .map_err(db_to_svc)?
                .ok_or_else(|| ServiceError::not_found(&crate::tr!("error.flow.def_not_found")))?;
            let graph = crate::common::flow_graph::FlowGraph::parse_and_validate(&def.graph_json)
                .map_err(|e| ServiceError::bad_request(&e))?;
            let snapshot: serde_json::Value = serde_json::from_str(&doc.fields_json)
                .map_err(|e| ServiceError::internal(&format!("字段快照损坏: {e}")))?;
            let route = graph
                .route_graph(&snapshot)
                .map_err(|e| ServiceError::bad_request(&e))?;
            let nodes = graph_to_specs(&graph, &route)?;
            Ok(RoundChain {
                nodes,
                dept_id: doc.dept_id,
            })
        })
    }

    /// 图驱动单据的投影回写（`flow_graph_doc` 派生列——契约与 demo 一致）
    fn graph_projection_sync(
        db: &DatabaseConnection,
        biz_id: i64,
        p: FlowProjection,
    ) -> Pin<Box<dyn Future<Output = Result<(), ServiceError>> + Send + 'static>> {
        let db = db.clone();
        Box::pin(async move {
            let am = crate::entity::prelude::FlowGraphDocActiveModel {
                tenant_id: Set(p.tenant_id),
                doc_id: Set(biz_id),
                status: Set(p.status),
                current_round: Set(p.current_round),
                current_node_seq: Set(p.current_node_seq),
                finished_at: Set(p.finished_at),
                update_time: Set(Some(p.now)),
                ..Default::default()
            };
            crate::entity::prelude::FlowGraphDocEntity::update(am)
                .exec(&db)
                .await
                .map_err(db_to_svc)?;
            Ok(())
        })
    }

    /// 注册表：新增业务类型（含 gen_table 生成的审批单据）**必须同时**：
    /// ① 在 `ALL` 登记类型常量；② 在本表追加注册项（链提供者 + 投影回写）。
    ///
    /// 二者不一致由单测 `registry_matches_registered_types` 锁定，
    /// 避免出现"登记了但推进不了"（推进路径取不到注册项 → 显式失败，不静默降级）。
    pub const REGISTRY: &[BizTypeRegistration] = &[
        BizTypeRegistration {
            biz_type: DEMO_DOC,
            chain: demo_chain,
            sync_projection: demo_projection_sync,
        },
        BizTypeRegistration {
            biz_type: GRAPH_DOC,
            chain: graph_chain,
            sync_projection: graph_projection_sync,
        },
    ];

    /// 按业务类型取注册项（未登记 → `None`，调用方显式报错）
    pub fn find(biz_type: &str) -> Option<&'static BizTypeRegistration> {
        REGISTRY.iter().find(|r| r.biz_type == biz_type)
    }
}

/// 引擎 → 适配层的**派生投影**回写指令
///
/// 引擎在推进/终止单据后据此调用注册项的 `sync_projection`，由适配层写回自己的单据表；
/// 引擎自身不构造任何业务表的 SQL（`biz_type` 泛化的关键：引擎不知道单据表结构）。
#[derive(Debug, Clone)]
pub struct FlowProjection {
    /// 目标单据状态（`pending` / `approved` / `rejected` / `withdrawn`）
    pub status: String,
    /// 当前轮次
    pub current_round: i32,
    /// 当前节点序号（办结/撤回后为最后一个节点）
    pub current_node_seq: Option<i32>,
    /// 办结时间（`approved` / `rejected` 时写；`None` = 不改写该列）
    pub finished_at: Option<NaiveDateTime>,
    /// 写入时间（投影列 `update_time`）
    pub now: NaiveDateTime,
    /// 单据所属租户（与 task / log 行一致）
    pub tenant_id: i64,
}

/// 内置示例单据的业务类型（历史常量名保留，等价于 `biz_type::DEMO_DOC`）
pub const BIZ_TYPE_DEMO: &str = biz_type::DEMO_DOC;

/// 升级提醒判定（W-7 纯函数，独立单测覆盖）
///
/// `last_reminded_at` 非空（首次提醒已发）且距 `now` 已满 N 天（`days`）⇒ 需要升级提醒。
/// `days == 0` = 关闭升级；`last_reminded_at` 为空（尚未首次提醒）⇒ 永不升级。
/// 周期事实源 = DB `last_reminded_at`：每次升级提醒会重写该字段 ⇒ 自动进入下一个 N 天周期，
/// Redis 仅承担多实例互斥窗（不再依赖长 TTL 去重，Redis 清空也不会重复升级）。
fn should_escalate(last_reminded_at: Option<NaiveDateTime>, now: NaiveDateTime, days: u64) -> bool {
    if days == 0 {
        return false;
    }
    match last_reminded_at {
        Some(reminded_at) => (now - reminded_at) >= chrono::Duration::days(days as i64),
        None => false,
    }
}

// ==================== 审批人策略（编译期枚举，V2 §2.2 / V3 §1.1） ====================

/// 审批人策略：编译期枚举，提交时解析一次并**快照**进 task 行（不运行时重算）。
/// 策略变更 = 发版（D2 定案）；运营期换人用转办，不改策略。
/// 批次十六：role_key 改 String——图驱动单据（flow_graph_doc）的审批策略来自
/// graph_json 运行时数据（&'static str 无法承载）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApproverPolicy {
    /// 提交人部门主管（sys_dept.leader_user_id）
    DeptLeader,
    /// 指定角色下的全部启用用户
    Role { role_key: String },
    /// 指定用户
    User { user_id: i64 },
}

/// 会签/或签/加权判定（G-02 M2 扩展：四模式对齐 flow_graph::MultiMode）
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Quorum {
    /// 全部通过才算节点通过
    All,
    /// 任一通过即节点通过
    Any,
    /// 加权票：已通过行的权重和 ≥ threshold 即节点通过（权重提交时快照进 task 行）
    Weighted { threshold: i64 },
}

/// 高级动作全量清单（demo/gen 链默认开放——与批次十七前行为一致）
pub const FULL_ACTIONS: &[&str] = &["delegate", "countersign_add", "countersign_del"];
/// 全量动作白名单的 String Vec（NodeSpec.actions 构造用）
pub fn full_actions_vec() -> Vec<String> {
    FULL_ACTIONS.iter().map(|s| String::from(*s)).collect()
}

/// 单个审批节点规格
#[derive(Debug, Clone)]
pub struct NodeSpec {
    pub node_seq: i32,
    pub node_name: String,
    pub policies: Vec<ApproverPolicy>,
    pub quorum: Quorum,
    /// 节点是否为**或签**（多审批人任一通过即节点通过，兄弟 pending 行取消）；
    /// 仅与 [`Quorum::Any`] 搭配（G-02 M2）
    pub or_sign: bool,
    /// 与 `policies` 平行的策略级权重（weighted 节点生效；同策略解析出的全部用户共享；
    /// 空 = 全 1）。非 weighted 节点忽略（G-02 M2）
    pub policy_weights: Vec<i64>,
    /// 节点开放的高级动作白名单（批次十七：delegate/countersign_add/countersign_del）；
    /// 快照进 task 行（actions_json），动作入口按白名单收窄——**显式声明优于隐式**，
    /// demo/gen 链填全量（行为与批次十七前一致），图节点按设计器勾选。
    pub actions: Vec<String>,
}

impl NodeSpec {
    /// 引擎 task_type 映射（对齐 flow_graph::MultiMode 四模式）
    pub fn task_type(&self) -> &'static str {
        match self.quorum {
            Quorum::All => "countersign",
            Quorum::Weighted { .. } => "weighted",
            Quorum::Any if self.or_sign => "or_sign",
            Quorum::Any => "single",
        }
    }
}

/// 示例单据的审批链（G-02 M2：四模式演示——single/countersign/or_sign/weighted）
///
/// - single：两级单审（部门主管 → 管理员）
/// - countersign：一级会签（部门主管 与 管理员 全部通过，Quorum::All）
/// - or_sign：一级或签（部门主管 或 管理员 任一通过即节点通过，兄弟 pending 取消）
/// - weighted：一级加权票（部门主管权重 1 / 管理员权重 2，阈值 2——管理员单票即过，
///   仅主管通过不达标需管理员跟进）
pub fn demo_nodes(flow_mode: &str) -> Vec<NodeSpec> {
    match flow_mode {
        "countersign" => vec![NodeSpec {
            node_seq: 1,
            node_name: "主管与管理员会签".to_string(),
            policies: vec![
                ApproverPolicy::DeptLeader,
                ApproverPolicy::Role {
                    role_key: "admin".to_string(),
                },
            ],
            quorum: Quorum::All,
            or_sign: false,
            policy_weights: vec![],
            actions: full_actions_vec(),
        }],
        "or_sign" => vec![NodeSpec {
            node_seq: 1,
            node_name: "主管或管理员任一通过".to_string(),
            policies: vec![
                ApproverPolicy::DeptLeader,
                ApproverPolicy::Role {
                    role_key: "admin".to_string(),
                },
            ],
            quorum: Quorum::Any,
            or_sign: true,
            policy_weights: vec![],
            actions: full_actions_vec(),
        }],
        "weighted" => vec![NodeSpec {
            node_seq: 1,
            node_name: "加权票（阈值 2）".to_string(),
            policies: vec![
                ApproverPolicy::DeptLeader,
                ApproverPolicy::Role {
                    role_key: "admin".to_string(),
                },
            ],
            quorum: Quorum::Weighted { threshold: 2 },
            or_sign: false,
            policy_weights: vec![1, 2],
            actions: full_actions_vec(),
        }],
        _ => vec![
            NodeSpec {
                node_seq: 1,
                node_name: "部门主管审批".to_string(),
                policies: vec![ApproverPolicy::DeptLeader],
                quorum: Quorum::Any,
                or_sign: false,
                policy_weights: vec![],
                actions: full_actions_vec(),
            },
            NodeSpec {
                node_seq: 2,
                node_name: "管理员审批".to_string(),
                policies: vec![ApproverPolicy::Role {
                    role_key: "admin".to_string(),
                }],
                quorum: Quorum::Any,
                or_sign: false,
                policy_weights: vec![],
                actions: full_actions_vec(),
            },
        ],
    }
}

// ==================== DTO 与返回结构 ====================

/// 图 → 线性审批链（批次十六：图驱动单据推进的核心转换）。
///
/// route 序列中的 approve 节点重编号为 `node_seq` 1..n（start/end 跳过）；
/// `multi` 四模式 → `Quorum` 映射：single→Any / countersign→All / or_sign→Any+or_sign /
/// weighted→Weighted{threshold}；`policy_weights` 恒空（BPMN-lite 无审批人级权重
/// 编辑，加权门槛由节点 `threshold` 承载）。节点名缺省回退节点 id。
fn graph_to_specs(
    graph: &crate::common::flow_graph::FlowGraph,
    route: &[String],
) -> Result<Vec<NodeSpec>, ServiceError> {
    let mut specs = Vec::new();
    for nid in route {
        let node = graph
            .nodes
            .iter()
            .find(|n| &n.id == nid)
            .ok_or_else(|| ServiceError::internal(&format!("路由节点缺失: {nid}")))?;
        if node.node_type != "approve" {
            continue;
        }
        let mut policies = Vec::new();
        for a in &node.assignees {
            if a.0 == "dept_leader" {
                policies.push(ApproverPolicy::DeptLeader);
            } else if let Some(key) = a.0.strip_prefix("role:") {
                policies.push(ApproverPolicy::Role {
                    role_key: key.to_string(),
                });
            } else {
                return Err(ServiceError::bad_request(&format!(
                    "节点 {} 审批人形态非法: {}（校验器回归）",
                    node.id, a.0
                )));
            }
        }
        let multi = node
            .multi
            .unwrap_or(crate::common::flow_graph::MultiMode::Single);
        let or_sign = multi == crate::common::flow_graph::MultiMode::OrSign;
        let quorum = match multi {
            crate::common::flow_graph::MultiMode::Single
            | crate::common::flow_graph::MultiMode::OrSign => Quorum::Any,
            crate::common::flow_graph::MultiMode::Countersign => Quorum::All,
            crate::common::flow_graph::MultiMode::Weighted => Quorum::Weighted {
                threshold: node.threshold.unwrap_or(1),
            },
        };
        specs.push(NodeSpec {
            node_seq: (specs.len() + 1) as i32,
            node_name: if node.name.is_empty() {
                node.id.clone()
            } else {
                node.name.clone()
            },
            policies,
            quorum,
            or_sign,
            policy_weights: vec![],
            actions: node.actions.clone(),
        });
    }
    if specs.is_empty() {
        return Err(ServiceError::bad_request(&crate::tr!(
            "error.flow.graph_no_approve"
        )));
    }
    Ok(specs)
}

/// 提交示例请假单 DTO
#[derive(Debug, Clone, serde::Deserialize, garde::Validate, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct FlowSubmitDto {
    /// 单据标题（trim 后非空，≤200）
    #[garde(length(chars, min = 1, max = 200))]
    pub title: String,
    /// 请假类型（annual/sick/personal，枚举校验防任意 ascii 入库撞列宽）
    #[garde(ascii, length(chars, max = 16), custom(validate_leave_type))]
    pub leave_type: String,
    /// 请假天数（1-365）
    #[garde(range(min = 1, max = 365))]
    pub days: i32,
    /// 事由
    #[garde(length(chars, max = 500))]
    pub reason: Option<String>,
    /// 审批模式（single/countersign，枚举校验——非法值显式 400，不静默回退）
    #[garde(ascii, length(chars, max = 16), custom(validate_flow_mode))]
    pub flow_mode: String,
}

/// leave_type 枚举白名单（对齐迁移字典 sys_flow_leave_type 与 DB VARCHAR(16)）
fn validate_leave_type(value: &str, _ctx: &()) -> garde::Result {
    if matches!(value, "annual" | "sick" | "personal") {
        Ok(())
    } else {
        Err(garde::Error::new(crate::tr!(
            "error.flow.leave_type_invalid"
        )))
    }
}

/// flow_mode 枚举白名单（G-02 M2 扩为四模式；非法值 400，不静默回退）
fn validate_flow_mode(value: &str, _ctx: &()) -> garde::Result {
    if matches!(value, "single" | "countersign" | "or_sign" | "weighted") {
        Ok(())
    } else {
        Err(garde::Error::new(crate::tr!("error.flow.mode_invalid")))
    }
}

/// 审批动作 DTO
#[derive(Debug, serde::Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct FlowActionDto {
    /// 动作（approve/reject/withdraw/transfer/delegate）
    pub action: String,
    /// 审批意见
    pub comment: Option<String>,
    /// 转办/委派目标 user_id（仅 transfer/delegate 必填）
    pub to_user_id: Option<i64>,
}

/// 加签 DTO（W-3：对当前节点追加一名会签审批人）
#[derive(Debug, Clone, serde::Deserialize, garde::Validate, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct FlowCountersignDto {
    /// 被加签的审批人 user_id（必须为正整数；garde 拦截 0/负数）
    #[garde(range(min = 1))]
    pub to_user_id: i64,
}

#[derive(Debug, serde::Deserialize, utoipa::IntoParams)]
#[serde(rename_all = "camelCase")]
pub struct FlowPageQuery {
    pub page_num: Option<u64>,
    pub page_size: Option<u64>,
    pub status: Option<String>,
}

fn page_args(query: &FlowPageQuery) -> (u64, u64) {
    crate::common::page::page_args(query.page_num.unwrap_or(1), query.page_size.unwrap_or(10))
}

/// 提交/重提交结果：单据 + 首轮待通知的审批人列表（通知由调用方执行）
#[derive(Debug)]
pub struct FlowSubmitOutcome {
    pub doc: flow_demo_doc::Model,
    pub notify_assignees: Vec<i64>,
}

/// 图驱动单据提交 DTO（批次十六）：flow_code 定位**已发布**版本；
/// fields 为条件求值字段池（对象；提交时冻结进单据）。
#[derive(Debug, Clone, serde::Deserialize, garde::Validate, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct FlowGraphSubmitDto {
    #[garde(length(chars, min = 1, max = 64))]
    pub flow_code: String,
    #[garde(length(chars, min = 1, max = 200))]
    pub title: String,
    /// 条件求值字段池（JSON 对象；如 `{"days": 5, "leaveType": "sick"}`）
    #[garde(skip)]
    pub fields: serde_json::Value,
}

/// 图驱动单据提交结果
#[derive(Debug)]
pub struct GraphSubmitOutcome {
    pub doc: flow_graph_doc::Model,
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
    /// 升级提醒条数（超 N 小时 → 部门主管；W-7）
    pub escalated: u64,
    /// 一致性巡检发现的漂移条数（W-9：聚合校验，仅告警不回写）
    pub drift: u64,
    /// (assignee_id, title)
    pub notify: Vec<(i64, String)>,
}

// ==================== Service ====================

/// 「已办」视图行（W-8）：流水字段 + 单据标题（流水表本身无标题，需按 biz_id 联查）
#[derive(Debug, Clone, serde::Serialize, utoipa::ToSchema, ts_rs::TS)]
#[serde(rename_all = "camelCase")]
#[ts(
    export,
    rename = "FlowDoneVo",
    export_to = "FlowDoneVo.ts",
    rename_all = "camelCase"
)]
pub struct FlowDoneVo {
    pub log_id: i64,
    pub biz_type: String,
    pub biz_id: i64,
    /// 单据标题（取自业务单据；单据被删时为空串）
    pub title: String,
    pub round_no: i32,
    pub node_seq: Option<i32>,
    pub action: String,
    pub comment: Option<String>,
    pub acted_at: Option<NaiveDateTime>,
}

/// 离岗自动转办结果项（W-4）：调用方据此推送"新待办"通知与站内审计
#[derive(Debug, Clone)]
pub struct FlowReassignItem {
    pub task_id: i64,
    /// 新审批人
    pub to_user_id: i64,
    /// 单据标题（task 行冗余快照）
    pub title: String,
}

/// 引擎开轮入参（W-19）：一轮审批的完整**快照**上下文
///
/// 关键点：**不含任何 `biz_type` 硬编码**——业务适配层传入自己的 `biz_type` 即可复用引擎；
/// 审批人在此定格（D2：运行期不重算策略），单据表自身的投影列由适配层在同一事务内回写。
#[derive(Debug, Clone)]
pub struct OpenRoundSpec<'a> {
    /// 业务单据类型（登记于 `biz_type` 模块）
    pub biz_type: &'a str,
    /// 业务单据主键
    pub biz_id: i64,
    /// 轮次（首次提交 1；重提交为 `current_round + 1`）
    pub round_no: i32,
    /// 单据标题（冗余快照进 task 行，列表免 join）
    pub title: &'a str,
    /// 申请人 user_id
    pub applicant_id: i64,
    /// 申请人姓名快照（可空）
    pub applicant_name: Option<&'a str>,
    /// 单据所属租户
    pub tenant_id: i64,
    /// 首节点序号
    pub node_seq: i32,
    /// 首节点名称
    pub node_name: &'a str,
    /// 节点任务类型：`single`（单审）/ `countersign`（会签）/ `or_sign`（或签）/ `weighted`（加权票）
    pub task_type: &'a str,
    /// 快照审批人（已由 `resolve_node_assignees` 解析，引擎不再查库）
    pub assignees: &'a [i64],
    /// 与 `assignees` 平行的权重快照（weighted 节点生效；空/缺位 = 1，G-02 M2）
    pub weights: &'a [i64],
    /// weighted 节点门槛快照（权重和 ≥ threshold 即节点通过；NULL = 非 weighted，G-02 M2）
    pub node_threshold: Option<i64>,
    /// 节点高级动作白名单快照（批次十七；快照进 task 行 actions_json）
    pub actions: &'a [String],
    /// SLA 到期时间（可空）
    pub due_at: Option<NaiveDateTime>,
    /// 流水 `from_status`（首提交 `draft`；重提交为提交前状态）
    pub from_status: Option<&'a str>,
    /// 流水备注（提交说明 / 重提交意见）
    pub comment: Option<&'a str>,
    /// 动作时间
    pub now: NaiveDateTime,
}

/// 由 `data_scope` 取值与预取上下文决定单据可见范围（纯函数，W-5）
///
/// 拆出为纯函数以便无 DB 单测全部取值分支；`role_bound_dept_ids` / `dept_subtree_ids`
/// 由调用方**按需**预取（仅 2 / 4 分支需要），此处不做 IO。
fn decide_doc_scope(
    data_scope: Option<i32>,
    operator_id: i64,
    operator_dept_id: Option<i64>,
    role_bound_dept_ids: Vec<i64>,
    dept_subtree_ids: Option<Vec<i64>>,
) -> FlowDocScope {
    match data_scope {
        // 全部数据
        Some(1) => FlowDocScope::All,
        // 自定义：角色绑定部门并集（单据表无自定义字段，custom_sql 不参与）
        Some(2) => FlowDocScope::Depts(role_bound_dept_ids),
        // 本部门
        Some(3) => FlowDocScope::Depts(operator_dept_id.map(|d| vec![d]).unwrap_or_default()),
        // 本部门及以下：部门子树（含自身）
        Some(4) => FlowDocScope::Depts(dept_subtree_ids.unwrap_or_default()),
        // 仅本人(5) / 无角色(None) / 未知值：安全降级（fail-closed）
        _ => FlowDocScope::Applicant(operator_id),
    }
}

// ==================== 审批人解析（自由函数：引擎 ⇄ 业务适配层共用，W-18） ====================
//
// 之所以是**自由函数**而非 `SysFlowService` 方法：代码生成器（`flow` 模板）产出的业务适配层
// 需要在**自己的事务**内解析审批人（单据投影回写 + 开轮必须同事务），此时只能拿到
// `&DatabaseTransaction`，无法持有 Service 实例。自由函数对 `DatabaseConnection` /
// `DatabaseTransaction` 一视同仁，引擎语义（启用态过滤、主管缺失显式报错、禁自审回退）
// 得以**单点复用**，生成代码不必复制一份再各自漂移。

/// 解析单个策略为审批人列表。解析失败**显式报错**，不静默跳过（V2-P0-5）。
async fn resolve_policy(
    conn: &impl ConnectionTrait,
    policy: &ApproverPolicy,
    applicant_dept_id: Option<i64>,
) -> Result<Vec<i64>, ServiceError> {
    match policy {
        ApproverPolicy::User { user_id } => Ok(vec![*user_id]),
        ApproverPolicy::DeptLeader => {
            let dept_id = applicant_dept_id
                .ok_or_else(|| ServiceError::bad_request(&crate::tr!("error.flow.dept_missing")))?;
            let dept = sys_dept::Entity::find_by_id(dept_id)
                .one(conn)
                .await?
                .ok_or_else(|| ServiceError::not_found(&crate::tr!("error.flow.dept_not_found")))?;
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
                .filter(sys_role::Column::RoleKey.eq(role_key))
                .one(conn)
                .await?
                .ok_or_else(|| ServiceError::not_found(&crate::tr!("error.flow.role_not_found")))?;
            let urs = sys_user_role::Entity::find()
                .filter(sys_user_role::Column::RoleId.eq(role.role_id))
                .all(conn)
                .await?;
            // b71 N+1 治理：原实现循环逐个 find_by_id，角色用户多时每次审批提交放大 N 次查询；
            // 改为一次 is_in 批查后内存过滤（仅启用且未删除的用户可作为审批人，语义不变）。
            // 列投影（b74 §一.16 同族）：审批人判定只用 (user_id, status, del_flag)，
            // 未投影会把 `password`（argon2 摘要）读进审批链路内存
            let user_ids: Vec<i64> = urs.iter().map(|ur| ur.user_id).collect();
            let users = if user_ids.is_empty() {
                Vec::new()
            } else {
                sys_user::Entity::find()
                    .select_only()
                    .column(sys_user::Column::UserId)
                    .column(sys_user::Column::Status)
                    .column(sys_user::Column::DelFlag)
                    .filter(sys_user::Column::UserId.is_in(user_ids))
                    .into_tuple::<(i64, Option<String>, Option<String>)>()
                    .all(conn)
                    .await?
            };
            let ids: Vec<i64> = users
                .into_iter()
                .filter(|(_, status, del_flag)| {
                    status.as_deref() == Some("0") && del_flag.as_deref() != Some("2")
                })
                .map(|(user_id, _, _)| user_id)
                .collect();
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
///
/// `pub` 供业务适配层（代码生成器的 `flow` 模板）复用：自审剔除与 admin 回退是**引擎规则**，
/// 复制到生成代码会随引擎演进而漂移。
pub async fn resolve_node_assignees(
    conn: &impl ConnectionTrait,
    spec: &NodeSpec,
    applicant_id: i64,
    applicant_dept_id: Option<i64>,
) -> Result<Vec<i64>, ServiceError> {
    let pairs = resolve_node_assignee_pairs(conn, spec, applicant_id, applicant_dept_id).await?;
    Ok(pairs.into_iter().map(|(uid, _)| uid).collect())
}

/// 解析节点审批人并**携带权重**（G-02 M2）：weighted 节点按 `policy_weights`
/// 与策略对位取权重（同策略解析出的全部用户共享该权重）；其余节点恒 1。
///
/// 与 [`resolve_node_assignees`] 共用去重/自审守卫（`dedupe_and_guard`），不复制不漂移。
pub async fn resolve_node_assignee_pairs(
    conn: &impl ConnectionTrait,
    spec: &NodeSpec,
    applicant_id: i64,
    applicant_dept_id: Option<i64>,
) -> Result<Vec<(i64, i64)>, ServiceError> {
    let mut pairs: Vec<(i64, i64)> = Vec::new();
    for (idx, p) in spec.policies.iter().enumerate() {
        let weight = spec
            .policy_weights
            .get(idx)
            .copied()
            .filter(|w| *w > 0)
            .unwrap_or(1);
        for uid in resolve_policy(conn, p, applicant_dept_id).await? {
            pairs.push((uid, weight));
        }
    }
    let pairs = dedupe_and_guard(pairs, applicant_id);
    if pairs.is_empty() {
        // 全链自审 → 显式拒绝（保持 V2 §6-4 原错误语义：防单据卡死）
        return Err(ServiceError::bad_request(&crate::tr!(
            "error.flow.self_approve_chain"
        )));
    }
    Ok(pairs)
}

/// 去重（同一审批人多重身份**取较大权重**——一人一票，权重取最高身份，避免
/// "主管与角色兼任"场景下权重被首策略覆盖而不可达门槛）+ 自审剔除守卫（V2 §6-4）：
/// 提交人出现 → 剔除；剔除后仍有他人 → 回退 admin 补位（权重 1）；
/// 剔除后为空 → 该节点唯一审批人就是提交人（全链自审）→ 返回空（调用层显式 400）。
fn dedupe_and_guard(pairs: Vec<(i64, i64)>, applicant_id: i64) -> Vec<(i64, i64)> {
    let mut seen: Vec<(i64, i64)> = Vec::new();
    for (uid, w) in pairs {
        match seen.iter_mut().find(|(u, _)| *u == uid) {
            Some((_, w0)) => {
                if w > *w0 {
                    *w0 = w;
                }
            }
            None => seen.push((uid, w)),
        }
    }
    if seen.iter().any(|(uid, _)| *uid == applicant_id) {
        seen.retain(|(uid, _)| *uid != applicant_id);
        if seen.is_empty() {
            return Vec::new();
        }
        if !seen.iter().any(|(uid, _)| *uid == 1) {
            seen.push((1, 1));
        }
    }
    seen
}

/// 审批工作流 Service
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

    // ---------- 提交（创建示例单据并发起审批） ----------

    /// 提交示例请假单并创建第一轮审批任务（单事务：doc + tasks + log）
    pub async fn submit_demo(
        &self,
        applicant_id: i64,
        applicant_name: &str,
        mut dto: FlowSubmitDto,
    ) -> Result<FlowSubmitOutcome, ServiceError> {
        // title 白空格防御：trim 后必须非空（garde min=1 拦不住 " "）
        dto.title = dto.title.trim().to_string();
        if dto.title.is_empty() {
            return Err(ServiceError::bad_request(&crate::tr!(
                "error.flow.title_blank"
            )));
        }
        let user = sys_user::Entity::find_by_id(applicant_id)
            .one(&self.db)
            .await?
            .ok_or_else(|| ServiceError::not_found(&crate::tr!("error.flow.user_not_found")))?;
        let dept_id = user.dept_id;
        // 多租户 Phase 2：业务单据/任务/流水归属提交人用户的租户
        let applicant_tid = user.tenant_id;
        let specs = demo_nodes(&dto.flow_mode);
        let first = specs
            .first()
            .cloned()
            .ok_or_else(|| ServiceError::bad_request(&crate::tr!("error.flow.mode_invalid")))?;
        let assignee_pairs =
            resolve_node_assignee_pairs(&self.db, &first, applicant_id, dept_id).await?;
        let weights: Vec<i64> = assignee_pairs.iter().map(|(_, w)| *w).collect();
        let assignees: Vec<i64> = assignee_pairs.iter().map(|(u, _)| *u).collect();

        let now = crate::common::datetime::now_naive();
        let due_at = now + chrono::Duration::hours(self.config.flow.timeout_hours);
        let node_task_type = first.task_type();
        let node_threshold = match first.quorum {
            Quorum::Weighted { threshold } => Some(threshold),
            _ => None,
        };
        // 事务闭包要求 'static：克隆捕获字段，避免借用外层局部变量
        let first_node_seq = first.node_seq;
        let first_node_name = first.node_name.clone();
        let first_actions = first.actions.clone();
        let applicant_name_owned = applicant_name.to_string();

        let db = &self.db;
        let doc = db
            .transaction::<_, flow_demo_doc::Model, ServiceError>(|txn| {
                let dto = dto.clone();
                let applicant_name = applicant_name_owned.clone();
                let assignees = assignees.clone();
                Box::pin(async move {
                    let doc_am = FlowDemoDocActiveModel {
                        tenant_id: Set(applicant_tid),
                        title: Set(dto.title.clone()),
                        applicant_id: Set(applicant_id),
                        applicant_name: Set(Some(applicant_name.clone())),
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

                    // W-19：开审批走通用引擎（biz_type 显式传入，引擎不感知单据表）
                    super::sys_flow_service::engine_open_round(
                        txn,
                        OpenRoundSpec {
                            biz_type: BIZ_TYPE_DEMO,
                            biz_id: doc.doc_id,
                            round_no: 1,
                            title: &dto.title,
                            applicant_id,
                            applicant_name: Some(applicant_name.as_str()),
                            tenant_id: applicant_tid,
                            node_seq: first_node_seq,
                            node_name: &first_node_name,
                            task_type: node_task_type,
                            assignees: &assignees,
                            weights: &weights,
                            node_threshold,
                            actions: &first_actions,
                            due_at: Some(due_at),
                            from_status: Some("draft"),
                            comment: dto.reason.as_deref(),
                            now,
                        },
                    )
                    .await?;

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

    /// 提交**图驱动**单据（批次十六）：任一**已发布**流程定义（`is_latest='1'` +
    /// `status='1'`）都可作为审批流——提交时静态路由成线性链，字段快照冻结进单据
    /// （推进时由 `biz_type::graph_chain` 重放同路径，确定性）。
    ///
    /// 与 `submit_demo` 的差异：审批链不再来自 `demo_nodes` 硬编码，而来自设计器
    /// 画的图（G-02 M3 的"按图推进"闭环）；条件边按 `fields` 求值（fail-closed）。
    pub async fn submit_graph(
        &self,
        applicant_id: i64,
        applicant_name: &str,
        dto: FlowGraphSubmitDto,
    ) -> Result<GraphSubmitOutcome, ServiceError> {
        let title = dto.title.trim().to_string();
        if title.is_empty() {
            return Err(ServiceError::bad_request(&crate::tr!(
                "error.flow.title_blank"
            )));
        }
        if !dto.fields.is_object() {
            return Err(ServiceError::bad_request(&crate::tr!(
                "error.flow.graph_fields_invalid"
            )));
        }
        let user = sys_user::Entity::find_by_id(applicant_id)
            .one(&self.db)
            .await?
            .ok_or_else(|| ServiceError::not_found(&crate::tr!("error.flow.user_not_found")))?;
        let dept_id = user.dept_id;
        let applicant_tid = user.tenant_id;

        // 绑定已发布版本（租户可引用平台图 tid=0 与本租户图；版本快照 = is_latest 行）
        let def = crate::entity::prelude::FlowDefinition::find()
            .filter(crate::entity::flow_definition::Column::FlowCode.eq(dto.flow_code.as_str()))
            .filter(crate::entity::flow_definition::Column::IsLatest.eq("1"))
            .filter(crate::entity::flow_definition::Column::Status.eq("1"))
            .filter(crate::entity::flow_definition::Column::DelFlag.eq("0"))
            .filter(crate::entity::flow_definition::Column::TenantId.is_in(vec![0, applicant_tid]))
            .one(&self.db)
            .await?
            .ok_or_else(|| {
                ServiceError::not_found(&crate::tr!("error.flow.graph_not_published"))
            })?;
        let graph = crate::common::flow_graph::FlowGraph::parse_and_validate(&def.graph_json)
            .map_err(|e| {
                ServiceError::bad_request(&format!(
                    "{}: {e}",
                    crate::tr!("error.flow.graph_invalid")
                ))
            })?;
        let snapshot = dto.fields.clone();
        let route = graph
            .route_graph(&snapshot)
            .map_err(|e| ServiceError::bad_request(&e))?;
        let specs = graph_to_specs(&graph, &route)?;

        let first = specs
            .first()
            .cloned()
            .ok_or_else(|| ServiceError::bad_request(&crate::tr!("error.flow.graph_no_approve")))?;
        let assignee_pairs =
            resolve_node_assignee_pairs(&self.db, &first, applicant_id, dept_id).await?;
        let weights: Vec<i64> = assignee_pairs.iter().map(|(_, w)| *w).collect();
        let assignees: Vec<i64> = assignee_pairs.iter().map(|(u, _)| *u).collect();

        let now = crate::common::datetime::now_naive();
        let due_at = now + chrono::Duration::hours(self.config.flow.timeout_hours);
        let node_task_type = first.task_type();
        let node_threshold = match first.quorum {
            Quorum::Weighted { threshold } => Some(threshold),
            _ => None,
        };
        let first_node_seq = first.node_seq;
        let first_node_name = first.node_name.clone();
        let first_actions = first.actions.clone();
        let applicant_name_owned = applicant_name.to_string();
        let fields_json = snapshot.to_string();
        let flow_id = def.flow_id;
        let flow_code = def.flow_code.clone();

        let db = &self.db;
        let doc = db
            .transaction::<_, flow_graph_doc::Model, ServiceError>(|txn| {
                let title = title.clone();
                let applicant_name = applicant_name_owned.clone();
                let assignees = assignees.clone();
                let fields_json = fields_json.clone();
                let flow_code = flow_code.clone();
                let first_node_name = first_node_name.clone();
                Box::pin(async move {
                    let doc_am = flow_graph_doc::ActiveModel {
                        tenant_id: Set(applicant_tid),
                        dept_id: Set(dept_id),
                        flow_id: Set(flow_id),
                        flow_code: Set(flow_code),
                        title: Set(title.clone()),
                        fields_json: Set(fields_json),
                        status: Set("pending".to_string()),
                        current_round: Set(1),
                        current_node_seq: Set(Some(first_node_seq)),
                        submitted_at: Set(Some(now)),
                        ..Default::default()
                    };
                    let res = flow_graph_doc::Entity::insert(doc_am)
                        .exec(txn)
                        .await
                        .map_err(super::sys_flow_service::db_to_svc)?;
                    let doc = flow_graph_doc::Entity::find_by_id(res.last_insert_id)
                        .one(txn)
                        .await
                        .map_err(super::sys_flow_service::db_to_svc)?
                        .ok_or_else(|| {
                            ServiceError::internal(&crate::tr!("error.flow.graph_doc_not_found"))
                        })?;

                    super::sys_flow_service::engine_open_round(
                        txn,
                        OpenRoundSpec {
                            biz_type: biz_type::GRAPH_DOC,
                            biz_id: doc.doc_id,
                            round_no: 1,
                            title: &title,
                            applicant_id,
                            applicant_name: Some(applicant_name.as_str()),
                            tenant_id: applicant_tid,
                            node_seq: first_node_seq,
                            node_name: &first_node_name,
                            task_type: node_task_type,
                            assignees: &assignees,
                            weights: &weights,
                            node_threshold,
                            actions: &first_actions,
                            due_at: Some(due_at),
                            from_status: Some("draft"),
                            comment: None,
                            now,
                        },
                    )
                    .await?;

                    Ok(doc)
                })
            })
            .await
            .map_err(super::sys_flow_service::tx_to_svc)?;

        Ok(GraphSubmitOutcome {
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
            // G-02 M2：委派（处理完回不到 A；delegate_from 落库审计）
            "delegate" => {
                let to = dto.to_user_id.ok_or_else(|| {
                    ServiceError::bad_request(&crate::tr!("error.flow.to_user_required"))
                })?;
                self.delegate(operator_id, task_id, to, dto.comment.as_deref())
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

        // 业务类型必须已注册（W-19）：推进/终止都要用注册项的链与投影回写。
        // 必须在**任何写入之前**判定——否则 task 行已被条件更新为 approved/rejected，
        // 却在取注册项时失败，会留下"任务已动、流水与单据未动"的半应用状态
        // （回归锁：test_flow_act_unregistered_biz_type_fails_closed）。
        let reg = biz_type::find(&task.biz_type).ok_or_else(|| {
            ServiceError::internal(&crate::tr!("error.flow.biz_type_unregistered"))
        })?;
        let _ = &reg;

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
                task.tenant_id,
            )
            .await?;
            self.sync_projection(
                &task.biz_type,
                task.biz_id,
                FlowProjection {
                    status: "rejected".to_string(),
                    current_round: task.round_no,
                    current_node_seq: Some(task.node_seq),
                    finished_at: Some(now),
                    now,
                    tenant_id: task.tenant_id,
                },
            )
            .await?;
            outcome.notify_finished = Some((task.applicant_id, "rejected"));
            return Ok(outcome);
        }

        // 同意：聚合判定 + 推进/办结（G-02 M2 抽为 settle_node，与减签收敛共用）
        let to_status = self.settle_node(&task, now, &mut outcome).await?;

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
            task.tenant_id,
        )
        .await?;

        outcome.task = self.task_by_id(task_id).await?;
        Ok(outcome)
    }

    /// 节点聚合判定 + 推进/办结（G-02 M2：approve 与 countersign_del 共用推进收敛）
    ///
    /// 返回本单 to_status：`"pending"`（节点未完成，单据仍 pending）或 `"approved"`（办结）。
    /// 为何共用：减签清空 pending 后必须**重新聚合收敛**——否则"多行会签部分已批、
    /// 剩余被减签"的单据将永久卡死（无 pending 行、也无新动作触发推进）。
    /// 推进/办结的一切写入均为条件安全（条件更新/幂等流水），重复调用无副作用。
    async fn settle_node(
        &self,
        task: &sys_flow_task::Model,
        now: NaiveDateTime,
        outcome: &mut FlowActOutcome,
    ) -> Result<&'static str, ServiceError> {
        // 租户精确收敛（W-2 建议②）：同轮 task 行写入同一租户，带 `Some(tid)` 可杜绝
        // 把他租户同 (biz_type,biz_id,round_no) 的 approved 行计入本节点 ⇒ 防误判完成。
        let rows = self
            .task_repo()
            .find_by_biz_round(
                &task.biz_type,
                task.biz_id,
                task.round_no,
                Some(task.tenant_id),
            )
            .await?;
        let same_node: Vec<&sys_flow_task::Model> = rows
            .iter()
            .filter(|r| r.node_seq == task.node_seq)
            .collect();
        // G-02 M2 四模式聚合。countersign 判定由"all approved"**安全放宽**为
        // "无 pending 且有 approved"——驳回时整单已终止（V4-E4），同节点行只会是
        // pending/approved/cancelled/discarded；加减签产生的 cancelled/discarded
        // 行不再阻塞节点完成 = 设计文档"已投票减签记 discarded 并 threshold-1"语义
        // （All 门槛 = 有效行数，置 discarded 即减一），无需数值 threshold 列。
        // 前置防线（countersign_del 入口）保证节点至少剩一名有效审批人，杜绝全清空误判。
        let node_done = match task.task_type.as_str() {
            "countersign" => {
                !same_node.iter().any(|r| r.status == "pending")
                    && same_node.iter().any(|r| r.status == "approved")
            }
            "weighted" => {
                let approved_weight: i64 = same_node
                    .iter()
                    .filter(|r| r.status == "approved")
                    .map(|r| r.weight)
                    .sum();
                let reached = match task.threshold {
                    Some(t) if t > 0 => approved_weight >= t,
                    // fail-closed：门槛快照缺失/非法 → 不判定完成（warn 留痕待人工）
                    _ => {
                        tracing::warn!(
                            "weighted 节点门槛快照缺失或非法（biz={}/{}, round={}, node={}），不判定完成",
                            task.biz_type,
                            task.biz_id,
                            task.round_no,
                            task.node_seq
                        );
                        false
                    }
                };
                if reached {
                    // 达标 → 兄弟 pending 行取消（未投票者的待办随节点完成收敛）
                    self.task_repo()
                        .cancel_pending_by_node(
                            &task.biz_type,
                            task.biz_id,
                            task.round_no,
                            task.node_seq,
                            Some(task.tenant_id),
                        )
                        .await?;
                }
                reached
            }
            "or_sign" => {
                let any = same_node.iter().any(|r| r.status == "approved");
                if any {
                    // 或签：任一通过 → 兄弟 pending 行取消（剩余待办不再悬挂）
                    self.task_repo()
                        .cancel_pending_by_node(
                            &task.biz_type,
                            task.biz_id,
                            task.round_no,
                            task.node_seq,
                            Some(task.tenant_id),
                        )
                        .await?;
                }
                any
            }
            _ => same_node.iter().any(|r| r.status == "approved"),
        };

        let mut to_status = "pending";

        if node_done {
            // 当前节点完成 → 找下一个节点或办结。
            // 链与投影均来自业务类型注册项（W-19）：引擎不感知任何单据表，
            // 故新登记类型（含 gen_table 生成的审批单据）无需改引擎即可推进。
            let reg = biz_type::find(&task.biz_type).ok_or_else(|| {
                ServiceError::internal(&crate::tr!("error.flow.biz_type_unregistered"))
            })?;
            // 部门快照：适配层给出优先（demo = 单据 `dept_id`）；缺失时回退申请人当前部门
            let chain = (reg.chain)(&self.db, task.biz_id).await?;
            let dept_id = match chain.dept_id {
                Some(d) => Some(d),
                None => sys_user::Entity::find_by_id(task.applicant_id)
                    .one(&self.db)
                    .await
                    .map_err(db_to_svc)?
                    .and_then(|u| u.dept_id),
            };
            let specs = chain.nodes;
            let next = specs.iter().find(|s| s.node_seq > task.node_seq);
            match next {
                Some(next_spec) => {
                    // 推进下一节点（按提交人部门解析，快照；G-02 M2：weighted 行带权重/门槛）
                    let assignee_pairs = resolve_node_assignee_pairs(
                        &self.db,
                        next_spec,
                        task.applicant_id,
                        dept_id,
                    )
                    .await?;
                    let weights: Vec<i64> = assignee_pairs.iter().map(|(_, w)| *w).collect();
                    let assignees: Vec<i64> = assignee_pairs.iter().map(|(u, _)| *u).collect();
                    let due_at = now + chrono::Duration::hours(self.config.flow.timeout_hours);
                    let next_task_type = next_spec.task_type();
                    let next_threshold = match next_spec.quorum {
                        Quorum::Weighted { threshold } => Some(threshold),
                        _ => None,
                    };
                    let db = &self.db;
                    let next_name = next_spec.node_name.clone();
                    let next_seq = next_spec.node_seq;
                    let next_actions_json = serde_json::to_string(&next_spec.actions)
                        .unwrap_or_else(|_| "[]".to_string());
                    let task_biz_type = task.biz_type.clone();
                    let task_title = task.title.clone();
                    let task_applicant_name = task.applicant_name.clone();
                    // 事务闭包要求 'static：task 是引用参数，使用到的字段提前值化（避免借用逃逸）
                    let task_tenant_id = task.tenant_id;
                    let task_biz_id = task.biz_id;
                    let task_round_no = task.round_no;
                    let task_applicant_id = task.applicant_id;
                    db.transaction::<_, (), ServiceError>(|txn| {
                        let assignees = assignees.clone();
                        let weights = weights.clone();
                        let task_biz_type = task_biz_type.clone();
                        let task_title = task_title.clone();
                        let task_applicant_name = task_applicant_name.clone();
                        Box::pin(async move {
                            for (idx, uid) in assignees.iter().enumerate() {
                                let am = sys_flow_task::ActiveModel {
                                    tenant_id: Set(task_tenant_id),
                                    biz_type: Set(task_biz_type.clone()),
                                    biz_id: Set(task_biz_id),
                                    round_no: Set(task_round_no),
                                    node_seq: Set(next_seq),
                                    node_name: Set(Some(next_name.clone())),
                                    assignee_id: Set(*uid),
                                    task_type: Set(next_task_type.to_string()),
                                    status: Set("pending".to_string()),
                                    weight: Set(weights.get(idx).copied().unwrap_or(1)),
                                    threshold: Set(next_threshold),
                                    actions_json: Set(Some(next_actions_json.clone())),
                                    title: Set(task_title.clone()),
                                    applicant_id: Set(task_applicant_id),
                                    applicant_name: Set(task_applicant_name.clone()),
                                    due_at: Set(Some(due_at)),
                                    ..Default::default()
                                };
                                sys_flow_task::Entity::insert(am)
                                    .exec(txn)
                                    .await
                                    .map_err(super::sys_flow_service::db_to_svc)?;
                            }
                            Ok(())
                        })
                    })
                    .await
                    .map_err(super::sys_flow_service::tx_to_svc)?;
                    // 单据投影推进（展示列；事实源是 task 行，漂移由 W-9 巡检兜底）
                    self.sync_projection(
                        &task.biz_type,
                        task.biz_id,
                        FlowProjection {
                            status: "pending".to_string(),
                            current_round: task.round_no,
                            current_node_seq: Some(next_seq),
                            finished_at: None,
                            now,
                            tenant_id: task.tenant_id,
                        },
                    )
                    .await?;
                    outcome.notify_assignees = assignees;
                }
                None => {
                    // 全部节点完成 → 办结（同单残余 pending 全部取消）
                    to_status = "approved";
                    self.task_repo()
                        .cancel_pending_by_biz(&task.biz_type, task.biz_id, task.round_no)
                        .await?;
                    self.sync_projection(
                        &task.biz_type,
                        task.biz_id,
                        FlowProjection {
                            status: "approved".to_string(),
                            current_round: task.round_no,
                            current_node_seq: Some(task.node_seq),
                            finished_at: Some(now),
                            now,
                            tenant_id: task.tenant_id,
                        },
                    )
                    .await?;
                    outcome.notify_finished = Some((task.applicant_id, "approved"));
                }
            }
        }

        Ok(to_status)
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
            .find_first_pending_by_biz(
                BIZ_TYPE_DEMO,
                doc_id,
                crate::common::tenant::tenant_scope(doc.tenant_id),
            )
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
        // 业务类型必须已注册（W-19）：同 `approve_or_reject`，先判定再写入，
        // 避免"待办已批量取消、单据投影未回写"的半应用状态
        if biz_type::find(&task.biz_type).is_none() {
            return Err(ServiceError::internal(&crate::tr!(
                "error.flow.biz_type_unregistered"
            )));
        }
        let now = crate::common::datetime::now_naive();
        // b102：批量取消与流水必须同事务——原实现两步独立提交，流水写失败时
        // 待办已全部 cancelled 而审批凭证缺失（撤回成了无审计的事实）。
        let task_repo = self.task_repo();
        let log_repo = self.log_repo();
        let task_biz_type = task.biz_type.clone();
        let task_biz_id = task.biz_id;
        let task_round_no = task.round_no;
        let task_tenant_id = task.tenant_id;
        let log_am = flow_log_model(
            task_tenant_id,
            &task_biz_type,
            task_biz_id,
            task_round_no,
            None,
            "withdraw",
            Some("pending"),
            Some("withdrawn"),
            Some(operator_id),
            None,
            comment,
            now,
        );
        self.db
            .transaction::<_, (), ServiceError>(|txn| {
                let task_repo = task_repo.clone();
                let log_repo = log_repo.clone();
                let task_biz_type = task_biz_type.clone();
                let log_am = log_am.clone();
                Box::pin(async move {
                    let affected = task_repo
                        .cancel_pending_by_biz_conn(txn, &task_biz_type, task_biz_id, task_round_no)
                        .await
                        .map_err(db_to_svc)?;
                    if affected == 0 {
                        return Err(ServiceError::bad_request(&crate::tr!(
                            "error.flow.task_not_pending"
                        )));
                    }
                    log_repo
                        .base()
                        .insert_conn(txn, log_am)
                        .await
                        .map_err(db_to_svc)?;
                    Ok(())
                })
            })
            .await
            .map_err(tx_to_svc)?;
        // 投影是派生列（事实源 = task 行），W-9 巡检可自愈；保留在事务外，
        // 与审批主链的既有口径一致（不让派生写入放大事务持锁时间）。
        self.sync_projection(
            &task.biz_type,
            task.biz_id,
            FlowProjection {
                status: "withdrawn".to_string(),
                current_round: task.round_no,
                current_node_seq: None,
                finished_at: None,
                now,
                tenant_id: task.tenant_id,
            },
        )
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

        let now = crate::common::datetime::now_naive();
        // b102：改派与流水同事务（原实现改派成功而流水失败 ⇒ 换了持有人但查不到是谁改的）
        let transferred = self
            .transfer_pending_atomic(&task, to_user_id, Some(operator_id), comment, now)
            .await?;
        if !transferred {
            return Err(ServiceError::bad_request(&crate::tr!(
                "error.flow.task_not_pending"
            )));
        }
        Ok(FlowActOutcome {
            task: self.task_by_id(task_id).await?,
            notify_assignees: vec![to_user_id],
            notify_finished: None,
        })
    }

    /// 改派 + 流水单事务（人为转办与离岗自动转办共用）。
    ///
    /// 返回 `false` = 条件更新 0 行（并发下已被处理），调用方按幂等跳过。
    async fn transfer_pending_atomic(
        &self,
        task: &sys_flow_task::Model,
        to_user_id: i64,
        operator_id: Option<i64>,
        comment: Option<&str>,
        now: NaiveDateTime,
    ) -> Result<bool, ServiceError> {
        let task_repo = self.task_repo();
        let log_repo = self.log_repo();
        let task_id = task.task_id;
        let log_am = flow_log_model(
            task.tenant_id,
            &task.biz_type,
            task.biz_id,
            task.round_no,
            Some(task.node_seq),
            "transfer",
            Some("pending"),
            Some("pending"),
            operator_id,
            Some(to_user_id),
            comment,
            now,
        );
        self.db
            .transaction::<_, bool, ServiceError>(|txn| {
                let task_repo = task_repo.clone();
                let log_repo = log_repo.clone();
                let log_am = log_am.clone();
                Box::pin(async move {
                    let affected = task_repo
                        .transfer_if_pending_conn(txn, task_id, to_user_id)
                        .await
                        .map_err(db_to_svc)?;
                    if affected == 0 {
                        return Ok(false);
                    }
                    log_repo
                        .base()
                        .insert_conn(txn, log_am)
                        .await
                        .map_err(db_to_svc)?;
                    Ok(true)
                })
            })
            .await
            .map_err(tx_to_svc)
    }

    // ---------- 加签（W-3 / 方案 §7.6） ----------

    // ---------- 委派（G-02 M2，方案 §3.3） ----------

    /// 委派：把自己的待办交给 B 处理（**处理完回不到 A**——assignee 换 B 后状态机不变，
    /// `delegate_from` 记录转出人供审计）
    ///
    /// 与转办（transfer）同型校验（禁自委派 / 禁委派给提交人 / 目标必须启用）；
    /// 差异仅在流水 `action = delegate` 与 `delegate_from` 落库。M3 图驱动接入后按节点
    /// `actions` 白名单收窄（当前 demo 链默认开放，与 transfer 同级——D2 禁的是运行时
    /// 重算审批策略，委派/转办均为有人发起的一次性显式运营动作，不违反 D2）。
    pub async fn delegate(
        &self,
        operator_id: i64,
        task_id: i64,
        to_user_id: i64,
        comment: Option<&str>,
    ) -> Result<FlowActOutcome, ServiceError> {
        let task = self.load_task_for_act(task_id, operator_id).await?;
        ensure_action_allowed(task.actions_json.as_deref(), "delegate")?;
        if to_user_id == operator_id {
            return Err(ServiceError::bad_request(&crate::tr!(
                "error.flow.delegate_self_forbidden"
            )));
        }
        if to_user_id == task.applicant_id {
            return Err(ServiceError::bad_request(&crate::tr!(
                "error.flow.self_approve_forbidden"
            )));
        }
        // 目标用户必须启用且未删除（对齐 transfer）
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
            .delegate_if_pending(task_id, to_user_id, operator_id)
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
            "delegate",
            Some("pending"),
            Some("pending"),
            Some(operator_id),
            Some(to_user_id),
            comment,
            now,
            task.tenant_id,
        )
        .await?;
        Ok(FlowActOutcome {
            task: self.task_by_id(task_id).await?,
            notify_assignees: vec![to_user_id],
            notify_finished: None,
        })
    }

    /// 减签：从当前节点移除一名会签审批人（G-02 M2，与 W-3 加签配对）
    ///
    /// 语义（方案 §3.3）：
    /// - 目标人**未投票**（pending）→ 行置 `cancelled`（直接删）；
    /// - 目标人**已投票**（approved）→ 行置 `discarded`，聚合判定排除之（等价
    ///   "threshold-1"：All 门槛 = 有效行数，无需数值门槛列）；
    /// - **前置防线**：移除后节点仍须 ≥1 名有效审批人（pending/approved），否则 400
    ///   （防"threshold 归零/节点清空"造成单据卡死——"threshold 归零"边界的正确处理）。
    pub async fn countersign_del(
        &self,
        operator_id: i64,
        is_pat: bool,
        task_id: i64,
        to_user_id: i64,
        comment: Option<&str>,
    ) -> Result<FlowActOutcome, ServiceError> {
        if is_pat {
            return Err(ServiceError::bad_request(&crate::tr!(
                "error.flow.pat_forbidden"
            )));
        }
        let task = self.load_task_for_act(task_id, operator_id).await?;
        ensure_action_allowed(task.actions_json.as_deref(), "countersign_del")?;
        let rows = self
            .task_repo()
            .find_by_biz_round(
                &task.biz_type,
                task.biz_id,
                task.round_no,
                Some(task.tenant_id),
            )
            .await?;
        let node_rows: Vec<&sys_flow_task::Model> = rows
            .iter()
            .filter(|r| r.node_seq == task.node_seq)
            .collect();
        // 目标行必须与本任务同轮同节点
        let target_row = node_rows
            .iter()
            .copied()
            .find(|r| r.assignee_id == to_user_id)
            .ok_or_else(|| {
                ServiceError::bad_request(&crate::tr!("error.flow.countersign_del_not_found"))
            })?;
        // 前置防线：移除后节点仍须 ≥1 名有效审批人（pending/approved）
        let effective_after = node_rows
            .iter()
            .filter(|r| r.task_id != target_row.task_id)
            .filter(|r| r.status == "pending" || r.status == "approved")
            .count();
        if effective_after == 0 {
            return Err(ServiceError::bad_request(&crate::tr!(
                "error.flow.countersign_del_last_assignee"
            )));
        }
        let (from_status, to_status) = match target_row.status.as_str() {
            "pending" => {
                let affected = self
                    .task_repo()
                    .cancel_row_if_pending(target_row.task_id)
                    .await?;
                if affected == 0 {
                    return Err(ServiceError::bad_request(&crate::tr!(
                        "error.flow.task_not_pending"
                    )));
                }
                ("pending", "cancelled")
            }
            "approved" => {
                let affected = self
                    .task_repo()
                    .discard_row_if_approved(target_row.task_id)
                    .await?;
                if affected == 0 {
                    return Err(ServiceError::bad_request(&crate::tr!(
                        "error.flow.task_not_pending"
                    )));
                }
                ("approved", "discarded")
            }
            _ => {
                return Err(ServiceError::bad_request(&crate::tr!(
                    "error.flow.countersign_del_not_found"
                )));
            }
        };
        let now = crate::common::datetime::now_naive();
        self.write_log(
            &task.biz_type,
            task.biz_id,
            task.round_no,
            Some(task.node_seq),
            "countersign_del",
            Some(from_status),
            Some(to_status),
            Some(operator_id),
            Some(to_user_id),
            comment,
            now,
            task.tenant_id,
        )
        .await?;
        // G-02 M2：减签后**重新聚合收敛**（共用 settle_node）——清空 pending 后
        // 节点若已满足完成条件（有 approved 无 pending），必须立即推进/办结，
        // 否则单据永久卡死。settle 的全部写入条件安全，未完成时为纯读 + 幂等。
        let mut outcome = FlowActOutcome {
            task: task.clone(),
            notify_assignees: vec![],
            notify_finished: None,
        };
        let _to_status = self.settle_node(&task, now, &mut outcome).await?;
        outcome.task = self.task_by_id(task_id).await?;
        Ok(outcome)
    }

    /// 加签：对当前待办所在节点追加一名会签审批人
    ///
    /// 语义：**显式运营动作**（审批人知情、有流水），复用提交时的快照事务模式，
    /// **不违反 D2**（D2 禁的是"运行时重算审批策略"，加签是有人发起的一次性追加）。
    ///
    /// 行为：
    /// 1. 同轮同节点的全部 pending 行升级为 `countersign`（节点由单审转为会签，须全部通过）；
    /// 2. 追加一条同轮同节点的 pending 会签行（快照 node_name/title/applicant/due_at）；
    /// 3. 写 `countersign_add` 流水。
    ///
    /// 防重：先按 `(biz,round,node,assignee)` 判重（显式 400），唯一索引 `uk_flow_task_biz` 兜底。
    pub async fn countersign_add(
        &self,
        operator_id: i64,
        is_pat: bool,
        task_id: i64,
        to_user_id: i64,
    ) -> Result<FlowActOutcome, ServiceError> {
        if is_pat {
            return Err(ServiceError::bad_request(&crate::tr!(
                "error.flow.pat_forbidden"
            )));
        }
        let task = self.load_task_for_act(task_id, operator_id).await?;
        ensure_action_allowed(task.actions_json.as_deref(), "countersign_add")?;
        if task.status != "pending" {
            return Err(ServiceError::bad_request(&crate::tr!(
                "error.flow.task_not_pending"
            )));
        }
        if to_user_id == operator_id {
            return Err(ServiceError::bad_request(&crate::tr!(
                "error.flow.transfer_to_self"
            )));
        }
        // 禁自审：加签目标不得是单据提交人
        if to_user_id == task.applicant_id {
            return Err(ServiceError::bad_request(&crate::tr!(
                "error.flow.self_approve_forbidden"
            )));
        }
        let target = sys_user::Entity::find_by_id(to_user_id)
            .one(&self.db)
            .await?
            .ok_or_else(|| ServiceError::not_found(&crate::tr!("error.flow.user_not_found")))?;
        if target.status.as_deref() != Some("0") || target.del_flag.as_deref() == Some("2") {
            return Err(ServiceError::bad_request(&crate::tr!(
                "error.flow.user_disabled"
            )));
        }
        // 防重：同轮同节点已存在该审批人（含已处理行）→ 400，避免唯一索引报错暴露为 500
        if self
            .task_repo()
            .exists_node_assignee(
                &task.biz_type,
                task.biz_id,
                task.round_no,
                task.node_seq,
                to_user_id,
            )
            .await?
        {
            return Err(ServiceError::bad_request(&crate::tr!(
                "error.flow.countersign_duplicate"
            )));
        }

        let now = crate::common::datetime::now_naive();
        let task_biz_type = task.biz_type.clone();
        let task_title = task.title.clone();
        let task_applicant_name = task.applicant_name.clone();
        let task_node_name = task.node_name.clone();
        let task_due_at = task.due_at;
        self.db
            .transaction::<_, (), ServiceError>(|txn| {
                Box::pin(async move {
                    // 1) 同轮同节点 pending 行升级为会签
                    sys_flow_task::Entity::update_many()
                        .col_expr(
                            sys_flow_task::Column::TaskType,
                            sea_query::Expr::value("countersign"),
                        )
                        .filter(sys_flow_task::Column::BizType.eq(task_biz_type.clone()))
                        .filter(sys_flow_task::Column::BizId.eq(task.biz_id))
                        .filter(sys_flow_task::Column::RoundNo.eq(task.round_no))
                        .filter(sys_flow_task::Column::NodeSeq.eq(task.node_seq))
                        .filter(sys_flow_task::Column::Status.eq("pending"))
                        .exec(txn)
                        .await
                        .map_err(super::sys_flow_service::db_to_svc)?;

                    // 2) 追加会签行（快照同节点上下文）
                    let am = sys_flow_task::ActiveModel {
                        tenant_id: Set(task.tenant_id),
                        biz_type: Set(task_biz_type.clone()),
                        biz_id: Set(task.biz_id),
                        round_no: Set(task.round_no),
                        node_seq: Set(task.node_seq),
                        node_name: Set(task_node_name.clone()),
                        assignee_id: Set(to_user_id),
                        task_type: Set("countersign".to_string()),
                        status: Set("pending".to_string()),
                        title: Set(task_title.clone()),
                        applicant_id: Set(task.applicant_id),
                        applicant_name: Set(task_applicant_name.clone()),
                        due_at: Set(task_due_at),
                        ..Default::default()
                    };
                    sys_flow_task::Entity::insert(am)
                        .exec(txn)
                        .await
                        .map_err(super::sys_flow_service::db_to_svc)?;

                    // 3) 流水
                    let log_am = sys_flow_log::ActiveModel {
                        tenant_id: Set(task.tenant_id),
                        biz_type: Set(task_biz_type.clone()),
                        biz_id: Set(task.biz_id),
                        round_no: Set(task.round_no),
                        node_seq: Set(Some(task.node_seq)),
                        action: Set("countersign_add".to_string()),
                        from_status: Set(Some("pending".to_string())),
                        to_status: Set(Some("pending".to_string())),
                        operator_id: Set(Some(operator_id)),
                        to_user_id: Set(Some(to_user_id)),
                        acted_at: Set(Some(now)),
                        ..Default::default()
                    };
                    sys_flow_log::Entity::insert(log_am)
                        .exec(txn)
                        .await
                        .map_err(super::sys_flow_service::db_to_svc)?;
                    Ok(())
                })
            })
            .await
            .map_err(super::sys_flow_service::tx_to_svc)?;

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
        let assignee_pairs =
            resolve_node_assignee_pairs(&self.db, &first, doc.applicant_id, doc.dept_id).await?;
        let weights: Vec<i64> = assignee_pairs.iter().map(|(_, w)| *w).collect();
        let assignees: Vec<i64> = assignee_pairs.iter().map(|(u, _)| *u).collect();
        let now = crate::common::datetime::now_naive();
        let due_at = now + chrono::Duration::hours(self.config.flow.timeout_hours);
        let node_task_type = first.task_type();
        let node_threshold = match first.quorum {
            Quorum::Weighted { threshold } => Some(threshold),
            _ => None,
        };
        // 事务闭包要求 'static：把捕获的字段提前克隆为拥有值（避免借用外层局部变量）
        let first_node_seq = first.node_seq;
        let first_node_name = first.node_name.clone();
        let first_actions = first.actions.clone();
        let applicant_id_snap = doc.applicant_id;
        let applicant_name_snap = doc.applicant_name.clone();
        let doc_title_snap = doc.title.clone();
        let doc_status_snap = doc.status.clone();
        let doc_tid = doc.tenant_id;
        let comment_owned = comment.map(|c| c.to_string());

        let db = &self.db;
        db.transaction::<_, (), ServiceError>(|txn| {
            let assignees = assignees.clone();
            let weights = weights.clone();
            let doc_title = doc_title_snap.clone();
            let doc_status = doc_status_snap.clone();
            let comment_owned = comment_owned.clone();
            Box::pin(async move {
                // W-19：重提交同样走通用引擎（biz_type 显式传入）
                super::sys_flow_service::engine_open_round(
                    txn,
                    OpenRoundSpec {
                        biz_type: BIZ_TYPE_DEMO,
                        biz_id: doc_id,
                        round_no: new_round,
                        title: &doc_title,
                        applicant_id: applicant_id_snap,
                        applicant_name: applicant_name_snap.as_deref(),
                        tenant_id: doc_tid,
                        node_seq: first_node_seq,
                        node_name: &first_node_name,
                        task_type: node_task_type,
                        assignees: &assignees,
                        weights: &weights,
                        node_threshold,
                        actions: &first_actions,
                        due_at: Some(due_at),
                        from_status: Some(doc_status.as_str()),
                        comment: comment_owned.as_deref(),
                        now,
                    },
                )
                .await?;
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

    /// 「已办」：我作为审批人处理过的流水（W-8；口径见 `find_done_page`）
    ///
    /// 返回视图行：流水字段 + 按 `biz_id` 批量补单据标题（一次 `IN` 查询，避免 N+1）。
    pub async fn done_page(
        &self,
        operator_id: i64,
        query: FlowPageQuery,
    ) -> Result<(Vec<FlowDoneVo>, u64), ServiceError> {
        let (offset, limit) = page_args(&query);
        let (rows, total) = self
            .log_repo()
            .find_done_page(operator_id, offset, limit)
            .await?;
        // 标题补齐：内置示例单据联查单据表；其它业务类型回退 task 行快照（W-19）。
        // 键含 biz_type，避免不同业务类型主键相同时标题串台。
        //
        // **租户维度（必须）**：唯一索引 `uk_flow_task_tenant_biz` 使 `(biz_type, biz_id)`
        // **不跨租户唯一**，故按 biz_id 无租户查询会取到他租户同行号的标题（跨租户泄漏）。
        // 精确做法 = 按**流水行自身的 `tenant_id`** 分组查询（task/log 开轮时写入同一租户，
        // 故该租户必与目标单据行一致；平台行 tid=0 亦精确匹配平台单据）。
        let mut titles: std::collections::HashMap<(String, i64), String> =
            std::collections::HashMap::new();

        let mut demo_by_tid: std::collections::HashMap<i64, Vec<i64>> =
            std::collections::HashMap::new();
        let mut others: std::collections::HashMap<(String, i64), Vec<i64>> =
            std::collections::HashMap::new();
        for r in &rows {
            if r.biz_type == biz_type::DEMO_DOC {
                demo_by_tid.entry(r.tenant_id).or_default().push(r.biz_id);
            } else {
                others
                    .entry((r.biz_type.clone(), r.tenant_id))
                    .or_default()
                    .push(r.biz_id);
            }
        }
        for (tid, ids) in demo_by_tid {
            for (id, t) in self.doc_repo().find_titles_by_ids(ids, Some(tid)).await? {
                titles.insert((biz_type::DEMO_DOC.to_string(), id), t);
            }
        }
        for ((bt, tid), ids) in others {
            for (id, t) in self
                .task_repo()
                .find_titles_by_biz(&bt, ids, Some(tid))
                .await?
            {
                titles.insert((bt.clone(), id), t);
            }
        }
        let vos = rows
            .into_iter()
            .map(|r| FlowDoneVo {
                title: titles
                    .get(&(r.biz_type.clone(), r.biz_id))
                    .cloned()
                    .unwrap_or_default(),
                log_id: r.log_id,
                biz_type: r.biz_type,
                biz_id: r.biz_id,
                round_no: r.round_no,
                node_seq: r.node_seq,
                action: r.action,
                comment: r.comment,
                acted_at: r.acted_at,
            })
            .collect();
        Ok((vos, total))
    }

    /// 管理视图：全部单据（**调用方须持有 system:flow:list**）
    ///
    /// - `tenant_scope`：租户操作者 → `Some(tid)` 仅本租户单据；平台 → `None` 全量
    /// - `doc_scope`：按操作者 `data_scope` 解析出的单据可见范围（W-5 / 方案 §7.6）
    pub async fn all_page(
        &self,
        query: FlowPageQuery,
        tenant_scope: Option<i64>,
        doc_scope: &FlowDocScope,
    ) -> Result<(Vec<flow_demo_doc::Model>, u64), ServiceError> {
        let (offset, limit) = page_args(&query);
        let status = query.status.as_deref();
        Ok(self
            .doc_repo()
            .find_all_page(status, offset, limit, tenant_scope, doc_scope)
            .await?)
    }

    /// 管理视图导出（W-11）：与 `all_page` **完全同口径**（租户 + `data_scope` 双层过滤）
    ///
    /// 导出必须复用列表的可见范围计算，否则会成为数据泄露旁路；
    /// 行数上限由 `EXPORT_MAX_ROWS` 兜底（超限由 excel 层打 `X-Export-Truncated` 标记）。
    pub async fn export_docs(
        &self,
        query: FlowPageQuery,
        tenant_scope: Option<i64>,
        doc_scope: &FlowDocScope,
    ) -> Result<(Vec<flow_demo_doc::Model>, bool), ServiceError> {
        let limit = crate::common::page::EXPORT_MAX_ROWS;
        let status = query.status.as_deref();
        let (rows, total) = self
            .doc_repo()
            .find_all_page(status, 0, limit, tenant_scope, doc_scope)
            .await?;
        Ok((rows, total > limit))
    }

    /// 解析操作者在管理视图中的单据可见范围（W-5）
    ///
    /// 方案 §7.6 定案：**只做「部门树 + 本人」过滤**（复用 `min_data_scope` +
    /// `find_descendant_ids`），**否决**把 `custom_sql`（`sys_user` 字段白名单）套到单据表上
    /// —— 属语义错配。取值口径：
    /// - 超管（`SUPER_ADMIN_USER_ID`）/ `data_scope=1` → 全部
    /// - `data_scope=2`（自定义）→ 角色绑定部门（`sys_role_dept`）的并集
    /// - `data_scope=3`（本部门）→ 操作者部门
    /// - `data_scope=4`（本部门及以下）→ 部门子树（递归 CTE，含自身）
    /// - `data_scope=5` / 无角色 / 未知值 → 仅本人（安全降级，fail-closed）
    pub async fn resolve_doc_scope(&self, operator_id: i64) -> Result<FlowDocScope, ServiceError> {
        if operator_id == crate::common::constants::SUPER_ADMIN_USER_ID {
            return Ok(FlowDocScope::All);
        }
        let op_user = sys_user::Entity::find_by_id(operator_id)
            .one(&self.db)
            .await?
            .ok_or_else(|| ServiceError::not_found(&crate::tr!("error.flow.user_not_found")))?;
        let roles = self.operator_roles(operator_id).await?;
        let min_scope = crate::common::data_scope::min_data_scope(&roles);

        // 按需取"角色绑定部门"（仅 data_scope=2 需要）
        let role_bound_dept_ids = if min_scope == Some(2) {
            let role_ids: Vec<i64> = roles
                .iter()
                .filter(|r| r.data_scope.as_deref() == Some("2"))
                .map(|r| r.role_id)
                .collect();
            if role_ids.is_empty() {
                Vec::new()
            } else {
                crate::entity::sys_role_dept::Entity::find()
                    .filter(crate::entity::sys_role_dept::Column::RoleId.is_in(role_ids))
                    .all(&self.db)
                    .await?
                    .into_iter()
                    .map(|rd| rd.dept_id)
                    .collect()
            }
        } else {
            Vec::new()
        };

        // 按需取"部门子树"（仅 data_scope=4 需要）
        let dept_subtree_ids = if min_scope == Some(4) {
            let dept_id = op_user.dept_id.unwrap_or(0);
            Some(
                crate::repository::sys_dept::SysDeptRepository::new(self.db.clone())
                    .find_descendant_ids(dept_id)
                    .await?,
            )
        } else {
            None
        };

        Ok(decide_doc_scope(
            min_scope,
            operator_id,
            op_user.dept_id,
            role_bound_dept_ids,
            dept_subtree_ids,
        ))
    }

    /// 查询操作者的全部角色（用于 data_scope 解析）
    async fn operator_roles(&self, operator_id: i64) -> Result<Vec<sys_role::Model>, ServiceError> {
        let links = sys_user_role::Entity::find()
            .filter(sys_user_role::Column::UserId.eq(operator_id))
            .all(&self.db)
            .await?;
        if links.is_empty() {
            return Ok(Vec::new());
        }
        let role_ids: Vec<i64> = links.into_iter().map(|l| l.role_id).collect();
        Ok(sys_role::Entity::find()
            .filter(sys_role::Column::RoleId.is_in(role_ids))
            .all(&self.db)
            .await?)
    }

    // ---------- 离岗自动转办（W-4 / 方案 §7.6） ----------

    /// 用户离岗（停用 / 删除）→ 其全部 pending 待办自动转办
    ///
    /// 目标解析链：所在部门主管（`sys_dept.leader_user_id`）→ 不可用（缺失/停用/已删除/
    /// 等于本人/等于单据提交人）时回退 `admin(SUPER_ADMIN_USER_ID)`。
    /// 系统动作：`operator_id = NULL`（对齐 `sys_task.operator_id=None` 系统归因），
    /// 逐条写 `transfer` 流水；返回成功转办的 `(task_id, to_user_id)` 列表供调用方推送通知。
    ///
    /// 幂等性：依赖 `transfer_if_pending` 的条件更新（`WHERE status='pending'`），
    /// 并发下已被处理的行走 `rows_affected == 0` 跳过，不产生重复流水。
    pub async fn handle_user_disabled(
        &self,
        user_id: i64,
    ) -> Result<Vec<FlowReassignItem>, ServiceError> {
        let pending = self.task_repo().find_pending_by_assignee(user_id).await?;
        if pending.is_empty() {
            return Ok(Vec::new());
        }
        let mut done: Vec<FlowReassignItem> = Vec::new();
        for task in pending {
            let target = self
                .resolve_reassign_target(user_id, task.applicant_id)
                .await?;
            let now = crate::common::datetime::now_naive();
            // b102：改派与流水同事务；`false` = 并发下已被处理（撤回/审批/他人转办），
            // 跳过以保持幂等，不产生重复流水。
            let transferred = self
                .transfer_pending_atomic(
                    &task,
                    target,
                    // 系统动作：无操作者（离岗转办由停用/删除用户触发，非人为审批动作）
                    None,
                    Some("用户离岗自动转办"),
                    now,
                )
                .await?;
            if !transferred {
                continue;
            }
            done.push(FlowReassignItem {
                task_id: task.task_id,
                to_user_id: target,
                title: task.title.clone().unwrap_or_default(),
            });
        }
        Ok(done)
    }

    /// 解析离岗转办的目标审批人：部门主管 → admin 回退
    ///
    /// 过滤条件：可用（`status='0'` 且未软删除）、不等于离岗本人、不等于单据提交人（禁自审）。
    async fn resolve_reassign_target(
        &self,
        disabled_user_id: i64,
        applicant_id: i64,
    ) -> Result<i64, ServiceError> {
        let mut candidates: Vec<i64> = Vec::new();
        if let Some(u) = sys_user::Entity::find_by_id(disabled_user_id)
            .one(&self.db)
            .await?
            && let Some(dept_id) = u.dept_id
            && let Some(dept) = sys_dept::Entity::find_by_id(dept_id).one(&self.db).await?
            && let Some(leader) = dept.leader_user_id
            && leader > 0
        {
            candidates.push(leader);
        }
        // 回退链终点：超管（部门主管缺失/不可用时保底，避免待办悬空）
        candidates.push(crate::common::constants::SUPER_ADMIN_USER_ID);

        for c in candidates {
            if c == disabled_user_id || c == applicant_id {
                continue;
            }
            if self.is_active_user(c).await? {
                return Ok(c);
            }
        }
        Err(ServiceError::bad_request(&crate::tr!(
            "error.flow.no_assignee"
        )))
    }

    /// 用户是否可用（启用且未软删除）
    async fn is_active_user(&self, user_id: i64) -> Result<bool, ServiceError> {
        let Some(u) = sys_user::Entity::find_by_id(user_id).one(&self.db).await? else {
            return Ok(false);
        };
        Ok(u.status.as_deref() == Some("0") && u.del_flag.as_deref() != Some("2"))
    }

    /// 解析升级提醒的目标（W-7）：申请人部门主管 → admin 回退
    ///
    /// 跳过"待办持有者本人"（升级给自己无意义）与"申请人本人"（申请人已由首次提醒覆盖）；
    /// 候选均不可用时返回 `None`（不打扰，交由人工/一致性巡检发现）。
    async fn resolve_escalation_target(
        &self,
        assignee_id: i64,
        applicant_id: i64,
    ) -> Result<Option<i64>, ServiceError> {
        let mut candidates: Vec<i64> = Vec::new();
        if let Some(applicant) = sys_user::Entity::find_by_id(applicant_id)
            .one(&self.db)
            .await?
            && let Some(dept_id) = applicant.dept_id
            && let Some(dept) = sys_dept::Entity::find_by_id(dept_id).one(&self.db).await?
            && let Some(leader) = dept.leader_user_id
            && leader > 0
        {
            candidates.push(leader);
        }
        candidates.push(crate::common::constants::SUPER_ADMIN_USER_ID);
        for c in candidates {
            if c == assignee_id || c == applicant_id {
                continue;
            }
            if self.is_active_user(c).await? {
                return Ok(Some(c));
            }
        }
        Ok(None)
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
            .find_timeline(
                &task.biz_type,
                task.biz_id,
                crate::common::tenant::tenant_scope(task.tenant_id),
            )
            .await?;
        // 仅示例单据内联返回单据主体：其它业务类型的明细由业务模块自身接口提供
        // （引擎不感知单据表结构，W-19），避免把同 id 的无关 demo 单据当成本单据返回。
        //
        // 只有「单据确实不存在（404）」才降级为不内联：任务本身仍可查看，历史任务在
        // 单据被删除后依然要能打开。DB 故障（超时/连接耗尽/转换错误）必须上抛——
        // 原实现 `.await.ok()` 会让一次抖动在界面上表现为「这条任务没有关联单据」。
        let doc = if task.biz_type == biz_type::DEMO_DOC {
            match self.doc_by_id(task.biz_id).await {
                Ok(doc) => Some(doc),
                Err(e) if e.code == 404 => None,
                Err(e) => return Err(e),
            }
        } else {
            None
        };
        Ok(serde_json::json!({
            "task": task,
            "doc": doc,
            "timeline": timeline,
        }))
    }

    // ---------- 超时扫描（scheduler 调用；V7-E1 路径② / V5 §1.2） ----------

    /// 超时扫描（共享态存储经参数注入，Service 不持有连接资源；由 scheduler 调用）
    ///
    /// SharedStore 迁移：原两处 `SET NX EX` 互斥/去重窗口改为 `store.set_nx_ex`（原子语义等价）；
    /// 命令级超时由 store 内部统一管理（原 `cmd_timeout` 包裹语义），Redis 故障按原
    /// `unwrap_or(None)` 口径视为「未抢占成功」——宁可漏提醒/重复提醒，不阻断扫描主流程。
    pub async fn scan_timeouts_with_redis(
        &self,
        store: Arc<dyn crate::shared_store::SharedStore>,
        limit: u64,
    ) -> Result<FlowScanOutcome, ServiceError> {
        let now = crate::common::datetime::now_naive();
        let candidates = self.task_repo().find_timeout_candidates(now, limit).await?;
        let mut outcome = FlowScanOutcome::default();
        let interval = self.config.flow.remind_interval_secs;
        let escalate_days = self.config.flow.remind_escalate_days;
        for task in candidates {
            // ---- 首次提醒（W-7 策略：只提醒一次 + 待办红点常驻）----
            // 事实源 = DB `last_reminded_at IS NULL`；Redis SETNX 仅作多实例互斥窗口，
            // 避免多实例同时提醒（TTL = remind_interval_secs）。
            if task.last_reminded_at.is_none() {
                let key = format!("flow_remind:{}", task.task_id);
                // 首次提醒互斥窗（原 SET NX EX；store.set_nx_ex 等价，Err 视为未抢占 → 跳过）
                let acquired = store.set_nx_ex(&key, "1", interval).await.unwrap_or(false);
                if !acquired {
                    outcome.skipped += 1;
                    continue;
                }
                let now2 = crate::common::datetime::now_naive();
                if let Err(e) = self
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
                        task.tenant_id,
                    )
                    .await
                {
                    tracing::warn!(task_id = task.task_id, error = %e, "超时提醒流水写入失败");
                }
                // b71 吞错治理：`last_reminded_at` 是提醒去重的**唯一事实源**——写入失败若被
                // 静默丢弃（原 `let _ =`），下一轮扫描会再次命中同一任务，向审批人无限重复
                // 推送，且日志零线索。语义保持不变（不阻断本轮），但故障必须留痕。
                if let Err(e) = self.task_repo().touch_reminded(task.task_id, now2).await {
                    tracing::warn!(
                        task_id = task.task_id,
                        error = %e,
                        "超时提醒去重位写入失败：下一轮扫描可能对同一任务重复提醒"
                    );
                }
                let title = task.title.clone().unwrap_or_default();
                self.send_flow_audit(task.assignee_id, "flow_timeout", &title)
                    .await;
                outcome.notify.push((task.assignee_id, title));
                outcome.reminded += 1;
            } else {
                // 已提醒过：不再重复打扰（红点由待办列表/pending-count 常驻体现）
                outcome.skipped += 1;
            }

            // ---- 升级提醒（W-7）：首次提醒后超 N 天仍未处理 → 提醒申请人部门主管（回退 admin）----
            // 周期事实源 = DB `last_reminded_at`：升级提醒同样重写该字段 ⇒ 进入下一个 N 天周期；
            // Redis SETNX 仅作多实例互斥窗（TTL = remind_interval_secs，与首次提醒同窗口径），
            // 存储 故障/清空时最坏退化为本轮多实例各发一次，不会形成旧版"7 天一轮"的周期性重复。
            if should_escalate(task.last_reminded_at, now, escalate_days)
                && let Some(target) = self
                    .resolve_escalation_target(task.assignee_id, task.applicant_id)
                    .await?
            {
                // 升级提醒多实例互斥窗（原 SET NX EX；store.set_nx_ex 等价，Err 视为未抢占 → 跳过）
                let key = format!("flow_escalate:{}", task.task_id);
                let acquired = store.set_nx_ex(&key, "1", interval).await.unwrap_or(false);
                if acquired {
                    let now2 = crate::common::datetime::now_naive();
                    // 升级提醒写流水（系统归因 operator_id=NULL）+ 重写 last_reminded_at 重置周期
                    if let Err(e) = self
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
                            Some("超时升级提醒（部门主管）"),
                            now2,
                            task.tenant_id,
                        )
                        .await
                    {
                        tracing::warn!(task_id = task.task_id, error = %e, "升级提醒流水写入失败");
                    }
                    // b71 吞错治理：升级提醒同样重写去重位（决定下一个 N 天周期），
                    // 与首次提醒共用同一留痕口径。
                    if let Err(e) = self.task_repo().touch_reminded(task.task_id, now2).await {
                        tracing::warn!(
                            task_id = task.task_id,
                            error = %e,
                            "升级提醒去重位写入失败：下一轮扫描可能对同一任务重复提醒"
                        );
                    }
                    let title = task.title.clone().unwrap_or_default();
                    self.send_flow_audit(target, "flow_timeout", &title).await;
                    outcome.notify.push((target, title));
                    outcome.escalated += 1;
                }
            }
        }
        // W-9：同 Job 尾部做聚合一致性巡检（省一个调度位；漂移仅告警，不回写）
        outcome.drift = self.inspect_consistency(limit).await.unwrap_or_else(|e| {
            tracing::warn!("flow 一致性巡检失败（不影响本轮提醒）: {}", e.message);
            0
        });
        Ok(outcome)
    }

    /// 一致性巡检（W-9）：单据 `status` 与 task 聚合的**双向**漂移检测
    ///
    /// `status` / `current_round` / `current_node_seq` 是派生投影，与 task/log 同事务写入，
    /// 正常路径下不会漂移；本巡检只在本轮扫描尾部抽样核对，发现不一致**仅告警不回写**
    /// （自动回写会掩盖写入路径的 bug，且可能覆盖人工修数）。
    ///
    /// 两类漂移：
    /// - **A 单据 pending 但无 pending 待办**（待办被误取消/漏建 ⇒ 单据卡死）
    /// - **B 存在 pending 待办但单据非 pending**（撤回/驳回未级联取消 ⇒ 幽灵待办）
    pub async fn inspect_consistency(&self, limit: u64) -> Result<u64, ServiceError> {
        let mut drift = 0u64;
        // A：pending 单据应至少有一条 pending 待办
        let pending_docs = self
            .doc_repo()
            .find_page_by_status("pending", 0, limit)
            .await?;
        // b71 N+1 治理：A 类判定由"逐 pending 单据点查待办"（limit 次往返）收敛为一次批查；
        // 判定口径不变（该单据是否至少还有一条 pending 待办）。
        let doc_ids: Vec<i64> = pending_docs.iter().map(|d| d.doc_id).collect();
        let docs_with_pending = self
            .task_repo()
            .find_pending_biz_ids(BIZ_TYPE_DEMO, &doc_ids)
            .await?;
        for doc in pending_docs {
            if !docs_with_pending.contains(&doc.doc_id) {
                drift += 1;
                tracing::warn!(
                    doc_id = doc.doc_id,
                    round = doc.current_round,
                    node_seq = ?doc.current_node_seq,
                    "flow 一致性漂移 A：单据为 pending 但无 pending 待办（可能卡死）"
                );
            }
        }
        // B：pending 待办应对应 pending 单据
        // 仅巡检**内置示例单据**：引擎不感知其它业务类型的单据表（W-19），
        // 拿 `flow_demo_doc` 判非 demo 任务必然假阳性。
        let pending_tasks = self.task_repo().find_pending_page(0, limit).await?;
        // b71 N+1 治理：B 类判定原为"逐 pending 待办点查单据"。改为两轮——
        // ① 按 (biz_type, biz_id) 去重收集候选（去重口径与判次顺序不变）；
        // ② 一次批查单据状态后内存判定。漂移计数与 WARN 文案、遍历顺序均保持原样。
        let mut checked: std::collections::HashSet<(String, i64)> =
            std::collections::HashSet::new();
        let mut candidates: Vec<(i64, i64)> = Vec::new();
        for task in &pending_tasks {
            if task.biz_type != biz_type::DEMO_DOC {
                continue;
            }
            if checked.insert((task.biz_type.clone(), task.biz_id)) {
                candidates.push((task.task_id, task.biz_id));
            }
        }
        let biz_ids: Vec<i64> = candidates.iter().map(|(_, biz_id)| *biz_id).collect();
        let doc_statuses = self.doc_repo().find_statuses_by_ids(&biz_ids).await?;
        for (task_id, biz_id) in candidates {
            // 单据行不存在同样计为漂移（与改造前 `find_by_id → None` 口径一致）
            let doc_pending = doc_statuses
                .get(&biz_id)
                .is_some_and(|status| status == "pending");
            if !doc_pending {
                drift += 1;
                tracing::warn!(
                    biz_id,
                    task_id,
                    "flow 一致性漂移 B：存在 pending 待办但单据非 pending（幽灵待办）"
                );
            }
        }
        Ok(drift)
    }

    /// 发送站内审计消息（site 渠道；to_addr = 字符串化 user_id，V7-E3；模板按场景选择）
    ///
    /// 供 handler / scheduler 调用（通知的最终执行点）；失败不阻断业务。
    pub async fn send_flow_audit(&self, user_id: i64, template_code: &str, title: &str) {
        let dto = SendDto {
            template_code: template_code.to_string(),
            channel_code: Some("site".to_string()),
            to_addr: user_id.to_string(),
            params: std::collections::HashMap::from([("title".to_string(), title.to_string())]),
        };
        if let Err(e) = self.msg_service.send(dto, "system", 0).await {
            tracing::warn!("flow 站内提醒发送失败（不阻断业务）: {}", e.message);
        }
    }

    /// 站内审计的收件地址约定：site 渠道 to_addr = 字符串化 user_id（`sys_msg_service.rs:688-691`）。
    /// 提取为纯函数便于单测守护该约定（喂错类型会被 dispatch 静默记成功，V7-E3）。
    pub fn site_to_addr(user_id: i64) -> String {
        user_id.to_string()
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
        tenant_tid: i64,
    ) -> Result<sys_flow_log::Model, ServiceError> {
        let am = flow_log_model(
            tenant_tid,
            biz_type,
            biz_id,
            round_no,
            node_seq,
            action,
            from_status,
            to_status,
            operator_id,
            to_user_id,
            comment,
            now,
        );
        self.log_repo()
            .insert(am)
            .await
            .map_err(super::sys_flow_service::db_to_svc)
    }

    /// 回写单据派生投影（按业务类型分发到注册项，W-19）
    ///
    /// 引擎不感知任何单据表：未登记业务类型 → 显式失败（**不静默降级**，
    /// 否则任务推进成功而单据状态永停 `pending`，成为最隐蔽的一致性破坏）。
    async fn sync_projection(
        &self,
        biz_type: &str,
        biz_id: i64,
        p: FlowProjection,
    ) -> Result<(), ServiceError> {
        let reg = biz_type::find(biz_type).ok_or_else(|| {
            ServiceError::internal(&crate::tr!("error.flow.biz_type_unregistered"))
        })?;
        (reg.sync_projection)(&self.db, biz_id, p).await
    }
}

/// 通用审批引擎：在**调用方事务内**为任意业务单据开一轮审批（W-19）
///
/// 写入内容（与"提交时快照"规则一致，D2：运行期不重算策略）：
/// - `assignees.len()` 条 pending 待办（审批人在此定格，`task_type` = single/countersign）
/// - 1 条 `submit` 流水
///
/// 两张表（`sys_flow_task` / `sys_flow_log`）**与单据类型无关**，`biz_type` 由入参显式给出；
/// 单据表自身的投影列（status / current_round / current_node_seq / submitted_at 等）
/// 由业务适配层在同一事务内自行回写——引擎不感知任何单据表结构。
///
/// 之所以是**自由函数**而非 `SysFlowService` 方法：SeaORM `transaction()` 的回调是
/// `for<'c> FnOnce(&'c DatabaseTransaction)` HRTB，闭包内借用 `&self` 无法对所有 `'c` 成立；
/// 自由函数只依赖 `txn` 与入参，天然可在事务闭包内调用。
pub async fn engine_open_round(
    txn: &DatabaseTransaction,
    spec: OpenRoundSpec<'_>,
) -> Result<(), ServiceError> {
    for (idx, uid) in spec.assignees.iter().enumerate() {
        let task_am = sys_flow_task::ActiveModel {
            tenant_id: Set(spec.tenant_id),
            biz_type: Set(spec.biz_type.to_string()),
            biz_id: Set(spec.biz_id),
            round_no: Set(spec.round_no),
            node_seq: Set(spec.node_seq),
            node_name: Set(Some(spec.node_name.to_string())),
            assignee_id: Set(*uid),
            task_type: Set(spec.task_type.to_string()),
            status: Set("pending".to_string()),
            // G-02 M2：weighted 行快照权重与门槛（缺位/非法回退 1；非 weighted threshold=NULL）
            weight: Set(spec
                .weights
                .get(idx)
                .copied()
                .filter(|w| *w > 0)
                .unwrap_or(1)),
            threshold: Set(spec.node_threshold),
            actions_json: Set(Some(
                serde_json::to_string(spec.actions).unwrap_or_else(|_| "[]".to_string()),
            )),
            title: Set(Some(spec.title.to_string())),
            applicant_id: Set(spec.applicant_id),
            applicant_name: Set(spec.applicant_name.map(|s| s.to_string())),
            due_at: Set(spec.due_at),
            ..Default::default()
        };
        sys_flow_task::Entity::insert(task_am)
            .exec(txn)
            .await
            .map_err(db_to_svc)?;
    }

    let log_am = sys_flow_log::ActiveModel {
        tenant_id: Set(spec.tenant_id),
        biz_type: Set(spec.biz_type.to_string()),
        biz_id: Set(spec.biz_id),
        round_no: Set(spec.round_no),
        node_seq: Set(None),
        action: Set("submit".to_string()),
        from_status: Set(spec.from_status.map(|s| s.to_string())),
        to_status: Set(Some("pending".to_string())),
        operator_id: Set(Some(spec.applicant_id)),
        comment: Set(spec.comment.map(|s| s.to_string())),
        acted_at: Set(Some(spec.now)),
        ..Default::default()
    };
    sys_flow_log::Entity::insert(log_am)
        .exec(txn)
        .await
        .map_err(db_to_svc)?;
    Ok(())
}

/// actions 白名单收窄（批次十七，M2 遗留 TODO 闭环）：task 行
/// 快照该节点开放的高级动作——**NULL = 存量行向后兼容全开放**；非 NULL = 白名单
/// 严格匹配（不在清单 → 403）。demo/gen 链显式填全量（行为与收窄前一致）。
fn ensure_action_allowed(actions_json: Option<&str>, action: &str) -> Result<(), ServiceError> {
    match actions_json {
        None => Ok(()),
        Some(raw) => {
            let list: Vec<String> = serde_json::from_str(raw).unwrap_or_default();
            if list.iter().any(|a| a == action) {
                Ok(())
            } else {
                Err(ServiceError::forbidden(&crate::tr!(
                    "error.flow.action_not_allowed",
                    action = action
                )))
            }
        }
    }
}

/// DbErr → ServiceError（事务闭包内统一映射）
/// 构造流水 ActiveModel（自由函数：事务闭包是 `'static`，不能借用 `&self`）
#[allow(clippy::too_many_arguments)]
pub(super) fn flow_log_model(
    tenant_tid: i64,
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
) -> sys_flow_log::ActiveModel {
    sys_flow_log::ActiveModel {
        // 运行期产物：流水归属上游单据/任务的租户
        tenant_id: Set(tenant_tid),
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
    }
}

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

#[cfg(test)]
mod tests {
    use super::*;

    /// W-7：升级提醒判定纯函数的全部分支（时间快进不可行，故抽纯函数单测）
    #[test]
    fn should_escalate_covers_all_branches() {
        let now = crate::common::datetime::now_naive();
        // days=0 = 关闭升级（即便首提已过很久）
        assert!(!should_escalate(
            Some(now - chrono::Duration::days(30)),
            now,
            0
        ));
        // 尚未首次提醒（last_reminded_at 为空）⇒ 永不升级
        assert!(!should_escalate(None, now, 3));
        // 首提后不足 N 天 ⇒ 不升级（边界：N-1 天）
        assert!(!should_escalate(
            Some(now - chrono::Duration::days(2)),
            now,
            3
        ));
        // 恰好 N 天 ⇒ 升级（>= 边界含等号）
        assert!(should_escalate(
            Some(now - chrono::Duration::days(3)),
            now,
            3
        ));
        // 超 N 天 ⇒ 升级
        assert!(should_escalate(
            Some(now - chrono::Duration::days(4)),
            now,
            3
        ));
        // 升级后周期重置语义：last_reminded_at 被重写为当前时刻 ⇒ 回到"不升级"
        assert!(!should_escalate(Some(now), now, 3));
    }

    /// W-5：管理视图 data_scope → 单据可见范围的全部分支（纯函数，无 DB）
    #[test]
    fn decide_doc_scope_covers_all_data_scope_branches() {
        // 1 全部
        assert_eq!(
            decide_doc_scope(Some(1), 7, Some(100), vec![9], Some(vec![100, 101])),
            FlowDocScope::All
        );
        // 2 自定义 → 角色绑定部门（不使用 dept 子树/本人）
        assert_eq!(
            decide_doc_scope(Some(2), 7, Some(100), vec![9, 11], Some(vec![100, 101])),
            FlowDocScope::Depts(vec![9, 11])
        );
        // 2 自定义但未绑定部门 → 空集合（不可见任何单据，而非降级为全量）
        assert_eq!(
            decide_doc_scope(Some(2), 7, Some(100), vec![], None),
            FlowDocScope::Depts(vec![])
        );
        // 3 本部门
        assert_eq!(
            decide_doc_scope(Some(3), 7, Some(100), vec![], None),
            FlowDocScope::Depts(vec![100])
        );
        // 3 本部门但操作者无部门 → 空集合
        assert_eq!(
            decide_doc_scope(Some(3), 7, None, vec![], None),
            FlowDocScope::Depts(vec![])
        );
        // 4 本部门及以下 → 子树
        assert_eq!(
            decide_doc_scope(Some(4), 7, Some(100), vec![], Some(vec![100, 101, 102])),
            FlowDocScope::Depts(vec![100, 101, 102])
        );
        // 5 仅本人
        assert_eq!(
            decide_doc_scope(Some(5), 7, Some(100), vec![], None),
            FlowDocScope::Applicant(7)
        );
        // 无角色（None）/ 未知值：一律安全降级为仅本人
        assert_eq!(
            decide_doc_scope(None, 7, Some(100), vec![], None),
            FlowDocScope::Applicant(7)
        );
        assert_eq!(
            decide_doc_scope(Some(99), 7, Some(100), vec![], None),
            FlowDocScope::Applicant(7)
        );
    }

    /// V7-E3 / 3-9：site 渠道 to_addr 必须是字符串化 user_id。
    /// dispatch 对非数字 to_addr 会**静默记成功**（status='0'），喂错类型的回归只能靠该约定单测拦截。
    #[test]
    fn site_to_addr_is_numeric_string_of_user_id() {
        assert_eq!(SysFlowService::site_to_addr(1), "1");
        assert_eq!(SysFlowService::site_to_addr(42), "42");
        // 产物必须可被 dispatch 解析回同一 user_id（sys_msg_service.rs:689 parse::<i64>）
        let addr = SysFlowService::site_to_addr(987654321);
        assert_eq!(addr.trim().parse::<i64>().ok(), Some(987654321));
        assert!(
            addr.chars().all(|c| c.is_ascii_digit()),
            "to_addr 不得包含非数字字符（否则 dispatch 静默丢件）: {addr}"
        );
    }

    /// demo_nodes：single 两级 / countersign 单级会签（Quorum::All）
    #[test]
    fn demo_nodes_shape_matches_flow_mode() {
        let single = demo_nodes("single");
        assert_eq!(single.len(), 2);
        assert_eq!(single[0].quorum, Quorum::Any);
        assert_eq!(single[1].quorum, Quorum::Any);

        let countersign = demo_nodes("countersign");
        assert_eq!(countersign.len(), 1);
        assert_eq!(countersign[0].quorum, Quorum::All);
        assert_eq!(countersign[0].policies.len(), 2);
    }

    /// 未知模式回退到 single（两级单审），不 panic
    #[test]
    fn demo_nodes_unknown_mode_falls_back_to_single() {
        assert_eq!(demo_nodes("whatever").len(), 2);
    }

    /// actions 白名单收窄矩阵（批次十七）：NULL=存量行全开放；命中放行；未命中 403
    #[test]
    fn test_ensure_action_allowed_matrix() {
        // 存量行（NULL）向后兼容全开放
        assert!(ensure_action_allowed(None, "delegate").is_ok());
        assert!(ensure_action_allowed(None, "countersign_add").is_ok());
        // 白名单命中
        let full = Some(r#"["delegate","countersign_add"]"#);
        assert!(ensure_action_allowed(full, "delegate").is_ok());
        assert!(ensure_action_allowed(full, "countersign_add").is_ok());
        // 未命中 → 403
        assert!(ensure_action_allowed(full, "countersign_del").is_err());
        // 空 JSON 数组 = 全禁
        assert!(ensure_action_allowed(Some("[]"), "delegate").is_err());
        // 损坏 JSON fail-closed（解析失败 → 空清单 → 全禁）
        assert!(ensure_action_allowed(Some("not-json"), "delegate").is_err());
    }

    /// W-19：业务类型注册表——内置类型可识别，未登记类型不得冒充内置
    ///
    /// 注册表是"新增单据类型"的单一入口：若漏登记，`is_registered` 会给出 false，
    /// 使依赖它的治理/校验逻辑 fail-closed 而不是把未知类型当内置放行。
    #[test]
    fn biz_type_registry_lists_only_registered_types() {
        assert_eq!(BIZ_TYPE_DEMO, "demo_doc");
        assert_eq!(biz_type::DEMO_DOC, BIZ_TYPE_DEMO);
        // 批次十六：图驱动单据类型入注册表
        assert_eq!(biz_type::ALL, &["demo_doc", "flow_graph_doc"]);
        assert!(biz_type::is_registered(BIZ_TYPE_DEMO));
        assert!(biz_type::is_registered(biz_type::GRAPH_DOC));
        assert!(!biz_type::is_registered("purchase_order"));
        assert!(!biz_type::is_registered(""));
        assert!(
            !biz_type::is_registered("demo_doc "),
            "不得宽松匹配（防脏值）"
        );
    }

    /// W-19：推进注册表与类型登记表**必须严格一致**
    ///
    /// 二者不一致会直接破坏链路：只登记 `ALL` 而未注册 `REGISTRY`，推进路径
    /// （`/system/flow/act`）取不到链提供者/投影回写 → 报 `biz_type_unregistered`；
    /// 只在 `REGISTRY` 而未登记 `ALL`，则治理/校验逻辑视其为未登记类型。
    #[test]
    fn registry_matches_registered_types() {
        let reg_keys: Vec<&str> = biz_type::REGISTRY.iter().map(|r| r.biz_type).collect();
        assert_eq!(
            reg_keys,
            biz_type::ALL.to_vec(),
            "REGISTRY 与 ALL 的业务类型集合与顺序必须一致"
        );
        for r in biz_type::REGISTRY {
            assert!(
                biz_type::is_registered(r.biz_type),
                "注册项 {} 未在 ALL 登记",
                r.biz_type
            );
            assert!(
                biz_type::find(r.biz_type).is_some(),
                "注册项 {} 必须可被 find 检索到",
                r.biz_type
            );
        }
        assert!(biz_type::find("purchase_order").is_none());
        assert!(biz_type::find("").is_none());
    }

    // ============ b142 项 3：任务详情的单据读取不得吞掉非 404 失败 ============

    const SOURCE: &str = include_str!("sys_flow_service.rs");

    fn function_body(name: &str) -> String {
        let marker = format!("fn {name}");
        let start = SOURCE
            .find(&marker)
            .unwrap_or_else(|| panic!("找不到函数 {name}（改名后本锁必须同步）"));
        let open = SOURCE[start..]
            .find('{')
            .map(|i| start + i)
            .expect("函数签名后必须有花括号");
        let mut depth = 0usize;
        for (i, ch) in SOURCE[open..].char_indices() {
            match ch {
                '{' => depth += 1,
                '}' => {
                    depth -= 1;
                    if depth == 0 {
                        return SOURCE[open..=open + i].to_string();
                    }
                }
                _ => {}
            }
        }
        panic!("函数 {name} 花括号不配平");
    }

    /// 判据：只有 404 允许降级为「无单据」，其余错误必须上抛；且**代码行**里不得出现 `.ok()`
    /// 折叠。注释不参与判定——本函数的说明文字里就写着被禁止的形状（`原实现 .await.ok()`），
    /// 按原文匹配会让锁红在自己的注释上（AGENTS ⑬：刀口只能落在代码上）。
    fn downgrades_only_missing_doc(body: &str) -> bool {
        let code: String = body
            .lines()
            .filter(|line| !line.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n");
        code.contains("Err(e) if e.code == 404 => None")
            && code.contains("Err(e) => return Err(e)")
            && !code.contains(".await.ok()")
    }

    #[test]
    fn task_detail_only_downgrades_missing_doc_not_db_errors() {
        let body = function_body("task_detail");
        assert!(
            body.contains("match self.doc_by_id(task.biz_id).await"),
            "单据读取必须用 match 区分 404 与其它错误（`.ok()` 会把 DB 故障折成「没有单据」）"
        );
        assert!(
            downgrades_only_missing_doc(&body),
            "task_detail 必须只在 404 时降级、其余错误 `return Err(e)`；\
             否则一次 DB 抖动会让界面显示「这条任务没有关联单据」"
        );
    }

    /// 判据活性：HEAD 的缺陷形状（`.await.ok()`）必须被同一谓词判否
    #[test]
    fn missing_doc_downgrade_detector_is_falsifiable() {
        let original_shape = r#"
            let doc = if task.biz_type == biz_type::DEMO_DOC {
                self.doc_by_id(task.biz_id).await.ok()
            } else {
                None
            };
        "#;
        assert!(
            !downgrades_only_missing_doc(original_shape),
            "缺陷形状必须被判否：{original_shape}"
        );
        let compliant = r#"
            match self.doc_by_id(task.biz_id).await {
                Ok(doc) => Some(doc),
                Err(e) if e.code == 404 => None,
                Err(e) => return Err(e),
            }
        "#;
        assert!(downgrades_only_missing_doc(compliant), "合规形状必须放行");
        // 注释里提到被禁的形状不得影响判定（本函数的说明文字正是这样写的）
        let commented = format!("// 禁止 .await.ok() 折叠\n{compliant}");
        assert!(
            downgrades_only_missing_doc(&commented),
            "注释不得决定刀口：只有代码行才参与判定"
        );
    }
}
