// stepby-axum/src/common/flow_graph.rs
//! 流程图定义（graph_json）白名单校验器（G-02 M1，批次七）
//!
//! **设计立场**：graph_json 是**受限 BPMN-lite**——不是通用表达式/脚本引擎：
//! - 节点仅 `start | approve | end` 三类；审批人仅 `dept_leader | role:<key>` 白名单形态；
//! - 多签模式仅 `single | countersign | or_sign | weighted`；条件边仅
//!   `字段 比较符 值` 白名单原子条件（拒绝 eval 类方案——注入面）；
//! - 校验**纯函数 + 全量单测**：前后端双份校验中，后端保存时复验（防绕过前端直投 API）；
//! - M2 推进函数将把 `approve` 节点映射为 `NodeSpec`（node_seq/policies/quorum 一一对齐），
//!   本模块的解析结构即转换的中间形态。

use serde::{Deserialize, Serialize};

/// 审批人形态白名单：`dept_leader`（部门主管）或 `role:<role_key>`
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Assignee(pub String);

impl Assignee {
    pub fn validate(&self) -> Result<(), String> {
        let s = &self.0;
        if s == "dept_leader" {
            return Ok(());
        }
        if let Some(key) = s.strip_prefix("role:") {
            if !key.is_empty()
                && key.len() <= 64
                && key
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
            {
                return Ok(());
            }
            return Err(format!(
                "role 形态非法: {s}（应为 role:<role_key>，key 限字母数字_-）"
            ));
        }
        Err(format!(
            "审批人形态不在白名单: {s}（仅支持 dept_leader / role:<role_key>）"
        ))
    }
}

/// 多签模式（M2 落地 or_sign/weighted 推进语义）
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MultiMode {
    Single,
    Countersign,
    OrSign,
    Weighted,
}

/// 条件边原子条件：`field op value`（字段白名单由**实例提交时的单据快照**键决定，
/// 这里校验形态：字段名标识符、op ∈ 6 种比较符、值 = 字符串或数字）
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EdgeCondition {
    pub field: String,
    pub op: String,
    #[serde(deserialize_with = "deserialize_cond_value")]
    pub value: serde_json::Value,
}

fn deserialize_cond_value<'de, D>(deserializer: D) -> Result<serde_json::Value, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let v = serde_json::Value::deserialize(deserializer)?;
    match &v {
        serde_json::Value::String(_) | serde_json::Value::Number(_) => Ok(v),
        other => Err(serde::de::Error::custom(format!(
            "条件值仅允许字符串或数字，实际: {other}"
        ))),
    }
}

impl EdgeCondition {
    pub fn validate(&self) -> Result<(), String> {
        if self.field.is_empty()
            || self.field.len() > 64
            || !self
                .field
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_')
        {
            return Err(format!("条件字段名非法: {}", self.field));
        }
        if !["=", "!=", ">", ">=", "<", "<="].contains(&self.op.as_str()) {
            return Err(format!("条件比较符不在白名单: {}", self.op));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphNode {
    pub id: String,
    #[serde(rename = "type")]
    pub node_type: String, // start | approve | end
    #[serde(default)]
    pub name: String,
    /// 审批人形态列表（approve 节点必填 ≥1）
    #[serde(default)]
    pub assignees: Vec<Assignee>,
    /// 多签模式（缺省 single）
    #[serde(default)]
    pub multi: Option<MultiMode>,
    /// 门槛（countersign = 全部；weighted = 权重和 ≥ threshold；缺省 1）
    #[serde(default)]
    pub threshold: Option<i64>,
    /// 该节点开放的高级动作（M2：delegate / countersign_add / countersign_del）
    #[serde(default)]
    pub actions: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphEdge {
    pub from: String,
    pub to: String,
    #[serde(default)]
    pub condition: Option<EdgeCondition>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlowGraph {
    pub nodes: Vec<GraphNode>,
    pub edges: Vec<GraphEdge>,
}

const NODE_ID_MAX: usize = 64;
const ACTIONS_WHITELIST: &[&str] = &["delegate", "countersign_add", "countersign_del"];
const MAX_NODES: usize = 64;
const MAX_EDGES: usize = 128;

impl FlowGraph {
    /// 解析并全量校验。任何一项不合法即 Err（fail-closed，绝不带着未校验图入库）。
    pub fn parse_and_validate(raw: &str) -> Result<FlowGraph, String> {
        let graph: FlowGraph = serde_json::from_str(raw)
            .map_err(|e| format!("graph_json 不是合法 JSON 或结构不符: {e}"))?;
        graph.validate()?;
        Ok(graph)
    }

    pub fn validate(&self) -> Result<(), String> {
        // 1. 规模上界（防构造超大 JSON 拖垮解析）
        if self.nodes.is_empty() {
            return Err("nodes 不能为空".to_string());
        }
        if self.nodes.len() > MAX_NODES || self.edges.len() > MAX_EDGES {
            return Err(format!(
                "节点/边数量超上界（nodes≤{MAX_NODES}, edges≤{MAX_EDGES}）"
            ));
        }
        // 2. 节点逐一校验：id 唯一性 + 类型白名单 + approve 必填 assignees + 动作白名单
        let mut ids = std::collections::HashSet::new();
        let mut starts: Vec<&GraphNode> = Vec::new();
        let mut ends: Vec<&GraphNode> = Vec::new();
        for n in &self.nodes {
            if n.id.is_empty() || n.id.len() > NODE_ID_MAX {
                return Err(format!("节点 id 非法（1-{NODE_ID_MAX} 字符）: {}", n.id));
            }
            if !ids.insert(n.id.as_str()) {
                return Err(format!("节点 id 重复: {}", n.id));
            }
            match n.node_type.as_str() {
                "start" => starts.push(n),
                "end" => ends.push(n),
                "approve" => {
                    if n.assignees.is_empty() {
                        return Err(format!("审批节点 {} 缺少 assignees", n.id));
                    }
                    for a in &n.assignees {
                        a.validate().map_err(|e| format!("节点 {}: {e}", n.id))?;
                    }
                    let mode = n.multi.unwrap_or(MultiMode::Single);
                    if let Some(t) = n.threshold {
                        if t <= 0 {
                            return Err(format!(
                                "节点 {} 的 threshold 必须为正整数（加权/会签门槛）",
                                n.id
                            ));
                        }
                        if !(0..=1000).contains(&t) {
                            return Err(format!("节点 {} threshold 越界: {t}", n.id));
                        }
                    }
                    if let (MultiMode::Weighted, None) = (mode, n.threshold) {
                        return Err(format!("加权节点 {} 缺少 threshold", n.id));
                    }
                }
                other => return Err(format!("节点类型不在白名单: {other}")),
            }
            for act in &n.actions {
                if !ACTIONS_WHITELIST.contains(&act.as_str()) {
                    return Err(format!(
                        "节点 {} 动作不在白名单: {act}（仅 {ACTIONS_WHITELIST:?}）",
                        n.id
                    ));
                }
            }
        }
        if starts.len() != 1 {
            return Err(format!("start 节点必须恰好 1 个，实际 {}", starts.len()));
        }
        if ends.len() != 1 {
            return Err(format!("end 节点必须恰好 1 个，实际 {}", ends.len()));
        }
        // 3. 边校验：端点存在 + 无自环 + 重复边 + 条件白名单
        let mut seen_edges = std::collections::HashSet::new();
        for e in &self.edges {
            if !ids.contains(e.from.as_str()) {
                return Err(format!("边起点不存在: {}", e.from));
            }
            if !ids.contains(e.to.as_str()) {
                return Err(format!("边终点不存在: {}", e.to));
            }
            if e.from == e.to {
                return Err(format!("自环边: {}", e.from));
            }
            if !seen_edges.insert((e.from.as_str(), e.to.as_str())) {
                return Err(format!("重复边: {} → {}", e.from, e.to));
            }
            if let Some(c) = &e.condition {
                c.validate()
                    .map_err(|err| format!("边 {} → {}: {err}", e.from, e.to))?;
            }
        }
        // 4. 可达性：start 可达 end（BFS）；同时检测不可达 approve 节点（孤儿）
        let mut adj: std::collections::HashMap<&str, Vec<&str>> = Default::default();
        for e in &self.edges {
            adj.entry(e.from.as_str()).or_default().push(e.to.as_str());
        }
        let start_id = starts[0].id.as_str();
        let end_id = ends[0].id.as_str();
        let mut visited: std::collections::HashSet<&str> = std::collections::HashSet::new();
        let mut queue = std::collections::VecDeque::new();
        queue.push_back(start_id);
        visited.insert(start_id);
        while let Some(cur) = queue.pop_front() {
            if let Some(nexts) = adj.get(cur) {
                for nx in nexts {
                    if visited.insert(nx) {
                        queue.push_back(*nx);
                    }
                }
            }
        }
        if !visited.contains(end_id) {
            return Err("start 不可达 end（流程无出口）".to_string());
        }
        for n in &self.nodes {
            if n.node_type == "approve" && !visited.contains(n.id.as_str()) {
                return Err(format!("审批节点 {} 不可达（孤立节点）", n.id));
            }
        }
        // 5. 环检测：有向图 DFS 三色标记（允许汇聚，不允许环——审批回路经"退回重提"而非图环表达）
        let mut state: std::collections::HashMap<&str, u8> = Default::default(); // 0=未访问 1=栈中 2=完成
        fn dfs<'a>(
            id: &'a str,
            adj: &std::collections::HashMap<&'a str, Vec<&'a str>>,
            state: &mut std::collections::HashMap<&'a str, u8>,
        ) -> Result<(), String> {
            state.insert(id, 1);
            if let Some(nexts) = adj.get(id) {
                for nx in nexts {
                    match state.get(*nx).copied().unwrap_or(0) {
                        1 => return Err(format!("检测到环: {} → {}", id, nx)),
                        0 => dfs(nx, adj, state)?,
                        _ => {}
                    }
                }
            }
            state.insert(id, 2);
            Ok(())
        }
        dfs(start_id, &adj, &mut state)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn graph(nodes: serde_json::Value, edges: serde_json::Value) -> String {
        serde_json::json!({ "nodes": nodes, "edges": edges }).to_string()
    }

    const VALID_TWO_LEVEL: &str = r#"{
        "nodes": [
            {"id":"start","type":"start"},
            {"id":"a1","type":"approve","name":"主管审批","assignees":["dept_leader"],"quorum":"any"},
            {"id":"a2","type":"approve","name":"管理员审批","assignees":["role:admin"],"quorum":"any"},
            {"id":"end","type":"end"}
        ],
        "edges": [
            {"from":"start","to":"a1"},
            {"from":"a1","to":"a2"},
            {"from":"a2","to":"end"}
        ]
    }"#;

    #[test]
    fn test_valid_two_level_passes() {
        assert!(FlowGraph::parse_and_validate(VALID_TWO_LEVEL).is_ok());
    }

    #[test]
    fn test_invalid_json_rejected() {
        assert!(FlowGraph::parse_and_validate("{not json").is_err());
    }

    #[test]
    fn test_missing_start_rejected() {
        let g = graph(
            serde_json::json!([
                {"id":"a1","type":"approve","assignees":["dept_leader"]},
                {"id":"end","type":"end"}
            ]),
            serde_json::json!([{"from":"a1","to":"end"}]),
        );
        let err = FlowGraph::parse_and_validate(&g).unwrap_err();
        assert!(err.contains("start"), "err={err}");
    }

    #[test]
    fn test_two_starts_rejected() {
        let g = graph(
            serde_json::json!([
                {"id":"s1","type":"start"},
                {"id":"s2","type":"start"},
                {"id":"end","type":"end"}
            ]),
            serde_json::json!([{"from":"s1","to":"end"},{"from":"s2","to":"end"}]),
        );
        let err = FlowGraph::parse_and_validate(&g).unwrap_err();
        assert!(err.contains("恰好 1"), "err={err}");
    }

    #[test]
    fn test_unknown_node_type_rejected() {
        let g = graph(
            serde_json::json!([
                {"id":"s","type":"start"},
                {"id":"x","type":"gateway"},
                {"id":"e","type":"end"}
            ]),
            serde_json::json!([{"from":"s","to":"x"},{"from":"x","to":"e"}]),
        );
        let err = FlowGraph::parse_and_validate(&g).unwrap_err();
        assert!(err.contains("白名单"), "err={err}");
    }

    #[test]
    fn test_duplicate_node_id_rejected() {
        let g = graph(
            serde_json::json!([
                {"id":"s","type":"start"},
                {"id":"a","type":"approve","assignees":["dept_leader"]},
                {"id":"a","type":"approve","assignees":["dept_leader"]},
                {"id":"e","type":"end"}
            ]),
            serde_json::json!([{"from":"s","to":"a"},{"from":"a","to":"e"}]),
        );
        let err = FlowGraph::parse_and_validate(&g).unwrap_err();
        assert!(err.contains("重复"), "err={err}");
    }

    #[test]
    fn test_approve_without_assignees_rejected() {
        let g = graph(
            serde_json::json!([
                {"id":"s","type":"start"},
                {"id":"a","type":"approve"},
                {"id":"e","type":"end"}
            ]),
            serde_json::json!([{"from":"s","to":"a"},{"from":"a","to":"e"}]),
        );
        let err = FlowGraph::parse_and_validate(&g).unwrap_err();
        assert!(err.contains("assignees"), "err={err}");
    }

    #[test]
    fn test_bad_assignee_form_rejected() {
        let g = graph(
            serde_json::json!([
                {"id":"s","type":"start"},
                {"id":"a","type":"approve","assignees":["admin"]},
                {"id":"e","type":"end"}
            ]),
            serde_json::json!([{"from":"s","to":"a"},{"from":"a","to":"e"}]),
        );
        let err = FlowGraph::parse_and_validate(&g).unwrap_err();
        assert!(err.contains("白名单") || err.contains("role"), "err={err}");
    }

    #[test]
    fn test_role_form_valid() {
        let g = graph(
            serde_json::json!([
                {"id":"s","type":"start"},
                {"id":"a","type":"approve","assignees":["role:manager_1"]},
                {"id":"e","type":"end"}
            ]),
            serde_json::json!([{"from":"s","to":"a"},{"from":"a","to":"e"}]),
        );
        assert!(FlowGraph::parse_and_validate(&g).is_ok());
    }

    #[test]
    fn test_edge_to_missing_node_rejected() {
        let g = graph(
            serde_json::json!([
                {"id":"s","type":"start"},
                {"id":"e","type":"end"}
            ]),
            serde_json::json!([{"from":"s","to":"ghost"}]),
        );
        let err = FlowGraph::parse_and_validate(&g).unwrap_err();
        assert!(err.contains("不存在"), "err={err}");
    }

    #[test]
    fn test_self_loop_rejected() {
        let g = graph(
            serde_json::json!([
                {"id":"s","type":"start"},
                {"id":"a","type":"approve","assignees":["dept_leader"]},
                {"id":"e","type":"end"}
            ]),
            serde_json::json!([{"from":"s","to":"a"},{"from":"a","to":"a"},{"from":"a","to":"e"}]),
        );
        let err = FlowGraph::parse_and_validate(&g).unwrap_err();
        assert!(err.contains("自环"), "err={err}");
    }

    #[test]
    fn test_cycle_rejected() {
        let g = graph(
            serde_json::json!([
                {"id":"s","type":"start"},
                {"id":"a","type":"approve","assignees":["dept_leader"]},
                {"id":"b","type":"approve","assignees":["dept_leader"]},
                {"id":"e","type":"end"}
            ]),
            serde_json::json!([{"from":"s","to":"a"},{"from":"a","to":"b"},{"from":"b","to":"a"},{"from":"b","to":"e"}]),
        );
        let err = FlowGraph::parse_and_validate(&g).unwrap_err();
        assert!(err.contains("环"), "err={err}");
    }

    #[test]
    fn test_unreachable_approve_rejected() {
        let g = graph(
            serde_json::json!([
                {"id":"s","type":"start"},
                {"id":"a","type":"approve","assignees":["dept_leader"]},
                {"id":"orphan","type":"approve","assignees":["role:admin"]},
                {"id":"e","type":"end"}
            ]),
            serde_json::json!([{"from":"s","to":"a"},{"from":"a","to":"e"}]),
        );
        let err = FlowGraph::parse_and_validate(&g).unwrap_err();
        assert!(err.contains("不可达"), "err={err}");
    }

    #[test]
    fn test_no_path_to_end_rejected() {
        let g = graph(
            serde_json::json!([
                {"id":"s","type":"start"},
                {"id":"a","type":"approve","assignees":["dept_leader"]},
                {"id":"e","type":"end"}
            ]),
            serde_json::json!([{"from":"s","to":"a"}]),
        );
        let err = FlowGraph::parse_and_validate(&g).unwrap_err();
        assert!(err.contains("无出口"), "err={err}");
    }

    #[test]
    fn test_conditional_edge_valid() {
        let g = graph(
            serde_json::json!([
                {"id":"s","type":"start"},
                {"id":"a","type":"approve","assignees":["dept_leader"]},
                {"id":"e","type":"end"}
            ]),
            serde_json::json!([
                {"from":"s","to":"a","condition":{"field":"amount","op":"<","value":10000}},
                {"from":"a","to":"e"}
            ]),
        );
        assert!(FlowGraph::parse_and_validate(&g).is_ok());
    }

    #[test]
    fn test_conditional_edge_bad_op_rejected() {
        let g = graph(
            serde_json::json!([
                {"id":"s","type":"start"},
                {"id":"a","type":"approve","assignees":["dept_leader"]},
                {"id":"e","type":"end"}
            ]),
            serde_json::json!([
                {"from":"s","to":"a","condition":{"field":"amount","op":"LIKE","value":"x"}},
                {"from":"a","to":"e"}
            ]),
        );
        let err = FlowGraph::parse_and_validate(&g).unwrap_err();
        assert!(err.contains("比较符"), "err={err}");
    }

    #[test]
    fn test_conditional_value_object_rejected() {
        let g = graph(
            serde_json::json!([
                {"id":"s","type":"start"},
                {"id":"a","type":"approve","assignees":["dept_leader"]},
                {"id":"e","type":"end"}
            ]),
            serde_json::json!([
                {"from":"s","to":"a","condition":{"field":"amount","op":"=","value":{"nested":1}}},
                {"from":"a","to":"e"}
            ]),
        );
        let err = FlowGraph::parse_and_validate(&g).unwrap_err();
        assert!(err.contains("字符串或数字"), "err={err}");
    }

    #[test]
    fn test_weighted_without_threshold_rejected() {
        let g = graph(
            serde_json::json!([
                {"id":"s","type":"start"},
                {"id":"a","type":"approve","assignees":["dept_leader","role:admin"],"multi":"weighted"},
                {"id":"e","type":"end"}
            ]),
            serde_json::json!([{"from":"s","to":"a"},{"from":"a","to":"e"}]),
        );
        let err = FlowGraph::parse_and_validate(&g).unwrap_err();
        assert!(err.contains("threshold"), "err={err}");
    }

    #[test]
    fn test_unknown_action_rejected() {
        let g = graph(
            serde_json::json!([
                {"id":"s","type":"start"},
                {"id":"a","type":"approve","assignees":["dept_leader"],"actions":["grant_admin"]},
                {"id":"e","type":"end"}
            ]),
            serde_json::json!([{"from":"s","to":"a"},{"from":"a","to":"e"}]),
        );
        let err = FlowGraph::parse_and_validate(&g).unwrap_err();
        assert!(err.contains("动作"), "err={err}");
    }

    #[test]
    fn test_oversize_graph_rejected() {
        // 65 个 approve 节点 > MAX_NODES
        let mut nodes = vec![serde_json::json!({"id":"s","type":"start"})];
        for i in 0..65 {
            nodes.push(
                serde_json::json!({"id":format!("a{i}"),"type":"approve","assignees":["dept_leader"]}),
            );
        }
        nodes.push(serde_json::json!({"id":"e","type":"end"}));
        let g = graph(serde_json::Value::Array(nodes), serde_json::json!([]));
        let err = FlowGraph::parse_and_validate(&g).unwrap_err();
        assert!(err.contains("上界"), "err={err}");
    }

    #[test]
    fn test_duplicate_edge_rejected() {
        let g = graph(
            serde_json::json!([
                {"id":"s","type":"start"},
                {"id":"e","type":"end"}
            ]),
            serde_json::json!([{"from":"s","to":"e"},{"from":"s","to":"e"}]),
        );
        let err = FlowGraph::parse_and_validate(&g).unwrap_err();
        assert!(err.contains("重复边"), "err={err}");
    }

    #[test]
    fn test_or_sign_valid() {
        let g = graph(
            serde_json::json!([
                {"id":"s","type":"start"},
                {"id":"a","type":"approve","name":"或签","assignees":["role:admin","role:manager"],"multi":"or_sign"},
                {"id":"e","type":"end"}
            ]),
            serde_json::json!([{"from":"s","to":"a"},{"from":"a","to":"e"}]),
        );
        assert!(FlowGraph::parse_and_validate(&g).is_ok());
    }
}
