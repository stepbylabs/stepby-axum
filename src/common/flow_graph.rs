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
    /// 按单据字段快照求值条件（批次十六：图驱动单据推进的核心求值器）。
    ///
    /// - `snapshot`：单据字段快照 JSON（对象，如 `{"days": 5, "leave_type": "sick"}`）；
    /// - 数字比较：两边均可数值化（i64/u64/f64 宽松化到 f64）；
    /// - 字符串比较：仅 `=` / `!=`（6 比较符白名单对字符串只保留等值语义，有序比较
    ///   对字符串业务含义不明——fail-closed 拒绝而非猜测）；
    /// - 字段缺失 / 类型不符 / 非法比较符 → **Err（fail-closed）**：图引用了单据
    ///   没有的字段 = 图与业务不匹配，提交时必须显式 400 而非静默走某条边。
    pub fn evaluate(&self, snapshot: &serde_json::Value) -> Result<bool, String> {
        let field_val = snapshot.get(&self.field).ok_or_else(|| {
            format!(
                "条件字段 {} 不在单据字段快照中（图与业务不匹配）",
                self.field
            )
        })?;
        match (&self.value, field_val) {
            (serde_json::Value::Number(want), got) => {
                let got = got
                    .as_f64()
                    .ok_or_else(|| format!("字段 {} 的值不是数字: {got}", self.field))?;
                let want = want.as_f64().unwrap_or(f64::NAN);
                Ok(match self.op.as_str() {
                    "=" => got == want,
                    "!=" => got != want,
                    ">" => got > want,
                    ">=" => got >= want,
                    "<" => got < want,
                    "<=" => got <= want,
                    other => return Err(format!("比较符不在白名单: {other}")),
                })
            }
            (serde_json::Value::String(want), got) => {
                let got = got
                    .as_str()
                    .ok_or_else(|| format!("字段 {} 的值不是字符串: {got}", self.field))?;
                Ok(match self.op.as_str() {
                    "=" => got == want,
                    "!=" => got != want,
                    other => return Err(format!("字符串字段不支持比较符 {other}（仅 = / !=）")),
                })
            }
            _ => Err(format!("条件值类型不支持: {}", self.value)),
        }
    }

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

    /// 提交时**静态路由**（批次十六：图驱动单据推进的核心）。
    ///
    /// 从 start 出发，每个节点按出边条件对 `snapshot` 求值选边：
    /// 真值条件边优先（声明序），全假时走第一条**无条件默认边**，
    /// 无真值且无默认 → Err（fail-closed，提交时 400）；
    /// 直到 end，返回途经节点 id 序列（含 start/end——approve 节点在序列中的
    /// 顺序即之后 `node_seq` 重编号依据）。
    ///
    /// 为何是**提交时静态**而非运行期动态选边：字段快照冻结在单据（提交时写入）
    /// ⇒ 同单据重放同路径（确定性）；引擎推进内核（线性链 + 节点内四模式）零改动，
    /// 或签/加权/会签与加减签全部复用。并行分支等超集能力超出 BPMN-lite 白名单
    /// 设计立场（validate 已保证无环）。
    pub fn route_graph(&self, snapshot: &serde_json::Value) -> Result<Vec<String>, String> {
        let start = self
            .nodes
            .iter()
            .find(|n| n.node_type == "start")
            .ok_or_else(|| "缺少 start 节点".to_string())?;
        let end = self
            .nodes
            .iter()
            .find(|n| n.node_type == "end")
            .ok_or_else(|| "缺少 end 节点".to_string())?;
        // 邻接表（保持边声明序——真值边"声明序优先"语义依赖此顺序）
        let mut adj: std::collections::HashMap<&str, Vec<&GraphEdge>> = Default::default();
        for e in &self.edges {
            adj.entry(e.from.as_str()).or_default().push(e);
        }
        let mut route = vec![start.id.clone()];
        let mut cur = start;
        // 步数上界双保险（validate 已保证无环；防御 route 逻辑自身回归）
        let max_steps = self.nodes.len() + 1;
        for _ in 0..max_steps {
            if cur.id == end.id {
                return Ok(route);
            }
            let out = adj
                .get(cur.id.as_str())
                .ok_or_else(|| format!("节点 {} 无出边（流程中断）", cur.id))?;
            let mut default_edge: Option<&GraphEdge> = None;
            let mut chosen: Option<&GraphEdge> = None;
            for e in out {
                match &e.condition {
                    Some(c) => {
                        if c.evaluate(snapshot)? {
                            chosen = Some(e);
                            break;
                        }
                    }
                    None => {
                        if default_edge.is_none() {
                            default_edge = Some(e);
                        }
                    }
                }
            }
            let next_edge = chosen.or(default_edge).ok_or_else(|| {
                format!("节点 {} 的全部条件边均为假且无默认边（无可达路径）", cur.id)
            })?;
            let next = self
                .nodes
                .iter()
                .find(|n| n.id == next_edge.to)
                .ok_or_else(|| format!("边指向不存在的节点: {}", next_edge.to))?;
            route.push(next.id.clone());
            cur = next;
        }
        Err("路由步数超上界（疑似环，validate 回归）".to_string())
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

    // ==================== 批次十六：条件求值 + 静态路由（图驱动推进） ====================

    /// 求值器：数字 6 比较符矩阵
    #[test]
    fn test_evaluate_condition_numeric_ops() {
        let snap = serde_json::json!({ "days": 5 });
        let cond = |op: &str, v: i64| EdgeCondition {
            field: "days".into(),
            op: op.into(),
            value: serde_json::json!(v),
        };
        assert!(cond("=", 5).evaluate(&snap).unwrap());
        assert!(!cond("=", 4).evaluate(&snap).unwrap());
        assert!(cond("!=", 4).evaluate(&snap).unwrap());
        assert!(cond(">", 4).evaluate(&snap).unwrap());
        assert!(!cond(">", 5).evaluate(&snap).unwrap());
        assert!(cond(">=", 5).evaluate(&snap).unwrap());
        assert!(!cond("<", 5).evaluate(&snap).unwrap());
        assert!(cond("<=", 5).evaluate(&snap).unwrap());
    }

    /// 求值器：字符串仅等值；有序比较符 fail-closed；字段缺失 fail-closed
    #[test]
    fn test_evaluate_condition_string_and_fail_closed() {
        let snap = serde_json::json!({ "leave_type": "sick" });
        let cond = |op: &str, v: &str| EdgeCondition {
            field: "leave_type".into(),
            op: op.into(),
            value: serde_json::json!(v),
        };
        assert!(cond("=", "sick").evaluate(&snap).unwrap());
        assert!(cond("!=", "annual").evaluate(&snap).unwrap());
        // 字符串有序比较符 → Err（语义不明，fail-closed）
        assert!(cond(">", "a").evaluate(&snap).is_err());
        // 字段缺失 → Err
        let missing = EdgeCondition {
            field: "nonexistent".into(),
            op: "=".into(),
            value: serde_json::json!(1),
        };
        assert!(missing.evaluate(&snap).is_err(), "缺失字段必须 fail-closed");
    }

    /// 路由：菱形多分支——真值条件边优先（请假 >3 天走长链，否则走默认短链）
    #[test]
    fn test_route_graph_conditional_branch() {
        let g = FlowGraph::parse_and_validate(&graph(
            serde_json::json!([
                {"id":"s","type":"start"},
                {"id":"leader","type":"approve","name":"主管","assignees":["dept_leader"]},
                {"id":"director","type":"approve","name":"总监","assignees":["role:director"],"multi":"weighted","threshold":2},
                {"id":"end","type":"end"}
            ]),
            serde_json::json!([
                {"from":"s","to":"leader"},
                {"from":"leader","to":"director","condition":{"field":"days","op":">","value":3}},
                {"from":"leader","to":"end"},
                {"from":"director","to":"end"}
            ]),
        ))
        .expect("图应合法");
        // days=5：条件真 → 经总监
        let long = g
            .route_graph(&serde_json::json!({ "days": 5 }))
            .expect("应可路由");
        assert_eq!(long, vec!["s", "leader", "director", "end"]);
        // days=1：条件假 → 默认边直达 end
        let short = g
            .route_graph(&serde_json::json!({ "days": 1 }))
            .expect("应可路由");
        assert_eq!(short, vec!["s", "leader", "end"]);
    }

    /// 路由：全部条件边为假且无默认边 → Err（fail-closed）
    #[test]
    fn test_route_graph_no_reachable_path_rejected() {
        let g = FlowGraph::parse_and_validate(&graph(
            serde_json::json!([
                {"id":"s","type":"start"},
                {"id":"a","type":"approve","name":"审批","assignees":["dept_leader"]},
                {"id":"e","type":"end"}
            ]),
            serde_json::json!([
                {"from":"s","to":"a","condition":{"field":"days","op":">","value":100}},
                {"from":"a","to":"e"}
            ]),
        ))
        .expect("图应合法");
        let err = g
            .route_graph(&serde_json::json!({ "days": 1 }))
            .unwrap_err();
        assert!(err.contains("无可达路径"), "err={err}");
    }
}
