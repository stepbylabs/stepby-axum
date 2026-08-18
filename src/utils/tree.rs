// axum-backend/src/utils/tree.rs

/// 通用树节点 trait（通用树工具）
///
/// R5-TYPE-15：新增关联类型 `Id`，避免将节点 ID 硬编码为 `i64`，
/// 允许实现者按需选择 `i64`/`u64`/`String` 等 ID 类型。
pub trait TreeNode {
    /// 节点 ID 类型（需支持相等比较）
    type Id: Eq;
    /// 节点 ID
    fn id(&self) -> Self::Id;
    /// 父节点 ID
    fn parent_id(&self) -> Self::Id;
    /// 可变子节点列表
    fn children_mut(&mut self) -> &mut Option<Vec<Self>> where Self: Sized;
}

/// 将扁平列表构建为树结构
/// root_parent_id 为根节点的 parent_id（通常为 0）
///
/// P1：递归加深度上限（MAX_TREE_DEPTH），防止脏数据成环（parent_id 循环）
/// 导致无限递归栈溢出（8MB 栈也扛不住深层递归）。
pub fn build_tree<T: TreeNode + Clone>(list: &[T], root_parent_id: T::Id) -> Vec<T> {
    let mut roots: Vec<T> = list.iter()
        .filter(|n| n.parent_id() == root_parent_id)
        .cloned()
        .collect();
    for root in &mut roots {
        build_children(root, list, 0);
    }
    roots
}

/// 树最大深度（超过即判定存在循环引用/异常数据，停止递归）
pub const MAX_TREE_DEPTH: usize = 30;

fn build_children<T: TreeNode + Clone>(node: &mut T, list: &[T], depth: usize) {
    if depth >= MAX_TREE_DEPTH {
        tracing::warn!(
            "树构建达到最大深度 {}（可能存在 parent_id 循环引用），停止递归",
            MAX_TREE_DEPTH
        );
        return;
    }
    let node_id = node.id();
    let children: Vec<T> = list.iter()
        .filter(|n| n.parent_id() == node_id)
        .cloned()
        .collect();
    if children.is_empty() {
        return;
    }
    // 直接将 Option 设为 Some(children)。
    // 注意：之前用 `if let Some(kids) = node.children_mut()` 是错误的，
    // 因为 freshly loaded 模型的 children 字段为 None，Some 模式不匹配，
    // 导致 children 永远不会被赋值（getRouters 返回 children:null 的根因）。
    *node.children_mut() = Some(children);
    // 递归处理每个 child
    if let Some(kids) = node.children_mut() {
        for kid in kids.iter_mut() {
            build_children(kid, list, depth + 1);
        }
    }
}
