//! 数据权限（data_scope）共享计算工具。
//!
//! 各业务 Service（sys_user / sys_role / sys_dept）在解析 operator 的数据权限时，
//! 都需要从 operator 的全部角色中取 `data_scope` 值**最小者**（最宽松者）生效。
//! 该取值逻辑完全相同，在此抽取为纯函数，消除三处重复（P2 去重，零行为变更）。
//!
//! data_scope 取值语义（与 sea-orm entity `sys_role.data_scope` 一致）：
//! - 1 = 全部数据
//! - 2 = 自定义（角色绑定部门）
//! - 3 = 本部门
//! - 4 = 本部门及以下
//! - 5 = 仅本人
//!
//! 取最小值即"最宽松权限优先"。无角色 / 无 data_scope / 解析失败 → 返回 `None`，
//! 由各调用方按自身资源语义安全降级（见各 Service 的 match 分支）。

use crate::entity::sys_role;

/// 从 operator 的角色列表中取 `data_scope` 的最小值（最宽松者）。
///
/// - 忽略 `data_scope` 为 `None` 的角色；
/// - 忽略无法解析为 `i32` 的非法值；
/// - 所有角色均无有效 `data_scope` 时返回 `None`。
///
/// 纯函数，不触碰数据库，可独立单测。
pub fn min_data_scope(roles: &[sys_role::Model]) -> Option<i32> {
    roles
        .iter()
        .filter_map(|r| r.data_scope.as_deref())
        .filter_map(|s| s.parse::<i32>().ok())
        .min()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn role(id: i64, scope: Option<&str>) -> sys_role::Model {
        sys_role::Model {
            role_id: id,
            role_name: format!("role-{id}"),
            role_key: format!("key-{id}"),
            role_sort: 0,
            data_scope: scope.map(|s| s.to_owned()),
            menu_check_strictly: None,
            dept_check_strictly: None,
            status: "0".to_owned(),
            del_flag: None,
            create_by: None,
            create_time: None,
            update_by: None,
            update_time: None,
            remark: None,
        }
    }

    #[test]
    fn test_min_data_scope_picks_smallest() {
        let roles = vec![role(1, Some("3")), role(2, Some("1")), role(3, Some("5"))];
        assert_eq!(min_data_scope(&roles), Some(1));
    }

    #[test]
    fn test_min_data_scope_ignores_none_and_invalid() {
        let roles = vec![role(1, None), role(2, Some("x")), role(3, Some("4"))];
        assert_eq!(min_data_scope(&roles), Some(4));
    }

    #[test]
    fn test_min_data_scope_empty() {
        assert_eq!(min_data_scope(&[]), None);
        let roles = vec![role(1, None), role(2, Some("bad"))];
        assert_eq!(min_data_scope(&roles), None);
    }
}
