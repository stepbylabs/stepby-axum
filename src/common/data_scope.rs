//! 数据权限（data_scope）共享计算工具。
//!
//! 各业务 Service（sys_user / sys_role / sys_dept）在解析 operator 的数据权限时，
//! 都需要从 operator 的全部角色中取 `data_scope` 值**最小者**（最宽松者）生效。
//! 该取值逻辑完全相同，在此抽取为纯函数，消除三处重复（P2 去重，零行为变更）。
//!
//! data_scope 取值语义（与 sea-orm entity `sys_role.data_scope` 一致）：
//! - 1 = 全部数据
//! - 2 = 自定义（角色绑定部门，sys_role_dept 关联表）
//!
//! 权威口径与消费面矩阵见 docs/optimization/data-scope-matrix-2026-10-07.md。
//! - 3 = 本部门
//! - 4 = 本部门及以下
//! - 5 = 仅本人
//!
//! 取最小值即"最宽松权限优先"。无角色 / 无 data_scope / 解析失败 → 返回 `None`，
//! 由各调用方按自身资源语义安全降级（见各 Service 的 match 分支）。

use crate::entity::sys_role;

/// 数据范围档位白名单（与 `sys_role.data_scope` 列语义、前端 `sys_normal_disable` 之外的
/// 数据字典 `sys_data_scope` 同一口径）。
pub const DATA_SCOPE_VALUES: [i32; 5] = [1, 2, 3, 4, 5];

/// 写入侧档位校验（**单一事实源**：`add_role` / `edit_role` / `update_data_scope` 三条路径共用）。
///
/// 为什么必须在写入侧也判：读取侧 `min_data_scope` + 各 Service 的 `_ =>` 兜底已经把未知档位
/// 安全降级成"本部门"，所以非法值不会越权——但它会**静默落库**。b79 实测：
/// `PUT /system/role/dataScope` 传 `dataScope="9"` 返回 `200 修改成功` 并写入 `sys_role`，
/// 而该角色的实际过滤语义是"本部门"，管理端显示的却是"9"。显示与行为分裂后，
/// 管理员"改回正常档"的操作失去依据，且 `min_data_scope` 取最小值的规则会让 `0`/负数档
/// 覆盖掉同用户其他角色的合法档（比预期更窄，故障形态是"权限莫名变小"）。
/// 按开关规范②"非法取值一律拒绝，不得静默失效"，写入即拒。
///
/// `None`（新增缺省 / 编辑不改）由调用方回落 `"1"`，不在此判。
///
/// 必须是**规范单字符**形态：`"02"` 能 `parse` 成 2，但落库后所有
/// `data_scope.as_deref() == Some("2")` 的自定义档判定都会静默失配（`min_data_scope`
/// 仍能解析成 2，于是"取最小值"生效而"自定义部门"分支根本不触发）——
/// 与"未知档位被拒"同类的显示/行为分裂，故按字面收口。
pub fn is_valid_data_scope(raw: &str) -> bool {
    raw.len() == 1
        && raw
            .parse::<i32>()
            .map(|v| DATA_SCOPE_VALUES.contains(&v))
            .unwrap_or(false)
}

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
            tenant_id: 0,
            is_system: false,
            role_id: id,
            role_name: format!("role-{id}"),
            role_key: format!("key-{id}"),
            role_sort: 0,
            data_scope: scope.map(|s| s.to_owned()),
            custom_sql: None,
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

    #[test]
    fn data_scope_whitelist_accepts_every_registered_tier() {
        for v in DATA_SCOPE_VALUES {
            assert!(is_valid_data_scope(&v.to_string()), "档位 {v} 必须合法");
        }
    }

    #[test]
    fn data_scope_whitelist_rejects_out_of_range_and_non_numeric() {
        // 每条都是"实测能落库"的形状（b79 探针里 '9' 就是 200 修改成功）
        for bad in ["0", "6", "9", "10", "-1", "x", "", "1 ", " 1", "01", "1.0"] {
            assert!(!is_valid_data_scope(bad), "非法档位 {bad:?} 必须被拒");
        }
    }

    /// 反证面：白名单必须**窄于**"任何可解析整数"，否则本条与 `min_data_scope` 的
    /// 忽略规则等价，写入侧等于没判。
    #[test]
    fn data_scope_whitelist_is_narrower_than_parseable() {
        assert!("9".parse::<i32>().is_ok(), "前置：9 本身可解析");
        assert!(!is_valid_data_scope("9"), "但白名单必须拒它");
    }
}
