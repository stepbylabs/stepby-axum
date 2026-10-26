//! 权限键格式的单一事实源。
//!
//! 权限键（`sys_menu.perms`）是 RBAC 的唯一授予来源：运行时中间件按字符串精确匹配，
//! 超管短路只认 `*:*:*`。因此菜单写面必须拒绝通配符与任意分隔符——否则一次菜单编辑
//! 就能把普通角色变成超管（`*:*:*` 直接命中 `permission.rs` 的超管短路）。
//!
//! 本模块只提供**纯谓词**；错误文案与 HTTP 语义由调用方（菜单服务）决定，
//! 这样种子数据契约测试与运行时写面共用同一把尺，不会出现"测试合法、线上可写"的漂移。

/// 合法权限键：非空，且只允许 ASCII 字母/数字、`:`、`_`、`-`。
///
/// 连字符用于与路由路径同名的权限键（如 `system:webhook:test-send`）；
/// `*` 被刻意排除——它只属于超管内部标记，不得由菜单写入。
pub fn is_well_formed_perm(perm: &str) -> bool {
    !perm.is_empty()
        && perm
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == ':' || c == '_' || c == '-')
}

#[cfg(test)]
mod tests {
    use super::is_well_formed_perm;

    #[test]
    fn accepts_normal_module_entity_action_keys() {
        assert!(is_well_formed_perm("system:user:list"));
        assert!(is_well_formed_perm("report:dashboard:edit"));
        assert!(is_well_formed_perm("system:webhook:test-send"));
        assert!(is_well_formed_perm("ai:chat"));
    }

    #[test]
    fn rejects_wildcards_and_separators() {
        assert!(!is_well_formed_perm("*:*:*"));
        assert!(!is_well_formed_perm("system:*"));
        assert!(!is_well_formed_perm("system user list"));
        assert!(!is_well_formed_perm("system/user/list"));
        assert!(!is_well_formed_perm("system:user:list\n"));
        assert!(!is_well_formed_perm(""));
    }

    #[test]
    fn wildcard_judge_is_falsifiable() {
        // 控制组：把 `*` 换成普通字符后必须通过，证明拒绝不是"整串都拒"的退化实现。
        let candidate = "*:*:*".replace('*', "x");
        assert!(is_well_formed_perm(&candidate));
    }
}
