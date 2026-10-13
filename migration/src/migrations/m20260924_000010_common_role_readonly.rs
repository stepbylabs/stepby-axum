// stepby-axum/migration/src/m20260924_000010_common_role_readonly.rs
//! 普通角色（role_id=2）权限收紧为只读白名单——§8.2 安全发现修复（福哥拍板推荐方案）。
//!
//! 背景：m20250711_000001_init 的 insert_sys_role_menu 把全部菜单（含 50+ 条写权限
//! 按钮）关联给 common 角色，新部署默认即"普通角色拥有全站写权限"，与"普通角色
//! 只读"的语义预期不符（详见 docs/optimization/topic-multitenant-sso-audit-2026-09-23.md
//! §8.2 安全发现）。
//!
//! 目标状态（声明式，与 stepby-vue tests/e2e/deep-e2e.mjs M9 前置完全同款语义）：
//!   - 全部目录(M)与页面(C)：页面可见可进；
//!   - F 按钮中仅只读权限（perms 以 :list/:query/:view/:center 结尾）：
//!     保住页面内子资源 API（如字典 :query）不被 403，页面能正常加载数据；
//!   - 其余写权限按钮（:add/:edit/:remove/:export/:import/:run 等）全部收回。
//!
//! 实现要点：
//!   - DELETE + SELECT 重插：天然幂等（重复执行结果一致），与"声明式目标状态"
//!     语义一致——等同于管理端角色授权 PUT 全量替换 menuIds；
//!   - sys_menu 为全局表（menu_id 全局自增主键、无租户维度，见 init 建表与
//!     m20260924_000005 租户迁移的覆盖范围），role_id=2 为 init 种子角色；
//!   - LIKE 后缀匹配三方言（sqlite/postgres/mysql）通用，perms 值均为小写无
//!     collation 歧义；
//!   - 存量兼容：stepby 当前无生产用户依赖 common 写权限（本地开发 + e2e 库），
//!     收回无存量风险；e2e 库此前已由 deep-e2e M9 前置收紧至同一目标集合，
//!     本迁移与其幂等收敛。

use sea_orm_migration::prelude::*;

pub struct Migration;

impl MigrationName for Migration {
    fn name(&self) -> &str {
        "m20260924_000010_common_role_readonly"
    }
}

/// F 按钮中的只读权限后缀（与 deep-e2e M9 前置 readOnlyPerms 正则同语义）
const READONLY_PERMS_SUFFIX: [&str; 4] = [":list", ":query", ":view", ":center"];

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let conn = manager.get_connection();
        // 1. 清空 common 的既有菜单关联（声明式目标状态下的全量重分配）
        conn.execute_unprepared("DELETE FROM sys_role_menu WHERE role_id = 2")
            .await?;
        // 2. 重插目标集合：未删除的 M/C 页面 + F 按钮中的只读权限
        //    del_flag='0' 与 API /system/menu/list 的过滤对齐（软删菜单不入授权，
        //    避免 116 vs 83 的脏差异——get_menu_list 同样只返回 del_flag='0'）
        let suffix_clause = READONLY_PERMS_SUFFIX
            .iter()
            .map(|s| format!("perms LIKE '%{}'", s))
            .collect::<Vec<_>>()
            .join(" OR ");
        let sql = format!(
            r#"INSERT INTO sys_role_menu (role_id, menu_id)
               SELECT 2, menu_id FROM sys_menu
               WHERE del_flag = '0'
                 AND (menu_type IN ('M', 'C')
                  OR (menu_type = 'F' AND ({suffix_clause})))"#
        );
        conn.execute_unprepared(&sql).await?;
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // 回滚 = 恢复 init 的"全菜单关联"语义（仅重插 sys_menu 中仍存在的初始项，
        // 避免引用已被后续菜单类迁移删除/合并的 menu_id 导致外键失败）
        const INIT_MENU_IDS: &[i64] = &[
            1, 2, 3, 4, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114,
            115, 116, 117, 500, 501, 1000, 1001, 1002, 1003, 1004, 1005, 1006, 1007, 1008, 1009,
            1010, 1011, 1012, 1013, 1014, 1015, 1016, 1017, 1018, 1019, 1020, 1021, 1022, 1023,
            1024, 1025, 1026, 1027, 1028, 1029, 1030, 1031, 1032, 1033, 1034, 1035, 1036, 1037,
            1038, 1039, 1040, 1041, 1042, 1043, 1044, 1045, 1046, 1047, 1048, 1049, 1050, 1051,
            1052, 1053, 1054, 1055, 1056, 1057, 1058, 1059, 1060,
        ];
        let conn = manager.get_connection();
        conn.execute_unprepared("DELETE FROM sys_role_menu WHERE role_id = 2")
            .await?;
        let id_list = INIT_MENU_IDS
            .iter()
            .map(|i| i.to_string())
            .collect::<Vec<_>>()
            .join(", ");
        conn.execute_unprepared(&format!(
            r#"INSERT INTO sys_role_menu (role_id, menu_id)
               SELECT 2, menu_id FROM sys_menu WHERE menu_id IN ({id_list})"#
        ))
        .await?;
        Ok(())
    }
}
