//! G-01/G-02 M1：流程定义与报表数据集/大屏的菜单权限承载（menu_id 4140-4148）
//!
//! 为何必须有本迁移：契约测试 `menu_perm_contract`（单一数据源
//! `PERM_ROUTE_TABLE`）断言「后端所需权限 ⊆ sys_menu.perms」——
//!
//! - `flow:definition:*` 6 键（m20261007_000003 引入路由映射）此前无菜单行承载；
//! - `report:dataset:*` / `report:dashboard:*` 3 键（m20261007_000004 配套路由）同理。
//!
//! 缺菜单行 ⇒ 普通角色永远无法被授予这些能力（契约测试变红）。
//!
//! 设计要点：
//! - **全新 4140 段位**（4130/4131 已被报表看板 m20261003_000006 占用）；
//! - 页面菜单 `visible='1'`（隐藏）：M1 仅落地 API/权限链路，前端页面 M2 上线时
//!   再翻转可见性，避免 M1 出现"点击即 404"的死入口；
//! - 幂等 INSERT（方言感知 IGNORE 前后缀，与 m20261007_000002 同构）；
//! - 超管（role_id=1）经 isAdmin 特判拥有全部 perms，无需 role_menu 授权行；
//! - 存量库兜底：`initialize::ensure_flow_report_menus`（同构幂等 seed + E6 内容校验）。

use sea_orm_migration::prelude::*;

pub struct Migration;

impl MigrationName for Migration {
    fn name(&self) -> &str {
        "m20261007_000005_flow_report_menus"
    }
}

/// 幂等 INSERT（方言感知 IGNORE 前后缀，与 m20261007_000002 同构）
fn idempotent_insert(backend: sea_orm::DatabaseBackend, body: &str) -> String {
    match backend {
        sea_orm::DatabaseBackend::Sqlite => format!("INSERT OR IGNORE INTO {body}"),
        sea_orm::DatabaseBackend::Postgres => format!("INSERT INTO {body} ON CONFLICT DO NOTHING"),
        _ => format!("INSERT IGNORE INTO {body}"),
    }
}

/// 菜单 seed 行（单一事实源，写库顺序即数组顺序）
struct MenuSeed {
    menu_id: i64,
    menu_name: &'static str,
    parent_id: i64,
    order_num: i64,
    menu_type: &'static str,
    path: &'static str,
    component: &'static str,
    perms: &'static str,
    icon: &'static str,
    remark: &'static str,
}

const MENUS: &[MenuSeed] = &[
    MenuSeed {
        menu_id: 4140,
        menu_name: "流程定义",
        parent_id: 1,
        order_num: 16,
        menu_type: "C",
        path: "flowDefinition",
        component: "flow/designer/index",
        perms: "flow:definition:list",
        icon: "form",
        remark: "G-02 可视化流程定义管理页（M2 前端上线时翻转可见）",
    },
    MenuSeed {
        menu_id: 4141,
        menu_name: "流程定义查询",
        parent_id: 4140,
        order_num: 1,
        menu_type: "F",
        path: "",
        component: "",
        perms: "flow:definition:query",
        icon: "#",
        remark: "流程定义详情查询按钮",
    },
    MenuSeed {
        menu_id: 4142,
        menu_name: "流程定义新增",
        parent_id: 4140,
        order_num: 2,
        menu_type: "F",
        path: "",
        component: "",
        perms: "flow:definition:add",
        icon: "#",
        remark: "流程定义新增按钮",
    },
    MenuSeed {
        menu_id: 4143,
        menu_name: "流程定义编辑",
        parent_id: 4140,
        order_num: 3,
        menu_type: "F",
        path: "",
        component: "",
        perms: "flow:definition:edit",
        icon: "#",
        remark: "流程定义编辑按钮",
    },
    MenuSeed {
        menu_id: 4144,
        menu_name: "流程定义发布",
        parent_id: 4140,
        order_num: 4,
        menu_type: "F",
        path: "",
        component: "",
        perms: "flow:definition:publish",
        icon: "#",
        remark: "流程定义发布按钮（生成新版本并切换 is_latest）",
    },
    MenuSeed {
        menu_id: 4145,
        menu_name: "流程定义删除",
        parent_id: 4140,
        order_num: 5,
        menu_type: "F",
        path: "",
        component: "",
        perms: "flow:definition:remove",
        icon: "#",
        remark: "流程定义删除按钮",
    },
    MenuSeed {
        menu_id: 4146,
        menu_name: "报表数据集",
        parent_id: 1,
        order_num: 17,
        menu_type: "C",
        path: "reportDataset",
        component: "report/dataset/index",
        perms: "report:dataset:list",
        icon: "chart",
        remark: "G-01 受控数据集管理页（M2 前端上线时翻转可见）",
    },
    MenuSeed {
        menu_id: 4147,
        menu_name: "数据集编辑",
        parent_id: 4146,
        order_num: 1,
        menu_type: "F",
        path: "",
        component: "",
        perms: "report:dataset:edit",
        icon: "#",
        remark: "数据集新增/编辑/删除/试跑按钮（含 preview，权限合并模型）",
    },
    MenuSeed {
        menu_id: 4148,
        menu_name: "大屏管理",
        parent_id: 1,
        order_num: 18,
        menu_type: "C",
        path: "reportDashboard",
        component: "report/view/index",
        perms: "report:dashboard:view",
        icon: "dashboard",
        remark: "G-01 大屏查看/保存/删除入口（save/view 同权限键，M2 前端上线时翻转可见）",
    },
];

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let backend = manager.get_connection().get_database_backend();
        let now_expr = match backend {
            sea_orm::DatabaseBackend::Sqlite => {
                format!("'{}'", chrono::Local::now().format("%Y-%m-%d %H:%M:%S"))
            }
            _ => "NOW()".to_string(),
        };
        for m in MENUS {
            let sql = idempotent_insert(
                backend,
                &format!(
                    "sys_menu (menu_id, menu_name, parent_id, order_num, path, component, query, \
                     route_name, is_frame, is_cache, menu_type, visible, status, perms, icon, \
                     create_by, create_time, remark, del_flag) VALUES \
                     ({}, '{}', {}, {}, '{}', '{}', '', '', \
                     '1', '0', '{}', '1', '0', '{}', '{}', 'admin', \
                     {}, '{}', '0')",
                    m.menu_id,
                    m.menu_name,
                    m.parent_id,
                    m.order_num,
                    m.path,
                    m.component,
                    m.menu_type,
                    m.perms,
                    m.icon,
                    now_expr,
                    m.remark
                ),
            );
            manager.get_connection().execute_unprepared(&sql).await?;
        }
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let ids = MENUS
            .iter()
            .map(|m| m.menu_id.to_string())
            .collect::<Vec<_>>()
            .join(", ");
        manager
            .get_connection()
            .execute_unprepared(&format!("DELETE FROM sys_menu WHERE menu_id IN ({ids})"))
            .await?;
        Ok(())
    }
}
