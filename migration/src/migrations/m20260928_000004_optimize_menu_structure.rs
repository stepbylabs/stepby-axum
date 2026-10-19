// stepby-axum/migration/src/migrations/m20260928_000004_optimize_menu_structure.rs
//! 菜单信息架构优化（用户实测反馈：目录结构混乱 / icon 语义重复 / 排序冲突）。
//!
//! 三类修正（全部幂等，可重复执行）：
//! 1. **order 冲突清理**：「系统管理」下 order=8 出现两次（通知公告/租户管理）、
//!    「系统监控」下 order=10/11 各出现 2~3 次（118/3550、119/133/160/501/3560），
//!    显示顺序依赖 menu_id 次序不稳定 ⇒ 按语义全量重排。
//! 2. **游离顶级页收编**：「我的域名」(3900) /「导航设置」(3627) 是租户自助页，
//!    此前游离在菜单树顶层尾部 ⇒ 收编进新目录 3950「租户服务」
//!    （page 菜单移入目录后由 menu_to_router 正常走 Layout 结构，路由变为
//!    /tenant-space/*——component 与权限码不变，L3 引用按 menu_id 不受影响）。
//! 3. **icon 语义去重/修正**：peoples 四处复用、connection 两处、documentation
//!    五处、monitor 父子同名、log 三处等 ⇒ 按语义改为 sprite 内更贴切图标
//!    （不新增 svg，全部使用 src/assets/icons/svg 现有集合）。
//!
//! 注意：本迁移不删除任何菜单、不改权限码（perms）、不改 component，
//! role_menu 按 menu_id 引用不受 parent 调整影响。

use sea_orm_migration::prelude::*;
use sea_orm_migration::sea_orm::{DatabaseBackend, Statement};

pub struct Migration;

impl MigrationName for Migration {
    fn name(&self) -> &str {
        "m20260928_000004_optimize_menu_structure"
    }
}

/// (menu_id, order_num) 重排清单：三个目录内按语义排序，消除重复 order
const ORDER_UPDATES: &[(i64, i32)] = &[
    // ---- 顶层：工作台 0 / 数据看板 1 / 系统管理 2 / 系统监控 3 / 系统工具 4 / 租户服务 5 / 官网 6 ----
    (127, 0),
    (132, 1),
    (1, 2),
    (2, 3),
    (3, 4),
    (3950, 5),
    (4, 6),
    // ---- 系统管理(1)：账号权限 → 配置 → 日志 → 协作/集成 ----
    (100, 1),
    (101, 2),
    (102, 3),
    (103, 4),
    (104, 5),
    (105, 6),
    (106, 7),
    (107, 8),
    (3700, 9),
    (108, 10),
    (125, 11),
    (134, 12),
    (140, 13),
    (151, 14),
    (3600, 15),
    (145, 16),
    (157, 17),
    // ---- 系统监控(2)：会话/任务 → 存储/日志 → 运维观测 ----
    (109, 1),
    (110, 2),
    (119, 3),
    (113, 4),
    (135, 5),
    (118, 6),
    (3550, 7),
    (133, 8),
    (121, 9),
    (122, 10),
    (120, 11),
    (160, 12),
    (501, 13),
    // ---- 系统工具(3)：开发构建 → 集成调试 → 个人令牌 → 信息页 ----
    (115, 1),
    (116, 2),
    (117, 3),
    (3410, 4),
    (3560, 5),
    (124, 6),
    (128, 7),
    (129, 8),
    (131, 9),
];

/// (menu_id, icon) 语义修正清单（**语义直觉优先**，同语义页面允许复用同图标；
/// 全部使用现有 sprite 图标，防拼写错误渲染空白）：
/// - 消息/公告分流：公告=message(广播)、消息管理=email(站内信)、渠道=mail；
/// - 日志族统一 log：日志管理/实时日志/发送记录；
/// - 认证族：单点登录=enter、登录配置=key(密钥凭证)、WebHook=link(回调)；
/// - 结构族：租户管理=nested(层级)、租户服务=peoples(组织)、我的导航=drag(拖拽摆位)；
/// - 其余：健康检查=druid(连接池巡检)、备份=backup、运行监控=server、
///   报表=excel、审批=form、关于系统=icon(信息)。
const ICON_UPDATES: &[(i64, &str)] = &[
    (107, "message"),    // 通知公告：广播
    (140, "email"),      // 消息管理：站内信/邮件
    (118, "backup"),     // 备份管理
    (124, "icon"),       // 关于系统：信息
    (133, "druid"),      // 健康检查：连接池巡检
    (135, "log"),        // 实时日志
    (145, "enter"),      // 单点登录：进入
    (146, "switch"),     // 登录配置：SSO 切换（⚠️ sprite 无 key.svg，勿用）
    (3560, "clipboard"), // API 令牌：复制凭证（历史遗留 key.svg 不存在，渲染空白）
    (151, "excel"),      // 报表中心
    (157, "link"),       // WebHook：回调链接
    (3550, "server"),    // 运行监控：服务
    (3600, "form"),      // 审批中心：审批表单
    (3700, "nested"),    // 租户管理：层级结构
    (3950, "peoples"),   // 租户服务：组织
    (3627, "drag"),      // 我的导航：拖拽摆位
];

fn idempotent_insert_prefix(backend: DatabaseBackend) -> &'static str {
    match backend {
        DatabaseBackend::Sqlite => "INSERT OR IGNORE INTO",
        DatabaseBackend::MySql => "INSERT IGNORE INTO",
        DatabaseBackend::Postgres => "INSERT INTO",
        _ => "INSERT INTO",
    }
}

fn is_postgres(manager: &SchemaManager) -> bool {
    manager.get_connection().get_database_backend() == DatabaseBackend::Postgres
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let conn = manager.get_connection();
        let backend = conn.get_database_backend();

        // 1. 新目录 3950「租户服务」（幂等插入；已存在时跳过）
        let exists: Option<i64> = conn
            .query_one_raw(Statement::from_sql_and_values(
                backend,
                "SELECT menu_id FROM sys_menu WHERE menu_id = 3950",
                [],
            ))
            .await?
            .map(|row| row.try_get_by_index::<i64>(0).unwrap_or(0));
        if exists.is_none() {
            let now = if backend == DatabaseBackend::Sqlite {
                "'2026-09-28 00:00:00'".to_string()
            } else {
                "NOW()".to_string()
            };
            let insert_sql = format!(
                "{} sys_menu (menu_id, menu_name, parent_id, order_num, path, component, query, route_name, is_frame, is_cache, menu_type, visible, status, perms, icon, create_by, create_time, remark, del_flag, i18n_key) VALUES (3950, '租户服务', 0, 5, 'tenant-space', NULL, '', '', '1', '0', 'M', '0', '0', '', 'shopping', 'admin', {}, '租户自助功能聚合（我的域名 / 导航设置）', '0', 'menu.tenantSpace')",
                idempotent_insert_prefix(backend),
                now
            );
            conn.execute_unprepared(&insert_sql).await?;
            // 平台普通角色可见该目录（子页 3900/3627 的授权维持原状）
            let rm_sql = if is_postgres(manager) {
                "INSERT INTO sys_role_menu (role_id, menu_id) VALUES (2, 3950) ON CONFLICT DO NOTHING".to_string()
            } else {
                format!(
                    "{} sys_role_menu (role_id, menu_id) VALUES (2, 3950)",
                    idempotent_insert_prefix(backend)
                )
            };
            conn.execute_unprepared(&rm_sql).await?;
        }

        // 2. 自助页收编：parent 移入 3950 + 改名（幂等 UPDATE）；
        //    「域名管理」与「菜单管理」区分：菜单管理=定义全系统菜单；本页=租户自助管理域名绑定；
        //    「我的导航」与「菜单管理」区分：本页=租户自助调整已授权导航的摆位
        for (menu_id, parent) in [(3900_i64, 3950_i64), (3627_i64, 3950_i64)] {
            conn.execute_unprepared(&format!(
                "UPDATE sys_menu SET parent_id = {} WHERE menu_id = {}",
                parent, menu_id
            ))
            .await?;
        }
        conn.execute_unprepared("UPDATE sys_menu SET menu_name = '域名管理' WHERE menu_id = 3900")
            .await?;
        conn.execute_unprepared("UPDATE sys_menu SET menu_name = '我的导航' WHERE menu_id = 3627")
            .await?;
        // 2b. API 令牌（个人开发者向）归属「系统工具」（原在系统监控下，
        //     order=5 与实时日志冲突；移动后 parent=3、order=5 无冲突）
        conn.execute_unprepared("UPDATE sys_menu SET parent_id = 3 WHERE menu_id = 3560")
            .await?;
        // 子页 order：我的域名 1 / 导航设置 2
        conn.execute_unprepared("UPDATE sys_menu SET order_num = 1 WHERE menu_id = 3900")
            .await?;
        conn.execute_unprepared("UPDATE sys_menu SET order_num = 2 WHERE menu_id = 3627")
            .await?;

        // 3. order 重排（幂等 UPDATE）
        for (menu_id, order) in ORDER_UPDATES {
            conn.execute_unprepared(&format!(
                "UPDATE sys_menu SET order_num = {} WHERE menu_id = {}",
                order, menu_id
            ))
            .await?;
        }

        // 4. icon 语义修正（幂等 UPDATE）
        for (menu_id, icon) in ICON_UPDATES {
            conn.execute_unprepared(&format!(
                "UPDATE sys_menu SET icon = '{}' WHERE menu_id = {}",
                icon, menu_id
            ))
            .await?;
        }

        Ok(())
    }

    async fn down(&self, _manager: &SchemaManager) -> Result<(), DbErr> {
        // 有意为 no-op：菜单结构优化不提供自动回滚（恢复旧 order/icon 无业务意义；
        // 3900/3627 若需移回顶层请人工评估 L3 引用后执行）
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 可证伪：ORDER_UPDATES 不允许同一父目录下出现重复 order。
    /// （按 parent 分组后 order 必须唯一——否则修了冲突又制造冲突）
    #[test]
    fn order_updates_have_no_duplicate_order_per_parent() {
        // parent 归属：从清单语义推导（3900/3627 归 3950；其余按 menu_id 前缀语义）
        let mut by_parent: std::collections::HashMap<i64, Vec<i32>> =
            std::collections::HashMap::new();
        for (menu_id, order) in ORDER_UPDATES {
            let parent = match *menu_id {
                3900 | 3627 => 3950,
                100 | 101 | 102 | 103 | 104 | 105 | 106 | 107 | 108 | 125 | 134 | 140 | 151
                | 3600 | 145 | 157 | 3700 => 1,
                109 | 110 | 113 | 118 | 119 | 120 | 121 | 122 | 133 | 135 | 160 | 3550 | 501 => 2,
                115 | 116 | 117 | 124 | 128 | 129 | 131 | 3410 | 3560 => 3,
                127 | 132 | 1 | 2 | 3 | 3950 | 4 => 0,
                other => panic!("未归类菜单: {}", other),
            };
            by_parent.entry(parent).or_default().push(*order);
        }
        for (parent, orders) in by_parent {
            let mut sorted = orders.clone();
            sorted.sort();
            sorted.dedup();
            assert_eq!(
                sorted.len(),
                orders.len(),
                "parent {} 存在重复 order: {:?}",
                parent,
                sorted
            );
        }
    }

    /// 可证伪：ICON_UPDATES 的图标必须属于现有 sprite 集合（防拼写错误渲染空白）。
    #[test]
    fn icon_updates_use_known_sprites() {
        const KNOWN: &[&str] = &[
            "404",
            "backup",
            "bell",
            "bug",
            "build",
            "button",
            "cascader",
            "chart",
            "checkbox",
            "clipboard",
            "code",
            "color",
            "component",
            "dashboard",
            "date",
            "date-range",
            "dict",
            "documentation",
            "download",
            "drag",
            "druid",
            "edit",
            "education",
            "email",
            "enter",
            "example",
            "excel",
            "exit-fullscreen",
            "eye",
            "eye-open",
            "form",
            "fullscreen",
            "gitee",
            "github",
            "guide",
            "icon",
            "input",
            "international",
            "job",
            "language",
            "link",
            "list",
            "lock",
            "log",
            "logininfor",
            "logo",
            "message",
            "money",
            "monitor",
            "moon",
            "more-up",
            "nested",
            "number",
            "online",
            "password",
            "pdf",
            "people",
            "peoples",
            "phone",
            "post",
            "qq",
            "question",
            "radio",
            "rate",
            "redis",
            "redis-list",
            "row",
            "search",
            "select",
            "server",
            "shopping",
            "size",
            "skill",
            "slider",
            "star",
            "sunny",
            "swagger",
            "switch",
            "system",
            "tab",
            "table",
            "textarea",
            "theme",
            "time",
            "time-range",
            "tool",
            "tree",
            "tree-table",
            "upload",
            "user",
            "validCode",
            "wechat",
            "wecom",
            "zip",
        ];
        for (menu_id, icon) in ICON_UPDATES {
            assert!(
                KNOWN.contains(icon),
                "menu {} icon '{}' 不在 sprite 集合内",
                menu_id,
                icon
            );
        }
    }
}
