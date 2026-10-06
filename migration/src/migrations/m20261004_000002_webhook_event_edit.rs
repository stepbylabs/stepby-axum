// stepby-axum/migration/src/migrations/m20261004_000002_webhook_event_edit.rs
//! 全链路核查补录（2026-10-04）：sys_webhook_event.enabled 切换入口的权限种子
//!
//! entity 注释定义「停用 = 目录下架展示」语义，但此前全链路无任何切换入口
//! （repository 无 update、handler 无端点、前端无按钮），`enabled` 字段沦为
//! 死配置。本轮补齐：菜单按钮 3564（`system:webhook:event:edit`）+
//! 后端 `PUT /system/webhook/event/{id}/enabled` 端点 + 前端目录开关。
//!
//! 语义边界：enabled 仅控制**目录展示与订阅校验**（validate_subscribed_events
//! 对停用事件拒绝新订阅），事件派发（emit_event）以 hook 订阅关系为准、不查目录
//! enabled——存量 hook 不因目录停用而中断。
//!
//! ## 口径
//!
//! 菜单种子对齐 m20261003_000002 范式（3564 挂「回调配置」页面 menu_id=158 下，
//! 授予超管角色 role_id=2）；`pub fn` 供 `initialize/mod.rs` 兜底引用（单一事实源）。

use sea_orm_migration::prelude::*;

pub struct Migration;

impl MigrationName for Migration {
    fn name(&self) -> &str {
        "m20261004_000002_webhook_event_edit"
    }
}

/// 幂等 INSERT（种子数据按唯一约束去重；与 m20261003_000002 同款口径，
/// 该实现为彼文件私有故此处同构复制）
async fn execute_idempotent_insert(manager: &SchemaManager<'_>, body: &str) -> Result<(), DbErr> {
    let sql = match manager.get_connection().get_database_backend() {
        sea_orm::DatabaseBackend::Sqlite => format!("INSERT OR IGNORE INTO {}", body),
        sea_orm::DatabaseBackend::Postgres => {
            format!("INSERT INTO {} ON CONFLICT DO NOTHING", body)
        }
        _ => format!("INSERT IGNORE INTO {}", body),
    };
    manager.get_connection().execute_unprepared(&sql).await?;
    Ok(())
}

/// 菜单按钮 3564 种子行（迁移与兜底共用）
pub const WEBHOOK_EVENT_EDIT_ROW: (i64, &str, i64, i64, &str, &str, &str) = (
    3564,
    "目录停用启用",
    158,
    3,
    "system:webhook:event:edit",
    "edit",
    "webhook 事件目录停用/启用（目录下架展示并拒绝新订阅）",
);

/// 菜单按钮 INSERT 语句体（不含幂等前缀，迁移与兜底共用）
///
/// 返回顺序：菜单 3564 → role_menu(2,3564)。
pub fn webhook_event_edit_menu_bodies(now_expr: &str) -> Vec<String> {
    let (menu_id, name, parent_id, order_num, perms, icon, remark) = WEBHOOK_EVENT_EDIT_ROW;
    vec![
        format!(
            "sys_menu (menu_id, menu_name, parent_id, order_num, path, component, query, route_name, is_frame, is_cache, menu_type, visible, status, perms, icon, create_by, create_time, remark, del_flag) VALUES \
            ({menu_id}, '{name}', {parent_id}, {order_num}, '', '', '', '', '1', '0', 'F', '0', '0', '{perms}', '{icon}', 'admin', {now_expr}, '{remark}', '0')"
        ),
        format!("sys_role_menu (role_id, menu_id) VALUES (2, {menu_id})"),
    ]
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let now = match manager.get_connection().get_database_backend() {
            sea_orm::DatabaseBackend::MySql => "NOW()",
            sea_orm::DatabaseBackend::Postgres => "NOW()",
            _ => "CURRENT_TIMESTAMP",
        };
        for body in webhook_event_edit_menu_bodies(now) {
            execute_idempotent_insert(manager, &body).await?;
        }
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .get_connection()
            .execute_unprepared("DELETE FROM sys_role_menu WHERE menu_id = 3564")
            .await?;
        manager
            .get_connection()
            .execute_unprepared("DELETE FROM sys_menu WHERE menu_id = 3564")
            .await?;
        Ok(())
    }
}
