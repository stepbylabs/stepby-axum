// axum-backend/src/repository/sys_menu.rs
//! sys_menu 数据访问层
//!
//! 继承 BaseRepository 通用 CRUD，扩展菜单特有查询：
//! - 按用户 ID 查询菜单（通过 sys_user_role → sys_role_menu 关联）
//! - 按角色 ID 查询菜单
//! - 按父菜单查询
//! - 软删除过滤（del_flag = '0'）

use chrono::NaiveDateTime;
use sea_orm::sea_query::Expr;
use sea_orm::*;

use crate::entity::sys_menu::{ActiveModel, Column, Entity as SysMenu, Model};
use crate::entity::sys_role_menu::{Column as RoleMenuColumn, Entity as SysRoleMenu};
use crate::repository::base::BaseRepository;

/// 菜单 Repository
#[derive(Clone)]
pub struct SysMenuRepository {
    base: BaseRepository<SysMenu>,
}

impl SysMenuRepository {
    pub fn new(db: DatabaseConnection) -> Self {
        Self {
            base: BaseRepository::new(db),
        }
    }

    pub fn base(&self) -> &BaseRepository<SysMenu> {
        &self.base
    }

    /// 查询所有未删除菜单（del_flag = '0'）
    /// 按 order_num 升序、menu_id 升序排序，确保菜单按配置顺序展示
    pub async fn find_active_all(&self) -> Result<Vec<Model>, DbErr> {
        SysMenu::find()
            .filter(Column::DelFlag.eq("0"))
            .order_by_asc(Column::OrderNum)
            .order_by_asc(Column::MenuId)
            .all(self.base.db())
            .await
    }

    /// 按父菜单 ID 查询
    /// 按 order_num 升序、menu_id 升序排序
    pub async fn find_by_parent_id(&self, parent_id: i64) -> Result<Vec<Model>, DbErr> {
        SysMenu::find()
            .filter(Column::ParentId.eq(parent_id))
            .filter(Column::DelFlag.eq("0"))
            .order_by_asc(Column::OrderNum)
            .order_by_asc(Column::MenuId)
            .all(self.base.db())
            .await
    }

    /// 按角色 ID 查询关联菜单（通过 sys_role_menu 关联表）
    pub async fn find_by_role_id(&self, role_id: i64) -> Result<Vec<Model>, DbErr> {
        // 先查角色菜单关联表，获取 menu_id 列表
        let role_menus: Vec<i64> = SysRoleMenu::find()
            .filter(RoleMenuColumn::RoleId.eq(role_id))
            .all(self.base.db())
            .await?
            .into_iter()
            .map(|rm| rm.menu_id)
            .collect();

        if role_menus.is_empty() {
            return Ok(vec![]);
        }

        // 再查菜单表
        SysMenu::find()
            .filter(Column::MenuId.is_in(role_menus))
            .filter(Column::DelFlag.eq("0"))
            .all(self.base.db())
            .await
    }

    /// 按用户 ID 查询其可访问的所有菜单
    /// 链路：user_id → sys_user_role → role_id → sys_role_menu → menu_id
    ///
    /// DB-21：原实现使用 3 次顺序查询（sys_user_role → sys_role_menu → sys_menu），
    /// 改为单次 JOIN 查询，减少数据库往返开销。
    /// 使用 DISTINCT 去重：同一菜单可能被用户的多个角色同时授予。
    /// 按 order_num 升序、menu_id 升序排序，确保菜单顺序正确。
    pub async fn find_by_user_id(&self, user_id: i64) -> Result<Vec<Model>, DbErr> {
        let db = self.base.db();
        let backend = db.get_database_backend();
        // 占位符差异：MySQL 使用 `?`，PostgreSQL/SQLite 使用 `$1`（SQLite 同时兼容两者）
        let sql = match backend {
            DatabaseBackend::MySql => {
                r#"SELECT DISTINCT m.* FROM sys_menu m
                INNER JOIN sys_role_menu rm ON m.menu_id = rm.menu_id
                INNER JOIN sys_user_role ur ON rm.role_id = ur.role_id
                WHERE ur.user_id = ? AND m.del_flag = '0'
                ORDER BY m.order_num ASC, m.menu_id ASC"#
            }
            _ => {
                r#"SELECT DISTINCT m.* FROM sys_menu m
                INNER JOIN sys_role_menu rm ON m.menu_id = rm.menu_id
                INNER JOIN sys_user_role ur ON rm.role_id = ur.role_id
                WHERE ur.user_id = $1 AND m.del_flag = '0'
                ORDER BY m.order_num ASC, m.menu_id ASC"#
            }
        };
        let stmt = Statement::from_sql_and_values(backend, sql, [user_id.into()]);
        Model::find_by_statement(stmt).all(db).await
    }

    /// 按菜单 ID 集合查询 (menu_id, perms)，仅取两列（§27.13.4 授予前覆盖校验用）
    ///
    /// perms 为 None 或空串表示目录 / 无权限点的菜单，调用方需自行跳过。
    /// 返回顺序不保证；不存在的 ID 自然缺省（由套餐白名单校验负责其合法性）。
    pub async fn find_perms_by_ids(
        &self,
        menu_ids: &[i64],
    ) -> Result<Vec<(i64, Option<String>)>, DbErr> {
        if menu_ids.is_empty() {
            return Ok(vec![]);
        }
        SysMenu::find()
            .select_only()
            .column(Column::MenuId)
            .column(Column::Perms)
            .filter(Column::MenuId.is_in(menu_ids.to_vec()))
            .filter(Column::DelFlag.eq("0"))
            .into_tuple::<(i64, Option<String>)>()
            .all(self.base.db())
            .await
    }

    /// 软删除菜单
    pub async fn soft_delete(&self, menu_id: i64) -> Result<UpdateResult, DbErr> {
        SysMenu::update_many()
            .col_expr(Column::DelFlag, Expr::value("2"))
            .filter(Column::MenuId.eq(menu_id))
            .exec(self.base.db())
            .await
    }

    /// 直接更新菜单排序字段（避免 find_by_id + update 两轮 DB 往返）
    ///
    /// 仅更新 order_num / update_by / update_time 三个字段，通过 WHERE menu_id 过滤。
    /// 若记录不存在则 affected_rows=0，由调用方按需处理（如 silent skip）。
    pub async fn update_sort_conn<C: ConnectionTrait>(
        &self,
        conn: &C,
        menu_id: i64,
        order_num: i32,
        update_by: &str,
        update_time: NaiveDateTime,
    ) -> Result<UpdateResult, DbErr> {
        SysMenu::update_many()
            .col_expr(Column::OrderNum, Expr::value(order_num))
            .col_expr(Column::UpdateBy, Expr::value(update_by))
            .col_expr(Column::UpdateTime, Expr::value(update_time))
            .filter(Column::MenuId.eq(menu_id))
            .exec(conn)
            .await
    }

    /// 插入菜单
    pub async fn insert(&self, model: ActiveModel) -> Result<Model, DbErr> {
        self.base.insert(model).await
    }

    /// 更新菜单
    pub async fn update(&self, model: ActiveModel) -> Result<Model, DbErr> {
        self.base.update(model).await
    }
}
