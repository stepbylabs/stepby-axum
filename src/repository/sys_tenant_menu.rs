// stepby-axum/src/repository/sys_tenant_menu.rs
//! sys_tenant_menu（L3 租户自建导航）数据访问层（多租户 Phase 3 / 批次 3）
//!
//! 语义要点（与 `entity/sys_tenant_menu.rs` 的硬边界一致）：
//! - L3 行只表达"租户自己的导航结构（父级 / 排序 / 显隐）"，**不携带** component / perms；
//! - `ref_menu_id` 指向平台 L1 菜单，组件/路径/权限码一律取自它；
//! - 所有集合读路径**必须**带 `tenant_id` 过滤（本表在 `TENANT_FILTER_MATRIX` 登记为
//!   `Covered`），`tenant_scope` 为 `None` 仅用于平台侧的跨租户管理视图。

use sea_orm::sea_query::Expr;
use sea_orm::*;

use crate::entity::sys_tenant_menu::{Column, Entity as SysTenantMenu, Model};
use crate::repository::base::BaseRepository;

/// L3 节点 ID 段位起点（`docs/optimization/menu-id-registry.md`「L3 租户自建导航 5000 起」）
pub const L3_ID_BASE: i64 = 5000;

/// L3 导航 Repository
#[derive(Clone)]
pub struct SysTenantMenuRepository {
    base: BaseRepository<SysTenantMenu>,
}

impl SysTenantMenuRepository {
    pub fn new(db: DatabaseConnection) -> Self {
        Self {
            base: BaseRepository::new(db),
        }
    }

    pub fn base(&self) -> &BaseRepository<SysTenantMenu> {
        &self.base
    }

    /// 列表（del_flag='0'；`tenant_id=Some(tid)` 时仅本租户，`None` 为平台全量）
    pub async fn list(&self, tenant_id: Option<i64>) -> Result<Vec<Model>, DbErr> {
        let mut query = SysTenantMenu::find().filter(Column::DelFlag.eq("0"));
        if let Some(tid) = tenant_id {
            query = query.filter(Column::TenantId.eq(tid));
        }
        query
            .order_by_asc(Column::TenantId)
            .order_by_asc(Column::ParentId)
            .order_by_asc(Column::OrderNum)
            .order_by_asc(Column::L3Id)
            .all(self.base.db())
            .await
    }

    /// **加载期钳制的数据源**：某租户**生效**的 L3 行（`status='0'` + `del_flag='0'`）。
    ///
    /// `status='1'`（停用）的行会被忽略 ⇒ 该节点回退到平台默认位置（不删导航），
    /// 这是"停用即回退"的保守语义。
    pub async fn list_effective(&self, tenant_id: i64) -> Result<Vec<Model>, DbErr> {
        SysTenantMenu::find()
            .filter(Column::TenantId.eq(tenant_id))
            .filter(Column::DelFlag.eq("0"))
            .filter(Column::Status.eq("0"))
            .order_by_asc(Column::ParentId)
            .order_by_asc(Column::OrderNum)
            .order_by_asc(Column::L3Id)
            .all(self.base.db())
            .await
    }

    /// 按 l3_id 查询未删除行（**含**停用行；范围校验由调用方按 tenant_allowed 完成）
    pub async fn find_by_id(&self, l3_id: i64) -> Result<Option<Model>, DbErr> {
        SysTenantMenu::find()
            .filter(Column::L3Id.eq(l3_id))
            .filter(Column::DelFlag.eq("0"))
            .one(self.base.db())
            .await
    }

    /// 该租户是否已存在对 `ref_menu_id` 的 L3 行（防重复挂载同一菜单）
    pub async fn exists_ref(
        &self,
        tenant_id: i64,
        ref_menu_id: i64,
        exclude_l3_id: Option<i64>,
    ) -> Result<bool, DbErr> {
        let mut query = SysTenantMenu::find()
            .filter(Column::TenantId.eq(tenant_id))
            .filter(Column::RefMenuId.eq(ref_menu_id))
            .filter(Column::DelFlag.eq("0"));
        if let Some(exclude) = exclude_l3_id {
            query = query.filter(Column::L3Id.ne(exclude));
        }
        Ok(query.count(self.base.db()).await? > 0)
    }

    /// 该租户对 `ref_menu_id` 的**软删行**（曾被卸载、如今要重新挂载的那一行）
    ///
    /// 为什么必须有这一步：唯一索引 `uk_sys_tenant_menu (tenant_id, ref_menu_id)`
    /// **不含 del_flag**，而 [`Self::exists_ref`] 只看 `del_flag='0'` ⇒ "卸载后重新挂载"
    /// 这条真实流程会绕过重复检查直接 INSERT，撞唯一索引返回 500（b80 P-A 实测缺陷）。
    /// 一个 `(tenant_id, ref_menu_id)` 上至多一行，故取 `one()`。
    pub async fn find_revivable_ref(
        &self,
        tenant_id: i64,
        ref_menu_id: i64,
    ) -> Result<Option<Model>, DbErr> {
        SysTenantMenu::find()
            .filter(Column::TenantId.eq(tenant_id))
            .filter(Column::RefMenuId.eq(ref_menu_id))
            .filter(Column::DelFlag.eq("2"))
            .one(self.base.db())
            .await
    }

    /// 某 L3 节点的直接子节点数（删除前的引用保护）
    pub async fn count_children(&self, tenant_id: i64, l3_id: i64) -> Result<u64, DbErr> {
        SysTenantMenu::find()
            .filter(Column::TenantId.eq(tenant_id))
            .filter(Column::ParentId.eq(l3_id))
            .filter(Column::DelFlag.eq("0"))
            .count(self.base.db())
            .await
    }

    /// 分配下一个 `l3_id`（段位 5000 起；`MAX(l3_id)+1`，无行时取 [`L3_ID_BASE`]）
    ///
    /// 说明：本表 `l3_id` 为**非自增**主键（段位需可读可辨）。`MAX+1` 在读与写之间没有锁，
    /// 并发挂载会算出同一个 id ⇒ **调用方必须按主键冲突重算重试**
    /// （`service::sys_tenant_nav_service::add`，见 `L3_ID_RETRY_LIMIT`）。
    /// L3 为低频人工配置，不引入独立序列。
    pub async fn next_l3_id(&self) -> Result<i64, DbErr> {
        let max: Option<i64> = SysTenantMenu::find()
            .select_only()
            .column_as(Column::L3Id.max(), "max_id")
            .into_tuple::<Option<i64>>()
            .one(self.base.db())
            .await?
            .flatten();
        Ok(std::cmp::max(
            max.map(|m| m + 1).unwrap_or(L3_ID_BASE),
            L3_ID_BASE,
        ))
    }

    /// 插入一条 L3 行
    ///
    /// ⚠️ **不可复用 `BaseRepository::insert`**：本表主键 `l3_id` 为**非自增**，
    /// MySQL 分支下 `last_insert_id` 恒为 0 ⇒ 回查必然失败（见 `base.rs` 的 DB-22 说明）。
    /// 故这里对 MySQL 用 `exec` + 按显式主键回查，其余方言用 `exec_with_returning`。
    pub async fn insert(
        &self,
        model: crate::entity::sys_tenant_menu::ActiveModel,
    ) -> Result<Model, DbErr> {
        let db = self.base.db();
        match db.get_database_backend() {
            DatabaseBackend::MySql => {
                let l3_id = match &model.l3_id {
                    ActiveValue::Set(v) | ActiveValue::Unchanged(v) => *v,
                    _ => {
                        return Err(DbErr::Custom(
                            "sys_tenant_menu 插入前必须显式设置 l3_id（非自增主键）".to_string(),
                        ));
                    }
                };
                SysTenantMenu::insert(model).exec(db).await?;
                SysTenantMenu::find_by_id(l3_id)
                    .one(db)
                    .await?
                    .ok_or_else(|| {
                        DbErr::RecordNotFound("sys_tenant_menu 插入后按主键回查失败".to_string())
                    })
            }
            _ => SysTenantMenu::insert(model).exec_with_returning(db).await,
        }
    }

    /// 更新一条 L3 行
    pub async fn update(
        &self,
        model: crate::entity::sys_tenant_menu::ActiveModel,
    ) -> Result<Model, DbErr> {
        self.base.update(model).await
    }

    /// 软删（del_flag='2'，并记录 update_by / update_time）
    pub async fn soft_delete(&self, l3_id: i64, operator: &str) -> Result<u64, DbErr> {
        let res = SysTenantMenu::update_many()
            .col_expr(Column::DelFlag, Expr::value("2"))
            .col_expr(Column::UpdateBy, Expr::value(operator))
            .col_expr(
                Column::UpdateTime,
                Expr::value(crate::common::datetime::now_naive()),
            )
            .filter(Column::L3Id.eq(l3_id))
            .filter(Column::DelFlag.eq("0"))
            .exec(self.base.db())
            .await?;
        Ok(res.rows_affected)
    }
}
