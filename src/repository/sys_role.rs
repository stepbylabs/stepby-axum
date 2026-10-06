// stepby-axum/src/repository/sys_role.rs
//! sys_role 数据访问层
//!
//! 继承 BaseRepository 通用 CRUD，扩展角色特有查询：
//! - 按用户 ID 查询角色（关联 sys_user_role）
//! - 按 role_key 查询
//! - 软删除过滤（del_flag = '0'）
//! - 软删除操作（del_flag = '2'）

use chrono::NaiveDateTime;
use sea_orm::sea_query::Expr;
use sea_orm::*;

use crate::common::like_escape;
use crate::common::sort::SortOrder;
use crate::entity::sys_role::{ActiveModel, Column, Entity as SysRole, Model};
use crate::entity::sys_user_role::{Column as UserRoleColumn, Entity as SysUserRole};
use crate::repository::base::BaseRepository;

/// 角色 Repository
#[derive(Clone)]
pub struct SysRoleRepository {
    base: BaseRepository<SysRole>,
}

impl SysRoleRepository {
    pub fn new(db: DatabaseConnection) -> Self {
        Self {
            base: BaseRepository::new(db),
        }
    }

    pub fn base(&self) -> &BaseRepository<SysRole> {
        &self.base
    }

    /// 查询未删除角色（del_flag = '0'）。
    ///
    /// 多租户：`tenant_scope = Some(tid)` → 仅本租户角色（`tenant_id = tid`）；
    /// `None`（平台操作者）→ 全量不过滤。
    pub async fn find_active_all(&self, tenant_scope: Option<i64>) -> Result<Vec<Model>, DbErr> {
        let mut query = SysRole::find().filter(Column::DelFlag.eq("0"));
        if let Some(tid) = tenant_scope {
            query = query.filter(Column::TenantId.eq(tid));
        }
        query.all(self.base.db()).await
    }

    /// 按 role_id 列表批量查询未删除角色（P0-R81-005 用于校验待分配角色层级）
    pub async fn find_by_ids(&self, role_ids: &[i64]) -> Result<Vec<Model>, DbErr> {
        if role_ids.is_empty() {
            return Ok(vec![]);
        }
        SysRole::find()
            .filter(Column::RoleId.is_in(role_ids.to_vec()))
            .filter(Column::DelFlag.eq("0"))
            .all(self.base.db())
            .await
    }

    /// 按 role_key 在**指定租户内**查询（台账 P0-3：与唯一索引
    /// `uk_sys_role_tenant_key (tenant_id, role_key)` 语义对齐）。
    ///
    /// 管理面键租户内唯一（§27 原则 A）：不同租户可存在同名 role_key，
    /// 故写路径的查重范围必须是角色归属租户，而非全局。
    pub async fn find_by_role_key_in_tenant(
        &self,
        role_key: &str,
        tenant_id: i64,
    ) -> Result<Option<Model>, DbErr> {
        SysRole::find()
            .filter(Column::RoleKey.eq(role_key))
            .filter(Column::TenantId.eq(tenant_id))
            .filter(Column::DelFlag.eq("0"))
            .one(self.base.db())
            .await
    }

    /// 按用户 ID 查询其所有未删除且未停用的角色
    /// 通过 sys_user_role 关联表查询
    ///
    /// 过滤 status='1'（停用）的角色：角色被禁用后，用户不应再使用该角色的权限（P0-43）
    pub async fn find_by_user_id(&self, user_id: i64) -> Result<Vec<Model>, DbErr> {
        // 先查用户角色关联表，获取 role_id 列表
        let user_roles: Vec<i64> = SysUserRole::find()
            .filter(UserRoleColumn::UserId.eq(user_id))
            .all(self.base.db())
            .await?
            .into_iter()
            .map(|ur| ur.role_id)
            .collect();

        if user_roles.is_empty() {
            return Ok(vec![]);
        }

        // 再查角色表，过滤已删除和已停用的角色
        SysRole::find()
            .filter(Column::RoleId.is_in(user_roles))
            .filter(Column::DelFlag.eq("0"))
            .filter(Column::Status.eq("0"))
            .all(self.base.db())
            .await
    }

    /// 角色下拉选项查询（启用 + 未删 + 租户行级过滤，按 role_sort 排序）
    ///
    /// 供 `GET /system/role/optionselect`（数据权限规则页角色下拉等场景）。
    pub async fn find_all_enabled(&self, tenant_scope: Option<i64>) -> Result<Vec<Model>, DbErr> {
        let mut query = SysRole::find()
            .filter(Column::DelFlag.eq("0"))
            .filter(Column::Status.eq("0"));
        if let Some(t) = tenant_scope {
            query = query.filter(Column::TenantId.eq(t));
        }
        query.order_by_asc(Column::RoleSort).all(self.base.db()).await
    }

    /// 软删除角色
    pub async fn soft_delete(&self, role_id: i64) -> Result<UpdateResult, DbErr> {
        SysRole::update_many()
            .col_expr(Column::DelFlag, Expr::value("2"))
            .filter(Column::RoleId.eq(role_id))
            .exec(self.base.db())
            .await
    }

    /// 插入角色
    pub async fn insert(&self, model: ActiveModel) -> Result<Model, DbErr> {
        self.base.insert(model).await
    }

    /// 更新角色
    pub async fn update(&self, model: ActiveModel) -> Result<Model, DbErr> {
        self.base.update(model).await
    }

    /// 多条件分页查询（role_name 模糊，role_key 模糊，status 精确，时间范围）
    #[allow(clippy::too_many_arguments)]
    pub async fn find_page_filtered(
        &self,
        offset: u64,
        limit: u64,
        role_name: Option<&str>,
        role_key: Option<&str>,
        status: Option<&str>,
        begin_time: Option<NaiveDateTime>,
        end_time: Option<NaiveDateTime>,
        tenant_scope: Option<i64>,
    ) -> Result<(Vec<Model>, u64), DbErr> {
        let mut query = SysRole::find().filter(Column::DelFlag.eq("0"));
        if let Some(t) = tenant_scope {
            query = query.filter(Column::TenantId.eq(t));
        }
        if let Some(name) = role_name {
            query = query.filter(Column::RoleName.like(format!("%{}%", like_escape(name))));
        }
        if let Some(key) = role_key {
            query = query.filter(Column::RoleKey.like(format!("%{}%", like_escape(key))));
        }
        if let Some(st) = status {
            query = query.filter(Column::Status.eq(st));
        }
        if let Some(begin) = begin_time {
            query = query.filter(Column::CreateTime.gte(begin));
        }
        if let Some(end) = end_time {
            query = query.filter(Column::CreateTime.lte(end));
        }

        let total = query.clone().count(self.base.db()).await?;
        let rows = query
            .order_by_asc(Column::RoleSort)
            .offset(offset)
            .limit(limit)
            .all(self.base.db())
            .await?;
        Ok((rows, total))
    }

    /// 多条件分页查询 + data_scope 数据权限过滤（P0-R81-004）
    ///
    /// 在 find_page_filtered 基础上追加：
    /// - scope_role_ids: Some 时限定 role_id 在此集合内（用于 data_scope=5 仅本人角色）
    ///   - Some(空): 不可见任何角色 → 返回空结果
    ///   - Some(非空): 限定 role_id IN 集合
    ///   - None: 不追加过滤（data_scope=1 全部）
    ///
    /// `sort`：动态排序（方案 B，白名单已在 service 层解析为 `SortOrder`）；
    /// `None` 时回退默认 `role_sort ASC`。
    #[allow(clippy::too_many_arguments)]
    pub async fn find_page_with_data_scope(
        &self,
        offset: u64,
        limit: u64,
        role_name: Option<&str>,
        role_key: Option<&str>,
        status: Option<&str>,
        scope_role_ids: Option<&[i64]>,
        begin_time: Option<NaiveDateTime>,
        end_time: Option<NaiveDateTime>,
        tenant_scope: Option<i64>,
        sort: Option<SortOrder<Column>>,
    ) -> Result<(Vec<Model>, u64), DbErr> {
        let mut query = SysRole::find().filter(Column::DelFlag.eq("0"));
        // 多租户 Phase 2：租户用户仅见本租户角色；平台 0 不过滤
        if let Some(t) = tenant_scope {
            query = query.filter(Column::TenantId.eq(t));
        }
        if let Some(name) = role_name {
            query = query.filter(Column::RoleName.like(format!("%{}%", like_escape(name))));
        }
        if let Some(key) = role_key {
            query = query.filter(Column::RoleKey.like(format!("%{}%", like_escape(key))));
        }
        if let Some(st) = status {
            query = query.filter(Column::Status.eq(st));
        }
        match scope_role_ids {
            Some([]) => {
                // 空集合：无可见角色，返回空结果（用永假条件）
                query = query.filter(Column::RoleId.eq(-1_i64));
            }
            Some(ids) => {
                query = query.filter(Column::RoleId.is_in(ids.to_vec()));
            }
            None => {}
        }
        if let Some(begin) = begin_time {
            query = query.filter(Column::CreateTime.gte(begin));
        }
        if let Some(end) = end_time {
            query = query.filter(Column::CreateTime.lte(end));
        }

        let total = query.clone().count(self.base.db()).await?;
        // 动态排序（白名单已解析）或默认 role_sort ASC（角色列表惯例，排序号小的在前）
        let rows = match sort {
            Some(s) => query.order_by(s.column, s.dir),
            None => query.order_by_asc(Column::RoleSort),
        }
        .offset(offset)
        .limit(limit)
        .all(self.base.db())
        .await?;
        Ok((rows, total))
    }
}
