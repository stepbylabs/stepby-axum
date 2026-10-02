// stepby-axum/src/repository/sys_dict_data.rs
//! sys_dict_data 数据访问层（字典数据表）
//!
//! 继承 BaseRepository 通用 CRUD，扩展字典数据特有查询：
//! - 按 dict_type 查询所有字典数据（前端字典下拉用）
//! - 软删除过滤（del_flag = '0'）
//! - 软删除操作（del_flag = '2'）

use sea_orm::sea_query::Expr;
use sea_orm::*;

use crate::common::like_escape;
use crate::common::sort::SortOrder;
use crate::entity::sys_dict_data::{ActiveModel, Column, Entity as SysDictData, Model};
use crate::repository::base::BaseRepository;

/// 字典数据 Repository
#[derive(Clone)]
pub struct SysDictDataRepository {
    base: BaseRepository<SysDictData>,
}

impl SysDictDataRepository {
    pub fn new(db: DatabaseConnection) -> Self {
        Self {
            base: BaseRepository::new(db),
        }
    }

    pub fn base(&self) -> &BaseRepository<SysDictData> {
        &self.base
    }

    /// 按 (tenant_id, dict_type) 查询未删除字典数据（指定归属层）。
    ///
    /// 多租户：字典数据按**类型归属层**隔离——平台类型的数据 `tenant_id=0`，
    /// 租户自建类型的数据 `tenant_id=租户 ID`，不存在跨层混读。
    pub async fn find_by_tenant_dict_type(
        &self,
        tenant_id: i64,
        dict_type: &str,
    ) -> Result<Vec<Model>, DbErr> {
        SysDictData::find()
            .filter(Column::TenantId.eq(tenant_id))
            .filter(Column::DictType.eq(dict_type))
            .filter(Column::DelFlag.eq("0"))
            .all(self.base.db())
            .await
    }

    /// 软删除字典数据
    pub async fn soft_delete(&self, dict_code: i64) -> Result<UpdateResult, DbErr> {
        SysDictData::update_many()
            .col_expr(Column::DelFlag, Expr::value("2"))
            .filter(Column::DictCode.eq(dict_code))
            .exec(self.base.db())
            .await
    }

    /// 按 dict_code 列表批量软删除字典数据（单次 UPDATE，替代循环 N 次）
    pub async fn soft_delete_many(&self, dict_codes: Vec<i64>) -> Result<UpdateResult, DbErr> {
        if dict_codes.is_empty() {
            return Ok(UpdateResult::default());
        }
        SysDictData::update_many()
            .col_expr(Column::DelFlag, Expr::value("2"))
            .filter(Column::DictCode.is_in(dict_codes))
            .exec(self.base.db())
            .await
    }

    /// 插入字典数据
    pub async fn insert(&self, model: ActiveModel) -> Result<Model, DbErr> {
        self.base.insert(model).await
    }

    /// 更新字典数据
    pub async fn update(&self, model: ActiveModel) -> Result<Model, DbErr> {
        self.base.update(model).await
    }

    /// 按 dict_code 查询未删除字典数据
    pub async fn find_active_by_id(&self, dict_code: i64) -> Result<Option<Model>, DbErr> {
        SysDictData::find()
            .filter(Column::DictCode.eq(dict_code))
            .filter(Column::DelFlag.eq("0"))
            .one(self.base.db())
            .await
    }

    /// 按 dict_code 列表批量查询未删除字典数据（单次 SELECT，替代循环 N 次）
    pub async fn find_active_by_ids(&self, dict_codes: &[i64]) -> Result<Vec<Model>, DbErr> {
        if dict_codes.is_empty() {
            return Ok(Vec::new());
        }
        SysDictData::find()
            .filter(Column::DictCode.is_in(dict_codes.to_vec()))
            .filter(Column::DelFlag.eq("0"))
            .all(self.base.db())
            .await
    }

    /// 按 dict_type 查询正常状态字典数据（指定归属层，status='0'，按 dict_sort 排序）
    ///
    /// 多租户：`tenant_id` 为**类型归属层**（平台类型=0 / 租户自建类型=租户 ID），
    /// 由调用方先解析生效类型的归属层再传入，避免跨层混读。
    pub async fn find_active_by_dict_type_in_tenant(
        &self,
        tenant_id: i64,
        dict_type: &str,
    ) -> Result<Vec<Model>, DbErr> {
        SysDictData::find()
            .filter(Column::TenantId.eq(tenant_id))
            .filter(Column::DictType.eq(dict_type))
            .filter(Column::DelFlag.eq("0"))
            .filter(Column::Status.eq("0"))
            .order_by_asc(Column::DictSort)
            .all(self.base.db())
            .await
    }

    /// 多条件分页查询（dict_type 精确，dict_label 模糊，status 精确）
    ///
    /// 多租户：`tenant_scope = Some(tid)` → `tenant_id IN (0, tid)`（平台类型数据 + 本租户自建类型数据）；
    /// `None`（平台操作者）→ 全量不过滤。
    ///
    /// `sort`：动态排序（方案 B，白名单已在 service 层解析为 `SortOrder`）；
    /// `None` 时回退默认 `dict_sort ASC`（原排序语义不变）。
    pub async fn find_page_filtered(
        &self,
        offset: u64,
        limit: u64,
        tenant_scope: Option<i64>,
        dict_type: Option<&str>,
        dict_label: Option<&str>,
        status: Option<&str>,
        sort: Option<SortOrder<Column>>,
    ) -> Result<(Vec<Model>, u64), DbErr> {
        let mut query = SysDictData::find().filter(Column::DelFlag.eq("0"));
        if let Some(tid) = tenant_scope {
            query = query.filter(Column::TenantId.is_in([0i64, tid]));
        }
        if let Some(dt) = dict_type {
            query = query.filter(Column::DictType.eq(dt));
        }
        if let Some(label) = dict_label {
            query = query.filter(Column::DictLabel.like(format!("%{}%", like_escape(label))));
        }
        if let Some(st) = status {
            query = query.filter(Column::Status.eq(st));
        }

        let total = query.clone().count(self.base.db()).await?;
        let rows = match sort {
            Some(s) => query.order_by(s.column, s.dir),
            None => query.order_by_asc(Column::DictSort),
        }
        .offset(offset)
        .limit(limit)
        .all(self.base.db())
        .await?;
        Ok((rows, total))
    }

    /// 软删除字典数据（事务上下文）
    pub async fn soft_delete_conn<C: ConnectionTrait>(
        &self,
        conn: &C,
        dict_code: i64,
    ) -> Result<UpdateResult, DbErr> {
        SysDictData::update_many()
            .col_expr(Column::DelFlag, Expr::value("2"))
            .filter(Column::DictCode.eq(dict_code))
            .exec(conn)
            .await
    }

    /// 按 (tenant_id, dict_type) 批量更新字典数据的 dict_type（事务上下文，用于字典类型变更时级联同步）
    ///
    /// 多租户：必须带 `tenant_id` 归属层条件，否则会误改其它租户的同名自建类型数据。
    pub async fn update_dict_type_conn<C: ConnectionTrait>(
        &self,
        conn: &C,
        tenant_id: i64,
        old_dict_type: &str,
        new_dict_type: &str,
    ) -> Result<UpdateResult, DbErr> {
        SysDictData::update_many()
            .col_expr(Column::DictType, Expr::value(new_dict_type))
            .filter(Column::TenantId.eq(tenant_id))
            .filter(Column::DictType.eq(old_dict_type))
            .filter(Column::DelFlag.eq("0"))
            .exec(conn)
            .await
    }

    /// 按 (tenant_id, dict_type) 批量软删除字典数据（事务上下文，用于删除字典类型时级联删除）
    ///
    /// 多租户：同样必须带 `tenant_id` 归属层条件，避免误删其它租户同名类型数据。
    pub async fn soft_delete_by_dict_type_conn<C: ConnectionTrait>(
        &self,
        conn: &C,
        tenant_id: i64,
        dict_type: &str,
    ) -> Result<UpdateResult, DbErr> {
        SysDictData::update_many()
            .col_expr(Column::DelFlag, Expr::value("2"))
            .filter(Column::TenantId.eq(tenant_id))
            .filter(Column::DictType.eq(dict_type))
            .filter(Column::DelFlag.eq("0"))
            .exec(conn)
            .await
    }
}
