// stepby-axum/src/repository/sys_dict_type.rs
//! sys_dict_type 数据访问层（字典类型表）
//!
//! 继承 BaseRepository 通用 CRUD，扩展字典类型特有查询：
//! - 按 dict_type 查询（唯一约束）
//! - 软删除过滤（del_flag = '0'）
//! - 软删除操作（del_flag = '2'）

use chrono::NaiveDateTime;
use sea_orm::sea_query::Expr;
use sea_orm::*;

use crate::common::like_escape;
use crate::entity::sys_dict_type::{ActiveModel, Column, Entity as SysDictType, Model};
use crate::repository::base::BaseRepository;

/// 字典类型 Repository
#[derive(Clone)]
pub struct SysDictTypeRepository {
    base: BaseRepository<SysDictType>,
}

impl SysDictTypeRepository {
    pub fn new(db: DatabaseConnection) -> Self {
        Self {
            base: BaseRepository::new(db),
        }
    }

    pub fn base(&self) -> &BaseRepository<SysDictType> {
        &self.base
    }

    /// 按 (tenant_id, dict_type) 查询单行（复合唯一域 `uk_sys_dict_type_tenant`）。
    ///
    /// 用于精确定位某一层（平台 `tenant_id=0` 或某租户）的字典类型。
    pub async fn find_by_tenant_dict_type(
        &self,
        tenant_id: i64,
        dict_type: &str,
    ) -> Result<Option<Model>, DbErr> {
        SysDictType::find()
            .filter(Column::TenantId.eq(tenant_id))
            .filter(Column::DictType.eq(dict_type))
            .filter(Column::DelFlag.eq("0"))
            .one(self.base.db())
            .await
    }

    /// 按 dict_type 查询平台行（`tenant_id = 0`）——平台层类型查询入口。
    pub async fn find_platform_by_dict_type(
        &self,
        dict_type: &str,
    ) -> Result<Option<Model>, DbErr> {
        self.find_by_tenant_dict_type(0, dict_type).await
    }

    /// **生效类型查询**：租户自建类型（`tenant_id = tid`）优先，无则回落平台类型（`tenant_id = 0`）。
    ///
    /// - `tenant_scope = None / Some(0)`：只读平台层；
    /// - `tenant_scope = Some(tid)`（tid≠0）：`tenant_id IN (0, tid)`，按 tenant_id 降序取首行。
    ///
    /// 这是 dict_type 的**唯一**按名生效读取入口，不存在"只按 dict_type 查、无租户条件"的路径。
    pub async fn find_effective_by_dict_type(
        &self,
        dict_type: &str,
        tenant_scope: Option<i64>,
    ) -> Result<Option<Model>, DbErr> {
        match tenant_scope.filter(|t| *t != 0) {
            Some(tid) => {
                SysDictType::find()
                    .filter(Column::DictType.eq(dict_type))
                    .filter(Column::TenantId.is_in([0i64, tid]))
                    .filter(Column::DelFlag.eq("0"))
                    .order_by_desc(Column::TenantId)
                    .one(self.base.db())
                    .await
            }
            None => self.find_platform_by_dict_type(dict_type).await,
        }
    }

    /// 查询未删除字典类型（`del_flag = '0'`）。
    ///
    /// 多租户：`tenant_scope = Some(tid)` → 本租户自建类型 + 平台类型（`tenant_id IN (0, tid)`）；
    /// `None`（平台操作者）→ 全量不过滤。
    pub async fn find_active_all(&self, tenant_scope: Option<i64>) -> Result<Vec<Model>, DbErr> {
        let mut query = SysDictType::find().filter(Column::DelFlag.eq("0"));
        if let Some(tid) = tenant_scope {
            query = query.filter(Column::TenantId.is_in([0i64, tid]));
        }
        query.all(self.base.db()).await
    }

    /// 软删除字典类型
    pub async fn soft_delete(&self, dict_id: i64) -> Result<UpdateResult, DbErr> {
        SysDictType::update_many()
            .col_expr(Column::DelFlag, Expr::value("2"))
            .filter(Column::DictId.eq(dict_id))
            .exec(self.base.db())
            .await
    }

    /// 插入字典类型
    pub async fn insert(&self, model: ActiveModel) -> Result<Model, DbErr> {
        self.base.insert(model).await
    }

    /// 更新字典类型
    pub async fn update(&self, model: ActiveModel) -> Result<Model, DbErr> {
        self.base.update(model).await
    }

    /// 按 dict_id 查询未删除字典类型
    pub async fn find_active_by_id(&self, dict_id: i64) -> Result<Option<Model>, DbErr> {
        SysDictType::find()
            .filter(Column::DictId.eq(dict_id))
            .filter(Column::DelFlag.eq("0"))
            .one(self.base.db())
            .await
    }

    /// 按 dict_id 列表批量查询未删除字典类型（单次 SELECT，替代循环 N 次）
    pub async fn find_active_by_ids(&self, dict_ids: &[i64]) -> Result<Vec<Model>, DbErr> {
        if dict_ids.is_empty() {
            return Ok(Vec::new());
        }
        SysDictType::find()
            .filter(Column::DictId.is_in(dict_ids.to_vec()))
            .filter(Column::DelFlag.eq("0"))
            .all(self.base.db())
            .await
    }

    /// 多条件分页查询（dict_name 模糊，dict_type 模糊，status 精确，时间范围）
    ///
    /// 多租户：`tenant_scope = Some(tid)` → 本租户自建类型 + 平台类型（`tenant_id IN (0, tid)`）；
    /// `None`（平台操作者）→ 全量不过滤。
    #[allow(clippy::too_many_arguments)]
    pub async fn find_page_filtered(
        &self,
        offset: u64,
        limit: u64,
        tenant_scope: Option<i64>,
        dict_name: Option<&str>,
        dict_type: Option<&str>,
        status: Option<&str>,
        begin_time: Option<NaiveDateTime>,
        end_time: Option<NaiveDateTime>,
    ) -> Result<(Vec<Model>, u64), DbErr> {
        let mut query = SysDictType::find().filter(Column::DelFlag.eq("0"));
        if let Some(tid) = tenant_scope {
            query = query.filter(Column::TenantId.is_in([0i64, tid]));
        }
        if let Some(name) = dict_name {
            query = query.filter(Column::DictName.like(format!("%{}%", like_escape(name))));
        }
        if let Some(dt) = dict_type {
            query = query.filter(Column::DictType.like(format!("%{}%", like_escape(dt))));
        }
        if let Some(st) = status {
            query = query.filter(Column::Status.eq(st));
        }
        // P1：稳定排序，防翻页重复/漏行
        query = query.order_by_asc(Column::DictId);
        if let Some(begin) = begin_time {
            query = query.filter(Column::CreateTime.gte(begin));
        }
        if let Some(end) = end_time {
            query = query.filter(Column::CreateTime.lte(end));
        }

        let total = query.clone().count(self.base.db()).await?;
        let rows = query
            .offset(offset)
            .limit(limit)
            .all(self.base.db())
            .await?;
        Ok((rows, total))
    }

    /// 软删除字典类型（事务上下文）
    pub async fn soft_delete_conn<C: ConnectionTrait>(
        &self,
        conn: &C,
        dict_id: i64,
    ) -> Result<UpdateResult, DbErr> {
        SysDictType::update_many()
            .col_expr(Column::DelFlag, Expr::value("2"))
            .filter(Column::DictId.eq(dict_id))
            .exec(conn)
            .await
    }

    /// 软删除字典类型并重命名 dict_type（REGRESS-003：释放唯一索引 uk_sys_dict_type）
    ///
    /// 软删除记录仍占用 dict_type 唯一索引，导致无法重新创建同 dict_type。
    /// 在同一 UPDATE 中将 dict_type 改为 `{original}_deleted_{dict_id}`，避免冲突。
    pub async fn soft_delete_with_rename_conn<C: ConnectionTrait>(
        &self,
        conn: &C,
        dict_id: i64,
        new_dict_type: String,
    ) -> Result<UpdateResult, DbErr> {
        SysDictType::update_many()
            .col_expr(Column::DelFlag, Expr::value("2"))
            .col_expr(Column::DictType, Expr::value(new_dict_type))
            .filter(Column::DictId.eq(dict_id))
            .exec(conn)
            .await
    }
}
