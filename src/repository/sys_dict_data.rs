// axum-backend/src/repository/sys_dict_data.rs
//! sys_dict_data 数据访问层（字典数据表）
//!
//! 继承 BaseRepository 通用 CRUD，扩展字典数据特有查询：
//! - 按 dict_type 查询所有字典数据（前端字典下拉用）
//! - 软删除过滤（del_flag = '0'）
//! - 软删除操作（del_flag = '2'）

use sea_orm::*;
use sea_orm::sea_query::Expr;

use crate::common::like_escape;
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

    /// 按 dict_type 查询所有未删除字典数据（前端字典下拉用）
    pub async fn find_by_dict_type(&self, dict_type: &str) -> Result<Vec<Model>, DbErr> {
        SysDictData::find()
            .filter(Column::DictType.eq(dict_type))
            .filter(Column::DelFlag.eq("0"))
            .all(self.base.db())
            .await
    }

    /// 查询所有未删除字典数据
    pub async fn find_active_all(&self) -> Result<Vec<Model>, DbErr> {
        SysDictData::find()
            .filter(Column::DelFlag.eq("0"))
            .all(self.base.db())
            .await
    }

    /// 分页查询未删除字典数据
    pub async fn find_active_page(
        &self,
        offset: u64,
        limit: u64,
    ) -> Result<(Vec<Model>, u64), DbErr> {
        let total = SysDictData::find()
            .filter(Column::DelFlag.eq("0"))
            .count(self.base.db())
            .await?;
        let rows = SysDictData::find()
            .filter(Column::DelFlag.eq("0"))
            .offset(offset)
            .limit(limit)
            .all(self.base.db())
            .await?;
        Ok((rows, total))
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
            .filter(Column::DictCode.is_in(dict_codes.iter().copied().collect::<Vec<i64>>()))
            .filter(Column::DelFlag.eq("0"))
            .all(self.base.db())
            .await
    }

    /// 按 dict_type 查询正常状态字典数据（前端下拉用，status='0'，按 dict_sort 排序）
    pub async fn find_active_by_dict_type(&self, dict_type: &str) -> Result<Vec<Model>, DbErr> {
        SysDictData::find()
            .filter(Column::DictType.eq(dict_type))
            .filter(Column::DelFlag.eq("0"))
            .filter(Column::Status.eq("0"))
            .order_by_asc(Column::DictSort)
            .all(self.base.db())
            .await
    }

    /// 多条件分页查询（dict_type 精确，dict_label 模糊，status 精确）
    pub async fn find_page_filtered(
        &self,
        offset: u64,
        limit: u64,
        dict_type: Option<&str>,
        dict_label: Option<&str>,
        status: Option<&str>,
    ) -> Result<(Vec<Model>, u64), DbErr> {
        let mut query = SysDictData::find().filter(Column::DelFlag.eq("0"));
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
        let rows = query
            .order_by_asc(Column::DictSort)
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

    /// 按 dict_type 批量更新字典数据的 dict_type 字段（事务上下文，用于字典类型变更时级联同步）
    pub async fn update_dict_type_conn<C: ConnectionTrait>(
        &self,
        conn: &C,
        old_dict_type: &str,
        new_dict_type: &str,
    ) -> Result<UpdateResult, DbErr> {
        SysDictData::update_many()
            .col_expr(Column::DictType, Expr::value(new_dict_type))
            .filter(Column::DictType.eq(old_dict_type))
            .filter(Column::DelFlag.eq("0"))
            .exec(conn)
            .await
    }

    /// 按 dict_type 批量软删除字典数据（事务上下文，用于删除字典类型时级联删除）
    pub async fn soft_delete_by_dict_type_conn<C: ConnectionTrait>(
        &self,
        conn: &C,
        dict_type: &str,
    ) -> Result<UpdateResult, DbErr> {
        SysDictData::update_many()
            .col_expr(Column::DelFlag, Expr::value("2"))
            .filter(Column::DictType.eq(dict_type))
            .filter(Column::DelFlag.eq("0"))
            .exec(conn)
            .await
    }
}
