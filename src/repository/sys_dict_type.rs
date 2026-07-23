// axum-backend/src/repository/sys_dict_type.rs
//! sys_dict_type 数据访问层（字典类型表）
//!
//! 继承 BaseRepository 通用 CRUD，扩展字典类型特有查询：
//! - 按 dict_type 查询（唯一约束）
//! - 软删除过滤（del_flag = '0'）
//! - 软删除操作（del_flag = '2'）

use chrono::NaiveDateTime;
use sea_orm::*;
use sea_orm::sea_query::Expr;

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

    /// 按 dict_type 查询（唯一约束，用于获取字典类型详情）
    pub async fn find_by_dict_type(&self, dict_type: &str) -> Result<Option<Model>, DbErr> {
        SysDictType::find()
            .filter(Column::DictType.eq(dict_type))
            .filter(Column::DelFlag.eq("0"))
            .one(self.base.db())
            .await
    }

    /// 查询所有未删除字典类型（del_flag = '0'）
    pub async fn find_active_all(&self) -> Result<Vec<Model>, DbErr> {
        SysDictType::find()
            .filter(Column::DelFlag.eq("0"))
            .all(self.base.db())
            .await
    }

    /// 分页查询未删除字典类型
    pub async fn find_active_page(
        &self,
        offset: u64,
        limit: u64,
    ) -> Result<(Vec<Model>, u64), DbErr> {
        let total = SysDictType::find()
            .filter(Column::DelFlag.eq("0"))
            .count(self.base.db())
            .await?;
        let rows = SysDictType::find()
            .filter(Column::DelFlag.eq("0"))
            .offset(offset)
            .limit(limit)
            .all(self.base.db())
            .await?;
        Ok((rows, total))
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
            .filter(Column::DictId.is_in(dict_ids.iter().copied().collect::<Vec<i64>>()))
            .filter(Column::DelFlag.eq("0"))
            .all(self.base.db())
            .await
    }

    /// 多条件分页查询（dict_name 模糊，dict_type 模糊，status 精确，时间范围）
    #[allow(clippy::too_many_arguments)]
    pub async fn find_page_filtered(
        &self,
        offset: u64,
        limit: u64,
        dict_name: Option<&str>,
        dict_type: Option<&str>,
        status: Option<&str>,
        begin_time: Option<NaiveDateTime>,
        end_time: Option<NaiveDateTime>,
    ) -> Result<(Vec<Model>, u64), DbErr> {
        let mut query = SysDictType::find().filter(Column::DelFlag.eq("0"));
        if let Some(name) = dict_name {
            query = query.filter(Column::DictName.like(format!("%{}%", like_escape(name))));
        }
        if let Some(dt) = dict_type {
            query = query.filter(Column::DictType.like(format!("%{}%", like_escape(dt))));
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
