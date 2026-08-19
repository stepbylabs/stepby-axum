// axum-backend/src/repository/sys_report_sub.rs
//! sys_report_sub 数据访问层（报表订阅表）
//!
//! 继承 BaseRepository 通用 CRUD，扩展订阅特有查询：
//! - 按 sub_id / report_id 查询
//! - 分页查询（report_id/sub_name/status 过滤）
//! - 查询某报表下的订阅列表（下拉/级联）
//! - 查询全部启用订阅（供定时推送扫描）
//! - 按 ID 列表物理/逻辑删除
//! - 更新 last_run_time
//! - 级联删除某报表的所有订阅

use sea_orm::sea_query::Expr;
use sea_orm::*;

use crate::common::like_escape;
use crate::entity::sys_report_sub::{ActiveModel, Column, Entity as SysReportSub, Model};
use crate::repository::base::BaseRepository;

/// 报表订阅 Repository
#[derive(Clone)]
pub struct SysReportSubRepository {
    base: BaseRepository<SysReportSub>,
}

impl SysReportSubRepository {
    pub fn new(db: DatabaseConnection) -> Self {
        Self {
            base: BaseRepository::new(db),
        }
    }

    pub fn base(&self) -> &BaseRepository<SysReportSub> {
        &self.base
    }

    /// 按 sub_id 查询订阅（未删除）
    pub async fn find_by_id(&self, sub_id: i64) -> Result<Option<Model>, DbErr> {
        SysReportSub::find()
            .filter(Column::SubId.eq(sub_id))
            .filter(Column::DelFlag.ne("2"))
            .one(self.base.db())
            .await
    }

    /// 查询某报表下的全部订阅（未删除）
    pub async fn find_by_report_id(&self, report_id: i64) -> Result<Vec<Model>, DbErr> {
        SysReportSub::find()
            .filter(Column::ReportId.eq(report_id))
            .filter(Column::DelFlag.ne("2"))
            .order_by_asc(Column::SubId)
            .all(self.base.db())
            .await
    }

    /// 查询全部启用订阅（status='0' 且未删除），供定时推送扫描
    pub async fn find_all_enabled(&self) -> Result<Vec<Model>, DbErr> {
        SysReportSub::find()
            .filter(Column::Status.eq("0"))
            .filter(Column::DelFlag.ne("2"))
            .order_by_asc(Column::SubId)
            .all(self.base.db())
            .await
    }

    /// 分页查询订阅（report_id/sub_name/status 过滤）
    #[allow(clippy::too_many_arguments)]
    pub async fn find_page_filtered(
        &self,
        offset: u64,
        limit: u64,
        report_id: Option<i64>,
        sub_name: Option<&str>,
        status: Option<&str>,
    ) -> Result<(Vec<Model>, u64), DbErr> {
        let mut query = SysReportSub::find();
        query = query.filter(Column::DelFlag.ne("2"));
        if let Some(rid) = report_id {
            query = query.filter(Column::ReportId.eq(rid));
        }
        if let Some(name) = sub_name {
            query = query.filter(Column::SubName.like(format!("%{}%", like_escape(name))));
        }
        if let Some(st) = status {
            query = query.filter(Column::Status.eq(st));
        }
        query = query.order_by_asc(Column::SubId);

        let total = query.clone().count(self.base.db()).await?;
        let rows = query
            .offset(offset)
            .limit(limit)
            .all(self.base.db())
            .await?;
        Ok((rows, total))
    }

    /// 按 ID 列表查询订阅（用于删除前校验）
    pub async fn find_by_ids(&self, sub_ids: &[i64]) -> Result<Vec<Model>, DbErr> {
        if sub_ids.is_empty() {
            return Ok(Vec::new());
        }
        SysReportSub::find()
            .filter(Column::SubId.is_in(sub_ids.to_vec()))
            .filter(Column::DelFlag.ne("2"))
            .all(self.base.db())
            .await
    }

    /// 按 ID 列表物理删除
    pub async fn delete_by_ids(&self, sub_ids: Vec<i64>) -> Result<DeleteResult, DbErr> {
        SysReportSub::delete_many()
            .filter(Column::SubId.is_in(sub_ids))
            .exec(self.base.db())
            .await
    }

    /// 按 ID 列表逻辑删除（del_flag='2'）
    pub async fn soft_delete_by_ids(&self, sub_ids: &[i64]) -> Result<UpdateResult, DbErr> {
        SysReportSub::update_many()
            .col_expr(Column::DelFlag, Expr::value("2"))
            .filter(Column::SubId.is_in(sub_ids.to_vec()))
            .exec(self.base.db())
            .await
    }

    /// 级联逻辑删除某报表下的全部订阅（删除报表时调用）
    pub async fn soft_delete_by_report_id(&self, report_id: i64) -> Result<UpdateResult, DbErr> {
        SysReportSub::update_many()
            .col_expr(Column::DelFlag, Expr::value("2"))
            .filter(Column::ReportId.eq(report_id))
            .exec(self.base.db())
            .await
    }

    /// 更新 last_run_time（定时推送成功后调用）
    pub async fn update_last_run_time(
        &self,
        sub_id: i64,
        last_run_time: chrono::NaiveDateTime,
    ) -> Result<UpdateResult, DbErr> {
        SysReportSub::update_many()
            .col_expr(Column::LastRunTime, Expr::value(last_run_time))
            .filter(Column::SubId.eq(sub_id))
            .exec(self.base.db())
            .await
    }

    /// 插入订阅
    pub async fn insert(&self, model: ActiveModel) -> Result<Model, DbErr> {
        self.base.insert(model).await
    }

    /// 更新订阅
    pub async fn update(&self, model: ActiveModel) -> Result<Model, DbErr> {
        self.base.update(model).await
    }
}
