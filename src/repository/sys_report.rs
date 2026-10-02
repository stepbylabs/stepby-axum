// stepby-axum/src/repository/sys_report.rs
//! sys_report 数据访问层（报表定义表）
//!
//! 继承 BaseRepository 通用 CRUD，扩展报表特有查询：
//! - 按 report_id / report_code 查询
//! - 按 report_code 判断唯一性
//! - 分页查询（name/code/type/status 过滤）
//! - 查询所有启用报表（供订阅推送与下拉选择）
//! - 按 ID 列表物理删除 / 逻辑删除（del_flag='2'）

use sea_orm::*;

use crate::common::like_escape;
use crate::common::sort::SortOrder;
use crate::entity::sys_report::{ActiveModel, Column, Entity as SysReport, Model};
use crate::repository::base::BaseRepository;

/// 报表 Repository
#[derive(Clone)]
pub struct SysReportRepository {
    base: BaseRepository<SysReport>,
}

impl SysReportRepository {
    pub fn new(db: DatabaseConnection) -> Self {
        Self {
            base: BaseRepository::new(db),
        }
    }

    pub fn base(&self) -> &BaseRepository<SysReport> {
        &self.base
    }

    /// 按 report_id 查询报表
    pub async fn find_by_id(&self, report_id: i64) -> Result<Option<Model>, DbErr> {
        SysReport::find()
            .filter(Column::ReportId.eq(report_id))
            .filter(Column::DelFlag.ne("2"))
            .one(self.base.db())
            .await
    }

    /// 按 report_code 查询报表（唯一编码，仅查未删除）
    pub async fn find_by_code(&self, report_code: &str) -> Result<Option<Model>, DbErr> {
        SysReport::find()
            .filter(Column::ReportCode.eq(report_code))
            .filter(Column::DelFlag.ne("2"))
            .one(self.base.db())
            .await
    }

    /// 按 report_code 判断是否已存在（未删除）
    pub async fn exists_by_code(&self, report_code: &str) -> Result<bool, DbErr> {
        let count = SysReport::find()
            .filter(Column::ReportCode.eq(report_code))
            .filter(Column::DelFlag.ne("2"))
            .count(self.base.db())
            .await?;
        Ok(count > 0)
    }

    /// 查询所有启用（status='0' 且未删除）报表
    pub async fn find_all_enabled(&self) -> Result<Vec<Model>, DbErr> {
        SysReport::find()
            .filter(Column::Status.eq("0"))
            .filter(Column::DelFlag.ne("2"))
            .order_by_asc(Column::ReportCode)
            .order_by_asc(Column::ReportId)
            .all(self.base.db())
            .await
    }

    /// 分页查询报表（report_name 模糊 + report_code/report_type/status 精确）
    ///
    /// `sort`：动态排序（方案 B，白名单已在 service 层解析为 `SortOrder`）；
    /// `None` 或未命中时回退默认 `report_id ASC`。
    #[allow(clippy::too_many_arguments)]
    pub async fn find_page_filtered(
        &self,
        offset: u64,
        limit: u64,
        report_name: Option<&str>,
        report_code: Option<&str>,
        report_type: Option<&str>,
        status: Option<&str>,
        tenant_scope: Option<i64>,
        sort: Option<SortOrder<Column>>,
    ) -> Result<(Vec<Model>, u64), DbErr> {
        let mut query = SysReport::find();
        query = query.filter(Column::DelFlag.ne("2"));
        if let Some(tid) = tenant_scope {
            query = query.filter(Column::TenantId.eq(tid));
        }
        if let Some(name) = report_name {
            query = query.filter(Column::ReportName.like(format!("%{}%", like_escape(name))));
        }
        if let Some(code) = report_code {
            query = query.filter(Column::ReportCode.eq(code));
        }
        if let Some(ty) = report_type {
            query = query.filter(Column::ReportType.eq(ty));
        }
        if let Some(st) = status {
            query = query.filter(Column::Status.eq(st));
        }

        let total = query.clone().count(self.base.db()).await?;
        let rows = match sort {
            Some(s) => query.order_by(s.column, s.dir),
            None => query.order_by_asc(Column::ReportId),
        }
        .offset(offset)
        .limit(limit)
        .all(self.base.db())
        .await?;
        Ok((rows, total))
    }

    /// 按 ID 列表查询报表（用于删除前校验）
    pub async fn find_by_ids(&self, report_ids: &[i64]) -> Result<Vec<Model>, DbErr> {
        if report_ids.is_empty() {
            return Ok(Vec::new());
        }
        SysReport::find()
            .filter(Column::ReportId.is_in(report_ids.to_vec()))
            .filter(Column::DelFlag.ne("2"))
            .all(self.base.db())
            .await
    }

    /// 按 ID 列表物理删除
    pub async fn delete_by_ids(&self, report_ids: Vec<i64>) -> Result<DeleteResult, DbErr> {
        SysReport::delete_many()
            .filter(Column::ReportId.is_in(report_ids))
            .exec(self.base.db())
            .await
    }

    /// 按 ID 列表逻辑删除（del_flag='2'）
    pub async fn soft_delete_by_ids(&self, report_ids: &[i64]) -> Result<UpdateResult, DbErr> {
        SysReport::update_many()
            .col_expr(Column::DelFlag, sea_orm::sea_query::Expr::value("2"))
            .filter(Column::ReportId.is_in(report_ids.to_vec()))
            .exec(self.base.db())
            .await
    }

    /// 插入报表
    pub async fn insert(&self, model: ActiveModel) -> Result<Model, DbErr> {
        self.base.insert(model).await
    }

    /// 更新报表
    pub async fn update(&self, model: ActiveModel) -> Result<Model, DbErr> {
        self.base.update(model).await
    }

    /// 更新状态（status='0'/'1'）
    pub async fn update_status(&self, report_id: i64, status: &str) -> Result<UpdateResult, DbErr> {
        SysReport::update_many()
            .col_expr(
                Column::Status,
                sea_orm::sea_query::Expr::value(status.to_string()),
            )
            .filter(Column::ReportId.eq(report_id))
            .exec(self.base.db())
            .await
    }
}
