// stepby-axum/src/repository/sys_audit_change.rs
//! sys_audit_change 数据访问层（业务数据变更留痕表）
//!
//! 继承 BaseRepository 通用 CRUD，扩展审计查询：
//! - 多条件分页（table_name / row_pk / action 精确，operator_name 模糊，时间范围）
//! - 动态排序（白名单在 service 层解析为 `SortOrder`）
//! - 导出全量（受 EXPORT_MAX_ROWS 限制）

use chrono::NaiveDateTime;
use sea_orm::*;

use crate::common::like_escape;
use crate::common::sort::SortOrder;
use crate::entity::sys_audit_change::{Column, Entity as SysAuditChange, Model};
use crate::repository::base::BaseRepository;

/// 审计变更 Repository
#[derive(Clone)]
pub struct SysAuditChangeRepository {
    base: BaseRepository<SysAuditChange>,
}

impl SysAuditChangeRepository {
    pub fn new(db: DatabaseConnection) -> Self {
        Self {
            base: BaseRepository::new(db),
        }
    }

    pub fn base(&self) -> &BaseRepository<SysAuditChange> {
        &self.base
    }

    /// 保留期清理：删除 operated_at 早于 cutoff 的留痕行（批五十七）
    ///
    /// 无防篡改链（变更留痕为写后只读快照域），直删安全；
    /// tenant_scope=Some(t) 仅清理该租户；None（平台兜底清理）→ 全量。
    pub async fn delete_older_than(
        &self,
        cutoff: NaiveDateTime,
        tenant_scope: Option<i64>,
    ) -> Result<DeleteResult, DbErr> {
        let mut query = SysAuditChange::delete_many().filter(Column::OperatedAt.lt(cutoff));
        if let Some(t) = tenant_scope {
            query = query.filter(Column::TenantId.eq(t));
        }
        query.exec(self.base.db()).await
    }

    /// 插入一条变更留痕（支持事务上下文）
    pub async fn insert_conn<C: ConnectionTrait>(
        &self,
        conn: &C,
        model: crate::entity::sys_audit_change::ActiveModel,
    ) -> Result<Model, DbErr> {
        self.base.insert_conn(conn, model).await
    }

    /// 多条件分页查询
    ///
    /// 过滤：table_name / row_pk / action 精确，operator_name 模糊（含转义），
    /// 时间范围 [begin, end] 闭区间；`tenant_scope = Some(tid)` 时仅返回本租户记录。
    ///
    /// `sort`：动态排序（白名单已在 service 层解析）；None 回退默认 operated_at DESC。
    #[allow(clippy::too_many_arguments)]
    pub async fn find_page_filtered(
        &self,
        offset: u64,
        limit: u64,
        table_name: Option<&str>,
        row_pk: Option<&str>,
        action: Option<&str>,
        operator_name: Option<&str>,
        begin_time: Option<NaiveDateTime>,
        end_time: Option<NaiveDateTime>,
        tenant_scope: Option<i64>,
        sort: Option<SortOrder<Column>>,
    ) -> Result<(Vec<Model>, u64), DbErr> {
        let query = Self::build_filtered(
            table_name,
            row_pk,
            action,
            operator_name,
            begin_time,
            end_time,
            tenant_scope,
        );

        // 过滤条件已齐备，统计总数
        let total = query.clone().count(self.base.db()).await?;

        let rows = match sort {
            Some(s) => query.order_by(s.column, s.dir),
            None => query.order_by_desc(Column::Id),
        }
        .offset(offset)
        .limit(limit)
        .all(self.base.db())
        .await?;
        Ok((rows, total))
    }

    /// 导出全量查询（与 `find_page_filtered` 同过滤口径，不截断分页；
    /// 上限由调用方以 limit = EXPORT_MAX_ROWS 控制）
    #[allow(clippy::too_many_arguments)]
    pub async fn find_all_filtered(
        &self,
        limit: u64,
        table_name: Option<&str>,
        row_pk: Option<&str>,
        action: Option<&str>,
        operator_name: Option<&str>,
        begin_time: Option<NaiveDateTime>,
        end_time: Option<NaiveDateTime>,
        tenant_scope: Option<i64>,
    ) -> Result<Vec<Model>, DbErr> {
        let query = Self::build_filtered(
            table_name,
            row_pk,
            action,
            operator_name,
            begin_time,
            end_time,
            tenant_scope,
        );
        query
            .order_by_desc(Column::Id)
            .limit(limit)
            .all(self.base.db())
            .await
    }

    /// 组装过滤条件（分页与导出共用，保证口径一致）
    #[allow(clippy::too_many_arguments)]
    fn build_filtered(
        table_name: Option<&str>,
        row_pk: Option<&str>,
        action: Option<&str>,
        operator_name: Option<&str>,
        begin_time: Option<NaiveDateTime>,
        end_time: Option<NaiveDateTime>,
        tenant_scope: Option<i64>,
    ) -> Select<SysAuditChange> {
        let mut query = SysAuditChange::find();
        // 多租户：租户操作者仅见本租户记录；平台（None）全量
        if let Some(t) = tenant_scope {
            query = query.filter(Column::TenantId.eq(t));
        }
        if let Some(t) = table_name {
            query = query.filter(Column::TableName.eq(t));
        }
        if let Some(pk) = row_pk {
            query = query.filter(Column::RowPk.eq(pk));
        }
        if let Some(a) = action {
            query = query.filter(Column::Action.eq(a));
        }
        if let Some(name) = operator_name {
            query = query.filter(Column::OperatorName.like(format!("%{}%", like_escape(name))));
        }
        if let Some(begin) = begin_time {
            query = query.filter(Column::OperatedAt.gte(begin));
        }
        if let Some(end) = end_time {
            query = query.filter(Column::OperatedAt.lte(end));
        }
        query
    }
}
