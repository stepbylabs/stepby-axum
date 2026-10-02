// stepby-axum/src/repository/sys_task.rs
//! sys_task 数据访问层（任务进度中心表）
//!
//! 继承 BaseRepository 通用 CRUD，扩展任务进度特有查询：
//! - 多条件分页查询（task_type / status / operator / 时间范围）
//! - 按 ID 查询
//! - 批量删除
//! - 更新进度

use chrono::NaiveDateTime;
use sea_orm::*;

use crate::common::sort::SortOrder;
use crate::entity::sys_task::{ActiveModel, Column, Entity as SysTask, Model};
use crate::repository::base::BaseRepository;

/// 任务进度 Repository
#[derive(Clone)]
pub struct SysTaskRepository {
    base: BaseRepository<SysTask>,
}

impl SysTaskRepository {
    pub fn new(db: DatabaseConnection) -> Self {
        Self {
            base: BaseRepository::new(db),
        }
    }

    pub fn base(&self) -> &BaseRepository<SysTask> {
        &self.base
    }

    /// 多条件分页查询
    ///
    /// 多租户 Phase 2：tenant_scope=Some(tid) 仅返回本租户任务；None（平台 0）不过滤。
    ///
    /// `sort`：动态排序（方案 B，白名单已在 service 层解析为 `SortOrder`）；
    /// `None` 时回退默认 `create_time DESC`。
    #[allow(clippy::too_many_arguments)]
    pub async fn find_page_filtered(
        &self,
        offset: u64,
        limit: u64,
        task_type: Option<&str>,
        status: Option<&str>,
        operator: Option<&str>,
        begin_time: Option<NaiveDateTime>,
        end_time: Option<NaiveDateTime>,
        tenant_scope: Option<i64>,
        sort: Option<SortOrder<Column>>,
    ) -> Result<(Vec<Model>, u64), DbErr> {
        let mut query = SysTask::find();
        if let Some(t) = tenant_scope {
            query = query.filter(Column::TenantId.eq(t));
        }
        if let Some(tt) = task_type {
            query = query.filter(Column::TaskType.eq(tt));
        }
        if let Some(st) = status {
            query = query.filter(Column::Status.eq(st));
        }
        if let Some(op) = operator {
            // 安全：调用 like_escape 转义 %/_ 通配符，防止用户输入 % 匹配全表
            query = query
                .filter(Column::Operator.like(format!("%{}%", crate::common::like_escape(op))));
        }
        if let Some(begin) = begin_time {
            query = query.filter(Column::CreateTime.gte(begin));
        }
        if let Some(end) = end_time {
            query = query.filter(Column::CreateTime.lte(end));
        }

        let total = query.clone().count(self.base.db()).await?;
        // 动态排序（白名单已解析）或默认 create_time 倒序
        let rows = match sort {
            Some(s) => query.order_by(s.column, s.dir),
            None => query.order_by_desc(Column::CreateTime),
        }
        .offset(offset)
        .limit(limit)
        .all(self.base.db())
        .await?;
        Ok((rows, total))
    }

    /// 按 ID 查询
    pub async fn find_by_id(&self, task_id: i64) -> Result<Option<Model>, DbErr> {
        SysTask::find_by_id(task_id).one(self.base.db()).await
    }

    /// 插入一条记录
    pub async fn insert(&self, model: ActiveModel) -> Result<Model, DbErr> {
        self.base.insert(model).await
    }

    /// 更新记录
    pub async fn update(&self, model: ActiveModel) -> Result<Model, DbErr> {
        self.base.update(model).await
    }

    /// 批量删除（物理删除）
    pub async fn delete_by_ids(&self, ids: Vec<i64>) -> Result<DeleteResult, DbErr> {
        SysTask::delete_many()
            .filter(Column::TaskId.is_in(ids))
            .exec(self.base.db())
            .await
    }
}
