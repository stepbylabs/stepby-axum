// stepby-axum/src/repository/sys_web_hook.rs
//! sys_web_hook 数据访问层（WebHook 回调配置表，逻辑删除）
//!
//! 继承 BaseRepository 通用 CRUD，扩展回调特有查询：
//! - 按 id 查询（未删除）
//! - 分页查询（hook_name/event_types/status 过滤）
//! - 查询全部启用回调（供事件分发扫描）
//! - 按事件类型匹配启用回调（event_types 逗号分隔；空串匹配全部）
//! - 按 ID 列表逻辑删除（del_flag='2'）
//! - 修改后更新状态

use sea_orm::sea_query::Expr;
use sea_orm::*;

use crate::common::like_escape;
use crate::common::sort::SortOrder;
use crate::entity::sys_web_hook::{ActiveModel, Column, Entity as SysWebHook, Model};
use crate::repository::base::BaseRepository;

/// WebHook 配置 Repository
#[derive(Clone)]
pub struct SysWebHookRepository {
    base: BaseRepository<SysWebHook>,
}

impl SysWebHookRepository {
    pub fn new(db: DatabaseConnection) -> Self {
        Self {
            base: BaseRepository::new(db),
        }
    }

    pub fn base(&self) -> &BaseRepository<SysWebHook> {
        &self.base
    }

    /// 按 id 查询回调（未删除）
    pub async fn find_by_id(&self, id: i64) -> Result<Option<Model>, DbErr> {
        SysWebHook::find()
            .filter(Column::Id.eq(id))
            .filter(Column::DelFlag.ne("2"))
            .one(self.base.db())
            .await
    }

    /// 查询全部启用回调（status='0' 且未删除），**按租户分组**返回，供事件分发扫描。
    ///
    /// 事件分发为后台批量任务：必须先按租户分组，再逐组以该组 tid 为上下文投递，
    /// 严禁跨租户批量触达（A 租户事件不得推给 B 租户回调）。
    pub async fn find_all_enabled(&self) -> Result<Vec<(i64, Vec<Model>)>, DbErr> {
        let rows = SysWebHook::find()
            .filter(Column::Status.eq("0"))
            .filter(Column::DelFlag.ne("2"))
            .order_by_asc(Column::Id)
            .all(self.base.db())
            .await?;
        Ok(crate::common::tenant::group_by_tenant(rows, |h| {
            h.tenant_id
        }))
    }

    /// 分页查询回调（hook_name/event_types/status 过滤，未删除）
    ///
    /// `sort`：动态排序（方案 B，白名单已在 service 层解析为 `SortOrder`）；
    /// `None` 时回退默认 `id DESC`。
    #[allow(clippy::too_many_arguments)]
    pub async fn find_page_filtered(
        &self,
        offset: u64,
        limit: u64,
        hook_name: Option<&str>,
        event_types: Option<&str>,
        status: Option<&str>,
        tenant_scope: Option<i64>,
        sort: Option<SortOrder<Column>>,
    ) -> Result<(Vec<Model>, u64), DbErr> {
        let mut query = SysWebHook::find();
        query = query.filter(Column::DelFlag.ne("2"));
        if let Some(tid) = tenant_scope {
            query = query.filter(Column::TenantId.eq(tid));
        }
        if let Some(name) = hook_name {
            query = query.filter(Column::HookName.like(format!("%{}%", like_escape(name))));
        }
        if let Some(ev) = event_types {
            query = query.filter(Column::EventTypes.like(format!("%{}%", like_escape(ev))));
        }
        if let Some(st) = status {
            query = query.filter(Column::Status.eq(st));
        }

        let total = query.clone().count(self.base.db()).await?;
        // 动态排序（白名单已解析）或默认 id DESC
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

    /// 分页全量查询（导出用，EXPORT_MAX_ROWS 上限）
    pub async fn find_all_filtered(
        &self,
        hook_name: Option<&str>,
        event_types: Option<&str>,
        status: Option<&str>,
        tenant_scope: Option<i64>,
    ) -> Result<Vec<Model>, DbErr> {
        let mut query = SysWebHook::find();
        query = query.filter(Column::DelFlag.ne("2"));
        if let Some(tid) = tenant_scope {
            query = query.filter(Column::TenantId.eq(tid));
        }
        if let Some(name) = hook_name {
            query = query.filter(Column::HookName.like(format!("%{}%", like_escape(name))));
        }
        if let Some(ev) = event_types {
            query = query.filter(Column::EventTypes.like(format!("%{}%", like_escape(ev))));
        }
        if let Some(st) = status {
            query = query.filter(Column::Status.eq(st));
        }
        query
            .order_by_desc(Column::Id)
            .limit(crate::common::page::EXPORT_MAX_ROWS)
            .all(self.base.db())
            .await
    }

    /// 按 ID 列表查询回调（未删除）
    pub async fn find_by_ids(&self, ids: &[i64]) -> Result<Vec<Model>, DbErr> {
        if ids.is_empty() {
            return Ok(Vec::new());
        }
        SysWebHook::find()
            .filter(Column::Id.is_in(ids.to_vec()))
            .filter(Column::DelFlag.ne("2"))
            .all(self.base.db())
            .await
    }

    /// 按 ID 列表逻辑删除（del_flag='2'）
    pub async fn soft_delete_by_ids(&self, ids: &[i64]) -> Result<UpdateResult, DbErr> {
        SysWebHook::update_many()
            .col_expr(Column::DelFlag, Expr::value("2"))
            .filter(Column::Id.is_in(ids.to_vec()))
            .exec(self.base.db())
            .await
    }

    /// 更新状态（启停）
    pub async fn update_status(&self, id: i64, status: &str) -> Result<UpdateResult, DbErr> {
        SysWebHook::update_many()
            .col_expr(Column::Status, Expr::value(status.to_string()))
            .filter(Column::Id.eq(id))
            .exec(self.base.db())
            .await
    }

    /// 插入回调
    pub async fn insert(&self, model: ActiveModel) -> Result<Model, DbErr> {
        self.base.insert(model).await
    }

    /// 更新回调
    pub async fn update(&self, model: ActiveModel) -> Result<Model, DbErr> {
        self.base.update(model).await
    }
}
