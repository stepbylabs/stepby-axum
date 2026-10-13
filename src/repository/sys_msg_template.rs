// stepby-axum/src/repository/sys_msg_template.rs
//! sys_msg_template 数据访问层（消息模板表）
//!
//! 继承 BaseRepository 通用 CRUD，扩展模板特有查询：
//! - 按 template_name 模糊 + template_code/channel_code/status 精确分页查询（过滤已删 del_flag='0'）
//! - 按 template_code 查询模板（唯一编码，用于发送时按编码加载）
//! - 按 channel_code 统计模板数（渠道删除前校验引用）
//! - 按 ID 列表物理删除

use sea_orm::*;

use crate::common::like_escape;
use crate::common::sort::SortOrder;
use crate::entity::sys_msg_template::{ActiveModel, Column, Entity as SysMsgTemplate, Model};
use crate::repository::base::BaseRepository;

/// 消息模板 Repository
#[derive(Clone)]
pub struct SysMsgTemplateRepository {
    base: BaseRepository<SysMsgTemplate>,
}

impl SysMsgTemplateRepository {
    pub fn new(db: DatabaseConnection) -> Self {
        Self {
            base: BaseRepository::new(db),
        }
    }

    pub fn base(&self) -> &BaseRepository<SysMsgTemplate> {
        &self.base
    }

    /// 按 template_id 查询模板（未删除）
    pub async fn find_active_by_id(&self, template_id: i64) -> Result<Option<Model>, DbErr> {
        SysMsgTemplate::find()
            .filter(Column::TemplateId.eq(template_id))
            .filter(Column::DelFlag.eq("0"))
            .one(self.base.db())
            .await
    }

    /// 按 template_code 查询模板（唯一编码，未删除；tenant_scope 过滤租户）
    pub async fn find_by_code(
        &self,
        template_code: &str,
        tenant_scope: Option<i64>,
    ) -> Result<Option<Model>, DbErr> {
        let mut q = SysMsgTemplate::find();
        q = q.filter(Column::TemplateCode.eq(template_code));
        q = q.filter(Column::DelFlag.eq("0"));
        if let Some(tid) = tenant_scope {
            q = q.filter(Column::TenantId.eq(tid));
        }
        q.one(self.base.db()).await
    }

    /// 按 ID 列表批量查询模板（单次 SELECT）
    pub async fn find_by_ids(&self, template_ids: &[i64]) -> Result<Vec<Model>, DbErr> {
        if template_ids.is_empty() {
            return Ok(Vec::new());
        }
        SysMsgTemplate::find()
            .filter(Column::TemplateId.is_in(template_ids.to_vec()))
            .all(self.base.db())
            .await
    }

    /// 按渠道编码统计启用模板数（删除渠道前校验引用；tenant_scope 过滤租户）
    pub async fn count_by_channel_code(
        &self,
        channel_code: &str,
        tenant_scope: Option<i64>,
    ) -> Result<u64, DbErr> {
        let mut q = SysMsgTemplate::find();
        q = q.filter(Column::ChannelCode.eq(channel_code));
        q = q.filter(Column::DelFlag.eq("0"));
        if let Some(tid) = tenant_scope {
            q = q.filter(Column::TenantId.eq(tid));
        }
        q.count(self.base.db()).await
    }

    /// 多条件分页查询（template_name 模糊 + template_code/channel_code/status 精确）
    ///
    /// `sort`：动态排序（方案 B，白名单已在 service 层解析为 `SortOrder`）；
    /// `None` 时回退默认 `template_id ASC`。
    #[allow(clippy::too_many_arguments)]
    pub async fn find_page_filtered(
        &self,
        offset: u64,
        limit: u64,
        template_name: Option<&str>,
        template_code: Option<&str>,
        channel_code: Option<&str>,
        status: Option<&str>,
        tenant_scope: Option<i64>,
        sort: Option<SortOrder<Column>>,
    ) -> Result<(Vec<Model>, u64), DbErr> {
        let mut query = SysMsgTemplate::find();
        query = query.filter(Column::DelFlag.eq("0"));
        if let Some(tid) = tenant_scope {
            query = query.filter(Column::TenantId.eq(tid));
        }
        if let Some(name) = template_name {
            query = query.filter(Column::TemplateName.like(format!("%{}%", like_escape(name))));
        }
        if let Some(code) = template_code {
            query = query.filter(Column::TemplateCode.eq(code));
        }
        if let Some(cc) = channel_code {
            query = query.filter(Column::ChannelCode.eq(cc));
        }
        if let Some(st) = status {
            query = query.filter(Column::Status.eq(st));
        }

        let total = query.clone().count(self.base.db()).await?;
        // 动态排序（白名单已解析）或默认 template_id ASC
        let rows = match sort {
            Some(s) => query.order_by(s.column, s.dir),
            None => query.order_by_asc(Column::TemplateId),
        }
        .offset(offset)
        .limit(limit)
        .all(self.base.db())
        .await?;
        Ok((rows, total))
    }

    /// 按 ID 列表物理删除模板
    pub async fn delete_by_ids(&self, template_ids: Vec<i64>) -> Result<DeleteResult, DbErr> {
        SysMsgTemplate::delete_many()
            .filter(Column::TemplateId.is_in(template_ids))
            .exec(self.base.db())
            .await
    }

    /// 按 template_code 判断是否已存在（唯一编码校验）
    pub async fn exists_by_code(&self, template_code: &str) -> Result<bool, DbErr> {
        let count = SysMsgTemplate::find()
            .filter(Column::TemplateCode.eq(template_code))
            .count(self.base.db())
            .await?;
        Ok(count > 0)
    }

    /// 插入模板
    pub async fn insert(&self, model: ActiveModel) -> Result<Model, DbErr> {
        self.base.insert(model).await
    }

    /// 更新模板
    pub async fn update(&self, model: ActiveModel) -> Result<Model, DbErr> {
        self.base.update(model).await
    }
}
