// stepby-axum/src/repository/sys_msg_channel.rs
//! sys_msg_channel 数据访问层（消息渠道表）
//!
//! 继承 BaseRepository 通用 CRUD，扩展渠道特有查询：
//! - 按 channel_name 模糊 + channel_code/channel_type/status 精确分页查询（过滤已删 del_flag='0'）
//! - 按 channel_code 查询渠道（唯一编码，用于发送时按编码定位）
//! - 按 ID 列表物理删除

use sea_orm::*;

use crate::common::like_escape;
use crate::common::sort::SortOrder;
use crate::entity::sys_msg_channel::{ActiveModel, Column, Entity as SysMsgChannel, Model};
use crate::repository::base::BaseRepository;

/// 消息渠道 Repository
#[derive(Clone)]
pub struct SysMsgChannelRepository {
    base: BaseRepository<SysMsgChannel>,
}

impl SysMsgChannelRepository {
    pub fn new(db: DatabaseConnection) -> Self {
        Self {
            base: BaseRepository::new(db),
        }
    }

    pub fn base(&self) -> &BaseRepository<SysMsgChannel> {
        &self.base
    }

    /// 按 channel_id 查询渠道（未删除）
    pub async fn find_active_by_id(&self, channel_id: i64) -> Result<Option<Model>, DbErr> {
        SysMsgChannel::find()
            .filter(Column::ChannelId.eq(channel_id))
            .filter(Column::DelFlag.eq("0"))
            .one(self.base.db())
            .await
    }

    /// 按 channel_code 查询渠道（唯一编码，未删除；tenant_scope 过滤租户）
    pub async fn find_by_code(
        &self,
        channel_code: &str,
        tenant_scope: Option<i64>,
    ) -> Result<Option<Model>, DbErr> {
        let mut q = SysMsgChannel::find();
        q = q.filter(Column::ChannelCode.eq(channel_code));
        q = q.filter(Column::DelFlag.eq("0"));
        if let Some(tid) = tenant_scope {
            q = q.filter(Column::TenantId.eq(tid));
        }
        q.one(self.base.db()).await
    }

    /// 按 ID 列表批量查询渠道（单次 SELECT）
    pub async fn find_by_ids(&self, channel_ids: &[i64]) -> Result<Vec<Model>, DbErr> {
        if channel_ids.is_empty() {
            return Ok(Vec::new());
        }
        SysMsgChannel::find()
            .filter(Column::ChannelId.is_in(channel_ids.to_vec()))
            .all(self.base.db())
            .await
    }

    /// 多条件分页查询（channel_name 模糊 + channel_code/channel_type/status 精确）
    ///
    /// `sort`：动态排序（方案 B，白名单已在 service 层解析为 `SortOrder`）；
    /// `None` 时回退默认 `channel_id ASC`。
    #[allow(clippy::too_many_arguments)]
    pub async fn find_page_filtered(
        &self,
        offset: u64,
        limit: u64,
        channel_name: Option<&str>,
        channel_code: Option<&str>,
        channel_type: Option<&str>,
        status: Option<&str>,
        tenant_scope: Option<i64>,
        sort: Option<SortOrder<Column>>,
    ) -> Result<(Vec<Model>, u64), DbErr> {
        let mut query = SysMsgChannel::find();
        query = query.filter(Column::DelFlag.eq("0"));
        if let Some(tid) = tenant_scope {
            query = query.filter(Column::TenantId.eq(tid));
        }
        if let Some(name) = channel_name {
            query = query.filter(Column::ChannelName.like(format!("%{}%", like_escape(name))));
        }
        if let Some(code) = channel_code {
            query = query.filter(Column::ChannelCode.eq(code));
        }
        if let Some(ty) = channel_type {
            query = query.filter(Column::ChannelType.eq(ty));
        }
        if let Some(st) = status {
            query = query.filter(Column::Status.eq(st));
        }

        let total = query.clone().count(self.base.db()).await?;
        // 动态排序（白名单已解析）或默认 channel_id ASC
        let rows = match sort {
            Some(s) => query.order_by(s.column, s.dir),
            None => query.order_by_asc(Column::ChannelId),
        }
        .offset(offset)
        .limit(limit)
        .all(self.base.db())
        .await?;
        Ok((rows, total))
    }

    /// 按 ID 列表物理删除渠道
    pub async fn delete_by_ids(&self, channel_ids: Vec<i64>) -> Result<DeleteResult, DbErr> {
        SysMsgChannel::delete_many()
            .filter(Column::ChannelId.is_in(channel_ids))
            .exec(self.base.db())
            .await
    }

    /// 按 channel_code 判断是否已存在（唯一编码校验）
    pub async fn exists_by_code(&self, channel_code: &str) -> Result<bool, DbErr> {
        let count = SysMsgChannel::find()
            .filter(Column::ChannelCode.eq(channel_code))
            .count(self.base.db())
            .await?;
        Ok(count > 0)
    }

    /// 插入渠道
    pub async fn insert(&self, model: ActiveModel) -> Result<Model, DbErr> {
        self.base.insert(model).await
    }

    /// 更新渠道
    pub async fn update(&self, model: ActiveModel) -> Result<Model, DbErr> {
        self.base.update(model).await
    }
}
