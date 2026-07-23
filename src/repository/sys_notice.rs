// axum-backend/src/repository/sys_notice.rs
//! sys_notice 数据访问层（通知公告表）
//!
//! 继承 BaseRepository 通用 CRUD，扩展通知公告特有查询：
//! - 按 notice_title 模糊 + notice_type 精确 + create_by 精确 + 时间范围 分页查询
//! - 按 notice_id 查询详情
//! - 按 ID 列表物理删除（notice 表无 del_flag）

use chrono::NaiveDateTime;
use sea_orm::*;

use crate::common::like_escape;
use crate::entity::sys_notice::{ActiveModel, Column, Entity as SysNotice, Model};
use crate::repository::base::BaseRepository;

/// 通知公告 Repository
#[derive(Clone)]
pub struct SysNoticeRepository {
    base: BaseRepository<SysNotice>,
}

impl SysNoticeRepository {
    pub fn new(db: DatabaseConnection) -> Self {
        Self {
            base: BaseRepository::new(db),
        }
    }

    pub fn base(&self) -> &BaseRepository<SysNotice> {
        &self.base
    }

    /// 按 notice_id 查询通知公告
    pub async fn find_active_by_id(&self, notice_id: i64) -> Result<Option<Model>, DbErr> {
        SysNotice::find()
            .filter(Column::NoticeId.eq(notice_id))
            .one(self.base.db())
            .await
    }

    /// 按 notice_id 列表批量查询通知公告（单次 SELECT，替代循环 N 次）
    pub async fn find_by_ids(&self, notice_ids: &[i64]) -> Result<Vec<Model>, DbErr> {
        if notice_ids.is_empty() {
            return Ok(Vec::new());
        }
        SysNotice::find()
            .filter(Column::NoticeId.is_in(notice_ids.iter().copied().collect::<Vec<i64>>()))
            .all(self.base.db())
            .await
    }

    /// 多条件分页查询（notice_title 模糊，notice_type 精确，create_by 精确，时间范围）
    #[allow(clippy::too_many_arguments)]
    pub async fn find_page_filtered(
        &self,
        offset: u64,
        limit: u64,
        notice_title: Option<&str>,
        notice_type: Option<&str>,
        create_by: Option<&str>,
        begin_time: Option<NaiveDateTime>,
        end_time: Option<NaiveDateTime>,
    ) -> Result<(Vec<Model>, u64), DbErr> {
        let mut query = SysNotice::find();
        if let Some(title) = notice_title {
            query = query.filter(Column::NoticeTitle.like(format!("%{}%", like_escape(title))));
        }
        if let Some(nt) = notice_type {
            query = query.filter(Column::NoticeType.eq(nt));
        }
        if let Some(cb) = create_by {
            query = query.filter(Column::CreateBy.eq(cb));
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

    /// 按 ID 列表物理删除通知公告（notice 表无 del_flag）
    pub async fn delete_by_ids(&self, notice_ids: Vec<i64>) -> Result<DeleteResult, DbErr> {
        SysNotice::delete_many()
            .filter(Column::NoticeId.is_in(notice_ids))
            .exec(self.base.db())
            .await
    }

    /// 按 ID 列表物理删除通知公告（使用指定连接，用于事务内调用）
    pub async fn delete_by_ids_conn<C: ConnectionTrait>(
        &self,
        conn: &C,
        notice_ids: Vec<i64>,
    ) -> Result<DeleteResult, DbErr> {
        SysNotice::delete_many()
            .filter(Column::NoticeId.is_in(notice_ids))
            .exec(conn)
            .await
    }

    /// 查询状态正常的顶部公告（status='0'），限制返回条数
    pub async fn find_top_notices(&self, limit: u64) -> Result<Vec<Model>, DbErr> {
        SysNotice::find()
            .filter(Column::Status.eq("0"))
            .order_by_desc(Column::CreateTime)
            .limit(limit)
            .all(self.base.db())
            .await
    }

    /// 插入通知公告
    pub async fn insert(&self, model: ActiveModel) -> Result<Model, DbErr> {
        self.base.insert(model).await
    }

    /// 更新通知公告
    pub async fn update(&self, model: ActiveModel) -> Result<Model, DbErr> {
        self.base.update(model).await
    }
}
