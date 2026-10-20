// stepby-axum/src/repository/sys_notice.rs
//! sys_notice 数据访问层（通知公告表）
//!
//! 继承 BaseRepository 通用 CRUD，扩展通知公告特有查询：
//! - 分页查询 / 计数 / 取 ID：三条路径共用 [`NoticeFilter`] 与 `SysNoticeRepository::base_query`
//!   （b80 P-B：改造前列表、未读角标、跨页全部已读各写各的谓词，同屏可以互相矛盾）
//! - 按 notice_id 查询详情
//! - 按 ID 列表物理删除（notice 表无 del_flag；写侧只保留事务内版本）

use chrono::NaiveDateTime;
use sea_orm::sea_query::{Expr, SelectStatement};
use sea_orm::*;

use crate::common::like_escape;
use crate::common::sort::SortOrder;
use crate::entity::sys_notice::{Column, Entity as SysNotice, Model};
use crate::entity::sys_notice_read::{Column as ReadColumn, Entity as SysNoticeRead};
use crate::repository::base::BaseRepository;

/// 通知公告过滤条件——**公告可见性口径的单一事实源**（b80 P-B）
///
/// 三条消费路径共用 `SysNoticeRepository::base_query`：分页列表（`list`）、未读数角标
/// （`count_unread`）、跨页「全部已读」（`mark_all_unread_read`）。改造前它们各自手写谓词，
/// 于是同一屏可以同时出现「列表里有 3 条未读、角标说 0」这类互相矛盾的结论。
///
/// 生命周期：`status` 用 `'static`（由 service 侧白名单解析产出常量切片），
/// 因此本结构可以比 DTO 活得久，`base_query` 不需要借用 DTO。
#[derive(Debug, Clone, Default)]
pub struct NoticeFilter<'a> {
    /// 租户谓词（`common::tenant::tenant_scope()` 的产出：`Some(t)` 仅本租户，`None` 平台视角）
    pub tenant_scope: Option<i64>,
    /// 标题模糊
    pub title: Option<&'a str>,
    /// 公告类型精确
    pub notice_type: Option<&'a str>,
    /// 创建人精确
    pub create_by: Option<&'a str>,
    /// 状态精确（`"0"` 正常 / `"1"` 关闭）；`None` = 不过滤（管理面全量）
    pub status: Option<&'a str>,
    /// 创建时间下界
    pub begin: Option<NaiveDateTime>,
    /// 创建时间上界
    pub end: Option<NaiveDateTime>,
    /// 已读态半连接：`None` 不过滤；`Some(true)` 仅已读；`Some(false)` 仅未读。
    /// 判定依据是 `user_id` 的已读记录集合（见 `read_notice_id_subquery`）
    pub read: Option<bool>,
    /// `read` 所依据的用户（`read` 为 `None` 时不参与 SQL）
    pub user_id: i64,
}

/// 「这个用户已读了哪些公告」的子查询（`SELECT notice_id FROM sys_notice_read WHERE …`）
///
/// 用**非相关子查询 + IN / NOT IN 半连接**而不是手写 `NOT EXISTS`：三方言的占位符与语法
/// 由 ORM 生成，本仓不再出现 `match backend` 的方言分支（b79 之前 `count_unread` 有四支
/// 手写 SQL，是全仓唯一按方言展开的公告查询）。
///
/// 租户谓词与外层**同一个** `tenant_scope`：`sys_notice_read.tenant_id` 落的是父公告租户
/// （`sys_notice_service.rs` 的 mark_read 写侧），故租户操作者两侧谓词等价；平台操作者两侧
/// 都不加过滤，代管视角照常。
///
/// `NOT IN` 的安全性：`sys_notice_read.notice_id` 非空且是 `UNIQUE(notice_id, user_id)` 的
/// 成员，子查询不可能产出 NULL ⇒ `NOT IN` 不会因三值逻辑整体退化为 UNKNOWN。
fn read_notice_id_subquery(user_id: i64, tenant_scope: Option<i64>) -> SelectStatement {
    let mut q = SysNoticeRead::find()
        .filter(ReadColumn::UserId.eq(user_id))
        .select_only()
        .column(ReadColumn::NoticeId);
    if let Some(tid) = tenant_scope {
        q = q.filter(ReadColumn::TenantId.eq(tid));
    }
    q.into_query()
}

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
            .filter(Column::NoticeId.is_in(notice_ids.to_vec()))
            .all(self.base.db())
            .await
    }

    /// 由 [`NoticeFilter`] 构造公告查询——**列表、未读数、全部已读三条路径的唯一谓词出口**
    ///
    /// 返回的是未分页、未排序的 `Select`，调用方各自追加 count / limit / order。
    /// 这样"我数出来的未读"与"我列出来的未读"在结构上不可能不一致（口径漂移只能发生在
    /// 本函数这一处，且只有一处可审）。
    fn base_query(f: &NoticeFilter<'_>) -> Select<SysNotice> {
        let mut query = SysNotice::find();
        if let Some(tid) = f.tenant_scope {
            query = query.filter(Column::TenantId.eq(tid));
        }
        if let Some(title) = f.title {
            query = query.filter(Column::NoticeTitle.like(format!("%{}%", like_escape(title))));
        }
        if let Some(nt) = f.notice_type {
            query = query.filter(Column::NoticeType.eq(nt));
        }
        if let Some(cb) = f.create_by {
            query = query.filter(Column::CreateBy.eq(cb));
        }
        if let Some(st) = f.status {
            query = query.filter(Column::Status.eq(st));
        }
        if let Some(begin) = f.begin {
            query = query.filter(Column::CreateTime.gte(begin));
        }
        if let Some(end) = f.end {
            query = query.filter(Column::CreateTime.lte(end));
        }
        if let Some(read) = f.read {
            let sub = read_notice_id_subquery(f.user_id, f.tenant_scope);
            let expr = Expr::col(Column::NoticeId);
            query = query.filter(if read {
                expr.in_subquery(sub)
            } else {
                expr.not_in_subquery(sub)
            });
        }
        query
    }

    /// 多条件分页查询（谓词全部来自 `NoticeFilter`，见 `base_query`）
    ///
    /// `sort`：动态排序（方案 B，白名单已在 service 层解析为 `SortOrder`）；
    /// `None` 时回退默认 `notice_id ASC`（P1 稳定排序，防翻页重复/漏行）。
    pub async fn find_page_filtered(
        &self,
        offset: u64,
        limit: u64,
        filter: &NoticeFilter<'_>,
        sort: Option<SortOrder<Column>>,
    ) -> Result<(Vec<Model>, u64), DbErr> {
        let total = Self::base_query(filter).count(self.base.db()).await?;
        // 动态排序（白名单已解析）或默认 notice_id ASC（P1 稳定排序，防翻页重复/漏行）
        let query = Self::base_query(filter);
        let rows = match sort {
            Some(s) => query.order_by(s.column, s.dir),
            None => query.order_by_asc(Column::NoticeId),
        }
        .offset(offset)
        .limit(limit)
        .all(self.base.db())
        .await?;
        Ok((rows, total))
    }

    /// 按过滤条件计数（未读角标用：`status="0" + read=Some(false)`）
    pub async fn count_by_filter(&self, filter: &NoticeFilter<'_>) -> Result<u64, DbErr> {
        Self::base_query(filter).count(self.base.db()).await
    }

    /// 按过滤条件取 `(notice_id, tenant_id)`（跨页「全部已读」用）
    ///
    /// 只投影两列：写侧需要父公告租户才能保证 read 记录租户与公告一致（AGENTS 铁律 1）。
    pub async fn find_id_tenant_pairs(
        &self,
        filter: &NoticeFilter<'_>,
    ) -> Result<Vec<(i64, i64)>, DbErr> {
        Self::base_query(filter)
            .select_only()
            .column(Column::NoticeId)
            .column(Column::TenantId)
            .into_tuple::<(i64, i64)>()
            .all(self.base.db())
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

    /// 查询状态正常的顶部公告（status='0'），限制返回条数（tenant_scope 过滤租户）
    ///
    /// 谓词走 `base_query`（`status="0"` + 租户），与未读数角标同源 ⇒
    /// 铃铛弹层里的行、角标数字、通知中心列表三者不会互相矛盾。
    pub async fn find_top_notices(
        &self,
        limit: u64,
        tenant_scope: Option<i64>,
    ) -> Result<Vec<Model>, DbErr> {
        Self::base_query(&NoticeFilter {
            tenant_scope,
            status: Some("0"),
            ..Default::default()
        })
        .order_by_desc(Column::CreateTime)
        .limit(limit)
        .all(self.base.db())
        .await
    }
}
