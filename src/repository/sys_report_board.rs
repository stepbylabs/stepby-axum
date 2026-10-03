// stepby-axum/src/repository/sys_report_board.rs
//! 报表看板（sys_report_board 表）数据访问层
//!
//! v1 语义：仅本人可读写（所有查询/写入按 user_id 过滤），租户隔离由服务层在
//! 写入时归 operator 租户、读取时按属主行收敛（属主行天然带本人租户）。

use sea_orm::sea_query::Expr;
use sea_orm::*;

use crate::entity::sys_report_board::{ActiveModel, Column, Entity as SysReportBoard, Model};
use crate::repository::base::BaseRepository;

/// 报表看板 Repository
#[derive(Clone)]
pub struct SysReportBoardRepository {
    base: BaseRepository<SysReportBoard>,
}

impl SysReportBoardRepository {
    pub fn new(db: DatabaseConnection) -> Self {
        Self {
            base: BaseRepository::new(db),
        }
    }

    pub fn base(&self) -> &BaseRepository<SysReportBoard> {
        &self.base
    }

    /// 查询某用户的全部看板（按更新时间倒序）
    pub async fn find_by_user_id(&self, user_id: i64) -> Result<Vec<Model>, DbErr> {
        SysReportBoard::find()
            .filter(Column::UserId.eq(user_id))
            .order_by_desc(Column::UpdateTime)
            .all(self.base.db())
            .await
    }

    /// 按 ID 查询看板（强制限定属主；他人/不存在的看板统一返回 None → 服务层 404 语义）
    pub async fn find_by_id_and_user(
        &self,
        id: i64,
        user_id: i64,
    ) -> Result<Option<Model>, DbErr> {
        SysReportBoard::find()
            .filter(Column::Id.eq(id))
            .filter(Column::UserId.eq(user_id))
            .one(self.base.db())
            .await
    }

    /// 检查同用户下同名看板是否已存在（创建时的唯一性预检；exclude_id 用于更新场景排除自身）
    pub async fn name_exists(
        &self,
        user_id: i64,
        name: &str,
        exclude_id: Option<i64>,
    ) -> Result<bool, DbErr> {
        let mut q = SysReportBoard::find()
            .filter(Column::UserId.eq(user_id))
            .filter(Column::Name.eq(name));
        if let Some(id) = exclude_id {
            q = q.filter(Column::Id.ne(id));
        }
        q.one(self.base.db()).await.map(|m| m.is_some())
    }

    /// 插入看板（返回自增 ID；create_time/update_time 由 ActiveModelBehavior 兜底填充）
    pub async fn insert(&self, model: Model) -> Result<i64, DbErr> {
        let mut am: ActiveModel = model.into();
        // 循环测试轮修复：Model→ActiveModel 转换会把 id=0 变成 Set(0)，SQLite 显式
        // 插入 0 覆盖自增 → 所有行 id=0，第二个看板触发 PRIMARY KEY 冲突（"数据重复"）。
        // id 必须置 NotSet 让自增生效（create_time 兜底仍由 before_save 填充）。
        am.id = sea_orm::NotSet;
        // 必须走 ActiveModelTrait::insert（内部触发 before_save 兜底时间戳）；
        // `Entity::insert(am).exec()` 不经过 ActiveModelBehavior，create_time 会以
        // NULL 入库并触发 NOT NULL 约束失败（Model→ActiveModel 转换把 None 变 Set(NULL)）。
        let saved = am.insert(self.base.db()).await?;
        Ok(saved.id)
    }

    /// 更新看板（按属主过滤，仅更新给定的列；update_time 同步刷新）
    ///
    /// 返回影响行数，0 = 看板不存在或非本人（404 语义）。
    pub async fn update_by_id_and_user(
        &self,
        id: i64,
        user_id: i64,
        name: Option<String>,
        config: Option<String>,
        enabled: Option<String>,
    ) -> Result<u64, DbErr> {
        let mut upd = SysReportBoard::update_many()
            .col_expr(
                Column::UpdateTime,
                Expr::value(crate::common::datetime::now_naive()),
            )
            .filter(Column::Id.eq(id))
            .filter(Column::UserId.eq(user_id));
        if let Some(n) = name {
            upd = upd.col_expr(Column::Name, Expr::value(n));
        }
        if let Some(c) = config {
            upd = upd.col_expr(Column::Config, Expr::value(c));
        }
        if let Some(e) = enabled {
            upd = upd.col_expr(Column::Enabled, Expr::value(e));
        }
        let res = upd.exec(self.base.db()).await?;
        Ok(res.rows_affected)
    }

    /// 删除看板（按属主过滤；返回影响行数）
    pub async fn delete_by_id_and_user(&self, id: i64, user_id: i64) -> Result<u64, DbErr> {
        let res = SysReportBoard::delete_many()
            .filter(Column::Id.eq(id))
            .filter(Column::UserId.eq(user_id))
            .exec(self.base.db())
            .await?;
        Ok(res.rows_affected)
    }

    /// 原始插入（供单元测试/工具使用）
    #[allow(dead_code)]
    pub async fn insert_raw(&self, model: Model) -> Result<(), DbErr> {
        let am: ActiveModel = model.into();
        SysReportBoard::insert(am).exec(self.base.db()).await?;
        Ok(())
    }
}
