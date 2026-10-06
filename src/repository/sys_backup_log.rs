// stepby-axum/src/repository/sys_backup_log.rs
//! sys_backup_log 数据访问层（数据备份日志表）
//!
//! 继承 BaseRepository 通用 CRUD，扩展备份日志特有查询：
//! - 多条件分页查询（backup_type / status / 时间范围）
//! - 按 ID 查询
//! - 批量删除

use chrono::NaiveDateTime;
use sea_orm::*;

use crate::common::sort::SortOrder;
use crate::entity::sys_backup_log::{ActiveModel, Column, Entity as SysBackupLog, Model};
use crate::repository::base::BaseRepository;

/// 数据备份日志 Repository
#[derive(Clone)]
pub struct SysBackupLogRepository {
    base: BaseRepository<SysBackupLog>,
}

impl SysBackupLogRepository {
    pub fn new(db: DatabaseConnection) -> Self {
        Self {
            base: BaseRepository::new(db),
        }
    }

    pub fn base(&self) -> &BaseRepository<SysBackupLog> {
        &self.base
    }

    /// 多条件分页查询
    ///
    /// 支持 backup_type 精确、status 精确、时间范围筛选，按 create_time 倒序；
    /// `tenant_id = Some(t)` 时按租户收窄；`tenant_export_only = true` 时只返回
    /// `backup_type = 'tenant_export'` 的行。
    ///
    /// 批次 2：租户自助只读路径复用本方法——同时传 `tenant_id = Some(自己)` 与
    /// `tenant_export_only = true` ⇒ 结构性保证租户看不到整库备份行（含路径/大小元数据）。
    ///
    /// `sort`：动态排序（方案 B，白名单已在 service 层解析为 `SortOrder`）；
    /// `None` 时回退默认 `create_time DESC`。
    #[allow(clippy::too_many_arguments)]
    pub async fn find_page_filtered(
        &self,
        offset: u64,
        limit: u64,
        backup_type: Option<&str>,
        status: Option<&str>,
        begin_time: Option<NaiveDateTime>,
        end_time: Option<NaiveDateTime>,
        tenant_id: Option<i64>,
        tenant_export_only: bool,
        sort: Option<SortOrder<Column>>,
    ) -> Result<(Vec<Model>, u64), DbErr> {
        let mut query = SysBackupLog::find();
        if let Some(tid) = tenant_id {
            query = query.filter(Column::TenantId.eq(tid));
        }
        if tenant_export_only {
            query = query.filter(
                Column::BackupType
                    .eq(crate::service::sys_backup_service::BACKUP_TYPE_TENANT_EXPORT),
            );
        }
        if let Some(bt) = backup_type {
            query = query.filter(Column::BackupType.eq(bt));
        }
        if let Some(st) = status {
            query = query.filter(Column::Status.eq(st));
        }
        if let Some(begin) = begin_time {
            query = query.filter(Column::CreateTime.gte(begin));
        }
        if let Some(end) = end_time {
            query = query.filter(Column::CreateTime.lte(end));
        }

        let total = query.clone().count(self.base.db()).await?;
        // 动态排序（白名单已解析）或默认 create_time DESC
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
    pub async fn find_by_id(&self, backup_id: i64) -> Result<Option<Model>, DbErr> {
        SysBackupLog::find_by_id(backup_id)
            .one(self.base.db())
            .await
    }

    /// 按 ID 批量查询（避免 N+1 查询）
    pub async fn find_by_ids(&self, ids: &[i64]) -> Result<Vec<Model>, DbErr> {
        SysBackupLog::find()
            .filter(Column::BackupId.is_in(ids.iter().copied()))
            .all(self.base.db())
            .await
    }

    /// 查询超出保留数量的 success 状态整库备份 ID 列表（按 BackupId 倒序，跳过最新 keep 条）
    ///
    /// 仅统计 `manual` / `auto` 整库备份：
    /// - `tenant_export` 是租户数据包留档，不参与轮转计数；
    /// - `restore` 只是恢复记录、无落盘文件，同样不参与。
    pub async fn find_excess_success_ids(&self, keep: usize) -> Result<Vec<i64>, DbErr> {
        let rows = SysBackupLog::find()
            .filter(
                Condition::any()
                    .add(Column::BackupType.eq("manual"))
                    .add(Column::BackupType.eq("auto")),
            )
            .filter(Column::Status.eq("success"))
            .order_by_desc(Column::BackupId)
            .all(self.base.db())
            .await?;
        Ok(rows.into_iter().skip(keep).map(|r| r.backup_id).collect())
    }

    /// 插入一条记录
    pub async fn insert(&self, model: ActiveModel) -> Result<Model, DbErr> {
        self.base.insert(model).await
    }

    /// 更新一条记录
    pub async fn update(&self, model: ActiveModel) -> Result<Model, DbErr> {
        model.update(self.base.db()).await
    }

    /// 批量删除（物理删除）
    pub async fn delete_by_ids(&self, ids: Vec<i64>) -> Result<DeleteResult, DbErr> {
        SysBackupLog::delete_many()
            .filter(Column::BackupId.is_in(ids))
            .exec(self.base.db())
            .await
    }
}
