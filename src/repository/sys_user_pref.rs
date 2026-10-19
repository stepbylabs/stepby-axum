// stepby-axum/src/repository/sys_user_pref.rs
//! 用户消息偏好 / 免打扰（sys_user_pref 表）数据访问层
//!
//! 以 user_id 为主键，每用户至多一行。提供单用户查询、批量查询（enforcement 用）
//! 与安全的 upsert 写入（跨 SQLite / PostgreSQL / MySQL 均采用原生冲突处理语义）。

use sea_orm::*;

use crate::entity::sys_user_pref::{Column, Entity as SysUserPref, Model};
use crate::repository::base::BaseRepository;

/// 用户消息偏好 Repository
#[derive(Clone)]
pub struct SysUserPrefRepository {
    base: BaseRepository<SysUserPref>,
}

impl SysUserPrefRepository {
    pub fn new(db: DatabaseConnection) -> Self {
        Self {
            base: BaseRepository::new(db),
        }
    }

    pub fn base(&self) -> &BaseRepository<SysUserPref> {
        &self.base
    }

    /// 按 user_id 查询偏好（无记录返回 None，调用方按默认值处理）
    pub async fn find_by_user_id(&self, user_id: i64) -> Result<Option<Model>, DbErr> {
        SysUserPref::find_by_id(user_id).one(self.base.db()).await
    }

    /// 批量查询多个用户的偏好（enforcement：一次查询关联用户，减少 N 次往返）
    pub async fn find_by_user_ids(&self, user_ids: &[i64]) -> Result<Vec<Model>, DbErr> {
        if user_ids.is_empty() {
            return Ok(Vec::new());
        }
        SysUserPref::find()
            .filter(Column::UserId.is_in(user_ids.iter().copied()))
            .all(self.base.db())
            .await
    }

    /// 幂等写入偏好（用户无记录则插入，有则整行更新）
    ///
    /// 使用数据库原生 upsert 语义（SQLite/PostgreSQL `ON CONFLICT ... DO UPDATE`，
    /// MySQL `ON DUPLICATE KEY UPDATE`），避免「先查后写」的 TOCTOU 竞态，
    /// 并规避 BaseRepository::insert 在 MySQL 复合/非自增主键表上的局限（本表主键为 user_id）。
    pub async fn upsert(&self, user_id: i64, model: &Model) -> Result<(), DbErr> {
        let db = self.base.db();
        let backend = db.get_database_backend();
        let now = crate::common::datetime::now_naive();
        let sql = match backend {
            DatabaseBackend::Sqlite => {
                "INSERT INTO sys_user_pref \
                 (user_id, tenant_id, email_notify, sysmsg_notify, announce_notify, dnd_enabled, dnd_start, dnd_end, update_time) \
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) \
                 ON CONFLICT(user_id) DO UPDATE SET \
                    email_notify=excluded.email_notify, sysmsg_notify=excluded.sysmsg_notify, \
                    announce_notify=excluded.announce_notify, dnd_enabled=excluded.dnd_enabled, \
                    dnd_start=excluded.dnd_start, dnd_end=excluded.dnd_end, update_time=excluded.update_time"
            }
            DatabaseBackend::Postgres => {
                "INSERT INTO sys_user_pref \
                 (user_id, tenant_id, email_notify, sysmsg_notify, announce_notify, dnd_enabled, dnd_start, dnd_end, update_time) \
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) \
                 ON CONFLICT(user_id) DO UPDATE SET \
                    email_notify=excluded.email_notify, sysmsg_notify=excluded.sysmsg_notify, \
                    announce_notify=excluded.announce_notify, dnd_enabled=excluded.dnd_enabled, \
                    dnd_start=excluded.dnd_start, dnd_end=excluded.dnd_end, update_time=excluded.update_time"
            }
            DatabaseBackend::MySql => {
                "INSERT INTO sys_user_pref \
                 (user_id, tenant_id, email_notify, sysmsg_notify, announce_notify, dnd_enabled, dnd_start, dnd_end, update_time) \
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) \
                 ON DUPLICATE KEY UPDATE \
                    email_notify=VALUES(email_notify), sysmsg_notify=VALUES(sysmsg_notify), \
                    announce_notify=VALUES(announce_notify), dnd_enabled=VALUES(dnd_enabled), \
                    dnd_start=VALUES(dnd_start), dnd_end=VALUES(dnd_end), update_time=VALUES(update_time)"
            }
            _ => unreachable!("unknown backend"),
        };
        let values: Vec<Value> = vec![
            user_id.into(),
            model.tenant_id.into(),
            model.email_notify.clone().into(),
            model.sysmsg_notify.clone().into(),
            model.announce_notify.clone().into(),
            model.dnd_enabled.clone().into(),
            model.dnd_start.clone().into(),
            model.dnd_end.clone().into(),
            now.into(),
        ];
        let stmt = Statement::from_sql_and_values(backend, sql, values);
        db.execute_raw(stmt).await?;
        Ok(())
    }
}
