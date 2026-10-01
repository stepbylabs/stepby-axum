//! sys_shared_lock 实体定义（SharedStore 调度锁表）
//!
//! 承载：job 防重入锁 `lock:scheduler:{job_id}`（**单实例也需要**）与
//! 内置任务整轮互斥锁（随 `[scheduler].cluster_mode`）。
//!
//! 语义与 Redis 分布式锁等价：
//! - acquire  = `INSERT`（PK 冲突且未过期 → 失败；已过期 → 抢占式 UPDATE）
//! - release  = `DELETE WHERE lock_key = ? AND lock_token = ?`（CAS，防误删他实例锁）
//! - renew    = `UPDATE expire_at WHERE lock_key = ? AND lock_token = ?`（CAS）
//!
//! 全部单语句原子（DB 行级约束保证），无 Lua 需求。

use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, DeriveEntityModel)]
#[sea_orm(table_name = "sys_shared_lock")]
pub struct Model {
    /// 锁键（如 `lock:scheduler:flow_timeout_scan`）
    #[sea_orm(primary_key, auto_increment = false)]
    pub lock_key: String,
    /// 持锁者 fencing token（UUID v4；释放/续期必须匹配，防误删）
    pub lock_token: String,
    /// 过期时间（UTC 秒；超时后其他实例可抢占）
    pub expire_at: i64,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

#[async_trait::async_trait]
impl ActiveModelBehavior for ActiveModel {}
