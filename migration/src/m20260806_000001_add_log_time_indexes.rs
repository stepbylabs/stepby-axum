// axum-backend/migration/src/m20260806_000001_add_log_time_indexes.rs
//! 第三十一次迁移：补充日志表时间/状态索引（R10 性能优化）
//!
//! 新增索引（按 P0 优先级）：
//! 1. sys_oper_log.oper_time — 操作日志按时间倒序分页 + 时间范围清理
//! 2. sys_logininfor.login_time — 登录日志按时间倒序分页 + 在线用户过滤
//! 3. sys_logininfor (status, login_time) 复合索引 — daily_stats 聚合 + find_online 查询
//! 4. sys_notice_read (notice_id, user_id) 复合索引 — 通知已读查询
//!
//! 性能影响：
//! - sys_oper_log 和 sys_logininfor 是生产增长最快的两张表
//! - 之前按 login_time/oper_time 过滤的分页查询走全表扫描
//! - daily_stats（每天 2 次 COUNT）通过 (status, login_time) 复合索引可走 Index Only Scan
//!
//! 所有索引使用 if_not_exists 确保幂等，兼容 PostgreSQL / MySQL / SQLite

use sea_orm_migration::prelude::*;

pub struct Migration;

impl MigrationName for Migration {
    fn name(&self) -> &str {
        "m20260806_000001_add_log_time_indexes"
    }
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // 1. sys_oper_log.oper_time — 操作日志按时间倒序分页 + 时间范围清理
        manager
            .create_index(
                Index::create()
                    .if_not_exists()
                    .name("idx_sys_oper_log_oper_time")
                    .table(Alias::new("sys_oper_log"))
                    .col(Alias::new("oper_time"))
                    .to_owned(),
            )
            .await?;

        // 2. sys_logininfor.login_time — 登录日志按时间倒序分页 + 在线用户过滤
        manager
            .create_index(
                Index::create()
                    .if_not_exists()
                    .name("idx_sys_logininfor_login_time")
                    .table(Alias::new("sys_logininfor"))
                    .col(Alias::new("login_time"))
                    .to_owned(),
            )
            .await?;

        // 3. sys_logininfor (status, login_time) 复合索引
        //    覆盖 daily_stats（WHERE status = ? AND login_time BETWEEN ? AND ?）
        //    和 find_online（WHERE status = '0' ORDER BY login_time DESC）
        manager
            .create_index(
                Index::create()
                    .if_not_exists()
                    .name("idx_sys_logininfor_status_login_time")
                    .table(Alias::new("sys_logininfor"))
                    .col(Alias::new("status"))
                    .col(Alias::new("login_time"))
                    .to_owned(),
            )
            .await?;

        // 4. sys_notice_read (notice_id, user_id) 复合索引
        //    覆盖"我的通知"列表（WHERE notice_id = ? ORDER BY user_id）
        //    和已读标记查询（WHERE notice_id = ? AND user_id = ?）
        manager
            .create_index(
                Index::create()
                    .if_not_exists()
                    .name("idx_sys_notice_read_notice_user")
                    .table(Alias::new("sys_notice_read"))
                    .col(Alias::new("notice_id"))
                    .col(Alias::new("user_id"))
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // 按反序删除索引
        for (idx_name, table) in [
            ("idx_sys_notice_read_notice_user", "sys_notice_read"),
            ("idx_sys_logininfor_status_login_time", "sys_logininfor"),
            ("idx_sys_logininfor_login_time", "sys_logininfor"),
            ("idx_sys_oper_log_oper_time", "sys_oper_log"),
        ] {
            manager
                .drop_index(
                    Index::drop()
                        .name(idx_name)
                        .table(Alias::new(table))
                        .to_owned(),
                )
                .await?;
        }
        Ok(())
    }
}
