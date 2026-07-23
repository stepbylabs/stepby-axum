// axum-backend/migration/src/m20260718_000001_add_more_indexes.rs
//! 第四次迁移：补充索引（修复 ROUNDS5-7 DB-23/24/27/28/29/30）
//!
//! 新增索引：
//! 1. DB-23: sys_dict_data.dict_label — 字典标签等值查询（LIKE %xxx% 仍走全表扫描）
//! 2. DB-24: sys_user.phonenumber — 手机号查询（user_name 已有唯一索引）
//! 3. DB-27: sys_oper_log.operator_type — 操作人类型筛选（business_type 已有索引）
//! 4. DB-28: sys_job.invoke_target — 调用目标查询
//! 5. DB-29: sys_job_log.job_name — 按任务名筛选日志（status/create_time 已有索引）
//! 6. DB-30: del_flag 软删除字段索引（8 张含 del_flag 的表）
//!
//! 说明：
//! - sys_dict_data 的 LIKE %xxx% 查询无法用 B-tree 索引优化，此处索引仅覆盖等值查询
//! - sys_notice / sys_config 无 del_flag 字段（物理删除），不创建 del_flag 索引
//! - 所有索引均使用 if_not_exists 确保幂等，兼容 PostgreSQL / MySQL / SQLite

use sea_orm_migration::prelude::*;

pub struct Migration;

impl MigrationName for Migration {
    fn name(&self) -> &str {
        "m20260718_000001_add_more_indexes"
    }
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // ========== DB-23: sys_dict_data.dict_label ==========
        manager
            .create_index(
                Index::create()
                    .if_not_exists()
                    .name("idx_sys_dict_data_label")
                    .table(Alias::new("sys_dict_data"))
                    .col(Alias::new("dict_label"))
                    .to_owned(),
            )
            .await?;

        // ========== DB-24: sys_user.phonenumber ==========
        manager
            .create_index(
                Index::create()
                    .if_not_exists()
                    .name("idx_sys_user_phonenumber")
                    .table(Alias::new("sys_user"))
                    .col(Alias::new("phonenumber"))
                    .to_owned(),
            )
            .await?;

        // ========== DB-27: sys_oper_log.operator_type ==========
        // 注：business_type 已有 idx_sys_oper_log_bt 索引
        manager
            .create_index(
                Index::create()
                    .if_not_exists()
                    .name("idx_sys_oper_log_operator_type")
                    .table(Alias::new("sys_oper_log"))
                    .col(Alias::new("operator_type"))
                    .to_owned(),
            )
            .await?;

        // ========== DB-28: sys_job.invoke_target ==========
        manager
            .create_index(
                Index::create()
                    .if_not_exists()
                    .name("idx_sys_job_invoke_target")
                    .table(Alias::new("sys_job"))
                    .col(Alias::new("invoke_target"))
                    .to_owned(),
            )
            .await?;

        // ========== DB-29: sys_job_log.job_name ==========
        // 注：status/create_time 已有索引
        manager
            .create_index(
                Index::create()
                    .if_not_exists()
                    .name("idx_sys_job_log_job_name")
                    .table(Alias::new("sys_job_log"))
                    .col(Alias::new("job_name"))
                    .to_owned(),
            )
            .await?;

        // ========== DB-30: del_flag 软删除字段索引 ==========
        // 为所有含 del_flag 字段的表补充索引，加速 WHERE del_flag = '0' 过滤
        // sys_notice / sys_config 无 del_flag（物理删除），不在此列
        for (idx_name, table) in [
            ("idx_sys_user_del_flag", "sys_user"),
            ("idx_sys_role_del_flag", "sys_role"),
            ("idx_sys_dept_del_flag", "sys_dept"),
            ("idx_sys_post_del_flag", "sys_post"),
            ("idx_sys_dict_type_del_flag", "sys_dict_type"),
            ("idx_sys_dict_data_del_flag", "sys_dict_data"),
            ("idx_sys_job_del_flag", "sys_job"),
        ] {
            manager
                .create_index(
                    Index::create()
                        .if_not_exists()
                        .name(idx_name)
                        .table(Alias::new(table))
                        .col(Alias::new("del_flag"))
                        .to_owned(),
                )
                .await?;
        }

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // 按反序删除索引
        for (idx_name, table) in [
            ("idx_sys_job_del_flag", "sys_job"),
            ("idx_sys_dict_data_del_flag", "sys_dict_data"),
            ("idx_sys_dict_type_del_flag", "sys_dict_type"),
            ("idx_sys_post_del_flag", "sys_post"),
            ("idx_sys_dept_del_flag", "sys_dept"),
            ("idx_sys_role_del_flag", "sys_role"),
            ("idx_sys_user_del_flag", "sys_user"),
            ("idx_sys_job_log_job_name", "sys_job_log"),
            ("idx_sys_job_invoke_target", "sys_job"),
            ("idx_sys_oper_log_operator_type", "sys_oper_log"),
            ("idx_sys_user_phonenumber", "sys_user"),
            ("idx_sys_dict_data_label", "sys_dict_data"),
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
