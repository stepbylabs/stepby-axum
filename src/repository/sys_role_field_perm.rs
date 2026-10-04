// stepby-axum/src/repository/sys_role_field_perm.rs
//! sys_role_field_perm 数据访问层（角色字段级权限矩阵，物理删除）
//!
//! 提供字段权限矩阵的读写：
//! - 按角色 + 表查询 hidden 字段行（矩阵回显）
//! - 按角色集合 + 表查询 hidden 字段并集（列表裁剪判定的高频路径）
//! - 全量覆盖式保存（事务内 DELETE + INSERT，INSERT 冲突忽略保证幂等重放）
//!
//! 唯一约束 (role_id, table_key, field_key) 由迁移 m20261003_000005 承担，
//! 并发覆盖保存不会产生重复行。

use sea_orm::*;

use crate::entity::sys_role_field_perm::{Column, Entity as SysRoleFieldPerm, Model};
use crate::repository::base::BaseRepository;

/// 角色字段级权限 Repository
#[derive(Clone)]
pub struct SysRoleFieldPermRepository {
    base: BaseRepository<SysRoleFieldPerm>,
}

impl SysRoleFieldPermRepository {
    pub fn new(db: DatabaseConnection) -> Self {
        Self {
            base: BaseRepository::new(db),
        }
    }

    pub fn base(&self) -> &BaseRepository<SysRoleFieldPerm> {
        &self.base
    }

    /// 查询某角色在某业务表下的 hidden 字段行（矩阵回显用）
    pub async fn find_by_role_and_table(
        &self,
        role_id: i64,
        table_key: &str,
    ) -> Result<Vec<Model>, DbErr> {
        SysRoleFieldPerm::find()
            .filter(Column::RoleId.eq(role_id))
            .filter(Column::TableKey.eq(table_key))
            .all(self.base.db())
            .await
    }

    /// 查询角色集合在某业务表下的 hidden 字段并集（去重）
    ///
    /// 列表裁剪判定入口：operator 可能持有多个角色，hidden 语义取**并集**
    /// （任一角色声明隐藏即隐藏，收窄方向单一，不会因角色叠加而放宽）。
    pub async fn hidden_fields_by_roles(
        &self,
        role_ids: &[i64],
        table_key: &str,
    ) -> Result<Vec<String>, DbErr> {
        if role_ids.is_empty() {
            return Ok(Vec::new());
        }
        let rows = SysRoleFieldPerm::find()
            .filter(Column::RoleId.is_in(role_ids.to_vec()))
            .filter(Column::TableKey.eq(table_key))
            .all(self.base.db())
            .await?;
        // 去重：UNIQUE 约束保证 (role, table, field) 不重复，但多角色可声明同一字段
        let mut seen = std::collections::HashSet::new();
        Ok(rows
            .into_iter()
            .map(|r| r.field_key)
            .filter(|f| seen.insert(f.clone()))
            .collect())
    }

    /// 按角色集合物理删除 hidden 行（角色删除级联清理；事务上下文变体）
    ///
    /// 对齐 sys_role_menu 删除纪律：角色删除时同步清理其字段权限配置，
    /// 避免孤儿行累积（hidden 判定按用户当前角色集合查询，孤儿行无泄漏
    /// 风险但违背关联表清理纪律）。
    pub async fn delete_by_role_ids_conn<C: ConnectionTrait>(
        &self,
        txn: &C,
        role_ids: &[i64],
    ) -> Result<DeleteResult, DbErr> {
        if role_ids.is_empty() {
            return Ok(DeleteResult { rows_affected: 0 });
        }
        SysRoleFieldPerm::delete_many()
            .filter(Column::RoleId.is_in(role_ids.to_vec()))
            .exec(txn)
            .await
    }

    /// 全量覆盖式保存：删除该角色在该表下的全部行后重建 hidden 清单
    ///
    /// 事务保证：DELETE 与 INSERT 同事务，中途失败不产生"半清空"状态。
    /// INSERT 使用方言冲突忽略（依赖 UNIQUE 约束），重复提交 / 并发保存幂等。
    /// 入参 `hidden_fields` 应已由服务层做白名单过滤与去重。
    pub async fn replace_role_fields(
        &self,
        role_id: i64,
        table_key: &str,
        hidden_fields: &[String],
    ) -> Result<(), DbErr> {
        let db = self.base.db();
        let txn = db.begin().await?;

        // 1) 清空该角色在该表下的既有行
        SysRoleFieldPerm::delete_many()
            .filter(Column::RoleId.eq(role_id))
            .filter(Column::TableKey.eq(table_key))
            .exec(&txn)
            .await?;

        // 2) 重建 hidden 行（冲突忽略：并发保存时 UNIQUE 冲突静默跳过）。
        //    create_time 由 SQL 表达式提供（三方言）：表列 NOT NULL 无默认，
        //    缺列会被 INSERT OR IGNORE/IGNORE **静默吞掉**（NOT NULL 违规同被忽略），
        //    故必须在语句中显式提供。
        if !hidden_fields.is_empty() {
            let backend = db.get_database_backend();
            // 列清单与时间表达式固定来自代码（无用户可控拼接面）；值经参数化绑定
            let insert_sql = match backend {
                DatabaseBackend::Postgres => {
                    "INSERT INTO sys_role_field_perm (role_id, table_key, field_key, create_time) VALUES ($1, $2, $3, NOW()) ON CONFLICT DO NOTHING"
                }
                DatabaseBackend::Sqlite => {
                    "INSERT OR IGNORE INTO sys_role_field_perm (role_id, table_key, field_key, create_time) VALUES (?, ?, ?, datetime('now'))"
                }
                DatabaseBackend::MySql => {
                    "INSERT IGNORE INTO sys_role_field_perm (role_id, table_key, field_key, create_time) VALUES (?, ?, ?, NOW())"
                }
            };
            for field in hidden_fields {
                let stmt = Statement::from_sql_and_values(
                    backend,
                    insert_sql,
                    vec![role_id.into(), table_key.into(), field.into()],
                );
                txn.execute(stmt).await?;
            }
        }

        txn.commit().await?;
        Ok(())
    }
}
