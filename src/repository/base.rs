// stepby-axum/src/repository/base.rs
//! 通用 Repository 基类：封装 SeaORM 原生 CRUD 操作
//!
//! 设计原则：
//! - 仅使用 SeaORM 原生 API，不引入任何 Web 层类型
//! - 泛型约束 `E: EntityTrait`，支持所有 SeaORM 实体
//! - 复杂约束的方法（insert/update）通过 where 子句按需约束
//! - `_conn` 系列方法接受 `impl ConnectionTrait`，支持事务上下文
//!   使 Service 层在事务闭包内仍可通过 Repository 访问数据库

use sea_orm::PaginatorTrait;
use sea_orm::*;
use std::marker::PhantomData;

/// 通用 Repository 基类，封装常见的数据库 CRUD 操作
#[derive(Clone)]
pub struct BaseRepository<E: EntityTrait> {
    db: DatabaseConnection,
    _phantom: PhantomData<E>,
}

impl<E: EntityTrait + Send + Sync> BaseRepository<E>
where
    E::Model: Send + Sync,
{
    /// 创建 Repository 实例
    pub fn new(db: DatabaseConnection) -> Self {
        Self {
            db,
            _phantom: PhantomData,
        }
    }

    /// 获取数据库连接引用
    pub fn db(&self) -> &DatabaseConnection {
        &self.db
    }

    /// 查询全部记录
    pub async fn find_all(&self) -> Result<Vec<E::Model>, DbErr> {
        E::find().all(&self.db).await
    }

    /// 按主键查询单条记录
    /// 单主键传 i64，复合主键传 (i64, i64)
    pub async fn find_by_id<V>(&self, id: V) -> Result<Option<E::Model>, DbErr>
    where
        V: Into<<E::PrimaryKey as PrimaryKeyTrait>::ValueType>,
    {
        E::find_by_id(id).one(&self.db).await
    }

    /// 统计总记录数
    pub async fn count(&self) -> Result<u64, DbErr> {
        E::find().paginate(&self.db, 1).num_items().await
    }

    /// 执行自定义查询并返回多条记录
    pub async fn find_many(&self, select: Select<E>) -> Result<Vec<E::Model>, DbErr> {
        select.all(&self.db).await
    }

    /// 执行自定义查询并返回单条记录
    pub async fn find_one(&self, select: Select<E>) -> Result<Option<E::Model>, DbErr> {
        select.one(&self.db).await
    }

    /// 插入一条记录（返回完整 Model）
    ///
    /// DB-22：MySQL 不支持 RETURNING 子句，按 backend 分支处理：
    /// - PostgreSQL / SQLite：使用 `exec_with_returning`（原生 RETURNING）
    /// - MySQL：先 `exec`，再按主键性质分支（P0-7 修复）：
    ///   - 单列自增主键：`find_by_id(last_insert_id)` 回查（正确）
    ///   - 复合主键/非自增表（sys_role_menu / sys_role_dept / sys_user_post /
    ///     sys_user_role 等）：last_insert_id 恒为 0，回查必失败。此类表在
    ///     service 层一律使用 `insert_many_conn` 或各关联表专用批量方法，
    ///     本方法对它们返回明确错误指引，避免误用后得到误导性的 RecordNotFound。
    pub async fn insert(&self, model: E::ActiveModel) -> Result<E::Model, DbErr>
    where
        E::Model: IntoActiveModel<E::ActiveModel>,
    {
        let backend = self.db.get_database_backend();
        match backend {
            DatabaseBackend::MySql => {
                let res = E::insert(model).exec(&self.db).await?;
                if <E::PrimaryKey as PrimaryKeyTrait>::auto_increment() {
                    E::find_by_id(res.last_insert_id)
                        .one(&self.db)
                        .await?
                        .ok_or_else(|| {
                            DbErr::RecordNotFound("Failed to find inserted item".to_owned())
                        })
                } else {
                    tracing::warn!(
                        "BaseRepository::insert 不适用于 MySQL 复合主键/非自增表，请使用 insert_many_conn 或专用批量方法"
                    );
                    Err(DbErr::RecordNotFound(
                        "复合主键/非自增表在 MySQL 下请使用 insert_many_conn 或专用插入方法"
                            .to_owned(),
                    ))
                }
            }
            _ => E::insert(model).exec_with_returning(&self.db).await,
        }
    }

    /// 更新一条记录（返回更新后的 Model）
    pub async fn update(&self, model: E::ActiveModel) -> Result<E::Model, DbErr>
    where
        E::ActiveModel: ActiveModelTrait<Entity = E> + Send,
        E::Model: IntoActiveModel<E::ActiveModel>,
    {
        model.update(&self.db).await
    }

    /// 按主键物理删除
    pub async fn delete_by_id<V>(&self, id: V) -> Result<DeleteResult, DbErr>
    where
        V: Into<<E::PrimaryKey as PrimaryKeyTrait>::ValueType>,
    {
        E::delete_by_id(id).exec(&self.db).await
    }

    // ==================== 事务上下文方法（_conn 系列） ====================
    //
    // 这些方法接受 `impl ConnectionTrait` 参数，既可传入 `&DatabaseConnection`
    // 也可传入 `&Transaction`，使 Service 层在事务闭包内仍通过 Repository 访问数据库。
    // 方法为实例方法（`&self`）以复用具体 Repository 的调用路径，但内部不使用 `self.db`。

    /// 按主键查询单条记录（使用指定连接）
    pub async fn find_by_id_conn<C, V>(&self, conn: &C, id: V) -> Result<Option<E::Model>, DbErr>
    where
        C: ConnectionTrait,
        V: Into<<E::PrimaryKey as PrimaryKeyTrait>::ValueType>,
    {
        E::find_by_id(id).one(conn).await
    }

    /// 执行自定义查询返回单条记录（使用指定连接）
    pub async fn find_one_conn<C: ConnectionTrait>(
        &self,
        conn: &C,
        select: Select<E>,
    ) -> Result<Option<E::Model>, DbErr> {
        select.one(conn).await
    }

    /// 执行自定义查询返回多条记录（使用指定连接）
    pub async fn find_many_conn<C: ConnectionTrait>(
        &self,
        conn: &C,
        select: Select<E>,
    ) -> Result<Vec<E::Model>, DbErr> {
        select.all(conn).await
    }

    /// 插入一条记录（使用指定连接，返回完整 Model）
    ///
    /// DB-22：MySQL 不支持 RETURNING 子句，按 backend 分支处理：
    /// - PostgreSQL / SQLite：使用 `exec_with_returning`（原生 RETURNING）
    /// - MySQL：单列自增回查 last_insert_id；复合主键/非自增表返回明确错误指引（P0-7）
    pub async fn insert_conn<C>(&self, conn: &C, model: E::ActiveModel) -> Result<E::Model, DbErr>
    where
        C: ConnectionTrait,
        E::Model: IntoActiveModel<E::ActiveModel>,
    {
        let backend = conn.get_database_backend();
        match backend {
            DatabaseBackend::MySql => {
                let res = E::insert(model).exec(conn).await?;
                if <E::PrimaryKey as PrimaryKeyTrait>::auto_increment() {
                    E::find_by_id(res.last_insert_id)
                        .one(conn)
                        .await?
                        .ok_or_else(|| {
                            DbErr::RecordNotFound("Failed to find inserted item".to_owned())
                        })
                } else {
                    tracing::warn!(
                        "BaseRepository::insert_conn 不适用于 MySQL 复合主键/非自增表，请使用 insert_many_conn 或专用批量方法"
                    );
                    Err(DbErr::RecordNotFound(
                        "复合主键/非自增表在 MySQL 下请使用 insert_many_conn 或专用插入方法"
                            .to_owned(),
                    ))
                }
            }
            _ => E::insert(model).exec_with_returning(conn).await,
        }
    }

    /// 批量插入记录（使用指定连接）
    ///
    /// 注意：MySQL 不支持 `exec_with_returning`，返回的是受影响行数而非 Model 列表。
    /// §5.52（sea-orm 2.0）：insert_many 返回 InsertManyResult（last_insert_id 变为
    /// Option）——本包装统一改返回受影响行数 u64（调用方仅需行数语义，无取回 last id 需求）。
    pub async fn insert_many_conn<C>(
        &self,
        conn: &C,
        models: Vec<E::ActiveModel>,
    ) -> Result<u64, DbErr>
    where
        C: ConnectionTrait,
        E::Model: IntoActiveModel<E::ActiveModel>,
    {
        // §5.52（sea-orm 2.0）：InsertManyResult 无 rows_affected 字段——
        // 批量插入的受影响行数 = 输入模型数（INSERT 语义恒等）
        let n = models.len() as u64;
        E::insert_many(models).exec(conn).await?;
        Ok(n)
    }

    /// 更新一条记录（使用指定连接，返回更新后的 Model）
    pub async fn update_conn<C>(&self, conn: &C, model: E::ActiveModel) -> Result<E::Model, DbErr>
    where
        C: ConnectionTrait,
        E::ActiveModel: ActiveModelTrait<Entity = E> + Send,
        E::Model: IntoActiveModel<E::ActiveModel>,
    {
        model.update(conn).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entity::sys_job::{self, ActiveModel as SysJobActiveModel, Entity as SysJob};

    // 覆盖意图：
    // - 基础 CRUD（find_all / find_by_id / count / insert / update / delete_by_id）
    // - 自定义查询（find_many / find_one）
    // - _conn 系列（insert_conn / find_by_id_conn / find_many_conn / find_one_conn /
    //   insert_many_conn / update_conn）
    // - 事务上下文（begin/commit 可见性 + rollback 回滚）
    // 使用 test_support::migrated_db() 创建隔离 SQLite，避免外部依赖。

    fn make_job(name: &str) -> SysJobActiveModel {
        SysJobActiveModel {
            tenant_id: Set(0),
            job_name: Set(name.to_string()),
            job_group: Set("DEFAULT".to_string()),
            invoke_target: Set("unitTest.base".to_string()),
            cron_expression: Set(Some("0 0 3 * * *".to_string())),
            misfire_policy: Set(Some("3".to_string())),
            concurrent: Set(Some("1".to_string())),
            status: Set(Some("0".to_string())),
            create_by: Set(None),
            create_time: Set(None),
            update_by: Set(None),
            update_time: Set(None),
            remark: Set(None),
            del_flag: Set(Some("0".to_string())),
            job_id: NotSet,
        }
    }

    #[tokio::test]
    async fn test_crud_roundtrip() {
        let db = crate::repository::test_support::migrated_db()
            .await
            .unwrap();
        let repo = BaseRepository::<SysJob>::new(db.clone());

        // 迁移种子数据默认 3 条系统任务
        assert_eq!(repo.count().await.unwrap(), 3);
        assert_eq!(repo.find_all().await.unwrap().len(), 3);

        // insert：返回完整 Model，自增主键已填充
        let model = repo.insert(make_job("t1")).await.unwrap();
        assert!(model.job_id > 0);
        assert_eq!(model.job_name, "t1");
        assert_eq!(model.del_flag.as_deref(), Some("0"));
        // 实体无 before_save 自动时间戳钩子，插入时 create_time/update_time 保持 None
        assert!(model.create_time.is_none());
        assert!(model.update_time.is_none());

        assert_eq!(repo.count().await.unwrap(), 4);

        // find_by_id：命中与未命中
        let found = repo.find_by_id(model.job_id).await.unwrap().unwrap();
        assert_eq!(found.job_name, "t1");
        assert!(repo.find_by_id(999999999).await.unwrap().is_none());

        // find_all 返回 4 条（3 种子 + 1 新增）
        assert_eq!(repo.find_all().await.unwrap().len(), 4);

        // update：修改字段后回读
        let mut am = found.into_active_model();
        am.job_name = Set("t1-updated".to_string());
        let updated = repo.update(am).await.unwrap();
        assert_eq!(updated.job_name, "t1-updated");
        assert_eq!(
            repo.find_by_id(model.job_id)
                .await
                .unwrap()
                .unwrap()
                .job_name,
            "t1-updated"
        );

        // delete_by_id：物理删除，恢复种子数量
        let res = repo.delete_by_id(model.job_id).await.unwrap();
        assert_eq!(res.rows_affected, 1);
        assert_eq!(repo.count().await.unwrap(), 3);
        assert!(repo.find_by_id(model.job_id).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn test_find_many_and_find_one() {
        let db = crate::repository::test_support::migrated_db()
            .await
            .unwrap();
        let repo = BaseRepository::<SysJob>::new(db.clone());
        repo.insert(make_job("alpha")).await.unwrap();
        repo.insert(make_job("beta")).await.unwrap();
        repo.insert(make_job("gamma")).await.unwrap();

        // 条件查询多条（仅 alpha 含 "ph"）
        let sel = SysJob::find().filter(sys_job::Column::JobName.like("%ph%"));
        let rows = repo.find_many(sel.clone()).await.unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].job_name, "alpha");

        // 查询单条
        let one = repo.find_one(sel).await.unwrap().unwrap();
        assert_eq!(one.job_name, "alpha");

        // 宽泛匹配（alpha/beta/gamma 均含 'a'）
        let all = repo
            .find_many(SysJob::find().filter(sys_job::Column::JobName.like("%a%")))
            .await
            .unwrap();
        assert_eq!(all.len(), 3);

        // 空结果
        let none = SysJob::find().filter(sys_job::Column::JobName.eq("zzz"));
        assert!(repo.find_one(none).await.unwrap().is_none());
        assert!(
            repo.find_many(SysJob::find().filter(sys_job::Column::JobName.eq("zzz")))
                .await
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn test_conn_variants_with_database_connection() {
        let db = crate::repository::test_support::migrated_db()
            .await
            .unwrap();
        let repo = BaseRepository::<SysJob>::new(db.clone());

        // insert_conn
        let model = repo.insert_conn(&db, make_job("conn-a")).await.unwrap();
        assert!(model.job_id > 0);

        // find_by_id_conn
        let found = repo
            .find_by_id_conn(&db, model.job_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(found.job_name, "conn-a");

        // find_many_conn / find_one_conn
        let sel = SysJob::find().filter(sys_job::Column::JobId.eq(model.job_id));
        assert_eq!(
            repo.find_many_conn(&db, sel.clone()).await.unwrap().len(),
            1
        );
        assert!(repo.find_one_conn(&db, sel).await.unwrap().is_some());

        // insert_many_conn（§5.52 sea-orm 2.0：改返回受影响行数）
        let res = repo
            .insert_many_conn(&db, vec![make_job("conn-b"), make_job("conn-c")])
            .await
            .unwrap();
        assert_eq!(res, 2);
        // 总条数 = 3 种子 + 3 新增
        assert_eq!(repo.count().await.unwrap(), 6);

        // update_conn
        let mut am = found.into_active_model();
        am.job_name = Set("conn-a-updated".to_string());
        let updated = repo.update_conn(&db, am).await.unwrap();
        assert_eq!(updated.job_name, "conn-a-updated");
    }

    #[tokio::test]
    async fn test_transaction_commit_persists_changes() {
        let db = crate::repository::test_support::migrated_db()
            .await
            .unwrap();
        let repo = BaseRepository::<SysJob>::new(db.clone());

        let tx = db.begin().await.unwrap();
        let model = repo.insert_conn(&tx, make_job("tx-commit")).await.unwrap();
        // 事务内可见
        assert!(
            repo.find_by_id_conn(&tx, model.job_id)
                .await
                .unwrap()
                .is_some()
        );
        tx.commit().await.unwrap();

        // 提交后通过连接池可见
        let found = repo.find_by_id(model.job_id).await.unwrap().unwrap();
        assert_eq!(found.job_name, "tx-commit");
    }

    #[tokio::test]
    async fn test_transaction_rollback_discards_changes() {
        let db = crate::repository::test_support::migrated_db()
            .await
            .unwrap();
        let repo = BaseRepository::<SysJob>::new(db.clone());

        let tx = db.begin().await.unwrap();
        let model = repo
            .insert_conn(&tx, make_job("tx-rollback"))
            .await
            .unwrap();
        assert!(
            repo.find_by_id_conn(&tx, model.job_id)
                .await
                .unwrap()
                .is_some()
        );
        tx.rollback().await.unwrap();

        // 回滚后连接池不可见，数量恢复种子 3 条
        assert!(repo.find_by_id(model.job_id).await.unwrap().is_none());
        assert_eq!(repo.count().await.unwrap(), 3);
    }

    #[tokio::test]
    async fn test_find_by_id_unknown_id_returns_none() {
        let db = crate::repository::test_support::migrated_db()
            .await
            .unwrap();
        let repo = BaseRepository::<SysJob>::new(db.clone());
        // 种子占用 1-3，999999999 必然不存在
        assert!(repo.find_by_id(999999999).await.unwrap().is_none());
        assert!(
            repo.find_by_id_conn(&db, 999999999)
                .await
                .unwrap()
                .is_none()
        );
    }
}
