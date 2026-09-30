// stepby-axum/migration/src/m20250711_000001_init.rs
//! 初始迁移：创建 15 张系统核心表 + 索引 + 初始数据
//!
//! 表清单（按创建顺序）：
//! 1. sys_user        - 用户信息表
//! 2. sys_role        - 角色信息表
//! 3. sys_menu        - 菜单权限表
//! 4. sys_user_role   - 用户角色关联表
//! 5. sys_role_menu   - 角色菜单关联表
//! 6. sys_dict_type   - 字典类型表
//! 7. sys_dict_data   - 字典数据表
//! 8. sys_oper_log    - 操作日志表
//! 9. sys_logininfor  - 系统访问记录表
//! 10. sys_job        - 定时任务调度表
//! 11. sys_job_log    - 定时任务调度日志表
//! 12. sys_dept       - 部门信息表
//! 13. sys_post       - 岗位信息表
//! 14. sys_user_post  - 用户岗位关联表
//! 15. sys_role_dept  - 角色部门关联表

use sea_orm_migration::prelude::*;

/// 判断当前数据库是否为 SQLite
fn is_sqlite(manager: &SchemaManager<'_>) -> bool {
    let backend = manager.get_connection().get_database_backend();
    matches!(backend, sea_orm_migration::sea_orm::DatabaseBackend::Sqlite)
}

/// 判断当前数据库是否为 PostgreSQL
fn is_postgres(manager: &SchemaManager<'_>) -> bool {
    let backend = manager.get_connection().get_database_backend();
    matches!(
        backend,
        sea_orm_migration::sea_orm::DatabaseBackend::Postgres
    )
}

/// 获取当前时间 SQL 表达式（数据库兼容）
///
/// SQLite 的 `datetime('now')` 在 `execute_unprepared` 中可能与 SQL 字符串的单引号冲突，
/// 因此 SQLite 使用预计算的时间字符串；MySQL/PostgreSQL 使用 `NOW()` 函数。
fn now_expr(manager: &SchemaManager<'_>) -> String {
    if is_sqlite(manager) {
        // SQLite: 预计算为 ISO8601 字符串，避免函数调用中的单引号冲突
        let now = chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
        format!("'{}'", now)
    } else {
        "NOW()".to_string()
    }
}

/// 构建幂等 INSERT 语句（P0-65）
///
/// 多数据库兼容的幂等插入：
/// - SQLite: `INSERT OR IGNORE INTO ...`
/// - MySQL: `INSERT IGNORE INTO ...`
/// - PostgreSQL: `INSERT INTO ... ON CONFLICT DO NOTHING`
///
/// 参数 `body` 为不含 `INSERT INTO` 前缀的 SQL 主体，如：
/// `"sys_user (user_id, ...) VALUES (...)"`
async fn execute_idempotent_insert(manager: &SchemaManager<'_>, body: &str) -> Result<(), DbErr> {
    let sql = if is_sqlite(manager) {
        format!("INSERT OR IGNORE INTO {}", body)
    } else if is_postgres(manager) {
        format!("INSERT INTO {} ON CONFLICT DO NOTHING", body)
    } else {
        // MySQL
        format!("INSERT IGNORE INTO {}", body)
    };
    manager.get_connection().execute_unprepared(&sql).await?;
    Ok(())
}

pub struct Migration;

impl MigrationName for Migration {
    fn name(&self) -> &str {
        "m20250711_000001_init"
    }
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // ========== 1. 创建表 ==========
        create_sys_user(manager).await?;
        create_sys_role(manager).await?;
        create_sys_menu(manager).await?;
        create_sys_user_role(manager).await?;
        create_sys_role_menu(manager).await?;
        create_sys_dict_type(manager).await?;
        create_sys_dict_data(manager).await?;
        create_sys_oper_log(manager).await?;
        create_sys_logininfor(manager).await?;
        create_sys_job(manager).await?;
        create_sys_job_log(manager).await?;
        create_sys_dept(manager).await?;
        create_sys_post(manager).await?;
        create_sys_user_post(manager).await?;
        create_sys_role_dept(manager).await?;
        create_sys_config(manager).await?;
        create_sys_notice(manager).await?;

        // ========== 2. 设置自增起始值 ==========
        set_auto_increment(manager).await?;

        // ========== 3. 插入初始数据 ==========
        insert_sys_user(manager).await?;
        insert_sys_role(manager).await?;
        insert_sys_menu(manager).await?;
        insert_sys_user_role(manager).await?;
        insert_sys_role_menu(manager).await?;
        insert_sys_dict_type(manager).await?;
        insert_sys_dict_data(manager).await?;
        insert_sys_job(manager).await?;
        insert_sys_dept(manager).await?;
        insert_sys_post(manager).await?;
        insert_sys_config(manager).await?;
        insert_sys_notice(manager).await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // 按反序删除表
        let tables = [
            "sys_notice",
            "sys_config",
            "sys_role_dept",
            "sys_user_post",
            "sys_post",
            "sys_dept",
            "sys_job_log",
            "sys_job",
            "sys_logininfor",
            "sys_oper_log",
            "sys_dict_data",
            "sys_dict_type",
            "sys_role_menu",
            "sys_user_role",
            "sys_menu",
            "sys_role",
            "sys_user",
        ];
        for table in tables {
            // 表名均为简单标识符（sys_xxx），无需引号，跨数据库兼容
            let sql = format!("DROP TABLE IF EXISTS {}", table);
            manager.get_connection().execute_unprepared(&sql).await?;
        }
        Ok(())
    }
}

// ========== 建表函数 ==========

/// 创建 sys_user 表
async fn create_sys_user(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    manager
        .create_table(
            Table::create()
                .table(Alias::new("sys_user"))
                .if_not_exists()
                .col(
                    ColumnDef::new(Alias::new("user_id"))
                        .big_integer()
                        .not_null()
                        .auto_increment()
                        .primary_key(),
                )
                .col(ColumnDef::new(Alias::new("dept_id")).big_integer().null())
                .col(
                    ColumnDef::new(Alias::new("user_name"))
                        .string_len(30)
                        .not_null(),
                )
                .col(
                    ColumnDef::new(Alias::new("nick_name"))
                        .string_len(30)
                        .not_null(),
                )
                .col(
                    ColumnDef::new(Alias::new("user_type"))
                        .string_len(2)
                        .default("00"),
                )
                .col(
                    ColumnDef::new(Alias::new("email"))
                        .string_len(50)
                        .default(""),
                )
                .col(
                    ColumnDef::new(Alias::new("phonenumber"))
                        .string_len(11)
                        .default(""),
                )
                .col(
                    ColumnDef::new(Alias::new("country_code"))
                        .string_len(8)
                        .null(),
                )
                .col(ColumnDef::new(Alias::new("sex")).char().default("0"))
                .col(
                    ColumnDef::new(Alias::new("avatar"))
                        .string_len(100)
                        .default(""),
                )
                .col(
                    ColumnDef::new(Alias::new("password"))
                        .string_len(255)
                        .default(""),
                )
                .col(ColumnDef::new(Alias::new("status")).char().default("0"))
                .col(ColumnDef::new(Alias::new("del_flag")).char().default("0"))
                .col(
                    ColumnDef::new(Alias::new("login_ip"))
                        .string_len(128)
                        .default(""),
                )
                .col(ColumnDef::new(Alias::new("login_date")).date_time().null())
                .col(
                    ColumnDef::new(Alias::new("create_by"))
                        .string_len(64)
                        .default(""),
                )
                .col(ColumnDef::new(Alias::new("create_time")).date_time().null())
                .col(
                    ColumnDef::new(Alias::new("update_by"))
                        .string_len(64)
                        .default(""),
                )
                .col(ColumnDef::new(Alias::new("update_time")).date_time().null())
                .col(ColumnDef::new(Alias::new("remark")).string_len(500).null())
                .to_owned(),
        )
        .await?;

    // 唯一索引
    manager
        .create_index(
            Index::create()
                .if_not_exists()
                .name("uk_sys_user_name")
                .table(Alias::new("sys_user"))
                .col(Alias::new("user_name"))
                .unique()
                .to_owned(),
        )
        .await?;

    // 普通索引
    manager
        .create_index(
            Index::create()
                .if_not_exists()
                .name("idx_sys_user_dept")
                .table(Alias::new("sys_user"))
                .col(Alias::new("dept_id"))
                .to_owned(),
        )
        .await?;

    Ok(())
}

/// 创建 sys_role 表
async fn create_sys_role(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    manager
        .create_table(
            Table::create()
                .table(Alias::new("sys_role"))
                .if_not_exists()
                .col(
                    ColumnDef::new(Alias::new("role_id"))
                        .big_integer()
                        .not_null()
                        .auto_increment()
                        .primary_key(),
                )
                .col(
                    ColumnDef::new(Alias::new("role_name"))
                        .string_len(30)
                        .not_null(),
                )
                .col(
                    ColumnDef::new(Alias::new("role_key"))
                        .string_len(100)
                        .not_null(),
                )
                .col(ColumnDef::new(Alias::new("role_sort")).integer().not_null())
                .col(ColumnDef::new(Alias::new("data_scope")).char().default("1"))
                .col(
                    ColumnDef::new(Alias::new("menu_check_strictly"))
                        .boolean()
                        .default(true),
                )
                .col(
                    ColumnDef::new(Alias::new("dept_check_strictly"))
                        .boolean()
                        .default(true),
                )
                .col(ColumnDef::new(Alias::new("status")).char().not_null())
                .col(ColumnDef::new(Alias::new("del_flag")).char().default("0"))
                .col(
                    ColumnDef::new(Alias::new("create_by"))
                        .string_len(64)
                        .default(""),
                )
                .col(ColumnDef::new(Alias::new("create_time")).date_time().null())
                .col(
                    ColumnDef::new(Alias::new("update_by"))
                        .string_len(64)
                        .default(""),
                )
                .col(ColumnDef::new(Alias::new("update_time")).date_time().null())
                .col(ColumnDef::new(Alias::new("remark")).string_len(500).null())
                .to_owned(),
        )
        .await?;

    manager
        .create_index(
            Index::create()
                .if_not_exists()
                .name("uk_sys_role_key")
                .table(Alias::new("sys_role"))
                .col(Alias::new("role_key"))
                .unique()
                .to_owned(),
        )
        .await?;

    Ok(())
}

/// 创建 sys_menu 表
async fn create_sys_menu(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    manager
        .create_table(
            Table::create()
                .table(Alias::new("sys_menu"))
                .if_not_exists()
                .col(
                    ColumnDef::new(Alias::new("menu_id"))
                        .big_integer()
                        .not_null()
                        .auto_increment()
                        .primary_key(),
                )
                .col(
                    ColumnDef::new(Alias::new("menu_name"))
                        .string_len(50)
                        .not_null(),
                )
                .col(
                    ColumnDef::new(Alias::new("parent_id"))
                        .big_integer()
                        .default(0),
                )
                .col(ColumnDef::new(Alias::new("order_num")).integer().default(0))
                .col(
                    ColumnDef::new(Alias::new("path"))
                        .string_len(200)
                        .default(""),
                )
                .col(
                    ColumnDef::new(Alias::new("component"))
                        .string_len(255)
                        .null(),
                )
                .col(ColumnDef::new(Alias::new("query")).string_len(255).null())
                .col(
                    ColumnDef::new(Alias::new("route_name"))
                        .string_len(50)
                        .default(""),
                )
                .col(ColumnDef::new(Alias::new("is_frame")).char().default("1"))
                .col(ColumnDef::new(Alias::new("is_cache")).char().default("0"))
                .col(ColumnDef::new(Alias::new("menu_type")).char().default(""))
                .col(ColumnDef::new(Alias::new("visible")).char().default("0"))
                .col(ColumnDef::new(Alias::new("status")).char().default("0"))
                .col(ColumnDef::new(Alias::new("perms")).string_len(100).null())
                .col(
                    ColumnDef::new(Alias::new("icon"))
                        .string_len(100)
                        .default("#"),
                )
                .col(
                    ColumnDef::new(Alias::new("create_by"))
                        .string_len(64)
                        .default(""),
                )
                .col(ColumnDef::new(Alias::new("create_time")).date_time().null())
                .col(
                    ColumnDef::new(Alias::new("update_by"))
                        .string_len(64)
                        .default(""),
                )
                .col(ColumnDef::new(Alias::new("update_time")).date_time().null())
                .col(
                    ColumnDef::new(Alias::new("remark"))
                        .string_len(500)
                        .default(""),
                )
                .col(ColumnDef::new(Alias::new("del_flag")).char().default("0"))
                .to_owned(),
        )
        .await?;

    manager
        .create_index(
            Index::create()
                .if_not_exists()
                .name("idx_sys_menu_parent")
                .table(Alias::new("sys_menu"))
                .col(Alias::new("parent_id"))
                .to_owned(),
        )
        .await?;

    Ok(())
}

/// 创建 sys_user_role 表（复合主键）
async fn create_sys_user_role(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    manager
        .create_table(
            Table::create()
                .table(Alias::new("sys_user_role"))
                .if_not_exists()
                .col(
                    ColumnDef::new(Alias::new("user_id"))
                        .big_integer()
                        .not_null(),
                )
                .col(
                    ColumnDef::new(Alias::new("role_id"))
                        .big_integer()
                        .not_null(),
                )
                .primary_key(
                    Index::create()
                        .col(Alias::new("user_id"))
                        .col(Alias::new("role_id")),
                )
                .to_owned(),
        )
        .await?;

    manager
        .create_index(
            Index::create()
                .if_not_exists()
                .name("idx_sys_user_role_role")
                .table(Alias::new("sys_user_role"))
                .col(Alias::new("role_id"))
                .to_owned(),
        )
        .await?;

    Ok(())
}

/// 创建 sys_role_menu 表（复合主键）
async fn create_sys_role_menu(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    manager
        .create_table(
            Table::create()
                .table(Alias::new("sys_role_menu"))
                .if_not_exists()
                .col(
                    ColumnDef::new(Alias::new("role_id"))
                        .big_integer()
                        .not_null(),
                )
                .col(
                    ColumnDef::new(Alias::new("menu_id"))
                        .big_integer()
                        .not_null(),
                )
                .primary_key(
                    Index::create()
                        .col(Alias::new("role_id"))
                        .col(Alias::new("menu_id")),
                )
                .to_owned(),
        )
        .await?;

    manager
        .create_index(
            Index::create()
                .if_not_exists()
                .name("idx_sys_role_menu_menu")
                .table(Alias::new("sys_role_menu"))
                .col(Alias::new("menu_id"))
                .to_owned(),
        )
        .await?;

    Ok(())
}

/// 创建 sys_dict_type 表
async fn create_sys_dict_type(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    manager
        .create_table(
            Table::create()
                .table(Alias::new("sys_dict_type"))
                .if_not_exists()
                .col(
                    ColumnDef::new(Alias::new("dict_id"))
                        .big_integer()
                        .not_null()
                        .auto_increment()
                        .primary_key(),
                )
                .col(
                    ColumnDef::new(Alias::new("dict_name"))
                        .string_len(100)
                        .default(""),
                )
                .col(
                    ColumnDef::new(Alias::new("dict_type"))
                        .string_len(100)
                        .default(""),
                )
                .col(ColumnDef::new(Alias::new("status")).char().default("0"))
                .col(
                    ColumnDef::new(Alias::new("create_by"))
                        .string_len(64)
                        .default(""),
                )
                .col(ColumnDef::new(Alias::new("create_time")).date_time().null())
                .col(
                    ColumnDef::new(Alias::new("update_by"))
                        .string_len(64)
                        .default(""),
                )
                .col(ColumnDef::new(Alias::new("update_time")).date_time().null())
                .col(ColumnDef::new(Alias::new("remark")).string_len(500).null())
                .col(ColumnDef::new(Alias::new("del_flag")).char().default("0"))
                .to_owned(),
        )
        .await?;

    manager
        .create_index(
            Index::create()
                .if_not_exists()
                .name("uk_sys_dict_type")
                .table(Alias::new("sys_dict_type"))
                .col(Alias::new("dict_type"))
                .unique()
                .to_owned(),
        )
        .await?;

    Ok(())
}

/// 创建 sys_dict_data 表
async fn create_sys_dict_data(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    manager
        .create_table(
            Table::create()
                .table(Alias::new("sys_dict_data"))
                .if_not_exists()
                .col(
                    ColumnDef::new(Alias::new("dict_code"))
                        .big_integer()
                        .not_null()
                        .auto_increment()
                        .primary_key(),
                )
                .col(ColumnDef::new(Alias::new("dict_sort")).integer().default(0))
                .col(
                    ColumnDef::new(Alias::new("dict_label"))
                        .string_len(100)
                        .default(""),
                )
                .col(
                    ColumnDef::new(Alias::new("dict_value"))
                        .string_len(100)
                        .default(""),
                )
                .col(
                    ColumnDef::new(Alias::new("dict_type"))
                        .string_len(100)
                        .default(""),
                )
                .col(
                    ColumnDef::new(Alias::new("css_class"))
                        .string_len(100)
                        .null(),
                )
                .col(
                    ColumnDef::new(Alias::new("list_class"))
                        .string_len(100)
                        .null(),
                )
                .col(ColumnDef::new(Alias::new("is_default")).char().default("N"))
                .col(ColumnDef::new(Alias::new("status")).char().default("0"))
                .col(
                    ColumnDef::new(Alias::new("create_by"))
                        .string_len(64)
                        .default(""),
                )
                .col(ColumnDef::new(Alias::new("create_time")).date_time().null())
                .col(
                    ColumnDef::new(Alias::new("update_by"))
                        .string_len(64)
                        .default(""),
                )
                .col(ColumnDef::new(Alias::new("update_time")).date_time().null())
                .col(ColumnDef::new(Alias::new("remark")).string_len(500).null())
                .col(ColumnDef::new(Alias::new("del_flag")).char().default("0"))
                .to_owned(),
        )
        .await?;

    manager
        .create_index(
            Index::create()
                .if_not_exists()
                .name("idx_sys_dict_data_type")
                .table(Alias::new("sys_dict_data"))
                .col(Alias::new("dict_type"))
                .to_owned(),
        )
        .await?;

    Ok(())
}

/// 创建 sys_oper_log 表
async fn create_sys_oper_log(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    manager
        .create_table(
            Table::create()
                .table(Alias::new("sys_oper_log"))
                .if_not_exists()
                .col(
                    ColumnDef::new(Alias::new("oper_id"))
                        .big_integer()
                        .not_null()
                        .auto_increment()
                        .primary_key(),
                )
                .col(
                    ColumnDef::new(Alias::new("title"))
                        .string_len(50)
                        .default(""),
                )
                .col(
                    ColumnDef::new(Alias::new("business_type"))
                        .integer()
                        .default(0),
                )
                .col(
                    ColumnDef::new(Alias::new("method"))
                        .string_len(100)
                        .default(""),
                )
                .col(
                    ColumnDef::new(Alias::new("request_method"))
                        .string_len(10)
                        .default(""),
                )
                .col(
                    ColumnDef::new(Alias::new("operator_type"))
                        .integer()
                        .default(0),
                )
                .col(
                    ColumnDef::new(Alias::new("oper_name"))
                        .string_len(50)
                        .default(""),
                )
                .col(
                    ColumnDef::new(Alias::new("dept_name"))
                        .string_len(50)
                        .default(""),
                )
                .col(
                    ColumnDef::new(Alias::new("oper_url"))
                        .string_len(255)
                        .default(""),
                )
                .col(
                    ColumnDef::new(Alias::new("oper_ip"))
                        .string_len(128)
                        .default(""),
                )
                .col(
                    ColumnDef::new(Alias::new("oper_location"))
                        .string_len(255)
                        .default(""),
                )
                .col(
                    ColumnDef::new(Alias::new("oper_param"))
                        .string_len(2000)
                        .default(""),
                )
                .col(
                    ColumnDef::new(Alias::new("json_result"))
                        .string_len(2000)
                        .default(""),
                )
                .col(ColumnDef::new(Alias::new("status")).char().default("0"))
                .col(
                    ColumnDef::new(Alias::new("error_msg"))
                        .string_len(2000)
                        .default(""),
                )
                .col(ColumnDef::new(Alias::new("oper_time")).date_time().null())
                .col(
                    ColumnDef::new(Alias::new("cost_time"))
                        .big_integer()
                        .default(0),
                )
                .to_owned(),
        )
        .await?;

    // 索引
    for (idx_name, col) in [
        ("idx_sys_oper_log_bt", "business_type"),
        ("idx_sys_oper_log_s", "status"),
        ("idx_sys_oper_log_ot", "oper_time"),
    ] {
        manager
            .create_index(
                Index::create()
                    .if_not_exists()
                    .name(idx_name)
                    .table(Alias::new("sys_oper_log"))
                    .col(Alias::new(col))
                    .to_owned(),
            )
            .await?;
    }

    Ok(())
}

/// 创建 sys_logininfor 表
async fn create_sys_logininfor(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    manager
        .create_table(
            Table::create()
                .table(Alias::new("sys_logininfor"))
                .if_not_exists()
                .col(
                    ColumnDef::new(Alias::new("info_id"))
                        .big_integer()
                        .not_null()
                        .auto_increment()
                        .primary_key(),
                )
                .col(
                    ColumnDef::new(Alias::new("user_name"))
                        .string_len(50)
                        .default(""),
                )
                .col(
                    ColumnDef::new(Alias::new("ipaddr"))
                        .string_len(128)
                        .default(""),
                )
                .col(
                    ColumnDef::new(Alias::new("login_location"))
                        .string_len(255)
                        .default(""),
                )
                .col(
                    ColumnDef::new(Alias::new("browser"))
                        .string_len(50)
                        .default(""),
                )
                .col(ColumnDef::new(Alias::new("os")).string_len(50).default(""))
                .col(ColumnDef::new(Alias::new("status")).char().default("0"))
                .col(
                    ColumnDef::new(Alias::new("msg"))
                        .string_len(255)
                        .default(""),
                )
                .col(ColumnDef::new(Alias::new("login_time")).date_time().null())
                .to_owned(),
        )
        .await?;

    for (idx_name, col) in [
        ("idx_sys_logininfor_s", "status"),
        ("idx_sys_logininfor_lt", "login_time"),
        ("idx_sys_logininfor_user_name", "user_name"),
    ] {
        manager
            .create_index(
                Index::create()
                    .if_not_exists()
                    .name(idx_name)
                    .table(Alias::new("sys_logininfor"))
                    .col(Alias::new(col))
                    .to_owned(),
            )
            .await?;
    }

    Ok(())
}

/// 创建 sys_job 表
async fn create_sys_job(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    manager
        .create_table(
            Table::create()
                .table(Alias::new("sys_job"))
                .if_not_exists()
                .col(
                    ColumnDef::new(Alias::new("job_id"))
                        .big_integer()
                        .not_null()
                        .auto_increment()
                        .primary_key(),
                )
                .col(
                    ColumnDef::new(Alias::new("job_name"))
                        .string_len(64)
                        .not_null()
                        .default(""),
                )
                .col(
                    ColumnDef::new(Alias::new("job_group"))
                        .string_len(64)
                        .not_null()
                        .default("DEFAULT"),
                )
                .col(
                    ColumnDef::new(Alias::new("invoke_target"))
                        .string_len(500)
                        .not_null(),
                )
                .col(
                    ColumnDef::new(Alias::new("cron_expression"))
                        .string_len(255)
                        .default(""),
                )
                .col(
                    ColumnDef::new(Alias::new("misfire_policy"))
                        .string_len(20)
                        .default("3"),
                )
                .col(ColumnDef::new(Alias::new("concurrent")).char().default("1"))
                .col(ColumnDef::new(Alias::new("status")).char().default("0"))
                .col(
                    ColumnDef::new(Alias::new("create_by"))
                        .string_len(64)
                        .default(""),
                )
                .col(ColumnDef::new(Alias::new("create_time")).date_time().null())
                .col(
                    ColumnDef::new(Alias::new("update_by"))
                        .string_len(64)
                        .default(""),
                )
                .col(ColumnDef::new(Alias::new("update_time")).date_time().null())
                .col(
                    ColumnDef::new(Alias::new("remark"))
                        .string_len(500)
                        .default(""),
                )
                .col(ColumnDef::new(Alias::new("del_flag")).char().default("0"))
                .to_owned(),
        )
        .await?;

    // 唯一索引 (job_name, job_group)
    manager
        .create_index(
            Index::create()
                .if_not_exists()
                .name("uk_sys_job_name_group")
                .table(Alias::new("sys_job"))
                .col(Alias::new("job_name"))
                .col(Alias::new("job_group"))
                .unique()
                .to_owned(),
        )
        .await?;

    Ok(())
}

/// 创建 sys_job_log 表
async fn create_sys_job_log(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    manager
        .create_table(
            Table::create()
                .table(Alias::new("sys_job_log"))
                .if_not_exists()
                .col(
                    ColumnDef::new(Alias::new("job_log_id"))
                        .big_integer()
                        .not_null()
                        .auto_increment()
                        .primary_key(),
                )
                .col(
                    ColumnDef::new(Alias::new("job_name"))
                        .string_len(64)
                        .not_null(),
                )
                .col(
                    ColumnDef::new(Alias::new("job_group"))
                        .string_len(64)
                        .not_null(),
                )
                .col(
                    ColumnDef::new(Alias::new("invoke_target"))
                        .string_len(500)
                        .not_null(),
                )
                .col(
                    ColumnDef::new(Alias::new("job_message"))
                        .string_len(500)
                        .null(),
                )
                .col(ColumnDef::new(Alias::new("status")).char().default("0"))
                .col(
                    ColumnDef::new(Alias::new("exception_info"))
                        .string_len(2000)
                        .default(""),
                )
                .col(ColumnDef::new(Alias::new("create_time")).date_time().null())
                .to_owned(),
        )
        .await?;

    // 索引
    for (idx_name, col) in [
        ("idx_sys_job_log_status", "status"),
        ("idx_sys_job_log_create_time", "create_time"),
    ] {
        manager
            .create_index(
                Index::create()
                    .if_not_exists()
                    .name(idx_name)
                    .table(Alias::new("sys_job_log"))
                    .col(Alias::new(col))
                    .to_owned(),
            )
            .await?;
    }

    Ok(())
}

/// 构建 sys_dept 建表语句（独立成函数，便于单测直接断言列定义 DDL）
fn sys_dept_table_stmt() -> TableCreateStatement {
    Table::create()
        .table(Alias::new("sys_dept"))
        .if_not_exists()
        .col(
            ColumnDef::new(Alias::new("dept_id"))
                .big_integer()
                .not_null()
                .auto_increment()
                .primary_key(),
        )
        .col(
            ColumnDef::new(Alias::new("parent_id"))
                .big_integer()
                .default(0),
        )
        .col(
            // R5-DB-26：ancestors 是逗号拼接的祖先 ID 链（如 "0,100,101,102,..."），
            // 部门树较深或 ID 较大时必然超过 50 字符。SQLite 不强制 VARCHAR 长度
            // （静默放行），但 PostgreSQL/MySQL 会强制 ⇒ 写部门时插入失败/截断，
            // 故建为 VARCHAR(500)（存量库由 m20260928_000001 方言感知放宽）。
            ColumnDef::new(Alias::new("ancestors"))
                .string_len(500)
                .default(""),
        )
        .col(
            ColumnDef::new(Alias::new("dept_name"))
                .string_len(30)
                .default(""),
        )
        .col(ColumnDef::new(Alias::new("order_num")).integer().default(0))
        .col(ColumnDef::new(Alias::new("leader")).string_len(20).null())
        .col(ColumnDef::new(Alias::new("phone")).string_len(11).null())
        .col(ColumnDef::new(Alias::new("email")).string_len(50).null())
        .col(ColumnDef::new(Alias::new("status")).char().default("0"))
        .col(ColumnDef::new(Alias::new("del_flag")).char().default("0"))
        .col(
            ColumnDef::new(Alias::new("create_by"))
                .string_len(64)
                .default(""),
        )
        .col(ColumnDef::new(Alias::new("create_time")).date_time().null())
        .col(
            ColumnDef::new(Alias::new("update_by"))
                .string_len(64)
                .default(""),
        )
        .col(ColumnDef::new(Alias::new("update_time")).date_time().null())
        .to_owned()
}

/// 创建 sys_dept 表（部门信息表，树形结构）
async fn create_sys_dept(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    manager.create_table(sys_dept_table_stmt()).await?;
    Ok(())
}

/// 创建 sys_post 表（岗位信息表）
async fn create_sys_post(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    manager
        .create_table(
            Table::create()
                .table(Alias::new("sys_post"))
                .if_not_exists()
                .col(
                    ColumnDef::new(Alias::new("post_id"))
                        .big_integer()
                        .not_null()
                        .auto_increment()
                        .primary_key(),
                )
                .col(
                    ColumnDef::new(Alias::new("post_code"))
                        .string_len(64)
                        .not_null(),
                )
                .col(
                    ColumnDef::new(Alias::new("post_name"))
                        .string_len(50)
                        .not_null(),
                )
                .col(ColumnDef::new(Alias::new("post_sort")).integer().not_null())
                .col(ColumnDef::new(Alias::new("status")).char().default("0"))
                .col(ColumnDef::new(Alias::new("del_flag")).char().default("0"))
                .col(
                    ColumnDef::new(Alias::new("create_by"))
                        .string_len(64)
                        .default(""),
                )
                .col(ColumnDef::new(Alias::new("create_time")).date_time().null())
                .col(
                    ColumnDef::new(Alias::new("update_by"))
                        .string_len(64)
                        .default(""),
                )
                .col(ColumnDef::new(Alias::new("update_time")).date_time().null())
                .col(ColumnDef::new(Alias::new("remark")).string_len(500).null())
                .to_owned(),
        )
        .await?;

    // 唯一索引
    manager
        .create_index(
            Index::create()
                .if_not_exists()
                .name("uk_sys_post_code")
                .table(Alias::new("sys_post"))
                .col(Alias::new("post_code"))
                .unique()
                .to_owned(),
        )
        .await?;

    Ok(())
}

/// 创建 sys_user_post 表（用户岗位关联表，复合主键）
async fn create_sys_user_post(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    manager
        .create_table(
            Table::create()
                .table(Alias::new("sys_user_post"))
                .if_not_exists()
                .col(
                    ColumnDef::new(Alias::new("user_id"))
                        .big_integer()
                        .not_null(),
                )
                .col(
                    ColumnDef::new(Alias::new("post_id"))
                        .big_integer()
                        .not_null(),
                )
                .primary_key(
                    Index::create()
                        .col(Alias::new("user_id"))
                        .col(Alias::new("post_id")),
                )
                .to_owned(),
        )
        .await?;

    manager
        .create_index(
            Index::create()
                .if_not_exists()
                .name("idx_sys_user_post_post")
                .table(Alias::new("sys_user_post"))
                .col(Alias::new("post_id"))
                .to_owned(),
        )
        .await?;

    Ok(())
}

/// 创建 sys_role_dept 表（角色部门关联表，复合主键，用于自定义数据权限）
async fn create_sys_role_dept(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    manager
        .create_table(
            Table::create()
                .table(Alias::new("sys_role_dept"))
                .if_not_exists()
                .col(
                    ColumnDef::new(Alias::new("role_id"))
                        .big_integer()
                        .not_null(),
                )
                .col(
                    ColumnDef::new(Alias::new("dept_id"))
                        .big_integer()
                        .not_null(),
                )
                .primary_key(
                    Index::create()
                        .col(Alias::new("role_id"))
                        .col(Alias::new("dept_id")),
                )
                .to_owned(),
        )
        .await?;

    manager
        .create_index(
            Index::create()
                .if_not_exists()
                .name("idx_sys_role_dept_dept")
                .table(Alias::new("sys_role_dept"))
                .col(Alias::new("dept_id"))
                .to_owned(),
        )
        .await?;

    Ok(())
}

// ========== 自增起始值设置 ==========

/// 设置自增起始值（预留低 ID 为系统内置数据）
///
/// SQLite 不支持 ALTER TABLE ... AUTO_INCREMENT 语法，
/// 通过更新 sqlite_sequence 表实现相同效果。
/// PostgreSQL 使用 setval + pg_get_serial_sequence 重置序列。
async fn set_auto_increment(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    // (表名, 主键列名, 起始值)
    let tables_and_values: &[(&str, &str, i64)] = &[
        ("sys_user", "user_id", 100),
        ("sys_role", "role_id", 100),
        ("sys_menu", "menu_id", 2000),
        ("sys_dict_type", "dict_id", 100),
        ("sys_dict_data", "dict_code", 100),
        ("sys_oper_log", "oper_id", 100),
        ("sys_logininfor", "info_id", 100),
        ("sys_job", "job_id", 100),
        ("sys_dept", "dept_id", 200),
        ("sys_post", "post_id", 100),
    ];

    for (table, pk_col, value) in tables_and_values {
        if is_sqlite(manager) {
            // SQLite: 通过 sqlite_sequence 表设置（需先有 AUTOINCREMENT 列才会存在该表）
            let sql = format!(
                "INSERT OR REPLACE INTO sqlite_sequence (name, seq) VALUES ('{}', {})",
                table, value
            );
            // R5-DB-23：维持 best-effort（表可能尚无 sqlite_sequence 记录，失败不阻断迁移），
            // 但不能像原先 `let _ = ...` 那样静默吞错——失败必须可见（方言 + 底层错误）。
            // 本 crate 未引入 tracing（避免新增依赖），沿用既有最轻量设施 eprintln!。
            if let Err(e) = manager.get_connection().execute_unprepared(&sql).await {
                eprintln!(
                    "[migration][warn] m20250711_000001 set_auto_increment(sqlite) {table}: \
                     自增起始值设置失败，已忽略（不阻断迁移）: {e}"
                );
            }
        } else if is_postgres(manager) {
            // PostgreSQL: 使用 setval 重置序列
            // pg_get_serial_sequence 自动查找 SERIAL/IDENTITY 列对应的序列名
            // 第三个参数 false 表示下一次 nextval 返回 value（而非 value+1）
            let sql = format!(
                "SELECT setval(pg_get_serial_sequence('{}', '{}'), {}, false)",
                table, pk_col, value
            );
            // R5-DB-23：同上，best-effort 但失败可见（如 pg_get_serial_sequence 返回 NULL）
            if let Err(e) = manager.get_connection().execute_unprepared(&sql).await {
                eprintln!(
                    "[migration][warn] m20250711_000001 set_auto_increment(postgres) \
                     {table}.{pk_col}: 序列起始值设置失败，已忽略（不阻断迁移）: {e}"
                );
            }
        } else {
            // MySQL
            let sql = format!("ALTER TABLE {} AUTO_INCREMENT = {}", table, value);
            manager.get_connection().execute_unprepared(&sql).await?;
        }
    }
    Ok(())
}

// ========== 初始数据插入 ==========

/// 插入 sys_user 初始数据（admin + stepby）
/// 密码均为 admin123，盐值 stepby_admin，MD5(明文+盐值)
async fn insert_sys_user(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    let now = now_expr(manager);
    let sqls = [
        format!(
            "sys_user (user_id, dept_id, user_name, nick_name, user_type, email, phonenumber, sex, avatar, password, status, del_flag, login_ip, login_date, create_by, create_time, remark) VALUES (1, 103, 'admin', 'Stepby管理员', '00', 'stepby@tzkj.net', '15888888888', '0', '', 'ba976d23f6d1012cfe81ceb960a1058c', '0', '0', '127.0.0.1', {now}, 'admin', {now}, '管理员')"
        ),
        format!(
            "sys_user (user_id, dept_id, user_name, nick_name, user_type, email, phonenumber, sex, avatar, password, status, del_flag, login_ip, login_date, create_by, create_time, remark) VALUES (2, 105, 'stepby', 'Stepby', '00', 'stepby@tzkj.net', '15666666666', '1', '', 'ba976d23f6d1012cfe81ceb960a1058c', '0', '0', '127.0.0.1', {now}, 'admin', {now}, '测试员')"
        ),
    ];
    for sql in sqls {
        execute_idempotent_insert(manager, &sql).await?;
    }
    Ok(())
}

/// 插入 sys_role 初始数据（超级管理员 + 普通角色）
async fn insert_sys_role(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    let now = now_expr(manager);
    // 注意：menu_check_strictly / dept_check_strictly 为 boolean 类型，
    // 使用 TRUE/FALSE 跨数据库兼容（SQLite 3.23+, MySQL, PostgreSQL 均支持）
    let sqls = [
        format!(
            "sys_role (role_id, role_name, role_key, role_sort, data_scope, menu_check_strictly, dept_check_strictly, status, del_flag, create_by, create_time, remark) VALUES (1, '超级管理员', 'admin', 1, '1', TRUE, TRUE, '0', '0', 'admin', {now}, '超级管理员')"
        ),
        format!(
            "sys_role (role_id, role_name, role_key, role_sort, data_scope, menu_check_strictly, dept_check_strictly, status, del_flag, create_by, create_time, remark) VALUES (2, '普通角色', 'common', 2, '2', TRUE, TRUE, '0', '0', 'admin', {now}, '普通角色')"
        ),
    ];
    for sql in sqls {
        execute_idempotent_insert(manager, &sql).await?;
    }
    Ok(())
}

/// 插入 sys_menu 初始数据（目录 + 菜单 + 按钮）
async fn insert_sys_menu(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    let now = now_expr(manager);
    let sql = format!(
        "sys_menu (menu_id, menu_name, parent_id, order_num, path, component, query, route_name, is_frame, is_cache, menu_type, visible, status, perms, icon, create_by, create_time, remark, del_flag) VALUES \
(1, '系统管理', 0, 1, 'system', NULL, '', '', '1', '0', 'M', '0', '0', '', 'system', 'admin', {now}, '系统管理目录', '0'), \
(2, '系统监控', 0, 2, 'monitor', NULL, '', '', '1', '0', 'M', '0', '0', '', 'monitor', 'admin', {now}, '系统监控目录', '0'), \
(3, '系统工具', 0, 3, 'tool', NULL, '', '', '1', '0', 'M', '0', '0', '', 'tool', 'admin', {now}, '系统工具目录', '0'), \
(4, 'Stepby官网', 0, 4, 'https://stepby.tzkj.net', NULL, '', '', '0', '0', 'M', '0', '0', '', 'guide', 'admin', {now}, 'Stepby官网地址', '0'), \
(4100, 'AI助手', 0, 5, 'ai', 'ai/panel/index', '', '', '1', '0', 'C', '0', '0', 'ai:chat', 'chart', 'admin', {now}, 'AI 数据查询助手（NL2SQL，受白名单与租户隔离约束）', '0'), \
(100, '用户管理', 1, 1, 'user', 'system/user/index', '', '', '1', '0', 'C', '0', '0', 'system:user:list', 'user', 'admin', {now}, '用户管理菜单', '0'), \
(101, '角色管理', 1, 2, 'role', 'system/role/index', '', '', '1', '0', 'C', '0', '0', 'system:role:list', 'peoples', 'admin', {now}, '角色管理菜单', '0'), \
(102, '菜单管理', 1, 3, 'menu', 'system/menu/index', '', '', '1', '0', 'C', '0', '0', 'system:menu:list', 'tree-table', 'admin', {now}, '菜单管理菜单', '0'), \
(103, '部门管理', 1, 4, 'dept', 'system/dept/index', '', '', '1', '0', 'C', '0', '0', 'system:dept:list', 'tree', 'admin', {now}, '部门管理菜单', '0'), \
(104, '岗位管理', 1, 5, 'post', 'system/post/index', '', '', '1', '0', 'C', '0', '0', 'system:post:list', 'post', 'admin', {now}, '岗位管理菜单', '0'), \
(105, '字典管理', 1, 6, 'dict', 'system/dict/index', '', '', '1', '0', 'C', '0', '0', 'system:dict:list', 'dict', 'admin', {now}, '字典管理菜单', '0'), \
(106, '参数设置', 1, 7, 'config', 'system/config/index', '', '', '1', '0', 'C', '0', '0', 'system:config:list', 'edit', 'admin', {now}, '参数设置菜单', '0'), \
(107, '通知公告', 1, 8, 'notice', 'system/notice/index', '', '', '1', '0', 'C', '0', '0', 'system:notice:list', 'message', 'admin', {now}, '通知公告菜单', '0'), \
(108, '日志管理', 1, 9, 'log', '', '', '', '1', '0', 'M', '0', '0', '', 'log', 'admin', {now}, '日志管理菜单', '0'), \
(109, '在线用户', 2, 1, 'online', 'monitor/online/index', '', '', '1', '0', 'C', '0', '0', 'monitor:online:list', 'online', 'admin', {now}, '在线用户菜单', '0'), \
(110, '定时任务', 2, 2, 'job', 'monitor/job/index', '', '', '1', '0', 'C', '0', '0', 'monitor:job:list', 'job', 'admin', {now}, '定时任务菜单', '0'), \
(111, '数据监控', 2, 3, 'druid', 'monitor/druid/index', '', '', '1', '0', 'C', '0', '0', 'monitor:druid:list', 'druid', 'admin', {now}, '数据监控菜单', '0'), \
(112, '服务监控', 2, 4, 'server', 'monitor/server/index', '', '', '1', '0', 'C', '0', '0', 'monitor:server:list', 'server', 'admin', {now}, '服务监控菜单', '0'), \
(113, '缓存监控', 2, 5, 'cache', 'monitor/cache/index', '', '', '1', '0','C', '0', '0', 'monitor:cache:list', 'redis', 'admin', {now}, '缓存监控菜单', '0'), \
(114, '缓存列表', 2, 6, 'cacheList', 'monitor/cache/list', '', '', '1', '0','C', '0', '0', 'monitor:cache:list', 'redis-list', 'admin', {now}, '缓存列表菜单', '0'), \
(115, '表单构建', 3, 1, 'build', 'tool/build/index', '', '', '1', '0','C', '0', '0', 'tool:build:list', 'build', 'admin', {now}, '表单构建菜单', '0'), \
(116, '代码生成', 3, 2, 'gen', 'tool/gen/index', '', '', '1', '0','C', '0', '0', 'tool:gen:list', 'code', 'admin', {now}, '代码生成菜单', '0'), \
(117, '系统接口', 3, 3, 'swagger', 'tool/swagger/index', '', '', '1', '0','C', '0', '0', 'tool:swagger:list', 'swagger', 'admin', {now}, '系统接口菜单', '0'), \
(500, '操作日志', 108, 1, 'operlog', 'monitor/operlog/index', '', '', '1', '0','C', '0', '0', 'monitor:operlog:list', 'form', 'admin', {now}, '操作日志菜单', '0'), \
(501, '登录日志', 108, 2, 'logininfor', 'monitor/logininfor/index', '', '', '1', '0','C', '0', '0', 'monitor:logininfor:list', 'logininfor', 'admin', {now}, '登录日志菜单', '0'), \
(1000, '用户查询', 100, 1, '', '', '', '', '1', '0','F', '0', '0', 'system:user:query', '#', 'admin', {now}, '', '0'), \
(1001, '用户新增', 100, 2, '', '', '', '', '1', '0','F', '0', '0', 'system:user:add', '#', 'admin', {now}, '', '0'), \
(1002, '用户修改', 100, 3, '', '', '', '', '1', '0','F', '0', '0', 'system:user:edit', '#', 'admin', {now}, '', '0'), \
(1003, '用户删除', 100, 4, '', '', '', '', '1', '0','F', '0', '0', 'system:user:remove', '#', 'admin', {now}, '', '0'), \
(1004, '用户导出', 100, 5, '', '', '', '', '1', '0','F', '0', '0', 'system:user:export', '#', 'admin', {now}, '', '0'), \
(1005, '用户导入', 100, 6, '', '', '', '', '1', '0','F', '0', '0', 'system:user:import', '#', 'admin', {now}, '', '0'), \
(1006, '重置密码', 100, 7, '', '', '', '', '1', '0','F', '0', '0', 'system:user:resetPwd', '#', 'admin', {now}, '', '0'), \
(1007, '角色查询', 101, 1, '', '', '', '', '1', '0','F', '0', '0', 'system:role:query', '#', 'admin', {now}, '', '0'), \
(1008, '角色新增', 101, 2, '', '', '', '', '1', '0','F', '0', '0', 'system:role:add', '#', 'admin', {now}, '', '0'), \
(1009, '角色修改', 101, 3, '', '', '', '', '1', '0','F', '0', '0', 'system:role:edit', '#', 'admin', {now}, '', '0'), \
(1010, '角色删除', 101, 4, '', '', '', '', '1', '0','F', '0', '0', 'system:role:remove', '#', 'admin', {now}, '', '0'), \
(1011, '角色导出', 101, 5, '', '', '', '', '1', '0','F', '0', '0', 'system:role:export', '#', 'admin', {now}, '', '0'), \
(1012, '菜单查询', 102, 1, '', '', '', '', '1', '0','F', '0', '0', 'system:menu:query', '#', 'admin', {now}, '', '0'), \
(1013, '菜单新增', 102, 2, '', '', '', '', '1', '0','F', '0', '0', 'system:menu:add', '#', 'admin', {now}, '', '0'), \
(1014, '菜单修改', 102, 3, '', '', '', '', '1', '0','F', '0', '0', 'system:menu:edit', '#', 'admin', {now}, '', '0'), \
(1015, '菜单删除', 102, 4, '', '', '', '', '1', '0','F', '0', '0', 'system:menu:remove', '#', 'admin', {now}, '', '0'), \
(1016, '部门查询', 103, 1, '', '', '', '', '1', '0','F', '0', '0', 'system:dept:query', '#', 'admin', {now}, '', '0'), \
(1017, '部门新增', 103, 2, '', '', '', '', '1', '0','F', '0', '0', 'system:dept:add', '#', 'admin', {now}, '', '0'), \
(1018, '部门修改', 103, 3, '', '', '', '', '1', '0','F', '0', '0', 'system:dept:edit', '#', 'admin', {now}, '', '0'), \
(1019, '部门删除', 103, 4, '', '', '', '', '1', '0','F', '0', '0', 'system:dept:remove', '#', 'admin', {now}, '', '0'), \
(1020, '岗位查询', 104, 1, '', '', '', '', '1', '0','F', '0', '0', 'system:post:query', '#', 'admin', {now}, '', '0'), \
(1021, '岗位新增', 104, 2, '', '', '', '', '1', '0','F', '0', '0', 'system:post:add', '#', 'admin', {now}, '', '0'), \
(1022, '岗位修改', 104, 3, '', '', '', '', '1', '0','F', '0', '0', 'system:post:edit', '#', 'admin', {now}, '', '0'), \
(1023, '岗位删除', 104, 4, '', '', '', '', '1', '0','F', '0', '0', 'system:post:remove', '#', 'admin', {now}, '', '0'), \
(1024, '岗位导出', 104, 5, '', '', '', '', '1', '0','F', '0', '0', 'system:post:export', '#', 'admin', {now}, '', '0'), \
(1025, '字典查询', 105, 1, '#', '', '', '', '1', '0','F', '0', '0', 'system:dict:query', '#', 'admin', {now}, '', '0'), \
(1026, '字典新增', 105, 2, '#', '', '', '', '1', '0','F', '0', '0', 'system:dict:add', '#', 'admin', {now}, '', '0'), \
(1027, '字典修改', 105, 3, '#', '', '', '', '1', '0','F', '0', '0', 'system:dict:edit', '#', 'admin', {now}, '', '0'), \
(1028, '字典删除', 105, 4, '#', '', '', '', '1', '0','F', '0', '0', 'system:dict:remove', '#', 'admin', {now}, '', '0'), \
(1029, '字典导出', 105, 5, '#', '', '', '', '1', '0','F', '0', '0', 'system:dict:export', '#', 'admin', {now}, '', '0'), \
(1030, '参数查询', 106, 1, '#', '', '', '', '1', '0','F', '0', '0', 'system:config:query', '#', 'admin', {now}, '', '0'), \
(1031, '参数新增', 106, 2, '#', '', '', '', '1', '0','F', '0', '0', 'system:config:add', '#', 'admin', {now}, '', '0'), \
(1032, '参数修改', 106, 3, '#', '', '', '', '1', '0','F', '0', '0', 'system:config:edit', '#', 'admin', {now}, '', '0'), \
(1033, '参数删除', 106, 4, '#', '', '', '', '1', '0','F', '0', '0', 'system:config:remove', '#', 'admin', {now}, '', '0'), \
(1034, '参数导出', 106, 5, '#', '', '', '', '1', '0','F', '0', '0', 'system:config:export', '#', 'admin', {now}, '', '0'), \
(1035, '公告查询', 107, 1, '#', '', '', '', '1', '0','F', '0', '0', 'system:notice:query', '#', 'admin', {now}, '', '0'), \
(1036, '公告新增', 107, 2, '#', '', '', '', '1', '0','F', '0', '0', 'system:notice:add', '#', 'admin', {now}, '', '0'), \
(1037, '公告修改', 107, 3, '#', '', '', '', '1', '0','F', '0', '0', 'system:notice:edit', '#', 'admin', {now}, '', '0'), \
(1038, '公告删除', 107, 4, '#', '', '', '', '1', '0','F', '0', '0', 'system:notice:remove', '#', 'admin', {now}, '', '0'), \
(1039, '操作查询', 500, 1, '#', '', '', '', '1', '0','F', '0', '0', 'monitor:operlog:query', '#', 'admin', {now}, '', '0'), \
(1040, '操作删除', 500, 2, '#', '', '', '', '1', '0','F', '0', '0', 'monitor:operlog:remove', '#', 'admin', {now}, '', '0'), \
(1041, '日志导出', 500, 3, '#', '', '', '', '1', '0','F', '0', '0', 'monitor:operlog:export', '#', 'admin', {now}, '', '0'), \
(1042, '登录查询', 501, 1, '#', '', '', '', '1', '0','F', '0', '0', 'monitor:logininfor:query', '#', 'admin', {now}, '', '0'), \
(1043, '登录删除', 501, 2, '#', '', '', '', '1', '0','F', '0', '0', 'monitor:logininfor:remove', '#', 'admin', {now}, '', '0'), \
(1044, '日志导出', 501, 3, '#', '', '', '', '1', '0','F', '0', '0', 'monitor:logininfor:export', '#', 'admin', {now}, '', '0'), \
(1045, '账户解锁', 501, 4, '#', '', '', '', '1', '0','F', '0', '0', 'monitor:logininfor:unlock', '#', 'admin', {now}, '', '0'), \
(1046, '在线查询', 109, 1, '#', '', '', '', '1', '0','F', '0', '0', 'monitor:online:query', '#', 'admin', {now}, '', '0'), \
(1047, '批量强退', 109, 2, '#', '', '', '', '1', '0','F', '0', '0', 'monitor:online:batchLogout', '#', 'admin', {now}, '', '0'), \
(1048, '单条强退', 109, 3, '#', '', '', '', '1', '0','F', '0', '0', 'monitor:online:forceLogout', '#', 'admin', {now}, '', '0'), \
(1049, '任务查询', 110, 1, '#', '', '', '', '1', '0','F', '0', '0', 'monitor:job:query', '#', 'admin', {now}, '', '0'), \
(1050, '任务新增', 110, 2, '#', '', '', '', '1', '0','F', '0', '0', 'monitor:job:add', '#', 'admin', {now}, '', '0'), \
(1051, '任务修改', 110, 3, '#', '', '', '', '1', '0','F', '0', '0', 'monitor:job:edit', '#', 'admin', {now}, '', '0'), \
(1052, '任务删除', 110, 4, '#', '', '', '', '1', '0','F', '0', '0', 'monitor:job:remove', '#', 'admin', {now}, '', '0'), \
(1053, '状态修改', 110, 5, '#', '', '', '', '1', '0','F', '0', '0', 'monitor:job:changeStatus', '#', 'admin', {now}, '', '0'), \
(1054, '任务导出', 110, 6, '#', '', '', '', '1', '0','F', '0', '0', 'monitor:job:export', '#', 'admin', {now}, '', '0'), \
(1055, '生成查询', 116, 1, '#', '', '', '', '1', '0','F', '0', '0', 'tool:gen:query', '#', 'admin', {now}, '', '0'), \
(1056, '生成修改', 116, 2, '#', '', '', '', '1', '0','F', '0', '0', 'tool:gen:edit', '#', 'admin', {now}, '', '0'), \
(1057, '生成删除', 116, 3, '#', '', '', '', '1', '0','F', '0', '0', 'tool:gen:remove', '#', 'admin', {now}, '', '0'), \
(1058, '导入代码', 116, 4, '#', '', '', '', '1', '0','F', '0', '0', 'tool:gen:import', '#', 'admin', {now}, '', '0'), \
(1059, '预览代码', 116, 5, '#', '', '', '', '1', '0','F', '0', '0', 'tool:gen:preview', '#', 'admin', {now}, '', '0'), \
(1060, '生成代码', 116, 6, '#', '', '', '', '1', '0','F', '0', '0', 'tool:gen:code', '#', 'admin', {now}, '', '0')"
    );
    execute_idempotent_insert(manager, &sql).await?;
    Ok(())
}

/// 插入 sys_user_role 初始数据
async fn insert_sys_user_role(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    let sql = "sys_user_role (user_id, role_id) VALUES (1, 1), (2, 2)";
    execute_idempotent_insert(manager, sql).await?;
    Ok(())
}

/// 插入 sys_role_menu 初始数据（普通角色 role_id=2 关联全部菜单）
async fn insert_sys_role_menu(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    let menu_ids = [
        1, 2, 3, 4, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 115,
        116, 117, 500, 501, 1000, 1001, 1002, 1003, 1004, 1005, 1006, 1007, 1008, 1009, 1010, 1011,
        1012, 1013, 1014, 1015, 1016, 1017, 1018, 1019, 1020, 1021, 1022, 1023, 1024, 1025, 1026,
        1027, 1028, 1029, 1030, 1031, 1032, 1033, 1034, 1035, 1036, 1037, 1038, 1039, 1040, 1041,
        1042, 1043, 1044, 1045, 1046, 1047, 1048, 1049, 1050, 1051, 1052, 1053, 1054, 1055, 1056,
        1057, 1058, 1059, 1060,
    ];
    let values: Vec<String> = menu_ids
        .iter()
        .map(|&mid| format!("(2, {})", mid))
        .collect();
    let sql = format!(
        "sys_role_menu (role_id, menu_id) VALUES {}",
        values.join(", ")
    );
    execute_idempotent_insert(manager, &sql).await?;
    Ok(())
}

/// 插入 sys_dict_type 初始数据（10 条内置字典类型）
async fn insert_sys_dict_type(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    let now = now_expr(manager);
    let sql = format!(
        "sys_dict_type (dict_id, dict_name, dict_type, status, create_by, create_time, remark, del_flag) VALUES \
(1, '用户性别', 'sys_user_sex', '0', 'admin', {now}, '用户性别列表', '0'), \
(2, '菜单状态', 'sys_show_hide', '0', 'admin', {now}, '菜单状态列表', '0'), \
(3, '系统开关', 'sys_normal_disable', '0', 'admin', {now}, '系统开关列表', '0'), \
(4, '任务状态', 'sys_job_status', '0', 'admin', {now}, '任务状态列表', '0'), \
(5, '任务分组', 'sys_job_group', '0', 'admin', {now}, '任务分组列表', '0'), \
(6, '系统是否', 'sys_yes_no', '0', 'admin', {now}, '系统是否列表', '0'), \
(7, '通知类型', 'sys_notice_type', '0', 'admin', {now}, '通知类型列表', '0'), \
(8, '通知状态', 'sys_notice_status', '0', 'admin', {now}, '通知状态列表', '0'), \
(9, '操作类型', 'sys_oper_type', '0', 'admin', {now}, '操作类型列表', '0'), \
(10, '系统状态', 'sys_common_status', '0', 'admin', {now}, '登录状态列表', '0')"
    );
    execute_idempotent_insert(manager, &sql).await?;
    Ok(())
}

/// 插入 sys_dict_data 初始数据（29 条内置字典数据）
async fn insert_sys_dict_data(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    let now = now_expr(manager);
    let sql = format!(
        "sys_dict_data (dict_code, dict_sort, dict_label, dict_value, dict_type, css_class, list_class, is_default, status, create_by, create_time, remark, del_flag) VALUES \
(1, 1, '男', '0', 'sys_user_sex', '', '', 'Y', '0', 'admin', {now}, '性别男', '0'), \
(2, 2, '女', '1', 'sys_user_sex', '', '', 'N', '0', 'admin', {now}, '性别女', '0'), \
(3, 3, '未知', '2', 'sys_user_sex', '', '', 'N', '0', 'admin', {now}, '性别未知', '0'), \
(4, 1, '显示', '0', 'sys_show_hide', '', 'primary', 'Y', '0', 'admin', {now}, '显示菜单', '0'), \
(5, 2, '隐藏', '1', 'sys_show_hide', '', 'danger', 'N', '0', 'admin', {now}, '隐藏菜单', '0'), \
(6, 1, '正常', '0', 'sys_normal_disable', '', 'primary', 'Y', '0', 'admin', {now}, '正常状态', '0'), \
(7, 2, '停用', '1', 'sys_normal_disable', '', 'danger', 'N', '0', 'admin', {now}, '停用状态', '0'), \
(8, 1, '正常', '0', 'sys_job_status', '', 'primary', 'Y', '0', 'admin', {now}, '正常状态', '0'), \
(9, 2, '暂停', '1', 'sys_job_status', '', 'danger', 'N', '0', 'admin', {now}, '停用状态', '0'), \
(10, 1, '默认', 'DEFAULT', 'sys_job_group', '', '', 'Y', '0', 'admin', {now}, '默认分组', '0'), \
(11, 2, '系统', 'SYSTEM', 'sys_job_group', '', '', 'N', '0', 'admin', {now}, '系统分组', '0'), \
(12, 1, '是', 'Y', 'sys_yes_no', '', 'primary', 'Y', '0', 'admin', {now}, '系统默认是', '0'), \
(13, 2, '否', 'N', 'sys_yes_no', '', 'danger', 'N', '0', 'admin', {now}, '系统默认否', '0'), \
(14, 1, '通知', '1', 'sys_notice_type', '', 'warning', 'Y', '0', 'admin', {now}, '通知', '0'), \
(15, 2, '公告', '2', 'sys_notice_type', '', 'success', 'N', '0', 'admin', {now}, '公告', '0'), \
(16, 1, '正常', '0', 'sys_notice_status', '', 'primary', 'Y', '0', 'admin', {now}, '正常状态', '0'), \
(17, 2, '关闭', '1', 'sys_notice_status', '', 'danger', 'N', '0', 'admin', {now}, '关闭状态', '0'), \
(18, 99, '其他', '0', 'sys_oper_type', '', 'info', 'N', '0', 'admin', {now}, '其他操作', '0'), \
(19, 1, '新增', '1', 'sys_oper_type', '', 'info', 'N', '0', 'admin', {now}, '新增操作', '0'), \
(20, 2, '修改', '2', 'sys_oper_type', '', 'info', 'N', '0', 'admin', {now}, '修改操作', '0'), \
(21, 3, '删除', '3', 'sys_oper_type', '', 'danger', 'N', '0', 'admin', {now}, '删除操作', '0'), \
(22, 4, '授权', '4', 'sys_oper_type', '', 'primary', 'N', '0', 'admin', {now}, '授权操作', '0'), \
(23, 5, '导出', '5', 'sys_oper_type', '', 'warning', 'N', '0', 'admin', {now}, '导出操作', '0'), \
(24, 6, '导入', '6', 'sys_oper_type', '', 'warning', 'N', '0', 'admin', {now}, '导入操作', '0'), \
(25, 7, '强退', '7', 'sys_oper_type', '', 'danger', 'N', '0', 'admin', {now}, '强退操作', '0'), \
(26, 8, '生成代码', '8', 'sys_oper_type', '', 'warning', 'N', '0', 'admin', {now}, '生成操作', '0'), \
(27, 9, '清空数据', '9', 'sys_oper_type', '', 'danger', 'N', '0', 'admin', {now}, '清空操作', '0'), \
(28, 1, '成功', '0', 'sys_common_status', '', 'primary', 'N', '0', 'admin', {now}, '正常状态', '0'), \
(29, 2, '失败', '1', 'sys_common_status', '', 'danger', 'N', '0', 'admin', {now}, '停用状态', '0')"
    );
    execute_idempotent_insert(manager, &sql).await?;
    Ok(())
}

/// 插入 sys_job 初始数据（3 个系统默认定时任务）
async fn insert_sys_job(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    let now = now_expr(manager);
    let sql = format!(
        "sys_job (job_id, job_name, job_group, invoke_target, cron_expression, misfire_policy, concurrent, status, create_by, create_time, remark, del_flag) VALUES \
(1, '系统默认（无参）', 'DEFAULT', 'demoTask.demoNoParams', '0/10 * * * * ?', '3', '1', '1', 'admin', {now}, '', '0'), \
(2, '系统默认（有参）', 'DEFAULT', 'demoTask.demoParams(''demo'')', '0/15 * * * * ?', '3', '1', '1', 'admin', {now}, '', '0'), \
(3, '系统默认（多参）', 'DEFAULT', 'demoTask.demoMultipleParams(''demo'', true, 2000L, 316.50D, 100)', '0/20 * * * * ?', '3', '1', '1', 'admin', {now}, '', '0')"
    );
    execute_idempotent_insert(manager, &sql).await?;
    Ok(())
}

/// 插入 sys_dept 初始数据（Stepby 标准 5 级部门树）
async fn insert_sys_dept(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    let now = now_expr(manager);
    let sql = format!(
        "sys_dept (dept_id, parent_id, ancestors, dept_name, order_num, leader, phone, email, status, del_flag, create_by, create_time) VALUES \
(100, 0, '0', 'Stepby科技', 0, 'Stepby', '15888888888', 'stepby@tzkj.net', '0', '0', 'admin', {now}), \
(101, 100, '0,100', '深圳总公司', 1, 'Stepby', '15888888888', 'stepby@tzkj.net', '0', '0', 'admin', {now}), \
(102, 100, '0,100', '长沙分公司', 2, 'Stepby', '15888888888', 'stepby@tzkj.net', '0', '0', 'admin', {now}), \
(103, 101, '0,100,101', '研发部门', 1, 'Stepby', '15888888888', 'stepby@tzkj.net', '0', '0', 'admin', {now}), \
(104, 101, '0,100,101', '市场部门', 2, 'Stepby', '15888888888', 'stepby@tzkj.net', '0', '0', 'admin', {now}), \
(105, 101, '0,100,101', '测试部门', 3, 'Stepby', '15888888888', 'stepby@tzkj.net', '0', '0', 'admin', {now}), \
(106, 101, '0,100,101', '财务部门', 4, 'Stepby', '15888888888', 'stepby@tzkj.net', '0', '0', 'admin', {now}), \
(107, 101, '0,100,101', '运维部门', 5, 'Stepby', '15888888888', 'stepby@tzkj.net', '0', '0', 'admin', {now}), \
(108, 102, '0,100,102', '市场部门', 1, 'Stepby', '15888888888', 'stepby@tzkj.net', '0', '0', 'admin', {now}), \
(109, 102, '0,100,102', '财务部门', 2, 'Stepby', '15888888888', 'stepby@tzkj.net', '0', '0', 'admin', {now})"
    );
    execute_idempotent_insert(manager, &sql).await?;
    Ok(())
}

/// 插入 sys_post 初始数据（Stepby 标准 4 个岗位）
async fn insert_sys_post(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    let now = now_expr(manager);
    let sql = format!(
        "sys_post (post_id, post_code, post_name, post_sort, status, del_flag, create_by, create_time, remark) VALUES \
(1, 'ceo', '董事长', 1, '0', '0', 'admin', {now}, ''), \
(2, 'se', '项目经理', 2, '0', '0', 'admin', {now}, ''), \
(3, 'hr', '人力资源', 3, '0', '0', 'admin', {now}, ''), \
(4, 'user', '普通员工', 4, '0', '0', 'admin', {now}, '')"
    );
    execute_idempotent_insert(manager, &sql).await?;

    // 插入 sys_user_post 关联（admin 关联董事长，ry 关联普通员工）
    let user_post_sql = "sys_user_post (user_id, post_id) VALUES (1, 1), (2, 4)";
    execute_idempotent_insert(manager, user_post_sql).await?;
    Ok(())
}

// ========== sys_config 建表与初始数据 ==========

/// 创建 sys_config 表（参数配置）
async fn create_sys_config(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    manager
        .create_table(
            Table::create()
                .table(Alias::new("sys_config"))
                .if_not_exists()
                .col(
                    ColumnDef::new(Alias::new("config_id"))
                        .big_integer()
                        .not_null()
                        .auto_increment()
                        .primary_key(),
                )
                .col(
                    ColumnDef::new(Alias::new("config_name"))
                        .string_len(100)
                        .default(""),
                )
                .col(
                    ColumnDef::new(Alias::new("config_key"))
                        .string_len(100)
                        .not_null(),
                )
                .col(
                    ColumnDef::new(Alias::new("config_value"))
                        .string_len(255)
                        .default(""),
                )
                .col(
                    ColumnDef::new(Alias::new("config_type"))
                        .char()
                        .default("N"),
                )
                .col(
                    ColumnDef::new(Alias::new("create_by"))
                        .string_len(64)
                        .default(""),
                )
                .col(ColumnDef::new(Alias::new("create_time")).date_time().null())
                .col(
                    ColumnDef::new(Alias::new("update_by"))
                        .string_len(64)
                        .default(""),
                )
                .col(ColumnDef::new(Alias::new("update_time")).date_time().null())
                .col(ColumnDef::new(Alias::new("remark")).string_len(500).null())
                .to_owned(),
        )
        .await?;

    manager
        .create_index(
            Index::create()
                .if_not_exists()
                .name("uk_sys_config_key")
                .table(Alias::new("sys_config"))
                .col(Alias::new("config_key"))
                .unique()
                .to_owned(),
        )
        .await?;

    Ok(())
}

/// 插入 sys_config 初始数据（Stepby 标准参数配置）
async fn insert_sys_config(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    let now = now_expr(manager);
    let sql = format!(
        "sys_config (config_id, config_name, config_key, config_value, config_type, create_by, create_time, remark) VALUES \
(1, '主框架页-默认皮肤主题名称', 'sys.index.skinName', 'skin-blue', 'Y', 'admin', {now}, '蓝色 skin-blue、绿色 skin-green、黄色 skin-yellow、红色 skin-red'), \
(2, '用户管理-账号初始密码', 'sys.user.initPassword', '123456', 'Y', 'admin', {now}, '初始化密码 123456'), \
(3, '主框架页-侧边栏主题', 'sys.index.sideTheme', 'theme-dark', 'Y', 'admin', {now}, '深色主题 theme-dark，浅色主题 theme-light'), \
(4, '账号自助-验证码开关', 'sys.account.captchaEnabled', 'true', 'Y', 'admin', {now}, '是否开启登录验证码'), \
(5, '账号自助-注册开关', 'sys.account.registerUser', 'false', 'Y', 'admin', {now}, '是否开启注册用户功能'), \
(6, '用户登录-黑名单列表', 'sys.login.blackIPList', '', 'Y', 'admin', {now}, '设置登录 IP 黑名单限制')",
        now = now
    );
    execute_idempotent_insert(manager, &sql).await?;
    Ok(())
}

// ========== sys_notice 建表与初始数据 ==========

/// 创建 sys_notice 表（通知公告）
async fn create_sys_notice(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    manager
        .create_table(
            Table::create()
                .table(Alias::new("sys_notice"))
                .if_not_exists()
                .col(
                    ColumnDef::new(Alias::new("notice_id"))
                        .big_integer()
                        .not_null()
                        .auto_increment()
                        .primary_key(),
                )
                .col(
                    ColumnDef::new(Alias::new("notice_title"))
                        .string_len(50)
                        .not_null(),
                )
                .col(ColumnDef::new(Alias::new("notice_type")).char().not_null())
                .col(ColumnDef::new(Alias::new("notice_content")).text().null())
                .col(ColumnDef::new(Alias::new("status")).char().default("0"))
                .col(
                    ColumnDef::new(Alias::new("create_by"))
                        .string_len(64)
                        .default(""),
                )
                .col(ColumnDef::new(Alias::new("create_time")).date_time().null())
                .col(
                    ColumnDef::new(Alias::new("update_by"))
                        .string_len(64)
                        .default(""),
                )
                .col(ColumnDef::new(Alias::new("update_time")).date_time().null())
                .col(ColumnDef::new(Alias::new("remark")).string_len(255).null())
                .to_owned(),
        )
        .await?;
    Ok(())
}

/// 插入 sys_notice 初始数据（Stepby 标准 2 条通知公告）
async fn insert_sys_notice(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    let now = now_expr(manager);
    let sql = format!(
        "sys_notice (notice_id, notice_title, notice_type, notice_content, status, create_by, create_time, remark) VALUES \
(1, '温馨提醒：Stepby管理系统新版本发布啦', '2', '新版本内容', '0', 'admin', {now}, '管理员'), \
(2, '维护通知：Stepby系统凌晨维护', '1', '维护内容', '0', 'admin', {now}, '管理员')",
        now = now
    );
    execute_idempotent_insert(manager, &sql).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    // QueryStatementBuilder（提供 `to_string(query_builder)`）已由 `super::*`（prelude）带入
    use sea_orm_migration::sea_orm::sea_query::PostgresQueryBuilder;

    /// 可证伪（R5-DB-26）：全新库 `sys_dept.ancestors` 必须建为 VARCHAR(500)。
    ///
    /// 该缺陷在 SQLite 上测不出来（不强制 VARCHAR 长度），但 PostgreSQL/MySQL 会强制：
    /// 若宽度回退到 50，深层部门的祖先链 CSV 写入会失败/截断。本断言直接锚定生成的
    /// 建表 DDL，故任何人改回 50 都会立即失败。
    #[test]
    fn sys_dept_ancestors_is_varchar_500() {
        let ddl = sys_dept_table_stmt()
            .to_string(PostgresQueryBuilder)
            .to_lowercase();
        assert!(
            ddl.contains("\"ancestors\" varchar(500)"),
            "sys_dept.ancestors 应为 varchar(500)，实际建表 DDL: {ddl}"
        );
    }
}
