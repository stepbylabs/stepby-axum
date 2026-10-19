// stepby-axum/migration/src/migrations/m20260820_000001_demo_seed.rs
//! 演示种子数据迁移（B 类演示种子）
//!
//! 目的：提供一套「开箱即用、可登录演示」的真实示例数据，方便在线 Demo / 本地体验，
//! 让每个业务模块都有前置内容可看可用，而非空白界面。
//!
//! 安全设计：
//!   - 仅当环境变量 `SEED_DEMO=1` 时写入（生产/日常开发默认不加该变量 → 本迁移为 no-op），
//!     从根上避免演示数据污染生产库。Docker 编排可加 `SEED_DEMO=1` 开启。
//!   - 全部走 execute_idempotent_insert（INSERT OR IGNORE / ON CONFLICT DO NOTHING / INSERT IGNORE），
//!     同一迁移可重复执行不产生重复行。
//!   - 主键使用高段保留 ID（9000+），与 init/menu 既有 ID（1~3551）不冲突。
//!   - 用户沿用 init 的密码策略（admin123，MD5(明文+盐值)），登录账号演示即可用。
//!
//! 演示数据范围：示例用户（绑定研发部门）、演示角色（授权系统管理基础页面）、
//! 示例岗位、示例系统参数。字典/部门/菜单基础结构由 init 迁移提供。

use sea_orm_migration::prelude::*;

pub struct Migration;

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

/// 种子时间表达式（批七十四 B1：归口到 `crate::seed_now_expr`，三方言统一 UTC 字面量）。
/// 本函数只是委托，**不得**在此另拼时间 ⇒ 换库/换时区不再换口径。
fn now_expr(_manager: &SchemaManager<'_>) -> String {
    crate::seed_now_expr()
}

/// 幂等 INSERT（兼容 SQLite / PostgreSQL / MySQL）
async fn execute_idempotent_insert(manager: &SchemaManager<'_>, body: &str) -> Result<(), DbErr> {
    let sql = if is_sqlite(manager) {
        format!("INSERT OR IGNORE INTO {}", body)
    } else if is_postgres(manager) {
        format!("INSERT INTO {} ON CONFLICT DO NOTHING", body)
    } else {
        format!("INSERT IGNORE INTO {}", body)
    };
    manager.get_connection().execute_unprepared(&sql).await?;
    Ok(())
}

impl MigrationName for Migration {
    fn name(&self) -> &str {
        "m20260820_000001_demo_seed"
    }
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // 仅显式开启演示种子（SEED_DEMO=1）时写入，生产安全
        if !std::env::var("SEED_DEMO")
            .map(|v| v == "1")
            .unwrap_or(false)
        {
            eprintln!("SEED_DEMO 未开启，跳过演示种子数据");
            return Ok(());
        }

        let now = now_expr(manager);

        // ---- 1. 示例用户（4 个，绑定研发部门 103 / 测试部门 105，密码均为 admin123）----
        const USER_BASE: i64 = 9000;
        let users = [
            (USER_BASE, 103i64, "demo_zhang", "张同学", "0"),
            (USER_BASE + 1, 103, "demo_li", "李产品", "0"),
            (USER_BASE + 2, 105, "demo_wang", "王测试", "0"),
            (USER_BASE + 3, 105, "demo_zhao", "赵运营", "1"),
        ];
        for (id, dept_id, name, nick, sex) in users {
            let sql = format!(
                "sys_user (user_id, dept_id, user_name, nick_name, user_type, email, phonenumber, sex, avatar, password, status, del_flag, login_ip, login_date, create_by, create_time, remark) VALUES \
                 ({id}, {dept_id}, '{name}', '{nick}', '00', '{name}@tzkj.net', '18{sex}888888', '{sex}', '', 'ba976d23f6d1012cfe81ceb960a1058c', '0', '0', '127.0.0.1', {now}, 'demo', {now}, '演示用户')"
            );
            execute_idempotent_insert(manager, &sql).await?;
        }

        // ---- 2. 演示角色（role_id=9000，绑定系统管理基础页面）----
        const ROLE_ID: i64 = 9000;
        let role_sql = format!(
            "sys_role (role_id, role_name, role_key, role_sort, data_scope, menu_check_strictly, dept_check_strictly, status, del_flag, create_by, create_time, remark) VALUES \
             ({ROLE_ID}, '演示角色', 'demo', 3, '2', TRUE, TRUE, '0', '0', 'demo', {now}, '演示角色：拥有系统管理基础页面查看/编辑权限')"
        );
        execute_idempotent_insert(manager, &role_sql).await?;

        // 角色授权：用户/角色/菜单/部门/岗位 五个 C 页面菜单（init 已定义 100~104）
        const C_MENUS: [i64; 5] = [100, 101, 102, 103, 104];
        let role_menu_values = C_MENUS
            .iter()
            .map(|m| format!("({ROLE_ID}, {})", m))
            .collect::<Vec<_>>()
            .join(", ");
        execute_idempotent_insert(
            manager,
            &format!(
                "sys_role_menu (role_id, menu_id) VALUES {}",
                role_menu_values
            ),
        )
        .await?;

        // 演示用户全部挂到演示角色
        let mut pairs = Vec::new();
        for i in 0..4 {
            pairs.push(format!("({}, {ROLE_ID})", USER_BASE + i));
        }
        execute_idempotent_insert(
            manager,
            &format!(
                "sys_user_role (user_id, role_id) VALUES {}",
                pairs.join(", ")
            ),
        )
        .await?;

        // ---- 3. 示例岗位（post_id=9000）----
        let post_sql = format!(
            "sys_post (post_id, post_code, post_name, post_sort, status, del_flag, create_by, create_time, remark) VALUES \
             (9000, 'demo', '演示岗位', 5, '0', '0', 'demo', {now}, '演示岗位示例')"
        );
        execute_idempotent_insert(manager, &post_sql).await?;

        // ---- 4. 示例系统参数（config_id=9000）----
        let config_sql = format!(
            "sys_config (config_id, config_name, config_key, config_value, config_type, create_by, create_time, remark) VALUES \
             (9000, '登录背景图', 'sys.login.background', '/uploads/demo-bg.svg', 'Y', 'demo', {now}, '演示登录背景图配置')"
        );
        execute_idempotent_insert(manager, &config_sql).await?;

        eprintln!("演示种子数据写入完成（演示登录：demo_zhang / admin123）");
        Ok(())
    }

    // 演示种子不做下移：迁移框架前向只 up，破坏性回退走备份恢复（见 docs/migrations.md）。
    async fn down(&self, _manager: &SchemaManager) -> Result<(), DbErr> {
        Ok(())
    }
}
