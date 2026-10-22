//! 口令有效期与服务端强改密闸门（批八十四 项 A）：把两件"已发布但是假的"能力做成真的。
//!
//! 背景（缺陷取证）：
//! 1. `src/service/auth_service.rs` 把 `is_password_expired` **写死为 `false`**，而
//!    `docs/auth-spec.md` 早已把"密码过期"当交付能力写进文档，前端 `store/modules/user.ts`
//!    也备好了对应弹框分支——即"接口字段存在但恒假"的假功能（用户改不掉、无人判红）。
//!    根因是**库里没有任何"口令何时设置过"的事实**：`sys_user` 只有 `create_time/update_time/
//!    login_date`，而 `update_time` 被 `impl_timestamped_active_model!` 在**任何**更新上刷新
//!    （改昵称、传头像、软删都会动它），结构上不能当口令年龄用。
//! 2. `sys.user.forceFirstLoginChangePwd`（B4）只有**前端弹框**，服务端零闸门 ⇒ "强改密"是
//!    一个可以绕过的建议（直接调 API 照常读写），属 AGENTS 开关规范③禁止的"只做前端隐藏"。
//!
//! 本迁移落三件事（全部默认关闭态 = 现状零变化）：
//!
//! 1. `sys_user.pwd_update_time DATETIME NULL`：口令**最后一次真实变更**的时刻。
//!    - 由代码显式写入（不依赖 DDL 默认值，见 `common/datetime.rs` 的"DDL default 不可依赖"锁）；
//!    - **不**在 `upgrade_password_hash`（MD5→Argon2 静默换哈希、口令本身未变）上刷新，
//!      否则一次登录就把过期时钟归零，有效期形同虚设；
//!    - 存量回填 `create_time`（口令年龄 ≥ 账号年龄，是唯一可辩护的代理），
//!      `create_time` 也为 NULL 的行取建列时刻（宁可让管理员看到"刚设置"，不得凭空判过期）。
//! 2. `sys_config` 种子 `sys.user.pwdExpireDays = '0'`：0 = 永不过期 = 现状；
//!    解析失败/负值一律回落 0 并 WARN（fail-safe，缺行=现状）。
//! 3. `sys_config` 种子 `sys.user.pwdChangeGate = 'off'`：强改密的服务端闸门档位，
//!    按**开放度单调**排列 `deny_all | deny_write | off`（下标越大越开放）：
//!    - `deny_all`：除"仅登录白名单"（`is_login_only_path`，与 deny_by_default **同一张表**）
//!      外一律 403；
//!    - `deny_write`：只拦写方法（POST/PUT/DELETE），读放行——给管理员"先看影响面再收紧"的台阶；
//!    - `off`（默认）：不拦（= 现状）。
//!      非法值回落 `off` 并 WARN；档位读取失败按 `off`（不明确的姿态不得拦截用户）。
//!
//! ## 口径
//!
//! - 加列幂等（逐列 `has_column`，存量库兜底可能已补列而不登记版本）；
//! - config 种子仅幂等 INSERT（不 UPDATE，尊重管理员已改值）；
//! - `pub fn` 供 `initialize/schema.rs` 兜底引用（单一事实源，等价性由
//!   `initialize::tests::schema_equivalence_lock` 钉住）；
//! - 时间表达式一律由调用方传入 `crate::seed_now_expr()`（`seed_paths_never_use_local_clock` 锁），
//!   本文件内不出现 `CURRENT_TIMESTAMP` / `NOW()` 分支。

use sea_orm_migration::prelude::*;
use sea_orm_migration::sea_orm::{ConnectionTrait, Statement, Value};

use crate::adapt_placeholders;

pub struct Migration;

impl MigrationName for Migration {
    fn name(&self) -> &str {
        "m20261022_000001_pwd_expire_policy"
    }
}

/// 口令有效期天数（热键，0 = 永不过期 = 现状）
///
/// **命名不是风格问题**：`sys_config` 的读回接口 `GET /system/config/configKey/{key}`
/// 有一层"键名含 `password`/`secret`/`token` 即脱敏"的**兜底启发式**
/// （`sys_config_service::is_sensitive_key`）。原名 `passwordExpireDays` 撞上它，
/// 于是平台管理员在参数管理页看到的生效值是 `***`——策略值被当成密钥藏起来，
/// 运维既确认不了自己设了多少，也没法用它做任何校验（本批 e2e M91 实测抓到）。
/// 取 `pwdExpireDays` 与本仓既有 house style（`pwdChangeGate` / `must_change_pwd` /
/// `forceFirstLoginChangePwd`）一致，且不与启发式对打。
pub const PWD_EXPIRE_DAYS_CONFIG_KEY: &str = "sys.user.pwdExpireDays";

/// 旧键名 → 新键名（**必须在种子里改名**，不是"改了名就当没发生过"）。
///
/// 为什么必须在迁移里做：`sys_config` 种子走 `INSERT OR IGNORE`（尊重管理员已改值），
/// 而两版键名共用 `config_id=9011` ⇒ 已跑过旧版的存量库里 9011 被旧键占着，
/// 新键那条会被**静默忽略**——参数面从此看不见这个能力（"能力存在但无处开启"= 没做，
/// 也正是 AGENTS 项目定位明令禁止的那一类）。改名保住了管理员可能已改过的值本身。
pub const KEY_RENAMES: &[(&str, &str)] =
    &[("sys.user.passwordExpireDays", "sys.user.pwdExpireDays")];
pub const PWD_EXPIRE_DAYS_CONFIG_DEFAULT: &str = "0";

/// 服务端强改密闸门档位（热键，off = 现状）
pub const PWD_CHANGE_GATE_CONFIG_KEY: &str = "sys.user.pwdChangeGate";
pub const PWD_CHANGE_GATE_CONFIG_DEFAULT: &str = "off";

/// 两个键在参数管理页里的**说明文案**（种子与存量库兜底归一共用同一常量）。
///
/// 为什么必须是常量：`off | deny_write | deny_all` 三档的区别**只写在这句 remark 里**，
/// 而存量库上这两个键可能先由治理注册表兜底建行（remark 是一句通用文案），
/// 于是运维在页面上看不到档位语义就会配错（b84 seed_diff 实测出的正是这一支）。
/// 兜底归一（`initialize/schema.rs::ensure_user_pwd_expire_policy`）与本种子必须取同一串，
/// 否则归一永远不成立而没有任何地方报错。
pub const PWD_EXPIRE_DAYS_REMARK: &str = "0=永不过期（现状）；>0 时自口令最后一次变更起到期即判过期，配合 sys.user.pwdChangeGate 决定是否服务端拦截";
pub const PWD_CHANGE_GATE_REMARK: &str = "deny_all=除仅登录白名单外全部403 / deny_write=只拦写方法 / off=不拦截（默认，现状）；档位按开放度单调排列，非法值回落 off 并 WARN";

/// 幂等检查列是否存在（三方言，与 `m20261004_000003` 同口径：
/// SQLite 的 `PRAGMA table_info` 返回**全部列**，必须按 name 过滤，
/// 以"行非空"判定会恒 true、ALTER 永不执行）。
async fn has_column(manager: &SchemaManager<'_>, table: &str, column: &str) -> Result<bool, DbErr> {
    let conn = manager.get_connection();
    let backend = conn.get_database_backend();
    match backend {
        sea_orm_migration::sea_orm::DatabaseBackend::Sqlite => {
            let rows = conn
                .query_all_raw(Statement::from_string(
                    backend,
                    format!("PRAGMA table_info({table})"),
                ))
                .await?;
            Ok(rows.iter().any(|row| {
                row.try_get::<String>("", "name")
                    .map(|n| n.eq_ignore_ascii_case(column))
                    .unwrap_or(false)
            }))
        }
        _ => {
            let schema = if backend == sea_orm::DatabaseBackend::Postgres {
                "table_schema=current_schema()"
            } else {
                "table_schema=DATABASE()"
            };
            let rows = conn
                .query_all_raw(Statement::from_string(
                    backend,
                    format!(
                        "SELECT 1 FROM information_schema.columns WHERE table_name='{table}' AND column_name='{column}' AND {schema} LIMIT 1"
                    ),
                ))
                .await?;
            Ok(!rows.is_empty())
        }
    }
}

/// 幂等 INSERT（种子按唯一约束去重）
async fn execute_idempotent_insert(manager: &SchemaManager<'_>, body: &str) -> Result<(), DbErr> {
    let sql = match manager.get_connection().get_database_backend() {
        sea_orm::DatabaseBackend::Sqlite => format!("INSERT OR IGNORE INTO {}", body),
        sea_orm::DatabaseBackend::Postgres => {
            format!("INSERT INTO {} ON CONFLICT DO NOTHING", body)
        }
        _ => format!("INSERT IGNORE INTO {}", body),
    };
    manager.get_connection().execute_unprepared(&sql).await?;
    Ok(())
}

/// 旧键名 → 新键名的就地收敛（**迁移与 initialize 兜底共用**）。
///
/// 为什么不能是一条 `UPDATE ... SET config_key = 新名`（本批实测踩过的启动事故）：
/// `sys_config` 上有 `UNIQUE(tenant_id, config_key)`，而启动序里
/// `initialize::tenant::治理参数项缺行补齐` 会**先**按治理注册表把新键的默认行建出来；
/// 于是裸改名必然撞唯一键 ⇒ `?` 直接冒泡 ⇒ initialize 退出、**整个服务起不来**。
/// 一条"看着幂等"的 DDL 能把启动打死，这就是兜底必须按事实分情况而不是按名字硬写的原因。
///
/// 三种存量态都要收敛到"新键一行、值取管理员已改的那个"：
/// - 只有旧行 ⇒ 就地改名（保住 config_id 与值，`INSERT OR IGNORE` 之后不会重复种）；
/// - 新旧都有 ⇒ 旧行的值**搬进**新行（尊重管理员已改值，种子的默认值不得覆盖它），再删旧行；
/// - 只有新行 / 都没有 ⇒ 什么都不做（后者由种子补出默认行）。
///
/// 按 `tenant_id` 逐行处理，不假设"平台专属键不可能有租户覆盖行"——
/// 前提成立与否不由本函数赌（AGENTS 铁律①：读侧与写侧共用同一租户谓词）。
pub async fn rename_legacy_keys<C>(conn: &C) -> Result<(), DbErr>
where
    C: ConnectionTrait,
{
    let backend = conn.get_database_backend();
    // 占位符一律按 PG 风格写 `$N`，再经 `adapt_placeholders` 适配 MySQL/SQLite 的 `?`
    // （本 crate 的唯一事实源）。直接写 `?` 在 PostgreSQL 上是**语法错误**——
    // `from_sql_and_values` 不改写占位符，执行路径把 SQL 原样交给 sqlx；
    // 而本机测试跑在 SQLite 上看不见这一支，所以由 `scripts/pg_placeholder_scan.py` 拦。
    for (from_raw, to_raw) in KEY_RENAMES {
        let (from, to): (&str, &str) = (*from_raw, *to_raw);
        let legacy = conn
            .query_all_raw(Statement::from_sql_and_values(
                backend,
                adapt_placeholders(
                    backend,
                    "SELECT tenant_id, config_value FROM sys_config WHERE config_key = $1",
                ),
                [Value::String(Some(from.to_owned()))],
            ))
            .await?;
        for row in legacy {
            let tid: i64 = row.try_get("", "tenant_id")?;
            let val: Option<String> = row.try_get("", "config_value")?;
            let target = conn
                .query_one_raw(Statement::from_sql_and_values(
                    backend,
                    adapt_placeholders(
                        backend,
                        "SELECT config_id FROM sys_config WHERE config_key = $1 AND tenant_id = $2",
                    ),
                    [Value::String(Some(to.to_owned())), Value::BigInt(Some(tid))],
                ))
                .await?;
            if target.is_some() {
                // 新行已存在：值搬过去，再清理旧行
                if let Some(v) = val {
                    conn.execute_raw(Statement::from_sql_and_values(
                        backend,
                        adapt_placeholders(
                            backend,
                            "UPDATE sys_config SET config_value = $1 \
                             WHERE config_key = $2 AND tenant_id = $3",
                        ),
                        [
                            Value::String(Some(v)),
                            Value::String(Some(to.to_owned())),
                            Value::BigInt(Some(tid)),
                        ],
                    ))
                    .await?;
                }
                conn.execute_raw(Statement::from_sql_and_values(
                    backend,
                    adapt_placeholders(
                        backend,
                        "DELETE FROM sys_config WHERE config_key = $1 AND tenant_id = $2",
                    ),
                    [
                        Value::String(Some(from.to_owned())),
                        Value::BigInt(Some(tid)),
                    ],
                ))
                .await?;
            } else {
                conn.execute_raw(Statement::from_sql_and_values(
                    backend,
                    adapt_placeholders(
                        backend,
                        "UPDATE sys_config SET config_key = $1 \
                         WHERE config_key = $2 AND tenant_id = $3",
                    ),
                    [
                        Value::String(Some(to.to_owned())),
                        Value::String(Some(from.to_owned())),
                        Value::BigInt(Some(tid)),
                    ],
                ))
                .await?;
            }
        }
    }
    Ok(())
}

/// 两个热键的 `sys_config` 幂等 INSERT 体（**迁移与 `initialize` 兜底共用同一份文本**）。
///
/// 为什么在这里给函数、而不是像 `m20261004_000003` 那样在兜底侧再抄一遍：这两个键的默认值
/// **就是**"关闭态"，抄一份就意味着"迁移侧种 `0` / 兜底侧种 `1`"这类漂移只能靠
/// `schema_equivalence_lock` 的种子比对偶然抓到——键名与默认值同源生成，漂移在结构上不可能。
///
/// 两键都取**显式 config_id**：无显式 id 的 INSERT 在 PG 上取决于该列是否 serial，
/// 本仓 sys_config 种子一律给 id（与 9010 同口径），不赌方言默认。
pub fn config_bodies(now_expr: &str) -> Vec<String> {
    vec![
        format!(
            "sys_config (config_id, config_name, config_key, config_value, config_type, create_by, create_time, remark) VALUES \
            (9011, '口令有效期天数', '{PWD_EXPIRE_DAYS_CONFIG_KEY}', '{PWD_EXPIRE_DAYS_CONFIG_DEFAULT}', 'Y', 'admin', {now_expr}, '{PWD_EXPIRE_DAYS_REMARK}')"
        ),
        format!(
            "sys_config (config_id, config_name, config_key, config_value, config_type, create_by, create_time, remark) VALUES \
            (9012, '强改密服务端闸门', '{PWD_CHANGE_GATE_CONFIG_KEY}', '{PWD_CHANGE_GATE_CONFIG_DEFAULT}', 'Y', 'admin', {now_expr}, '{PWD_CHANGE_GATE_REMARK}')"
        ),
    ]
}

/// 加列 + 两个热键种子的**共用**实现（迁移与 `initialize` 兜底的单一事实源）。
///
/// 返回 `newly_added`：`true` 表示本次真的建了列 ⇒ 调用方执行存量回填
/// （存量库重跑不得反复回填，否则管理员把口令年龄洗成"刚改过"）。
pub async fn upsert_pwd_expire_columns(
    manager: &SchemaManager<'_>,
    now_expr: &str,
) -> Result<(bool, Vec<String>), DbErr> {
    let newly_added = !has_column(manager, "sys_user", "pwd_update_time").await?;
    if newly_added {
        manager
            .alter_table(
                Table::alter()
                    .table(Alias::new("sys_user"))
                    .add_column(
                        ColumnDef::new(Alias::new("pwd_update_time"))
                            .date_time()
                            .null(),
                    )
                    .to_owned(),
            )
            .await?;
    }

    Ok((newly_added, config_bodies(now_expr)))
}

/// 存量口令年龄回填语句体（**仅建列时**执行；先按账号年龄代理，再兜底建列时刻）。
///
/// 顺序即语义：`create_time` 有值的行用它（口令年龄 ≥ 账号年龄，是唯一可辩护的代理），
/// 仍为 NULL 的行（历史脏数据）取建列时刻——宁可让管理员看到"刚设置过"，
/// 也不得凭空判过期（fail-safe：默认姿态是不拦截）。
pub fn backfill_bodies(now_expr: &str) -> Vec<String> {
    vec![
        "UPDATE sys_user SET pwd_update_time = create_time WHERE pwd_update_time IS NULL AND create_time IS NOT NULL".to_string(),
        format!("UPDATE sys_user SET pwd_update_time = {now_expr} WHERE pwd_update_time IS NULL"),
    ]
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let now = crate::seed_now_expr();
        rename_legacy_keys(manager.get_connection()).await?;
        let (newly_added, config_bodies) = upsert_pwd_expire_columns(manager, &now).await?;

        if newly_added {
            for body in backfill_bodies(&now) {
                manager.get_connection().execute_unprepared(&body).await?;
            }
        }
        for body in config_bodies {
            execute_idempotent_insert(manager, &body).await?;
        }
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .get_connection()
            .execute_unprepared(&format!(
                "DELETE FROM sys_config WHERE config_key IN ('{PWD_EXPIRE_DAYS_CONFIG_KEY}', '{PWD_CHANGE_GATE_CONFIG_KEY}', 'sys.user.passwordExpireDays')"
            ))
            .await?;
        if !has_column(manager, "sys_user", "pwd_update_time").await? {
            return Ok(());
        }
        manager
            .alter_table(
                Table::alter()
                    .table(Alias::new("sys_user"))
                    .drop_column(Alias::new("pwd_update_time"))
                    .to_owned(),
            )
            .await?;
        Ok(())
    }
}
