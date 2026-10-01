# 数据库迁移任务分解（db-tasks.md）

> **阶段：** 第二阶段「系统核心数据库表结构设计」
> **对应规范：** `docs/db-spec.md`
> **规则基线：** `stepby-axum/.trae/rules/project-rules.md`
> **用途：** 按任务顺序执行，每个任务含完整代码块，可一键创建文件

---

## 任务总览

| 任务 | 内容 | 依赖 |
|------|------|------|
| Task 1 | 创建 sys_user 实体 | 无 |
| Task 2 | 创建 sys_role 实体 | 无 |
| Task 3 | 创建 sys_menu 实体 | 无 |
| Task 4 | 创建 sys_user_role 实体（复合主键） | 无 |
| Task 5 | 创建 sys_role_menu 实体（复合主键） | 无 |
| Task 6 | 创建 sys_dict_type 实体 | 无 |
| Task 7 | 创建 sys_dict_data 实体 | 无 |
| Task 8 | 创建 sys_oper_log 实体 | 无 |
| Task 9 | 创建 sys_logininfor 实体 | 无 |
| Task 10 | 创建 sys_job 实体 | 无 |
| Task 11 | 创建 sys_job_log 实体 | 无 |
| Task 12 | 更新 entity/mod.rs + 创建 prelude.rs | Task 1-11 |
| Task 13 | 填充 migration 建表语句（11 张表 + 索引） | Task 12 |
| Task 14 | 添加初始数据（admin + 角色 + 菜单 + 字典） | Task 13 |
| Task 15 | 编译验证 + 自查 | Task 14 |

---

## Task 1: 创建 sys_user 实体

**文件：** `src/entity/sys_user.rs`

```rust
//! sys_user 实体定义（用户信息表）

use chrono::NaiveDateTime;
use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize)]
#[sea_orm(table_name = "sys_user")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub user_id: i64,
    pub dept_id: Option<i64>,
    #[sea_orm(unique)]
    pub user_name: String,
    pub nick_name: String,
    pub user_type: Option<String>,
    pub email: Option<String>,
    pub phonenumber: Option<String>,
    pub sex: Option<String>,
    pub avatar: Option<String>,
    pub password: Option<String>,
    pub status: Option<String>,
    pub del_flag: Option<String>,
    pub login_ip: Option<String>,
    pub login_date: Option<NaiveDateTime>,
    pub create_by: Option<String>,
    pub create_time: Option<NaiveDateTime>,
    pub update_by: Option<String>,
    pub update_time: Option<NaiveDateTime>,
    pub remark: Option<String>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {
    /// 保存前自动维护 create_time / update_time
    fn before_save(mut self, _db: &DatabaseConnection, insert: bool) -> impl Future<Output = Result<Self, DbErr>> + Send {
        let now = chrono::Local::now().naive_local();
        if insert {
            self.create_time = Set(Some(now));
        }
        self.update_time = Set(Some(now));
        async { Ok(self) }
    }
}
```

---

## Task 2: 创建 sys_role 实体

**文件：** `src/entity/sys_role.rs`

```rust
//! sys_role 实体定义（角色信息表）

use chrono::NaiveDateTime;
use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize)]
#[sea_orm(table_name = "sys_role")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub role_id: i64,
    pub role_name: String,
    #[sea_orm(unique)]
    pub role_key: String,
    pub role_sort: i32,
    pub data_scope: Option<String>,
    pub menu_check_strictly: Option<bool>,
    pub dept_check_strictly: Option<bool>,
    pub status: String,
    pub del_flag: Option<String>,
    pub create_by: Option<String>,
    pub create_time: Option<NaiveDateTime>,
    pub update_by: Option<String>,
    pub update_time: Option<NaiveDateTime>,
    pub remark: Option<String>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {
    fn before_save(mut self, _db: &DatabaseConnection, insert: bool) -> impl Future<Output = Result<Self, DbErr>> + Send {
        let now = chrono::Local::now().naive_local();
        if insert {
            self.create_time = Set(Some(now));
        }
        self.update_time = Set(Some(now));
        async { Ok(self) }
    }
}
```

> **说明：** `menu_check_strictly` / `dept_check_strictly` 使用 `Option<bool>`，SeaORM 会映射为 `tinyint(1)`，对齐前端 `boolean` 类型。

---

## Task 3: 创建 sys_menu 实体

**文件：** `src/entity/sys_menu.rs`

```rust
//! sys_menu 实体定义（菜单权限表）

use chrono::NaiveDateTime;
use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize)]
#[sea_orm(table_name = "sys_menu")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub menu_id: i64,
    pub menu_name: String,
    pub parent_id: Option<i64>,
    pub order_num: Option<i32>,
    pub path: Option<String>,
    pub component: Option<String>,
    pub query: Option<String>,
    pub route_name: Option<String>,
    pub is_frame: Option<i32>,
    pub is_cache: Option<i32>,
    pub menu_type: Option<String>,
    pub visible: Option<String>,
    pub status: Option<String>,
    pub perms: Option<String>,
    pub icon: Option<String>,
    pub create_by: Option<String>,
    pub create_time: Option<NaiveDateTime>,
    pub update_by: Option<String>,
    pub update_time: Option<NaiveDateTime>,
    pub remark: Option<String>,
    pub del_flag: Option<String>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {
    fn before_save(mut self, _db: &DatabaseConnection, insert: bool) -> impl Future<Output = Result<Self, DbErr>> + Send {
        let now = chrono::Local::now().naive_local();
        if insert {
            self.create_time = Set(Some(now));
        }
        self.update_time = Set(Some(now));
        async { Ok(self) }
    }
}
```

---

## Task 4: 创建 sys_user_role 实体（复合主键）

**文件：** `src/entity/sys_user_role.rs`

```rust
//! sys_user_role 实体定义（用户角色关联表，复合主键）

use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize)]
#[sea_orm(table_name = "sys_user_role")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub user_id: i64,
    #[sea_orm(primary_key)]
    pub role_id: i64,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
```

---

## Task 5: 创建 sys_role_menu 实体（复合主键）

**文件：** `src/entity/sys_role_menu.rs`

```rust
//! sys_role_menu 实体定义（角色菜单关联表，复合主键）

use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize)]
#[sea_orm(table_name = "sys_role_menu")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub role_id: i64,
    #[sea_orm(primary_key)]
    pub menu_id: i64,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
```

---

## Task 6: 创建 sys_dict_type 实体

**文件：** `src/entity/sys_dict_type.rs`

```rust
//! sys_dict_type 实体定义（字典类型表）

use chrono::NaiveDateTime;
use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize)]
#[sea_orm(table_name = "sys_dict_type")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub dict_id: i64,
    pub dict_name: Option<String>,
    #[sea_orm(unique)]
    pub dict_type: Option<String>,
    pub status: Option<String>,
    pub create_by: Option<String>,
    pub create_time: Option<NaiveDateTime>,
    pub update_by: Option<String>,
    pub update_time: Option<NaiveDateTime>,
    pub remark: Option<String>,
    pub del_flag: Option<String>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {
    fn before_save(mut self, _db: &DatabaseConnection, insert: bool) -> impl Future<Output = Result<Self, DbErr>> + Send {
        let now = chrono::Local::now().naive_local();
        if insert {
            self.create_time = Set(Some(now));
        }
        self.update_time = Set(Some(now));
        async { Ok(self) }
    }
}
```

---

## Task 7: 创建 sys_dict_data 实体

**文件：** `src/entity/sys_dict_data.rs`

```rust
//! sys_dict_data 实体定义（字典数据表）

use chrono::NaiveDateTime;
use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize)]
#[sea_orm(table_name = "sys_dict_data")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub dict_code: i64,
    pub dict_sort: Option<i32>,
    pub dict_label: Option<String>,
    pub dict_value: Option<String>,
    pub dict_type: Option<String>,
    pub css_class: Option<String>,
    pub list_class: Option<String>,
    pub is_default: Option<String>,
    pub status: Option<String>,
    pub create_by: Option<String>,
    pub create_time: Option<NaiveDateTime>,
    pub update_by: Option<String>,
    pub update_time: Option<NaiveDateTime>,
    pub remark: Option<String>,
    pub del_flag: Option<String>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {
    fn before_save(mut self, _db: &DatabaseConnection, insert: bool) -> impl Future<Output = Result<Self, DbErr>> + Send {
        let now = chrono::Local::now().naive_local();
        if insert {
            self.create_time = Set(Some(now));
        }
        self.update_time = Set(Some(now));
        async { Ok(self) }
    }
}
```

---

## Task 8: 创建 sys_oper_log 实体

**文件：** `src/entity/sys_oper_log.rs`

```rust
//! sys_oper_log 实体定义（操作日志表）

use chrono::NaiveDateTime;
use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize)]
#[sea_orm(table_name = "sys_oper_log")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub oper_id: i64,
    pub title: Option<String>,
    pub business_type: Option<i32>,
    pub method: Option<String>,
    pub request_method: Option<String>,
    pub operator_type: Option<i32>,
    pub oper_name: Option<String>,
    pub dept_name: Option<String>,
    pub oper_url: Option<String>,
    pub oper_ip: Option<String>,
    pub oper_location: Option<String>,
    pub oper_param: Option<String>,
    pub json_result: Option<String>,
    pub status: Option<i32>,
    pub error_msg: Option<String>,
    pub oper_time: Option<NaiveDateTime>,
    pub cost_time: Option<i64>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
```

> **说明：** 日志表不实现 `before_save` 时间自动维护，`oper_time` 由业务层显式设置。

---

## Task 9: 创建 sys_logininfor 实体

**文件：** `src/entity/sys_logininfor.rs`

```rust
//! sys_logininfor 实体定义（系统访问记录 / 登录日志表）

use chrono::NaiveDateTime;
use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize)]
#[sea_orm(table_name = "sys_logininfor")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub info_id: i64,
    pub user_name: Option<String>,
    pub ipaddr: Option<String>,
    pub login_location: Option<String>,
    pub browser: Option<String>,
    pub os: Option<String>,
    pub status: Option<String>,
    pub msg: Option<String>,
    pub login_time: Option<NaiveDateTime>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
```

> **注意：** `ipaddr` 字段保持全小写（对齐前端 `SysLogininfor.ipaddr` 与既有 SQL 脚本），不要写成 `ip_addr` 或 `ipAddr`。

---

## Task 10: 创建 sys_job 实体

**文件：** `src/entity/sys_job.rs`

```rust
//! sys_job 实体定义（定时任务调度表）

use chrono::NaiveDateTime;
use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize)]
#[sea_orm(table_name = "sys_job")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub job_id: i64,
    pub job_name: String,
    pub job_group: String,
    pub invoke_target: String,
    pub cron_expression: Option<String>,
    pub misfire_policy: Option<String>,
    pub concurrent: Option<String>,
    pub status: Option<String>,
    pub create_by: Option<String>,
    pub create_time: Option<NaiveDateTime>,
    pub update_by: Option<String>,
    pub update_time: Option<NaiveDateTime>,
    pub remark: Option<String>,
    pub del_flag: Option<String>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {
    fn before_save(mut self, _db: &DatabaseConnection, insert: bool) -> impl Future<Output = Result<Self, DbErr>> + Send {
        let now = chrono::Local::now().naive_local();
        if insert {
            self.create_time = Set(Some(now));
        }
        self.update_time = Set(Some(now));
        async { Ok(self) }
    }
}
```

---

## Task 11: 创建 sys_job_log 实体

**文件：** `src/entity/sys_job_log.rs`

```rust
//! sys_job_log 实体定义（定时任务调度日志表）

use chrono::NaiveDateTime;
use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize)]
#[sea_orm(table_name = "sys_job_log")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub job_log_id: i64,
    pub job_name: String,
    pub job_group: String,
    pub invoke_target: String,
    pub job_message: Option<String>,
    pub status: Option<String>,
    pub exception_info: Option<String>,
    pub create_time: Option<NaiveDateTime>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
```

---

## Task 12: 更新 entity/mod.rs + 创建 prelude.rs

### Task 12.1: 更新 `src/entity/mod.rs`

**文件：** `src/entity/mod.rs`（覆盖原占位内容）

```rust
//! stepby-axum SeaORM 实体层
//! 包含 11 个系统核心表的实体定义

pub mod sys_dict_data;
pub mod sys_dict_type;
pub mod sys_job;
pub mod sys_job_log;
pub mod sys_logininfor;
pub mod sys_menu;
pub mod sys_oper_log;
pub mod sys_role;
pub mod sys_role_menu;
pub mod sys_user;
pub mod sys_user_role;

pub mod prelude;
```

### Task 12.2: 创建 `src/entity/prelude.rs`

**文件：** `src/entity/prelude.rs`

```rust
//! 实体 prelude 重导出
//! 使用方式：`use axum_backend::entity::prelude::*;`

pub use super::sys_dict_data::Entity as SysDictData;
pub use super::sys_dict_type::Entity as SysDictType;
pub use super::sys_job::Entity as SysJob;
pub use super::sys_job_log::Entity as SysJobLog;
pub use super::sys_logininfor::Entity as SysLogininfor;
pub use super::sys_menu::Entity as SysMenu;
pub use super::sys_oper_log::Entity as SysOperLog;
pub use super::sys_role::Entity as SysRole;
pub use super::sys_role_menu::Entity as SysRoleMenu;
pub use super::sys_user::Entity as SysUser;
pub use super::sys_user_role::Entity as SysUserRole;
```

---

## Task 13: 填充 migration 建表语句（11 张表 + 索引）

**文件：** `migration/src/m20250711_000001_init.rs`（覆盖原空骨架）

```rust
//! 首个迁移：创建系统核心表结构 + 索引 + 初始数据

use sea_orm_migration::prelude::*;

pub struct Migration;

impl MigrationName for Migration {
    fn name(&self) -> &str {
        "m20250711_000001_init"
    }
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // 1. 创建表（按依赖顺序）
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

        // 2. 创建索引
        create_indexes(manager).await?;

        // 3. 插入初始数据
        init_data(manager).await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // 按反序删除表
        manager.drop_table(Table::drop().table(SysJobLog::Table).to_owned()).await?;
        manager.drop_table(Table::drop().table(SysJob::Table).to_owned()).await?;
        manager.drop_table(Table::drop().table(SysLogininfor::Table).to_owned()).await?;
        manager.drop_table(Table::drop().table(SysOperLog::Table).to_owned()).await?;
        manager.drop_table(Table::drop().table(SysDictData::Table).to_owned()).await?;
        manager.drop_table(Table::drop().table(SysDictType::Table).to_owned()).await?;
        manager.drop_table(Table::drop().table(SysRoleMenu::Table).to_owned()).await?;
        manager.drop_table(Table::drop().table(SysUserRole::Table).to_owned()).await?;
        manager.drop_table(Table::drop().table(SysMenu::Table).to_owned()).await?;
        manager.drop_table(Table::drop().table(SysRole::Table).to_owned()).await?;
        manager.drop_table(Table::drop().table(SysUser::Table).to_owned()).await?;
        Ok(())
    }
}

// ==================== 表名标识 ====================

#[derive(Iden)]
enum SysUser {
    Table,
    UserId,
    DeptId,
    UserName,
    NickName,
    UserType,
    Email,
    Phonenumber,
    Sex,
    Avatar,
    Password,
    Status,
    DelFlag,
    LoginIp,
    LoginDate,
    CreateBy,
    CreateTime,
    UpdateBy,
    UpdateTime,
    Remark,
}

#[derive(Iden)]
enum SysRole {
    Table,
    RoleId,
    RoleName,
    RoleKey,
    RoleSort,
    DataScope,
    MenuCheckStrictly,
    DeptCheckStrictly,
    Status,
    DelFlag,
    CreateBy,
    CreateTime,
    UpdateBy,
    UpdateTime,
    Remark,
}

#[derive(Iden)]
enum SysMenu {
    Table,
    MenuId,
    MenuName,
    ParentId,
    OrderNum,
    Path,
    Component,
    Query,
    RouteName,
    IsFrame,
    IsCache,
    MenuType,
    Visible,
    Status,
    Perms,
    Icon,
    CreateBy,
    CreateTime,
    UpdateBy,
    UpdateTime,
    Remark,
    DelFlag,
}

#[derive(Iden)]
enum SysUserRole {
    Table,
    UserId,
    RoleId,
}

#[derive(Iden)]
enum SysRoleMenu {
    Table,
    RoleId,
    MenuId,
}

#[derive(Iden)]
enum SysDictType {
    Table,
    DictId,
    DictName,
    DictType,
    Status,
    CreateBy,
    CreateTime,
    UpdateBy,
    UpdateTime,
    Remark,
    DelFlag,
}

#[derive(Iden)]
enum SysDictData {
    Table,
    DictCode,
    DictSort,
    DictLabel,
    DictValue,
    DictType,
    CssClass,
    ListClass,
    IsDefault,
    Status,
    CreateBy,
    CreateTime,
    UpdateBy,
    UpdateTime,
    Remark,
    DelFlag,
}

#[derive(Iden)]
enum SysOperLog {
    Table,
    OperId,
    Title,
    BusinessType,
    Method,
    RequestMethod,
    OperatorType,
    OperName,
    DeptName,
    OperUrl,
    OperIp,
    OperLocation,
    OperParam,
    JsonResult,
    Status,
    ErrorMsg,
    OperTime,
    CostTime,
}

#[derive(Iden)]
enum SysLogininfor {
    Table,
    InfoId,
    UserName,
    Ipaddr,
    LoginLocation,
    Browser,
    Os,
    Status,
    Msg,
    LoginTime,
}

#[derive(Iden)]
enum SysJob {
    Table,
    JobId,
    JobName,
    JobGroup,
    InvokeTarget,
    CronExpression,
    MisfirePolicy,
    Concurrent,
    Status,
    CreateBy,
    CreateTime,
    UpdateBy,
    UpdateTime,
    Remark,
    DelFlag,
}

#[derive(Iden)]
enum SysJobLog {
    Table,
    JobLogId,
    JobName,
    JobGroup,
    InvokeTarget,
    JobMessage,
    Status,
    ExceptionInfo,
    CreateTime,
}

// ==================== 建表函数 ====================

async fn create_sys_user(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    manager
        .create_table(
            Table::create()
                .table(SysUser::Table)
                .if_not_exists()
                .col(ColumnDef::new(SysUser::UserId).big_integer().not_null().auto_increment().primary_key())
                .col(ColumnDef::new(SysUser::DeptId).big_integer().null())
                .col(ColumnDef::new(SysUser::UserName).string_len(30).not_null().unique_key())
                .col(ColumnDef::new(SysUser::NickName).string_len(30).not_null())
                .col(ColumnDef::new(SysUser::UserType).string_len(2).default("00"))
                .col(ColumnDef::new(SysUser::Email).string_len(50).default(""))
                .col(ColumnDef::new(SysUser::Phonenumber).string_len(11).default(""))
                .col(ColumnDef::new(SysUser::Sex).char_len(1).default("0"))
                .col(ColumnDef::new(SysUser::Avatar).string_len(100).default(""))
                .col(ColumnDef::new(SysUser::Password).string_len(100).default(""))
                .col(ColumnDef::new(SysUser::Status).char_len(1).default("0"))
                .col(ColumnDef::new(SysUser::DelFlag).char_len(1).default("0"))
                .col(ColumnDef::new(SysUser::LoginIp).string_len(128).default(""))
                .col(ColumnDef::new(SysUser::LoginDate).date_time().null())
                .col(ColumnDef::new(SysUser::CreateBy).string_len(64).default(""))
                .col(ColumnDef::new(SysUser::CreateTime).date_time().null())
                .col(ColumnDef::new(SysUser::UpdateBy).string_len(64).default(""))
                .col(ColumnDef::new(SysUser::UpdateTime).date_time().null())
                .col(ColumnDef::new(SysUser::Remark).string_len(500).null())
                .to_owned(),
        )
        .await
}

async fn create_sys_role(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    manager
        .create_table(
            Table::create()
                .table(SysRole::Table)
                .if_not_exists()
                .col(ColumnDef::new(SysRole::RoleId).big_integer().not_null().auto_increment().primary_key())
                .col(ColumnDef::new(SysRole::RoleName).string_len(30).not_null())
                .col(ColumnDef::new(SysRole::RoleKey).string_len(100).not_null().unique_key())
                .col(ColumnDef::new(SysRole::RoleSort).integer().not_null())
                .col(ColumnDef::new(SysRole::DataScope).char_len(1).default("1"))
                .col(ColumnDef::new(SysRole::MenuCheckStrictly).tiny_integer().default(1))
                .col(ColumnDef::new(SysRole::DeptCheckStrictly).tiny_integer().default(1))
                .col(ColumnDef::new(SysRole::Status).char_len(1).not_null())
                .col(ColumnDef::new(SysRole::DelFlag).char_len(1).default("0"))
                .col(ColumnDef::new(SysRole::CreateBy).string_len(64).default(""))
                .col(ColumnDef::new(SysRole::CreateTime).date_time().null())
                .col(ColumnDef::new(SysRole::UpdateBy).string_len(64).default(""))
                .col(ColumnDef::new(SysRole::UpdateTime).date_time().null())
                .col(ColumnDef::new(SysRole::Remark).string_len(500).null())
                .to_owned(),
        )
        .await
}

async fn create_sys_menu(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    manager
        .create_table(
            Table::create()
                .table(SysMenu::Table)
                .if_not_exists()
                .col(ColumnDef::new(SysMenu::MenuId).big_integer().not_null().auto_increment().primary_key())
                .col(ColumnDef::new(SysMenu::MenuName).string_len(50).not_null())
                .col(ColumnDef::new(SysMenu::ParentId).big_integer().default(0))
                .col(ColumnDef::new(SysMenu::OrderNum).integer().default(0))
                .col(ColumnDef::new(SysMenu::Path).string_len(200).default(""))
                .col(ColumnDef::new(SysMenu::Component).string_len(255).null())
                .col(ColumnDef::new(SysMenu::Query).string_len(255).null())
                .col(ColumnDef::new(SysMenu::RouteName).string_len(50).default(""))
                .col(ColumnDef::new(SysMenu::IsFrame).integer().default(1))
                .col(ColumnDef::new(SysMenu::IsCache).integer().default(0))
                .col(ColumnDef::new(SysMenu::MenuType).char_len(1).default(""))
                .col(ColumnDef::new(SysMenu::Visible).char_len(1).default("0"))
                .col(ColumnDef::new(SysMenu::Status).char_len(1).default("0"))
                .col(ColumnDef::new(SysMenu::Perms).string_len(100).null())
                .col(ColumnDef::new(SysMenu::Icon).string_len(100).default("#"))
                .col(ColumnDef::new(SysMenu::CreateBy).string_len(64).default(""))
                .col(ColumnDef::new(SysMenu::CreateTime).date_time().null())
                .col(ColumnDef::new(SysMenu::UpdateBy).string_len(64).default(""))
                .col(ColumnDef::new(SysMenu::UpdateTime).date_time().null())
                .col(ColumnDef::new(SysMenu::Remark).string_len(500).default(""))
                .col(ColumnDef::new(SysMenu::DelFlag).char_len(1).default("0"))
                .to_owned(),
        )
        .await
}

async fn create_sys_user_role(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    manager
        .create_table(
            Table::create()
                .table(SysUserRole::Table)
                .if_not_exists()
                .col(ColumnDef::new(SysUserRole::UserId).big_integer().not_null())
                .col(ColumnDef::new(SysUserRole::RoleId).big_integer().not_null())
                .primary_key(Index::create().col(SysUserRole::UserId).col(SysUserRole::RoleId))
                .to_owned(),
        )
        .await
}

async fn create_sys_role_menu(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    manager
        .create_table(
            Table::create()
                .table(SysRoleMenu::Table)
                .if_not_exists()
                .col(ColumnDef::new(SysRoleMenu::RoleId).big_integer().not_null())
                .col(ColumnDef::new(SysRoleMenu::MenuId).big_integer().not_null())
                .primary_key(Index::create().col(SysRoleMenu::RoleId).col(SysRoleMenu::MenuId))
                .to_owned(),
        )
        .await
}

async fn create_sys_dict_type(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    manager
        .create_table(
            Table::create()
                .table(SysDictType::Table)
                .if_not_exists()
                .col(ColumnDef::new(SysDictType::DictId).big_integer().not_null().auto_increment().primary_key())
                .col(ColumnDef::new(SysDictType::DictName).string_len(100).default(""))
                .col(ColumnDef::new(SysDictType::DictType).string_len(100).default("").unique_key())
                .col(ColumnDef::new(SysDictType::Status).char_len(1).default("0"))
                .col(ColumnDef::new(SysDictType::CreateBy).string_len(64).default(""))
                .col(ColumnDef::new(SysDictType::CreateTime).date_time().null())
                .col(ColumnDef::new(SysDictType::UpdateBy).string_len(64).default(""))
                .col(ColumnDef::new(SysDictType::UpdateTime).date_time().null())
                .col(ColumnDef::new(SysDictType::Remark).string_len(500).null())
                .col(ColumnDef::new(SysDictType::DelFlag).char_len(1).default("0"))
                .to_owned(),
        )
        .await
}

async fn create_sys_dict_data(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    manager
        .create_table(
            Table::create()
                .table(SysDictData::Table)
                .if_not_exists()
                .col(ColumnDef::new(SysDictData::DictCode).big_integer().not_null().auto_increment().primary_key())
                .col(ColumnDef::new(SysDictData::DictSort).integer().default(0))
                .col(ColumnDef::new(SysDictData::DictLabel).string_len(100).default(""))
                .col(ColumnDef::new(SysDictData::DictValue).string_len(100).default(""))
                .col(ColumnDef::new(SysDictData::DictType).string_len(100).default(""))
                .col(ColumnDef::new(SysDictData::CssClass).string_len(100).null())
                .col(ColumnDef::new(SysDictData::ListClass).string_len(100).null())
                .col(ColumnDef::new(SysDictData::IsDefault).char_len(1).default("N"))
                .col(ColumnDef::new(SysDictData::Status).char_len(1).default("0"))
                .col(ColumnDef::new(SysDictData::CreateBy).string_len(64).default(""))
                .col(ColumnDef::new(SysDictData::CreateTime).date_time().null())
                .col(ColumnDef::new(SysDictData::UpdateBy).string_len(64).default(""))
                .col(ColumnDef::new(SysDictData::UpdateTime).date_time().null())
                .col(ColumnDef::new(SysDictData::Remark).string_len(500).null())
                .col(ColumnDef::new(SysDictData::DelFlag).char_len(1).default("0"))
                .to_owned(),
        )
        .await
}

async fn create_sys_oper_log(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    manager
        .create_table(
            Table::create()
                .table(SysOperLog::Table)
                .if_not_exists()
                .col(ColumnDef::new(SysOperLog::OperId).big_integer().not_null().auto_increment().primary_key())
                .col(ColumnDef::new(SysOperLog::Title).string_len(50).default(""))
                .col(ColumnDef::new(SysOperLog::BusinessType).integer().default(0))
                .col(ColumnDef::new(SysOperLog::Method).string_len(100).default(""))
                .col(ColumnDef::new(SysOperLog::RequestMethod).string_len(10).default(""))
                .col(ColumnDef::new(SysOperLog::OperatorType).integer().default(0))
                .col(ColumnDef::new(SysOperLog::OperName).string_len(50).default(""))
                .col(ColumnDef::new(SysOperLog::DeptName).string_len(50).default(""))
                .col(ColumnDef::new(SysOperLog::OperUrl).string_len(255).default(""))
                .col(ColumnDef::new(SysOperLog::OperIp).string_len(128).default(""))
                .col(ColumnDef::new(SysOperLog::OperLocation).string_len(255).default(""))
                .col(ColumnDef::new(SysOperLog::OperParam).string_len(2000).default(""))
                .col(ColumnDef::new(SysOperLog::JsonResult).string_len(2000).default(""))
                .col(ColumnDef::new(SysOperLog::Status).integer().default(0))
                .col(ColumnDef::new(SysOperLog::ErrorMsg).string_len(2000).default(""))
                .col(ColumnDef::new(SysOperLog::OperTime).date_time().null())
                .col(ColumnDef::new(SysOperLog::CostTime).big_integer().default(0))
                .to_owned(),
        )
        .await
}

async fn create_sys_logininfor(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    manager
        .create_table(
            Table::create()
                .table(SysLogininfor::Table)
                .if_not_exists()
                .col(ColumnDef::new(SysLogininfor::InfoId).big_integer().not_null().auto_increment().primary_key())
                .col(ColumnDef::new(SysLogininfor::UserName).string_len(50).default(""))
                .col(ColumnDef::new(SysLogininfor::Ipaddr).string_len(128).default(""))
                .col(ColumnDef::new(SysLogininfor::LoginLocation).string_len(255).default(""))
                .col(ColumnDef::new(SysLogininfor::Browser).string_len(50).default(""))
                .col(ColumnDef::new(SysLogininfor::Os).string_len(50).default(""))
                .col(ColumnDef::new(SysLogininfor::Status).char_len(1).default("0"))
                .col(ColumnDef::new(SysLogininfor::Msg).string_len(255).default(""))
                .col(ColumnDef::new(SysLogininfor::LoginTime).date_time().null())
                .to_owned(),
        )
        .await
}

async fn create_sys_job(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    manager
        .create_table(
            Table::create()
                .table(SysJob::Table)
                .if_not_exists()
                .col(ColumnDef::new(SysJob::JobId).big_integer().not_null().auto_increment().primary_key())
                .col(ColumnDef::new(SysJob::JobName).string_len(64).not_null().default(""))
                .col(ColumnDef::new(SysJob::JobGroup).string_len(64).not_null().default("DEFAULT"))
                .col(ColumnDef::new(SysJob::InvokeTarget).string_len(500).not_null())
                .col(ColumnDef::new(SysJob::CronExpression).string_len(255).default(""))
                .col(ColumnDef::new(SysJob::MisfirePolicy).string_len(20).default("3"))
                .col(ColumnDef::new(SysJob::Concurrent).char_len(1).default("1"))
                .col(ColumnDef::new(SysJob::Status).char_len(1).default("0"))
                .col(ColumnDef::new(SysJob::CreateBy).string_len(64).default(""))
                .col(ColumnDef::new(SysJob::CreateTime).date_time().null())
                .col(ColumnDef::new(SysJob::UpdateBy).string_len(64).default(""))
                .col(ColumnDef::new(SysJob::UpdateTime).date_time().null())
                .col(ColumnDef::new(SysJob::Remark).string_len(500).default(""))
                .col(ColumnDef::new(SysJob::DelFlag).char_len(1).default("0"))
                .to_owned(),
        )
        .await
}

async fn create_sys_job_log(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    manager
        .create_table(
            Table::create()
                .table(SysJobLog::Table)
                .if_not_exists()
                .col(ColumnDef::new(SysJobLog::JobLogId).big_integer().not_null().auto_increment().primary_key())
                .col(ColumnDef::new(SysJobLog::JobName).string_len(64).not_null())
                .col(ColumnDef::new(SysJobLog::JobGroup).string_len(64).not_null())
                .col(ColumnDef::new(SysJobLog::InvokeTarget).string_len(500).not_null())
                .col(ColumnDef::new(SysJobLog::JobMessage).string_len(500).null())
                .col(ColumnDef::new(SysJobLog::Status).char_len(1).default("0"))
                .col(ColumnDef::new(SysJobLog::ExceptionInfo).string_len(2000).default(""))
                .col(ColumnDef::new(SysJobLog::CreateTime).date_time().null())
                .to_owned(),
        )
        .await
}

// ==================== 索引创建 ====================

async fn create_indexes(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    // sys_user 索引
    manager.create_index(
        Index::create()
            .name("idx_sys_user_dept")
            .table(SysUser::Table)
            .col(SysUser::DeptId)
            .to_owned(),
    ).await?;

    // sys_menu 索引
    manager.create_index(
        Index::create()
            .name("idx_sys_menu_parent")
            .table(SysMenu::Table)
            .col(SysMenu::ParentId)
            .to_owned(),
    ).await?;

    // sys_user_role 索引
    manager.create_index(
        Index::create()
            .name("idx_sys_user_role_role")
            .table(SysUserRole::Table)
            .col(SysUserRole::RoleId)
            .to_owned(),
    ).await?;

    // sys_role_menu 索引
    manager.create_index(
        Index::create()
            .name("idx_sys_role_menu_menu")
            .table(SysRoleMenu::Table)
            .col(SysRoleMenu::MenuId)
            .to_owned(),
    ).await?;

    // sys_dict_data 索引
    manager.create_index(
        Index::create()
            .name("idx_sys_dict_data_type")
            .table(SysDictData::Table)
            .col(SysDictData::DictType)
            .to_owned(),
    ).await?;

    // sys_oper_log 索引
    manager.create_index(
        Index::create()
            .name("idx_sys_oper_log_bt")
            .table(SysOperLog::Table)
            .col(SysOperLog::BusinessType)
            .to_owned(),
    ).await?;

    manager.create_index(
        Index::create()
            .name("idx_sys_oper_log_s")
            .table(SysOperLog::Table)
            .col(SysOperLog::Status)
            .to_owned(),
    ).await?;

    manager.create_index(
        Index::create()
            .name("idx_sys_oper_log_ot")
            .table(SysOperLog::Table)
            .col(SysOperLog::OperTime)
            .to_owned(),
    ).await?;

    // sys_logininfor 索引
    manager.create_index(
        Index::create()
            .name("idx_sys_logininfor_s")
            .table(SysLogininfor::Table)
            .col(SysLogininfor::Status)
            .to_owned(),
    ).await?;

    manager.create_index(
        Index::create()
            .name("idx_sys_logininfor_lt")
            .table(SysLogininfor::Table)
            .col(SysLogininfor::LoginTime)
            .to_owned(),
    ).await?;

    // sys_job 唯一索引（job_name + job_group）
    manager.create_index(
        Index::create()
            .name("uk_sys_job_name_group")
            .table(SysJob::Table)
            .col(SysJob::JobName)
            .col(SysJob::JobGroup)
            .unique()
            .to_owned(),
    ).await?;

    Ok(())
}

// ==================== 初始数据 ====================

async fn init_data(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    let db = manager.get_connection();

    // 1. 插入 admin 用户（密码: admin123 + stepby_admin 盐值 MD5）
    db.execute_unprepared(
        r#"INSERT INTO sys_user (user_id, dept_id, user_name, nick_name, user_type, email, phonenumber, sex, avatar, password, status, del_flag, create_by, create_time, remark)
           VALUES (1, 100, 'admin', '演示管理员', '00', 'admin@tzkj.net', '15888888888', '0', '', 'ba976d23f6d1012cfe81ceb960a1058c', '0', '0', 'admin', NOW(), '管理员')"#,
    ).await?;

    // 2. 插入 admin 角色
    db.execute_unprepared(
        r#"INSERT INTO sys_role (role_id, role_name, role_key, role_sort, data_scope, menu_check_strictly, dept_check_strictly, status, del_flag, create_by, create_time, remark)
           VALUES (1, '超级管理员', 'admin', 1, '1', 1, 1, '0', '0', 'admin', NOW(), '超级管理员')"#,
    ).await?;

    // 3. 关联 admin 用户与 admin 角色
    db.execute_unprepared(
        r#"INSERT INTO sys_user_role (user_id, role_id) VALUES (1, 1)"#,
    ).await?;

    // 4. 插入基础菜单（系统管理目录 + 系统监控目录）
    db.execute_unprepared(
        r#"INSERT INTO sys_menu (menu_id, menu_name, parent_id, order_num, path, component, query, route_name, is_frame, is_cache, menu_type, visible, status, perms, icon, create_by, create_time, remark, del_flag) VALUES
           (1, '系统管理', 0, 1, 'system', NULL, '', '', 1, 0, 'M', '0', '0', '', 'system', 'admin', NOW(), '', '0'),
           (2, '系统监控', 0, 2, 'monitor', NULL, '', '', 1, 0, 'M', '0', '0', '', 'monitor', 'admin', NOW(), '', '0'),
           (100, '用户管理', 1, 1, 'user', 'system/user/index', '', '', 1, 0, 'C', '0', '0', 'system:user:list', 'user', 'admin', NOW(), '', '0'),
           (101, '角色管理', 1, 2, 'role', 'system/role/index', '', '', 1, 0, 'C', '0', '0', 'system:role:list', 'peoples', 'admin', NOW(), '', '0'),
           (102, '菜单管理', 1, 3, 'menu', 'system/menu/index', '', '', 1, 0, 'C', '0', '0', 'system:menu:list', 'tree-table', 'admin', NOW(), '', '0'),
           (103, '字典管理', 1, 4, 'dict', 'system/dict/index', '', '', 1, 0, 'C', '0', '0', 'system:dict:list', 'dict', 'admin', NOW(), '', '0'),
           (104, '操作日志', 2, 1, 'operlog', 'monitor/operlog/index', '', '', 1, 0, 'C', '0', '0', 'monitor:operlog:list', 'form', 'admin', NOW(), '', '0'),
           (105, '登录日志', 2, 2, 'logininfor', 'monitor/logininfor/index', '', '', 1, 0, 'C', '0', '0', 'monitor:logininfor:list', 'logininfor', 'admin', NOW(), '', '0'),
           (106, '定时任务', 2, 3, 'job', 'monitor/job/index', '', '', 1, 0, 'C', '0', '0', 'monitor:job:list', 'job', 'admin', NOW(), '', '0')"#,
    ).await?;

    // 5. 关联 admin 角色与所有菜单
    db.execute_unprepared(
        r#"INSERT INTO sys_role_menu (role_id, menu_id) VALUES
           (1, 1), (1, 2), (1, 100), (1, 101), (1, 102), (1, 103), (1, 104), (1, 105), (1, 106)"#,
    ).await?;

    // 6. 插入内置字典类型
    db.execute_unprepared(
        r#"INSERT INTO sys_dict_type (dict_id, dict_name, dict_type, status, del_flag, create_by, create_time, remark) VALUES
           (1, '用户性别', 'sys_user_sex', '0', '0', 'admin', NOW(), '用户性别列表'),
           (2, '菜单状态', 'sys_show_hide', '0', '0', 'admin', NOW(), '菜单状态列表'),
           (3, '系统开关', 'sys_normal_disable', '0', '0', 'admin', NOW(), '系统开关列表'),
           (4, '任务状态', 'sys_job_status', '0', '0', 'admin', NOW(), '任务状态列表'),
           (5, '任务分组', 'sys_job_group', '0', '0', 'admin', NOW(), '任务分组列表'),
           (6, '系统是否', 'sys_yes_no', '0', '0', 'admin', NOW(), '系统是否列表'),
           (7, '通知类型', 'sys_notice_type', '0', '0', 'admin', NOW(), '通知类型列表'),
           (8, '通知状态', 'sys_notice_status', '0', '0', 'admin', NOW(), '通知状态列表'),
           (9, '操作类型', 'sys_oper_type', '0', '0', 'admin', NOW(), '操作类型列表'),
           (10, '系统状态', 'sys_common_status', '0', '0', 'admin', NOW(), '登录状态列表')"#,
    ).await?;

    // 7. 插入内置字典数据（精选常用项）
    db.execute_unprepared(
        r#"INSERT INTO sys_dict_data (dict_sort, dict_label, dict_value, dict_type, css_class, list_class, is_default, status, del_flag, create_by, create_time, remark) VALUES
           (1, '男', '0', 'sys_user_sex', '', 'info', 'Y', '0', '0', 'admin', NOW(), '性别男'),
           (2, '女', '1', 'sys_user_sex', '', 'danger', 'N', '0', '0', 'admin', NOW(), '性别女'),
           (3, '未知', '2', 'sys_user_sex', '', 'warning', 'N', '0', '0', 'admin', NOW(), '性别未知'),
           (1, '显示', '0', 'sys_show_hide', '', 'primary', 'Y', '0', '0', 'admin', NOW(), '显示菜单'),
           (2, '隐藏', '1', 'sys_show_hide', '', 'danger', 'N', '0', '0', 'admin', NOW(), '隐藏菜单'),
           (1, '正常', '0', 'sys_normal_disable', '', 'primary', 'Y', '0', '0', 'admin', NOW(), '正常状态'),
           (2, '停用', '1', 'sys_normal_disable', '', 'danger', 'N', '0', '0', 'admin', NOW(), '停用状态'),
           (1, '正常', '0', 'sys_job_status', '', 'primary', 'Y', '0', '0', 'admin', NOW(), '正常状态'),
           (2, '暂停', '1', 'sys_job_status', '', 'danger', 'N', '0', '0', 'admin', NOW(), '暂停状态'),
           (1, '默认', 'DEFAULT', 'sys_job_group', '', '', 'Y', '0', '0', 'admin', NOW(), '默认分组'),
           (1, '是', 'Y', 'sys_yes_no', '', 'primary', 'Y', '0', '0', 'admin', NOW(), '系统默认是'),
           (2, '否', 'N', 'sys_yes_no', '', 'danger', 'N', '0', '0', 'admin', NOW(), '系统默认否'),
           (1, '正常', '0', 'sys_common_status', '', 'primary', 'Y', '0', '0', 'admin', NOW(), '正常状态'),
           (2, '异常', '1', 'sys_common_status', '', 'danger', 'N', '0', '0', 'admin', NOW(), '异常状态')"#,
    ).await?;

    Ok(())
}
```

> **说明：**
> - `string_len(n)` 对应 `varchar(n)`
> - `char_len(n)` 对应 `char(n)`
> - `unique_key()` 在建表时创建唯一约束（内联）
> - `Index::create().unique()` 创建独立唯一索引
> - 初始数据使用 `execute_unprepared` 直接执行 SQL，避免参数绑定的复杂性
> - `NOW()` 由 MySQL 自动填充当前时间

---

## Task 14: 添加初始数据

> **已在 Task 13 的 `init_data()` 函数中完成，无需单独任务。**

初始数据包含：
- 1 条 admin 用户（user_id=1）
- 1 条 admin 角色（role_id=1）
- 1 条用户角色关联
- 9 条基础菜单（2 个目录 + 7 个菜单）
- 9 条角色菜单关联
- 10 条字典类型
- 14 条字典数据

---

## Task 15: 编译验证 + 自查

### 15.1 编译验证命令

```bash
# 主 crate 编译
cargo check

# migration 子 crate 编译
cargo check -p migration

# 全量编译
cargo build

# 单元测试
cargo test
```

### 15.2 自查清单

执行完所有任务后，按 `docs/db-checklist.md` 逐项核对：

1. **全局规则合规性**：无 salvo/rbatis、单一 ORM、分层单向依赖
2. **实体文件完整性**：11 个实体文件全部存在
3. **迁移文件完整性**：建表 + 索引 + 初始数据
4. **字段对齐**：100% 覆盖本项目前端字段
5. **编译通过**：主 crate + migration 子 crate 零 error
6. **测试通过**：含时间自动维护的单元测试

### 15.3 验收标准

- `cargo check` 成功，无 error
- `cargo check -p migration` 成功，无 error
- `cargo test` 通过
- `cargo run -p migration` 可执行（需 MySQL 可用）
- 数据库中 11 张表全部创建成功
- 初始数据正确插入（admin 用户 + admin 角色 + 菜单 + 字典）
