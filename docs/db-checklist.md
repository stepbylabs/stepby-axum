# 数据库表结构设计 验收清单（db-checklist.md）

> **阶段：** 第二阶段「系统核心数据库表结构设计」
> **对应规范：** `docs/db-spec.md`
> **对应任务：** `docs/db-tasks.md`
> **规则基线：** `axum-backend/.trae/rules/project-rules.md`
> **用途：** 执行完所有任务后，逐项核对验收。任一项未通过视为阶段未完成。

---

## 1. 全局规则合规性校验

### 1.1 绝对禁令核对

- [ ] `src/entity/` 下 **无 salvo 依赖**（搜索 `salvo` 无结果）
- [ ] `src/entity/` 下 **无 rbatis 依赖**（搜索 `rbatis` 无结果）
- [ ] 实体定义 **无 `#[handler]` 宏** 使用
- [ ] 实体定义 **无 Depot 容器** 使用
- [ ] **单一 ORM**：全程使用 SeaORM `#[derive(DeriveEntityModel)]`，无其他 ORM
- [ ] **未直接复制** ref-axum-admin 的 codegen 显式展开风格（使用宏写法）
- [ ] **未修改**任何 `ref-` 前缀的参考项目源码
- [ ] migration 子 crate **独立于主 crate**（不依赖 axum-backend）

### 1.2 分层依赖校验

- [ ] Entity 层（`src/entity/`）仅定义 Model/ActiveModel/Relation，无业务逻辑
- [ ] Entity 层 **无 Axum/Web 类型**（搜索 `axum::` 在 entity/ 下无结果）
- [ ] Entity 层 **无 Repository/Service 调用**
- [ ] Relation 枚举留空（本阶段不定义静态关联）
- [ ] 时间自动维护通过 `ActiveModelBehavior` 实现（非全局静态）

### 1.3 输出规范校验

- [ ] 所有实体文件均在 `src/entity/` 目录内
- [ ] 代码使用蛇形命名法（snake_case）
- [ ] 核心逻辑添加必要注释（文件级 `//!` 注释）
- [ ] 错误处理完善（实体层无 `unwrap()` 暴露）

---

## 2. 实体文件完整性校验

### 2.1 实体文件清单

- [ ] `src/entity/sys_user.rs` 存在且定义完整（19 字段）
- [ ] `src/entity/sys_role.rs` 存在且定义完整（14 字段）
- [ ] `src/entity/sys_menu.rs` 存在且定义完整（21 字段，含 route_name）
- [ ] `src/entity/sys_user_role.rs` 存在且定义完整（2 字段，复合主键）
- [ ] `src/entity/sys_role_menu.rs` 存在且定义完整（2 字段，复合主键）
- [ ] `src/entity/sys_dict_type.rs` 存在且定义完整（10 字段，含 del_flag）
- [ ] `src/entity/sys_dict_data.rs` 存在且定义完整（15 字段，含 del_flag）
- [ ] `src/entity/sys_oper_log.rs` 存在且定义完整（17 字段）
- [ ] `src/entity/sys_logininfor.rs` 存在且定义完整（9 字段）
- [ ] `src/entity/sys_job.rs` 存在且定义完整（14 字段，含 del_flag）
- [ ] `src/entity/sys_job_log.rs` 存在且定义完整（8 字段）

### 2.2 模块声明文件

- [ ] `src/entity/mod.rs` 声明全部 11 个实体模块
- [ ] `src/entity/mod.rs` 声明 `prelude` 模块
- [ ] `src/entity/prelude.rs` 重导出全部 11 个 Entity

### 2.3 禁止存在的文件

- [ ] 无业务模块文件（`src/service/sys_user.rs` 等业务阶段才创建）
- [ ] 无 `ref-` 项目被修改的痕迹

---

## 3. 表结构字段校验

### 3.1 sys_user（19 字段）

- [ ] `user_id: i64`（主键，auto_increment）
- [ ] `dept_id: Option<i64>`
- [ ] `user_name: String`（唯一约束）
- [ ] `nick_name: String`
- [ ] `user_type: Option<String>`
- [ ] `email: Option<String>`
- [ ] `phonenumber: Option<String>`
- [ ] `sex: Option<String>`
- [ ] `avatar: Option<String>`
- [ ] `password: Option<String>`
- [ ] `status: Option<String>`（默认 '0'）
- [ ] `del_flag: Option<String>`（默认 '0'）
- [ ] `login_ip: Option<String>`
- [ ] `login_date: Option<NaiveDateTime>`
- [ ] `create_by: Option<String>`
- [ ] `create_time: Option<NaiveDateTime>`
- [ ] `update_by: Option<String>`
- [ ] `update_time: Option<NaiveDateTime>`
- [ ] `remark: Option<String>`

### 3.2 sys_role（14 字段）

- [ ] `role_id: i64`（主键，auto_increment）
- [ ] `role_name: String`
- [ ] `role_key: String`（唯一约束）
- [ ] `role_sort: i32`
- [ ] `data_scope: Option<String>`（默认 '1'）
- [ ] `menu_check_strictly: Option<bool>`
- [ ] `dept_check_strictly: Option<bool>`
- [ ] `status: String`
- [ ] `del_flag: Option<String>`（默认 '0'）
- [ ] `create_by` / `create_time` / `update_by` / `update_time` / `remark`

### 3.3 sys_menu（21 字段，含新增字段）

- [ ] `menu_id: i64`（主键，auto_increment）
- [ ] `menu_name: String`
- [ ] `parent_id: Option<i64>`（默认 0）
- [ ] `order_num: Option<i32>`
- [ ] `path` / `component` / `query` / `perms` / `icon`
- [ ] **`route_name: Option<String>`**（新增字段，对齐前端 routeName）
- [ ] `is_frame: Option<i32>` / `is_cache: Option<i32>`
- [ ] `menu_type` / `visible` / `status`
- [ ] `create_by` / `create_time` / `update_by` / `update_time` / `remark`
- [ ] **`del_flag: Option<String>`**（新增字段，统一软删除）

### 3.4 sys_user_role（2 字段，复合主键）

- [ ] `user_id: i64`（复合主键部分）
- [ ] `role_id: i64`（复合主键部分）
- [ ] 两个 `#[sea_orm(primary_key)]` 注解

### 3.5 sys_role_menu（2 字段，复合主键）

- [ ] `role_id: i64`（复合主键部分）
- [ ] `menu_id: i64`（复合主键部分）
- [ ] 两个 `#[sea_orm(primary_key)]` 注解

### 3.6 sys_dict_type（10 字段，含新增 del_flag）

- [ ] `dict_id: i64`（主键）
- [ ] `dict_name` / `dict_type`（唯一约束） / `status`
- [ ] `create_by` / `create_time` / `update_by` / `update_time` / `remark`
- [ ] **`del_flag: Option<String>`**（新增字段，统一软删除）

### 3.7 sys_dict_data（15 字段，含新增 del_flag）

- [ ] `dict_code: i64`（主键）
- [ ] `dict_sort: Option<i32>`（类型为 i32，非 i8）
- [ ] `dict_label` / `dict_value` / `dict_type`
- [ ] `css_class` / `list_class` / `is_default` / `status`
- [ ] `create_by` / `create_time` / `update_by` / `update_time` / `remark`
- [ ] **`del_flag: Option<String>`**（新增字段，统一软删除）

### 3.8 sys_oper_log（17 字段）

- [ ] `oper_id: i64`（主键）
- [ ] `title` / `business_type: Option<i32>` / `method` / `request_method`
- [ ] `operator_type: Option<i32>` / `oper_name` / `dept_name`
- [ ] `oper_url` / `oper_ip` / `oper_location`
- [ ] `oper_param` / `json_result` / `status: Option<i32>`
- [ ] `error_msg` / `oper_time: Option<NaiveDateTime>` / `cost_time: Option<i64>`

### 3.9 sys_logininfor（9 字段）

- [ ] `info_id: i64`（主键）
- [ ] `user_name` / **`ipaddr`**（全小写，非 ip_addr）/ `login_location`
- [ ] `browser` / `os` / `status` / `msg`
- [ ] `login_time: Option<NaiveDateTime>`

### 3.10 sys_job（14 字段，主键改为单主键 + 含 del_flag）

- [ ] `job_id: i64`（主键，auto_increment，**单主键**非复合主键）
- [ ] `job_name: String` / `job_group: String` / `invoke_target: String`
- [ ] `cron_expression` / `misfire_policy` / `concurrent` / `status`
- [ ] `create_by` / `create_time` / `update_by` / `update_time` / `remark`
- [ ] **`del_flag: Option<String>`**（新增字段，统一软删除）

### 3.11 sys_job_log（8 字段）

- [ ] `job_log_id: i64`（主键）
- [ ] `job_name: String` / `job_group: String` / `invoke_target: String`
- [ ] `job_message` / `status` / `exception_info`
- [ ] `create_time: Option<NaiveDateTime>`

---

## 4. 索引与约束校验

### 4.1 主键约束

- [ ] sys_user: `PRIMARY KEY (user_id)`
- [ ] sys_role: `PRIMARY KEY (role_id)`
- [ ] sys_menu: `PRIMARY KEY (menu_id)`
- [ ] sys_user_role: `PRIMARY KEY (user_id, role_id)`（复合主键）
- [ ] sys_role_menu: `PRIMARY KEY (role_id, menu_id)`（复合主键）
- [ ] sys_dict_type: `PRIMARY KEY (dict_id)`
- [ ] sys_dict_data: `PRIMARY KEY (dict_code)`
- [ ] sys_oper_log: `PRIMARY KEY (oper_id)`
- [ ] sys_logininfor: `PRIMARY KEY (info_id)`
- [ ] sys_job: `PRIMARY KEY (job_id)`（单主键，非复合主键）
- [ ] sys_job_log: `PRIMARY KEY (job_log_id)`

### 4.2 唯一索引

- [ ] `uk_sys_user_name (user_name)` —— sys_user.user_name 唯一
- [ ] `uk_sys_role_key (role_key)` —— sys_role.role_key 唯一
- [ ] `uk_sys_dict_type (dict_type)` —— sys_dict_type.dict_type 唯一
- [ ] `uk_sys_job_name_group (job_name, job_group)` —— sys_job 任务名组内唯一

### 4.3 普通索引

- [ ] `idx_sys_user_dept (dept_id)` —— sys_user 按部门查询
- [ ] `idx_sys_menu_parent (parent_id)` —— sys_menu 按父节点查询
- [ ] `idx_sys_user_role_role (role_id)` —— sys_user_role 按角色反查
- [ ] `idx_sys_role_menu_menu (menu_id)` —— sys_role_menu 按菜单反查
- [ ] `idx_sys_dict_data_type (dict_type)` —— sys_dict_data 按类型查询
- [ ] `idx_sys_oper_log_bt (business_type)` —— sys_oper_log 按业务类型
- [ ] `idx_sys_oper_log_s (status)` —— sys_oper_log 按状态
- [ ] `idx_sys_oper_log_ot (oper_time)` —— sys_oper_log 按操作时间
- [ ] `idx_sys_logininfor_s (status)` —— sys_logininfor 按状态
- [ ] `idx_sys_logininfor_lt (login_time)` —— sys_logininfor 按登录时间

---

## 5. 软删除与时间维护校验

### 5.1 软删除字段（6 张业务表）

- [ ] sys_user 含 `del_flag` 字段，默认值 '0'
- [ ] sys_role 含 `del_flag` 字段，默认值 '0'
- [ ] sys_menu 含 `del_flag` 字段，默认值 '0'
- [ ] sys_dict_type 含 `del_flag` 字段，默认值 '0'
- [ ] sys_dict_data 含 `del_flag` 字段，默认值 '0'
- [ ] sys_job 含 `del_flag` 字段，默认值 '0'

### 5.2 无软删除字段（5 张表）

- [ ] sys_user_role 无 `del_flag`（关联表物理删除）
- [ ] sys_role_menu 无 `del_flag`（关联表物理删除）
- [ ] sys_oper_log 无 `del_flag`（日志表物理删除）
- [ ] sys_logininfor 无 `del_flag`（日志表物理删除）
- [ ] sys_job_log 无 `del_flag`（日志表物理删除）

### 5.3 时间自动维护（ActiveModelBehavior）

- [ ] sys_user 实现 `before_save`，insert 时填充 create_time + update_time
- [ ] sys_role 实现 `before_save`
- [ ] sys_menu 实现 `before_save`
- [ ] sys_dict_type 实现 `before_save`
- [ ] sys_dict_data 实现 `before_save`
- [ ] sys_job 实现 `before_save`
- [ ] sys_user_role **未实现** `before_save`（无时间字段）
- [ ] sys_role_menu **未实现** `before_save`（无时间字段）
- [ ] sys_oper_log **未实现** `before_save`（日志表，oper_time 由业务层设置）
- [ ] sys_logininfor **未实现** `before_save`（日志表，login_time 由业务层设置）
- [ ] sys_job_log **未实现** `before_save`（日志表，create_time 由业务层设置）

---

## 6. 前端字段对齐校验（本项目前端）

### 6.1 sys_user 字段对齐

- [ ] `userId` → `user_id`（i64）
- [ ] `deptId` → `dept_id`（Option<i64>）
- [ ] `userName` → `user_name`（String）
- [ ] `nickName` → `nick_name`（String）
- [ ] `email` / `phonenumber` / `sex` / `avatar` / `password` / `status` / `remark` 对齐
- [ ] `createBy` → `create_by` / `createTime` → `create_time` / `updateBy` → `update_by` / `updateTime` → `update_time`

### 6.2 sys_role 字段对齐

- [ ] `roleId` → `role_id` / `roleName` → `role_name` / `roleKey` → `role_key` / `roleSort` → `role_sort`
- [ ] `dataScope` → `data_scope`（取值 '1'-'5'）
- [ ] `menuCheckStrictly` → `menu_check_strictly`（前端 boolean，后端 Option<bool>）
- [ ] `deptCheckStrictly` → `dept_check_strictly`（前端 boolean，后端 Option<bool>）

### 6.3 sys_menu 字段对齐

- [ ] `menuId` → `menu_id` / `parentId` → `parent_id` / `menuName` → `menu_name` / `orderNum` → `order_num`
- [ ] `isFrame` → `is_frame` / `isCache` → `is_cache` / `menuType` → `menu_type`
- [ ] **`routeName` → `route_name`**（新增字段，前端有定义）
- [ ] `perms` / `icon` / `visible` / `status` / `component` / `query` / `path` 对齐

### 6.4 sys_dict_data 字段对齐

- [ ] `dictCode` → `dict_code` / `dictLabel` → `dict_label` / `dictValue` → `dict_value` / `dictType` → `dict_type`
- [ ] `cssClass` → `css_class` / `listClass` → `list_class` / `isDefault` → `is_default` / `dictSort` → `dict_sort`

### 6.5 sys_oper_log 字段对齐

- [ ] `operId` → `oper_id` / `businessType` → `business_type` / `requestMethod` → `request_method`
- [ ] `operatorType` → `operator_type` / `operName` → `oper_name` / `operUrl` → `oper_url`
- [ ] `operIp` → `oper_ip` / `operLocation` → `oper_location` / `operParam` → `oper_param`
- [ ] `jsonResult` → `json_result` / `errorMsg` → `error_msg` / `operTime` → `oper_time` / `costTime` → `cost_time`

### 6.6 sys_logininfor 字段对齐（特例）

- [ ] `infoId` → `info_id` / `userName` → `user_name`
- [ ] **`ipaddr` → `ipaddr`**（全小写，**不转换**，特例）
- [ ] `loginLocation` → `login_location` / `loginTime` → `login_time`

### 6.7 sys_job / sys_job_log 字段对齐

- [ ] `jobId` → `job_id` / `jobName` → `job_name` / `jobGroup` → `job_group`
- [ ] `invokeTarget` → `invoke_target` / `cronExpression` → `cron_expression`
- [ ] `misfirePolicy` → `misfire_policy`
- [ ] `jobLogId` → `job_log_id` / `jobMessage` → `job_message` / `exceptionInfo` → `exception_info`

---

## 7. 与 ref-salvo-admin 差异校验

### 7.1 新增字段

- [ ] sys_menu 新增 `route_name` 字段（对齐前端 routeName）
- [ ] sys_menu 新增 `del_flag` 字段（统一软删除）
- [ ] sys_dict_type 新增 `del_flag` 字段（统一软删除）
- [ ] sys_dict_data 新增 `del_flag` 字段（统一软删除）
- [ ] sys_job 新增 `del_flag` 字段（统一软删除）

### 7.2 结构性变更

- [ ] sys_job 主键从复合主键 `(job_id, job_name, job_group)` 改为单主键 `job_id`
- [ ] sys_job 新增唯一索引 `uk_sys_job_name_group (job_name, job_group)`
- [ ] sys_dict_data.dict_sort 类型为 `i32`（非 ref-axum-admin 的 `i8`）

### 7.3 新增索引（ref-salvo-admin 未定义）

- [ ] sys_user: `uk_sys_user_name` + `idx_sys_user_dept`
- [ ] sys_role: `uk_sys_role_key`
- [ ] sys_menu: `idx_sys_menu_parent`
- [ ] sys_user_role: `idx_sys_user_role_role`
- [ ] sys_role_menu: `idx_sys_role_menu_menu`
- [ ] sys_dict_data: `idx_sys_dict_data_type`

### 7.4 兼容性保证

- [ ] 所有表名与 ref-salvo-admin 完全一致
- [ ] 所有核心字段名与 ref-salvo-admin 完全一致
- [ ] 可直接导入 ref-salvo-admin 的 `ry_20230223.sql` 数据（新增字段有默认值，向后兼容）
- [ ] admin 用户密码 `bfb6b8dd9b268e241c82a257e235e550`（`admin123` + `yebot_admin` 盐值 MD5，不兼容 ref-salvo-admin 旧密码）

---

## 8. migration 子 crate 校验

### 8.1 迁移文件

- [ ] `migration/src/m20250711_000001_init.rs` 已填充完整建表语句
- [ ] `MigrationName` trait 实现（返回 "m20250711_000001_init"）
- [ ] `MigrationTrait::up()` 创建 11 张表 + 索引 + 初始数据
- [ ] `MigrationTrait::down()` 按反序删除 11 张表

### 8.2 建表顺序（依赖关系）

- [ ] sys_user → sys_role → sys_menu → sys_user_role → sys_role_menu
- [ ] sys_dict_type → sys_dict_data
- [ ] sys_oper_log → sys_logininfor → sys_job → sys_job_log

### 8.3 初始数据

- [ ] 1 条 admin 用户（user_id=1，密码 MD5 加盐）
- [ ] 1 条 admin 角色（role_id=1，role_key="admin"）
- [ ] 1 条用户角色关联（user_id=1, role_id=1）
- [ ] 9 条基础菜单（2 目录 + 7 菜单）
- [ ] 9 条角色菜单关联
- [ ] 10 条字典类型
- [ ] 14 条字典数据

### 8.4 编译与运行

- [ ] `cargo check -p migration` 成功，无 error
- [ ] `cargo build -p migration` 成功
- [ ] `cargo run -p migration` 可执行（需 MySQL 可用）
- [ ] 数据库中 11 张表全部创建成功
- [ ] `seaql_migrations` 表记录迁移状态

---

## 9. 编译与测试校验

### 9.1 编译

- [ ] `cargo check` 成功，无 error（主 crate）
- [ ] `cargo check -p migration` 成功，无 error
- [ ] `cargo build` 成功
- [ ] 无 unused dependency 警告

### 9.2 单元测试

- [ ] `cargo test` 成功
- [ ] 第一阶段的 `test_encrypt_and_verify` 仍通过

### 9.3 数据库验证（需 MySQL 可用）

- [ ] `cargo run -p migration` 输出 "迁移完成"
- [ ] `SELECT COUNT(*) FROM sys_user` 返回 1（admin 用户）
- [ ] `SELECT COUNT(*) FROM sys_role` 返回 1（admin 角色）
- [ ] `SELECT COUNT(*) FROM sys_menu` 返回 9（基础菜单）
- [ ] `SELECT COUNT(*) FROM sys_dict_type` 返回 10（字典类型）
- [ ] `SELECT COUNT(*) FROM sys_dict_data` 返回 14（字典数据）
- [ ] `SHOW INDEX FROM sys_user` 包含 uk_sys_user_name 和 idx_sys_user_dept
- [ ] `SHOW INDEX FROM sys_job` 包含 uk_sys_job_name_group

---

## 10. 自查结果模板

执行完所有任务后，填写以下自查结果：

```
✅ 自查结果

全局规则合规性：
- 无 salvo/rbatis 依赖：✓
- 单一 ORM（SeaORM）：✓
- Entity 层无 Web 类型：✓
- 未复制 ref-axum-admin codegen 风格（使用宏写法）：✓
- 未修改 ref- 项目：✓

实体文件完整性：
- 11 个实体文件全部存在：✓
- mod.rs + prelude.rs 声明完整：✓
- 无禁止文件：✓

表结构字段：
- sys_user（19 字段）：✓
- sys_role（14 字段）：✓
- sys_menu（21 字段，含 route_name + del_flag）：✓
- sys_user_role（2 字段，复合主键）：✓
- sys_role_menu（2 字段，复合主键）：✓
- sys_dict_type（10 字段，含 del_flag）：✓
- sys_dict_data（15 字段，含 del_flag）：✓
- sys_oper_log（17 字段）：✓
- sys_logininfor（9 字段，ipaddr 全小写）：✓
- sys_job（14 字段，单主键 + del_flag）：✓
- sys_job_log（8 字段）：✓

索引与约束：
- 11 个主键全部定义：✓
- 4 个唯一索引全部定义：✓
- 10 个普通索引全部定义：✓

软删除与时间维护：
- 6 张业务表含 del_flag（默认 '0'）：✓
- 5 张表无 del_flag（关联表 + 日志表）：✓
- 6 张业务表实现 before_save 时间自动维护：✓
- 5 张表不实现 before_save（关联表 + 日志表）：✓

前端字段对齐：
- sys_user 字段对齐：✓
- sys_role 字段对齐（含 boolean 类型）：✓
- sys_menu 字段对齐（含 route_name 新增）：✓
- sys_dict_data 字段对齐：✓
- sys_oper_log 字段对齐：✓
- sys_logininfor 字段对齐（ipaddr 特例）：✓
- sys_job / sys_job_log 字段对齐：✓

与 ref-salvo-admin 差异：
- sys_menu 新增 route_name + del_flag：✓
- sys_dict_type / sys_dict_data 新增 del_flag：✓
- sys_job 新增 del_flag + 主键改为单主键 + 唯一索引：✓
- 6 个新增索引：✓
- 向后兼容（新增字段有默认值）：✓

migration 子 crate：
- 11 张表建表语句完整：✓
- 索引创建语句完整：✓
- 初始数据完整（admin + 角色 + 菜单 + 字典）：✓
- down 方法按反序删表：✓
- 独立编译运行：✓

编译运行：
- cargo check 成功：✓
- cargo check -p migration 成功：✓
- cargo test 通过：✓
- cargo run -p migration 可执行：✓
- 11 张表创建成功：✓
- 初始数据正确插入：✓

违规点：无
风险点：无
```

---

## 11. 阶段完成判定

**全部以下条件满足时，本阶段视为完成：**

1. 上述所有 `- [ ]` 项全部勾选为 `- [x]`
2. `cargo check` 零 error（主 crate + migration 子 crate）
3. `cargo test` 单元测试通过
4. `cargo run -p migration` 可执行迁移（需 MySQL 可用）
5. 数据库中 11 张表全部创建成功
6. 初始数据正确插入（admin 用户 + admin 角色 + 菜单 + 字典）
7. 所有索引和约束正确创建
8. 6 张业务表实现时间自动维护（`ActiveModelBehavior::before_save`）
9. 自查结果无违规点、无风险点
10. 所有代码已提交到版本库
