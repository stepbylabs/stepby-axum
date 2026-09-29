# 数据库表结构设计文档（db-spec.md）

> **阶段：** 第二阶段「系统核心数据库表结构设计」
> **项目：** axum-backend（纯 Axum 0.8 + SeaORM 1.1 生产级后端服务）
> **规则基线：** `backend-axum/.trae/rules/project-rules.md`（全程永久生效）
> **开发优先原则：** 接口契约对齐 frontend-vue 前端调用规范 ＞ 架构规范遵循 Axum 官方最佳实践 ＞ 同栈细节遵循 Axum + SeaORM 原生惯例

---

## 1. 概述与目标

### 1.1 本阶段目标

基于第一阶段已搭建的工程脚手架，设计并实现系统核心数据库表结构，完成以下交付：

1. **11 张核心表**的完整字段定义（含主键、索引、唯一约束、默认值、非空约束）
2. **统一软删除**机制（`del_flag` 字段，'0'存在 / '2'删除）
3. **创建/更新时间自动维护**（通过 SeaORM `ActiveModelBehavior` trait）
4. **SeaORM 实体层**完整实现（`src/entity/` 下 11 个实体文件）
5. **数据库迁移脚本**（填充 `m20250711_000001_init.rs` 建表 + 索引 + 初始数据）
6. 字段 **100% 覆盖**本项目前端 TypeScript 类型定义

### 1.2 表清单

| 分类 | 表名 | 中文注释 | 主键类型 | 软删除 |
|------|------|----------|----------|--------|
| 核心 | `sys_user` | 用户信息表 | 单主键 `user_id` | ✓ del_flag |
| 核心 | `sys_role` | 角色信息表 | 单主键 `role_id` | ✓ del_flag |
| 核心 | `sys_menu` | 菜单权限表 | 单主键 `menu_id` | ✓ del_flag |
| 核心 | `sys_user_role` | 用户角色关联表 | 复合主键 `(user_id, role_id)` | ✗ |
| 核心 | `sys_role_menu` | 角色菜单关联表 | 复合主键 `(role_id, menu_id)` | ✗ |
| 配套 | `sys_dict_type` | 字典类型表 | 单主键 `dict_id` | ✓ del_flag |
| 配套 | `sys_dict_data` | 字典数据表 | 单主键 `dict_code` | ✓ del_flag |
| 配套 | `sys_oper_log` | 操作日志表 | 单主键 `oper_id` | ✗ |
| 配套 | `sys_logininfor` | 系统访问记录（登录日志） | 单主键 `info_id` | ✗ |
| 配套 | `sys_job` | 定时任务调度表 | 单主键 `job_id` | ✓ del_flag |
| 配套 | `sys_job_log` | 定时任务调度日志表 | 单主键 `job_log_id` | ✗ |

> **表名说明：** 登录日志表使用 `sys_logininfor`（非 `sys_login_log`），对齐本项目前端 `SysLogininfor` 类型定义与既有 SQL 脚本。

### 1.3 非目标（本阶段不实现）

- 业务接口实现（CRUD Handler/Service/Repository，留待第三阶段）
- 部门表 `sys_dept`、岗位表 `sys_post`、配置表 `sys_config`、通知表 `sys_notice`（留待后续阶段）
- 数据权限过滤逻辑（`data_scope` 字段仅定义，过滤逻辑在业务阶段实现）
- Quartz 调度框架集成（`QRTZ_*` 系列表不在本阶段范围）

---

## 2. 设计原则与决策

### 2.1 命名规范

| 维度 | 规范 | 示例 | 说明 |
|------|------|------|------|
| 表名 | snake_case，`sys_` 前缀 | `sys_user` | 对齐既有设计 |
| 列名 | snake_case | `user_id`、`create_time` | 对齐既有 SQL 脚本 |
| 主键名 | `<表名缩写>_id` 或语义化 | `user_id`、`dict_code` | 对齐既有惯例 |
| 索引名 | `idx_<表名>_<列缩写>` | `idx_sys_oper_log_bt` | 对齐既有设计 |
| 唯一索引 | `uk_<表名>_<列缩写>` | `uk_sys_user_name` | 本项目统一命名 |
| 外键 | 不使用外键约束 | - | 对齐既有设计，关联靠应用层维护 |

> **前端字段对齐：** 前端 TypeScript 使用 camelCase（`userId`、`createTime`），后端数据库使用 snake_case（`user_id`、`create_time`），通过 SeaORM 实体的 `#[serde(rename_all = "camelCase")]` 自动转换。

### 2.2 类型映射规范

| MySQL 类型 | SeaORM ColumnType | Rust 类型 | 用途 |
|-----------|-------------------|-----------|------|
| `bigint` | `BigInteger` | `i64` | 主键、外键、计数字段 |
| `int` | `Integer` | `i32` | 排序、业务类型枚举 |
| `tinyint(1)` | `TinyInteger` | `i8` | 布尔型（menu_check_strictly 等） |
| `char(1)` | `Char(Some(1))` | `String` | 状态标志位（'0'/'1'/'2'） |
| `varchar(n)` | `String(StringLen::N(n))` | `String` | 名称、路径等定长字符串 |
| `text` | `Text` | `String` | 长文本（error_msg、exception_info） |
| `datetime` | `DateTime` | `chrono::NaiveDateTime` | 时间字段 |

> **说明：** `char(1)` 类型在 Rust 侧统一用 `String` 表示（SeaORM 不支持 `char` 原生映射），通过应用层校验保证取值范围。

### 2.3 软删除设计决策

**决策：** 使用 `del_flag char(1) DEFAULT '0'` 字段实现软删除。

| 取值 | 含义 | 说明 |
|------|------|------|
| `'0'` | 存在 | 正常数据 |
| `'2'` | 已删除 | 软删除标记 |

**适用范围：**
- **使用软删除的表（6 张）：** `sys_user`、`sys_role`、`sys_menu`、`sys_dict_type`、`sys_dict_data`、`sys_job`
- **不使用软删除的表（5 张）：** `sys_user_role`、`sys_role_menu`（关联表，物理删除）、`sys_oper_log`、`sys_logininfor`、`sys_job_log`（日志表，物理删除/定期清理）

**实现方式：**
- 查询层：所有查询自动过滤 `del_flag = '0'`（通过 Repository 层封装）
- 删除层：`update set del_flag = '2'` 实现软删除
- 不在 SeaORM 实体层做全局过滤（避免复杂度），由 Repository 层显式处理

> **软删除实现说明：** 常见做法使用 `deleted_at: Option<DateTime>` 实现软删除，本项目改用 `del_flag char(1)` 字段，保持与既有数据库结构兼容。

### 2.4 时间自动维护设计决策

**决策：** 通过 SeaORM `ActiveModelBehavior` trait 的 `before_save` / `before_update` 钩子自动填充时间字段。

**实现方式：** 在 `src/entity/` 下创建通用行为模块，为每个含时间字段的实体实现 `ActiveModelBehavior`：

```rust
// 示例：sys_user 的 ActiveModelBehavior
impl ActiveModelBehavior for ActiveModel {
    fn before_save(mut self, _db: &DatabaseConnection, insert: bool) -> impl Future<Output = Result<Self, DbErr>> + Send {
        let now = Local::now().naive_local();
        if insert {
            self.create_time = Set(Some(now));
        }
        self.update_time = Set(Some(now));
        async { Ok(self) }
    }
}
```

**时间字段约定：**
- `create_time`：插入时自动填充，更新时不修改
- `update_time`：插入和更新时都自动填充
- 日志表的 `oper_time`、`login_time` 由业务层显式设置（非自动维护）
- `sys_job_log` 仅含 `create_time`，由业务层设置

> **注意：** `ActiveModelBehavior` 的 `before_save` 第二个参数 `insert: bool` 在 SeaORM 1.1 中可用，用于区分插入和更新操作。

### 2.5 审计字段设计

所有业务表统一包含审计字段（按既有设计）：

| 字段 | 类型 | 说明 |
|------|------|------|
| `create_by` | `varchar(64) DEFAULT ''` | 创建者账号 |
| `update_by` | `varchar(64) DEFAULT ''` | 更新者账号 |

> **说明：** `create_by` / `update_by` 由业务层从 JWT Claims 中提取 `username` 后显式设置，不在 `ActiveModelBehavior` 中自动填充（因为实体层无法访问请求上下文）。

---

## 3. 通用字段设计

### 3.1 业务表通用字段（8 字段）

以下 8 个字段出现在所有业务表（非日志表、非关联表）中：

```sql
create_by     varchar(64)  DEFAULT ''    COMMENT '创建者',
create_time   datetime     DEFAULT NULL  COMMENT '创建时间',
update_by     varchar(64)  DEFAULT ''    COMMENT '更新者',
update_time   datetime     DEFAULT NULL  COMMENT '更新时间',
remark        varchar(500) DEFAULT NULL  COMMENT '备注',
del_flag      char(1)      DEFAULT '0'   COMMENT '删除标志（0存在 2删除）',  -- 仅 6 张业务表
status        char(1)      DEFAULT '0'   COMMENT '状态（0正常 1停用）',     -- 除 sys_user_role/sys_role_menu 外
```

### 3.2 日志表通用字段

日志表（`sys_oper_log`、`sys_logininfor`、`sys_job_log`）不含审计字段和软删除字段，仅含业务时间字段：

| 表 | 时间字段 | 说明 |
|----|----------|------|
| `sys_oper_log` | `oper_time` | 操作时间，业务层设置 |
| `sys_logininfor` | `login_time` | 登录时间，业务层设置 |
| `sys_job_log` | `create_time` | 创建时间，业务层设置 |

### 3.3 关联表设计

关联表（`sys_user_role`、`sys_role_menu`）为纯关联表：
- 仅含两个外键字段
- 使用复合主键
- 无时间字段、无审计字段、无软删除
- 物理删除

---

## 4. 表结构详细设计

### 4.1 sys_user（用户信息表）

**用途：** 存储系统用户账号信息
**主键：** `user_id bigint AUTO_INCREMENT`
**软删除：** `del_flag`
**自增起始值：** 100（预留 1-99 为系统内置用户）

| 序号 | 字段名 | 类型 | 可空 | 默认值 | 注释 |
|------|--------|------|------|--------|------|
| 1 | `user_id` | bigint | NOT NULL | AUTO_INCREMENT | 用户ID（主键） |
| 2 | `dept_id` | bigint | NULL | NULL | 部门ID |
| 3 | `user_name` | varchar(30) | NOT NULL | - | 用户账号（唯一） |
| 4 | `nick_name` | varchar(30) | NOT NULL | - | 用户昵称 |
| 5 | `user_type` | varchar(2) | NULL | '00' | 用户类型（00系统用户） |
| 6 | `email` | varchar(50) | NULL | '' | 用户邮箱 |
| 7 | `phonenumber` | varchar(11) | NULL | '' | 手机号码 |
| 8 | `sex` | char(1) | NULL | '0' | 用户性别（0男 1女 2未知） |
| 9 | `avatar` | varchar(100) | NULL | '' | 头像地址 |
| 10 | `password` | varchar(100) | NULL | '' | 密码（Argon2id 哈希，旧数据可能为 MD5 格式） |
| 11 | `status` | char(1) | NULL | '0' | 帐号状态（0正常 1停用） |
| 12 | `del_flag` | char(1) | NULL | '0' | 删除标志（0存在 2删除） |
| 13 | `login_ip` | varchar(128) | NULL | '' | 最后登录IP |
| 14 | `login_date` | datetime | NULL | NULL | 最后登录时间 |
| 15 | `create_by` | varchar(64) | NULL | '' | 创建者 |
| 16 | `create_time` | datetime | NULL | NULL | 创建时间 |
| 17 | `update_by` | varchar(64) | NULL | '' | 更新者 |
| 18 | `update_time` | datetime | NULL | NULL | 更新时间 |
| 19 | `remark` | varchar(500) | NULL | NULL | 备注 |

**索引：**
- 主键：`PRIMARY KEY (user_id)`
- 唯一索引：`uk_sys_user_name (user_name)` —— 用户账号唯一
- 普通索引：`idx_sys_user_dept (dept_id)` —— 按部门查询优化

**前端字段对齐说明：**
- `userId` → `user_id`、`nickName` → `nick_name`、`phonenumber` 保持原样（前端也是全小写）
- 前端 `SysUser` 的 `dept`（SysDept 对象）、`roles`（SysRole[]）、`roleIds`、`postIds` 为关联查询字段，不对应数据库列
- 前端 `SysUser` 不显式包含 `del_flag`、`login_ip`、`login_date`、`user_type`，但后端保留以兼容既有数据库结构

---

### 4.2 sys_role（角色信息表）

**用途：** 存储系统角色信息
**主键：** `role_id bigint AUTO_INCREMENT`
**软删除：** `del_flag`
**自增起始值：** 100

| 序号 | 字段名 | 类型 | 可空 | 默认值 | 注释 |
|------|--------|------|------|--------|------|
| 1 | `role_id` | bigint | NOT NULL | AUTO_INCREMENT | 角色ID（主键） |
| 2 | `role_name` | varchar(30) | NOT NULL | - | 角色名称 |
| 3 | `role_key` | varchar(100) | NOT NULL | - | 角色权限字符串（如 admin、common） |
| 4 | `role_sort` | int | NOT NULL | - | 显示顺序 |
| 5 | `data_scope` | char(1) | NULL | '1' | 数据范围（1全部 2自定义 3本部门 4本部门及以下 5仅本人） |
| 6 | `menu_check_strictly` | tinyint(1) | NULL | 1 | 菜单树选择项是否关联显示（布尔） |
| 7 | `dept_check_strictly` | tinyint(1) | NULL | 1 | 部门树选择项是否关联显示（布尔） |
| 8 | `status` | char(1) | NOT NULL | - | 角色状态（0正常 1停用） |
| 9 | `del_flag` | char(1) | NULL | '0' | 删除标志（0存在 2删除） |
| 10 | `create_by` | varchar(64) | NULL | '' | 创建者 |
| 11 | `create_time` | datetime | NULL | NULL | 创建时间 |
| 12 | `update_by` | varchar(64) | NULL | '' | 更新者 |
| 13 | `update_time` | datetime | NULL | NULL | 更新时间 |
| 14 | `remark` | varchar(500) | NULL | NULL | 备注 |

**索引：**
- 主键：`PRIMARY KEY (role_id)`
- 唯一索引：`uk_sys_role_key (role_key)` —— 角色权限字符串唯一

**前端字段对齐说明：**
- `roleId` → `role_id`、`roleKey` → `role_key`、`roleSort` → `role_sort`
- `menuCheckStrictly` → `menu_check_strictly`（前端为 boolean，数据库为 tinyint(1)，Rust 用 `i8`）
- 前端 `SysRole` 的 `menuIds`、`deptIds` 为关联操作字段，不对应数据库列
- `dataScope` 取值范围 '1'-'5'，增加 '5'（仅本人）对齐前端定义

---

### 4.3 sys_menu（菜单权限表）

**用途：** 存储菜单与按钮权限信息
**主键：** `menu_id bigint AUTO_INCREMENT`
**软删除：** `del_flag`
**自增起始值：** 2000

| 序号 | 字段名 | 类型 | 可空 | 默认值 | 注释 |
|------|--------|------|------|--------|------|
| 1 | `menu_id` | bigint | NOT NULL | AUTO_INCREMENT | 菜单ID（主键） |
| 2 | `menu_name` | varchar(50) | NOT NULL | - | 菜单名称 |
| 3 | `parent_id` | bigint | NULL | 0 | 父菜单ID（根节点为 0） |
| 4 | `order_num` | int | NULL | 0 | 显示顺序 |
| 5 | `path` | varchar(200) | NULL | '' | 路由地址 |
| 6 | `component` | varchar(255) | NULL | NULL | 组件路径 |
| 7 | `query` | varchar(255) | NULL | NULL | 路由参数 |
| 8 | `route_name` | varchar(50) | NULL | '' | 路由名称（对齐前端 routeName） |
| 9 | `is_frame` | int(1) | NULL | 1 | 是否为外链（0是 1否） |
| 10 | `is_cache` | int(1) | NULL | 0 | 是否缓存（0缓存 1不缓存） |
| 11 | `menu_type` | char(1) | NULL | '' | 菜单类型（M目录 C菜单 F按钮） |
| 12 | `visible` | char(1) | NULL | '0' | 菜单状态（0显示 1隐藏） |
| 13 | `status` | char(1) | NULL | '0' | 菜单状态（0正常 1停用） |
| 14 | `perms` | varchar(100) | NULL | NULL | 权限标识（如 system:user:list） |
| 15 | `icon` | varchar(100) | NULL | '#' | 菜单图标 |
| 16 | `create_by` | varchar(64) | NULL | '' | 创建者 |
| 17 | `create_time` | datetime | NULL | NULL | 创建时间 |
| 18 | `update_by` | varchar(64) | NULL | '' | 更新者 |
| 19 | `update_time` | datetime | NULL | NULL | 更新时间 |
| 20 | `remark` | varchar(500) | NULL | '' | 备注 |
| 21 | `del_flag` | char(1) | NULL | '0' | 删除标志（0存在 2删除） |

**索引：**
- 主键：`PRIMARY KEY (menu_id)`
- 普通索引：`idx_sys_menu_parent (parent_id)` —— 按父节点查询子菜单优化

**新增/调整字段：**
- **新增 `route_name` 字段**：本项目前端 `SysMenu` 类型含 `routeName` 字段，本项目补充以对齐前端
- **新增 `del_flag` 字段**：sys_menu 此前无软删除，本项目统一软删除设计

**前端字段对齐说明：**
- `menuId` → `menu_id`、`parentId` → `parent_id`、`orderNum` → `order_num`
- `isFrame` → `is_frame`、`isCache` → `is_cache`、`menuType` → `menu_type`
- 前端 `SysMenu` 的 `children` 为树构建字段，不对应数据库列
- `isFrame` / `isCache` 前端为 `'0' | '1'` 字符串字面量，数据库用 `int(1)`，Rust 用 `i32`

---

### 4.4 sys_user_role（用户角色关联表）

**用途：** 用户与角色的多对多关联
**主键：** 复合主键 `(user_id, role_id)`
**软删除：** 无

| 序号 | 字段名 | 类型 | 可空 | 默认值 | 注释 |
|------|--------|------|------|--------|------|
| 1 | `user_id` | bigint | NOT NULL | - | 用户ID |
| 2 | `role_id` | bigint | NOT NULL | - | 角色ID |

**索引：**
- 复合主键：`PRIMARY KEY (user_id, role_id)`
- 普通索引：`idx_sys_user_role_role (role_id)` —— 按角色反查用户优化

---

### 4.5 sys_role_menu（角色菜单关联表）

**用途：** 角色与菜单的多对多关联
**主键：** 复合主键 `(role_id, menu_id)`
**软删除：** 无

| 序号 | 字段名 | 类型 | 可空 | 默认值 | 注释 |
|------|--------|------|------|--------|------|
| 1 | `role_id` | bigint | NOT NULL | - | 角色ID |
| 2 | `menu_id` | bigint | NOT NULL | - | 菜单ID |

**索引：**
- 复合主键：`PRIMARY KEY (role_id, menu_id)`
- 普通索引：`idx_sys_role_menu_menu (menu_id)` —— 按菜单反查角色优化

---

### 4.6 sys_dict_type（字典类型表）

**用途：** 存储字典类型定义（如 sys_user_sex、sys_normal_disable）
**主键：** `dict_id bigint AUTO_INCREMENT`
**软删除：** `del_flag`
**自增起始值：** 100

| 序号 | 字段名 | 类型 | 可空 | 默认值 | 注释 |
|------|--------|------|------|--------|------|
| 1 | `dict_id` | bigint | NOT NULL | AUTO_INCREMENT | 字典主键 |
| 2 | `dict_name` | varchar(100) | NULL | '' | 字典名称 |
| 3 | `dict_type` | varchar(100) | NULL | '' | 字典类型（唯一） |
| 4 | `status` | char(1) | NULL | '0' | 状态（0正常 1停用） |
| 5 | `create_by` | varchar(64) | NULL | '' | 创建者 |
| 6 | `create_time` | datetime | NULL | NULL | 创建时间 |
| 7 | `update_by` | varchar(64) | NULL | '' | 更新者 |
| 8 | `update_time` | datetime | NULL | NULL | 更新时间 |
| 9 | `remark` | varchar(500) | NULL | NULL | 备注 |
| 10 | `del_flag` | char(1) | NULL | '0' | 删除标志（0存在 2删除） |

**索引：**
- 主键：`PRIMARY KEY (dict_id)`
- 唯一索引：`uk_sys_dict_type (dict_type)` —— 字典类型唯一

**新增/调整字段：**
- **新增 `del_flag` 字段**：sys_dict_type 此前无软删除，本项目统一软删除设计

---

### 4.7 sys_dict_data（字典数据表）

**用途：** 存储字典数据项
**主键：** `dict_code bigint AUTO_INCREMENT`
**软删除：** `del_flag`
**自增起始值：** 100

| 序号 | 字段名 | 类型 | 可空 | 默认值 | 注释 |
|------|--------|------|------|--------|------|
| 1 | `dict_code` | bigint | NOT NULL | AUTO_INCREMENT | 字典编码（主键） |
| 2 | `dict_sort` | int | NULL | 0 | 字典排序 |
| 3 | `dict_label` | varchar(100) | NULL | '' | 字典标签 |
| 4 | `dict_value` | varchar(100) | NULL | '' | 字典键值 |
| 5 | `dict_type` | varchar(100) | NULL | '' | 字典类型（关联 sys_dict_type.dict_type） |
| 6 | `css_class` | varchar(100) | NULL | NULL | 样式属性 |
| 7 | `list_class` | varchar(100) | NULL | NULL | 表格回显样式（primary/success/info/warning/danger） |
| 8 | `is_default` | char(1) | NULL | 'N' | 是否默认（Y是 N否） |
| 9 | `status` | char(1) | NULL | '0' | 状态（0正常 1停用） |
| 10 | `create_by` | varchar(64) | NULL | '' | 创建者 |
| 11 | `create_time` | datetime | NULL | NULL | 创建时间 |
| 12 | `update_by` | varchar(64) | NULL | '' | 更新者 |
| 13 | `update_time` | datetime | NULL | NULL | 更新时间 |
| 14 | `remark` | varchar(500) | NULL | NULL | 备注 |
| 15 | `del_flag` | char(1) | NULL | '0' | 删除标志（0存在 2删除） |

**索引：**
- 主键：`PRIMARY KEY (dict_code)`
- 普通索引：`idx_sys_dict_data_type (dict_type)` —— 按字典类型查询数据项优化

**新增/调整字段：**
- **新增 `del_flag` 字段**：统一软删除设计
- **`dict_sort` 类型对齐**：SQL 为 `int(4)`，Rust 实体用 `i32`（曾误用 `i8`，本项目已修正）

**前端字段对齐说明：**
- `dictCode` → `dict_code`、`dictLabel` → `dict_label`、`dictValue` → `dict_value`
- `cssClass` → `css_class`、`listClass` → `list_class`、`isDefault` → `is_default`、`dictSort` → `dict_sort`

---

### 4.8 sys_oper_log（操作日志表）

**用途：** 记录系统操作日志
**主键：** `oper_id bigint AUTO_INCREMENT`
**软删除：** 无（日志表物理删除）
**自增起始值：** 100

| 序号 | 字段名 | 类型 | 可空 | 默认值 | 注释 |
|------|--------|------|------|--------|------|
| 1 | `oper_id` | bigint | NOT NULL | AUTO_INCREMENT | 日志主键 |
| 2 | `title` | varchar(50) | NULL | '' | 模块标题 |
| 3 | `business_type` | int(2) | NULL | 0 | 业务类型（0其它 1新增 2修改 3删除 4授权 5导出 6导入 7强退 8生成代码 9清空数据） |
| 4 | `method` | varchar(100) | NULL | '' | 方法名称 |
| 5 | `request_method` | varchar(10) | NULL | '' | 请求方式（GET/POST/PUT/DELETE） |
| 6 | `operator_type` | int(1) | NULL | 0 | 操作类别（0其它 1后台用户 2手机端用户） |
| 7 | `oper_name` | varchar(50) | NULL | '' | 操作人员 |
| 8 | `dept_name` | varchar(50) | NULL | '' | 部门名称 |
| 9 | `oper_url` | varchar(255) | NULL | '' | 请求URL |
| 10 | `oper_ip` | varchar(128) | NULL | '' | 主机地址 |
| 11 | `oper_location` | varchar(255) | NULL | '' | 操作地点 |
| 12 | `oper_param` | varchar(2000) | NULL | '' | 请求参数 |
| 13 | `json_result` | varchar(2000) | NULL | '' | 返回参数 |
| 14 | `status` | int(1) | NULL | 0 | 操作状态（0正常 1异常） |
| 15 | `error_msg` | varchar(2000) | NULL | '' | 错误消息 |
| 16 | `oper_time` | datetime | NULL | NULL | 操作时间 |
| 17 | `cost_time` | bigint | NULL | 0 | 消耗时间（毫秒） |

**索引：**
- 主键：`PRIMARY KEY (oper_id)`
- 普通索引：`idx_sys_oper_log_bt (business_type)` —— 按业务类型查询
- 普通索引：`idx_sys_oper_log_s (status)` —— 按状态查询
- 普通索引：`idx_sys_oper_log_ot (oper_time)` —— 按操作时间查询

**前端字段对齐说明：**
- `operId` → `oper_id`、`businessType` → `business_type`、`requestMethod` → `request_method`
- `operatorType` → `operator_type`、`operName` → `oper_name`、`operUrl` → `oper_url`
- `operIp` → `oper_ip`、`operLocation` → `oper_location`、`operParam` → `oper_param`
- `jsonResult` → `json_result`、`errorMsg` → `error_msg`、`operTime` → `oper_time`、`costTime` → `cost_time`
- **`status` 字段类型差异**：前端为 `'0' | '1'` 字符串，数据库为 `int(1)`，Rust 用 `i32`，需在 handler 层做类型转换

---

### 4.9 sys_logininfor（系统访问记录 / 登录日志表）

**用途：** 记录用户登录日志
**主键：** `info_id bigint AUTO_INCREMENT`
**软删除：** 无（日志表物理删除）
**自增起始值：** 100

| 序号 | 字段名 | 类型 | 可空 | 默认值 | 注释 |
|------|--------|------|------|--------|------|
| 1 | `info_id` | bigint | NOT NULL | AUTO_INCREMENT | 访问ID（主键） |
| 2 | `user_name` | varchar(50) | NULL | '' | 用户账号 |
| 3 | `ipaddr` | varchar(128) | NULL | '' | 登录IP地址（注意：全小写，无下划线） |
| 4 | `login_location` | varchar(255) | NULL | '' | 登录地点 |
| 5 | `browser` | varchar(50) | NULL | '' | 浏览器类型 |
| 6 | `os` | varchar(50) | NULL | '' | 操作系统 |
| 7 | `status` | char(1) | NULL | '0' | 登录状态（0成功 1失败） |
| 8 | `msg` | varchar(255) | NULL | '' | 提示消息 |
| 9 | `login_time` | datetime | NULL | NULL | 访问时间 |

**索引：**
- 主键：`PRIMARY KEY (info_id)`
- 普通索引：`idx_sys_logininfor_s (status)` —— 按状态查询
- 普通索引：`idx_sys_logininfor_lt (login_time)` —— 按登录时间查询

**前端字段对齐说明（重要特例）：**
- `infoId` → `info_id`、`userName` → `user_name`、`loginLocation` → `login_location`
- **`ipaddr` 保持全小写**：前端 TypeScript 定义为 `ipaddr`（非 `ipAddr` 或 `ip_addr`），数据库列名保持 `ipaddr`，Rust 字段名也用 `ipaddr`，serde 无需转换
- `loginTime` → `login_time`

---

### 4.10 sys_job（定时任务调度表）

**用途：** 存储定时任务调度配置
**主键：** `job_id bigint AUTO_INCREMENT`（单主键）
**软删除：** `del_flag`
**自增起始值：** 100

| 序号 | 字段名 | 类型 | 可空 | 默认值 | 注释 |
|------|--------|------|------|--------|------|
| 1 | `job_id` | bigint | NOT NULL | AUTO_INCREMENT | 任务ID（主键） |
| 2 | `job_name` | varchar(64) | NOT NULL | '' | 任务名称 |
| 3 | `job_group` | varchar(64) | NOT NULL | 'DEFAULT' | 任务组名 |
| 4 | `invoke_target` | varchar(500) | NOT NULL | - | 调用目标字符串 |
| 5 | `cron_expression` | varchar(255) | NULL | '' | cron 执行表达式 |
| 6 | `misfire_policy` | varchar(20) | NULL | '3' | 计划执行错误策略（1立即执行 2执行一次 3放弃执行） |
| 7 | `concurrent` | char(1) | NULL | '1' | 是否并发执行（0允许 1禁止） |
| 8 | `status` | char(1) | NULL | '0' | 状态（0正常 1暂停） |
| 9 | `create_by` | varchar(64) | NULL | '' | 创建者 |
| 10 | `create_time` | datetime | NULL | NULL | 创建时间 |
| 11 | `update_by` | varchar(64) | NULL | '' | 更新者 |
| 12 | `update_time` | datetime | NULL | NULL | 更新时间 |
| 13 | `remark` | varchar(500) | NULL | '' | 备注信息 |
| 14 | `del_flag` | char(1) | NULL | '0' | 删除标志（0存在 2删除） |

**索引：**
- 主键：`PRIMARY KEY (job_id)`
- 唯一索引：`uk_sys_job_name_group (job_name, job_group)` —— 任务名称在组内唯一

**主键设计（重要）：**
- **主键改为单主键**：本项目使用单主键 `job_id` + 唯一索引 `(job_name, job_group)`，原因：
  1. 前端 `SysJob.jobId` 为 `number` 类型，期望单主键
  2. SeaORM 单主键更易维护（复合主键在 SeaORM 中需用元组类型，操作复杂）
  3. 唯一索引保证 `(job_name, job_group)` 唯一性
- **新增 `del_flag` 字段**：统一软删除设计

**前端字段对齐说明：**
- `jobId` → `job_id`、`jobName` → `job_name`、`jobGroup` → `job_group`
- `invokeTarget` → `invoke_target`、`cronExpression` → `cron_expression`
- `misfirePolicy` → `misfire_policy`
- 前端 `SysJob` 的 `nextValidTime` 为计算字段（下次执行时间），不对应数据库列

---

### 4.11 sys_job_log（定时任务调度日志表）

**用途：** 记录定时任务执行日志
**主键：** `job_log_id bigint AUTO_INCREMENT`
**软删除：** 无（日志表物理删除）

| 序号 | 字段名 | 类型 | 可空 | 默认值 | 注释 |
|------|--------|------|------|--------|------|
| 1 | `job_log_id` | bigint | NOT NULL | AUTO_INCREMENT | 任务日志ID（主键） |
| 2 | `job_name` | varchar(64) | NOT NULL | - | 任务名称 |
| 3 | `job_group` | varchar(64) | NOT NULL | - | 任务组名 |
| 4 | `invoke_target` | varchar(500) | NOT NULL | - | 调用目标字符串 |
| 5 | `job_message` | varchar(500) | NULL | NULL | 日志信息 |
| 6 | `status` | char(1) | NULL | '0' | 执行状态（0正常 1失败） |
| 7 | `exception_info` | varchar(2000) | NULL | '' | 异常信息 |
| 8 | `create_time` | datetime | NULL | NULL | 创建时间 |

**索引：**
- 主键：`PRIMARY KEY (job_log_id)`

**前端字段对齐说明：**
- `jobLogId` → `job_log_id`、`jobName` → `job_name`、`jobGroup` → `job_group`
- `invokeTarget` → `invoke_target`、`jobMessage` → `job_message`
- `exceptionInfo` → `exception_info`

---

## 5. 索引设计汇总

### 5.1 主键索引

| 表 | 主键类型 | 主键字段 |
|----|----------|----------|
| sys_user | 单主键自增 | user_id |
| sys_role | 单主键自增 | role_id |
| sys_menu | 单主键自增 | menu_id |
| sys_user_role | 复合主键 | (user_id, role_id) |
| sys_role_menu | 复合主键 | (role_id, menu_id) |
| sys_dict_type | 单主键自增 | dict_id |
| sys_dict_data | 单主键自增 | dict_code |
| sys_oper_log | 单主键自增 | oper_id |
| sys_logininfor | 单主键自增 | info_id |
| sys_job | 单主键自增 | job_id |
| sys_job_log | 单主键自增 | job_log_id |

### 5.2 唯一索引

| 索引名 | 表 | 字段 | 说明 |
|--------|----|------|------|
| uk_sys_user_name | sys_user | user_name | 用户账号唯一 |
| uk_sys_role_key | sys_role | role_key | 角色权限字符串唯一 |
| uk_sys_dict_type | sys_dict_type | dict_type | 字典类型唯一 |
| uk_sys_job_name_group | sys_job | (job_name, job_group) | 任务名称在组内唯一 |

### 5.3 普通索引

| 索引名 | 表 | 字段 | 说明 |
|--------|----|------|------|
| idx_sys_user_dept | sys_user | dept_id | 按部门查询优化 |
| idx_sys_menu_parent | sys_menu | parent_id | 按父节点查询子菜单 |
| idx_sys_user_role_role | sys_user_role | role_id | 按角色反查用户 |
| idx_sys_role_menu_menu | sys_role_menu | menu_id | 按菜单反查角色 |
| idx_sys_dict_data_type | sys_dict_data | dict_type | 按字典类型查询数据项 |
| idx_sys_oper_log_bt | sys_oper_log | business_type | 按业务类型查询 |
| idx_sys_oper_log_s | sys_oper_log | status | 按状态查询 |
| idx_sys_oper_log_ot | sys_oper_log | oper_time | 按操作时间查询 |
| idx_sys_logininfor_s | sys_logininfor | status | 按状态查询 |
| idx_sys_logininfor_lt | sys_logininfor | login_time | 按登录时间查询 |

---

## 6. SeaORM 实体设计规范

### 6.1 实体写法选择

**决策：** 使用 `#[derive(DeriveEntityModel)]` 宏写法（SeaORM 官方推荐）。

**原因：**
1. 代码更简洁，一行注解替代 5 段式定义
2. SeaORM 官方文档主推写法
3. 第一阶段 Cargo.toml 已启用 `macros` feature
4. 宏写法是主流生态的普遍做法

### 6.2 实体文件组织

```
src/entity/
├── mod.rs                  # 模块声明与 re-export
├── prelude.rs              # prelude 重导出
├── sys_user.rs             # sys_user 实体
├── sys_role.rs             # sys_role 实体
├── sys_menu.rs             # sys_menu 实体
├── sys_user_role.rs        # sys_user_role 实体
├── sys_role_menu.rs        # sys_role_menu 实体
├── sys_dict_type.rs        # sys_dict_type 实体
├── sys_dict_data.rs        # sys_dict_data 实体
├── sys_oper_log.rs         # sys_oper_log 实体
├── sys_logininfor.rs       # sys_logininfor 实体
├── sys_job.rs              # sys_job 实体
└── sys_job_log.rs          # sys_job_log 实体
```

### 6.3 实体定义模板（单主键自增）

```rust
//! sys_user 实体定义

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

### 6.4 实体定义模板（复合主键）

```rust
//! sys_user_role 实体定义（复合主键）

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

### 6.5 serde 序列化配置

**决策：** 不在实体上全局使用 `#[serde(rename_all = "camelCase")]`，而是通过 handler 层的 DTO（Data Transfer Object）进行字段名转换。

**原因：**
1. 实体层应保持与数据库列名一致（snake_case）
2. 全局 `rename_all = "camelCase"` 会导致 `ipaddr` 被错误转换为 `ipaddr`（实际无需转换）或引发其他命名问题
3. DTO 层负责数据库实体与前端契约之间的转换

> **本阶段说明：** 本阶段仅定义实体，DTO 层在第三阶段业务接口实现时创建。本阶段实体的 `Serialize`/`Deserialize` 用于内部测试，不直接暴露给前端。

### 6.6 时间自动维护实现

通过 `ActiveModelBehavior::before_save` 实现：

| 操作 | create_time | update_time |
|------|-------------|-------------|
| 插入（insert=true） | Set(now) | Set(now) |
| 更新（insert=false） | 不修改 | Set(now) |

**适用表：** 所有含 `create_time` / `update_time` 字段的业务表（6 张：sys_user、sys_role、sys_menu、sys_dict_type、sys_dict_data、sys_job）

**不适用表：**
- 关联表（sys_user_role、sys_role_menu）：无时间字段
- 日志表（sys_oper_log、sys_logininfor、sys_job_log）：时间字段由业务层显式设置

---

## 7. 初始数据设计

### 7.1 必需的初始数据

| 表 | 初始数据 | 说明 |
|----|----------|------|
| sys_user | 1 条：admin 用户 | 超级管理员，密码 `admin123` 加盐 MD5 |
| sys_role | 1 条：admin 角色 | 超级管理员角色，role_key = "admin" |
| sys_menu | 若干条：基础菜单 | 系统管理、系统监控目录及子菜单 |
| sys_user_role | 1 条 | admin 用户关联 admin 角色 |
| sys_role_menu | 若干条 | admin 角色关联所有菜单 |
| sys_dict_type | 10 条 | 内置字典类型（用户性别、菜单状态等） |
| sys_dict_data | 29 条 | 内置字典数据项 |

### 7.2 admin 用户初始数据

```sql
INSERT INTO sys_user (user_id, dept_id, user_name, nick_name, user_type, email, phonenumber, sex, avatar, password, status, del_flag, create_by, create_time, remark)
VALUES (1, 100, 'admin', '演示管理员', '00', 'admin@ry.com', '15888888888', '0', '', 'ba976d23f6d1012cfe81ceb960a1058c', '0', '0', 'admin', NOW(), '管理员');
```

> **密码说明：** `admin123` + `stepby_admin` 盐值后 MD5 = `ba976d23f6d1012cfe81ceb960a1058c`。盐值已从 `"salvo_admin"` 改为 `"stepby_admin"`，不兼容旧密码。

### 7.3 admin 角色初始数据

```sql
INSERT INTO sys_role (role_id, role_name, role_key, role_sort, data_scope, menu_check_strictly, dept_check_strictly, status, del_flag, create_by, create_time, remark)
VALUES (1, '超级管理员', 'admin', 1, '1', 1, 1, '0', '0', 'admin', NOW(), '超级管理员');
```

### 7.4 内置字典类型（10 条）

| dict_name | dict_type | 说明 |
|-----------|-----------|------|
| 用户性别 | sys_user_sex | 0男 1女 2未知 |
| 菜单状态 | sys_show_hide | 0显示 1隐藏 |
| 系统开关 | sys_normal_disable | 0正常 1停用 |
| 任务状态 | sys_job_status | 0正常 1暂停 |
| 任务分组 | sys_job_group | DEFAULT默认 |
| 系统是否 | sys_yes_no | Y是 N否 |
| 通知类型 | sys_notice_type | 1通知 2公告 |
| 通知状态 | sys_notice_status | 0正常 1关闭 |
| 操作类型 | sys_oper_type | 0其它 1新增 2修改 3删除... |
| 系统状态 | sys_common_status | 0正常 1异常 |

---

## 8. 结构差异说明

### 8.1 结构性差异

| 差异点 | 基础结构 | 本项目 | 原因 |
|--------|-----------------|--------|------|
| sys_menu.route_name | 无 | 有 | 对齐前端 `routeName` 字段 |
| sys_menu.del_flag | 无 | 有 | 统一软删除设计 |
| sys_dict_type.del_flag | 无 | 有 | 统一软删除设计 |
| sys_dict_data.del_flag | 无 | 有 | 统一软删除设计 |
| sys_job.del_flag | 无 | 有 | 统一软删除设计 |
| sys_job 主键 | 复合主键 (job_id, job_name, job_group) | 单主键 job_id + 唯一索引 | 对齐前端 `jobId: number`，SeaORM 单主键更易维护 |
| sys_user 索引 | 无 | uk_sys_user_name + idx_sys_user_dept | 补充唯一约束和查询优化索引 |
| sys_role 索引 | 无 | uk_sys_role_key | 补充 role_key 唯一约束 |
| sys_menu 索引 | 无 | idx_sys_menu_parent | 补充 parent_id 查询优化 |
| sys_dict_data 索引 | 无 | idx_sys_dict_data_type | 补充 dict_type 查询优化 |
| sys_user_role 索引 | 无 | idx_sys_user_role_role | 补充 role_id 反查优化 |
| sys_role_menu 索引 | 无 | idx_sys_role_menu_menu | 补充 menu_id 反查优化 |

### 8.2 字段类型差异

| 字段 | 基础结构 | 本项目 | 原因 |
|------|-----------------|--------|------|
| sys_dict_data.dict_sort | int(4) | int | Rust 用 `i32`（曾误用 `i8`，本项目已修正） |
| sys_oper_log.status | int(1) | int(1) | 保持一致，Rust 用 `i32`，handler 层做 string 转换 |

### 8.3 兼容性保证

- **数据库兼容**：所有表名、核心字段名保持既有结构，可直接导入既有 `ry_20230223.sql` 数据
- **前端兼容**：所有前端字段通过 DTO 层 camelCase 转换对齐
- **新增字段向后兼容**：`route_name`、`del_flag` 新增字段均有默认值，不影响现有数据

---

## 9. 迁移策略

### 9.1 迁移文件规划

**文件：** `migration/src/m20250711_000001_init.rs`（填充第一阶段空骨架）

**迁移内容：**
1. 创建 11 张表（按依赖顺序：sys_user → sys_role → sys_menu → sys_user_role → sys_role_menu → sys_dict_type → sys_dict_data → sys_oper_log → sys_logininfor → sys_job → sys_job_log）
2. 创建全部索引（主键、唯一索引、普通索引）
3. 插入初始数据（admin 用户、admin 角色、基础菜单、字典数据）

### 9.2 建表顺序（依赖关系）

```
sys_user (无依赖)
sys_role (无依赖)
sys_menu (无依赖)
sys_user_role (依赖 sys_user, sys_role)
sys_role_menu (依赖 sys_role, sys_menu)
sys_dict_type (无依赖)
sys_dict_data (依赖 sys_dict_type.dict_type 逻辑关联)
sys_oper_log (无依赖)
sys_logininfor (无依赖)
sys_job (无依赖)
sys_job_log (依赖 sys_job 逻辑关联)
```

### 9.3 迁移实现方式

**决策：** 使用 `sea-orm-migration` 的 `Table::create()` 显式建表，不使用 `Schema::create_table_from_entity()`。

**原因：**
1. 显式建表更易控制字段精度、默认值、注释
2. 避免 entity 定义与 migration 的循环依赖
3. 便于在迁移中插入初始数据

---

## 10. 实体 Relation 设计

### 10.1 本阶段 Relation 策略

**决策：** 本阶段实体内 `Relation` 枚举留空（`enum Relation {}`），不在实体层定义静态关联。

**原因：**
1. 关联在服务层动态构建（与既有模块保持一致）
2. 避免 SeaORM Relation 的复杂性
3. 本阶段仅定义表结构，不实现业务查询

### 10.2 后续业务阶段的关联查询方式

在服务层使用 `join_rev` + `belongs_to` 动态构建：

```rust
// 示例：用户关联部门（第三阶段实现）
sys_user::Entity::find()
    .join_rev(
        JoinType::LeftJoin,
        sys_dept::Entity::belongs_to(sys_user::Entity)
            .from(sys_dept::Column::DeptId)
            .to(sys_user::Column::DeptId)
            .into(),
    )
    .filter(sys_user::Column::DelFlag.eq("0"))
    .select_also(sys_dept::Entity);
```

---

## 11. 验收标准摘要

本阶段验收标准详见 `docs/db-checklist.md`，核心指标：

1. 11 张表全部创建成功（含全部字段、索引、约束）
2. 11 个 SeaORM 实体文件编译通过
3. `cargo build -p migration` 成功
4. `cargo run -p migration` 可执行迁移
5. `cargo check` 主 crate 编译通过
6. 初始数据正确插入（admin 用户可登录验证）
7. 时间自动维护机制工作正常（通过单元测试验证）
8. 软删除字段默认值 '0' 生效

---

## 附录 A：SQL 脚本位置

- 主库脚本：`sql/ry_20230223.sql`（只读，禁止修改）
- Quartz 表脚本：`sql/quartz.sql`（本阶段不使用）

## 附录 B：本项目前端类型定义文件位置
- 基础类型：`types/api/common.ts`（只读）
- 系统模块：`types/api/system/*.ts`（只读）
- 监控模块：`types/api/monitor/*.ts`（只读）
