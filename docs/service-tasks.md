# Service 层接口清单（service-tasks.md）

> **阶段：** 第三阶段「用户/角色/菜单 Service 层业务实现」
> **项目：** axum-backend
> **配套文档：** [service-spec.md](./service-spec.md)、[service-checklist.md](./service-checklist.md)

---

## 1. 任务总览

| 编号 | 任务 | 优先级 | 依赖 |
|------|------|--------|------|
| T00 | 添加新依赖（futures, regex, once_cell）+ 盐值改为 yebot_admin | P0 | — |
| T01 | 创建 DTO 定义（用户/角色/菜单） | P0 | T00 |
| T02 | 为 SysMenuModel 实现 TreeNode trait + 新增 children 字段 | P0 | T00 |
| T03 | 实现 SysUserService 用户业务逻辑 | P0 | T01, T02 |
| T04 | 实现 SysRoleService 角色业务逻辑 | P0 | T01, T02 |
| T05 | 实现 SysMenuService 菜单业务逻辑 | P0 | T01, T02 |
| T06 | 更新 service/mod.rs 模块声明 | P0 | T03, T04, T05 |
| T07 | 编译验证 cargo check | P0 | T06 |
| T08 | 单元测试编写（密码加密、树形组装） | P1 | T07 |
| T09 | 前端接口契约对齐自查 | P0 | T07 |

---

## 2. 任务详细分解

### T00 添加新依赖 + 盐值修改

**文件：** `Cargo.toml`、`src/common/constants.rs`、`src/utils/password.rs`、`migration/src/m20250711_000001_init.rs`

**交付物：**
1. Cargo.toml 添加依赖：
   - `futures = "0.3"`（事务闭包 `boxed()`）
   - `regex = "1"`（garde regex 校验）
   - `once_cell = "1"`（全局正则常量）
2. `constants.rs` 中 `PASSWORD_SALT` 改为 `"yebot_admin"`
3. `password.rs` 注释更新
4. migration 初始用户密码改为新盐值生成的 MD5（admin123 + yebot_admin = `bfb6b8dd9b268e241c82a257e235e550`）

**验收：**
- [ ] Cargo.toml 依赖添加
- [ ] 盐值常量修改
- [ ] migration 密码数据更新
- [ ] `cargo check` 通过

### T01 创建 DTO 定义

**文件：** `src/service/dto/mod.rs`（可选）或各 service 文件内

**交付物：**

用户 DTO：
- `UserAddDto`（新增用户）
- `UserEditDto`（修改用户）
- `UserPwdResetDto`（管理员重置密码）
- `UserPwdUpdateDto`个人中心改密）
- `UserQueryDto`（分页查询）
- `UserVo`（用户详情返回，含 role_ids）
- `UserProfileVo`（个人中心返回，含 role_group/post_group）

角色 DTO：
- `RoleAddDto`（新增角色）
- `RoleEditDto`（修改角色）
- `RoleQueryDto`（分页查询）
- `RoleVo`（角色详情返回，含 menu_ids）

菜单 DTO：
- `MenuAddDto`（新增菜单）
- `MenuEditDto`（修改菜单）
- `MenuQueryDto`（列表查询）
- `MenuVo`（菜单详情返回，含 children）

**要求：**
- 所有 DTO 添加 `#[serde(rename_all = "camelCase")]` 对齐前端
- 使用 `garde` crate 注解校验规则
- DTO 字段类型使用 `Option<T>` 表示可空

**验收：**
- [ ] 所有 DTO 定义完成
- [ ] garde 注解正确
- [ ] serde 驼峰映射注解添加

---

### T02 为 SysMenuModel 实现 TreeNode trait

**文件：** `src/entity/sys_menu.rs`

**交付物：**
1. 在 `Model` 中新增 `#[sea_orm(ignore)] pub children: Option<Vec<Model>>` 字段
2. 在 `src/utils/tree.rs` 或 `src/entity/sys_menu.rs` 中为 `Model` 实现 `TreeNode` trait

**实现：**

```rust
// sys_menu.rs Model 中新增
#[sea_orm(ignore)]
#[serde(skip_serializing_if = "Option::is_none")]
pub children: Option<Vec<Model>>,

// 实现 TreeNode
impl crate::utils::tree::TreeNode for Model {
    fn id(&self) -> i64 { self.menu_id }
    fn parent_id(&self) -> i64 { self.parent_id.unwrap_or(0) }
    fn children_mut(&mut self) -> &mut Option<Vec<Self>> { &mut self.children }
}
```

**验收：**
- [ ] children 字段标注 `#[sea_orm(ignore)]`
- [ ] TreeNode trait 实现正确
- [ ] serde 序列化时 children 为空则不输出

---

### T03 实现 SysUserService

**文件：** `src/service/sys_user_service.rs`

**交付物：** `SysUserService` 结构体，包含以下方法：

| 方法 | 签名 | 事务 |
|------|------|------|
| new | `new(db: DatabaseConnection) -> Self` | — |
| get_user_page | `async fn(&self, query: UserQueryDto) -> Result<TableDataInfo<UserVo>, AppError>` | 否 |
| get_user_by_id | `async fn(&self, user_id: i64) -> Result<UserVo, AppError>` | 否 |
| add_user | `async fn(&self, dto: UserAddDto, operator: &str) -> Result<SysUserModel, AppError>` | 是 |
| edit_user | `async fn(&self, dto: UserEditDto, operator: &str) -> Result<SysUserModel, AppError>` | 是 |
| delete_user | `async fn(&self, user_id: i64) -> Result<(), AppError>` | 是 |
| reset_user_pwd | `async fn(&self, user_id: i64, password: &str) -> Result<(), AppError>` | 否 |
| update_user_password | `async fn(&self, user_id: i64, old_pwd: &str, new_pwd: &str) -> Result<(), AppError>` | 否 |
| update_user_status | `async fn(&self, user_id: i64, status: &str) -> Result<(), AppError>` | 否 |
| assign_user_roles | `async fn(&self, user_id: i64, role_ids: Vec<i64>) -> Result<(), AppError>` | 是 |
| get_user_by_username | `async fn(&self, user_name: &str) -> Result<Option<SysUserModel>, AppError>` | 否 |

**业务规则实现点：**
- [ ] add_user: 用户名查重
- [ ] add_user: 密码 `encrypt_password`
- [ ] add_user: 事务内插用户 + 批量插 user_role
- [ ] edit_user: 超管保护（user_id==1 禁停用）
- [ ] edit_user: role_ids=None 不修改，Some(vec![]) 清空
- [ ] delete_user: 超管保护（user_id==1 禁删除）
- [ ] delete_user: 事务内软删除 + 清理 user_role
- [ ] update_user_password: `verify_password` 校验旧密码
- [ ] update_user_password: 新旧密码不能相同
- [ ] update_user_status: 超管保护（user_id==1 禁停用）
- [ ] assign_user_roles: 事务内先删后插

**验收：**
- [ ] 所有方法实现完成
- [ ] 事务方法使用 `TransactionTrait`
- [ ] 错误统一返回 `AppError`
- [ ] 密码使用 `utils::password` 加密

---

### T04 实现 SysRoleService

**文件：** `src/service/sys_role_service.rs`

**交付物：** `SysRoleService` 结构体，包含以下方法：

| 方法 | 签名 | 事务 |
|------|------|------|
| new | `new(db: DatabaseConnection) -> Self` | — |
| get_role_page | `async fn(&self, query: RoleQueryDto) -> Result<TableDataInfo<SysRoleModel>, AppError>` | 否 |
| get_role_by_id | `async fn(&self, role_id: i64) -> Result<RoleVo, AppError>` | 否 |
| get_all_roles | `async fn(&self) -> Result<Vec<SysRoleModel>, AppError>` | 否 |
| add_role | `async fn(&self, dto: RoleAddDto, operator: &str) -> Result<SysRoleModel, AppError>` | 是 |
| edit_role | `async fn(&self, dto: RoleEditDto, operator: &str) -> Result<SysRoleModel, AppError>` | 是 |
| delete_role | `async fn(&self, role_id: i64) -> Result<(), AppError>` | 是 |
| update_role_status | `async fn(&self, role_id: i64, status: &str) -> Result<(), AppError>` | 否 |
| assign_role_menus | `async fn(&self, role_id: i64, menu_ids: Vec<i64>) -> Result<(), AppError>` | 是 |
| get_roles_by_user_id | `async fn(&self, user_id: i64) -> Result<Vec<SysRoleModel>, AppError>` | 否 |
| get_role_keys_by_user_id | `async fn(&self, user_id: i64) -> Result<Vec<String>, AppError>` | 否 |

**业务规则实现点：**
- [ ] add_role: role_key 查重
- [ ] add_role: data_scope 默认 "1"
- [ ] add_role: 事务内插角色 + 批量插 role_menu
- [ ] edit_role: 超管保护（role_id==1 禁改 role_key）
- [ ] edit_role: role_key 变更时查重
- [ ] edit_role: menu_ids=None 不修改，Some(vec![]) 清空
- [ ] delete_role: 超管保护（role_id==1 禁删除）
- [ ] delete_role: 级联删除校验（有关联用户时拒绝）
- [ ] delete_role: 事务内软删除 + 清理 role_menu + 清理 user_role
- [ ] update_role_status: 超管保护（role_id==1 禁停用）
- [ ] assign_role_menus: 事务内先删后插

**验收：**
- [ ] 所有方法实现完成
- [ ] 事务方法使用 `TransactionTrait`
- [ ] 级联删除校验正确

---

### T05 实现 SysMenuService

**文件：** `src/service/sys_menu_service.rs`

**交付物：** `SysMenuService` 结构体，包含以下方法：

| 方法 | 签名 | 事务 |
|------|------|------|
| new | `new(db: DatabaseConnection) -> Self` | — |
| get_menu_list | `async fn(&self, query: MenuQueryDto) -> Result<Vec<SysMenuModel>, AppError>` | 否 |
| get_menu_tree | `async fn(&self) -> Result<Vec<SysMenuModel>, AppError>` | 否 |
| get_menu_by_id | `async fn(&self, menu_id: i64) -> Result<SysMenuModel, AppError>` | 否 |
| add_menu | `async fn(&self, dto: MenuAddDto, operator: &str) -> Result<SysMenuModel, AppError>` | 否 |
| edit_menu | `async fn(&self, dto: MenuEditDto, operator: &str) -> Result<SysMenuModel, AppError>` | 否 |
| delete_menu | `async fn(&self, menu_id: i64) -> Result<(), AppError>` | 是 |
| get_menu_tree_by_user_id | `async fn(&self, user_id: i64) -> Result<Vec<SysMenuModel>, AppError>` | 否 |
| get_permissions_by_user_id | `async fn(&self, user_id: i64) -> Result<Vec<String>, AppError>` | 否 |

**业务规则实现点：**
- [ ] add_menu: parent_id 校验（非 0 时查父菜单存在）
- [ ] add_menu: perms 查重（C/F 类型且 perms 非空时）
- [ ] add_menu: 按 menu_type 分支处理字段（M/C/F）
- [ ] edit_menu: perms 变更时查重
- [ ] edit_menu: parent_id 校验 + 防环校验
- [ ] delete_menu: 子菜单校验（有子菜单拒绝）
- [ ] delete_menu: 菜单分配校验（已分配角色拒绝）
- [ ] delete_menu: 事务内软删除 + 清理 role_menu
- [ ] get_menu_tree_by_user_id: 超管短路
- [ ] get_menu_tree_by_user_id: 过滤 F 类型
- [ ] get_permissions_by_user_id: 超管短路返回 ["*:*:*"]
- [ ] get_permissions_by_user_id: 去重

**验收：**
- [ ] 所有方法实现完成
- [ ] 树形组装使用 `utils::tree::build_tree`
- [ ] 超管短路逻辑正确

---

### T06 更新 service/mod.rs 模块声明

**文件：** `src/service/mod.rs`

**交付物：**

```rust
//! 业务逻辑层（Service Layer）
//!
//! 职责：封装业务逻辑，调用 Repository 层
//! 依赖方向：Handler → Service → Repository → SeaORM
//!
//! 模块组织：
//! - sys_user_service: 用户业务
//! - sys_role_service: 角色业务
//! - sys_menu_service: 菜单业务

pub mod sys_user_service;
pub mod sys_role_service;
pub mod sys_menu_service;

pub use sys_user_service::SysUserService;
pub use sys_role_service::SysRoleService;
pub use sys_menu_service::SysMenuService;
```

**验收：**
- [ ] 模块声明完整
- [ ] re-export Service 结构体

---

### T07 编译验证 cargo check

**命令：** `cargo check`

**验收：**
- [ ] 编译通过，0 error
- [ ] 无 warning（或 warning 可解释）

---

### T08 单元测试编写

**文件：** 各 service 文件内 `#[cfg(test)] mod tests`

**测试用例：**
- [ ] 密码加密验证（已有 `utils::password` 测试，扩展覆盖）
- [ ] 树形组装测试（构造扁平列表 → 验证树结构）
- [ ] DTO 校验测试（garde 注解触发）
- [ ] 超管保护逻辑测试

**验收：**
- [ ] `cargo test` 通过

---

### T09 前端接口契约对齐自查

**检查项：**
- [ ] 用户模块返回字段对齐 `ruoyi-vue3-ts/src/types/api/system/user.ts`
- [ ] 角色模块返回字段对齐 `ruoyi-vue3-ts/src/types/api/system/role.ts`
- [ ] 菜单模块返回字段对齐 `ruoyi-vue3-ts/src/types/api/system/menu.ts`
- [ ] 分页响应对齐 `TableDataInfo`
- [ ] 普通响应对齐 `AjaxResult`（Service 层不返回 AjaxResult，由 Handler 包装）
- [ ] DTO 字段驼峰映射对齐

**验收：**
- [ ] 字段对齐报告输出
