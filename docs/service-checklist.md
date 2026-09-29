# Service 层验收清单（service-checklist.md）

> **阶段：** 第三阶段「用户/角色/菜单 Service 层业务实现」
> **项目：** stepby-axum
> **配套文档：** [service-spec.md](./service-spec.md)、[service-tasks.md](./service-tasks.md)

---

## 1. 架构合规性验收

### 1.1 分层独立性

- [ ] Service 层不依赖 `axum` / `tower` / `tower-http` 任何 Web 框架类型
- [ ] Service 层不依赖 `http` / `hyper` 类型
- [ ] Service 方法返回 `Result<T, AppError>`，不返回 `axum::response::Response`
- [ ] Service 层不直接操作 HTTP 请求/响应（不解析 body、不设置 header）
- [ ] Service 层通过 Repository 操作数据库，不直接调用 `E::find()`（除 Service 内部跨 Repository 的辅助查询）

### 1.2 模块组织

- [ ] `src/service/mod.rs` 声明 3 个 service 模块
- [ ] `src/service/sys_user_service.rs` 存在
- [ ] `src/service/sys_role_service.rs` 存在
- [ ] `src/service/sys_menu_service.rs` 存在
- [ ] 每个文件内 DTO 与 Service 共存（不过度拆分）

### 1.3 依赖方向

- [ ] Service → Repository（单向依赖）
- [ ] Service 不被 Repository 引用
- [ ] Service 不被 Entity 引用

---

## 2. 事务控制验收

### 2.1 事务使用正确性

- [ ] 多表操作使用 `db.transaction(|txn| async { ... }.boxed())`
- [ ] 事务闭包内所有 DB 操作绑定到 `txn` 连接
- [ ] 事务闭包内不使用外部 `self.db` 连接（通过 Repository 的 `db()` 获取的连接不参与事务）
- [ ] 事务闭包内使用 SeaORM 原生 API（`Entity::find().filter(...).one(&txn)`）而非 Repository 方法
- [ ] 不存在 `commit()` 后 `rollback()` 的矛盾代码
- [ ] 闭包返回 `Err` 时 SeaORM 自动回滚事务

### 2.2 事务覆盖范围

- [ ] `add_user`：插用户 + 批量插 user_role 在同一事务
- [ ] `edit_user`：更新用户 + 重绑 user_role 在同一事务
- [ ] `delete_user`：软删除用户 + 清理 user_role 在同一事务
- [ ] `assign_user_roles`：清空旧关联 + 插入新关联在同一事务
- [ ] `add_role`：插角色 + 批量插 role_menu 在同一事务
- [ ] `edit_role`：更新角色 + 重绑 role_menu 在同一事务
- [ ] `delete_role`：软删除角色 + 清理 role_menu + 清理 user_role 在同一事务
- [ ] `assign_role_menus`：清空旧关联 + 插入新关联在同一事务
- [ ] `delete_menu`：软删除菜单 + 清理 role_menu 在同一事务

---

## 3. 参数校验验收

### 3.1 garde 注解

- [ ] 所有 AddDto/EditDto 派生 `Validate`
- [ ] 字符串长度校验（user_name 2-30, role_key 2-100 等）
- [ ] 邮箱格式校验（`#[garde(email)]`）
- [ ] 手机号正则校验（`#[garde(regex)]`）
- [ ] 数值范围校验（role_sort 0-999）
- [ ] Service 方法入口调用 `dto.validate()?`

### 3.2 业务规则校验

- [ ] 用户名查重（add_user）
- [ ] role_key 查重（add_role / edit_role 变更时）
- [ ] perms 查重（add_menu / edit_menu 变更时）
- [ ] 父菜单存在性校验（add_menu / edit_menu）
- [ ] 菜单防环校验（edit_menu，parent_id 不能是自己或后代）
- [ ] 子菜单存在性校验（delete_menu）
- [ ] 菜单已分配角色校验（delete_menu）
- [ ] 角色已分配用户校验（delete_role）

---

## 4. 密码安全验收

- [ ] 盐值为 `"stepby_admin"`（非 `"salvo_admin"`）
- [ ] migration 初始用户密码使用新盐值生成（admin123 + stepby_admin）
- [ ] 新增用户：明文密码经 `encrypt_password` 加密后入库
- [ ] 重置密码：明文密码经 `encrypt_password` 加密后入库
- [ ] 个人改密：`verify_password` 校验旧密码
- [ ] 个人改密：新密码经 `encrypt_password` 加密后入库
- [ ] 个人改密：新旧密码不相同校验
- [ ] 密码不在任何返回值中输出（DTO 和 Vo 不含 password 字段，或序列化时 skip）
- [ ] Service 层不硬编码盐值（使用 `constants::PASSWORD_SALT`）

---

## 5. 超管保护验收

- [ ] `delete_user`：user_id==1 拒绝删除
- [ ] `update_user_status`：user_id==1 且 status=='1' 拒绝停用
- [ ] `delete_role`：role_id==1 拒绝删除
- [ ] `update_role_status`：role_id==1 且 status=='1' 拒绝停用
- [ ] `edit_role`：role_id==1 拒绝修改 role_key

---

## 6. 软删除验收

- [ ] `delete_user`：设置 `del_flag='2'`，非物理删除
- [ ] `delete_role`：设置 `del_flag='2'`，非物理删除
- [ ] `delete_menu`：设置 `del_flag='2'`，非物理删除
- [ ] 所有查询方法过滤 `del_flag='0'`（除 `get_user_by_username` 登录场景）

---

## 7. 级联清理验收

- [ ] `delete_user`：清理 sys_user_role 关联
- [ ] `delete_role`：清理 sys_role_menu 关联
- [ ] `delete_role`：清理 sys_user_role 关联
- [ ] `delete_menu`：清理 sys_role_menu 关联
- [ ] `edit_user`（role_ids=Some）：先删后插 user_role
- [ ] `edit_role`（menu_ids=Some）：先删后插 role_menu
- [ ] `assign_user_roles`：先删后插 user_role
- [ ] `assign_role_menus`：先删后插 role_menu

---

## 8. 树形组装验收

- [ ] `SysMenuModel` 实现 `TreeNode` trait
- [ ] `SysMenuModel` 新增 `children: Option<Vec<SysMenuModel>>` 字段（`#[sea_orm(ignore)]`）
- [ ] `get_menu_tree` 使用 `utils::tree::build_tree`
- [ ] `get_menu_tree_by_user_id` 使用 `utils::tree::build_tree`
- [ ] `get_menu_tree_by_user_id` 过滤 `menu_type != 'F'`
- [ ] 不存在递归 clone 整个数组的 O(n²) 写法

---

## 9. 超管短路验收

- [ ] `get_menu_tree_by_user_id`：超管返回所有未删除菜单
- [ ] `get_permissions_by_user_id`：超管返回 `["*:*:*"]`
- [ ] 超管判定基于 `role_key == "admin"`（不硬编码 user_id==1）

---

## 10. menu_type 分支处理验收

- [ ] add_menu (M 目录)：perms 置空，component 置空
- [ ] add_menu (C 菜单)：保留 path/component/query/perms
- [ ] add_menu (F 按钮)：path 置空，component 置空，保留 perms
- [ ] edit_menu 同 add_menu 分支逻辑

---

## 11. 防环校验验收

- [ ] edit_menu: parent_id == menu_id 时拒绝
- [ ] edit_menu: parent_id 是 menu_id 的后代节点时拒绝
- [ ] 防环校验算法正确（向上遍历祖先链，非向下遍历后代树）

---

## 12. 错误处理验收

- [ ] 所有 Service 方法返回 `Result<T, AppError>`
- [ ] 参数校验失败返回 `AppError::bad_request`
- [ ] 资源不存在返回 `AppError::not_found`
- [ ] DbErr 自动转换为 AppError（`From<DbErr> for AppError`）
- [ ] 事务闭包内 DbErr 触发自动回滚
- [ ] 无 `unwrap()` / `expect()` 调用（测试代码除外）

---

## 13. 依赖验收

- [ ] Cargo.toml 包含 `futures = "0.3"`
- [ ] Cargo.toml 包含 `regex = "1"`
- [ ] Cargo.toml 包含 `once_cell = "1"`
- [ ] 事务闭包使用 `futures::future::FutureExt::boxed`
- [ ] 手机号校验使用 `regex` + `once_cell` 定义的全局正则

---

## 14. 编译与测试验收

- [ ] `cargo check` 通过，0 error
- [ ] `cargo build` 通过
- [ ] `cargo test` 通过
- [ ] `cargo clippy` 无严重 warning

---

## 15. 前端接口契约对齐验收

### 15.1 用户模块

- [ ] `UserVo` 字段对齐 `SysUser` TS 接口
- [ ] `UserVo` 包含 `userId`/`deptId`/`userName`/`nickName`/`email`/`phonenumber`/`sex`/`avatar`/`status`/`roleIds`
- [ ] `UserVo` 继承 BaseEntity 字段（`createBy`/`createTime`/`updateBy`/`updateTime`/`remark`）
- [ ] 不返回 `password` 字段

### 15.2 角色模块

- [ ] `RoleVo` 字段对齐 `SysRole` TS 接口
- [ ] `RoleVo` 包含 `roleId`/`roleName`/`roleKey`/`roleSort`/`dataScope`/`menuCheckStrictly`/`deptCheckStrictly`/`status`/`menuIds`

### 15.3 菜单模块

- [ ] `SysMenuModel` 序列化字段对齐 `SysMenu` TS 接口
- [ ] 包含 `menuId`/`parentId`/`menuName`/`orderNum`/`path`/`component`/`query`/`routeName`/`perms`/`icon`/`isFrame`/`isCache`/`menuType`/`visible`/`status`/`children`

### 15.4 序列化映射

- [ ] 所有 DTO 添加 `#[serde(rename_all = "camelCase")]`
- [ ] 所有 Vo/Model 的 `#[serde(rename_all = "camelCase")]` 生效
- [ ] `children` 字段为空时不序列化（`#[serde(skip_serializing_if = "Option::is_none")]`）

---

## 16. 关键缺陷修复对照

| 旧实现缺陷 | 本项目修复 | 验收 |
|---------------------|----------|------|
| 事务形同虚设 | 使用 `TransactionTrait` 真事务 | [ ] |
| 删除用户未清理 user_role | 事务内清理 | [ ] |
| 删除角色未清理 user_role | 事务内清理 | [ ] |
| 删除菜单未清理 role_menu | 事务内清理 | [ ] |
| 无 role_key 查重 | add_role/edit_role 校验 | [ ] |
| 无 perms 查重 | add_menu/edit_menu 校验 | [ ] |
| 无子菜单校验 | delete_menu 校验 | [ ] |
| 无菜单分配校验 | delete_menu 校验 | [ ] |
| 无角色分配用户校验 | delete_role 校验 | [ ] |
| 无超管保护 | 多处超管保护 | [ ] |
| 树形 O(n²) | `build_tree` 单次遍历 | [ ] |
| SQL 注入风险 | SeaORM 参数化查询 | [ ] |
| `unwrap()` panic | `?` 错误传播 | [ ] |

---

## 17. 文档一致性验收

- [ ] `service-spec.md` 业务逻辑设计与实现一致
- [ ] `service-tasks.md` 任务全部完成
- [ ] `service-checklist.md` 验收项全部通过
- [ ] `service/mod.rs` 模块注释更新
- [ ] 无残留 TODO 注释（除明确标注的后续阶段任务）
