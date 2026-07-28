# axum-backend 测试指引文档

> 版本：v0.2.0 | 更新日期：2026-07-24

## 目录

1. [测试体系总览](#1-测试体系总览)
2. [环境准备](#2-环境准备)
3. [单元测试](#3-单元测试)
4. [TypeScript 类型导出测试](#4-typescript-类型导出测试)
5. [集成测试](#5-集成测试)
6. [API 接口测试](#6-api-接口测试)
7. [安全测试](#7-安全测试)
8. [性能测试](#8-性能测试)
9. [CI/CD 集成](#9-cicd-集成)
10. [测试用例清单](#10-测试用例清单)

---

## 1. 测试体系总览

本项目采用多层测试策略：

```
┌─────────────────────────────────────────────────┐
│  L1  单元测试（cargo test）                       │
│  ├── 密码工具测试（Argon2 / MD5 升级）             │
│  ├── IP 归属地测试（内网/公网/mmdb 降级）          │
│  ├── 菜单路由转换测试（12 个场景）                 │
│  ├── 定时任务测试（cron 解析 / 状态切换）          │
│  └── ts-rs 类型导出测试（19 个 struct）            │
├─────────────────────────────────────────────────┤
│  L2  API 接口测试（curl / Postman / Swagger）     │
│  ├── 认证模块（登录 / 登出 / 验证码）              │
│  ├── 用户管理 CRUD                                │
│  ├── 角色管理 CRUD                                │
│  ├── 菜单管理 CRUD                                │
│  └── 监控模块（在线用户 / 缓存 / 服务器）          │
├─────────────────────────────────────────────────┤
│  L3  安全测试                                     │
│  ├── 认证绕过 / 越权访问                           │
│  ├── SQL 注入 / XSS                               │
│  ├── 暴力破解防护                                  │
│  └── 文件上传安全                                 │
├─────────────────────────────────────────────────┤
│  L4  性能测试                                     │
│  └── 并发 / 响应时间 / 资源占用                    │
└─────────────────────────────────────────────────┘
```

当前测试统计：
- **单元测试**：约 120 个（实际数量随开发迭代变化，以 `cargo test` 输出为准）
- **ts-rs 导出测试**：19 个
- **集成测试**：依赖外部服务（MySQL/Redis），需手动执行

---

## 2. 环境准备

### 2.1 开发环境

```bash
# 安装 Rust 工具链
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source $HOME/.cargo/env

# 验证
rustc --version  # 1.96+
cargo --version
```

### 2.2 依赖服务

单元测试**不需要**外部服务（MySQL/Redis）。以下服务仅在集成测试/API 测试时需要：

```bash
# MySQL 8.0
sudo systemctl start mysql

# Redis 7.0
sudo systemctl start redis-server
```

### 2.3 配置

```bash
# 复制配置模板
cp config/config.toml.example config/config.toml

# 编辑 config.toml，填入真实数据库和 Redis 连接信息
# 或创建 .env 文件
cat > .env << EOF
DATABASE_URL=mysql://yebot:password@127.0.0.1:3306/yebot
REDIS_URL=redis://:password@127.0.0.1:6379/0
JWT_SECRET=test_secret_at_least_32_characters_long!!
EOF
```

PowerShell 等价命令：

```powershell
# PowerShell 等价命令
@"
DATABASE_URL=sqlite://./data/yebot.db?mode=rwc
REDIS_URL=redis://127.0.0.1:6379
JWT_SECRET=change_me_in_production
RUST_LOG=info
"@ | Set-Content -Path .env -Encoding UTF8
```

### 2.4 数据库初始化

```bash
export DATABASE_URL="mysql://yebot:password@127.0.0.1:3306/yebot"
cd migration && cargo run && cd ..
```

---

## 3. 单元测试

### 3.1 运行全部单元测试

```bash
cargo test
```

期望输出：
```
running N tests（N 为当前测试数）
test utils::ip_location::tests::test_is_private_ip_v4 ... ok
test utils::ip_location::tests::test_is_not_private_ip_v4 ... ok
test utils::ip_location::tests::test_is_private_ip_v6 ... ok
test utils::ip_location::tests::test_locate_with_missing_file ... ok
test utils::ip_location::tests::test_locate_with_real_mmdb ... ok
test utils::password::tests::test_encrypt_and_verify_argon2 ... ok
test utils::password::tests::test_verify_empty_hash ... ok
test utils::password::tests::test_verify_legacy_md5 ... ok
test utils::password::tests::test_password_complexity_valid ... ok
test utils::password::tests::test_password_complexity_weak_blacklist ... ok
...（共 N 个测试，N 为当前测试数）
test result: ok. N passed; 0 failed; 0 ignored（N 为当前测试数）
```

### 3.2 运行指定模块测试

```bash
# 密码工具测试
cargo test password

# IP 归属地测试
cargo test ip_location

# 菜单路由转换测试
cargo test menu_to_router

# 定时任务测试
cargo test sys_job

# 调度器测试
cargo test scheduler
```

### 3.3 显示测试输出

```bash
cargo test -- --nocapture
```

### 3.4 测试覆盖率（可选）

```bash
# 安装 tarpaulin
cargo install cargo-tarpaulin

# 生成覆盖率报告
cargo tarpaulin --out Html
```

### 3.5 单元测试清单

| 模块 | 测试数 | 说明 |
|------|--------|------|
| `utils::password` | 8 | Argon2 加密验证、空哈希验证、MD5 旧哈希识别、密码复杂度校验、弱口令黑名单、强度评分 |
| `utils::ip_location` | 6 | 内网 IP 判断（v4/v6）、公网 IP 判断、mmdb 缺失降级、真实 mmdb 查询 |
| `utils::ip` | 4 | 可信代理 XFF 提取、CIDR 匹配、untrusted peer 忽略 |
| `utils::sanitize` | 5 | oper_log 响应体脱敏（token/password/phone/email 等 10 字段掩码） |
| `utils::crypto` | 5 | 加密/解密工具 |
| `utils::captcha` | 2 | 验证码生成 |
| `utils::xdb_reader` | 6 | ip2region xdb 离线库读取 |
| `service::auth_service` | 21 | 菜单转路由（各种 menu_type/visible/is_frame 组合）、登录限流、验证码校验 |
| `service::sys_job_service` | 3 | cron 表达式解析、任务状态切换 |
| `service::ip_location_service` | 3 | IP 归属地服务降级 |
| `middleware::oper_log` | 21 | 操作日志脱敏、UTF-8 安全截断（safe_truncate）、模块推断 |
| `middleware::rate_limit` | 3 | 限流中间件 |
| `middleware::idempotency` | 4 | 幂等性中间件 |
| `middleware::security_headers` | 4 | 安全响应头校验 |
| `scheduler::registry` | 3 | 调度器任务注册/移除 |
| ts-rs export_bindings | 19 | 13 个 entity + 6 个 Vo 的 TypeScript 导出 |
| 其他 | 2 | datetime 序列化等 |
| **合计** | **N**（以 `cargo test` 输出为准） | |

---

## 4. TypeScript 类型导出测试

### 4.1 运行 ts-rs 导出

```bash
cargo test --lib -- "export_bindings"
```

### 4.2 导出目录

导出的 `.ts` 文件位于 `../yebot-ui/src/types/api/generated/`：

```
generated/
├── JobVo.ts
├── ProfileVo.ts
├── RoleVo.ts
├── SysConfig.ts
├── SysDept.ts
├── SysDictData.ts
├── SysDictType.ts
├── SysJob.ts
├── SysJobLog.ts
├── SysLogininfor.ts
├── SysMenu.ts
├── SysNotice.ts
├── SysOperLog.ts
├── SysPost.ts
├── SysRole.ts
├── SysUser.ts
├── UserAuthRoleVo.ts
├── UserFormVo.ts
└── UserVo.ts
```

### 4.3 配置说明

`.cargo/config.toml`：
```toml
[env]
TS_RS_EXPORT_DIR = { value = "../yebot-ui/src/types/api/generated", relative = true }
TS_RS_LARGE_INT = "number"  # i64 映射为 number 而非 string
```

### 4.4 验证导出结果

```bash
# 检查文件是否生成
ls -la ../yebot-ui/src/types/api/generated/

# 验证类型内容（示例）
cat ../yebot-ui/src/types/api/generated/SysUser.ts
# 期望输出：
# export type Model = { userId: number, deptId: number | null, ... }
```

### 4.5 CI 校验

在 CI 中添加类型导出一致性检查：

```bash
# 导出类型
cargo test --lib -- "export_bindings"

# 检查是否有未提交的变更（类型与代码不一致时失败）
git diff --exit-code ../yebot-ui/src/types/api/generated/
```

---

## 5. 集成测试

### 5.1 编译检查

```bash
# 编译检查（不运行）
cargo check

# Clippy 代码质量检查
cargo clippy --all-targets
```

期望：无错误，无项目代码警告（仅可能存在第三方依赖 `error2` 的 future-incompat 提醒，与项目代码无关）。

### 5.2 Release 构建测试

```bash
cargo build --release
```

### 5.3 数据库迁移测试

```bash
export DATABASE_URL="mysql://yebot:password@127.0.0.1:3306/yebot"
cd migration && cargo run && cd ..
```

验证：
```bash
mysql -u yebot -p yebot -e "SHOW TABLES;"
# 期望输出 24 张表（23 张业务表 + seaql_migrations）
# 业务表：sys_config, sys_dept, sys_dict_data, sys_dict_type, sys_job, sys_job_log,
#         sys_logininfor, sys_menu, sys_notice, sys_notice_read, sys_oper_log, sys_post,
#         sys_rate_limit, sys_role, sys_role_dept, sys_role_menu, sys_task, sys_user,
#         sys_user_post, sys_user_role, gen_table, gen_table_column, sys_backup_log
```

---

## 6. API 接口测试

### 6.1 启动服务

```bash
# 确保 MySQL 和 Redis 已启动
# 确保 .env 或环境变量已配置
cargo run --release
```

### 6.2 健康检查

```bash
curl http://localhost:8080/health
# 期望: {"code":200,"msg":"操作成功","data":"ok"}
```

### 6.3 Swagger UI 测试

开发环境（`docs_enabled = true`）访问：
- Swagger UI: http://localhost:8080/swagger-ui
- OpenAPI JSON: http://localhost:8080/api-docs/openapi.json

### 6.4 认证流程测试

**1. 获取验证码**

```bash
curl http://localhost:8080/captchaImage
```

期望响应：
```json
{
  "code": 200,
  "msg": "操作成功",
  "captchaEnabled": true,
  "img": "<base64 编码的验证码图片>",
  "uuid": "<验证码会话 UUID>"
}
```

**2. 登录**

```bash
# 需要从验证码图片中识别出验证码字符
curl -X POST http://localhost:8080/login \
  -H "Content-Type: application/json" \
  -d '{
    "username": "admin",
    "password": "admin123",
    "code": "<验证码>",
    "uuid": "<上一步的 uuid>"
  }'
```

期望响应：
```json
{
  "code": 200,
  "msg": "操作成功",
  "token": "<JWT token>"
}
```

**3. 获取用户信息**

```bash
TOKEN="<上一步获取的 token>"
curl http://localhost:8080/getInfo \
  -H "Authorization: Bearer $TOKEN"
```

期望响应包含 `user`、`roles`、`permissions` 字段。

**4. 登出**

```bash
curl -X POST http://localhost:8080/logout \
  -H "Authorization: Bearer $TOKEN"
```

### 6.5 CRUD 接口测试

以下测试均需在 Header 中携带 `Authorization: Bearer <token>`。

**用户管理**

```bash
# 分页查询用户
curl "http://localhost:8080/system/user/list?pageNum=1&pageSize=10" \
  -H "Authorization: Bearer $TOKEN"

# 查询用户详情
curl http://localhost:8080/system/user/1 \
  -H "Authorization: Bearer $TOKEN"

# 新增用户
curl -X POST http://localhost:8080/system/user \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "userName": "testuser",
    "nickName": "测试用户",
    "password": "test123456",
    "deptId": 100
  }'

# 修改用户
curl -X PUT http://localhost:8080/system/user \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "userId": 2,
    "nickName": "修改后的昵称"
  }'

# 删除用户
curl -X DELETE http://localhost:8080/system/user/2 \
  -H "Authorization: Bearer $TOKEN"
```

**角色管理**

```bash
# 分页查询角色
curl "http://localhost:8080/system/role/list?pageNum=1&pageSize=10" \
  -H "Authorization: Bearer $TOKEN"

# 查询角色详情（含 menuIds）
curl http://localhost:8080/system/role/1 \
  -H "Authorization: Bearer $TOKEN"
```

**部门管理**

```bash
# 部门列表
curl http://localhost:8080/system/dept/list \
  -H "Authorization: Bearer $TOKEN"

# 部门下拉树
curl http://localhost:8080/system/dept/treeselect \
  -H "Authorization: Bearer $TOKEN"
```

**字典管理**

```bash
# 按字典类型查询字典数据
curl http://localhost:8080/system/dict/data/type/sys_user_sex \
  -H "Authorization: Bearer $TOKEN"
```

**监控模块**

```bash
# 在线用户列表
curl "http://localhost:8080/monitor/online/list" \
  -H "Authorization: Bearer $TOKEN"

# 缓存概览
curl http://localhost:8080/monitor/cache \
  -H "Authorization: Bearer $TOKEN"

# 服务器信息
curl http://localhost:8080/monitor/server \
  -H "Authorization: Bearer $TOKEN"
```

### 6.6 导出接口测试

```bash
# 导出用户列表（注意 Content-Type 为 form-urlencoded）
curl -X POST http://localhost:8080/system/user/export \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "pageNum=1&pageSize=10" \
  -o users.xlsx
```

### 6.7 使用 Postman 集合

1. 导入 OpenAPI JSON：`http://localhost:8080/api-docs/openapi.json`
2. 设置环境变量 `baseUrl = http://localhost:8080`
3. 设置环境变量 `token = <登录获取的 JWT>`

---

## 7. 安全测试

### 7.1 认证绕过测试

**无 Token 访问受保护接口**

```bash
curl http://localhost:8080/getInfo
# 期望: 401 {"code":401,"msg":"请求未携带 token，请重新登录"}
```

**无效 Token 访问**

```bash
curl http://localhost:8080/getInfo -H "Authorization: Bearer invalid_token"
# 期望: 401 token 无效
```

**过期 Token 访问**

等待 JWT 过期后访问，期望 401。

**登出后 Token 访问**

```bash
# 登录获取 token
# 登出
# 使用原 token 访问
curl http://localhost:8080/getInfo -H "Authorization: Bearer $TOKEN"
# 期望: 401 "会话已注销，请重新登录"
```

### 7.2 越权访问测试

**普通用户访问管理接口**

使用非超级管理员账号的 token 访问用户管理接口，期望 403。

**操作超级管理员账号**

```bash
# 尝试删除 admin（user_id=1）
curl -X DELETE http://localhost:8080/system/user/1 \
  -H "Authorization: Bearer $TOKEN"
# 期望: 400 "不允许删除超级管理员"
```

### 7.3 暴力破解防护测试

**连续错误登录**

```bash
# 连续 5 次错误密码登录
for i in $(seq 1 5); do
  curl -X POST http://localhost:8080/login \
    -H "Content-Type: application/json" \
    -d '{"username":"admin","password":"wrong","code":"x","uuid":"x"}'
done
# 第 6 次期望: "密码错误次数过多，请 5 分钟后再试"
```

**IP 频率限制**

同一 IP 1 分钟内超过 10 次登录请求，期望返回 "访问频率过高，请稍后再试"。

### 7.4 SQL 注入测试

```bash
# 用户名注入尝试
curl "http://localhost:8080/system/user/list?userName=admin'%20OR%201=1--" \
  -H "Authorization: Bearer $TOKEN"
# 期望: 正常返回空列表或模糊匹配结果，不返回全部用户

# LIKE 查询注入尝试
curl "http://localhost:8080/system/user/list?userName=%25%25%25" \
  -H "Authorization: Bearer $TOKEN"
# 期望: 已转义 % 字符，不匹配所有记录
```

### 7.5 文件上传安全测试

**伪造文件扩展名**

```bash
# 尝试上传 .exe 文件但声明为 .png
curl -X POST http://localhost:8080/system/user/profile/avatar \
  -H "Authorization: Bearer $TOKEN" \
  -F "avatarfile=@malicious.exe;filename=test.png"
# 期望: 400 "无法识别的图片格式"
```

**超大文件**

```bash
# 上传超过 5MB 的文件
# 期望: 400 "头像大小不能超过 5MB"
```

### 7.6 缓存安全测试

**尝试清除非白名单缓存**

```bash
curl -X DELETE http://localhost:8080/monitor/cache/clearCacheName/blacklist: \
  -H "Authorization: Bearer $TOKEN"
# 期望: 400 "不允许操作缓存前缀"
```

**尝试通配符注入**

```bash
curl http://localhost:8080/monitor/cache/getKeys/* \
  -H "Authorization: Bearer $TOKEN"
# 期望: 400 "缓存名称不允许包含通配符"
```

---

## 8. 性能测试

### 8.1 基准测试工具

使用 `wrk` 或 `hey` 进行 HTTP 压力测试：

```bash
# 安装 wrk
sudo apt install wrk

# 或安装 hey
go install github.com/rakyll/hey@latest
```

### 8.2 基准测试场景

**健康检查（无鉴权）**

```bash
wrk -t4 -c100 -d30s http://localhost:8080/health
```

**用户列表查询（需鉴权）**

```bash
# 先获取 token
TOKEN=$(curl -s -X POST http://localhost:8080/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"admin123","code":"...","uuid":"..."}' \
  | jq -r '.token')

wrk -t4 -c100 -d30s \
  -H "Authorization: Bearer $TOKEN" \
  http://localhost:8080/system/user/list?pageNum=1&pageSize=10
```

### 8.3 性能基准参考

单实例（4C/4G）参考性能：

| 接口 | QPS | P99 延迟 |
|------|-----|---------|
| GET /health | 50000+ | < 5ms |
| GET /system/user/list | 2000+ | < 50ms |
| POST /login | 500+ | < 100ms |

### 8.4 资源监控

```bash
# 使用 monitor/server 接口查看服务器资源
curl http://localhost:8080/monitor/server \
  -H "Authorization: Bearer $TOKEN" | jq

# 关注字段：
# - cpu.used: CPU 使用率
# - mem.usage: 内存使用率
# - jvm.used: 进程内存（MB）
```

---

## 9. CI/CD 集成

### 9.1 GitHub Actions 示例

```yaml
name: CI

on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install Rust
        uses: dtolnay/rust-toolchain@stable
        with:
          components: clippy

      - name: Cache cargo
        uses: actions/cache@v4
        with:
          path: |
            ~/.cargo/registry
            ~/.cargo/git
            target
          key: ${{ runner.os }}-cargo-${{ hashFiles('**/Cargo.lock') }}

      - name: Check
        run: cargo check

      - name: Clippy
        run: cargo clippy --all-targets -- -D warnings

      - name: Test
        run: cargo test

      - name: Export TypeScript types
        run: cargo test --lib -- "export_bindings"

      - name: Check TS types unchanged
        run: git diff --exit-code ../yebot-ui/src/types/api/generated/

      - name: Build release
        run: cargo build --release
```

### 9.2 预提交钩子

`.git/hooks/pre-commit`：

```bash
#!/bin/sh
set -e

cargo check
cargo clippy --all-targets -- -D warnings
cargo test --lib

echo "All checks passed!"
```

```bash
chmod +x .git/hooks/pre-commit
```

---

## 10. 测试用例清单

### 10.1 认证模块

| 编号 | 测试场景 | 预期结果 | 优先级 |
|------|---------|---------|--------|
| AUTH-001 | 正确用户名密码 + 正确验证码登录 | 200 + token | P0 |
| AUTH-002 | 错误密码登录 | 500 "用户不存在/密码错误" | P0 |
| AUTH-003 | 错误验证码登录 | 500 "验证码错误" | P0 |
| AUTH-004 | 验证码重放攻击（同一 uuid 两次使用） | 第二次 500 "验证码已过期" | P0 |
| AUTH-005 | 登出后原 token 不可用 | 401 "会话已注销" | P0 |
| AUTH-006 | 无 Token 访问受保护接口 | 401 | P0 |
| AUTH-007 | 伪造 Token 访问 | 401 | P0 |
| AUTH-008 | 连续 5 次错误密码 | 第 6 次 "密码错误次数过多" | P1 |
| AUTH-009 | 同 IP 1 分钟 10 次登录 | 第 11 次 "访问频率过高" | P1 |
| AUTH-010 | Redis 不可用时登录 | 503 "认证服务暂时不可用" | P1 |

### 10.2 用户管理

| 编号 | 测试场景 | 预期结果 | 优先级 |
|------|---------|---------|--------|
| USER-001 | 分页查询用户列表 | 200 + 分页数据 | P0 |
| USER-002 | 查询用户详情 | 200 + UserFormVo | P0 |
| USER-003 | 新增用户 | 200 "新增成功" | P0 |
| USER-004 | 修改用户 | 200 "修改成功" | P0 |
| USER-005 | 删除普通用户 | 200 "删除成功" | P0 |
| USER-006 | 删除超级管理员（id=1） | 400 "不允许删除" | P0 |
| USER-007 | 修改个人信息 | 200 "修改成功" | P1 |
| USER-008 | 修改个人密码 | 200 "密码修改成功" | P1 |
| USER-009 | 头像上传（PNG） | 200 + imgUrl | P1 |
| USER-010 | 头像上传（伪造扩展名） | 400 "无法识别的图片格式" | P1 |
| USER-011 | 用户名 SQL 注入 | 正常返回，无注入 | P0 |
| USER-012 | 分页 size > 100 | 限制为 100 | P1 |

### 10.3 角色管理

| 编号 | 测试场景 | 预期结果 | 优先级 |
|------|---------|---------|--------|
| ROLE-001 | 分页查询角色 | 200 + 分页数据 | P0 |
| ROLE-002 | 新增角色 | 200 | P0 |
| ROLE-003 | 修改角色 | 200 | P0 |
| ROLE-004 | 删除角色 | 200 | P0 |
| ROLE-005 | 角色名称重复 | 400 "角色名称已存在" | P1 |
| ROLE-006 | 分配用户角色 | 200 | P1 |
| ROLE-007 | 角色部门树 | 200 + checkedKeys + depts | P1 |

### 10.4 菜单管理

| 编号 | 测试场景 | 预期结果 | 优先级 |
|------|---------|---------|--------|
| MENU-001 | 菜单列表 | 200 + 扁平列表 | P0 |
| MENU-002 | 菜单下拉树 | 200 + TreeSelect | P0 |
| MENU-003 | 新增菜单 | 200 | P0 |
| MENU-004 | 删除菜单 | 200 | P0 |
| MENU-005 | 角色菜单树（含 checkedKeys） | 200 | P1 |

### 10.5 监控模块

| 编号 | 测试场景 | 预期结果 | 优先级 |
|------|---------|---------|--------|
| MON-001 | 在线用户列表 | 200 + 列表 | P1 |
| MON-002 | 缓存概览 | 200 + info + dbSize | P1 |
| MON-003 | 缓存键名列表 | 200 + 分组列表 | P2 |
| MON-004 | 清除指定缓存（白名单内） | 200 | P1 |
| MON-005 | 清除非白名单缓存 | 400 | P1 |
| MON-006 | 服务器信息 | 200 + CPU/内存/磁盘 | P1 |

### 10.6 字典管理

| 编号 | 测试场景 | 预期结果 | 优先级 |
|------|---------|---------|--------|
| DICT-001 | 字典类型列表 | 200 + 分页数据 | P0 |
| DICT-002 | 按类型查字典数据 | 200 + 列表 | P0 |
| DICT-003 | 新增字典类型 | 200 | P0 |
| DICT-004 | 刷新字典缓存 | 200 | P1 |

### 10.7 日志模块

| 编号 | 测试场景 | 预期结果 | 优先级 |
|------|---------|---------|--------|
| LOG-001 | 操作日志列表 | 200 + 分页数据 | P1 |
| LOG-002 | 登录日志列表 | 200 + 分页数据 | P1 |
| LOG-003 | 清空操作日志 | 200 | P2 |
| LOG-004 | 解锁用户 | 200 | P2 |
| LOG-005 | 写操作自动记录日志 | sys_oper_log 有新记录 | P1 |

### 10.8 安全测试

| 编号 | 测试场景 | 预期结果 | 优先级 |
|------|---------|---------|--------|
| SEC-001 | 越权访问（无权限） | 403 | P0 |
| SEC-002 | SQL 注入 | 无注入 | P0 |
| SEC-003 | XSS（输入特殊字符） | 正常转义 | P0 |
| SEC-004 | LIKE 查询通配符注入 | 已转义 | P0 |
| SEC-005 | 文件上传伪造 | 400 | P0 |
| SEC-006 | CORS 跨域 | 非白名单域拒绝 | P1 |
| SEC-007 | 生产环境关闭 Swagger | 404 | P1 |

### 10.9 N+1 查询优化（v2.6 第125轮）

> 后端批量操作接口原先在循环内逐条查询数据库（典型 N+1），已改为单次批量查询。相关仓库方法：`find_by_ids` / `find_by_names` / `find_columns_by_table_ids`。

| 编号 | 测试场景 | 优化前 | 优化后 | 优先级 |
|------|---------|--------|--------|--------|
| NPLUS-001 | `gen_table_service.delete_tables` 批量删除 | 循环 `find_by_id` N 次查询 | 单次 `find_by_ids` 批量查询 | P2 |
| NPLUS-002 | `gen_table_service.batch_gen_code` 批量生成代码 | 循环按表名查 + 循环查列 | `find_by_names` + `find_columns_by_table_ids` 各 1 次 | P2 |
| NPLUS-003 | `sys_rate_limit_service.remove` 批量删除 | 循环 `find_by_id` N 次查询 | 单次 `find_by_ids` 批量查询 | P2 |

**验证方式**：开启 SQL 日志（`RUST_LOG=sqlx=trace` 或 SeaORM `stmt` 层），执行批量删除/生成操作，确认 SELECT 语句数量由 O(N) 降为 O(1)。

### 10.10 E2E 端到端测试套件（45 项功能）

> 测试脚本：`tests/main.mjs`（Playwright 驱动，覆盖前端 + 后端 + 嵌入式模式）

#### 运行方式

```powershell
# PowerShell 环境变量设置
$env:YEBOT_TEST_USER='admin'
$env:YEBOT_TEST_PASS='admin123'

# 全量测试（45 项功能）
node tests/main.mjs

# 单项测试（如 feature 44）
node tests/main.mjs --feature=44

# 无头模式
node tests/main.mjs --headless
```

#### 关键测试项说明

| 功能 | 测试内容 | 验证方式 |
|------|---------|---------|
| 17 | 备份写权限收紧（ry 角色） | 恢复按钮隐藏 + API 403 |
| 18 | IP 库管理只读权限（ry 角色） | 写按钮隐藏 + GET 200 / PUT·POST 403 |
| 31 | 备份恢复权限 system:backup:edit | ry 调用 POST /system/backup 返回 403 |
| 37 | U1 Dashboard 跳转操作日志路由 | 验证跳转到 `/system/log/operlog` |
| 43 | operlog title i18n 本地化 | `formatModuleTitle` 剥离 `module.` 前缀后 `te()` 回退 |
| 44 | 提交按钮 `:loading` 绑定 | 源码检查 `submitLoading` ref + `finally` 重置模式 |

#### 测试脚本注意事项

- **PowerShell heredoc 限制**：PowerShell 不支持 `<<EOF` 语法，`git commit` 多行消息应使用 `-F 文件` 或单行 `-m`
- **并行测试**：`--feature=N` 可并行运行多项，但 7+ 浏览器并行可能导致 DOM 交互测试（如 feature 44 对话框打开）超时
- **源码检查优先**：UI 交互测试（对话框打开/按钮点击）受 tree-sidebar 布局遮挡、API 响应延迟等因素影响，源码检查（`page.evaluate` + `fetch(script.src)`）更可靠
- **嵌入式前端**：测试默认使用 `http://localhost:8080`（嵌入式模式），需确保 `frontend-dist` 已同步最新构建

### 10.11 深度 E2E 测试套件（282 项，14 模块）

> 测试脚本：`tests/deep-e2e.mjs`（Playwright 驱动，深度覆盖每个前端界面的每个功能）

#### 运行方式

```powershell
# PowerShell 环境变量设置
$env:YEBOT_TEST_USER='admin'
$env:YEBOT_TEST_PASS='admin123'
$env:YEBOT_BASE_URL='http://localhost:8080'

# 全量深度测试（282 项，14 模块）
node tests/deep-e2e.mjs --headless

# 单模块测试（如模块 9：权限隔离）
node tests/deep-e2e.mjs --headless --feature=9

# 有头模式（可视化调试，默认）
node tests/deep-e2e.mjs
```

#### 14 个测试模块说明

| 模块 | 名称 | 测试项数 | 覆盖内容 |
|------|------|---------|---------|
| M1 | 系统管理页面深度测试 | 73 | 用户/角色/菜单/部门/岗位/字典/参数/通知中心/通知公告/日志 CRUD、搜索表单、表格列、对话框、详情抽屉 |
| M2 | 监控页面深度测试 | 52 | 在线用户/缓存管理/服务器监控/缓存监控/登录日志/操作日志/审计大屏/IP 库管理/备份管理 |
| M3 | 系统工具页面深度测试 | 23 | 表单构建器（三栏布局）、代码生成器（导入/创建/预览对话框）、接口文档（Swagger iframe） |
| M4 | 帮助中心页面深度测试 | 25 | 关于系统（版本/依赖/技术栈）、更新日志（时间线）、快捷键中心、帮助中心（FAQ/联系） |
| M5 | Dashboard 和工作台深度测试 | 27 | 数据看板（统计卡片/图表/快捷入口/查看全部跳转）、个人工作台、首页 |
| M6 | 个人中心深度测试 | 8 | 基本资料 Tab、修改密码表单、TOTP Tab |
| M7 | 带参数路由页面测试 | 13 | 代码生成编辑（tableId）、定时任务日志（jobId）、用户分配角色（userId）、角色分配用户（roleId） |
| M8 | 错误页面和特殊页面测试 | 20 | 401/403/404/500/网络错误/隐私政策/锁屏页 |
| M9 | 权限隔离深度测试（ry 用户） | 9 | 菜单加载、参数设置/字典管理新增按钮隐藏、在线用户/登录日志访问、写操作 API 403 |
| M10 | i18n 完整性深度扫描 | 3 | 切换英文、中文残留扫描（0 处）、控制台错误 |
| M11 | 暗色模式深度测试 | 5 | 切换暗色模式、系统管理/监控页面无硬编码白色背景 |
| M12 | CRUD 操作深度测试 | 10 | 岗位/字典/参数/通知 新增对话框表单字段验证 |
| M13 | 注册页测试 | 7 | 注册表单（用户名/密码/确认密码/验证码）、注册按钮、返回登录链接、页面标题 |
| M14 | 字典数据详情页测试 | 7 | 字典数据详情页加载、表格列、搜索表单、新增/关闭按钮、新增字典数据对话框 |

#### 关键测试技术

- **Tour 遮罩处理**：登录后通过 `localStorage.setItem('yebot-layout-tour', 'completed')` 禁用新手引导，已显示的遮罩通过 Escape 键关闭
- **三阶段点击策略**：`clickButton` 函数依次尝试普通点击 → force click → evaluate 触发 click，绕过 Tour 遮罩和遮挡元素
- **403/401 错误过滤**：通过 `page.on('response')` 追踪 403/401 响应 URL，过滤 `/register` 探测和权限隔离测试产生的预期错误
- **嵌入式模式适配**：M9 写操作权限测试通过 `basePaths = ['', '/dev-api']` 依次尝试，适配嵌入式模式（同源）和开发模式（/dev-api 代理）
- **控制台错误过滤**：过滤 favicon、manifest、chrome-extension、rbicon.woff2、CSP 字体加载等无害错误

#### 测试前置条件

1. 后端启动在 `http://localhost:8080`（release 构建嵌入式模式）
2. `frontend-dist/` 已同步最新前端构建（`pnpm run build:embedded` + robocopy 同步）
3. `admin/admin123` 和 `ry/admin123` 账号可用
4. 数据库已初始化（含定时任务 jobId=1、代码生成 tableId=4、角色 roleId=144）

#### 测试报告

测试完成后生成 JSON 详细报告：`tests/deep-e2e-report.json`

```json
{
  "total": 282,
  "passed": 282,
  "failed": 0,
  "passRate": "100.0%",
  "results": [
    { "module": 1, "name": "用户管理页面加载", "passed": true, "detail": "" }
  ]
}
```

#### 已修复的测试问题（v0.2.1）

| 问题 | 根因 | 修复方式 |
|------|------|---------|
| 验证码图片 `data:image/gif;base64,undefined` | 后端 `captchaEnabled=false` 时 `res.img` 为空，前端未校验直接拼接 | `login.vue` 和 `register.vue` 的 `getCode()` 增加 `res.img` 非空校验 |
| 嵌入式模式登录失败 | 误用 `build:prod`（`VITE_APP_BASE_API='/prod-api'`）构建嵌入式前端 | 改用 `build:embedded`（`VITE_APP_BASE_API=''`）同源访问 |
| M9 写操作权限测试 status=200 | 测试使用 `/dev-api/system/user`，嵌入式模式下 404 | 依次尝试 `''` 和 `'/dev-api'` 两个 base path |
| Tour 遮罩拦截按钮点击 | `yebot-tour-mask` overlay 覆盖全屏 | 登录后设置 localStorage + Escape 键关闭 + 三阶段点击策略 |
| `/register` 探测产生 403 | 前端 `checkRegisterEnabled()` 单独探测 `/register` | 从 `/captchaImage` 响应读取 `registerEnabled` 字段 |
| 通知中心详情对话框不显示 | `handleViewDetail` 打开对话框后调用 `handleMarkRead`，后者检测到 `currentNotice.noticeId === row.noticeId` 后立即关闭对话框 | 拆分 `handleMarkRead`（不关闭对话框）和 `handleDialogMarkRead`（对话框内标记后关闭），消除竞态 |
| `sanitizeHtml is not a function` | `notice-center/index.vue` 缺少 `sanitizeHtml` 导入 | 添加 `import { sanitizeHtml } from '@/utils/index'` |
| 抽屉/对话框识别失败 | `waitForSelector('.el-drawer', {state:'visible'})` 选中隐藏的遗留元素 | 新增 `waitForVisibleDrawer` / `waitForVisibleDialog` 辅助函数，使用 `:visible` 伪类 |

---

## 附录：常用测试命令速查

```bash
# 全部单元测试
cargo test

# 指定模块测试
cargo test <module_name>

# 显示 println 输出
cargo test -- --nocapture

# 仅运行 ts-rs 导出测试
cargo test --lib -- "export_bindings"

# 编译检查
cargo check

# Clippy 代码质量
cargo clippy --all-targets

# Release 构建
cargo build --release

# 数据库迁移
cd migration && DATABASE_URL=mysql://... cargo run

# 查看测试覆盖率
cargo tarpaulin --out Html
```
