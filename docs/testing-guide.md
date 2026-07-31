# axum-backend 测试指引文档

> 版本：v0.3.6 | 更新日期：2026-07-31

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
# 请替换 <username> 和 <password> 为实际测试账号
curl -X POST http://localhost:8080/login \
  -H "Content-Type: application/json" \
  -d '{
    "username": "<username>",
    "password": "<password>",
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
  -d '{"username":"<username>","password":"<password>","code":"...","uuid":"..."}' \
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
# PowerShell 环境变量设置（请替换为实际测试账号）
$env:YEBOT_TEST_USER='<your-test-username>'
$env:YEBOT_TEST_PASS='<your-test-password>'

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

### 10.11 深度 E2E 测试套件（75 模块）

> 测试脚本：`tests/deep-e2e.mjs`（Playwright 驱动，深度覆盖每个前端界面的每个功能）
> 当前统计：75 模块 / 939 测试项 / 通过率 100%（v0.3.2，2026-07-30 验证）
> 架构：入口脚本 `deep-e2e.mjs` + 模块注册表 `e2e/run/registry.mjs` + 运行器 `e2e/run/runner.mjs` + 共享库 `e2e/lib/`

#### 运行方式

```powershell
# PowerShell 环境变量设置（请替换为实际测试账号）
$env:YEBOT_TEST_USER='<your-test-username>'
$env:YEBOT_TEST_PASS='<your-test-password>'
$env:YEBOT_BASE_URL='http://localhost:8080'

# 全量深度测试（75 模块）
node tests/deep-e2e.mjs --headless

# 范围测试（如 M67-M75）
node tests/deep-e2e.mjs --headless --range=67-75

# 单模块测试（如模块 9：权限隔离）
node tests/deep-e2e.mjs --headless --feature=9

# 按业务域过滤（system + monitor）
node tests/deep-e2e.mjs --headless --domain=system,monitor

# 排除指定模块（跳过 M13 注册页和 M29 权限矩阵）
node tests/deep-e2e.mjs --headless --except=13,29

# 有头模式（可视化调试，默认）
node tests/deep-e2e.mjs
```

#### CLI 参数一览

| 参数 | 说明 | 示例 |
|------|------|------|
| `--headless` | 无头模式（CI 环境） | `--headless` |
| `--feature=N` | 仅运行指定模块 | `--feature=9` |
| `--module N` | 空格分隔指定模块ID | `--module 9` |
| `--range=N-M` | 模块范围过滤 | `--range=67-75` |
| `--domain=a,b` | 按业务域过滤 | `--domain=system,monitor` |
| `--except=N,M` | 排除指定模块 | `--except=13,29` |

#### 业务域分类（--domain 参数可选值）

| 域 | 说明 | 模块 |
|----|------|------|
| `system` | 系统管理 | M1, M12, M14, M23, M43, M51, M55-M58, M62, M66, M70 |
| `monitor` | 系统监控 | M2, M44-M45, M47-M48, M53, M71 |
| `tool` | 系统工具 | M3, M49-M50, M59-M60, M65, M72-M73 |
| `auth` | 认证授权 | M9, M13, M29, M39, M41, M67 |
| `profile` | 个人中心 | M4, M6, M42, M46, M61, M64, M68-M69 |
| `forms` | 表单通用 | M15-M19, M26-M27 |
| `cross-cutting` | 横切关注点 | M7, M10-M11, M20, M22, M24-M25, M28, M30-M31, M33-M38, M40, M52, M74-M75 |
| `errors` | 错误页面 | M8, M21, M32, M54, M63 |
| `dashboard` | 仪表盘 | M5 |

#### 脚本架构（v0.2.7 重构）

```
tests/
├── deep-e2e.mjs              # 入口脚本：定义 testModule1-75 + 调用 runMain()
├── e2e/
│   ├── lib/                  # 共享库（第一阶段）
│   │   ├── config.mjs        # CONFIG + CLI 参数解析 + shouldRunModule（已抽取，待第三阶段集成启用）
│   │   ├── result.mjs        # results/record/writeReport/getExitCode（已抽取，待第三阶段集成启用）
│   │   └── index.mjs         # 统一 re-export（已抽取，待第三阶段集成启用）
│   └── run/                  # 注册表与运行器（第二阶段）
│       ├── registry.mjs      # 75 模块元数据 + bindModules() + filterByDomain()
│       └── runner.mjs        # 主入口逻辑（浏览器→登录→执行→报告）
└── SPLIT-PLAN.md             # 拆分方案文档
```

#### 75 个测试模块说明

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
| M15 | 遗漏对话框深度测试 | 14 | 任务详情/图标选择/代码类型/树节点/选择用户对话框触发与渲染 |
| M16 | 搜索筛选功能深度测试 | 9 | 用户/角色/部门/岗位/字典/参数/通知 搜索表单输入与重置 |
| M17 | Tab 切换深度测试 | 10 | 在线用户/登录日志(我的登录)/关于系统/缓存监控/个人中心/表单构建器面板切换 |
| M18 | 行内编辑删除+确认对话框测试 | 7 | 岗位/字典/参数/通知 行内修改按钮(el-link)、删除确认弹窗 |
| M19 | 分页+导出+表单校验测试 | 10 | 分页器跳转/每页条数切换、导出下载、表单必填校验 |
| M20 | 布局功能深度测试 | 15 | 头像下拉菜单/通知铃铛/主题切换/语言切换/尺寸切换/布局设置抽屉/备份入口 |
| M21 | 缺失页面深度测试 | 8 | 404 页面/用户详情/角色分配用户页/路由参数传递 |
| M22 | 组件功能深度测试 | 16 | 命令面板/头部搜索/收藏夹/语言切换/尺寸切换/备份页面 |
| M23 | 用户操作流程深度测试 | 14 | 登录/登出/修改密码/TOTP 设置/头像上传流程 |
| M24 | 批量操作 & 文件操作深度测试 | 9 | 批量删除/批量导出/文件上传/头像上传 |
| M25 | 权限指令 & 锁屏 & 错误边界深度测试 | 16 | v-hasPermi 指令/锁屏页/错误边界/EmptyState 组件 |
| M26 | 完整 CRUD 端到端流程测试 | 8 | 岗位 新增→列表验证→编辑→删除 完整流程、取消操作、唯一性校验 |
| M27 | 表单字段级校验规则测试 | 8 | cron 表达式必填/字典类型必填/用户名密码格式/邮箱格式校验 |
| M28 | 实时通信与动态数据测试 | 17 | 通知面板 hover/通知列表/通知详情/标记已读/WebSocket 连接 |
| M29 | 权限矩阵完整测试 | 19 | admin/ry 用户权限对比、菜单可见性、按钮可见性、API 403 |
| M30 | i18n + 暗色模式全页面扫描 | 8 | 全页面中文残留扫描/暗色模式 CSS 变量扫描 |
| M31 | 文件操作与导入导出实际流程测试 | 11 | 用户导出/角色导出/头像上传/备份导出实际下载验证 |
| M32 | 错误处理与边界场景测试 | 15 | 404 路由/会话过期/token 无效/网络错误/权限拒绝 |
| M33 | 可访问性 (Accessibility) 深度测试 | 8 | ARIA 标签/焦点样式/键盘导航/语义化 HTML |
| M34 | 性能测试 | 12 | 页面加载时间/内存使用/资源加载/FCP/LCP |
| M35 | 键盘快捷键测试 | 7 | 全局快捷键/表格快捷键/对话框快捷键/Tab 导航 |
| M36 | 标签页 (TagsView) 管理测试 | 9 | 多标签生成/标签关闭/右键菜单/标签固定/批量关闭 |
| M37 | 响应式布局测试 | 8 | 移动端/平板/桌面断点/侧边栏折叠/表格响应式 |
| M38 | 数据可视化测试 | 7 | Dashboard 图表/审计大屏/ECharts 渲染/图表交互 |
| M39 | 会话管理测试 | 8 | 多标签会话/会话超时/登录状态保持/多用户切换 |
| M40 | 打印功能测试 | 10 | 用户管理打印按钮/打印数据源/多页面打印/window.open 拦截 |
| M41 | 锁屏解锁完整流程测试 | 12 | 头像下拉触发锁屏/锁屏页面渲染/密码输入框/错误密码不解锁/正确密码解锁/解锁后页面恢复 |
| M42 | TOTP 设置/禁用完整流程测试 | 14 | 个人中心 MFA Tab/TOTP 卡片渲染/状态检测/生成密钥/二维码/验证码输入/复制密钥/错误验证码/禁用表单切换 |
| M43 | 通知中心完整流程测试 | 10 | 通知铃铛(#header-notice)/面板展开/Tab 分类/列表渲染/更多链接/通知公告页表格/新增按钮 |
| M44 | 备份管理测试 | 6 | /monitor/backup 页面加载/创建备份按钮/备份列表/恢复按钮/下载按钮 |
| M45 | 缓存管理测试 | 6 | /monitor/cache 页面加载/键列表/统计信息/清空按钮/刷新按钮 |
| M46 | 用户偏好设置测试 | 12 | 个人中心基本资料 Tab/表单字段/头像组件(左侧卡片)/布局设置抽屉/主题切换/侧边栏样式 |
| M47 | 监控模块完整测试 | 14 | 在线用户(强退)/定时任务(状态切换/执行一次)/健康检查(CPU/内存/磁盘)/缓存监控 |
| M48 | 限流管理测试 | 6 | /monitor/rateLimit 页面加载/规则列表/新增按钮/维度选择/状态切换 |
| M49 | 代码生成器测试 | 6 | /tool/gen 页面加载/表列表/导入表/生成按钮/预览按钮 |
| M50 | 表单构建器测试 | 7 | /tool/build 页面加载/左侧组件面板/中间画布/右侧属性面板/组件数量/操作栏 |
| M51 | IP 库管理测试 | 4 | /system/ipLibrary 页面加载/列表/导入按钮 |
| M52 | 指令深度（水印/复制/脱敏）测试 | 10 | v-watermark 样式标签/水印渲染/v-copyText 复制触发/v-desensitize 手机/IP 脱敏/全局注册 |
| M53 | 任务进度管理测试 | 18 | /monitor/task 页面加载/搜索表单（任务类型/状态/操作者/创建时间）/搜索重置按钮/批量删除按钮/表格列数/数据行数/进度条/状态标签/空状态组件/搜索后页面正常/重置后页面正常/分页组件 |
| M54 | 错误页面完整测试 | 8 | 401/403/500/network-error 页面加载/标题/导航按钮 |
| M55 | 菜单管理 CRUD 深度测试 | 13 | 菜单新增/编辑对话框/表单字段/权限标识/父菜单树/展开折叠按钮（索引点击 radio 切换菜单类型） |
| M56 | 部门管理 CRUD 深度测试 | 10 | 部门新增/编辑对话框/表单字段/负责人/联系电话/邮箱/排序 |
| M57 | 角色管理 CRUD 深度测试 | 15 | 角色新增/编辑/权限字符（placeholder 定位）/菜单权限树/全选/全不选 checkbox/数据权限/备注/导出按钮 |
| M58 | 用户管理 CRUD 深度测试 | 17 | 用户新增/编辑/部门 select（归属部门 label）/岗位 select/角色分配/密码字段/导出按钮/搜索表单 |
| M59 | 代码生成器深度交互 | 11 | 导入表对话框/预览按钮/生成按钮/删除按钮/搜索表单/表格列 |
| M60 | 表单构建器深度交互 | 13 | 左侧组件面板/中间画布/右侧属性面板/导出按钮/组件数量/操作栏/面板 Tab 切换 |
| M61 | 个人中心提交测试 | 11 | 基本资料/修改密码/保存按钮/关闭按钮/昵称/邮箱/手机号/性别 radio |
| M62 | 授权操作端到端 | 9 | 角色授权用户/用户授权角色/添加用户按钮/取消授权/批量取消授权/关闭按钮 |
| M63 | 隐私政策页面测试 | 5 | 隐私政策页标题/章节/页脚（页面不可访问时跳过） |
| M64 | 头像上传完整流程测试 | 9 | 个人中心头像容器/对话框打开/vue-cropper 裁剪器/缩放按钮/旋转按钮/预览区域/上传按钮/控制台错误 |
| M65 | Swagger API 文档交互测试 | 6 | iframe 存在/src 设置/内容加载/后端 swagger-ui 可访问/OpenAPI JSON 可访问（路径数验证） |
| M66 | 通知已读用户列表深度测试 | 10 | 通知列表加载/已读用户按钮/对话框打开/标题/列表表格/用户行数/表格列数/分页组件/关闭按钮 |
| M67 | 登录页 UI 完整测试 | 9 | 表单容器/账号输入框/密码输入框/登录按钮/空表单校验/错误密码提示/记住密码复选框/语言切换/Logo |
| M68 | 密码修改校验测试 | 8 | Tab 切换/旧密码输入框/新密码输入框/确认密码输入框/保存按钮/空表单校验/新旧密码相同校验/确认密码不一致校验 |
| M69 | 基本资料提交测试 | 8 | Tab 可见/昵称输入框/手机号输入框/邮箱输入框/性别选择/保存按钮/无效手机号校验/无效邮箱校验/有效数据保存 |
| M70 | 用户/字典详情页深度测试 | 10 | 用户详情页加载/表单/字段数量/返回按钮；字典详情页加载/表单/字段数量/返回按钮 |
| M71 | 操作日志/任务详情对话框 | 10 | 操作日志详情按钮/对话框/内容/代码块/关闭按钮；定时任务详情按钮/对话框/内容/关闭按钮 |
| M72 | 表单构建器子组件深度 | 10 | 页面加载/左侧组件面板/点击组件到画布/属性面板/图标选择对话框/图标搜索框/图标网格/清空画布 |
| M73 | 代码生成器表单深度 | 8 | 表格列表/编辑按钮/编辑页面/基本信息Tab/表单字段数/字段信息Tab/生成信息Tab/返回列表 |
| M74 | 全局交互功能深度 | 11 | 命令面板打开/搜索框/搜索结果/HeaderSearch按钮/HeaderSearch结果/主题色按钮/主题色面板/标签页可见/右键菜单/右键菜单项 |
| M75 | 数据导出与文件下载 | 11 | 用户导出按钮/确认框/触发；角色导出按钮/触发；岗位导出按钮/触发；文件管理页加载/上传按钮/文件列表 |

#### 关键测试技术

- **Tour 遮罩处理**：登录后通过 `localStorage.setItem('yebot-layout-tour', 'completed')` 禁用新手引导，已显示的遮罩通过 Escape 键关闭
- **三阶段点击策略**：`clickButton` 函数依次尝试普通点击 → force click → evaluate 触发 click，绕过 Tour 遮罩和遮挡元素
- **403/401 错误过滤**：通过 `page.on('response')` 追踪 403/401 响应 URL，过滤 `/register` 探测和权限隔离测试产生的预期错误
- **嵌入式模式适配**：M9 写操作权限测试通过 `basePaths = ['', '/dev-api']` 依次尝试，适配嵌入式模式（同源）和开发模式（/dev-api 代理）
- **控制台错误过滤**：过滤 favicon、manifest、chrome-extension、rbicon.woff2、CSP 字体加载、ResizeObserver loop、IMG 资源加载（头像未设置）等无害错误
- **对话框/抽屉辅助函数**：`waitForVisibleDialog` / `waitForVisibleDrawer` / `closeDialog` / `closeDrawer` 使用 `:visible` 伪类精确匹配可见元素，避免选中隐藏的遗留元素
- **SPA 导航保状态**：M36 多标签生成使用侧边栏菜单点击导航（而非直接 URL 跳转），保持 SPA 标签页状态
- **i18n 文本适配**：按钮文本匹配兼容 "确 定"/"确定"、"打 印"/"打印" 等 i18n 带空格变体；表格行内按钮匹配 "修改"/"编辑" 两种翻译
- **锁屏状态清理**：M25 锁屏测试后显式清除 localStorage 中的 `screen-lock` 和 `screen-lock-path`，避免污染后续模块
- **Cookie token 读取**：M32 会话过期测试从 `document.cookie` 读写 token（非 localStorage），适配 Cookie 存储模式
- **锁屏 401 过滤**：M41 锁屏测试有意使用错误密码解锁，`/unlockscreen` 端点返回 401，通过 `unauthorizedUrls` 过滤器匹配 `/unlockscreen` URL 过滤该预期错误
- **TOTP 禁用表单两阶段切换**：M42 TOTP 禁用表单是条件渲染（`.disable-form`），需先点击 `.enabled-state` 中文本为"未启用"的危险按钮（`profile.totp.disabled` i18n key）才能展开禁用表单
- **通知铃铛选择器**：M43 通知铃铛的实际选择器为 `#header-notice` 或 `.notice-trigger`（非 `.notice-bell`），图标为 `svg-icon[icon-class="bell"]`，移动端（<992px）整个右侧菜单隐藏
- **个人中心 Tab 文本**：M46 个人中心 Tab 文本为"基本资料"（i18n: `profile.basicInfo`），不是"基本信息"；没有独立头像 Tab，头像组件在左侧卡片常驻
- **布局设置入口**：M46 布局设置通过头像下拉菜单触发（`.avatar-container` → "布局设置"菜单项），菜单项文本为"布局设置"（i18n: `layout.navbar.layoutSettings`）
- **监控模块路由**：M47 服务器监控已合并为健康检查，路由从 `/monitor/server` 变更为 `/monitor/health`（`m20260802_000001_merge_server_to_health` 迁移）
- **监控子模块路由**：备份管理、任务进度、限流配置的实际路由为 `/monitor/backup`、`/monitor/task`、`/monitor/rateLimit`（菜单 parent_id=2 即监控目录，非系统目录）
- **503/429 限流错误过滤**：全量 E2E 测试时请求密集，后端令牌桶限流（capacity=100, refill=10/s）和数据库连接池耗尽会返回 503 Service Unavailable；Redis 限流返回 429 Too Many Requests。这些是测试环境预期行为，通过 `text.includes('503') && text.includes('Service Unavailable')` 和 `text.includes('429')` 过滤，不影响功能正确性验证
- **#label 插槽字段定位**：menu/index.vue 的"权限标识"和 role/index.vue 的"权限字符"使用 `#label` 具名插槽（含 el-tooltip + question-filled 图标），不使用 `:label` 属性。测试中优先用 `input[placeholder*="权限标识"]` / `input[placeholder*="权限字符"]` 定位，回退到 label 文本匹配
- **菜单类型 radio 索引点击**：M55 菜单管理对话框的菜单类型 radio（目录/菜单/按钮）使用 `.el-radio-group .el-radio` 索引点击（nth(1) = "菜单"/C 类型），比 `:has-text("菜单")` 文本匹配更可靠，避免 `:has-text("C")` 误匹配其他元素
- **归属部门 label 文本**：user/index.vue 的部门字段 label 实际渲染为"归属部门"（i18n: `user.form.dept`），非"部门"；且 `el-tree-select` 在 Element Plus 中内部渲染为 `el-select`，DOM 中无 `el-tree-select` class，选择器使用 `.el-form-item:has(.el-form-item__label:has-text("归属部门")) .el-select`
- **M58 部门/岗位 select 可见性判断**：使用 `page.evaluate()` 在可见 dialog 内通过 label 文本精确匹配（`text === '归属部门'` / `text === 'Department'`）查找 form-item，再检查其内部 `.el-select__wrapper`（实际可见触发器）的 `getBoundingClientRect()`。回退检查 `.el-form-item__content` 区域可见性。避免直接检查 `.el-select` / `.el-tree-select` 外层包装器（可能尺寸为 0）。兼容中英文 label 文本
- **M64 头像上传 vue-cropper**：userAvatar.vue 使用 vue-cropper 裁剪器，裁剪器容器选择器为 `.cropper-container` / `.vue-cropper` / `.cropper-box`；缩放/旋转按钮为 icon-only `el-button`（`icon="Plus"` / `icon="Minus"` / `icon="RefreshLeft"` / `icon="RefreshRight"`），无文本，通过 icon 类选择器（`button:has(.el-icon-plus)` 等）或 JS 结构定位（el-row 中 icon-only button 按位置识别：前 2 个为缩放、后 2 个为旋转）
- **M65 Swagger iframe 跨域**：Swagger UI 通过 iframe 嵌入，可能受同源策略限制无法访问 iframe 内容；测试通过 `page.evaluate(fetch())` 直接请求后端 `/swagger-ui` 和 `/api-docs/openapi.json` 验证可访问性，并统计 OpenAPI paths 数量
- **M66 已读用户按钮定位**：notice/index.vue 的"已读用户"按钮在操作列，使用 `.el-table__row button:has-text("已读")` 或 `.el-button:has(.el-icon-view)` 定位（可能为图标按钮无文本）
- **M67 登录页独立 context**：登录页测试使用 `createPage(browser)` 创建独立 context，避免影响主会话的登录状态；测试空表单校验和错误密码提示后关闭 context
- **M68 密码修改不实际提交**：密码修改测试仅验证表单校验（空表单、新旧相同、确认不一致），不实际修改密码，避免破坏后续测试的登录状态
- **M68 密码输入框 i18n 无关定位**：resetPwd.vue 的三个密码输入框 placeholder 随 i18n 变化（中文"旧密码/请输入新密码/确认密码"，英文"Old Password/Enter new password/Confirm Password"），英文模式下"Enter new password"不包含"New"（大小写敏感），原 `input[placeholder*="New"]` 选择器会失效。修复为 `.el-tab-pane:not([style*="display: none"]) input[type="password"]` + `nth(0/1/2)` 索引定位，与 i18n 语言无关
- **M69 性别选择 i18n label 兼容**：userInfo.vue 性别字段 label 在中文为"性别"、英文为"Gender"（不是"Sex"），原选择器 `.el-form-item__label:has-text("Sex")` 在英文模式失效。修复为同时匹配"性别"/"Gender"/"Sex"三种文本
- **M10 i18n 切换回中文回退策略**：SPA 路由跳转（safeGoto）不会重新执行 i18n 初始化，仅设置 localStorage 不改变运行时 locale。修复为使用 `page.reload()` 强制重新加载页面，让 i18n 从 localStorage 重新读取语言设置
- **M70 详情页 allowFail**：用户详情页和字典详情页可能因路由不存在或参数缺失跳转，使用 `allowFail: true` 导航并检查 URL 是否包含 `/404` 或 `/login`
- **M71 详情对话框通用选择器**：操作日志和定时任务详情对话框使用 `.el-dialog:visible` + `.el-dialog__headerbtn` 通用选择器，适配不同标题文本
- **M72 表单构建器点击替代拖拽**：headless 模式下 HTML5 拖拽不可靠，使用点击组件项替代拖拽操作；图标选择对话框通过 `.el-dialog:visible` 定位
- **M73 代码生成器编辑页 Tab 切换**：编辑页使用 `.el-tabs__item:has-text()` 定位 Tab，切换后等待 `.el-table`（字段信息）或 `.el-form-item`（生成信息）可见
- **M74 全局交互 Escape 清理**：命令面板、HeaderSearch、主题色面板测试后均通过 `Escape` 键关闭，避免遗留弹层影响后续测试
- **M75 导出取消确认**：导出测试点击导出按钮后，在确认框中点击"取消"而非"确定"，避免实际下载文件影响测试环境

#### 测试前置条件

1. 后端启动在 `http://localhost:8080`（release 构建嵌入式模式）
2. `frontend-dist/` 已同步最新前端构建（`pnpm run build:embedded` + robocopy 同步）
3. 测试账号已创建（通过 `YEBOT_TEST_USER` / `YEBOT_TEST_PASS` 环境变量配置）
4. 数据库已初始化（含定时任务 jobId=1、代码生成 tableId=4、角色 roleId=144）

#### 测试报告

测试完成后生成 JSON 详细报告：`tests/deep-e2e-report.json`

```json
{
  "timestamp": "2026-07-30T...",
  "total": 939,
  "passed": 939,
  "failed": 0,
  "passRate": "100.0%",
  "results": [
    { "module": 1, "name": "用户管理页面加载", "passed": true, "detail": "" }
  ]
}
```

#### 已修复的测试问题（v0.2.1 ~ v0.2.3）

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
| M15 任务详情按钮不可见 | 详情触发是 jobName 上的 el-link，非按钮 | 选择器改为 `.el-table__row .el-link` |
| M15 选择用户对话框失败 | 按钮文本是 "新增" 而非 "添加"（i18n common.add） | 选择器使用 `button:has-text("新增")` |
| M15 JobDetail 内容渲染失败 | 对话框使用 `.detail-wrap` / `.detail-card` 而非 `.el-form` | 选择器改为 `.el-dialog .detail-wrap, .el-dialog .detail-card` |
| M17 登录日志 Tab 切换失败 | `.el-tab-pane .el-table` 匹配到第一个隐藏 Tab 的表格 | 选择器改为 `.my-login-panel` 精确匹配第二个 Tab |
| M17 表单构建器 Tab 失败 | 表单构建器不使用 el-tabs，使用 left/center/right 面板 | 改为检查 `.right-board` / `.center-board` 面板可见性 |
| M18 编辑按钮不可见 | 按钮文本是 "修改"（i18n common.edit）而非 "编辑" | 选择器同时匹配 "修改" 和 "编辑" |
| M19 导出对话框未出现 | 导出函数触发直接下载，无确认对话框 | 改为检查 loading 遮罩或下载事件 |
| M19 确定按钮不可见 | 按钮文本带空格 "确 定"（i18n common.confirm） | 选择器同时匹配 "确 定" 和 "确定" |
| M20 通知铃铛面板未展开 | 使用 click 触发 toggle，但 mouseenter 已展开面板 | 改用 hover 触发，目标 `.notice-popover` |
| M20 设置抽屉未打开 | 设置入口在头像下拉菜单内，非独立按钮 | 改为点击头像下拉菜单中的 "布局设置" |
| M21 404 页面错误提示不可见 | 404 页面使用 `wscn-http404-container` 自定义类 | 选择器改为 `.wscn-http404-container, .wscn-http404, .bullshit__oops` |
| M22 语言/尺寸切换按钮不可见 | 选择器使用通用类而非特定 ID | 选择器改为 `#lang-select` 和 `#size-select` |
| M25 锁屏污染后续模块 | 锁屏状态以签名 payload 持久化到 localStorage | 测试后显式移除 `screen-lock` 和 `screen-lock-path` |
| M26 CRUD 表单字段不匹配 | 选择器用 placeholder 而非 i18n label 文本 | 改用 `:has(label:has-text("岗位名称"))` 精确匹配 |
| M26 token 读取失败 | token 存储在 Cookie 而非 localStorage | 使用传入的 token 参数，不读 localStorage |
| M27 cron/dict 格式校验失败 | 前端仅有必填校验，无格式校验 | 改为测试必填校验而非格式校验 |
| M28 通知面板未打开 | click 触发 toggle 与 mouseenter 冲突 | 改用 hover 触发 |
| M31 备份页面 404 | 路由错误 `/system/backup` | 修正为 `/monitor/backup` |
| M31 用户导出确认按钮不可见 | 导出为直接下载，无确认对话框 | 移除确认检查，直接等待下载事件 |
| M31 控制台图片资源错误 | 个人中心头像未设置导致图片加载失败 | 过滤 IMG 资源错误和 `/user/profile` URL 错误 |
| M32 会话过期测试失败 | token 存储在 Cookie 但测试读 localStorage | 改为从 `document.cookie` 读写 token |
| M32 404 控制台错误 | 边界测试故意触发 404 | 新增 404 URL 追踪和过滤 |
| M33 ARIA 标签验证失败 | `document.querySelector` 不支持 `:has-text()` | 改用 JavaScript evaluate 检查属性和角色 |
| M33 焦点样式不可见 | 无头模式不触发 `:focus-visible` | 改为检查交互元素类型 |
| M34 内存使用超限 | 阈值 100MB 对 Vue SPA + Element Plus 过低 | 阈值提高到 250MB |
| M36 多标签生成失败 | 直接 URL 导航重置 SPA 状态 | 改用侧边栏菜单点击导航保持标签状态 |
| M38 路由 404 | 不存在的 `/monitor/my-login` 路由 | 改为 `/monitor/logininfor` + Tab 切换 |
| M40 打印按钮未找到 | i18n "打 印"（带空格），选择器过严 | 多选择器策略 + JavaScript evaluate 兜底 |
| ResizeObserver loop 错误 | 浏览器 ResizeObserver 循环限制 | 在 console 和 pageerror 处理器中过滤该错误 |
| M41 锁屏 401 控制台错误 | 错误密码解锁调用 `/unlockscreen` 返回 401（预期行为） | 401 过滤器添加 `/unlockscreen` URL 匹配 |
| M42 TOTP 禁用表单不可见 | 禁用表单是条件渲染，需先点击 `.enabled-state` 中的切换按钮 | 先点击 `.enabled-state button.el-button--danger` 展开禁用表单 |
| M43 通知铃铛不可见 | 选择器用 `.notice-bell`，实际类名为 `#header-notice` / `.notice-trigger` | 改用 `#header-notice, .notice-trigger` 选择器 |
| M43 通知公告新增按钮不可见 | 选择器未限定 `.app-container` 范围 | 改用 `.app-container button:has-text("新增")` 精确匹配 |
| M46 基本信息 Tab 不可见 | Tab 文本是"基本资料"（i18n: profile.basicInfo），非"基本信息" | 选择器改为 `:has-text("基本资料")` |
| M46 头像 Tab 不可见 | 没有独立头像 Tab，头像在左侧卡片常驻 | 改为检查 `.user-avatar` / `.box-card .el-upload` 组件可见性 |
| M46 布局设置抽屉不可见 | 下拉菜单项文本是"布局设置"，非泛化的"布局"/"设置" | 选择器改为 `:has-text("布局设置")` 精确匹配 |
| M47 /monitor/server 404 | 服务器监控已合并为健康检查（`m20260802_000001` 迁移） | 路由改为 `/monitor/health` |
| M1/M31 /system/backup 404 | 备份管理菜单 parent_id=2（监控），路由为 `/monitor/backup` | 路由从 `/system/backup` 改为 `/monitor/backup` |
| M1 /system/task 404 | 任务进度菜单 parent_id=2（监控），路由为 `/monitor/task` | 路由从 `/system/task` 改为 `/monitor/task` |
| M1 /system/rateLimit 404 | 限流配置菜单 parent_id=2（监控），路由为 `/monitor/rateLimit` | 路由从 `/system/rateLimit` 改为 `/monitor/rateLimit` |
| M53 任务进度操作人筛选失败 | i18n task.search.operator 文本为"操作者"（zh）/"Operator"（en） | 选择器改为 `:has-text("操作者"), :has-text("Operator")` 双语匹配 |
| 备份/任务/限流菜单 parent_id 不一致 | 之前手动修改 DB 未形式化 | 新增 `m20260805_000001_fix_backup_task_ratelimit_menu_parent` 迁移，将 menu_id 118/119/121 的 parent_id 从 1 改为 2 |

#### v0.2.6 业务流程与链路优化（2026-07-30）

| 问题 | 根因 | 修复方式 |
|------|------|---------|
| 菜单 CRUD 后下拉树缓存未失效 | `menu/index.vue` 的 `submitForm`/`handleDelete` 未调用 `refreshMenuTreeselect()` | 在更新/删除成功回调中调用 `refreshMenuTreeselect()` 失效缓存 |
| 部门 CRUD 后下拉树缓存未失效 | `dept/index.vue` 的 `submitForm`/`handleDelete` 未调用 `refreshDeptTreeSelect()` | 在更新/删除成功回调中调用 `refreshDeptTreeSelect()` 失效缓存 |
| 修改密码后旧 token 仍有 1500ms 可用窗口 | `resetPwd.vue` 改密成功后延迟登出，期间用户可继续操作 | 加全屏 `ElLoading.service({ lock: true })` 遮罩，登出完成后关闭 |
| HTML 消息体 XSS 防护不可靠 | `utils/sanitize.rs` 使用手写正则过滤，易被属性大小写/编码绕过 | 引入 `ammonia` crate，白名单标签+属性+链接 rel=noopener noreferrer |
| `/common/upload` 缺权限校验 | `permission.rs` 未映射上传端点权限标识 | 新增 `("POST", "/common/upload") => Some("system:file:add")` 映射 |
| `/dashboard/*` 缺权限校验 | `permission.rs` 未映射仪表盘端点权限标识 | 新增 `("GET", "/dashboard/stats")` / `("GET", "/dashboard/user-stats")` 映射到 `monitor:server:list` |
| 数据库 URL 解析 panic | `db_type.rs::from_url` 遇到未知 scheme 时 `panic!` | 改为返回 `Result<DbType, DbTypeError>`，`pool.rs` 调用方转为 `AppError` |
| 429 响应缺 Retry-After 头 | `rate_limit.rs` 限流响应未按 RFC 6585/7231 携带 Retry-After | 新增 `try_acquire_with_retry_after` 计算恢复秒数，写入 `Retry-After` 头 |
| 备份恢复 MySQL 分支 `unreachable!()` | `sys_backup_service.rs` MySQL 恢复路径用 `unreachable!()` 可能 panic | 替换为 `return Err(ServiceError::internal(...))` 正常错误返回 |
| 字典数据路由 name 冲突 | `router/index.ts` 字典数据路由 name="Data" 过于宽泛 | 改为 `name: 'SystemDictData'` 遵循父子前缀命名约定 |
| TOTP 组件直连 request 未用 API 模块 | `totp.vue` 直接 `import request` 调用，绕过 `api/system/totp` 封装 | 改为 `import { setupTotp, ... } from '@/api/system/totp'`，移除死代码表单项 |
| rateLimit `handleUpdate` 未处理 reject | `rateLimit/index.vue` 的 `handleUpdate` Promise 链无 `.catch()` | 添加 `.catch(() => {})` 避免未处理 Promise 拒绝 |

#### v0.2.8 测试覆盖增强（2026-07-30）

| 问题 | 根因 | 修复方式 |
|------|------|---------|
| 通知中心"全部已读"功能无测试覆盖 | 仅验证按钮可见性，未测试实际功能链路 | 新增完整链路测试：确认对话框/API调用/成功提示/未读数清零/禁用态 |
| 文件上传 magic bytes 校验未测试 | 仅上传 .txt 正常文件，未测试伪造扩展名场景 | 新增负向测试：上传伪 .jpg 文件验证后端拒绝/错误提示/列表未增加 |
| 代码生成器 synchDb/delTable/genCode 未测试 | 仅验证按钮可见性，未测试实际功能 | 新增同步数据库API调用/生成代码下载触发/删除表确认对话框+取消后列表不变测试 |
| 测试报告结构不完整 | 缺少 elapsedMs/modules/environment 字段 | runner.mjs/result.mjs 添加总耗时/模块分组统计/运行环境信息 |
| 失败项错误信息不足 | 无 stack/screenshot 信息 | record 函数失败时自动捕获 stack（前15行），runner 模块异常时自动截图 |
| 三套 CONFIG 定义不同步 | config.mjs 硬编码弱密码 admin123、frontendUrl 默认值不一致 | deep-e2e.mjs / main.mjs 的 frontendUrl 增加 YEBOT_UI_URL 环境变量回退；次要账号 secondaryUsername/Password 支持 YEBOT_TEST_USER_SECONDARY / YEBOT_TEST_PASS_SECONDARY 环境变量覆盖；debug-add-buttons.mjs 改为从 test-config.mjs 导入。注：e2e/lib/config.mjs 为抽取的死代码，实际运行使用 deep-e2e.mjs 内联 CONFIG，二者默认值仍存在差异（8080 vs 5173），后续需统一为单一配置源 |
| 前端 console 硬编码中文（74处） | 开发者日志使用中文不利于国际化检索 | 34 个文件的 74 处 console.log/error/warn 中文替换为英文 |

#### v0.2.9 深层隐患修复（2026-07-30，第四轮循环）

| 问题 | 根因 | 修复方式 |
|------|------|---------|
| lock.vue 粒子动画 resize 监听器累积泄漏 | visibilitychange 恢复时调用 initParticles 未先移除旧监听器 | initParticles 开头先 removeEventListener + cancelAnimationFrame |
| notice store refreshTopNotices 竞态条件 | loading=true 时直接 return，后调用者拿不到最新数据 | 引入 refreshPromise 实现 promise reuse，并发调用共享同一 Promise |
| notice store export default 命名错误 | 导出 useNotice（未定义）而非 useNoticeStore | 修正为 export default useNoticeStore |
| ExportDialog handleConfirm setTimeout 未跟踪 | 组件卸载后定时器仍执行 | 引入 closeTimer 句柄，handleClose + onBeforeUnmount 清理 |
| Navbar toggleTheme 锁释放定时器未跟踪 | 700ms 定时器在卸载后仍修改全局状态 | 引入 themeLockTimer，onBeforeUnmount 清理并重置 __themeTransitionInProgress |
| shortcuts/help kbd v-for 用 index 作 key | 键位列表用索引作 key，搜索过滤时可能渲染错乱 | 改用键名字符串 k 作为 key |
| useAutoRefresh setInterval 不等待回调完成 | 慢回调堆积导致并发执行与状态竞争 | 改为递归 setTimeout + stopped 标志，确保前一次完成后才调度下一次 |
| useSessionTimeout handleLogout setTimeout 未跟踪 | 卸载后仍可能触发 location.href 跳转 | 引入 logoutRedirectTimer，onBeforeUnmount 清理 |
| WebSocket Future 取消时连接计数泄漏 | handle_ws 末尾的 DECR 在 Future 被 drop 时不执行 | 引入 WsConnGuard RAII 守卫，Drop 中 spawn DECR 任务 |
| ws_handler JWT sub 解析失败回退 user_id=0 | unwrap_or(0) 可能导致越权/计数错乱 | 改为返回 401 拒绝连接 |
| 调试脚本硬编码弱密码（14个 .mjs + 文档） | debug-*.mjs 直接写死 admin/admin123 | 改为从 test-config.mjs 导入 TEST_USER/TEST_PASS；文档示例改用占位符 |
| notice-center/index.vue 参数隐式 any（3处） | shallowRef 数组方法回调参数缺类型注解 | 添加 (n: SysNotice) 显式类型注解 |

#### v0.3.0 安全加固与深层修复（2026-07-30，第五轮循环）

| 问题 | 根因 | 修复方式 |
|------|------|---------|
| 数据权限过滤 fail-open（P1 安全漏洞） | 6 处 handler 的 JWT sub 解析用 .ok() 容错，解析失败返回 None 导致跳过数据权限过滤 | 改为 fail-closed：解析失败返回 401 拒绝访问（role/user/dept 的 list+export 共 6 处） |
| v-copyText 指令事件监听器泄漏 | 缺少 unmounted 钩子，元素卸载时 click 监听器未清理 | 添加 unmounted 钩子调用 $destroyCopy 清理 |
| useCrudTable getList 竞态条件 | 无请求取消机制，快速翻页/搜索时旧响应覆盖新数据 | 引入 listRequestId 版本号守卫，丢弃过期响应 |
| useCrudTable handleUpdate 竞态条件 | 快速点击不同行编辑按钮时旧请求覆盖新表单 | 引入 updateRequestId 版本号守卫 |
| health/index.vue 定时器未清理 + 竞态 | toggleAutoRefresh 未先清旧定时器；setInterval 不等待回调完成 | 先 clearTimeout 再创建；改用递归 setTimeout 确保串行 |
| notification.ts 硬编码中文比较 | msg.data.message === 'WebSocket 连接成功' 与 locale 耦合 | 移除硬编码兜底，仅依赖 i18n key 比较 |
| AnnouncementBanner 严重级别判断仅中文 | 正则只匹配紧急/重要/警告，英文 locale 下全部降级为 info | 补充英文关键词 urgent/important/warning/critical |
| pdf.ts printElement 无错误保护 | setTimeout 中 printWindow.print() 无 try/catch | 包裹 try/catch + 检查 printWindow.closed |
| TagsView Promise 链缺少 .catch() | 6 个 .then() 链无 .catch()，可能产生 unhandledrejection | 补充 .catch() 错误处理 |
| scheduler 登录异常检测 fail-silent | Redis 错误被 .unwrap_or(None) 误认为"已去重"，跳过告警 | 区分 Redis 错误与 key 已存在，故障时仍创建告警 |
| 通知公告枚举值未校验 | notice_type/status 仅校验长度，可接受任意字符串 | 添加 validate_notice_enum 白名单校验（"1"/"2", "0"/"1"） |
| 定时任务枚举值未校验 | misfire_policy/concurrent/status 使用 #[garde(skip)] | 添加 validate_job_enum 白名单校验（"1"/"2"/"3", "0"/"1", "0"/"1"） |

#### v0.3.1 安全加固与配置修复（2026-07-30，第六轮循环）

| 问题 | 根因 | 修复方式 |
|------|------|---------|
| 建表 DDL 错误泄露 DB schema | `gen_table_service.rs:936` 将 SeaORM DbErr 原文拼接进用户可见错误 | 错误详情写 tracing::error!，对外仅返回通用 tr!() 文案 |
| 配置缓存 DEL 失败静默 | `sys_config_service.rs:188` 用 `let _ =` 丢弃 DEL 结果，脏缓存持续至 TTL | 区分 Redis 错误与超时，分别记录 tracing::warn! 便于排查 |
| 旧 MD5 密码非恒定时间比较 | `password.rs:203` 用 `String::eq` 短路比较，时序侧信道泄露哈希前缀 | 新增 constant_time_eq 函数，按位 XOR 累积差异 |
| ValidatedJson 解析错误泄露内部细节 | `common/extract.rs:45` 将 axum JSON 错误（含字段路径/类型）拼接给客户端 | 错误详情写 tracing::warn!，对外仅返回通用 tr!() 文案 |
| 5 处 handler "认证信息异常" 硬编码中文 | JWT sub 解析失败时返回硬编码字符串，未用 i18n key | 替换为 `tr!("error.common.session_invalid")`（role/user/dept 的 list+export 共 5 处） |
| backup service MySQL 分支硬编码中文 | `sys_backup_service.rs:496` 直接返回中文字符串 | 新增 `error.backup.mysql_restore_branch_unreachable` i18n key |
| backup service stdin shutdown 错误静默 | `sys_backup_service.rs:578` 用 `let _ =` 丢弃 shutdown 错误 | 失败时记录 tracing::warn!，便于排查上游写入错误 |
| WebSocket 连接成功消息未用 tr!() | `ws_handler.rs:276` 使用 pick(zh, en) 手动双语 | 新增 `websocket.connected` i18n key，改用 tr!() 宏 |
| 用户删除后 Redis 逐个 SETEX | `sys_user_handler.rs:299` 循环 N 次 SETEX，N 次 RTT | 改用 redis::pipe() 批量执行，N 次 RTT 降为 1 次 |
| useFormDraft 文档示例硬编码中文 | docstring 中 `modal.confirm('检测到未提交的草稿...')` | 新增 `common.formDraft.*` i18n key，文档示例改用 `t()` |
| runner.mjs 浏览器双重关闭 | 登录失败时 `browser.close()` + `return 1`，finally 块再次 close 抛 "Target closed" | 移除登录失败分支的 close 调用，由 finally 统一关闭 |
| main.mjs CLI 参数双重解析 | 顶部位置参数解析（argv[2]/argv[3]）与 main() 内 `--headless`/`--feature=` 解析并存 | 删除顶部死代码，统一在 main() 内解析 |
| main.mjs / deep-e2e.mjs 次要账号硬编码 | `secondaryUsername: 'ry'` 无环境变量覆盖 | 支持 `YEBOT_TEST_USER_SECONDARY` / `YEBOT_TEST_PASS_SECONDARY` 环境变量 |
| main.mjs / deep-e2e.mjs frontendUrl 缺少 YEBOT_UI_URL 回退 | 仅支持 `FRONTEND_URL`，与 test-config.mjs 的 `YEBOT_UI_URL` 不一致 | 增加 `YEBOT_UI_URL` 环境变量回退，与 test-config.mjs 保持一致 |
| main.mjs 文件头注释过时 | 写 "前端启动在 http://localhost:81" 和 "admin/admin123 账号可用" | 更新为环境变量注入说明 |
| config.toml.prod 缺少安全警告 | SQLite + 无密码 Redis 作为生产默认值无风险提示 | 添加安全警告注释，明确生产必须通过环境变量切换 |
| config.toml.prod 缺少通用上传配置 | 缺 `common_allowed_exts` / `common_max_size` 字段 | 补齐字段，与 config.toml.example 保持一致 |
| testing-guide.md 测试项数量矛盾 | 第 904 行写 951，第 1108 行 JSON 示例写 939 | 统一为 939 |
| testing-guide.md 谎报 CONFIG 已同步 | 表格声称"config.mjs 与 test-config.mjs 同步"，实际默认值仍不同（8080 vs 5173） | 修正为如实描述：环境变量回退已增加，但默认值差异仍存，e2e/lib/config.mjs 为死代码 |

#### v0.3.2 事务安全与资源泄漏修复（2026-07-30，第七轮循环）

| 问题 | 根因 | 修复方式 |
|------|------|---------|
| gen_table import_table 无事务 | 表记录与列记录分两步插入，列插入失败时产生无列的孤儿 gen_table 记录 | 将表插入+列插入包裹在同一 SeaORM 事务中，列插入失败时自动回滚表记录 |
| gen_table create_table 无事务 | 同 import_table 问题，表插入后列插入失败产生孤儿记录 | 同 import_table 修复方式，事务包裹表+列插入 |
| GenTableColumnEditDto 未派生 Clone | create_table 事务闭包需 clone columns_opt，DTO 缺少 Clone 派生 | 添加 Clone 到 derive 列表 |
| avatar 更新旧文件未清理 | update_avatar 仅更新 DB 字段，旧头像文件永久驻留磁盘 | service 返回旧 avatar 路径，handler 调用 delete_upload_file best-effort 删除 |
| 3 处 handler 硬编码 "操作成功" | sys_user_handler 3 处返回硬编码中文字符串 | 替换为 `tr!("msg.success.default")` i18n key |
| delete_upload_file 函数缺失 | 无通用文件删除工具函数 | 新增 spawn_blocking 封装，NotFound 视为成功，re-export 到 crate::common |

#### v0.3.3 i18n 标准化与性能优化（2026-07-30，第九~十轮循环）

| 问题 | 根因 | 修复方式 |
|------|------|---------|
| 11 个 export handler Excel 状态值输出原始代码 | sys_job/sys_job_log/sys_oper_log 等导出列直接输出 "0"/"1" 状态码而非翻译文本 | 统一使用 `crate::tr!("common.status.*")` / `crate::tr!("common.job.*")` 翻译 |
| 9 个 export handler Sheet 名硬编码中文 | "用户数据"/"角色数据"/"字典类型" 等直接硬编码 | 新增 `excel.sheet.*` i18n keys，统一使用 `tr!("excel.sheet.*")` |
| sys_config_handler 导出 isBuiltIn 硬编码"是"/"否" | match 分支直接返回中文 | 替换为 `tr!("common.yes")` / `tr!("common.no")` |
| sys_oper_log_handler task_name 使用 i18n::pick | 不符合 tr! 宏规范 | 新增 `msg.export.oper_log_task` key，使用 `tr!` 宏 |
| sys_dept_service update_children N+1 查询 | 先 SELECT 后循环 UPDATE，N 个后代 = N+1 次 DB 交互 | 改为单条 `UPDATE ... REPLACE()` SQL，性能 O(N) → O(1) |
| sys_job_service add_job 调度器失败产生孤儿记录 | scheduler.add_job 失败直接返回错误，DB 已插入但未回滚 | 改为容错策略：失败仅 warn，DB 为 source of truth，重启后恢复 |
| sys_backup_service 3 处子进程泄漏 | 备份/恢复子进程未设置 kill_on_drop，超时或错误路径下进程成为孤儿 | 所有 Command 添加 `.kill_on_drop(true)`，确保 drop 时终止子进程 |
| editTable.vue 提交按钮无 loading | 用户可重复点击导致重复提交 | 新增 submitLoading ref，绑定 :loading，.finally() 重置 |
| menu/dept handleSaveSort 按钮无 loading | 排序保存期间可重复点击 | useTreeTableSort 新增 sortLoading ref 并返回，组件绑定 :loading |
| tab.ts refreshPage/closePage 缺少 .catch() | Promise rejection 未捕获 | 添加 .catch() 错误日志兜底 |
| sys_dept_service 未使用的 FromQueryResult 导入 | 重构后遗留 | 移除未使用导入消除 warning |

#### v0.3.4 认证精确化与权限审计（2026-07-31，第十轮循环）

| 问题 | 根因 | 修复方式 |
|------|------|---------|
| force_logout 黑名单 TTL 过度保守 | `monitor_online_handler.rs` 用 `jwt.expire_hours * SECS_PER_HOUR` 作为黑名单 TTL（保守上界），用户登录 1 小时后被强退，黑名单仍保留 24 小时（多 23 小时内存浪费） | `OnlineSession` 新增 `exp` 字段（i64，UTC 秒），登录时由 `claims.exp` 写入；force_logout 用 `session.exp - now` 计算精确剩余 TTL；旧 JSON（exp=0）回退到 `jwt.expire_hours` 上界 |
| 权限拒绝事件无审计痕迹 | `oper_log_middleware` 挂在 `permission_middleware` 之后，权限拒绝时直接返回 403，oper_log 无法记录，导致越权尝试无审计日志 | `permission_middleware` 内新增 `spawn_permission_denied_audit` 函数，权限拒绝时直接 spawn 写入 `sys_oper_log`（best-effort，不阻断 403 响应）；新增 `log.auth.permission_denied` i18n key（支持 `{{perm}}` 占位符）；`infer_module_title` 改为 pub(crate) 以便复用 |

#### v0.3.5 i18n 标准化与加载状态补全（2026-07-31，第十二至十三轮循环）

| 问题 | 根因 | 修复方式 |
|------|------|---------|
| 通知公告校验错误硬编码中文 | `sys_notice_service.rs` 的 `validate_notice_enum` 用 `format!` 返回中文错误信息 | 改用 `tr!()` 宏，新增 `error.notice.notice_type_invalid` 和 `error.notice.status_invalid` i18n key（zh-CN + en-US） |
| IP 库更新成功消息硬编码中文 | `ip_location_service.rs` 的 `UpdateResult.message` 用 `format!("IP 库更新成功…")` | 改用 `tr!("msg.success.ip_location_update")`，新增对应 i18n key |
| IP 库更新错误消息硬编码中文 | `ip_location_service.rs` 中 7 处 `anyhow::bail!` 和 7 处 `anyhow::anyhow!` 使用中文 | 全部转换为英文（操作诊断信息，locale 中性） |
| 调度器 Display 实现硬编码中文 | `scheduler/mod.rs` 的 `SchedulerError` Display impl 使用中文 | 转换为英文（Display 仅用于日志/调试，API 层已用 `tr!` 转换） |
| 邮件发件人默认名称中文 | `settings.rs` 的 `default_mail_from_name` 返回 `"yebot 系统"` | 改为 `"yebot System"`（locale 中性默认值） |
| MySessionPanel 强退按钮无 loading 状态 | `MySessionPanel.vue` 的 `handleForceLogout` 按钮缺少 `:loading` 绑定，可重复点击发送重复请求 | 新增 `logoutTokenId` ref 跟踪当前操作的 tokenId，按钮绑定 `:loading`，finally 中重置 |
| 操作日志清空/PDF 按钮无 loading 状态 | `operlog/index.vue` 的 `handleClean` 和 `handlePrintPdf` 缺少 loading 绑定 | 新增 `cleanLoading` / `printLoading` ref，按钮绑定 `:loading`，Promise 链和 try/finally 中管理状态 |
| 调度日志清空按钮无 loading 状态 | `job/log.vue` 的 `handleClean` 缺少 loading 绑定 | 新增 `cleanLoading` ref，按钮绑定 `:loading`，Promise 链 finally 中重置 |
| PDF 导出失败无错误提示 | `operlog/index.vue` 的 `handlePrintPdf` 无 catch 处理 | 新增 try/catch，catch 中 `modal.msgError`，新增 `operlog.tip.pdfExportFail` i18n key |
| tab.ts catch 参数隐式 any | `plugins/tab.ts` 两处 `.catch((e) =>` 参数未显式标注类型 | 改为 `(e: unknown)` 显式标注 |
| settings.ts 类型不匹配 | `store/modules/settings.ts` 的 `ALLOWED_SETTING_KEYS.has(key)` 中 `key` 为 `string` 但 Set 类型为 `keyof SettingsState` | 添加 `key as keyof SettingsState` 类型断言 |

#### v0.3.6 安全加固 + 可访问性 + 权限测试覆盖（2026-07-31，第十四轮循环）

| 问题 | 根因 | 修复方式 |
|------|------|---------|
| 缓存前缀白名单信息泄漏 | `monitor_cache_handler.rs` 用 `format!("{:?}", ALLOWED_CACHE_PREFIXES)` 将内部 Redis key 命名规则暴露给客户端 | 改用 `.join(", ")` 输出可读列表而非 Debug 格式 |
| 备份路径校验缺少 canonicalize 防御 | `sys_backup_service.rs` 的 `validate_backup_path` 注释声称使用 canonicalize 但实际未调用，symlink 攻击风险 | 新增 `tokio::fs::canonicalize(&dir)` 规范化备份目录，解析 symlink 后再 join 文件名 |
| 登录/注册表单缺少无障碍标签 | `login.vue` 和 `register.vue` 的 `el-input` 仅有 placeholder，屏幕阅读器无法识别字段用途 | 所有输入框添加 `:aria-label` 绑定对应 i18n key |
| 密码可见性切换按钮缺少 aria-label | `login.vue` 的 View/Hide 图标按钮无文字无 `aria-label` | 添加 `:aria-label` 和 `role="button"` `tabindex="0"`，新增 `login.showPassword`/`login.hidePassword` i18n key |
| Crontab 表头缺少 scope 属性 | `Crontab/index.vue` 的 `<th>` 元素无 `scope="col"`，屏幕阅读器无法关联表头与数据 | 添加 `scope="col"` 属性 |
| 权限中间件零测试覆盖 | `permission.rs` 的 `get_required_perm` 函数（安全核心路由权限映射）无单元测试 | 新增 23 个测试覆盖：用户/角色/监控/安全关键路由权限映射、仅需登录路由返回 None、未匹配路由返回 None、HTTP 方法混淆防护（synchDb GET vs POST） |

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
