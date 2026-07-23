# axum-backend 部署文档

> 版本：v0.1.0 | 更新日期：2026-07-12

## 目录

1. [环境要求](#1-环境要求)
2. [依赖服务部署](#2-依赖服务部署)
3. [源码构建](#3-源码构建)
4. [配置说明](#4-配置说明)
5. [数据库初始化](#5-数据库初始化)
6. [IP 归属地数据库](#6-ip-归属地数据库)
7. [启动服务](#7-启动服务)
8. [反向代理配置](#8-反向代理配置)
9. [Docker 部署](#9-docker-部署)
10. [生产环境检查清单](#10-生产环境检查清单)
11. [故障排查](#11-故障排查)

---

## 1. 环境要求

| 组件 | 最低版本 | 推荐版本 |
|------|---------|---------|
| Rust | 1.96+ | 1.96+ |
| MySQL / PostgreSQL / SQLite | 8.0+ / 13+ / 3.35+ | 8.0+ / 15+ / 最新版 |
| Redis | 6.0+ | 7.0+ |
| 操作系统 | Linux x86_64 | Ubuntu 22.04 / CentOS 8+ |

> 数据库支持 MySQL、PostgreSQL 和 SQLite 三种类型，通过 `DATABASE_URL` 协议前缀自动识别：
> - MySQL：`mysql://user:password@host:3306/database`
> - PostgreSQL：`postgres://user:password@host:5432/database`
> - SQLite：`sqlite://./data/yebot.db?mode=rwc`（适合开发/测试环境）

**硬件建议（生产环境）**

| 资源 | 最低配置 | 推荐配置 |
|------|---------|---------|
| CPU | 2 核 | 4 核 |
| 内存 | 2 GB | 4 GB |
| 磁盘 | 20 GB | 50 GB SSD |
| 网络 | 100 Mbps | 1 Gbps |

---

## 2. 依赖服务部署

### 2.1 MySQL 8.0

```bash
# Ubuntu
sudo apt update
sudo apt install mysql-server-8.0
sudo systemctl enable mysql
sudo systemctl start mysql

# 创建数据库和用户
sudo mysql -u root -p
```

```sql
CREATE DATABASE yebot CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER 'yebot'@'%' IDENTIFIED BY 'your_strong_password';
GRANT ALL PRIVILEGES ON yebot.* TO 'yebot'@'%';
FLUSH PRIVILEGES;
```

**PostgreSQL 替代方案**

如使用 PostgreSQL，连接串改为 `postgres://yebot:password@127.0.0.1:5432/yebot`：

```bash
sudo apt install postgresql postgresql-contrib
sudo systemctl enable postgresql
sudo systemctl start postgresql

sudo -u postgres psql
```

```sql
CREATE DATABASE yebot;
CREATE USER yebot WITH PASSWORD 'your_strong_password';
GRANT ALL PRIVILEGES ON DATABASE yebot TO yebot;
```

**SQLite 替代方案（开发/测试环境）**

SQLite 无需独立服务，连接串使用 `sqlite://./data/yebot.db?mode=rwc`，数据库文件自动创建于 `data/` 目录下。

### 2.2 Redis 7.0

```bash
# Ubuntu
sudo apt install redis-server
sudo systemctl enable redis-server
sudo systemctl start redis-server

# 验证连接
redis-cli ping
# 期望输出: PONG
```

**安全加固（生产环境必做）**

编辑 `/etc/redis/redis.conf`：
```
# 设置密码
requirepass your_redis_password

# 禁用危险命令
rename-command FLUSHDB ""
rename-command FLUSHALL ""
rename-command CONFIG ""
```

> 注意：如果禁用了 `FLUSHDB`，缓存监控的"清除全部缓存"功能将不可用。

---

## 3. 源码构建

### 3.1 安装 Rust 工具链

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source $HOME/.cargo/env

# 验证
rustc --version
cargo --version
```

### 3.2 克隆代码

```bash
git clone <your-repo-url> yebot
cd yebot/axum-backend
```

### 3.3 编译构建

**开发环境（Debug 构建）**

```bash
cargo build
```

**生产环境（Release 构建）**

```bash
cargo build --release
```

Release 构建启用了以下优化（见 `Cargo.toml` `[profile.release]`）：
- `opt-level = 3`：最高优化等级
- `lto = "fat"`：全量链接时优化
- `codegen-units = 1`：单代码生成单元（更好优化）
- `strip = true`：移除调试符号（减小二进制体积）

编译产物位于 `target/release/axum-backend`。

### 3.4 执行数据库迁移

```bash
# 设置数据库连接串
export DATABASE_URL="mysql://yebot:your_password@127.0.0.1:3306/yebot"

# 执行迁移（创建 15 张系统表 + 索引 + 初始数据）
cd migration
cargo run
cd ..
```

迁移会创建以下表：
- `sys_user` / `sys_role` / `sys_menu` / `sys_dept` / `sys_post`
- `sys_user_role` / `sys_role_menu` / `sys_user_post` / `sys_role_dept`
- `sys_dict_type` / `sys_dict_data`
- `sys_oper_log` / `sys_logininfor`
- `sys_job` / `sys_job_log`
- `sys_config` / `sys_notice`

初始数据包含：超级管理员账号（admin / admin123）、默认角色、默认菜单、系统字典。

---

## 4. 配置说明

### 4.1 配置文件

```bash
# 从模板创建配置
cp config/config.toml.example config/config.toml
```

编辑 `config/config.toml`：

```toml
[server]
host = "0.0.0.0"
port = 8080
# CORS 允许的 Origin 白名单（生产环境必须显式配置）
cors_origins = ["https://your-domain.com"]
# 可信代理 IP 白名单（CIDR 或精确 IP）
trusted_proxies = ["127.0.0.1"]
# 是否启用 API 文档（生产环境建议 false）
docs_enabled = false

[database]
url = "mysql://yebot:password@127.0.0.1:3306/yebot"
max_connections = 10
min_connections = 1
connect_timeout = 10
idle_timeout = 600

[redis]
url = "redis://:password@127.0.0.1:6379/0"
max_connections = 10

[jwt]
secret = "your_strong_secret_at_least_32_characters_long"
expire_hours = 24
issuer = "yebot"

[log]
level = "info"
sql_logging = false

[upload]
avatar_dir = "uploads/avatar"
avatar_url_prefix = "/uploads/avatar"
avatar_allowed_exts = ["jpg", "jpeg", "png", "gif"]
avatar_max_size = 5242880

[ip_location]
mmdb_path = "data/GeoLite2-City.mmdb"
```

### 4.2 环境变量覆盖

敏感配置支持通过环境变量注入（优先级高于配置文件）：

| 环境变量 | 说明 | 示例 |
|---------|------|------|
| `DATABASE_URL` | 数据库连接串 | `mysql://user:pass@host:3306/db` |
| `REDIS_URL` | Redis 连接串 | `redis://:pass@host:6379/0` |
| `JWT_SECRET` | JWT 签名密钥（≥32 字符） | `my-super-secret-key-32chars!!` |
| `JWT_EXPIRE_HOURS` | JWT 过期小时数 | `24` |
| `SERVER_HOST` | 监听地址 | `0.0.0.0` |
| `SERVER_PORT` | 监听端口 | `8080` |

### 4.3 安全校验

启动时会自动校验以下配置：
- `jwt.secret` 不能包含 `CHANGE_ME` 占位符
- `jwt.secret` 长度必须 ≥ 32 字符
- `database.url` 不能包含 `CHANGE_ME` 占位符

校验失败将拒绝启动，防止生产环境使用不安全配置。

### 4.4 使用 .env 文件

在项目根目录创建 `.env` 文件（已被 `.gitignore` 排除）：

```env
DATABASE_URL=mysql://yebot:password@127.0.0.1:3306/yebot
REDIS_URL=redis://:password@127.0.0.1:6379/0
JWT_SECRET=your_strong_secret_at_least_32_characters_long
```

---

## 5. 数据库初始化

迁移已在 [3.4 节](#34-执行数据库迁移) 完成。初始账号：

| 字段 | 值 |
|------|-----|
| 用户名 | admin |
| 密码 | admin123 |
| 角色 | 超级管理员 |

**首次登录后请立即修改密码。**

---

## 6. IP 归属地数据库

登录日志和操作日志会自动记录 IP 归属地，需要 MaxMindDB 离线数据库。

### 6.1 下载

```bash
mkdir -p data
# 方式一：MaxMind 官方（需注册账号）
# https://dev.maxmind.com/geoip/geolite2-free-geolocation-data

# 方式二：P3TERX 开源镜像
# 国内用户建议通过代理下载
curl -L -o data/GeoLite2-City.mmdb \
  "https://github.com/P3TERX/GeoLite.mmdb/releases/latest/download/GeoLite2-City.mmdb"

# 国内加速
curl -L -o data/GeoLite2-City.mmdb \
  "https://gh-proxy.com/https://github.com/P3TERX/GeoLite.mmdb/releases/latest/download/GeoLite2-City.mmdb"
```

### 6.2 验证

文件大小约 60-70 MB。放置于 `data/GeoLite2-City.mmdb`。

若文件不存在，IP 归属地查询会优雅降级（返回空字符串），不影响业务流程。

### 6.3 更新

建议每月更新一次 mmdb 文件以获取最新的 IP 归属数据。可直接覆盖 `data/GeoLite2-City.mmdb`，无需重启服务（IpLocator 在每次查询时读取内存中的 Reader，更新需重启）。

> 更新 mmdb 文件后需重启服务才能生效。

---

## 7. 启动服务

### 7.1 直接启动

```bash
# 设置环境变量（或通过 .env 文件）
export DATABASE_URL="mysql://yebot:password@127.0.0.1:3306/yebot"
export REDIS_URL="redis://:password@127.0.0.1:6379/0"
export JWT_SECRET="your_strong_secret_at_least_32_characters_long"

# 启动
./target/release/axum-backend
```

输出：
```
2026-07-12T10:00:00Z INFO 服务启动于 http://0.0.0.0:8080
```

### 7.2 Systemd 服务

创建 `/etc/systemd/system/yebot.service`：

```ini
[Unit]
Description=YeBot Axum Backend
After=network.target mysql.service redis-server.service

[Service]
Type=simple
User=yebot
Group=yebot
WorkingDirectory=/opt/yebot
EnvironmentFile=/opt/yebot/.env
ExecStart=/opt/yebot/axum-backend
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable yebot
sudo systemctl start yebot

# 查看日志
sudo journalctl -u yebot -f
```

### 7.3 健康检查

```bash
curl http://localhost:8080/health
# 期望: {"code":200,"msg":"操作成功","data":"ok"}
```

### 7.4 API 文档

开发环境可访问 Swagger UI（需 `docs_enabled = true`）：
- Swagger UI: `http://localhost:8080/swagger-ui`
- OpenAPI JSON: `http://localhost:8080/api-docs/openapi.json`

---

## 8. 反向代理配置

### 8.1 Nginx 配置

```nginx
server {
    listen 80;
    server_name api.your-domain.com;

    # 前端静态资源
    location / {
        root /opt/yebot/frontend/dist;
        try_files $uri $uri/ /index.html;
    }

    # API 反向代理（与前端 .env.production 的 VITE_APP_BASE_API='/prod-api' 对齐）
    # 必须配置 /prod-api/ location，否则 /prod-api/uploads/avatar/xxx.png 等请求会落入 location /
    # 导致前端头像加载 404（FE-AVATAR-001）
    location /prod-api/ {
        proxy_pass http://127.0.0.1:8080/;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        # 文件上传大小限制
        client_max_body_size 10m;

        # 超时设置
        proxy_connect_timeout 30s;
        proxy_read_timeout 60s;
    }

    # 上传文件直连访问（保留作为 fallback，主路径已通过 /prod-api/ 转发）
    location /uploads/ {
        proxy_pass http://127.0.0.1:8080/uploads/;
    }
}
```

### 8.2 HTTPS 配置

```bash
# 使用 Let's Encrypt 获取免费 SSL 证书
sudo apt install certbot python3-certbot-nginx
sudo certbot --nginx -d api.your-domain.com
```

### 8.3 可信代理配置

使用反向代理时，必须在 `config.toml` 中配置 `trusted_proxies`：

```toml
[server]
trusted_proxies = ["127.0.0.1"]
```

否则后端无法正确获取客户端真实 IP（会取到 Nginx 的 IP）。

---

## 9. Docker 部署

### 9.1 Dockerfile

```dockerfile
FROM rust:1.80-slim AS builder

WORKDIR /app
COPY . .
RUN cargo build --release

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY --from=builder /app/target/release/axum-backend .
COPY --from=builder /app/config/config.toml.example ./config/config.toml

EXPOSE 8080
CMD ["./axum-backend"]
```

### 9.2 docker-compose.yml

```yaml
version: '3.8'

services:
  backend:
    build: ./axum-backend
    ports:
      - "8080:8080"
    environment:
      - DATABASE_URL=mysql://yebot:password@db:3306/yebot
      - REDIS_URL=redis://redis:6379/0
      - JWT_SECRET=your_strong_secret_at_least_32_characters_long
    depends_on:
      - db
      - redis
    volumes:
      - ./data:/app/data
      - uploads:/app/uploads

  db:
    image: mysql:8.0
    environment:
      - MYSQL_DATABASE=yebot
      - MYSQL_USER=yebot
      - MYSQL_PASSWORD=password
      - MYSQL_ROOT_PASSWORD=root_password
    volumes:
      - mysql_data:/var/lib/mysql

  redis:
    image: redis:7-alpine
    command: redis-server --requirepass your_redis_password
    volumes:
      - redis_data:/data

volumes:
  mysql_data:
  redis_data:
  uploads:
```

```bash
docker-compose up -d
```

---

## 10. 生产环境检查清单

部署前请逐项确认：

### 安全配置
- [ ] `config.toml` 已从模板复制并修改所有 `CHANGE_ME` 占位符
- [ ] `JWT_SECRET` 通过环境变量注入，长度 ≥ 32 字符
- [ ] `DATABASE_URL` 通过环境变量注入，密码非弱口令
- [ ] `REDIS_URL` 包含 Redis 密码
- [ ] `cors_origins` 仅包含生产域名，不含 `*`
- [ ] `docs_enabled = false`（关闭 Swagger UI）
- [ ] `sql_logging = false`（关闭 SQL 日志）
- [ ] `trusted_proxies` 配置为反向代理真实 IP
- [ ] MySQL 用户仅授权 `yebot.*` 数据库
- [ ] Redis 已设置密码并禁用危险命令

### 数据
- [ ] 数据库迁移已执行（`cargo run` in `migration/`）
- [ ] 默认 admin 密码已修改
- [ ] `data/GeoLite2-City.mmdb` 已下载（可选但推荐）

### 运维
- [ ] Systemd 服务已配置并设置开机自启
- [ ] Nginx 反向代理已配置 HTTPS
- [ ] 日志收集已配置（journalctl / ELK）
- [ ] 数据库备份策略已制定
- [ ] Redis 持久化已配置（如需）
- [ ] 监控告警已配置（Prometheus / Grafana）

### 网络
- [ ] 防火墙仅开放 80/443 端口
- [ ] 8080 端口不对外暴露（仅 Nginx 可访问）
- [ ] MySQL 3306 端口不对外暴露
- [ ] Redis 6379 端口不对外暴露

---

## 11. 故障排查

### 11.1 启动失败

**错误：`jwt.secret 不能使用默认占位符`**

配置中的 `JWT_SECRET` 仍为 `CHANGE_ME`，请通过环境变量注入真实密钥。

**错误：`jwt.secret 长度不足 32 字符`**

JWT 密钥长度不足，请使用至少 32 字符的强密钥。

**错误：`连接数据库失败`**

检查 `DATABASE_URL` 格式：`mysql://user:password@host:3306/database`，确认 MySQL 服务运行中且网络可达。

**错误：`连接 Redis 失败`**

检查 `REDIS_URL` 格式：`redis://:password@host:6379/0`，确认 Redis 服务运行中。

### 11.2 运行时问题

**登录返回 503 "认证服务暂时不可用"**

Redis 连接异常，登录限流和黑名单校验采用 fail-closed 策略。检查 Redis 连接和密码。

**IP 归属地显示为空**

`data/GeoLite2-City.mmdb` 文件不存在或格式错误。下载文件并重启服务。

**头像上传失败 "无法识别的图片格式"**

文件 magic bytes 不匹配允许的格式（jpg/jpeg/png/gif）。确认上传的是真实图片文件。

**Swagger UI 无法访问**

`docs_enabled = false` 或通过非本地访问。生产环境默认关闭，开发环境设为 `true`。

**CORS 错误**

`cors_origins` 未包含前端域名。在 `config.toml` 中添加前端域名。

### 11.3 日志查看

```bash
# Systemd 日志
sudo journalctl -u yebot -f --since "1 hour ago"

# 按级别过滤
sudo journalctl -u yebot -p err

# Docker 日志
docker-compose logs -f backend
```

### 11.4 性能调优

| 参数 | 配置位置 | 建议值 | 说明 |
|------|---------|--------|------|
| `max_connections` | `[database]` | 20-50 | 根据 DB 连接池调整 |
| `max_connections` | `[redis]` | 10 | 当前使用单连接多路复用，此值暂不生效 |
| `expire_hours` | `[jwt]` | 2-24 | 短过期时间更安全 |
| `avatar_max_size` | `[upload]` | 2-5 MB | 根据需求调整 |
