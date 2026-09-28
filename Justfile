# axum-backend 常用命令封装（R6-BE-ENG-16）
#
# 使用方式：
#   安装 just：cargo install just  或  scoop install just (Windows)
#   查看所有命令：just --list
#   执行命令：just <recipe-name>
#
# 说明：
# - 所有命令默认在 axum-backend 目录下执行（由 justfile 文件位置决定）
# - 工具链版本由 rust-toolchain.toml 固定为 stable 1.96.0
# - 依赖服务（PostgreSQL/MySQL/Redis）通过 docker compose 启动

# 默认命令：显示帮助
default:
    @just --list

# 编译（debug）
build:
    cargo build

# 编译（release）
release:
    cargo build --release

# 运行后端服务
run *ARGS:
    cargo run -- {{ARGS}}

# 运行 migration 子 crate（数据库迁移）
migrate *ARGS:
    cargo run -p migration -- {{ARGS}}

# 运行单元测试
test:
    cargo test

# 运行 clippy 检查（与 CI 一致：-D warnings）
clippy:
    cargo clippy --all-targets -- -D warnings

# 格式化代码
fmt:
    cargo fmt

# 检查格式化是否符合规范（不修改文件）
fmt-check:
    cargo fmt --check

# 快速检查（不生成产物）
check:
    cargo check

# 检查并修复依赖问题
update:
    cargo update

# 清理构建产物
clean:
    cargo clean

# 启动开发环境数据库容器（PostgreSQL + MySQL + Redis）
dev-db-up:
    docker compose up -d

# 停止开发环境数据库容器
dev-db-down:
    docker compose down

# 停止并删除数据库容器及数据卷（清空数据，谨慎使用）
dev-db-reset:
    docker compose down -v

# 查看数据库容器日志
dev-db-logs:
    docker compose logs -f

# 构建生产 Docker 镜像
docker-build:
    docker build -t stepby-backend:latest .

# 构建开发 Docker 镜像
docker-build-dev:
    docker build -f Dockerfile.dev -t stepby-backend:dev .

# 一键检查（CI 本地等价）：fmt-check + clippy + test
ci-check: fmt-check clippy test

# 生成并打开文档
docs:
    cargo doc --no-deps --open

# 查看 cargo tree
tree:
    cargo tree

# 监听文件变化并自动重新编译（需要 cargo-watch：cargo install cargo-watch）
watch *ARGS:
    cargo watch -x run -- {{ARGS}}
