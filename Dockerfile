# ===== 构建阶段 =====
# INFRA-001：rust-toolchain.toml 跟随 stable channel（最低 1.96，允许更高版本）；镜像钉具体版本保证构建可复现，可按需升级
# 原 rust:1.81 不支持 edition 2024（需 1.85+）和 let-chains 稳定语法（需 1.88+）
FROM rust:1.96-bookworm AS builder
WORKDIR /app

# 依赖缓存层：先复制 Cargo.toml/Cargo.lock，模拟空 src 预编译依赖
# 这样在源码改动时，只要 Cargo.toml/Cargo.lock 未变，依赖缓存层即可复用，避免完整依赖重编译
# migration 是 workspace 子 crate，需一并复制其 Cargo.toml 以解析 workspace 依赖图
#
# 说明：`|| true` 是 Docker 缓存优化的容错策略——依赖预编译失败时不阻断镜像构建，
# 真正的编译错误会在后续 `cargo build --release` 步骤暴露。
# 失败原因通常是网络问题（crates.io 拉取失败）或 Cargo.lock 解析冲突，
# 此时依赖缓存层为空，下一步会完整编译，不影响最终构建正确性。
COPY Cargo.toml Cargo.lock ./
COPY migration/Cargo.toml migration/
RUN mkdir -p src migration/src && \
    echo "fn main() {}" > src/main.rs && \
    echo "fn main() {}" > migration/src/main.rs && \
    (cargo build --release 2>&1 | tee /tmp/dep-build.log || echo "[warn] 依赖预编译失败，将在下一步完整编译") && \
    rm -rf src migration/src

# 复制整个工作区（含 Cargo.toml、Cargo.lock、src、migration）
# 覆盖 dummy src，触发仅源码层的增量编译
COPY . .

# 编译 release 版本（默认只构建根包 axum-backend；migration 是独立工具二进制，
# 不是 axum-backend 的依赖，cargo build 不会自动构建它，需显式指定 -p migration）
RUN cargo build --release
# 显式构建 migration 独立二进制（用于数据库迁移），否则 target/release/migration 不会产出
RUN cargo build --release -p migration

# ===== 运行阶段 =====
FROM debian:bookworm-slim
# 运行时依赖：ca-certificates（HTTPS 请求）；项目使用 rustls，无需 libssl
# curl 用于 HEALTHCHECK 健康探测
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl && \
    rm -rf /var/lib/apt/lists/*

# INFRA-002：创建非 root 用户 appuser，遵循最小权限原则
# 容器内默认以 root 运行会扩大攻击面（容器逃逸时直接获得宿主 root 权限）
# 使用 useradd 创建系统用户（无 home 目录、无登录 shell），UID 固定为 1000 避免与宿主用户冲突
RUN useradd --no-create-home --system --uid 1000 appuser

WORKDIR /app

# 复制编译产物
COPY --from=builder /app/target/release/axum-backend /app/axum-backend
COPY --from=builder /app/target/release/migration /app/migration
# 复制配置模板（生产环境通过环境变量覆盖敏感字段，或挂载 config.toml）
COPY --from=builder /app/config /app/config

# 创建运行时目录（上传文件、SQLite 数据、日志等）并设置归属
# uploads / data 目录需 appuser 可写，否则服务启动失败
RUN mkdir -p /app/uploads /app/data && \
    chown -R appuser:appuser /app

# 切换到非 root 用户运行
USER appuser

ENV TZ=Asia/Shanghai
EXPOSE 8080

# 健康检查：K8s/编排平台据此判断容器就绪状态
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD curl -f http://localhost:8080/health || exit 1

# 默认启动后端服务
# 敏感配置通过环境变量注入：DATABASE_URL / REDIS_URL / JWT_SECRET / JWT_EXPIRE_HOURS
CMD ["./axum-backend"]
