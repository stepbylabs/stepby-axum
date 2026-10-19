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
# workspace 成员与显式声明的 target 必须**逐个**登记（当前成员 = governance + migration；
# 显式 target = [[bench]] hot_paths）。漏一个，依赖缓存层整条静默失效：
#   `failed to load manifest for workspace member /app/governance`
#   `can't find hot_paths bench at benches/hot_paths.rs`
# 这两句原先只被 `|| echo [warn]` 洗成一行警告，于是每次镜像构建都退化成无缓存全量编译，
# 且没有任何一步显式失败（本轮实测踩中两次）。末尾的 grep 是"正向断言"：
# 预编译没真的 Finished 就直接 fail，宁可构建红，也不要慢得没人怀疑。
COPY governance/Cargo.toml governance/
RUN mkdir -p src migration/src governance/src benches && \
    echo "fn main() {}" > src/main.rs && \
    echo "fn main() {}" > migration/src/main.rs && \
    echo "" > governance/src/lib.rs && \
    echo "fn main() {}" > benches/hot_paths.rs && \
    (cargo build --release 2>&1 | tee /tmp/dep-build.log || true) && \
    grep -q "Finished" /tmp/dep-build.log || { \
      echo "[FATAL] 依赖预编译层没有成功：Cargo.toml 声明的成员/target 与本步骤的 stub 清单不一致"; \
      tail -20 /tmp/dep-build.log; exit 1; \
    }; \
    rm -rf src migration/src governance/src benches

# 复制整个工作区（含 Cargo.toml、Cargo.lock、src、migration）
# 覆盖 dummy src，触发仅源码层的增量编译
COPY . .

# 编译 release 版本（默认只构建根包 stepby-axum；migration 是独立工具二进制，
# 不是 stepby-axum 的依赖，cargo build 不会自动构建它，需显式指定 -p migration）
#
# 前端产物前提：本镜像没有 node 阶段，rust-embed 编译期嵌入的 `frontend-dist/` 完全来自
# 上面的 `COPY . .`——构建镜像前必须先在宿主机刷新它（`scripts/build-all.ps1`，或
# `pnpm --dir stepby-vue build:embedded` 后镜像复制）。目录缺失会由 build.rs panic（响亮）；
# 目录存在但内容是上一轮则**不会有任何提示**，产出"新后端 + 旧界面"的镜像（见 docs/deployment.md §3.3）。
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
COPY --from=builder /app/target/release/stepby-axum /app/stepby-axum
COPY --from=builder /app/target/release/migration /app/migration
# 复制配置模板（生产环境通过环境变量覆盖敏感字段，或挂载 config.toml）
COPY --from=builder /app/config /app/config

# 创建运行时目录（上传文件、SQLite 数据、日志）并设置归属
# 三个目录都必须在这里创建：默认日志目录是相对 WORKDIR 的 "logs"（settings.rs 的
# file_path 默认值），而**编排层把 named volume 挂在 /app/logs 时，Docker 只在"镜像里
# 该目录已存在"时才把它的归属复制给新卷**。缺 /app/logs 的话卷根就是 root:root 755，
# 以 appuser 运行的进程会在 tracing-appender 初始化处 panic（实测：failed to create
# log file: Permission denied，backend 永远 unhealthy、frontend 因 depends_on 也起不来）。
RUN mkdir -p /app/uploads /app/data /app/logs && \
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
CMD ["./stepby-axum"]
