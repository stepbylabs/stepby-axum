// stepby-axum/src/lib.rs
//! stepby-axum 库入口
//! 声明全部 17 个模块，供 main.rs 与测试调用

// T-05：编译期嵌入 locales/*.yml，默认回退 zh-CN。
// 之后任意位置可用 `rust_i18n::t!("error.common.not_found", locale = &loc)`。
rust_i18n::i18n!("locales", fallback = "zh-CN");

// ========== 配置管理 ==========
pub mod config;

// ========== 通用能力 ==========
pub mod common;

// ========== 数据连接 ==========
pub mod db;

// ========== SeaORM 实体层 ==========
pub mod entity;

// ========== 数据访问层 ==========
pub mod repository;

// ========== 业务逻辑层 ==========
pub mod service;

// ========== AI 助手（NL2SQL Copilot，方案 topic-ai-nl2sql-v4/v4.1）==========
pub mod ai;

// ========== HTTP Handler 层 ==========
pub mod handler;

// ========== 中间件 ==========
pub mod middleware;

// ========== 路由定义 ==========
pub mod router;

// ========== OpenAPI 文档定义 ==========
pub mod docs;

// ========== JWT 工具 ==========
pub mod jwt;

// ========== 初始化编排 ==========
pub mod initialize;

// ========== 通用工具 ==========
pub mod utils;

// ========== 应用状态 ==========
pub mod state;

// ========== 日志体系 ==========
pub mod logger;

// ========== 可观测性（慢请求/错误聚合/Prometheus 指标）==========
pub mod observability;

// ========== 定时任务调度内核 ==========
pub mod scheduler;

// ========== 前端静态资源嵌入 ==========
pub mod embedded_assets;

// ========== 文件存储抽象（F1：本地 / MinIO-S3）==========
pub mod storage;

// ========== 共享态存储抽象（SharedStore：[cache].mode = local | redis 双档）==========
pub mod shared_store;

// ========== 审计合规域（数据变更留痕：diff 记录 + CSV 导出）==========
pub mod audit;

// ========== 集成测试（login → getInfo 冒烟）==========
// 仅在 `cargo test` 下编译；复用 crate 内部 pub 项构造隔离的 AppState。
#[cfg(test)]
mod integration_tests;
