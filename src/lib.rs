// axum-backend/src/lib.rs
//! axum-backend 库入口
//! 声明全部 14 个模块，供 main.rs 与测试调用

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

// ========== 定时任务调度内核 ==========
pub mod scheduler;

// ========== 前端静态资源嵌入 ==========
pub mod embedded_assets;
