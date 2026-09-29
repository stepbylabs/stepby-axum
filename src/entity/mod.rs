// backend-axum/src/entity/mod.rs
//! SeaORM 实体层：系统核心表的实体定义
//!
//! 字段命名规范：
//! - 数据库列名：snake_case（如 user_id、create_time）
//! - Rust 字段名：snake_case（与数据库对齐）
//! - 序列化输出：camelCase（通过 #[serde(rename_all = "camelCase")] 自动转换）

pub mod prelude;

pub mod flow_demo_doc;
pub mod gen_table;
pub mod gen_table_column;
pub mod sys_backup_log;
pub mod sys_config;
pub mod sys_dept;
pub mod sys_dict_data;
pub mod sys_dict_type;
pub mod sys_flow_log;
pub mod sys_flow_task;
pub mod sys_frontend_error;
pub mod sys_job;
pub mod sys_job_log;
pub mod sys_logininfor;
pub mod sys_menu;
pub mod sys_msg_channel;
pub mod sys_msg_send_log;
pub mod sys_msg_template;
pub mod sys_notice;
pub mod sys_notice_read;
pub mod sys_oauth_client;
pub mod sys_oauth_consent;
pub mod sys_oauth_provider;
pub mod sys_oauth_user;
pub mod sys_oper_log;
pub mod sys_pat;
pub mod sys_post;
pub mod sys_rate_limit;
pub mod sys_report;
pub mod sys_report_sub;
pub mod sys_role;
pub mod sys_role_dept;
pub mod sys_role_menu;
pub mod sys_scim_group;
pub mod sys_scim_group_binding;
pub mod sys_scim_group_member;
pub mod sys_task;
pub mod sys_tenant;
pub mod sys_tenant_domain;
pub mod sys_tenant_menu;
pub mod sys_tenant_migration_map;
pub mod sys_tenant_package;
pub mod sys_user;
pub mod sys_user_credential;
pub mod sys_user_dept;
pub mod sys_user_post;
pub mod sys_user_pref;
pub mod sys_user_role;
pub mod sys_web_hook;
pub mod sys_web_hook_log;
