// axum-backend/src/repository/mod.rs
//! 数据访问层（Repository Layer）
//!
//! 职责：封装数据库查询操作，仅与 SeaORM 交互
//! 依赖方向：Handler → Service → Repository → SeaORM
//!
//! 模块组织：
//! - base.rs: 通用 BaseRepository<E> 泛型基类
//! - sys_*.rs: 各实体专用 Repository，扩展 BaseRepository 并添加实体特有查询

pub mod base;
pub mod gen_table;
pub mod sys_backup_log;
pub mod sys_config;
pub mod sys_dept;
pub mod sys_dict_data;
pub mod sys_dict_type;
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
pub mod sys_oauth_provider;
pub mod sys_oauth_user;
pub mod sys_oper_log;
pub mod sys_post;
pub mod sys_rate_limit;
pub mod sys_report;
pub mod sys_report_sub;
pub mod sys_role;
pub mod sys_role_dept;
pub mod sys_role_menu;
pub mod sys_task;
pub mod sys_user;
pub mod sys_user_post;
pub mod sys_user_pref;
pub mod sys_user_role;
pub mod sys_web_hook;
pub mod sys_web_hook_log;

#[cfg(test)]
pub mod test_support;

pub use base::BaseRepository;
pub use sys_rate_limit::SysRateLimitRepository;
pub use sys_report::SysReportRepository;
pub use sys_report_sub::SysReportSubRepository;
