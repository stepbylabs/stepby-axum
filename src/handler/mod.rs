// stepby-axum/src/handler/mod.rs

/// API 出口契约总锁（批七十四 轮 27）：错误契约 / 用户表列投影 / 绝对路径折叠单源
#[cfg(test)]
pub mod api_contract_guard;
pub mod auth_handler;
pub mod common_handler;
pub mod common_search_handler;
pub mod data_rule_handler;
/// 死面与假跳板总锁（批七十四）：零调用者符号必须删除或接线，不得挂抑制静默
#[cfg(test)]
pub mod dead_face_guard;
/// 安全/一致性守卫的读取失败不得静默放行总锁（批七十一）
#[cfg(test)]
pub mod fail_closed_guard;
pub mod file_handler;
pub mod flow_definition_handler;
pub mod flow_handler;
pub mod health;
pub mod health_probes;
pub mod ip_location_handler;
pub mod monitor_alert_handler;
pub mod monitor_cache_handler;
pub mod monitor_log_handler;
pub mod monitor_observability_handler;
pub mod monitor_online_handler;
pub mod monitor_server_handler;
/// 生产代码防 panic 守卫（批六十六）：handler 不得 `.unwrap()`
#[cfg(test)]
pub mod no_panic_guard;
pub mod op_recording_handler;
/// 出站组件指标覆盖总锁（批七十四）：每个 `reqwest::Client` 构造点必须有可验证的结局归属
#[cfg(test)]
pub mod outbound_metrics_guard;
pub mod report_dataset_handler;
pub mod scim_handler;
pub mod sso_handler;
pub mod sys_backup_handler;
pub mod sys_config_handler;
pub mod sys_dept_handler;
pub mod sys_dict_handler;
pub mod sys_frontend_error_handler;
pub mod sys_http_debug_handler;
pub mod sys_job_handler;
pub mod sys_job_log_handler;
pub mod sys_logininfor_handler;
pub mod sys_menu_handler;
pub mod sys_msg_handler;
pub mod sys_notice_handler;
pub mod sys_oauth_handler;
pub mod sys_oper_log_handler;
pub mod sys_pat_handler;
pub mod sys_post_handler;
pub mod sys_rate_limit_handler;
pub mod sys_report_board_handler;
pub mod sys_report_handler;
pub mod sys_role_field_perm_handler;
pub mod sys_role_handler;
pub mod sys_scim_group_handler;
pub mod sys_task_handler;
pub mod sys_tenant_domain_handler;
pub mod sys_tenant_handler;
pub mod sys_tenant_nav_handler;
pub mod sys_user_handler;
pub mod sys_user_pref_handler;
pub mod sys_web_hook_handler;
pub mod sys_webhook_event_handler;
pub mod tool_gen_handler;
pub mod totp_handler;
pub mod upload_chunk_handler;
pub mod upload_config_handler;
pub mod webauthn_handler;
pub mod ws_handler;

pub use health::{health, metrics};
