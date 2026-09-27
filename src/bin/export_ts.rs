//! ts-rs TypeScript 绑定导出的**独立触发入口**（无需运行整套 `cargo test`）。
//!
//! 用法（二选一）：
//!   cargo ts                        # 见 .cargo/config.toml 的 [alias]
//!   cargo run --bin export_ts
//!
//! 输出目录由 `.cargo/config.toml` 的 `[env] TS_RS_EXPORT_DIR` 提供，
//! `Config::from_env()` 运行时读取，与 `#[ts(export)]` 自动生成的导出测试同源，
//! 因此这里与 `cargo test` 生成的文件完全一致。
//!
//! 说明：`TS::export_all` 会**递归导出该类型的全部依赖**，故此处只需列出各「根」
//! VO/DTO；新增带 `#[ts(export)]` 的类型后，若它不是任何已列出类型的依赖，
//! 需在此登记一行——但 `cargo test`（derive 自动生成 export_bindings_* 测试）始终是零漂移兜底。
use ts_rs::{Config, TS};

/// 对每个类型调用 `export_all`，收集并汇总失败项，最终据此决定退出码。
macro_rules! export_all {
    ($cfg:expr, $($ty:path),+ $(,)?) => {{
        let cfg = $cfg;
        let mut total = 0usize;
        let mut failed: Vec<&'static str> = Vec::new();
        $(
            total += 1;
            if let Err(e) = <$ty as TS>::export_all(cfg) {
                let name = std::any::type_name::<$ty>();
                failed.push(name);
                eprintln!("[export_ts] 导出 {name} 失败: {e}");
            }
        )+
        (total, failed)
    }};
}

fn main() {
    let cfg = Config::from_env();
    let (total, failed) = export_all!(
        &cfg,
        // ---- entity：各业务实体出参（SeaORM 生成的 Model，经 export_to 命名） ----
        axum_backend::entity::sys_config::Model,
        axum_backend::entity::sys_dept::Model,
        axum_backend::entity::sys_dict_data::Model,
        axum_backend::entity::sys_dict_type::Model,
        axum_backend::entity::sys_frontend_error::Model,
        axum_backend::entity::sys_job::Model,
        axum_backend::entity::sys_job_log::Model,
        axum_backend::entity::sys_logininfor::Model,
        axum_backend::entity::sys_menu::Model,
        axum_backend::entity::sys_msg_channel::Model,
        axum_backend::entity::sys_msg_send_log::Model,
        axum_backend::entity::sys_msg_template::Model,
        axum_backend::entity::sys_notice::Model,
        axum_backend::entity::sys_oauth_provider::Model,
        axum_backend::entity::sys_oauth_user::Model,
        axum_backend::entity::sys_oper_log::Model,
        axum_backend::entity::sys_post::Model,
        axum_backend::entity::sys_rate_limit::Model,
        axum_backend::entity::sys_report::Model,
        axum_backend::entity::sys_report_sub::Model,
        axum_backend::entity::sys_role::Model,
        axum_backend::entity::sys_tenant::Model,
        axum_backend::entity::sys_tenant_package::Model,
        axum_backend::entity::sys_user::Model,
        axum_backend::entity::sys_user_pref::Model,
        axum_backend::entity::sys_web_hook::Model,
        axum_backend::entity::sys_web_hook_log::Model,
        // ---- entity：SCIM Group / 多部门任职（v5-D12 Group） ----
        axum_backend::entity::sys_scim_group::Model,
        axum_backend::entity::sys_scim_group_binding::Model,
        axum_backend::entity::sys_scim_group_member::Model,
        axum_backend::entity::sys_user_dept::Model,
        // ---- service：SSO / OIDC Provider（应用私有 API） ----
        axum_backend::service::sso_service::SsoClientVo,
        axum_backend::service::sso_service::SsoClientQueryDto,
        axum_backend::service::sso_service::SsoClientUpsertDto,
        axum_backend::service::sso_service::SsoClientCreateResult,
        axum_backend::service::sso_service::SsoClientRotateResult,
        axum_backend::service::sso_service::ConsentDto,
        axum_backend::service::sso_service::SsoGrantVo,
        // ---- service：SCIM Group 管理（v5-D12 Group） ----
        axum_backend::service::scim_group_service::ScimGroupAdminRow,
        axum_backend::service::scim_group_service::ScimGroupAdminDetail,
        axum_backend::service::scim_group_service::ScimGroupAdminMember,
        axum_backend::handler::sys_scim_group_handler::ScimGroupAdminUpsertDto,
        // ---- service：其它 VO / DTO ----
        axum_backend::service::sys_job_service::JobVo,
        axum_backend::service::sys_logininfor_service::LoginDailyStat,
        axum_backend::service::sys_pat_service::PatVo,
        axum_backend::service::sys_pat_service::CreatePatDto,
        axum_backend::service::sys_pat_service::CreatePatResult,
        axum_backend::service::sys_role_service::RoleVo,
        axum_backend::service::sys_user_service::UserVo,
        axum_backend::service::sys_user_service::UserAuthRoleVo,
        axum_backend::service::sys_user_service::ProfileVo,
        axum_backend::service::sys_user_service::UserFormVo,
        // ---- service：GDPR 用户匿名化（被遗忘权）报告 ----
        axum_backend::service::user_erasure_service::UserErasureReport,
        // ---- service：审批工作流（W-8 已办视图行） ----
        axum_backend::service::sys_flow_service::FlowDoneVo,
        // ---- service：租户套餐能力位（三层开关中间层，管理面） ----
        axum_backend::service::sys_tenant_service::PackageFeatureItemVo,
        axum_backend::service::sys_tenant_service::PackageFeaturesVo,
        axum_backend::service::sys_tenant_service::PackageFeaturesUpdateDto,
    );

    if !failed.is_empty() {
        eprintln!("[export_ts] 完成：{total} 个类型，失败 {} 个", failed.len());
        std::process::exit(1);
    }
    println!("[export_ts] 完成：{total} 个类型已全部导出");
}
