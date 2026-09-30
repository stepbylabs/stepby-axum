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

/// 解析实际导出目录（改名/clone 布局免疫的探测兜底）：
/// 1. `.cargo/config.toml` [env] 注入的 `TS_RS_EXPORT_DIR` 目录**存在** → 原样使用（常规路径，零行为变化）；
/// 2. 否则按序探测常见兄弟仓布局（stepby-<技术栈> 命名规范；历史名 frontend-vue/stepby-ui 已随改名清理）；
/// 3. 全部未命中 → 回落 env 原值（保持 `Config::from_env` 的既有报错行为）。
///
/// 背景：导出目录跨仓硬编码是目录改名链路的最大断点（本项目已三次改名各断一次），
/// 此探测使 `cargo ts` 在目录改名后无需同步修改 `.cargo/config.toml` 即可继续工作。
/// 注：`cargo test` 的 export_bindings_* 测试不走本入口，仍依赖 env 默认值（常规布局下二者一致）。
fn effective_export_dir() -> String {
    let from_env = std::env::var("TS_RS_EXPORT_DIR")
        .unwrap_or_else(|_| "../stepby-vue/src/types/api/generated".to_string());
    if std::path::Path::new(&from_env).is_dir() {
        return from_env;
    }
    let candidates = [
        "../stepby-vue/src/types/api/generated",
        "stepby-vue/src/types/api/generated",
    ];
    for c in candidates {
        if std::path::Path::new(c).is_dir() {
            eprintln!("[export_ts] TS_RS_EXPORT_DIR 指向的目录不存在，探测到可用导出目录: {c}");
            return c.to_string();
        }
    }
    from_env
}

fn main() {
    let dir = effective_export_dir();
    // 单线程入口内进程级 env 覆盖（edition 2024 要求 unsafe），供 Config::from_env 统一消费
    unsafe { std::env::set_var("TS_RS_EXPORT_DIR", &dir) };
    let cfg = Config::from_env();
    let (total, failed) = export_all!(
        &cfg,
        // ---- entity：各业务实体出参（SeaORM 生成的 Model，经 export_to 命名） ----
        stepby_axum::entity::sys_config::Model,
        stepby_axum::entity::sys_dept::Model,
        stepby_axum::entity::sys_dict_data::Model,
        stepby_axum::entity::sys_dict_type::Model,
        stepby_axum::entity::sys_frontend_error::Model,
        stepby_axum::entity::sys_job::Model,
        stepby_axum::entity::sys_job_log::Model,
        stepby_axum::entity::sys_logininfor::Model,
        stepby_axum::entity::sys_menu::Model,
        stepby_axum::entity::sys_msg_channel::Model,
        stepby_axum::entity::sys_msg_send_log::Model,
        stepby_axum::entity::sys_msg_template::Model,
        stepby_axum::entity::sys_notice::Model,
        stepby_axum::entity::sys_oauth_provider::Model,
        stepby_axum::entity::sys_oauth_user::Model,
        stepby_axum::entity::sys_oper_log::Model,
        stepby_axum::entity::sys_post::Model,
        stepby_axum::entity::sys_rate_limit::Model,
        stepby_axum::entity::sys_report::Model,
        stepby_axum::entity::sys_report_sub::Model,
        stepby_axum::entity::sys_role::Model,
        stepby_axum::entity::sys_tenant::Model,
        stepby_axum::entity::sys_tenant_package::Model,
        stepby_axum::entity::sys_user::Model,
        stepby_axum::entity::sys_user_pref::Model,
        stepby_axum::entity::sys_web_hook::Model,
        stepby_axum::entity::sys_web_hook_log::Model,
        // ---- entity：SCIM Group / 多部门任职（v5-D12 Group） ----
        stepby_axum::entity::sys_scim_group::Model,
        stepby_axum::entity::sys_scim_group_binding::Model,
        stepby_axum::entity::sys_scim_group_member::Model,
        stepby_axum::entity::sys_user_dept::Model,
        // ---- service：SSO / OIDC Provider（应用私有 API） ----
        stepby_axum::service::sso_service::SsoClientVo,
        stepby_axum::service::sso_service::SsoClientQueryDto,
        stepby_axum::service::sso_service::SsoClientUpsertDto,
        stepby_axum::service::sso_service::SsoClientCreateResult,
        stepby_axum::service::sso_service::SsoClientRotateResult,
        stepby_axum::service::sso_service::ConsentDto,
        stepby_axum::service::sso_service::SsoGrantVo,
        // ---- service：SCIM Group 管理（v5-D12 Group） ----
        stepby_axum::service::scim_group_service::ScimGroupAdminRow,
        stepby_axum::service::scim_group_service::ScimGroupAdminDetail,
        stepby_axum::service::scim_group_service::ScimGroupAdminMember,
        stepby_axum::handler::sys_scim_group_handler::ScimGroupAdminUpsertDto,
        // ---- service：其它 VO / DTO ----
        stepby_axum::service::sys_job_service::JobVo,
        stepby_axum::service::sys_logininfor_service::LoginDailyStat,
        stepby_axum::service::sys_pat_service::PatVo,
        stepby_axum::service::sys_pat_service::CreatePatDto,
        stepby_axum::service::sys_pat_service::CreatePatResult,
        stepby_axum::service::sys_role_service::RoleVo,
        stepby_axum::service::sys_user_service::UserVo,
        stepby_axum::service::sys_user_service::UserAuthRoleVo,
        stepby_axum::service::sys_user_service::ProfileVo,
        stepby_axum::service::sys_user_service::UserFormVo,
        // ---- service：WebHook 回调配置出参 VO（脱敏：不含 secret 原文） ----
        stepby_axum::service::sys_web_hook_service::WebHookVo,
        // ---- service：GDPR 用户匿名化（被遗忘权）报告 ----
        stepby_axum::service::user_erasure_service::UserErasureReport,
        // ---- service：审批工作流（W-8 已办视图行） ----
        stepby_axum::service::sys_flow_service::FlowDoneVo,
        // ---- service：租户套餐能力位（三层开关中间层，管理面） ----
        stepby_axum::service::sys_tenant_service::PackageFeatureItemVo,
        stepby_axum::service::sys_tenant_service::PackageFeaturesVo,
        stepby_axum::service::sys_tenant_service::PackageFeaturesUpdateDto,
        // ---- service：WebAuthn / Passkey（能力位 auth.webauthn） ----
        stepby_axum::service::webauthn_service::WebauthnRegisterFinishDto,
        stepby_axum::service::webauthn_service::AttestationResponseDto,
        stepby_axum::service::webauthn_service::WebauthnLoginStartDto,
        stepby_axum::service::webauthn_service::WebauthnLoginFinishDto,
        stepby_axum::service::webauthn_service::AssertionResponseDto,
        stepby_axum::service::webauthn_service::WebauthnCredentialVo,
    );

    if !failed.is_empty() {
        eprintln!("[export_ts] 完成：{total} 个类型，失败 {} 个", failed.len());
        std::process::exit(1);
    }
    println!("[export_ts] 完成：{total} 个类型已全部导出");
}
