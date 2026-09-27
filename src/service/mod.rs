// axum-backend/src/service/mod.rs
//! 业务逻辑层（Service Layer）
//!
//! 职责：封装全部业务逻辑、事务控制、参数校验
//! 依赖方向：Handler → Service → Repository → Entity
//! 约束：Service 层完全独立，不依赖任何 Web 框架类型（axum / tower / tower-http）
//!
//! 模块组织：
//! - sys_user_service.rs: 用户模块（用户 CRUD、密码加密校验、用户角色分配、状态启停）
//! - sys_role_service.rs: 角色模块（角色 CRUD、角色菜单绑定、数据权限配置、级联删除校验）
//! - sys_menu_service.rs: 菜单模块（菜单 CRUD、树形结构递归组装、权限标识校验）
//! - auth_service.rs: 认证服务（登录、登出、验证码、getInfo、getRouters）

pub mod acme_service;
pub mod auth_service;
pub mod event_outbox_service;
pub mod gen_table_service;
pub mod ip_location_service;
pub mod mailer_service;
pub mod scim_group_service;
pub mod scim_service;
pub mod sso_service;
pub mod sys_backup_service;
pub mod sys_config_service;
pub mod sys_dept_service;
pub mod sys_dict_service;
pub mod sys_flow_service;
pub mod sys_frontend_error_service;
pub mod sys_http_debug_service;
pub mod sys_job_service;
pub mod sys_logininfor_service;
pub mod sys_menu_service;
pub mod sys_msg_service;
pub mod sys_notice_service;
pub mod sys_oauth_service;
pub mod sys_oper_log_service;
pub mod sys_pat_service;
pub mod sys_post_service;
pub mod sys_rate_limit_service;
pub mod sys_report_service;
pub mod sys_role_service;
pub mod sys_task_service;
pub mod sys_tenant_domain_service;
pub mod sys_tenant_nav_service;
pub mod sys_tenant_service;
pub mod sys_user_pref_service;
pub mod sys_user_service;
pub mod sys_web_hook_service;
pub mod user_erasure_service;
pub mod webauthn_service;

pub use auth_service::AuthService;
pub use gen_table_service::GenTableService;
pub use ip_location_service::IpLocationService;
pub use mailer_service::MailerService;
pub use sso_service::SsoService;
pub use sys_backup_service::SysBackupService;
pub use sys_config_service::SysConfigService;
pub use sys_dept_service::SysDeptService;
pub use sys_dict_service::SysDictService;
pub use sys_flow_service::SysFlowService;
pub use sys_frontend_error_service::SysFrontendErrorService;
pub use sys_http_debug_service::SysHttpDebugService;
pub use sys_job_service::SysJobService;
pub use sys_logininfor_service::SysLogininforService;
pub use sys_menu_service::SysMenuService;
pub use sys_msg_service::SysMsgService;
pub use sys_notice_service::SysNoticeService;
pub use sys_oauth_service::SysOauthService;
pub use sys_oper_log_service::SysOperLogService;
pub use sys_pat_service::SysPatService;
pub use sys_post_service::SysPostService;
pub use sys_rate_limit_service::SysRateLimitService;
pub use sys_report_service::SysReportService;
pub use sys_role_service::SysRoleService;
pub use sys_task_service::SysTaskService;
pub use sys_tenant_domain_service::SysTenantDomainService;
pub use sys_tenant_nav_service::SysTenantNavService;
pub use sys_tenant_service::SysTenantService;
pub use sys_user_pref_service::SysUserPrefService;
pub use sys_user_service::SysUserService;
pub use sys_web_hook_service::SysWebHookService;
pub use user_erasure_service::UserErasureService;
pub use webauthn_service::WebauthnService;

use crate::common::TreeSelectVo;
use crate::entity::sys_dept::Model as SysDeptModel;

/// 将扁平部门列表组装为 TreeSelect 树结构
///
/// - 根节点 parent_id = 0 或 null
/// - disabled = status != "0"（停用状态禁用选择）
pub fn build_dept_tree_select(list: &[SysDeptModel], root_parent_id: i64) -> Vec<TreeSelectVo> {
    let mut roots: Vec<TreeSelectVo> = list
        .iter()
        .filter(|d| d.parent_id.unwrap_or(0) == root_parent_id)
        .map(dept_model_to_tree_select)
        .collect();
    for root in &mut roots {
        build_dept_tree_children(root, list, 0);
    }
    roots
}

/// 部门树最大深度（P1：防脏数据 parent_id 成环导致无限递归栈溢出）
const MAX_DEPT_TREE_DEPTH: usize = 30;

pub fn build_dept_tree_children(node: &mut TreeSelectVo, list: &[SysDeptModel], depth: usize) {
    if depth >= MAX_DEPT_TREE_DEPTH {
        tracing::warn!(
            "部门树构建达到最大深度 {}（可能存在 parent_id 循环引用），停止递归",
            MAX_DEPT_TREE_DEPTH
        );
        return;
    }
    let node_id = node.id;
    let children: Vec<TreeSelectVo> = list
        .iter()
        .filter(|d| d.parent_id.unwrap_or(0) == node_id)
        .map(dept_model_to_tree_select)
        .collect();
    if children.is_empty() {
        return;
    }
    node.children = children;
    for kid in &mut node.children {
        build_dept_tree_children(kid, list, depth + 1);
    }
}

/// 将 SysDeptModel 转换为 TreeSelectVo 节点
pub fn dept_model_to_tree_select(d: &SysDeptModel) -> TreeSelectVo {
    TreeSelectVo {
        id: d.dept_id,
        label: d.dept_name.clone(),
        disabled: d.status.as_deref() != Some("0"),
        children: vec![],
    }
}
