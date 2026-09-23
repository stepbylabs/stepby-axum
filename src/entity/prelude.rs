//! 实体 prelude：重导出所有实体模块的公共类型
//!
//! 使用方式：`use crate::entity::prelude::*;`

pub use super::sys_config::{
    ActiveModel as SysConfigActiveModel, Column as SysConfigColumn, Entity as SysConfig,
    Model as SysConfigModel,
};
pub use super::sys_dict_data::{
    ActiveModel as SysDictDataActiveModel, Column as SysDictDataColumn, Entity as SysDictData,
    Model as SysDictDataModel,
};
pub use super::sys_dict_type::{
    ActiveModel as SysDictTypeActiveModel, Column as SysDictTypeColumn, Entity as SysDictType,
    Model as SysDictTypeModel,
};
pub use super::sys_job::{
    ActiveModel as SysJobActiveModel, Column as SysJobColumn, Entity as SysJob,
    Model as SysJobModel,
};
pub use super::sys_job_log::{
    ActiveModel as SysJobLogActiveModel, Column as SysJobLogColumn, Entity as SysJobLog,
    Model as SysJobLogModel,
};
pub use super::sys_logininfor::{
    ActiveModel as SysLogininforActiveModel, Column as SysLogininforColumn,
    Entity as SysLogininfor, Model as SysLogininforModel,
};
pub use super::sys_menu::{
    ActiveModel as SysMenuActiveModel, Column as SysMenuColumn, Entity as SysMenu,
    Model as SysMenuModel,
};
pub use super::sys_msg_channel::{
    ActiveModel as SysMsgChannelActiveModel, Column as SysMsgChannelColumn,
    Entity as SysMsgChannel, Model as SysMsgChannelModel,
};
pub use super::sys_msg_send_log::{
    ActiveModel as SysMsgSendLogActiveModel, Column as SysMsgSendLogColumn,
    Entity as SysMsgSendLog, Model as SysMsgSendLogModel,
};
pub use super::sys_msg_template::{
    ActiveModel as SysMsgTemplateActiveModel, Column as SysMsgTemplateColumn,
    Entity as SysMsgTemplate, Model as SysMsgTemplateModel,
};
pub use super::sys_notice::{
    ActiveModel as SysNoticeActiveModel, Column as SysNoticeColumn, Entity as SysNotice,
    Model as SysNoticeModel,
};
pub use super::sys_oper_log::{
    ActiveModel as SysOperLogActiveModel, Column as SysOperLogColumn, Entity as SysOperLog,
    Model as SysOperLogModel,
};
pub use super::sys_role::{
    ActiveModel as SysRoleActiveModel, Column as SysRoleColumn, Entity as SysRole,
    Model as SysRoleModel,
};
pub use super::sys_role_menu::{
    ActiveModel as SysRoleMenuActiveModel, Column as SysRoleMenuColumn, Entity as SysRoleMenu,
    Model as SysRoleMenuModel,
};
pub use super::sys_user::{
    ActiveModel as SysUserActiveModel, Column as SysUserColumn, Entity as SysUser,
    Model as SysUserModel,
};
pub use super::sys_user_role::{
    ActiveModel as SysUserRoleActiveModel, Column as SysUserRoleColumn, Entity as SysUserRole,
    Model as SysUserRoleModel,
};
// 补全其余实体模块的公共类型重导出（P3：prelude 完整性）
pub use super::flow_demo_doc::{
    ActiveModel as FlowDemoDocActiveModel, Column as FlowDemoDocColumn, Entity as FlowDemoDoc,
    Model as FlowDemoDocModel,
};
pub use super::gen_table::{
    ActiveModel as GenTableActiveModel, Column as GenTableColumn, Entity as GenTable,
    Model as GenTableModel,
};
pub use super::gen_table_column::{
    ActiveModel as GenTableColumnActiveModel, Column as GenTableColumnColumn,
    Entity as GenTableColumnEntity, Model as GenTableColumnModel,
};
pub use super::sys_backup_log::{
    ActiveModel as SysBackupLogActiveModel, Column as SysBackupLogColumn, Entity as SysBackupLog,
    Model as SysBackupLogModel,
};
pub use super::sys_dept::{
    ActiveModel as SysDeptActiveModel, Column as SysDeptColumn, Entity as SysDept,
    Model as SysDeptModel,
};
pub use super::sys_flow_log::{
    ActiveModel as SysFlowLogActiveModel, Column as SysFlowLogColumn, Entity as SysFlowLog,
    Model as SysFlowLogModel,
};
pub use super::sys_flow_task::{
    ActiveModel as SysFlowTaskActiveModel, Column as SysFlowTaskColumn, Entity as SysFlowTask,
    Model as SysFlowTaskModel,
};
pub use super::sys_notice_read::{
    ActiveModel as SysNoticeReadActiveModel, Column as SysNoticeReadColumn,
    Entity as SysNoticeRead, Model as SysNoticeReadModel,
};
pub use super::sys_post::{
    ActiveModel as SysPostActiveModel, Column as SysPostColumn, Entity as SysPost,
    Model as SysPostModel,
};
pub use super::sys_rate_limit::{
    ActiveModel as SysRateLimitActiveModel, Column as SysRateLimitColumn, Entity as SysRateLimit,
    Model as SysRateLimitModel,
};
pub use super::sys_report::{
    ActiveModel as SysReportActiveModel, Column as SysReportColumn, Entity as SysReport,
    Model as SysReportModel,
};
pub use super::sys_report_sub::{
    ActiveModel as SysReportSubActiveModel, Column as SysReportSubColumn, Entity as SysReportSub,
    Model as SysReportSubModel,
};
pub use super::sys_role_dept::{
    ActiveModel as SysRoleDeptActiveModel, Column as SysRoleDeptColumn, Entity as SysRoleDept,
    Model as SysRoleDeptModel,
};
pub use super::sys_task::{
    ActiveModel as SysTaskActiveModel, Column as SysTaskColumn, Entity as SysTask,
    Model as SysTaskModel,
};
pub use super::sys_user_post::{
    ActiveModel as SysUserPostActiveModel, Column as SysUserPostColumn, Entity as SysUserPost,
    Model as SysUserPostModel,
};
pub use super::sys_web_hook::{
    ActiveModel as SysWebHookActiveModel, Column as SysWebHookColumn, Entity as SysWebHook,
    Model as SysWebHookModel,
};
pub use super::sys_web_hook_log::{
    ActiveModel as SysWebHookLogActiveModel, Column as SysWebHookLogColumn,
    Entity as SysWebHookLog, Model as SysWebHookLogModel,
};
