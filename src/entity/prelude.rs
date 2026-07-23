//! 实体 prelude：重导出所有实体模块的公共类型
//!
//! 使用方式：`use crate::entity::prelude::*;`

pub use super::sys_config::{ActiveModel as SysConfigActiveModel, Column as SysConfigColumn, Entity as SysConfig, Model as SysConfigModel};
pub use super::sys_dict_data::{ActiveModel as SysDictDataActiveModel, Column as SysDictDataColumn, Entity as SysDictData, Model as SysDictDataModel};
pub use super::sys_dict_type::{ActiveModel as SysDictTypeActiveModel, Column as SysDictTypeColumn, Entity as SysDictType, Model as SysDictTypeModel};
pub use super::sys_job::{ActiveModel as SysJobActiveModel, Column as SysJobColumn, Entity as SysJob, Model as SysJobModel};
pub use super::sys_job_log::{ActiveModel as SysJobLogActiveModel, Column as SysJobLogColumn, Entity as SysJobLog, Model as SysJobLogModel};
pub use super::sys_logininfor::{ActiveModel as SysLogininforActiveModel, Column as SysLogininforColumn, Entity as SysLogininfor, Model as SysLogininforModel};
pub use super::sys_menu::{ActiveModel as SysMenuActiveModel, Column as SysMenuColumn, Entity as SysMenu, Model as SysMenuModel};
pub use super::sys_notice::{ActiveModel as SysNoticeActiveModel, Column as SysNoticeColumn, Entity as SysNotice, Model as SysNoticeModel};
pub use super::sys_oper_log::{ActiveModel as SysOperLogActiveModel, Column as SysOperLogColumn, Entity as SysOperLog, Model as SysOperLogModel};
pub use super::sys_role::{ActiveModel as SysRoleActiveModel, Column as SysRoleColumn, Entity as SysRole, Model as SysRoleModel};
pub use super::sys_role_menu::{ActiveModel as SysRoleMenuActiveModel, Column as SysRoleMenuColumn, Entity as SysRoleMenu, Model as SysRoleMenuModel};
pub use super::sys_user::{ActiveModel as SysUserActiveModel, Column as SysUserColumn, Entity as SysUser, Model as SysUserModel};
pub use super::sys_user_role::{ActiveModel as SysUserRoleActiveModel, Column as SysUserRoleColumn, Entity as SysUserRole, Model as SysUserRoleModel};
