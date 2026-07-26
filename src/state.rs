// axum-backend/src/state.rs

use std::sync::Arc;
use redis::aio::ConnectionManager;
use sea_orm::DatabaseConnection;
use tokio::sync::broadcast;
use crate::config::Settings;
use crate::handler::ws_handler::WsMessage;
use crate::repository::sys_logininfor::SysLogininforRepository;
use crate::scheduler::JobScheduler;
use crate::service::{AuthService, GenTableService, IpLocationService, MailerService, SysBackupService, SysConfigService, SysDeptService, SysDictService, SysJobService, SysLogininforService, SysMenuService, SysNoticeService, SysOperLogService, SysPostService, SysRateLimitService, SysRoleService, SysTaskService, SysUserService};
use crate::utils::ip_location::IpLocator;

/// 应用全局共享状态
/// 通过 Axum State<Arc<AppState>> 注入到所有 handler
/// 注：AppState 本身无需 Clone，因始终通过 Arc<AppState> 共享
pub struct AppState {
    /// 数据库连接池
    pub db: DatabaseConnection,
    /// Redis 连接池
    pub redis: ConnectionManager,
    /// 全局配置
    pub config: Arc<Settings>,
    /// 用户模块 Service
    pub user_service: SysUserService,
    /// 角色模块 Service
    pub role_service: SysRoleService,
    /// 菜单模块 Service
    pub menu_service: SysMenuService,
    /// 通知公告模块 Service
    pub notice_service: SysNoticeService,
    /// 部门模块 Service
    pub dept_service: SysDeptService,
    /// 认证服务
    pub auth_service: AuthService,
    /// 定时任务 Service
    pub job_service: SysJobService,
    /// 字典模块 Service
    pub dict_service: SysDictService,
    /// 参数配置模块 Service
    pub config_service: SysConfigService,
    /// 岗位模块 Service
    pub post_service: SysPostService,
    /// 操作日志 Service
    pub oper_log_service: SysOperLogService,
    /// API 限流配置 Service
    pub rate_limit_service: SysRateLimitService,
    /// 登录日志 Service
    pub logininfor_service: SysLogininforService,
    /// 代码生成模块 Service
    pub gen_table_service: GenTableService,
    /// 数据备份 Service
    pub backup_service: SysBackupService,
    /// 任务进度 Service
    pub task_service: SysTaskService,
    /// 邮件发送 Service（未启用时降级为 no-op）
    pub mailer_service: MailerService,
    /// 定时任务调度器
    pub job_scheduler: Arc<JobScheduler>,
    /// IP 归属地查询器（mmdb 文件不存在时所有查询返回空字符串）
    /// 通过 Arc 共享，支持后台管理触发热加载（reload 不重启服务）
    pub ip_locator: Arc<IpLocator>,
    /// IP 库管理 Service（下载/解压/校验/热加载/配置加解密）
    pub ip_location_service: IpLocationService,
    /// WebSocket 全局广播通道（实时通知推送）
    pub ws_broadcast: broadcast::Sender<WsMessage>,
}

impl AppState {
    /// 构建 AppState 时初始化全部 Service
    ///
    /// 保持同步函数签名，调度器在 AppInitializer::run 中提前异步创建后传入
    ///
    /// 修复 P0-R81-014：原本 AuthService::new(db) 内部重复实例化 user/role/menu service，
    /// 导致与 AppState 中的同名实例各自独立（15 个重复 Repository 实例）。
    /// 现在先实例化 user/role/menu service，再 clone 一份传入 AuthService::new，
    /// 同时也实例化 logininfor_repo / config_repo 传入，确保单实例共享。
    pub fn new(
        db: DatabaseConnection,
        redis: ConnectionManager,
        config: Arc<Settings>,
        job_scheduler: Arc<JobScheduler>,
        ip_locator: Arc<IpLocator>,
        ip_location_service: IpLocationService,
    ) -> Self {
        // WebSocket 广播通道（容量 256，超出后旧消息被丢弃；客户端按需订阅）
        let (ws_broadcast, _) = broadcast::channel::<WsMessage>(256);

        // 先实例化 user/role/menu service，再 clone 一份注入 AuthService（共享底层 Repository 实例）
        let user_service = SysUserService::new(db.clone());
        let role_service = SysRoleService::new(db.clone());
        let menu_service = SysMenuService::new(db.clone());

        // H-4：config_service 提前实例化（持有 Redis 用于 cache-aside 缓存），
        // clone 一份注入 AuthService，使登录/注册流程的验证码开关、注册开关查询走 Redis 缓存，
        // 减少每次登录 2 次 DB 查询（captchaEnabled + registerUser）。
        let config_service = SysConfigService::new(db.clone(), redis.clone());

        // AuthService 复用上述 Service 实例 + 单独实例化 logininfor_repo
        // REGRESS-007 说明：P0-R81-014 已消除 15 个重复 Repository。
        // 剩余 1 个 logininfor_repo 是 AuthService 直接调用 Repository 层 insert 方法，
        // Repository 实例仅持有 Arc<DatabaseConnection>，开销极低，保持当前设计。
        let auth_service = AuthService::new(
            user_service.clone(),
            role_service.clone(),
            menu_service.clone(),
            SysLogininforRepository::new(db.clone()),
            config_service.clone(),
        );

        Self {
            user_service,
            role_service,
            menu_service,
            notice_service: SysNoticeService::new(db.clone()),
            dept_service: SysDeptService::new(db.clone()),
            auth_service,
            job_service: SysJobService::new(db.clone(), job_scheduler.clone()),
            dict_service: SysDictService::new(db.clone(), redis.clone()),
            config_service,
            post_service: SysPostService::new(db.clone()),
            oper_log_service: SysOperLogService::new(db.clone()),
            rate_limit_service: SysRateLimitService::new(db.clone(), redis.clone()),
            logininfor_service: SysLogininforService::new(db.clone()),
            gen_table_service: GenTableService::new(db.clone()),
            backup_service: SysBackupService::new(db.clone(), config.clone()),
            task_service: SysTaskService::new(db.clone()),
            mailer_service: MailerService::new(config.clone()),
            job_scheduler,
            db,
            redis,
            config,
            ip_locator,
            ip_location_service,
            ws_broadcast,
        }
    }
}
