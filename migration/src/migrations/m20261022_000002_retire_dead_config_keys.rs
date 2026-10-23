//! 参数页三个死键收口（批八十六 项 N-1）：一个变真旋钮，两个把行清掉。
//!
//! ## 为什么存在
//!
//! §5.23 当年把 `sys.index.sideTheme` / `sys.index.skinName` / `sys.login.background`
//! "退出治理注册表、数据保留"，**只做了注册表那一半**：参数页三行仍然可见可编辑，
//! 而后端零消费者、前端主题走 localStorage——正是《开关类能力设计规范》§5.15-5.17
//! 定义的假入口（"菜单/表单可见但请求零生效"比"看不见"更贵：运维照着改完以为生效了）。
//!
//! 本批把收口拆成两半，两半的判据不同：
//!
//! 1. **`sys.index.sideTheme` 变真旋钮**：键回到注册表（`governance::CONFIGS` 里
//!    `Coverage::Free` 的首项，定义原文即"值本身无有序档位，如主题名"），前端登录后
//!    按**租户层生效值**把它作为侧边栏主题缺省（用户显式选择过则尊重用户）。
//!    这里只动**数据缺省与说明文案**：把 init 迁移那个从未被消费过的 `theme-dark`
//!    归一到 `theme-auto`（= 改造前用户实际看到的值，开关规范①"缺省 = 现状 = 零行为变化"），
//!    并把合法取值写进说明，让管理员在参数页就读得见值域。
//! 2. **`sys.index.skinName` 与 `sys.login.background` 退役**：没有任何运行时消费者，
//!    也没有任何前端配置面（登录页背景图从来不由 `sys_config` 驱动），行留在库里 =
//!    永久假入口 ⇒ DELETE。写入侧同时被 `sys_config_service::ensure_value_writable`
//!    闸门拒绝，所以"存量库等价兜底"（`initialize::menu::ensure_dead_config_keys_retired`）
//!    只可能清掉历史遗留，不可能反复摧毁管理员事后建立的行——AGENTS 禁止挂启动兜底
//!    做回收的那条前提（"管理员的意图会被洗掉"）在本对键上不成立。
//!
//! ## 口径
//!
//! - 三条语句文本全部取自 `governance`（[`governance::dead_config_keys_retire_sql`] /
//!   [`governance::side_theme_normalize_sql`]），与启动兜底**同一事实源**；本文件不写第二份 SQL；
//! - 全部按"仍是历史字面量"守卫 ⇒ 幂等，重放（`live_db_smoke` 的 up→down→up）零影响；
//! - 只作用于 `tenant_id = 0` 的平台层（租户覆盖行的值由租户自己决定）；
//! - 不改 `update_time`：数据卫生收敛不是管理员操作，冒充操作时刻会污染审计面；
//! - 不做下移：前向只 up，破坏性回退走备份恢复（同 `m20260820_000001_demo_seed` 的登记）。

use sea_orm_migration::prelude::*;

pub struct Migration;

impl MigrationName for Migration {
    fn name(&self) -> &str {
        "m20261022_000002_retire_dead_config_keys"
    }
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let conn = manager.get_connection();
        // 先归一在册键（sideTheme），再删退役键：两条语句作用在不同键上，
        // 但顺序写成"补/改在前、删在后"，与启动兜底的执行序一致（避免两条路径各演化成不同终态）。
        for body in governance::side_theme_normalize_sql() {
            conn.execute_unprepared(&body).await?;
        }
        conn.execute_unprepared(&governance::dead_config_keys_retire_sql())
            .await?;
        eprintln!(
            "参数页死键收口完成：sideTheme 缺省归一 + 退役键清理（{} 个键）",
            governance::RETIRED_CONFIG_KEYS.len()
        );
        Ok(())
    }

    /// 不做下移：退役的是"没有任何代码消费的死行"，把它们种回来等于把假入口种回来。
    async fn down(&self, _manager: &SchemaManager) -> Result<(), DbErr> {
        Ok(())
    }
}
