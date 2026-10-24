//! 敏感操作独立限流的**单一事实源**与幂等播种（AGENTS 工程硬基线 C.10）。
//!
//! 为什么需要这一层（b72 实测起点）：`sys_rate_limit` 里只有 6 条种子
//! ——全局 `*`（100 突发 / 10·s⁻¹）+ 5 条 SSO 分档。也就是说，改密、重置他人密码、
//! TOTP 绑定/校验/解绑、WebAuthn 注册、PAT AK 轮换/吊销、OAuth client secret 轮换、
//! 第三方账号解绑、会话吊销、备份恢复/自导出、租户恢复、用户匿名化、批量导入
//! 这些**高危写操作全部只靠全局限流兜底**。全局限流的语义是"别把服务打爆"，
//! 不是"别把某个凭据爆破成功"——二者差 1~2 个数量级。
//!
//! 设计口径：
//! - **模式取档而非裸 bool**：每条 = `(路由模板, 桶容量, 每秒补充, 描述)`，容量与速率
//!   都是管理端可改的运行态数据（`sys_rate_limit` 表 + 管理界面），本矩阵只提供**初始档位**；
//!   已存在的 `route_pattern` **不覆盖**（管理员调过的配额优先，播种只补不覆盖）。
//! - **不新增配置键**：沿用"DB 权威 + 5 分钟缓存 + fail-closed 503"的既有限流面，
//!   避免"两边都能改但行为不一致"（AGENTS C.7）。
//! - **档位必须打得断爆破、又打不断业务**：桶容量按"一次正常人工操作的实际请求数"上取整
//!   （改密/绑定 TOTP 一次流程 ≤ 5 次），补充速率保证 20 分钟窗口内累计额度远大于
//!   任何 UI 流程（e2e 全量 40 分钟对同一端点最多 5 次调用，实测口径见台账）。
//! - **`route_pattern` 必须是路由模板**（`{id}` 形态，与 axum `MatchedPath` 同口径）：
//!   写成真实路径会**静默失配并回落 `*`**，规则形同虚设——故下方有形状锁逐条对账 router 注册表。

use sea_orm::{
    ActiveModelTrait, ActiveValue::Set, ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter,
};

use crate::common::datetime;
use crate::entity::sys_rate_limit::{ActiveModel, Column, Entity};

/// 敏感操作独立限流档位矩阵（路由模板须与 `src/router/*.rs` 注册逐字一致）。
///
/// 字段：`(route_pattern, capacity, refill_per_second, description)`
/// 分档原则：凭证/密钥类最严（防在线爆破），破坏性/重资源类次严（防误操作与批量滥用），
/// 自助批量类（会话注销、分片初始化）留足突发额度避免打断正常操作。
pub const SENSITIVE_LIMIT_TIERS: &[(&str, i32, f64, &str)] = &[
    // ===== 凭证变更与密钥轮换：防在线爆破、防凭据枚举 =====
    (
        "/system/user/profile/updatePwd",
        5,
        0.05,
        "本人改密（b72 敏感操作独立限流；正常一次流程 ≤3 次，突发 5 后每 20s 一个额度）",
    ),
    (
        "/system/user/resetPwd",
        5,
        0.1,
        "管理员重置他人密码（防越权批量重置；审计与操作日志同链路留痕）",
    ),
    (
        "/system/user/totp/setup",
        5,
        0.1,
        "TOTP 绑定初始化（防反复取密钥轮换种子）",
    ),
    (
        "/system/user/totp/verify",
        10,
        0.2,
        "TOTP 校验（6 位码暴力枚举面：桶 10 + 每 5s 一个额度，叠加服务侧失败锁定）",
    ),
    (
        "/system/user/totp/disable",
        5,
        0.1,
        "TOTP 解绑（高危关闭动作，低频严档）",
    ),
    (
        "/system/user/webauthn/register/start",
        10,
        0.2,
        "Passkey 注册挑战（浏览器导航需一定突发额度，严档会误伤正常注册）",
    ),
    (
        "/system/user/webauthn/register/finish",
        10,
        0.2,
        "Passkey 注册完成（与 start 同档，防挑战重放刷写）",
    ),
    (
        "/system/pat/{patId}/rotate-ak",
        5,
        0.05,
        "PAT AK/SK 轮换（SK 明文仅返回一次，属最高危面之一）",
    ),
    (
        "/system/pat/{patId}/revoke-ak",
        5,
        0.1,
        "PAT AK 吊销（可逆破坏性操作，防批量吊销他人凭据）",
    ),
    (
        "/system/oauth/client/{id}/rotate-secret",
        5,
        0.05,
        "SSO 客户端 secret 轮换（泄露即等同授权服务器失守）",
    ),
    (
        "/oauth2/unbind",
        10,
        0.2,
        "第三方账号解绑（自我锁定面：解绑后可能无法再登录，故限而非禁）",
    ),
    // ===== 会话与令牌吊销：防枚举 tokenHash =====
    (
        "/monitor/my-session/{tokenHash}",
        10,
        0.5,
        "本人会话吊销（正常用户可能一次清多台设备，留突发额度）",
    ),
    (
        "/sso/revoke",
        20,
        1.0,
        "OIDC 令牌吊销端点（RP 侧批量轮换属正常流量，过严会造成集成故障）",
    ),
    // ===== 破坏性 / 重资源：防误操作与批量滥用 =====
    (
        "/system/backup/restore/{backupId}",
        3,
        0.02,
        "备份恢复（覆盖性操作，一分钟内连续恢复即视为异常）",
    ),
    (
        "/system/backup/self-export",
        3,
        0.05,
        "全库自导出（整库外带：数据防泄露面，须与 oper_log 留痕配套）",
    ),
    (
        "/system/tenant/restore/{tenantId}",
        5,
        0.05,
        "租户恢复（平台代管高危操作，配合平台专属守卫）",
    ),
    (
        "/system/user/{userId}/anonymize",
        5,
        0.05,
        "用户匿名化（GDPR 被遗忘权，不可逆；重复触发即异常）",
    ),
    (
        "/system/user/importData",
        5,
        0.1,
        "批量导入用户（重资源 + 权限发放面，配合解析前的容量上限）",
    ),
    (
        "/common/upload/chunk/init",
        20,
        1.0,
        "分片上传初始化（大文件分片数天然多，过严会打断正常上传；与 complete 信号量互补）",
    ),
    // ===== 批七十六：补齐 `sensitive_route_audit.py` 反向差集（40 条缺口 → 0）=====
    // b74 台账把这一批缺口记为"遗留到下一轮"，并明确"不登记成豁免，逐条登记档位"。
    // 限流匹配只看 MatchedPath（路由模板，不含方法），故同一模板的 POST/PUT 共用一条
    // 档位（下面 `/system/menu`、`/system/role`、`/system/dataRule`、`/system/rateLimit`
    // 各覆盖注册表里的两条写路由）。
    //
    // ---- 审计销毁面（各 `*/clean`：清空即销毁留痕，重复触发本身就该视为异常）----
    (
        "/monitor/frontendError/clean",
        3,
        0.02,
        "前端错误日志清空（审计销毁面；正常运维一天不超过几次，3 次突发后每 50s 一个额度）",
    ),
    (
        "/monitor/jobLog/clean",
        3,
        0.02,
        "调度日志清空（审计销毁面，同上口径）",
    ),
    (
        "/monitor/logininfor/clean",
        3,
        0.02,
        "登录记录清空（爆破取证线索的唯一来源，销毁必须刺眼）",
    ),
    (
        "/monitor/operlog/clean",
        3,
        0.02,
        "操作日志清空（审计销毁面；与链式归档锚点配套，清空后无法重放校验）",
    ),
    (
        "/monitor/webHook/log/clean",
        3,
        0.02,
        "WebHook 投递日志清空（外部回执证据面）",
    ),
    (
        "/system/msg/log/clean",
        3,
        0.02,
        "消息发送记录清空（投递证据面；重试/幂等排查依赖它）",
    ),
    // ---- 批量删除（前端一次勾选把 id 拼进一条请求，故按"次"而非"行"计额度）----
    (
        "/system/user/{id}",
        10,
        0.2,
        "删除用户（账号整理常一次连删 5~10 个，留突发；权限发放面故严于普通治理写）",
    ),
    (
        "/system/role/{id}",
        10,
        0.2,
        "删除角色（连带角色-菜单/用户授权关系收敛，误删放大面广）",
    ),
    (
        "/system/menu/{id}",
        20,
        0.5,
        "删除菜单（树形整理逐节点删除是正常节奏，20 次突发 + 每 2s 一个额度）",
    ),
    // ---- 治理写面（权限/导航/限流自配置）----
    (
        "/system/dataRule",
        30,
        0.5,
        "数据权限规则新增/修改（写坏即全局越权面，但表单编辑节奏低）",
    ),
    (
        "/system/menu",
        30,
        0.5,
        "菜单新增/修改（导航与权限点单一事实源；正常整理一批节点在数十次内）",
    ),
    (
        "/system/menu/updateSort",
        60,
        1.0,
        "菜单批量改排序（拖拽逐条保存，突发额度必须容下一轮完整整理，否则整理到一半被 429 打断且顺序半应用）",
    ),
    (
        "/system/rateLimit",
        10,
        0.1,
        "限流规则新增/修改（限流面自身的配置入口：改坏会放大到全站，且是攻击者试图放宽约束时的直接目标）",
    ),
    (
        "/system/rateLimit/export",
        10,
        0.1,
        "限流规则导出（当前生效档位即防护拓扑情报）",
    ),
    (
        "/system/role",
        30,
        0.5,
        "角色新增/修改（权限集合的直接写入面）",
    ),
    (
        "/system/role/authUser/cancel",
        20,
        0.3,
        "取消单个用户角色（授权收敛，逐人操作节奏）",
    ),
    (
        "/system/role/authUser/cancelAll",
        10,
        0.1,
        "批量取消用户角色（一次作用整批人，误用/滥用影响面大）",
    ),
    (
        "/system/role/authUser/selectAll",
        10,
        0.1,
        "批量发放角色（提权面：一次把整批人挂上某角色）",
    ),
    (
        "/system/role/changeStatus",
        20,
        0.3,
        "角色停用/启用（停用即批量剥夺权限，应急时确实需要反复切换，故中等档）",
    ),
    (
        "/system/role/dataScope",
        20,
        0.3,
        "角色数据范围调整（越权边界写入面）",
    ),
    ("/system/role/export", 10, 0.1, "角色导出（权限拓扑外带）"),
    (
        "/system/tenant/domain",
        10,
        0.2,
        "租户域名新增（域名绑定即租户解析入口，配错/抢注都需刺眼）",
    ),
    (
        "/system/tenant/domain/changeStatus",
        10,
        0.2,
        "租户域名停用/启用（停用即该租户入口失效）",
    ),
    (
        "/system/tenant/domain/primary",
        5,
        0.05,
        "租户主域名切换（直接改变解析入口，一分钟内连续切换必属异常）",
    ),
    (
        "/system/tenant/domain/verify/{domainId}",
        5,
        0.05,
        "租户域名归属校验（触发真实 DNS 查询：既是治理写也是出站探测面）",
    ),
    (
        "/system/tenant/domain/{domainId}",
        10,
        0.2,
        "删除租户域名（解绑即入口消失）",
    ),
    // ---- 出站探测面（目标由管理员给定 ⇒ SSRF / 成本 / 元数据读取）----
    (
        "/monitor/webHook/{id}/test",
        5,
        0.05,
        "WebHook 连通性测试（向管理员填写的 URL 发起真实出站请求 = SSRF 面，也是外部靶场的打点入口）",
    ),
    (
        "/system/webhook/{id}/test-send",
        5,
        0.05,
        "WebHook 测试发送（同上出站面，且会真实投递一条事件）",
    ),
    (
        "/system/aiConfig/test",
        5,
        0.05,
        "AI 配置连通性测试（出站调用推理服务：成本 + SSRF 双面，测试按钮不该被脚本刷）",
    ),
    (
        "/system/msg/channel/test/{channelId}",
        5,
        0.05,
        "消息渠道测试（按渠道配置真实调用网关/SMTP，凭据错误时反复重试会触发云厂商封禁）",
    ),
    (
        "/system/uploadConfig/test",
        5,
        0.05,
        "对象存储配置测试（真实写探针到远端桶）",
    ),
    (
        "/system/uploadConfig/switchBackend",
        5,
        0.05,
        "存储后端切换（一次调用即改变所有后续落盘位置，运维编排动作必须低频且留痕）",
    ),
    (
        "/tool/gen/synchDb/{tableName}",
        10,
        0.2,
        "代码生成按表同步库结构（逐表读元数据，批量同步是正常流程但每张表一次点击）",
    ),
    // ---- 整库/整租户外带 ----
    (
        "/system/backup/tenant-export/{tenantId}",
        3,
        0.02,
        "整租户导出（数据防泄露面：与自导出同档，配合操作日志留痕）",
    ),
    // ---- 凭据吊销 ----
    (
        "/system/user/profile/tokens/{patId}",
        10,
        0.1,
        "本人令牌吊销（可逆破坏性操作；批量吊销他人凭据是典型越权试探面）",
    ),
    // ---- 会话闸门 ----
    (
        "/monitor/logininfor/unlock/{userName}",
        5,
        0.05,
        "解锁被锁定的账号（它本身就是爆破闸门，因此自己必须更严——否则成为绕过锁定的旁路）",
    ),
    (
        "/monitor/online/batchLogout",
        10,
        0.2,
        "批量强制下线（一次作用于多台在线设备，误用即大面积打断）",
    ),
];

/// 幂等播种敏感操作限流档位。
///
/// 只补**缺失**的 `route_pattern`：已存在则保持现值（运行态优先，管理员在管理端调过的
/// 配额不得被启动流程悄悄改回去）。返回新插入条数，供启动日志与测试断言。
pub async fn ensure_sensitive_rate_limit_tiers(db: &DatabaseConnection) -> anyhow::Result<usize> {
    // 先读后派生写：一次 IN 查询取回"已存在的 route_pattern 集合"，替代逐条点查。
    // b89 由 `rust_hygiene_scan` 在新采集面上抓回这一处 N+1（19 条 = 19 次往返）。
    // 谓词形状与改造前**逐字相同**（`route_pattern ∈ 矩阵`，无租户过滤——本表是平台级
    // 限流档位表），所以读侧与写侧共用同一集合，不引入新的作用域口径。
    let patterns: Vec<String> = SENSITIVE_LIMIT_TIERS
        .iter()
        .map(|(p, _, _, _)| (*p).to_string())
        .collect();
    let existing: std::collections::HashSet<String> = Entity::find()
        .filter(Column::RoutePattern.is_in(patterns))
        .all(db)
        .await?
        .into_iter()
        .map(|m| m.route_pattern)
        .collect();
    let mut inserted = 0usize;
    for (pattern, capacity, refill, description) in SENSITIVE_LIMIT_TIERS {
        if existing.contains(*pattern) {
            continue;
        }
        let now = datetime::now_naive();
        ActiveModel {
            route_pattern: Set((*pattern).to_string()),
            capacity: Set(*capacity),
            refill_per_second: Set(*refill),
            enabled: Set(true),
            description: Set(Some((*description).to_string())),
            create_by: Set(Some("system".to_string())),
            create_time: Set(Some(now)),
            update_by: Set(Some("system".to_string())),
            update_time: Set(Some(now)),
            ..Default::default()
        }
        .insert(db)
        .await?;
        inserted += 1;
    }
    if inserted > 0 {
        tracing::info!("已为 {inserted} 个敏感操作插入独立限流档位（b72，AGENTS C.10）");
    }
    Ok(inserted)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn collect_router_files(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let p = entry.path();
            if p.is_dir() {
                collect_router_files(&p, out);
            } else if p.extension().is_some_and(|x| x == "rs") {
                out.push(p);
            }
        }
    }

    /// 读取 `src/router/` 下全部路由注册文本（剔除注释行，避免注释里的示例路径骗过形状锁）。
    fn router_registry() -> String {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/router");
        let mut files = Vec::new();
        collect_router_files(&root, &mut files);
        assert!(
            !files.is_empty(),
            "未读到任何 router 源文件（本锁的扫描面失效，而非路由为空）"
        );
        let mut out = String::new();
        for f in files {
            let src = std::fs::read_to_string(&f).unwrap_or_default();
            for line in src.lines() {
                if !line.trim_start().starts_with("//") {
                    out.push_str(line);
                    out.push('\n');
                }
            }
        }
        out
    }

    /// 形状锁：矩阵里每条 `route_pattern` **必须**是 router 已注册的路由模板。
    ///
    /// 为什么单独锁这一条：限流匹配是"`MatchedPath` 模板**精确**相等，未命中静默回落 `*`"。
    /// 于是写错一个字符（漏 `{id}`、多一段前缀、用了 `:id` 老语法）不会报错、不会变红，
    /// 只会让这条规则**永久不生效**——看起来"已配限流"，实际全靠全局兜底。
    /// 这类"静默失效"正是 AGENTS C.10 要防的形态，必须机械对账。
    #[test]
    fn every_sensitive_pattern_is_a_registered_route_template() {
        let registry = router_registry();
        let mut missing = Vec::new();
        for (pattern, _, _, _) in SENSITIVE_LIMIT_TIERS {
            // router 里以 `.route("/x/{id}", …)` 注册，故按"带引号的完整模板"检索
            let needle = format!("\"{pattern}\"");
            if !registry.contains(&needle) {
                missing.push(*pattern);
            }
        }
        assert!(
            missing.is_empty(),
            "以下敏感操作限流规则在 router 中找不到同字面量的路由模板（将静默回落 `*`）：{missing:?}"
        );
    }

    /// 档位单调性：敏感操作必须**严格严于**全局默认（100 / 10·s⁻¹），否则"配了等于没配"。
    #[test]
    fn sensitive_tiers_are_strictly_tighter_than_global_default() {
        const GLOBAL_CAPACITY: i32 = 100;
        const GLOBAL_REFILL: f64 = 10.0;
        for (pattern, capacity, refill, _) in SENSITIVE_LIMIT_TIERS {
            assert!(
                *capacity < GLOBAL_CAPACITY && *refill < GLOBAL_REFILL,
                "{pattern} 档位 (capacity={capacity}, refill={refill}) 未严格严于全局默认 \
                 ({GLOBAL_CAPACITY}, {GLOBAL_REFILL})，独立限流形同虚设"
            );
            assert!(*capacity >= 1 && *refill > 0.0, "{pattern} 档位非法");
        }
    }

    /// 模板参数名必须与 router 的 `{}` 风格一致（axum 0.8；`:id` 是 0.6 老语法，
    /// 混用会既匹配不上又看不出错误）。
    #[test]
    fn sensitive_patterns_use_axum_curly_placeholders() {
        for (pattern, _, _, _) in SENSITIVE_LIMIT_TIERS {
            assert!(
                !pattern.contains(':'),
                "{pattern} 含 `:`，疑似旧的 `:id` 路径参数写法；本仓路由模板用 `{{id}}`"
            );
        }
    }
}
