// stepby-axum/src/integration_tests/common_handler.rs
//! 公共端点 + 通用模块链路集成测试：
//! - 验证码 /captchaImage：测试库默认关闭验证码，img/uuid 优雅降级为空（读取 auth_service 真实行为）
//! - 登录后 /getInfo、/getRouters（公开/受保护链路）
//! - 注册 /register：参数校验分支（无效 uuid / 过短用户名 / 弱口令）与默认禁注册（403 防刷）
//! - 健康检查 /health（真实探测 DB/Redis）与 /metrics
//! - 通用文件下载参数校验（路径穿越 → 400）
//! - 仪表盘 /dashboard/stats 聚合结构
//!
//! 说明：
//! - 迁移种子中 sys.account.captchaEnabled 被测试 harness 强制改为 false，
//!   generate_captcha 在开关关闭时返回空 img/uuid（见 auth_service::generate_captcha），
//!   故此处断言关闭态降级行为；开启态真实图片由 auth.rs / file_common.rs 覆盖。
//! - 迁移种子中 sys.account.registerUser=false（默认禁注册，安全失败），
//!   /register 携带合法参数会被 403 拒绝（register_disabled），此为预期防刷行为。
//! - /common/download 等受保护端点复用 TestContext 的鉴权 token。

use axum::http::{Method, StatusCode};

use super::TestContext;

/// 健康检查：真实探测 DB 与 Redis，均应 UP，版本非空。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn it_com_health_check() {
    let ctx = TestContext::new().await;

    let v = ctx.get_json("/health").await;
    assert_eq!(
        v["data"]["status"].as_str(),
        Some("UP"),
        "整体状态应为 UP，实际: {v}"
    );
    assert_eq!(v["data"]["db"].as_str(), Some("UP"), "DB 应 UP，实际: {v}");
    assert_eq!(
        v["data"]["redis"].as_str(),
        Some("UP"),
        "Redis 应 UP，实际: {v}"
    );
    assert!(
        !v["data"]["version"].as_str().unwrap_or("").is_empty(),
        "version 不应为空，实际: {v}"
    );
    // b72 B3 关闭态契约锁：默认 off ⇒ 外部探针字段**必须缺省**（响应体与改造前等价，
    // 公开端点不泄露"本部署有哪些外部依赖"，也不会真的去连 SMTP/OSS）。
    assert!(
        v["data"].get("external").is_none(),
        "off 档不应出现 external 字段，实际: {v}"
    );
    assert!(
        v["data"].get("externalStatus").is_none(),
        "off 档不应出现 externalStatus 字段，实际: {v}"
    );
}

/// 外部依赖探活 `basic` 档（AGENTS #5）：字段形状 + 档位登记清单 + **不改核心 status**。
///
/// 探针结论本身随环境而变（本机可能没配 SMTP/OSS），故这里锁的是**契约形状**而不是
/// 具体状态：数量与顺序必须等于 `BASIC_PROBES`，状态必须落在公开字面量集合内，
/// 且核心 `status` 仍为 UP（可选依赖不得把业务正常的实例判成故障）。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn it_com_health_external_probes_basic_mode() {
    use crate::handler::health_probes::{BASIC_PROBES, PROBE_STATUSES};

    let ctx = TestContext::new_with(&[], |s| {
        s.health.external_probes = "basic".to_string();
    })
    .await;

    let v = ctx.get_json("/health").await;
    assert_eq!(v["data"]["status"].as_str(), Some("UP"), "实际: {v}");
    let probes = v["data"]["external"]
        .as_array()
        .unwrap_or_else(|| panic!("basic 档应出现 external 数组，实际: {v}"));
    assert_eq!(
        probes.len(),
        BASIC_PROBES.len(),
        "external 条数必须等于登记清单，实际: {v}"
    );
    let names: Vec<&str> = probes.iter().filter_map(|p| p["name"].as_str()).collect();
    assert_eq!(
        names,
        BASIC_PROBES.to_vec(),
        "external 顺序必须按登记清单固定（编排脚本据此比对）"
    );
    for p in probes {
        let st = p["status"].as_str().unwrap_or_default();
        assert!(
            PROBE_STATUSES.contains(&st),
            "探针状态必须是公开字面量之一，实际: {st} / {p}"
        );
        assert!(
            p["detail"].as_str().is_some(),
            "每条探针都要有可读说明（UP/SKIPPED/DOWN 都不例外），实际: {p}"
        );
        // 脱敏契约：说明文本绝不含凭据键值（纵深防御，即使依赖库回显也不进公开端点）
        let detail = p["detail"]
            .as_str()
            .unwrap_or_default()
            .to_ascii_lowercase();
        for forbidden in ["password=", "bearer", "secret=", "token="] {
            assert!(
                !detail.contains(forbidden),
                "detail 泄露凭据形态 `{forbidden}`：{detail}"
            );
        }
        // b73：绝对文件系统路径也不得出现——`/health` 挂在 public.rs（免鉴权 200），
        // 曾实测 storage 探针把上传目录的完整路径写进 detail（= 把部署目录结构给未认证访问者）。
        // **本判据故意与 `common::redact::fold_abs_paths` 不同源**：这是出口侧的独立探针，
        // 复用 sanitizer 自己的正则会让"sanitizer 失效"与"探针通过"同时成立（自证清白＝虚锁）。
        // 因此这里比 sanitizer **更宽**（任意 ≥3 段 POSIX 路径都算泄露），并由
        // `handler::api_contract_guard` 锁住"全仓只允许一处实现 + 本处独立探针"。
        static FS_PATH_RE: std::sync::LazyLock<regex::Regex> = std::sync::LazyLock::new(|| {
            regex::Regex::new(r"(?:^|\s)(?:/[A-Za-z0-9._-]+){3,}|[A-Za-z]:[\\/][A-Za-z0-9._-]")
                .expect("静态正则")
        });
        let raw_detail = p["detail"].as_str().unwrap_or_default();
        assert!(
            !FS_PATH_RE.is_match(raw_detail),
            "detail 泄露文件系统绝对路径（公开端点信息暴露）：{raw_detail}"
        );
    }
    let overall = v["data"]["externalStatus"].as_str().unwrap_or_default();
    assert!(
        ["UP", "DEGRADED", "DOWN"].contains(&overall),
        "externalStatus 聚合值非法，实际: {overall}"
    );
    // 组件级指标（AGENTS #4）：探针计数必须进全局注册表的出站指标系列。
    // 直接读注册体而非再发一次 /metrics HTTP 请求：后者已有 file_common 的用例覆盖，
    // 且文本切片断言在中文/多字节边界上脆断（此处只需 series 是否存在）。
    let rendered = crate::observability::metrics::MetricsRegistry::global().render_prometheus();
    assert!(
        rendered.contains("stepby_outbound_requests_total{component=\"probe:"),
        "外部探针必须落组件级出站指标；实际含 probe 行数：{}",
        rendered.lines().filter(|l| l.contains("probe:")).count()
    );
}

/// 验证码默认关闭态：测试 harness 强制 captchaEnabled=false，
/// generate_captcha 返回空 img/uuid（优雅降级），registerEnabled 为布尔。
/// 字段在响应顶层（无 data 包装）。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn it_com_captcha_disabled_default() {
    let ctx = TestContext::new().await;

    let v = ctx.get_json("/captchaImage").await;
    assert_eq!(v["code"], 200, "captchaImage 业务码应为 200，实际: {v}");
    assert_eq!(
        v["captchaEnabled"], false,
        "测试库默认应关闭验证码，实际: {v}"
    );
    assert_eq!(v["img"].as_str(), Some(""), "关闭态 img 应为空，实际: {v}");
    assert_eq!(
        v["uuid"].as_str(),
        Some(""),
        "关闭态 uuid 应为空，实际: {v}"
    );
    assert!(
        v["registerEnabled"].is_boolean(),
        "registerEnabled 应为布尔，实际: {v}"
    );
}

/// 登录后的用户信息 /getInfo 与路由树 /getRouters。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn it_com_get_info_routers() {
    let ctx = TestContext::new().await;

    // getInfo：字段在顶层
    let v = ctx.get_json("/getInfo").await;
    assert_eq!(
        v["user"]["userName"].as_str(),
        Some("admin"),
        "getInfo 应返回 admin 用户，实际: {v}"
    );
    let roles = v["roles"].as_array().expect("roles 应为数组，实际: {v}");
    assert!(
        roles.iter().any(|r| r.as_str() == Some("admin")),
        "admin roles 应包含 admin，实际: {v}"
    );
    let perms = v["permissions"]
        .as_array()
        .expect("permissions 应为数组，实际: {v}");
    assert!(
        perms.iter().any(|p| p.as_str() == Some("*:*:*")),
        "超管权限应包含 *:*:*，实际: {v}"
    );

    // getRouters：data 为路由树数组
    let v = ctx.get_json("/getRouters").await;
    let routers = v["data"]
        .as_array()
        .expect("getRouters data 应为数组，实际: {v}");
    assert!(!routers.is_empty(), "admin 路由树不应为空，实际: {v}");
    assert!(
        routers
            .iter()
            .all(|r| r.get("path").is_some() && r.get("name").is_some()),
        "路由节点应含 path/name，实际: {v}"
    );
}

/// 注册 /register 参数校验与默认禁注册防刷分支（均为公开接口，无需真实外部服务）。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn it_com_register_validation_branches() {
    let ctx = TestContext::new().await;
    let uri = "/register";

    // 1. 无效 uuid 格式 → 400（garde custom validate_captcha_uuid_format）
    let (status, v) = ctx
        .send_raw(ctx.request(
            Method::POST,
            uri,
            Some(serde_json::json!({
                "username": "it_com_user",
                "password": "It@12345z",
                "code": "1234",
                "uuid": "not-a-valid-uuid"
            })),
        ))
        .await;
    assert_ne!(v["code"], 200, "无效 uuid 业务码不应为 200，实际: {v}");
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "无效 uuid 应 400，实际: {status}"
    );

    // 2. 用户名过短（< 2）→ 400（garde length）
    let (status, v) = ctx
        .send_raw(ctx.request(
            Method::POST,
            uri,
            Some(serde_json::json!({
                "username": "a",
                "password": "It@12345z",
                "code": "",
                "uuid": ""
            })),
        ))
        .await;
    assert_ne!(v["code"], 200, "过短用户名业务码不应为 200，实际: {v}");
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "过短用户名应 400，实际: {status}"
    );

    // 3. 弱口令（无数字）→ 400（password 复杂度校验，注册入口拦截）
    let (status, v) = ctx
        .send_raw(ctx.request(
            Method::POST,
            uri,
            Some(serde_json::json!({
                "username": "it_com_user",
                "password": "onlyletters",
                "code": "",
                "uuid": ""
            })),
        ))
        .await;
    assert_ne!(v["code"], 200, "弱口令业务码不应为 200，实际: {v}");
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "弱口令应 400，实际: {status}"
    );

    // 4. 合法参数 + 默认禁注册 → 403（registerUser 默认 false，安全失败禁止注册）
    let (status, v) = ctx
        .send_raw(ctx.request(
            Method::POST,
            uri,
            Some(serde_json::json!({
                "username": "it_com_fresh",
                "password": "It@12345z",
                "code": "",
                "uuid": ""
            })),
        ))
        .await;
    assert_ne!(v["code"], 200, "禁注册时业务码不应为 200，实际: {v}");
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "默认禁注册应 403，实际: {status} {v}"
    );
}

/// 通用文件下载参数校验失败分支（无需真实文件，命中 handler 的参数校验即返回 400）。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn it_com_common_download_validation() {
    let ctx = TestContext::new().await;

    // 1. /common/download：fileName 含路径穿越符 `..` → 400
    let (status, v) = ctx
        .send_raw(ctx.request(
            Method::GET,
            "/common/download?fileName=..%2F..%2Fetc%2Fpasswd",
            None,
        ))
        .await;
    assert_ne!(v["code"], 200, "路径穿越下载业务码不应为 200，实际: {v}");
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "路径穿越下载应 400，实际: {status}"
    );

    // 2. /common/download/resource：resource 含 `..` → 400
    let (status, v) = ctx
        .send_raw(ctx.request(
            Method::GET,
            "/common/download/resource?resource=uploads%2F..%2Fsecret.txt",
            None,
        ))
        .await;
    assert_ne!(v["code"], 200, "资源路径穿越业务码不应为 200，实际: {v}");
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "资源路径穿越应 400，实际: {status}"
    );
}

/// 仪表盘聚合统计 /dashboard/stats（本地 DB/Redis 聚合，稳定通过）。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn it_com_dashboard_stats_structure() {
    let ctx = TestContext::new().await;

    let v = ctx.get_json("/dashboard/stats").await;
    assert!(
        v["data"]["totalUsers"].is_number(),
        "totalUsers 应为数字，实际: {v}"
    );
    assert!(
        v["data"]["totalRoles"].is_number(),
        "totalRoles 应为数字，实际: {v}"
    );
    assert!(
        v["data"]["activeRoles"].is_number(),
        "activeRoles 应为数字，实际: {v}"
    );
    assert!(
        v["data"]["onlineCount"].is_number(),
        "onlineCount 应为数字，实际: {v}"
    );
    assert!(
        v["data"]["todayLogins"].is_number(),
        "todayLogins 应为数字，实际: {v}"
    );
    assert!(
        v["data"]["recentOperLogs"].is_array(),
        "recentOperLogs 应为数组，实际: {v}"
    );
}
