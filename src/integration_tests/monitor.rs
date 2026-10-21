// stepby-axum/src/integration_tests/monitor.rs
//! 系统监控面板链路集成测试：
//! - 缓存监控：概览（info/dbSize/commandStats）/ 名称列表 / 键列表 / 值 / 清理 / 白名单校验错误
//! - 在线用户：列表（含当前 admin 会话）/ 强退（超管保护 403 / 不存在 404）
//! - 服务器信息（CPU / 内存 / 运行时 / 系统 / 磁盘）
//! - 可观测性：慢请求 / 错误日志 / Redis 运行指标
//! - 实时日志：文件列表 / 尾部读取（非法文件名 / 文件不存在错误分支）
//!
//! 数据说明：
//! - 缓存 / 在线 / 可观测性数据均来自进程内监控实例 + Redis（每个 TestContext 独占 Redis DB），
//!   无持久化种子数据；登录后 Redis 存在 `online:{token_hash}` 键，供缓存/在线链路复用。
//! - admin 是超管（`*:*:*`），所有受保护端点均可访问。
//! - 不依赖本地日志文件是否存在：日志文件列表只断言响应结构，错误分支选确定性路径。

use super::{TestContext, login};
use axum::http::{Method, StatusCode};

/// 缓存监控全链路：概览 → 名称列表 → 键列表 → 值 → 清理。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_cache_monitoring_chain() {
    let ctx = TestContext::new().await;

    // 1. 概览：info / dbSize / commandStats
    let v = ctx.get_json("/monitor/cache").await;
    let info = v["data"]["info"]
        .as_object()
        .expect("info 应为对象，实际: {v}");
    assert!(info.len() >= 3, "info 应包含 Redis INFO 键值对，实际: {v}");
    assert!(
        v["data"]["dbSize"].is_number(),
        "dbSize 应为数字，实际: {v}"
    );
    // SharedStore 迁移后 commandstats 指标不再经 trait 暴露（redis 档专属观测段未
    // 封装进 SharedStore 能力），已登记降级：commandStats 允许为空列表，
    // 前端饼图按空态兼容，这里只校验字段仍为数组
    assert!(
        v["data"]["commandStats"].is_array(),
        "commandStats 应为数组（迁移后允许为空），实际: {v}"
    );

    // 2. 名称列表：登录后应存在 online: 前缀分组
    let v = ctx.get_json("/monitor/cache/getNames").await;
    let names = v["data"].as_array().expect("data 应为数组，实际: {v}");
    assert!(
        names.iter().any(|n| n["cacheName"] == "online:"),
        "应包含 online: 前缀分组，实际: {v}"
    );

    // 3. 键列表：online:* 至少包含当前 admin 会话
    let v = ctx.get_json("/monitor/cache/getKeys/online:").await;
    let keys = v["data"].as_array().expect("data 应为数组，实际: {v}");
    assert!(!keys.is_empty(), "online: 前缀应至少 1 个键，实际: {v}");
    let first_key = keys[0].as_str().expect("键应为字符串").to_string();

    // 4. 值：读取该键的 OnlineSession JSON
    let v = ctx
        .get_json(&format!("/monitor/cache/getValue/online:/{}", first_key))
        .await;
    assert_eq!(
        v["data"]["cacheName"].as_str(),
        Some("online:"),
        "cacheName 应回显，实际: {v}"
    );
    assert_eq!(
        v["data"]["cacheKey"].as_str(),
        Some(first_key.as_str()),
        "cacheKey 应回显，实际: {v}"
    );
    assert!(
        !v["data"]["cacheValue"].as_str().unwrap_or("").is_empty(),
        "cacheValue 应为非空 OnlineSession JSON，实际: {v}"
    );

    // 5. 清理：清空不存在的键（合法前缀 online:）→ 200 成功消息（DEL 0 幂等）
    let v = ctx
        .delete_json("/monitor/cache/clearCacheKey/online:it-nonexistent-hash")
        .await;
    ctx.assert_ok(&v);

    // 6. 清理：按前缀清空 online: 分组后，键列表应为空
    let v = ctx
        .delete_json("/monitor/cache/clearCacheName/online:")
        .await;
    ctx.assert_ok(&v);
    let v = ctx.get_json("/monitor/cache/getKeys/online:").await;
    let keys = v["data"].as_array().expect("data 应为数组，实际: {v}");
    assert!(keys.is_empty(), "清空后 online: 应无键，实际: {v}");
}

/// 缓存监控白名单与参数校验错误分支（确定性，不依赖外部）。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_cache_validation_errors() {
    let ctx = TestContext::new().await;

    // 1. 通配符前缀 → 400（name_wildcard_forbidden）
    let (status, v) = ctx
        .send_raw(ctx.request(Method::GET, "/monitor/cache/getKeys/dict:*", None))
        .await;
    assert_ne!(v["code"], 200, "通配符前缀业务码不应为 200，实际: {v}");
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "通配符前缀应 400，实际: {status}"
    );

    // 2. 非白名单前缀 → 400（prefix_not_allowed）
    let (status, v) = ctx
        .send_raw(ctx.request(Method::GET, "/monitor/cache/getKeys/session:", None))
        .await;
    assert_ne!(v["code"], 200, "非白名单前缀业务码不应为 200，实际: {v}");
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "非白名单前缀应 400，实际: {status}"
    );

    // 3. getValue 的 cacheKey 不以 cacheName 开头（IDOR 防护）→ 400
    let (status, v) = ctx
        .send_raw(ctx.request(
            Method::GET,
            "/monitor/cache/getValue/dict:/blacklist:evil-key",
            None,
        ))
        .await;
    assert_ne!(v["code"], 200, "IDOR 越权读值业务码不应为 200，实际: {v}");
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "cacheKey 前缀不符应 400，实际: {status}"
    );

    // 4. clearCacheKey 带通配符 → 400（name_wildcard_forbidden）
    let (status, v) = ctx
        .send_raw(ctx.request(Method::DELETE, "/monitor/cache/clearCacheKey/dict:*", None))
        .await;
    assert_ne!(v["code"], 200, "通配符清理业务码不应为 200，实际: {v}");
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "通配符清理应 400，实际: {status}"
    );
}

/// 在线用户列表与强退：列表含 admin 会话；超管保护 403 / 不存在 404。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_online_users_list_and_force_logout() {
    let ctx = TestContext::new().await;

    // 1. 列表：应包含当前 admin 会话（登录即写入 online:{token_hash}）
    let v = ctx.get_json("/monitor/online/list").await;
    let rows = v["rows"].as_array().expect("rows 应为数组，实际: {v}");
    assert!(!rows.is_empty(), "在线列表不应为空，实际: {v}");
    assert!(
        v["total"].as_u64().unwrap_or(0) >= 1,
        "total 应 >= 1，实际: {v}"
    );
    let admin_row = rows
        .iter()
        .find(|r| r["userName"] == "admin")
        .expect("在线列表应包含 admin 会话，实际: {v}");
    assert_eq!(
        admin_row["userName"].as_str(),
        Some("admin"),
        "userName 应为 admin，实际: {v}"
    );
    assert!(
        admin_row["tokenId"].is_string(),
        "tokenId 应为字符串（token_hash），实际: {v}"
    );
    let admin_token_hash = admin_row["tokenId"].as_str().unwrap().to_string();

    // 2. 强退超管 → 403（admin_force_logout_forbidden）
    let (status, v) = ctx
        .send_raw(ctx.request(
            Method::DELETE,
            &format!("/monitor/online/{}", admin_token_hash),
            None,
        ))
        .await;
    assert_ne!(v["code"], 200, "强退超管业务码不应为 200，实际: {v}");
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "强退超管应 403，实际: {status}"
    );

    // 3. 强退不存在的会话 → 404（session_not_found）
    let (status, v) = ctx
        .send_raw(ctx.request(
            Method::DELETE,
            "/monitor/online/it-nonexistent-token-hash",
            None,
        ))
        .await;
    assert_ne!(v["code"], 200, "强退不存在会话业务码不应为 200，实际: {v}");
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "强退不存在会话应 404，实际: {status}"
    );
}

/// 自助会话入口的属主隔离（b82）：`GET /monitor/my-session/list` 只返回本人会话。
///
/// 缺陷原形：该端点把 `userName` 改写成操作人用户名后，复用管理员列表的 `contains` 模糊
/// 匹配 ⇒ 短名账号（`it_adm`）能在「我的登录设备」里看到长名账号（`it_admx`）的会话，
/// 连带暴露对方实时 `tokenId`、内网 IP、浏览器与登录时刻。`DELETE my-session/{hash}`
/// 有 user_id 属主校验拦着，所以是**信息泄漏**而非冒用——但展示层与写层判定口径不一致
/// 本身就是铁律 1 说的"散落两处必然漂移"。
///
/// 判据三侧（缺一即虚锁）：
/// ① 泄漏方向：短名账号的自助列表不得出现任何非本人行；
/// ② **正控**：两条夹具会话必须先在管理员视图里同时在线——否则 ① 靠"列表本来就空"蒙绿；
/// ③ 对照组 + 写侧：长名账号同样只看得到自己，且短名账号借自助入口踢长名会话仍 403。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_my_session_list_is_owner_exact() {
    use axum::body::Body;
    use axum::extract::ConnectInfo;
    use axum::http::Request;
    use std::net::SocketAddr;

    let ctx = TestContext::new().await;

    let bearer_get = |bearer: &str, uri: &str| {
        let mut req = Request::builder()
            .method(Method::GET)
            .uri(uri)
            .header("authorization", format!("Bearer {bearer}"))
            .body(Body::empty())
            .expect("构造请求失败");
        req.extensions_mut()
            .insert(ConnectInfo(SocketAddr::from((ctx.peer_ip, 4321))));
        req
    };

    // 夹具：两个用户名互为前缀的普通用户（role_id=2 已关联全部菜单种子）
    for (idx, uname) in ["it_adm", "it_admx"].iter().enumerate() {
        let v = ctx
            .post_json(
                "/system/user",
                serde_json::json!({
                    "deptId": 103,
                    "userName": uname,
                    "nickName": format!("属主隔离夹具{}", idx),
                    "email": "stepby@tzkj.net",
                    "phonenumber": format!("1380000611{}", idx),
                    "sex": "0",
                    "password": "Stepby@12345",
                    "status": "0",
                    "roleIds": [2]
                }),
            )
            .await;
        ctx.assert_ok(&v);
    }
    let adm_token = login(&ctx.app, ctx.peer_ip, "it_adm", "Stepby@12345").await;
    let admx_token = login(&ctx.app, ctx.peer_ip, "it_admx", "Stepby@12345").await;
    assert!(
        !adm_token.is_empty() && !admx_token.is_empty(),
        "两条夹具登录都应拿到 token"
    );

    // ② 正控：管理员视图（contains 搜索，本来就该同时命中两条）证明会话确实都在线
    let v = ctx.get_json("/monitor/online/list?userName=it_adm").await;
    let online_names: Vec<String> = v["rows"]
        .as_array()
        .cloned()
        .unwrap_or_default()
        .iter()
        .filter_map(|r| r["userName"].as_str().map(|s| s.to_string()))
        .collect();
    assert!(
        online_names.contains(&"it_adm".to_string())
            && online_names.contains(&"it_admx".to_string()),
        "正控失败：两条夹具会话未同时在线，后续『看不到』不成立，实际: {online_names:?}"
    );

    // ① 短名账号的自助列表：本人必须在列，且一行他人都不许有
    let (status, v) = ctx
        .send_raw(bearer_get(&adm_token, "/monitor/my-session/list"))
        .await;
    assert_eq!(status, StatusCode::OK, "自助列表应 200，实际: {v}");
    let adm_rows = v["rows"].as_array().cloned().unwrap_or_default();
    assert!(
        adm_rows
            .iter()
            .any(|r| r["userName"].as_str() == Some("it_adm")),
        "本人会话必须在列（不得靠空列表蒙绿），实际: {v}"
    );
    let leaked: Vec<String> = adm_rows
        .iter()
        .filter(|r| r["userName"].as_str() != Some("it_adm"))
        .map(|r| r["userName"].as_str().unwrap_or_default().to_string())
        .collect();
    assert!(
        leaked.is_empty(),
        "自助列表混入他人会话（前缀同名泄漏）: {leaked:?}"
    );

    // ③ 对照组：长名账号同样只看得到自己（把它的 tokenHash 摘出来给下一步用）
    let (_, v2) = ctx
        .send_raw(bearer_get(&admx_token, "/monitor/my-session/list"))
        .await;
    let admx_rows = v2["rows"].as_array().cloned().unwrap_or_default();
    let admx_foreign: Vec<String> = admx_rows
        .iter()
        .filter(|r| r["userName"].as_str() != Some("it_admx"))
        .map(|r| r["userName"].as_str().unwrap_or_default().to_string())
        .collect();
    assert!(
        admx_foreign.is_empty(),
        "长名账号的自助列表混入他人会话: {admx_foreign:?}"
    );
    let admx_hash = admx_rows
        .iter()
        .find(|r| r["userName"].as_str() == Some("it_admx"))
        .and_then(|r| r["tokenId"].as_str())
        .expect("长名账号应能看到自己的会话行")
        .to_string();

    // ④ 写侧不变宽：借自助入口踢他人会话必须 403（属主校验不得随展示层修复被放宽）
    let del_req = {
        let mut req = Request::builder()
            .method(Method::DELETE)
            .uri(format!("/monitor/my-session/{admx_hash}"))
            .header("authorization", format!("Bearer {adm_token}"))
            .body(Body::empty())
            .expect("构造请求失败");
        req.extensions_mut()
            .insert(ConnectInfo(SocketAddr::from((ctx.peer_ip, 4321))));
        req
    };
    let (status, v) = ctx.send_raw(del_req).await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "踢他人会话必须 403，实际: {status} {v}"
    );

    // 收尾：长名会话自助注销自己 ⇒ 200，且再用它请求 ⇒ 401（自助语义可用）
    let (status, v) = ctx
        .send_raw({
            let mut req = Request::builder()
                .method(Method::DELETE)
                .uri(format!("/monitor/my-session/{admx_hash}"))
                .header("authorization", format!("Bearer {admx_token}"))
                .body(Body::empty())
                .expect("构造请求失败");
            req.extensions_mut()
                .insert(ConnectInfo(SocketAddr::from((ctx.peer_ip, 4321))));
            req
        })
        .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "本人注销自己的会话应 200，实际: {v}"
    );
    let (status, _) = ctx
        .send_raw(bearer_get(&admx_token, "/monitor/my-session/list"))
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "注销后该令牌再请求应 401");
}

/// 服务器信息端点（sysinfo 采集，只断言结构存在性）。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_server_info() {
    let ctx = TestContext::new().await;

    let v = ctx.get_json("/monitor/server").await;
    // CPU：核心数应 >= 1
    assert!(
        v["data"]["cpu"]["cpuNum"].as_u64().unwrap_or(0) >= 1,
        "cpu.cpuNum 应 >= 1，实际: {v}"
    );
    // 内存：总量应 > 0
    assert!(
        v["data"]["mem"]["total"].as_f64().unwrap_or(0.0) > 0.0,
        "mem.total 应 > 0，实际: {v}"
    );
    // 系统：操作系统名不应为空
    assert!(
        !v["data"]["sys"]["osName"].as_str().unwrap_or("").is_empty(),
        "sys.osName 不应为空，实际: {v}"
    );
    // 运行时：名称/版本应为字符串
    assert!(
        v["data"]["jvm"]["name"].is_string(),
        "jvm.name 应为字符串，实际: {v}"
    );
    assert!(
        v["data"]["jvm"]["version"].is_string(),
        "jvm.version 应为字符串，实际: {v}"
    );
    // 磁盘：应为数组
    assert!(
        v["data"]["sysFiles"].is_array(),
        "sysFiles 应为数组，实际: {v}"
    );
}

/// 可观测性面板：慢请求列表/统计/清空 + 错误日志列表/统计/清空 + Redis 指标。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_observability_slow_error_redis() {
    let ctx = TestContext::new().await;

    // 1. 慢请求：列表 / 统计 / 清空
    //    列表遵循 TableDataInfo 扁平约定（code/msg/total/rows），与前端 response.rows/response.total 对齐
    let v = ctx
        .get_json("/monitor/slow-sql/list?pageNum=1&pageSize=10")
        .await;
    assert!(v["rows"].is_array(), "slow-sql rows 应为数组，实际: {v}");
    assert!(v["total"].is_number(), "slow-sql total 应为数字，实际: {v}");
    let v = ctx.get_json("/monitor/slow-sql/stats").await;
    assert!(v["data"].is_object(), "slow-sql stats 应为对象，实际: {v}");
    let v = ctx.delete_json("/monitor/slow-sql/clear").await;
    assert!(
        v["data"]["cleared"].is_number(),
        "slow-sql clear 应返回 cleared 数字，实际: {v}"
    );

    // 2. 错误日志：列表（含 module/level 过滤）/ 统计 / 清空
    let v = ctx
        .get_json("/monitor/error-log/list?pageNum=1&pageSize=10")
        .await;
    assert!(v["rows"].is_array(), "error-log rows 应为数组，实际: {v}");
    let v = ctx
        .get_json("/monitor/error-log/list?module=unknown_module&level=ERROR")
        .await;
    assert!(
        v["rows"].is_array(),
        "error-log 过滤 rows 应为数组，实际: {v}"
    );
    let v = ctx.get_json("/monitor/error-log/stats").await;
    assert!(v["data"].is_object(), "error-log stats 应为对象，实际: {v}");
    let v = ctx.delete_json("/monitor/error-log/clear").await;
    assert!(
        v["data"]["cleared"].is_number(),
        "error-log clear 应返回 cleared 数字，实际: {v}"
    );

    // 3. Redis 运行指标（INFO 解析字符串字段）
    let v = ctx.get_json("/monitor/redis/stats").await;
    assert!(
        v["data"]["uptimeSeconds"].is_string(),
        "uptimeSeconds 应为字符串，实际: {v}"
    );
    assert!(
        v["data"]["connectedClients"].is_string(),
        "connectedClients 应为字符串，实际: {v}"
    );
    assert!(
        v["data"]["usedMemoryBytes"].is_string(),
        "usedMemoryBytes 应为字符串，实际: {v}"
    );
    assert!(
        v["data"]["totalCommandsProcessed"].is_string(),
        "totalCommandsProcessed 应为字符串，实际: {v}"
    );
}

/// 实时日志：文件列表（结构断言）+ 尾部读取错误分支。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_log_files_and_tail() {
    let ctx = TestContext::new().await;

    // 1. 文件列表：目录可能为空，但响应结构固定（data.rows 数组）
    let v = ctx.get_json("/monitor/log/files").await;
    let rows = v["data"]["rows"]
        .as_array()
        .expect("rows 应为数组，实际: {v}");
    // 若存在日志文件，每项应含 file_name 字段
    if let Some(first) = rows.first() {
        assert!(
            first["fileName"].is_string(),
            "日志文件项应含 fileName，实际: {v}"
        );
    }

    // 2. 非法文件名（含路径分隔符，路径穿越）→ 400（invalid_name）
    let (status, v) = ctx
        .send_raw(ctx.request(
            Method::GET,
            "/monitor/log/tail?fileName=..%2F..%2Fetc%2Fpasswd",
            None,
        ))
        .await;
    assert_ne!(v["code"], 200, "非法文件名业务码不应为 200，实际: {v}");
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "非法文件名应 400，实际: {status}"
    );

    // 3. 空文件名 → 400（invalid_name）
    let (status, v) = ctx
        .send_raw(ctx.request(Method::GET, "/monitor/log/tail?fileName=", None))
        .await;
    assert_ne!(v["code"], 200, "空文件名业务码不应为 200，实际: {v}");
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "空文件名应 400，实际: {status}"
    );

    // 4. 文件名格式合法（app.log.YYYY-MM-DD）但文件不存在 → 400（file_not_found）
    let (status, v) = ctx
        .send_raw(ctx.request(
            Method::GET,
            "/monitor/log/tail?fileName=app.log.2000-01-01",
            None,
        ))
        .await;
    assert_ne!(v["code"], 200, "文件不存在业务码不应为 200，实际: {v}");
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "文件不存在应 400，实际: {status}"
    );
}
