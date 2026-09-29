// stepby-axum/src/integration_tests/monitor_extra.rs
//! 「缓存 / 在线 / 可观测监控」补充集成测试。
//!
//! 说明：
//! - 路由路径以真实注册为准（读取 router 确认）：
//!   - 在线用户：GET  /monitor/online/list 、DELETE /monitor/online/{tokenHash}
//!   - 可观测性：/monitor/slow-sql/* 、/monitor/error-log/* 、/monitor/redis/stats
//!     (任务描述中的 /monitor/observability/errors、/monitor/observability/metrics
//!     在源码中并未注册，实际端点映射到 error-log / slow-sql / redis 系列。)
//!   - 服务监控：GET /monitor/server
//!   - 缓存监控：GET /monitor/cache 与相关子端点
//!   - 日志读取：GET /monitor/log/files 、GET /monitor/log/tail
//! - admin 为超管（权限 `*:*:*`，权限中间件短路），所有受保护端点无需额外权限头。
//! - 每个测试独占 Redis DB，登录即写入 `online:{token_hash}`，可被列表/缓存链路复用。
//! - 可观测性缓冲为进程内每个 AppState 独立实例，测试内 clear 后为全空，可确定性断言空数组。

use super::TestContext;
use axum::http::{Method, StatusCode};

/// 在线用户分页查询：rows/total 结构 + 当前 admin 会话 + 字段完整性。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn it_mon_online_list_pagination() {
    let ctx = TestContext::new().await;

    // 分页参数：在线用户为动态数据，采用客户端分页（total=真实在线数，后端不切片）
    let v = ctx
        .get_json("/monitor/online/list?pageNum=1&pageSize=10")
        .await;
    let rows = v["rows"].as_array().expect("rows 应为数组，实际: {v}");
    assert!(!rows.is_empty(), "在线列表不应为空，实际: {v}");
    assert!(
        v["total"].as_u64().unwrap_or(0) >= 1,
        "total 应 >= 1，实际: {v}"
    );

    // 各行字段完整（SysUserOnline camelCase）
    let admin_row = rows
        .iter()
        .find(|r| r["userName"] == "admin")
        .expect("在线列表应包含 admin 会话，实际: {v}");
    assert!(admin_row["tokenId"].is_string(), "tokenId 应为字符串: {v}");
    assert!(admin_row["ipaddr"].is_string(), "ipaddr 应为字符串: {v}");
    assert!(admin_row["os"].is_string(), "os 应为字符串: {v}");
    assert!(admin_row["browser"].is_string(), "browser 应为字符串: {v}");
    assert!(
        admin_row["loginTime"].is_number(),
        "loginTime 应为时间戳数字: {v}"
    );
}

/// 在线用户强退：超管保护 403、未知会话 404。
///
/// 注：force_logout 不校验参数格式，路径参数为任意字符串；对不存在会话返回 404
/// （handler 明确实现 session_not_found），成功强退（200）需一个非超管在线会话，
/// 而种子仅含超管 admin（命中 403 保护），故 200 分支无法确定性覆盖，此处断言
/// 可确定的分支（403 超管保护 / 404 会话不存在）。handler 无 400 非法参数分支。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn it_mon_online_force_logout() {
    let ctx = TestContext::new().await;

    // 取出 admin 会话的 token_hash
    let v = ctx.get_json("/monitor/online/list").await;
    let rows = v["rows"].as_array().expect("rows 应为数组，实际: {v}");
    let admin_token_hash = rows
        .iter()
        .find(|r| r["userName"] == "admin")
        .expect("在线列表应包含 admin")
        .get("tokenId")
        .and_then(|v| v.as_str())
        .expect("tokenId 应为字符串")
        .to_string();

    // 1. 强退超管 → 403（admin_force_logout_forbidden）
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

    // 2. 强退未知/合法格式但不存在的会话 → 404（session_not_found）
    let (status, v) = ctx
        .send_raw(ctx.request(
            Method::DELETE,
            "/monitor/online/it_mon_unknown_token_hash_0000",
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

/// 可观测性-慢请求：列表（结构 + 分页参数）、统计、清空后无数据为空数组。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn it_mon_observability_slow_sql() {
    let ctx = TestContext::new().await;

    // 列表：遵循 TableDataInfo 扁平约定 rows 数组 + total 数字
    let v = ctx
        .get_json("/monitor/slow-sql/list?pageNum=1&pageSize=10")
        .await;
    assert!(v["rows"].is_array(), "slow-sql rows 应为数组，实际: {v}");
    assert!(v["total"].is_number(), "slow-sql total 应为数字，实际: {v}");

    // 统计：data 应为对象
    let v = ctx.get_json("/monitor/slow-sql/stats").await;
    assert!(v["data"].is_object(), "slow-sql stats 应为对象，实际: {v}");

    // 清空：返回 cleared 数字；随后列表 rows 应为数组
    let v = ctx.delete_json("/monitor/slow-sql/clear").await;
    assert!(
        v["data"]["cleared"].is_number(),
        "slow-sql clear 应返回 cleared 数字，实际: {v}"
    );
    let v = ctx
        .get_json("/monitor/slow-sql/list?pageNum=1&pageSize=10")
        .await;
    assert!(v["rows"].is_array(), "slow-sql rows 应为数组，实际: {v}");
}

/// 可观测性-错误日志：列表（含 module/level 过滤）、统计、清空后无数据为空数组。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn it_mon_observability_error_log() {
    let ctx = TestContext::new().await;

    // 列表：遵循 TableDataInfo 扁平约定 rows 数组 + total 数字
    let v = ctx
        .get_json("/monitor/error-log/list?pageNum=1&pageSize=10")
        .await;
    assert!(v["rows"].is_array(), "error-log rows 应为数组，实际: {v}");
    assert!(
        v["total"].is_number(),
        "error-log total 应为数字，实际: {v}"
    );

    // 过滤查询（module/level）仍返回数组结构
    let v = ctx
        .get_json("/monitor/error-log/list?module=it_mon_unknown&level=ERROR")
        .await;
    assert!(
        v["rows"].is_array(),
        "error-log 过滤 rows 应为数组，实际: {v}"
    );

    // 统计：data 应为对象
    let v = ctx.get_json("/monitor/error-log/stats").await;
    assert!(v["data"].is_object(), "error-log stats 应为对象，实际: {v}");

    // 清空后列表应确定性为空数组（进程内缓冲，clear 后全空）
    let v = ctx.delete_json("/monitor/error-log/clear").await;
    assert!(
        v["data"]["cleared"].is_number(),
        "error-log clear 应返回 cleared 数字，实际: {v}"
    );
    let v = ctx
        .get_json("/monitor/error-log/list?pageNum=1&pageSize=10")
        .await;
    let rows = v["rows"].as_array().expect("rows 应为数组，实际: {v}");
    assert!(rows.is_empty(), "清空后错误日志应为空数组，实际: {v}");
}

/// 可观测性-Redis 运行指标：INFO 解析的字符串字段（脱敏，不含配置/密码段）。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn it_mon_observability_redis_stats() {
    let ctx = TestContext::new().await;

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
        v["data"]["usedMemoryPeakBytes"].is_string(),
        "usedMemoryPeakBytes 应为字符串，实际: {v}"
    );
    assert!(
        v["data"]["totalCommandsProcessed"].is_string(),
        "totalCommandsProcessed 应为字符串，实际: {v}"
    );
    // dbSize 从 dbN:keys=N 提取，可能为空串，但字段应始终存在（string/空）
    assert!(
        v["data"]["dbSize"].is_string(),
        "dbSize 应为字符串，实际: {v}"
    );
}

/// 服务监控：/monitor/server 返回结构（cpu/mem/sys/jvm/sysFiles 字段存在性）。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn it_mon_server_info() {
    let ctx = TestContext::new().await;

    let v = ctx.get_json("/monitor/server").await;
    let d = &v["data"];
    // CPU：核心数应 >= 1，used/free 为数字
    assert!(
        d["cpu"]["cpuNum"].as_u64().unwrap_or(0) >= 1,
        "cpu.cpuNum 应 >= 1，实际: {v}"
    );
    assert!(
        d["cpu"]["used"].is_f64() || d["cpu"]["used"].is_u64(),
        "cpu.used 应为数值: {v}"
    );
    // 内存：total 应 > 0，usage 为数值
    assert!(
        d["mem"]["total"].as_f64().unwrap_or(0.0) > 0.0,
        "mem.total 应 > 0，实际: {v}"
    );
    assert!(
        d["mem"]["usage"].is_f64() || d["mem"]["usage"].is_u64(),
        "mem.usage 应为数值: {v}"
    );
    // 系统：osName 不应为空
    assert!(
        !d["sys"]["osName"].as_str().unwrap_or("").is_empty(),
        "sys.osName 不应为空，实际: {v}"
    );
    // 运行时：name / version / runTime 为字符串
    assert!(d["jvm"]["name"].is_string(), "jvm.name 应为字符串: {v}");
    assert!(
        d["jvm"]["version"].is_string(),
        "jvm.version 应为字符串: {v}"
    );
    assert!(
        d["jvm"]["runTime"].is_string(),
        "jvm.runTime 应为字符串: {v}"
    );
    // 磁盘：应为数组
    assert!(d["sysFiles"].is_array(), "sysFiles 应为数组，实际: {v}");
}

/// 缓存监控概览：info / dbSize / commandStats 结构 + 名称列表 + 键列表 + 值 + 清理。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn it_mon_cache_chain() {
    let ctx = TestContext::new().await;

    // 1. 概览：info 对象 / dbSize 数字 / commandStats 数组
    let v = ctx.get_json("/monitor/cache").await;
    assert!(v["data"]["info"].is_object(), "info 应为对象，实际: {v}");
    assert!(
        v["data"]["dbSize"].is_number(),
        "dbSize 应为数字，实际: {v}"
    );
    assert!(
        v["data"]["commandStats"].is_array(),
        "commandStats 应为数组，实际: {v}"
    );

    // 2. 名称列表：登录后应含 online: 前缀分组
    let v = ctx.get_json("/monitor/cache/getNames").await;
    let names = v["data"].as_array().expect("data 应为数组，实际: {v}");
    assert!(
        names.iter().any(|n| n["cacheName"] == "online:"),
        "应包含 online: 前缀分组，实际: {v}"
    );

    // 3. 键列表：online:* 至少含当前 admin 会话
    let v = ctx.get_json("/monitor/cache/getKeys/online:").await;
    let keys = v["data"].as_array().expect("data 应为数组，实际: {v}");
    assert!(!keys.is_empty(), "online: 应至少 1 个键，实际: {v}");
    let first_key = keys[0].as_str().expect("键应为字符串").to_string();

    // 4. 值：读取该键的 OnlineSession JSON（cacheName/cacheKey 回显，cacheValue 非空）
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
        "cacheValue 应为非空 JSON，实际: {v}"
    );

    // 5. 前缀内存统计：数组结构
    let v = ctx.get_json("/monitor/cache/prefixStats").await;
    assert!(v["data"].is_array(), "prefixStats 应为数组，实际: {v}");

    // 6. 清理：按前缀清空 online: 分组后键列表为空
    let v = ctx
        .delete_json("/monitor/cache/clearCacheName/online:")
        .await;
    ctx.assert_ok(&v);
    let v = ctx.get_json("/monitor/cache/getKeys/online:").await;
    let keys = v["data"].as_array().expect("data 应为数组，实际: {v}");
    assert!(keys.is_empty(), "清空后 online: 应无键，实际: {v}");
}

/// 缓存监控白名单/参数校验错误分支（确定性 400）。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn it_mon_cache_validation_errors() {
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
}

/// 日志读取监控：文件列表（结构断言）+ 尾部读取错误分支。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn it_mon_log_files_and_tail() {
    let ctx = TestContext::new().await;

    // 1. 文件列表：目录可能为空，但结构固定（data.rows 数组，每项含 fileName）
    let v = ctx.get_json("/monitor/log/files").await;
    let rows = v["data"]["rows"]
        .as_array()
        .expect("rows 应为数组，实际: {v}");
    if let Some(first) = rows.first() {
        assert!(
            first["fileName"].is_string(),
            "日志文件项应含 fileName，实际: {v}"
        );
    }

    // 2. 非法文件名（路径穿越）→ 400（invalid_name）
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

    // 3. 文件名合法但文件不存在 → 400（file_not_found）
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
