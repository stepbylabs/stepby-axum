// stepby-axum/src/integration_tests/upload_chunk.rs
//! G-10 分片上传/断点续传集成测试
//!
//! 覆盖：init→part×N→complete 全链路（内容回读一致）→ 断点续传查询 →
//! 错误分支（缺片 complete / 未知会话 / 危险扩展名 / 超总上限 / 跨租户会话隔离）。

use axum::body::Body;
use axum::http::StatusCode;
use axum::http::{Method, Request};
use tower::ServiceExt;

use crate::integration_tests::TestContext;

/// 构造 multipart 多字段请求体（sessionId / partIndex / file）
fn chunk_part_body(boundary: &str, session_id: &str, index: u32, data: &[u8]) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(
        format!(
            "--{boundary}\r\nContent-Disposition: form-data; name=\"sessionId\"\r\n\r\n{session_id}\r\n"
        )
        .as_bytes(),
    );
    body.extend_from_slice(
        format!(
            "--{boundary}\r\nContent-Disposition: form-data; name=\"partIndex\"\r\n\r\n{index}\r\n"
        )
        .as_bytes(),
    );
    body.extend_from_slice(
        format!(
            "--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"part.bin\"\r\nContent-Type: application/octet-stream\r\n\r\n"
        )
        .as_bytes(),
    );
    body.extend_from_slice(data);
    body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
    body
}

/// 发送 multipart 请求（带鉴权 + ConnectInfo）
async fn send_multipart(
    ctx: &TestContext,
    method: Method,
    uri: &str,
    body: Vec<u8>,
) -> (StatusCode, serde_json::Value) {
    let boundary = "it-chunk-boundary";
    let mut req = Request::builder()
        .method(method)
        .uri(uri)
        .header("authorization", format!("Bearer {}", ctx.token))
        .header(
            "content-type",
            format!("multipart/form-data; boundary={boundary}"),
        )
        .body(Body::from(body))
        .expect("构造 multipart 请求失败");
    req.extensions_mut()
        .insert(axum::extract::ConnectInfo(std::net::SocketAddr::from((
            ctx.peer_ip,
            4321,
        ))));
    ctx.send_raw(req).await
}

/// 快乐路径全链路：init → part×3 → session 查询 → complete → 下载回读内容一致
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_chunk_upload_full_chain() {
    let ctx = TestContext::new().await;

    // 1. init：txt 白名单文件，3 片
    let (status, v) = ctx
        .send_raw(ctx.request(
            Method::POST,
            "/common/upload/chunk/init",
            Some(serde_json::json!({
                "fileName": "it-chunk.txt",
                "totalParts": 3,
                "totalSize": 9,
                "partSize": 3
            })),
        ))
        .await;
    assert_eq!(status, StatusCode::OK, "init 应成功: {v}");
    let session_id = v["data"]["sessionId"]
        .as_str()
        .expect("init 应返回 sessionId")
        .to_string();
    assert_eq!(v["data"]["chunkSize"], 3, "单片期望大小应为 3");
    assert_eq!(v["data"]["ttlSecs"], 7200, "TTL 应回显配置默认值");

    // 2. 逐片上传（乱序：1, 0, 2——BTreeSet 天然归序）
    let boundary = "it-chunk-boundary";
    for (n, (idx, data)) in [(1u32, b"BBB".as_slice()), (0, b"AAA"), (2, b"CCC")]
        .into_iter()
        .enumerate()
    {
        let (st, v) = send_multipart(
            &ctx,
            Method::POST,
            "/common/upload/chunk/part",
            chunk_part_body(boundary, &session_id, idx, data),
        )
        .await;
        assert_eq!(st, StatusCode::OK, "part {idx} 应成功: {v}");
        // 乱序上传：已收计数按提交序数递增（第 n 片提交后 received == n）
        assert_eq!(v["data"]["received"], (n + 1) as u64, "已收计数应递增: {v}");
    }
    let (st, v) = ctx
        .send_raw(ctx.request(
            Method::GET,
            &format!("/common/upload/chunk/session/{session_id}"),
            None,
        ))
        .await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(
        v["data"]["complete"], true,
        "三片收齐后 complete 应为 true: {v}"
    );

    // 3. complete：拼接 + 校验 + 落最终存储
    let (st, v) = ctx
        .send_raw(ctx.request(
            Method::POST,
            "/common/upload/chunk/complete",
            Some(serde_json::json!({ "sessionId": session_id })),
        ))
        .await;
    assert_eq!(st, StatusCode::OK, "complete 应成功: {v}");
    let url = v["data"]["url"].as_str().expect("应返回 url").to_string();
    assert!(
        url.starts_with("/uploads/0/file/"),
        "url 应位于平台租户 file 目录，实际: {v}"
    );
    let new_file_name = v["data"]["newFileName"]
        .as_str()
        .expect("应返回 newFileName")
        .to_string();

    // 4. 下载回读：内容与分片顺序一致（AAABBBCCC）——fileName 参数用 newFileName
    let req = ctx.request(
        Method::GET,
        &format!("/common/download?fileName={new_file_name}"),
        None,
    );
    let resp = ctx.app.clone().oneshot(req).await.expect("下载请求失败");
    assert_eq!(resp.status(), StatusCode::OK, "下载应 200");
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .expect("读取下载体失败");
    assert_eq!(&bytes[..], b"AAABBBCCC", "拼接内容应与分片顺序一致");

    // 5. complete 后会话已清理：再次 complete → 400（会话不存在，防重复 complete）
    let (st, _) = ctx
        .send_raw(ctx.request(
            Method::POST,
            "/common/upload/chunk/complete",
            Some(serde_json::json!({ "sessionId": session_id })),
        ))
        .await;
    assert_eq!(st, StatusCode::BAD_REQUEST, "重复 complete 应 400");
}

/// 错误分支：缺片 complete / 未知会话 / 危险扩展名 / 超总上限 / abort 清理
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_chunk_upload_error_branches() {
    let ctx = TestContext::new().await;
    let boundary = "it-chunk-boundary";

    // 1. 危险扩展名 init → 400
    let (st, _) = ctx
        .send_raw(ctx.request(
            Method::POST,
            "/common/upload/chunk/init",
            Some(serde_json::json!({
                "fileName": "evil.html",
                "totalParts": 1,
                "totalSize": 3
            })),
        ))
        .await;
    assert_eq!(st, StatusCode::BAD_REQUEST, "危险扩展名应 400");

    // 2. 超总上限（1025MB > 1GB 默认，批次十八 64MB→1GB）→ 400
    let (st, _) = ctx
        .send_raw(ctx.request(
            Method::POST,
            "/common/upload/chunk/init",
            Some(serde_json::json!({
                "fileName": "big.zip",
                "totalParts": 7,
                "totalSize": 1074790401
            })),
        ))
        .await;
    assert_eq!(st, StatusCode::BAD_REQUEST, "超总上限应 400");

    // 3. 快乐 init 后：缺片 complete → 400
    let (_, v) = ctx
        .send_raw(ctx.request(
            Method::POST,
            "/common/upload/chunk/init",
            Some(serde_json::json!({
                "fileName": "it-e.txt",
                "totalParts": 2,
                "totalSize": 6
            })),
        ))
        .await;
    let sid = v["data"]["sessionId"].as_str().unwrap().to_string();
    let (st, _v) = send_multipart(
        &ctx,
        Method::POST,
        "/common/upload/chunk/part",
        chunk_part_body(boundary, &sid, 0, b"AAA"),
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    let (st, v) = ctx
        .send_raw(ctx.request(
            Method::POST,
            "/common/upload/chunk/complete",
            Some(serde_json::json!({ "sessionId": sid })),
        ))
        .await;
    assert_eq!(st, StatusCode::BAD_REQUEST, "缺片 complete 应 400: {v}");

    // 3.5 越界分片序号（批七十五 B2）：闸门必须双侧
    //     ①畸形入参 ⇒ 400 且 received **不涨**（否则越界序号会写盘并挤占计数，
    //       使 merge 的"已收 N/M"判据永久无法满足，会话在 TTL 内不可完成）；
    //     ②对照组 ⇒ 合法末片必须照常 200（只写①的话，"这个入口永远拒收"也能过）。
    let (st, v) = send_multipart(
        &ctx,
        Method::POST,
        "/common/upload/chunk/part",
        chunk_part_body(boundary, &sid, 999, b"ZZZ"),
    )
    .await;
    assert_eq!(st, StatusCode::BAD_REQUEST, "越界分片序号必须 400: {v}");
    let msg = v["msg"].as_str().unwrap_or_default().to_string();
    assert!(
        !msg.contains("%{") && !msg.contains("error."),
        "越界序号的错误文案必须已把占位符渲染成实际数字，实际: {msg}"
    );
    assert!(
        msg.contains("999"),
        "文案必须带上被拒绝的实际序号（排障可用性），实际: {msg}"
    );
    let (_, sv) = ctx
        .send_raw(ctx.request(
            Method::GET,
            &format!("/common/upload/chunk/session/{sid}"),
            None,
        ))
        .await;
    assert_eq!(
        sv["data"]["received"].as_u64(),
        Some(1),
        "越界序号不得进入 received（会话仍只承认合法的 0 号片）: {sv}"
    );
    let (st, v) = send_multipart(
        &ctx,
        Method::POST,
        "/common/upload/chunk/part",
        chunk_part_body(boundary, &sid, 1, b"BBB"),
    )
    .await;
    assert_eq!(st, StatusCode::OK, "合法末片不得被闸门误伤: {v}");
    assert_eq!(
        v["data"]["complete"].as_bool(),
        Some(true),
        "收齐后 complete 标记必须为真: {v}"
    );

    // 4. abort：清理后 session 查询 → 400（会话不存在）
    let (st, _) = ctx
        .send_raw(ctx.request(Method::DELETE, &format!("/common/upload/chunk/{sid}"), None))
        .await;
    assert_eq!(st, StatusCode::OK, "abort 应成功");
    let (st, _) = ctx
        .send_raw(ctx.request(
            Method::GET,
            &format!("/common/upload/chunk/session/{sid}"),
            None,
        ))
        .await;
    assert_eq!(st, StatusCode::BAD_REQUEST, "abort 后会话应不存在");

    // 5. 未知会话 part → 400
    let (st, _) = send_multipart(
        &ctx,
        Method::POST,
        "/common/upload/chunk/part",
        chunk_part_body(boundary, "00000000-0000-4000-8000-000000000000", 0, b"X"),
    )
    .await;
    assert_eq!(st, StatusCode::BAD_REQUEST, "未知会话 part 应 400");

    // 6. 非法 session_id 形态（路径穿越）→ 400
    let (st, _) = ctx
        .send_raw(ctx.request(
            Method::GET,
            "/common/upload/chunk/session/..%2F..%2Fetc",
            None,
        ))
        .await;
    assert_eq!(st, StatusCode::BAD_REQUEST, "路径穿越 session_id 应 400");
}

// ==================== G-11 第二档：backend 档位热切换 ====================

/// 热切换链路：非法档位 400 / s3 配置不完整 fail-closed 400 / 同档重装 200 +
/// 切档后上传链路仍通 + masked 回显生效档位
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_switch_backend_chain() {
    let ctx = TestContext::new().await;

    // 1. 非法档位 → 400
    let (st, _) = ctx
        .send_raw(ctx.request(
            Method::POST,
            "/system/uploadConfig/switchBackend",
            Some(serde_json::json!({ "mode": "ftp" })),
        ))
        .await;
    assert_eq!(st, StatusCode::BAD_REQUEST, "非法档位应 400");

    // 2. s3 档配置不完整（endpoint/bucket 均空）→ fail-closed 400
    let (st, _) = ctx
        .send_raw(ctx.request(
            Method::POST,
            "/system/uploadConfig/switchBackend",
            Some(serde_json::json!({ "mode": "s3" })),
        ))
        .await;
    assert_eq!(st, StatusCode::BAD_REQUEST, "s3 配置不完整应拒绝切换");

    // 3. 同档重装（local → local，幂等）→ 200
    let (st, v) = ctx
        .send_raw(ctx.request(
            Method::POST,
            "/system/uploadConfig/switchBackend",
            Some(serde_json::json!({ "mode": "local" })),
        ))
        .await;
    assert_eq!(st, StatusCode::OK, "local 重装应成功: {v}");
    assert_eq!(v["data"]["mode"], "local");

    // 4. masked 回显生效档位（local）
    let v = ctx.get_json("/system/uploadConfig").await;
    assert_eq!(v["data"]["backendMode"], "local", "回显应为生效档位: {v}");

    // 4b. 回显必须跟随**覆盖值**而不是出厂快照（b74 §一.6，C.7"显示 8、实际 4"同型缺陷）。
    //     直接把 `sys.upload.backend` 写成 s3（绕开 fail-closed 的切换编排，模拟"已持久化
    //     的覆盖档"），GET 必须报 s3；改回原值后必须报回 local。
    //     改造前此处恒回显 startup_backend_mode ⇒ 这一支必然红。
    use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};
    // 嵌套 async fn（不是 async 闭包）：闭包返回借用 ctx 的 future 过不了类型检查，
    // 同 b74 轮 24 终态锁里 `probe(db)` 的处理方式
    async fn set_backend(ctx: &TestContext, val: &str) {
        crate::entity::sys_config::Entity::update_many()
            .col_expr(
                crate::entity::sys_config::Column::ConfigValue,
                sea_orm::sea_query::Expr::value(val),
            )
            .filter(crate::entity::sys_config::Column::ConfigKey.eq("sys.upload.backend"))
            .exec(&ctx.state.db)
            .await
            .expect("写 sys.upload.backend 失败");
        // 档位读的是 config 缓存 ⇒ 必须让缓存失效，否则测的是缓存而不是库
        ctx.state
            .config_service
            .refresh_cache()
            .await
            .expect("刷新配置缓存失败");
    }
    let prev: Option<String> = {
        let row = crate::entity::sys_config::Entity::find()
            .filter(crate::entity::sys_config::Column::ConfigKey.eq("sys.upload.backend"))
            .one(&ctx.state.db)
            .await
            .expect("读 sys.upload.backend 失败");
        row.and_then(|r| r.config_value)
    };
    set_backend(&ctx, "s3").await;
    let v = ctx.get_json("/system/uploadConfig").await;
    assert_eq!(
        v["data"]["backendMode"], "s3",
        "回显必须跟随生效档位（改前恒回显出厂档 ⇒ 显示与行为分裂）: {v}"
    );
    match prev {
        Some(old) => set_backend(&ctx, &old).await,
        None => {
            crate::entity::sys_config::Entity::delete_many()
                .filter(crate::entity::sys_config::Column::ConfigKey.eq("sys.upload.backend"))
                .exec(&ctx.state.db)
                .await
                .expect("清理测试写入失败");
            ctx.state
                .config_service
                .refresh_cache()
                .await
                .expect("刷新缓存失败");
        }
    }
    let v = ctx.get_json("/system/uploadConfig").await;
    assert_eq!(
        v["data"]["backendMode"], "local",
        "恢复原值后回显应回到 local: {v}"
    );

    // 5. 切档后上传链路仍通（热层 local 后端接管）
    let boundary = "it-switch-boundary";
    let body = {
        let mut b = Vec::new();
        b.extend_from_slice(
            format!(
                "--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"it-switch.txt\"\r\nContent-Type: text/plain\r\n\r\n"
            )
            .as_bytes(),
        );
        b.extend_from_slice(b"switch-hot-upload");
        b.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
        b
    };
    let mut req = Request::builder()
        .method(Method::POST)
        .uri("/common/upload")
        .header("authorization", format!("Bearer {}", ctx.token))
        .header(
            "content-type",
            format!("multipart/form-data; boundary={boundary}"),
        )
        .body(Body::from(body))
        .expect("构造请求失败");
    req.extensions_mut()
        .insert(axum::extract::ConnectInfo(std::net::SocketAddr::from((
            ctx.peer_ip,
            4321,
        ))));
    let (st, v) = ctx.send_raw(req).await;
    assert_eq!(st, StatusCode::OK, "切档后上传应成功: {v}");
    assert!(
        v["url"]
            .as_str()
            .unwrap_or_default()
            .starts_with("/uploads/0/file/"),
        "上传 URL 应位于 file 目录: {v}"
    );
}
