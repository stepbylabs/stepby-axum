//! 报表数据集集成测试（G-01 M1 验收欠账补齐，批次九）：
//! - CRUD 全链：建（合法 SELECT 模板）→ list → info → edit → preview → remove
//! - SQL 白名单 fail-closed：INSERT 模板 → 400
//! - 租户隔离：dataset 行归属租户 2 时，平台（tenant 0）操作者 ensure_access → 403
//!   （tenant_allowed 单向语义：平台操作租户行 = 越权，与 e2e 功能 74 同口径）
//! - **批七十五 B4**：模板末尾分号与 `LIMIT` 硬顶的口径配对（带分号的模板必须仍能试跑并截到 100 行）；
//!   合法但 0 行的查询必须仍给出真实列名、且不得把空采样写进 `columns_meta`
//!
//! 账号：admin（平台，tenant 0，持 report:dataset:* 全部权限）。

use super::{TestContext, login};
use axum::body::Body;
use axum::extract::connect_info::ConnectInfo;
use axum::http::{Method, Request, StatusCode};
use std::net::SocketAddr;

fn token_request(
    ctx: &TestContext,
    token: &str,
    method: Method,
    uri: &str,
    body: Option<serde_json::Value>,
) -> Request<Body> {
    let builder = Request::builder()
        .method(method)
        .uri(uri)
        .header("authorization", format!("Bearer {token}"));
    let mut req = match body {
        Some(b) => builder
            .header("content-type", "application/json")
            .body(Body::from(b.to_string()))
            .expect("构造请求失败"),
        None => builder.body(Body::empty()).expect("构造请求失败"),
    };
    req.extensions_mut()
        .insert(ConnectInfo(SocketAddr::from((ctx.peer_ip, 4321))));
    req
}

async fn post_json(
    ctx: &TestContext,
    token: &str,
    uri: &str,
    body: serde_json::Value,
) -> serde_json::Value {
    ctx.send_json(token_request(ctx, token, Method::POST, uri, Some(body)))
        .await
}

async fn put_json(
    ctx: &TestContext,
    token: &str,
    uri: &str,
    body: serde_json::Value,
) -> serde_json::Value {
    ctx.send_json(token_request(ctx, token, Method::PUT, uri, Some(body)))
        .await
}

async fn get_json(ctx: &TestContext, token: &str, uri: &str) -> serde_json::Value {
    ctx.send_json(token_request(ctx, token, Method::GET, uri, None))
        .await
}

/// 直接对运行库计数（用于给"硬顶是否真的生效"准备**非零探针面**）
async fn count_rows(ctx: &TestContext, table: &str) -> i64 {
    use sea_orm::{ConnectionTrait, DatabaseBackend, Statement};
    let row = ctx
        .state
        .db
        .query_one_raw(Statement::from_string(
            DatabaseBackend::Sqlite,
            format!("SELECT COUNT(*) AS n FROM {table}"),
        ))
        .await
        .expect("计数查询失败")
        .expect("COUNT 必有一行");
    row.try_get::<i64>("", "n").expect("n 列应为整数")
}

/// 链路：合法数据集 CRUD 全链 + 白名单拒绝 + preview
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_report_dataset_crud_chain() {
    let ctx = TestContext::new().await;
    let admin_token = ctx.token.clone();

    // 1) 新增（合法参数化 SELECT）
    let v = post_json(
        &ctx,
        &admin_token,
        "/report/dataset",
        serde_json::json!({
            "datasetCode": "it_ds_daily",
            "datasetName": "集成测试·日报数据集",
            "sqlTemplate": "SELECT user_id, user_name FROM sys_user WHERE status = :status",
            "paramsSchema": [{"name": "status", "type": "string", "required": true}],
            "status": "0",
            "remark": "it"
        }),
    )
    .await;
    ctx.assert_ok(&v);
    let dataset_id = v["data"]["datasetId"].as_i64().expect("应返回 datasetId");

    // 2) list 命中
    let v = get_json(
        &ctx,
        &admin_token,
        "/report/dataset/list?pageNum=1&pageSize=50",
    )
    .await;
    assert!(
        v["rows"]
            .as_array()
            .expect("rows 应为数组")
            .iter()
            .any(|r| r["datasetId"].as_i64() == Some(dataset_id)),
        "list 应含新建数据集: {v}"
    );

    // 3) SQL 明文经专用端点回填：admin（持 edit 键）得明文；info 出参恒无明文（零泄漏面）
    let v = post_json(
        &ctx,
        &admin_token,
        &format!("/report/dataset/{dataset_id}/sql"),
        serde_json::json!({}),
    )
    .await;
    ctx.assert_ok(&v);
    assert_eq!(
        v["data"].as_str(),
        Some("SELECT user_id, user_name FROM sys_user WHERE status = :status"),
        "持 edit 权限者经专用端点应得 SQL 明文，实际: {v}"
    );
    let v = get_json(&ctx, &admin_token, &format!("/report/dataset/{dataset_id}")).await;
    assert!(
        v["data"]["sqlTemplate"].is_null(),
        "info 出参不得携带 SQL 明文，实际: {v}"
    );

    // 3b) 无 edit 权限者调 SQL 端点 → 403（权限键 fail-closed 拦截）
    // 批次十三起 role 2 全量授权 G-01/G-02 菜单（用户拍板），种子 stepby 用户（role 2）
    // 已合法持有 report:dataset:edit ⇒ 临时摘除其角色构造"真正无权限者"，断言后恢复。
    {
        use sea_orm::{ConnectionTrait, DatabaseBackend, Statement};
        let db = &ctx.state.db;
        db.execute_raw(Statement::from_string(
            DatabaseBackend::Sqlite,
            "DELETE FROM sys_user_role WHERE user_id = \
             (SELECT user_id FROM sys_user WHERE user_name = 'stepby')"
                .to_string(),
        ))
        .await
        .expect("摘除 stepby 角色失败");
        let stepby_token =
            super::login(&ctx.app, super::next_peer_ip(), "stepby", "admin123").await;
        let (status, _) = ctx
            .send_raw(token_request(
                &ctx,
                &stepby_token,
                Method::POST,
                &format!("/report/dataset/{dataset_id}/sql"),
                Some(serde_json::json!({})),
            ))
            .await;
        assert_eq!(
            status, 403,
            "无 edit 权限取 SQL 明文必须 403，实际: {status}"
        );
        // 恢复 stepby ↔ role 2（不影响其它用例的种子假设）
        db.execute_raw(Statement::from_string(
            DatabaseBackend::Sqlite,
            "INSERT INTO sys_user_role (user_id, role_id) \
             SELECT user_id, 2 FROM sys_user WHERE user_name = 'stepby'"
                .to_string(),
        ))
        .await
        .expect("恢复 stepby 角色失败");
    }

    // 4) 非法模板（INSERT）→ 400（白名单 fail-closed；走 send_raw，不触发 200 断言）
    let (status, body) = ctx
        .send_raw(token_request(
            &ctx,
            &admin_token,
            Method::POST,
            "/report/dataset",
            Some(serde_json::json!({
                "datasetCode": "it_ds_bad",
                "datasetName": "非法模板",
                "sqlTemplate": "DELETE FROM sys_user",
                "status": "0"
            })),
        ))
        .await;
    assert_eq!(status, 400, "DML 模板必须 400，实际: {status} {body}");
    assert!(
        body["msg"]
            .as_str()
            .unwrap_or_default()
            .contains("SQL 模板校验失败"),
        "错误消息应来自白名单校验器: {body}"
    );

    // 5) preview（带参数）→ 返回列与行
    let v = post_json(
        &ctx,
        &admin_token,
        "/report/dataset/preview",
        serde_json::json!({
            "datasetId": dataset_id,
            "params": {"status": "0"}
        }),
    )
    .await;
    ctx.assert_ok(&v);
    // G-01 M3：columns_meta 走临时视图探针——应返回真实列名（而非 colN 占位）
    let cols = v["data"]["columns"]
        .as_array()
        .expect("columns 应为数组")
        .iter()
        .map(|c| c.as_str().unwrap_or_default().to_string())
        .collect::<Vec<_>>();
    assert!(!cols.is_empty(), "preview 应返回列元数据");
    assert!(
        cols.iter()
            .all(|c| !c.starts_with("col1") || *c == "user_id"),
        "探针应取真实列名，实际: {cols:?}"
    );
    assert!(
        cols.contains(&"user_id".to_string()) && cols.contains(&"user_name".to_string()),
        "探针应取到真实列名 user_id/user_name，实际: {cols:?}"
    );

    // 6) 编辑（改名）
    let v = put_json(
        &ctx,
        &admin_token,
        "/report/dataset",
        serde_json::json!({
            "datasetId": dataset_id,
            "datasetCode": "it_ds_daily",
            "datasetName": "集成测试·日报数据集（改）",
            "sqlTemplate": "SELECT user_id, user_name FROM sys_user WHERE status = :status",
            "status": "0"
        }),
    )
    .await;
    ctx.assert_ok(&v);

    // 7) 删除
    let v = ctx
        .send_json(token_request(
            &ctx,
            &admin_token,
            Method::DELETE,
            &format!("/report/dataset/{dataset_id}"),
            None,
        ))
        .await;
    ctx.assert_ok(&v);
    // 删除后 info 应 not_found——用 send_raw（get_json 内部断言 200，无法表达预期 404）
    let (status, body) = ctx
        .send_raw(token_request(
            &ctx,
            &admin_token,
            Method::GET,
            &format!("/report/dataset/{dataset_id}"),
            None,
        ))
        .await;
    assert_eq!(
        status, 404,
        "删除后 info 应 not_found（数据集不存在），实际: {status} {body}"
    );
}

/// 批七十五 B4：模板以 `;` 结束时，试跑必须既**不报错**又**仍然截到 100 行**。
///
/// 缺陷本体：校验器刻意放行末尾分号（`dataset_sql::test_trailing_semi_allowed`），
/// 而 preview 直接 `format!("{sql} LIMIT 100")` ⇒ `SELECT … ; LIMIT 100` 在驱动侧是
/// **两条语句**。变异运行实测：三档方言一律 500（SQLite/sqlx 报多语句，返回
/// `{"code":500,"msg":"数据库操作失败，请联系管理员"}`；MySQL/PG 报语法错）。
/// 用户可见面是"保存时校验通过、试跑永久失败，且看不出只差一个分号"。
///
/// 对照组：同一查询**不带**分号必须给出完全相同的截断结果——归一不得改变合法模板语义。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_report_dataset_preview_trailing_semicolon_keeps_hard_cap() {
    let ctx = TestContext::new().await;
    let admin_token = ctx.token.clone();

    // 非零探针面：模板扫的表行数必须大于硬顶，否则"截到 100 行"这件事证不出来
    let total = count_rows(&ctx, "sys_menu").await;
    assert!(
        total > 100,
        "探针面不足：sys_menu 只有 {total} 行（需 > 100），本用例无法证明 LIMIT 生效"
    );

    let cases = [
        (
            "it_ds_semi",
            "SELECT menu_id FROM sys_menu WHERE menu_id > 0;",
        ),
        (
            "it_ds_nosemi",
            "SELECT menu_id FROM sys_menu WHERE menu_id > 0",
        ),
    ];
    for (code, template) in cases {
        let v = post_json(
            &ctx,
            &admin_token,
            "/report/dataset",
            serde_json::json!({
                "datasetCode": code,
                "datasetName": format!("集成测试·分号硬顶 {code}"),
                "sqlTemplate": template,
                "status": "0"
            }),
        )
        .await;
        ctx.assert_ok(&v);
        let dataset_id = v["data"]["datasetId"].as_i64().expect("应返回 datasetId");

        let v = post_json(
            &ctx,
            &admin_token,
            "/report/dataset/preview",
            serde_json::json!({ "datasetId": dataset_id, "params": {} }),
        )
        .await;
        ctx.assert_ok(&v);
        let rows = v["data"]["rows"].as_array().expect("rows 应为数组");
        assert_eq!(
            rows.len(),
            100,
            "[{template}] LIMIT 硬顶必须截到 100 行，实际 {}（总行数 {total}）——\
             返回总数即说明追加的子句落进了分号之后的第二条语句、整体没生效",
            rows.len()
        );
        assert_eq!(
            v["data"]["truncated"],
            serde_json::Value::Bool(true),
            "[{template}] 触顶时 truncated 必须为真，实际: {}",
            v["data"]["truncated"]
        );
        assert_eq!(
            v["data"]["columns"]
                .as_array()
                .expect("columns 应为数组")
                .len(),
            1,
            "[{template}] 列采样应恰为 menu_id 一列"
        );
    }
}

/// 批七十五 B4（第二支）：**合法但当前 0 行**的查询必须仍给出真实列名，
/// 且不得把空采样写进 `columns_meta`。
///
/// 缺陷本体：列名提取挂在 `for (idx, row) … if idx == 0` 里 ⇒ 空结果集一次都不进分支，
/// `columns` 为空 ⇒ 设计器字段选择器整块空，且空清单被当采样结果缓存回写。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_report_dataset_preview_zero_rows_still_yields_columns() {
    use sea_orm::EntityTrait;

    let ctx = TestContext::new().await;
    let admin_token = ctx.token.clone();

    let v = post_json(
        &ctx,
        &admin_token,
        "/report/dataset",
        serde_json::json!({
            "datasetCode": "it_ds_empty",
            "datasetName": "集成测试·空结果列采样",
            "sqlTemplate": "SELECT user_id, user_name FROM sys_user WHERE status = :status;",
            "paramsSchema": [{"name": "status", "type": "string", "required": true}],
            "status": "0"
        }),
    )
    .await;
    ctx.assert_ok(&v);
    let dataset_id = v["data"]["datasetId"].as_i64().expect("应返回 datasetId");

    let v = post_json(
        &ctx,
        &admin_token,
        "/report/dataset/preview",
        serde_json::json!({ "datasetId": dataset_id, "params": { "status": "__no_such_status__" } }),
    )
    .await;
    ctx.assert_ok(&v);
    // 前提核对：这次查询确实返回 0 行（否则本用例什么都没测）
    assert_eq!(
        v["data"]["rows"].as_array().expect("rows 应为数组").len(),
        0,
        "构造前提失效：该参数值应查不到行，实际: {}",
        v["data"]["rows"]
    );
    let cols: Vec<&str> = v["data"]["columns"]
        .as_array()
        .expect("columns 应为数组")
        .iter()
        .map(|c| c.as_str().unwrap_or_default())
        .collect();
    assert_eq!(
        cols,
        vec!["user_id", "user_name"],
        "0 行也必须返回真实列名（列名与行数无关）"
    );
    assert_eq!(
        v["data"]["truncated"],
        serde_json::Value::Bool(false),
        "空结果不得误报触顶"
    );

    // 回写的缓存必须是**非空**采样（此前空清单会被写进 columns_meta 并长期污染设计器）
    let model = crate::entity::report_dataset::Entity::find_by_id(dataset_id)
        .one(&ctx.state.db)
        .await
        .expect("查询数据集失败")
        .expect("数据集应存在");
    let meta = model
        .columns_meta
        .as_deref()
        .unwrap_or_default()
        .to_string();
    let parsed: serde_json::Value =
        serde_json::from_str(&meta).expect("columns_meta 应为合法 JSON");
    let cached: Vec<&str> = parsed["columns"]
        .as_array()
        .expect("columns_meta.columns 应为数组")
        .iter()
        .map(|c| c.as_str().unwrap_or_default())
        .collect();
    assert_eq!(
        cached,
        vec!["user_id", "user_name"],
        "0 行试跑不得把空列清单写入 columns_meta，实际缓存: {meta}"
    );
}

/// b94：报告大屏写权限拆分 + ID 列表严格解析（同一链路取证）。
///
/// 判据四段：
/// 1. 种子契约：4148=view、4149=edit、4150=remove；common(role 2) 不持有写按钮；
/// 2. 只读角色：list/info 200，save/delete 403；
/// 3. 补授 edit：save 200，delete 仍 403（证明两个写键互相独立）；
/// 4. 补授 remove 后：畸形 ID（`<id>,abc`）必须 400 且看板仍在（旧解析器会静默删掉前半段）；
///    合法 ID 200 且 info 转 404。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_report_dashboard_write_perm_and_strict_id_list() {
    use crate::entity::{sys_menu, sys_role_menu};
    use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};

    let ctx = TestContext::new().await;
    let db = &ctx.state.db;

    // 1. 种子契约
    for (menu_id, perm) in [
        (4148_i64, "report:dashboard:view"),
        (4149_i64, "report:dashboard:edit"),
        (4150_i64, "report:dashboard:remove"),
    ] {
        let m = sys_menu::Entity::find_by_id(menu_id)
            .one(db)
            .await
            .expect("查询 sys_menu 失败")
            .unwrap_or_else(|| panic!("菜单 {menu_id} 应存在"));
        assert_eq!(
            m.perms.as_deref(),
            Some(perm),
            "菜单 {menu_id} 的权限键应为 {perm}"
        );
    }
    for menu_id in [4149_i64, 4150] {
        let granted = sys_role_menu::Entity::find()
            .filter(sys_role_menu::Column::RoleId.eq(2))
            .filter(sys_role_menu::Column::MenuId.eq(menu_id))
            .one(db)
            .await
            .expect("查询 sys_role_menu 失败")
            .is_some();
        assert!(
            !granted,
            "common(role 2) 不得持有大屏写按钮 {menu_id}（写权限必须显式授权）"
        );
    }

    // 2. admin 建一个大屏作为被删对象
    let v = ctx
        .post_json(
            "/report/dashboard",
            serde_json::json!({
                "dashboardCode": "it_b94_board",
                "dashboardName": "b94 权限用例",
                "layoutJson": {"schemaVersion": 2, "charts": []},
                "status": "0"
            }),
        )
        .await;
    let dashboard_id = v["data"]["dashboardId"]
        .as_i64()
        .expect("新建大屏应返回 dashboardId");

    // 3. 只授页面菜单 4148 的只读角色
    let role_key = "it_report_viewer";
    let v = ctx
        .post_json(
            "/system/role",
            serde_json::json!({
                "roleName": "大屏只读",
                "roleKey": role_key,
                "roleSort": 97,
                "status": "0",
                "menuIds": [4148]
            }),
        )
        .await;
    ctx.assert_ok(&v);
    let v = ctx
        .get_json(&format!("/system/role/list?roleKey={role_key}"))
        .await;
    let role_id = v["rows"][0]["roleId"].as_i64().expect("应能查到只读角色");

    let uname = "it_report_viewer";
    let v = ctx
        .post_json(
            "/system/user",
            serde_json::json!({
                "deptId": 103,
                "userName": uname,
                "nickName": "大屏只读用户",
                "email": "stepby@tzkj.net",
                "phonenumber": "13800009996",
                "sex": "0",
                "password": "Stepby@12345",
                "status": "0",
                "roleIds": [role_id]
            }),
        )
        .await;
    ctx.assert_ok(&v);
    let token = login(&ctx.app, ctx.peer_ip, uname, "Stepby@12345").await;

    // 读接口 200（证明不是没登录/没权限）
    for uri in [
        "/report/dashboard/list".to_string(),
        format!("/report/dashboard/{dashboard_id}"),
    ] {
        let (status, v) = ctx.send_raw_with_token(Method::GET, &uri, &token).await;
        assert_eq!(status, StatusCode::OK, "只读用户应能读取 {uri}: {v}");
        assert_eq!(v["code"], 200, "只读用户读取 {uri} 业务码应为 200: {v}");
    }

    // 写接口 403
    let save_body = serde_json::json!({
        "dashboardId": dashboard_id,
        "dashboardCode": "it_b94_board",
        "dashboardName": "b94 权限用例（只读改名）",
        "layoutJson": {"schemaVersion": 2, "charts": []},
        "status": "0"
    });
    let (status, v) = ctx
        .send_raw(token_request(
            &ctx,
            &token,
            Method::POST,
            "/report/dashboard",
            Some(save_body.clone()),
        ))
        .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "只读角色保存大屏必须 403: {v}"
    );
    let (status, v) = ctx
        .send_raw_with_token(
            Method::DELETE,
            &format!("/report/dashboard/{dashboard_id}"),
            &token,
        )
        .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "只读角色删除大屏必须 403: {v}"
    );

    // 4. 补授 edit：保存 200，删除仍 403
    let v = ctx
        .put_json(
            "/system/role",
            serde_json::json!({
                "roleId": role_id,
                "roleName": "大屏只读+编辑",
                "menuIds": [4148, 4149]
            }),
        )
        .await;
    ctx.assert_ok(&v);
    let (status, v) = ctx
        .send_raw(token_request(
            &ctx,
            &token,
            Method::POST,
            "/report/dashboard",
            Some(save_body),
        ))
        .await;
    assert_eq!(status, StatusCode::OK, "补授 edit 后保存应成功: {v}");
    let (status, v) = ctx
        .send_raw_with_token(
            Method::DELETE,
            &format!("/report/dashboard/{dashboard_id}"),
            &token,
        )
        .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "只有 edit 时删除仍须 403: {v}"
    );

    // 5. 补授 remove：畸形 ID 400 且对象仍在；合法删除 200
    let v = ctx
        .put_json(
            "/system/role",
            serde_json::json!({
                "roleId": role_id,
                "roleName": "大屏读写删",
                "menuIds": [4148, 4149, 4150]
            }),
        )
        .await;
    ctx.assert_ok(&v);
    let (status, v) = ctx
        .send_raw_with_token(
            Method::DELETE,
            &format!("/report/dashboard/{dashboard_id},abc"),
            &token,
        )
        .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "畸形 ID 列表必须 400（旧解析器会静默删掉前半段）: {v}"
    );
    let (status, v) = ctx
        .send_raw_with_token(
            Method::GET,
            &format!("/report/dashboard/{dashboard_id}"),
            &token,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "畸形删除不得产生任何副作用: {v}");

    let (status, v) = ctx
        .send_raw_with_token(
            Method::DELETE,
            &format!("/report/dashboard/{dashboard_id}"),
            &token,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "补授 remove 后合法删除应成功: {v}");
    let (status, _) = ctx
        .send_raw_with_token(
            Method::GET,
            &format!("/report/dashboard/{dashboard_id}"),
            &token,
        )
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "软删后详情应为 404");
}
