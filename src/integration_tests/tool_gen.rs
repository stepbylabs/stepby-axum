// stepby-axum/src/integration_tests/tool_gen.rs
//! 代码生成模块链路集成测试：
//! - 创建表 → 列表 → 详情 → 编辑 → 预览 → 删除 全 CRUD
//! - 参数校验错误分支
//!
//! 种子数据（m20250711_000001_init）：
//! gen_table / gen_table_column 表仅建表，无种子数据。
//! 测试前需通过 `/tool/gen/createTable` 创建测试表并导入到 gen_table。
//!
//! 唯一前缀：it_gen。

use super::TestContext;
use axum::http::Method;

/// 创建表 → 列表 → 详情 → 编辑 → 预览 → 删除 全链路。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_gen_table_create_list_detail_edit_preview_delete_chain() {
    let ctx = TestContext::new().await;

    // 1. 查询列表（初始为空）
    let v = ctx.get_json("/tool/gen/list?pageNum=1&pageSize=10").await;
    let rows = v["rows"].as_array().expect("rows 应为数组");
    assert!(rows.is_empty(), "初始应无 gen_table 记录，实际: {v}");

    // 2. 创建测试表
    let v = ctx
        .post_json(
            "/tool/gen/createTable",
            serde_json::json!({
                "tableName": "it_gen_test_table",
                "tableComment": "集成测试代码生成表",
                "columns": [
                    {
                        "columnName": "id",
                        "dataType": "bigint",
                        "isPrimaryKey": true,
                        "isAutoIncrement": true,
                        "isNotNull": true
                    },
                    {
                        "columnName": "name",
                        "dataType": "varchar",
                        "length": 100,
                        "isNotNull": true
                    },
                    {
                        "columnName": "status",
                        "dataType": "tinyint",
                        "defaultValue": "0"
                    }
                ],
                "importToGen": true
            }),
        )
        .await;
    ctx.assert_ok(&v);
    let table_id = v["data"]["tableId"].as_i64().expect("应返回 tableId");
    assert!(table_id > 0, "tableId 应为正数，实际: {table_id}");
    assert_eq!(
        v["data"]["tableName"].as_str(),
        Some("it_gen_test_table"),
        "tableName 应匹配，实际: {v}"
    );

    // 3. 列表查询应包含新表
    let v = ctx.get_json("/tool/gen/list?pageNum=1&pageSize=10").await;
    let rows = v["rows"].as_array().expect("rows 应为数组");
    assert!(
        rows.iter().any(|r| r["tableName"] == "it_gen_test_table"),
        "列表应包含新创建的表，实际: {v}"
    );

    // 4. 详情查询
    let v = ctx.get_json(&format!("/tool/gen/{}", table_id)).await;
    assert_eq!(
        v["data"]["info"]["tableName"].as_str(),
        Some("it_gen_test_table"),
        "详情 tableName 应匹配，实际: {v}"
    );
    let columns = v["data"]["rows"]
        .as_array()
        .expect("详情应包含 columns 数组");
    assert!(columns.len() >= 3, "应至少 3 列，实际: {v}");

    // 5. 编辑表配置
    let v = ctx
        .put_json(
            "/tool/gen",
            serde_json::json!({
                "tableId": table_id,
                "tableName": "it_gen_test_table",
                "tableComment": "集成测试代码生成表(已编辑)",
                "className": "ItGenTestTable",
                "functionName": "集成测试",
                "functionAuthor": "tester",
                "tplCategory": "crud",
                "tplWebType": "element-plus",
                "packageName": "com.stepby.gen",
                "moduleName": "gen",
                "businessName": "test_table",
                "genType": "0",
                "remark": "集成测试编辑"
            }),
        )
        .await;
    ctx.assert_ok(&v);

    // 6. 确认编辑生效
    let v = ctx.get_json(&format!("/tool/gen/{}", table_id)).await;
    assert_eq!(
        v["data"]["info"]["functionName"].as_str(),
        Some("集成测试"),
        "编辑后的 functionName 应生效，实际: {v}"
    );

    // 7. 预览代码
    let v = ctx
        .get_json(&format!("/tool/gen/preview/{}", table_id))
        .await;
    let data = v["data"].as_object().expect("预览 data 应为对象");
    assert!(!data.is_empty(), "预览应返回至少一个模板文件，实际: {v}");
    // 应包含常见模板文件（src/entity/{TableName}.rs）
    let has_entity = data.keys().any(|k| k.contains("src/entity/"));
    assert!(
        has_entity,
        "预览应包含 entity 模板，实际 keys: {:?}",
        data.keys()
    );

    // 8. 删除表
    let v = ctx.delete_json(&format!("/tool/gen/{}", table_id)).await;
    ctx.assert_ok(&v);

    // 9. 确认删除生效
    let v = ctx.get_json("/tool/gen/list?pageNum=1&pageSize=10").await;
    let rows = v["rows"].as_array().expect("rows 应为数组");
    assert!(
        !rows.iter().any(|r| r["tableName"] == "it_gen_test_table"),
        "删除后不应再查到该表，实际: {v}"
    );
}

/// 参数校验错误分支。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_gen_validation_errors() {
    let ctx = TestContext::new().await;

    // 1. 创建表缺少列定义 → 400
    let (status, v) = ctx
        .send_raw(ctx.request(
            Method::POST,
            "/tool/gen/createTable",
            Some(serde_json::json!({
                "tableName": "it_gen_bad",
                "columns": []
            })),
        ))
        .await;
    assert_ne!(
        v["code"], 200,
        "缺少列定义创建表业务码不应为 200，实际: {v}"
    );
    assert_eq!(
        status,
        axum::http::StatusCode::BAD_REQUEST,
        "缺少列定义应 400，实际: {status}"
    );

    // 2. 创建表使用非法表名 → 400
    let (status, v) = ctx
        .send_raw(ctx.request(
            Method::POST,
            "/tool/gen/createTable",
            Some(serde_json::json!({
                "tableName": "it gen bad space",
                "columns": [
                    {
                        "columnName": "id",
                        "dataType": "bigint",
                        "isPrimaryKey": true
                    }
                ]
            })),
        ))
        .await;
    assert_ne!(v["code"], 200, "非法表名创建表业务码不应为 200，实际: {v}");
    assert_eq!(
        status,
        axum::http::StatusCode::BAD_REQUEST,
        "非法表名应 400，实际: {status}"
    );

    // 3. 删除不存在的表 → 404
    let (status, v) = ctx
        .send_raw(ctx.request(Method::DELETE, "/tool/gen/999999", None))
        .await;
    assert_ne!(v["code"], 200, "删除不存在表业务码不应为 200，实际: {v}");
    assert_eq!(
        status,
        axum::http::StatusCode::NOT_FOUND,
        "删除不存在表应 404，实际: {status}"
    );

    // 4. 预览不存在的表 → 404
    let (status, v) = ctx
        .send_raw(ctx.request(Method::GET, "/tool/gen/preview/999999", None))
        .await;
    assert_ne!(v["code"], 200, "预览不存在表业务码不应为 200，实际: {v}");
    assert_eq!(
        status,
        axum::http::StatusCode::NOT_FOUND,
        "预览不存在表应 404，实际: {status}"
    );

    // 5. 编辑不存在的表 → 404
    let (status, v) = ctx
        .send_raw(ctx.request(
            Method::PUT,
            "/tool/gen",
            Some(serde_json::json!({
                "tableId": 999999,
                "tableName": "nonexistent",
                "className": "Nonexistent"
            })),
        ))
        .await;
    assert_ne!(v["code"], 200, "编辑不存在表业务码不应为 200，实际: {v}");
    assert_eq!(
        status,
        axum::http::StatusCode::NOT_FOUND,
        "编辑不存在表应 404，实际: {status}"
    );

    // 6. 批量生成代码未传 tables → 400
    let (status, v) = ctx
        .send_raw(ctx.request(Method::GET, "/tool/gen/batchGenCode", None))
        .await;
    assert_ne!(v["code"], 200, "未传 tables 业务码不应为 200，实际: {v}");
    assert_eq!(
        status,
        axum::http::StatusCode::BAD_REQUEST,
        "未传 tables 应 400，实际: {status}"
    );
}

/// 读出 ZIP 的全部条目名（b139：ZIP 条目结构是这条链路的真实产物）。
fn zip_entry_names(bytes: &[u8]) -> Vec<String> {
    let mut zip = zip::ZipArchive::new(std::io::Cursor::new(bytes))
        .expect("响应体应是合法 ZIP（前端此前把字节丢进 JSON 解析）");
    (0..zip.len())
        .map(|i| zip.by_index(i).expect("读条目失败").name().to_string())
        .collect()
}

/// b139：代码生成的 ZIP 条目路径必须由 `path` 参数决定。
///
/// 立项取证（改造前）：`gen_table.gen_path` 在**全后端**只有 DTO/entity/默认值四处出现，
/// `gen_code` 从不读它、也从不写磁盘；前端 `genCode()` 没声明 `responseType: 'blob'`，
/// ZIP 字节被 axios 当文本解析、响应拦截器按"无 code ⇒ 200"判定成功，页面弹
/// 「成功生成到自定义路径：{path}」——用户点了既拿不到文件、也收不到错误。
///
/// 本用例钉住四件事：① ZIP 真能读回 ② `path` 决定条目前缀 ③ 前缀只加目录不改变文件集
/// ④ 穿越/绝对路径/反斜杠/NUL 一律 400（Zip Slip 防线）。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_gen_code_zip_entries_follow_path_prefix() {
    let ctx = TestContext::new().await;

    // 1. 建表并导入到代码生成
    let v = ctx
        .post_json(
            "/tool/gen/createTable",
            serde_json::json!({
                "tableName": "it_gen_path_prefix",
                "tableComment": "路径前缀集成测试",
                "columns": [
                    {
                        "columnName": "id",
                        "dataType": "bigint",
                        "isPrimaryKey": true,
                        "isAutoIncrement": true,
                        "isNotNull": true
                    },
                    {
                        "columnName": "name",
                        "dataType": "varchar",
                        "length": 100,
                        "isNotNull": true
                    }
                ],
                "importToGen": true
            }),
        )
        .await;
    ctx.assert_ok(&v);

    // 2. 缺省 path ⇒ 平铺，且响应头是可用的文件名（b139 之前 tool_gen 是"失败静默不设头"）
    let (status, headers, body) = ctx
        .send_binary(ctx.request(Method::GET, "/tool/gen/genCode/it_gen_path_prefix", None))
        .await;
    assert_eq!(status, axum::http::StatusCode::OK, "缺省生成应 200");
    assert_eq!(
        headers.get("content-type").and_then(|v| v.to_str().ok()),
        Some("application/zip"),
        "响应必须是 application/zip"
    );
    let cd = headers
        .get("content-disposition")
        .and_then(|v| v.to_str().ok())
        .expect("下载响应必须带 Content-Disposition");
    assert!(
        cd.contains("filename=\"it_gen_path_prefix.zip\""),
        "实际: {cd}"
    );
    // 2b. 可复现性：同样的表连续生成两次必须逐字节相同。
    // 改造前 `render_templates` 返回 `HashMap`，ZIP 条目顺序随机 ⇒ 两个包字节不同、
    // 内容却完全一致（无法做校验和/缓存/跨环境比对）。
    let (_, _, body_again) = ctx
        .send_binary(ctx.request(Method::GET, "/tool/gen/genCode/it_gen_path_prefix", None))
        .await;
    assert_eq!(
        body, body_again,
        "同输入两次生成的 ZIP 必须逐字节相同（BTreeMap 定序）"
    );

    let flat = zip_entry_names(&body);
    assert!(!flat.is_empty(), "ZIP 不应为空");
    // 模板条目名**本身**带目录（`src/entity/…`、`migration/…`），所以"平铺"的判据
    // 是"不带调用方前缀"，不是"不含斜杠"——这条区别是本用例第一版红在自己身上的原因。
    assert!(
        flat.iter().all(|n| !n.starts_with("module/system/")),
        "缺省不应出现调用方前缀，实际: {flat:?}"
    );

    // 3. path=module/system ⇒ 每个条目都带该前缀（genPath 从"死字段"转正的证据）
    let (status, _, body) = ctx
        .send_binary(ctx.request(
            Method::GET,
            "/tool/gen/genCode/it_gen_path_prefix?path=module/system",
            None,
        ))
        .await;
    assert_eq!(status, axum::http::StatusCode::OK, "带前缀生成应 200");
    let nested = zip_entry_names(&body);
    assert_eq!(nested.len(), flat.len(), "前缀不应改变条目数量");
    assert!(
        nested.iter().all(|n| n.starts_with("module/system/")),
        "实际: {nested:?}"
    );
    // 前缀只是目录：条目集合等于 `module/system/` + 缺省条目名（按集合比，不押注顺序）
    let mut expected: Vec<String> = flat.iter().map(|n| format!("module/system/{n}")).collect();
    expected.sort();
    let mut actual = nested.clone();
    actual.sort();
    assert_eq!(actual, expected, "前缀必须只加目录、不改条目名");

    // 4. 路径穿越 / 绝对路径 / 反斜杠 / NUL 一律 400（Zip Slip 防线）
    for bad in ["..%2Fetc", "%2Fetc", "a%5Cb", "a%00b"] {
        let (status, _, _) = ctx
            .send_binary(ctx.request(
                Method::GET,
                &format!("/tool/gen/genCode/it_gen_path_prefix?path={bad}"),
                None,
            ))
            .await;
        assert_eq!(
            status,
            axum::http::StatusCode::BAD_REQUEST,
            "path={bad} 应 400（Zip Slip 防线）"
        );
    }

    // 5. 清理
    let v = ctx.get_json("/tool/gen/list?pageNum=1&pageSize=50").await;
    let id = v["rows"]
        .as_array()
        .expect("rows 应为数组")
        .iter()
        .find(|r| r["tableName"] == "it_gen_path_prefix")
        .and_then(|r| r["tableId"].as_i64())
        .expect("应能查到刚创建的表");
    ctx.assert_ok(&ctx.delete_json(&format!("/tool/gen/{id}")).await);
}
