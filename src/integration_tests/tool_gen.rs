// axum-backend/src/integration_tests/tool_gen.rs
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
                "packageName": "com.yebot.gen",
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
