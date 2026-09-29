// backend-axum/src/integration_tests/sys_config_dict.rs
//! 参数配置 + 字典模块链路集成测试：
//! - 参数：列表 / 按 key 查值 / 详情 / 新增 → 修改 → 删除 / 刷新缓存
//! - 字典类型：列表 / 下拉 / 详情 / 新增 → 修改 → 删除 / 刷新缓存
//! - 字典数据：列表 / 按类型查 / 详情 / 新增 → 修改 → 删除

use super::TestContext;

/// 参数配置全链路。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_config_chain() {
    let ctx = TestContext::new().await;

    // 1. 分页列表
    let v = ctx
        .get_json("/system/config/list?pageNum=1&pageSize=10")
        .await;
    let rows = v["rows"].as_array().expect("rows 应为数组");
    assert!(rows.len() >= 6, "种子应至少 6 条参数配置，实际: {v}");

    // 2. 按 configKey 查询值（data 为字符串值）
    let v = ctx
        .get_json("/system/config/configKey/sys.index.skinName")
        .await;
    assert_eq!(
        v["data"].as_str(),
        Some("skin-blue"),
        "sys.index.skinName 值应为 skin-blue，实际: {v}"
    );

    // 3. 详情
    let v = ctx.get_json("/system/config/1").await;
    assert_eq!(
        v["data"]["configId"], 1,
        "参数详情 configId 应为 1，实际: {v}"
    );

    // 4. 新增参数
    let v = ctx
        .post_json(
            "/system/config",
            serde_json::json!({
                "configName": "集成测试参数",
                "configKey": "it.test.configKey",
                "configValue": "it-value",
                "configType": "Y",
                "remark": "集成测试"
            }),
        )
        .await;
    ctx.assert_ok(&v);

    // 5. 按 key 查新参数值
    let v = ctx
        .get_json("/system/config/configKey/it.test.configKey")
        .await;
    assert_eq!(
        v["data"].as_str(),
        Some("it-value"),
        "新参数值应为 it-value，实际: {v}"
    );

    // 6. 修改参数（取回 configId）
    let v = ctx
        .get_json("/system/config/list?configKey=it.test.configKey")
        .await;
    let config_id = v["rows"][0]["configId"]
        .as_i64()
        .expect("应查到新参数 configId");
    let v = ctx
        .put_json(
            "/system/config",
            serde_json::json!({
                "configId": config_id,
                "configKey": "it.test.configKey",
                "configValue": "it-value-edited"
            }),
        )
        .await;
    ctx.assert_ok(&v);
    let v = ctx
        .get_json("/system/config/configKey/it.test.configKey")
        .await;
    assert_eq!(
        v["data"].as_str(),
        Some("it-value-edited"),
        "修改后参数值应生效，实际: {v}"
    );

    // 7. 刷新缓存
    let v = ctx.delete_json("/system/config/refreshCache").await;
    ctx.assert_ok(&v);

    // 8. 删除参数
    let v = ctx
        .delete_json(&format!("/system/config/{}", config_id))
        .await;
    ctx.assert_ok(&v);
    let v = ctx
        .get_json("/system/config/list?configKey=it.test.configKey")
        .await;
    let rows = v["rows"].as_array().expect("rows 应为数组");
    assert!(rows.is_empty(), "删除后不应再查到该参数，实际: {v}");
}

/// 字典类型全链路。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_dict_type_chain() {
    let ctx = TestContext::new().await;

    // 1. 分页列表
    let v = ctx
        .get_json("/system/dict/type/list?pageNum=1&pageSize=20")
        .await;
    let rows = v["rows"].as_array().expect("rows 应为数组");
    assert!(rows.len() >= 10, "种子应至少 10 条字典类型，实际: {v}");

    // 2. 下拉
    let v = ctx.get_json("/system/dict/type/optionselect").await;
    let data = v["data"].as_array().expect("data 应为数组");
    assert!(
        data.iter().any(|d| d["dictType"] == "sys_user_sex"),
        "下拉应包含 sys_user_sex，实际: {v}"
    );

    // 3. 详情
    let v = ctx.get_json("/system/dict/type/1").await;
    assert_eq!(
        v["data"]["dictId"], 1,
        "字典类型详情 dictId 应为 1，实际: {v}"
    );

    // 4. 新增字典类型
    let v = ctx
        .post_json(
            "/system/dict/type",
            serde_json::json!({
                "dictName": "集成测试字典",
                "dictType": "it_test_dict",
                "status": "0",
                "remark": "集成测试"
            }),
        )
        .await;
    ctx.assert_ok(&v);

    // 5. 按 dictType 过滤查询到新字典类型
    let v = ctx
        .get_json("/system/dict/type/list?dictType=it_test_dict")
        .await;
    let rows = v["rows"].as_array().expect("rows 应为数组");
    assert_eq!(rows.len(), 1, "应查到 1 条新字典类型，实际: {v}");
    let dict_id = rows[0]["dictId"].as_i64().expect("dictId 应为数字");

    // 6. 修改字典类型
    let v = ctx
        .put_json(
            "/system/dict/type",
            serde_json::json!({
                "dictId": dict_id,
                "dictName": "集成测试字典改",
                "dictType": "it_test_dict",
                "status": "0"
            }),
        )
        .await;
    ctx.assert_ok(&v);
    let v = ctx
        .get_json(&format!("/system/dict/type/{}", dict_id))
        .await;
    assert_eq!(
        v["data"]["dictName"].as_str(),
        Some("集成测试字典改"),
        "修改后的 dictName 应生效，实际: {v}"
    );

    // 7. 刷新缓存
    let v = ctx.delete_json("/system/dict/type/refreshCache").await;
    ctx.assert_ok(&v);

    // 8. 删除字典类型
    let v = ctx
        .delete_json(&format!("/system/dict/type/{}", dict_id))
        .await;
    ctx.assert_ok(&v);
    let v = ctx
        .get_json("/system/dict/type/list?dictType=it_test_dict")
        .await;
    let rows = v["rows"].as_array().expect("rows 应为数组");
    assert!(rows.is_empty(), "删除后不应再查到该字典类型，实际: {v}");
}

/// 字典数据全链路。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_dict_data_chain() {
    let ctx = TestContext::new().await;

    // 0. 先创建字典类型 it_test_dict_data，否则新增数据会报"字典类型不存在"
    let v = ctx
        .post_json(
            "/system/dict/type",
            serde_json::json!({
                "dictName": "集成测试数据字典",
                "dictType": "it_test_dict_data",
                "status": "0",
                "remark": "集成测试"
            }),
        )
        .await;
    ctx.assert_ok(&v);

    // 1. 按字典类型分页列表
    let v = ctx
        .get_json("/system/dict/data/list?dictType=sys_user_sex")
        .await;
    let rows = v["rows"].as_array().expect("rows 应为数组");
    assert!(rows.len() >= 3, "sys_user_sex 应有 3 条数据，实际: {v}");

    // 2. 按类型查（data 数组）
    let v = ctx.get_json("/system/dict/data/type/sys_user_sex").await;
    let data = v["data"].as_array().expect("data 应为数组");
    assert!(data.len() >= 3, "sys_user_sex 数据应 >= 3 条，实际: {v}");

    // 3. 详情
    let v = ctx.get_json("/system/dict/data/1").await;
    assert_eq!(
        v["data"]["dictCode"], 1,
        "字典数据详情 dictCode 应为 1，实际: {v}"
    );

    // 4. 新增字典数据
    let v = ctx
        .post_json(
            "/system/dict/data",
            serde_json::json!({
                "dictSort": 99,
                "dictLabel": "集成测试标签",
                "dictValue": "IT",
                "dictType": "it_test_dict_data",
                "status": "0",
                "remark": "集成测试"
            }),
        )
        .await;
    ctx.assert_ok(&v);

    // 5. 按类型查询到新数据
    let v = ctx
        .get_json("/system/dict/data/type/it_test_dict_data")
        .await;
    let data = v["data"].as_array().expect("data 应为数组");
    assert_eq!(data.len(), 1, "应查到 1 条新字典数据，实际: {v}");
    let dict_code = data[0]["dictCode"].as_i64().expect("dictCode 应为数字");

    // 6. 修改字典数据
    let v = ctx
        .put_json(
            "/system/dict/data",
            serde_json::json!({
                "dictCode": dict_code,
                "dictLabel": "集成测试标签改",
                "dictValue": "IT2",
                "dictType": "it_test_dict_data",
                "status": "0"
            }),
        )
        .await;
    ctx.assert_ok(&v);
    let v = ctx
        .get_json(&format!("/system/dict/data/{}", dict_code))
        .await;
    assert_eq!(
        v["data"]["dictLabel"].as_str(),
        Some("集成测试标签改"),
        "修改后的 dictLabel 应生效，实际: {v}"
    );

    // 7. 删除字典数据
    let v = ctx
        .delete_json(&format!("/system/dict/data/{}", dict_code))
        .await;
    ctx.assert_ok(&v);
    let v = ctx
        .get_json("/system/dict/data/type/it_test_dict_data")
        .await;
    let data = v["data"].as_array().expect("data 应为数组");
    assert!(data.is_empty(), "删除后不应再查到该字典数据，实际: {v}");

    // 8. 清理字典类型
    let v = ctx
        .get_json("/system/dict/type/list?dictType=it_test_dict_data")
        .await;
    let dict_type_id = v["rows"][0]["dictId"]
        .as_i64()
        .expect("应查到测试字典类型 dictId");
    let v = ctx
        .delete_json(&format!("/system/dict/type/{}", dict_type_id))
        .await;
    ctx.assert_ok(&v);
}
