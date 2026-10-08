// stepby-axum/src/integration_tests/sys_config_dict.rs
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

    // 运行时唯一后缀：并行/残留场景下固定键 it_test_dict 会让
    // 「应查到 1 条」断言偶发翻车（上一轮失败残留未清理时 rows=2）。
    // 唯一键 + 末尾按 dictId 精确删除，保证幂等可重跑。
    let unique = format!(
        "it_test_dict_{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("系统时间应晚于 UNIX_EPOCH")
            .as_millis()
    );

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
                "dictType": unique.clone(),
                "status": "0",
                "remark": "集成测试"
            }),
        )
        .await;
    ctx.assert_ok(&v);

    // 5. 按 dictType 过滤查询到新字典类型
    let v = ctx
        .get_json(&format!("/system/dict/type/list?dictType={}", unique))
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
                "dictType": unique.clone(),
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
        .get_json(&format!("/system/dict/type/list?dictType={}", unique))
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

/// E-04 参数治理 UI 后端守卫（批次十九收尾立项）：
/// ① 平台改治理三列生效（列表 VO 回读）；
/// ② 平台改 scope 而未传标志位 → 按新 scope 推导（治理一致性语义）；
/// ③ Locked 键改 scope → resolve_governance fail-closed 强制回 platform_only/'0'/'0'；
/// ④ governance-locked 清单端点（平台 200 + 含已知锁定键；租户 403）。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_config_governance_ui_guard() {
    let ctx = TestContext::new().await;

    // ① 平台新增参数并指定治理属性（platform_default = 下发租户可覆盖可见）
    let v = ctx
        .post_json(
            "/system/config",
            serde_json::json!({
                "configName": "it_gov_参数",
                "configKey": "it.gov.key",
                "configValue": "v1",
                "configType": "N",
                "scope": "platform_default",
                "tenantEditable": "1",
                "visibleToTenant": "1"
            }),
        )
        .await;
    ctx.assert_ok(&v);
    let list = ctx
        .get_json("/system/config/list?pageNum=1&pageSize=50&configKey=it.gov.key")
        .await;
    let row = list["rows"]
        .as_array()
        .expect("rows 应为数组")
        .iter()
        .find(|r| r["configKey"].as_str() == Some("it.gov.key"))
        .expect("应能找到 it.gov.key 行");
    assert_eq!(
        row["scope"].as_str(),
        Some("platform_default"),
        "平台指定 scope 应落库，实际: {row}"
    );
    assert_eq!(
        row["tenantEditable"].as_str(),
        Some("1"),
        "tenantEditable 应落库，实际: {row}"
    );
    assert_eq!(
        row["visibleToTenant"].as_str(),
        Some("1"),
        "visibleToTenant 应落库，实际: {row}"
    );
    let config_id = row["configId"].as_i64().expect("configId 应为数字");

    // ② 平台改治理属性（platform_default → platform_only）：Locked 语义外的键应生效
    let v = ctx
        .put_json(
            "/system/config",
            serde_json::json!({
                "configId": config_id,
                "configName": "it_gov_参数",
                "configKey": "it.gov.key",
                "configValue": "v1",
                "configType": "N",
                "scope": "platform_only"
            }),
        )
        .await;
    ctx.assert_ok(&v);
    let v = ctx
        .get_json("/system/config/list?pageNum=1&pageSize=50&configKey=it.gov.key")
        .await;
    let row = v["rows"]
        .as_array()
        .expect("rows")
        .iter()
        .find(|r| r["configKey"].as_str() == Some("it.gov.key"))
        .expect("行应存在");
    // 显式改 scope 未传标志位 → 按新 scope 推导（platform_only → '0'/'0'）
    assert_eq!(
        row["scope"].as_str(),
        Some("platform_only"),
        "scope 应更新，实际: {row}"
    );
    assert_eq!(
        row["tenantEditable"].as_str(),
        Some("0"),
        "标志位应随 scope 推导，实际: {row}"
    );
    assert_eq!(
        row["visibleToTenant"].as_str(),
        Some("0"),
        "标志位应随 scope 推导，实际: {row}"
    );

    // ③ Locked 键改 scope → resolve_governance fail-closed 强制回 platform_only/'0'/'0'
    //    （取注册表已知锁定键 ip_location.update_source）
    let locked_list = ctx
        .get_json("/system/config/list?pageNum=1&pageSize=100&configKey=ip_location.update_source")
        .await;
    let locked_row = locked_list["rows"]
        .as_array()
        .expect("rows")
        .iter()
        .find(|r| r["configKey"].as_str() == Some("ip_location.update_source"))
        .expect("迁移种子应含 ip_location.update_source");
    let locked_id = locked_row["configId"].as_i64().expect("configId");
    let v = ctx
        .put_json(
            "/system/config",
            serde_json::json!({
                "configId": locked_id,
                "configName": locked_row["configName"],
                "configKey": "ip_location.update_source",
                "configValue": locked_row["configValue"],
                "configType": "Y",
                "scope": "platform_default",
                "tenantEditable": "1",
                "visibleToTenant": "1"
            }),
        )
        .await;
    // Locked 键：resolve_governance 强制 platform_only/'0'/'0'（保存成功但治理属性不被下放）
    ctx.assert_ok(&v);
    let v = ctx.get_json(&format!("/system/config/{locked_id}")).await;
    assert_eq!(
        v["data"]["scope"].as_str(),
        Some("platform_only"),
        "Locked 键 scope 应强制 platform_only，实际: {v}"
    );
    assert_eq!(
        v["data"]["tenantEditable"].as_str(),
        Some("0"),
        "Locked 键 editable 强制 0，实际: {v}"
    );

    // ④ governance-locked 清单端点：平台 200 + 含锁定键；clean up
    let v = ctx.get_json("/system/config/governance-locked").await;
    let keys = v["data"].as_array().expect("data 应为数组");
    assert!(
        keys.iter()
            .any(|k| k.as_str() == Some("ip_location.update_source")),
        "锁定清单应含 ip_location.update_source，实际: {v}"
    );
    let _ = ctx
        .delete_json(&format!("/system/config/{config_id}"))
        .await;
}
