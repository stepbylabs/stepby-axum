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
    //    批八十六 N-1：`sys.index.skinName`（旧断言目标）已随死键退役被清除，
    //    改读**真旋钮** `sys.index.sideTheme`——它同时是注册表里第一个 `Coverage::Free`
    //    参数项，值必须是 `governance::SIDE_THEME_DOMAIN` 首项（缺省 = 改造前现状）。
    let v = ctx
        .get_json("/system/config/configKey/sys.index.sideTheme")
        .await;
    assert_eq!(
        v["data"].as_str(),
        Some("theme-auto"),
        "sys.index.sideTheme 缺省值应为 theme-auto（= 改造前前端实际生效值），实际: {v}"
    );

    // 3. 详情（按**回读到的 configId** 查，而不是硬编码 1）
    //    原先硬编码 `/system/config/1`——那一行正是本批退役删除的 `sys.index.skinName`，
    //    于是"详情查不到"会被读成详情接口回归。取号必须由自己从列表读，
    //    判据才不绑在某个种子行的主键上（主键随批次漂移是常态）。
    let list = ctx
        .get_json("/system/config/list?pageNum=1&pageSize=10&configKey=sys.account.captchaEnabled")
        .await;
    let detail_id = list["rows"][0]["configId"]
        .as_i64()
        .expect("应查到 captchaEnabled 的 configId");
    let v = ctx.get_json(&format!("/system/config/{detail_id}")).await;
    assert_eq!(
        v["data"]["configId"], detail_id,
        "参数详情 configId 应回显同一行，实际: {v}"
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

/// 批八十六 项 N-1 + N-2：死键退役与值域闸门（**五个判据，缺一即假绿**）。
///
/// 为什么不能只测"读不到"：`§5.23` 的教训正是"注册表那一半做了、数据那一半没做"，
/// 于是参数页留着三行可见可编辑而零消费者。因此本用例判的是**可见面 + 写入面**同时消失，
/// 而写入面又必须配一条"合法键照常可写"的对照组——否则实现可以是"这个端点永远 400"，
/// 那同样能让前三支判据全绿（同 AGENTS 前端归一规范 §3.③ 的三侧判据）。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_config_retired_keys_and_value_domain() {
    let ctx = TestContext::new().await;

    // 负路径一律走 `send_raw`：`get_json/post_json/put_json` 都经 `send_json`，
    // 而它内置"业务码必须 200"的断言（mod.rs:750）——用它测 400/404 会先 panic 在
    // 判据之外，报出来的是 harness 而不是本用例的结论。
    use axum::http::Method;

    // ---- ① 退役键在参数页与取值面都消失（404 = 能力不存在，与 403 = 被治理拒绝 不同语义）----
    for key in governance::RETIRED_CONFIG_KEYS {
        let (_status, v) = ctx
            .send_raw(ctx.request(
                Method::GET,
                &format!("/system/config/configKey/{key}"),
                None,
            ))
            .await;
        assert_eq!(v["code"], 404, "退役键 {key} 读取应 404，实际: {v}");
        let list = ctx
            .get_json(&format!(
                "/system/config/list?pageNum=1&pageSize=20&configKey={key}"
            ))
            .await;
        let rows = list["rows"].as_array().expect("rows 应为数组");
        assert!(
            rows.is_empty(),
            "退役键 {key} 不应再出现在参数页列表，实际: {list}"
        );
    }

    // ---- ② 新建退役键被拒（400，且不得落库）----
    for key in governance::RETIRED_CONFIG_KEYS {
        let (_status, v) = ctx
            .send_raw(ctx.request(
                Method::POST,
                "/system/config",
                Some(serde_json::json!({
                    "configName": "试图复活退役键",
                    "configKey": key,
                    "configValue": "whatever",
                    "configType": "N"
                })),
            ))
            .await;
        assert_eq!(v["code"], 400, "新建退役键 {key} 必须 400，实际: {v}");
        assert!(
            !v["msg"]
                .as_str()
                .unwrap_or_default()
                .contains("error.config."),
            "必须给出可读文案而不是原始键名，实际: {v}"
        );
        let list = ctx
            .get_json(&format!(
                "/system/config/list?pageNum=1&pageSize=20&configKey={key}"
            ))
            .await;
        assert_eq!(
            list["rows"].as_array().expect("rows").len(),
            0,
            "被拒的新建不得留下任何行，实际: {list}"
        );
    }

    // ---- ③ 在册键改名到退役键同样被拒，且改名失败不能动到原行 ----
    let probe_key = "it.retire.rename_probe";
    let add = ctx
        .post_json(
            "/system/config",
            serde_json::json!({
                "configName": "改名探针",
                "configKey": probe_key,
                "configValue": "probe-value",
                "configType": "N"
            }),
        )
        .await;
    ctx.assert_ok(&add);
    let list = ctx
        .get_json(&format!("/system/config/list?configKey={probe_key}"))
        .await;
    let probe_id = list["rows"][0]["configId"]
        .as_i64()
        .expect("应查到改名探针 configId");
    let retired = governance::RETIRED_CONFIG_KEYS[0];
    let (_status, v) = ctx
        .send_raw(ctx.request(
            Method::PUT,
            "/system/config",
            Some(serde_json::json!({
                "configId": probe_id,
                "configName": "改名探针",
                "configKey": retired,
                "configValue": "probe-value"
            })),
        ))
        .await;
    assert_eq!(v["code"], 400, "改名到退役键必须 400，实际: {v}");
    let v = ctx
        .get_json(&format!("/system/config/configKey/{probe_key}"))
        .await;
    assert_eq!(
        v["data"].as_str(),
        Some("probe-value"),
        "被拒的改名不应改动原行，实际: {v}"
    );

    // ---- ④ 真旋钮：合法值可写并回读生效；非法值 400 且原文案带出允许清单 ----
    let side = ctx
        .get_json("/system/config/list?configKey=sys.index.sideTheme")
        .await;
    let side_row = &side["rows"][0];
    let side_id = side_row["configId"]
        .as_i64()
        .expect("sideTheme 平台行应存在（注册表在册键）");
    assert_eq!(
        side_row["scope"].as_str(),
        Some("platform_default"),
        "Free 参数项的平台层治理姿态必须由注册表收敛为 platform_default，实际: {side_row}"
    );
    assert_eq!(
        side_row["tenantEditable"].as_str(),
        Some("1"),
        "Free 参数项租户必须可覆盖，实际: {side_row}"
    );
    // 非法值：先判"必须拒"，再判"拒之后值没变"
    for bad in ["skin-blue", "theme-auto ", "Theme-auto", ""] {
        let (_status, v) = ctx
            .send_raw(ctx.request(
                Method::PUT,
                "/system/config",
                Some(serde_json::json!({
                    "configId": side_id,
                    "configKey": "sys.index.sideTheme",
                    "configValue": bad
                })),
            ))
            .await;
        assert_eq!(v["code"], 400, "值域外的 {bad:?} 必须 400，实际: {v}");
        let read = ctx
            .get_json("/system/config/configKey/sys.index.sideTheme")
            .await;
        assert_eq!(
            read["data"].as_str(),
            Some("theme-auto"),
            "被拒的写入不得改动生效值，实际: {read}"
        );
    }
    let (_status, msg) = ctx
        .send_raw(ctx.request(
            Method::PUT,
            "/system/config",
            Some(serde_json::json!({
                "configId": side_id,
                "configKey": "sys.index.sideTheme",
                "configValue": "skin-blue"
            })),
        ))
        .await;
    let msg_text = msg["msg"].as_str().unwrap_or_default().to_string();
    for want in governance::SIDE_THEME_DOMAIN {
        assert!(
            msg_text.contains(want),
            "拒绝文案必须把允许清单逐条列全（否则运维只能猜），实际: {msg_text}"
        );
    }
    // 合法值：改 → 回读 → 复原（不留测试痕迹）
    let v = ctx
        .put_json(
            "/system/config",
            serde_json::json!({
                "configId": side_id,
                "configKey": "sys.index.sideTheme",
                "configValue": "theme-dark"
            }),
        )
        .await;
    ctx.assert_ok(&v);
    let v = ctx
        .get_json("/system/config/configKey/sys.index.sideTheme")
        .await;
    assert_eq!(
        v["data"].as_str(),
        Some("theme-dark"),
        "合法值必须真实生效，实际: {v}"
    );
    let v = ctx
        .put_json(
            "/system/config",
            serde_json::json!({
                "configId": side_id,
                "configKey": "sys.index.sideTheme",
                "configValue": "theme-auto"
            }),
        )
        .await;
    ctx.assert_ok(&v);

    // ---- ⑤ 对照组：未登记键（租户自建参数）不受值域闸影响，照常可写 ----
    let v = ctx
        .put_json(
            "/system/config",
            serde_json::json!({
                "configId": probe_id,
                "configKey": probe_key,
                "configValue": "any-tenant-value"
            }),
        )
        .await;
    ctx.assert_ok(&v);
    let v = ctx
        .get_json(&format!("/system/config/configKey/{probe_key}"))
        .await;
    assert_eq!(
        v["data"].as_str(),
        Some("any-tenant-value"),
        "对照组必须照常出网并写入（否则实现可以是\"一律拒绝\"），实际: {v}"
    );

    // ---- 清理：探针行删除，退役键面保持零行 ----
    let v = ctx.delete_json(&format!("/system/config/{probe_id}")).await;
    ctx.assert_ok(&v);
    let (_status, v) = ctx
        .send_raw(ctx.request(
            Method::GET,
            &format!("/system/config/configKey/{probe_key}"),
            None,
        ))
        .await;
    assert_eq!(v["code"], 404, "探针清理后应 404，实际: {v}");
}

/// b130：字典类型的批量删除同样按「去重保序」判缺失（`models.len()` 命名的那一族）。
///
/// 与 `sys_msg::test_msg_channel_batch_delete_dedupes_repeated_ids` 是**两个不同的接入面**：
/// 那条覆盖 `existing.len()` 命名，这条覆盖 `models.len()` 命名，且各自验证
/// "去重后真的按去重结果删"（形状锁只能判"去重调用在长度比较之前"，判不了下游用哪个变量）。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_dict_type_batch_delete_dedupes_repeated_ids() {
    use axum::http::{Method, StatusCode};

    let ctx = TestContext::new().await;
    let unique = format!(
        "it_bdel_dict_{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("系统时间应晚于 UNIX_EPOCH")
            .as_millis()
    );

    // 建两条类型；id 一律回查（该端点的新增响应不带 dictId）
    let mut ids = Vec::new();
    for suffix in ["a", "b"] {
        let dict_type = format!("{unique}_{suffix}");
        let v = ctx
            .post_json(
                "/system/dict/type",
                serde_json::json!({
                    "dictName": format!("批量删除用例{suffix}"),
                    "dictType": dict_type,
                    "status": "0",
                    "remark": "b130"
                }),
            )
            .await;
        ctx.assert_ok(&v);
        let v = ctx
            .get_json(&format!("/system/dict/type/list?dictType={dict_type}"))
            .await;
        let row = v["rows"]
            .as_array()
            .and_then(|a| a.first())
            .cloned()
            .unwrap_or_else(|| panic!("应查到字典类型 {dict_type}，实际：{v}"));
        ids.push((dict_type, row["dictId"].as_i64().expect("dictId 应为数字")));
    }

    // ① 重复 id ⇒ 200 且行真的被删（曾因原始长度当分母被判成"不存在"）
    let (type_a, id_a) = ids[0].clone();
    let v = ctx
        .delete_json(&format!("/system/dict/type/{id_a},{id_a}"))
        .await;
    ctx.assert_ok(&v);
    assert_eq!(
        dict_type_rows(&ctx, &type_a).await,
        0,
        "重复 id 的批量删除必须真的删掉 {type_a}"
    );

    // ② 真缺失混入 ⇒ 404 且零删除
    let (type_b, id_b) = ids[1].clone();
    let (status, body) = ctx
        .send_raw(ctx.request(
            Method::DELETE,
            &format!("/system/dict/type/{id_b},999999999"),
            None,
        ))
        .await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "批内有真缺失时必须 404，实际 {status}：{body}"
    );
    assert_eq!(
        dict_type_rows(&ctx, &type_b).await,
        1,
        "批内混入缺失 id 时一条都不许删：{body}"
    );

    // ③ 收尾：单 id 删除照常生效（同一入口的对照组）
    let v = ctx.delete_json(&format!("/system/dict/type/{id_b}")).await;
    ctx.assert_ok(&v);
    assert_eq!(
        dict_type_rows(&ctx, &type_b).await,
        0,
        "对照组：单 id 删除必须真的删掉"
    );
}

/// 按 `dictType` 回查行数（b130 批量删除用例：判"到底删没删"）。
async fn dict_type_rows(ctx: &TestContext, dict_type: &str) -> usize {
    let v = ctx
        .get_json(&format!("/system/dict/type/list?dictType={dict_type}"))
        .await;
    v["rows"].as_array().map(|a| a.len()).unwrap_or(0)
}
