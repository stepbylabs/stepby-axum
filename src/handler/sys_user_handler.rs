// stepby-axum/src/handler/sys_user_handler.rs
//! 用户模块 Handler（Axum 原生实现）
//!
//! 接口路径与返回格式对齐 stepby-vue 前端调用规范：
//! - GET    /system/user/list                       分页查询用户
//! - POST   /system/user                            新增用户
//! - PUT    /system/user                            修改用户
//! - DELETE /system/user/{id}                       删除用户
//! - GET    /system/user/{id}                       查询用户详情
//! - PUT    /system/user/changeStatus               启停用户
//! - PUT    /system/user/resetPwd                   重置密码
//! - PUT    /system/user/profile/updatePwd          个人改密
//! - GET    /system/user/profile                    个人信息
//! - PUT    /system/user/profile                    修改个人信息
//! - POST   /system/user/profile/avatar             头像上传（multipart，imgUrl 在顶层）
//! - GET    /system/user/                           获取角色和部门（角色下拉用）
//! - PUT    /system/user/authRole                   分配用户角色
//! - GET    /system/user/authRole/{userId}          查询授权角色（user/roles 在顶层）
//! - GET    /system/user/deptTree                   部门下拉树

use axum::Json;
use axum::extract::{Form, Multipart, Path, Query, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::Response;
use garde::Validate;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use utoipa::{IntoParams, ToSchema};

use crate::common::ValidatedJson;

use crate::common::constants::MAX_BATCH_DELETE_SIZE;
use crate::common::excel::{
    CellValue, ExcelColumn, ImportColumn, build_import_template_bytes, export_to_excel,
};
use crate::common::{AjaxResult, AppError, TableDataInfo, TreeSelectVo};
use crate::entity::sys_post::Model as SysPostModel;
use crate::entity::sys_role::Model as SysRoleModel;
use crate::entity::sys_user::Model as SysUserModel;
use crate::middleware::{Operator, TargetTenant};
use crate::service::sys_user_service::{
    ImportResultVo, ProfileUpdateDto, UserAddDto, UserAuthRoleVo, UserEditDto, UserPwdResetDto,
    UserPwdUpdateDto, UserQueryDto, UserVo,
};
use crate::service::user_erasure_service::UserErasureReport;
use crate::state::AppState;
use crate::utils::parse_id_list;

/// 导入文件大小上限（5 MB，足够承载数百行用户数据）
const MAX_IMPORT_SIZE: usize = 5 * 1024 * 1024;

// ==================== 辅助 DTO ====================

/// 启停用户请求体
#[derive(Debug, Deserialize, Validate, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ChangeStatusDto {
    #[garde(skip)]
    pub user_id: i64,
    #[garde(length(min = 1, max = 1))]
    pub status: String,
}

/// 分配用户角色请求体（对齐前端 PUT /system/user/authRole?userId=&roleIds=）
/// 本接口字段走 Query，这里同样走 Query 以保持兼容
#[derive(Debug, Deserialize, Validate, IntoParams)]
#[serde(rename_all = "camelCase")]
pub struct AssignAuthRoleDto {
    #[garde(range(min = 1))]
    pub user_id: i64,
    /// 逗号分隔的角色 ID 字符串（对齐前端 params.roleIds）
    #[garde(skip)]
    pub role_ids: String,
}

/// 个人改密请求体
#[derive(Debug, Deserialize, Validate, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ProfilePwdDto {
    #[garde(length(min = 5, max = 20))]
    pub old_password: String,
    #[garde(length(min = 5, max = 20))]
    pub new_password: String,
}

// ==================== Handler 实现 ====================

/// GET /system/user/list
/// 分页查询用户
#[utoipa::path(
    get,
    path = "/system/user/list",
    params(UserQueryDto),
    responses(
        (status = 200, description = "分页用户列表", body = TableDataInfo<UserVo>),
        (status = 500, description = "服务器错误"),
    ),
    tag = "system-user"
)]
pub async fn list(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    Query(query): Query<UserQueryDto>,
) -> Result<TableDataInfo<UserVo>, AppError> {
    // 数据权限（P0-R81-004）：传入 operator_user_id 进行 data_scope 过滤
    // P1 修复: fail-closed — JWT sub 解析失败时拒绝访问，防止绕过数据权限过滤
    let operator_user_id: i64 = operator.user_id().parse::<i64>().map_err(|_| {
        tracing::warn!(sub = %operator.user_id(), "用户列表: JWT sub 解析失败，拒绝访问");
        AppError::unauthorized(&crate::tr!("error.common.session_invalid"))
    })?;
    let (rows, total) = state
        .user_service
        .get_user_page(
            query,
            Some(operator_user_id),
            crate::common::tenant::tenant_scope(operator.tenant_id()),
        )
        .await?;
    Ok(TableDataInfo::new(total, rows))
}

/// POST /system/user/export
/// 导出用户列表为 Excel
///
/// 前端 download() 发送 application/x-www-form-urlencoded，使用 Form 提取器
/// P0-1 修复：增加 Operator 参数，应用数据权限过滤，防止越权导出
#[utoipa::path(
    post,
    path = "/system/user/export",
    params(UserQueryDto),
    responses(
        (status = 200, description = "用户列表 xlsx", content_type = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"),
        (status = 500, description = "服务器错误"),
    ),
    tag = "system-user"
)]
pub async fn export(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    Form(query): Form<UserQueryDto>,
) -> Result<Response, AppError> {
    // P1 修复: fail-closed — JWT sub 解析失败时拒绝访问
    let operator_user_id: i64 = operator.user_id().parse::<i64>().map_err(|_| {
        tracing::warn!(sub = %operator.user_id(), "用户导出: JWT sub 解析失败，拒绝访问");
        AppError::unauthorized(&crate::tr!("error.common.session_invalid"))
    })?;
    let rows = state
        .user_service
        .export_users(
            query,
            Some(operator_user_id),
            crate::common::tenant::tenant_scope(operator.tenant_id()),
        )
        .await?;

    let columns = [
        ExcelColumn {
            key: "userId",
            header: ("用户编号", "User ID"),
            getter: |r: &UserVo| CellValue::Number(r.user.user_id as f64),
        },
        ExcelColumn {
            key: "loginName",
            header: ("登录名称", "Login Name"),
            getter: |r: &UserVo| CellValue::Text(r.user.user_name.clone().into()),
        },
        ExcelColumn {
            key: "nickName",
            header: ("用户姓名", "Nickname"),
            getter: |r: &UserVo| CellValue::Text(r.user.nick_name.clone().into()),
        },
        ExcelColumn {
            key: "dept.deptName",
            header: ("部门", "Department"),
            getter: |r: &UserVo| {
                CellValue::Text(
                    r.dept
                        .as_ref()
                        .map(|d| d.dept_name.clone())
                        .unwrap_or_default()
                        .into(),
                )
            },
        },
        ExcelColumn {
            key: "phonenumber",
            header: ("手机号码", "Phone"),
            getter: |r: &UserVo| {
                CellValue::Text(r.user.phonenumber.clone().unwrap_or_default().into())
            },
        },
        ExcelColumn {
            key: "email",
            header: ("邮箱", "Email"),
            getter: |r: &UserVo| CellValue::Text(r.user.email.clone().unwrap_or_default().into()),
        },
        ExcelColumn {
            key: "status",
            header: ("状态", "Status"),
            getter: |r: &UserVo| {
                CellValue::Text(
                    if r.user.status.as_deref() == Some("0") {
                        crate::tr!("common.status.normal")
                    } else {
                        crate::tr!("common.status.disabled")
                    }
                    .into(),
                )
            },
        },
        ExcelColumn {
            key: "createTime",
            header: ("创建时间", "Create Time"),
            getter: |r: &UserVo| CellValue::from_opt_datetime(r.user.create_time),
        },
    ];

    export_to_excel(&crate::tr!("excel.sheet.user"), "user", &columns, &rows).await
}

/// 导入查询参数（对齐前端 ElUpload ?updateSupport=0|1）
#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ImportQuery {
    /// 1=已存在用户则更新资料；0=已存在则报错跳过
    #[serde(default)]
    pub update_support: u8,
}

/// POST /system/user/importTemplate
/// 下载用户导入模板 xlsx（表头 + 示例行）
///
/// 模板列：登录名称* / 用户姓名* / 部门名称 / 手机号码 / 邮箱 / 性别 / 状态
#[utoipa::path(
    post,
    path = "/system/user/importTemplate",
    responses(
        (status = 200, description = "导入模板 xlsx", content_type = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"),
        (status = 500, description = "服务器错误"),
    ),
    tag = "system-user"
)]
pub async fn import_template(State(state): State<Arc<AppState>>) -> Result<Response, AppError> {
    let locale_zh = crate::common::i18n::is_zh();
    let columns = [
        ImportColumn {
            header: ("登录名称", "Login Name"),
            sample: "zhangsan",
            width: 18.0,
        },
        ImportColumn {
            header: ("用户姓名", "Nickname"),
            sample: "张三",
            width: 14.0,
        },
        ImportColumn {
            header: ("部门名称", "Department"),
            sample: "研发部",
            width: 16.0,
        },
        ImportColumn {
            header: ("手机号码", "Phone"),
            sample: "13800138000",
            width: 18.0,
        },
        ImportColumn {
            header: ("邮箱", "Email"),
            sample: "zhangsan@example.com",
            width: 26.0,
        },
        ImportColumn {
            header: ("性别", "Gender"),
            sample: "男",
            width: 10.0,
        },
        ImportColumn {
            header: ("状态", "Status"),
            sample: "正常",
            width: 10.0,
        },
    ];
    let bytes =
        build_import_template_bytes(&crate::tr!("excel.sheet.user_import"), &columns, locale_zh)?;
    let _ = state;
    let mut response = Response::new(bytes.into());
    *response.status_mut() = StatusCode::OK;
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static(
            "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        ),
    );
    response.headers_mut().insert(
        header::CONTENT_DISPOSITION,
        HeaderValue::from_static("attachment; filename=user_import_template.xlsx"),
    );
    Ok(response)
}

/// POST /system/user/importData
/// 上传 xlsx 批量导入用户（multipart 字段名 file）
///
/// 逐行校验，失败行不中断整批；返回成功数 + 错误行回显。
#[utoipa::path(
    post,
    path = "/system/user/importData",
    responses(
        (status = 200, description = "导入结果（成功数 + 错误回显）", body = AjaxResult<ImportResultVo>),
        (status = 400, description = "文件缺失/格式错误"),
        (status = 500, description = "服务器错误"),
    ),
    tag = "system-user"
)]
pub async fn import_data(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    Query(query): Query<ImportQuery>,
    mut multipart: Multipart,
) -> Result<AjaxResult<ImportResultVo>, AppError> {
    // 从 multipart 提取 file 字段并限定长度读取
    let mut file_bytes: Option<Vec<u8>> = None;
    let mut file_name: Option<String> = None;
    while let Some(mut field) = multipart.next_field().await.map_err(|e| {
        AppError::bad_request(&crate::tr!("error.file.multipart_parse_failed", e = e))
    })? {
        if field.name() == Some("file") {
            let (bytes, _, original) =
                crate::common::upload::read_field_limited(&mut field, MAX_IMPORT_SIZE).await?;
            file_name = original;
            file_bytes = Some(bytes);
        }
    }
    let bytes = file_bytes.ok_or_else(|| {
        AppError::bad_request(&crate::tr!("error.common_handler.field_not_found_file"))
    })?;
    // 仅允许 xlsx（前端 accept 已限制，后端二次校验）
    if let Some(name) = file_name.as_deref()
        && !name.to_lowercase().ends_with(".xlsx")
    {
        return Err(AppError::bad_request(&crate::tr!("excel.tip_import_xlsx")));
    }

    // 默认初始密码（读系统配置，读取失败回退与迁移种子一致）
    // 多租户 Phase 3：显式传入操作者租户，租户级覆盖优先于平台默认层
    let default_password = state
        .config_service
        .get_config_value_by_key_cached("sys.user.initPassword", Some(operator.tenant_id()))
        .await
        .ok()
        .flatten()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| "123456".to_string());

    let result = state
        .user_service
        .import_users(
            bytes,
            query.update_support == 1,
            operator.username(),
            operator.tenant_id(),
            &default_password,
        )
        .await?;

    let msg = crate::tr!("msg.success.user_import", n = result.success);
    Ok(AjaxResult {
        code: 200,
        msg,
        data: Some(result),
    })
}

/// GET /system/user/{id}
/// 查询用户详情（对齐前端 UserFormDataResult，data/roleIds/postIds/roles/posts 在顶层）
///
/// 返回结构：`{ code, msg, data, roleIds, postIds, roles, posts }`
/// - data: 用户信息
/// - roleIds: 用户已绑定的角色 ID 列表
/// - postIds: 用户已绑定的岗位 ID 列表
/// - roles: 全部可用角色列表（下拉选择用）
/// - posts: 全部可用岗位列表（下拉选择用）
#[utoipa::path(
    get,
    path = "/system/user/{id}",
    params(
        ("id" = i64, Path, description = "用户 ID")
    ),
    responses(
        (status = 200, description = "用户详情（含角色和岗位列表）", body = UserFormResult),
        (status = 404, description = "用户不存在"),
    ),
    tag = "system-user"
)]
pub async fn get_info_by_id(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    Path(user_id): Path<i64>,
) -> Result<UserFormResult, AppError> {
    // P0-6：传入 operator_user_id 校验目标用户在数据范围内（此前可越权读取他人 PII）
    let operator_user_id: Option<i64> = operator.user_id().parse().ok();
    let vo = state
        .user_service
        .get_user_form_data(
            Some(user_id),
            operator_user_id,
            crate::common::tenant::tenant_scope(operator.tenant_id()),
        )
        .await?;
    Ok(UserFormResult {
        code: 200,
        msg: crate::tr!("msg.success.default"),
        data: vo.data,
        role_ids: vo.role_ids,
        post_ids: vo.post_ids,
        roles: vo.roles,
        posts: vo.posts,
    })
}

/// POST /system/user
/// 新增用户
#[utoipa::path(
    post,
    path = "/system/user",
    request_body = UserAddDto,
    responses(
        (status = 200, description = "新增成功", body = AjaxResult<serde_json::Value>),
        (status = 400, description = "参数错误或用户名重复"),
    ),
    tag = "system-user"
)]
pub async fn add(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    Json(dto): Json<UserAddDto>,
) -> Result<AjaxResult<serde_json::Value>, AppError> {
    let user = state
        .user_service
        .add_user(dto, operator.username(), operator.tenant_id())
        .await?;
    // 对齐前端：新增返回提示消息
    Ok(AjaxResult::success_msg(&crate::tr!(
        "msg.success.add_user",
        name = user.user_name
    )))
}

/// PUT /system/user
/// 修改用户
#[utoipa::path(
    put,
    path = "/system/user",
    request_body = UserEditDto,
    responses(
        (status = 200, description = "修改成功", body = AjaxResult<serde_json::Value>),
        (status = 400, description = "参数错误"),
        (status = 404, description = "用户不存在"),
    ),
    tag = "system-user"
)]
pub async fn edit(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    target_tenant: TargetTenant,
    Json(dto): Json<UserEditDto>,
) -> Result<AjaxResult<serde_json::Value>, AppError> {
    let operator_user_id: i64 = operator
        .user_id()
        .parse()
        .map_err(|_| AppError::internal(&crate::tr!("error.user.operator_id_parse_failed")))?;
    // 多租户 Phase 3：记录被操作用户所属租户，供审计 target_tenant_id（平台代管场景）
    if let Ok(vo) = state.user_service.get_user_by_id(dto.user_id).await {
        target_tenant.set(vo.user.tenant_id);
    }
    state
        .user_service
        .edit_user(
            dto,
            operator.username(),
            operator_user_id,
            operator.tenant_id(),
        )
        .await?;
    Ok(AjaxResult::success_msg(&crate::tr!("msg.success.edit")))
}

/// DELETE /system/user/{ids}
/// 删除用户（支持批量逗号分隔，R8-API-002）
///
/// 路径参数 ids 接受单个 ID 或逗号分隔的多个 ID（如 `1` 或 `1,2,3`）。
/// 批量删除在 service 层包装在单个事务中，保证原子性（部分失败回滚）。
#[utoipa::path(
    delete,
    path = "/system/user/{ids}",
    params(
        ("ids" = String, Path, description = "用户 ID 列表（逗号分隔）")
    ),
    responses(
        (status = 200, description = "删除成功", body = AjaxResult<serde_json::Value>),
        (status = 400, description = "不允许删除超级管理员或 ID 不合法"),
        (status = 404, description = "用户不存在"),
    ),
    tag = "system-user"
)]
pub async fn remove(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    target_tenant: TargetTenant,
    Path(ids): Path<String>,
) -> Result<AjaxResult<serde_json::Value>, AppError> {
    let operator_user_id: i64 = operator
        .user_id()
        .parse()
        .map_err(|_| AppError::internal(&crate::tr!("error.user.operator_id_parse_failed")))?;

    // R8-API-002：解析逗号分隔的 ID 列表
    let user_ids: Vec<i64> = parse_id_list::<i64>(&ids);
    if user_ids.is_empty() {
        return Err(AppError::bad_request(&crate::tr!("error.user.id_empty")));
    }
    // R8-API-005：批量上限校验
    if user_ids.len() > MAX_BATCH_DELETE_SIZE {
        return Err(AppError::bad_request(&crate::tr!(
            "error.common.batch_size_exceeded",
            max = MAX_BATCH_DELETE_SIZE
        )));
    }

    // 单个 ID 走原路径（保持现有垂直越权校验语义）
    // 批量 ID 调用新增的 delete_users 事务方法（原子性保证）
    // 多租户 Phase 3：解析被删用户所属租户，全部可解析且唯一时记录审计 target_tenant_id
    // （跨多个租户或存在解析失败时保持 NULL，避免误标归属）
    {
        let mut resolved: Vec<i64> = Vec::new();
        let mut all_resolved = true;
        for uid in &user_ids {
            match state.user_service.get_user_by_id(*uid).await {
                Ok(vo) => {
                    if !resolved.contains(&vo.user.tenant_id) {
                        resolved.push(vo.user.tenant_id);
                    }
                }
                Err(_) => all_resolved = false,
            }
        }
        if all_resolved && resolved.len() == 1 {
            target_tenant.set(resolved[0]);
        }
    }

    let deleted_user_ids = user_ids.clone();
    state
        .user_service
        .delete_users(user_ids, operator_user_id, operator.tenant_id())
        .await?;

    // P0-5 修复：用户删除后失效其活动会话
    // P0-R81-007 版本号机制：递增 pwd_ver，使被删除用户已签发的 JWT 在 auth 中间件被拒绝
    // （auth.rs 检查存储当前版本 > claim.pwd_ver 则返回 401）。
    // 版本号单调递增，无需 TTL；fail-closed：写入失败返回错误，避免旧 token 继续可用。
    // 原 Redis pipeline 批量 INCR → 逐用户 `store.pwd_ver_incr`（内部含 Redis INCR +
    // DB password_version 列双写，均已封装进实现）
    if !deleted_user_ids.is_empty() {
        for uid in &deleted_user_ids {
            if let Err(e) = state.store.pwd_ver_incr(&uid.to_string()).await {
                tracing::error!(
                    user_ids = ?deleted_user_ids,
                    error = %e,
                    "删除用户后递增 pwd_ver 标记失败（fail-closed）"
                );
                return Err(AppError::internal(&crate::tr!(
                    "error.user.pwd_reset_token_invalidate_failed"
                )));
            }
        }
        // v4 #18：删除用户同步吊销其全部 SSO 访问令牌（sso:at:* + online:*）——
        // userinfo 只认绑定不校验 pwd_ver，不做联动则旧 AT 在 TTL 内仍可换取身份
        // （原 sso_service::revoke_user_sso_tokens 语义已收敛为 store.revoke_all_for_user）
        for uid in &deleted_user_ids {
            if let Err(e) = state.store.revoke_all_for_user(&uid.to_string()).await {
                tracing::warn!(user_id = *uid, error = %e, "删除用户后吊销 SSO 令牌失败");
            }
        }
    }

    // v5-D12 Group：用户删除联动清理 SCIM 组成员记录与 scim 来源授权/兼职
    // （失败不阻断删除主流程——成员记录悬挂仅影响组详情展示，grant 引擎对
    // 软删用户天然拒绝）
    for uid in &deleted_user_ids {
        if let Err(e) = state.scim_group_service.cleanup_user_membership(*uid).await {
            tracing::warn!("用户删除 SCIM 成员清理失败 user_id={uid}: {}", e.detail);
        }
    }

    // W-4：用户离岗（删除）→ 其 pending 审批待办自动转办（部门主管 → admin 回退）
    // 非阻断：删除已生效，转办失败仅告警（待办保持 pending，可由管理员人工转办）
    for uid in &deleted_user_ids {
        auto_reassign_flow_tasks(&state, *uid).await;
    }

    Ok(AjaxResult::success_msg(&crate::tr!("msg.success.delete")))
}

/// W-4：离岗用户的 pending 审批待办自动转办 + 通知新审批人
///
/// 失败不阻断调用方主流程（用户停用/删除已生效），仅记录告警。
async fn auto_reassign_flow_tasks(state: &AppState, user_id: i64) {
    match state.flow_service.handle_user_disabled(user_id).await {
        Ok(items) => {
            for item in items {
                // WS 定向推送"新待办"（严禁全局广播：待办含他人单据标题）
                state.broadcast_to_user(
                    item.to_user_id,
                    "flowTodo",
                    serde_json::json!({
                        "bizType": crate::service::sys_flow_service::BIZ_TYPE_DEMO,
                        "taskId": item.task_id,
                        "title": item.title,
                        "message": crate::tr!("msg.flow.todo_created"),
                    }),
                );
                state
                    .flow_service
                    .send_flow_audit(item.to_user_id, "flow_todo", &item.title)
                    .await;
            }
        }
        Err(e) => {
            tracing::warn!(
                user_id,
                error = %e.message,
                "离岗自动转办失败（待办保持 pending，需人工转办）"
            );
        }
    }
}

/// GET /system/user/{userId}/anonymize/precheck
///
/// GDPR 被遗忘权 / 用户匿名化**只读预检**（dry-run）：返回将被置换的字段清单 + 受影响
/// 关系计数（PAT / 第三方绑定 / 在线会话），**不产生任何写入**。
///
/// 能力位 `privacy.user_erasure` 需 ≥ `precheck`，且操作者必须为平台管理员（`tenantId == 0`）；
/// 任一不满足以 **404** 隐藏端点存在性（与 `[sso].introspection_enabled` 同口径）。
#[utoipa::path(
    get,
    path = "/system/user/{userId}/anonymize/precheck",
    params(("userId" = i64, Path, description = "用户 ID")),
    responses(
        (status = 200, description = "匿名化预检报告", body = UserErasureReport),
        (status = 404, description = "能力位未开启 / 非平台操作者 / 用户不存在"),
        (status = 400, description = "平台用户或超级管理员不可匿名化"),
    ),
    tag = "system-user"
)]
pub async fn anonymize_precheck(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    Path(user_id): Path<i64>,
) -> Result<AjaxResult<UserErasureReport>, AppError> {
    let report = state
        .user_erasure_service
        .anonymize_precheck(user_id, operator.tenant_id())
        .await?;
    Ok(AjaxResult {
        code: 200,
        msg: crate::tr!("msg.success.default"),
        data: Some(report),
    })
}

/// POST /system/user/{userId}/anonymize
///
/// GDPR 被遗忘权 / 用户匿名化**执行**（**不可逆**）：置换 PII 字段、释放全局唯一登录键、
/// 停用并软删除，并吊销该用户全部会话 / PAT / SSO 令牌；审计留痕保留。
///
/// 能力位 `privacy.user_erasure` 需达 `full`，且操作者必须为平台管理员（`tenantId == 0`）；
/// 任一不满足以 **404** 隐藏端点存在性。幂等：目标已匿名化 ⇒ 直接返回报告。
/// 匿名化动作本身由 `oper_log_middleware` 记录（写操作留痕）。
#[utoipa::path(
    post,
    path = "/system/user/{userId}/anonymize",
    params(("userId" = i64, Path, description = "用户 ID")),
    responses(
        (status = 200, description = "匿名化完成报告", body = UserErasureReport),
        (status = 404, description = "能力位未开启 / 非平台操作者 / 用户不存在"),
        (status = 400, description = "平台用户或超级管理员不可匿名化"),
    ),
    tag = "system-user"
)]
pub async fn anonymize_user(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    target_tenant: TargetTenant,
    Path(user_id): Path<i64>,
) -> Result<AjaxResult<UserErasureReport>, AppError> {
    // 审计 target_tenant_id：记录被匿名化用户的租户归属（平台代管场景）
    if let Ok(vo) = state.user_service.get_user_by_id(user_id).await {
        target_tenant.set(vo.user.tenant_id);
    }
    let report = state
        .user_erasure_service
        .anonymize_user(user_id, operator.username(), operator.tenant_id())
        .await?;
    Ok(AjaxResult {
        code: 200,
        msg: crate::tr!("msg.success.erasure_done"),
        data: Some(report),
    })
}

/// PUT /system/user/changeStatus
/// 启停用户
#[utoipa::path(
    put,
    path = "/system/user/changeStatus",
    request_body = ChangeStatusDto,
    responses(
        (status = 200, description = "修改成功", body = AjaxResult<serde_json::Value>),
        (status = 400, description = "参数错误、不允许停用超管或 Redis 写入失败"),
    ),
    tag = "system-user"
)]
pub async fn change_status(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    ValidatedJson(dto): ValidatedJson<ChangeStatusDto>,
) -> Result<AjaxResult<serde_json::Value>, AppError> {
    let operator_user_id: i64 = operator
        .user_id()
        .parse()
        .map_err(|_| AppError::internal(&crate::tr!("error.user.operator_id_parse_failed")))?;

    // P0-C1 / P0-R81-007：停用后旧 token 立即失效（版本号机制），
    // 用户重新启用后需重新登录（安全行为）；启用时不需要递增。
    //
    // SharedStore 迁移后的 R2 级联修复：原"先 INCR pwd_ver → UPDATE DB → 失败 DECR 回滚"
    // 两阶段补偿随 `store.pwd_ver_incr` 内部双写（Redis INCR + DB password_version 列
    // 同步均在实现内）而简化——新顺序 = 先 UPDATE DB 用户状态，成功后递增版本号。
    // 原 DECR 补偿随双写落库简化删除（Redis 与 DB 列一致性由实现单点维护）；
    // pwd_ver_incr 失败仅 WARN——DB 列双写失败不破坏 Redis 当期安全。
    let needs_pwd_changed = dto.status == "1";

    // 步骤1：更新 DB 用户状态
    state
        .user_service
        .update_user_status(
            dto.user_id,
            &dto.status,
            operator.username(),
            operator_user_id,
            operator.tenant_id(),
        )
        .await?;

    // 步骤2：DB 成功后递增 pwd_ver + 吊销 SSO 令牌
    if needs_pwd_changed {
        if let Err(e) = state.store.pwd_ver_incr(&dto.user_id.to_string()).await {
            tracing::warn!(
                user_id = dto.user_id,
                error = %e,
                "停用用户后递增 pwd_ver 失败（原 DECR 补偿随双写落库简化删除）"
            );
        }
        // v4 #18：停用用户同步吊销其全部 SSO 访问令牌（pwd_ver 不约束不透明 AT）
        if let Err(e) = state.store.revoke_all_for_user(&dto.user_id.to_string()).await {
            tracing::warn!(user_id = dto.user_id, error = %e, "停用用户后吊销 SSO 令牌失败");
        }
        // W-4：停用即离岗 → 其 pending 审批待办自动转办（部门主管 → admin 回退）
        // 非阻断：停用已生效，转办失败仅告警（待办保持 pending，可由管理员人工转办）
        auto_reassign_flow_tasks(&state, dto.user_id).await;
    }

    Ok(AjaxResult::success_msg(&crate::tr!("msg.success.edit")))
}

/// PUT /system/user/resetPwd
/// 管理员重置密码
#[utoipa::path(
    put,
    path = "/system/user/resetPwd",
    request_body = UserPwdResetDto,
    responses(
        (status = 200, description = "重置成功", body = AjaxResult<serde_json::Value>),
        (status = 400, description = "参数错误或 Redis 写入失败"),
        (status = 404, description = "用户不存在"),
    ),
    tag = "system-user"
)]
pub async fn reset_pwd(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    Json(dto): Json<UserPwdResetDto>,
) -> Result<AjaxResult<serde_json::Value>, AppError> {
    // P0-R81-007：捕获 user_id 用于改密后递增 pwd_ver 标记
    let user_id = dto.user_id;
    let operator_user_id: i64 = operator
        .user_id()
        .parse()
        .map_err(|_| AppError::internal(&crate::tr!("error.user.operator_id_parse_failed")))?;

    // P0-C1 / P0-R81-007：版本号单调递增，无需 TTL（auth 中间件据此使旧 token 立即失效）。
    //
    // SharedStore 迁移后的 R2 级联修复（同 change_status）：先更新 DB 密码，成功后调
    // `store.pwd_ver_incr`（内部含 Redis INCR + DB 列双写）；原 DECR 补偿随双写落库
    // 简化删除；pwd_ver_incr 失败仅 WARN——DB 列双写失败不破坏 Redis 当期安全。
    //
    // 步骤1：更新 DB 密码
    state
        .user_service
        .reset_user_pwd(
            dto,
            operator.username(),
            operator_user_id,
            operator.tenant_id(),
        )
        .await?;

    // 步骤2：递增 pwd_ver（返回新版本号，本流程无需消费）+ 吊销 SSO 令牌
    if let Err(e) = state.store.pwd_ver_incr(&user_id.to_string()).await {
        tracing::warn!(
            user_id,
            error = %e,
            "重置密码后递增 pwd_ver 失败（原 DECR 补偿随双写落库简化删除）"
        );
    }

    // v4 #18：重置密码同步吊销该用户全部 SSO 访问令牌（pwd_ver 不约束不透明 AT）
    if let Err(e) = state.store.revoke_all_for_user(&user_id.to_string()).await {
        tracing::warn!(user_id, error = %e, "重置密码后吊销 SSO 令牌失败");
    }

    Ok(AjaxResult::success_msg(&crate::tr!(
        "msg.success.password_reset"
    )))
}

/// PUT /system/user/profile/updatePwd
/// 个人中心改密
///
/// 前端通过 JSON body 传递 oldPassword/newPassword（避免密码泄露到 URL/日志/浏览器历史）
#[utoipa::path(
    put,
    path = "/system/user/profile/updatePwd",
    request_body = ProfilePwdDto,
    responses(
        (status = 200, description = "改密成功", body = AjaxResult<serde_json::Value>),
        (status = 400, description = "参数错误或旧密码错误"),
    ),
    tag = "system-user"
)]
pub async fn update_profile_pwd(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    ValidatedJson(dto): ValidatedJson<ProfilePwdDto>,
) -> Result<AjaxResult<serde_json::Value>, AppError> {
    let user_id: i64 = operator
        .user_id()
        .parse()
        .map_err(|_| AppError::internal(&crate::tr!("error.user.operator_id_parse_failed")))?;
    let pwd_dto = UserPwdUpdateDto {
        old_password: dto.old_password,
        new_password: dto.new_password,
    };

    // P0-C1 / P0-R81-007：版本号机制使旧 token 立即失效。
    //
    // SharedStore 迁移后的 R2 级联修复（同 change_status）：先更新 DB 密码，成功后调
    // `store.pwd_ver_incr`（内部含 Redis INCR + DB 列双写）；原 DECR 补偿随双写落库
    // 简化删除；pwd_ver_incr 失败仅 WARN——DB 列双写失败不破坏 Redis 当期安全。
    //
    // 步骤1：更新 DB 密码
    state
        .user_service
        .update_user_password(user_id, pwd_dto)
        .await?;

    // 步骤2：递增 pwd_ver（返回新版本号，本流程无需消费）+ 吊销 SSO 令牌
    if let Err(e) = state.store.pwd_ver_incr(&user_id.to_string()).await {
        tracing::warn!(
            user_id,
            error = %e,
            "改密后递增 pwd_ver 失败（原 DECR 补偿随双写落库简化删除）"
        );
    }

    // v4 #18：改密同步吊销本人全部 SSO 访问令牌（pwd_ver 不约束不透明 AT）
    if let Err(e) = state.store.revoke_all_for_user(&user_id.to_string()).await {
        tracing::warn!(user_id, error = %e, "改密后吊销 SSO 令牌失败");
    }

    Ok(AjaxResult::success_msg(&crate::tr!(
        "msg.success.password_change"
    )))
}

/// GET /system/user/profile
/// 个人信息（含 roleGroup / postGroup）
///
/// 返回结构对齐前端 UserProfileResult extends AjaxResult：
/// `{ code, msg, data, roleGroup, postGroup }`（roleGroup/postGroup 在根对象，非 data 内）
#[utoipa::path(
    get,
    path = "/system/user/profile",
    responses(
        (status = 200, description = "个人信息（含角色组/岗位组）", body = ProfileResult),
        (status = 401, description = "未授权"),
    ),
    tag = "system-user"
)]
pub async fn get_profile(
    State(state): State<Arc<AppState>>,
    operator: Operator,
) -> Result<ProfileResult, AppError> {
    let user_id: i64 = operator
        .user_id()
        .parse()
        .map_err(|_| AppError::internal(&crate::tr!("error.user.operator_id_parse_failed")))?;
    let vo = state.user_service.get_profile(user_id).await?;
    Ok(ProfileResult {
        code: 200,
        msg: crate::tr!("msg.success.default"),
        data: vo.user,
        role_group: vo.role_group,
        post_group: vo.post_group,
    })
}

/// PUT /system/user/profile
/// 修改个人信息（nickName / phonenumber / email / sex）
///
/// 对齐前端 userInfo.vue 提交的 updateUserProfile(data) 请求。
#[utoipa::path(
    put,
    path = "/system/user/profile",
    request_body = ProfileUpdateDto,
    responses(
        (status = 200, description = "修改成功", body = AjaxResult<serde_json::Value>),
        (status = 400, description = "参数错误"),
    ),
    tag = "system-user"
)]
pub async fn update_profile(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    ValidatedJson(dto): ValidatedJson<ProfileUpdateDto>,
) -> Result<AjaxResult<serde_json::Value>, AppError> {
    let user_id: i64 = operator
        .user_id()
        .parse()
        .map_err(|_| AppError::internal(&crate::tr!("error.user.operator_id_parse_failed")))?;
    state.user_service.update_profile(user_id, dto).await?;
    Ok(AjaxResult::success_msg(&crate::tr!("msg.success.edit")))
}

/// GET /system/user/
/// 获取角色和岗位列表（用于新增用户表单的下拉选择）
///
/// 对齐前端 getUser()（无 userId 参数）调用：返回 UserFormResult，data 为 None，
/// roleIds/postIds 为空数组，roles/posts 为全部可用列表。
#[utoipa::path(
    get,
    path = "/system/user/",
    responses(
        (status = 200, description = "角色/岗位下拉数据（新增用户表单用）", body = UserFormResult),
        (status = 401, description = "未授权"),
    ),
    tag = "system-user"
)]
pub async fn get_roles_for_user_form(
    State(state): State<Arc<AppState>>,
    operator: Operator,
) -> Result<UserFormResult, AppError> {
    // 新增表单场景（None）：不校验目标用户（无目标），roles/posts 下拉按操作者租户过滤
    let vo = state
        .user_service
        .get_user_form_data(
            None,
            None,
            crate::common::tenant::tenant_scope(operator.tenant_id()),
        )
        .await?;
    Ok(UserFormResult {
        code: 200,
        msg: crate::tr!("msg.success.default"),
        data: vo.data,
        role_ids: vo.role_ids,
        post_ids: vo.post_ids,
        roles: vo.roles,
        posts: vo.posts,
    })
}

/// PUT /system/user/authRole
/// 分配用户角色（对齐前端：Query 参数 userId + roleIds）
#[utoipa::path(
    put,
    path = "/system/user/authRole",
    params(AssignAuthRoleDto),
    responses(
        (status = 200, description = "分配成功", body = AjaxResult<serde_json::Value>),
        (status = 400, description = "参数错误或角色层级越权"),
    ),
    tag = "system-user"
)]
pub async fn auth_role(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    Query(dto): Query<AssignAuthRoleDto>,
) -> Result<AjaxResult<serde_json::Value>, AppError> {
    crate::common::i18n::validate(&dto)?;
    // 垂直越权校验（P0-R81-005）：传入 operator_user_id 进行角色层级校验
    let operator_user_id: i64 = operator
        .user_id()
        .parse()
        .map_err(|_| AppError::internal(&crate::tr!("error.user.operator_id_parse_failed")))?;
    // role_ids 是逗号分隔字符串，解析为 Vec<i64>
    let role_ids: Vec<i64> = if dto.role_ids.is_empty() {
        vec![]
    } else {
        parse_id_list::<i64>(&dto.role_ids)
    };
    state
        .user_service
        .assign_user_roles(
            dto.user_id,
            role_ids,
            operator_user_id,
            operator.tenant_id(),
        )
        .await?;
    Ok(AjaxResult::success_msg(&crate::tr!(
        "msg.success.assign_role"
    )))
}

/// GET /system/user/deptTree
/// 部门下拉树（对齐前端 deptTreeSelect，返回 AjaxResult<Vec<TreeSelectVo>>）
#[utoipa::path(
    get,
    path = "/system/user/deptTree",
    responses(
        (status = 200, description = "部门下拉树", body = AjaxResult<Vec<TreeSelectVo>>),
        (status = 500, description = "服务器错误"),
    ),
    tag = "system-user"
)]
pub async fn dept_tree_select(
    State(state): State<Arc<AppState>>,
    operator: Operator,
) -> Result<AjaxResult<Vec<TreeSelectVo>>, AppError> {
    // P0-6 / 多租户：走 dept_service 统一入口，同时应用 data_scope 与租户过滤
    // （此前调用 user_service.get_dept_tree 无任何过滤，可枚举全平台部门）
    let operator_user_id: Option<i64> = operator.user_id().parse().ok();
    let tree = state
        .dept_service
        .build_dept_tree_select(
            operator_user_id,
            crate::common::tenant::tenant_scope(operator.tenant_id()),
        )
        .await?;
    Ok(AjaxResult::success(tree))
}

/// GET /system/user/authRole/{userId}
/// 查询用户授权角色信息（对齐前端 UserAuthRoleResult，user/roles 在顶层）
///
/// 返回结构与 AjaxResult 不同：user 和 roles 字段直接挂在响应根对象上，
/// 故使用自定义 AuthRoleResult 而非 AjaxResult<UserAuthRoleVo>。
#[utoipa::path(
    get,
    path = "/system/user/authRole/{userId}",
    params(("userId" = i64, Path, description = "用户 ID")),
    responses(
        (status = 200, description = "用户授权角色信息", body = AuthRoleResult),
        (status = 404, description = "用户不存在"),
    ),
    tag = "system-user"
)]
pub async fn auth_role_get(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    Path(user_id): Path<i64>,
) -> Result<AuthRoleResult, AppError> {
    let operator_user_id: i64 = operator
        .user_id()
        .parse()
        .map_err(|_| AppError::internal(&crate::tr!("error.user.operator_id_parse_failed")))?;
    let vo: UserAuthRoleVo = state
        .user_service
        .get_auth_role(
            user_id,
            operator_user_id,
            crate::common::tenant::tenant_scope(operator.tenant_id()),
        )
        .await?;
    Ok(AuthRoleResult {
        code: 200,
        msg: crate::tr!("msg.success.default"),
        user: vo.user,
        roles: vo.roles,
    })
}

/// POST /system/user/profile/avatar
/// 个人头像上传（multipart/form-data，字段名 avatarfile）
///
/// 实现要点：
/// - 使用 axum::extract::Multipart 读取 avatarfile 字段
/// - 保存到本地 uploads/avatar/{uuid}.{ext} 目录
/// - 更新 sys_user.avatar 字段为可访问的 URL 路径
/// - 返回 { code, msg, imgUrl }（imgUrl 在顶层，对齐前端 UserProfileAvatarResult）
#[utoipa::path(
    post,
    path = "/system/user/profile/avatar",
    responses(
        (status = 200, description = "头像上传成功（返回 imgUrl）", body = AvatarUploadResult),
        (status = 400, description = "缺少 avatarfile 字段或文件类型/大小非法"),
    ),
    tag = "system-user"
)]
pub async fn avatar_upload(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    mut multipart: Multipart,
) -> Result<AvatarUploadResult, AppError> {
    let user_id: i64 = operator
        .user_id()
        .parse()
        .map_err(|_| AppError::internal(&crate::tr!("error.user.operator_id_parse_failed")))?;

    // 从 multipart 中提取 avatarfile 字段（P0-3：流式限长读取，不再整读内存）
    let upload_cfg = &state.config.upload;
    let mut file_bytes: Option<Vec<u8>> = None;
    let mut file_ext: Option<String> = None;
    while let Some(mut field) = multipart.next_field().await.map_err(|e| {
        AppError::bad_request(&crate::tr!("error.file.multipart_parse_failed", e = e))
    })? {
        if field.name() == Some("avatarfile") {
            let (bytes, ext, _original) =
                crate::common::upload::read_field_limited(&mut field, upload_cfg.avatar_max_size)
                    .await?;
            file_ext = ext;
            file_bytes = Some(bytes);
        }
    }

    // 上传扫描集成点（`[upload_scan]`，默认 off ⇒ **零出站**、逐字节等价于改造前）
    if let Some(bytes) = file_bytes.as_deref() {
        crate::common::upload_scan::ensure_clean(&state.config.upload_scan, "avatar", bytes)
            .await?;
    }

    // P0-3：统一校验 + 保存（头像白名单、危险类型拒绝、magic bytes 以实际类型为准、UUID 文件名、写盘）
    let saved = crate::common::upload::save_upload_bytes(
        state.storage.as_ref(),
        file_bytes.as_deref().ok_or_else(|| {
            AppError::bad_request(&crate::tr!("error.common_handler.field_not_found_avatar"))
        })?,
        file_ext.as_deref(),
        None,
        upload_cfg,
        operator.tenant_id(),
        crate::common::upload::UploadKind::Avatar,
    )
    .await?;
    let img_url = saved.url;
    let filename = saved.new_filename;

    // 更新用户 avatar 字段，并获取旧 avatar 路径用于文件清理
    let old_avatar = state.user_service.update_avatar(user_id, &img_url).await?;

    // P2 修复: 删除旧头像文件（best-effort，失败仅记录日志，不影响上传流程；F1：统一走存储后端，含路径校验）
    if let Some(old_url) = old_avatar
        && let Some(old_filename) = old_url.rsplit('/').next()
        && !old_filename.is_empty()
        && old_filename != filename
    {
        // 旧头像文件位于同一租户目录内（URL 形如 /uploads/{tid}/avatar/xxx.png）
        let result = state
            .storage
            .delete(&upload_cfg.avatar_dir, operator.tenant_id(), old_filename)
            .await;
        if let Err(e) = &result {
            tracing::warn!(
                error = %e,
                old_filename = %old_filename,
                "删除旧头像文件失败（best-effort，不影响业务）"
            );
        }
    }

    Ok(AvatarUploadResult {
        code: 200,
        msg: crate::tr!("msg.success.default"),
        img_url,
    })
}

// detect_image_ext / normalize_ext 已抽到 crate::common::image（C13），此处不再重复定义。

// ==================== 顶层响应类型 ====================

/// 个人信息响应（对齐前端 UserProfileResult extends AjaxResult）
///
/// roleGroup / postGroup 字段直接挂在响应根对象上（非 data 字段内），
/// data 为用户信息。
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ProfileResult {
    pub code: i32,
    pub msg: String,
    pub data: SysUserModel,
    pub role_group: String,
    pub post_group: String,
}

/// 用户表单数据响应（对齐前端 UserFormDataResult extends AjaxResult）
///
/// data/roleIds/postIds/roles/posts 字段直接挂在响应根对象上。
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct UserFormResult {
    pub code: i32,
    pub msg: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<SysUserModel>,
    pub role_ids: Vec<i64>,
    pub post_ids: Vec<i64>,
    pub roles: Vec<SysRoleModel>,
    pub posts: Vec<SysPostModel>,
}

/// 用户授权角色查询响应（对齐前端 UserAuthRoleResult extends AjaxResult）
///
/// user 和 roles 字段直接挂在响应根对象上（非 data 字段），
/// 故需自定义类型而非使用 AjaxResult<T>。
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct AuthRoleResult {
    pub code: i32,
    pub msg: String,
    pub user: crate::entity::sys_user::Model,
    pub roles: Vec<SysRoleModel>,
}

/// 头像上传响应（对齐前端 UserProfileAvatarResult extends AjaxResult）
///
/// imgUrl 字段直接挂在响应根对象上。
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct AvatarUploadResult {
    pub code: i32,
    pub msg: String,
    pub img_url: String,
}

crate::impl_into_response!(
    ProfileResult,
    UserFormResult,
    AuthRoleResult,
    AvatarUploadResult
);
