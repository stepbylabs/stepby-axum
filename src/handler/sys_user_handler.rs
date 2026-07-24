// axum-backend/src/handler/sys_user_handler.rs
//! 用户模块 Handler（Axum 原生实现）
//!
//! 接口路径与返回格式对齐 ref-salvo-admin / ruoyi-vue3-ts：
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

use std::sync::Arc;
use axum::extract::{Form, Multipart, Path, Query, State};
use axum::response::Response;
use axum::Json;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use validator::Validate;

use crate::common::ValidatedJson;
use crate::common::{AjaxResult, AppError, TableDataInfo, TreeSelectVo};
use crate::common::constants::{MAX_BATCH_DELETE_SIZE, SECS_PER_HOUR};
use crate::common::excel::{export_to_excel, ExcelColumn};
use crate::entity::sys_post::Model as SysPostModel;
use crate::entity::sys_role::Model as SysRoleModel;
use crate::entity::sys_user::Model as SysUserModel;
use crate::middleware::Operator;
use crate::service::sys_user_service::{
    ProfileUpdateDto, UserAddDto, UserAuthRoleVo, UserEditDto, UserPwdResetDto,
    UserPwdUpdateDto, UserQueryDto, UserVo,
};
use crate::state::AppState;
use crate::utils::parse_id_list;

// ==================== 辅助 DTO ====================

/// 启停用户请求体
#[derive(Debug, Deserialize, Validate)]
#[serde(rename_all = "camelCase")]
pub struct ChangeStatusDto {
    pub user_id: i64,
    #[validate(length(min = 1, max = 1, message = "状态值不合法"))]
    pub status: String,
}

/// 分配用户角色请求体（对齐前端 PUT /system/user/authRole?userId=&roleIds=）
/// ref-salvo-admin 此接口走 Query，这里同样走 Query 以保持兼容
#[derive(Debug, Deserialize, Validate)]
#[serde(rename_all = "camelCase")]
pub struct AssignAuthRoleDto {
    #[validate(range(min = 1, message = "用户 ID 不合法"))]
    pub user_id: i64,
    /// 逗号分隔的角色 ID 字符串（对齐前端 params.roleIds）
    pub role_ids: String,
}

/// 个人改密请求体
#[derive(Debug, Deserialize, Validate)]
#[serde(rename_all = "camelCase")]
pub struct ProfilePwdDto {
    #[validate(length(min = 5, max = 20, message = "原密码长度必须在5-20之间"))]
    pub old_password: String,
    #[validate(length(min = 5, max = 20, message = "新密码长度必须在5-20之间"))]
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
    let operator_user_id: Option<i64> = operator
        .user_id()
        .parse::<i64>()
        .ok();
    let (rows, total) = state
        .user_service
        .get_user_page(query, operator_user_id)
        .await?;
    Ok(TableDataInfo::new(total, rows))
}

/// POST /system/user/export
/// 导出用户列表为 Excel
///
/// 前端 download() 发送 application/x-www-form-urlencoded，使用 Form 提取器
pub async fn export(
    State(state): State<Arc<AppState>>,
    Form(query): Form<UserQueryDto>,
) -> Result<Response, AppError> {
    let rows = state.user_service.export_users(query).await?;

    let columns = [
        ExcelColumn { header: "用户编号", getter: |r: &UserVo| r.user.user_id.to_string().into() },
        ExcelColumn { header: "登录名称", getter: |r: &UserVo| r.user.user_name.clone().into() },
        ExcelColumn { header: "用户姓名", getter: |r: &UserVo| r.user.nick_name.clone().into() },
        ExcelColumn { header: "部门", getter: |r: &UserVo| r.user.dept_id.map(|d| d.to_string()).unwrap_or_default().into() },
        ExcelColumn { header: "手机号码", getter: |r: &UserVo| r.user.phonenumber.clone().unwrap_or_default().into() },
        ExcelColumn { header: "邮箱", getter: |r: &UserVo| r.user.email.clone().unwrap_or_default().into() },
        ExcelColumn { header: "状态", getter: |r: &UserVo| if r.user.status.as_deref() == Some("0") { "正常".to_string() } else { "停用".to_string() }.into() },
        ExcelColumn {
            header: "创建时间",
            getter: |r: &UserVo| {
                r.user.create_time
                    .map(|dt| dt.format("%Y-%m-%d %H:%M:%S").to_string())
                    .unwrap_or_default()
                    .into()
            }
        },
    ];

    export_to_excel("用户数据", "user", &columns, &rows)
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
    Path(user_id): Path<i64>,
) -> Result<UserFormResult, AppError> {
    let vo = state.user_service.get_user_form_data(Some(user_id)).await?;
    Ok(UserFormResult {
        code: 200,
        msg: "操作成功".to_string(),
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
    let user = state.user_service.add_user(dto, operator.username()).await?;
    // 对齐前端：新增返回提示消息
    Ok(AjaxResult::success_msg(&format!("新增用户 {} 成功", user.user_name)))
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
    Json(dto): Json<UserEditDto>,
) -> Result<AjaxResult<serde_json::Value>, AppError> {
    let operator_user_id: i64 = operator
        .user_id()
        .parse()
        .map_err(|_| AppError::internal("操作人用户 ID 解析失败"))?;
    state
        .user_service
        .edit_user(dto, operator.username(), operator_user_id)
        .await?;
    Ok(AjaxResult::success_msg("修改成功"))
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
    Path(ids): Path<String>,
) -> Result<AjaxResult<serde_json::Value>, AppError> {
    let operator_user_id: i64 = operator
        .user_id()
        .parse()
        .map_err(|_| AppError::internal("操作人用户 ID 解析失败"))?;

    // R8-API-002：解析逗号分隔的 ID 列表
    let user_ids: Vec<i64> = parse_id_list::<i64>(&ids);
    if user_ids.is_empty() {
        return Err(AppError::bad_request("用户 ID 不能为空"));
    }
    // R8-API-005：批量上限校验
    if user_ids.len() > MAX_BATCH_DELETE_SIZE {
        return Err(AppError::bad_request(&format!(
            "批量操作数量不能超过{}",
            MAX_BATCH_DELETE_SIZE
        )));
    }

    // 单个 ID 走原路径（保持现有垂直越权校验语义）
    // 批量 ID 调用新增的 delete_users 事务方法（原子性保证）
    state
        .user_service
        .delete_users(user_ids, operator_user_id)
        .await?;
    Ok(AjaxResult::success_msg("删除成功"))
}

/// PUT /system/user/changeStatus
/// 启停用户
pub async fn change_status(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    ValidatedJson(dto): ValidatedJson<ChangeStatusDto>,
) -> Result<AjaxResult<serde_json::Value>, AppError> {
    let operator_user_id: i64 = operator
        .user_id()
        .parse()
        .map_err(|_| AppError::internal("操作人用户 ID 解析失败"))?;
    state
        .user_service
        .update_user_status(
            dto.user_id,
            &dto.status,
            operator.username(),
            operator_user_id,
        )
        .await?;
    Ok(AjaxResult::success_msg("修改成功"))
}

/// PUT /system/user/resetPwd
/// 管理员重置密码
pub async fn reset_pwd(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    Json(dto): Json<UserPwdResetDto>,
) -> Result<AjaxResult<serde_json::Value>, AppError> {
    // P0-R81-007：捕获 user_id 用于改密后写入 pwd_changed 标记
    let user_id = dto.user_id;
    let operator_user_id: i64 = operator
        .user_id()
        .parse()
        .map_err(|_| AppError::internal("操作人用户 ID 解析失败"))?;
    state
        .user_service
        .reset_user_pwd(dto, operator.username(), operator_user_id)
        .await?;

    // P0-R81-007：改密后写入 pwd_changed:{user_id} 标记，使改密前签发的旧 token 失效
    // TTL 与 JWT 最大有效期对齐：expire_hours * SECS_PER_HOUR 秒（修复 REGRESS-001：原硬编码 7200s < JWT 24h，2h 后旧 token 可重用）
    // fail-closed：写入失败返回错误，避免旧 token 继续可用
    let pwd_changed_key = format!("pwd_changed:{}", user_id);
    let now = chrono::Utc::now().timestamp();
    let pwd_ttl = state.config.jwt.expire_hours * SECS_PER_HOUR;
    let mut redis = state.redis.clone();
    redis::cmd("SETEX")
        .arg(&pwd_changed_key)
        .arg(pwd_ttl)
        .arg(now)
        .query_async::<()>(&mut redis)
        .await
        .map_err(|e| {
            tracing::error!("写入 pwd_changed 标记失败（fail-closed）: {}", e);
            AppError::internal("密码重置成功，但旧 token 失效标记写入失败")
        })?;

    Ok(AjaxResult::success_msg("密码重置成功"))
}

/// PUT /system/user/profile/updatePwd
/// 个人中心改密
///
/// 前端通过 JSON body 传递 oldPassword/newPassword（避免密码泄露到 URL/日志/浏览器历史）
pub async fn update_profile_pwd(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    ValidatedJson(dto): ValidatedJson<ProfilePwdDto>,
) -> Result<AjaxResult<serde_json::Value>, AppError> {
    let user_id: i64 = operator
        .user_id()
        .parse()
        .map_err(|_| AppError::internal("操作人用户 ID 解析失败"))?;
    let pwd_dto = UserPwdUpdateDto {
        old_password: dto.old_password,
        new_password: dto.new_password,
    };
    state
        .user_service
        .update_user_password(user_id, pwd_dto)
        .await?;

    // P0-R81-007：改密后写入 pwd_changed:{user_id} 标记，使改密前签发的旧 token 失效
    // TTL 与 JWT 最大有效期对齐：expire_hours * SECS_PER_HOUR 秒（修复 REGRESS-001：原硬编码 7200s < JWT 24h）
    // fail-closed：写入失败返回错误，避免旧 token 继续可用
    let pwd_changed_key = format!("pwd_changed:{}", user_id);
    let now = chrono::Utc::now().timestamp();
    let pwd_ttl = state.config.jwt.expire_hours * SECS_PER_HOUR;
    let mut redis = state.redis.clone();
    redis::cmd("SETEX")
        .arg(&pwd_changed_key)
        .arg(pwd_ttl)
        .arg(now)
        .query_async::<()>(&mut redis)
        .await
        .map_err(|e| {
            tracing::error!("写入 pwd_changed 标记失败（fail-closed）: {}", e);
            AppError::internal("密码修改成功，但旧 token 失效标记写入失败")
        })?;

    Ok(AjaxResult::success_msg("密码修改成功"))
}

/// GET /system/user/profile
/// 个人信息（含 roleGroup / postGroup）
///
/// 返回结构对齐前端 UserProfileResult extends AjaxResult：
/// `{ code, msg, data, roleGroup, postGroup }`（roleGroup/postGroup 在根对象，非 data 内）
pub async fn get_profile(
    State(state): State<Arc<AppState>>,
    operator: Operator,
) -> Result<ProfileResult, AppError> {
    let user_id: i64 = operator
        .user_id()
        .parse()
        .map_err(|_| AppError::internal("操作人用户 ID 解析失败"))?;
    let vo = state.user_service.get_profile(user_id).await?;
    Ok(ProfileResult {
        code: 200,
        msg: "操作成功".to_string(),
        data: vo.user,
        role_group: vo.role_group,
        post_group: vo.post_group,
    })
}

/// PUT /system/user/profile
/// 修改个人信息（nickName / phonenumber / email / sex）
///
/// 对齐前端 userInfo.vue 提交的 updateUserProfile(data) 请求。
pub async fn update_profile(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    ValidatedJson(dto): ValidatedJson<ProfileUpdateDto>,
) -> Result<AjaxResult<serde_json::Value>, AppError> {
    let user_id: i64 = operator
        .user_id()
        .parse()
        .map_err(|_| AppError::internal("操作人用户 ID 解析失败"))?;
    state.user_service.update_profile(user_id, dto).await?;
    Ok(AjaxResult::success_msg("修改成功"))
}

/// GET /system/user/
/// 获取角色和岗位列表（用于新增用户表单的下拉选择）
///
/// 对齐前端 getUser()（无 userId 参数）调用：返回 UserFormResult，data 为 None，
/// roleIds/postIds 为空数组，roles/posts 为全部可用列表。
pub async fn get_roles_for_user_form(
    State(state): State<Arc<AppState>>,
) -> Result<UserFormResult, AppError> {
    let vo = state.user_service.get_user_form_data(None).await?;
    Ok(UserFormResult {
        code: 200,
        msg: "操作成功".to_string(),
        data: vo.data,
        role_ids: vo.role_ids,
        post_ids: vo.post_ids,
        roles: vo.roles,
        posts: vo.posts,
    })
}

/// PUT /system/user/authRole
/// 分配用户角色（对齐前端：Query 参数 userId + roleIds）
pub async fn auth_role(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    Query(dto): Query<AssignAuthRoleDto>,
) -> Result<AjaxResult<serde_json::Value>, AppError> {
    dto.validate()?;
    // 垂直越权校验（P0-R81-005）：传入 operator_user_id 进行角色层级校验
    let operator_user_id: i64 = operator
        .user_id()
        .parse()
        .map_err(|_| AppError::internal("操作人用户 ID 解析失败"))?;
    // role_ids 是逗号分隔字符串，解析为 Vec<i64>
    let role_ids: Vec<i64> = if dto.role_ids.is_empty() {
        vec![]
    } else {
        parse_id_list::<i64>(&dto.role_ids)
    };
    state
        .user_service
        .assign_user_roles(dto.user_id, role_ids, operator_user_id)
        .await?;
    Ok(AjaxResult::success_msg("分配角色成功"))
}

/// GET /system/user/deptTree
/// 部门下拉树（对齐前端 deptTreeSelect，返回 AjaxResult<Vec<TreeSelectVo>>）
pub async fn dept_tree_select(
    State(state): State<Arc<AppState>>,
) -> Result<AjaxResult<Vec<TreeSelectVo>>, AppError> {
    let tree = state.user_service.get_dept_tree().await?;
    Ok(AjaxResult::success(tree))
}

/// GET /system/user/authRole/{userId}
/// 查询用户授权角色信息（对齐前端 UserAuthRoleResult，user/roles 在顶层）
///
/// 返回结构与 AjaxResult 不同：user 和 roles 字段直接挂在响应根对象上，
/// 故使用自定义 AuthRoleResult 而非 AjaxResult<UserAuthRoleVo>。
pub async fn auth_role_get(
    State(state): State<Arc<AppState>>,
    Path(user_id): Path<i64>,
) -> Result<AuthRoleResult, AppError> {
    let vo: UserAuthRoleVo = state.user_service.get_auth_role(user_id).await?;
    Ok(AuthRoleResult {
        code: 200,
        msg: "操作成功".to_string(),
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
pub async fn avatar_upload(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    mut multipart: Multipart,
) -> Result<AvatarUploadResult, AppError> {
    let user_id: i64 = operator
        .user_id()
        .parse()
        .map_err(|_| AppError::internal("操作人用户 ID 解析失败"))?;

    // 从 multipart 中提取 avatarfile 字段
    let mut file_bytes: Option<Vec<u8>> = None;
    let mut file_ext: Option<String> = None;
    while let Some(field) = multipart
        .next_field()
        .await
        .map_err(|e| AppError::bad_request(&format!("解析 multipart 失败: {}", e)))?
    {
        if field.name() == Some("avatarfile") {
            // 从文件名推断扩展名（前端 vue-cropper 默认输出 blob，无 filename，默认 png）
            if let Some(filename) = field.file_name()
                && let Some(ext) = std::path::Path::new(filename)
                    .extension()
                    .and_then(|e| e.to_str())
            {
                file_ext = Some(ext.to_lowercase());
            }
            let bytes = field
                .bytes()
                .await
                .map_err(|e| AppError::bad_request(&format!("读取文件内容失败: {}", e)))?;
            file_bytes = Some(bytes.to_vec());
        }
    }

    let bytes = file_bytes.ok_or_else(|| AppError::bad_request("未找到 avatarfile 字段"))?;
    if bytes.is_empty() {
        return Err(AppError::bad_request("上传文件为空"));
    }

    // 限制头像大小（从配置读取，默认 5MB）
    let upload_cfg = &state.config.upload;
    if bytes.len() > upload_cfg.avatar_max_size {
        return Err(AppError::bad_request(&format!(
            "头像大小不能超过 {}MB",
            upload_cfg.avatar_max_size / 1024 / 1024
        )));
    }

    // MIME magic bytes 校验：通过文件头识别真实类型，防止伪造扩展名
    let detected_ext = detect_image_ext(&bytes)
        .ok_or_else(|| AppError::bad_request("无法识别的图片格式，仅支持 jpg/jpeg/png/gif"))?;

    // 扩展名白名单校验：前端传入的扩展名必须与 magic bytes 识别结果一致，且在白名单内
    let allowed: &[&str] = &["jpg", "jpeg", "png", "gif"];
    let ext = match &file_ext {
        Some(e) if allowed.contains(&e.as_str()) => {
            // 前端扩展名与 magic bytes 不一致时，以 magic bytes 为准（防止伪造）
            if normalize_ext(e) != normalize_ext(&detected_ext) {
                tracing::warn!(
                    "头像扩展名与实际类型不一致: 声明={}, 实际={}",
                    e,
                    detected_ext
                );
            }
            detected_ext
        }
        _ => detected_ext,
    };

    // 生成唯一文件名
    let filename = crate::common::gen_uuid_filename(&ext);
    // 解析上传目录为绝对路径，确保与 ServeDir 服务路径一致
    let avatar_dir = crate::common::resolve_upload_dir(&upload_cfg.avatar_dir).await;
    let file_path = avatar_dir.join(&filename);

    // 写入文件系统（公共函数封装了 spawn_blocking + create_dir_all + write）
    crate::common::write_upload_file(file_path, &avatar_dir.to_string_lossy(), &bytes).await?;

    // 可访问的 URL 路径（前端通过 VITE_APP_BASE_API + imgUrl 访问）
    let img_url = format!("{}/{}", upload_cfg.avatar_url_prefix, filename);

    // 更新用户 avatar 字段
    state
        .user_service
        .update_avatar(user_id, &img_url)
        .await?;

    Ok(AvatarUploadResult {
        code: 200,
        msg: "操作成功".to_string(),
        img_url,
    })
}

/// 通过文件头 magic bytes 识别图片真实格式
///
/// 返回标准化扩展名（小写）：
/// - JPEG: FF D8 FF
/// - PNG: 89 50 4E 47 0D 0A 1A 0A
/// - GIF: 47 49 46 38 (37/39)
fn detect_image_ext(bytes: &[u8]) -> Option<String> {
    // 每次切片前单独校验长度，避免越界 panic（P0-New-1）
    // JPEG: FF D8 FF
    if bytes.len() >= 3 && bytes[0] == 0xFF && bytes[1] == 0xD8 && bytes[2] == 0xFF {
        return Some("jpg".to_string());
    }
    // PNG: 89 50 4E 47 0D 0A 1A 0A（需 8 字节）
    if bytes.len() >= 8 && bytes[0..8] == [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A] {
        return Some("png".to_string());
    }
    // GIF: 47 49 46 38 (37/39)（需 5 字节）
    if bytes.len() >= 5 && bytes[0..4] == [0x47, 0x49, 0x46, 0x38] && (bytes[4] == 0x37 || bytes[4] == 0x39) {
        return Some("gif".to_string());
    }
    None
}

/// 标准化扩展名（jpeg → jpg）
fn normalize_ext(ext: &str) -> String {
    let lower = ext.to_lowercase();
    match lower.as_str() {
        "jpeg" => "jpg".to_string(),
        _ => lower,
    }
}

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

crate::impl_into_response!(ProfileResult, UserFormResult, AuthRoleResult, AvatarUploadResult);
