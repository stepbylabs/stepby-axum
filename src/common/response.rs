// stepby-axum/src/common/response.rs

use axum::Json;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::{Deserialize, Serialize};
use ts_rs::TS;
use utoipa::ToSchema;

/// 普通接口响应（对齐前端 AjaxResult）
/// JSON: { "code": 200, "msg": "操作成功", "data": <T> }
///
/// 注：泛型类型不直接 export（ts-rs 12 不支持导出泛型 TS 文件），
/// 仅 derive TS 以便其他具体类型引用时能正确推导。
#[derive(Debug, Clone, Serialize, Deserialize, TS, ToSchema)]
pub struct AjaxResult<T> {
    pub code: i32,
    pub msg: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub data: Option<T>,
}

impl<T> AjaxResult<T> {
    /// 成功响应（带数据）
    pub fn success(data: T) -> Self {
        Self {
            code: 200,
            msg: crate::tr!("msg.success.default"),
            data: Some(data),
        }
    }

    /// 成功响应（仅消息）
    pub fn success_msg(msg: &str) -> Self {
        Self {
            code: 200,
            msg: msg.to_string(),
            data: None,
        }
    }

    /// 错误响应
    pub fn error(code: i32, msg: &str) -> Self {
        Self {
            code,
            msg: msg.to_string(),
            data: None,
        }
    }
}

/// AjaxResult 直接实现 IntoResponse
/// handler 可直接返回 `Result<AjaxResult<T>, AppError>`，无需手动包 Json
/// HTTP 状态码统一 200，业务错误由 body.code 表达
impl<T: Serialize> IntoResponse for AjaxResult<T> {
    fn into_response(self) -> Response {
        (StatusCode::OK, Json(self)).into_response()
    }
}

/// 下拉树节点（对齐前端 TreeSelect 类型）
///
/// 用于菜单下拉树、部门下拉树等场景。字段挂在响应根对象上：
/// `{ id, label, disabled, children }`
///
/// `children` 是自引用递归字段，使用 `#[schema(no_recursion)]` 属性
/// 让 utoipa 生成 `$ref` 自引用，打破递归（utoipa 5.1.0+ 官方方案）。
#[derive(Debug, Clone, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct TreeSelectVo {
    pub id: i64,
    pub label: String,
    pub disabled: bool,
    #[schema(no_recursion)]
    pub children: Vec<TreeSelectVo>,
}

/// 分页接口响应（对齐前端 TableDataInfo）
/// JSON: { "code": 200, "msg": "查询成功", "total": 100, "rows": [...] }
///
/// 注：泛型类型不直接 export，仅 derive TS 以便具体类型引用时正确推导。
#[derive(Debug, Clone, Serialize, Deserialize, TS, ToSchema)]
pub struct TableDataInfo<T> {
    pub code: i32,
    pub msg: String,
    pub total: u64,
    pub rows: Vec<T>,
}

impl<T> TableDataInfo<T> {
    /// 构造分页响应
    pub fn new(total: u64, rows: Vec<T>) -> Self {
        Self {
            code: 200,
            msg: crate::tr!("msg.success.query"),
            total,
            rows,
        }
    }
}

/// TableDataInfo 直接实现 IntoResponse
impl<T: Serialize> IntoResponse for TableDataInfo<T> {
    fn into_response(self) -> Response {
        (StatusCode::OK, Json(self)).into_response()
    }
}
