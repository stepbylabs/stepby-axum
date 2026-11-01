// stepby-axum/src/service/op_recording.rs
//! 操作录制与回放的 **采集 / 存储 / 导出** 半边（回放执行见 [`super::op_recording_replay`]）。
//!
//! ## 为什么采集放在 HTTP 边界，而不是前端埋点
//!
//! 前端埋点要"每个页面记得调用录制 SDK"——新页面、新弹窗、绕过前端的脚本调用都会漏，
//! 而漏掉的那一步在回放时表现为"后续步骤全失败"却查不出原因。HTTP 边界是**唯一所有
//! 操作都必经**的位置：一次请求的方法/路径/查询串/请求体就是这一步的全部输入。
//!
//! 代价与对策（三条，都是本模块的硬约束）：
//! 1. **请求体是流**：中间件必须在交给 handler 之前把 body 读出来再放回去，否则
//!    `Json<T>` 提取器会看到空 body。读取上限 [`MAX_CAPTURED_BODY_BYTES`]，
//!    超限只记长度不记内容（**宁可少记，不可把内存交给客户端**）。
//! 2. **凭据不得入库**：`Authorization` / `Cookie` / `X-Token` 一律不采集；回放时由
//!    执行者自己的令牌重新注入（见回放服务）。录制库里出现别人的令牌 = 一次库导出
//!    就是一次凭据泄露。
//! 3. **敏感字段必须脱敏**：密码类字段按字段名折叠成 `***`（[`redact_json_like`]）。
//!
//! ## 采集开关
//!
//! 请求头 `X-Record-Into: <recordingId>` + 权限 `tool:recording:record`。**默认关**：
//! 没有这个头时中间件只做一次 header 查找就返回，不进 body 读取路径。
//!
//! ## 回放目标不可由录制内容决定
//!
//! 步骤只存 `path`（必须以单个 `/` 开头）。绝对 URL、协议相对 URL（`//host/x`）、
//! 含 `..` 的路径**在写入侧就拒绝**，在回放侧再校验一次——两处都查的理由是：写入侧
//! 可能被历史数据或直接改库绕过，而回放侧是真正出网的那一刻（AGENTS ㉔「判据要问
//! 这一刻谁在做那件事」）。

use std::collections::BTreeMap;
use std::collections::BTreeSet;

use chrono::NaiveDateTime;
use sea_orm::Set;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::common::error::ServiceError;
use crate::common::i18n::pick;
use crate::common::page::PageDomain;
use crate::common::sort::{self, SortOrder};
use crate::entity::sys_op_recording::{
    ActiveModel as RecordingActiveModel, Column as RecordingColumn, Model as RecordingModel,
};
use crate::entity::sys_op_recording_step::Model as StepModel;
use crate::repository::op_recording::{OpRecordingRepository, StepSeed};
use crate::service::sys_task_service::SysTaskService;

// ==================== 硬上限 ====================

/// 单个录制最多保留的步骤数。
///
/// 取 200 的判据：一次人工业务流程（新建→配置→提交→审批→验收）通常 10~30 步；
/// 200 步足够覆盖"把一整套初始化脚本录进来"，同时保证一次回放在 30s×200 的最坏
/// 情况下仍是分钟级（回放本身还有重活闸与逐步超时）。
pub const MAX_STEPS_PER_RECORDING: i32 = 200;

/// 单步请求体采集上限（64 KiB）。
///
/// 超限只记录长度与截断标记：把上限设成 1 MiB 会让 200 步的录制最坏占 200 MiB 库容量，
/// 而真实业务请求体（表单/JSON）绝大多数小于 8 KiB。上传类请求另有 `is_capturable`
/// 直接排除（二进制内容存进文本列既无意义也不可回放）。
pub const MAX_CAPTURED_BODY_BYTES: usize = 64 * 1024;

/// 查询串采集上限（2 KiB）——与实体列宽一致。
pub const MAX_CAPTURED_QUERY_BYTES: usize = 2048;

/// 允许回放的请求头白名单。
///
/// 只保留"影响请求语义但不承载身份"的头。`Authorization` / `Cookie` / `X-Token` /
/// `X-Api-Key` 等一律不采集：回放用的是执行者自己的令牌，录制内容不得携带任何凭据。
pub const REPLAYABLE_HEADERS: &[&str] = &[
    "content-type",
    "accept",
    "accept-language",
    "x-request-id",
    "if-match",
];

/// 采集排除的路径前缀（**都是精确前缀，不用通配**，防误伤业务写接口）。
///
/// - `/auth/`：登录/登出/刷新/验证码——含口令与一次性凭据，且回放登录没有意义。
/// - `/tool/recording`：录制自身的控制面，采集它会自我递归。
/// - `/common/upload`、`/file/`、`/system/file`：二进制上传，不可用文本回放。
/// - `/monitor/frontendError`：机器遥测通道，高频且非用户操作。
/// - `/ai/`：推理请求昂贵且不确定（同一 prompt 两次结果不同），回放不能作为回归判据。
pub const CAPTURE_EXCLUDED_PREFIXES: &[&str] = &[
    "/auth/",
    "/tool/recording",
    "/common/upload",
    "/file/",
    "/system/file",
    "/monitor/frontendError",
    "/ai/",
];

/// 敏感字段名（小写比对，全部折叠成 `***`）。
pub const SENSITIVE_FIELD_NAMES: &[&str] = &[
    "password",
    "oldpassword",
    "newpassword",
    "confirmpassword",
    "passwd",
    "pwd",
    "secret",
    "token",
    "accesstoken",
    "refreshtoken",
    "apikey",
    "api_key",
    "privatekey",
    "private_key",
    "clientsecret",
    "client_secret",
    "idcard",
    "id_card",
    "bankcard",
    "bank_card",
];

// ==================== DTO ====================

/// 分页查询 DTO
#[derive(Debug, Clone, Deserialize, utoipa::IntoParams, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct RecordingQueryDto {
    #[serde(default = "crate::common::page::default_page_num")]
    pub page_num: u64,
    #[serde(default = "crate::common::page::default_page_size")]
    pub page_size: u64,
    #[serde(default)]
    pub order_by_column: Option<String>,
    #[serde(default)]
    pub is_asc: Option<String>,
    /// 名称模糊
    #[serde(default)]
    pub name: Option<String>,
    /// 状态（draft/ready/archived）
    #[serde(default)]
    pub status: Option<String>,
    /// 来源（ui/api/import）
    #[serde(default)]
    pub source: Option<String>,
}

impl From<&RecordingQueryDto> for PageDomain {
    fn from(dto: &RecordingQueryDto) -> Self {
        let mut page = PageDomain {
            page_num: dto.page_num,
            page_size: dto.page_size,
            order_by_column: dto.order_by_column.clone(),
            is_asc: dto.is_asc.clone(),
        };
        page.sanitize_order_fields();
        page
    }
}

/// 新建录制 DTO
#[derive(Debug, Clone, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct RecordingCreateDto {
    /// 名称（1..=120）
    pub name: String,
    /// 说明
    #[serde(default)]
    pub description: Option<String>,
    /// 来源（缺省 ui）
    #[serde(default)]
    pub source: Option<String>,
}

/// 编辑录制 DTO
#[derive(Debug, Clone, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct RecordingUpdateDto {
    pub recording_id: i64,
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
    /// ready / draft / archived
    #[serde(default)]
    pub status: Option<String>,
}

/// 追加/修改单步 DTO（API 方式写入录制的入口）
#[derive(Debug, Clone, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct StepWriteDto {
    pub method: String,
    pub path: String,
    #[serde(default)]
    pub query_string: Option<String>,
    #[serde(default)]
    pub body: Option<String>,
    #[serde(default)]
    pub note: Option<String>,
    #[serde(default)]
    pub expect_status: Option<i32>,
    /// 返回值抽取规则（`{"deptId":"data.deptId"}`），供后续步骤以 `{{deptId}}` 引用
    #[serde(default)]
    pub extract_json: Option<String>,
}

/// 录制详情（抬头 + 步骤）
#[derive(Debug, Clone, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct RecordingDetailVo {
    #[serde(flatten)]
    pub recording: RecordingModel,
    pub steps: Vec<StepModel>,
}

/// 导出格式
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScriptFormat {
    /// bash + curl，可直接 `sh run.sh`
    Curl,
    /// `.http`（VS Code REST Client / JetBrains HTTP Client）
    Http,
    /// 结构化 JSON（本服务 `/tool/recording/{id}/replay` 可直接吃）
    Json,
}

impl ScriptFormat {
    pub fn parse(raw: &str) -> Option<Self> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "curl" | "bash" | "sh" => Some(Self::Curl),
            "http" => Some(Self::Http),
            "json" => Some(Self::Json),
            _ => None,
        }
    }

    pub fn extension(self) -> &'static str {
        match self {
            Self::Curl => "sh",
            Self::Http => "http",
            Self::Json => "json",
        }
    }

    pub fn content_type(self) -> &'static str {
        match self {
            Self::Curl => "text/x-shellscript; charset=utf-8",
            Self::Http => "text/plain; charset=utf-8",
            Self::Json => "application/json; charset=utf-8",
        }
    }
}

/// 采集判定（**三态**，不是布尔）。
///
/// 布尔会强迫调用方把"不是写操作"与"这个路径被排除"折成同一个 false，于是
/// `/metrics` 上只有一个 `skipped` 数字，排查时无法回答"我这次操作为什么没被录进去"。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CaptureDecision {
    /// 采集
    Capture,
    /// 不采集：非写方法（GET/HEAD/OPTIONS）
    NotMutating,
    /// 不采集：路径在排除清单内（登录/上传/遥测/录制自身…）
    Excluded(&'static str),
    /// 不采集：路径形状非法（空/不以单斜杠开头/含 `..`/绝对 URL）
    BadPath,
    /// 不采集：该录制已达步数上限
    Full,
}

impl CaptureDecision {
    /// 指标标签值（与 `/metrics` 的 outcome 口径一一对应）
    pub fn outcome(&self) -> &'static str {
        match self {
            Self::Capture => "recorded",
            Self::NotMutating => "not_mutating",
            Self::Excluded(_) => "excluded",
            Self::BadPath => "bad_path",
            Self::Full => "full",
        }
    }
}

// ==================== 纯函数（可证伪判据的落点）====================

/// 路径形状校验：**只接受单斜杠开头的站内路径**。
///
/// 拒绝的形态各自对应一种真实风险：
/// - 绝对 URL（`http://…`）⇒ 回放变成 SSRF；
/// - 协议相对（`//host/x`）⇒ 浏览器语义里就是跨站，出网目标随之可控；
/// - `..` 段 ⇒ 规范化后可能逃出预期前缀。
pub fn validate_step_path(path: &str) -> Result<(), &'static str> {
    let p = path.trim();
    if p.is_empty() {
        return Err("路径不能为空");
    }
    if p.len() > 512 {
        return Err("路径过长（上限 512 字符）");
    }
    if !p.starts_with('/') {
        return Err("路径必须以 / 开头（只接受站内相对路径）");
    }
    if p.starts_with("//") {
        return Err("路径不得以 // 开头（协议相对 URL 会把回放变成出站请求）");
    }
    if p.split('/').any(|seg| seg == "..") {
        return Err("路径不得包含 .. 段");
    }
    if p.contains('\\') {
        return Err("路径不得包含反斜杠");
    }
    Ok(())
}

/// 采集判定（纯函数）。
pub fn decide_capture(method: &str, path: &str, current_steps: i32) -> CaptureDecision {
    let m = method.trim().to_ascii_uppercase();
    if !matches!(m.as_str(), "POST" | "PUT" | "PATCH" | "DELETE") {
        return CaptureDecision::NotMutating;
    }
    if validate_step_path(path).is_err() {
        return CaptureDecision::BadPath;
    }
    // 查询串不参与排除判定：按 path 比前缀（`/auth/login?x=1` 的 path 是 `/auth/login`）
    for prefix in CAPTURE_EXCLUDED_PREFIXES {
        if path.starts_with(prefix) {
            return CaptureDecision::Excluded(prefix);
        }
    }
    if current_steps >= MAX_STEPS_PER_RECORDING {
        return CaptureDecision::Full;
    }
    CaptureDecision::Capture
}

/// 请求头筛选：只留白名单，且同名只留第一条（大小写无关）。
///
/// 返回 `BTreeMap` 的理由是**输出稳定**：同样的请求两次采集必须得到逐字节相同的
/// `headers_json`，否则"这段录制改过没有"这个问题在 diff 里永远为真。
pub fn filter_headers(headers: impl Iterator<Item = (String, String)>) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    for (k, v) in headers {
        let lower = k.trim().to_ascii_lowercase();
        if !REPLAYABLE_HEADERS.contains(&lower.as_str()) {
            continue;
        }
        // 只保留第一条：多值头（如重复的 Accept）在回放侧没有语义收益
        out.entry(lower).or_insert_with(|| v);
    }
    out
}

/// 字段名是否敏感（大小写无关，忽略 `_` 与 `-`）。
pub fn is_sensitive_field(name: &str) -> bool {
    let normalized: String = name
        .chars()
        .filter(|c| *c != '_' && *c != '-')
        .collect::<String>()
        .to_ascii_lowercase();
    let matched = |candidate: &str| {
        SENSITIVE_FIELD_NAMES
            .iter()
            .any(|s| s.replace(['_', '-'], "") == candidate)
    };
    if matched(&normalized) {
        return true;
    }
    // 自定义头形态：`X-API-KEY` / `X-Token` 归一后是 `xapikey` / `xtoken`，
    // 与登记名差一个 `x` 前缀。只在这一种形态上放宽（剥掉 `x` 后仍需**完全相等**），
    // 不能改成 `contains`——那会把 `tokenCount`、`passwordHint` 这类业务字段一起折叠，
    // 变成"脱敏把正常数据吃了"的反向故障。
    normalized
        .strip_prefix('x')
        .is_some_and(|rest| !rest.is_empty() && matched(rest))
}

/// JSON 风格请求体的敏感字段折叠。
///
/// 实现成**字符级扫描**而不是先 `serde_json::from_str` 再序列化，理由有三：
/// 1. 请求体可能不是合法 JSON（表单、混合内容），解析失败就整段不脱敏 = 密码入库；
/// 2. 反序列化再序列化会改变字段顺序与数字格式，"录制内容是否变化"失去可比性；
/// 3. 本函数是纯字符串变换，可被单测逐形态钉住。
///
/// 覆盖三种常见形态：`"password":"x"`、`password=x`、`"password": 123`。
pub fn redact_json_like(body: &str) -> String {
    let mut out = String::with_capacity(body.len());
    let bytes: Vec<char> = body.chars().collect();
    let mut i = 0usize;
    while i < bytes.len() {
        let c = bytes[i];
        // 只在"键的起始位置"尝试匹配：前一个非空白字符是 { , 或行首，或 & 分隔
        let at_key_start = {
            let mut j = i;
            while j > 0 && bytes[j - 1].is_whitespace() {
                j -= 1;
            }
            j == 0 || matches!(bytes[j - 1], '{' | ',' | '&' | ';')
        };
        if at_key_start && (c == '"' || c.is_ascii_alphabetic() || c == '_') {
            // 取键名
            let quote = c == '"';
            let mut k = if quote { i + 1 } else { i };
            let key_start = k;
            while k < bytes.len()
                && (bytes[k].is_alphanumeric() || bytes[k] == '_' || bytes[k] == '-')
            {
                k += 1;
            }
            let key: String = bytes[key_start..k].iter().collect();
            // 找键后的分隔符（: 或 =）
            let mut s = k;
            if quote && s < bytes.len() && bytes[s] == '"' {
                s += 1;
            }
            while s < bytes.len() && bytes[s].is_whitespace() {
                s += 1;
            }
            let sep = if s < bytes.len() && (bytes[s] == ':' || bytes[s] == '=') {
                Some(bytes[s])
            } else {
                None
            };
            // 只有"敏感键 + 后面真有分隔符"才需要吞掉值：其它情形按键原文复制
            if let Some(sep) = sep.filter(|_| is_sensitive_field(&key)) {
                // 复制 "key" + sep + 空白
                out.extend(bytes[i..=s].iter());
                let mut v = s + 1;
                while v < bytes.len() && bytes[v].is_whitespace() {
                    out.push(bytes[v]);
                    v += 1;
                }
                // 吃掉值（字符串到闭合引号；裸值到分隔符）
                if v < bytes.len() && bytes[v] == '"' {
                    v += 1;
                    while v < bytes.len() && bytes[v] != '"' {
                        if bytes[v] == '\\' {
                            v += 1;
                        }
                        v += 1;
                    }
                    v = (v + 1).min(bytes.len());
                } else {
                    while v < bytes.len() && !matches!(bytes[v], ',' | '}' | '&' | ';') {
                        v += 1;
                    }
                }
                out.push_str("\"***\"");
                let _ = sep;
                i = v;
                continue;
            }
        }
        out.push(c);
        i += 1;
    }
    out
}

/// 查询串脱敏：`a=1&password=x` → `a=1&password=***`。
pub fn redact_query(query: &str) -> String {
    query
        .split('&')
        .filter(|p| !p.is_empty())
        .map(|pair| match pair.split_once('=') {
            Some((k, _)) if is_sensitive_field(k) => format!("{k}=***"),
            _ => pair.to_string(),
        })
        .collect::<Vec<_>>()
        .join("&")
}

/// 按字节上限截断（**按字符边界**，不切坏 UTF-8）。
///
/// 返回 `(截断后文本, 是否截断)`。调用方必须把"截断了"记进正文（[`truncate_body`]），
/// 否则回放时发出去的是半截 JSON——比不录更坏，因为它看起来是完整的一步。
pub fn truncate_bytes(text: &str, max: usize) -> (String, bool) {
    if text.len() <= max {
        return (text.to_string(), false);
    }
    let mut end = max;
    while end > 0 && !text.is_char_boundary(end) {
        end -= 1;
    }
    (text[..end].to_string(), true)
}

/// 截断请求体并追加显式标记。
pub fn truncate_body(text: &str) -> (String, bool) {
    let (cut, truncated) = truncate_bytes(text, MAX_CAPTURED_BODY_BYTES);
    if truncated {
        (
            format!(
                "{cut}\n/* [stepby] 请求体超过 {MAX_CAPTURED_BODY_BYTES} 字节已截断，回放时该步不可直接使用 */"
            ),
            true,
        )
    } else {
        (cut, false)
    }
}

/// `{{name}}` 变量替换。
///
/// 缺变量时返回**具体是哪个变量**的错误：回放的失败原因必须能指到"哪一步缺哪个值"，
/// 否则使用者只能拿到一句"回放失败"。
pub fn substitute_vars(template: &str, vars: &BTreeMap<String, String>) -> Result<String, String> {
    let mut out = String::with_capacity(template.len());
    let mut rest = template;
    while let Some(start) = rest.find("{{") {
        out.push_str(&rest[..start]);
        let after = &rest[start + 2..];
        let Some(end) = after.find("}}") else {
            // 未闭合：原样保留（不制造新的失败模式）
            out.push_str(&rest[start..]);
            return Ok(out);
        };
        let name = after[..end].trim();
        match vars.get(name) {
            Some(v) => out.push_str(v),
            None => return Err(format!("缺少变量 {{{{{name}}}}}")),
        }
        rest = &after[end + 2..];
    }
    out.push_str(rest);
    Ok(out)
}

/// 从响应体里按点路径取值（用于把上一步的返回值喂给下一步）。
///
/// 支持 `data.rows.0.id` 这种形态。**只支持对象键与数组下标**，不实现完整 JSONPath：
/// 一个能被三条断言钉住的最小实现，好过一个"看起来支持一切"却没人能验证的解析器。
pub fn extract_json_path(body: &str, path: &str) -> Option<String> {
    let value: serde_json::Value = serde_json::from_str(body).ok()?;
    let mut cur = &value;
    for seg in path.split('.') {
        if seg.is_empty() {
            return None;
        }
        if let Ok(idx) = seg.parse::<usize>() {
            cur = cur.get(idx)?;
        } else {
            cur = cur.get(seg)?;
        }
    }
    Some(match cur {
        serde_json::Value::String(s) => s.clone(),
        other => other.to_string(),
    })
}

/// 归一化"返回值抽取规则"：`{"变量名":"点路径"}`。
///
/// 校验三条（都是回放期**无法补救**的形态，只能在写入侧挡）：
/// 1. 必须是 JSON 对象，值必须是字符串；
/// 2. 变量名只能由字母/数字/下划线组成（它要能出现在 `{{name}}` 里）；
/// 3. 点路径的每一段只能是非空字母/数字/下划线（不允许 `$`、`[]`、`..`）。
///
/// 输出按变量名排序：同样的规则两次保存必须得到逐字节相同的字符串，
/// 否则"这段录制改过没有"在 diff 里永远为真。
pub fn normalize_extract_rules(raw: &str) -> Result<String, ServiceError> {
    let parsed: serde_json::Value = serde_json::from_str(raw).map_err(|e| {
        ServiceError::bad_request(&format!(
            "{}: {e}",
            pick("抽取规则不是合法 JSON", "Extract rules must be valid JSON")
        ))
    })?;
    let obj = parsed.as_object().ok_or_else(|| {
        ServiceError::bad_request(pick(
            "抽取规则必须是 {\"变量名\":\"点路径\"} 形态的对象",
            "Extract rules must be an object of {\"var\":\"dot.path\"}",
        ))
    })?;
    let mut out = BTreeMap::new();
    for (k, v) in obj {
        let key = k.trim();
        if key.is_empty() || !key.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
            return Err(ServiceError::bad_request(&format!(
                "{}: {k}",
                pick(
                    "变量名只能包含字母/数字/下划线",
                    "Variable names may only contain letters, digits and underscores"
                )
            )));
        }
        let Some(path) = v.as_str() else {
            return Err(ServiceError::bad_request(pick(
                "抽取路径必须是字符串",
                "Extract paths must be strings",
            )));
        };
        let path = path.trim();
        if path.is_empty()
            || !path.split('.').all(|seg| {
                !seg.is_empty() && seg.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
            })
        {
            return Err(ServiceError::bad_request(&format!(
                "{}: {path}",
                pick(
                    "点路径的每一段只能是非空字母/数字/下划线（如 data.rows.0.id）",
                    "Each dot-path segment must be non-empty alphanumerics (e.g. data.rows.0.id)"
                )
            )));
        }
        out.insert(key.to_string(), path.to_string());
    }
    serde_json::to_string(&out).map_err(|e| ServiceError::internal(&e.to_string()))
}

/// 解析抽取规则（回放侧调用，输入已由 [`normalize_extract_rules`] 归一）。
pub fn parse_extract_rules(raw: &str) -> BTreeMap<String, String> {
    serde_json::from_str::<BTreeMap<String, String>>(raw).unwrap_or_default()
}

/// 生成可执行脚本。
///
/// 三种格式共用一个**单一事实源**（同一份 `steps`），差别只在序列化外壳：
/// 各自写一遍循环必然漂（AGENTS ㉘）。
pub fn build_script(
    format: ScriptFormat,
    recording: &RecordingModel,
    steps: &[StepModel],
    base_url: &str,
) -> String {
    let base = base_url.trim_end_matches('/');
    match format {
        ScriptFormat::Curl => {
            let mut s = String::new();
            s.push_str("#!/usr/bin/env bash\n");
            s.push_str("# 由 Stepby 操作录制导出——按录制顺序重放这段业务流程\n");
            s.push_str(&format!(
                "# 录制：{}（{} 步）\n",
                recording.name,
                steps.len()
            ));
            s.push_str("# 用法：STEPBY_TOKEN=<你的令牌> [STEPBY_BASE=...] sh this.sh\n");
            s.push_str("set -euo pipefail\n");
            s.push_str(&format!("BASE=\"${{STEPBY_BASE:-{base}}}\"\n"));
            s.push_str("TOKEN=\"${STEPBY_TOKEN:?请先设置 STEPBY_TOKEN}\"\n");
            s.push_str("AUTH=(-H \"Authorization: Bearer $TOKEN\")\n\n");
            for st in steps {
                let url = step_url(base, st);
                s.push_str(&format!(
                    "# ---- 第 {} 步{} ----\n",
                    st.seq,
                    st.note
                        .as_ref()
                        .map(|n| format!("：{n}"))
                        .unwrap_or_default()
                ));
                s.push_str("curl -sS -X ");
                s.push_str(&st.method);
                s.push_str(" \"$BASE");
                s.push_str(url.trim_start_matches(base));
                s.push_str("\" \"${AUTH[@]}\"");
                if let Some(ct) = st.content_type.as_deref().filter(|c| !c.is_empty()) {
                    s.push_str(&format!(" -H 'Content-Type: {ct}'"));
                }
                s.push_str(&expect_suffix(st));
                if let Some(body) = st.body.as_deref().filter(|b| !b.is_empty()) {
                    s.push_str(&format!(" --data-binary {}", shell_single_quote(body)));
                }
                s.push('\n');
            }
            s
        }
        ScriptFormat::Http => {
            let mut s = String::new();
            s.push_str(&format!("# 录制：{}\n", recording.name));
            // .http 变量引用语法是 {{name}}，定义语法是 @name = value
            // （JetBrains HTTP Client 与 VS Code REST Client 一致）；写成 {name} 不会被解析。
            s.push_str("# 变量：把 @token 换成你自己的访问令牌，脚本不内联任何真实凭据\n");
            s.push_str(&format!("@base = {base}\n"));
            s.push_str("@token = <在此粘贴你的访问令牌>\n\n");
            for st in steps {
                s.push_str("###\n");
                s.push_str(&format!(
                    "### 第 {} 步{}\n",
                    st.seq,
                    st.note
                        .as_ref()
                        .map(|n| format!("：{n}"))
                        .unwrap_or_default()
                ));
                s.push_str(&format!(
                    "{} {{{{base}}}}{}\n",
                    st.method,
                    step_path_with_query(st)
                ));
                s.push_str("Authorization: Bearer {{token}}\n");
                if let Some(ct) = st.content_type.as_deref().filter(|c| !c.is_empty()) {
                    s.push_str(&format!("Content-Type: {ct}\n"));
                }
                if let Some(body) = st.body.as_deref().filter(|b| !b.is_empty()) {
                    s.push('\n');
                    s.push_str(body);
                    s.push('\n');
                }
                s.push('\n');
            }
            s
        }
        ScriptFormat::Json => {
            let steps_json: Vec<serde_json::Value> = steps
                .iter()
                .map(|st| {
                    serde_json::json!({
                        "seq": st.seq,
                        "method": st.method,
                        "path": st.path,
                        "queryString": st.query_string,
                        "contentType": st.content_type,
                        "body": st.body,
                        "expectStatus": st.expect_status,
                        "note": st.note,
                    })
                })
                .collect();
            serde_json::to_string_pretty(&serde_json::json!({
                "name": recording.name,
                "description": recording.description,
                "baseUrl": base,
                "steps": steps_json,
            }))
            .unwrap_or_else(|_| "{}".to_string())
        }
    }
}

fn step_url(base: &str, st: &StepModel) -> String {
    let mut u = format!("{base}{}", st.path);
    if let Some(q) = st.query_string.as_deref().filter(|q| !q.is_empty()) {
        u.push('?');
        u.push_str(q);
    }
    u
}

fn step_path_with_query(st: &StepModel) -> String {
    match st.query_string.as_deref().filter(|q| !q.is_empty()) {
        Some(q) => format!("{}?{}", st.path, q),
        None => st.path.clone(),
    }
}

fn expect_suffix(st: &StepModel) -> String {
    match st.expect_status {
        Some(code) => format!(" \\\n  -w '\\n[stepby] 期望状态码 {code}，实际 %{{http_code}}\\n'",),
        None => String::new(),
    }
}

/// POSIX shell 单引号转义（`'` → `'\''`）。
fn shell_single_quote(raw: &str) -> String {
    format!("'{}'", raw.replace('\'', "'\\''"))
}

// ==================== Service ====================

pub struct OpRecordingService {
    repo: OpRecordingRepository,
    task_service: SysTaskService,
}

impl OpRecordingService {
    pub fn new(db: sea_orm::DatabaseConnection) -> Self {
        Self {
            repo: OpRecordingRepository::new(db.clone()),
            task_service: SysTaskService::new(db),
        }
    }

    pub fn repo(&self) -> &OpRecordingRepository {
        &self.repo
    }

    pub fn task_service(&self) -> &SysTaskService {
        &self.task_service
    }

    // ---------- 抬头 ----------

    pub async fn page(
        &self,
        dto: RecordingQueryDto,
        tenant_scope: Option<i64>,
    ) -> Result<(Vec<RecordingModel>, u64), ServiceError> {
        let page: PageDomain = (&dto).into();
        let sort = match page.order_by_column.as_deref() {
            Some(col) => {
                let column = match sort::camel_to_snake(col).as_str() {
                    "recording_id" => Some(RecordingColumn::RecordingId),
                    "name" => Some(RecordingColumn::Name),
                    "status" => Some(RecordingColumn::Status),
                    "source" => Some(RecordingColumn::Source),
                    "step_count" => Some(RecordingColumn::StepCount),
                    "last_run_time" => Some(RecordingColumn::LastRunTime),
                    "create_time" => Some(RecordingColumn::CreateTime),
                    "update_time" => Some(RecordingColumn::UpdateTime),
                    _ => None,
                };
                column.map(|c| SortOrder::new(c, sort::parse_direction(page.is_asc.as_deref())))
            }
            None => None,
        };
        Ok(self
            .repo
            .find_page_filtered(
                page.offset(),
                page.limit(),
                dto.name.as_deref().filter(|s| !s.is_empty()),
                dto.status.as_deref().filter(|s| !s.is_empty()),
                dto.source.as_deref().filter(|s| !s.is_empty()),
                tenant_scope,
                sort,
            )
            .await?)
    }

    /// 详情：抬头 + 步骤（**两条查询都按租户收敛**，不是只查抬头再无条件取步）。
    pub async fn detail(
        &self,
        recording_id: i64,
        tenant_scope: Option<i64>,
    ) -> Result<RecordingDetailVo, ServiceError> {
        let recording = self
            .repo
            .find_by_id(recording_id)
            .await?
            .filter(|r| tenant_scope.is_none_or(|t| r.tenant_id == t))
            .ok_or_else(|| ServiceError::not_found(pick("录制不存在", "Recording not found")))?;
        let steps = self.repo.steps_of(recording_id).await?;
        // 步骤表自带 tenant_id：逐行再收敛一次（防历史数据跨租户串号）
        let steps = steps
            .into_iter()
            .filter(|s| tenant_scope.is_none_or(|t| s.tenant_id == t))
            .collect();
        Ok(RecordingDetailVo { recording, steps })
    }

    pub async fn create(
        &self,
        dto: RecordingCreateDto,
        tenant_id: i64,
        owner_id: Option<i64>,
        owner_name: &str,
    ) -> Result<RecordingModel, ServiceError> {
        let name = dto.name.trim();
        if name.is_empty() || name.chars().count() > 120 {
            return Err(ServiceError::bad_request(pick(
                "录制名称长度必须在 1~120 之间",
                "Recording name length must be 1..=120",
            )));
        }
        let source = match dto.source.as_deref().unwrap_or("ui") {
            s @ ("ui" | "api" | "import") => s.to_string(),
            other => {
                return Err(ServiceError::bad_request(&format!(
                    "{}: {other}",
                    pick("不支持的来源", "Unsupported source")
                )));
            }
        };
        let now = crate::common::datetime::now_naive();
        let model = self
            .repo
            .insert(RecordingActiveModel {
                tenant_id: Set(tenant_id),
                name: Set(name.to_string()),
                description: Set(dto
                    .description
                    .map(|d| d.trim().to_string())
                    .filter(|d| !d.is_empty())),
                source: Set(source),
                status: Set("ready".to_string()),
                step_count: Set(0),
                last_run_status: Set(None),
                last_run_time: Set(None),
                owner_id: Set(owner_id),
                owner_name: Set(Some(owner_name.to_string())),
                create_time: Set(Some(now)),
                update_time: Set(Some(now)),
                ..Default::default()
            })
            .await?;
        Ok(model)
    }

    pub async fn update(
        &self,
        dto: RecordingUpdateDto,
        tenant_scope: Option<i64>,
    ) -> Result<u64, ServiceError> {
        let name = dto.name.trim();
        if name.is_empty() || name.chars().count() > 120 {
            return Err(ServiceError::bad_request(pick(
                "录制名称长度必须在 1~120 之间",
                "Recording name length must be 1..=120",
            )));
        }
        let status = match dto.status.as_deref().unwrap_or("ready") {
            s @ ("draft" | "ready" | "archived") => s.to_string(),
            other => {
                return Err(ServiceError::bad_request(&format!(
                    "{}: {other}",
                    pick("不支持的状态", "Unsupported status")
                )));
            }
        };
        let now = crate::common::datetime::now_naive();
        let affected = self
            .repo
            .touch_meta(
                dto.recording_id,
                tenant_scope,
                name.to_string(),
                dto.description
                    .map(|d| d.trim().to_string())
                    .filter(|d| !d.is_empty()),
                status,
                now,
            )
            .await?;
        if affected == 0 {
            return Err(ServiceError::not_found(pick(
                "录制不存在或无权修改",
                "Recording not found or not editable",
            )));
        }
        Ok(affected)
    }

    /// 批量删除。
    ///
    /// **先把请求集收敛成授权集再删子表**：直接 `purge_children(请求 ids)` 会让一次越权
    /// 删除把他租户的步骤/运行记录清掉（b74 B5 实证的同族形态）。
    pub async fn delete(
        &self,
        ids: &[i64],
        tenant_scope: Option<i64>,
    ) -> Result<u64, ServiceError> {
        let authorized = self.repo.existing_ids(ids, tenant_scope).await?;
        if authorized.is_empty() {
            return Ok(0);
        }
        let authorized: Vec<i64> = authorized.into_iter().collect();
        self.repo.purge_children(&authorized).await?;
        Ok(self.repo.delete_by_ids(&authorized, tenant_scope).await?)
    }

    // ---------- 步骤 ----------

    pub async fn append_step(
        &self,
        recording_id: i64,
        tenant_id: i64,
        tenant_scope: Option<i64>,
        dto: StepWriteDto,
        now: NaiveDateTime,
    ) -> Result<StepModel, ServiceError> {
        let recording = self
            .repo
            .find_by_id(recording_id)
            .await?
            .filter(|r| tenant_scope.is_none_or(|t| r.tenant_id == t))
            .ok_or_else(|| ServiceError::not_found(pick("录制不存在", "Recording not found")))?;
        if recording.status == "archived" {
            return Err(ServiceError::bad_request(pick(
                "已归档的录制不可再追加步骤",
                "Archived recordings cannot accept new steps",
            )));
        }
        if recording.step_count >= MAX_STEPS_PER_RECORDING {
            return Err(ServiceError::bad_request(&format!(
                "{} ({MAX_STEPS_PER_RECORDING})",
                pick("该录制步骤数已达上限", "Recording reached the step limit")
            )));
        }
        let method = dto.method.trim().to_ascii_uppercase();
        if !matches!(
            method.as_str(),
            "GET" | "POST" | "PUT" | "PATCH" | "DELETE" | "HEAD" | "OPTIONS"
        ) {
            return Err(ServiceError::bad_request(pick(
                "不支持的 HTTP 方法",
                "Unsupported HTTP method",
            )));
        }
        validate_step_path(&dto.path).map_err(ServiceError::bad_request)?;

        let query_string = dto
            .query_string
            .map(|q| redact_query(q.trim_start_matches('?')))
            .filter(|q| !q.is_empty())
            .map(|q| truncate_bytes(&q, MAX_CAPTURED_QUERY_BYTES).0);
        let (body, _truncated) = match dto.body.filter(|b| !b.is_empty()) {
            Some(b) => {
                let redacted = redact_json_like(&b);
                let (cut, t) = truncate_body(&redacted);
                (Some(cut), t)
            }
            None => (None, false),
        };
        let content_type = if body.is_some() {
            Some("application/json".to_string())
        } else {
            None
        };
        // 抽取规则：必须是"变量名 → 点路径"的字符串映射。非法形态在写入侧就拒绝，
        // 而不是留到回放时才发现"这一步永远抽不到值"。
        let extract_json = match dto.extract_json.filter(|e| !e.trim().is_empty()) {
            Some(raw) => Some(normalize_extract_rules(&raw)?),
            None => None,
        };
        let (model, _seq) = self
            .repo
            .append_step(
                recording_id,
                tenant_id,
                StepSeed {
                    method,
                    path: dto.path.trim().to_string(),
                    query_string,
                    content_type,
                    body,
                    headers_json: None,
                    extract_json,
                    expect_status: dto.expect_status,
                    note: dto.note.map(|n| truncate_bytes(&n, 200).0),
                },
                now,
            )
            .await?;
        Ok(model)
    }

    /// 中间件采集入口（内部调用，已由中间件完成权限与租户判定）。
    pub async fn capture_step(
        &self,
        recording_id: i64,
        tenant_id: i64,
        method: &str,
        path: &str,
        query_string: Option<String>,
        content_type: Option<String>,
        body: Option<String>,
        headers_json: Option<String>,
        now: NaiveDateTime,
    ) -> Result<StepModel, ServiceError> {
        let (model, _seq) = self
            .repo
            .append_step(
                recording_id,
                tenant_id,
                StepSeed {
                    method: method.to_ascii_uppercase(),
                    path: path.to_string(),
                    query_string,
                    content_type,
                    body,
                    headers_json,
                    extract_json: None,
                    expect_status: None,
                    note: None,
                },
                now,
            )
            .await?;
        Ok(model)
    }

    pub async fn delete_step(
        &self,
        recording_id: i64,
        step_id: i64,
        tenant_scope: Option<i64>,
    ) -> Result<i32, ServiceError> {
        let removed = self
            .repo
            .delete_step(recording_id, step_id, tenant_scope)
            .await?;
        if removed == 0 {
            return Err(ServiceError::not_found(pick(
                "步骤不存在或无权删除",
                "Step not found or not deletable",
            )));
        }
        let now = crate::common::datetime::now_naive();
        self.repo.compact_seq(recording_id, now).await?;
        let count = self.repo.recount_steps(recording_id, now).await?;
        Ok(count)
    }

    pub async fn clear_steps(
        &self,
        recording_id: i64,
        tenant_scope: Option<i64>,
    ) -> Result<i32, ServiceError> {
        let recording = self
            .repo
            .find_by_id(recording_id)
            .await?
            .filter(|r| tenant_scope.is_none_or(|t| r.tenant_id == t))
            .ok_or_else(|| ServiceError::not_found(pick("录制不存在", "Recording not found")))?;
        let _ = recording;
        self.repo.delete_steps_of(recording_id).await?;
        let now = crate::common::datetime::now_naive();
        Ok(self.repo.recount_steps(recording_id, now).await?)
    }

    // ---------- 导出 ----------

    pub async fn export_script(
        &self,
        recording_id: i64,
        tenant_scope: Option<i64>,
        format: ScriptFormat,
        base_url: &str,
    ) -> Result<(String, String, String), ServiceError> {
        let detail = self.detail(recording_id, tenant_scope).await?;
        if detail.steps.is_empty() {
            return Err(ServiceError::bad_request(pick(
                "该录制还没有任何步骤，无法导出",
                "This recording has no steps to export",
            )));
        }
        let content = build_script(format, &detail.recording, &detail.steps, base_url);
        let filename = format!(
            "recording-{}-{}.{}",
            detail.recording.recording_id,
            sanitize_filename(&detail.recording.name),
            format.extension()
        );
        Ok((filename, format.content_type().to_string(), content))
    }
}

/// 文件名安全化（保留字母/数字/中日韩字符，其余折叠成 `-`）。
pub fn sanitize_filename(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    let mut last_dash = false;
    for c in raw.chars() {
        if c.is_alphanumeric() {
            out.push(c);
            last_dash = false;
        } else if !last_dash {
            out.push('-');
            last_dash = true;
        }
    }
    let trimmed = out.trim_matches('-').to_string();
    if trimmed.is_empty() {
        "recording".to_string()
    } else {
        truncate_bytes(&trimmed, 60).0
    }
}

/// 收集一组录制 ID 的授权子集（供 handler 侧删除前调用）。
pub async fn authorized_ids(
    repo: &OpRecordingRepository,
    ids: &[i64],
    tenant_scope: Option<i64>,
) -> Result<BTreeSet<i64>, ServiceError> {
    Ok(repo.existing_ids(ids, tenant_scope).await?)
}
