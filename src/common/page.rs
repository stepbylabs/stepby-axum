// axum-backend/src/common/page.rs

use serde::Deserialize;
use utoipa::ToSchema;

/// 分页查询参数（对齐前端 PageDomain）
/// 前端通过 GET 查询串传递：?pageNum=1&pageSize=10&orderByColumn=createTime&isAsc=desc
#[derive(Debug, Clone, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct PageDomain {
    /// 页码，从 1 开始（默认 1）
    #[serde(default = "default_page_num")]
    pub page_num: u64,

    /// 每页条数（默认 10，上限 100）
    #[serde(default = "default_page_size")]
    pub page_size: u64,

    /// 排序字段（可选）
    pub order_by_column: Option<String>,

    /// 排序方向：asc / desc（可选）
    pub is_asc: Option<String>,
}

/// 默认页码
pub fn default_page_num() -> u64 {
    1
}

/// 默认每页条数
pub fn default_page_size() -> u64 {
    10
}

/// 每页条数上限（防止恶意大分页拖垮 DB）
pub const MAX_PAGE_SIZE: u64 = 100;

/// 导出接口单次返回行数上限（防止 OOM 与长事务拖垮 DB）
///
/// 各 service 的 `export_*` 方法在调用 repository 全量/大分页查询时，
/// 应统一使用此常量作为 limit，避免 `i32::MAX` 无上限或被 PageDomain
/// 截断为 100 行导致的导出数据错误。
pub const EXPORT_MAX_ROWS: u64 = 50000;

impl PageDomain {
    /// 计算 offset（0-based）
    pub fn offset(&self) -> u64 {
        // 使用已封顶的 limit()（page_size.min(MAX_PAGE_SIZE)），并对乘法做 saturating，
        // 防止超大 page_size/page_num 触发 u64 整数溢出（release 回绕 / debug panic，构成 DoS 面）
        // P2：page_num=0 防御性归一到第 1 页（原 saturating_sub 得 0，与第 1 页 offset 相同，
        // 前端误传 0 会重复返回第一页，语义不明确）
        let page_num = if self.page_num == 0 { 1 } else { self.page_num };
        page_num.saturating_sub(1).saturating_mul(self.limit())
    }

    /// 获取 limit（即 page_size，已限制上限）
    pub fn limit(&self) -> u64 {
        self.page_size.min(MAX_PAGE_SIZE)
    }

    /// 校验排序字段名是否为合法 SQL 标识符（ERR-30 防注入）
    ///
    /// 规则：仅允许 ASCII 字母开头，后跟字母/数字/下划线，长度 ≤ 64。
    /// 拒绝含空格、引号、分号、逗号等特殊字符的输入，防止 SQL 注入。
    pub fn is_valid_order_by_column(col: &str) -> bool {
        if col.is_empty() || col.len() > 64 {
            return false;
        }
        let mut chars = col.chars();
        let Some(first) = chars.next() else {
            return false;
        };
        if !(first.is_ascii_alphabetic() || first == '_') {
            return false;
        }
        chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
    }

    /// 校验排序方向是否合法（ERR-31 白名单）
    ///
    /// 允许值：asc / desc / ascending / descending（不区分大小写）
    pub fn is_valid_is_asc(asc: &str) -> bool {
        matches!(
            asc.to_lowercase().as_str(),
            "asc" | "desc" | "ascending" | "descending"
        )
    }

    /// 校验并净化排序字段（非法值置为 None，防御性丢弃而非报错）
    ///
    /// 调用方在构造 PageDomain 后应调用此方法，确保 order_by_column 和 is_asc
    /// 不含恶意输入。当前各 service 的 From impl 均将排序字段置为 None，
    /// 此方法为后续启用动态排序时的安全防线。
    pub fn sanitize_order_fields(&mut self) {
        if let Some(ref col) = self.order_by_column
            && !Self::is_valid_order_by_column(col)
        {
            self.order_by_column = None;
        }
        if let Some(ref asc) = self.is_asc
            && !Self::is_valid_is_asc(asc)
        {
            self.is_asc = None;
        }
    }
}

impl Default for PageDomain {
    fn default() -> Self {
        Self {
            page_num: default_page_num(),
            page_size: default_page_size(),
            order_by_column: None,
            is_asc: None,
        }
    }
}
