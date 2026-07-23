//! 数据库类型检测工具
//!
//! 根据 DATABASE_URL 协议前缀自动判断数据库类型，
//! 用于迁移和 SQL 兼容性处理。

/// 支持的数据库类型
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DbType {
    Mysql,
    Postgres,
    Sqlite,
}

impl DbType {
    /// 从数据库连接 URL 检测数据库类型
    ///
    /// 支持的 URL 前缀：
    /// - `mysql://` → Mysql
    /// - `postgres://` 或 `postgresql://` → Postgres
    /// - `sqlite://` → Sqlite
    ///
    /// # Panics
    /// 不支持的协议前缀会 panic（启动时配置错误）
    pub fn from_url(url: &str) -> Self {
        if url.starts_with("mysql://") {
            DbType::Mysql
        } else if url.starts_with("postgres://") || url.starts_with("postgresql://") {
            DbType::Postgres
        } else if url.starts_with("sqlite://") {
            DbType::Sqlite
        } else {
            // 脱敏：不打印完整 URL（可能含密码），仅提示协议前缀错误
            panic!("不支持的数据库 URL 协议前缀，支持 mysql://, postgres://, sqlite://")
        }
    }

    /// 返回数据库类型名称（用于日志输出）
    pub fn name(&self) -> &'static str {
        match self {
            DbType::Mysql => "MySQL",
            DbType::Postgres => "PostgreSQL",
            DbType::Sqlite => "SQLite",
        }
    }
}
