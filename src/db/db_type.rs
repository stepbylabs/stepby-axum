//! 数据库类型检测工具
//!
//! 根据 DATABASE_URL 协议前缀自动判断数据库类型，
//! 用于迁移和 SQL 兼容性处理。

use std::fmt;

/// 解析数据库 URL 时的错误
#[derive(Debug)]
pub enum DbTypeError {
    /// 不支持的协议前缀
    UnsupportedScheme(String),
}

impl fmt::Display for DbTypeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DbTypeError::UnsupportedScheme(scheme) => {
                write!(
                    f,
                    "不支持的数据库 URL 协议前缀 '{}'，支持 mysql://, postgres://, postgresql://, sqlite://",
                    scheme
                )
            }
        }
    }
}

impl std::error::Error for DbTypeError {}

/// 支持的数据库类型
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DbType {
    Mysql,
    Postgres,
    Sqlite,
}

impl DbType {
    /// 从数据库连接 URL 检测数据库类型（返回 Result，不 panic）
    ///
    /// 支持的 URL 前缀：
    /// - `mysql://` → Mysql
    /// - `postgres://` 或 `postgresql://` → Postgres
    /// - `sqlite://` → Sqlite
    pub fn from_url(url: &str) -> Result<Self, DbTypeError> {
        if url.starts_with("mysql://") {
            Ok(DbType::Mysql)
        } else if url.starts_with("postgres://") || url.starts_with("postgresql://") {
            Ok(DbType::Postgres)
        } else if url.starts_with("sqlite://") {
            Ok(DbType::Sqlite)
        } else {
            // 提取协议前缀用于错误提示（不含密码）
            let scheme = url.split("://").next().unwrap_or("unknown");
            Err(DbTypeError::UnsupportedScheme(scheme.to_string()))
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mysql_url() {
        assert_eq!(
            DbType::from_url("mysql://user:pass@localhost:3306/db").unwrap(),
            DbType::Mysql
        );
    }

    #[test]
    fn test_postgres_url() {
        assert_eq!(
            DbType::from_url("postgres://user:pass@localhost:5432/db").unwrap(),
            DbType::Postgres
        );
        assert_eq!(
            DbType::from_url("postgresql://user:pass@localhost:5432/db").unwrap(),
            DbType::Postgres
        );
    }

    #[test]
    fn test_sqlite_url() {
        assert_eq!(
            DbType::from_url("sqlite://./data/stepby.db?mode=rwc").unwrap(),
            DbType::Sqlite
        );
    }

    #[test]
    fn test_unsupported_scheme_returns_error() {
        let result = DbType::from_url("mongodb://localhost:27017/db");
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("mongodb"));
        assert!(err.to_string().contains("mysql://"));
    }

    #[test]
    fn test_name() {
        assert_eq!(DbType::Mysql.name(), "MySQL");
        assert_eq!(DbType::Postgres.name(), "PostgreSQL");
        assert_eq!(DbType::Sqlite.name(), "SQLite");
    }
}
