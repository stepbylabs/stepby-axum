//! stepby-axum 构建脚本（R6-BE-ENG-20）
//!
//! 功能：
//!   1. 生成构建时间戳（UTC 秒级），通过 `cargo:rustc-env=BUILD_TIMESTAMP=...` 注入
//!      主程序可通过 `env!("BUILD_TIMESTAMP")` 在编译时读取，用于版本诊断与日志溯源
//!   2. 尝试读取 Git 提交哈希（不强制依赖 git，失败则使用占位符）
//!      主程序可通过 `env!("GIT_HASH")` / `option_env!("GIT_HASH")` 读取
//!   3. 校验前端构建产物 `frontend-dist/` 是否存在
//!      若不存在则 panic 提示先执行 `pnpm build:embedded` 并复制到 frontend-dist
//!
//! 重运行策略：
//!   - 仅当 build.rs 自身变更时重新运行（避免每次编译都更新时间戳，
//!     否则会导致增量编译失效）
//!   - 若需要每次构建都刷新时间戳，可移除 rerun-if-changed 指令
//!
//! 注意：
//!   - 使用 std::time::SystemTime 而非 chrono，避免在 build script 中引入额外依赖
//!   - Git 信息通过命令行 `git` 工具读取，CI 环境（浅克隆）可能不可用

use std::path::Path;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

fn main() {
    // ===== 构建时间戳（UTC 秒级）=====
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    println!("cargo:rustc-env=BUILD_TIMESTAMP={}", timestamp);

    // ===== Git 提交哈希（短哈希）=====
    // 失败时不阻断构建，使用 "unknown" 占位符
    let git_hash = Command::new("git")
        .args(["rev-parse", "--short", "HEAD"])
        .output()
        .ok()
        .and_then(|output| {
            if output.status.success() {
                String::from_utf8(output.stdout)
                    .ok()
                    .map(|s| s.trim().to_string())
            } else {
                None
            }
        })
        .unwrap_or_else(|| "unknown".to_string());
    println!("cargo:rustc-env=GIT_HASH={}", git_hash);

    // ===== Git 工作树状态（dirty / clean）=====
    // 若存在未提交改动，标记为 "dirty"，便于排查构建来源
    let git_dirty = Command::new("git")
        .args(["status", "--porcelain"])
        .output()
        .ok()
        .map(|output| !output.stdout.is_empty())
        .unwrap_or(false);
    println!(
        "cargo:rustc-env=GIT_DIRTY={}",
        if git_dirty { "dirty" } else { "clean" }
    );

    // ===== 校验前端构建产物（rust-embed 编译时强制要求） =====
    // rust-embed 在编译时扫描 folder 指定的目录，若目录不存在会 panic
    // 此处提前校验并给出友好错误提示，避免编译到一半才失败
    //
    // 使用 `frontend-dist/`（项目内路径）而非 `../stepby-vue/dist/`：
    // - cross 交叉编译时，容器只自动挂载 Cargo.toml 所在目录
    // - `../stepby-vue/dist` 需要额外挂载，而中文路径（如 `桌面`）在 Docker 挂载时可能失败
    // - `frontend-dist/` 在项目内部，cross 自动挂载，无需额外配置
    let frontend_dist = Path::new("frontend-dist");
    if !frontend_dist.exists() {
        panic!(
            "\n\n========================================\n\
             前端构建产物不存在: frontend-dist/\n\
             请先执行构建脚本（会自动复制 stepby-vue/dist → frontend-dist）：\n\
             \n  powershell -File scripts/build-all.ps1\n\
             \n或手动复制：\n\
             \n  pnpm --dir stepby-vue build:embedded\n\
             \n  xcopy /E /I /Y stepby-vue\\dist stepby-axum\\frontend-dist\n\
             ========================================\n"
        );
    }

    // 进一步检查 index.html 是否存在（dist 目录可能为空）
    let index_html = frontend_dist.join("index.html");
    if !index_html.exists() {
        panic!(
            "\n\n========================================\n\
             前端入口文件不存在: {}\n\
             frontend-dist 目录可能为空，请重新执行构建脚本\n\
             ========================================\n",
            index_html.display()
        );
    }

    // 监听 frontend-dist 目录变化，触发重新编译（嵌入最新前端资源）
    println!("cargo:rerun-if-changed=frontend-dist");

    // 仅在 build.rs 自身变更时重新运行，避免每次构建都更新时间戳
    // 导致增量编译失效
    println!("cargo:rerun-if-changed=build.rs");
}
