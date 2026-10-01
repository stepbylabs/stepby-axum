# `stepby-axum/fuzz` — 覆盖率导向 fuzz（cargo-fuzz）

`libFuzzer` 驱动的覆盖率导向 fuzz 工程，针对后端**安全边界上的纯函数**。
用 nightly 工具链运行，是一个**独立 workspace**（刻意不参与主 workspace 构建）。

---

## 1. 用途

对"输入不可信 + 一旦出错就是安全问题"的纯函数做**自动化对抗性输入搜索**：
libFuzzer 会观察代码覆盖率并持续变异输入，试图触发 `panic` / 断言失败 / 异常路径，
比手写用例更容易触达解析器的深分支与边界。

当前覆盖 4 个 target（与 `src/common/fuzz_invariants.rs` 的选点对齐）：

| target | 被测函数 | 关注的安全语义 |
| --- | --- | --- |
| `ssrf_url` | `common::ssrf::validate_url` | SSRF 第一道防线：只放行 http/https、放行必含非空主机名 |
| `clear_fields` | `common::clear_fields::resolve` | 「显式清空」契约：白名单、值/清空冲突、确定性 |
| `webhook_url` | `common::webhook::url_is_http` | 出站目标 scheme 判定等价性 |
| `excel_parse` | `common::excel::read_xlsx_rows` | 不可信 xlsx 字节解析：绝不 panic |

每个 target 的断言口径是 **"不 panic + 输出满足不变量"**，而不是"输出等于某个具体值"
——具体值由单元测试锁定，fuzz 只负责搜"会不会炸 / 会不会破契约"。

---

## 2. 如何本地跑

前置：已安装 nightly 工具链与 `cargo-fuzz`。

```powershell
# 一次性安装（网络可用）
rustup toolchain install nightly
cargo install cargo-fuzz --locked

# 进入 fuzz 工程（独立 workspace）
cd d:\Projects\stepby\stepby-axum\fuzz

# 编译全部 target（验证能真实编译）
cargo +nightly fuzz build

# 跑单个 target：2000 次 + 最多 20 秒（短跑冒烟）
cargo +nightly fuzz run ssrf_url -- -runs=2000 -max_total_time=20

# 长跑（取消轮数/时间上限，Ctrl-C 停止；corpus 会持续累积）
cargo +nightly fuzz run clear_fields
```

`-runs` / `-max_total_time` 之后的参数会透传给 libFuzzer；其它常用项：
`-jobs=N -workers=N`（并行）、`-rss_limit_mb=...`（内存上限）、`-print_final_stats=1`。

### Windows 运行期依赖（实测踩坑）

nightly 的 fuzz 二进制会**动态链接 AddressSanitizer 运行时** `clang_rt.asan_dynamic-x86_64.dll`
（可用 `dumpbin /dependents <target>.exe` 确认）。该 DLL 不在 rustup 工具链里，需把其所在目录
加入 `PATH`，否则直接运行会以 `0xC0000135`（STATUS_DLL_NOT_FOUND）退出：

```powershell
# LLVM 自带（版本号按本机实际）
$env:PATH = "C:\Program Files\LLVM\lib\clang\22\lib\windows;$env:PATH"
# 或 Visual Studio 自带（与 link.exe 用的同名 .lib 版本**必须一致**）
$env:PATH = "C:\Program Files\Microsoft Visual Studio\18\Community\VC\Tools\MSVC\14.51.36231\bin\Hostx64\x64;$env:PATH"
```

若加错版本目录会以 `0xC0000139`（STATUS_ENTRYPOINT_NOT_FOUND）退出——换成与链接期
`clang_rt.asan_dynamic-x86_64.lib` 同源的那个目录即可。Linux（CI 所用）无此问题。

---

## 3. 与 `src/common/fuzz_invariants.rs` 的分工

两者是**互补**关系，不是替代：

| | `src/common/fuzz_invariants.rs` | `fuzz/fuzz_targets/*.rs`（本目录） |
| --- | --- | --- |
| 工具链 | **stable**（进主 CI 门禁） | **nightly**（cargo-fuzz / libFuzzer） |
| 输入生成 | 固定种子 **LCG 确定性**伪随机 + 手写对抗输入池 | **覆盖率导向**变异（非确定性、持续进化） |
| 可复现 | 完全可复现（同种子同结果） | 发现 crash 后由 `artifacts/` 的最小输入复现 |
| 定位 | 快速回归门禁：每次 push/PR 都跑，防契约退化 | 夜间深挖：探索手写输入池到不了的解析路径 |
| 失败后果 | 直接阻断合并 | 夜间告警 + 保留复现输入，人工分析 |

一句话：**确定性不变式守门（每次提交），覆盖率 fuzz 探险（每天夜里）**。
断言口径刻意保持一致（同样的"不变量"），以便夜里 fuzz 发现的破约能立刻补成 stable 回归用例。

---

## 4. 如何看 crash

libFuzzer 触发崩溃（`panic` / 断言失败 / 内存错误）时，进程以**非 0 退出码**结束，
并在 `fuzz/artifacts/<target>/` 下留下**最小复现输入**文件（文件名形如 `crash-<hash>`）。

```powershell
# 用某个 crash 输入重放（会打印完整 panic 栈）
cargo +nightly fuzz run ssrf_url artifacts/ssrf_url/crash-<hash>

# 或直接看最小输入的原始字节
Format-Hex fuzz\artifacts\ssrf_url\crash-<hash>
```

处理原则：

1. **先判断是不是真 bug**：能稳定重放 ⇒ 是被测函数的真实缺陷（如某条 SSRF 绕过、
   `resolve` 放行了白名单外字段），**修业务代码**，不要改 fuzz 去迁就；
2. **若是 fuzz 工程自身问题**（如 target 里误把"合法 Err"当成崩溃、输入解码不当），
   修 `fuzz_targets/`；
3. 修复后把最小输入**补成 `fuzz_invariants.rs` / 单元测试的回归断言**，让 stable 门禁长期守住；
4. CI 失败时，`fuzz-artifacts` 这个 workflow artifact 里同时含 `artifacts/` 与 `corpus/`。

---

## 5. 目录结构

```
fuzz/
├── Cargo.toml            # 独立 workspace（自带 [workspace]），依赖 path = ".."
├── fuzz_targets/
│   ├── ssrf_url.rs
│   ├── clear_fields.rs
│   ├── webhook_url.rs
│   └── excel_parse.rs
├── corpus/<target>/      # libFuzzer 累积的语料（git 忽略，CI 缓存）
├── artifacts/<target>/   # crash 的最小复现输入（git 忽略）
└── target/               # 构建产物（git 忽略）
```

> 主 workspace（`../Cargo.toml`）的 `[workspace] exclude` 已排除 `fuzz`，
> 因此常规 `cargo build/test/clippy` 与 stable CI **不会**触碰本目录。

---

## 6. 夜间 CI

见仓库根 `.github/workflows/fuzz.yml`：仅 `schedule`（每日夜间）+ `workflow_dispatch` 触发，
用 nightly 安装 `cargo-fuzz` 并依次跑 4 个 target（每个固定轮数 + 墙钟上限），
发现 crash 时上传 `artifacts/` 与 `corpus/` 供定位。**刻意不在 push/PR 上触发**
（概率性耗时任务不适合做合并门禁——那个角色由 stable 的 `fuzz_invariants.rs` 承担）。