#!/usr/bin/env bash
# b68 Rust 覆盖率缺口分析：llvm-cov 全量 lib，输出按未覆盖行数排序的 Top 缺口
set -uo pipefail
cd /d/Projects/stepby/stepby-axum || exit 2
cargo llvm-cov --lib --summary-only 2>&1 | tail -120
echo "=== LLVMCOV-DONE rc=$? ==="
