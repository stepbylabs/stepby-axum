// stepby-axum/benches/hot_paths.rs
//! 热路径性能基准（criterion）（AGENTS.md D11 硬基线：真实基准替换占位）
//!
//! # 基准覆盖面
//!
//! 全部为**真实业务纯函数**（无 mock、无 IO），按调用频次选取四类热路径：
//!
//! 1. `utils::masking`（业务展示口径脱敏，M1 字段级权限）——user 列表每行
//!    每敏感字段调用一次，QPS 直接相关：
//!    - `mask_phone`：典型（11 位手机号）+ 边界（空串）；
//!    - `mask_email`：典型（标准邮箱）+ 边界（空串）；
//!    - `mask_id_card`：典型（18 位）+ 边界（异常长度 5 位，走保守掩码）；
//!    - `mask_keep`（掩码底座）：典型（11 位 3/4 保留）+ 边界（空串）。
//! 2. `middleware::ak_sign::sign_string`（AK/SK 签名 HMAC-SHA256）——每个
//!    开放 API 请求验签一次：典型（64 字符 SK + 完整 string_to_sign 五段）
//!    + 边界（空 SK + 空 body 摘要）。
//! 3. `common::sort`（动态排序白名单解析，方案 B）——每个分页列表请求调用：
//!    - `camel_to_snake`：典型（camelCase prop）+ 边界（空串）；
//!    - `resolve_column`：典型（白名单命中）+ 边界（未命中回退 None）。
//! 4. `service::sys_web_hook_service`（webhook 遗留事件口径兼容）：
//!    - `map_legacy_event_key`：典型（命中映射表 `login_success`）+ 边界
//!      （目录外事件名原样返回）；
//!    - `convert_legacy_event_types`：典型（混合遗留/目录事件、含空白尾逗号）
//!      + 边界（空串 = 订阅全部，返回 `None`）。
//!
//! # 运行方式
//!
//! ```text
//! cargo bench                                        # 完整采样（每基准默认 5s）
//! cargo bench -- --measurement-time 1                # 快速跑一轮（每基准采样 1s）
//! cargo bench --bench hot_paths -- --sample-size 20  # 仅 hot_paths + 缩小样本
//! ```
//!
//! 报告输出：`target/criterion/report/index.html`（含均值/中位数/置信区间）。
//!
//! # 注意
//!
//! - 仅引用各模块 `pub` 纯函数（不引用私有函数，不为此改可见性）；
//! - `clippy --all-targets` 会编译本文件，需保持零告警；
//! - 所有典型/边界输入均为字面量，通过 `black_box` 防止编译器常量折叠。

use std::hint::black_box;

use criterion::{Criterion, criterion_group, criterion_main};

use stepby_axum::common::sort::{camel_to_snake, resolve_column};
use stepby_axum::entity::sys_logininfor::{Column, Entity as Logininfor};
use stepby_axum::middleware::ak_sign::sign_string;
use stepby_axum::service::sys_web_hook_service::{convert_legacy_event_types, map_legacy_event_key};
use stepby_axum::utils::masking::{mask_email, mask_id_card, mask_keep, mask_phone};

// ==================== 输入素材（真实业务口径字面量） ====================

/// 典型 11 位手机号（与 masking 单测同口径）
const PHONE_11: &str = "13812345678";
/// 典型 18 位身份证号
const ID_CARD_18: &str = "110101199001011234";
/// 异常长度身份证（5 位，走保守掩码分支）
const ID_CARD_SHORT: &str = "12345";
/// 典型邮箱
const EMAIL: &str = "alice@example.com";
/// 典型 64 字符 secret key（AK/SK 协议的 SK 口径）
const SECRET_64: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
/// 典型 string_to_sign：METHOD\nPATH\nTIMESTAMP\nNONCE\nSHA256(body 摘要 hex) 五段
const STRING_TO_SIGN: &str = "POST\n/open/v1/profile\n1767225600\n5f1a7c2e-9d4b-4f6a-8e21-3c9b0a7d5e11\n9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08";
/// 空 body 的 SHA-256 摘要（AK 协议边界：请求体为空时 body 段即此值）
const EMPTY_BODY_SHA256: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
/// 登录日志表白名单（与 common::sort 单测/服务接入同口径的排序允许列）
const ALLOW_LOGININFOR: &[(&str, Column)] = &[
    ("info_id", Column::InfoId),
    ("ipaddr", Column::Ipaddr),
    ("user_name", Column::UserName),
    ("status", Column::Status),
    ("login_time", Column::LoginTime),
];

// ==================== 1. masking：业务展示口径脱敏 ====================

fn bench_masking(c: &mut Criterion) {
    let mut g = c.benchmark_group("masking");

    // mask_phone：11 位命中快路径（保留 3/4）
    g.bench_function("mask_phone/11_digits", |b| {
        b.iter(|| mask_phone(black_box(PHONE_11)))
    });
    // mask_phone：空串边界（trim 后为空，原样返回）
    g.bench_function("mask_phone/empty", |b| {
        b.iter(|| mask_phone(black_box("")))
    });

    // mask_email：标准邮箱（本地部分掩码 + 域名保留）
    g.bench_function("mask_email/normal", |b| {
        b.iter(|| mask_email(black_box(EMAIL)))
    });
    // mask_email：空串边界（原样返回分支）
    g.bench_function("mask_email/empty", |b| {
        b.iter(|| mask_email(black_box("")))
    });

    // mask_id_card：18 位（保留 4/4）
    g.bench_function("mask_id_card/18_chars", |b| {
        b.iter(|| mask_id_card(black_box(ID_CARD_18)))
    });
    // mask_id_card：异常长度边界（5 位，保守掩码分支）
    g.bench_function("mask_id_card/abnormal_5_chars", |b| {
        b.iter(|| mask_id_card(black_box(ID_CARD_SHORT)))
    });

    // mask_keep：掩码底座典型用法（11 位保留 3/4）
    g.bench_function("mask_keep/phone_3_4", |b| {
        b.iter(|| mask_keep(black_box(PHONE_11), 3, 4))
    });
    // mask_keep：空串边界（n==0 提前返回）
    g.bench_function("mask_keep/empty", |b| {
        b.iter(|| mask_keep(black_box(""), 1, 1))
    });

    g.finish();
}

// ==================== 2. ak_sign：AK/SK HMAC 签名 ====================

fn bench_ak_sign(c: &mut Criterion) {
    let mut g = c.benchmark_group("ak_sign");

    // 典型：64 字符 SK + 完整五段 string_to_sign（每开放 API 请求一次）
    g.bench_function("sign_string/64char_secret_full", |b| {
        b.iter(|| sign_string(black_box(SECRET_64), black_box(STRING_TO_SIGN)))
    });
    // 边界：空 SK + 空 body 摘要 string_to_sign（HMAC 接受任意长度密钥）
    g.bench_function("sign_string/empty_secret_empty_body", |b| {
        b.iter(|| sign_string(black_box(""), black_box(EMPTY_BODY_SHA256)))
    });

    g.finish();
}

// ==================== 3. sort：白名单排序解析 ====================

fn bench_sort(c: &mut Criterion) {
    let mut g = c.benchmark_group("sort");

    // camel_to_snake：典型 camelCase prop（每个分页请求一次归一）
    g.bench_function("camel_to_snake/camelCase", |b| {
        b.iter(|| camel_to_snake(black_box("loginTime")))
    });
    // camel_to_snake：空串边界
    g.bench_function("camel_to_snake/empty", |b| {
        b.iter(|| camel_to_snake(black_box("")))
    });

    // resolve_column：白名单命中（loginTime → Column::LoginTime）
    g.bench_function("resolve_column/whitelist_hit", |b| {
        b.iter(|| resolve_column::<Logininfor>(black_box("loginTime"), ALLOW_LOGININFOR))
    });
    // resolve_column：未命中边界（非法列回退 None，不透传任意列）
    g.bench_function("resolve_column/whitelist_miss", |b| {
        b.iter(|| resolve_column::<Logininfor>(black_box("passwd"), ALLOW_LOGININFOR))
    });

    g.finish();
}

// ==================== 4. webhook：遗留事件口径兼容 ====================

fn bench_webhook(c: &mut Criterion) {
    let mut g = c.benchmark_group("webhook_legacy_events");

    // map_legacy_event_key：命中映射表（login_success → login.success）
    g.bench_function("map_legacy_event_key/map_hit", |b| {
        b.iter(|| map_legacy_event_key(black_box("login_success")))
    });
    // map_legacy_event_key：目录外事件名边界（原样返回，SCIM 口径）
    g.bench_function("map_legacy_event_key/no_map_passthrough", |b| {
        b.iter(|| map_legacy_event_key(black_box("scim.user.created")))
    });

    // convert_legacy_event_types：典型混合输入（遗留名 + 目录名 + 空白元素）
    g.bench_function("convert_legacy_event_types/mixed_list", |b| {
        b.iter(|| convert_legacy_event_types(black_box("login, login_failure, scim.user.created, ")))
    });
    // convert_legacy_event_types：空串边界（= 订阅全部，返回 None）
    g.bench_function("convert_legacy_event_types/empty_all", |b| {
        b.iter(|| convert_legacy_event_types(black_box("")))
    });

    g.finish();
}

criterion_group!(
    benches,
    bench_masking,
    bench_ak_sign,
    bench_sort,
    bench_webhook
);
criterion_main!(benches);
