// stepby-axum/scripts/start-rustfs.mjs
// 本地 S3 兼容服务（RustFS）常驻启动器——供 storage s3 集成测试
// （src/storage/s3.rs 的 s3_backend_roundtrip_live）探活自动运行。
//
// 用法：node scripts/start-rustfs.mjs
// 前置：test-tools/rustfs/rustfs.exe（获取方式见该测试的文档注释）
// 行为：RustFS 已在跑则直接退出（幂等）；数据目录 test-tools/rustfs-data。
import { spawn } from "node:child_process";
import net from "node:net";
import { existsSync, mkdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const EXE = join(ROOT, "test-tools", "rustfs", "rustfs.exe");
const DATA = join(ROOT, "test-tools", "rustfs-data");
const HOST = "127.0.0.1";
const PORT = 9000;

/** TCP 探活（1s 超时，node net 直连——不依赖 PowerShell） */
function probe(port) {
  return new Promise((resolve) => {
    const s = net.connect(port, HOST);
    s.setTimeout(1000);
    s.on("connect", () => {
      s.destroy();
      resolve(true);
    });
    s.on("error", () => resolve(false));
    s.on("timeout", () => {
      s.destroy();
      resolve(false);
    });
  });
}

const alive = await probe(PORT);
if (alive) {
  console.log(`RUSTFS_ALREADY_UP port=${PORT}`);
  process.exit(0);
}

if (!existsSync(EXE)) {
  console.error(
    `RustFS 二进制不存在: ${EXE}\n获取方式见 src/storage/s3.rs 的 s3_backend_roundtrip_live 测试注释（GitHub release rustfs-windows-x86_64）`,
  );
  process.exit(1);
}
if (!existsSync(DATA)) mkdirSync(DATA, { recursive: true });

const child = spawn(
  EXE,
  ["server", "--address", `${HOST}:${PORT}`, DATA],
  {
    detached: true,
    stdio: "ignore",
    env: {
      ...process.env,
      RUSTFS_ACCESS_KEY: "minioadmin",
      RUSTFS_SECRET_KEY: "minioadmin123",
    },
  },
);
child.unref();

// 启动确认（最多等 10s；RustFS 初始化卷需要数秒）
let up = false;
for (let i = 0; i < 10; i++) {
  await new Promise((r) => setTimeout(r, 1000));
  if (await probe(PORT)) {
    up = true;
    break;
  }
}
if (!up) {
  console.error("RUSTFS_START_FAILED：10s 内未监听端口（检查 rustfs-data 是否残留半初始化数据）");
  process.exit(1);
}
console.log(`RUSTFS_UP pid=${child.pid} port=${PORT}`);
