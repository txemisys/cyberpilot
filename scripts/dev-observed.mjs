import { mkdirSync, createWriteStream } from "node:fs";
import { spawn } from "node:child_process";
import path from "node:path";

const root = path.resolve(import.meta.dirname, "..");
const logDir = path.join(root, "var", "log", "cyberpilot");
const logPath = path.join(logDir, "app.log");

mkdirSync(logDir, { recursive: true });

const log = createWriteStream(logPath, { flags: "a" });
const pnpm = process.platform === "win32" ? "pnpm.cmd" : "pnpm";
const child = spawn(pnpm, ["--filter", "@cyberpilot/web", "dev"], {
  cwd: root,
  env: process.env,
  stdio: ["inherit", "pipe", "pipe"],
});

for (const stream of [child.stdout, child.stderr]) {
  stream.pipe(process.stdout);
  stream.pipe(log, { end: false });
}

child.on("exit", (code, signal) => {
  log.end();
  if (signal) {
    process.kill(process.pid, signal);
    return;
  }
  process.exit(code ?? 1);
});

for (const signal of ["SIGINT", "SIGTERM"]) {
  process.on(signal, () => child.kill(signal));
}
