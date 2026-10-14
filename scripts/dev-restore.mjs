import { readFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import path from "node:path";

const root = path.resolve(import.meta.dirname, "..");
const input = process.argv[2];

if (!input) {
  console.error("Usage: pnpm dev:restore -- backups/<file>.dump");
  process.exit(2);
}

const backupPath = path.resolve(root, input);
const backup = readFileSync(backupPath);
const compose = ["compose", "-f", path.join(root, "compose.dev.yml"), "exec", "-T", "postgres"];

function run(args, options = {}) {
  const result = spawnSync("docker", [...compose, ...args], {
    cwd: root,
    encoding: options.encoding ?? "utf8",
    input: options.input,
    maxBuffer: 256 * 1024 * 1024,
  });

  if (result.status !== 0) {
    if (result.stdout) process.stderr.write(result.stdout);
    if (result.stderr) process.stderr.write(result.stderr);
    process.exit(result.status ?? 1);
  }
}

run(["psql", "--username=postgres", "--dbname=postgres", "-v", "ON_ERROR_STOP=1", "-c",
  "DROP DATABASE IF EXISTS cyberpilot_restore;"]);
run(["psql", "--username=postgres", "--dbname=postgres", "-v", "ON_ERROR_STOP=1", "-c",
  "CREATE DATABASE cyberpilot_restore;"]);
run(
  ["pg_restore", "--username=postgres", "--dbname=cyberpilot_restore", "--no-owner", "--no-privileges", "--exit-on-error"],
  { encoding: null, input: backup },
);

console.log("Restore completed at: postgresql://postgres:postgres@localhost:5432/cyberpilot_restore");
console.log("Verify with: DATABASE_URL=postgresql://postgres:postgres@localhost:5432/cyberpilot_restore pnpm db:migrate:status");
