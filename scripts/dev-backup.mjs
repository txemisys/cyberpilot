import { mkdirSync, writeFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import path from "node:path";

const root = path.resolve(import.meta.dirname, "..");
const backupDir = path.join(root, "backups");
mkdirSync(backupDir, { recursive: true });

const stamp = new Date().toISOString().replaceAll(":", "-").replaceAll(".", "-");
const outputPath = path.join(backupDir, `cyberpilot-${stamp}.dump`);

const result = spawnSync(
  "docker",
  [
    "compose", "-f", path.join(root, "compose.dev.yml"),
    "exec", "-T", "postgres",
    "pg_dump",
    "--username=postgres",
    "--dbname=cyberpilot",
    "--format=custom",
    "--no-owner",
    "--no-privileges",
  ],
  { cwd: root, encoding: null, maxBuffer: 256 * 1024 * 1024 },
);

if (result.status !== 0) {
  process.stderr.write(result.stderr ?? Buffer.from("Backup failed.\n"));
  process.exit(result.status ?? 1);
}

writeFileSync(outputPath, result.stdout);
console.log(`Backup written to ${outputPath}`);
