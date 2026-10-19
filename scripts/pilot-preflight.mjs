import { spawnSync } from "node:child_process";

import {
  assertPilotRuntimeChecks,
  checkPilotRuntime,
} from "../apps/web/lib/pilot-local-preflight.ts";

function run(command, args) {
  process.stdout.write(`\n→ ${command} ${args.join(" ")}\n`);

  const result = spawnSync(command, args, {
    cwd: process.cwd(),
    env: process.env,
    stdio: "inherit",
    shell: process.platform === "win32",
  });

  if (result.error) {
    throw result.error;
  }

  if (result.status !== 0) {
    throw new Error(`${command} ${args.join(" ")} failed.`);
  }
}

async function main() {
  console.log("CyberPilot first LIVE pilot local preflight");
  console.log("No secret values will be printed by this command.");

  run("pnpm", ["pilot:check"]);
  run("pnpm", ["db:migrate:status"]);

  const checks = await checkPilotRuntime(fetch, {
    appHealth:
      process.env.CYBERPILOT_PREFLIGHT_APP_HEALTH_URL ??
      "http://127.0.0.1:3000/api/health",
    lokiReady:
      process.env.CYBERPILOT_PREFLIGHT_LOKI_READY_URL ??
      "http://127.0.0.1:3100/ready",
    grafanaHealth:
      process.env.CYBERPILOT_PREFLIGHT_GRAFANA_HEALTH_URL ??
      "http://127.0.0.1:3001/api/health",
  });

  console.log("\nRuntime checks:");

  for (const check of checks) {
    console.log(`[${check.ok ? "OK" : "FAIL"}] ${check.name}: ${check.detail}`);
  }

  assertPilotRuntimeChecks(checks);

  console.log("\nPilot local preflight passed.");
  console.log(
    "This does not replace Microsoft admin consent, the read-only probe, or first real-tenant evidence validation.",
  );
}

main().catch((error) => {
  console.error(
    error instanceof Error
      ? `\nPilot local preflight failed: ${error.message}`
      : "\nPilot local preflight failed.",
  );
  process.exitCode = 1;
});
