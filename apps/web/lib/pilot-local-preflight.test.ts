import { describe, expect, it } from "vitest";

import {
  assertPilotRuntimeChecks,
  checkPilotRuntime,
} from "./pilot-local-preflight";

describe("pilot local runtime preflight", () => {
  it("accepts healthy app, PostgreSQL, Loki and Grafana responses", async () => {
    const fetcher = async (input: string | URL | Request) => {
      const url = String(input);

      if (url.includes("/api/health") && url.includes(":3000")) {
        return new Response(
          JSON.stringify({ status: "ok", database: "ok" }),
          { status: 200, headers: { "content-type": "application/json" } },
        );
      }

      return new Response("ok", { status: 200 });
    };

    const checks = await checkPilotRuntime(fetcher);

    expect(checks.every((check) => check.ok)).toBe(true);
    expect(() => assertPilotRuntimeChecks(checks)).not.toThrow();
  });

  it("fails closed when application health does not confirm PostgreSQL", async () => {
    const fetcher = async (input: string | URL | Request) => {
      const url = String(input);

      if (url.includes(":3000")) {
        return new Response(
          JSON.stringify({ status: "degraded", database: "error" }),
          { status: 503, headers: { "content-type": "application/json" } },
        );
      }

      return new Response("ok", { status: 200 });
    };

    const checks = await checkPilotRuntime(fetcher);

    expect(checks.find((check) => check.name.includes("PostgreSQL"))?.ok).toBe(
      false,
    );
    expect(() => assertPilotRuntimeChecks(checks)).toThrow(
      "CyberPilot application + PostgreSQL",
    );
  });

  it("does not include endpoint response bodies in failures", async () => {
    const fetcher = async () =>
      new Response("secret upstream payload", { status: 500 });

    const checks = await checkPilotRuntime(fetcher);

    expect(checks.map((check) => check.detail).join(" ")).not.toContain(
      "secret upstream payload",
    );
  });
});
